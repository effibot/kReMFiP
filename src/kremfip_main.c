/**
 * @file kremfip_main.c
 * @author Andrea Efficace (andrea.efficace1@gmail.com)
 * @brief Main file for the kReMFiP project
 * @version 0.1
 * @date 2024-07-29
 *
 * @copyright Copyright (c) 2024
 *
 */

#define EXPORT_SYMTAB

#include "../scth/headers/scth_lib.h"
#include "include/kremfip.h"
#include "include/rm.h"
#include "utils/misc.h"
#include "utils/pathmgm.h"
#include <linux/compiler.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Efficace");
MODULE_DESCRIPTION("Reference Monitor File System");
MODULE_INFO(name, MODNAME);
MODULE_INFO(OS, "Linux");
MODULE_VERSION("1.0");

/**
 * Since we have to runtime installs system calls we need to check the kernel version and
 * limit the module to a specific range of versions. The lower bound is to don't be bothered
 * with the old kernel versions, while the upper bound is to avoid the changes in the system
 * call management that happened after the 5.4 version.
 */
#if !(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) && \
	  LINUX_VERSION_CODE <= KERNEL_VERSION(5, 5, 0))
#error "This module requires kernel in range [4.17.x, 5.4.x]"
#endif

/* Reference monitor pointer. */
rm_t *rm_p = NULL;

// syscall numbers
int state_get_nr = -1;
int state_set_nr = -1;
int reconfigure_nr = -1;
int pwd_check_nr = -1;

__SYSCALL_DEFINEx(1, _state_get, state_t __user *, u_state) {
#ifdef DEBUG
	INFO("invoking __x64_sys_state_get\n");
#endif
	if (!try_module_get(THIS_MODULE))
		return -ENOSYS;
	const int ret = rm_state_get(u_state);
	if (ret != 0) {
		WARNING("failed to copy to user\n");
		module_put(THIS_MODULE);
		return -EFAULT;
	}
	module_put(THIS_MODULE);
	return ret;
}

__SYSCALL_DEFINEx(1, _state_set, const state_t __user *, state) {
#ifdef DEBUG
	INFO("Invoking __x64_sys_state_set\n");
#endif
	if (!try_module_get(THIS_MODULE))
		return -ENOSYS;
	// password is checked in user space, if we came here, we can trust the user
	const uid_t old_euid = elevate_privileges();
	if (get_euid() != 0) { // if this is not zero we have an error
		WARNING("Failed to elevate the privileges\n");
		module_put(THIS_MODULE);
		return old_euid;
	}
	// we are root now, change the state of the monitor.
	const int ret = rm_state_set(state);
	if (ret != 0) {
		// just log the error, we have to restore privileges anyway
		WARNING("Unable to change the state of the monitor with error code: %d\n", ret);
	}
	// restore the privileges
	const int priv_err = reset_privileges(old_euid);
	if (priv_err != 0) {
		WARNING("Failed to reset the privileges\n");
		module_put(THIS_MODULE);
		return priv_err;
	}
	module_put(THIS_MODULE);
	return ret;
}

__SYSCALL_DEFINEx(2, _reconfigure, const path_op_t __user *, op, const char __user *, path) {
#ifdef DEBUG
	INFO("Invoking __x64_sys_reconfigure\n");
#endif
	if (!try_module_get(THIS_MODULE))
		return -ENOSYS;
	const uid_t old_euid = elevate_privileges();
	if (get_euid() != 0) { // if this is not zero we have an error
		WARNING("Failed to elevate the privileges\n");
		module_put(THIS_MODULE);
		return old_euid;
	}
	const int ret = rm_reconfigure(op, path);
	if (ret != 0) {
		WARNING("failed to reconfigure the monitor with error: %d\n", ret);
	}
	// restore the privileges
	const int priv_err = reset_privileges(old_euid);
	if (priv_err != 0) {
		WARNING("Failed to reset the privileges\n");
		module_put(THIS_MODULE);
		return priv_err;
	}
	module_put(THIS_MODULE);
	return ret;
}

__SYSCALL_DEFINEx(1, _pwd_check, const char __user *, pwd) {
#ifdef DEBUG
	INFO("Invoking __x64_sys_pwd_check\n");
#endif
	if (!try_module_get(THIS_MODULE))
		return -ENOSYS;
	int ret = rm_pwd_check(pwd);
	if (ret != 0) {
		WARNING("failed to copy to user with error: %d\n", ret);
		module_put(THIS_MODULE);
		return -EFAULT;
	}
	module_put(THIS_MODULE);
	return ret;
}

// KProbes
static struct kprobe kp_open = {
	.symbol_name = "do_filp_open",
	.pre_handler = rm_open_pre_handler,
};
/*static struct kprobe kp_unlink = {
	.symbol_name =  "do_unlinkat",
	.pre_handler = rm_unlink_pre_handler,
};

static struct kprobe kp_mkdir = {
	.symbol_name =  "do_mkdirat",
	.pre_handler = rm_mkdir_pre_handler,
};

static struct kprobe kp_rmdir = {
	.symbol_name =  "do_rmdir",
	.pre_handler = rm_rmdir_pre_handler,
};*/


static int __init kremfip_init(void) {
	// Check if the SCTH module is loaded by inspecting the existence of its /sysfs folder
	if (unlikely(!path_exists("/sys/module/scth"))) {
		WARNING("The SCTH module is not loaded\n");
		return -ENOENT;
	}
	// the system call is exposed, we can hack it later
	INFO("The SCTH module is loaded")
	rm_p = rm_init();
	if (unlikely(rm_p == NULL)) {
		printk(KERN_ERR "Failed to initialize the reference monitor\n");
		rm_free(rm_p);
		return -ENOMEM;
	}

	// Register the system call
	state_get_nr = scth_hack(__x64_sys_state_get);
	state_set_nr = scth_hack(__x64_sys_state_set);
	reconfigure_nr = scth_hack(__x64_sys_reconfigure);
	pwd_check_nr = scth_hack(__x64_sys_pwd_check);
	pr_info("%d", state_get_nr);
	if (state_get_nr < 0) {
		scth_cleanup();
		rm_free(rm_p);
		WARNING("Failed to install state get syscall at %d\n", state_get_nr);
		return -EPERM;
	}
	if (state_set_nr < 0) {
		scth_cleanup();
		rm_free(rm_p);
		WARNING("Failed to install state set syscall at %d\n", state_set_nr);
		return -EPERM;
	}
	if (reconfigure_nr < 0) {
		scth_cleanup();
		rm_free(rm_p);
		WARNING("Failed to install reconfigure syscall at %d\n", reconfigure_nr);
		return -EPERM;
	}
	if (pwd_check_nr < 0) {
		scth_cleanup();
		rm_free(rm_p);
		WARNING("Failed to install pwd check syscall at %d\n", pwd_check_nr);
		return -EPERM;
	}
	// Register the KProbes
	if (register_kprobe(&kp_open) < 0) {
		WARNING("Failed to register kprobe for do_filp_open\n");
		return -EPERM;
	}
	// if (register_kprobe(&kp_unlink) < 0) {
	// 	WARNING("Failed to register kprobe for do_unlinkat\n");
	// 	return -EPERM;
	// }
	// if (register_kprobe(&kp_mkdir) < 0) {
	// 	WARNING("Failed to register kprobe for do_mkdirat\n");
	// 	return -EPERM;
	// }
	// if (register_kprobe(&kp_rmdir) < 0) {
	// 	WARNING("Failed to register kprobe for do_rmdir\n");
	// 	return -EPERM;
	// }
	printk(KERN_INFO "kReMFiP module loaded\n");
	return 0;
}
static void __exit kremfip_exit(void) {

	// Unregister the system call
	scth_cleanup();
	//unregistering kprobes
	unregister_kprobe(&kp_open);
	// unregister_kprobe(&kp_unlink);
	// unregister_kprobe(&kp_mkdir);
	// unregister_kprobe(&kp_rmdir);
	// Dereference the SCTH module
	//module_put(scth_mod);
	// Free the reference monitor
	rm_free(rm_p);
	INFO("Module unloaded\n");
}

module_init(kremfip_init);
module_exit(kremfip_exit);
