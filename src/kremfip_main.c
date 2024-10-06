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

//#define TEST
/* Reference monitor pointer. */
rm_t *rm_p = NULL;

// Retrieve the syscalls function pointers

#ifdef TEST
#define RD_THREAD 1
#define WR_THREAD 2
#define THREAD_NAME 16

static struct task_struct *task_read[RD_THREAD], *task_write[WR_THREAD];

static int read_func(void *arg) {
	while (!kthread_should_stop()) {
		// read from hash table every 10 seconds
		ssleep(10);
		ht_print(rm_p->ht);
	}
	return 0;
}

static int write_func(void *arg) {
	int count = 0;
	int choice = 0;
	int ret;
	node_t *node = NULL;
	while (!kthread_should_stop()) {
		char path[100];
		char *base = "/home/effi/file";
		// write to hash table every 5 seconds
		ssleep(5);
		switch (choice) {
		// simulate the addition of a file to the hash table
		case 0:
			sprintf(path, "%s%d%s", base, count, ".txt");
			count++;
			node = node_init(path);
			if (unlikely(node == NULL)) {
				printk(KERN_ERR "Failed to allocate memory for the node\n");
				goto out;
			}
			printk("key: %llu\n", node->key);
			ret = ht_insert_node(rm_p->ht, node);
			if (unlikely(ret != 0)) {
				printk(KERN_ERR "Failed to insert the node in the hash table\n");
			}
out:
			break;
		case 1:
			// simulate the removal of the first file from the hash table
			if (count % 3 == 0) {
				ret = ht_delete_node(rm_p->ht, node);
				if (unlikely(ret != 0)) {
					printk(KERN_ERR "Failed to delete the node from the hash table\n");
					//return -ENOMEM;
					break;
				}
			}
			count++;
			break;
		default:
			choice = -1;
			break;
		}
		choice++;
		if (count >= 5) {
			count = 0;
		}
	}
	return 0;
}
#endif

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
static struct kprobe kp_unlink = {
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
};

/* Required module's reference. */
struct module *scth_mod = NULL;

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
#ifdef TEST
	unsigned int counter;
	char thread_name[THREAD_NAME] = { 0 };

	for (counter = 0; counter < WR_THREAD; ++counter) {
		snprintf(thread_name, THREAD_NAME, "write_func_%ud", counter);
		task_write[counter] = kthread_create(write_func, NULL, thread_name);
		if (IS_ERR(task_write[counter])) {
			printk(KERN_ERR "Failed to create %s (%ld)\n", thread_name,
				   PTR_ERR(task_write[counter]));
			return PTR_ERR(task_write[counter]);
		} else {
			wake_up_process(task_write[counter]);
		}
	}
	for (counter = 0; counter < RD_THREAD; ++counter) {
		snprintf(thread_name, THREAD_NAME, "read_func_%ud", counter);
		task_read[counter] = kthread_create(read_func, NULL, thread_name);
		if (IS_ERR(task_read[counter])) {
			printk(KERN_ERR "Failed to create %s (%ld)\n", thread_name,
				   PTR_ERR(task_read[counter]));
			return PTR_ERR(task_read[counter]);
		} else {
			wake_up_process(task_read[counter]);
		}
	}
#endif

	// Register the system call
	state_get_nr = scth_hack(__x64_sys_state_get);
	state_set_nr = scth_hack(__x64_sys_state_set);
	reconfigure_nr = scth_hack(__x64_sys_reconfigure);
	pwd_check_nr = scth_hack(__x64_sys_pwd_check);
	pr_info("%d", state_get_nr);
	if (state_get_nr < 0) {
		scth_cleanup();
		rm_free(rm_p);
		module_put(scth_mod);
		WARNING("Failed to install state get syscall at %d\n", state_get_nr);
		return -EPERM;
	}
	if (state_set_nr < 0) {
		scth_cleanup();
		rm_free(rm_p);
		module_put(scth_mod);
		WARNING("Failed to install state set syscall at %d\n", state_set_nr);
		return -EPERM;
	}
	if (reconfigure_nr < 0) {
		scth_cleanup();
		rm_free(rm_p);
		module_put(scth_mod);
		WARNING("Failed to install reconfigure syscall at %d\n", reconfigure_nr);
		return -EPERM;
	}
	if (pwd_check_nr < 0) {
		scth_cleanup();
		rm_free(rm_p);
		module_put(scth_mod);
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
#ifdef TEST
	int rc;
	unsigned int counter;

	for (counter = 0; counter < RD_THREAD; ++counter) {
		if (task_read[counter] && !IS_ERR(task_read[counter])) {
			rc = kthread_stop(task_read[counter]);
			printk(KERN_INFO "read_func_%u stopped with rc (%d)\n", counter, rc);
		}
	}
	for (counter = 0; counter < WR_THREAD; ++counter) {
		if (task_write[counter] && !IS_ERR(task_write[counter])) {
			rc = kthread_stop(task_write[counter]);
			printk(KERN_INFO "write_func_%u stopped with rc (%d)\n", counter, rc);
		}
	}
#endif
	// Unregister the system call
	scth_cleanup();
	//unregistering kprobes
	unregister_kprobe(&kp_open);
	unregister_kprobe(&kp_unlink);
	unregister_kprobe(&kp_mkdir);
	unregister_kprobe(&kp_rmdir);
	// Dereference the SCTH module
	module_put(scth_mod);
	// Free the reference monitor
	rm_free(rm_p);
	INFO("Module unloaded\n");
}

module_init(kremfip_init);
module_exit(kremfip_exit);
