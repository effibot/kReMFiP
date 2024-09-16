/**
 * @brief Main source file for the "System Call Table Hacker" kernel module.
 *        See other source files for more information.
 *
 * @author Andrea Efficace <andrea.efficace1@gmail.com>
 *
 * @date August 31, 2024
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/version.h>

#include "include/scth.h"
#include "../headers/scth_lib.h"

/**
 * Since we have to runtime installs system calls we need to check the kernel version and
 * limit the module to a specific range of versions. The lower bound is to don't be bothered
 * with the old kernel versions, while the upper bound is to avoid the changes in the system
 * call management that happened after the 5.4 version.
 * TODO: we could check if this could be ported up to the 5.15 version 5.15.154
 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 4, 0)
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
#error "This module requires kernel in range [4.17.x, 5.4.x]"
#endif
#endif

extern int nr_sysnis;
extern struct scth_entry *avail_sysnis;
/* This ensures that operations on the Table are performed atomically. */
DEFINE_MUTEX(scth_lock);
/* Module initialization routine. */
static int __init scth_init(void) {
	void **table_addr = scth_finder();
	if (table_addr == NULL) {
		printk(KERN_ERR "%s: Shutdown...\n", MODNAME);
		return -EFAULT;
	}
	printk(KERN_INFO "%s: Ready, %d available entries.\n", MODNAME, nr_sysnis);
	printk(KERN_CONT "The corrisponding indexes are:\n");
	int i;
	for (i = 0; i < nr_sysnis; i++) {
		printk(KERN_CONT "%d ", avail_sysnis[i].tab_index);
	}
	printk(KERN_CONT "\n");
	return 0;
}

/* Module cleanup routine. */
static void __exit scth_exit(void) {
	scth_cleanup();
	printk(KERN_INFO "%s: Shutdown...\n", MODNAME);
}

module_init(scth_init);
module_exit(scth_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Efficace <andrea.efficace1@gmail.com>");
MODULE_DESCRIPTION("Discovers and hacks the system call table.");
MODULE_INFO(name, MODNAME);
MODULE_INFO(OS, "Linux");
MODULE_VERSION("1.0");