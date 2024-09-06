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

#include "lib/scth.h"

/* This module only works for kernels equal or later than 4.17. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
#error "This module requires kernel >= 4.17."
#endif

extern int nr_sysnis;

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