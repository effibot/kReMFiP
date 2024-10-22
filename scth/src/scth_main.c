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
#include <linux/kobject.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/sysfs.h>
#include <linux/syscalls.h>
#include "../headers/scth_lib.h"
#include "include/scth.h"
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Efficace <andrea.efficace1@gmail.com>");
MODULE_DESCRIPTION("Discovers and hacks the system call table.");
MODULE_INFO(name, MODNAME);
MODULE_INFO(OS, "Linux");
MODULE_VERSION("1.0");

/**
 * Since we have to runtime installs system calls we need to check the kernel version and
 * limit the module to a specific range of versions. The lower bound is to don't be bothered
 * with the old kernel versions, while the upper bound is to avoid the changes in the system
 * call management that happened after the 5.4 version.
 */
#if !(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0))
#error "This module requires kernel in range [4.17.x, 5.4.x]"
#endif

extern int nr_sysnis;
extern struct scth_entry *avail_sysnis;
/* This ensures that operations on the Table are performed atomically. */
DEFINE_MUTEX(scth_lock);

/* Show function for the sysnis_kobj. */
static ssize_t sysnis_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t hsysnis_show(struct kobject * kobj, struct kobj_attribute * attr, char * buf);

/* The sysnis attribute of the sysnis_kobj.
 * As we only need to read the sysnis, we can define it as read-only.
 * Also, we don't need a fully-fledged kobject since we just want to expose a file
 * and the module kset is already available.
 */
static struct kobj_attribute sysnis_attr = __ATTR(sysnis, 0444, sysnis_show, NULL);
static struct kobj_attribute hsysnis_attr = __ATTR(hsysnis, 0444, hsysnis_show, NULL);
/* Module initialization routine. */
static int __init scth_init(void) {
	// Inspect system memory and find the system call table address
	void **table_addr = scth_finder();
	if (table_addr == NULL) {
		printk(KERN_ERR "%s: Shutdown...\n", MODNAME);
		return -EFAULT;
	}
	// at this point, all our data structures are initialized and can be used.

	// Create the kobject
	if (sysfs_create_file(&THIS_MODULE->mkobj.kobj, &sysnis_attr.attr)) {
		printk(KERN_ERR "Error creating the sysnis attribute\n");
		return -EFAULT;
	}
	if (sysfs_create_file(&THIS_MODULE->mkobj.kobj, &hsysnis_attr.attr)) {
		printk(KERN_ERR "Error creating the sysnis attribute\n");
		return -EFAULT;
	}

	// Get the indexes of the unused system calls
	printk(KERN_INFO "%s: Ready, found %d entries.\n", MODNAME, nr_sysnis);
	printk(KERN_CONT "The corresponding indexes are:\n");
	for (int i = 0; i < nr_sysnis ; i++) {
		if(!avail_sysnis[i].hacked)
			printk(KERN_CONT "%d ", avail_sysnis[i].tab_index);
	}
	printk(KERN_CONT "\n");
	printk(KERN_INFO "The system call table is exposed\n");
	return 0;
}

module_init(scth_init);

/* Module cleanup routine. */
static void __exit scth_exit(void) {
	printk(KERN_INFO "%s: Shutdown...\n", MODNAME);
	sysfs_remove_file(&THIS_MODULE->mkobj.kobj, &sysnis_attr.attr);
	sysfs_remove_file(&THIS_MODULE->mkobj.kobj, &hsysnis_attr.attr);
	scth_cleanup();
	printk(KERN_INFO "The system call table is no longer exposed\n");
}

module_exit(scth_exit);

/**
 * @brief Returns a pointer to an integer array containing the indexes of the unused system calls.
 * The array is exposed as through a char* buffer as a space-separated list of integers.
 * @param kobj The kobject that will be used to expose the syscalls information.
 * @param attr The attribute of the kobject.
 * @param buf The buffer that will contain the information.
 * @return ssize_t The number of bytes written to the buffer.
 */
static ssize_t sysnis_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
	int len = 0;
	for (int i = 0; i < nr_sysnis; i++) {
		if (!avail_sysnis[i].hacked) {
			len += sprintf(buf + len, "%d ", avail_sysnis[i].tab_index);
		}
	}
	len += sprintf(buf + len, "\n");
	return len;
}
static ssize_t hsysnis_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
	int len = 0;
	for (int i = 0; i < nr_sysnis; i++) {
		if (avail_sysnis[i].hacked) {
			len += sprintf(buf + len, "%d ", avail_sysnis[i].tab_index);
		}
	}
	len += sprintf(buf + len, "\n");
	return len;
}
