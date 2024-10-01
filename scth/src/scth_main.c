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
 * call management that happened after the 5.15 version.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) && LINUX_VERSION_CODE <= KERNEL_VERSION(5, 15, 0)
#error "This module requires kernel in range [4.17.x, 5.15.x]"
#endif

extern int nr_sysnis;
extern struct scth_entry *avail_sysnis;
/* This ensures that operations on the Table are performed atomically. */
DEFINE_MUTEX(scth_lock);

/* Show function for the sysnis_kobj. */
static ssize_t sysnis_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);

/* The sysnis attribute of the sysnis_kobj.
 * As we only need to read the sysnis, we can define it as read-only.
 * Also, we don't need a fully-fledged kobject since we just want to expose a file
 * and the module kset is already available.
 */
static struct kobj_attribute sysnis_attr = __ATTR_RO(sysnis);

// Add a system call to export the available indexes
__SYSCALL_DEFINEx(1, _get_sysnis, int *, arg) {
	const int *sysnis = scth_get_sysnis();
	if (sysnis == NULL) {
		return -EFAULT;
	}
	if (copy_to_user(arg, sysnis, nr_sysnis * sizeof(int))) {
		return -EFAULT;
	}
	return 0;
}

/* Module initialization routine. */
static int __init scth_init(void) {
	void **table_addr = scth_finder();
	if (table_addr == NULL) {
		printk(KERN_ERR "%s: Shutdown...\n", MODNAME);
		return -EFAULT;
	}
	// Create the kobject
	if(sysfs_create_file(&THIS_MODULE->mkobj.kobj, &sysnis_attr.attr)) {
		printk(KERN_ERR "Error creating the sysnis attribute\n");
		return -EFAULT;
	}
	// Reserve the first index to add our own system call
	const int ret = scth_hack(__x64_sys_get_sysnis);
	if (ret < 0) {
		printk(KERN_ERR "%s: Shutdown...\n", MODNAME);
		return -EFAULT;
	}

	struct file *f = filp_open("/sys/module/scth/sysnis", O_RDONLY, 0);
	if (IS_ERR(f)) {
		printk(KERN_ERR "Error opening the sysnis file\n");
		return -EFAULT;
	}
	char *buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	ssize_t bytes_read = kernel_read(f, buf, PAGE_SIZE, &f->f_pos);
	if (bytes_read < 0) {
		printk(KERN_ERR "Error reading the sysnis file\n");
		return -EFAULT;
	}
	// Log some messages
	printk(KERN_INFO "%s: Ready, %d available entries.\n", MODNAME, nr_sysnis);
	printk(KERN_CONT "The corresponding indexes are:\n");
	printk(KERN_CONT "%s", buf);
	printk(KERN_CONT "\n");

	printk(KERN_INFO "The system call table is exposed\n");
	return 0;
}

module_init(scth_init);

/* Module cleanup routine. */
static void __exit scth_exit(void) {
	scth_cleanup();
	sysfs_remove_file(&THIS_MODULE->mkobj.kobj, &sysnis_attr.attr);
	printk(KERN_INFO "%s: Shutdown...\n", MODNAME);
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
	// Loop over the unused syscalls
	for (int i = 0; i < nr_sysnis; i++) {
		// If the syscall is not used, add it to the buffer
		if(!avail_sysnis[i].hacked)
			len += sprintf(buf + len, "%d ", avail_sysnis[i].tab_index);
	}
	// Add a newline at the end and return the number of bytes written
	len += sprintf(buf + len, "\n");
	return len;
}
