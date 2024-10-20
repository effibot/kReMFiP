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
#include "include/kremfip.h"
#include "utils/misc.h"
#include "include/rm.h"
#include "../scth/src/include/scth.h"
#include <linux/compiler.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>

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
//#define TEST

/* Reference monitor pointer. */
rm_t *rm_p = NULL;

// Retrieve the syscalls function pointers
extern void* __x64_sys_state_get;
extern void* __x64_sys_state_set;
extern void* __x64_sys_reconfigure;

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
/* Required module's reference. */
struct module *scth_mod = NULL;




static int __init kremfip_init(void) {
	// Lock the SCTH module.

	mutex_lock(&module_mutex);
	scth_mod = find_module("SCTH");
	if (!try_module_get(scth_mod)) {
		mutex_unlock(&module_mutex);
		printk(KERN_ERR "%s: SCTH module not found.\n", MODNAME);
		return -EPERM;
	}
	mutex_unlock(&module_mutex);
	// the system call is exposed, we can hack it later

	rm_p = rm_init();

	if (unlikely(rm_p == NULL)) {
		printk(KERN_ERR "Failed to initialize the reference monitor\n");
		return -ENOMEM;
	}
#ifdef TEST
	unsigned int counter;
	char thread_name[THREAD_NAME] = { 0 };

	for (counter = 0; counter < WR_THREAD; ++counter) {
		snprintf(thread_name, THREAD_NAME, "write_func_%d", counter);
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
		snprintf(thread_name, THREAD_NAME, "read_func_%d", counter);
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
	if (state_get_nr < 0) {
		scth_unhack(state_get_nr);
		module_put(scth_mod);
		WARNING("Failed to install state syscall at %d\n", state_get_nr);
		return -EPERM;
	}
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
	scth_unhack(state_get_nr);
	scth_unhack(state_set_nr);
	scth_unhack(reconfigure_nr);
	module_put(scth_mod);
	rm_free(rm_p);
	INFO("Module unloaded\n");
}

module_init(kremfip_init);
module_exit(kremfip_exit);
MODULE_DESCRIPTION("Reference Monitor File System");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Efficace");
