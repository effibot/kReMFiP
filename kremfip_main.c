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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/kobject.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include "include/rmfs.h"

#ifndef RM_INIT_STATE
#define RM_INIT_STATE OFF
#endif


#define state_ops(rmfs) rmfs->kobj.ktype->sysfs_ops
#define show_op(rmfs) state_ops(rmfs)->show

static rmfs_t *rmfs;

static int __init kremfip_init(void) {
    rmfs = rm_init();
    if (unlikely(rmfs == NULL)) {
        printk(KERN_ERR "Failed to initialize the reference monitor\n");
        return -ENOMEM;
    }
    printk(KERN_INFO "kReMFiP module loaded\n");

    rmfs->state = RM_INIT_STATE;
    // TODO: find a way to set the state of the reference monitor at startup


    return 0;
}

static void __exit kremfip_exit(void) {
    rm_free(rmfs);
    printk(KERN_INFO "kReMFiP module unloaded\n");
}


module_init(kremfip_init);
module_exit(kremfip_exit);
MODULE_DESCRIPTION("Reference Monitor File System");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Efficace");
