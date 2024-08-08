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

#ifndef MODNAME
#define MODNAME "kremfip_module"
#endif

#define EXPORT_SYMTAB

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/list.h>
#include "include/rmfs.h"
#include "include/utils.h"

rmfs_t *rmfs_ptr = NULL;

static int __init kremfip_init(void) {
    //rmfs_ptr = kzalloc(sizeof(rmfs_t), GFP_KERNEL);
    rmfs_ptr = rm_init();
    //printk(KERN_INFO "%p\n", &rmfs);
    if (unlikely(rmfs_ptr == NULL)) {
        printk(KERN_ERR "Failed to initialize the reference monitor\n");
        return -ENOMEM;
    }
    printk(KERN_INFO "kReMFiP module loaded\n");
    return 0;
}

static void __exit kremfip_exit(void) {
    LOG_MSG("Unloading the kReMFiP module", "");
    rm_free(rmfs_ptr);
    printk(KERN_INFO "kReMFiP module unloaded\n");
}


module_init(kremfip_init);
module_exit(kremfip_exit);
MODULE_DESCRIPTION("Reference Monitor File System");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Efficace");
