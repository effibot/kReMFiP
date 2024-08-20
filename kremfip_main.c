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

rm_t *rm_p = NULL;

static int __init kremfip_init(void) {
    rm_p = rm_init();
     if (unlikely(rm_p == NULL)) {
         printk(KERN_ERR "Failed to initialize the reference monitor\n");
         return -ENOMEM;
     }
    INFO("adding the file to the hash table");
    // simulate the addition of a file to the hash table
    char *path = "/home/effi/file.txt";
    node_t *node = node_init(path);
    if (unlikely(node == NULL)) {
        printk(KERN_ERR "Failed to allocate memory for the node\n");
        return -ENOMEM;
    }
    printk("key: %lu\n", node->key);
    int ret = ht_insert(rm_p->ht, node);
    if (unlikely(ret != 0)) {
        printk(KERN_ERR "Failed to insert the node in the hash table\n");
        return -ENOMEM;
    }
    ht_print(rm_p->ht);
    // INFO("adding a second file to the hash table");
    // simulate the addition of a second file to the hash table
    // char *path2 = "/home/effi/file2.txt";
    /*node_t *node2 = node_init(path2);
    if (unlikely(node2 == NULL)) {
        printk(KERN_ERR "Failed to allocate memory for the node\n");
        return -ENOMEM;

    }
    printk("key: %lu\n", node2->key);
    ret = ht_insert(rm_p->ht, node2);
    if (unlikely(ret != 0)) {
        printk(KERN_ERR "Failed to insert the node in the hash table\n");
        return -ENOMEM;
    }
    ht_print(rm_p->ht);
    */
    INFO("searching for the first file in the hash table");
    // simulate the search of the first file in the hash table
    node_t *found = ht_lookup(rm_p->ht, node);
    if (unlikely(found == NULL)) {
        printk(KERN_ERR "Failed to find the node in the hash table\n");
        return -ENOMEM;
    }
    printk("found: %s with key %lu\n", found->path, found->key);
    INFO("remove the first file from the hash table");
    // simulate the removal of the first file from the hash table
    ret = ht_delete(rm_p->ht, node);
    if (unlikely(ret != 0)) {
        printk(KERN_ERR "Failed to delete the node from the hash table\n");
        return -ENOMEM;
    }
    ht_print(rm_p->ht);
    printk(KERN_INFO "kReMFiP module loaded\n");
    return 0;
}

static void __exit kremfip_exit(void) {
    rm_free(rm_p);
    INFO("Module unloaded\n");
}


module_init(kremfip_init);
module_exit(kremfip_exit);
MODULE_DESCRIPTION("Reference Monitor File System");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Efficace");
