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
#include "include/utils.h"
#include <linux/kthread.h>
#include <linux/delay.h>



#include "include/rmfs.h"

//#define TEST

rm_t *rm_p = NULL;

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
                    if(count % 3 == 0) {
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
        if(count >= 5) {
            count = 0;
        }
    }
    return 0;
}
#endif

static int __init kremfip_init(void) {
    rm_p = rm_init();
     if (unlikely(rm_p == NULL)) {
         printk(KERN_ERR "Failed to initialize the reference monitor\n");
         return -ENOMEM;
     }
#ifdef TEST
    unsigned int            counter;
    char                    thread_name[THREAD_NAME] = { 0 };

    for (counter = 0; counter < WR_THREAD; ++counter) {
        snprintf(thread_name, THREAD_NAME, "write_func_%d", counter);
        task_write[counter] = kthread_create(write_func, NULL, thread_name);
        if (IS_ERR(task_write[counter])) {
            printk(KERN_ERR "Failed to create %s (%ld)\n", thread_name, PTR_ERR(task_write[counter]));
            return PTR_ERR(task_write[counter]);
        } else {
            wake_up_process(task_write[counter]);
        }
    }
    for (counter = 0; counter < RD_THREAD; ++counter) {
        snprintf(thread_name, THREAD_NAME, "read_func_%d", counter);
        task_read[counter] = kthread_create(read_func, NULL, thread_name);
        if (IS_ERR(task_read[counter])) {
            printk(KERN_ERR "Failed to create %s (%ld)\n", thread_name, PTR_ERR(task_read[counter]));
            return PTR_ERR(task_read[counter]);
        } else {
            wake_up_process(task_read[counter]);
        }
    }
#endif
    printk(KERN_INFO "kReMFiP module loaded\n");
    return 0;
}
static void __exit kremfip_exit(void) {
#ifdef TEST
    int                     rc;
    unsigned int            counter;

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
    rm_free(rm_p);
    INFO("Module unloaded\n");
}




module_init(kremfip_init);
module_exit(kremfip_exit);
MODULE_DESCRIPTION("Reference Monitor File System");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Efficace");
