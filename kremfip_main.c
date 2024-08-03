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
#include "include/rm_state.h"
#include "include/types.h"
#include "include/utils.h"
//#include "include/rmfs.h"



#define MODNAME "kremfip"
static rmfs_t *rmfs;
static int __init kremfip_init(void) {
	rmfs = rm_init();
	if (!rmfs) {
		printk(KERN_ERR "Failed to initialize the reference monitor\n");
		return -ENOMEM;
	}
	printk(KERN_INFO "kReMFiP module loaded\n");
	return 0;
}

static void __exit kremfip_exit(void) {
	rm_free(rmfs);
	printk(KERN_INFO "kReMFiP module unloaded\n");
}

int main(int argc, char *argv[]) {
	printk(KERN_INFO "Hello, world\n");
	// check the current state of the reference monitor
	printk(KERN_INFO "Current state: %d\n", rmfs->state);
	// change the state of the reference monitor
	rmfs->state = REC_ON;
	printk(KERN_INFO "New state: %d\n", rmfs->state);
	return 0;
}

module_init(kremfip_init);
module_exit(kremfip_exit);
MODULE_DESCRIPTION("Reference Monitor File System");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Efficace");
