
/**
 * @file rmfs.c
 * @author your name (you@domain.com)
 * @brief Implementation of the reference monitor as a folder under /sys/kernel
 * We provide show/store operations and initialization functions for the reference monitor structure
 * @version 0.1
 * @date 2024-08-03
 *
 * @copyright Copyright (c) 2024
 *
 */


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/kobject.h>

#include "rmfs.h"

#ifndef RM_NAME
#define RM_NAME "rmfs"
#endif

#ifndef RM_INIT_STATE
//enum _rm_state_t RM_INIT_STATE = OFF;
#define RM_INIT_STATE OFF
#endif



// functions prototypes
static ssize_t state_show(struct kobject *kobj,
                          struct kobj_attribute *attr, char *buf);
static ssize_t state_store(struct kobject *kobj, struct kobj_attribute *attr,
                           const char *buf, size_t count);

// Macro to get a pointer to the reference monitor structure from the kobject
#define to_rmfs_t(obj) container_of(obj, rmfs_t, kobj)


// define sysfs operations
static ssize_t state_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf){
	const rmfs_t *rmfs = to_rmfs_t(kobj);
	printk(KERN_INFO "[%s::%s]: read op invoked by monitor %d", MODNAME, "rmfs.c", rmfs->id);
	int count = sprintf(buf, "%d\n", rmfs->state);
	printk(KERN_INFO "[%s::%s]: read state is %s", MODNAME, "rmfs.c", buf);
	return count;
}

static ssize_t state_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count){
	rmfs_t *rmfs = to_rmfs_t(kobj);
	printk(KERN_INFO "[%s::%s]: store op invoked by monitor %d, msg is %s", MODNAME, "rmfs.c", rmfs->id,buf);
	if(unlikely(rmfs == NULL)){
		printk(KERN_INFO "[%s::%s]: error in to_rmfs_t", MODNAME, "rmfs.c");
		return -EINVAL;
	}
	printk(KERN_INFO "[%s::%s]: rmfs: %p", MODNAME, "rmfs.c", rmfs);
	int new_state;
	// should check if the new state is valid and if ops invoked as root
	// change datastructure state
	if (kstrtoint(buf, 10, &new_state)){
		printk(KERN_INFO "[%s::%s]: error in kstrtoint, %d", MODNAME, "rmfs.c", new_state);
		return -EINVAL;
	}
	rmfs->state = new_state;
	printk(KERN_INFO "[%s::%s]: new state is %d", MODNAME, "rmfs.c", rmfs->state);
	return count;
}

static void rm_release(struct kobject *kobj){
	rmfs_t *rmfs = to_rmfs_t(kobj);
	kobject_put(&rmfs->kobj);
}

// Define the attrribute struct for the state file
static struct kobj_attribute state_attr = __ATTR(state, 0664, state_show, state_store);
static struct attribute *rmfs_attrs[] = {
	&state_attr.attr,
	NULL,
};
//ATTRIBUTE_GROUPS(rmfs);
static struct attribute_group rmfs_groups = {
	.attrs = rmfs_attrs,
};
// static struct kobj_type rmfs_ktype = {
// 	.release = rm_release,
// 	.sysfs_ops = &kobj_sysfs_ops, // default sysfs operations
// 	.default_groups = rmfs_groups,
//};
// Define the kobj_type for the reference monitor

// Define the reference monitor instance
rmfs_t *rm_init(void){
	printk(KERN_INFO "[%s::%s] init invoked", MODNAME, "rmfs.c");
	rmfs_t *rmfs = kzalloc(sizeof(rmfs_t), GFP_KERNEL);
	printk(KERN_INFO "[%s::%s] kzalloc invoked", MODNAME, "rmfs.c");
	printk(KERN_INFO "[%s::%s] rmfs: %p", MODNAME, "rmfs.c", rmfs);
	// check if the allocation was successful
	if (unlikely(rmfs == NULL)){
		printk(KERN_INFO "[%s::%s] init error with code %d",MODNAME, "rm_init", ENOMEM);
		return NULL;
	}
	printk(KERN_INFO "[%s::%s] init success", MODNAME, "rmfs.c");
	// give id
	unsigned random_ticket;
	get_random_bytes(&random_ticket, sizeof(random_ticket));
	rmfs->id = 1u + (random_ticket % 16u);
	// create kobject inside /sys/kernel
	rmfs->kobj =  *kobject_create_and_add("kremfip", kernel_kobj);
	if(unlikely(&(rmfs->kobj) == NULL)){
		printk(KERN_INFO "[%s::%s] init error with code %d",MODNAME, "rm_init", ENOMEM);
		kfree(rmfs);
		return NULL;
	}
	printk(KERN_INFO "[%s::%s] kobject created", MODNAME, "rmfs.c");
	// initialize the kobject with the attribute group

	int ret = sysfs_create_group(&(rmfs->kobj), &rmfs_groups);
	if(ret) { // 0 on success
		printk(KERN_INFO "[%s::%s] init error with code %d",MODNAME, "rm_init", ENOMEM);

	}

	printk(KERN_INFO "[%s::%s] kobject added", MODNAME, "rmfs.c");
	//const int ret = kobject_init_and_add(&rmfs->kobj, &rmfs_ktype, kernel_kobj, "%s",'kremfip');
	//if(ret)
	//	printk(KERN_INFO "[%s::%s] init error with code %d",MODNAME, "rm_init", ENOMEM);
	// initialize the reference monitor state
	return rmfs;
}

// Free the reference monitor instance
int rm_free(rmfs_t *rmfs){
	// remove the kobject if it exists
	rm_release(&rmfs->kobj);
	kfree(rmfs);
	return 0;
}