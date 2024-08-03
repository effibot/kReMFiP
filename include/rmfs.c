
/**
 * @file rmfs.c
 * @author your name (you@domain.com)
 * @brief Implementation of the reference monitor as a filesystem
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
#include <linux/version.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/list.h>
#include <linux/kobject.h>

#include "types.h"
#include "utils.h"
//#include "rm_state.h"

#ifndef RM_NAME
#define RM_NAME "rmfs"
#endif

#ifndef RM_INIT_STATE
#define RM_INIT_STATE (state_t)0
#endif




static ssize_t state_show(struct kobject *kobj,
                          struct kobj_attribute *attr, char *buf);
static ssize_t state_store(struct kobject *kobj, struct kobj_attribute *attr,
                           const char *buf, size_t count);

#define to_rmfs_t(kobj) container_of(kobj, rmfs_t, kobj)
#define get_rm_state(rmfs) rmfs->state
#define set_rm_state(rmfs, new_state) rmfs->state = new_state

// define sysfs attributes
static ssize_t state_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf){
	return sprintf(buf, "%d\n", get_rm_state(to_rmfs_t(kobj)));
}

static ssize_t state_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count){
	int new_state;
	// should check if the new state is valid and if ops invoked as root
	if (sscanf(buf, "%d", &new_state) != 2){
		return -EINVAL;
	}

	set_rm_state(to_rmfs_t(kobj), new_state);
	return count;
}

// create the sysfs attributes
static struct kobj_attribute state_attribute;

static void my_file_release(struct kobject *kobj)
{
	// Invoked when kobject_put is called to destroy this kobject
	printk("Anything to do!\n");
}

ATTRIBUTE_GROUPS(my_file);

static const struct kobj_type my_ktype = {
	.sysfs_ops = &(struct sysfs_ops){
		.show = state_show,
		.store = state_store,
	},
	.release = my_file_release,
	.default_groups = my_file_groups,
};

// Define the reference monitor instance
static rmfs_t *rm_init(void){
	rmfs_t *rmfs = kzalloc(sizeof(rmfs_t), GFP_KERNEL);
	if (!rmfs){
		return NULL;
	}
	rmfs->name = RM_NAME;
	rmfs->hooked_functions = "vfs_open";
	rmfs->allowed_modes = al_mode_t;
	rmfs->blocked_modes = NULL;
	rmfs->kobj = (struct kobject){};
	rmfs->state = RM_INIT_STATE;
	state_t state = RM_INIT_STATE;
	state_attribute = __ATTR(state, 0664, state_show, state_store);
	ret = kobject_init_and_add(&rmfs->kobj, &my_ktype, NULL, "%s", rmfs->name);

	int ret = sysfs_create_file(&rmfs->kobj, &state_attribute.attr);
	if(ret){
		kobject_put(&rmfs->kobj);
		kfree(rmfs);
		return NULL;
	}

	return rmfs;
}

// Free the reference monitor instance
static int rm_free(rmfs_t *rm){
	kobject_put(&rm->kobj);
	kfree(rm);
	return 0;
}