
/**
 * @file rmfs.c
 * @author Andrea Efficace (andrea.efficace1@gmail.com)
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
#include <linux/string.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include "rmfs.h"
#include "utils.h"

#define DEBUG 1

// Attribute function prototypes
static ssize_t rm_attr_show(struct kobject *kobj, struct attribute *attr, char *buf);
static ssize_t rm_attr_store(struct kobject *kobj, struct attribute *attr, const char *buf, size_t count);
static void rm_release(struct kobject *kobj);
// State function prototypes
static ssize_t state_show(rmfs_t *rmfs, rm_attr_t *attr, char *buf);
static ssize_t state_store(rmfs_t *rmfs, rm_attr_t *attr, const char *buf, size_t count);
/*
 * Define the default operations for the sysfs. These will be used by sysfs for
 * whenever a read/write operation is performed on the file under the reference monitor.
 * After the initialization, we must redirect the default operation to the specific
 * for the requested attribute.
 */

static ssize_t rm_attr_show(struct kobject *kobj, struct attribute *attr, char *buf){
	// retrieve istances of the attribute and the reference monitor
	rm_attr_t *rm_attr = to_rm_attr(attr);
	rm_kobj_t *rm_kobj = to_rm_kobj(kobj);
#ifdef DEBUG
	INFO("Show Op invoked for attribute %s", rm_attr->attr.name);
#endif
	// check if the show operation is implemented
	if (unlikely(rm_attr->show == NULL)){
		INFO("Show operation not implemented for this attribute");
		return -EIO;
	}
	// invoke the actual show operation
	return rm_attr->show(rm_kobj, rm_attr, buf);
}

static ssize_t rm_attr_store(struct kobject *kobj, struct attribute *attr, const char *buf, size_t count) {
	// retrieve instances of the attribute and the reference monitor
	rm_attr_t *rm_attr = to_rm_attr(attr);
	rm_kobj_t *rm_kobj = to_rm_kobj(kobj);
#ifdef DEBUG
	INFO("Store Op invoked for attribute %s", rm_attr->attr.name);
#endif
	// check if the store operation is implemented
	if (unlikely(rm_attr->store == NULL)){
		INFO("Store operation not implemented for this attribute");
		return -EIO;
	}
	// invoke the actual store operation
	return rm_attr->store(rm_kobj, rm_attr, buf, count);
}
 // Define the show and store operations for the state attribute
static const struct sysfs_ops rm_sysfs_ops = {
	.show = rm_attr_show,
	.store = rm_attr_store,
};
// Define a release operation for the generic kobject
static void rm_release(struct kobject *kobj){
	// retrieve the reference monitor instance
	rm_kobj_t *rm_kobj = to_rm_kobj(kobj);
#ifdef DEBUG
	INFO("Releasing kobject");
#endif
	kfree(rm_kobj);
}

// Define some dummy show and store operations for the state attribute
static ssize_t state_show(rm_kobj_t *rm_kobj, rm_attr_t *attr, char *buf) {
	// retrieve the reference monitor instance
	rmfs_t *rmfs = to_rmfs_obj(rm_kobj);

}

// Define the attrribute struct for the state file
static rm_attr_t state_attr = __ATTR(state, 0664, state_show, state_store);

// Define the attribute group
static struct attribute *rmfs_attrs[] = {
	&state_attr.attr, // add the state attribute to the group
	// add other attributes here
	NULL,	// ! terminate the list with NULL -- mandatory
};

ATTRIBUTE_GROUPS(rmfs); // define the attribute group adding ##_group to the name

static const struct kobj_type rmfs_ktype = {
	.sysfs_ops = &rm_sysfs_ops,
	.release = rm_release,
	.default_groups = rmfs_groups,
};


// create a kobject that could be added to the kset
static struct kobject *create_obj(const char *name, struct kset *set){
	// check if the set is valid
	if (set == NULL){
		INFO("Invalid kset", "");
		return NULL;
	}
	// allocate memory for the kobject
	struct kobject *obj = kzalloc(sizeof(struct kobject*), GFP_KERNEL);
	if(obj == NULL){
		INFO("Failed to allocate memory for kobject", "");
		return NULL;
	}
	// add the kobject to the kset -- we assume that the kset is already created
	obj->kset = set;
	// initialize the kobject
#ifdef DEBUG
	INFO("Adding kobject to kset", name);
#endif
	if(kobject_init_and_add(obj, &rmfs_ktype, NULL, "%s", name)) {
		INFO("Failed to initialize and add kobject", name);
		kobject_put(obj);
		return NULL;
	}
	/*
	 * We are always responsible for sending the uevent that the kobject
	 * was added to the system.
	*/
	kobject_uevent(obj, KOBJ_ADD);
	return obj;

}

// Destroy the kobject
static void destroy_obj(struct kobject *obj){
	if (obj == NULL){
		INFO("Invalid kobject%d", 5);
		return;
	}
#ifdef DEBUG
	INFO("Removing kobject from kset %s", obj->name);
#endif
	// remove the kobject from the kset
	kobject_put(obj);
}

// Define the reference monitor instance

rmfs_t* rm_init(void){
	// allocate memory for the reference monitor
	rmfs_t *rmfs = kzalloc(sizeof(rmfs_t), GFP_KERNEL);
	if (rmfs == NULL){
		INFO("Failed to allocate memory for reference monitor");
		return NULL;
	}

	return rmfs;
}

// Free the reference monitor instance




void rm_display(const rmfs_t *rmfs_ptr){
	int len = sizeof(snprintf(NULL, 0,
		"Reference Monitor %s(%d)\n State: %d\n",
		rmfs_ptr->name, rmfs_ptr->id, rmfs_ptr->state
	))+1;
	char *disp_msg = kzalloc(sizeof(char)*len, GFP_KERNEL);
	snprintf(disp_msg,
		"Reference Monitor %s(%d) State: %d\n",
		rmfs_ptr->name, rmfs_ptr->id, rmfs_ptr->state
	);
	printk(KERN_INFO "%s\n", disp_msg);

}


/****************************************************
 * Define the reference monitor functions
 ****************************************************/

int set_state(rmfs_t *rmfs, rm_state_t state) {
	// check if the state is valid
	if (!is_state_valid(state)) {
		INFO("Trying to set an invalid state - %s is given", get_state_str(state));
		goto error;
	}
#ifdef DEBUG
	RM_LOG_STR(rmfs, "Setting state to ", get_state_str(state));
	rm_display(rmfs);
#endif
	// set the state
	rmfs->state = state;

	return 0;

error:
	return -EINVAL;
}



rm_state_t get_state(rmfs_t *rmfs) {
	// openthe state file
	return rmfs->state;
}
