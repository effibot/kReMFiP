
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


/*
 * Define the default operations for the sysfs. These will be used by sysfs for
 * whenever a read/write operation is performed on the file under the reference monitor.
 * After the initialization, we must redirect the default operation to the specific
 * for the requested attribute.
 */

static ssize_t rm_attr_show(struct kobject *kobj, struct attribute *attr, char *buf){
	// retrieve istances of the attribute and the reference monitor
	rm_attr_t *rm_attr = to_rm_attr(attr);
	rmfs_t *rmfs = to_rfmfs_obj(kobj);
#ifdef DEBUG
	RM_LOG_STR(rmfs, "Show Op invoked for attr ", rm_attr->attr.name);
#endif
	// check if the show operation is implemented
	if (!rm_attr->show){
		LOG_MSG("Show operation not implemented for attribute", rm_attr->attr.name);
		return -EIO;
	}
	// invoke the actual show operation
	return rm_attr->show(rmfs, rm_attr, buf);
}

static ssize_t rm_attr_store(struct kobject *kobj, struct attribute *attr, const char *buf, size_t count) {
	// retrieve instances of the attribute and the reference monitor
	rm_attr_t *rm_attr = to_rm_attr(attr);
	rmfs_t *rmfs = to_rfmfs_obj(kobj);
#ifdef DEBUG
	RM_LOG_STR(rmfs, "Store Op invoked for attr ", rm_attr->attr.name);
#endif
	// check if the store operation is implemented
	if (!rm_attr->store){
		LOG_MSG("Store operation not implemented for attribute", rm_attr->attr.name);
		return -EIO;
	}
	// invoke the actual store operation
	return rm_attr->store(rmfs, rm_attr, buf, count);
}

static void rm_release(struct kobject *kobj){
	// retrieve the reference monitor instance
	rmfs_t *rmfs = to_rfmfs_obj(kobj);
#ifdef DEBUG
	RM_LOG_STR(rmfs, "Releasing kobject");
#endif
	kfree(rmfs);
}

static const struct sysfs_ops rm_sysfs_ops = {
	.show = rm_attr_show,
	.store = rm_attr_store,
};


// define state operations
static ssize_t state_show(rmfs_t *rmfs, rm_attr_t *attr, char *buf){
#ifdef DEBUG
	RM_LOG_STR(rmfs, "reading state file");
	rm_display(rmfs);
#endif
	// read the state from the reference monitor
	return sysfs_emit(buf, "%d\n", rmfs->state);
}

static ssize_t state_store(rmfs_t *rmfs, rm_attr_t *attr, const char *buf, size_t count){

	// check if the given state is valid
	if (!is_state_valid(get_state_from_str(buf))){
		LOG_MSG("write error", "invalid state");
		return -EINVAL;
	}
	//
	int new_state;
	if (kstrtoint(buf, 10, &new_state) < 0){
		LOG_MSG("write error", "kstrtoint failed");
		return -EINVAL;
	}
	// set the new state
	rmfs->state = new_state;
#ifdef DEBUG
	RM_LOG_STR(rmfs, "changed state to ", get_state_str(rmfs->state));
	rm_display(rmfs);
#endif
	return count;
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


// create the state file
static struct kobject *create_obj(const char *name, struct kset *set){ {
	// check if the set is valid
	if (set == NULL){
		LOG_MSG("Invalid kset", "");
		return NULL;
	}
	// allocate memory for the kobject
	struct kobject *obj = kzalloc(sizeof(struct kobject*), GFP_KERNEL);
	if(obj == NULL){
		LOG_MSG("Failed to allocate memory for kobject", "");
		return NULL;
	}
	// add the kobject to the kset -- we assume that the kset is already created
	obj->kset = set;
	// initialize the kobject
#ifdef DEBUG
	LOG_MSG("Adding kobject to kset", name);
#endif
	if(kobject_init_and_add(&obj, &rmfs_ktype, NULL, "%s", name)) {
		LOG_MSG("Failed to initialize and add kobject", name);
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


// Define the reference monitor instance

rmfs_t* rm_init(void){
	// allocate memory for the reference monitor
	rmfs_t *rm_ptr = kzalloc(sizeof(rmfs_t), GFP_KERNEL);


	// initialize the reference monitor
	rmfs_ptr_p->name = RMFS_DEFAULT_NAME;
	rmfs_ptr_p->state = RMFS_INIT_STATE;
	rmfs_ptr_p->blocked_modes = NULL;
	rmfs_ptr_p->allowed_modes = NULL;
	rmfs_ptr_p->hooked_functions = NULL;
	rmfs_ptr_p->id = rnd_id();
	// create kobject inside /sys/

	// initialize the /sys/kremfip/state file


}

// Free the reference monitor instance




void rm_display(const rmfs_t *rmfs_ptr){
	int len = sizeof(snprintf(NULL, 0,
		"Reference Monitor %s(%d)\n State: %d\n",
		rmfs_ptr->name, rmfs_ptr->id, rmfs_ptr->state
	))+1;
	char *disp_msg = kzalloc(sizeof(char)*len, GFP_KERNEL);
	sprintf(disp_msg,
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
		LOG_MSG("Trying to set an invalid state", get_state_str(state));
		return -EINVAL;
	}
#ifdef DEBUG
	RM_LOG_STR(rmfs, "Setting state to ", get_state_str(state));
	rm_display(rmfs);
#endif
	// set the state
	//rmfs->state = state;
	// perform write to the state file
	struct file *state_file = filp_open(RMFS_STATE_FILE, O_WRONLY|O_TRUNC, 0);
	file_open_check(state_file, RMFS_STATE_FILE);
	static char state_buf[2];
	if(snprintf(state_buf, 2, "%d",state) < 0) {
		printk(KERN_ERR "Failed to convert the state to a string\n");
		goto error;
	}
	// write the state to the file
	if(kernel_write(state_file, state_buf, 2, &state_file->f_pos) < 0) {
		printk(KERN_ERR "Failed to write the state to the file\n");
		goto error;
	}
	filp_close(state_file, NULL);
	return 0;
	error:
		filp_close(state_file, NULL);
	return -EINVAL;
}



rm_state_t get_state(void) {
#ifdef DEBUG
	LOG_MSG("Reading from state file", RMFS_STATE_FILE);
#endif
	// open the state file
	struct file *state_file = filp_open(RMFS_STATE_FILE, O_RDONLY, 0);
	file_open_check(state_file, RMFS_STATE_FILE);
	// read the state from the file
	static char state_buf[2];
	if(kernel_read(state_file, state_buf, 2, &state_file->f_pos) < 0) {
		printk(KERN_ERR "Failed to read the state from the file\n");
		goto error;
	}
	filp_close(state_file, NULL);
	// convert the state from string to int
	int state_int;
	if (kstrtoint(state_buf, 10, &state_int)) {
		printk(KERN_ERR "Failed to convert the state to an integer\n");
		return -EINVAL;
	}
	return state_int;
	error:
		filp_close(state_file, NULL);
	return -EINVAL;
}
