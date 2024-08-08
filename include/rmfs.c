
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


// functions prototypes
static ssize_t state_show(struct kobject *kobj,
                          struct kobj_attribute *attr, char *buf);
static ssize_t state_store(struct kobject *kobj, struct kobj_attribute *attr,
                           const char *buf, size_t count);

// Macro to get a pointer to the reference monitor structure from the kobject
#define to_rmfs_t(obj) container_of(obj, rmfs_t, kobj)


// define sysfs operations
static ssize_t state_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf){
	rmfs_t *rmfs_ptr = to_rmfs_t(kobj);
	rm_display(rmfs_ptr);
	RM_LOG_MSG(rmfs_ptr, "read op invoked");
	printk(KERN_INFO "state is %d\n", rmfs_ptr->state);
	int count = sysfs_emit(buf, "%d\n", rmfs_ptr->state);
	RM_LOG_MSG(rmfs_ptr, "read op success");
	return count;
}

static ssize_t state_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count){
	rmfs_t *rmfs_ptr = to_rmfs_t(kobj);
	printk(KERN_INFO "%p\n", rmfs_ptr);
	rm_display(rmfs_ptr);
	RM_LOG_MSG(rmfs_ptr, "store op invoked");
	//LOG_MSG("Attempting to write state", buf);
	int new_state;
	// should check if the new state is valid and if ops invoked as root
	// change datastructure state
	if (kstrtoint(buf, 10, &new_state)){
		LOG_MSG("write error", "kstrtoint failed");
		return -EINVAL;
	}
	rmfs_ptr->state = new_state;
	RM_LOG_MSG(rmfs_ptr, "store op success");
	return count;
}

static void rm_release(struct kobject *kobj){
	rmfs_t *rmfs_ptr = to_rmfs_t(kobj);
	kobject_put(&rmfs_ptr->kobj);
}


int set_state(rmfs_t *rm, rm_state_t state) {
	// check if the state is valid
	if (!is_state_valid(state)) {
		LOG_MSG("Trying to set an invalid state", "state");
		return -EINVAL;
	}
	int len = sizeof(snprintf(NULL, 0,"Setting state to %s", get_state_str(state)))+1;
	char* msg = kzalloc(sizeof(char)*len, GFP_KERNEL);
	sprintf(msg, "Setting state to %s", get_state_str(state));
	rm_display(rm);
	RM_LOG_MSG(rm, get_state_str(state));
	// set the state
	rm->state = state;
	// perform write to the state file
	struct file *state_file = filp_open(RMFS_STATE_FILE, O_WRONLY|O_TRUNC, 0);
	file_open_check(state_file, RMFS_STATE_FILE);
	static char state_buf[2];
	if(snprintf(state_buf, 2, "%d", rm->state) < 0) {
		printk(KERN_ERR "Failed to convert the state to a string\n");
		return -EINVAL;
	}
	// write the state to the file
	kernel_write(state_file, state_buf, 2, &state_file->f_pos);
	filp_close(state_file, NULL);
	return 0;
}



rm_state_t get_state(void) {
	// open the state file
	struct file *state_file = filp_open(RMFS_STATE_FILE, O_RDONLY, 0);
	file_open_check(state_file, RMFS_STATE_FILE);
	// read the state from the file
	static char state_buf[2];
	kernel_read(state_file, state_buf, 2, &state_file->f_pos);
	filp_close(state_file, NULL);
	// convert the state to an integer
	int state_int;
	if (kstrtoint(state_buf, 10, &state_int)) {
		printk(KERN_ERR "Failed to convert the state to an integer\n");
		return -EINVAL;
	}
	return state_int;
}

// Define the attrribute struct for the state file

static struct kobj_attribute state_attr = __ATTR(state, 0664, state_show, state_store);

static struct attribute *rmfs_attrs[] = {
	&state_attr.attr,
	NULL,
};

static struct attribute_group rmfs_groups = {
	.attrs = rmfs_attrs,
};


// Define the reference monitor instance

rmfs_t* rm_init(void){
	//rmfs_t *rmfs_ptr = *rmfs_addr;
	// check if rmfs is a valid pointer
	rmfs_t *rmfs_ptr = kzalloc(sizeof(rmfs_ptr), GFP_KERNEL_ACCOUNT);
	mem_check(rmfs_ptr);
	// initialize the reference monitor
	rmfs_ptr->name = RMFS_DEFAULT_NAME;
	rmfs_ptr->state = RMFS_INIT_STATE;
	rmfs_ptr->blocked_modes = NULL;
	rmfs_ptr->allowed_modes = NULL;
	rmfs_ptr->hooked_functions = NULL;
	rmfs_ptr->id = rnd_id();
	// create kobject inside /sys
	rmfs_ptr->kobj = *kobject_create_and_add(rmfs_ptr->name, NULL);
	// initialize the kobject with the attribute group
	mem_check(&rmfs_ptr->kobj);
	// if the kernel object is created, create the sysfs group
	if (sysfs_create_group(&rmfs_ptr->kobj, &rmfs_groups)) goto free;
	// initialize the /sys/kremfip/state file
	set_state(rmfs_ptr, RMFS_INIT_STATE);
	RM_LOG_MSG(rmfs_ptr, "init success");
	return rmfs_ptr;

free:
	rm_free(rmfs_ptr);
	return NULL;
}

// Free the reference monitor instance


int rm_free(rmfs_t *rmfs){
	// remove the kobject if it exists
	if (unlikely(&(rmfs->kobj) != NULL)){
		RM_LOG_MSG(rmfs, "Releasing kobject");
		rm_release(&rmfs->kobj);
	}
	LOG_MSG("invoking kfree", "rmfs");
	if (unlikely(rmfs != NULL))	kfree(rmfs);
	return 0;
}


void rm_display(rmfs_t *rmfs_ptr){
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