/**
 * @file paths.c
 * @author your name (you@domain.com)
 * @brief Implementation of the protected paths as kernel objects inside the sysfs
 * @version 0.1
 * @date 2024-08-03
 *
 * @copyright Copyright (c) 2024
 *
 */



#include "types.h"
#include "utils.h"

// Define basic sysfs_ops for our use-case
static ssize_t path_show(struct kobject *kobj, struct attribute *attr, char *buf){
	// We want to allow the user to read the path
	// If what we reead is a file, we want to read the file
	// If what we read is a directory, we want to read the directory

	// Get the path_t structure from the kobject
	path_t *path = to_path_t(kobj);
	printk(KERN_INFO "Reading path: %s\n", path->dentry->d_name.name);
	if (S_ISDIR(path->inode->i_mode)){
		printk(KERN_INFO "Reading a directory\n");
	} else if (S_ISREG(path->inode->i_mode)){
		printk(KERN_INFO "Reading a file\n");
	}
	ssize_t ret = sysfs_emit(buf, "%s\n", path->dentry->d_name.name);
	return 0;


}

static ssize_t path_store(struct kobject *kobj, struct attribute *attr, const char *buf, size_t count){
	// Just for the sake of the example, we will not allow the user to write to the path
	printk(KERN_INFO "Writing to the path is not allowed\n");
	return 0;
}

static void path_release(struct kobject *kobj){
	// Get the path_t structure from the kobject
	path_t *path = to_path_t(kobj);
	printk(KERN_INFO "Releasing path: %s\n", path->dentry->d_name.name);

	// Free the path_t structure
	kfree(path);
}

// Define the sysfs operations for the protected paths
static path_ops_t path_ops = {
	.ops = {
		.show = path_show,
		.store = path_store,
	},
};

// Define the attributes for the protected paths
static path_attr_t path_attr = {
	.attr = {
		.name = "path",
		.mode = 0666,
	},
	.ops = &path_ops,
};

// Define the kobj_type for the protected paths
