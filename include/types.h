#ifndef TYPES_H
#define TYPES_H


#include <linux/types.h> // for mode_t
#include <linux/fs.h> // for struct file
#include <linux/fcntl.h> // for O_RDONLY
#include <linux/list.h> // for list_head - we want list_for_each macro
#include <linux/kobject.h> // for struct kobject
#include "rm_state.h" // for state_t
// Your existing code
// We need to define the function to bee hooked by the reference monitor

// TODO: check which kernel version you are using and change the function name accordingly
// using #include <linux/version.h> and #if LINUX_VERSION_CODE >= KERNEL_VERSION(?, 0, 0)
#define HOOKS {"vfs_open"}
/*
 * Since we want to block every mode but the read-only one,
 * we just define an allowed list of modes that are allowed.
 */

static const int* al_mode_t = O_RDONLY;

// The actual list of blocked modes could be something like this:
/* static const mode_t* bl_mode_t = {
        O_WRONLY, // Write-only
        O_RDWR, // Read-write
        O_CREAT, // Create
        O_APPEND, // Append
        O_TRUNC, // Truncate
        O_EXCL, // Exclusive
        O_SYNC, // Synchronous
        O_DSYNC, // Data-synchronous
        O_RSYNC, // Read-synchronous
        O_NONBLOCK, // Non-blocking
        O_CLOEXEC, // Close-on-exec
        O_DIRECT, // Direct
        O_DIRECTORY, // Directory
        O_NOFOLLOW, // No-follow
        O_NOATIME, // No-atime
        O_PATH, // Path
        O_TMPFILE, // Temporary file
        O_ASYNC, // Asynchronous
        O_LARGEFILE, // Large file
        O_NOCTTY, // No-controlling-terminal
   } */



/*
 * Just for reference: kobject structure
 * struct kobject {
 *	const char		*name;
 * 	struct list_head	entry;
 * 	struct kobject		*parent;
 * 	struct kset		*kset;
 * 	const struct kobj_type	*ktype;
 * 	struct kernfs_node	*sd; // sysfs directory entry
 * 	struct kref		kref;
 *
 * 	unsigned int state_initialized:1;
 * 	unsigned int state_in_sysfs:1;
 * 	unsigned int state_add_uevent_sent:1;
 * 	unsigned int state_remove_uevent_sent:1;
 * 	unsigned int uevent_suppress:1;
 *
 * #ifdef CONFIG_DEBUG_KOBJECT_RELEASE
 * 	struct delayed_work	release;
 * #endif
 * };
 */

// Define a structure to represent the protected paths
typedef struct _path_t {
	struct kobject *kobj;
	//TODO: add attributes to implement RCU-like behavior
	struct inode *inode;
	struct dentry *dentry;

} path_t;

// Define a kobj_type for our use-case
typedef struct _path_kobj_type_t {
	struct kobj_type ktype;
} path_type_t;

// Define the related sysfs operations
typedef struct _path_ops_t {
	struct sysfs_ops ops;
} path_ops_t;

// Define attributes for the protected paths
typedef struct _path_attr_t {
	struct attribute attr;
	struct path_ops_t *ops;
} path_attr_t;

// Define a list of protected paths
typedef struct _path_lst_t {
	struct kset *kset;
} path_lst_t;





#endif
