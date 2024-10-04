
/**
 * @file rm.c
 * @author Andrea Efficace (andrea.efficace1@gmail.com)
 * @brief Implementation of the reference monitor as a folder under /sys/kernel
 * We provide show/store operations and initialization functions for the reference monitor structure
 * @version 0.1
 * @date 2024-08-03
 *
 * @copyright Copyright (c) 2024
 *
 */

#include "rm.h"
#include "../utils/misc.h"
#include "../utils/pathmgm.h"
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/memory.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sysfs.h>

/*********************************
 * Internal functions prototypes *
 *********************************/

// dedicated sysfs file for the password hash
static ssize_t pwd_hash_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);

/*************************************************
 * Preliminary setup for the password management *
 *************************************************/
static char *module_pwd = NULL; // default value
u8 pwd_salt[RM_PWD_SALT_LEN];
static u8 rm_pwd_hash[RM_PWD_HASH_LEN];
module_param(module_pwd, charp, 0000);
MODULE_PARM_DESC(module_pwd, "The password for the reference monitor");

static struct kobj_attribute hash_pwd_attr = __ATTR_RO(pwd_hash);
static struct attribute *attrs[] = {
	&hash_pwd_attr.attr,
	NULL,
};
static struct attribute_group attr_group = {
	.attrs = attrs,
};

//********************************************************************************
/**
 * @brief Initialize the reference monitor
 *
 * This function initializes the reference monitor structure.
 * It allocates memory for the reference monitor, sets the default values,
 * and initializes the hash table.
 *
 * @return rm_t* A pointer to the reference monitor structure
 */

rm_t *rm;
rm_t *rm_init(void) {
	// Allocate memory for the reference monitor
	rm = kzalloc(sizeof(rm_t), GFP_KERNEL);
	if (unlikely(rm == NULL)) {
		WARNING("Failed to allocate memory for the reference monitor");
		return NULL;
	}
	// Set the default values
	rm->name = RM_DEFAULT_NAME;
	rm->state = RM_INIT_STATE;
	rm->id = rnd_id();
	// Initialize the hash table and be sure that all goes well
	rm->ht = ht_create(HT_SIZE);
	if (unlikely(rm->ht == NULL)) {
		WARNING("Failed to initialize the hash table");
		kfree(rm);
		return NULL;
	}

	// initialize the salt
	get_random_bytes(pwd_salt, RM_PWD_SALT_LEN);
	// hash the password with the salt
	if (hash_pwd(module_pwd, pwd_salt, rm_pwd_hash) != 0) {
		WARNING("Failed to hash the password");
		kfree(rm);
		return NULL;
	}
	// store the password hash in the dedicated sysfs file
	// we crate a subfolder under /sys/module/kremfip
	rm->kobj = kobject_create_and_add(RM_PWD_HASH_ATTR_NAME, &THIS_MODULE->mkobj.kobj);
	if (rm->kobj == NULL) {
		WARNING("Failed to create the sysfs file for the password hash");
		kfree(rm);
		return NULL;
	}
	// create the file creating the group
	if (sysfs_create_group(rm->kobj, &attr_group)) {
		WARNING("Failed to create the sysfs group for the password hash");
		kobject_put(rm->kobj);
		kfree(rm);
		return NULL;
	}
	// check if the password hash is stored correctly
	if (!verify_pwd(module_pwd)) {
		WARNING("Failed to verify the password hash");
		kfree(rm);
		return NULL;
	}
	memzero_explicit(module_pwd, strlen(module_pwd));
	kfree(module_pwd);
#ifdef DEBUG
	INFO("Password hash stored successfully\n");
#endif
	// Initialize the spinlock
	spin_lock_init(&rm->lock);
#ifdef DEBUG
	INFO("Reference Monitor Initialized successfully\n");
#endif
	return rm;
}
/**
 * @brief Set the state of the reference monitor to a VALID state.
 * Since this is the setter function, we avoid to make checks here,
 * as they should be done in the caller function.
 * @param rm The reference monitor structure
 * @param state The new state of the reference monitor
 * @return int 0 if the state is set successfully, an error code otherwise
 */
int set_state(rm_t *rm, const state_t state) {
	// safety checks
	if (unlikely(rm == NULL)) {
		WARNING("Reference monitor is NULL");
		return -EINVAL;
	}
	// set the state
#ifdef DEBUG
	INFO("Setting the state to %s\n", state_to_str(state));
#endif
	rm->state = state;
	// TODO: Add or remove the hooks based on the state
	return 0;
}
/**
* @brief Get the state of the reference monitor
* Since this is the getter function, we avoid to make checks here,
* as they should be done in the caller function.
* @param rm The reference monitor structure
* @return state_t The state of the reference monitor
*/
state_t get_state(const rm_t *rm) {
	// assert that the reference monitor is not NULL
	if (rm == NULL) {
		WARNING("Reference monitor is NULL");
		return -EINVAL;
	}
	// return the state
	return rm->state;
}

/**
* @brief Release the reference monitor allocated memory
* This function releases the memory allocated for the reference monitor
* removing the associated sysfs file and freeing the hash table.
* @param rm The reference monitor structure
*/
void rm_free(const rm_t *rm) {
	// assert that the reference monitor is not NULL
	if (rm == NULL) {
		WARNING("Reference monitor is NULL");
		return;
	}
	// free the hash table
	ht_destroy(rm->ht);
	// remove the sysfs file
	sysfs_remove_file(rm->kobj, &hash_pwd_attr.attr);
	kobject_put(rm->kobj);
	// free the reference monitor
	kfree(rm);
}

/**
 * @brief Check if the path is protected
 * This function checks if the path is present in the hash table.
 * @param path The path to check
 * @return int 0 if the path is not present in the hash table, 1 otherwise
 */

bool is_protected(const char *path) {
	// safety checks
	if (unlikely(path == NULL)) {
		WARNING("Path is NULL");
		goto f;
	}
	// be sure that our ht exists
	if (unlikely(rm->ht == NULL)) {
		WARNING("Hash table is NULL");
		goto f;
	}
	// Our lookup is key-based, so we need to hash the path
	const uint64_t key = compute_hash(path);
	// make a lookup in the hash table
	const node_t *found = ht_lookup(rm->ht, key);
	if (found) {
		return true;
	}
f:
	return false;
}

/*************************************
 * Internal function implementations *
 *************************************/

/**
 * @brief Show the password hash
 * This function shows the password hash in the sysfs file.
 * @param kobj The kobject
 * @param attr The kobject attribute
 * @param buf The buffer to store the password hash
 * @return ssize_t The number of bytes written
 */
static inline ssize_t pwd_hash_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
	// just copy the password hash to the buffer as a null-terminated string
	return snprintf(buf, RM_PWD_HASH_LEN * 2 + 1, "%s", hex_to_str(rm_pwd_hash, RM_PWD_HASH_LEN));
}

int rm_open_pre_handler(struct kprobe *ri, struct pt_regs *regs) {
	/* To check if the syscall can do its job we need to check 2 things:
	 * 1. If the flags imply open a path with some write permissions.
	 * According to the current ABI, we have:
	 * -- rdi->arg0: int dfd
	 * -- rsi->arg1: struct filename *pathname
	 * -- rdx->arg2: struct open_flags *flags
	 * 2. If the path is present inside the hash table
	 */

	// To reduce the overhead, we can check if the flags imply write permissions first
	struct open_flags *oflags = (struct open_flags *)regs->dx;
	if (unlikely(oflags == NULL)) {
		WARNING("Invalid flags for the open syscall");
		return -EINVAL;
	}
	// get the flags from the registers and check if they do not imply write permissions
	const int flags = oflags->open_flag;
	if (!(flags & O_RDWR) && !(flags & O_WRONLY) && !(flags & (O_CREAT | __O_TMPFILE | O_EXCL)))
		return 0;

	// the do_filp_open is attempting to write on the file, check the hash table
	const struct filename *fname = (struct filename *)regs->si;
	if (unlikely(fname == NULL)) {
		WARNING("Invalid filename for the open syscall");
		return -EINVAL;
	}
	//const __user char *upath = fname->uptr;
	const char *path = fname->name;
	if (unlikely(path == NULL)) {
		WARNING("Invalid path for the open syscall");
		return -EINVAL;
	}

	// The path could be a relative path. We decided to work only with absolute paths, so we need to obtain it.
	char *abs_path = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(abs_path == NULL)) {
		WARNING("Failed to allocate memory for the absolute path");
		return -ENOMEM;
	}
	int ret = get_abs_path(path, abs_path);
	int not_exists = 0;
	// if we can't resolve the path, abs_path is filled with the error keyword
	if(strcmp(abs_path, PATH_NOT_FOUND) == 0) {
		WARNING("Path not found\n");
		// we flip the flag because we still should check if the file is being created
		kfree(abs_path); // maybe just memset to 0?
		// if the file is being created, the error is legit and we have to flip the flag
		if (flags & (O_CREAT | __O_TMPFILE | O_EXCL)) {
			not_exists = 1;
		}
	}
	// if the path is not found and is not being created, exit
	if (ret <= 0 && not_exists == 0) {
		WARNING("Failed to get the absolute path");
		return ret;
	}
	// We can fall into 2 cases now:
	// 1. The path is found
	// 2. The path is not found and is being created
	char* path_to_check = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(path_to_check == NULL)) {
		WARNING("Failed to allocate memory for the path to check");
		kfree(abs_path);
		return -ENOMEM;
	}
	if (not_exists == 0) {
		// Case 1
		// get the file descriptor
		int dfd = (int)regs->di;
#ifdef DEBUG
		INFO("Intercepted open syscall at %s with flags %d and fd %d\n", path, flags, dfd);
#endif
		path_to_check = kstrdup(abs_path, GFP_KERNEL);
	} else {
		// Case 2
		/* We have to create the file, but to do so we need to check if the directory is protected.
		 * We need to do two things:
		 * 1. Check if we have to create the file in the current directory.
		 *		If so, we have to check if the directory is protected.
		 * 2. Check if we have to create the file in a external directory. Since the open syscall
		 *		could be used to make a recursive creation like in mkdir -p, we need to check if
		 *		the least common ancestor is protected. We can do this by checking the path up to
		 *		the last slash, iteratively, until we reach an existing directory.
		 *		If the existing directory is protected, we have to reject the call.
		 */
		// TODO Check if we have to create the file in the current directory
		// TODO: check if the current directory is protected
	case2loop:
		// get the pointer to the last slash
		char* last_slash = strrchr(path, '/');
		if (unlikely(last_slash == NULL)) {
			WARNING("Failed to get the last slash in the path");
			kfree(path_to_check);
			return -EINVAL;
		}
		// get the length of the path up to the last slash
		const size_t len = last_slash - path;
		// copy the path up to the last slash
		strncpy(path_to_check, path, len);
		// check if the path exists
		if (unlikely(!path_exists(path_to_check))) {
			WARNING("The path %s does not exist, checking the ancestor\n", path_to_check);
			goto case2loop;
		}
	}

	// // find the process working directory
	// char* dir_path = kzalloc(PATH_MAX, GFP_KERNEL);
	// if (unlikely(dir_path == NULL)) {
	// 	WARNING("Failed to get the directory path");
	// 	kfree(abs_path);
	// 	return -ENOMEM;
	// }
	// get_dir_path(path, dir_path);

	// Check if the path is protected
	const bool must_protect = is_protected(path_to_check);
	int reject_call = 0;
	if (must_protect) {
		INFO("Attempt to open a protected resource at %s\n", path_to_check);
		reject_call = 1;
		goto log_open;
	}
	// The path is not protected, so we can allow the open syscall
	return 0;
log_open:
	// TODO: log the open syscall

	// now handle the open syscall
	if (reject_call) {
		// We redirect the open at a NULL path, so the syscall will fail.
		regs->si = (unsigned long) NULL;
	} else {
		//the filp_open is executed but with flag 0_RDONLY. Any attempt to write will return an error.
		oflags->open_flag = ((flags ^ O_WRONLY) ^ O_RDWR) | O_RDONLY;
		// set the flags to read-only
		regs->dx = (unsigned long) oflags;		
	}
	return 0;
}
int rm_mkdir_pre_handler(struct kprobe *ri, struct pt_regs *regs) {
	return 0;
}
int rm_rmdir_pre_handler(struct kprobe *ri, struct pt_regs *regs) {
	return 0;
}
int rm_unlink_pre_handler(struct kprobe *ri, struct pt_regs *regs) {
	return 0;
}
