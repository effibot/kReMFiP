
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
	//rm->name = RM_DEFAULT_NAME;
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
	//sysfs_remove_file(rm->kobj, &hash_pwd_attr.attr);
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
	char *str = kzalloc((RM_PWD_HASH_LEN * 2 + 1) * sizeof(char), GFP_KERNEL);
	ssize_t error = hex_to_str(rm_pwd_hash, RM_PWD_HASH_LEN, str);
	if (error) {
		WARNING("Failed to convert the password hash to a string");
		kfree(str);
		return error;
	}
	ssize_t byte_written = snprintf(buf, RM_PWD_HASH_LEN * 2 + 1, "%s", str);
	kfree(str);
	return byte_written;
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
#ifdef DEBUG
		WARNING("Invalid flags for the open syscall");
#endif
		return -EINVAL;
	}
	// get the flags from the registers and check if they do not imply write permissions
	int flags = oflags->open_flag;
	const unsigned short mode = oflags->mode;
	if (!(flags & O_RDWR) && !(flags & O_WRONLY) && !(flags & (O_CREAT | __O_TMPFILE | O_EXCL))) {
		// the open syscall is not attempting to write on the file, so we can allow it
#ifdef DEBUG
		INFO("Skipping the check for the open syscall, no open flag\n");
#endif
		return 0;
	}

	// the do_filp_open is attempting to write on some file, so we have to do the probing work
	const struct filename *fname = (struct filename *)regs->si;
	if (unlikely(fname == NULL)) {
#ifdef DEBUG
		WARNING("Invalid filename for the open syscall");
#endif
		return -EINVAL;
	}

	const char *kpath = fname->name;
	const __user char *upath = fname->uptr;

	if (!kpath) {
#ifdef DEGBUG
		WARNING("Invalid or inaccessible path for the open syscall");
#endif
		return 0;
	}

	/* Avoid to check for temporary files and other special cases
	 * If the path exists, kpath is always filled with the resolved path,
	 * so we can use it to avoid probing temporary files and other special cases.
	 */
	if (!is_valid_path(kpath)) {
		// the path is not valid for our purposes, so we can allow the open syscall
#ifdef DEBUG
		INFO("skipping the check for the path %s\n", kpath);
#endif
		return 0;
	}
	// INFO("opening valid res %s\n", kpath);
	// get the file descriptor
	const int dfd = (int)regs->di;
	// Transform the path to an absolute path
	char *abs_path = NULL;
	int ret = 0, not_exists = 0;

	// The user path could be null in special cases (like temporary files), so we have to check it;
	if (upath == NULL) {
		abs_path = kstrdup(kpath, GFP_KERNEL);
	} else {
		abs_path = kzalloc(PATH_MAX, GFP_KERNEL);
		if (unlikely(abs_path == NULL)) {
			WARNING("Failed to allocate memory for the absolute path");
			return -ENOMEM;
		}
		ret = get_abs_path_user(dfd, upath, abs_path);
		if (ret <= 0) {
			kfree(abs_path);
			// fallback to kernel path
			abs_path = kstrdup(kpath, GFP_KERNEL);
			not_exists = 1;
		}
	}
	//INFO("called on %s\nprobing on %s\nexistance %d", kpath, abs_path, not_exists);

	// We can fall into 2 cases now:
	// 1. The path was found -> we check the path
	// 2. The path wasn't found because is being created -> we check the parent directory
#ifdef DEBUG
	INFO("Intercepted open syscall at %s with flags %d and fd %d\n", abs_path, flags, dfd);
#endif
	if (not_exists == 0) {
		// Case 1
		if (is_protected(abs_path)) {
#ifdef DEBUG
			INFO("Rejecting open on protected file %s", abs_path)
#endif
			kfree(abs_path);
			goto reject;
		}
	}

	if ((!(flags & O_CREAT) || mode) && not_exists) {
		// case 2
		char *parent_dir = kzalloc(PATH_MAX, GFP_KERNEL);
		if (unlikely(parent_dir == NULL)) {
			WARNING("Unable to allocate memory for the parent_dir path");
			kfree(abs_path);
			return -ENOMEM;
		}
		ret = find_dir(abs_path, parent_dir);
		INFO("parent dir: %s\n", parent_dir);
		if (ret < 0 || !is_dir(parent_dir)) {
			//"Unable to get parent directory, fallback to cwd";
			kfree(parent_dir);
			parent_dir = get_cwd();
			// check
			if (is_protected(parent_dir)) {
#ifdef DEBUG
				INFO("Rejecting open on protected directory %s", parent_dir);
#endif
				kfree(parent_dir);
				goto reject;
			}
		}
	}
	// not rejected, return
	return 0;

// 	// TODO: log the open syscall
reject:
	// now handle the open syscall
	if (not_exists == 1) {
		// We redirect the open at a NULL path, so the syscall will fail.
		regs->si = (unsigned long)NULL;
	} else {
		//the filp_open is executed but with flag 0_RDONLY. Any attempt to write will return an error.
		// Remove write-related flags and ensure only read-only flags are kept
		flags &= ~(O_WRONLY | O_RDWR | O_APPEND);
		flags |= O_RDONLY;
		oflags->open_flag = flags;
		// set the flags to read-only
		regs->dx = (unsigned long)oflags;
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
