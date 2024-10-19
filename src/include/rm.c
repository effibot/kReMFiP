
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
#include <linux/namei.h>
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
	if (unlikely(path == NULL) || unlikely(strlen(path) == 0)) {
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

#define PATH_LEN 1024

static inline void __send_sig_to_current(int sig) {
	struct task_struct *task = current;
	if (task)
		send_sig(sig, task, 0);
}

int rm_open_pre_handler(struct kprobe *ri, struct pt_regs *regs) {
	/* To check if the system calls can do its job we need to check 2 things:
	 * 1. If the flags imply open a path with some write permissions.
	 * According to the current ABI, we have:
	 * -- rdi->arg0: int dfd
	 * -- rsi->arg1: struct filename *pathname
	 * -- rdx->arg2: struct open_flags *flags
	 * 2. If the path is present inside the hash table
	 *
	 * returns are 0 if error occurs to don't interfere with the syscall, and they are non-zero
	 * if memory problem occurs.
	 * Remember that at least the parent directory of the opened resource must exist or the
	 * kernel fails even if the O_CREAT flag is set.
	 */
	// Extract the function arguments from the registers based on the x86_64 ABI
	const struct filename *name =
		(struct filename *)regs->si; // 2nd argument: filename (struct filename pointer)
	struct open_flags *open_flags =
		(struct open_flags *)regs->dx; // 3rd argument: open_flags (struct open_flags pointer)

	int flags = open_flags->open_flag; // Open flags
	// Only proceed if the file is opened for writing or creating
	if (!(flags & O_RDWR) && !(flags & O_WRONLY) && !(flags & (O_CREAT | __O_TMPFILE | O_EXCL)))
		return 0;

	// Get the file path from the filename struct
	const char *pathname = name->name;
	// If pathname is NULL, there's nothing to check, skip
	if (!pathname) {
		return 0;
	}

	// Check if the path is valid and should be monitored
	if (!is_valid_path(pathname)) {
		return 0; // Skip if the path is not valid
	}

#ifdef DEBUG
	int dfd = (int)regs->di; // 1st argument: directory file descriptor
	INFO("Probing do_filp_open with dfd %d and (flags, mode)=(%d, %d) for path %s\n", dfd,
		 open_flags->open_flag, open_flags->mode, pathname);
#endif
	// Get the absolute path of the file its parent directory
	char *path_buf = kzalloc(PATH_LEN * sizeof(char), GFP_KERNEL);
	if (!path_buf) {
		WARNING("Failed to allocate memory for the path buffer\n");
		return 0;
	}

	// resolve the path to its absolute form
	const int err_abs = get_abs_path(pathname, path_buf);
	if (err_abs != 0 && err_abs != -ENOENT) {
		// Something went wrong, log the error and return
		WARNING("Failed to get the absolute path of %s with code %d\n", pathname, err_abs);
		if (path_buf)
			kfree(path_buf);
		return 0;
	}
	// now we find the parent directory for the special case of opening a file which path
	// if it is one hop from our current working directory

	char *parent_buf = kzalloc(PATH_LEN * sizeof(char), GFP_KERNEL);
	if (!parent_buf) {
		WARNING("Failed to allocate memory for the parent buffer\n");
		kfree(path_buf);
		return 0;
	}

	const int err_parent = get_dir_path(path_buf, parent_buf);
	// Check if something went wrong when calculating the parent directory
	// or if the parent directory does not exist
	if (err_parent != 0 || !is_dir(parent_buf)) {
		WARNING("Failed to get the parent directory of %s with code %d\n", pathname, err_parent);
		if (parent_buf)
			kfree(parent_buf);
		if (path_buf)
			kfree(path_buf);
		return 0;
	}

#ifdef DEBUG
	INFO("\nFound Parent %s\nfor Resource %s", parent_buf, path_buf);
#endif
	// Check for parent protection
	if (is_protected(parent_buf)) {
		WARNING("Attempt to open a protected directory: %s\n", parent_buf);
		// Modify return value to indicate an error (EPERM: Operation not permitted)
		regs->ax = -EPERM;

		// Optionally, send a signal to the process (e.g., SIGKILL or SIGTERM)
		__send_sig_to_current(SIGKILL);

		kfree(parent_buf);
		kfree(path_buf);
		return 0;  // Stop further execution of the system call
	}
	if (strlen(path_buf) > 0 && is_protected(path_buf)) {
		WARNING("Attempt to open a protected file: %s\n", path_buf);
		// reject system call to reject file
		regs->ax = -EPERM;
		__send_sig_to_current(SIGKILL);

		kfree(parent_buf);
		kfree(path_buf);
		return 0;
	}

	goto out;
reject:
	//TODO register deferred work
out:
	if (path_buf)
		kfree(path_buf);
	if (parent_buf)
		kfree(parent_buf);
	return 0;
}

int rm_mkdir_pre_handler(struct kprobe *ri, struct pt_regs *regs) {
	// Extract the function arguments from the registers based on the x86_64 ABI
	const struct filename *name =
		(struct filename *)regs->si; // 2nd argument: filename (struct filename pointer)

	// Get the file path from the filename struct
	const char *pathname = name->name;
	// If pathname is NULL, there's nothing to check, skip
	if (!pathname) {
		return 0;
	}

	// Check if the path is valid and should be monitored
	if (!is_valid_path(pathname)) {
		return 0; // Skip if the path is not valid
	}

#ifdef DEBUG
	int dfd = (int)regs->di; // 1st argument: directory file descriptor
	INFO("Probing mkdir with dfd %d for path %s\n", dfd, pathname);
#endif
	// Get the absolute path of the file its parent directory
	char *path_buf = kzalloc(PATH_LEN * sizeof(char), GFP_KERNEL);
	if (!path_buf) {
		WARNING("Failed to allocate memory for the path buffer\n");
		return 0;
	}

	// resolve the path to its absolute form
	const int err_abs = get_abs_path(pathname, path_buf);
	if (err_abs != 0 && err_abs != -ENOENT) {
		// Something went wrong, log the error and return
		WARNING("Failed to get the absolute path of %s with code %d\n", pathname, err_abs);
		if (path_buf)
			kfree(path_buf);
		return 0;
	}
	// find the parent directory
	char *parent_buf = kzalloc(PATH_LEN * sizeof(char), GFP_KERNEL);
	if (!parent_buf) {
		WARNING("Failed to allocate memory for the parent buffer\n");
		kfree(path_buf);
		return 0;
	}

	const int err_parent = get_dir_path(path_buf, parent_buf);
	// Check if something went wrong when calculating the parent directory
	// or if the parent directory does not exist
	if (err_parent != 0 || !is_dir(parent_buf)) {
		WARNING("Failed to get the parent directory of %s with code %d\n", pathname, err_parent);
		if (parent_buf)
			kfree(parent_buf);
		if (path_buf)
			kfree(path_buf);
		return 0;
	}
	// Check for parent protection
	if (is_protected(parent_buf)) {
		WARNING("Attempt to open a protected directory: %s\n", parent_buf);
		// reject system call to reject directory
		__send_sig_to_current(SIGKILL);
		regs->ax = -EPERM;
		kfree(parent_buf);
		kfree(path_buf);
		return 0;
	}
	goto out;
reject:
	//TODO register deferred work

out:
	if (path_buf)
		kfree(path_buf);
	if (parent_buf)
		kfree(parent_buf);

	return 0;
}
int rm_rmdir_pre_handler(struct kprobe *ri, struct pt_regs *regs) {
	// Extract the function arguments from the registers based on the x86_64 ABI
	const struct filename *name =
		(struct filename *)regs->si; // 2nd argument: filename (struct filename pointer)

	// Get the file path from the filename struct
	const char *pathname = name->name;
	// If pathname is NULL, there's nothing to check, skip
	if (!pathname) {
		return 0;
	}

	// Check if the path is valid and should be monitored
	if (!is_valid_path(pathname)) {
		return 0; // Skip if the path is not valid
	}

#ifdef DEBUG
	int dfd = (int)regs->di; // 1st argument: directory file descriptor
	INFO("Probing rmdir with dfd %d for path %s\n", dfd, pathname);
#endif
	// Get the absolute path of the file its parent directory
	char *path_buf = kzalloc(PATH_LEN * sizeof(char), GFP_KERNEL);
	if (!path_buf) {
		WARNING("Failed to allocate memory for the path buffer\n");
		return 0;
	}

	// resolve the path to its absolute form
	const int err_abs = get_abs_path(pathname, path_buf);
	if (err_abs != 0 && err_abs != -ENOENT) {
		// Something went wrong, log the error and return
		WARNING("Failed to get the absolute path of %s with code %d\n", pathname, err_abs);
		if (path_buf)
			kfree(path_buf);
		return 0;
	}
	// find the parent directory
	char *parent_buf = kzalloc(PATH_LEN * sizeof(char), GFP_KERNEL);
	if (IS_ERR(parent_buf)) {
		WARNING("Failed to allocate memory for the parent buffer\n");
		kfree(path_buf);
		return 0;
	}

	const int err_parent = get_dir_path(path_buf, parent_buf);
	// Check if something went wrong when calculating the parent directory
	// or if the parent directory does not exist
	if (err_parent != 0 || !is_dir(parent_buf)) {
		WARNING("Failed to get the parent directory of %s with code %d\n", pathname, err_parent);
		if (parent_buf)
			kfree(parent_buf);
		if (path_buf)
			kfree(path_buf);
		return 0;
	}
	// Check for parent protection
	if (is_protected(parent_buf)) {
		WARNING("Attempt to open a protected directory: %s\n", parent_buf);
		// reject system call
		regs->ax = -EPERM;

		// Optionally, send a signal to the process (e.g., SIGKILL or SIGTERM)
		__send_sig_to_current(SIGKILL);
		if (path_buf)
			kfree(path_buf);
		if (parent_buf)
			kfree(parent_buf);
		return 0;

	}
	goto out;
reject:
	//TODO register deferred work

out:
	if (path_buf)
		kfree(path_buf);
	if (parent_buf)
		kfree(parent_buf);

	return 0;
}
int rm_unlink_pre_handler(struct kprobe *ri, struct pt_regs *regs) {
	// Extract the function arguments from the registers based on the x86_64 ABI
	const struct filename *name =
		(struct filename *)regs->si; // 2nd argument: filename (struct filename pointer)

	// Get the file path from the filename struct
	const char *pathname = name->name;
	// If pathname is NULL, there's nothing to check, skip
	if (!pathname) {
		return 0;
	}

	// Check if the path is valid and should be monitored
	if (!is_valid_path(pathname)) {
		return 0; // Skip if the path is not valid
	}

#ifdef DEBUG
	int dfd = (int)regs->di; // 1st argument: directory file descriptor
	INFO("Probing unlink with dfd %d for path %s\n", dfd, pathname);
#endif
	// Get the absolute path of the file its parent directory
	char *path_buf = kzalloc(PATH_LEN * sizeof(char), GFP_KERNEL);
	if (IS_ERR(path_buf)) {
		WARNING("Failed to allocate memory for the path buffer\n");
		return 0;
	}

	// resolve the path to its absolute form
	const int err_abs = get_abs_path(pathname, path_buf);
	if (err_abs != 0 && err_abs != -ENOENT) {
		// Something went wrong, log the error and return
		WARNING("Failed to get the absolute path of %s with code %d\n", pathname, err_abs);
		if (path_buf)
			kfree(path_buf);
		return 0;
	}
	// now we find the parent directory
	char *parent_buf = kzalloc(PATH_LEN * sizeof(char), GFP_KERNEL);
	if (IS_ERR(parent_buf)) {
		WARNING("Failed to allocate memory for the parent buffer\n");
		kfree(path_buf);
		return 0;
	}

	const int err_parent = get_dir_path(path_buf, parent_buf);
	// Check if something went wrong when calculating the parent directory
	// or if the parent directory does not exist
	if (err_parent != 0 || !is_dir(parent_buf)) {
		WARNING("Failed to get the parent directory of %s with code %d\n", pathname, err_parent);
		if (parent_buf)
			kfree(parent_buf);
		if (path_buf)
			kfree(path_buf);
		return 0;
	}
	// Check for parent protection
	if (is_protected(parent_buf)) {
		WARNING("Attempt to unlink a protected directory: %s\n", parent_buf);
		// reject system call to reject directory
		regs->ax = -EPERM;

		// Optionally, send a signal to the process (e.g., SIGKILL or SIGTERM)
		__send_sig_to_current(SIGKILL);
		if (path_buf)
			kfree(path_buf);
		if (parent_buf)
			kfree(parent_buf);
		return 0;
		
	}
	if (strlen(path_buf) > 0 && is_protected(path_buf)) {
		WARNING("Attempt to unlink a protected file: %s\n", path_buf);
		// reject system call to reject file
		//regs->si = "";
		regs->ax = -EPERM;

		// Optionally, send a signal to the process (e.g., SIGKILL or SIGTERM)
		__send_sig_to_current(SIGKILL);
		if (path_buf)
			kfree(path_buf);
		if (parent_buf)
			kfree(parent_buf);
		return 0;
	}
	goto out;
reject:
	//TODO register deferred work

out:
	if (path_buf)
		kfree(path_buf);
	if (parent_buf)
		kfree(parent_buf);

	return 0;
}
