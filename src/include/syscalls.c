/**
 * @file syscalls.c
 * @brief Source Code for the module's system calls
 */

#include "../include/rm.h"
#include "../lib/ht_dll_rcu/ht_dllist.h"
#include "../utils/misc.h"
#include "../utils/pathmgm.h"
#include "kremfip.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

#include <linux/uaccess.h>

// Reference monitor pointer
extern rm_t *rm_p;

/**
 * @brief System call to get the current state of the reference monitor
 * @return the current state of the reference monitor
 */
inline int rm_state_get(state_t __user *u_state) {
	// Check if the reference monitor is initialized
	if (unlikely(rm_p == NULL)) {
#ifdef DEBUG
		WARNING("Passing a NULL reference monitor to the system call\n");
#endif
		return -EINVAL;
	}
	// Grab the lock, so that we can have exclusive access to the reference monitor and its state
	spin_lock(&rm_p->lock);
	// access to the kernel space where the reference monitor is stored
	state_t state;
	int ret;
	state = get_state(rm_p);
#ifdef DEBUG
	INFO("got state %d\n", state);
#endif
	ret = (int)copy_to_user(u_state, &state, sizeof(state_t));
	asm volatile("mfence" ::: "memory");
#ifdef DEBUG
	INFO("RET: %d\n", ret);
#endif
	if (ret != 0) {
		WARNING("failed to copy to user\n");
		spin_unlock(&rm_p->lock);
		return -EFAULT;
	}
	spin_unlock(&rm_p->lock);
	return 0;
}

/**
 * @brief System call to set the state of the reference monitor.
 * The state can be in one of the four states defined in constants.h.
 * Before to actually set the state, the password is checked and then
 * the EUID of the running thread (which invokes the syscall) is marked as root.
 * @param u_state the new state of the reference monitor
 * @return 0 on success, -1 on error
 */
inline int rm_state_set(const state_t __user *u_state) {
	int ret = 0;
	// Check if the reference monitor is initialized
	if (unlikely(rm_p == NULL)) {
		WARNING("Passing a NULL reference monitor to the system call\n");
		ret = -EINVAL;
		goto out;
	}
	if (get_euid() != 0) {
		WARNING("The user is not root, cannot change the state\n");
		ret = -EPERM;
		goto out;
	}
	// Grab the lock
	spin_lock(&rm_p->lock);
	// Copy the state from the user space to the kernel space
	state_t *new_state = map_user_buffer(u_state, sizeof(state_t));
	map_check(new_state) {
		WARNING("failed to copy from user\n");
		ret = -EFAULT;
		goto state_out;
	}
	// checks if the state is valid
	if (unlikely(!is_state_valid(*new_state))) {
		WARNING("Invalid state");
		ret = -EINVAL;
		goto state_out;
	}
#ifdef DEBUG
	INFO("All Clear. Setting the state to %s\n", state_to_str(*new_state));
#endif
	if (set_state(rm_p, *new_state) != 0) {
		WARNING("failed to set the state\n");
		ret = -EFAULT;
	}
	// Free the allocated memory
state_out:
	kfree(new_state);
	spin_unlock(&rm_p->lock);
out:
	return ret;
}

/**
 * @brief System call to reconfigure the reference monitor.
 * The reference monitor can be reconfigured only if it is in the OFF state.
 * @param op the operation to perform on the path
 * @param path the path to reconfigure
 * @return 0 on success, error code on error
 */
inline int rm_reconfigure(const path_op_t __user *op, const char __user *path) {
	// Check if the reference monitor is initialized
	if (unlikely(rm_p == NULL)) {
		WARNING("Passing a NULL reference monitor to the system call\n");
		return -EINVAL;
	}
	int ret;
	if (get_euid() != 0) {
		WARNING("The user is not root, cannot reconfigure the monitor\n");
		ret = -EPERM;
		goto out;
	}
	//! We don't check if the state is REC_x because it's checked before calling this function
	// Grab the lock
	spin_lock(&rm_p->lock);
	ret = 0;
	// Check if the path is valid
	const char *kpath = map_user_buffer(path, strnlen_user(path, PAGE_SIZE));
	map_check(kpath) {
		WARNING("failed to copy from user\n");
		ret = -EFAULT;
		goto path_out;
	}
	// check if the path exists
	// This was previously done with path_exists but if we can't get an absolute path
	// we assume that it doesn't exist
	char *abs_path = kzalloc(PATH_MAX, GFP_KERNEL);
	if (get_abs_path(kpath, abs_path) != 0) {
		WARNING("The requested path does not exist\n");
		ret = -ENOENT;
		goto path_out;
	}
	// Check if the path is valid -> It must exist in the filesystem
	if (!is_valid_path(abs_path)) {
		WARNING("The requested path not valid for the monitor\n");
		ret = -EINVAL;
		goto path_out;
	}
#ifdef DEBUG
	INFO("The requested path exists\n");
#endif
	// Copy the operation from the user space to the kernel space
	const path_op_t *new_op = map_user_buffer(op, sizeof(path_op_t));
	map_check(new_op) {
		WARNING("failed to copy from user\n");
		ret = -EFAULT;
		goto op_out;
	}
	// checks if the operation is valid
	if (!is_op_valid(*new_op)) {
		WARNING("Invalid operation\n");
		ret = -EINVAL;
		goto op_out;
	}
#ifdef DEBUG
	INFO("Requested valid operation\n");
#endif
	// The data we received is valid, we can reconfigure the path
	// to protect a path we add a node in the hash table, to remove it we delete it
	switch (*new_op) {
	case PROTECT_PATH:
		ret = ht_insert_node(rm_p->ht, node_init(abs_path));
		break;
	case UNPROTECT_PATH:
		ret = ht_delete_node(rm_p->ht, node_init(abs_path));
		break;
	}
	if (ret == -EINVAL) {
		WARNING("failed to reconfigure the path\n");
	} else if (ret == -EEXIST) {
		WARNING("The path is already protected\n");
	} else if (ret == -ENOENT) {
		WARNING("The path was already removed\n");
	}
	// Free the allocated memory
op_out:
	kfree(new_op);
path_out:
	kfree(kpath);
	kfree(abs_path);
	spin_unlock(&rm_p->lock);
out:
	return ret;
}

/**
 * @brief System call to check the password hash
 * User-friendly way to let the user check for the password hash in user space
 * @return 0 on success, errno on error
 */
inline int rm_pwd_check(const char __user *pwd) {
#ifdef DEBUG
	INFO("Checking the password\n");
#endif
	int ret = 0;
	// Check if the reference monitor is initialized
	if (unlikely(rm_p == NULL)) {
		WARNING("Passing a NULL reference monitor to the system call\n");
		ret = -EINVAL;
		goto out;
	}
	// Copy the password from the user space to the kernel space
	char *kpwd = map_user_buffer(pwd, strnlen_user(pwd, RM_PWD_MAX_LEN));
	map_check(kpwd) {
		WARNING("failed to copy from user\n");
		ret = -EFAULT;
		goto pwd_out;
	}
#ifdef DEBUG
	INFO("Read pwd (%s) from user-space of length %lu\n", kpwd, strlen(kpwd));
#endif
	// Check if the password is valid
	if (strlen(kpwd) >= RM_PWD_MIN_LEN && strlen(kpwd) <= RM_PWD_MAX_LEN && verify_pwd(kpwd)) {
		printk(KERN_CONT "The password is valid\n");
	} else {
		WARNING("The password is not valid\n");
		ret = -EINVAL;
	}
#ifdef DEBUG
	INFO("Password check completed\n");
#endif
	// Free the allocated memory
pwd_out:
	kfree(kpwd);
out:
	return ret;
}
