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

#include <linux/uaccess.h>

// Reference monitor pointer
extern rm_t *rm_p;

/**
 * @brief System call to get the current state of the reference monitor
 * @return the current state of the reference monitor
 */
int rm_state_get(state_t __user *u_state) {
	INFO("getting state\n");
	// Check if the reference monitor is initialized
	if (unlikely(rm_p == NULL)) {
#ifdef DEBUG
		WARNING("Passing a NULL reference monitor to the system call\n");
#endif
		return -EINVAL;
	}
	// access to the kernel space where the reference monitor is stored
	state_t state;
	int ret;
	state = get_state(rm_p);
#ifdef DEBUG
	INFO("got state %d\n", state);
#endif
	ret = copy_to_user(u_state, &state, sizeof(state_t));
	asm volatile("mfence" ::: "memory");
#ifdef DEBUG
	INFO("RET: %d\n", ret);
#endif
	if (ret != 0) {
		WARNING("failed to copy to user\n");
		return -EFAULT;
	}
	return 0;
}

/**
 * @brief System call to set the state of the reference monitor.
 * The state can be in one of the four states defined in constants.h.
 * If the state is of reconfigurable type (REC_x), then we need to check
 * the monitor's pwd hash.
 * @param u_state the new state of the reference monitor
 * @param pwd the password to set the monitor to REC_ON or REC_OFF
 * @return 0 on success, -1 on error
 */
int rm_state_set(const state_t __user *u_state, const char __user *pwd) {
	// Check if the reference monitor is initialized
	if (unlikely(rm_p == NULL)) {
#ifdef DEBUG
		WARNING("Passing a NULL reference monitor to the system call\n");
#endif
		return -EINVAL;
	}
	// Depending on the state, we need to check the password
	state_t *new_state;
	new_state = map_user_buffer(u_state, sizeof(state_t));
	map_check(new_state) {
		WARNING("failed to copy from user\n");
		kfree(new_state);
		return -EFAULT;
	}
	// checks if the state is valid
	if (unlikely(!is_state_valid(*new_state))) {
		WARNING("Invalid state");
		kfree(new_state);
		return -EINVAL;
	}
#ifdef DEBUG
	INFO("Setting the state to %s\n", state_to_str(*new_state));
#endif
	/* Since the user could be prompted to enter the password, we need to
	 * check if the password is valid, but only if the state is REC_ON or REC_OFF.
	 * We have to copy the password from the user space to the kernel space anyway.
	 */
	char *kpwd;
	kpwd = (char *)map_user_buffer(pwd, strnlen_user(pwd, RM_PWD_MAX_LEN));
	map_check(kpwd) {
		WARNING("failed to copy password from user\n");
		kfree(new_state);
		return -EFAULT;
	}
#ifdef DEBUG
	INFO("copied password from user: %s (%ld)\n", kpwd, strlen(kpwd));
#endif
	// Check if the password is valid
	// If the state is ON or OFF we pass 'nopwd' as the password
	int ret = 0;
	switch (*new_state) {
	case ON: // fall through
	case OFF:
		if (strcmp(kpwd, RM_DEF_PWD) != 0) {
			WARNING("Password not compatible with state %d\n", *new_state);
			ret = -EINVAL;
			goto out;
		}
		break;
	case REC_ON: // fall through
	case REC_OFF:
		// Check if the password is valid
#ifdef DEBUG
		INFO("Checking the password validity\n");
#endif
		if (strlen(kpwd) >= RM_PWD_MIN_LEN && strlen(kpwd) <= RM_PWD_MAX_LEN && verify_pwd(kpwd)) {
#ifdef DEBUG
			INFO("The password is valid\n");
#endif
		} else {
			WARNING("Password is not valid, wrong length or hash\n");
			ret = -EINVAL;
			goto out;
		}
	}
#ifdef DEBUG
	INFO("All clear, setting the state\n");
#endif
	if (set_state(rm_p, *new_state) != 0) {
		WARNING("failed to set the state\n");
		ret = -EFAULT;
	}
	// Free the allocated memory
out:
	kfree(new_state);
	kfree(kpwd);
	return ret;
}

/**
 * @brief System call to reconfigure the reference monitor.
 * The reference monitor can be reconfigured only if it is in the OFF state.
 * @param op the operation to perform on the path
 * @param path the path to reconfigure
 * @param pwd the password to reconfigure the path
 * @return 0 on success, -1 on error
 */

int rm_reconfigure(const path_op_t __user *op, const char __user *path, const char __user *pwd) {
	// Check if the reference monitor is initialized
	if (unlikely(rm_p == NULL)) {
		WARNING("Passing a NULL reference monitor to the system call\n");
		return -EINVAL;
	}
	// We don't check if the state is REC_x because it's checked before calling this function
	// Check if the operation is valid
	int ret;
	ret = 0;
	// Check if the path is valid
	char *kpath;
	kpath = map_user_buffer(path, strnlen_user(path, PAGE_SIZE));
	map_check(kpath) {
		WARNING("failed to copy from user\n");
		ret = -EFAULT;
		goto path_out;
	}
	// Check if the path is valid -> It must exist in the filesystem
	if (unlikely(!path_exists(kpath) || !is_valid_path(kpath))) {
		WARNING("The requested path does not exist or is not valid for the system\n");
		ret = -EINVAL;
		goto path_out;
	}
#ifdef DEBUG
	INFO("The requested path exists\n");
#endif
	// Check if the password is valid
	char *kpwd;
	kpwd = map_user_buffer(pwd, strnlen_user(pwd, RM_PWD_MAX_LEN));
	map_check(kpwd) {
		WARNING("failed to copy from user\n");
		ret = -EFAULT;
		goto pwd_out;
	}
	// Check if the password is valid
	if (!(strlen(kpwd) >= RM_PWD_MIN_LEN && strlen(kpwd) <= RM_PWD_MAX_LEN && verify_pwd(kpwd))) {
		WARNING("The password is not valid\n");
		ret = -EINVAL;
		goto pwd_out;
	}
#ifdef DEBUG
	INFO("The inserted password is valid\n");
#endif
	path_op_t *new_op;
	new_op = map_user_buffer(op, sizeof(path_op_t));
	map_check(new_op) {
		WARNING("failed to copy from user\n");
		ret = -EFAULT;
		goto op_out;
	}
	// checks if the operation is valid
	if (unlikely(!is_op_valid(*new_op))) {
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
		ret = ht_insert_node(rm_p->ht, node_init(kpath));
		break;
	case UNPROTECT_PATH:
		ret = ht_delete_node(rm_p->ht, node_init(kpath));
		break;
	}
	if (ret != 0) {
		WARNING("failed to reconfigure the path\n");
		ret = -EFAULT;
	}
	// Free the allocated memory
op_out:
	kfree(new_op);
pwd_out:
	kfree(kpwd);
path_out:
	kfree(kpath);
	return ret;
}
