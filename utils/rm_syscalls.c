/**
 * @file rm_syscalls.c
 * @brief Source Code for the module's system calls
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "../include/kremfip.h"
#include "../include/misc.h"
#include "../include/rm.h"
#include "../include/ht_dllist.h"
#include "rm_syscalls.h"

#include <linux/uaccess.h>


#define DEBUG

// Reference monitor pointer
extern rm_t *rm_p;

/**
 * @brief System call to get the current state of the reference monitor
 * @return the current state of the reference monitor
 */
int rm_state_get(rm_state_t __user *u_state) {
	// Check if the reference monitor is initialized
	if (unlikely(rm_p == NULL)) {
#ifdef DEBUG
		WARNING("Passing a NULL reference monitor to the system call\n");
#endif
		return -EINVAL;
	}
	// access to the kernel space where the reference monitor is stored
	rm_state_t state;
	int ret;
	state = get_state(rm_p);
#ifdef DEBUG
	INFO("got state %d\n", state);
#endif
	ret = copy_to_user(u_state, &state, sizeof(rm_state_t));
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
 * The state can be in one of the four states defined in state.h.
 * If the state is of reconfigurable type (REC_x), then we need to check
 * the monitor's pwd hash.
 * @param state the new state of the reference monitor
 * @param pwd the password to set the monitor to REC_ON or REC_OFF
 * @return 0 on success, -1 on error
 */
int rm_state_set(const rm_state_t __user *u_state, const char __user *pwd, size_t pwd_len) {
	INFO("null check");
	// Check if the reference monitor is initialized
	if (unlikely(rm_p == NULL)) {
#ifdef DEBUG
		WARNING("Passing a NULL reference monitor to the system call\n");
#endif
		return -EINVAL;
	}
	INFO("null check");
	// Depending on the state, we need to check the password
	rm_state_t *new_state;
	new_state = kzalloc(sizeof(rm_state_t), GFP_KERNEL);
	int ret;
	ret = copy_from_user(new_state, u_state, sizeof(rm_state_t));
	asm volatile("mfence" ::: "memory");
	if (ret != 0) {
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
	kpwd = kzalloc(pwd_len+1, GFP_KERNEL);
	INFO("coping password from user");
	ret = copy_from_user(kpwd, pwd, pwd_len);
	asm volatile("mfence" ::: "memory");

	if (ret != 0) {
		WARNING("failed to copy from user\n");
		kfree(new_state);
		kfree(kpwd);
		return -EFAULT;
	}
	INFO("copied password from user: %s (%ld)\n", kpwd, strlen(kpwd));
	// Check if the password is valid
	// If the state is ON or OFF we pass 'nopwd' as the password
	switch (*new_state) {
	case ON: // fall through
	case OFF:
		if (strcmp(kpwd, "nopwd") != 0) {
			WARNING("Password is not valid\n");
			kfree(new_state);
			kfree(kpwd);
			return -EINVAL;
		}
		break;
	case REC_ON: // fall through
	case REC_OFF:
		// Check if the password is valid
#ifdef DEBUG
		INFO("Checking the password validity\n");
#endif
		if (strlen(kpwd) < RM_PWD_MIN_LEN || strlen(kpwd) > RM_PWD_MAX_LEN) {
			WARNING("Password is not valid, wrong length\n");
			kfree(new_state);
			kfree(kpwd);
			return -EINVAL;
		}
#ifdef DEBUG
		INFO("Length of the password is correct, checking the hash\n");
#endif
		if (!verify_pwd(kpwd)) {
			WARNING("Password is not valid, wrong hash\n");
			kfree(new_state);
			kfree(kpwd);
			return -EINVAL;
		}
		break;
	}
#ifdef DEBUG
	INFO("All clear, setting the state\n");
#endif
	ret = set_state(rm_p, *new_state);
	if (ret != 0) {
		WARNING("failed to set the state\n");
		kfree(new_state);
		kfree(kpwd);
		return -EFAULT;
	}
	// Free the allocated memory
	kfree(new_state);
	kfree(kpwd);
	return 0;
}

/**
 * @brief System call to reconfigure the reference monitor.
 * The reference monitor can be reconfigured only if it is in the OFF state.
 * @param op the operation to perform on the path
 * @param path the path to reconfigure
 * @param pwd the password to reconfigure the path
 * @return 0 on success, -1 on error
 */

int rm_reconfigure(const path_op_t __user *op, const char __user *path, size_t path_len, const char __user *pwd, size_t pwd_len) {
	// Check if the reference monitor is initialized
	if (unlikely(rm_p == NULL)) {
		WARNING("Passing a NULL reference monitor to the system call\n");
		return -EINVAL;
	}
	// We don't check if the state is REC_x because it's checked before calling this function
	// Check if the operation is valid
	path_op_t *new_op;
	new_op = kzalloc(sizeof(path_op_t), GFP_KERNEL);
	int ret;
	ret = copy_from_user(new_op, op, sizeof(path_op_t));
	asm volatile("mfence" ::: "memory");
	if (ret != 0) {
		WARNING("failed to copy from user\n");
		kfree(new_op);
		return -EFAULT;
	}
	if (unlikely(!is_op_valid(*new_op))) {
		WARNING("Invalid operation\n");
		kfree(new_op);
		return -EINVAL;
	}
	// Check if the path is valid
	char *kpath;
	kpath = kzalloc(path_len+1, GFP_KERNEL);
	ret = copy_from_user(kpath, path, path_len);
	asm volatile("mfence" ::: "memory");
	if (ret != 0) {
		WARNING("failed to copy from user\n");
		kfree(new_op);
		kfree(kpath);
		return -EFAULT;
	}
//	if (unlikely(!is_path_valid(kpath))) {
//		WARNING("Invalid path\n");
//		kfree(new_op);
//		kfree(kpath);
//		return -EINVAL;
//	}
	// Check if the password is valid
	char *kpwd;
	kpwd = kzalloc(pwd_len+1, GFP_KERNEL);
	ret = copy_from_user(kpwd, pwd, pwd_len);
	asm volatile("mfence" ::: "memory");
	if (ret != 0) {
		WARNING("failed to copy from user\n");
		kfree(new_op);
		kfree(kpath);
		kfree(kpwd);
		return -EFAULT;
	}
	if (!verify_pwd(kpwd)) {
		WARNING("Invalid password\n");
		kfree(new_op);
		kfree(kpath);
		kfree(kpwd);
		return -EINVAL;
	}
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
		kfree(new_op);
		kfree(kpath);
		kfree(kpwd);
		return -EFAULT;
	}
	// Free the allocated memory
	kfree(new_op);
	kfree(kpath);
	kfree(kpwd);
	return 0;
}