/**
 * @file rm_syscalls.c
 * @brief Source Code for the module's system calls
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include "../include/kremfip.h"
#include "../include/misc.h"
#include "../include/rm.h"
#include "rm_syscalls.h"

#include "../../../../media/sf_kReMFiP/include/misc.h"
#include "../../../../usr/src/linux-headers-5.4.0-150-generic/include/linux/slab.h"
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
int rm_state_set(rm_state_t __user *u_state, const char __user *pwd, size_t pwd_len) {
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
		return -EFAULT;
	}
	// checks if the state is valid
	if (unlikely(!is_state_valid(*new_state))) {
		WARNING("Invalid state");
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
			return -EINVAL;
		}
#ifdef DEBUG
		INFO("Length of the password is correct, checking the hash\n");
#endif
		if (!verify_pwd(kpwd)) {
			WARNING("Password is not valid, wrong hash\n");
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
		return -EFAULT;
	}
	return 0;
}