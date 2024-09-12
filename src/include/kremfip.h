/**
* @file kremfip.h
* @brief General header file for the kernel-side stuff of the kReMFiP project
* This file contains the definitions of some constants that have to be shared between the
*/
#ifndef KREMFIP_H
#define KREMFIP_H

#include "constants.h"

#ifdef __KERNEL__
/* Kernel Module Header Section */
#include <linux/syscalls.h>
#include "../utils/misc.h"
// System Calls Prototypes Internal Functions
int rm_state_get(state_t __user *u_state);
int rm_state_set(const state_t __user *u_state, const char __user *password, size_t pwd_len);
int rm_reconfigure(const path_op_t __user *op, const char __user *path, size_t path_len, const char __user *password, size_t pwd_len);

#else
/* User Space Header Section */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
/* Userspace System Calls Stubs */
/**
* @brief Ask the user for the password
* @return the password entered by the user
*/
static inline char *prompt_for_pwd(void) {
	char *pwd;
	pwd = getpass("Enter the password: ");
	if (pwd == NULL) {
		printf("Failed to read the password\n");
		goto out;
	}
	const int len = strlen(pwd);
	if (len < RM_PWD_MIN_LEN) {
		printf("The password is too short\n");
		goto out;
	}
	if (len > RM_PWD_MAX_LEN) {
		printf("The password is too long\n");
		goto out;
	}
	return pwd;
out:
	return NULL;
}
/**
 * @brief Get the current state of the reference monitor
 * @return the current state of the reference monitor
 */
static inline int state_get(state_t *u_state) {
	errno = 0;
	return syscall(__NR_state_get, u_state);
}

/**
 * @brief Set the state of the reference monitor
 * @param state the new state of the reference monitor
 * @return 0 on success, -1 on error
 */
static inline int state_set(state_t *state) {
	errno = 0;
	//TODO: we need to elevate the permission to root setting euid to 0
	// if the state we want to  is REC_ON or REC_OFF we need to prompt for the password
	char *pwd = "nopwd";
	switch (*state) {
	case REC_ON:
		printf("Setting the state to REC_ON\n");

	case REC_OFF:
		printf("Setting the state to REC_OFF\n");
		// prompt for password - this will overwrite whatever is stored in pwd.
		pwd = prompt_for_pwd();
		if (pwd == NULL)
			return -1;
		break;
	default:
		break;
	}
	return syscall(__NR_state_set, state, pwd);
}

/**
 * @brief Reconfigure the reference monitor
 * @param op the operation to perform on the path
 * @param path the path to reconfigure
 * @return 0 on success, -1 on error
 */
static inline int reconfigure(const path_op_t *op, const char *path) {
	errno = 0;
	// firstly we check the state of the reference monitor. If is ON or OFF it can't be reconfigured
	state_t state;
	int ret;
	ret = state_get(&state);
	if (ret < 0) {
		printf("Error: %s\n", strerror(errno));
		return -1;
	}
	if (state == ON || state == OFF) {
		printf("The reference monitor is in a state that can't be reconfigured\n");
		return -1;
	}
	// The monitor is reconfigurable, asking for the password
	char *pwd;
	pwd = prompt_for_pwd();
	if (pwd == NULL)
		return -1;
	// all clear, we can reconfigure
	return syscall(__NR_reconfigure, op, path, pwd);
}

#endif

#endif //KREMFIP_H
