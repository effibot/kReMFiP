#ifndef __KERNEL__
#include "kremfip.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/**
* @brief Ask the user for the password
* @return the password entered by the user
*/
inline char *prompt_for_pwd(void) {
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
inline int state_get(state_t *u_state) {
	errno = 0;
	return syscall(__NR_state_get, u_state);
}

/**
 * @brief Set the state of the reference monitor
 * @param state the new state of the reference monitor
 * @return 0 on success, -1 on error
 */
inline int state_set(state_t *state) {
	errno = 0;
	// safety checks
	if(state == NULL) {
		printf("Error: state is NULL\n");
		return -1;
	}
	// check access rights
	if(pwd_check() < 0)
		return -1;
	// all clear, we can set the state
	return syscall(__NR_state_set, state);
}

/**
 * @brief Reconfigure the reference monitor
 * @param op the operation to perform on the path
 * @param path the path to reconfigure
 * @return 0 on success, -1 on error
 */
inline int reconfigure(const path_op_t *op, const char *path) {
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
	if(pwd_check() < 0)
		return -1;
	// all clear, we can reconfigure
	return syscall(__NR_reconfigure, op, path);
}

/**
 * @brief Check if the password is correct
 * @return 0 on success, -1 on error
 */
inline int pwd_check(void) {
    errno = 0;
    char *pwd;
    pwd = prompt_for_pwd();
    if (pwd == NULL)
        return -1;
    return syscall(__NR_pwd_check, pwd);
}
#endif
