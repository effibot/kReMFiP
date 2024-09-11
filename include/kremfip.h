//
// Created by effi on 01/09/24.
//

#ifndef KREMFIP_H
#define KREMFIP_H

#include "state.h"

#define RM_PWD_MAX_LEN 128
#define RM_PWD_MIN_LEN 1

#ifdef __KERNEL__
/* Kernel Module Header Section */
#define MODNAME "KREMFIP"

// Default sizes of module's internal structures
#ifndef HT_BIT_SIZE
#define HT_BIT_SIZE 2
#endif
// be sure that the size of the hash table is under the maximum key size we can have
#if HT_BIT_SIZE > 32
printk("The size of the hash table is too big. We'll reduce to 32 bits\n");
#undef HT_BIT_SIZE
#define HT_BIT_SIZE 32
#endif

// define the size of the hash table
#ifndef HT_SIZE
#define HT_SIZE (1 << HT_BIT_SIZE) // this is 2^HT_BIT_SIZE
#endif

// default size of the key -- maximum amount of bits to (hopefully) avoid collisions
#ifndef HT_BIT_KEY_SIZE
#define HT_BIT_KEY_SIZE 32
#endif

// take a seed for the hash function - chosen at compile time
#ifndef HT_SEED
#define HT_SEED 0
#endif

// define the size of the cache line for x86 architecture
#define X86_CACHE_LINE_SIZE 64

#define RM_PWD_SALT_LEN 16
#define RM_PWD_HASH_LEN 32

#else
/* User Space Header Section */

// Define the system call numbers
#ifndef __NR_state_get
#define __NR_state_get 134
#endif

#ifndef __NR_state_set
#define __NR_state_set 174
#endif

#ifndef __NR_reconfigure
#define __NR_reconfigure 177
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
/* Userspace System Calls Stubs */
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
static inline int state_get(rm_state_t *u_state) {
	errno = 0;
	return syscall(__NR_state_get, u_state);
}

/**
 * @brief Set the state of the reference monitor
 * @param state the new state of the reference monitor
 * @return 0 on success, -1 on error
 */
static inline int state_set(rm_state_t *state) {
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

static inline int reconfigure(const path_op_t *op, const char *path) {
	errno = 0;
	// firstly we check the state of the reference monitor. If is ON or OFF it can't be reconfigured
	rm_state_t state;
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
	//y The monitor is reconfigurable, asking for the password
	char *pwd;
	pwd = prompt_for_pwd();
	if (pwd == NULL)
		return -1;
	// all clear, we can reconfigure
	return syscall(__NR_reconfigure, op, path, pwd);
	return -1;
}

#endif

#endif //KREMFIP_H
