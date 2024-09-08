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

#ifndef __NR_path_protect
#define __NR_path_protect 177
#endif

#ifndef __NR_path_unprotect
#define __NR_path_unprotect 178
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
/* Userspace System Calls Stubs */

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
static inline int state_set(rm_state_t state) {
	errno = 0;
	char *pwd;
	pwd = "nopwd";
	// We need to prompt the user to enter the password
	if (state == REC_ON || state == REC_OFF) {
		pwd = getpass("Enter the password: ");
		if (strlen(pwd) < RM_PWD_MIN_LEN || strlen(pwd) > RM_PWD_MAX_LEN) {
			printf("Password can't be empty and must be between %d and %d characters\n",
				   RM_PWD_MIN_LEN, RM_PWD_MAX_LEN);
			return -1;
		}
		if (pwd == NULL) {
			return -1;
		}
	}
	return syscall(__NR_state_set, state, pwd);
}
/**
 * @brief Protect a path by adding it to the reference monitor's hash table
 * @param path the path to protect
 * @return 0 on success, -1 on error
 */
static inline int path_protect(const char *path) {
	errno = 0;
	return syscall(__NR_path_protect, path);
}
/**
 * @brief Unprotect a path by removing it from the reference monitor's hash table
 * @param path the path to unprotect
 * @return 0 on success, -1 on error
 */
static inline int path_unprotect(const char *path) {
	errno = 0;
	return syscall(__NR_path_unprotect, path);
}

#endif

#endif //KREMFIP_H
