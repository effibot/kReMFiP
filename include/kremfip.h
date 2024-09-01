//
// Created by effi on 01/09/24.
//

#ifndef KREMFIP_H
#define KREMFIP_H

#ifdef __KERNEL__
/* Kernel Module Header Section */
#define MODNAME "KREMFIP"

// Default sizes of module's internal structures - could be overridden inside specific headers
#define HT_BIT_SIZE 2
#define HT_BIT_KEY_SIZE 32
#define HT_SEED 0
#define RM_PWD_MAX_LEN 128
#define RM_PWD_MIN_LEN 8
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

#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/ipc.h>

/* Userspace System Calls Stubs */

static inline int state_get(void) {
	errno = 0;
	return syscall(__NR_state_get);
}

static inline int state_set(rm_state_t state) {
	errno = 0;
	return syscall(__NR_state_set, state);
}
#endif

#endif //KREMFIP_H
