/**
* @file constants.h
* @brief Header file for the constants used in the project.
* This file is shared between user and kernel side of the project, so some ifdefs are necessary
* to prevent compile errors.
*/

#ifndef CONSTANTS_H
#define CONSTANTS_H

//#define DEBUG


// THIS SECTION IS SHAREABLE BETWEEN KERNEL AND USER SPACE
#define RM_PWD_MAX_LEN 128
#define RM_PWD_MIN_LEN 1

/**
* @brief The possible states in which the reference monitor can be.
* The reference monitor can be in one of the following states: OFF, ON, REC_OFF, REC_ON.
* - If the reference monitor is in REC_OFF or REC_ON, then the monitor is reconfigurable and
* paths can be added or removed from the monitor's protection list.
* - If the reference monitor is in OFF or ON, then the monitor is not reconfigurable and
* the protection mechanism can be, respectively, disabled or enabled.
*/
typedef enum _rm_state_t {
	OFF = 0,
	ON = 1,
	REC_OFF = 2,
	REC_ON = 3,
} state_t;

/**
* @brief The possible operations that can be performed on a path.
* The reference monitor can protect or unprotect a path.
*/
typedef enum _rm_path_op_t { PROTECT_PATH = 0, UNPROTECT_PATH = 1 } path_op_t;

// THIS SECTION IS ONLY FOR THE KERNEL SPACE
#ifdef __KERNEL__
#ifndef MODNAME
#define MODNAME "KREMFIP"
#endif
#include <linux/kernel.h>

// Default sizes of module's hash table
#ifndef HT_BIT_SIZE
#define HT_BIT_SIZE 2
#endif

// be sure that the size of the hash table is under the maximum key size we can have
#if HT_BIT_SIZE > 32
printk(KERN_INFO "The size of the hash table is too big. We'll reduce to 32 bits\n");
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

// take a seed for the hash function
#ifndef HT_SEED
#define HT_SEED 0
#endif

// define the size of the cache line for x86 architecture
#define X86_CACHE_LINE_SIZE 64

// define the size of the salt
#define RM_PWD_SALT_LEN 16

// define the size of the hash
#define RM_PWD_HASH_LEN 32
// the length of the hash in string format, to perform the checksum
#define RM_STR_HASH_LEN RM_PWD_HASH_LEN * 2 + 1
// define the name of the Monitor
#define RM_DEFAULT_NAME "KREMFIP"

// define the Initial State of the Monitor
#define RM_INIT_STATE REC_OFF

// define the default crypto algorithm
#define RM_CRYPTO_ALGO "sha256"

/**
 * Define the attribute name for the password hash.
 * BEWARE: this must be the same, at least, of the directory name in the sysfs.
 */
#define RM_PWD_HASH_ATTR_NAME "pwd_hash"	// the name of the attribute
#define RM_PWD_HASH_PATH "/sys/module/kremfip/pwd_hash/pwd_hash" // the path to the attribute
#endif
#endif
