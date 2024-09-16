

#ifndef MISC_H
#define MISC_H

#include "../include/constants.h"

// Function prototypes - no kernel specific code here
char *state_to_str(state_t state);
state_t str_to_state(const char *state_str);
int is_state_valid(state_t state);
int is_op_valid(path_op_t op);

#ifdef __KERNEL__
#include <linux/errno.h>
/* Some useful debug macros - the message we want to print is like
 * kern_type "[module::file::function::line]: message"
 */
#define INFO(fmt, ...)                                                                \
	printk(KERN_INFO "[%s::%s::%s::%d]: " fmt, MODNAME, __FILE__, __func__, __LINE__, \
		   ##__VA_ARGS__);
#define WARNING(fmt, ...)                                                                \
	printk(KERN_WARNING "[%s::%s::%s::%d]: " fmt, MODNAME, __FILE__, __func__, __LINE__, \
		   ##__VA_ARGS__);

// Function prototypes - kernel specific code here

/**
 * @brief Generate a random ID.
 * This function generates a random ID between 1 and 32 inclusive.
 * It uses the `get_random_bytes` function to obtain a random number,
 * and then maps this number to the range [1, 32].
 * @return The random ID
 */

unsigned int rnd_id(void);
/**
 * @brief Convert a hex string to a byte array.
 * This function converts a hex string to a byte array.
 * @param hex the hex string
 * @param len the length of the hex string
 * @return The byte array
 */

inline char *hex_to_str(const unsigned char *hex, size_t len);
/**
 * @brief Map user space buffer to kernel space.
 * Just a wrapper around the copy_from_user function to don't repeat the same code.
 * @param ubuff the user space buffer
 * @param len the length of the buffer in terms of bytes.
 * @return The result of the copy_from_user function
 */
inline void *map_user_buffer(const void __user *ubuff, size_t len);

// Useful macro to check if our mapping was successful
#define map_check(kbuff) \
	if (kbuff == ERR_PTR(-EINVAL) || kbuff == ERR_PTR(-ENOMEM) || kbuff == ERR_PTR(-EFAULT))
#endif

#endif
