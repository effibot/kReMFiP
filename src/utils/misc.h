

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
#include <linux/kernel.h>
#include <linux/types.h>

/* Some useful debug macros - the message we want to print is like
 * kern_type "[module::file::function::line]: message"
 */
#define INFO(fmt, ...)                                                                \
	printk(KERN_INFO "[%s::%s::%s::%d]: " fmt, MODNAME, __FILE__, __func__, __LINE__, \
		   ##__VA_ARGS__);
#define WARNING(fmt, ...)                                                                \
	printk(KERN_WARNING "[%s::%s::%s::%d]: " fmt, MODNAME, __FILE__, __func__, __LINE__, \
		   ##__VA_ARGS__);

/**
* @brief Generate a for-each loop stub to loop over an array.
* The keep, count and size variables needs to be declared outside the macro, due to
* C standards against we are working with.
* @param item the item to loop over
* @param array the array to loop over
* @param keep the condition to keep looping, it's just a int
* @param count the counter of the loop, used to change the item in the inner loop through pointer arithmetic
* @param size the size of the array.
*/
#define foreach(item, array) \
	for (typeof(*array) *item = (array); item < (array) + ARRAY_SIZE(array); ++item)
// Function prototypes - kernel specific code here

/**
 * @brief Generate a random ID.
 * This function generates a random ID between 1 and 32 inclusive.
 * It uses the `get_random_bytes` function to obtain a random number,
 * and then maps this number to the range [1, 32].
 * @return The random ID
 */

inline unsigned int rnd_id(void);
/**
 * @brief Convert a hex string to a byte array.
 * This function converts a hex string to a byte array.
 * @param hex the hex string
 * @param len the length of the hex string
 * @param buf the buffer where the byte array will be stored
 * @return The byte array
 */

inline int hex_to_str(const unsigned char *hex, size_t len, char *buf);
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

/**
 * @brief This function is used to hash a password using an algorithm defined in the constants.h file.
 * We pre-append the salt to the password before hashing it. The default algorithm is SHA256.
 * The result is stored in the pwd_hash buffer.
 * @param pwd the password to hash
 * @param pwd_salt the salt to append to the password
 * @param pwd_hash the buffer where the hashed password will be stored
 * @return 0 on success, -1 on error
 */
inline int hash_pwd(const char *pwd, const u8 *pwd_salt, u8 *pwd_hash);
int calculate_hash(const u8 *data, size_t data_len, u8 *output_hash);
/**
 * @brief Check if the string inserted by the user is the password of the reference monitor.
 * We hash the input string and compare it with the stored hash.
 * @param input_str the string to check
 * @return true if the string is the password, false otherwise
 */
inline bool verify_pwd(const char *input_str);

// Macro to get the EUID of the current process
#define get_euid() current->cred->euid.val

/**
 * @brief Elevate the privileges of the current process to root.
 * This function elevates the privileges of the current process to root, if it's not already root.
 * @remark REMEMBER TO STORE THE PREVIOUS UIDs AND GIDs TO RESTORE THEM LATER.
 * THIS MUST ALWAYS BE SUCCEEDED BY reset_privileges TO RESTORE THE PRIVILEGES.
 * @return int the old EUID of the thread on success, an error code otherwise.
 */
inline int elevate_privileges(void);
/**
 * @brief Reset the privileges of the current process.
 * This function resets the privileges of the current process to the original ones.
 * @return 0 on success, error code otherwise
 */
inline int reset_privileges(uid_t old_euid);
#endif
#endif
