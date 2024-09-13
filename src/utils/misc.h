

#ifndef MISC_H
#define MISC_H

#include "../include/constants.h"

// Function prototypes - no kernel specific code here
char *state_to_str(state_t state);
state_t str_to_state(const char *state_str);
int is_state_valid(state_t state);
int is_op_valid(path_op_t op);
#ifdef __KERNEL__

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
unsigned int rnd_id(void);
char *hex_to_str(const unsigned char *hex, size_t len);

#endif

#endif
