//
// Created by effi on 07/08/24.
//

#ifndef MISC_H
#define MISC_H

#include "kremfip.h"
#ifndef __KERNEL__
#include <string.h>
#endif
// Function prototypes - no kernel specific code here
char *state_to_str(rm_state_t state);
rm_state_t str_to_state(const char *state_str);
int is_state_valid(rm_state_t state);

#ifdef __KERNEL__
#include <linux/kernel.h>
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