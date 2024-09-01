//
// Created by effi on 07/08/24.
//

#ifndef UTILS_H
#define UTILS_H

#include <linux/fs.h>
#include "kremfip.h"
#include "rmfs.h"
#include "state.h"

#ifdef __KERNEL__
/* Some useful debug macros - the message we want to print is like
 * kern_type "[module::file::function::line]: message"
 */
#define INFO(fmt, ...) \
    printk(KERN_INFO "[%s::%s::%s::%d]: " fmt, MODNAME, __FILE__,  __func__, __LINE__, ##__VA_ARGS__);
#define WARNING(fmt, ...) \
    printk(KERN_WARNING "[%s::%s::%s::%d]: " fmt, MODNAME, __FILE__,  __func__, __LINE__, ##__VA_ARGS__);


// Function prototypes - kernel specific code here
unsigned int rnd_id(void);
char* hex_to_str(const unsigned char *hex, size_t len);
#endif

// Function prototypes - no kernel specific code here
char *state_to_str(rm_state_t state);
rm_state_t str_to_state(const char *state_str);
bool is_state_valid(rm_state_t state);

#endif //UTILS_H

