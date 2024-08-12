//
// Created by effi on 07/08/24.
//

#ifndef UTILS_H
#define UTILS_H

#include <linux/fs.h>
#include <linux/err.h>


#include "rmfs.h"

// Some useful debug macros

#define INFO(fmt, ...) \
    /* base msg is: [MODNAME::func_name]: */ \
    printk(KERN_INFO "[%s::%s]: " fmt, MODNAME, __func__, ##__VA_ARGS__);

#define SHOW(attr_name) \
    printk(KERN_INFO "[%s::%s]: Show operation invoked for attribute %s\n", MODNAME, __func__, attr_name)
#define STORE(attr_name) \
    printk(KERN_INFO "[%s::%s]: Store operation invoked for attribute %s\n", MODNAME, __func__, attr_name)

// Function prototypes
unsigned int rnd_id(void);
char *state_to_str(rm_state_t state);
rm_state_t str_to_state(const char *state_str);
bool is_state_valid(rm_state_t state);
#endif //UTILS_H

