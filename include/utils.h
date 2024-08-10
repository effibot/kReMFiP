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
    printk(KERN_INFO fmt, ##__VA_ARGS__)

#define RM_LOG_STR(rm, msg, ...) \
    do { \
        if (sizeof((char *[]){__VA_ARGS__}) / sizeof(char *) > 0) { \
            char full_msg[256]; \
            snprintf(full_msg, sizeof(full_msg), msg, ##__VA_ARGS__); \
            printk(KERN_INFO "[%s::monitor_%d::%s]: %s\n", MODNAME, rm->id, __func__, full_msg); \
        } else { \
            printk(KERN_INFO "[%s::monitor_%d::%s]: %s\n", MODNAME, rm->id, __func__, msg); \
        } \
    } while (0)


#define mem_check(ptr) \
    if (unlikely(ptr == NULL)) { \
        LOG_MSG("Memory allocation error", "kzalloc failed"); \
        goto free; \
    }

#define file_open_check(fp, f_path) \
    if (IS_ERR(fp)) { \
        LOG_MSG("Failed to open file at path", f_path); \
        return PTR_ERR(fp); \
	}

// Function prototypes
int rnd_id(void);
char *get_state_str(rm_state_t state);
rm_state_t get_state_from_str(const char *state_str);
bool is_state_valid(rm_state_t state);
#endif //UTILS_H

