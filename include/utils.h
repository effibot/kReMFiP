//
// Created by effi on 07/08/24.
//

#ifndef UTILS_H
#define UTILS_H

#include <linux/fs.h>
#include <linux/err.h>


#include "rmfs.h"

// Some useful debug macros

#define LOG_MSG(log_msg, msg) printk(KERN_INFO "[%s::%s::%s]: %s %s\n", MODNAME, __FILE__, __func__, log_msg, msg);
#define RM_LOG_MSG(rm, msg) printk(KERN_INFO "[%s::monitor_%d::%s]: %s\n", MODNAME, rm->id, __func__, msg);
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
bool is_state_valid(rm_state_t state);
#endif //UTILS_H

