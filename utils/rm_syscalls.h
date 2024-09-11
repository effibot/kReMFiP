//
// Created by effi on 01/09/24.
//

#ifndef RM_SYSCALLS_H
#define RM_SYSCALLS_H

#include "../include/rm.h"
#include "../include/state.h"

int rm_state_get(rm_state_t __user *u_state);
int rm_state_set(rm_state_t __user *u_state, const char __user *password, size_t pwd_len);
int rm_reconfigure(path_op_t __user *op, const char __user *path, size_t path_len, const char __user *password, size_t pwd_len);

#endif //RM_SYSCALLS_H
