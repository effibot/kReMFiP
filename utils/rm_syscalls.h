//
// Created by effi on 01/09/24.
//

#ifndef RM_SYSCALLS_H
#define RM_SYSCALLS_H

#include "../include/rm.h"
#include "../include/state.h"

int rm_state_get(rm_state_t __user *u_state);
int rm_state_set(rm_state_t __user state, const char __user *password);
int rm_path_protect(const char *path);
int rm_path_unprotect(const char *path);

#endif //RM_SYSCALLS_H
