//
// Created by effi on 01/09/24.
//

#ifndef RM_SYSCALLS_H
#define RM_SYSCALLS_H

#include "../include/rmfs.h"
#include "../include/state.h"

int rm_state_get(const rm_t *rm);
int rm_state_set(rm_state_t state);

#endif //RM_SYSCALLS_H
