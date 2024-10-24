//
// Created by effi on 24/10/24.
//

#ifndef KREMFIP_LIB_H
#define KREMFIP_LIB_H
#include "../include/constants.h"
#include "../../scth/headers/scth_lib.h"
/* Userspace System Calls Stubs */

char *prompt_for_pwd(void);
int state_get(state_t *u_state);
int state_set(state_t *state);
int reconfigure(const path_op_t *op, const char *path);
int pwd_check(void);

#endif //KREMFIP_LIB_H
