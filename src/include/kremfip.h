/**
* @file kremfip.h
* @brief General header file for the kernel-side stuff of the kReMFiP project
* This file contains the definitions of some constants that have to be shared between the
*/
#ifndef KREMFIP_H
#define KREMFIP_H

#include "constants.h"
#define DEBUG

#ifdef __KERNEL__
/* Kernel Module Header Section */

// System Calls Prototypes Internal Functions
int rm_state_get(state_t __user *u_state);
int rm_state_set(const state_t __user *u_state);
int rm_reconfigure(const path_op_t __user *op, const char __user *path);
int rm_pwd_check(const char __user *pwd);
#else
/* User Space Header Section */

/* Userspace System Calls Stubs */

char *prompt_for_pwd(void);
int state_get(state_t *u_state);
int state_set(state_t *state);
int reconfigure(const path_op_t *op, const char *path);
int pwd_check(void);

#endif

#endif //KREMFIP_H
