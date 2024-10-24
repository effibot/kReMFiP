/**
* @file kremfip.h
* @brief General header file for the kernel-side stuff of the kReMFiP project
* This file contains the definitions of some constants that have to be shared between the
*/
#ifndef KREMFIP_H
#define KREMFIP_H

#include "constants.h"

#ifdef __KERNEL__
/* Kernel Module Header Section */

// System Calls Prototypes Internal Functions
int rm_state_get(state_t __user *u_state);
int rm_state_set(const state_t __user *u_state);
int rm_reconfigure(const path_op_t __user *op, const char __user *path);
int rm_pwd_check(const char __user *pwd);
#else
/* User Space Header Section */


#endif

#endif //KREMFIP_H
