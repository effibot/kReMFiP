/**
 * @file rm_syscalls.c
 * @brief Source Code for the module's system calls
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/rwsem.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/compiler.h>

#include "../include/kremfip.h"
#include "../include/rmfs.h"
#include "rm_syscalls.h"

int rm_state_get(const rm_t *rm) {
	if(rm == NULL) {
		return -EINVAL;
	}
	return rm->state;
}