/**
 * @file rm_syscalls.c
 * @brief Source Code for the module's system calls
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include "../include/kremfip.h"
#include "../include/misc.h"
#include "../include/rm.h"
#include "rm_syscalls.h"
#include <linux/uaccess.h>
// Reference monitor pointer
extern rm_t *rm_p;

/**
 * @brief System call to get the current state of the reference monitor
 * @return the current state of the reference monitor
 */
int rm_state_get(rm_state_t *u_state) {
	// Check if the reference monitor is initialized
	if (unlikely(rm_p == NULL)) {
#ifdef DEBUG
		WARNING("Passing a NULL reference monitor to the system call\n");
#endif
		return -EINVAL;
	}
	// access to the kernel space where the reference monitor is stored
	rm_state_t state;
	int ret;
	state = get_state(rm_p);
	ret = copy_to_user(u_state, &state, sizeof(rm_state_t));
	if (ret < 0) {
		return -EFAULT;
	}
	return ret;
}

/**
 * @brief System call to set the state of the reference monitor.
 * The state can be in one of the four states defined in state.h.
 * If the state is of reconfigurable type (REC_x), then we need to check
 * the monitor's pwd hash.
 * @param state the new state of the reference monitor
 * @return 0 on success, -1 on error
 */
