
/**
 * @file rmfs.c
 * @author Andrea Efficace (andrea.efficace1@gmail.com)
 * @brief Implementation of the reference monitor as a folder under /sys/kernel
 * We provide show/store operations and initialization functions for the reference monitor structure
 * @version 0.1
 * @date 2024-08-03
 *
 * @copyright Copyright (c) 2024
 *
 */


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/namei.h>
#include "rmfs.h"
#include "utils.h"

#define DEBUG 1


// Define the reference monitor instance

rm_t *rm_init(void) {
	// Allocate memory for the reference monitor
	rm_t *rm = kzalloc(sizeof(rm), GFP_KERNEL);
	if (unlikely(rm == NULL)) {
		INFO("Failed to allocate memory for the reference monitor");
		return NULL;
	}
	// Set the default values
	rm->name = RMFS_DEFAULT_NAME;
	rm->state = RM_INIT_STATE;
	rm->id = rnd_id();
	// Initialize the hash table
	INFO("initializing the hash table");
	rm->ht = ht_create(HT_SIZE);
	if (unlikely(rm->ht == NULL)) {
		INFO("Failed to initialize the hash table");
		kfree(rm);
		return NULL;
	}
	INFO("Hash table initialized");
	return rm;
}
// Free the reference monitor instance






/****************************************************
 * Define the reference monitor functions
 ****************************************************/

int set_state(rm_t *rm, rm_state_t state) {
	// check if the state is valid
	if (!is_state_valid(state)) {
		INFO("Trying to set an invalid state - %s is given", state_to_str(state));
		goto error;
	}
#ifdef DEBUG
	INFO("Setting state to %s", state_to_str(state));
#endif
	// set the state
	rm->state = state;

	return 0;

error:
	return -EINVAL;
}



rm_state_t get_state(rm_t *rm) {
	// assert that the reference monitor is not NULL
	if (rm == NULL) {
		INFO("Reference monitor is NULL");
		return -EINVAL;
	}
	// return the state
	return rm->state;
}

void rm_free(rm_t *rm) {
	// assert that the reference monitor is not NULL
	if (rm == NULL) {
		INFO("Reference monitor is NULL");
		return;
	}
	// free the hash table
	ht_destroy(rm->ht);
	// free the reference monitor
	kfree(rm);
}



