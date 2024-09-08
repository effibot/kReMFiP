

#ifndef RMFS_H
#define RMFS_H

#include "ht_dllist.h"
#include "state.h"
#include <linux/module.h>

// define constants for files management
#define RM_INIT_STATE REC_ON
#define RMFS_DEFAULT_NAME "rmfs"
// define constants for password management
#ifndef RM_PWD_MAX_LEN
#define RM_PWD_MAX_LEN 128
#endif

#ifndef RM_PWD_MIN_LEN
#define RM_PWD_MIN_LEN 8
#endif

#ifndef RM_PWD_SALT_LEN
#define RM_PWD_SALT_LEN 16
#endif

#ifndef RM_PWD_HASH_LEN
#define RM_PWD_HASH_LEN 32
#endif

typedef struct _rm_t {
	const char *name; // Name of the reference monitor
	rm_state_t state; // State of the reference monitor
	ht_t *ht; // Hash table for the reference monitor
	const int *blocked_modes; // List of blacklisted modes - not used
	const int *allowed_modes; // List of whitelisted modes
	const char *hooked_functions; // List of hooked functions
	unsigned int id; // ID of the reference monitor
	//TODO: file system
	struct workqueue_struct *wq; // Workqueue for the reference monitor
	struct work_struct work; // Work structure for the reference monitor
	struct kobject *kobj; // Kobject for the reference monitor
} rm_t;

#define to_monitor_from_kobj(kobj) container_of(kobj, rm_t, kobj)

// Define function prototypes
rm_t *rm_init(void);
int set_state(rm_t *rm, rm_state_t state);
rm_state_t get_state(const rm_t *rm);
void rm_free(const rm_t *rm);
bool verify_pwd(const char *input_str);
#endif //RMFS_H
