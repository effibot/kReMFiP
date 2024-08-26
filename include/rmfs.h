

#ifndef RMFS_H
#define RMFS_H

#include <linux/module.h>
#include <linux/crypto.h>
#include "ht_dllist.h"

// define constants for files management
#define RM_INIT_STATE OFF
#define RMFS_DEFAULT_NAME "rmfs"
// define constants for password management
#define RM_PWD_MAX_LEN 128
#define RM_PWD_MIN_LEN 8
#define RM_PWD_SALT_LEN 16
#define RM_PWD_HASH_LEN 32



typedef enum _rm_state_t {
    OFF = 0,
    ON = 1,
    REC_OFF = 2,
    REC_ON = 3,
} rm_state_t;

// Define the attribute structure for reference monitor sysfs

typedef struct _rm_t {
    const char *name;                 // Name of the reference monitor
    rm_state_t state;                  // State of the reference monitor
    ht_t *ht;                           // Hash table for the reference monitor
    const int *blocked_modes;          // List of blacklisted modes - not used
    const int *allowed_modes;          // List of whitelisted modes
    const char *hooked_functions;        // List of hooked functions
    unsigned int id;                           // ID of the reference monitor
    //TODO: file system
    struct workqueue_struct *wq;        // Workqueue for the reference monitor
    struct work_struct work;            // Work structure for the reference monitor
    struct kset *rm_kset;                  // Kset for the reference monitor
} rm_t;





// Define function prototypes
rm_t* rm_init(void);
int set_state(rm_t *rm, rm_state_t state);
rm_state_t get_state(const rm_t *rm);
void rm_free(const rm_t *rm);



#endif //RMFS_H
