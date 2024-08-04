//
// Created by effi on 04/08/24.
//

#ifndef MODNAME
#define MODNAME "kremfip_module"
#endif

#ifndef RMFS_H
#define RMFS_H

typedef enum _rm_state_t {
    OFF = 0,
    ON = 1,
    REC_OFF = 2,
    REC_ON = 3,
} rm_state_t;

// Define the reference monitor structure
typedef struct _rm_t {
    const char *name;                 // Name of the reference monitor
    rm_state_t state;                    // State of the reference monitor
    //TODO: list of protected paths
    const int *blocked_modes;          // List of blacklisted modes - not used
    const int *allowed_modes;          // List of whitelisted modes
    const char *hooked_functions;        // List of hooked functions
    struct kobject kobj;              // kobject for the reference monitor
    unsigned id;                           // ID of the reference monitor
} rmfs_t;

// Define function prototypes
rmfs_t *rm_init(void);
int rm_free(rmfs_t *rm);

#endif //RMFS_H
