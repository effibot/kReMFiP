#ifndef MODNAME
#define MODNAME "kremfip_module"
#endif

#ifndef RMFS_H
#define RMFS_H

#include <linux/kobject.h>

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
}__randomize_layout rmfs_t;

// Define function prototypes
rmfs_t* rm_init(void);
int rm_free(rmfs_t *rm);
int set_state(rmfs_t *rm, rm_state_t state);
rm_state_t get_state(void);
void rm_display(rmfs_t *rm);

// define constants for files management
#define RMFS_STATE_FILE "/sys/kremfip/state"
#define RMFS_STATE_FILE_MODE 0644
#define RMFS_INIT_STATE OFF
#define RMFS_STATE_FILE_SIZE 2
#define RMFS_DEFAULT_NAME "kremfip"



#endif //RMFS_H
