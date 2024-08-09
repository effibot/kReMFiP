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
    struct kobject rm_kobj, *rm_kobj_p;              // kobject for the reference monitor
    struct kset rm_kset, *rm_kset_p;                 // kset for the reference monitor
    unsigned int id;                           // ID of the reference monitor
}__randomize_layout rmfs_t;
#define to_rfmfs_obj(x) container_of(x, rmfs_t, rm_kobj)

// Define the attribute structure for reference monitor state
typedef struct _rm_attribute_t {
    struct attribute attr;
    ssize_t (*show)(rmfs_t *rm, struct _rm_attribute_t *attr, char *buf);
    ssize_t (*store)(rmfs_t *rm, struct _rm_attribute_t *attr, const char *buf, size_t count);
}__randomize_layout rm_attr_t;
#define to_rm_attr(x) container_of(x, rm_attr_t, attr)

// Define function prototypes
rmfs_t* rm_init(void);
int set_state(rmfs_t *rm, rm_state_t state);
rm_state_t get_state(void);
void rm_display(const rmfs_t *rm);

// Attribute function prototypes
static ssize_t rm_attr_show(struct kobject *kobj, struct attribute *attr, char *buf);
static ssize_t rm_attr_store(struct kobject *kobj, struct attribute *attr, const char *buf, size_t count);
static void rm_release(struct kobject *kobj);
// State function prototypes
static ssize_t state_show(rmfs_t *rmfs, rm_attr_t *attr, char *buf);
static ssize_t state_store(rmfs_t *rmfs, rm_attr_t *attr, const char *buf, size_t count);



// define constants for files management
#define RMFS_STATE_FILE "/sys/kremfip/state"
#define RMFS_STATE_FILE_MODE 0644
#define RMFS_INIT_STATE OFF
#define RMFS_STATE_FILE_SIZE 2
#define RMFS_DEFAULT_NAME "kremfip"



#endif //RMFS_H
