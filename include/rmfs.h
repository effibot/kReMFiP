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


// Default structure for the objects in the reference monitor sysfs
typedef struct _rm_kobj_t {
    struct kobject kobj; // reference to a kernel object
    const char* name;   // name of the kernel object
    const char* type;   // type of the kernel object - directory or file
    const char* content; // content of the file represented by the kernel object in the sysfs
} rm_kobj_t;
#define to_rm_kobj(x) container_of(x, rm_kobj_t, kobj)

typedef struct _rm_kset_t {
    struct kset kset; // reference to a kernel set
    const char* name; // name of the kernel set
} rm_kset_t;
#define to_rm_kset(x) container_of(x, rm_kset_t, kset)

// Define the attribute structure for reference monitor sysfs

typedef struct _rm_attribute_t {
    struct attribute attr;
    ssize_t (*show)(rm_kobj_t *rm_kobj, struct _rm_attribute_t *attr, char *buf);
    ssize_t (*store)(rm_kobj_t *rm_kobj, struct _rm_attribute_t *attr, const char *buf, size_t count);
} rm_attr_t;
#define to_rm_attr(x) container_of(x, rm_attr_t, attr)


// Define the reference monitor structure

typedef struct _rm_t {
    const char *name;                 // Name of the reference monitor
    rm_state_t state;                  // State of the reference monitor
    //TODO: list of protected paths
    const int *blocked_modes;          // List of blacklisted modes - not used
    const int *allowed_modes;          // List of whitelisted modes
    const char *hooked_functions;        // List of hooked functions
    struct rm_kobj_t *rm_kobj_p;              // kobject for the reference monitor
    struct rm_kset_t *rm_kset_p;                 // kset for the reference monitor
    unsigned int id;                           // ID of the reference monitor
} rmfs_t;
#define to_rmfs_obj(x) \
    ({ \
        typeof(x) _x = (x); \
        rmfs_t *_rmfs; \
        if (_x->kobj.parent) { \
            _rmfs = container_of(_x, rmfs_t, rm_kobj_p); \
        } else { \
            _rmfs = container_of(_x, rmfs_t, rm_kset_p); \
        } \
        _rmfs; \
    })
// Define function prototypes
rmfs_t* rm_init(void);
int set_state(rmfs_t *rm, rm_state_t state);
rm_state_t get_state(rmfs_t *rm);
void rm_display(const rmfs_t *rm);

// define constants for files management
#define RMFS_INIT_STATE OFF
#define RMFS_DEFAULT_NAME "kremfip"

#endif //RMFS_H
