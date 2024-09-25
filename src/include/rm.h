

#ifndef RMFS_H
#define RMFS_H

#include "../lib/ht_dll_rcu/ht_dllist.h"
#include "constants.h"
#include <linux/module.h>
#include <linux/kprobes.h>

typedef struct _rm_t {
	const char *name; // Name of the reference monitor
	state_t state; // State of the reference monitor
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
int set_state(rm_t *rm, state_t state);
state_t get_state(const rm_t *rm);
void rm_free(const rm_t *rm);
bool is_protected(const char* path);
// Kernel Probes Functions
int rm_open_pre_handler(struct kprobe *ri, struct pt_regs *regs);
int rm_mkdir_pre_handler(struct kprobe *ri, struct pt_regs *regs);
int rm_rmdir_pre_handler(struct kprobe *ri, struct pt_regs *regs);
int rm_unlink_pre_handler(struct kprobe *ri, struct pt_regs *regs);

// Define support struct for kernel probes functions

// From linux/fs/internal.h
struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};

#endif //RMFS_H
