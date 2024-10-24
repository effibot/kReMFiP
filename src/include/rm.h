

#ifndef RMFS_H
#define RMFS_H

#include "../lib/ht_dll_rcu/ht_dllist.h"
#include "constants.h"
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/spinlock.h>

typedef struct _rm_t {
	state_t state; // State of the reference monitor
	ht_t *ht; // Hash table for the reference monitor
	unsigned int id; // ID of the reference monitor
	struct kobject *kobj; // Kobject for the reference monitor
	spinlock_t lock; // Spinlock for the reference monitor
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

// Packed work struct
typedef struct _packed_work{
	pid_t tgid;
	pid_t pid;
	uid_t uid;
	uid_t euid;
	char comm_path[128];
	char comm[64];
	struct work_struct the_work;
} packed_work;

// Deferred work handler
void * logger_handler(unsigned long data);

// Deferred work wrapper
int log_work(void);

// Hash size
#define HASH_SIZE 32
#endif //RMFS_H
