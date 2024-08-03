#ifndef UTILS_H
#define UTILS_H

#include <linux/version.h>

#include "types.h"


// Define a macro to get the uid/euid of the current process
#define get_uid()              current->cred->uid.val
#define get_euid()             current->cred->euid.val
// Define a macro to set the uid/euid of the current process
#define set_uid(uid)           current->cred->uid.val = uid
#define set_euid(euid)         current->cred->euid.val = euid
// Define a macro to get the pid of the current process
#define get_pid()              current->pid


// Define a macro to get major and minor numbers of a device file
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
#define get_major(session)      MAJOR(session->f_inode->i_rdev)
#define get_minor(session)      MINOR(session->f_inode->i_rdev)
#else
#define get_major(session)      MAJOR(session->f_dentry->d_inode->i_rdev)
#define get_minor(session)      MINOR(session->f_dentry->d_inode->i_rdev)
#endif







// Initialize a reference monitor structure

static rmfs_t *rm_init(void);


// Free a reference monitor structure
static int rm_free(rmfs_t *rm);


#endif