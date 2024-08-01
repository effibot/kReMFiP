#ifndef TYPES_H
#define TYPES_H


#include <sys/types.h> // for mode_t

// We need to define the function to bee hooked by the reference monitor

// check which kernel version you are using and change the function name accordingly

#include <linux/version.h>
//#if LINUX_VERSION_CODE >= KERNEL_VERSION


/*
 * Since we want to block every mode but the read-only one, we just define a whitelist of modes that are allowed.
 */

static const mode_t* wl_mode_t = O_RDONLY;

// The actual list of blacklisted modes could be something like this:
/* static const mode_t* bl_mode_t = {
        O_WRONLY, // Write-only
        O_RDWR, // Read-write
        O_CREAT, // Create
        O_APPEND, // Append
        O_TRUNC, // Truncate
        O_EXCL, // Exclusive
        O_SYNC, // Synchronous
        O_DSYNC, // Data-synchronous
        O_RSYNC, // Read-synchronous
        O_NONBLOCK, // Non-blocking
        O_CLOEXEC, // Close-on-exec
        O_DIRECT, // Direct
        O_DIRECTORY, // Directory
        O_NOFOLLOW, // No-follow
        O_NOATIME, // No-atime
        O_PATH, // Path
        O_TMPFILE, // Temporary file
        O_ASYNC, // Asynchronous
        O_LARGEFILE, // Large file
        O_NOCTTY, // No-controlling-terminal
   } */


typedef struct _rm_struct_t {
	//TODO: list of protected paths
	// blacklisted modes
	mode_t *mode;
} rm_struct_t;

#endif