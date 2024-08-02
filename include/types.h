#ifndef TYPES_H
#define TYPES_H


#include <linux/types.h> // for mode_t
#include <linux/fs.h> // for struct file
#include <linux/fcntl.h> // for O_RDONLY
// Your existing code
// We need to define the function to bee hooked by the reference monitor

// TODO: check which kernel version you are using and change the function name accordingly
// using #include <linux/version.h> and #if LINUX_VERSION_CODE >= KERNEL_VERSION(?, 0, 0)
static const char *hooked_functions[] = {"vfs_open"};

/*
 * Since we want to block every mode but the read-only one,
 * we just define an allowed list of modes that are allowed.
 */

static const int* al_mode_t = O_RDONLY;

// The actual list of blocked modes could be something like this:
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


// Define a structure to represent the protected paths
typedef struct _path_t {
        char *path; // Path to be protected

} path_t;

// Define the reference monitor structure
typedef struct _rm_t {
	//TODO: list of protected paths
	const int *blocked_modes;          // List of blacklisted modes - not used
	const int *allowed_modes;          // List of whitelisted modes
	const char **hooked_functions;        // List of hooked functions

} rm_t;

// Define a list of reference monitor structures
typedef struct _rm_lst_t {
	const rm_t *head;
	rm_t *next;
} rm_lst_t;


#endif