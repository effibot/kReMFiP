//
// Created by effi on 13/09/24.
//

#include "pathmgm.h"
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/dcache.h>
#include <linux/path.h>


// Define a vector of invalid system paths
static const char *invalid_paths[INVALID_PATHS_NUM] = {
	"bin",	"boot", "cdrom", "dev",	 "etc", "lib",		"lib64", "mnt", "opt", "proc",
	"root", "run",	"sbin",	 "snap", "srv", "swapfile", "sys",	 "usr", "var"
};

/**
 * @brief Checks if the path exists in the filesystem
 * We use the `kern_path` function to check if the path exists.
 * If the path exists, the kernel allocate a `struct path` object and increments the reference count.
 * Since we don't need the object, we call `path_put` to decrement the reference count.
 * @param path The path to check
 * @return true if the path is a directory, false otherwise
 */
bool path_exists(const char *path) {
	struct path p;
	const int ret = kern_path(path, LOOKUP_FOLLOW, &p);
	if (ret) {
		return false;
	}
#ifdef DEBUG
	INFO("found path %s", (char *)p.dentry->d_name.name);
#endif
	path_put(&p);
	return true;
}

/**
 * @name is_valid_path
 * @brief Check if the path is valid.
 * @param path - the path to be checked
 * @return true if the path is valid, false otherwise
 */
bool is_valid_path(const char *path) {
	if (unlikely(path == NULL)) {
#ifdef DEBUG
		INFO("Passing null path (%p)\n", path);
#endif
		return false;
	}

	const size_t len = strlen(path);

	// Check for empty path, root directory, or paths like . or ..
	if (len == 0 || strcmp(path, "/") == 0 || strcmp(path, ".") == 0 || strcmp(path, "..") == 0) {
		WARNING("Invalid path: empty, root, or relative path\n");
		return false;
	}

	// Check for double slashes
	if (strstr(path, "//") != NULL) {
		WARNING("Double slashes in the path\n");
		return false;
	}

	// Check if the mount point or full path is in the list of invalid paths
	for (int i = 0; i < INVALID_PATHS_NUM; i++) {
		if (strcmp(path, invalid_paths[i]) == 0 ||
			(path[0] == '/' && strcmp(path + 1, invalid_paths[i]) == 0)) {
			WARNING("Invalid path or mount point\n");
			return false;
		}
	}

	return true;
}


int get_abs_path(const char *path, char *abs_path) {
	if (unlikely(path == NULL)) {
		WARNING("Path is NULL\n");
		return -EINVAL;
	}

	struct path p;
	// let the kernel resolves the path
	const int ret = kern_path(path, LOOKUP_FOLLOW, &p);
	if (ret) {
		WARNING("Unable to resolve the path\n");
		return ret;
	}
	// Allocate temporary buffer to store the path
	char *tmp_path = kmalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(tmp_path == NULL)) {
		WARNING("Unable to allocate memory for the path\n");
		// release the path
		path_put(&p);
		return -ENOMEM;
	}
	// Get the absolute path -- d_path lets us get the path from the root
	const char *resolved_path = d_path(&p, tmp_path, PATH_MAX);
    if (IS_ERR(resolved_path)) {
        kfree(tmp_path);
        path_put(&p); // Release the path on failure
        return -ENOENT;
    }
	// Copy the resolved absolute path into the output buffer
    strncpy(abs_path, resolved_path, PATH_MAX);

    // Clean up
    kfree(tmp_path);
    path_put(&p); // Release the path
	return 0;
}

bool is_dir(const char *path) {
	struct kstat stat;
	if (unlikely(vfs_stat(path, &stat) != 0)) {
		WARNING("Unable to get the stat of the path\n");
		return false;
	}
	return S_ISDIR(stat.mode);
}
