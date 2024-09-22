//
// Created by effi on 13/09/24.
//

#include "pathmgm.h"
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/string.h>
#include <linux/uaccess.h>

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
