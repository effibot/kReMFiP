//
// Created by effi on 13/09/24.
//

#include "pathmgm.h"
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

// Define a vector of invalid system paths
static const char *invalid_paths[INVALID_PATHS_NUM] = { "/home/effi/file_i.txt", "boot",	"dev",	"etc",
														"lib", "lib64", "proc", "root",
														"run", "sbin",	"sys" };

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
	int ret;
	ret = kern_path(path, LOOKUP_FOLLOW, &p);

	INFO("kern_path returned %d\n", ret);

	if (ret) {
		return false;
	}
	INFO("found path %p", p.dentry->d_name.name);
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

	// Check for empty path
	if (len == 0) {
		WARNING("Empty path\n");
		return false;
	}

	// Check for paths like . or .. - we want the user to specify the full path
	if (strcmp(path, ".") == 0 || strcmp(path, "..") == 0) {
		WARNING("Path starts with . or ..\n");
		return false;
	}

	// Check for double slashes
	if (strstr(path, "//") != NULL) {
		WARNING("Double slashes in the path\n");
		return false;
	}

	// Check for / directory
	if (strcmp(path, "/") == 0) {
		WARNING("Root directory\n");
		return false;
	}

	/* Now we want to avoid some system paths, listed in pathmgm.h.
	 * Is sufficient to check if the first part of the path is in the list, so we need
	 * to split the path in the first part and the rest. We need to take care of the
	 * first slash, during the split.
	 */
	// Make a copy of the path
	char *path_copy = kstrdup(path, GFP_KERNEL);
	if (unlikely(path_copy == NULL)) {
		WARNING("Failed to allocate memory for the path copy\n");
		return false;
	}
	if (path_copy[0] == '/') {
		// Skip the first slash
		path_copy++;
	}
	// Split the path
	char *first_part = strsep(&path_copy, "/");
	printk("obtain first part: %s\n", first_part);
	printk("from path: %s\n", path);
	// Check if the first part is in the list
	int i;
	for (i = 0; i < INVALID_PATHS_NUM; i++) {
		if (strcmp(first_part, invalid_paths[i]) == 0) {
			WARNING("Invalid path\n");
			kfree(path_copy);
			return false;
		}
	}

	kfree(path_copy);
	return true;
}
