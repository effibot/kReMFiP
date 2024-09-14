//
// Created by effi on 13/09/24.
//

#include "pathmgm.h"
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/string.h>
#include <linux/uaccess.h>
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
	if (ret) {
		return false;
	}
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
		INFO("Empty path\n");
		return false;
	}

	// Check for root path
	if (strcmp(path, "/") == 0) {
		INFO("Root path\n");
		return false;
	}

	// Check for paths like . or ..
	if (strcmp(path, ".") == 0 || strcmp(path, "..") == 0) {
		INFO("Path starts with . or ..\n");
		return false;
	}

	// Check for double slashes
	if (strstr(path, "//") != NULL) {
		INFO("Double slashes in the path\n");
		return false;
	}

	return true;
}