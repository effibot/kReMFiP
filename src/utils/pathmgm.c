//
// Created by effi on 13/09/24.
//

#include "pathmgm.h"
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/kernel.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
// Define a vector of invalid system paths
static const char *invalid_paths[] = { "/run", "/var", "/tmp", "/dev", "/proc", "/etc", "/sys" };

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
 * @brief Check if the given path is valid for the reference monitor.
 * We assume that the path is an absolute path, so the system has already resolved it and check if
 * it exists. This means that no control on the structure of the path is needed.
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
	// if the path belongs to some system mount point, return false
	for (int i = 0; i < INVALID_PATHS_NUM; i++) {
		if (str_has_prefix(path, invalid_paths[i]) > 0) {
			return false;
		}
	}

	return true;
}
/**
 *
 * @param path the path to resolve.
 * Path must exist on the disk, we return an error otherwise
 * @param abs_path the buffer where the absolute path will be stored
 * @return error codes or 0 upon success
 */
int get_abs_path(const char *path, char *abs_path) {
	if (unlikely(path == NULL)) {
		WARNING("Path is NULL\n");
		return -EINVAL;
	}

	struct path path_struct;
	int ret = kern_path(path, LOOKUP_FOLLOW, &path_struct);
	if (ret) {
#ifdef DEBUG
		WARNING("Unable to resolve the path, fallback\n");
#endif
		ret = -ENOENT;
		goto not_found;
	}

	char *tmp_path = kzalloc(PATH_MAX * sizeof(char), GFP_KERNEL);
	if (unlikely(tmp_path == NULL)) {
		WARNING("Unable to allocate memory for the path\n");
		ret = -ENOMEM;
		goto out_path_put;
	}
	char *resolved_path = d_path(&path_struct, tmp_path, PATH_MAX);
	if (IS_ERR(resolved_path)) {
		ret = -ENOENT;
		goto out_free;
	}
	// terminate the string, just to be sure
	*(resolved_path + strlen(resolved_path)) = '\0';

	ret = (int)strscpy(abs_path, resolved_path, PATH_MAX);
	if (ret <= 0) {
		WARNING("Unable to copy the resolved path\n");
		ret = -ENOMEM;
	}
	ret = ret <= 0 ? ret : 0;
out_free:
	kfree(tmp_path);
out_path_put:
	path_put(&path_struct);
not_found:
	return ret;
}

int get_abs_path_user(const int dfd, const __user char *user_path, char *abs_path) {
	if (unlikely(user_path == NULL)) {
		WARNING("Path is NULL\n");
		return -EINVAL;
	}
	struct path path_struct;
	int ret = user_path_at(dfd, user_path, LOOKUP_FOLLOW, &path_struct);
	if (ret) {
		//ret = -ENOENT;
		goto not_found;
	}
	// Allocate temporary buffer to store the path
	// heap allocation because PATH_MAX could be too large for the stack
	char *tmp_path = kzalloc(PATH_MAX * sizeof(char), GFP_KERNEL);
	if (!tmp_path) {
		WARNING("Unable to allocate memory for the path\n");
		ret = -ENOMEM;
		goto out_path_put;
	}
	// Convert to a string
	char *resolved_path = d_path(&path_struct, tmp_path, PATH_MAX);
	if (IS_ERR(resolved_path)) {
		ret = -ENOENT;
		goto out_free;
	}
	// terminate the string, just to be sure
	*(resolved_path + strlen(resolved_path)) = '\0';
	// Copy the resolved absolute path into the output buffer
	ret = (int)strscpy(abs_path, resolved_path, PATH_MAX);
	if (ret <= 0) {
		WARNING("Unable to copy the resolved path\n");
	}
	ret = ret <= 0 ? ret : 0;
out_free:
	kfree(tmp_path);
out_path_put:
	path_put(&path_struct);
not_found:
	return ret;
}

int get_dir_path(const char *path, char *dir_path) {
	int ret = 0;
	char *tmp_path = NULL;

	if (unlikely(path == NULL)) {
		WARNING("Path is NULL\n");
		ret = -EINVAL;
		goto out;
	}

	// Copy the path to a temporary buffer
	tmp_path = kzalloc(PATH_MAX * sizeof(char), GFP_KERNEL);
	if (unlikely(tmp_path == NULL)) {
		WARNING("Unable to allocate memory for the path\n");
		ret = -ENOMEM;
		goto out;
	}
	ret = (int)strscpy(tmp_path, path, PATH_MAX);
	if (ret <= 0) {
		WARNING("Unable to copy the path\n");
		ret = -ENOMEM;
		goto out_free;
	}
	// reduce memory overhead by reallocating the buffer
	tmp_path = krealloc(tmp_path, strlen(tmp_path) + 1, GFP_KERNEL);
	/* Find the last occurrence of the directory separator:
	 * We could have three cases:
	 * 1. path = "/path/to/dir/file" ->  we need to find the last occurrence of the separator
	 * 2. path = "dir/file" -> we need to find the first occurrence of the separator
	 * 3. path = "file" -> we need to return the current directory
	 */
	const char *last_sep = strrchr(tmp_path, '/');

	if (last_sep) {
		// calculate the length +1 so that the copy include the null-terminator
		const size_t len = last_sep - tmp_path +1;
		// null-terminate the temp path to the last sep
		*(tmp_path + len) = '\0';
		// copy
		ret = (int)strscpy(dir_path, tmp_path, PATH_MAX);
		if (ret <= 0) {
			WARNING("Unable to copy the path\n");
			goto out_free;
		}
	} else {
		// If no separator is found, return the current directory
		const char * cwd = get_cwd();
		ret = (int)strscpy(dir_path, cwd, PATH_MAX);
		if (ret <= 0) {
			WARNING("Unable to copy the path\n");
			goto out_free;
		}
	}
	ret = 0;
out_free:
	kfree(tmp_path);
out:
	return ret;
}

char *get_cwd(void) {
	// We use 'current' to get the current task, so no need manage it
	const struct task_struct *task = current;
	// Get the current working directory
	struct path pwd_path;
	get_fs_pwd(task->fs, &pwd_path);
	// Get the path from the dentry, recursively from the end to the root
	char *pwd = kzalloc(PATH_MAX * sizeof(char), GFP_KERNEL);
	if (unlikely(pwd == NULL)) {
		WARNING("Unable to allocate memory for the path\n");
		return NULL;
	}
	char *pwd_path_str = dentry_path_raw(pwd_path.dentry, pwd, PATH_MAX);
	if (IS_ERR(pwd_path_str)) {
		WARNING("Unable to get the path\n");
		kfree(pwd);
		return NULL;
	}
	// Release the path
	path_put(&pwd_path);
	kfree(pwd);
	pwd_path_str = krealloc(pwd_path_str, strlen(pwd_path_str) + 1, GFP_KERNEL);
	return pwd_path_str;
}

bool is_dir(const char *path) {
	struct path path_struct;

	const int error = kern_path(path, LOOKUP_FOLLOW, &path_struct);
	if (error) {
		WARNING("Unable to resolve the path %s\n", path);
		return -1;
	}
	struct inode *inode = path_struct.dentry->d_inode;
	const bool is_dir = S_ISDIR(inode->i_mode);
	path_put(&path_struct);
	return is_dir;
}

bool is_file(const char *path) {
	struct path p;
	// Resolve the path to a struct path
	if (kern_path(path, LOOKUP_FOLLOW, &p) != 0) {
		WARNING("Unable to resolve the path\n");
		return false;
	}
	// Get the inode from the dentry
	const struct inode *inode = p.dentry->d_inode;
	// Check if the inode represents a regular file
	const bool is_regular_file = S_ISREG(inode->i_mode);
	// Release the path
	path_put(&p);
	return is_regular_file;
}

bool is_symlink(const char *path) {
	struct path p;
	const int ret = kern_path(path, LOOKUP_FOLLOW, &p);
	if (ret) {
		WARNING("Unable to resolve the path\n");
		return false;
	}
	const struct dentry *dentry = p.dentry;
	const bool is_symlink = S_ISLNK(dentry->d_inode->i_mode);
	path_put(&p);
	return is_symlink;
}
