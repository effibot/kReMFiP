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
static const char *invalid_paths[INVALID_PATHS_NUM] = {
	"/bin",	 "/boot", "/cdrom", "/dev",	 "/etc", "/lib",	  "/lib64", "/mnt", "/opt", "/proc",
	"/root", "/run",  "/sbin",	"/snap", "/srv", "/swapfile", "/sys",	"/usr", "/var", "/tmp"
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
#ifdef DEBUG
		WARNING("Invalid path: empty, root, or relative path\n");
#endif
		return false;
	}

	// Check for double slashes
	if (strstr(path, "//") != NULL) {
#ifdef DEBUG
		WARNING("Double slashes in the path\n");
#endif
		return false;
	}

	// Check if the mount point or full path is in the list of invalid paths
	for (int i = 0; i < INVALID_PATHS_NUM; i++) {
		if (strcmp(path, invalid_paths[i]) == 0) {
#ifdef DEBUG
			WARNING("Invalid path or mount point\n");
#endif
			return 0;
		}
	}
	if (path[0] == '/') {
		const char *first_slash = strchr(path + 1, '/');
		if (first_slash) {
			const size_t mnt_point_len = first_slash - path;
			const char *mnt_point = kstrndup(path, mnt_point_len, GFP_KERNEL);
			for (int i = 0; i < INVALID_PATHS_NUM; i++) {
				if (strncmp(mnt_point, invalid_paths[i], mnt_point_len) == 0) {
#ifdef DEBUG
					WARNING("Invalid path or mount point\n");
#endif
					kfree(mnt_point);
					return 0;
				}
			}
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
	char *tmp_path = NULL;
	int ret = kern_path(path, LOOKUP_FOLLOW, &p);
	if (ret) {
		WARNING("Unable to resolve the path\n");
		ret = -ENOENT;
		if (strscpy(abs_path, PATH_NOT_FOUND, PATH_MAX) != strlen(PATH_NOT_FOUND)) {
			WARNING("Unable to copy the path not found message\n");
			ret = -ENOMEM;
		}
		return ret;
	}

	tmp_path = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(tmp_path == NULL)) {
		WARNING("Unable to allocate memory for the path\n");
		ret = -ENOMEM;
		goto out_path_put;
	}

	const char *resolved_path = d_path(&p, tmp_path, PATH_MAX);
	if (IS_ERR(resolved_path)) {
		ret = -ENOENT;
		goto out_free;
	}

	ret = (int)strscpy(abs_path, resolved_path, PATH_MAX);
	if (ret <= 0) {
		WARNING("Unable to copy the resolved path\n");
		ret = -ENOMEM;
	}

out_free:
	kfree(tmp_path);
out_path_put:
	path_put(&p);
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
		ret = -ENOENT;
		WARNING("Unable to resolve the path\n");
		if (strscpy(abs_path, PATH_NOT_FOUND, PATH_MAX) != strlen(PATH_NOT_FOUND)) {
			WARNING("Unable to copy the path not found message\n");
			ret = -ENOMEM;
		}
		return ret;
	}
	// Allocate temporary buffer to store the path
	char *tmp_path = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(tmp_path == NULL)) {
		WARNING("Unable to allocate memory for the path\n");
		ret = -ENOMEM;
		goto out_path_put;
	}
	// Convert to a string
	const char *resolved_path = d_path(&path_struct, tmp_path, PATH_MAX);
	if (IS_ERR(resolved_path)) {
		ret = -ENOENT;
		goto out_free;
	}
	// Copy the resolved absolute path into the output buffer
	ret = (int)strscpy(abs_path, resolved_path, PATH_MAX);
	if (ret <= 0) {
		WARNING("Unable to copy the resolved path\n");
		ret = -ENOMEM;
	}
out_free:
	kfree(tmp_path);
out_path_put:
	path_put(&path_struct);
	return ret;
}

bool is_dir(const char *path) {
	struct path p;
	const int ret = kern_path(path, LOOKUP_FOLLOW, &p);
	if (ret) {
		WARNING("Unable to resolve the path\n");
		return false;
	}
	const struct dentry *dentry = p.dentry;
	const bool is_directory = S_ISDIR(dentry->d_inode->i_mode);
	path_put(&p);
	return is_directory;
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

int get_dir_path(const char *path, char *dir_path) {
	if (unlikely(path == NULL)) {
		WARNING("Path is NULL\n");
		return -EINVAL;
	}
	// Get the length of the path
	const size_t len = strlen(path);
	if (unlikely(len == 0)) {
		WARNING("Path is empty\n");
		return -EINVAL;
	}
	// Allocate temporary buffer to store the path
	char *tmp_path = kmalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(tmp_path == NULL)) {
		WARNING("Unable to allocate memory for the path\n");
		return -ENOMEM;
	}
	// Copy the path into the temporary buffer
	if (strscpy(tmp_path, path, PATH_MAX) <= 0) {
		WARNING("Unable to copy the path\n");
		kfree(tmp_path);
		return -EINVAL;
	}
	// Get the last element of the path
	char *last = strrchr(tmp_path, '/');
	if (unlikely(last == NULL)) {
		WARNING("Unable to find the last element of the path\n");
		kfree(tmp_path);
		return -EINVAL;
	}
	// Set the last element to null
	*last = '\0';
	// Copy the temporary path into the output buffer
	if (strscpy(dir_path, tmp_path, PATH_MAX) <= 0) {
		WARNING("Unable to copy the directory path\n");
		kfree(tmp_path);
		return -EINVAL;
	}
	// Clean up
	kfree(tmp_path);
	return 0;
}

char *get_cwd(void) {
	// We use 'current' to get the current task, so no need manage it
	const struct task_struct *task = current;
	// Get the current working directory
	struct path pwd_path;
	get_fs_pwd(task->fs, &pwd_path);
	// Get the path from the dentry, recursively from the end to the root
	char *pwd = kzalloc(PATH_MAX, GFP_KERNEL);
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
	return pwd_path_str;
}
