//
// Created by effi on 13/09/24.
//

#include "pathmgm.h"
#include <linux/fs.h>
#include <linux/stat.h>

/**
 * @brief
 * @param path The path to check
 * @return true if the path is a directory, false otherwise
 */
bool path_exists(const char *path) {
	// Declare a struct to store the statistics of the path
	struct kstat stat;
	int ret;
	// retrieve the stat of the path
	ret = vfs_stat(path, &stat);
	if (ret < 0) {
		return false;
	}
	return true;
}