/**
 * @file pathmgm.h
 * @brief Path management utilities header file. This is a collection of utility functions
 * to obtain information about the path to inspect, like if it's a directory or a file, and the
 * path from the root.
 */

#ifndef PATHMGM_H
#define PATHMGM_H

#include "misc.h"
#include <linux/types.h>

/**
 * @brief Check if the path is a directory
 * @param path the path to check
 * @return true if the path is a directory, false otherwise
 */
bool is_dir(const char *path);

/**
 * @brief Check if the path is a regular file
 * @param path the path to check
 * @return true if the path is a file, false otherwise
 */
bool is_file(const char *path);

/**
 * @brief Check if the path is a symbolic link
 * @param path the path to check
 * @return true if the path is a symbolic link, false otherwise
 */
bool is_symlink(const char *path);

/**
 * @brief Get the path from the root
 * @param path the path to get the root from
 * @return the root path
 */
char *get_full_path(const char *path);

/**
 * @brief Check if the path exists
 * @param path the path to check
 * @return true if the path exists, false otherwise
 */
bool path_exists(const char *path);

/**
 * @brief Check if the path respects our constraints
 * @param path the path to check
 * @return true if the path is valid, false otherwise
 */
bool is_valid_path(const char *path);

#endif //PATHMGM_H
