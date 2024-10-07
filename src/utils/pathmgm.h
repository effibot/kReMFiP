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

// Define a vector of invalid system paths
#define INVALID_PATHS_NUM 20

// Define a keyword for path not found
#define PATH_NOT_FOUND "Path not found"
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
 * @param abs_path the absolute path to fill
 * @return 0 or error codes on error.
 */
int get_abs_path(const char *path, char *abs_path);

/**
 * @brief Get the path from the root
 * @param dfd the file descriptor of the directory
 * @param user_path the path to get the root from
 * @param abs_path the absolute path to fill
 * @return 0 or error codes on error.
 */
int get_abs_path_user(int dfd, const __user char *user_path, char *abs_path);

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

/**
 * @brief Get the path from the root to the second to last element of the path
 * @param path The path to analyze
 * @param dir_path The buffer to store the path to the directory
 * @return the string containing the absolute path of the directory.
 */
int get_dir_path(const char *path, char *dir_path);

/**
 * @brief Get the current process working directory
 * @return the string containing the absolute path of the current working directory.
 */
char *get_cwd(void);
#endif //PATHMGM_H
