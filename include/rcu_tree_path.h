//
// Created by effi on 11/08/24.
//

/**
 * @file rcu_tree_path.h
 * @date 2024-08-11
 * @brief This file contains the RCU tree implementation.
 *
 * The RCU tree is a tree data structure that is protected by RCU.
 * It is used to store the file system paths and their types.
 */

#ifndef PATH_H
#define PATH_H

/**
 * @brief Type of the node
 * We want to distinguish between files, directories and symlinks
 */

typedef enum _ftype_t {
    FILE = 0,
    DIR = 1,
    SYMLINK = 2,
} ftype_t;

/**
 * @brief Node of the tree
 * The node of the tree is a simple structure that contains the name of the node,
 * the parent node, the list of children, the next and previous siblings, a unique id and the type of the node.
 * The id is a key computed by an hash function on the full path represented by the node.
 * e.g: the file 'foo.txt' under '../foo_dir/' will have the id computed on the string '../foo_dir/foo.txt'
 */

struct _node_t {
    char *name;
    struct _node_t *parent; // parent node
    struct _node_t *children; // list of children
    struct _node_t *next; // next sibling
    struct _node_t *prev; // previous sibling
    long id; // unique id
    ftype_t type; // type of the node
} node_t;

/**
 * @brief Tree structure
 * The tree structure is a simple structure that contains the root of the tree.
 */



#endif //PATH_H
