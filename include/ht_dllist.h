/**
 * ht_dllist.h
 *
 * This is an implementation of a hash table with use a doubly linked list to resolve collisions.
 * The choice of a doubly linked list is due to the fact that it is a simple data structure that
 * allows to insert and delete elements in constant time.
 *
 * The hash table is implemented as an array of pointers to the head of the linked list.
 * The hash function is taken as a parameter and it is used to calculate the index of the array
 * where the element should be inserted.
 *
 * Author: Andrea Efficace (andrea.efficace1@gmail.com
 * Date: 13/08/24
 *
 */


#ifndef HT_DLLIST_H
#define HT_DLLIST_H

#include <linux/types.h>
#include <linux/list.h>

// the node of the doubly linked list
typedef struct ht_dllist_node {
    struct list_head list; // we use the linux kernel list implementation - provide pointer to next and previous element
    void *data; // we point to a generic data
} node_t;

// the head of the doubly linked list
typedef struct ht_dllist {

} ht_dllist_t;

#endif //HT_DLLIST_H

/* https://www.oreilly.com/library/view/linux-device-drivers/0596000081/ch10s05.html */