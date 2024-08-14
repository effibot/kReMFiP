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

#ifndef HT_SIZE
#define HT_SIZE 4096
#endif

#ifndef DEBUG
#define DEBUG 1
#endif

// define the size of the cache line for x86 architecture
#define X86_CACHE_LINE_SIZE 64

// define the data structure that will be stored in the linked list
typedef struct _path_data_t {
    char *path;
    int len;
} __attribute__ ((packed)) path_t;

// define the data structure that will be stored in the hash table
/*
typedef struct head_data_t {
    size_t count; // number of elements in the linked list
    path_t *cached_data;
} __attribute__ ((packed)) head_t;
*/

// the node of the doubly linked list
typedef struct _ht_dllist_node_t {
    struct list_head list; // kernel-list: provides pointers to next and previous element
    void *data; // we point to a generic data
} __attribute__ ((aligned(X86_CACHE_LINE_SIZE))) node_t;

// the hash table wich nodes are the heads of the linked lists
typedef struct _ht_t {
    node_t **table; // array of pointers to the heads of the linked lists
    size_t size; // size of the hash table
    size_t (*hash)(void *); // hash function
} __attribute__ ((aligned(X86_CACHE_LINE_SIZE))) ht_t;

// define function prototypes
ht_t *ht_create(size_t size, size_t (*hash)(void *));
int ht_destroy(const ht_t *ht);
int ht_insert(const ht_t *ht, void *data);
int ht_delete(const ht_t *ht, void *data);
void *ht_search(const ht_t *ht, void *data);
size_t ht_size(const ht_t *ht);
size_t ht_count(const ht_t *ht, size_t index);
size_t ht_count_free(const ht_t *ht);
void ht_print(ht_t *ht);
#endif //HT_DLLIST_H

/* https://www.oreilly.com/library/view/linux-device-drivers/0596000081/ch10s05.html */