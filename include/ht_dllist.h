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
 * Heavily inspired by linux/hashtable.h and linux/rculist.h
 *
 */


#ifndef HT_DLLIST_H
#define HT_DLLIST_H

#include <linux/types.h>
#include <linux/spinlock.h>

#ifndef HT_BIT_SIZE
#define HT_BIT_SIZE 2 // default size of the hash table
#endif

#define HT_BIT_KEY_SIZE 32 // default size of the key -- maximum amount of bits to (hopefully) avoid collisions

// be sure that the size of the hash table is under the maximum key size we can have
#if HT_BIT_SIZE > 32
printk("The size of the hash table is too big. We'll reduce to 32 bits\n");
#undef HT_BIT_SIZE
#define HT_BIT_SIZE 32
#endif


#ifndef HT_SIZE
#define HT_SIZE (1 << HT_BIT_SIZE) // this is 2^HT_BIT_SIZE
#endif

#ifndef DEBUG
#define DEBUG 1
#endif

// define the size of the cache line for x86 architecture
#define X86_CACHE_LINE_SIZE 64

// the node of the doubly linked list
typedef struct _ht_dllist_node_t {
    struct list_head list; // kernel-list: provides pointers to next and previous element
    char *path; // path of the file - eg /home/user/file.txt
    size_t key; // key of the element - obtained as a hash of the path
    struct rcu_head rcu; // used for RCU
} __attribute__ ((aligned(X86_CACHE_LINE_SIZE))) node_t;

// the hash table wich nodes are the heads of the linked lists
typedef struct _ht_t {
    node_t **table; // array of pointers to the heads of the linked lists
    size_t size; // size of the hash table
    spinlock_t lock; // spinlock to protect the hash table
} __attribute__ ((aligned(X86_CACHE_LINE_SIZE))) ht_t;


// define function prototypes
ht_t* ht_create(size_t size);
int ht_destroy(ht_t *ht);
int ht_insert(ht_t *ht, node_t *node);
int ht_delete(ht_t *ht, node_t *node);
size_t* ht_count(ht_t *ht);
size_t ht_get_count_at(ht_t *ht, size_t index);
void ht_print(ht_t *ht);
ht_t* ht_get_instance(void);
node_t* ht_lookup(ht_t *ht, node_t *node);
node_t* node_init(const char* path);

// define the hash function
size_t hash_node(node_t *node);


#endif //HT_DLLIST_H

/* https://www.oreilly.com/library/view/linux-device-drivers/0596000081/ch10s05.html */