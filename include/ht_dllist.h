/**
 * ht_dllist.h
 *
 * This is an implementation of a hash table which use doubly linked lists to resolve collisions.
 * The choice of a doubly linked list is due to the fact that it is a simple data structure that
 * allows to insert and delete elements in constant time.
 *
 * The hash table is implemented as an array of pointers to the head of the linked list.
 * The hash function is taken as a parameter, and it is used to calculate the index of the array
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

#include "kremfip.h"
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/version.h>
/**
 * @brief Grab the lock on every bucket of the hash table
 * @param ht hash table to inspect
 */
#define HT_LOCK_TABLE(ht)                \
	do {                                 \
		size_t i;                        \
		for (i = 0; i < ht->size; i++) { \
			spin_lock(&ht->lock[i]);     \
		}                                \
	} while (0)

/**
 * @brief Release the lock on every bucket of the hash table
 * @param ht hash table to inspect
 */
#define HT_UNLOCK_TABLE(ht)              \
	do {                                 \
		size_t i;                        \
		for (i = 0; i < ht->size; i++) { \
			spin_unlock(&ht->lock[i]);   \
		}                                \
	} while (0)

/**
 * list_is_head - check if the node is the head of the list
 * @node: the node to check
 * @head: the head of the list
 * @remark: We need to redefine this macro if the kernel version is too old.
 * Return: 1 if the node is the head of the list, 0 otherwise
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)
#define list_for_each_rcu(pos, head)                                       \
	for (pos = rcu_dereference((head)->next); !list_is_first(pos, (head)); \
		 pos = rcu_dereference(pos->next))
#endif

// the node of the doubly linked list
typedef struct _ht_dllist_node_t {
	char *path; // path of the file - eg /home/user/file.txt
	uint64_t key; // key of the element - obtained as a hash of the path
	struct list_head list; // kernel-list: provides pointers to next and previous element
	struct rcu_head rcu; // used for RCU
} __attribute__((aligned(X86_CACHE_LINE_SIZE))) node_t;

// the hash table wich nodes are the heads of the linked lists
typedef struct _ht_t {
	node_t __rcu **table; // array of pointers to the heads of the linked lists
	size_t size; // size of the hash table
	spinlock_t *lock; // spinlock array to protect the hash table buckets
} __attribute__((aligned(X86_CACHE_LINE_SIZE))) ht_t;

// define function prototypes
node_t *ht_lookup(ht_t *ht, uint64_t key);
ht_t *ht_create(size_t size);
int ht_destroy(ht_t *ht);
int ht_insert_node(ht_t *ht, node_t *node);
int ht_delete_node(ht_t *ht, node_t *node);
size_t *ht_count(ht_t *ht);
size_t ht_get_count_at(ht_t *ht, size_t index);
void ht_print(ht_t *ht);
node_t *node_init(const char *path);

// define the hash function
uint64_t compute_hash(const char *key);

#endif //HT_DLLIST_H

/* https://www.oreilly.com/library/view/linux-device-drivers/0596000081/ch10s05.html */