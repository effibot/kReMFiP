//
// Created by effi on 13/08/24.
//

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uuid.h>
#include <linux/hash.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/rculist.h>
#include "utils.h"

#include "ht_dllist.h"




/* Internal API to manage the hash table - not exposed to the user.
 * The wrapper API, defined in ht_dllist.h, will call these functions,
 * and they are responsible for the RCU protection.
 */

// RCU dependent functions
void __ht_print_list(node_t *list); // print the elements in the given list
size_t __ht_count_list(node_t *list); // count the number of elements in the given list

// RCU independent functions
size_t __gen_key(const char* path); // generate a key from the pathname
size_t __ht_index(node_t *node);    // get the bucket were the node should be in the hash table
bool __is_path_valid(const char* path); // check if the path is valid
bool __path_exists(const char* path);   // check if the path exists in the file system


/**
 * @name ht_get_instance
 * @brief Get the global hash table instance like a singleton.
 * @return the global hash table instance
 */

ht_t *ht_create(const size_t size) {
    if(unlikely(size == 0)) {
#ifdef DEBUG
        INFO("Failed to create hash table (size: %lu)\n", size);
#endif
        return NULL;
    }
    ht_t *table = kzalloc(sizeof(*table), GFP_KERNEL);
    if (unlikely(table == NULL)) {
        INFO("Failed to allocate memory for hash table\n");
        goto ret_null;
    }
    // set the size of the hash table
    table->size = size;
    // allocate memory for the heads of the lists
    table->table = kzalloc(size * sizeof(node_t), GFP_KERNEL);
    if (unlikely(table->table == NULL)) {
        INFO("Failed to allocate memory for hash table\n");
        goto free_table;
    }
    // allocate memory for the spinlocks - one per bucket
    table->lock = kzalloc(size * sizeof(spinlock_t), GFP_KERNEL);
    // initialize the heads of the lists and the spinlocks
    for (size_t bkt = 0; bkt < size; bkt++) {
        table->table[bkt] = kzalloc(sizeof(node_t), GFP_KERNEL);
        if (unlikely(table->table[bkt] == NULL)) {
            INFO("Failed to allocate memory for list at bucket %lu\n", bkt);
            goto free_table;
        }
        INIT_LIST_HEAD_RCU(&table->table[bkt]->list);
        // initialize per-bucket spinlock
        spin_lock_init(&table->lock[bkt]);
    }
    INFO("allocated memory for hash table\n");
    return table;

free_table:
    kfree(table);
ret_null:
    return NULL;
}

/**
 * @name ht_lookup
 * @brief Look for the data in the hash table.
 * @param ht - the hash table where the data will be searched
 * @param key_p - the key of the data to be searched
 * @return the data if found, NULL otherwise
 */
node_t* ht_lookup(ht_t *ht, size_t *key_p) {
    if(unlikely(ht == NULL || key_p == 0)) {
#ifdef DEBUG
        INFO("Passing null table (%p) or invalid key (%lu)\n", ht, *key_p);
#endif
        goto not_found;
    }
    // find the bucket where the data should be
    const size_t bkt = hash_key(*key_p) % HT_SIZE;
    // define the loop cursor
    node_t *tmp_node;
    /*[RCU] - Read Critical Section
     * we need to iterate over the linked list at the given index
     * in the hash table so we need to lock the hash table
     */
    rcu_read_lock();
    // get the selected bucket in the hash table
    node_t *tmp_head = rcu_dereference(ht->table)[bkt];
    // traverse the list in RCU way
    list_for_each_entry_rcu(tmp_node, &tmp_head->list, list) {
        // compare the key of the node with the key of the data
        if (tmp_node->key == *key_p) {
            // the key is the same, be sure that the path is the same
            const node_t *node = container_of(key_p, node_t, key);
            if(unlikely(node == NULL)) {
                INFO("Failed to get the node from the key\n");
                goto not_found;
            }
            if (strcmp(tmp_node->path, node->path) != 0) {
                // the path is different, so we have a collision
                INFO("Collision detected for key %lu\n", node->key);
                // TODO: handle the collision
            }
            rcu_read_unlock();
            return tmp_node;
        }
    }
not_found:
    rcu_read_unlock();
    return NULL;
}

/**
 * @name ht_insert
 * @brief Insert a new element in the hash table.
 * @param ht - the hash table where the element will be inserted
 * @param node - the element to be inserted
 * @return
 */
int ht_insert_node(ht_t* ht, node_t *node) {
    if(unlikely(ht == NULL || node == NULL)) {
#ifdef DEBUG
        INFO("Passing null table (%p) or null data (%p)\n", ht, node);
#endif
        return -EINVAL;
    }
    // check if the data is already in the hash table - read critical section
    if (ht_lookup(ht, &node->key) != NULL) {
        INFO("Data already in the hash table\n");
        return -EEXIST;
    }
    // find the bucket where the data should be
    const size_t bkt = __ht_index(node);
    // grab the lock for the bucket where the data should be
    spin_lock(&ht->lock[bkt]);
    // insert the data at the head list
    list_add_rcu(&node->list, &ht->table[bkt]->list);
    // release the lock and synchronize the RCU
    spin_unlock(&ht->lock[bkt]);
    synchronize_rcu();
    return 0;

}

static void __node_reclaim_callback(struct rcu_head *rcu) {
    const node_t *node = container_of(rcu, node_t, rcu);
#ifdef DEBUG
    INFO("Callback free for node with key %lu. Preempt count: %d\n", node->key, preempt_count());
#endif
    kfree(node);
}

// int ht_destroy(ht_t *ht) {
// #ifdef DEBUG
//     INFO("Destroying hash table\n");
// #endif
//     // free the memory allocated for the hash table
//     ht_t *new_ht = kzalloc(sizeof(new_ht), GFP_KERNEL);
//     if (unlikely(new_ht == NULL)) {
//         INFO("Failed to allocate memory for new hash table\n");
//         return -ENOMEM;
//     }
//     ht_t *old_ht;
//     for (size_t i = 0; i < HT_SIZE; i++) {
//         spin_lock(&ht->lock[i]);
//         old_ht = rcu_dereference_protected(ht, lockdep_is_held(&ht->lock[i]));
//
//         *new_ht = *old_ht;
//         // free the memory allocated for the heads of the lists
//         //__ht_release_table(new_ht->table);
//
//         rcu_assign_pointer(ht, new_ht);
//         spin_unlock(&ht->lock[i]);
//         synchronize_rcu();
//         kfree(old_ht);
//         kfree(ht);
//     }
//     return 0;
// }


/**
 * @name ht_delete_node
 * @brief Delete the data from the hash table.
 * @param ht - the hash table where the data will be deleted
 * @param node - the data to be deleted
 * @return
 */
int ht_delete_node(ht_t *ht, node_t *node) {
    if (unlikely(ht == NULL || node == NULL)) {
#ifdef DEBUG
        INFO("Passing null table (%p) or null data (%p)\n", ht, node);
#endif
        return -EINVAL;
    }
    // lock the whole table to be sure that the data is not deleted while we are looking for it
    HT_LOCK_TABLE(ht);
    // check if the data is in the hash table
    node_t *removed = ht_lookup(ht, &node->key);
    if (removed == NULL) {
        // someone else deleted the data
        INFO("Data not found in the hash table\n");
        HT_UNLOCK_TABLE(ht);
        return -ENOENT;
    }
    // remove the data from the list
    list_del_rcu(&removed->list);
    // unlock the table
    HT_UNLOCK_TABLE(ht);
    // make async reclaim of the data
    call_rcu(&removed->rcu, __node_reclaim_callback);
    return 0;
}

size_t __ht_count_list(node_t *list) {
    if (unlikely(list == NULL)) {
#ifdef DEBUG
        INFO("Passing null table (%p)\n", list);
#endif
        return -EINVAL;
    }
    // initialize the counter
    size_t count = 0;
    struct list_head *node;
    // iterate over the list
    list_for_each_rcu(node, &list->list) {
        count++;
    }
    return count;
}

/**
 * @name ht_count
 * @brief Count the number of elements in the hash table for each bucket.
 * @param ht - the structure representing the hash table
 * @return the number of elements in the hash table as an array
 */
size_t *ht_count(ht_t *ht) {
    size_t *count = kzalloc(HT_SIZE * sizeof(size_t), GFP_KERNEL);
    if(unlikely(ht == NULL)) {
#ifdef DEBUG
        INFO("Passing Null table (%p)\n", ht);
#endif
        // fill the array with -EINVAL
        for(size_t i = 0; i < HT_SIZE; i++) count[i] = -EINVAL;
        goto ret;
    }
    rcu_read_lock();
    node_t **tmp_table = rcu_dereference(ht->table);
    for(size_t i = 0; i < HT_SIZE; i++) {
        count[i] = __ht_count_list(tmp_table[i]);
    }
    rcu_read_unlock();
ret:
    return count;
}

/**
 * @name ht_get_count_at
 * @brief Get the number of elements in the hash table at the given index.
 * @param ht - the structure representing the hash table
 * @param index - the index of the bucket in the hash table
 * @return the number of elements in the hash table at the given index
 */
size_t ht_get_count_at(ht_t *ht, const size_t index) {
    if(unlikely(ht == NULL || index < 0 || index >= HT_SIZE)) {
#ifdef DEBUG
        INFO("Passing null table (%p) or invalid index (%lu)\n", ht, index);
#endif
    }
    const size_t *count = ht_count(ht);
    const size_t ret = count[index];
    kfree(count);
    return ret;
}

/**
 * @name ht_print
 * @brief Print the hash table.
 * @param ht - the structure representing the hash table
 */
void ht_print(ht_t *ht) {
    if(unlikely(ht == NULL)) {
#ifdef DEBUG
        INFO("passing null table\n");
#endif
        return;
    }
    // print hash table infos
    INFO("Table of size %d\n", HT_SIZE);
    rcu_read_lock();
    for(size_t i = 0; i < HT_SIZE; i++) {
        // print the number of elements in the list at the given index
        node_t *tmp_list_head = rcu_dereference(ht->table[i]);
        printk("Index %lu: %lu elements\n", i, __ht_count_list(tmp_list_head));
        __ht_print_list(tmp_list_head);
    }
    rcu_read_unlock();
    INFO("End of table\n");
}

/**
 * @name __ht_print_list
 * @brief Print the elements in the given list.
 * @param list - the list to be printed
 */
void __ht_print_list(node_t *list) {
    if(unlikely(list == NULL)) {
#ifdef DEBUG
        INFO("passing null table (%p)\n", list);
#endif
        return;
    }
    // print the elements in the list at the given index
    node_t *tmp_head;
    list_for_each_entry_rcu(tmp_head, &list->list, list) {
        // print [key::path]-> for each element in the list
        printk(KERN_CONT "[%lu::%s]-->", tmp_head->key, tmp_head->path);
    }
    // print a newline at the end of the list
    printk("\n");
}

/****************************************************
 *Internal API to manage the nodes of the hash table*
 ****************************************************/

/**
 * @name __gen_key
 * @brief Generate a key from the pathname. We use kernel hash function to generate
 * a key for the data. Doing so, we have high probability to have unique keys for
 * different pathname (like the stars in the sky), but we can still have collisions for same pathname.
 * In this way, we'll be able to search for specific pathname just looking for the right key.
 * @param path - the pathname
 * @return the key
 */
size_t __gen_key(const char* path) {
    if (unlikely(path == NULL)) {
#ifdef DEBUG
        INFO("Passing null pathname (%p)\n", path);
#endif
        return -EINVAL;
    }
    // just call the kernel hash function
    return hash_ptr(path, HT_BIT_KEY_SIZE);
}

/**
 * @name __ht_index
 * @brief Get the bucket where the node should be in the hash table.
 * @param node - the node to be hashed
 * @return the index of the bucket
 */
size_t __ht_index(node_t *node) {
    if(unlikely(node == NULL)) {
#ifdef DEBUG
        INFO("Passing null node (%p)\n", node);
#endif
        return -EINVAL;
    }
    return hash_key(node->key) % HT_SIZE;
}

/**
 * @name hash_node
 * @brief Compute the hash of the node using its key.
 * @param key - the key of the node
 * @return the hash
 */
size_t hash_key(const size_t key) {
    if(unlikely(key == 0)) {
#ifdef DEBUG
        INFO("Passing invalid key (%lu)\n", key);
#endif
        return -EINVAL;
    }
    // compute the hash -- size_t is an alias for unsigned long
    return hash_long(key, HT_BIT_SIZE);

}

/**
 * @name __path_exists
 * @brief Check if the path exists in the file system.
 * @param path - the path to be checked
 * @return true if the path exists, false otherwise
 */
bool __path_exists(const char* path) {
    if(unlikely(path == NULL)) {
#ifdef DEBUG
        INFO("Passing null path (%p)\n", path);
#endif
        goto not_exists;
    }
    struct path p;
    const int ret = kern_path(path, LOOKUP_FOLLOW, &p);
    if (ret < 0) {
        INFO("Path %s does not exist\n", path);
        goto not_exists;
    }
    path_put(&p);
    return true;
    not_exists:
        return false;
}

/**
 * @name __is_path_valid
 * @brief Check if the path is valid.
 * @param path - the path to be checked
 * @return true if the path is valid, false otherwise
 */
bool __is_path_valid(const char* path) {
    if (unlikely(path == NULL)) {
#ifdef DEBUG
        INFO("Passing null path (%p)\n", path);
#endif
        return false;
    }

    const size_t len = strnlen(path, PATH_MAX);

    // Check for empty path
    if (len == 0) {
        INFO("Empty path\n");
        return false;
    }

    // Check for root path
    if (strcmp(path, "/") == 0) {
        INFO("Root path\n");
        return false;
    }

    // Check for paths like . or ..
    if (strcmp(path, ".") == 0 || strcmp(path, "..") == 0) {
        INFO("Path starts with . or ..\n");
        return false;
    }

    // Check for double slashes
    if (strstr(path, "//") != NULL) {
        INFO("Double slashes in the path\n");
        return false;
    }

    return true;
}

/**
 * @name node_init
 * @brief Initialize a new node with the given path.
 * @param path - the path of the file
 * @return the new node
 */
node_t* node_init(const char* path) {
    if (unlikely(path == NULL || strcmp(path, "") == 0)) {
        INFO("Empty path\n");
        return NULL;
    }
    // check if the inserted path is valid and exists
    if (!__is_path_valid(path)) {
        INFO("Invalid path %s\n", path);
        return NULL;
    }
    if (!__path_exists(path)) {
        INFO("Path %s does not exist\n", path);
        return NULL;
    }
    // allocate memory for the node
    node_t *node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (unlikely(node == NULL)) {
        INFO("Failed to allocate memory for the path\n");
        return NULL;
    }
    node->path = kzalloc(strlen(path)+1, GFP_KERNEL);
    if (unlikely(node->path == NULL)) {
        INFO("Failed to allocate memory for the path\n");
        kfree(node);
        return NULL;
    }
    // copy the path
    int ret = strscpy(node->path, path, strlen(path)+1);
    if (ret != strlen(path)) {
        INFO("Failed to copy the path\n");
        kfree(node->path);
        kfree(node);
        return NULL;
    }
    // generate the key
    node->key = __gen_key(path);
    // initialize pointers for new node
    INIT_LIST_HEAD_RCU(&node->list);
    return node;
}

