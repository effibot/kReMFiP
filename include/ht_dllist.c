//
// Created by effi on 13/08/24.
//

#include "ht_dllist.h"

#include <linux/module.h>
#include <linux/uuid.h>
#include <linux/hash.h>
#include "utils.h"


static ht_t __rcu *glb_ht;


/* Internal API to manage the hash table - not exposed to the user.
 * The wrapper API, defined in ht_dllist.h, will call these functions,
 * and they are responsible for the RCU protection.
 */
int _ht_release_list(node_t **table, int bkt); // effectively release the memory allocated at given bucket index
int _ht_release_table(node_t **table); // effectively release the memory allocated for the hash table
size_t _ht_index(ht_t *ht, void *data);
void _ht_print_list(node_t *table);
size_t _ht_count_list(node_t *table);
void* _ht_search_list(node_t *table, void *data);
node_t* _ht_remove_from_list(node_t *table, void *data);
char* _gen_key(void);

// get the instance of the global hash table
ht_t *ht_get_instance(void) {
    return glb_ht;
}

ht_t *ht_create(const size_t size, size_t (*hash)(void *)) {
    if(unlikely(size == 0) /*|| unlikely(hash == NULL)*/) {
#ifdef DEBUG
        INFO("Failed to create hash table (size: %lu)\n", size);
#endif
        return NULL;
    }
    glb_ht = kzalloc(sizeof(*glb_ht), GFP_KERNEL);
    if (unlikely(glb_ht == NULL)) {
        INFO("Failed to allocate memory for hash table\n");
        goto ret_null;
    }
    glb_ht->size = size;
    glb_ht->hash = hash;
    spin_lock_init(&glb_ht->lock);
    // allocate memory for the heads of the lists
    glb_ht->table = kzalloc(size * sizeof(node_t), GFP_KERNEL);
    if (unlikely(glb_ht->table == NULL)) {
        INFO("Failed to allocate memory for hash table\n");
        goto free_table;
    }
    // initialize the heads of the lists
    for (size_t i = 0; i < size; i++) {
        glb_ht->table[i] = kzalloc(sizeof(node_t), GFP_KERNEL);
        /* from rculist.h, if at init time the list isn't going to be used
         * or to be visible to readers, we don't need to use INIT_LIST_HEAD_RCU
         */
        INIT_LIST_HEAD(&glb_ht->table[i]->list);
    }
    INFO("allocated memory for hash table\n");
    return glb_ht;

free_table:
    kfree(glb_ht);
ret_null:
    return NULL;
}


/**
 * @name ht_destroy
 * @brief Free the memory allocated for the hash table.
 * @param ht - the hash table to be destroyed
 * @return
 */
int ht_destroy(ht_t *ht) {
#ifdef DEBUG
    INFO("Destroying hash table\n");
#endif
    // free the memory allocated for the hash table
    ht_t *new_ht = kzalloc(sizeof(new_ht), GFP_KERNEL);
    if (unlikely(new_ht == NULL)) {
        INFO("Failed to allocate memory for new hash table\n");
        return -ENOMEM;
    }
    ht_t *old_ht;
    spin_lock(&ht->lock);
    old_ht = rcu_dereference_protected(ht, lockdep_is_held(&ht->lock));
    *new_ht = *old_ht;
    // free the memory allocated for the heads of the lists
    _ht_release_table(new_ht->table);
    rcu_assign_pointer(ht, new_ht);
    spin_unlock(&ht->lock);
    synchronize_rcu();
    kfree(old_ht);
    kfree(ht);
    return 0;
}

/**
 * @name ht_insert
 * @brief Insert a new element in the hash table.
 * @param ht - the hash table where the element will be inserted
 * @param data - the element to be inserted
 * @return
 */
int ht_insert(ht_t *ht, void *data) {
    if(unlikely(ht == NULL || data == NULL)) {
#ifdef DEBUG
        INFO("Passing null table (%p) or null data (%p)\n", ht, data);
#endif
        return -EINVAL;
    }
    if (ht_lookup(ht, data) != NULL) {
        INFO("Data already in the hash table\n");
        return -EEXIST;
    }
    // we are modifying the hash table, so we are entering the critical section
    ht_t *new_ht = kzalloc(sizeof(new_ht), GFP_KERNEL);
    if (unlikely(new_ht == NULL)) {
        INFO("Failed to allocate memory for new hash table\n");
        return -ENOMEM;
    }
    // grab the lock
    ht_t *old_ht;
    spin_lock(&ht->lock);
    // get the current hash table
    old_ht = rcu_dereference_protected(ht, lockdep_is_held(&ht->lock));
    *new_ht = *old_ht;
    // now we are safe to modify the hash table
    size_t index = _ht_index(new_ht, data);
    node_t *new_node = kzalloc(sizeof(new_node), GFP_KERNEL);
    if (unlikely(new_node == NULL)) {
        INFO("Failed to allocate memory for new node\n");
        return -ENOMEM;
    }
    new_node->data = data;
    new_node->key = kzalloc(sizeof(char*)*(UUID_STRING_LEN+1), GFP_KERNEL);
    int ret = strscpy(new_node->key, _gen_key(), UUID_STRING_LEN+1);
    if( ret != UUID_STRING_LEN+1) {
        INFO("Failed to copy the key\n");
        return -E2BIG;
    }
    list_add_rcu(&new_node->list, &new_ht->table[index]->list);
    // update the hash table, then release the lock and synchronize the RCU
    rcu_assign_pointer(ht, new_ht);
    spin_unlock(&ht->lock);
    synchronize_rcu();
    kfree(old_ht);
    return 0;

}
//
// int ht_delete(const ht_t *ht, void *data);
//

// count the number of elements in the hash table

size_t *ht_count(ht_t *ht) {
    size_t *count = kzalloc(HT_SIZE * sizeof(size_t), GFP_KERNEL);
    if(unlikely(ht == NULL)) {
#ifdef DEBUG
        INFO("Passing Null table (%p)\n", ht);
#endif
        goto ret;
    }
    rcu_read_lock();
    const ht_t *tmp_ht = rcu_dereference(ht);
    for(size_t i = 0; i < HT_SIZE; i++) {
        count[i] = _ht_count_list(tmp_ht->table[i]);
    }
    rcu_read_unlock();
ret:
    return count;
}

// count the number of free elements in the hash table

size_t _ht_count_list(node_t *table) {
    if (unlikely(table == NULL)) {
#ifdef DEBUG
        INFO("Passing null table (%p)\n", table);
#endif
        return -EINVAL;
    }
    // initialize the counter
    size_t count = 0;
    struct list_head *node;
    // iterate over the list
    list_for_each_rcu(node, &table->list) {
        count++;
    }
    return count;
}

size_t ht_get_count_at(ht_t *ht, size_t index) {
    if(unlikely(ht == NULL || index < 0 || index >= HT_SIZE)) {
#ifdef DEBUG
        INFO("Passing null table (%p) or invalid index (%lu)\n", ht, index);
#endif
    }
    size_t *count = ht_count(ht);
    size_t ret = count[index];
    kfree(count);
    return ret;
}

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
        node_t *tmp_head = rcu_dereference(ht)->table[i];
        _ht_print_list(tmp_head);
    }
    rcu_read_unlock();
    INFO("End of table\n");
}

void _ht_print_list(node_t *table) {
    if(unlikely(table == NULL)) {
#ifdef DEBUG
        INFO("passing null table (%p)\n", table);
#endif
        return;
    }
    // print the elements in the list at the given index
    node_t *tmp_head;
    list_for_each_entry_rcu(tmp_head, &table->list, list) {
        INFO("Data: %p -->\t", tmp_head->data);
    }
    printk("\n");
}


// internal function to release the memory allocated for the list
int _ht_release_list(node_t **table, const int bkt) {
    if (unlikely(table == NULL || bkt < 0 || bkt >= HT_SIZE)) {
#ifdef DEBUG
        INFO("passing null table\n");
#endif
        return -EINVAL;
    }
    node_t *tmp_head;
    list_for_each_entry_rcu(tmp_head, &table[bkt]->list, list) {
        kfree(tmp_head);
    }
    return 0;

}

// internal function to release the memory allocated for the hash table
int _ht_release_table(node_t **table) {
    if (unlikely(table == NULL)) {
#ifdef DEBUG
        INFO("passing null table\n");
#endif
        return -EINVAL;
    }
#ifdef DEBUG
    INFO("Releasing hash table\n");
#endif
    for (size_t i = 0; i < HT_SIZE; i++) {
        if (table[i] != NULL) _ht_release_list(table, i);
    }
#ifdef DEBUG
    INFO("Table released\n");
#endif
    kfree(table);
    return 0;
}

/**
* @name _ht_index
* @brief Get the index of the element in the hash table. The index is calculated
* using the hash function. Since the hash function is fixed at compile time, we
* don't need to get lock to access it, we just need to get the pointer to the hash.
* @param ht - the hash table
* @param data - the element to be inserted
* @return hash(data) % HT_SIZE
*/

size_t _ht_index(ht_t *ht, void *data) {
    if(unlikely(ht == NULL || data == NULL)) {
#ifdef DEBUG
        INFO("Passing null table (%p) or null data (%p)\n", ht, data);
#endif
    }
    return ht->hash(data) % HT_SIZE;
}

void * ht_lookup(ht_t * ht, void * data) {
    if(unlikely(ht == NULL || data == NULL)) {
#ifdef DEBUG
        INFO("Passing null table (%p) or null data (%p)\n", ht, data);
#endif
        goto not_found;
    }
    // find the list where the data should be - no need to lock the hash table
    size_t index = _ht_index(ht, data);
    // we need to iterate over the linked list at the given index in the hash table
    // so we need to lock the hash table
    rcu_read_lock();
    node_t *tmp_head = rcu_dereference(ht)->table[index];
    void *found = _ht_search_list(tmp_head, data);
    rcu_read_unlock();
    if (found != NULL) {
        return found;
    }
not_found:
    return NULL;
}

void * _ht_search_list(node_t * table, void * data) {
    if(unlikely(table == NULL || data == NULL)) {
#ifdef DEBUG
        INFO("Passing null table (%p) or null data (%p)\n", table, data);
#endif
        goto not_found;
    }
    // find the element in the list
    node_t *node;   // loop cursor
    list_for_each_entry_rcu(node, &table->list, list) {
        // compare the key of the node with the key of the data
        if (strncmp(node->key, container_of(data, node_t, data)->key, UUID_STRING_LEN+1) == 0) {
            return node->data;
        }
    }
not_found:
    return NULL;
}

node_t* _ht_remove_from_list(node_t *table, void *data) {
    if (unlikely(table == NULL || data == NULL)) {
#ifdef DEBUG
        INFO("Passing null table (%p) or null data (%p)\n", table, data);
#endif
        return NULL;
    }
    // find the element in the list and remove it
    //! the wrapper function will take care of locking the hash table
    // remember that we are using a doubly linked list, so we can swap the pointers

    // be sure that the data is in the list
    if (_ht_search_list(table, data) == NULL) {
#ifdef DEBUG
        INFO("Data not found in the list\n");
#endif
        return NULL;
    }
    node_t *to_be_removed = list_entry_rcu(data, node_t, data);
    // the item is in the list, so we can swap the pointers
    struct list_head *prev = to_be_removed->list.prev;
    struct list_head *next = to_be_removed->list.next;
    list_del_rcu(data);
    prev->next = next;
    next->prev = prev;
    return to_be_removed;
}
int ht_delete(ht_t *ht, void *data) {
    if (unlikely(ht == NULL || data == NULL)) {
#ifdef DEBUG
        INFO("Passing null table (%p) or null data (%p)\n", ht, data);
#endif
        return -EINVAL;
    }
    // we are modifying the hash table, so we are entering the critical section
    ht_t *new_ht = kzalloc(sizeof(new_ht), GFP_KERNEL);
    if (unlikely(new_ht == NULL)) {
        INFO("Failed to allocate memory for new hash table\n");
        return -ENOMEM;
    }
    // grab the lock
    ht_t *old_ht;
    spin_lock(&ht->lock);
    // get the current hash table
    old_ht = rcu_dereference_protected(ht, lockdep_is_held(&ht->lock));
    *new_ht = *old_ht;
    // now we are safe to modify the hash table
    size_t index = _ht_index(new_ht, data);
    node_t *removed = _ht_remove_from_list(new_ht->table[index], data);
    if (removed == NULL) {
        INFO("Data not found in the hash table\n");
        return -ENOENT;
    }
    // free the memory allocated for the node
    kfree_rcu(removed, rcu);
    // update the hash table, then release the lock and synchronize the RCU
    rcu_assign_pointer(ht, new_ht);
    spin_unlock(&ht->lock);
    synchronize_rcu();
    kfree(old_ht);
    return 0;
}

// define the hash function
size_t hash_path(node_t *node) {
    if(unlikely(node == NULL)) {
#ifdef DEBUG
        INFO("Passing Null data (%p)\n", node);
#endif
        return -EINVAL;
    }
    // we convert the key to an unsigned integer to pass it to the hash function

    // compute the hash
    return hash_ptr(node->key, HT_BIT_SIZE);

}

char* _gen_key(void) {
    // we use kernel/uuid.h to generate a unique key for the data
    uuid_t uuid;
    uuid_gen(&uuid);
    char *key = kzalloc(UUID_STRING_LEN+1, GFP_KERNEL);
    if (unlikely(key == NULL)) {
        INFO("Failed to allocate memory for the key\n");
        return NULL;
    }
    // We have to store 36 + 1 characters in the string (including the null terminator)
    sprintf(
        key, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             uuid.b[0], uuid.b[1], uuid.b[2], uuid.b[3],
             uuid.b[4], uuid.b[5], uuid.b[6], uuid.b[7],
             uuid.b[8], uuid.b[9], uuid.b[10], uuid.b[11],
             uuid.b[12], uuid.b[13], uuid.b[14], uuid.b[15]
    );
    return key;
}


