//
// Created by effi on 13/08/24.
//

#include "ht_dllist.h"

#include <linux/module.h>

#include "utils.h"


static char* selected_hash = "unknown";
ht_t __rcu *glb_ht;
/* Internal API to manage the hash table - not exposed to the user.
 * The wrapper API, defined in ht_dllist.h, will call these functions,
 * and they are responsible for the RCU protection.
 */
int _ht_release_list(node_t **table, int bkt); // effectively release the memory allocated at given bucket index
int _ht_release_table(node_t **table); // effectively release the memory allocated for the hash table
size_t _ht_index(ht_t *ht, void *data);
void _ht_print_list(node_t **table, size_t index);

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
    selected_hash = "unknown";
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
    ht_t *new_ht = kmalloc(sizeof(new_ht), GFP_KERNEL);
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

// int ht_insert(const ht_t *ht, void *data);
//
// int ht_delete(const ht_t *ht, void *data);
//
// void *ht_search(const ht_t *ht, void *data);

size_t ht_size(const ht_t *ht) {
    if(unlikely(ht == NULL)) {
        return 0;
    }
    return ht->size;
}

// count the number of elements in the list at the given index

size_t ht_count(const ht_t *ht, const size_t index) {
    if(unlikely(ht == NULL) || unlikely(index >= ht->size)) {
        return 0;
    }
    // standard way to do it
    size_t count = 0;
    node_t *pos;
    list_for_each_entry(pos, &ht->table[index]->list, list) {
        count++;
    }
    return count;
}

// count the number of free elements in the hash table

size_t ht_count_free(const ht_t *ht) {
    if(unlikely(ht == NULL)) {
        return 0;
    }
    size_t count = 0;
    for(size_t i = 0; i < ht->size; i++) {
        if (ht->table[i]->data == NULL) {
            count++;
        }
    }
    return count;
}

void ht_print(ht_t *ht) {
    if(unlikely(ht == NULL)) {
#ifdef DEBUG
        INFO("passing null table\n");
#endif
        return;
    }
    // print hash table infos
    INFO("Table of size %lu, using hash function: %s\n", ht->size, selected_hash);
    for(size_t i = 0; i < ht->size; i++) {
        // print the number of elements in the list at the given index
        if(ht->table[i]->data != NULL) {
            INFO("Index %lu: %lu elements\n", i, ht_count(ht, i));
            _ht_print_list(ht->table, i);
        }
    }
    INFO("Free remaining slots: %lu\n", ht_count_free(ht));
}

void _ht_print_list(node_t **table, size_t index) {
    if(unlikely(table == NULL) || unlikely(index >= HT_SIZE)) {
#ifdef DEBUG
        INFO("passing null table (%p) or bad index (%lu)\n", table, index);
#endif
        return;
    }
    // print the elements in the list at the given index
    node_t *tmp_head;
    list_for_each_entry_rcu(tmp_head, &table[index]->list, list) {
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

size_t _ht_index(ht_t *ht, void *data) {
    rcu_read_lock();
    const ht_t *tmp_ht = rcu_dereference(ht);
    const size_t index = tmp_ht->hash(data) % tmp_ht->size;
    rcu_read_unlock();
    return index;
}
