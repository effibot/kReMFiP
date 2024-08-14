//
// Created by effi on 13/08/24.
//

#include "ht_dllist.h"

#include <linux/module.h>

#include "utils.h"


static char* selected_hash = "unknown";

int _ht_release_list(node_t *head);
int _ht_release_table(node_t **table, size_t size);
int _init_head(const ht_t *ht, size_t index);
void _ht_print_list(const ht_t *ht, const size_t index);

ht_t *ht_create(const size_t size, size_t (*hash)(void *)) {
    if(unlikely(size == 0) /*|| unlikely(hash == NULL)*/) {
#ifdef DEBUG
        INFO("Failed to create hash table (size: %lu)\n", size);
#endif
        return NULL;
    }
    ht_t *ht = kzalloc(sizeof(*ht), GFP_KERNEL);
    if (unlikely(ht == NULL)) {
        INFO("Failed to allocate memory for hash table\n");
        goto ret_null;
    }
    ht->size = size;
    ht->hash = hash;
    selected_hash = "unknown";
    // allocate memory for the heads of the lists
    ht->table = kzalloc(size * sizeof(node_t), GFP_KERNEL);
    if (unlikely(ht->table == NULL)) {
        INFO("Failed to allocate memory for hash table\n");
        goto free_table;
    }
    // initialize the heads of the lists
    for (size_t i = 0; i < size; i++) {
        ht->table[i] = kzalloc(sizeof(node_t), GFP_KERNEL);
        INIT_LIST_HEAD(&ht->table[i]->list);
    }
    INFO("allocated memory for hash table\n");
    return ht;

free_table:
    kfree(ht);
ret_null:
    return NULL;
}


/**
 * @name ht_destroy
 * @brief Free the memory allocated for the hash table.
 * @param ht - the hash table to be destroyed
 * @return
 */
int ht_destroy(const ht_t *ht) {
#ifdef DEBUG
    INFO("Destroying hash table\n");
#endif
    // free the memory allocated for the hash table
    if(!_ht_release_table(ht->table, ht->size)) {
        kfree(ht);
    }
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
        return;
    }
    // print hash table infos
    INFO("Table of size %lu, using hash function: %s\n", ht->size, selected_hash);
    for(size_t i = 0; i < ht->size; i++) {
        // print the number of elements in the list at the given index
        if(ht->table[i]->data != NULL) {
            INFO("Index %lu: %lu elements\n", i, ht_count(ht, i));
            _ht_print_list(ht, i);
        }
    }
    INFO("Free remaining slots: %lu\n", ht_count_free(ht));
}

void _ht_print_list(const ht_t *ht, const size_t index) {
    if(unlikely(ht == NULL) || unlikely(index >= ht->size)) {
        return;
    }
    // print the elements in the list at the given index
    node_t *pos;
    list_for_each_entry(pos, &ht->table[index]->list, list) {
        INFO("Data: %p -->\t", pos->data);
    }
    printk("\n");
}


// internal function to release the memory allocated for the list
int _ht_release_list(node_t *head) {
    if (unlikely(head == NULL)) {
        return -EINVAL;
    }
    node_t *tmp; // we need to use a temporary pointer to avoid dereferencing a freed pointer
    node_t *pos; // the current node
    list_for_each_entry_safe(pos, tmp, &head->list, list) {
        list_del(&pos->list);
        kfree(pos);
    }
    return 0;
}

// internal function to release the memory allocated for the hash table
int _ht_release_table(node_t **table, const size_t size) {
    if (unlikely(table == NULL) || unlikely(size == 0)) {
        return -EINVAL;
    }
#ifdef DEBUG
    INFO("Releasing hash table\n");
#endif
    for (size_t i = 0; i < size; i++) {
        if (table[i] != NULL) _ht_release_list(table[i]);
    }
#ifdef DEBUG
    INFO("Table released\n");
#endif
    kfree(table);
    return 0;
}


