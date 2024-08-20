//
// Created by effi on 13/08/24.
//

#include "ht_dllist.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uuid.h>
#include <linux/hash.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/namei.h>
#include "utils.h"





/* Internal API to manage the hash table - not exposed to the user.
 * The wrapper API, defined in ht_dllist.h, will call these functions,
 * and they are responsible for the RCU protection.
 */
int _ht_release_list(node_t *list); // effectively release the memory allocated at given bucket index
int _ht_release_table(node_t **table); // effectively release the memory allocated for the hash table
size_t _ht_index(node_t *node); // get the index of the element in the hash table
void _ht_print_list(node_t *list); // print the elements in the given list
size_t _ht_count_list(node_t *list); // count the number of elements in the given list
node_t* _ht_search_list_key(node_t *list, size_t key); // search for the data in the given list
node_t* _ht_remove_from_list(node_t *list, node_t *node); // remove the data from the given list
size_t _gen_key(const char* path); // generate a unique key for the data
bool _is_path_valid(const char* path);
bool _path_exists(const char* path);
size_t _ht_index(node_t *node);

static ht_t __rcu *glb_ht; // global hash table
// get the instance of the global hash table
ht_t *ht_get_instance(void) {
    return rcu_dereference(glb_ht);
}

ht_t *ht_create(const size_t size) {
    if(unlikely(size == 0)) {
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
 * @param node - the element to be inserted
 * @return
 */
int ht_insert(ht_t *ht, node_t *node) {
    if(unlikely(ht == NULL || node == NULL)) {
#ifdef DEBUG
        INFO("Passing null table (%p) or null data (%p)\n", ht, node);
#endif
        return -EINVAL;
    }
    INFO("looking up")
    // check if the data is already in the hash table
    if (ht_lookup(ht, node) != NULL) {
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
    INFO("grabbing the lock");
    // get the current hash table
    old_ht = rcu_dereference_protected(ht, lockdep_is_held(&ht->lock));
    *new_ht = *old_ht;
    // now we are safe to modify the hash table
    size_t index = _ht_index(node);
    // insert the node at the head of the list belonging to the given index
    INFO("ADDING");
    list_add_rcu(&node->list, &new_ht->table[index]->list);
    INFO("ADDED");
    // update the hash table, then release the lock and synchronize the RCU
    rcu_assign_pointer(ht, new_ht);
    spin_unlock(&ht->lock);
    INFO("releasing the lock");
    synchronize_rcu();
    INFO("sync");
    kfree(old_ht);
    return 0;

}

// count the number of elements in the hash table
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
    const ht_t *tmp_ht = rcu_dereference(ht);
    for(size_t i = 0; i < HT_SIZE; i++) {
        count[i] = _ht_count_list(tmp_ht->table[i]);
    }
    rcu_read_unlock();
ret:
    return count;
}

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
        node_t *tmp_list_head = rcu_dereference(ht)->table[i];
        printk("Index %lu: %lu elements\n", i, _ht_count_list(tmp_list_head));
        _ht_print_list(tmp_list_head);
    }
    rcu_read_unlock();
    INFO("End of table\n");
}

void _ht_print_list(node_t *list) {
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
        printk("[%lu::%s]-->", tmp_head->key, tmp_head->path);
    }
    // print a newline at the end of the list
    printk("\n");
}

// internal function to release the memory allocated for the list
int _ht_release_list(node_t *list) {
    if (unlikely(list == NULL)) {
#ifdef DEBUG
        INFO("passing null table\n");
#endif
        return -EINVAL;
    }
    node_t *tmp_head;
    list_for_each_entry_rcu(tmp_head, &list->list, list) {
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
        if (table[i] != NULL) _ht_release_list(table[i]);
    }
#ifdef DEBUG
    INFO("Table released\n");
#endif
    kfree(table);
    return 0;
}

/**
* @name _ht_index
* @brief Get the index of the element in the hash table.
* @param ht - the hash table
* @param node - the element to be inserted
* @return hash(data) % HT_SIZE
*/
node_t* ht_lookup(ht_t *ht, node_t *node) {
    if(unlikely(ht == NULL || node == NULL)) {
#ifdef DEBUG
        INFO("Passing null table (%p) or null node (%p)\n", ht, node);
#endif
        goto not_found;
    }
    // find the list where the data should be - no need to lock the hash table
    const size_t index = _ht_index(node);
    // we need to iterate over the linked list at the given index in the hash table
    // so we need to lock the hash table
    rcu_read_lock();
    node_t *tmp_head = rcu_dereference(ht)->table[index];
    node_t *found = _ht_search_list_key(tmp_head, node->key);
    rcu_read_unlock();
    if (found != NULL) {
        return found;
    }
not_found:
    return NULL;
}

node_t* _ht_search_list_key(node_t *list, const size_t key) {
    if(unlikely(list == NULL || key <= 0)) {
#ifdef DEBUG
        INFO("Passing null list (%p) or invalid key (%lu)\n", list, key);
#endif
        goto not_found;
    }
    // find the element in the list
    node_t *tmp_node;   // loop cursor
    list_for_each_entry_rcu(tmp_node, &list->list, list) {
        // compare the key of the node with the key of the data
        if (tmp_node->key == key) {
            return tmp_node;
        }
    }
not_found:
    return NULL;
}

node_t* _ht_remove_from_list(node_t *list, node_t *node) {
    if (unlikely(list == NULL || node == 0)) {
#ifdef DEBUG
        INFO("Passing null list (%p) or null node (%p)\n", list, node);
#endif
        return NULL;
    }
    // find the element in the list and remove it
    //! the wrapper function will take care of locking the hash table
    // remember that we are using a doubly linked list, so we can swap the pointers

    // be sure that the data is in the list
    if (_ht_search_list_key(list, node->key) == NULL) {
#ifdef DEBUG
        INFO("Data not found in the list\n");
#endif
        return NULL;
    }
    // the data is in the list
    node_t *to_be_removed = _ht_search_list_key(list, node->key);
    // the item is in the list, so we can swap the pointers
    struct list_head *prev = to_be_removed->list.prev;
    struct list_head *next = to_be_removed->list.next;
    list_del_rcu(&node->list);
    prev->next = next;
    next->prev = prev;
    return to_be_removed;
}

int ht_delete(ht_t *ht, node_t *node) {
    if (unlikely(ht == NULL || node == NULL)) {
#ifdef DEBUG
        INFO("Passing null table (%p) or null data (%p)\n", ht, node);
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
    size_t index = _ht_index(node);
    node_t *removed = _ht_remove_from_list(new_ht->table[index], node);
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

// generate a unique key for the data
size_t _gen_key(const char* path) {
     /* We use kernel hash function to generate a key for the data.
      * Doing so, we have high probability to have unique keys for different pathname (like the stars in the sky),
      * but we can still have collisions for same pathname.
     */
    if (unlikely(path == NULL)) {
#ifdef DEBUG
        INFO("Passing null pathname (%p)\n", path);
#endif
        return -EINVAL;
    }
    // just call the kernel hash function
    return hash_ptr(path, HT_BIT_KEY_SIZE);
}

node_t* node_init(const char* path) {
    if (unlikely(path == NULL || strcmp(path, "") == 0)) {
        INFO("Empty path\n");
        return NULL;
    }
    // check if the inserted path is valid and exists
    if (!_is_path_valid(path)) {
        INFO("Invalid path %s\n", path);
        return NULL;
    }
    if (!_path_exists(path)) {
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
    node->key = _gen_key(path);
    // initialize pointers for new node
    INIT_LIST_HEAD_RCU(&node->list);
    return node;
}

// define the hash function
size_t hash_node(node_t *node) {
    if(unlikely(node == NULL)) {
#ifdef DEBUG
        INFO("Passing Null data (%p)\n", node);
#endif
        return -EINVAL;
    }
    // compute the hash -- size_t is an alias for unsigned long
    return hash_long(node->key, HT_BIT_SIZE);

}

// check if the path exists in the file system
bool _path_exists(const char* path) {
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

bool _is_path_valid(const char* path) {
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

    // Check for trailing slash
    if (strcmp(&path[len - 1], "/") == 0) {
        INFO("Path ends with /\n");
        return false;
    }

    // Check for double slashes
    if (strstr(path, "//") != NULL) {
        INFO("Double slashes in the path\n");
        return false;
    }

    return true;
}

size_t _ht_index(node_t *node) {
    if(unlikely(node == NULL)) {
#ifdef DEBUG
        INFO("Passing null node (%p)\n", node);
#endif
        return -EINVAL;
    }
    return hash_node(node) % HT_SIZE;
}