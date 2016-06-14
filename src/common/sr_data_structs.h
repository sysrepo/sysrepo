/**
 * @file sr_data_structs.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo data structures API.
 *
 * @copyright
 * Copyright 2016 Cisco Systems, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SR_DATA_STRUCTS_H_
#define SR_DATA_STRUCTS_H_

/**
 * @defgroup data_structs Sysrepo Data Structures
 * @ingroup common
 * @{
 *
 * @brief Data structures used in sysrepo (list, linked-list, self-balanced binary tree, circular buffer).
 */

/**
 * @brief Doubly linked list node structure.
 */
typedef struct sr_llist_node_s {
    void *data;                    /**< Data of the node. */
    struct sr_llist_node_s *prev;  /**< Previous node. */
    struct sr_llist_node_s *next;  /**< Next node. */
} sr_llist_node_t;

/**
 * @brief Doubly linked list context structure.
 */
typedef struct sr_llist_s {
    sr_llist_node_t *first;  /**< First node in the linked-list. */
    sr_llist_node_t *last;   /**< Last node in the linked-list. */
} sr_llist_t;

/**
 * @brief  Allocates and initializes a new linked-list instance.
 *
 *  @param[out] llist Pointer to the linked-list structure, it is supposed to be freed by ::sr_llist_cleanup.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_llist_init(sr_llist_t **llist);

/**
 * @brief Cleans up the linked-list and all the nodes within it.
 *
 * @param[in] llist Pointer to the linked-list structure.
 */
void sr_llist_cleanup(sr_llist_t *llist);

/**
 * @brief Allocates and adds a new node into the linked-list (at the end of it).
 *
 * @note O(1).
 *
 * @param[in] llist Pointer to the linked-list structure.
 * @param[in] data Data to be added into the new linked-list node.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_llist_add_new(sr_llist_t *llist, void *data);

/**
 * @brief Removes and frees the node from the linked-list.
 *
 *  @note O(1).
 *
 * @param[in] llist Pointer to the linked-list structure.
 * @param[in] node Node to be removed from the linked-list.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_llist_rm(sr_llist_t *llist, sr_llist_node_t *node);

/**
 * @brief List data structure.
 */
typedef struct sr_list_s {
    size_t count;   /**< Count of the elements currently stored in the list. */
    void **data;    /**< Array of data elements stored in the list. */
    size_t _size;   /**< Current allocated size of the list. Internal member, should not be touched. */
} sr_list_t;

/**
 * @brief Allocates and initializes a new list instance.
 *
 * @param[out] list Pointer to the list structure, it is supposed to be freed by ::sr_list_cleanup.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_list_init(sr_list_t **list);

/**
 * @brief Cleans up the list structure.
 *
 * @param[in] list Pointer to the list structure.
 */
void sr_list_cleanup(sr_list_t *list);

/**
 * @brief Adds a new element at the end of the list.
 *
 * @note O(1).
 *
 * @param[in] list Pointer to the list structure.
 * @param[in] item Item to be added.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_list_add(sr_list_t *list, void *item);

/**
 * @brief Removes an element from the list. If there are multiple matching
 * elements, removes the first one.
 *
 * @note O(n), optimized for removing from the end with O(1).
 *
 * @param[in] list Pointer to the list structure.
 * @param[in] item Item to be removed.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_list_rm(sr_list_t *list, void *item);

/**
 * @brief Removes an list element at specified position (starting with 0).
 *
 * @note O(1), but includes memmove.
 *
 * @param[in] list Pointer to the list structure.
 * @param[in] index Index of the item to be removed.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_list_rm_at(sr_list_t *list, size_t index);

/**
 * @brief Common context of balanced binary tree, independent of the library used.
 */
typedef struct sr_btree_s sr_btree_t;

/**
 * @brief Callback to be called to compare two items stored in the binary tree.
 */
typedef int (*sr_btree_compare_item_cb)(const void *, const void *);

/**
 * @brief Callback to be called to release an item stored in the binary tree.
 */
typedef void (*sr_btree_free_item_cb)(void *);

/**
 * @brief Allocates and initializes a new binary tree where items will be ordered
 * by provided compare function and released by provided cleanup function.
 *
 * @param[in] compare_item_cb Callback function to compare two items.
 * @param[in] free_item_cb Callback function to release an item.
 * @param[out] tree Binary tree context that can be used for subsequent tree manipulation calls.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_btree_init(sr_btree_compare_item_cb compare_item_cb, sr_btree_free_item_cb free_item_cb, sr_btree_t **tree);

/**
 * @brief Destroys and cleans up the binary tree, including all items stored within it
 * (cleanup callback on each item stored within the tree is automatically called).
 *
 * @param[in] tree Binary tree context acquired with ::sr_btree_init.
 */
void sr_btree_cleanup(sr_btree_t* tree);

/**
 * @brief Inserts a new item into the tree.
 *
 * A matching item to the inserted one (according to the compare function) must
 * not already exist in the tree, otherwise SR_ERR_EXISTS error is returned.
 *
 * @note O(log n).
 *
 * @param[in] tree Binary tree context acquired with ::sr_btree_init.
 * @param[in] item Item to be inserted.
 *
 * @return Error code (SR_ERR_OK on success, SR_ERR_EXISTS if the item already
 * exists in the tree, SR_ERR_NOMEM by memory allocation error).
 */
int sr_btree_insert(sr_btree_t *tree, void *item);

/**
 * @brief Deletes the item from the tree, if matching item item (according to
 * the compare function) exists in the tree.
 *
 * @note O(log n).
 *
 * @param[in] tree Binary tree context acquired with ::sr_btree_init.
 * @param[in] item Item to be deleted.
 */
void sr_btree_delete(sr_btree_t *tree, void *item);

/**
 * @brief Search for an item in the tree, matching with provided item according
 * to the compare function.
 *
 * @note O(log n).
 *
 * @param[in] tree Binary tree context acquired with ::sr_btree_init.
 * @param[in] item Item to be searched for.
 *
 * @return Matching item, NULL if the item has not been fond.
 */
void *sr_btree_search(const sr_btree_t *tree, const void *item);

/**
 * @brief Returns an item at given index position. Can be used to iterate over
 * all items in the tree.
 *
 * All items stored in the tree are virtually marked with indexes from 0 to
 * (number of items - 1). This function return an item that is internally marked
 * with given index.
 *
 * @note Use this function in an iteration from 0 to (number of items - 1).
 * Any Other usage may lead to unexpected behavior.
 *
 * @note O(log n).
 *
 * @param[in] tree Binary tree context acquired with ::sr_btree_init.
 * @param[in] index Index of an item.
 *
 * @return The item with given index, NULL if the item with given index does not exist.
 */
void *sr_btree_get_at(sr_btree_t *tree, size_t index);

/**
 * @brief FIFO circular buffer queue context.
 */
typedef struct sr_cbuff_s sr_cbuff_t;

/**
 * @brief Initializes FIFO circular buffer of elements with given size.
 *
 * You can provide initial capacity of the buffer. The buffer automatically
 * enlarges when it's full (it always doubles its capacity).
 *
 * @param[in] initial_capacity Initial buffer capacity in number of elements.
 * @param[in] elem_size Size of one element (in bytes).
 * @param[out] buffer Circular buffer queue context.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_cbuff_init(const size_t initial_capacity, const size_t elem_size, sr_cbuff_t **buffer);

/**
 * @brief Cleans up circular buffer.
 *
 * All memory allocated within provided circular buffer context will be freed.
 *
 * @param[in] buffer Circular buffer context.
 */
void sr_cbuff_cleanup(sr_cbuff_t *buffer);

/**
 * @brief Enqueues an element into circular buffer.
 *
 * @note O(1).
 *
 * @param[in] buffer Circular buffer context.
 * @param[in] item The element to be enqueued (pointer to memory from where
 * the data will be copied to buffer).
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_cbuff_enqueue(sr_cbuff_t *buffer, void *item);

/**
 * @brief Dequeues an element from circular buffer.
 *
 * @note O(1).
 *
 * @param[in] buffer Circular buffer queue context.
 * @param[out] item Pointer to memory where dequeued data will be copied.
 *
 * @return TRUE if an element was dequeued, FALSE if the buffer is empty.
 */
bool sr_cbuff_dequeue(sr_cbuff_t *buffer, void *item);

/**
 * @brief Return number of elements currently stored in the queue.
 *
 * @note O(1).
 *
 * @param[in] buffer Circular buffer queue context.
 *
 * @return Number of elements currently stored in the queue.
 */
size_t sr_cbuff_items_in_queue(sr_cbuff_t *buffer);

/**
 * @brief Locking set context.
 */
typedef struct sr_locking_set_s sr_locking_set_t;

/**
 * @brief Allocates & initializes the file locking set.
 *
 * @param [in] lset Locking set context, it is supposed to be freed by ::sr_locking_set_cleanup.
 *
 * @return Error code (SR_ERR_OK on success)
 */
int sr_locking_set_init(sr_locking_set_t **lset);

/**
 * @brief Frees all resources allocated in the file locking set context and the context itself.
 *
 * @param [in] lset Locking set context.
 */
void sr_locking_set_cleanup(sr_locking_set_t *lset);

/**
 * @brief Checks if the file is not locked in the provided context.
 * If not it locks the file based on provided file name. Identity must be
 * switched before calling the function. Opens the file and set the output argument.
 *
 * @param [in] lock_ctx Locking set context.
 * @param [in] filename Name of the file to be opened & locked.
 * @param [in] write TRUE if the file should be locked for writing by inter-process
 * access, FALSE if just for reading.
 * @param [in] blocking TRUE if the call should block until the lock can be acquired or an error occurs.
 * @param [out] fd File descriptor of opened file, NULL in case of error.
 *
 * @return Error code (SR_ERR_OK on success), SR_ERR_LOCKED if the file is already locked,
 * SR_ERR_UNATHORIZED if the file can not be locked because of the permission.
 */
int sr_locking_set_lock_file_open(sr_locking_set_t *lock_ctx, char *filename, bool write, bool blocking, int *fd);

/**
 * @brief Same as ::sr_locking_set_lock_file_open however it expects that file is already opened.
 *
 * @param [in] lock_ctx Locking set context.
 * @param [in] fd File descriptor of the opened file to be locked.
 * @param [in] filename Name of the file to be locked.
 * @param [in] write TRUE if the file should be locked for writing by inter-process
 * access, FALSE if just for reading.
 * @param [in] blocking TRUE if the call should block until the lock can be acquired or an error occurs.
 *
 * @return Error code (SR_ERR_OK on success), SR_ERR_LOCKED if the file is already locked,
 * SR_ERR_UNATHORIZED if the file can not be locked because of the permission.
 */
int sr_locking_set_lock_fd(sr_locking_set_t *lock_ctx, int fd, char *filename, bool write, bool blocking);

/**
 * @brief Looks up the file based on the filename in locking set. Then the file is unlocked and fd is closed.
 *
 * @param [in] lock_ctx Locking set context.
 * @param [in] filename Name of the file to be unlocked & closed.
 *
 * @return Error code (SR_ERR_OK on success)
 * SR_ERR_INVAL_ARG if the file had not been locked in provided context.
 */
int sr_locking_set_unlock_close_file(sr_locking_set_t *lock_ctx, char *filename);

/**
 * @brief Looks up the file based on the file descriptor in locking set. Then the file is unlocked and fd is closed.
 *
 * @param [in] lock_ctx Locking set context.
 * @param [in] fd File descriptor of the file to be unlocked & closed.
 *
 * @return Error code (SR_ERR_OK on success)
 * SR_ERR_INVAL_ARG if the file had not been locked in provided context.
 */
int sr_locking_set_unlock_close_fd(sr_locking_set_t *lock_ctx, int fd);

/**@} data_structs */

#endif /* SR_DATA_STRUCTS_H_ */
