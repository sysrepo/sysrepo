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
 * @brief Data structures used in sysrepo (balanced binary tree, circular buffer).
 */

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
 * @param[in] tree Binary tree context acquired with ::sr_btree_init.
 * @param[in] item Item to be deleted.
 */
void sr_btree_delete(sr_btree_t *tree, void *item);

/**
 * @brief Search for an item in the tree, matching with provided item according
 * to the compare function.
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
 * @param[in] buffer Circular buffer queue context.
 * @param[out] item Pointer to memory where dequeued data will be copied.
 *
 * @return TRUE if an element was dequeued, FALSE if the buffer is empty.
 */
bool sr_cbuff_dequeue(sr_cbuff_t *buffer, void *item);

/**
 * @brief Return number of elements currently stored in the queue.
 *
 * @param[in] buffer Circular buffer queue context.
 *
 * @return Number of elements currently stored in the queue.
 */
size_t sr_cbuff_items_in_queue(sr_cbuff_t *buffer);

/**@} data_structs */

#endif /* SR_DATA_STRUCTS_H_ */
