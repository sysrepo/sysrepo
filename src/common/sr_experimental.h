/**
 * @file sr_experimental.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Sysrepo experimental memory management API.
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

#ifndef SR_EXPERIMENTAL_H_
#define SR_EXPERIMENTAL_H_

#include "sysrepo.h"
#include "sr_protobuf.h"
#include "sr_data_structs.h"


/**
 * @brief Internal structure representing a single memory block.
 */
typedef struct sr_mem_block_s {
    char *mem;
    size_t size;
} sr_mem_block_t;

/**
 * @brief Sysrepo memory context, used for allocation of values, trees and GPB messages.
 */
typedef struct sr_mem_ctx_s {
   sr_llist_t *mem_blocks;  /**< Items are pointers to sr_mem_block_t */
   sr_llist_node_t *cursor; /**< Currently used memory block */
   size_t used;             /**< Memory usage of the current block */
   unsigned ucount;         /**< Usage counter, i.e. how many value/trees/GPB messages use this context */
} sr_mem_ctx_t;

/**
 * @brief Snapshot of a Sysrepo memory context.
 * Invalidated by sr_mem_free and sr_mem_restore for an older snapshot of the same context.
 */
typedef struct sr_mem_snapshot_s {
    sr_mem_ctx_t *sr_mem;       /**< Associated Sysrepo memory context. */
    sr_llist_node_t *mem_block; /**< Current memory block at the time of the snapshot. */
    size_t used;                /**< Memory usage of the current memory block at the time of the snapshot. */
    unsigned ucount;            /**< Usage count of the context at the time of the snapshot. */
} sr_mem_snapshot_t;


/**
 * @brief Create a new Sysrepo memory context.
 *
 * @param [in] min_size Min size of the first memory block.
 * @param [out] sr_mem Returned memory context.
 */
int sr_mem_new(size_t min_size, sr_mem_ctx_t **sr_mem);

/**
 * @brief Allocate *size* bytes from the *sr_mem* memory context.
 *
 * @param [in] sr_mem Sysrepo memory context to allocate memory from.
 *                    If NULL then malloc is called instead.
 * @param [in] size Size of the memory to allocate in bytes.
 */
void *sr_malloc(sr_mem_ctx_t *sr_mem, size_t size);

/**
 * @brief Allocate zeroed memory for *nmemb* items, each having *size* bytes
 * from the *sr_mem* memory context.
 *
 * @param [in] sr_mem Sysrepo memory context.
 *                    If NULL then calloc is called instead.
 * @param [in] nmemb Number of items to allocate memory for.
 * @param [in] size Size of each item.
 */
void *sr_calloc(sr_mem_ctx_t *sr_mem, size_t nmemb, size_t size);

/**
 * @brief Deallocate Sysrepo memory context.
 *
 * @param [in] sr_mem Memory context to deallocate.
 */
void sr_mem_free(sr_mem_ctx_t *sr_mem);

/**
 * @brief Get allocator for the protobuf-c library that will use specified Sysrepo
 * memory context for all the allocation.
 *
 * @param [in] sr_mem Memory context to be used by protobuf-c library.
 */
ProtobufCAllocator sr_get_protobuf_allocator(sr_mem_ctx_t *sr_mem);

/**
 * @brief Create a snapshot of a Sysrepo memory context.
 *
 * @param [in] sr_mem Sysrepo memory context to get the snapshot of.
 * @param [out] snapshot Returned snapshot.
 */
void sr_mem_snapshot(sr_mem_ctx_t *sr_mem, sr_mem_snapshot_t *snapshot);

/**
 * @brief Restore snapshot of a Sysrepo memory context.
 *
 * @param [in] snapshot Snapshot to restore.
 */
void sr_mem_restore(sr_mem_snapshot_t snapshot);

/**
 * @brief Set/change value of a string.
 *
 * @param [in] sr_mem Sysrepo memory context to use for memory allocation.
 *                    If NULL, strdup is used instead.
 * @param [in] string_p Pointer to the string to be changed.
 * @param [in] new_val String value to set.
 */
int sr_mem_edit_string(sr_mem_ctx_t *sr_mem, char **string_p, const char *new_val);

/**
 * @brief Deallocate an instance of Sr__Msg.
 */
void sr_msg_free(Sr__Msg *msg);



/** NEW PUBLIC API: */


/**
 * @brief Allocate an instance of Sysrepo value.
 *
 * @param [in] xpath Xpath to set for the newly allocated value. Can be NULL.
 * @param [out] value_p Returned newly allocated value.
 */
int sr_new_val(const char *xpath, sr_val_t **value_p);

/**
 * @brief Allocate an array of sysrepo values.
 *
 * @param [in] count Length of the array to allocate.
 * @param [out] values_p Returned newly allocated array of values.
 */
int sr_new_values(size_t count, sr_val_t **values_p);

/**
 * @brief Set/change xpath of a Sysrepo value.
 *
 * @param [in] value Sysrepo value to change the xpath of.
 * @param [in] xpath XPath to set.
 */
int sr_val_set_xpath(sr_val_t *value, const char *xpath);

/**
 * @brief Store string into the Sysrepo value data.
 *
 * @param [in] value Sysrepo value to edit.
 * @param [in] string_val String value to set.
 */
int sr_val_set_string(sr_val_t *value, const char *string_val);

/**
 * @brief Duplicate value (with or without Sysrepo memory context) into a new
 * instance with memory context.
 *
 * @param [in] value Sysrepo value to duplicate
 * @param [out] value_dup_p Returned duplicate of the input value.
 */
int sr_dup_val(sr_val_t *value, sr_val_t **value_dup_p);

/**
 * @brief Duplicate values (with or without Sysrepo memory context) into a new
 * array with memory context.
 *
 * @param [in] values Array of sysrepo values to duplicate
 * @param [in] count Size of the array to duplicate.
 * @param [out] values_dup_p Returned duplicate of the input array.
 */
int sr_dup_values(sr_val_t *values, size_t count, sr_val_t **values_dup_p);

#endif /* SR_EXPERIMENTAL_H_ */
