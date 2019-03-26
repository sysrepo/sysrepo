/**
 * @file sr_mem_mgmt.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Sysrepo memory management API.
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

#ifndef SR_MEM_MGMT_H_
#define SR_MEM_MGMT_H_

#include <stdbool.h>

#include "sr_data_structs.h"
#include "sr_protobuf.h"

/* Configuration */
#define MEM_BLOCK_MIN_SIZE          256 /**< Minimal memory block size */
#define MAX_BLOCKS_AVAIL_FOR_ALLOC    3 /**< Maximum number of memory block available for allocation */
#define MAX_FREE_MEM_CONTEXTS         4 /**< Maximum number of free memory contexts */
#define MEM_PEAK_USAGE_HISTORY_LENGTH 3 /**< Length of peak memory usage history */

/**
 * @brief Internal structure representing a single memory block.
 */
typedef struct sr_mem_block_s {
    size_t size;     /**< Size of the memory block. */
    char mem[];      /**< Memory block. */
} sr_mem_block_t;

/**
 * @brief Sysrepo memory context, used for allocation of values, trees and GPB messages.
 */
typedef struct sr_mem_ctx_s {
   sr_llist_t *mem_blocks;  /**< Items are pointers to sr_mem_block_t */
   sr_llist_node_t *cursor; /**< Currently used memory block */
   size_t used[MAX_BLOCKS_AVAIL_FOR_ALLOC]; /**< Queue of memory usages of the last MAX_BLOCKS_AVAIL_FOR_ALLOC blocks */
   size_t used_head;        /**< Head of the *used* queue */
   size_t used_total;       /**< Total number of bytes allocated (or skipped) in a Sysrepo memory context. */
   size_t size_total;       /**< Total number of bytes used by a Sysrepo memory context. */
   size_t peak;             /**< Peak usage of the memory context. Resets only in ::sr_mem_free. */
   size_t piggy_back;       /**< Piggybacking.
                                 Used for threads to exchange information about the recent peak memory usage. */
   ATOMIC_UINT32_T obj_count; /**< Object counter, i.e. how many values/trees/GPB messages use this context */
} sr_mem_ctx_t;

/**
 * @brief Snapshot of a Sysrepo memory context.
 * Invalidated by sr_mem_free and sr_mem_restore for an older snapshot of the same context.
 */
typedef struct sr_mem_snapshot_s {
    sr_mem_ctx_t *sr_mem;       /**< Associated Sysrepo memory context. */
    sr_llist_node_t *mem_block; /**< Current memory block at the time of the snapshot. */
    size_t used[MAX_BLOCKS_AVAIL_FOR_ALLOC]; /**< Memory usage of the last MAX_BLOCKS_AVAIL_FOR_ALLOC blocks */
    size_t used_head;           /**< Head of the *used* queue */
    size_t used_total;          /**< Total memory usage at the time of the snapshot. */
    unsigned obj_count;         /**< Object count of the context at the time of the snapshot. */
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
 * @brief Reallocate *new_size* instead *old_size* bytes from the *sr_mem* memory context.
 *
 * @param [in] sr_mem Sysrepo memory context to allocate memory from.
 *                    If NULL then malloc is called instead.
 * @param [in] ptr Current memory held.
 * @param [in] old_size Size of the current memory in bytes.
 * @param [in] new_size Size of the new memory in bytes.
 */
void *sr_realloc(sr_mem_ctx_t *sr_mem, void *ptr, size_t old_size, size_t new_size);

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
void sr_mem_restore(sr_mem_snapshot_t *snapshot);

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
 * @brief Set/change value of a string using format string and a variable list of arguments.
 *
 * @param [in] sr_mem Sysrepo memory context to use for memory allocation.
 *                    If NULL, calloc is used instead.
 * @param [in] string_p Pointer to the string to be changed.
 * @param [in] format Format string of value to set.
 * @param [in] args Variable list of arguments to the format string.
 */
int sr_mem_edit_string_va(sr_mem_ctx_t *sr_mem, char **string_p, const char *format, va_list args);

/**
 * @brief Deallocate an instance of Sr__Msg.
 */
void sr_msg_free(Sr__Msg *msg);

#endif /* SR_MEM_MGMT_H_ */
