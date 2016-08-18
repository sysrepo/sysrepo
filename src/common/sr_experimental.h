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

/* Configuration */
#define MAX_BLOCKS_AVAIL_FOR_ALLOC 3

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
   unsigned obj_count;      /**< Object counter, i.e. how many values/trees/GPB messages use this context */
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



/**
 * @brief Allocate an instance of Sysrepo tree. The newly allocated tree has only
 * one node -- the tree root -- and can be expanded to its full desired size
 * through a repeated use of the function ::sr_node_add_child.
 *
 * @param [in] name Name for the newly allocated tree root. Can be NULL.
 * @param [in] module_name Name of the module that defines scheme of the tree root.
 *                         Can be NULL.
 * @param [out] node_p Returned newly allocated Sysrepo tree.
 */
int sr_new_tree(const char *root_name, const char *root_module_name, sr_node_t **tree_p);

/**
 * @brief Allocate an array of sysrepo trees (uninitialized tree roots).
 *
 * @param [in] count Length of the array to allocate.
 * @param [out] nodes_p Returned newly allocated array of trees.
 */
int sr_new_trees(size_t count, sr_node_t **trees_p);

/**
 * @brief Set/change name of a Sysrepo node.
 *
 * @param [in] node Sysrepo node to change the name of.
 * @param [in] name Name to set.
 */
int sr_node_set_name(sr_node_t *node, const char *name);

/**
 * @brief Set/change module of a Sysrepo node.
 *
 * @param [in] node Sysrepo node to change the module of.
 * @param [in] module_name Module name to set.
 */
int sr_node_set_module(sr_node_t *node, const char *module_name);

/**
 * @brief Store string into the Sysrepo node data.
 *
 * @param [in] node Sysrepo node to edit.
 * @param [in] string_val String value to set.
 */
int sr_node_set_string(sr_node_t *node, const char *string_val);

/**
 * @brief Create a new child for a given Sysrepo node.
 *
 * @param [in] parent Sysrepo node that should be parent of the newly created node.
 * @param [in] child_name Name of the newly created child node. Can be NULL.
 * @param [in] child_module_name Name of the module that defines scheme of the newly created
 *                               child node. Can be NULL.
 * @param [out] child_p Returned newly allocated child node.
 */
int sr_node_add_child(sr_node_t *parent, const char *child_name, const char *child_module_name,
        sr_node_t **child_p);

/**
 * @brief Duplicate node and all its descendants (with or without Sysrepo memory context)
 * into a new instance of Sysrepo tree with memory context.
 *
 * @param [in] root Root of a Sysrepo tree to duplicate.
 * @param [out] tree_dup_p Returned duplicate of the input tree.
 */
int sr_dup_tree(sr_node_t *tree, sr_node_t **tree_dup_p);

/**
 * @brief Duplicate an array of trees (with or without Sysrepo memory context) into a new
 * array of trees with memory context.
 *
 * @param [in] trees Array of sysrepo trees to duplicate.
 * @param [in] count Size of the array to duplicate.
 * @param [out] trees_dup_p Returned duplicate of the input array.
 */
int sr_dup_trees(sr_node_t *trees, size_t count, sr_node_t **trees_dup_p);

#endif /* SR_EXPERIMENTAL_H_ */
