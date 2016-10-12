/**
 * @file trees_internal.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Internal functions for simplified manipulation with Sysrepo trees.
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

#ifndef TREES_INTERNAL_H_
#define TREES_INTERNAL_H_

#include <stdio.h>

/**
 * @brief Type of the destination for the print operation.
 */
typedef enum sr_print_type_e {
    SR_PRINT_STREAM,  /**< File stream. */
    SR_PRINT_FD,      /**< File descriptor. */
    SR_PRINT_MEM      /**< Memory buffer. */
} sr_print_type_t;

/**
 * @brief Context for the print operation.
 */
typedef struct sr_print_ctx_s {
    sr_print_type_t type;
    union {
        int fd;
        FILE *stream;
        struct {
            char *buf;
            size_t len;
            size_t size;
        } mem;
    } method;
} sr_print_ctx_t;

/**
 * @brief Allocate a new instance of a sysrepo node over an existing sysrepo memory context.
 *
 * @param [in] sr_mem Sysrepo memory context.
 * @param [in] name Name of the node to create.
 * @param [in] module_name Name of the module that this node belongs to.
 * @param [out] node_p Returned newly allocate node.
 */
int sr_new_node(sr_mem_ctx_t *sr_mem, const char *name, const char *module_name, sr_node_t **node_p);

/**
 * @brief Insert child into the linked-list of children of a given parent node.
 *
 * @param [in] parent Parent node.
 * @param [in] child Child node.
 */
void sr_node_insert_child(sr_node_t *parent, sr_node_t *child);

/**
 * @brief Duplicate node and all its descendants (with or without Sysrepo memory context)
 * into a new instance of Sysrepo tree with memory context.
 * It is possible to specify the destination memory context or let the function to create a new one.
 *
 * @param [in] root Root of a Sysrepo tree to duplicate.
 * @param [in] sr_mem_dest Destination memory context.
 *                         If NULL, a new context will be created.
 * @param [out] tree_dup_p Returned duplicate of the input tree.
 */
int sr_dup_tree_ctx(sr_node_t *tree, sr_mem_ctx_t *sr_mem_dest, sr_node_t **tree_dup_p);

/**
 * @brief Duplicate an array of trees (with or without Sysrepo memory context) into a new
 * array of trees with memory context. It is possible to specify the destination memory context
 * or let the function to create a new one.
 *
 * @param [in] trees Array of sysrepo trees to duplicate.
 * @param [in] count Size of the array to duplicate.
 * @param [in] sr_mem_dest Destination memory context.
 *                         If NULL, a new context will be created.
 * @param [out] trees_dup_p Returned duplicate of the input array.
 */
int sr_dup_trees_ctx(sr_node_t *trees, size_t count, sr_mem_ctx_t *sr_mem_dest, sr_node_t **trees_dup_p);

#endif /* TREES_H_ */
