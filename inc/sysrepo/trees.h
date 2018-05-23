/**
 * @file trees.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Functions for simplified manipulation with Sysrepo trees.
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

#ifndef SYSREPO_TREES_H_
#define SYSREPO_TREES_H_

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup trees Tree Manipulation Utilities
 * @{
 *
 *  @brief Set of functions facilitating simplified manipulation and traversal
 *  of Sysrepo trees. As there are many connections between the tree nodes
 *  and also some internal attributes associated with each node, it is actually
 *  recommended to use these function rather than to allocate and initialize trees
 *  manually, which is very likely to lead to time-wasting and hard-to-debug programming
 *  errors.
 *  Iterative tree loading (@see SR_GET_SUBTREE_ITERATIVE) even requires to use
 *  designated functions for tree traversal -- ::sr_node_get_child and ::sr_node_get_next_sibling.
 *
 *  Another added benefit of using these function is that the trees created using
 *  ::sr_new_tree and ::sr_new_trees will be allocated using the Sysrepo's own memory management
 *  (if enabled) which was proven to be more efficient for larger data sets
 *  (far less copying, quicker conversion to/from google protocol buffer messages,
 *  stable memory footprint, etc.).
 */

/**
 * @brief Allocate an instance of Sysrepo tree. The newly allocated tree has only
 * one node -- the tree root -- and can be expanded to its full desired size
 * through a repeated use of the function ::sr_node_add_child.
 *
 * @param [in] root_name Name for the newly allocated tree root. Can be NULL.
 * @param [in] root_module_name Name of the module that defines scheme of the tree root.
 *                              Can be NULL.
 * @param [out] tree Returned newly allocated Sysrepo tree.
 */
int sr_new_tree(const char *root_name, const char *root_module_name, sr_node_t **tree);

/**
 * @brief Allocate an array of sysrepo trees (uninitialized tree roots).
 *
 * @param [in] tree_cnt Length of the array to allocate.
 * @param [out] trees Returned newly allocated array of trees.
 */
int sr_new_trees(size_t tree_cnt, sr_node_t **trees);

/**
 * @brief Reallocate an array of sysrepo trees (uninitialized tree roots).
 *
 * @param [in] old_tree_cnt Current length of the tree array.
 * @param [in] new_tree_cnt Desired length of the tree array.
 * @param [in,out] trees Returned newly allocated/enlarged array of trees.
 */
int sr_realloc_trees(size_t old_tree_cnt, size_t new_tree_cnt, sr_node_t **trees);

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
 * @brief Store data of string type into the Sysrepo node data.
 *
 * @param [in] node Sysrepo node to edit.
 * @param [in] type Exact type of the data.
 * @param [in] string_val String value to set.
 */
int sr_node_set_str_data(sr_node_t *node, sr_type_t type, const char *string_val);

/**
 * @brief Store data of string type into the Sysrepo node data. The actual data
 * will be built from the a format string and a variable arguments list.
 *
 * @param [in] node Sysrepo node to edit.
 * @param [in] type Exact type of the data.
 * @param [in] format Format string used to build the data.
 */
int sr_node_build_str_data(sr_node_t *node, sr_type_t type, const char *format, ...);

/**
 * @brief Create a new child for a given Sysrepo node.
 *
 * @param [in] parent Sysrepo node that should be parent of the newly created node.
 * @param [in] child_name Name of the newly created child node. Can be NULL.
 * @param [in] child_module_name Name of the module that defines scheme of the newly created
 *                               child node. Can be NULL.
 * @param [out] child Returned newly allocated child node.
 */
int sr_node_add_child(sr_node_t *parent, const char *child_name, const char *child_module_name,
        sr_node_t **child);

/**
 * @brief Duplicate node and all its descendants (with or without Sysrepo memory context)
 * into a new instance of Sysrepo tree with memory context.
 *
 * @param [in] tree Sysrepo tree to duplicate.
 * @param [out] tree_dup Returned duplicate of the input tree.
 */
int sr_dup_tree(const sr_node_t *tree, sr_node_t **tree_dup);

/**
 * @brief Duplicate an array of trees (with or without Sysrepo memory context) into a new
 * array of trees with memory context.
 *
 * @param [in] trees Array of sysrepo trees to duplicate.
 * @param [in] count Size of the array to duplicate.
 * @param [out] trees_dup Returned duplicate of the input array.
 */
int sr_dup_trees(const sr_node_t *trees, size_t count, sr_node_t **trees_dup);

/**
 * @brief Print sysrepo tree to STDOUT.
 *
 * @param [in] tree Sysrepo tree to print.
 * @param [in] depth_limit Maximum number of tree levels to print.
 */
int sr_print_tree(const sr_node_t *tree, int depth_limit);

/**
 * @brief Print sysrepo tree to the specified file descriptor.
 *
 * @param [in] fd File descriptor to print the tree into.
 * @param [in] tree Sysrepo tree to print.
 * @param [in] depth_limit Maximum number of tree levels to print.
 */
int sr_print_tree_fd(int fd, const sr_node_t *tree, int depth_limit);

/**
 * @brief Print sysrepo tree to the specified output file stream.
 *
 * @param [in] stream Output file stream to print the tree into.
 * @param [in] tree Sysrepo tree to print.
 * @param [in] depth_limit Maximum number of tree levels to print.
 */
int sr_print_tree_stream(FILE *stream, const sr_node_t *tree, int depth_limit);

/**
 * @brief Print sysrepo tree into a newly allocated memory buffer.
 * The caller is expected to eventually free the returned string.
 *
 * @param [in] mem_p Pointer to store the resulting dump.
 * @param [in] tree Sysrepo tree to print.
 * @param [in] depth_limit Maximum number of tree levels to print.
 */
int sr_print_tree_mem(char **mem_p, const sr_node_t *tree, int depth_limit);

/**
 * @brief Returns pointer to the first child (based on the schema) of a given node.
 * For a fully loaded tree it is equivalent to "node->first_child". For a partially
 * loaded tree (@see SR_GET_SUBTREE_ITERATIVE) it may internally issue a sysrepo
 * get-subtree-chunk request in order to obtain the data of the child
 * (and the data of some surrounding nodes with it for efficiency).
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] node Node to get the child of.
 * @return Pointer to a child node. NULL if there is none or an error occured.
 */
sr_node_t *sr_node_get_child(sr_session_ctx_t *session, sr_node_t *node);

/**
 * @brief Returns pointer to the next sibling (based on the schema) of a given node.
 * For a fully loaded tree it is equivalent to "node->next". For a partially
 * loaded tree (@see SR_GET_SUBTREE_ITERATIVE) it may internally issue a sysrepo
 * get-subtree-chunk request in order to obtain the data of the next sibling
 * (and the data of some surrounding nodes with it for efficiency).
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] node Node to get the next sibling of.
 * @return Pointer to the next sibling. NULL if this is the last sibling or an error occured.
 */
sr_node_t *sr_node_get_next_sibling(sr_session_ctx_t *session, sr_node_t *node);

/**
 * @brief Get the parent of a given node. It is equivalent to "node->parent", but for
 * a partially loaded tree it is preferred to use this function rather than to access
 * the pointer directly just for the sake of code cleanliness.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] node Node to get the parent of.
 * @return Pointer to the node's parent or NULL if the node is a root of a (sub)tree.
 */
sr_node_t *sr_node_get_parent(sr_session_ctx_t *session, sr_node_t *node);

/**@} trees */

#ifdef __cplusplus
}
#endif

#endif /* SYSREPO_TREES_H_ */
