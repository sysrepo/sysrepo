/**
 * @defgroup rp_lu Request processor's look up functions
 * @{
 * @brief Set of functions retrieving nodes from provided data tree according to
 * the location id.
 * @file rp_lookup.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 *
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

#ifndef RP_DT_LOOKUP_H
#define RP_DT_LOOKUP_H

#include <libyang/libyang.h>
#include "xpath_processor.h"
#include "data_manager.h"
#include "rp_internal.h"

/**
 * @brief Returns all children nodes. If check_enable is set to True returns
 * only the nodes that are enabled.
 * @param [in] node
 * @param [in] check_enable
 * @param [out] nodes
 * @param [out] count
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_get_all_children_node(struct lyd_node *node, bool check_enable, struct lyd_node ***nodes, size_t *count);

/**
 * Return the sibling nodes same name as provided node to the stack. Used
 * for list and leaf-list nodes. If check_enable is set to True returns
 * only the nodes that are enabled.
 * @param [in] node
 * @param [in] name
 * @param [out] nodes
 * @param [out] count
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_get_siblings_node_by_name(struct lyd_node *node, const char* name, struct lyd_node ***nodes, size_t *count);

/**
 * @brief Returns all the sibling nodes to the stack. Used for whole module xpath.
 * If check_enable is set to True returns only the nodes that are enabled.
 * @param [in] node
 * @param [in] check_enable
 * @param [out] nodes
 * @param [out] count
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_get_all_siblings(struct lyd_node *node, bool check_enable, struct lyd_node ***nodes, size_t *count);

/**
 * @brief Returns nodes under specified location_id. If location_id identifies
 * the container returns its children (if the request container is presence and contains
 * no children SR_ERR_OK is returned and returned count is 0).
 * If the location_id identifies the list instance and all key values are defined
 * the children of the list instance is returned. If the location_id identifies the list and key values for the last list
 * are omitted, all instances of the list are returned. If the location_id identifies leaf-list all its members
 * are returned. If the module xpath is provided it returns top level nodes.
 * @param [in] dm_ctx
 * @param [in] data_tree
 * @param [in] loc_id
 * @param [in] check_enable
 * @param [out] nodes
 * @param [out] count
 * @return Error code (SR_ERR_OK on success), SR_ERR_NOT_FOUND
 */
int rp_dt_get_nodes(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const xp_loc_id_t *loc_id, bool check_enable, struct lyd_node ***nodes, size_t *count);

/**
 * @brief Returns the nodes under specified location id. The selection of nodes can be altered using options recursive, offset, limit.
 * At the beginning, the nodes are pushed to stack according to the location id (the pushed content is the same as the result of ::rp_dt_get_nodes). Next
 * offset items is skipped. Then nodes are popped from stack and returned. Firs two
 * steps (pushing to stack, skipping) nodes can be skipped if saved state in get_items_ctx
 * correspond to the request.
 * @param [in] dm_ctx
 * @param [in] dm_session
 * @param [in] get_items_ctx - cache that can speed up the request. If the
 * subsequent nodes are requested.
 * @param [in] data_tree
 * @param [in] loc_id
 * @param [in] recursive - flag defining whether nodes of the subtrees should be included
 * @param [in] offset - how many nodes should be skipped at the beginning of the selection
 * @param [in] limit - maximum number of nodes that could be returned
 * @param [out] nodes
 * @param [out] count the length of returned nodes array
 * @return Error code (SR_ERR_OK on success), SR_ERR_NOT_FOUND
 */
int rp_dt_get_nodes_with_opts(const dm_ctx_t *dm_ctx, dm_session_t *dm_session, rp_dt_get_items_ctx_t *get_items_ctx, struct lyd_node *data_tree, const xp_loc_id_t *loc_id,
                                  bool recursive, size_t offset, size_t limit, struct lyd_node ***nodes, size_t *count);

/**
 * @brief Tries to find a match as deep as possible in provided data tree.
 * If the xpath identifies list/leaf-list first matching node is returned.
 * If the xpath identifies whole module first top level sibling is returned.
 * @param [in] data_tree - where the match is done
 * @param [in] loc_id
 * @param [in] allow_no_keys - if set to true the keys of the last list can be omitted,
 * otherwise SR_ERR_INVAL_ARG is returned
 * @param [in] check_enable - if set to true, not enabled nodes are skipped
 * @param [out] match_level - number of xpath level that has been match,
 * in case of whole module xpath 0
 * @param [out] node
 * @return Error code (SR_ERR_OK on success), SR_ERR_NOT_FOUND if no matching node has been found.
 * @note Function does not check if the xpath contains a valid nodes. To check xpath
 * validity use ::rp_dt_validate_node_xpath
 */
int rp_dt_find_deepest_match(struct lyd_node *data_tree, const xp_loc_id_t *loc_id, bool allow_no_keys, bool check_enable, size_t *match_level, struct lyd_node **node);

/**
 * @brief Looks up the exact match of node in data tree. Internally uses ::rp_dt_find_deepest_match.
 * @param [in] data_tree
 * @param [in] loc_id
 * @param [in] allow_no_keys if set to TRUE, keys of the last list in xpath can be omitted. xpath must identify a list
 * @param [in] check_enable
 * @param [out] node
 * @return Error code (SR_ERR_OK on success), SR_ERR_NOT_FOUND if match is not found
 */
int rp_dt_lookup_node(struct lyd_node *data_tree, const xp_loc_id_t *loc_id, bool allow_no_keys, bool check_enable, struct lyd_node **node);

#endif /* RP_DT_LOOKUP_H */

/**
 * @}
 */
