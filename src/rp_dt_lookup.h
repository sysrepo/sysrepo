/**
 * @defgroup rp_lu Request processor lookup functions 
 * @{
 * @brief 
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
#include "rp_node_stack.h"


/**
 * @brief Cache structure that holds the state of the last get_item_iter call.
 */
typedef struct rp_dt_get_items_ctx{
    char *xpath;            /**< xpath of the request*/
    bool recursive;         /**< flag denotes if the subtrees should be part of the response*/
    size_t offset;          /**< index of the node to be processed */
    rp_node_stack_t *stack; /**< stack of nodes to be processed in depth-first walk */
}rp_dt_get_items_ctx_t;

/**
 * @brief Returns children nodes
 * @param [in] node
 * @param [out] nodes
 * @param [out] count
 */
int rp_dt_get_all_children_node(struct lyd_node *node, struct lyd_node ***nodes, size_t *count);

/**
 * Return the sibling nodes with the same name
 * @param node
 * @param name
 * @param nodes
 * @param count
 * @return 
 */
int rp_dt_get_siblings_node_by_name(struct lyd_node *node, const char* name, struct lyd_node ***nodes, size_t *count);

/**
 * @brief Returns nodes under specified location_id. For leaf returns the same as rp_dt_get_node. If location_id identifies
 * the container returns its children. If the location_id identifies the list instance and all key values are defined
 * the children of the list instance is returned. If the location_id identifies the list and key values for the last list
 * are omitted, all instances of the list are returned. Finally, if the location_id identifies leaf-list all its members
 * are returned. If SR_ERR_OK is returned nodes must be freed by caller.
 * @param [in] dm_ctx
 * @param [in] data_tree
 * @param [in] loc_id
 * @param [out] nodes
 * @param [out] count
 * @return err_code
 */
int rp_dt_get_nodes(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const xp_loc_id_t *loc_id, struct lyd_node ***nodes, size_t *count);

/**
 * @brief Returns the nodes under specified location id. The selection of nodes can be altered using options recursive, offset, limit.
 * @param [in] dm_ctx
 * @param [in] dm_session
 * @param [in] get_items_ctx
 * @param [in] data_tree
 * @param [in] loc_id
 * @param [in] recursive
 * @param [in] offset
 * @param [in] limit
 * @param [out] nodes
 * @param [out] count
 * @return err_code
 */
int rp_dt_get_nodes_with_opts(const dm_ctx_t *dm_ctx, dm_session_t *dm_session, rp_dt_get_items_ctx_t *get_items_ctx, struct lyd_node *data_tree, const xp_loc_id_t *loc_id,
                                  bool recursive, size_t offset, size_t limit, struct lyd_node ***nodes, size_t *count);

/**
 * 
 * @param data_tree
 * @param loc_id
 * @param allow_no_keys
 * @param match_level
 * @param node
 * @return 
 */
int rp_dt_find_deepest_match(struct lyd_node *data_tree, const xp_loc_id_t *loc_id, bool allow_no_keys, size_t *match_level, struct lyd_node **node);

/**
 * @brief looks up the node in data tree. Returns first match in case of list without keys and leaf-list.
 * @param [in] data_tree
 * @param [in] loc_id
 * @param [in] allow_no_keys if set to TRUE, keys of the last list in xpath can be omitted. xpath must identify a list
 * @param [out] node
 */
int rp_dt_lookup_node(struct lyd_node *data_tree, const xp_loc_id_t *loc_id, bool allow_no_keys, struct lyd_node **node);

/**
 * @brief Retrieves node from datatree based on location_id. Location_id can identify leaf, leaf-list, container or list
 * with all key values defined.
 * @param [in] dm_ctx
 * @param [in] data_tree - root node of the model
 * @param [in] loc_id
 * @param [out] node
 * @return err_code
 */
int rp_dt_get_node(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const xp_loc_id_t *loc_id, struct lyd_node **node);

#endif /* RP_DT_LOOKUP_H */

/**
 * @}
 */
