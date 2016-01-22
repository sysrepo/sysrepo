/**
 * @defgroup rp_dt Request Processor's Datatree Helpers
 * @{
 * @brief Functions for accessing and manipulation data trees.
 * @file rp_data_tree.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief 
 *
 * @copyright
 * Copyright 2015 Cisco Systems, Inc.
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


#ifndef SRC_RP_DATA_TREE_H_
#define SRC_RP_DATA_TREE_H_

#include <libyang/libyang.h>
#include "xpath_processor.h"
#include "data_manager.h"
#include "sysrepo.h"
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
 * @brief Retrieves node from datatree based on location_id. Location_id can identify leaf, leaf-list, container or list
 * with all key values defined.
 * @param [in] dm_ctx
 * @param [in] data_tree - root node of the model
 * @param [in] loc_id
 * @param [out] node
 * @return err_code
 */
int rp_dt_get_node(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const xp_loc_id_t *loc_id, struct lyd_node **node);

/**
 * @brief Retrieves node from datatree based on xpath. It converts the xpath to loc_id and calls ::rp_dt_get_node internally.
 * @param [in] dm_ctx
 * @param [in] data_tree - root node of the model
 * @param [in] loc_id
 * @param [out] node
 * @return err_code
 */
int rp_dt_get_node_xpath(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, struct lyd_node **node);

/**
 * @brief Returns the value for the specified location_id for leaf, container and list.
 * @param [in] dm_ctx
 * @param [in] data_tree
 * @param [in] loc_id
 * @param [out] value
 * @return err_code
 */
int rp_dt_get_value(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const xp_loc_id_t *loc_id, sr_val_t **value);

/**
 * @brief Returns the value for the specified xpath for leaf, container and list. It converts the xpath to loc_id
 * and calls ::rp_dt_get_value internally.
 * @param [in] dm_ctx
 * @param [in] data_tree
 * @param [in] xpath
 * @param [out] value
 * @return err_code
 */
int rp_dt_get_value_xpath(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, sr_val_t **value);

/**
 * @brief Returns the value for the specified xpath. Internally converts xpath to location_id and looks up the datatree
 * @param [in] dm_ctx
 * @param [in] dm_session
 * @param [in] xpath
 * @param [out] value
 * @return err_code
 */
int rp_dt_get_value_wrapper(dm_ctx_t *dm_ctx, dm_session_t *dm_session, const char *xpath, sr_val_t **value);

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
 * @brief Converts the xpath to loc_id and calls ::rp_dt_get_nodes internally.
 * @param [in] dm_ctx
 * @param [in] data_tree
 * @param [in] xpath
 * @param [out] nodes
 * @param [out] count
 * @return err_code
 */
int rp_dt_get_nodes_xpath(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, struct lyd_node ***nodes, size_t *count);

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
 * @brief Retrieves all nodes corresponding to location_id using ::rp_dt_get_nodes and copy all values.
 * @param [in] dm_ctx
 * @param [in] data_tree
 * @param [in] loc_id
 * @param [out] values
 * @param [out] count
 * @return err_code
 */
int rp_dt_get_values(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const xp_loc_id_t *loc_id, sr_val_t ***values, size_t *count);


/**
 * @brief Converts the xpath to loc_id and calls ::rp_dt_get_values internally.
 * @param [in] dm_ctx
 * @param [in] data_tree
 * @param [in] xpath
 * @param [out] values
 * @param [out] count
 * @return err_code
 */
int rp_dt_get_values_xpath(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, sr_val_t ***values, size_t *count);


/**
 * @brief Returns the values for the specified xpath. Internally converts xpath to location_id and looks up the datatree.
 * @param [in] dm_ctx
 * @param [in] dm_session
 * @param [in] xpath
 * @param [out] values
 * @param [out] count
 * @return err_code
 */
int rp_dt_get_values_wrapper(dm_ctx_t *dm_ctx, dm_session_t *dm_session, const char *xpath, sr_val_t ***values, size_t *count);

/**
 * @brief Returns the values for the specified xpath. Internally converts xpath to location_id and looks up the datatree. The
 * selection of returned valued can be specified by recursive, limit and offset.
 * @param [in] dm_ctx
 * @param [in] dm_session
 * @param [in] get_items_ctx
 * @param [in] xpath
 * @param [in] recursive - include all nodes under the selected xpath
 * @param [in] offset - return the values with index and above
 * @param [in] limit - the maximum count of values that can be returned
 * @param [out] values
 * @param [out] count
 */
int rp_dt_get_values_wrapper_with_opts(dm_ctx_t *dm_ctx, dm_session_t *dm_session, rp_dt_get_items_ctx_t *get_items_ctx, const char *xpath,
                                       bool recursive, size_t offset, size_t limit, sr_val_t ***values, size_t *count);


/**
 * @}
 */
#endif /* SRC_RP_DATA_TREE_H_ */
