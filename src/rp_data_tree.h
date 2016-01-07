/**
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

/**
 * @defgroup rp_dt Request processor datatree
 * @brief Functions for accessing and manipulation data trees.
 * @{
 */

/**
 * @brief Retrieves node from datatree based on location_id. Location_id can identify leaf, container or list
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
 * @brief Returns nodes under specified location_id. For leaf returns the same as rp_dt_get_node. If location_id identifies
 * the container returns its children. If the location_id identifies the list instance and all key values defined
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
 * @brief Retrieves all nodes corresponding to location_id using ::rp_dt_get_value_xpath and copy all values.
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
 * @}
 */
#endif /* SRC_RP_DATA_TREE_H_ */
