/**
 * @defgroup xp_helpers Xpath test helpers 
 * @{
 * @brief 
 * @file xpath_helpers.h
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

#ifndef XPATH_HELPERS_H
#define XPATH_HELPERS_H

#include <libyang/libyang.h>
#include "data_manager.h"

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
 * @brief Retrieves node from datatree based on xpath. It converts the xpath to loc_id and calls ::rp_dt_get_node internally.
 * @param [in] dm_ctx
 * @param [in] data_tree - root node of the model
 * @param [in] loc_id
 * @param [out] node
 * @return err_code
 */
int rp_dt_get_node_xpath(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, struct lyd_node **node);

/**
 * @brief
 * @param [in] ctx
 * @param [in] session
 * @param [in] xpath
 * @param [in] opts
 * @param [in] val
 * @return Error code
 */
int rp_dt_set_item_xpath(dm_ctx_t *ctx, dm_session_t *session, const char *xpath, sr_edit_options_t opts, sr_val_t *val);
#endif /* XPATH_HELPERS_H */

/**
 * @}
 */
