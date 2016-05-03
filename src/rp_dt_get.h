/**
 * @defgroup rp_get Data tree get helpers
 * @ingroup rp
 * @{
 * @brief Function for retrieving values from data trees.
 * @file rp_dt_get.h
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

#ifndef RP_DT_GET_H
#define RP_DT_GET_H

#include "request_processor.h"
#include "rp_dt_lookup.h"

/**
 * @brief Retrieves all nodes matching xpath using ::rp_dt_find_nodes and copy fills sr_val_t structures.
 * @param [in] dm_ctx
 * @param [in] data_tree
 * @param [in] xpath
 * @param [in] check_enable
 * @param [out] values
 * @param [out] count
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_get_values(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, bool check_enable, sr_val_t ***values, size_t *count);

/**
 * @brief Returns the value for the specified xpath. If more than one node matching xpath,
 * SR_ERR_INVAL_ARG is returned.
 * @param [in] dm_ctx
 * @param [in] data_tree
 * @param [in] xpath
 * @param [in] check_enable
 * @param [out] value
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_get_value(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, bool check_enable, sr_val_t **value);

/**
 * @brief Returns the value for the specified xpath.
 * @param [in] rp_ctx
 * @param [in] rp_session
 * @param [in] xpath
 * @param [out] value
 * @return Error code (SR_ERR_OK on success), SR_ERR_NOT_FOUND, SR_ERR_UNKNOWN_MODEL, SR_ERR_BAD_ELEMENT
 */
int rp_dt_get_value_wrapper(rp_ctx_t *rp_ctx, rp_session_t *rp_session, const char *xpath, sr_val_t **value);

/**
 * @brief Returns the values for the specified xpath.
 * @param [in] rp_ctx
 * @param [in] rp_session
 * @param [in] xpath
 * @param [out] values
 * @param [out] count
 * @return Error code (SR_ERR_OK on success), SR_ERR_NOT_FOUND, SR_ERR_UNKNOWN_MODEL, SR_ERR_BAD_ELEMENT
 */
int rp_dt_get_values_wrapper(rp_ctx_t *rp_ctx, rp_session_t *rp_session, const char *xpath, sr_val_t ***values, size_t *count);

/**
 * @brief Returns the values for the specified xpath. Internally calls ::rp_dt_find_nodes_with_opts
 * to identify the matching nodes. The selection of returned values can be specified by limit and offset.
 * @param [in] rp_ctx
 * @param [in] rp_session
 * @param [in] get_items_ctx
 * @param [in] xpath
 * @param [in] offset - return the values with index and above
 * @param [in] limit - the maximum count of values that can be returned
 * @param [out] values
 * @param [out] count
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_get_values_wrapper_with_opts(rp_ctx_t *rp_ctx, rp_session_t *rp_session, rp_dt_get_items_ctx_t *get_items_ctx, const char *xpath,
                                       size_t offset, size_t limit, sr_val_t ***values, size_t *count);

#endif /* RP_DT_GET_H */

/**
 * @}
 */
