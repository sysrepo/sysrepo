/**
 * @defgroup rp_lu Data tree lookup functions
 * @ingroup rp
 * @{
 * @brief Set of functions retrieving nodes from provided data tree according to
 * the location id.
 * @file rp_dt_lookup.h
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
#include "data_manager.h"
#include "rp_internal.h"

/**
 * @brief Returns the nodes matching xpath. The selection of nodes can be altered using options offset and limit.
 * At the beginning, the nodes are looked up using ::rp_dt_find_nodes. Next
 * offset items are skipped. Then sr_val_t structures are filled from nodes. Nodes look up can
 * be skipped if saved state in get_items_ctx correspond to the request.
 * @param [in] dm_ctx
 * @param [in] dm_session
 * @param [in] get_items_ctx - cache that can speed up the request. If the
 * subsequent nodes are requested.
 * @param [in] data_tree
 * @param [in] xpath
 * @param [in] offset - how many nodes should be skipped at the beginning of the selection
 * @param [in] limit - maximum number of nodes that could be returned
 * @param [out] nodes
 * @return Error code (SR_ERR_OK on success), SR_ERR_NOT_FOUND
 */
int rp_dt_find_nodes_with_opts(const dm_ctx_t *dm_ctx, dm_session_t *dm_session, rp_dt_get_items_ctx_t *get_items_ctx, struct lyd_node *data_tree, const char *xpath,
                              size_t offset, size_t limit, struct ly_set **nodes);

/**
 * @brief Looks up the node matching xpath. If there are more than one node in result
 * SR_ERR_INVAL_ARG is returned.
 * @param [in] dm_ctx
 * @param [in] data_tree
 * @param [in] xpath
 * @param [in] check_enable
 * @param [out] node
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_find_node(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, bool check_enable, struct lyd_node **node);

/**
 * @brief Looks up the nodes matching xpath.
 * @param [in] dm_ctx
 * @param [in] data_tree
 * @param [in] xpath
 * @param [in] check_enable
 * @param [out] nodes
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_find_nodes(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, bool check_enable, struct ly_set **nodes);

/**
 * @brief Find matching changes
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] ms - model subscriptions where changes are stored
 * @param [in] change_ctx - cache for the iteration in changes
 * @param [in] xpath - used for selection of the changes to be returned
 * @param [in] offset
 * @param [in] limit - maximum number of changes to be returned
 * @param [out] changes - matching changes
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_find_changes(dm_ctx_t *dm_ctx, dm_session_t *session, dm_model_subscription_t *ms, rp_dt_change_ctx_t *change_ctx, const char *xpath, size_t offset, size_t limit, sr_list_t **changes);

#endif /* RP_DT_LOOKUP_H */

/**
 * @}
 */
