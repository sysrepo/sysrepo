/**
 * @defgroup rp_xp Data tree XPath helpers
 * @ingroup rp
 * @{
 * @brief Functions for creating and validating xpath.
 * @file rp_dt_xpath.h
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

#ifndef SRC_RP_DT_XPATH_H_
#define SRC_RP_DT_XPATH_H_

#include <libyang/libyang.h>
#include "data_manager.h"

/**
 * @brief Creates xpath for the selected node. Function walks from the node
 * up to the top-level node. Namespace is explictly specified for top level node
 * and augment nodes.
 * @param [in] node
 * @param [out] xpath
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_create_xpath_for_node(const struct lyd_node *node, char **xpath);

/**
 * @brief Validates the location_id with schema. If the provided xpath identifies whole
 * module it only validates if the module exists. For other xpaths, functions does the following checks:
 * - tests if the top level node's namespace is specified
 * - tests if the model exists (if not returns SR_ERR_UNKNOWN_MODEL)
 * - tests if the nodes exists in the model (if not returns SR_ERR_BAD_ELEMENT)
 * - tests if the keys name and key count are valid (if not returns SR_ERR_BAD_ELEMENT)
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] xpath input to be validated
 * @param [out] matched_module pointer to the module where the xpath is pointing (in case of augment, augmented module)
 * @param [out] match schema node is returned if NULL is not passed
 * @return Error code (SR_ERR_OK on success) SR_ERR_UNKNOWN_MODEL, SR_ERR_BAD_ELEMENT
 */
int rp_dt_validate_node_xpath(dm_ctx_t *dm_ctx, dm_session_t *session, const char *xpath, const struct lys_module **matched_module, struct lys_node **match);

/**
 * @brief Enables the subtree specified by xpath in running data store. Until then, data retrieval calls return
 * SR_ERR_NOT_FOUND and no edit like calls can be made for the specified xpath and the nodes underneath.
 *
 * @note Function expects that a schema info is locked for writing.
 *
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] schema_info - schema info where xpath should be enalbed. Function expects that caller holds a write lock
 * for the schema info
 * @param [in] xpath
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_enable_xpath(dm_ctx_t *dm_ctx, dm_session_t *session, dm_schema_info_t *schema_info, const char *xpath);

/**
 *
 * @note Schema info read lock is acquired on successful return from function. Must be released by caller.
 *
 * @param dm_ctx
 * @param session
 * @param xpath
 * @param schema_info
 * @param match
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_validate_node_xpath_lock(dm_ctx_t *dm_ctx, dm_session_t *session, const char *xpath, dm_schema_info_t **schema_info, struct lys_node **match);

/**
 *
 * @note Function acquires and releases read lock for the schema info.
 *
 * @param dm_ctx
 * @param session
 * @param xpath
 * @param schema_info
 * @param match
 * @return
 */
int rp_dt_validate_node_xpath_without_lock(dm_ctx_t *dm_ctx, dm_session_t *session, const char *xpath, dm_schema_info_t **schema_info, struct lys_node **match);

/**
 * @}
 */
#endif /* SRC_RP_DT_XPATH_H_ */
