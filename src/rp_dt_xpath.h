/**
 * @defgroup rp_xp Request Processor's xpath Helpers
 * @{
 * @brief Functions for creating xpath.
 * @file rp_xpath.h
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
#include "xpath_processor.h"

/**
 * @brief Creates xpath for the selected node.
 */
int rp_dt_create_xpath_for_node(const struct lyd_node *data_tree, char **xpath);

/**
 * @brief Validates the location_id with schema
 * @param [in] dm_ctx
 * @param [in] loc_id
 * @param [out]match schema node is returned if NULL is not passed
 * @return err_code
 */
int rp_dt_validate_node_xpath(dm_ctx_t *dm_ctx, const xp_loc_id_t *loc_id, struct lys_node **match);

/**
 * @}
 */
#endif /* SRC_RP_DT_XPATH_H_ */
