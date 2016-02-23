/**
 * @file dt_xpath_helpers.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief
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

#include "dt_xpath_helpers.h"
#include "rp_dt_get.h"
#include "rp_dt_edit.h"
#include "sr_common.h"

int
rp_dt_get_value_xpath(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, sr_val_t **value)
{
    CHECK_NULL_ARG4(dm_ctx, data_tree, xpath, value);

    int rc = SR_ERR_OK;
    xp_loc_id_t *l = NULL;
    rc = xp_char_to_loc_id(xpath, &l);

    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Converting xpath '%s' to loc_id failed.", xpath);
        return rc;
    }
    rc = rp_dt_get_value(dm_ctx, data_tree, l, false, value);
    xp_free_loc_id(l);
    return rc;
}

int
rp_dt_get_values_xpath(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, sr_val_t ***values, size_t *count)
{
    CHECK_NULL_ARG5(dm_ctx, data_tree, xpath, values, count);

    int rc = SR_ERR_OK;
    xp_loc_id_t *l = NULL;
    rc = xp_char_to_loc_id(xpath, &l);

    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Converting xpath '%s' to loc_id failed.", xpath);
        return rc;
    }
    rc = rp_dt_get_values(dm_ctx, data_tree, l, false, values, count);
    xp_free_loc_id(l);
    return rc;
}

int
rp_dt_get_nodes_xpath(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, struct lyd_node ***nodes, size_t *count)
{
    CHECK_NULL_ARG5(dm_ctx, data_tree, xpath, nodes, count);

    int rc = SR_ERR_OK;
    xp_loc_id_t *l = NULL;
    rc = xp_char_to_loc_id(xpath, &l);

    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Converting xpath '%s' to loc_id failed.", xpath);
        return rc;
    }
    rc = rp_dt_get_nodes(dm_ctx, data_tree, l, false, nodes, count);
    xp_free_loc_id(l);
    return rc;
}

int
rp_dt_get_node(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const xp_loc_id_t *loc_id, bool check_enable, struct lyd_node **node)
{
    CHECK_NULL_ARG4(dm_ctx, data_tree, loc_id, node);
    CHECK_NULL_ARG(loc_id->xpath);
    if (XP_IS_MODULE_XPATH(loc_id)) {
        SR_LOG_ERR("Module xpath %s can not be use in get_node call", loc_id->xpath);
        return SR_ERR_INVAL_ARG;
    }
    return rp_dt_lookup_node(data_tree, loc_id, false, check_enable, node);
}

int
rp_dt_get_node_xpath(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, struct lyd_node **node)
{
    CHECK_NULL_ARG4(dm_ctx, data_tree, xpath, node);

    int rc = SR_ERR_OK;
    xp_loc_id_t *l = NULL;
    rc = xp_char_to_loc_id(xpath, &l);

    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Converting xpath '%s' to loc_id failed.", xpath);
        return rc;
    }
    rc = rp_dt_get_node(dm_ctx, data_tree, l, false, node);
    xp_free_loc_id(l);
    return rc;
}

/**
 * Beware: doesn't log the operation to the session won't be permanent
 * even after commit
 * @param [in] ctx
 * @param [in] session
 * @param [in] xpath
 * @param [in] opts
 * @param [in] val
 * @return Error code (SR_ERR_OK on success)
 */
int
rp_dt_set_item_xpath(dm_ctx_t *ctx, dm_session_t *session, const char *xpath, sr_edit_options_t opts, sr_val_t *val)
{
    int rc = SR_ERR_OK;
    xp_loc_id_t *loc_id = NULL;
    rc = xp_char_to_loc_id(xpath, &loc_id);
    if(SR_ERR_OK != rc) {
        return rc;
    }

    rc = rp_dt_set_item(ctx, session, loc_id, opts, val);
    xp_free_loc_id(loc_id);
    return rc;
}
