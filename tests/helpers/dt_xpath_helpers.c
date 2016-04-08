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
    return rp_dt_get_value(dm_ctx, data_tree, xpath, false, value);
}

int
rp_dt_get_values_xpath(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, sr_val_t ***values, size_t *count)
{
    return rp_dt_get_values(dm_ctx, data_tree, xpath, false, values, count);
}

int
rp_dt_get_nodes_xpath(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, struct lyd_node ***nodes, size_t *count) {

    CHECK_NULL_ARG5(dm_ctx, data_tree, xpath, nodes, count);

    int rc = SR_ERR_OK;

    struct ly_set *set = NULL;
    rc = rp_dt_find_nodes(data_tree, xpath, false, &set);
    if (SR_ERR_OK != rc) {
        return rc;
    }

    *nodes = calloc(set->number, sizeof (**nodes));
    CHECK_NULL_NOMEM_GOTO(nodes, rc, cleanup);
    for (size_t i = 0; i < set->number; i++) {
        (*nodes)[i] = set->set.d[i];
    }
    *count = set->number;
cleanup:
    ly_set_free(set);
    return rc;
}

int
rp_dt_get_node(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, bool check_enable, struct lyd_node **node)
{
    return rp_dt_find_node(data_tree, xpath, check_enable, node);
}

int
rp_dt_get_node_xpath(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, struct lyd_node **node)
{
    return rp_dt_get_node(dm_ctx, data_tree, xpath, false, node);
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
    return rp_dt_set_item(ctx, session, xpath, opts, val);

}
