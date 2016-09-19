/**
 * @file rp_dt_lookup.c
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

#include <stdbool.h>
#include <pthread.h>

#include "rp_dt_lookup.h"
#include "rp_dt_xpath.h"

int
rp_dt_find_nodes(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, bool check_enable, struct ly_set **nodes)
{
    CHECK_NULL_ARG3(dm_ctx, xpath, nodes);
    int rc = SR_ERR_OK;
    if (NULL == data_tree) {
        return SR_ERR_NOT_FOUND;
    }
    CHECK_NULL_ARG3(data_tree->schema, data_tree->schema->module, data_tree->schema->module->name);
    struct ly_set *res = lyd_find_xpath(data_tree, xpath);
    if (NULL == res) {
        SR_LOG_ERR_MSG("Lyd get node failed");
        return LY_EINVAL == ly_errno || LY_EVALID == ly_errno ? SR_ERR_INVAL_ARG : SR_ERR_INTERNAL;
    }

    if (check_enable) {
        /* lock ly_ctx_lock to schema_info_tree*/
        dm_schema_info_t *si = NULL;
        rc = dm_get_module_and_lock((dm_ctx_t *) dm_ctx, data_tree->schema->module->name, &si);
        if (rc != SR_ERR_OK) {
            SR_LOG_ERR("Get schema info failed for %s", data_tree->schema->module->name);
            ly_set_free(res);
            return rc;
        }
        for (int i = res->number - 1; i >= 0; i--) {
            if (!dm_is_enabled_check_recursively(res->set.d[i]->schema)) {
                memmove(&res->set.d[i],
                        &res->set.d[i + 1],
                        (res->number - i - 1) * sizeof (*res->set.d));
                res->number--;
            }
        }
        pthread_rwlock_unlock(&si->model_lock);
    }

    if (0 == res->number) {
        ly_set_free(res);
        return SR_ERR_NOT_FOUND;
    }
    *nodes = res;
    return SR_ERR_OK;

}

int
rp_dt_find_node(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, bool check_enable, struct lyd_node **node)
{
    CHECK_NULL_ARG3(dm_ctx, xpath, node);
    if (NULL == data_tree) {
        return SR_ERR_NOT_FOUND;
    }
    int rc = SR_ERR_OK;
    struct ly_set *res = NULL;
    rc = rp_dt_find_nodes(dm_ctx, data_tree, xpath, check_enable, &res);
    if (SR_ERR_OK != rc) {
        return rc;
    } else if (1 != res->number) {
        SR_LOG_ERR("Xpath %s matches more than one node", xpath);
        rc = SR_ERR_INVAL_ARG;
    } else {
        *node = res->set.d[0];
    }
    ly_set_free(res);
    return rc;
}

int
rp_dt_find_nodes_with_opts(const dm_ctx_t *dm_ctx, dm_session_t *dm_session, rp_dt_get_items_ctx_t *get_items_ctx, struct lyd_node *data_tree,
        const char *xpath, size_t offset, size_t limit, struct ly_set **nodes)
{
    CHECK_NULL_ARG5(dm_ctx, dm_session, get_items_ctx, data_tree, xpath);
    CHECK_NULL_ARG(nodes);

    int rc = SR_ERR_OK;
    bool cache_hit = false;

    SR_LOG_DBG("Get_nodes opts with args: %s %zu %zu", xpath, limit, offset);
    /* check if we continue where we left */
    if (get_items_ctx->xpath == NULL || 0 != strcmp(xpath, get_items_ctx->xpath) ||
            offset != get_items_ctx->offset) {
        ly_set_free(get_items_ctx->nodes);
        get_items_ctx->nodes = NULL;
        rc = rp_dt_find_nodes(dm_ctx, data_tree, xpath, dm_is_running_ds_session(dm_session), &get_items_ctx->nodes);

        if (SR_ERR_OK != rc) {
            if (SR_ERR_NOT_FOUND != rc) {
                SR_LOG_ERR("Look up failed for xpath %s", xpath);
            }
            free(get_items_ctx->xpath);
            get_items_ctx->xpath = NULL;
            return rc;
        }

        free(get_items_ctx->xpath);
        get_items_ctx->xpath = strdup(xpath);
        if (NULL == get_items_ctx->xpath) {
            SR_LOG_ERR_MSG("String duplication failed");
            return SR_ERR_INTERNAL;
        }
        get_items_ctx->offset = offset;

        SR_LOG_DBG_MSG("Cache miss in get_nodes_with_opts");

    } else {
        cache_hit = true;
        SR_LOG_DBG_MSG("Cache hit in get_nodes_with_opts");
    }


    size_t cnt = 0;
    /* setup index whether we continue using get_items_ctx or starting fresh */
    size_t index = cache_hit ? get_items_ctx->offset : 0;

    /*allocate nodes*/
    *nodes = ly_set_new();
    CHECK_NULL_NOMEM_RETURN(*nodes);

    /* selection from matched nodes */
    for (; index < get_items_ctx->nodes->number; index++) {
        if (cnt >= limit) {
            break;
        }
        /* append node to result if it is in chosen range*/
        if (index >= offset) {
            if (-1 == ly_set_add(*nodes, get_items_ctx->nodes->set.d[index], LY_SET_OPT_USEASLIST)) {
                SR_LOG_ERR_MSG("Adding to the result nodes failed");
                ly_set_free(*nodes);
                *nodes = NULL;
                return SR_ERR_INTERNAL;
            }
            cnt++;
        }
    }

    /* mark the index where the processing stopped*/
    get_items_ctx->offset = index;
    if (0 == cnt) {
        ly_set_free(*nodes);
        *nodes = NULL;
        return SR_ERR_NOT_FOUND;
    } else {
        return SR_ERR_OK;
    }
}

/**
 * @brief Test if the change matches the selection
 */
static int
rp_dt_match_change(const struct lys_node *selection_node, const struct lys_node *node, bool *res)
{
    CHECK_NULL_ARG2(node, res);

    if (NULL == selection_node) {
        *res = true;
        return SR_ERR_OK;
    }

    /* check if a node has been changes under subscription */
    struct lys_node *n = (struct lys_node *) node;
    while (NULL != n) {
        if (selection_node == n) {
            *res = true;
            return SR_ERR_OK;
        }
        n = lys_parent(n);
    }
    *res = false;
    return SR_ERR_OK;
}

int
rp_dt_find_changes(dm_ctx_t *dm_ctx, dm_session_t *session, dm_model_subscription_t *ms,
        rp_dt_change_ctx_t *change_ctx, const char *xpath, size_t offset, size_t limit, sr_list_t **changes)
{
    CHECK_NULL_ARG(dm_ctx);
    CHECK_NULL_ARG5(session, ms, change_ctx, xpath, changes);
    int rc = SR_ERR_OK;
    bool cache_hit = false;
    char *module_name = NULL;

    if (NULL == change_ctx->xpath || 0 != strcmp(xpath, change_ctx->xpath) || offset != change_ctx->offset) {
        rc = rp_dt_validate_node_xpath(dm_ctx, session, xpath, NULL, (struct lys_node **) &change_ctx->schema_node);
        CHECK_RC_LOG_RETURN(rc, "Selection node for changes can not be found xpath '%s'", xpath);
        free(change_ctx->xpath);
        change_ctx->xpath = strdup(xpath);
        CHECK_NULL_NOMEM_RETURN(change_ctx->xpath);
        change_ctx->offset = 0;
        change_ctx->position = 0;
    } else {
        cache_hit = true;
    }

    SR_LOG_DBG("Get changes: %s limit:%zu offset:%zu cache %s", xpath, limit, offset, cache_hit ? "hit" : "miss");

    size_t cnt = 0; /* number of returned changes (in offset limit range) */
    size_t index = cache_hit ? change_ctx->offset : 0; /* number of matching changes */

    rc = sr_list_init(changes);
    CHECK_RC_MSG_GOTO(rc, cleanup, "sr_list_init failed");
    size_t position = 0; /* index to change set */

    /* selection from model changes */
    for (position = change_ctx->position; position < ms->changes->count; position++) {
        bool match = false;
        sr_change_t *change = (sr_change_t *) ms->changes->data[position];

        rc = rp_dt_match_change(change_ctx->schema_node, change->sch_node, &match);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Match subscription failed");

        if (!match) {
            continue;
        }

        if (cnt >= limit) {
            break;
        }
        /* append change to result if it is in the chosen range */
        if (index >= offset) {
            if (SR_ERR_OK != sr_list_add(*changes, change)) {
                SR_LOG_ERR_MSG("Adding to the result changes failed");
                sr_list_cleanup(*changes);
                *changes = NULL;
                return SR_ERR_INTERNAL;
            }
            cnt++;
        }
        index++;
    }

    /* mark the index where the processing stopped*/
    change_ctx->offset = index;
    change_ctx->position = position;
    if (0 == cnt) {
        sr_list_cleanup(*changes);
        *changes = NULL;
        rc = SR_ERR_NOT_FOUND;
    }

cleanup:
    free(module_name);
    return rc;
}
