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

#include "rp_dt_lookup.h"

int
rp_dt_get_all_children_node(struct lyd_node *node, bool check_enable, struct lyd_node ***nodes, size_t *count)
{
    CHECK_NULL_ARG3(node, nodes, count);
    /* get node count */
    size_t cnt = 0;
    struct lyd_node *n = node->child;
    while (NULL != n) {
        n = n->next;
        if (!check_enable || dm_is_enabled_check_recursively(n->schema)){
            cnt++;
        }
    }

    *count = cnt;
    *nodes = calloc(cnt, sizeof(**nodes));
    if (NULL == *nodes) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }

    n = node->child;
    cnt = 0;
    while (NULL != n) {
        if (!check_enable || dm_is_enabled_check_recursively(n->schema)){
            (*nodes)[cnt] = n;
            cnt++;
        }
        n = n->next;
    }
    return SR_ERR_OK;
}

int
rp_dt_get_siblings_node_by_name(struct lyd_node *node, const char* name, struct lyd_node ***nodes, size_t *count)
{
    CHECK_NULL_ARG4(node, name, nodes, count);
    CHECK_NULL_ARG2(node->schema, node->schema->name);
    size_t cnt = 0;
    struct lyd_node *n = node;
    while (NULL != n) {
        CHECK_NULL_ARG2(n->schema, n->schema->name);
        if (0 == strcmp(node->schema->name, n->schema->name)) {
            cnt++;
        }
        n = n->next;
    }

    *count = cnt;
    *nodes = calloc(cnt, sizeof(**nodes));
    if (NULL == *nodes) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }

    n = node;
    cnt = 0;
    while (NULL != n) {
        if (0 == strcmp(node->schema->name, n->schema->name)) {
            (*nodes)[cnt] = n;
            cnt++;
        }
        n = n->next;
    }
    return SR_ERR_OK;
}

int
rp_dt_get_all_siblings(struct lyd_node *node, bool check_enable, struct lyd_node ***nodes, size_t *count)
{
    CHECK_NULL_ARG3(node, nodes, count);
    CHECK_NULL_ARG2(node->schema, node->schema->name);
    size_t cnt = 0;
    struct lyd_node *n = node;
    while (NULL != n) {
        CHECK_NULL_ARG2(n->schema, n->schema->name);
        if (!check_enable || dm_is_enabled_check_recursively(n->schema)) {
            cnt++;
        }
        n = n->next;
    }

    *count = cnt;
    *nodes = calloc(cnt, sizeof(**nodes));
    if (NULL == *nodes) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }

    n = node;
    cnt = 0;
    while (NULL != n) {
        if (!check_enable || dm_is_enabled_check_recursively(n->schema)) {
            (*nodes)[cnt] = n;
            cnt++;
        }
        n = n->next;
    }
    return SR_ERR_OK;
}

int
rp_dt_find_nodes(struct lyd_node *data_tree, const char *xpath, bool check_enable, struct ly_set **nodes)
{
    CHECK_NULL_ARG2(xpath, nodes);
    if (NULL == data_tree) {
        return SR_ERR_NOT_FOUND;
    }
    struct ly_set *res = lyd_get_node(data_tree, xpath);
    if (NULL == res){
        SR_LOG_ERR_MSG("Lyd get node failed");
        return LY_EINVAL == ly_errno || LY_EVALID == ly_errno ? SR_ERR_INVAL_ARG : SR_ERR_INTERNAL;
    }

    if (check_enable) {
        for (size_t i = 0; i < res->number; i++) {
            if (!dm_is_enabled_check_recursively(res->set.d[i]->schema)) {
                ly_set_rm_index(res, i);
                i--; /* last item was moved to the index of remove node */
            }
        }
    }

    if (0 == res->number) {
        ly_set_free(res);
        return SR_ERR_NOT_FOUND;
    }
    *nodes = res;
    return SR_ERR_OK;
}

int
rp_dt_find_node(struct lyd_node *data_tree, const char *xpath, bool check_enable, struct lyd_node **node)
{
    CHECK_NULL_ARG2(xpath, node);
    if (NULL == data_tree) {
        return SR_ERR_NOT_FOUND;
    }
    int rc = SR_ERR_OK;
    struct ly_set *res = NULL;
    rc = rp_dt_find_nodes(data_tree, xpath, check_enable, &res);
    if (SR_ERR_OK != rc) {
        return rc;
    } else if (1 != res->number) {
        SR_LOG_ERR("Xpath %s matches more than one node", xpath);
        rc = SR_ERR_INVAL_ARG;
    } else{
        *node = res->set.d[0];
    }
    ly_set_free(res);
    return rc;
}


int
rp_dt_get_nodes(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, bool check_enable, struct lyd_node ***nodes, size_t *count)
{
    CHECK_NULL_ARG5(dm_ctx, data_tree, xpath, nodes, count);

    int rc = SR_ERR_OK;

    struct ly_set *set = NULL;
    rc = rp_dt_find_nodes(data_tree, xpath, check_enable, &set);
    if (SR_ERR_OK != rc) {
        return rc;
    }

    *nodes = calloc(set->number, sizeof(**nodes));
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
rp_dt_get_nodes_with_opts(const dm_ctx_t *dm_ctx, dm_session_t *dm_session, rp_dt_get_items_ctx_t *get_items_ctx, struct lyd_node *data_tree,
        const char *xpath, size_t offset, size_t limit, struct lyd_node ***nodes, size_t *count)
{
    CHECK_NULL_ARG5(dm_ctx, dm_session, get_items_ctx, data_tree, xpath);
    CHECK_NULL_ARG2(nodes, count);

    int rc = SR_ERR_OK;
    bool cache_hit = false;

    SR_LOG_DBG("Get_nodes opts with args: %s %zu %zu", xpath, limit, offset);
    /* check if we continue where we left */
    if (get_items_ctx->xpath == NULL || 0 != strcmp(xpath, get_items_ctx->xpath) ||
            offset != get_items_ctx->offset) {
        ly_set_free(get_items_ctx->nodes);
        get_items_ctx->nodes = NULL;
        rc = rp_dt_find_nodes(data_tree, xpath, dm_is_running_ds_session(dm_session), &get_items_ctx->nodes);

        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Look up failed for xpath %s",xpath);
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
    *nodes = calloc(limit, sizeof(**nodes));
    CHECK_NULL_NOMEM_RETURN(*nodes);

    /* process stack*/

    while (cnt < limit) {
        if (index >= get_items_ctx->nodes->number) {
            break;
        }
        /* append node to result if it is in chosen range*/
        if (index >= offset) {
            (*nodes)[cnt++] = get_items_ctx->nodes->set.d[index];
        }
        index++;
    }
    /* mark the index where the processing stopped*/
    get_items_ctx->offset = index;
    if (0 == cnt){
        free(*nodes);
        *nodes = NULL;
        return SR_ERR_NOT_FOUND;
    } else {
        *count = cnt;
        return SR_ERR_OK;
    }
}

int
rp_dt_lookup_node(struct lyd_node *data_tree, const char *xpath, bool allow_no_keys, bool check_enable, struct lyd_node **node)
{
    return rp_dt_find_node(data_tree, xpath, check_enable, node);
}
