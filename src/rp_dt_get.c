/**
 * @file rp_dt_get.c
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

#include <libyang/libyang.h>
#include <pthread.h>
#include <inttypes.h>
#include "sysrepo.h"
#include "sr_common.h"

#include "access_control.h"
#include "rp_internal.h"
#include "rp_dt_get.h"
#include "rp_dt_xpath.h"
#include "rp_dt_edit.h"
#include "rp_dt_filter.h"

void
rp_dt_free_state_data_ctx_content (rp_state_data_ctx_t *state_data)
{
    if (NULL != state_data) {
        if (NULL != state_data->subscriptions) {
            np_subscriptions_list_cleanup(state_data->subscriptions);
            state_data->subscriptions = NULL;
        }
        if (NULL != state_data->subtrees) {
            for (size_t i = 0; i< state_data->subtrees->count; i++) {
                free(state_data->subtrees->data[i]);
            }
        }
        sr_list_cleanup(state_data->subtrees);
        state_data->subtrees = NULL;

        sr_list_cleanup(state_data->subtree_nodes);
        state_data->subtree_nodes = NULL;

        sr_list_cleanup(state_data->subscription_nodes);
        state_data->subscription_nodes = NULL;

        if (NULL != state_data->requested_xpaths) {
            for (size_t i = 0; i < state_data->requested_xpaths->count; i++) {
                free(state_data->requested_xpaths->data[i]);
            }
            sr_list_cleanup(state_data->requested_xpaths);
            state_data->requested_xpaths = NULL;
        }
        state_data->overlapping_leaf_subscription = false;
        state_data->internal_state_data = false;
    }
}

/**
 * @brief Fills sr_val_t from lyd_node structure. It fills xpath and copies the value.
 * @param [in] node
 * @param [out] value
 * @return Error code (SR_ERR_OK on success)
 */
static int
rp_dt_get_value_from_node(struct lyd_node *node, sr_val_t *val)
{
    CHECK_NULL_ARG3(node, val, node->schema);

    int rc = SR_ERR_OK;
    char *xpath = NULL;
    struct lyd_node_leaf_list *data_leaf = NULL;
    struct lys_node_container *sch_cont = NULL;
    struct lyd_node_anydata *sch_any = NULL;

    rc = rp_dt_create_xpath_for_node(val->_sr_mem, node, &xpath);
    CHECK_RC_MSG_RETURN(rc, "Create xpath for node failed");
    val->xpath = xpath;

    switch (node->schema->nodetype) {
    case LYS_LEAF:
        data_leaf = (struct lyd_node_leaf_list *) node;
        val->dflt = node->dflt;
        val->type = sr_libyang_leaf_get_type(data_leaf);
        rc = sr_libyang_leaf_copy_value(data_leaf, val);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Copying of value failed");
        break;
    case LYS_CONTAINER:
        sch_cont = (struct lys_node_container *) node->schema;
        val->type = sch_cont->presence == NULL ? SR_CONTAINER_T : SR_CONTAINER_PRESENCE_T;
        val->dflt = node->dflt;
        break;
    case LYS_NOTIF:
        val->type = SR_NOTIFICATION_T;
        break;
    case LYS_LIST:
        val->type = SR_LIST_T;
        break;
    case LYS_LEAFLIST:
        data_leaf = (struct lyd_node_leaf_list *) node;
        val->dflt = node->dflt;
        val->type = sr_libyang_leaf_get_type(data_leaf);
        rc = sr_libyang_leaf_copy_value(data_leaf, val);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Copying of value failed");
        break;
    case LYS_ANYXML:
    case LYS_ANYDATA:
        sch_any = (struct lyd_node_anydata *) node;
        val->dflt = node->dflt;
        val->type = (LYS_ANYXML == node->schema->nodetype) ? SR_ANYXML_T : SR_ANYDATA_T;
        rc = sr_libyang_anydata_copy_value(sch_any, val);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Copying of value failed");
        break;
    default:
        SR_LOG_WRN_MSG("Get value is not implemented for this node type");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }
    return SR_ERR_OK;

cleanup:
    sr_free_val_content(val);
    return rc;
}

int
rp_dt_get_values_from_nodes(sr_mem_ctx_t *sr_mem, struct ly_set *nodes, sr_val_t **values, size_t *value_cnt)
{
    CHECK_NULL_ARG2(nodes, values);
    int rc = SR_ERR_OK;
    sr_val_t *vals = NULL;
    sr_mem_snapshot_t snapshot = { 0, };
    size_t cnt = 0;
    struct lyd_node *node = NULL;

    if (sr_mem) {
        sr_mem_snapshot(sr_mem, &snapshot);
    }

    vals = sr_calloc(sr_mem, nodes->number, sizeof(*vals));
    CHECK_NULL_NOMEM_RETURN(vals);
    if (sr_mem) {
        ATOMIC_INC(&sr_mem->obj_count);
    }

    for (size_t i = 0; i < nodes->number; i++) {
        vals[cnt]._sr_mem = sr_mem;
        node = nodes->set.d[i];
        if (NULL == node || NULL == node->schema || LYS_RPC == node->schema->nodetype ||
            LYS_NOTIF == node->schema->nodetype || LYS_ACTION == node->schema->nodetype) {
            /* ignore this node */
            continue;
        }
        rc = rp_dt_get_value_from_node(node, &vals[cnt]);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Getting value from node %s failed", node->schema->name);
            if (sr_mem) {
                sr_mem_restore(&snapshot);
            } else {
                sr_free_values(vals, cnt);
            }
            return SR_ERR_INTERNAL;
        }
        cnt++;
    }

    *values = vals;
    *value_cnt = cnt;

    return rc;
}

int
rp_dt_get_value(dm_ctx_t *dm_ctx, rp_session_t *rp_session, struct lyd_node *data_tree, sr_mem_ctx_t *sr_mem,
        const char *xpath, bool check_enabled, sr_val_t **value)
{
    CHECK_NULL_ARG5(dm_ctx, rp_session, data_tree, xpath, value);
    int rc = SR_ERR_OK;
    sr_val_t *val = NULL;
    struct lyd_node *node = NULL;
    unsigned int node_cnt = 1;

    rc = rp_dt_find_node(dm_ctx, data_tree, xpath, check_enabled, &node);
    if (SR_ERR_OK != rc) {
        if (SR_ERR_NOT_FOUND != rc) {
            SR_LOG_ERR("Find node failed (%d) xpath %s", rc, xpath);
        }
        return rc;
    }

    rc = rp_dt_nacm_filtering(dm_ctx, rp_session, data_tree, &node, &node_cnt);
    CHECK_RC_MSG_RETURN(rc, "Failed to filter node by NACM read access.");
    if (0 == node_cnt) {
        return SR_ERR_NOT_FOUND;
    }

    val = sr_calloc(sr_mem, 1, sizeof(*val));
    CHECK_NULL_NOMEM_RETURN(val);

    if (sr_mem) {
        val->_sr_mem = sr_mem;
        ATOMIC_INC(&sr_mem->obj_count);
    }

    rc = rp_dt_get_value_from_node(node, val);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Get value from node failed for xpath %s", xpath);
        sr_free_val(val);
    } else {
        *value = val;
    }

    return rc;
}

int
rp_dt_get_values(dm_ctx_t *dm_ctx, rp_session_t *rp_session, struct lyd_node *data_tree, sr_mem_ctx_t *sr_mem,
        const char *xpath, bool check_enable, sr_val_t **values, size_t *count)
{
    CHECK_NULL_ARG5(dm_ctx, data_tree, xpath, values, count);

    int rc = SR_ERR_OK;
    struct ly_set *nodes = NULL;

    rc = rp_dt_find_nodes(dm_ctx, data_tree, xpath, check_enable, &nodes);
    if (SR_ERR_OK != rc) {
        if (SR_ERR_NOT_FOUND != rc) {
            SR_LOG_ERR("Get nodes for xpath %s failed (%d)", xpath, rc);
        }
        goto cleanup;
    }

    rc = rp_dt_nacm_filtering(dm_ctx, rp_session, data_tree, nodes->set.d, &nodes->number);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to filter nodes by NACM read access.");
    if (0 == nodes->number) {
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    rc = rp_dt_get_values_from_nodes(sr_mem, nodes, values, count);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Copying values from nodes failed for xpath '%s'", xpath);
    }

cleanup:
    if (NULL != nodes) {
        ly_set_free(nodes);
    }
    return rc;
}

int
rp_dt_get_subtree(dm_ctx_t *dm_ctx, rp_session_t *rp_session, struct lyd_node *data_tree, sr_mem_ctx_t *sr_mem,
        const char *xpath, bool check_enabled, sr_node_t **subtree)
{
    CHECK_NULL_ARG4(dm_ctx, data_tree, xpath, subtree);
    int rc = SR_ERR_OK;
    sr_node_t *tree = NULL;
    struct lyd_node *node = NULL;
    sr_tree_pruning_cb pruning_cb = NULL;
    rp_tree_pruning_ctx_t *pruning_ctx = NULL;

    rc = rp_dt_find_node(dm_ctx, data_tree, xpath, check_enabled, &node);
    if (SR_ERR_OK != rc) {
        if (SR_ERR_NOT_FOUND != rc) {
            SR_LOG_ERR("Find node failed (%d) xpath %s", rc, xpath);
        }
        return rc;
    }

    rc = rp_dt_init_tree_pruning(dm_ctx, rp_session, node, data_tree, check_enabled, &pruning_cb, &pruning_ctx);
    if (SR_ERR_UNAUTHORIZED == rc) {
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to initialize sysrepo tree pruning.");

    tree = sr_calloc(sr_mem, 1, sizeof(*tree));
    CHECK_NULL_NOMEM_GOTO(tree, rc, cleanup);

    if (sr_mem) {
        tree->_sr_mem = sr_mem;
        ATOMIC_INC(&sr_mem->obj_count);
    }

    rc = sr_copy_node_to_tree(node, pruning_cb, (void *)pruning_ctx, tree);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Copy node to tree failed for xpath %s", xpath);

cleanup:
    rp_dt_cleanup_tree_pruning(pruning_ctx);
    if (SR_ERR_OK != rc) {
        sr_free_tree(tree);
    } else {
        *subtree = tree;
    }

    return rc;
}

int
rp_dt_get_subtree_chunk(dm_ctx_t *dm_ctx, rp_session_t *rp_session, struct lyd_node *data_tree, sr_mem_ctx_t *sr_mem,
        const char *xpath, size_t slice_offset, size_t slice_width, size_t child_limit, size_t depth_limit,
        bool check_enabled, sr_node_t **chunk, char **chunk_id)
{
    CHECK_NULL_ARG5(dm_ctx, data_tree, xpath, chunk, chunk_id);
    int rc = SR_ERR_OK;
    sr_node_t *tree = NULL;
    char *id = NULL, *id_cpy = NULL;
    struct lyd_node *node = NULL;
    sr_tree_pruning_cb pruning_cb = NULL;
    rp_tree_pruning_ctx_t *pruning_ctx = NULL;

    rc = rp_dt_find_node(dm_ctx, data_tree, xpath, check_enabled, &node);
    if (SR_ERR_OK != rc) {
        if (SR_ERR_NOT_FOUND != rc) {
            SR_LOG_ERR("Find node failed (%d) xpath %s", rc, xpath);
        }
        return rc;
    }

    rc = rp_dt_init_tree_pruning(dm_ctx, rp_session, node, data_tree, check_enabled, &pruning_cb, &pruning_ctx);
    if (SR_ERR_UNAUTHORIZED == rc) {
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to initialize sysrepo tree pruning.");

    tree = sr_calloc(sr_mem, 1, sizeof(*tree));
    CHECK_NULL_NOMEM_GOTO(tree, rc, cleanup);

    if (sr_mem) {
        tree->_sr_mem = sr_mem;
        ATOMIC_INC(&sr_mem->obj_count);
    }

    rc = sr_copy_node_to_tree_chunk(node, slice_offset, slice_width, child_limit, depth_limit, pruning_cb,
                                    (void *)pruning_ctx, tree);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Copy node to tree failed for xpath %s", xpath);

    /* get ID of the tree chunk */
    id = lyd_path(node);
    if (NULL == id) {
        SR_LOG_ERR("Failed to get ID of a subtree chunk with xpath %s", xpath);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }
    rc = sr_mem_edit_string(sr_mem, &id_cpy, id);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to copy ID of a subtree chunk with xpath %s", xpath);

cleanup:
    free(id);
    rp_dt_cleanup_tree_pruning(pruning_ctx);
    if (SR_ERR_OK != rc) {
        sr_free_tree(tree);
    } else {
        *chunk = tree;
        *chunk_id = id_cpy;
    }

    return rc;
}

int
rp_dt_get_subtrees(dm_ctx_t *dm_ctx, rp_session_t *rp_session, struct lyd_node *data_tree, sr_mem_ctx_t *sr_mem,
        const char *xpath, bool check_enable, sr_node_t **subtrees, size_t *count)
{
    CHECK_NULL_ARG5(dm_ctx, data_tree, xpath, subtrees, count);
    int rc = SR_ERR_OK;
    struct ly_set *nodes = NULL;
    sr_tree_pruning_cb pruning_cb = NULL;
    rp_tree_pruning_ctx_t *pruning_ctx = NULL;

    rc = rp_dt_find_nodes(dm_ctx, data_tree, xpath, check_enable, &nodes);
    if (SR_ERR_OK != rc) {
        if (SR_ERR_NOT_FOUND != rc) {
            SR_LOG_ERR("Get nodes for xpath %s failed (%d)", xpath, rc);
        }
        return rc;
    }

    rc = rp_dt_init_tree_pruning(dm_ctx, rp_session, NULL, data_tree, check_enable, &pruning_cb, &pruning_ctx);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to initialize sysrepo tree pruning.");

    rc = sr_nodes_to_trees(nodes, sr_mem, pruning_cb, (void *)pruning_ctx, subtrees, count);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Conversion of nodes to trees failed for xpath '%s'", xpath);
        goto cleanup;
    }
    if (0 == *count) {
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

cleanup:
    rp_dt_cleanup_tree_pruning(pruning_ctx);
    ly_set_free(nodes);
    return rc;
}

int
rp_dt_get_subtrees_chunks(dm_ctx_t *dm_ctx, rp_session_t *rp_session, struct lyd_node *data_tree, sr_mem_ctx_t *sr_mem,
        const char *xpath, size_t slice_offset, size_t slice_width, size_t child_limit, size_t depth_limit,
        bool check_enable, sr_node_t **chunks_p, size_t *count_p, char ***chunk_ids_p)
{
    CHECK_NULL_ARG3(dm_ctx, data_tree, xpath);
    CHECK_NULL_ARG3(chunks_p, count_p, chunk_ids_p);

    int rc = SR_ERR_OK;
    sr_node_t *chunks = NULL;
    size_t count = 0;
    char **chunk_ids = NULL;
    struct ly_set *nodes = NULL;
    sr_tree_pruning_cb pruning_cb = NULL;
    rp_tree_pruning_ctx_t *pruning_ctx = NULL;

    rc = rp_dt_find_nodes(dm_ctx, data_tree, xpath, check_enable, &nodes);
    if (SR_ERR_OK != rc) {
        if (SR_ERR_NOT_FOUND != rc) {
            SR_LOG_ERR("Get nodes for xpath %s failed (%d)", xpath, rc);
        }
        return rc;
    }

    rc = rp_dt_init_tree_pruning(dm_ctx, rp_session, NULL, data_tree, check_enable, &pruning_cb, &pruning_ctx);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to initialize sysrepo tree pruning.");

    rc = sr_nodes_to_tree_chunks(nodes, slice_offset, slice_width, child_limit, depth_limit, sr_mem,
            pruning_cb, (void *)pruning_ctx, &chunks, &count, &chunk_ids);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Conversion of nodes to trees failed for xpath '%s'", xpath);
    if (0 == count) {
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    *chunks_p = chunks;
    *count_p = count;
    *chunk_ids_p = chunk_ids;

cleanup:
    rp_dt_cleanup_tree_pruning(pruning_ctx);
    ly_set_free(nodes);
    return rc;
}

static bool
rp_dt_is_under_subtree(struct lys_node *subtree, size_t depth_limit, struct lys_node *node)
{
    struct lys_node *n = node;
    size_t depth = 0;

    while (depth_limit > depth && NULL != n) {
        if (subtree == n) {
            return true;
        }
        n = lys_parent(n);
        ++depth;
    }

    return false;
}

bool
rp_dt_depth_under_subtree(struct lys_node *subtree, struct lys_node *node, size_t *dep)
{
    struct lys_node *n = node;
    size_t depth = 0;

    while (NULL != n) {
        if (subtree == n) {
            if (NULL != dep) {
                *dep = depth;
            }
            return true;
        }
        n = lys_parent(n);
        ++depth;
    }

    return false;
}

/**
 * @brief Tests if there is an atom located under subtree.
 * @param [in] atoms
 * @param [in] subtree
 * @param [out] result
 * @return Error code (SR_ERR_OK on success)
 */
static int
rp_dt_atoms_require_subtree(struct ly_set *atoms, struct lys_node *subtree, bool *result)
{
    CHECK_NULL_ARG3(atoms, subtree, result);
    *result = false;

    for (unsigned int i = 0; i < atoms->number; i++) {
        if (rp_dt_depth_under_subtree(subtree, atoms->set.s[i], NULL)) {
            *result = true;
            break;
        }
    }

    return SR_ERR_OK;
}

/**
 * @brief Tests if any of the tree chunks contain the provided subtree.
 * @param [in] tree_roots
 * @param [in] depth_limit
 * @param [in] subtree
 * @param [out] result
 * @return Error code (SR_ERR_OK on success)
 */
static int
rp_dt_tree_chunks_contain_subtree(struct ly_set *tree_roots, size_t depth_limit,
        struct lys_node *subtree, bool *result)
{
    CHECK_NULL_ARG3(tree_roots, subtree, result);
    *result = false;

    for (unsigned int i = 0; i < tree_roots->number; i++) {
        if (rp_dt_is_under_subtree(tree_roots->set.s[i], depth_limit, subtree)) {
            *result = true;
            break;
        }
    }

    return SR_ERR_OK;
}

static int
rp_dt_get_start_node(dm_schema_info_t *schema_info, const char *absolute_xpath, struct lys_node **start_node_p)
{
    CHECK_NULL_ARG3(schema_info, absolute_xpath, start_node_p);

    struct lys_node *start_node = schema_info->module->data;
    struct lys_node *n = start_node;
    const char *first_node_name = absolute_xpath + strlen(schema_info->module_name) + 2 /* leading slash and colon */;

    while (NULL != n) {
        if (0 == strncmp(n->name, first_node_name, strlen(n->name))) {
            start_node = n;
            break;
        }
        n = n->next;
    }

    *start_node_p = start_node;
    return SR_ERR_OK;
}

static int
rp_dt_xpath_atomize(dm_schema_info_t *schema_info, const char *xpath, struct ly_set **atoms)
{
    CHECK_NULL_ARG3(schema_info, xpath, atoms);

    int rc = SR_ERR_OK;
    struct lys_node *start_node = NULL;

    rc = rp_dt_get_start_node(schema_info, xpath, &start_node);
    CHECK_RC_LOG_RETURN(rc, "Failed to get the start node for xpath %s", xpath);

    *atoms = lys_xpath_atomize(start_node, LYXP_NODE_ELEM, xpath, 0);
    if (NULL == *atoms) {
        SR_LOG_ERR("Failed to atomize xpath %s", xpath);
        rc = SR_ERR_INVAL_ARG;
    }
    return rc;
}

/**
 * @brief Get the set of tree roots matching the provided xpath.
 */
static int
rp_dt_get_tree_roots(dm_schema_info_t *schema_info, const char *xpath, struct ly_set **roots)
{
    CHECK_NULL_ARG3(schema_info, xpath, roots);

    int rc = SR_ERR_OK;
    struct lys_node *start_node = NULL;

    rc = rp_dt_get_start_node(schema_info, xpath, &start_node);
    CHECK_RC_LOG_RETURN(rc, "Failed to get the start node for xpath %s", xpath);

    *roots = lys_find_path(NULL, start_node, xpath);
    if (NULL == *roots) {
        SR_LOG_ERR("Failed to get the set of tree roots for xpath %s", xpath);
        rc = SR_ERR_INVAL_ARG;
    }
    return rc;
}

static int
rp_dt_subscriptions_to_schema_nodes(dm_ctx_t *dm_ctx, sr_list_t *subscriptions, sr_list_t **subscr_nodes)
{
    CHECK_NULL_ARG2(dm_ctx, subscr_nodes);
    int rc = SR_ERR_OK;
    struct lys_node *sub_node = NULL;
    sr_list_t *nodes = NULL;

    rc = sr_list_init(&nodes);
    CHECK_RC_MSG_RETURN(rc, "List init failed");

    /* find schema nodes corresponding to the subscriptions */
    if (NULL != subscriptions) {
        for (size_t i = 0; i < subscriptions->count; i++) {
            np_subscription_t *subscription = subscriptions->data[i];
            rc = rp_dt_validate_node_xpath(dm_ctx, NULL, subscription->xpath,
                        NULL, &sub_node);
            CHECK_RC_LOG_GOTO(rc, cleanup, "Node validation failed for xpath %s", subscription->xpath);

            rc = sr_list_add(nodes, sub_node);
            CHECK_RC_MSG_GOTO(rc, cleanup, "List add failed");
        }
    }

cleanup:
    if (SR_ERR_OK != rc) {
        sr_list_cleanup(nodes);
    } else {
        *subscr_nodes = nodes;
    }
    return rc;
}

static bool
rp_dt_no_parent_list_until(struct lys_node *until, struct lys_node *node)
{
    if (NULL == node) {
        return false;
    }

    struct lys_node *n = lys_parent(node);

    while (NULL != n) {
        if (until == n) {
            break;
        }
        if (LYS_LIST & n->nodetype) {
            return false;
        }
        n = lys_parent(n);
    }

    return true;
}

static bool
rp_dt_not_coverd_by_other_subs(sr_list_t *other, struct lys_node *node) {
    if (NULL == other || NULL == node) {
        return true;
    }
    for (size_t i = 0; i < other->count; i++) {
        struct lys_node *sub = (struct lys_node *) other->data[i];
        if (sub == node) {
            continue;
        }
        if (rp_dt_depth_under_subtree(sub, node, NULL)) {
            return false;
        }
    }

    return true;
}
/**
 * @brief Determines if (and what) state data subtrees are needed to be loaded.
 */
static int
rp_dt_xpath_requests_state_data(rp_ctx_t *rp_ctx, rp_session_t *session, dm_schema_info_t *schema_info, const char *xpath,
        sr_api_variant_t api_variant, size_t tree_depth_limit, rp_state_data_ctx_t *state_data_ctx)
{
    CHECK_NULL_ARG4(rp_ctx, schema_info, xpath, state_data_ctx);
    md_ctx_t *md_ctx = NULL;
    md_module_t *module = NULL;
    int rc = SR_ERR_OK;
    struct ly_set *atoms = NULL;
    struct ly_set *tree_roots = NULL;
    sr_list_t *subtree_nodes = NULL;
    char *xp = NULL, *schema_xpath = NULL;

    rc = dm_get_md_ctx(rp_ctx->dm_ctx, &md_ctx);
    CHECK_RC_MSG_RETURN(rc,"Failed to retrieve md_ctx");

    md_ctx_lock(md_ctx, false);

    rc = sr_list_init(&subtree_nodes);
    CHECK_RC_MSG_GOTO(rc, cleanup, "List init failed");

    schema_xpath = ly_path_data2schema(schema_info->ly_ctx, xpath);
    if (NULL == schema_xpath) {
        SR_LOG_ERR("Failed to transform data path '%s' to schema path", xpath);
        rc = SR_ERR_BAD_ELEMENT;
        goto cleanup;
    }

    rc = rp_dt_xpath_atomize(schema_info, schema_xpath, &atoms);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Failed to atomize xpath '%s'", xpath);
        SR_LOG_WRN_MSG("Request will continue without retrieving state data");
        rp_dt_free_state_data_ctx_content(state_data_ctx);
        session->dp_req_waiting = 0;
        rc = SR_ERR_OK;
        goto cleanup;
    }

    if (SR_API_TREES == api_variant) {
        rc = rp_dt_get_tree_roots(schema_info, schema_xpath, &tree_roots);
        CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to get the set of tree roots matching xpath %s", xpath);
    }

    rc = sr_list_init(&state_data_ctx->subtrees);
    CHECK_RC_MSG_GOTO(rc, cleanup, "List init failed");

    rc = md_get_module_info(md_ctx, schema_info->module_name, NULL, NULL, &module);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Module %s was not found in module dependency", schema_info->module_name);

    /* loop through operational node subtrees */
    sr_llist_node_t *node = module->op_data_subtrees->first;
    while (NULL != node) {
        md_subtree_ref_t *sub = node->data;
        bool subtree_needed = false;
        node = node->next;
        struct lys_node *state_data_node = NULL;

        rc = rp_dt_validate_node_xpath(rp_ctx->dm_ctx, NULL,
                    sub->xpath, NULL, &state_data_node);
        if (rc != SR_ERR_OK) {
            SR_LOG_WRN("Unable to find schema node for %s (it may be disabled)", sub->xpath);
            rc = SR_ERR_OK;
            continue;
        }

        rc = rp_dt_atoms_require_subtree(atoms, state_data_node, &subtree_needed);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Rp dt atoms require subtree failed");

        if (!subtree_needed && SR_API_TREES == api_variant) {
            // consider state data inside requested subtrees
            rc = rp_dt_tree_chunks_contain_subtree(tree_roots, tree_depth_limit, state_data_node, &subtree_needed);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Rp dt trees contain subtree failed");
        }

        /* test if subtree should be loaded */
        if (subtree_needed) {
            rc = sr_list_add(subtree_nodes, state_data_node);
            CHECK_RC_MSG_GOTO(rc, cleanup, "List add failed");

            xp = strdup(sub->xpath);
            CHECK_NULL_NOMEM_GOTO(xp, rc, cleanup);

            rc = sr_list_add(state_data_ctx->subtrees, xp);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Adding into subtree list failed");
            SR_LOG_DBG("State data in subtree %s requested.", xp);
            xp = NULL;
        }
    }

    session->state_data_ctx.subtree_nodes = subtree_nodes;
    subtree_nodes = NULL;

    SR_LOG_DBG("%zu subtrees of state data will be attempted to load in order to resolve %s", state_data_ctx->subtrees->count, xpath);

    if (state_data_ctx->subtrees->count > 0) {
        /* Check if the state data from this module is not handled internally */
        for (size_t i = 0; i < rp_ctx->modules_incl_intern_op_data->count; i++) {
            if (0 == strcmp(schema_info->module_name, (char *) rp_ctx->modules_incl_intern_op_data->data[i])) {
                session->state_data_ctx.internal_state_data = true;
                session->state_data_ctx.internal_state_data_index = i;
            }
        }

        rc = np_get_data_provider_subscriptions(rp_ctx->np_ctx, session, schema_info->module_name, &state_data_ctx->subscriptions);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Get data provider subscriptions failed");

        if (NULL == state_data_ctx->subscriptions || 0 == state_data_ctx->subscriptions->count) {
            goto cleanup;
        }

        rc = rp_dt_subscriptions_to_schema_nodes(rp_ctx->dm_ctx, state_data_ctx->subscriptions,
                &session->state_data_ctx.subscription_nodes);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Subscriptions to schema nodes failed");
    }

cleanup:
    free(xp);
    free(schema_xpath);
    ly_set_free(atoms);
    ly_set_free(tree_roots);
    md_ctx_unlock(md_ctx);
    sr_list_cleanup(subtree_nodes);
    if (SR_ERR_OK != rc) {
        rp_dt_free_state_data_ctx_content(state_data_ctx);
        session->dp_req_waiting = 0;
    }
    return rc;
}

bool
rp_dt_find_subscription_covering_subtree(rp_session_t *rp_session, struct lys_node *subtree_node, size_t *found_index)
{
    if (NULL == rp_session || NULL == subtree_node || NULL == found_index) {
        SR_LOG_ERR_MSG("Null argument provided to the function");
        return false;
    }

    bool match = false;
    size_t cnt = 0, match_index = 0;
    int match_difference = -1;

    cnt = (NULL != rp_session->state_data_ctx.subscriptions) ? rp_session->state_data_ctx.subscriptions->count : 0;

    for (size_t j = 0; j < cnt; j++) {
        struct lys_node *subs = (struct lys_node *) rp_session->state_data_ctx.subscription_nodes->data[j];
        size_t depth = 0;
        if (rp_dt_depth_under_subtree(subs, subtree_node, &depth)) {
            if (!match_index || depth < match_difference) {
                match_index = j;
                match_difference = depth;
                match = true;
                SR_LOG_DBG("Found match for %s with depth %zu index %zu", subtree_node->name, depth, match_index);
            }
            if (depth == 0) {
                /* exact match */
                break;
            }
        }
    }

    if (match) {
        *found_index = match_index;
    }

    return match;
}

bool
rp_dt_find_exact_match_subscription_for_node(rp_session_t *rp_session, struct lys_node *node, size_t *found_index)
{
    if (NULL == rp_session || NULL == node || NULL == found_index) {
        SR_LOG_ERR_MSG("Null argument provided to the function");
        return false;
    }

    bool match = false;
    size_t cnt = 0, match_index = 0;

    cnt = (NULL != rp_session->state_data_ctx.subscriptions) ? rp_session->state_data_ctx.subscriptions->count : 0;

    for (size_t j = 0; j < cnt; j++) {
        struct lys_node *sub = (struct lys_node *) rp_session->state_data_ctx.subscription_nodes->data[j];
        if (sub->nodetype != node->nodetype) {
            continue;
        }
        size_t depth = 0;
        if (rp_dt_depth_under_subtree(sub, node, &depth)) {
            if (0 == depth) {
                match_index = j;
                match = true;
                break;
            }
        }
    }

    if (match) {
        *found_index = match_index;
    }

    return match;
}

/**
 * @brief Tests whether one of parent nodes is list.
 */
static bool
rp_dt_has_parent_list(struct lys_node *node, struct lys_node **found_list, size_t *depth)
{
    if (NULL != node) {
        struct lys_node *n = lys_parent(node);
        size_t dep = 0;

        while (NULL != n) {
            if (0 == ((LYS_USES & n->nodetype) | (LYS_CHOICE & n->nodetype) | (LYS_CASE & n->nodetype))) {
                dep++;
            }
            if (LYS_LIST & n->nodetype) {
                if (NULL != depth) {
                    *depth = dep;
                }
                if (NULL != found_list) {
                    *found_list = n;
                }
                return true;
            }
            n = lys_parent(n);
        }
    }
    return false;
}

int
rp_dt_create_instance_xps(rp_session_t *session, const char *xpath, char ***xps, size_t *xp_count)
{
    CHECK_NULL_ARG4(session, xpath, xps, xp_count);
    int rc = SR_ERR_OK;
    struct ly_set *list_instances = NULL;
    char **xpaths = NULL;

    rc = dm_get_nodes_by_xpath(session->dm_session, session->module_name, xpath, &list_instances);
    CHECK_RC_MSG_RETURN(rc, "Dm_get_nodes_by_xpath failed");

    xpaths = calloc(list_instances->number, sizeof(*xpaths));
    CHECK_NULL_NOMEM_GOTO(xpaths, rc, cleanup);

    for (size_t i = 0; i < list_instances->number; i++) {
        xpaths[i] = lyd_path(list_instances->set.d[i]);
        CHECK_NULL_NOMEM_GOTO(xpaths[i], rc, cleanup);
    }

cleanup:
    if (SR_ERR_OK == rc) {
        *xps = xpaths;
        *xp_count = list_instances->number;
    } else {
        if (NULL != xpaths) {
            for (size_t i = 0; i < list_instances->number; i++) {
                free(xpaths[i]);
            }
            free(xpaths);
        }
    }

    ly_set_free(list_instances);
    return rc;
}

/**
 *
 * @param [in] rp_ctx
 * @param [in] rp_session
 * @param [in] subscription_index - index of subscription where the request will be addressed
 * @param [in] xp - must be allocated, must not be used after return from the function. It will be freed
 * even in case of error;
 * @return Error code (SR_ERR_OK on success)
 */
static int
rp_dt_send_request_to_dp_subscription(rp_ctx_t *rp_ctx, rp_session_t *rp_session, size_t subscription_index, struct lys_node *sch_node, char *xp)
{
    CHECK_NULL_ARG4(rp_ctx, rp_session, sch_node, xp);
    int rc = SR_ERR_OK;
    char **xpaths = NULL;
    char *request_xp = NULL;
    struct lys_node *parent_list = NULL;
    size_t list_depth = 0;
    size_t xp_cnt = 0;
    np_subscription_t *subscription = NULL;

    subscription = rp_session->state_data_ctx.subscriptions->data[subscription_index];

    if (rp_dt_has_parent_list(sch_node, &parent_list, &list_depth)) {
        SR_LOG_DBG("State data is nested in configuration list %s", xp);

        /* find the suffix in xpath after the list */
        char *ptr = xp + strlen(xp);
        while (ptr != xp && list_depth > 0) {
            if ('/' == *ptr) {
                list_depth--;
            }
            if (0 == list_depth) {
                *ptr = 0; /* split xpath into path with list without keys and suffix */
                ptr++;
                break;
            }
            ptr--;
        }

        rc = rp_dt_create_instance_xps(rp_session, xp, &xpaths, &xp_cnt);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create instance xpaths for list instances");

        SR_LOG_DBG("Found %zu instances of %s , will request %s", xp_cnt, xp, ptr);

        size_t suffix_len = strlen(ptr);

        for (size_t i = 0; i < xp_cnt; i++) {
            size_t len = strlen(xpaths[i]) + suffix_len + 2 /* slash + zero byte */;
            request_xp = calloc(len, sizeof(*request_xp));
            CHECK_NULL_NOMEM_GOTO(request_xp, rc, cleanup);

            snprintf(request_xp, len, "%s/%s", xpaths[i], ptr);

            rc = np_data_provider_request(rp_ctx->np_ctx, subscription, rp_session, request_xp);
            SR_LOG_DBG("Sending request for state data: %s", request_xp);
            if (SR_ERR_OK != rc) {
                SR_LOG_WRN("Request for operational data failed with xpath %s on subscription %s", request_xp, subscription->xpath);
                free(request_xp);
            } else {
                rp_session->dp_req_waiting += 1;
                rc = sr_list_add(rp_session->state_data_ctx.requested_xpaths, request_xp);
            }
        }
        free(xp);
        xp = NULL;

    } else {
        rc = np_data_provider_request(rp_ctx->np_ctx, subscription, rp_session, xp);
        SR_LOG_DBG("Sending request for state data: %s", xp);
        if (SR_ERR_OK != rc) {
            SR_LOG_WRN("Request for operational data failed with xpath %s on subscription %s", xp, subscription->xpath);
        } else {
            rp_session->dp_req_waiting += 1;
            rc = sr_list_add(rp_session->state_data_ctx.requested_xpaths, xp);
        }
    }

cleanup:
    if (SR_ERR_OK != rc) {
        free(xp);
    }
    if (NULL != xpaths) {
        for (size_t i = 0; i < xp_cnt; i++) {
            free(xpaths[i]);
        }
        free(xpaths);
    }
    return rc;
}

/**
 * @brief The function send the first set of requests to data providers for the selected subtrees
 * For each subtree it looks up a subscriber(data provider) using the following criteria:
 *      1. exact match - subscriber's node is the same as the requested subtree
 *      2. more generic - there is not exact match however there is a subscription to one of the parent nodes
 *      3. partial subscription - no subscription is found using the two ways above Try retrieve at least some
 *          parts of the requested subtree. Data provide request will be send to all subscribers that are under requested
 *          subtree and all list in the path are covered by a data provider
 * @param [in] rp_ctx
 * @param [in] rp_session
 * @return Error code (SR_ERR_OK on success)
 */
static int
rp_dt_send_first_set_of_dp_requests(rp_ctx_t *rp_ctx, rp_session_t *rp_session)
{
    CHECK_NULL_ARG(rp_session);
    int rc = SR_ERR_OK;
    Sr__Msg *req = NULL;
    char *xp = NULL;

    for (size_t i = 0; i < rp_session->state_data_ctx.subtrees->count; i++) {
        const char *subtree = (char *) rp_session->state_data_ctx.subtrees->data[i];

        struct lys_node *subtree_node = (struct lys_node *) rp_session->state_data_ctx.subtree_nodes->data[i];
        size_t match_index = 0;
        bool match = rp_dt_find_subscription_covering_subtree(rp_session, subtree_node, &match_index);

        if (match) {
            /* exact or more generic (data provider subscribed for ancestor node) */
            xp = strdup((char *) rp_session->state_data_ctx.subtrees->data[i]);
            CHECK_NULL_NOMEM_RETURN(xp);

            rc = rp_dt_send_request_to_dp_subscription(rp_ctx, rp_session, match_index, subtree_node, xp);
            CHECK_RC_MSG_RETURN(rc, "Sending of data provide request failed");

        } else if (LYS_CONTAINER & subtree_node->nodetype) {
            SR_LOG_DBG("Subscription covering subtree not found, looking for a subscription covering at least part of subtree %s", subtree);
            size_t cnt = (NULL != rp_session->state_data_ctx.subscriptions) ? rp_session->state_data_ctx.subscriptions->count : 0;
            for (size_t j = 0; j < cnt; j++) {
                struct lys_node *subs = (struct lys_node *) rp_session->state_data_ctx.subscription_nodes->data[j];
                size_t depth = 0;
                if (rp_dt_depth_under_subtree(subtree_node, subs, &depth)) {
                    if (1 == depth || (rp_dt_no_parent_list_until(subtree_node, subs))) {
                        if (rp_dt_not_coverd_by_other_subs(rp_session->state_data_ctx.subscription_nodes, subs)) {
                            match = true;

                            xp = lys_data_path(subs);
                            CHECK_NULL_NOMEM_RETURN(xp);

                            rc = rp_dt_send_request_to_dp_subscription(rp_ctx, rp_session, j, subs, xp);
                            CHECK_RC_MSG_RETURN(rc, "Sending of data provide request failed");
                        } else {
                            /* if the subscription node is also covered by another subscription at higher level
                             * do not request data at the first iteration. Data will be request in request_nested call
                             * in request processor
                             */
                            if ((LYS_LEAF | LYS_LEAFLIST) & subs->nodetype) {
                                rp_session->state_data_ctx.overlapping_leaf_subscription = true;
                            }
                        }
                    }
                }
            }
        }

        if (match) {
            /* mark the subtree to be cleaned up before next call */
            xp = strdup((char *) rp_session->state_data_ctx.subtrees->data[i]);
            CHECK_NULL_NOMEM_RETURN(xp);

            rc = sr_list_add(rp_session->loaded_state_data[rp_session->datastore], xp);
            CHECK_RC_MSG_GOTO(rc, cleanup, "List add failed");
            xp = NULL;
        } else {
            /* Internal state data */
            if (rp_session->state_data_ctx.internal_state_data) {
                sr_list_t *module_xp = rp_ctx->inter_op_data_xpath->data[rp_session->state_data_ctx.internal_state_data_index];
                for (size_t x = 0; x < module_xp->count; x++) {
                    struct lys_node *intern_node = NULL;
                    rc = rp_dt_validate_node_xpath(rp_ctx->dm_ctx, NULL, (char *) module_xp->data[x], NULL, &intern_node);
                    CHECK_RC_LOG_GOTO(rc, cleanup, "Node validation failed for xpath %s", (char *) module_xp->data[x]);
                    /* check only exact match for internal requests*/
                    if (subtree_node == intern_node) {
                        SR_LOG_DBG("Subtree %s will be handled by internal request", (char *) module_xp->data[x]);
                        match = true;
                        break;
                    }
                }
                if (match) {
                    /* generate internal message */
                    rc = sr_gpb_internal_req_alloc(NULL, SR__OPERATION__INTERNAL_STATE_DATA, &req);
                    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to allocate internal message");

                    req->internal_request->internal_state_data_req->request_id = rp_session->req->request->_id;

                    rc = sr_mem_edit_string((sr_mem_ctx_t *)req->_sysrepo_mem_ctx,
                            &req->internal_request->internal_state_data_req->xpath, subtree);
                    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to set string");

                    rc = rp_msg_process(rp_ctx, rp_session, req);
                    SR_LOG_DBG("Enqueued an internal message to obtain state data for request: %" PRIu64,
                            rp_session->req->request->_id);
                    req = NULL;
                    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to enqueue message");

                    /* increment counter for waiting dp request */
                    rp_session->dp_req_waiting++;

                    /* mark the subtree to be cleaned up before next call */
                    xp = strdup((char *) rp_session->state_data_ctx.subtrees->data[i]);
                    CHECK_NULL_NOMEM_GOTO(xp, rc, cleanup);

                    rc = sr_list_add(rp_session->loaded_state_data[rp_session->datastore], xp);
                    CHECK_RC_MSG_GOTO(rc, cleanup, "List add failed");
                    xp = NULL;
                    continue;
                }
            }
            SR_LOG_DBG("No data provider for xpath %s", subtree);
        }
    }

cleanup:
    sr_msg_free(req);
    free(xp);
    return rc;
}

int
rp_dt_remove_loaded_state_data(rp_ctx_t *rp_ctx, rp_session_t *rp_session)
{
    CHECK_NULL_ARG2(rp_ctx, rp_session);
    int rc = SR_ERR_OK;

    while (rp_session->loaded_state_data[rp_session->datastore]->count > 0) {
        char *item_xpath = (char *) rp_session->loaded_state_data[rp_session->datastore]->data[rp_session->loaded_state_data[rp_session->datastore]->count-1];
        rc = rp_dt_delete_item(rp_ctx->dm_ctx, rp_session->dm_session, item_xpath, SR_EDIT_DEFAULT, true);
        CHECK_RC_LOG_RETURN(rc, "Error %s occured while removing state data for xpath %s", sr_strerror(rc), item_xpath);
        sr_list_rm(rp_session->loaded_state_data[rp_session->datastore], item_xpath);
        free(item_xpath);
    }

    return rc;
}

int
rp_dt_prepare_data(rp_ctx_t *rp_ctx, rp_session_t *rp_session, const char *xpath, sr_api_variant_t api_variant,
        size_t tree_depth_limit,  struct lyd_node **data_tree)
{
    CHECK_NULL_ARG3(rp_ctx, rp_session, xpath);
    int rc = SR_ERR_OK;
    bool has_state_data = false;
    dm_data_info_t *data_info = NULL;

    if (RP_REQ_NEW == rp_session->state) {

        /* in case of get_items_with_opts module name is not freed to save some
         * copying in case of cache hit */
        free(rp_session->module_name);
        rp_session->module_name = NULL;

        rc = rp_dt_remove_loaded_state_data(rp_ctx, rp_session);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to remove state data from data tree");

        rc = sr_copy_first_ns(xpath, &rp_session->module_name);
        CHECK_RC_LOG_GOTO(rc, cleanup, "Copying module name failed for xpath '%s'", xpath);

        rc = ac_check_node_permissions(rp_session->ac_session, xpath, AC_OPER_READ);
        CHECK_RC_LOG_GOTO(rc, cleanup, "Access control check failed for xpath '%s'", xpath);

        rc = dm_get_data_info(rp_ctx->dm_ctx, rp_session->dm_session, rp_session->module_name, &data_info);

        /* check of data tree's emptiness is performed outside of this function -> ignore SR_ERR_NOT_FOUND */
        rc = SR_ERR_NOT_FOUND == rc ? SR_ERR_OK : rc;
        CHECK_RC_LOG_GOTO(rc, cleanup, "Getting data tree failed (%d) for xpath '%s'", rc, xpath);
        if (data_tree) {
            *data_tree = data_info->node;
        }

        /* if the request requires operational data pause the processing and wait for data to be provided */
        if ((SR_DS_RUNNING == rp_session->datastore || SR_DS_CANDIDATE == rp_session->datastore) &&
            (!(SR_SESS_CONFIG_ONLY & rp_session->options)) &&
            (!(SR__SESSION_FLAGS__SESS_NOTIFICATION & rp_session->options)) &&
            (SR_ERR_OK == dm_has_state_data(rp_ctx->dm_ctx, rp_session->module_name, &has_state_data) && has_state_data)) {

            rp_dt_free_state_data_ctx_content(&rp_session->state_data_ctx);
            rp_session->dp_req_waiting = 0;

            rc = sr_list_init(&rp_session->state_data_ctx.requested_xpaths);
            CHECK_RC_MSG_GOTO(rc, cleanup, "List init failed");

            rc = rp_dt_xpath_requests_state_data(rp_ctx, rp_session, data_info->schema, xpath, api_variant,
                    tree_depth_limit, &rp_session->state_data_ctx);
            CHECK_RC_MSG_GOTO(rc, cleanup, "rp_dt_xpath_requests_state_data failed");

            if (NULL == rp_session->state_data_ctx.subtrees || 0 == rp_session->state_data_ctx.subtrees->count) {
                SR_LOG_DBG("No state state data provider is asked for data because of xpath %s", xpath);
                goto cleanup;
            }

            rc = rp_dt_send_first_set_of_dp_requests(rp_ctx, rp_session);
            CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to send requests for xpath %s", xpath);

            if (rp_session->dp_req_waiting > 0) {
                rp_session->state = RP_REQ_WAITING_FOR_DATA;
            }

        }
        CHECK_RC_MSG_GOTO(rc, cleanup, "rp_dt_module_has_state data failed");

    } else if (RP_REQ_DATA_LOADED == rp_session->state) {
        SR_LOG_DBG("Session id = %u data loaded, continue processing", rp_session->id);
        if (data_tree) {
            rc = dm_get_datatree(rp_ctx->dm_ctx, rp_session->dm_session, rp_session->module_name, data_tree);
            /* check of data tree's emptiness is performed outside of this function -> ignore SR_ERR_NOT_FOUND */
            rc = SR_ERR_NOT_FOUND == rc ? SR_ERR_OK : rc;
        }
    } else {
        SR_LOG_ERR("Session id = %u is in invalid state.", rp_session->id);
        rc = SR_ERR_INTERNAL;
    }

cleanup:
    if (SR_ERR_OK != rc) {
        rp_dt_free_state_data_ctx_content(&rp_session->state_data_ctx);
        rp_session->dp_req_waiting = 0;
    }
    return rc;
}

int
rp_dt_get_value_wrapper(rp_ctx_t *rp_ctx, rp_session_t *rp_session, sr_mem_ctx_t *sr_mem, const char *xpath, sr_val_t **value)
{
    CHECK_NULL_ARG4(rp_ctx, rp_ctx->dm_ctx, rp_session, rp_session->dm_session);
    CHECK_NULL_ARG2(xpath, value);
    SR_LOG_INF("Get item request %s datastore, xpath: %s", sr_ds_to_str(rp_session->datastore), xpath);

    int rc = SR_ERR_OK;
    struct lyd_node *data_tree = NULL;

    rc = rp_dt_prepare_data(rp_ctx, rp_session, xpath, SR_API_VALUES, 0, &data_tree);
    CHECK_RC_LOG_GOTO(rc, cleanup, "rp_dt_prepare_data failed %s", sr_strerror(rc));

    if (RP_REQ_WAITING_FOR_DATA == rp_session->state) {
        SR_LOG_DBG("Session id = %u is waiting for the data", rp_session->id);
        return rc;
    }

    if (NULL == data_tree) {
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    rc = rp_dt_get_value(rp_ctx->dm_ctx, rp_session, data_tree, sr_mem, xpath,
            dm_is_running_ds_session(rp_session->dm_session), value);
    if (SR_ERR_UNAUTHORIZED == rc) {
        rc = SR_ERR_NOT_FOUND;
    } else if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Get value failed for xpath '%s'", xpath);
    }

cleanup:
    rp_session->state = RP_REQ_FINISHED;
    free(rp_session->module_name);
    rp_session->module_name = NULL;
    return rc;
}

int
rp_dt_get_values_wrapper(rp_ctx_t *rp_ctx, rp_session_t *rp_session, sr_mem_ctx_t *sr_mem, const char *xpath,
        sr_val_t **values, size_t *count)
{
    CHECK_NULL_ARG4(rp_ctx, rp_ctx->dm_ctx, rp_session, rp_session->dm_session);
    CHECK_NULL_ARG3(xpath, values, count);
    SR_LOG_INF("Get items request %s datastore, xpath: %s", sr_ds_to_str(rp_session->datastore), xpath);

    int rc = SR_ERR_OK;
    struct lyd_node *data_tree = NULL;

    rc = rp_dt_prepare_data(rp_ctx, rp_session, xpath, SR_API_VALUES, 0, &data_tree);
    CHECK_RC_MSG_GOTO(rc, cleanup, "rp_dt_prepare_data failed");

    if (RP_REQ_WAITING_FOR_DATA == rp_session->state) {
        SR_LOG_DBG("Session id = %u is waiting for the data", rp_session->id);
        return rc;
    }

    if (NULL == data_tree) {
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    rc = rp_dt_get_values(rp_ctx->dm_ctx, rp_session, data_tree, sr_mem, xpath,
            dm_is_running_ds_session(rp_session->dm_session), values, count);
    if (SR_ERR_UNAUTHORIZED == rc) {
        rc = SR_ERR_NOT_FOUND;
    } else if (SR_ERR_OK != rc && SR_ERR_NOT_FOUND != rc) {
        SR_LOG_ERR("Get values failed for xpath '%s'", xpath);
    }

cleanup:
    rp_session->state = RP_REQ_FINISHED;
    free(rp_session->module_name);
    rp_session->module_name = NULL;
    return rc;
}

int
rp_dt_get_values_wrapper_with_opts(rp_ctx_t *rp_ctx, rp_session_t *rp_session, rp_dt_get_items_ctx_t *get_items_ctx, sr_mem_ctx_t *sr_mem,
        const char *xpath, size_t offset, size_t limit, sr_val_t **values, size_t *count)
{
    CHECK_NULL_ARG5(rp_ctx, rp_ctx->dm_ctx, rp_session, rp_session->dm_session, get_items_ctx);
    CHECK_NULL_ARG3(xpath, values, count);
    SR_LOG_INF("Get items request %s datastore, xpath: %s, offset: %zu, limit: %zu", sr_ds_to_str(rp_session->datastore), xpath, offset, limit);

    int rc = SR_ERR_OK;
    struct lyd_node *data_tree = NULL;
    struct ly_set *nodes = NULL;

    if (get_items_ctx->xpath != NULL && 0 == strcmp(xpath, get_items_ctx->xpath) &&
            offset == get_items_ctx->offset) {
        /* cache hit do not load data from data providers */
        rp_session->state = RP_REQ_DATA_LOADED;
    }

    rc = rp_dt_prepare_data(rp_ctx, rp_session, xpath, SR_API_VALUES, 0, &data_tree);
    CHECK_RC_MSG_GOTO(rc, cleanup, "rp_dt_prepare_data failed");

    if (RP_REQ_WAITING_FOR_DATA == rp_session->state) {
        SR_LOG_DBG("Session id = %u is waiting for the data", rp_session->id);
        return rc;
    }

    if (NULL == data_tree) {
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    rc = rp_dt_find_nodes_with_opts(rp_ctx->dm_ctx, rp_session, get_items_ctx, data_tree, xpath, offset, limit, &nodes);
    if (SR_ERR_OK != rc) {
        if (SR_ERR_UNAUTHORIZED == rc) {
            rc = SR_ERR_NOT_FOUND;
        } else if (SR_ERR_NOT_FOUND != rc) {
            SR_LOG_ERR("Get nodes for xpath %s failed (%d)", xpath, rc);
        }
        goto cleanup;
    }

    rc = rp_dt_get_values_from_nodes(sr_mem, nodes, values, count);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Copying values from nodes failed for xpath '%s'", xpath);
    }

cleanup:
    ly_set_free(nodes);
    rp_session->state = RP_REQ_FINISHED;
    return rc;
}

int
rp_dt_get_subtree_wrapper(rp_ctx_t *rp_ctx, rp_session_t *rp_session, sr_mem_ctx_t *sr_mem, const char *xpath, sr_node_t **subtree)
{
    CHECK_NULL_ARG4(rp_ctx, rp_ctx->dm_ctx, rp_session, rp_session->dm_session);
    CHECK_NULL_ARG2(xpath, subtree);
    SR_LOG_INF("Get subtree request %s datastore, xpath: %s", sr_ds_to_str(rp_session->datastore), xpath);

    int rc = SR_ERR_OK;
    struct lyd_node *data_tree = NULL;

    rc = rp_dt_prepare_data(rp_ctx, rp_session, xpath, SR_API_TREES, SIZE_MAX, &data_tree);
    CHECK_RC_LOG_GOTO(rc, cleanup, "rp_dt_prepare_data failed %s", sr_strerror(rc));

    if (RP_REQ_WAITING_FOR_DATA == rp_session->state) {
        SR_LOG_DBG("Session id = %u is waiting for the data", rp_session->id);
        return rc;
    }

    if (NULL == data_tree) {
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    rc = rp_dt_get_subtree(rp_ctx->dm_ctx, rp_session, data_tree, sr_mem, xpath,
            dm_is_running_ds_session(rp_session->dm_session), subtree);
    if (SR_ERR_UNAUTHORIZED == rc) {
        rc = SR_ERR_NOT_FOUND;
    } else if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Get subtree failed for xpath '%s'", xpath);
    }
cleanup:
    rp_session->state = RP_REQ_FINISHED;
    free(rp_session->module_name);
    rp_session->module_name = NULL;
    return rc;
}

int
rp_dt_get_subtree_wrapper_with_opts(rp_ctx_t *rp_ctx, rp_session_t *rp_session, sr_mem_ctx_t *sr_mem, const char *xpath,
    size_t slice_offset, size_t slice_width, size_t child_limit, size_t depth_limit, sr_node_t **subtree, char **subtree_id)
{
    CHECK_NULL_ARG4(rp_ctx, rp_ctx->dm_ctx, rp_session, rp_session->dm_session);
    CHECK_NULL_ARG3(xpath, subtree, subtree_id);
    SR_LOG_INF("Get subtree request %s datastore, xpath: %s", sr_ds_to_str(rp_session->datastore), xpath);

    int rc = SR_ERR_OK;
    struct lyd_node *data_tree = NULL;

    rc = rp_dt_prepare_data(rp_ctx, rp_session, xpath, SR_API_TREES, depth_limit, &data_tree);
    CHECK_RC_LOG_GOTO(rc, cleanup, "rp_dt_prepare_data failed %s", sr_strerror(rc));

    if (RP_REQ_WAITING_FOR_DATA == rp_session->state) {
        SR_LOG_DBG("Session id = %u is waiting for the data", rp_session->id);
        return rc;
    }

    if (NULL == data_tree) {
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    rc = rp_dt_get_subtree_chunk(rp_ctx->dm_ctx, rp_session, data_tree, sr_mem, xpath, slice_offset, slice_width,
            child_limit, depth_limit, dm_is_running_ds_session(rp_session->dm_session), subtree, subtree_id);
    if (SR_ERR_UNAUTHORIZED == rc) {
        rc = SR_ERR_NOT_FOUND;
    } else if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Get subtree failed for xpath '%s'", xpath);
    }

cleanup:
    rp_session->state = RP_REQ_FINISHED;
    free(rp_session->module_name);
    rp_session->module_name = NULL;
    return rc;
}

int
rp_dt_get_subtrees_wrapper(rp_ctx_t *rp_ctx, rp_session_t *rp_session, sr_mem_ctx_t *sr_mem, const char *xpath, sr_node_t **subtrees, size_t *count)
{
    CHECK_NULL_ARG4(rp_ctx, rp_ctx->dm_ctx, rp_session, rp_session->dm_session);
    CHECK_NULL_ARG3(xpath, subtrees, count);
    SR_LOG_INF("Get subtrees request %s datastore, xpath: %s", sr_ds_to_str(rp_session->datastore), xpath);

    int rc = SR_ERR_OK;
    struct lyd_node *data_tree = NULL;

    rc = rp_dt_prepare_data(rp_ctx, rp_session, xpath, SR_API_TREES, SIZE_MAX, &data_tree);
    CHECK_RC_MSG_GOTO(rc, cleanup, "rp_dt_prepare_data failed");

    if (RP_REQ_WAITING_FOR_DATA == rp_session->state) {
        SR_LOG_DBG("Session id = %u is waiting for the data", rp_session->id);
        return rc;
    }

    if (NULL == data_tree) {
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    rc = rp_dt_get_subtrees(rp_ctx->dm_ctx, rp_session, data_tree, sr_mem, xpath,
                            dm_is_running_ds_session(rp_session->dm_session), subtrees, count);
    if (SR_ERR_UNAUTHORIZED == rc) {
        rc = SR_ERR_NOT_FOUND;
    } else if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Get subtrees failed for xpath '%s'", xpath);
    }

cleanup:
    rp_session->state = RP_REQ_FINISHED;
    free(rp_session->module_name);
    rp_session->module_name = NULL;
    return rc;
}

int
rp_dt_get_subtrees_wrapper_with_opts(rp_ctx_t *rp_ctx, rp_session_t *rp_session, sr_mem_ctx_t *sr_mem, const char *xpath,
    size_t slice_offset, size_t slice_width, size_t child_limit, size_t depth_limit, sr_node_t **subtrees, size_t *count,
    char ***subtree_ids)
{
    CHECK_NULL_ARG4(rp_ctx, rp_ctx->dm_ctx, rp_session, rp_session->dm_session);
    CHECK_NULL_ARG3(xpath, subtrees, count);
    SR_LOG_INF("Get subtrees request %s datastore, xpath: %s", sr_ds_to_str(rp_session->datastore), xpath);

    int rc = SR_ERR_OK;
    struct lyd_node *data_tree = NULL;

    rc = rp_dt_prepare_data(rp_ctx, rp_session, xpath, SR_API_TREES, depth_limit, &data_tree);
    CHECK_RC_MSG_GOTO(rc, cleanup, "rp_dt_prepare_data failed");

    if (RP_REQ_WAITING_FOR_DATA == rp_session->state) {
        SR_LOG_DBG("Session id = %u is waiting for the data", rp_session->id);
        return rc;
    }

    if (NULL == data_tree) {
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    rc = rp_dt_get_subtrees_chunks(rp_ctx->dm_ctx, rp_session, data_tree, sr_mem, xpath, slice_offset, slice_width,
            child_limit, depth_limit, dm_is_running_ds_session(rp_session->dm_session), subtrees, count, subtree_ids);
    if (SR_ERR_UNAUTHORIZED == rc) {
        rc = SR_ERR_NOT_FOUND;
    } else if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Get subtrees failed for xpath '%s'", xpath);
    }

cleanup:
    rp_session->state = RP_REQ_FINISHED;
    free(rp_session->module_name);
    rp_session->module_name = NULL;
    return rc;
}

/**
 * @brief generates changes for the children of created/deleted container/list
 *
 */
static int
rp_dt_add_changes_for_children(sr_list_t *changes, LYD_DIFFTYPE type, struct lyd_node *node, bool *added_p)
{
    CHECK_NULL_ARG3(changes, node, added_p);
    int rc = SR_ERR_OK;
    struct lyd_node *child = NULL;
    sr_change_t *change = NULL;
    bool added = false, added_child = false;
    size_t orig_len =  changes->count;

    if (node->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYDATA)) {
        child = NULL;
    } else {
        child = node->child;
    }
    while (child) {
        rc = rp_dt_add_changes_for_children(changes, type, child, &added);
        if (SR_ERR_OK != rc) {
            goto cleanup;
        }
        added_child |= added;
        child = child->next;
    }

    if ((LYS_CONTAINER == node->schema->nodetype) && node->dflt && !added_child) {
        *added_p = false;
        goto cleanup;
    }

    change = calloc(1, sizeof(*change));
    CHECK_NULL_NOMEM_GOTO(change, rc, cleanup);

    change->oper = type == LYD_DIFF_CREATED ?  SR_OP_CREATED : SR_OP_DELETED;
    change->sch_node = node->schema;

    sr_val_t **ptr = LYD_DIFF_CREATED == type ? &change->new_value : &change->old_value;
    *ptr = calloc(1, sizeof(**ptr));
    CHECK_NULL_NOMEM_GOTO(*ptr, rc, cleanup);
    rc = rp_dt_get_value_from_node(node, *ptr);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Get value from node failed");

    rc = sr_list_add(changes, change);
    CHECK_RC_MSG_GOTO(rc, cleanup, "List add failed");
    *added_p = true;

    /* store changes in DFS pre-order */
    if (LYD_DIFF_CREATED == type && added_child) {
        memmove(changes->data + orig_len + 1, changes->data + orig_len,
                (changes->count - orig_len - 1) * sizeof(*changes->data));
        changes->data[orig_len] = (void *)change;
    }
    change = NULL;

cleanup:
    if (NULL != change) {
        sr_free_changes(change, 1);
    }
    return rc;
}

/**
 * @brief Returns true if the given tree, excluding deleted and skipped subtrees,
 * contains only empty non-presence containers.
 */
static bool
rp_has_only_empty_np_containers(struct lyd_node *root, sr_list_t *deleted, struct lyd_node *skip)
{
    struct lyd_node *child = NULL;

    if (NULL == root) {
        return true;
    }

    if (root == skip) {
        return true;
    }

    for (size_t i = 0; NULL != deleted && i < deleted->count; ++i) {
        if (root == deleted->data[i]) {
            return true;
        }
    }

    if ((LYS_CONTAINER != root->schema->nodetype) || ((struct lys_node_container *)root->schema)->presence) {
        return false;
    }

    if (root->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYDATA)) {
        child = NULL;
    } else {
        child = root->child;
    }
    while (child) {
        if (!rp_has_only_empty_np_containers(child, deleted, skip)) {
            return false;
        }
        child = child->next;
    }

    return true;
}

/**
 * @brief Generates changes for the parents of created/deleted container/list
 *
 */
static int
rp_dt_add_changes_for_parents(sr_list_t *changes, sr_list_t *deleted, LYD_DIFFTYPE type, struct lyd_node *first_node,
        struct lyd_node *first_parent, struct lyd_node *second_parent, int added_parents)
{
    CHECK_NULL_ARG(changes);
    int rc = SR_ERR_OK;
    sr_val_t *val = NULL;
    sr_val_t **val_ptr = NULL;
    sr_change_oper_t op_type = (type == LYD_DIFF_CREATED ?  SR_OP_CREATED : SR_OP_DELETED);
    struct lyd_node *parent = (SR_OP_CREATED == op_type ? second_parent : first_parent);
    sr_change_t *change = NULL, *recorded_change = NULL;

    if (NULL == first_parent) {
        return SR_ERR_OK;
    }

    /* get value of the node */
    val = calloc(1, sizeof *val);
    CHECK_NULL_NOMEM_GOTO(val, rc, fail);
    rc = rp_dt_get_value_from_node(parent, val);
    CHECK_RC_MSG_GOTO(rc, fail, "Get value from node failed");

    if (LYD_DIFF_CREATED == type) {
        for (size_t i = 0; i < changes->count; ++i) {
            recorded_change = (sr_change_t *)changes->data[i];
            if (SR_OP_DELETED == recorded_change->oper &&
                0 == strcmp(val->xpath, recorded_change->old_value->xpath)) {
                /* removed in this commit, undo delete */
                recorded_change->sch_node = NULL; /* hack, mark for removal by NULLifying the schema node */
                sr_free_val(val);
                goto next_parent;
            }
        }
    }

    if (!rp_has_only_empty_np_containers(first_parent, deleted, first_node)) {
        /* created/deleted already before this commit */
        sr_free_val(val);
        return SR_ERR_OK;
    }

    for (size_t i = 0; i < changes->count; ++i) {
        recorded_change = (sr_change_t *)changes->data[i];
        val_ptr = (SR_OP_CREATED == recorded_change->oper ? &recorded_change->new_value : &recorded_change->old_value);
        if (op_type == recorded_change->oper &&
            0 == strcmp(val->xpath, (*val_ptr)->xpath)) {
            /* already recorded in this commit */
            sr_free_val(val);
            return SR_ERR_OK;
        }
    }

    change = calloc(1, sizeof(*change));
    CHECK_NULL_NOMEM_GOTO(change, rc, fail);

    change->oper = (type == LYD_DIFF_CREATED ?  SR_OP_CREATED : SR_OP_DELETED);
    change->sch_node = parent->schema;

    val_ptr = LYD_DIFF_CREATED == type ? &change->new_value : &change->old_value;
    *val_ptr = val;

    rc = sr_list_add(changes, change);
    CHECK_RC_MSG_GOTO(rc, fail, "List add failed");

    /* store changes in DFS pre-order */
    if (LYD_DIFF_CREATED == type && added_parents) {
        memmove(changes->data + changes->count - added_parents,
                changes->data + changes->count - added_parents - 1,
                added_parents * sizeof(*changes->data));
        changes->data[changes->count - added_parents - 1] = (void *)change;
    }
    change = NULL;

next_parent:
    return rp_dt_add_changes_for_parents(changes, deleted, type, first_parent, first_parent->parent,
            second_parent ? second_parent->parent : NULL, added_parents+1);

fail:
    if (NULL != val) {
        sr_free_val(val);
    }
    if (NULL != change) {
        sr_free_changes(change, 1);
    }
    return rc;
}

int
rp_dt_difflist_to_changes(struct lyd_difflist *difflist, sr_list_t **changes_p)
{
    CHECK_NULL_ARG2(difflist, changes_p);
    int rc = SR_ERR_OK;
    sr_change_t *ch = NULL, *recorded_change = NULL;
    bool added = false;
    size_t i = 0;

    sr_list_t *changes = NULL;
    sr_list_t *deleted = NULL;

    rc = sr_list_init(&changes);
    CHECK_RC_MSG_GOTO(rc, cleanup, "List init failed");

    rc = sr_list_init(&deleted);
    CHECK_RC_MSG_GOTO(rc, cleanup, "List init failed");

    /* collect the list of deleted nodes */
    for(size_t d_cnt = 0; LYD_DIFF_END != difflist->type[d_cnt]; d_cnt++) {
        if (LYD_DIFF_DELETED == difflist->type[d_cnt]) {
            rc = sr_list_add(deleted, difflist->first[d_cnt]);
            CHECK_RC_MSG_GOTO(rc, cleanup, "List add failed");
        }
    }

    /* convert libyang data tree changes into the sysrepo representation of changes */
    for(size_t d_cnt = 0; LYD_DIFF_END != difflist->type[d_cnt]; d_cnt++) {
        if (!(LYD_DIFF_CREATED == difflist->type[d_cnt] && (LYS_LIST | LYS_CONTAINER) & difflist->second[d_cnt]->schema->nodetype) &&
            !(LYD_DIFF_DELETED == difflist->type[d_cnt] && (LYS_LIST | LYS_CONTAINER) & difflist->first[d_cnt]->schema->nodetype)) {
            ch = calloc(1, sizeof(*ch));
            CHECK_NULL_NOMEM_GOTO(ch, rc, cleanup);
        }

        switch (difflist->type[d_cnt]) {
        case LYD_DIFF_CREATED:
            rc = rp_dt_add_changes_for_parents(changes, deleted, difflist->type[d_cnt], NULL, difflist->first[d_cnt],
                    difflist->second[d_cnt]->parent, 0);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Add changes for parents failed");
            if ((LYS_LIST | LYS_CONTAINER) & difflist->second[d_cnt]->schema->nodetype) {
                rc = rp_dt_add_changes_for_children(changes, difflist->type[d_cnt], difflist->second[d_cnt], &added);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Add changes for children failed");
            } else {
                ch->oper = SR_OP_CREATED;
                ch->sch_node = difflist->second[d_cnt]->schema;
                ch->new_value = calloc(1, sizeof(*ch->new_value));
                CHECK_NULL_NOMEM_GOTO(ch->new_value, rc, cleanup);
                rc = rp_dt_get_value_from_node(difflist->second[d_cnt], ch->new_value);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Get value from node failed");
            }
            break;
        case LYD_DIFF_DELETED:
            if ((LYS_LIST | LYS_CONTAINER) & difflist->first[d_cnt]->schema->nodetype) {
                rc = rp_dt_add_changes_for_children(changes, difflist->type[d_cnt], difflist->first[d_cnt], &added);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Add changes for children failed");
            } else {
                ch->oper = SR_OP_DELETED;
                ch->sch_node = difflist->first[d_cnt]->schema;
                ch->old_value = calloc(1, sizeof(*ch->old_value));
                CHECK_NULL_NOMEM_GOTO(ch->old_value, rc, cleanup);
                rc = rp_dt_get_value_from_node(difflist->first[d_cnt], ch->old_value);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Get value from node failed");
                rc = sr_list_add(changes, ch);
                CHECK_RC_MSG_GOTO(rc, cleanup, "List add failed");
                ch = NULL;
            }
            rc = rp_dt_add_changes_for_parents(changes, deleted, difflist->type[d_cnt], difflist->first[d_cnt],
                    difflist->first[d_cnt]->parent, NULL, 0);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Add changes for parents failed");
            break;
        case LYD_DIFF_MOVEDAFTER1:
            ch->oper = SR_OP_MOVED;
            ch->sch_node = difflist->first[d_cnt]->schema;

            if (NULL != difflist->second[d_cnt]){
                ch->old_value = calloc(1, sizeof(*ch->old_value));
                CHECK_NULL_NOMEM_GOTO(ch->old_value, rc, cleanup);
                rc = rp_dt_get_value_from_node(difflist->second[d_cnt], ch->old_value);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Get value from node failed");
            }

            ch->new_value = calloc(1, sizeof(*ch->new_value));
            CHECK_NULL_NOMEM_GOTO(ch->new_value, rc, cleanup);
            rc = rp_dt_get_value_from_node(difflist->first[d_cnt], ch->new_value);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Get value from node failed");
            break;
        case LYD_DIFF_MOVEDAFTER2:
            ch->oper = SR_OP_MOVED;
            ch->sch_node = difflist->second[d_cnt]->schema;

            if (NULL != difflist->first[d_cnt]){
                ch->old_value = calloc(1, sizeof(*ch->old_value));
                CHECK_NULL_NOMEM_GOTO(ch->old_value, rc, cleanup);
                rc = rp_dt_get_value_from_node(difflist->first[d_cnt], ch->old_value);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Get value from node failed");
            }

            ch->new_value = calloc(1, sizeof(*ch->new_value));
            CHECK_NULL_NOMEM_GOTO(ch->new_value, rc, cleanup);
            rc = rp_dt_get_value_from_node(difflist->second[d_cnt], ch->new_value);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Get value from node failed");
            break;
        default:
            /* case LYD_DIFF_CHANGED */
            ch->oper = SR_OP_MODIFIED;
            ch->sch_node = difflist->first[d_cnt]->schema;

            ch->old_value = calloc(1, sizeof(*ch->old_value));
            rc = rp_dt_get_value_from_node(difflist->first[d_cnt], ch->old_value);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Get value from node failed");

            ch->new_value = calloc(1, sizeof(*ch->new_value));
            rc = rp_dt_get_value_from_node(difflist->second[d_cnt], ch->new_value);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Get value from node failed");
        }

        if (NULL != ch) {
            rc = sr_list_add(changes, ch);
            CHECK_RC_MSG_GOTO(rc, cleanup, "List add failed");
            ch = NULL;
        }
    }

    /* remove deletes marked for undoing */
    i = 0;
    while (i < changes->count) {
        recorded_change = (sr_change_t *)changes->data[i];
        if (SR_OP_DELETED == recorded_change->oper && NULL == recorded_change->sch_node) {
            sr_free_changes(changes->data[i], 1);
            sr_list_rm_at(changes, i);
            continue;
        }
        ++i;
    }

cleanup:
    sr_list_cleanup(deleted);
    if (SR_ERR_OK != rc) {
        if (NULL != ch) {
            sr_free_changes(ch, 1);
        }
        for (int i = 0; i < changes->count; i++) {
            sr_free_changes(changes->data[i], 1);
        }
        sr_list_cleanup(changes);
    } else {
        *changes_p = changes;
    }
    return rc;
}

int
rp_dt_get_changes(rp_ctx_t *rp_ctx, rp_session_t *rp_session, dm_commit_context_t *c_ctx, const char *xpath,
        size_t offset, size_t limit, sr_list_t **matched_changes)
{
    CHECK_NULL_ARG4(rp_ctx, rp_session, c_ctx, xpath);
    CHECK_NULL_ARG(matched_changes);

    int rc = SR_ERR_OK;
    char *module_name = NULL;
    dm_model_subscription_t lookup = {0};
    dm_model_subscription_t *ms = NULL;
    dm_schema_info_t *schema_info = NULL;

    rc = sr_copy_first_ns(xpath, &module_name);
    CHECK_RC_MSG_RETURN(rc, "Copy first ns failed");

    rc = dm_get_module_and_lock(rp_ctx->dm_ctx, module_name, &schema_info);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Dm get module failed for %s", module_name);

    lookup.schema_info = schema_info;

    ms = sr_btree_search(c_ctx->subscriptions, &lookup);
    pthread_rwlock_unlock(&schema_info->model_lock);
    if (NULL == ms) {
        SR_LOG_ERR("Module subscription not found for module %s", lookup.schema_info->module_name);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }


    RWLOCK_RDLOCK_TIMED_CHECK_GOTO(&ms->changes_lock, rc, cleanup);

    /* generate changes on demand */
    if (!ms->changes_generated) {
        pthread_rwlock_unlock(&ms->changes_lock);
        /* acquire write lock */
        RWLOCK_WRLOCK_TIMED_CHECK_GOTO(&ms->changes_lock, rc, cleanup);
        /* check if some generated the changes meanwhile */
        if (!ms->changes_generated) {
            rc = rp_dt_difflist_to_changes(ms->difflist, &ms->changes);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR_MSG("Difflist to changes failed");
                pthread_rwlock_unlock(&ms->changes_lock);
                goto cleanup;
            }
            ms->changes_generated = true;
        }
    }

    rc = rp_dt_find_changes(rp_ctx->dm_ctx, rp_session->dm_session, ms, &rp_session->change_ctx, xpath, offset, limit, matched_changes);
    pthread_rwlock_unlock(&ms->changes_lock);

    if (SR_ERR_NOT_FOUND != rc) {
        CHECK_RC_LOG_GOTO(rc, cleanup, "Find changes failed for %s", xpath);
    }

cleanup:
    free(module_name);
    return rc;
}
