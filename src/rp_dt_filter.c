/**
 * @file rp_dt_filter.c
 * @author Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Functions for filtering data tree content before converting
 * it from libyang representation into sysrepo data structures.
 *
 * @copyright
 * Copyright 2016 Pantheon Technologies, s.r.o.
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
#include "sr_common.h"
#include "data_manager.h"
#include "rp_dt_filter.h"


int
rp_dt_nacm_filtering(dm_ctx_t *dm_ctx, rp_session_t *rp_session, struct lyd_node *data_tree,
        struct lyd_node **nodes, unsigned int *node_cnt)
{
    int rc = SR_ERR_OK;
    unsigned int i = 0, j = 0;
    nacm_ctx_t *nacm_ctx = NULL;
    nacm_data_val_ctx_t *nacm_data_val_ctx = NULL;
    nacm_action_t nacm_action = NACM_ACTION_PERMIT;
    const char *rule_name = NULL, *rule_info = NULL;
    struct lyd_node *node = NULL;
    CHECK_NULL_ARG4(dm_ctx, rp_session, nodes, node_cnt);

    rc = dm_get_nacm_ctx(dm_ctx, &nacm_ctx);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to get NACM context.");

    if (NULL == nacm_ctx || !(rp_session->options & SR_SESS_ENABLE_NACM)) {
        goto cleanup;
    }

    /* start NACM data access validation */
    rc = nacm_data_validation_start(nacm_ctx, rp_session->user_credentials, data_tree->schema, &nacm_data_val_ctx);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to start NACM data validation.");

    /* check read permission for each node */
    for (i = 0; i < *node_cnt; ++i) {
        node = nodes[i];
        rule_name = rule_info = NULL;
        rc = nacm_check_data(nacm_data_val_ctx, NACM_ACCESS_READ, node, &nacm_action, &rule_name, &rule_info);
        CHECK_RC_LOG_GOTO(rc, cleanup, "NACM data validation failed for node: %s.", node->schema->name);
        if (NACM_ACTION_DENY == nacm_action) {
            nacm_report_read_access_denied(rp_session->user_credentials, node, rule_name, rule_info);
            nodes[i] = NULL; /* omit the node from the result */
        }
    }

    /* move allowed nodes to the beginning of the array */
    i = j = 0;
    while (i < *node_cnt) {
        if (NULL == nodes[i]) {
            j = MAX(j, i+1);
            while (j < *node_cnt && NULL == nodes[j]) {
                ++j;
            }
            if (j < *node_cnt) {
                nodes[i] = nodes[j];
                nodes[j] = NULL;
            } else {
                break;
            }
        }
        ++i;
    }
    *node_cnt = i;

cleanup:
    nacm_data_validation_stop(nacm_data_val_ctx);
    return rc;
}

/**
 * @brief Callback to prune away disabled and NACM-read-inaccessible subtrees from a sysrepo tree.
 */
static int
rp_dt_tree_pruning(void *pruning_ctx_p, const struct lyd_node *subtree, bool *prune)
{
    int rc = SR_ERR_OK;
    nacm_action_t nacm_action = NACM_ACTION_PERMIT;
    const char *rule_name = NULL, *rule_info = NULL;
    rp_tree_pruning_ctx_t *pruning_ctx = (rp_tree_pruning_ctx_t *)pruning_ctx_p;
    CHECK_NULL_ARG3(pruning_ctx, subtree, prune);

    /* check read access */
    if (NULL != pruning_ctx->nacm_data_val_ctx) {
        rc = nacm_check_data(pruning_ctx->nacm_data_val_ctx, NACM_ACCESS_READ, subtree, &nacm_action,
                &rule_name, &rule_info);
        CHECK_RC_LOG_RETURN(rc, "NACM data validation failed for node: %s.", subtree->schema->name);
        if (NACM_ACTION_DENY == nacm_action) {
            nacm_report_read_access_denied(pruning_ctx->nacm_data_val_ctx->user_credentials, subtree,
                    rule_name, rule_info);
            *prune = true;
            return rc;
        }
    }

    /* check if enabled in running */
    if (pruning_ctx->check_enabled && !dm_is_enabled_check_recursively(subtree->schema)) {
        *prune = true;
        return rc;
    }

    *prune = false;
    return rc;
}

void
rp_dt_cleanup_tree_pruning(rp_tree_pruning_ctx_t *pruning_ctx)
{
    if (NULL == pruning_ctx) {
        return;
    }

    nacm_data_validation_stop(pruning_ctx->nacm_data_val_ctx);
    free(pruning_ctx);
}

int
rp_dt_init_tree_pruning(dm_ctx_t *dm_ctx, rp_session_t *rp_session, struct lyd_node *root, struct lyd_node *data_tree,
        bool check_enabled, sr_tree_pruning_cb *pruning_cb, rp_tree_pruning_ctx_t **pruning_ctx_p)
{
    int rc = SR_ERR_OK;
    rp_tree_pruning_ctx_t *pruning_ctx = NULL;
    CHECK_NULL_ARG5(dm_ctx, rp_session, data_tree, pruning_cb, pruning_ctx_p);

    pruning_ctx = calloc(1, sizeof *pruning_ctx);
    CHECK_NULL_NOMEM_RETURN(pruning_ctx);
    pruning_ctx->check_enabled = check_enabled;

    nacm_ctx_t *nacm_ctx = NULL;
    nacm_action_t nacm_action = NACM_ACTION_PERMIT;
    const char *rule_name = NULL, *rule_info;

    rc = dm_get_nacm_ctx(dm_ctx, &nacm_ctx);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to get NACM context.");

    if (NULL != nacm_ctx && (rp_session->options & SR_SESS_ENABLE_NACM)) {
        rc = nacm_data_validation_start(nacm_ctx, rp_session->user_credentials, data_tree->schema,
                &pruning_ctx->nacm_data_val_ctx);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to start NACM data validation.");
        if (NULL != root) {
            rc = nacm_check_data(pruning_ctx->nacm_data_val_ctx, NACM_ACCESS_READ, root, &nacm_action,
                    &rule_name, &rule_info);
            CHECK_RC_LOG_GOTO(rc, cleanup, "NACM data validation failed for node: %s.", root->schema->name);
            if (NACM_ACTION_DENY == nacm_action) {
                nacm_report_read_access_denied(rp_session->user_credentials, root, rule_name, rule_info);
                rc = SR_ERR_UNAUTHORIZED;
                goto cleanup;
            }
        }
    }

cleanup:
    if (SR_ERR_OK == rc) {
        *pruning_ctx_p = pruning_ctx;
        *pruning_cb = rp_dt_tree_pruning;
    } else {
        rp_dt_cleanup_tree_pruning(pruning_ctx);
    }
    return rc;
}
