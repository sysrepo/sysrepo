/**
 * @file rp_dt_xpath.c
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

#include <pthread.h>

#include "rp_dt_xpath.h"
#include "sr_common.h"

/**
 * @brief Creates xpath for the selected node.
 */
int
rp_dt_create_xpath_for_node(sr_mem_ctx_t *sr_mem, const struct lyd_node *node, char **xpath)
{
    CHECK_NULL_ARG3(node, xpath, node->schema);
    int rc = SR_ERR_OK;
    char *result = lyd_path((struct lyd_node *) node);
    CHECK_NULL_NOMEM_RETURN(result);

    /* remove leaf-list predicate */
    if (LYS_LEAFLIST & node->schema->nodetype) {
       char *leaf_list_name = strstr(result, "[.='");
       if (NULL != leaf_list_name) {
           *leaf_list_name = 0;
       } else if (NULL != (leaf_list_name = strstr(result, "[.=\""))) {
           *leaf_list_name = 0;
       }
    }

    rc = sr_mem_edit_string(sr_mem, xpath, result);
    free(result);
    return rc;
}

/**
 *
 * @brief Function tries to validate the xpath and to find the corresponding
 * node in schema if possible.
 *
 * @note Function expects that a schema info is locked for reading.
 *
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] schema_info
 * @param [in] xpath
 * @param [out] match
 * @return Error code (SR_ERR_OK on success)
 */
static int
rp_dt_validate_node_xpath_internal(dm_ctx_t *dm_ctx, dm_session_t *session, dm_schema_info_t *schema_info, const char *xpath, struct lys_node **match)
{
    CHECK_NULL_ARG3(dm_ctx, xpath, schema_info); /* match can be NULL */
    int rc = SR_ERR_OK;

    char *namespace = NULL;
    const struct lys_module *module = NULL;
    struct ly_set *set = NULL;

    rc = sr_copy_first_ns(xpath, &namespace);
    CHECK_RC_MSG_RETURN(rc, "Namespace copy failed");

    if (NULL != match) {
        *match = NULL;
    }

    module = ly_ctx_get_module(schema_info->ly_ctx, namespace, NULL, 1);
    if (NULL == module) {
        if (NULL != session) {
            dm_report_error(session, NULL, xpath, SR_ERR_UNKNOWN_MODEL);
        }
        SR_LOG_ERR("Module %s not found in provided schema info", namespace);
        free(namespace);
        return SR_ERR_UNKNOWN_MODEL;
    }
    free(namespace);

    rc = sr_find_schema_node(module, NULL, xpath, 0, &set);
    if (SR_ERR_OK != rc) {
        if (NULL != session) {
            rc = dm_report_error(session, "Invalid expression.", xpath, rc);
        }
        return rc;
    }

    if (match && set->number == 1) {
        *match = set->set.s[0];
    }
    ly_set_free(set);

    return rc;
}

int
rp_dt_validate_node_xpath_lock(dm_ctx_t *dm_ctx, dm_session_t *session, const char *xpath, dm_schema_info_t **schema_info, struct lys_node **match)
{
    CHECK_NULL_ARG3(dm_ctx, xpath, schema_info);
    int rc = SR_ERR_OK;

    char *namespace = NULL;
    dm_schema_info_t *si = NULL;

    rc = sr_copy_first_ns(xpath, &namespace);
    CHECK_RC_MSG_RETURN(rc, "Namespace copy failed");

    rc = dm_get_module_and_lock(dm_ctx, namespace, &si);
    if (SR_ERR_UNKNOWN_MODEL == rc && NULL != session) {
        rc = dm_report_error(session, NULL, xpath, rc);
    }
    CHECK_RC_LOG_GOTO(rc, cleanup, "Get module %s failed", namespace);

    rc = rp_dt_validate_node_xpath_internal(dm_ctx, session, si, xpath, match);

cleanup:
    *schema_info = si;
    if (NULL != si && SR_ERR_OK != rc) {
        pthread_rwlock_unlock(&si->model_lock);
        *schema_info = NULL;
    }
    free(namespace);
    return rc;
}

int
rp_dt_validate_node_xpath(dm_ctx_t *dm_ctx, dm_session_t *session, const char *xpath, dm_schema_info_t **schema_info, struct lys_node **match)
{
    CHECK_NULL_ARG2(dm_ctx, xpath);
    dm_schema_info_t *si = NULL;
    int rc = SR_ERR_OK;
    rc = rp_dt_validate_node_xpath_lock(dm_ctx, session, xpath, &si, match);
    if (SR_ERR_OK == rc) {
        pthread_rwlock_unlock(&si->model_lock);
        if (NULL != schema_info) {
            *schema_info = si;
        }
    }
    return rc;
}

static int
rp_dt_enable_key_nodes(struct lys_node *node)
{
    CHECK_NULL_ARG(node);
    int rc = SR_ERR_OK;
    if (LYS_LIST == node->nodetype) {
        /* enable list key nodes */
        struct lys_node_list *l = (struct lys_node_list *) node;
        for (size_t k = 0; k < l->keys_size; k++) {
            if (!dm_is_node_enabled((struct lys_node *) l->keys[k])) {
                rc = dm_set_node_state((struct lys_node *) l->keys[k], DM_NODE_ENABLED);
                if (SR_ERR_OK != rc) {
                    SR_LOG_ERR_MSG("Set node state failed");
                    return rc;
                }
            }
        }
    }
    return SR_ERR_OK;
}

static int
rp_dt_enable_mandatory_children(struct lys_node *node)
{
    CHECK_NULL_ARG(node);
    int rc = SR_ERR_OK;
    struct lys_node *n = NULL;
    if ((LYS_LIST | LYS_CONTAINER) & node->nodetype) {
        /* enable mandatory leaves */
        n = node->child;
        while (NULL != n) {
            if ((LYS_LEAF | LYS_LEAFLIST) & n->nodetype &&
                    !dm_is_node_enabled(n) &&
                    LYS_MAND_MASK & n->flags
                    ) {
                rc = dm_set_node_state(n, DM_NODE_ENABLED);
                if (SR_ERR_OK != rc) {
                    SR_LOG_ERR_MSG("Set node state failed");
                    return rc;
                }
            }
            n = n->next;
        }
    }
    return SR_ERR_OK;
}

int
rp_dt_enable_xpath(dm_ctx_t *dm_ctx, dm_session_t *session, dm_schema_info_t *schema_info, const char *xpath)
{
    CHECK_NULL_ARG2(dm_ctx, xpath);
    int rc = SR_ERR_OK;
    struct lys_node *match = NULL, *node = NULL;
    rc = rp_dt_validate_node_xpath_internal(dm_ctx, session, schema_info, xpath, &match);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Xpath validation failed %s", xpath);
        return rc;
    }
    if (NULL == match) {
        // TODO: XPath such as '/example-module://*' seems to return match == NULL
        SR_LOG_ERR("Unsupported xpath '%s'", xpath);
        return SR_ERR_UNSUPPORTED;
    }

    if ((LYS_CONTAINER | LYS_LIST) & match->nodetype) {
        rc = dm_set_node_state(match, DM_NODE_ENABLED_WITH_CHILDREN);
    } else {
        rc = dm_set_node_state(match, DM_NODE_ENABLED);
    }

    CHECK_RC_LOG_GOTO(rc, cleanup, "Set node state failed %s", xpath);

    node = match->parent;
    while (NULL != node) {
        if (NULL == node->parent && LYS_AUGMENT == node->nodetype) {
            node = ((struct lys_node_augment *) node)->target;
            continue;
        }
        if (!dm_is_node_enabled(node)) {
            rc = dm_set_node_state(node, DM_NODE_ENABLED);
            CHECK_RC_LOG_GOTO(rc, cleanup, "Set node state failed %s", xpath);

            rc = rp_dt_enable_key_nodes(node);
            CHECK_RC_LOG_GOTO(rc, cleanup, "Enable key nodes failed %s", xpath);

            rc = rp_dt_enable_mandatory_children(node);
            CHECK_RC_LOG_GOTO(rc, cleanup, "Enable of manadatory children failed %s node %s", xpath, node->name);
        }
        node = node->parent;

    }

cleanup:
    return rc;
}
