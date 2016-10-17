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
 * @brief Creates part of xpath for leaf and container nodes. Arguments specify if the namespace and trailing slash
 * should be included.
 */
static int
rp_dt_create_xpath_for_cont_leaf_node(const struct lyd_node *data_tree, char **xpath, bool namespace, bool trailing_slash)
{
    CHECK_NULL_ARG2(data_tree, xpath);
    char *s = NULL;
    size_t len = 1; /* terminating null byte*/
    size_t ns_len = 0;
    size_t node_len = 0;

    /* calculate length */
    if (namespace) {
        CHECK_NULL_ARG3(data_tree->schema, data_tree->schema->module, data_tree->schema->module->name);
        ns_len = strlen(data_tree->schema->module->name) + 1; /*namespace + colon*/
        len += ns_len;
    }
    CHECK_NULL_ARG(data_tree->schema->name);
    node_len = strlen(data_tree->schema->name);
    len += node_len;
    if (trailing_slash) {
        len++;
    }
    s = calloc(len, sizeof(*s));
    if (NULL == s) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }

    /* copy string */
    if (namespace) {
        strcpy(s, data_tree->schema->module->name);
        s[ns_len - 1] = ':';
    }
    strcpy(s + ns_len, data_tree->schema->name);

    if (trailing_slash) {
        s[ns_len + node_len] = '/';
    }

    *xpath = s;
    return SR_ERR_OK;
}

/**
 * @brief Creates part of xpath for list nodes. Arguments specify if the namespace and trailing slash
 * should be included.
 */
static int
rp_dt_create_xpath_for_list_node(const struct lyd_node *data_tree, char **xpath, bool namespace, bool trailing_slash)
{
    CHECK_NULL_ARG2(data_tree, xpath);
    char *s = NULL;
    size_t len = 1; /* terminating null byte*/
    size_t ns_len = 0;
    size_t offset = 0;

    /* calculate length*/
    if (namespace) {
        CHECK_NULL_ARG3(data_tree->schema, data_tree->schema->module, data_tree->schema->module->name);
        ns_len = strlen(data_tree->schema->module->name);
        len += ns_len + 1; /*namespace + colon*/
    }
    CHECK_NULL_ARG(data_tree->schema->name);
    len += strlen(data_tree->schema->name);
    if (trailing_slash) {
        len++;
    }
    /* lookup keys */
    struct lys_node_list *sch_list = (struct lys_node_list *) data_tree->schema;

    struct lyd_node_leaf_list **key_nodes = calloc(sch_list->keys_size, sizeof(*key_nodes));
    if (key_nodes == NULL) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }
    struct lyd_node *c = data_tree->child;
    size_t matched = 0;

    while (c != NULL) {
        for (int k = 0; k < sch_list->keys_size; k++) {
            if (NULL == sch_list->keys[k] || NULL == sch_list->keys[k]->name ||
                    NULL == c->schema || NULL == c->schema->name) {
                c = c->next;
                SR_LOG_WRN("Skipping node when matching keys for %s, schema information missing", sch_list->name);
                continue;
            }

            if (0 == strcmp(sch_list->keys[k]->name, c->schema->name)) {
                key_nodes[matched] = (struct lyd_node_leaf_list *) c;
                len += strlen(key_nodes[matched]->value_str); /*key value*/
                len += strlen(c->schema->name); /*key name*/
                len += 5; /*delimiting characters [='']*/
                matched++;
                break;
            }
        }
        c = c->next;
    }
    if (matched != sch_list->keys_size) {
        SR_LOG_ERR("Keys not found for list %s", sch_list->name);
        free(key_nodes);
        return SR_ERR_INTERNAL;
    }

    s = calloc(len, sizeof(*s));
    if (NULL == s) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        free(key_nodes);
        return SR_ERR_NOMEM;
    }

    /* copy string */
    if (namespace) {
        strcpy(s, data_tree->schema->module->name);
        s[ns_len] = ':';
        offset += ns_len + 1;
    }
    strcpy(s + offset, data_tree->schema->name);
    offset += strlen(data_tree->schema->name);
    for (int k = 0; k < sch_list->keys_size; k++) {
        s[offset++] = '[';
        strcpy(s + offset, key_nodes[k]->schema->name);
        offset += strlen(key_nodes[k]->schema->name);
        s[offset++] = '=';
        s[offset++] = '\'';
        strcpy(s + offset, key_nodes[k]->value_str);
        offset += strlen(key_nodes[k]->value_str);
        s[offset++] = '\'';
        s[offset++] = ']';
    }

    if (trailing_slash) {
        s[offset] = '/';
    }

    free(key_nodes);
    *xpath = s;
    return SR_ERR_OK;
}

/**
 * @brief Creates xpath for the selected node.
 */
int
rp_dt_create_xpath_for_node(sr_mem_ctx_t *sr_mem, const struct lyd_node *node, char **xpath)
{
    CHECK_NULL_ARG2(node, xpath);
    int rc = 0;
    char **parts = NULL;
    char *result = NULL;
    size_t offset = 0;
    size_t length = 0;
    size_t level = 0;

    /*find node depth*/
    const struct lyd_node *n = node;
    while (NULL != n) {
        n = n->parent;
        level++;
    }
    parts = calloc(level, sizeof(*parts));
    if (NULL == parts) {
        SR_LOG_ERR_MSG("Memory allocation failed.");
        return SR_ERR_NOMEM;
    }

    size_t i = level - 1;
    n = node;
    /*create parts of xpath */
    while (NULL != n) {
        /*append slash to all nodes except the last one*/
        bool slash = i != (level - 1);

        if (NULL == n->schema || NULL == n->schema->module || NULL == n->schema->module->name ||
                (NULL != n->parent && (NULL == n->parent || NULL == n->parent->schema ||
                NULL == n->parent->schema->module || NULL == n->parent->schema->module->name))) {
            SR_LOG_ERR("Schema node at level %zu is NULL", i);
            for (size_t j = 0; j < i; j++) {
                free(parts[j]);
            }
            free(parts);
            return SR_ERR_INTERNAL;
        }
        /*print namespace for the root node and when there is an augment*/
        bool namespace = NULL == n->parent || 0 != strcmp(n->parent->schema->module->name, n->schema->module->name);

        if (n->schema->nodetype & (LYS_LEAF | LYS_CONTAINER | LYS_LEAFLIST | LYS_RPC | LYS_NOTIF | LYS_ACTION)) {
            rc = rp_dt_create_xpath_for_cont_leaf_node(n, &parts[i], namespace, slash);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR_MSG("Creating xpath failed.");
                for (size_t j = 0; j < i; j++) {
                    free(parts[j]);
                }
                free(parts);
                return rc;
            }
        } else if (LYS_LIST == n->schema->nodetype) {
            rc = rp_dt_create_xpath_for_list_node(n, &parts[i], namespace, slash);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR_MSG("Creating xpath failed.");
                for (size_t j = 0; j < i; j++) {
                    free(parts[j]);
                }
                free(parts);
                return rc;
            }
        } else {
            SR_LOG_ERR_MSG("Unsupported node type.");
            for (size_t j = 0; j < i; j++) {
                free(parts[j]);
            }
            free(parts);
            return SR_ERR_INTERNAL;
        }
        n = n->parent;
        i--;
    }

    /*join parts*/
    length = 1; /*leading slash*/
    for (i = 0; i < level; i++) {
        length += strlen(parts[i]);
    }
    length++; /*terminating null byte*/

    result = sr_calloc(sr_mem, length, sizeof(*result));
    if (NULL == result) {
        SR_LOG_ERR_MSG("Memory allocation failed.");
        for (int j = 0; j < level; j++) {
            free(parts[j]);
        }
        free(parts);
        return SR_ERR_NOMEM;
    }

    result[offset] = '/';
    offset++;
    for (i = 0; i < level; i++) {
        strcpy(result + offset, parts[i]);
        offset += strlen(parts[i]);
    }

    /*free parts*/
    for (int i = 0; i < level; i++) {
        free(parts[i]);
    }
    free(parts);

    *xpath = result;
    return SR_ERR_OK;
}

/**
 * @brief Removes trailing characters from xpath to make it validateable by ly_ctx_get_node
 * @param [in] dm_ctx
 * @param [in] xpath
 * @param [out] trimmed
 * @return Error code (SR_ERR_OK on success)
 */
static int
rp_dt_trim_xpath(dm_ctx_t *dm_ctx, const char *xpath, char **trimmed)
{
    CHECK_NULL_ARG3(dm_ctx, xpath, trimmed);
    int rc = SR_ERR_OK;
    char *xp_copy = NULL;
    char *namespace = NULL;
    size_t xp_len = 0;

    xp_copy = strdup(xpath);
    CHECK_NULL_NOMEM_RETURN(xp_copy);

    /* remove trailing '*:/.' */
    bool change = false;
    while (0 < (xp_len = strlen(xp_copy))) {
        change = false;
        if ('.' == xp_copy[xp_len - 1]) {
            xp_copy[xp_len - 1] = 0;
            xp_len--;
            change = true;
        }
        if ('*' == xp_copy[xp_len - 1]) {
            xp_copy[xp_len - 1] = 0;
            xp_len--;
            change = true;
        }
        if ('/' == xp_copy[xp_len - 1]) {
            xp_copy[xp_len - 1] = 0;
            xp_len--;
            change = true;
        }
        if (':' == xp_copy[xp_len - 1]) {
            xp_copy[xp_len - 1] = 0;
            xp_len--;
            char *last_slash = rindex(xp_copy, '/');
            if (NULL == last_slash || xp_len < 1) {
                free(xp_copy);
                return SR_ERR_INVAL_ARG;
            }

            namespace = strdup(last_slash + 1); /* do not copy leading slash */
            dm_schema_info_t *tmp_sch_info = NULL;
            rc = dm_get_module_without_lock(dm_ctx, namespace, &tmp_sch_info);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Get module %s failed", namespace);
                free(namespace);
                free(xp_copy);
                return rc;
            }
            free(namespace);
            *last_slash = 0;
            change = true;
        }
        if (!change) {
            break;
        }
    }
    *trimmed = xp_copy;
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
rp_dt_validate_node_xpath_intrenal(dm_ctx_t *dm_ctx, dm_session_t *session, dm_schema_info_t *schema_info, const char *xpath, struct lys_node **match)
{
    CHECK_NULL_ARG3(dm_ctx, xpath, schema_info); /* match can be NULL */
    int rc = SR_ERR_OK;

    char *namespace = NULL;
    char *xp_copy = NULL;
    size_t xp_len = 0;
    const struct lys_module *module = NULL;
    rc = sr_copy_first_ns(xpath, &namespace);
    CHECK_RC_MSG_RETURN(rc, "Namespace copy failed");

    if (NULL != match) {
        *match = NULL;
    }

    module = ly_ctx_get_module(schema_info->ly_ctx, namespace, NULL);

    if (NULL == module) {
        if (NULL != session) {
            dm_report_error(session, NULL, xpath, SR_ERR_UNKNOWN_MODEL);
        }
        SR_LOG_ERR("Module %s not found in provided schema info", namespace);
        free(namespace);
        return SR_ERR_UNKNOWN_MODEL;
    }
    free(namespace);

    rc = rp_dt_trim_xpath(dm_ctx, xpath, &xp_copy);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Error while xpath trim %s", xpath);
        return rc;
    }

    xp_len = strlen(xp_copy);
    if (0 == xp_len) {
        free(xp_copy);
        return SR_ERR_OK;
    }


    const struct lys_node *start_node = NULL;
    if (NULL != schema_info->module) {
        start_node = schema_info->module->data;
    } else {
        const struct lys_module *m = NULL;
        uint32_t index = 0;
        while(NULL != (m = ly_ctx_get_module_iter(schema_info->ly_ctx, &index))) {
            if (NULL != m->data) {
                start_node = m->data;
                break;
            }
        }
    }

    const struct lys_node *sch_node = sr_find_schema_node(start_node, xp_copy, 0);
    if (NULL != sch_node) {
        if (NULL != match) {
            *match = (struct lys_node *) sch_node;
        }
    } else {
        switch (ly_vecode) {
        case LYVE_PATH_INKEY:
            if (NULL != session) {
                rc = dm_report_error(session, ly_errmsg(), ly_errpath(), SR_ERR_BAD_ELEMENT);
            } else {
                rc = SR_ERR_BAD_ELEMENT;
            }
            break;
        case LYVE_PATH_INMOD:
            if (NULL != session) {
                rc = dm_report_error(session, ly_errmsg(), ly_errpath(), SR_ERR_UNKNOWN_MODEL);
            } else {
                rc = SR_ERR_UNKNOWN_MODEL;
            }
            break;
        case LYVE_XPATH_INSNODE:
            if (NULL != session) {
                rc = dm_report_error(session, ly_errmsg(), xp_copy, SR_ERR_BAD_ELEMENT);
            } else {
                rc = SR_ERR_BAD_ELEMENT;
            }
            break;
        default:
            if (NULL != session) {
                rc = dm_report_error(session, ly_errmsg(), ly_errpath(), SR_ERR_INVAL_ARG);
            } else {
                rc = SR_ERR_INVAL_ARG;
            }
        }
    }
    free(xp_copy);
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

    rc = rp_dt_validate_node_xpath_intrenal(dm_ctx, session, si, xpath, match);

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
    rc = rp_dt_validate_node_xpath_intrenal(dm_ctx, session, schema_info, xpath, &match);
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
