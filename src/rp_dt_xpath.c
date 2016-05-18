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
rp_dt_create_xpath_for_node(const struct lyd_node *node, char **xpath)
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

        if (n->schema->nodetype & (LYS_LEAF | LYS_CONTAINER | LYS_LEAFLIST)) {
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

    result = calloc(length, sizeof(*result));
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
 * @brief Tries to match lys_node including choice nodes
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] xpath
 * @param [in] trimmed_xpath
 * @param [in] module
 * @param [out] match
 * @return Error code (SR_ERR_OK on success)
 */
static int
rp_dt_find_in_choice(dm_ctx_t *dm_ctx, dm_session_t *session, const char *xpath, const char *trimmed_xpath, const struct lys_module *module, struct lys_node **match)
{
    CHECK_NULL_ARG5(dm_ctx, xpath, trimmed_xpath, module, match);
    /* libyang err_msg is used to parse the match and unmatch part */
    int rc = SR_ERR_BAD_ELEMENT;
    #define MAX_NODE_NAME_LEN 100
    char *unmatch_part = NULL;
    char *err_msg = NULL;
    char *search = NULL;
    size_t search_size = 0;
    char *xp_copy = strdup(ly_errpath());
    CHECK_NULL_NOMEM_RETURN(xp_copy);
    char *last_slash = rindex(xp_copy, '/');
    if (NULL == last_slash) {
        goto done;
    }
    *last_slash = 0;

    err_msg = strdup(ly_errmsg());
    CHECK_NULL_NOMEM_GOTO(err_msg, rc, done);

    /* split xpath into unmatched part and the part that may contain a choice */
    unmatch_part = strdup(trimmed_xpath + strlen(xp_copy) + 1);
    CHECK_NULL_NOMEM_GOTO(unmatch_part, rc, done);

    search_size = MAX_NODE_NAME_LEN + strlen(unmatch_part);
    search = calloc(search_size, sizeof(*search));
    CHECK_NULL_NOMEM_GOTO(search, rc, done);

    const struct lys_node *node = dm_ly_ctx_get_node(dm_ctx, module->ctx, NULL, xp_copy);
    if (NULL == node) {
        goto done;
    }
    struct lys_node *iter = NULL;
    struct lys_node *child = NULL;

    LY_TREE_FOR(node->child, iter)
    {
        if (LYS_CHOICE == iter->nodetype) {
            /* TODO choice in choice */
            LY_TREE_FOR(iter->child, child) {
                if (LYS_CASE == child->nodetype || 0 == strcmp(unmatch_part, child->name)){
                    snprintf(search, search_size, "%s/%s", child->name, unmatch_part);
                } else {
                    continue;
                }
                *match = (struct lys_node *) ly_ctx_get_node(module->ctx, iter, search);
                if (NULL != *match) {
                    rc = SR_ERR_OK;
                    goto done;
                }
            }
        }
    }


done:
    free(search);
    free(xp_copy);
    free(unmatch_part);
    if (SR_ERR_OK != rc && NULL != session) {
        rc = dm_report_error(session, err_msg, xpath, SR_ERR_BAD_ELEMENT);
    }
    free(err_msg);
    return rc;
}

/**
 * @brief If the xpath identifies leaf-list instance it is not matched by rp_dt_validate_node_xpath.
 * The function tries to remove last characters identifying the leaf-list instance
 * and match a node.
 */
static int
rp_dt_find_leaflist(dm_session_t *session, const char *xpath, char *xp_copy, const struct lys_module *module, struct lys_node **match)
{
    CHECK_NULL_ARG4(xpath, xp_copy, module, match);
    int rc = SR_ERR_BAD_ELEMENT;
    char *err_msg = NULL;

    err_msg = strdup(ly_errmsg());
    CHECK_NULL_NOMEM_GOTO(err_msg, rc, not_matched);

    char *last_slash = rindex(xp_copy, '/');
    if (NULL == last_slash) {
        goto not_matched;
    }

    char *leaf_list = strstr(last_slash, "[.='");
    if (NULL == leaf_list) {
        goto not_matched;
    }
    *leaf_list = 0;

    *match = (struct lys_node *) ly_ctx_get_node(module->ctx, NULL, xp_copy);
    if (NULL != match) {
        rc = SR_ERR_OK;
    }

not_matched:
    if (SR_ERR_OK != rc && NULL != session) {
        rc = dm_report_error(session, err_msg, xpath, SR_ERR_BAD_ELEMENT);
    }
    free(err_msg);
    return rc;
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

    /* remove trailing '*:/' */
    bool change = false;
    while (0 < (xp_len = strlen(xp_copy))) {
        change = false;
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
            const struct lys_module *tmp_module = NULL;
            rc = dm_get_module(dm_ctx, namespace, NULL, &tmp_module);
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

int
rp_dt_validate_node_xpath(dm_ctx_t *dm_ctx, dm_session_t *session, const char *xpath, const struct lys_module **matched_module, struct lys_node **match)
{
    CHECK_NULL_ARG2(dm_ctx, xpath);
    int rc = SR_ERR_OK;

    char *namespace = NULL;
    char *xp_copy = NULL;
    size_t xp_len = 0;
    rc = sr_copy_first_ns(xpath, &namespace);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Namespace copy failed");
        return rc;
    }

    const struct lys_module *module = NULL;
    rc = dm_get_module(dm_ctx, namespace, NULL, &module);
    if (SR_ERR_UNKNOWN_MODEL == rc && NULL != session) {
        rc = dm_report_error(session, NULL, xpath, rc);
    }
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Get module %s failed", namespace);
        free(namespace);
        return rc;
    }
    if (NULL != matched_module) {
        *matched_module = module;
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

    const struct lys_node *sch_node = dm_ly_ctx_get_node(dm_ctx, module->ctx, NULL, xp_copy);
    if (NULL != sch_node) {
        if (NULL != match) {
            *match = (struct lys_node *) sch_node;
        }
    } else {
        switch (ly_vecode) {
        case LYVE_PATH_INNODE:
            /* ly_ctx_get_node is not able to locate nodes inside the choice */
            rc = rp_dt_find_in_choice(dm_ctx, session, xpath, xp_copy, module, (struct lys_node **) &sch_node);
            if (NULL != match) {
                *match = (struct lys_node *) sch_node;
            }
            break;
        case LYVE_PATH_INCHAR:
            rc = rp_dt_find_leaflist(session, xpath, xp_copy, module, (struct lys_node **) &sch_node);
            if (NULL != match) {
                *match = (struct lys_node *) sch_node;
            }
            break;
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

int
rp_dt_enable_xpath(dm_ctx_t *dm_ctx, dm_session_t *session, const char *xpath)
{
    CHECK_NULL_ARG2(dm_ctx, xpath);
    int rc = SR_ERR_OK;
    struct lys_node *match = NULL, *node = NULL;
    rc = rp_dt_validate_node_xpath(dm_ctx, session, xpath, NULL, &match);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Xpath validation failed %s", xpath);
        return rc;
    }

    dm_schema_info_t *si = NULL;
    rc = dm_get_schema_info(dm_ctx, match->module->name, &si);
    CHECK_RC_LOG_RETURN(rc, "Get schema info failed %s", match->module->name);

    pthread_rwlock_wrlock(&si->model_lock);
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
        }
        node = node->parent;

    }

cleanup:
    pthread_rwlock_unlock(&si->model_lock);
    return rc;
}
