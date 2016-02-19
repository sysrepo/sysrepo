/**
 * @file rp_xpath.c
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

#include "rp_dt_xpath.h"
#include "xpath_processor.h"
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
 * Tries to find the node in choice subtree. On success assign the found node into match.
 * @param [in] choice root of the choice subtree
 * @param [in] loc_id xpath that is being match
 * @param [in] level
 * @param [out] match
 * @return
 */
static int
rp_dt_match_in_choice(const struct lys_node *choice, const xp_loc_id_t *loc_id, const size_t level, struct lys_node **match)
{
    CHECK_NULL_ARG3(choice, loc_id, match);
    int rc = SR_ERR_OK;
    struct lys_node *n = choice->child;
    bool in_case = false;

    while (NULL != n) {
        if (LYS_CASE == n->nodetype) {
            in_case = true;
            n = n->child;
            continue;
        }
        else if (LYS_CHOICE == n->nodetype) {
            rc = rp_dt_match_in_choice(n, loc_id, level, match);
            if (SR_ERR_NOT_FOUND == rc) {
                n = n->next;
                continue;
            } else {
                return rc;
            }
        }

        if (!XP_EQ_NODE(loc_id, level, n->name)) {
            if (in_case && NULL == n->next){
                n = n->parent->next;
                in_case = false;
            }
            else {
                n = n->next;
            }
            continue;
        }
        else {
            break;
        }
    }

    if (NULL != n) {
        *match = n;
        return SR_ERR_OK;
    }
    return SR_ERR_NOT_FOUND;
}

/**
 * @brief Validates list node
 */
static int
rp_dt_validate_list(dm_session_t *session, const struct lys_node *node, const xp_loc_id_t *loc_id, const size_t level)
{
    CHECK_NULL_ARG3(session, node, loc_id);

    if (LYS_LIST != node->nodetype) {
        SR_LOG_ERR("Keys specified for the node that is not list %s", node->name);
        return dm_report_error(session, "Keys specified for the node that is not list", XP_CPY_UP_TO_NODE(loc_id, level), SR_ERR_BAD_ELEMENT);
    }
    struct lys_node_list *list = (struct lys_node_list *) node;
    if (list->keys_size != XP_GET_KEY_COUNT(loc_id, level)) {
        SR_LOG_ERR("Key count does not match %s", node->name);
        return dm_report_error(session, "Number of keys specified does not match the schema", XP_CPY_UP_TO_NODE(loc_id, level), SR_ERR_BAD_ELEMENT);
    }
    size_t matched_keys = 0;
    for (size_t k = 0; k < list->keys_size; k++) {
        if (NULL == list->keys || NULL == list->keys[k] || NULL == list->keys[k]->name) {
            return SR_ERR_INTERNAL;
        }
        for (size_t k_xp = 0; k_xp < list->keys_size; k_xp++) {
            if (XP_EQ_KEY_NAME(loc_id, level, k_xp, list->keys[k]->name)) {
                matched_keys++;
            }
        }
    }
    if (list->keys_size != matched_keys) {
        SR_LOG_ERR("Not all keys has been matched %s", loc_id->xpath);
        return dm_report_error(session, "Not all keys has been matched", XP_CPY_UP_TO_NODE(loc_id, level), SR_ERR_BAD_ELEMENT);
    }
    return SR_ERR_OK;
}

int
rp_dt_validate_node_xpath(dm_ctx_t *dm_ctx, dm_session_t *session, const xp_loc_id_t *loc_id, const struct lys_module **matched_module, struct lys_node **match)
{
    CHECK_NULL_ARG3(dm_ctx, session, loc_id);
    CHECK_NULL_ARG(loc_id->xpath);

    char *module_name = NULL;
    const struct lys_module *module = NULL;
    struct lys_node *node = NULL;
    int rc = SR_ERR_OK;

    module_name = XP_CPY_FIRST_NS(loc_id);
    if (NULL == module_name) {
        SR_LOG_ERR_MSG("Module name copy failed");
        return SR_ERR_INTERNAL;
    }

    rc = dm_get_module(dm_ctx, module_name, NULL, &module);
    free(module_name);
    if (SR_ERR_UNKNOWN_MODEL == rc) {
        return dm_report_error(session, NULL, XP_CPY_UP_TO_NODE(loc_id, 0), rc);
    }
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Get module failed");
        return rc;
    }

    if (NULL != matched_module) {
        *matched_module = module;
    }

    if (NULL == module->name) {
        SR_LOG_ERR_MSG("Missing schema information");
        return SR_ERR_INTERNAL;
    }

    if (XP_IS_MODULE_XPATH(loc_id)){
        SR_LOG_DBG("Module xpath %s, do not match node", loc_id->xpath);
        if (NULL != match) {
            *match = NULL;
        }
        return SR_ERR_OK;
    }
    node = module->data;

    size_t i = 0;
    for (; i < XP_GET_NODE_COUNT(loc_id); i++) {
        while (NULL != node) {
            if (NULL == node->name || NULL == node->module->name) {
                SR_LOG_ERR_MSG("Missing schema information");
                return SR_ERR_INTERNAL;
            }

            /* choice is represented by the node in schema tree */
            if (LYS_CHOICE == node->nodetype){
                rc = rp_dt_match_in_choice(node, loc_id, i, &node);
                if (SR_ERR_NOT_FOUND == rc) {
                    node = node->next;
                    rc = SR_ERR_OK;
                    continue;
                } else if (SR_ERR_OK != rc) {
                    SR_LOG_ERR_MSG("Match in choice failed");
                    return rc;
                }
            }

            if (XP_HAS_NODE_NS(loc_id, i)) {
                if (!XP_EQ_NODE_NS(loc_id, i, node->module->name)) {
                    const struct lys_module *m = NULL;
                    char *module_name = XP_CPY_NODE_NS(loc_id, i);
                    if (NULL == module_name) {
                        SR_LOG_ERR_MSG("Module name duplication failed");
                        return SR_ERR_INTERNAL;
                    }
                    rc = dm_get_module(dm_ctx, module_name,NULL, &m);
                    free(module_name);
                    if (SR_ERR_UNKNOWN_MODEL == rc) {
                        return dm_report_error(session, NULL, XP_CPY_UP_TO_NODE(loc_id, i), SR_ERR_UNKNOWN_MODEL);
                    }
                    node = node->next;
                    continue;
                }
            }

            if (!XP_EQ_NODE(loc_id, i, node->name)) {
                node = node->next;
                continue;
            }

            if (0 != XP_GET_KEY_COUNT(loc_id, i)) {
                rc = rp_dt_validate_list(session, node, loc_id, i);
                if (SR_ERR_OK != rc) {
                    SR_LOG_ERR("List validation failed %s", loc_id->xpath);
                    return rc;
                }
            }

            /* match at the i level found*/
            if (i != (XP_GET_NODE_COUNT(loc_id) - 1)) {
                node = node->child;
            }
            break;
        }

        if (NULL == node) {
            SR_LOG_ERR("Request node not found in schemas %s", loc_id->xpath);
            return dm_report_error(session, NULL, XP_CPY_UP_TO_NODE(loc_id, i), SR_ERR_BAD_ELEMENT);
        }
    }

    if (NULL != match) {
        *match = node;
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
            if (!dm_is_node_enabled((struct lys_node *)l->keys[k])) {
                rc = dm_set_node_state((struct lys_node *)l->keys[k], DM_NODE_ENABLED);
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
rp_dt_enable_xpath(dm_ctx_t *dm_ctx, dm_session_t *session, const xp_loc_id_t *loc_id)
{
    CHECK_NULL_ARG4(dm_ctx, session, loc_id, loc_id->xpath);
    int rc = SR_ERR_OK;
    struct lys_node *match = NULL, *node = NULL;
    rc = rp_dt_validate_node_xpath(dm_ctx, session, loc_id, NULL, &match);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Xpath validation failed %s", loc_id->xpath);
        return rc;
    }

    if ((LYS_CONTAINER | LYS_LIST) & match->nodetype) {
        rc = dm_set_node_state(match, DM_NODE_ENABLED_WITH_CHILDREN);
    } else {
        rc = dm_set_node_state(match, DM_NODE_ENABLED);
    }

    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Set node state failed %s", loc_id->xpath);
        return rc;
    }

    node = match->parent;
    while (NULL != node) {
        if (NULL == node->parent && LYS_AUGMENT == node->nodetype) {
            node = ((struct lys_node_augment *) node)->target;
            continue;
        }
        if (!dm_is_node_enabled(node)){
            rc = dm_set_node_state(node, DM_NODE_ENABLED);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Set node state failed %s", loc_id->xpath);
                return rc;
            }
            rc = rp_dt_enable_key_nodes(node);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Enable key nodes failed %s", loc_id->xpath);
                return rc;
            }

        }
        node = node->parent;

    }

    return rc;
}
