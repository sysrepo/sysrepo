/**
 * @file rp_dt_edit.c
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

#include "rp_dt_edit.h"
#include "rp_dt_lookup.h"
#include "rp_dt_xpath.h"
#include "sysrepo.h"
#include "sr_common.h"
#include "xpath_processor.h"

/**
 * @brief structure filled by ::rp_dt_find_deepest_match_wrapper.
 * It includes resources for further edit request processing.
 */
typedef struct rp_dt_match_s {
    xp_loc_id_t *loc_id;            /**< loc_id for the request xpath doesn't (xpath for matched node might just substring of it) */
    struct lys_node *schema_node;   /**< Matched schema node */
    dm_data_info_t *info;           /**< Data info structure for the model pointed by loc_id */

    size_t level;                   /**< Depth of the node that has been matched */
    struct lyd_node *node;          /**< Deepest match */
}rp_dt_match_t;

static int
rp_dt_find_deepest_match_wrapper(dm_ctx_t *ctx, dm_session_t *session, const char * xpath, rp_dt_match_t *match)
{
    CHECK_NULL_ARG3(ctx, session, xpath);
    const struct lys_module *module = NULL;
    int rc = xp_char_to_loc_id(xpath, &match->loc_id);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Converting xpath '%s' to loc_id failed.", xpath);
        return rc;
    }

    rc = rp_dt_validate_node_xpath(ctx, match->loc_id, &module, &match->schema_node);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Requested node is not valid %s", xpath);
        goto cleanup;
    }

    rc = dm_get_data_info(ctx, session, module->name, &match->info);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Getting data tree failed for xpath '%s'", xpath);
        goto cleanup;
    }

    rc = rp_dt_find_deepest_match(match->info->node, match->loc_id, true, dm_is_running_datastore_session(session), &match->level, &match->node);

cleanup:
    if (SR_ERR_OK != rc && SR_ERR_NOT_FOUND != rc) {
        xp_free_loc_id(match->loc_id);
        match->loc_id = NULL;
    }
    return rc;
}

/**
 * @brief Checks if the node has a key with the name
 */
static int
rp_dt_has_key(const struct lyd_node *node, const char *name, bool *res)
{
    CHECK_NULL_ARG(name);

    if (NULL != node && NULL != node->schema && LYS_LIST == node->schema->nodetype) {
        struct lys_node_list *list = (struct lys_node_list *) node->schema;
        for (size_t k = 0; k < list->keys_size; k++) {
            if (NULL == list->keys[k] || NULL == list->keys[k]->name) {
                SR_LOG_ERR_MSG("Missing schema information");
                return SR_ERR_INTERNAL;
            }
            if (0 == strcmp(name, list->keys[k]->name)) {
                *res = true;
                return SR_ERR_OK;
            }
        }
    }
    *res = false;
    return SR_ERR_OK;
}

/**
 * @brief Function creates list key nodes at the selected level and append them
 * to the provided parent. If there are no keys at the selected level it does nothing.
 */
static int
rp_dt_create_keys(rp_dt_match_t *match, struct lyd_node *parent, size_t level)
{
    CHECK_NULL_ARG2(match, parent);
    size_t key_count = XP_GET_KEY_COUNT(match->loc_id, level);
    char *key_name = NULL;
    char *key_value = NULL;
    if (key_count != 0) {
        for (size_t k = 0; k < key_count; k++) {
            key_name = XP_CPY_KEY_NAME(match->loc_id, level, k);
            key_value = XP_CPY_KEY_VALUE(match->loc_id, level, k);
            if (NULL == key_name || NULL == key_value) {
                SR_LOG_ERR("Copy of key name or key value failed %s", match->loc_id->xpath);
                goto cleanup;
            }
            if (NULL == sr_lyd_new_leaf(match->info, parent, parent->schema->module, key_name, key_value)) {
                SR_LOG_ERR("Adding key leaf failed %s", match->loc_id->xpath);
                goto cleanup;
            }
            free(key_name);
            free(key_value);
        }
    }
    return SR_ERR_OK;

cleanup:
    free(key_name);
    free(key_value);
    return SR_ERR_INTERNAL;
}

static int
rp_dt_find_closest_sibling_by_name(dm_data_info_t *info, struct lyd_node *start_node, sr_move_direction_t direction, struct lyd_node **sibling)
{
    CHECK_NULL_ARG3(info, start_node, sibling);
    CHECK_NULL_ARG2(start_node->schema, start_node->schema->name);

    struct lyd_node *sib = SR_MOVE_UP == direction ? start_node->prev : start_node->next;

    /* node where the lookup should be stopped - first sibling in case of direction == UP */
    struct lyd_node *stop_node = NULL != start_node->parent ? start_node->parent->child : info->node;
    if (stop_node == start_node && direction == SR_MOVE_UP){
        return SR_ERR_NOT_FOUND;
    }

    while (NULL != sib){
        CHECK_NULL_ARG2(sib->schema, sib->schema->name);
        if (0 == strcmp(start_node->schema->name, sib->schema->name)) {
            *sibling = sib;
            return SR_ERR_OK;
        }
        if (stop_node == sib) {
            break;
        }
        sib = SR_MOVE_UP == direction ? sib->prev : sib->next;
    }
    return SR_ERR_NOT_FOUND;
}

int
rp_dt_delete_item(dm_ctx_t *dm_ctx, dm_session_t *session, const char *xpath, const sr_edit_flag_t options)
{
    CHECK_NULL_ARG3(dm_ctx, session, xpath);

    int rc = SR_ERR_INVAL_ARG;
    struct lyd_node *node = NULL;
    struct lyd_node *parent = NULL;
    char *data_tree_name = NULL;
    rp_dt_match_t match = {0,};

    rc = rp_dt_find_deepest_match_wrapper(dm_ctx, session, xpath, &match);
    if (SR_ERR_NOT_FOUND == rc) {
        if (options & SR_EDIT_STRICT) {
            SR_LOG_ERR("No item exists '%s' deleted with strict opt", xpath);
            rc = SR_ERR_INVAL_ARG;
            goto cleanup;
        }
        rc = SR_ERR_OK;
        match.info->modified = true;
        goto cleanup;
    } else if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Find deepest match failed %s", xpath);
        goto cleanup;
    }

    /* check if match is complete */
    if (XP_GET_NODE_COUNT(match.loc_id) != match.level) {
        if (options & SR_EDIT_STRICT) {
            SR_LOG_ERR("No item exists '%s' deleted with strict opt", xpath);
            rc = SR_ERR_INVAL_ARG;
            goto cleanup;
        }
        match.info->modified = true;
        rc = SR_ERR_OK;
        goto cleanup;
    }


    if (NULL == match.node->schema || NULL == match.node->schema->name) {
        SR_LOG_ERR_MSG("Missing schema information");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* save parent to delete empty containers */
    parent = match.node->parent;

    /* perform delete according to the node type */
    if (match.node->schema->nodetype == LYS_CONTAINER) {
        if (options & SR_EDIT_NON_RECURSIVE) {
            SR_LOG_ERR("Item for xpath %s is container deleted with non recursive opt", xpath);
            rc = SR_ERR_INVAL_ARG;
            goto cleanup;
        }
        //TODO log to operation queue
        rc = sr_lyd_unlink(match.info, match.node);
        if (0 != rc) {
            SR_LOG_ERR("Unlinking of the node %s failed", xpath);
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
        lyd_free_withsiblings(match.node);
    } else if (match.node->schema->nodetype == LYS_LEAF) {
        bool is_key = false;
        rc = rp_dt_has_key(match.node->parent, match.node->schema->name, &is_key);
        if (SR_ERR_OK != rc){
            SR_LOG_ERR_MSG("Has key failed");
            goto cleanup;
        }
        if (is_key){
            SR_LOG_ERR("Key leaf can not be delete delete the list instead %s", xpath);
            rc = SR_ERR_INVAL_ARG;
            goto cleanup;
        }
        //TODO log to operation queue
        rc = sr_lyd_unlink(match.info, match.node);
        if (0 != rc) {
            SR_LOG_ERR("Unlinking of the node %s failed", xpath);
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
        lyd_free(match.node);
    } else if (match.node->schema->nodetype == LYS_LEAFLIST) {
        struct lyd_node **nodes = NULL;
        size_t count = 0;
        /* find all leaf-list records */
        rc = rp_dt_get_siblings_node_by_name(match.node, match.node->schema->name, &nodes, &count);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Get sibling by name failed for xpath %s ", xpath);
            goto cleanup;
        }

        /* delete leaf-list nodes */
        for (size_t i = 0; i < count; i++) {
            //TODO log to operation queue
            rc = sr_lyd_unlink(match.info, nodes[i]);
            if (0 != rc) {
                SR_LOG_ERR("Unlinking of the node %s failed", xpath);
                free(nodes);
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            lyd_free(nodes[i]);
        }
        free(nodes);
    } else if (match.node->schema->nodetype == LYS_LIST) {
        size_t last_node = XP_GET_NODE_COUNT(match.loc_id) - 1;
        if (options & SR_EDIT_NON_RECURSIVE) {
            /* count children */
            struct lyd_node *child = match.node->child;
            size_t child_cnt = 0;
            while (NULL != child) {
                child = child->next;
                child_cnt++;
            }
            if (XP_GET_KEY_COUNT(match.loc_id, last_node) != child_cnt) {
                SR_LOG_ERR("Item for xpath %s is non empty list. It can not be deleted with non recursive opt", xpath);
                rc = SR_ERR_INVAL_ARG;
                goto cleanup;
            }
        }
        if (0 != XP_GET_KEY_COUNT(match.loc_id, last_node)) {
            /* delete list instance */
            rc = sr_lyd_unlink(match.info, match.node);
            if (0 != rc) {
                SR_LOG_ERR("Unlinking of the node %s failed", xpath);
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            lyd_free_withsiblings(match.node);
        } else {
            /* delete all instances */
            struct lyd_node **nodes = NULL;
            size_t count = 0;
            /* find all list instances */
            rc = rp_dt_get_siblings_node_by_name(match.node, match.node->schema->name, &nodes, &count);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Get sibling by name failed for xpath %s ", xpath);
                goto cleanup;
            }

            /* delete list nodes*/
            for (size_t i = 0; i < count; i++) {
                //TODO log to operation queue
                rc = sr_lyd_unlink(match.info, nodes[i]);
                if (0 != rc) {
                    SR_LOG_ERR("Unlinking of the node %s failed", xpath);
                    free(nodes);
                    rc = SR_ERR_INTERNAL;
                    goto cleanup;
                }
                lyd_free_withsiblings(nodes[i]);
            }
            free(nodes);
        }
    }

    /* delete all empty parent containers */
    node = parent;
    while (NULL != node) {
        if (NULL == node->child && LYS_CONTAINER == node->schema->nodetype) {
            parent = node->parent;
            sr_lyd_unlink(match.info, node);
            lyd_free(node);
            node = parent;
        } else {
            break;
        }
    }

    /* mark to session copy that some change has been made */
    match.info->modified = true;
cleanup:
    xp_free_loc_id(match.loc_id);
    free(data_tree_name);
    return rc;
}

int
rp_dt_set_item(dm_ctx_t *dm_ctx, dm_session_t *session, const char *xpath, const sr_edit_flag_t options, const sr_val_t *value)
{
    CHECK_NULL_ARG3(dm_ctx, session, xpath);
    /* value can be NULL if the list is created */

    int rc = SR_ERR_INVAL_ARG;
    struct lyd_node *node = NULL;
    rp_dt_match_t m = {0,};

    /* to be freed during cleanup */
    struct lyd_node *created = NULL;
    char *new_value = NULL;
    char *node_name = NULL;
    char *module_name = NULL;

    rc = rp_dt_find_deepest_match_wrapper(dm_ctx, session, xpath, &m);
    if (SR_ERR_NOT_FOUND == rc) {
        if (XP_GET_NODE_COUNT(m.loc_id) != 1 && (options & SR_EDIT_NON_RECURSIVE)) {
            SR_LOG_ERR("A preceding node is missing '%s' create it or omit the non recursive option", xpath);
            rc = SR_ERR_INVAL_ARG;
            goto cleanup;
        } else {
            rc = SR_ERR_OK;
        }
    } else if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Find deepest match failed %s", xpath);
        goto cleanup;
    }

    /* if the session is tied to running, check if the leaf is enabled*/
    if (dm_is_running_datastore_session(session)) {
        if (!dm_is_enabled_check_recursively(m.schema_node)) {
            SR_LOG_ERR("Requested path '%s' is not enable in running data store", xpath);
            rc = SR_ERR_INVAL_ARG;
            goto cleanup;
        }
    }

    /* check if match is complete */
    if (XP_GET_NODE_COUNT(m.loc_id) != m.level) {
        if (XP_GET_NODE_COUNT(m.loc_id) != (m.level + 1)) {
            if (options & SR_EDIT_NON_RECURSIVE) {
                SR_LOG_ERR("A preceding item is missing '%s' create it or omit the non recursive option", xpath);
                rc = SR_ERR_INVAL_ARG;
                goto cleanup;
            }
        }
    } else if (options & SR_EDIT_STRICT) {
        SR_LOG_ERR("Item exists '%s' can not be created again with strict opt", xpath);
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    if (NULL != m.node) {
        if (NULL == m.node->schema || NULL == m.node->schema->name || NULL == m.node->schema->module || NULL == m.node->schema->module->name) {
            SR_LOG_ERR_MSG("Missing schema information");
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
    }

    if (NULL != value){
        /* if the list is being created value is NULL*/
        rc = sr_val_to_str(value, m.schema_node, &new_value);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Copy new value to string failed");
            goto cleanup;
        }
    } else if ((LYS_LEAF | LYS_LEAFLIST) & m.schema_node->nodetype) {
        struct lys_node_leaf *l_sch = (struct lys_node_leaf *) m.schema_node;
        if (LY_TYPE_EMPTY != l_sch->type.base){
            SR_LOG_ERR("NULL value passed %s", xpath);
            rc = SR_ERR_INVAL_ARG;
            goto cleanup;
        }
    }

    /* module of the node to be created*/
    const struct lys_module *module = m.node != NULL ? m.node->schema->module : m.info->module;

    /* updating the value */
    if (XP_GET_NODE_COUNT(m.loc_id) == m.level && NULL != m.node) {
        /* leaf-list append at the end */
        if (LYS_LEAFLIST == m.node->schema->nodetype){
            if (NULL == sr_lyd_new_leaf(m.info, m.node->parent, module, m.node->schema->name, new_value)) {
                SR_LOG_ERR("Adding leaf-list item failed %s", xpath);
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
        }
        else if (LYS_LEAF == m.node->schema->nodetype){
            /* replacing existing key leaf is not allowed */
            bool is_key = false;
            rc = rp_dt_has_key(m.node->parent, m.node->schema->name, &is_key);
            if (SR_ERR_OK != rc){
                SR_LOG_ERR_MSG("Is key failed");
                goto cleanup;
            }
            if (is_key){
                SR_LOG_ERR("Value of the key can not be updated %s", xpath);
                rc = SR_ERR_INVAL_ARG;
                goto cleanup;
            }
            /* leaf - replace existing */
            if (NULL == sr_lyd_new_leaf(m.info, m.node->parent, module, m.node->schema->name, new_value)) {
                SR_LOG_ERR("Replacing existing leaf failed %s", xpath);
                rc = ly_errno == LY_EINVAL ? SR_ERR_INVAL_ARG : SR_ERR_INTERNAL;
                goto cleanup;
            }
            sr_lyd_unlink(m.info, m.node);
            lyd_free(m.node);
        }
        else if (LYS_CONTAINER == m.node->schema->nodetype){
            /* setting existing container - do nothing */
            goto cleanup;
        } else if (LYS_LIST == m.node->schema->nodetype) {
            /* check if the to be set match has keys specified */
            if (XP_GET_KEY_COUNT(m.loc_id, m.level - 1) == 0) {
                /* Set item for list can not be called without keys */
                SR_LOG_ERR("Can not create list without keys %s", xpath);
                rc = SR_ERR_INVAL_ARG;
            }
            goto cleanup;
        }
    }

    node = m.node;
    /* create all preceding nodes*/
    for (size_t n = m.level; n < XP_GET_NODE_COUNT(m.loc_id); n++) {
        node_name = XP_CPY_TOKEN(m.loc_id, XP_GET_NODE_TOKEN(m.loc_id, n));
        if (XP_HAS_NODE_NS(m.loc_id, n) && !XP_EQ_NODE_NS(m.loc_id, n, module->name)) {
            module_name = XP_CPY_NODE_NS(m.loc_id, n);
            if (NULL == module_name) {
                SR_LOG_ERR_MSG("Copy of module name failed");
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            rc = dm_get_module(dm_ctx, module_name, NULL, &module);
            if (SR_ERR_OK != rc) {
                goto cleanup;
            }
            free(module_name);
            module_name = NULL;
        }

        /* check whether node is a last node (leaf, leaflist, presence container) in xpath */
        if (XP_GET_NODE_COUNT(m.loc_id) == (n + 1) && 0 == XP_GET_KEY_COUNT(m.loc_id, n)) {
            if (LYS_CONTAINER == m.schema_node->nodetype && NULL != ((struct lys_node_container *) m.schema_node)->presence) {
                /* presence container */
                node = sr_lyd_new(m.info, node, module, node_name);
            } else if (LYS_LEAF == m.schema_node->nodetype || LYS_LEAFLIST == m.schema_node->nodetype) {
                bool is_key = false;
                rc = rp_dt_has_key(node, node_name, &is_key);
                if (SR_ERR_OK != rc) {
                    SR_LOG_ERR_MSG("Is key failed");
                    goto cleanup;
                }
                if (is_key) {
                    SR_LOG_ERR("Value of the key can not be set %s", xpath);
                    rc = SR_ERR_INVAL_ARG;
                    goto cleanup;
                }
                node = sr_lyd_new_leaf(m.info, node, module, node_name, new_value);
            } else {
                SR_LOG_ERR_MSG("Request to create unsupported node type (non-presence container, list without keys ...)");
                rc = SR_ERR_INVAL_ARG;
                goto cleanup;
            }

            if (NULL == node) {
                SR_LOG_ERR("Creating new leaf failed %s", xpath);
                rc = ly_errno == LY_EINVAL ? SR_ERR_INVAL_ARG : SR_ERR_INTERNAL;
                goto cleanup;
            }

        } else {
            /* create container or list */
            node = sr_lyd_new(m.info, node, module, node_name);
            if (NULL == node) {
                SR_LOG_ERR("Creating container or list failed %s", xpath);
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            rc = rp_dt_create_keys(&m, node, n);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Creating keys failed %s", xpath);
                goto cleanup;
            }
        }
        if (NULL == created) {
            created = node;
        }
        free(node_name);
        node_name = NULL;
    }
cleanup:

    /* mark to session copy that some change has been made */
    if (NULL != m.info){
        m.info->modified = SR_ERR_OK == rc ? true : m.info->modified;
    }
    xp_free_loc_id(m.loc_id);
    free(new_value);
    free(node_name);
    if (SR_ERR_OK != rc && NULL != created) {
        sr_lyd_unlink(m.info, created);
        lyd_free(created);
    }
    return rc;
}

int
rp_dt_move_list(dm_ctx_t *dm_ctx, dm_session_t *session, const char *xpath, sr_move_direction_t direction)
{
    CHECK_NULL_ARG3(dm_ctx, session, xpath);
    int rc = SR_ERR_OK;
    rp_dt_match_t match = {0,};

    rc = rp_dt_find_deepest_match_wrapper(dm_ctx, session, xpath, &match);
    if (SR_ERR_NOT_FOUND == rc) {
        SR_LOG_ERR("List not found %s", xpath);
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    } else if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Find deepest match failed %s", xpath);
        goto cleanup;
    }

    /* check if match is complete */
    if (XP_GET_NODE_COUNT(match.loc_id) != match.level) {
        SR_LOG_ERR("List not found %s", xpath);
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    if (LYS_LIST != match.schema_node->nodetype || (!(LYS_USERORDERED & match.schema_node->flags))) {
        SR_LOG_ERR ("Xpath %s does not identify the user ordered list", xpath);
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    struct lyd_node *sibling = NULL;
    rc = rp_dt_find_closest_sibling_by_name(match.info, match.node, direction, &sibling);
    if (SR_ERR_NOT_FOUND == rc) {
        rc = SR_ERR_OK;
        goto cleanup;
    }
    else if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Find the closest sibling failed");
        goto cleanup;
    }

    if (SR_MOVE_UP == direction) {
        rc = sr_lyd_insert_before(match.info, sibling, match.node);
    } else {
        rc = sr_lyd_insert_after(match.info, sibling, match.node);
    }

    if (0 != rc) {
        SR_LOG_ERR_MSG("Moving of the node failed");
    }

cleanup:
    if (NULL != match.info){
        match.info->modified = SR_ERR_OK == rc ? true : match.info->modified;
    }
    xp_free_loc_id(match.loc_id);
    return rc;
}
