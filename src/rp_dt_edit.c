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
#include "access_control.h"
#include "xpath_processor.h"
#include <pthread.h>
#include <libyang/libyang.h>


/**
 * @brief structure filled by ::rp_dt_find_deepest_match_wrapper.
 * It includes resources for further edit request processing.
 */
typedef struct rp_dt_match_s {
    struct lys_node *schema_node;   /**< Matched schema node */
    dm_data_info_t *info;           /**< Data info structure for the model pointed by loc_id */

    size_t level;                   /**< Depth of the node that has been matched */
    struct lyd_node *node;          /**< Deepest match */
}rp_dt_match_t;

/**
 * @brief Fills the rp_dt_match_t structure. Converts xpath to location id, validates xpath,
 * and calls ::rp_dt_find_deepest_match. If the xpath identifies whole module matching
 * is not done only match->info is set.
 * @param [in] ctx
 * @param [in] session
 * @param [in] loc_id
 * @param [in] match
 * @return Error code (SR_ERR_OK on success), SR_ERR_NOT_FOUND, SR_ERR_UNKNOWN_MODEL, SR_ERR_BAD_ELEMENT
 */
static int
rp_dt_find_deepest_match_wrapper(dm_ctx_t *ctx, dm_session_t *session, const xp_loc_id_t *loc_id, rp_dt_match_t *match)
{
    CHECK_NULL_ARG4(ctx, session, loc_id, loc_id->xpath);
    const struct lys_module *module = NULL;

    int rc = rp_dt_validate_node_xpath(ctx, session, loc_id, &module, &match->schema_node);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Requested node is not valid %s", loc_id->xpath);
        goto cleanup;
    }

    rc = dm_get_data_info(ctx, session, module->name, &match->info);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Getting data tree failed for xpath '%s'", loc_id->xpath);
        goto cleanup;
    }

    if (XP_IS_MODULE_XPATH(loc_id)){
        /* do not match particular node if the xpath identifies the module */
        if (NULL == match->info->node){
            rc = SR_ERR_NOT_FOUND;
        }
        goto cleanup;
    }

    rc = rp_dt_find_deepest_match(match->info->node, loc_id, true, dm_is_running_ds_session(session), &match->level, &match->node);

cleanup:

    return rc;
}

/**
 * @brief Checks if the node has a key with the name and sets res.
 * @param [in] node
 * @param [in] name
 * @param [out] res
 * @return Error code (SR_ERR_OK on success)
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
 * @param [in] match
 * @param [in] loc_id
 * @param [in] parent
 * @param [in] level
 * @return Error code (SR_ERR_OK on success)
 */
static int
rp_dt_create_keys(rp_dt_match_t *match, const xp_loc_id_t *loc_id, struct lyd_node *parent, size_t level)
{
    CHECK_NULL_ARG3(match, parent, loc_id);
    size_t key_count = XP_GET_KEY_COUNT(loc_id, level);
    char *key_name = NULL;
    char *key_value = NULL;
    if (key_count != 0) {
        for (size_t k = 0; k < key_count; k++) {
            key_name = XP_CPY_KEY_NAME(loc_id, level, k);
            key_value = XP_CPY_KEY_VALUE(loc_id, level, k);
            if (NULL == key_name || NULL == key_value) {
                SR_LOG_ERR("Copy of key name or key value failed %s", loc_id->xpath);
                goto cleanup;
            }
            if (NULL == sr_lyd_new_leaf(match->info, parent, parent->schema->module, key_name, key_value)) {
                SR_LOG_ERR("Adding key leaf failed %s", loc_id->xpath);
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

/**
 * @brief Looks up the first sibling in specified direction with the name same as provide.
 * @param [in] info
 * @param [in] start_node
 * @param [in] direction
 * @param [out] sibling
 * @return Error code (SR_ERR_OK on success) SR_ERR_NOT_FOUND
 */
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
rp_dt_delete_item(dm_ctx_t *dm_ctx, dm_session_t *session, const xp_loc_id_t *loc_id, const sr_edit_flag_t options)
{
    CHECK_NULL_ARG4(dm_ctx, session, loc_id, loc_id->xpath);

    int rc = SR_ERR_INVAL_ARG;
    struct lyd_node *node = NULL;
    struct lyd_node *parent = NULL;
    char *data_tree_name = NULL;
    rp_dt_match_t match = {0,};

    rc = rp_dt_find_deepest_match_wrapper(dm_ctx, session, loc_id, &match);
    if (SR_ERR_NOT_FOUND == rc) {
        if (options & SR_EDIT_STRICT) {
            SR_LOG_ERR("No item exists '%s' deleted with strict opt", loc_id->xpath);
            rc = dm_report_error(session, NULL, strdup(loc_id->xpath), SR_ERR_DATA_MISSING);
            goto cleanup;
        }
        rc = SR_ERR_OK;
        goto cleanup;
    } else if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Find deepest match failed %s", loc_id->xpath);
        goto cleanup;
    }

    if (XP_IS_MODULE_XPATH(loc_id)) {
        if ((options & SR_EDIT_NON_RECURSIVE)) {
            SR_LOG_ERR("Delete for module xpath '%s' can not be called with non recursive", loc_id->xpath);
            rc = dm_report_error(session, "Delete whole module can not be performed with non recursive flag", strdup(loc_id->xpath), SR_ERR_DATA_EXISTS);
            goto cleanup;
        }

        struct lyd_node **nodes = NULL;
        size_t count = 0;
        /* find all top level nodes records */
        rc = rp_dt_get_all_siblings(match.info->node, dm_is_running_ds_session(session), &nodes, &count);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Get all siblings failed for xpath %s ", loc_id->xpath);
            goto cleanup;
        }

        /* delete all nodes */
        for (size_t i = 0; i < count; i++) {
            rc = sr_lyd_unlink(match.info, nodes[i]);
            if (0 != rc) {
                SR_LOG_ERR("Unlinking of the node %s failed", loc_id->xpath);
                free(nodes);
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            lyd_free(nodes[i]);
        }
        free(nodes);
        goto cleanup;
    }

    /* check if match is complete */
    if (XP_GET_NODE_COUNT(loc_id) != match.level) {
        if (options & SR_EDIT_STRICT) {
            SR_LOG_ERR("No item exists '%s' deleted with strict opt", loc_id->xpath);
            rc = dm_report_error(session, NULL, strdup(loc_id->xpath), SR_ERR_DATA_MISSING);
            goto cleanup;
        }
        match.info->modified = true;
        rc = SR_ERR_OK;
        goto cleanup;
    }


    if (NULL == match.node || NULL == match.node->schema || NULL == match.node->schema->name) {
        SR_LOG_ERR_MSG("Missing schema information");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* save parent to delete empty containers */
    parent = match.node->parent;

    /* perform delete according to the node type */
    if (match.node->schema->nodetype == LYS_CONTAINER) {
        if (options & SR_EDIT_NON_RECURSIVE) {
            SR_LOG_ERR("Item for xpath %s is container deleted with non recursive opt", loc_id->xpath);
            rc = dm_report_error(session, "Node contains children node, can not be deleted with non recursive option", strdup(loc_id->xpath), SR_ERR_DATA_EXISTS);
            goto cleanup;
        }
        rc = sr_lyd_unlink(match.info, match.node);
        if (0 != rc) {
            SR_LOG_ERR("Unlinking of the node %s failed", loc_id->xpath);
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
            SR_LOG_ERR("Key leaf can not be delete delete the list instead %s", loc_id->xpath);
            rc = dm_report_error(session, "List key can not be deleted", strdup(loc_id->xpath), SR_ERR_INVAL_ARG);
            goto cleanup;
        }
        rc = sr_lyd_unlink(match.info, match.node);
        if (0 != rc) {
            SR_LOG_ERR("Unlinking of the node %s failed", loc_id->xpath);
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
            SR_LOG_ERR("Get sibling by name failed for xpath %s ", loc_id->xpath);
            goto cleanup;
        }

        /* delete leaf-list nodes */
        for (size_t i = 0; i < count; i++) {
            rc = sr_lyd_unlink(match.info, nodes[i]);
            if (0 != rc) {
                SR_LOG_ERR("Unlinking of the node %s failed", loc_id->xpath);
                free(nodes);
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            lyd_free(nodes[i]);
        }
        free(nodes);
    } else if (match.node->schema->nodetype == LYS_LIST) {
        size_t last_node = XP_GET_NODE_COUNT(loc_id) - 1;
        if (options & SR_EDIT_NON_RECURSIVE) {
            /* count children */
            struct lyd_node *child = match.node->child;
            size_t child_cnt = 0;
            while (NULL != child) {
                child = child->next;
                child_cnt++;
            }
            if (XP_GET_KEY_COUNT(loc_id, last_node) != child_cnt) {
                SR_LOG_ERR("Item for xpath %s is non empty list. It can not be deleted with non recursive opt", loc_id->xpath);
                rc = dm_report_error(session, "Node contains children node, can not be deleted with non recursive option", strdup(loc_id->xpath), SR_ERR_DATA_EXISTS);
                goto cleanup;
            }
        }
        if (0 != XP_GET_KEY_COUNT(loc_id, last_node)) {
            /* delete list instance */
            rc = sr_lyd_unlink(match.info, match.node);
            if (0 != rc) {
                SR_LOG_ERR("Unlinking of the node %s failed", loc_id->xpath);
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
                SR_LOG_ERR("Get sibling by name failed for xpath %s ", loc_id->xpath);
                goto cleanup;
            }

            /* delete list nodes*/
            for (size_t i = 0; i < count; i++) {
                rc = sr_lyd_unlink(match.info, nodes[i]);
                if (0 != rc) {
                    SR_LOG_ERR("Unlinking of the node %s failed", loc_id->xpath);
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

cleanup:
    if (NULL != match.info) {
        /* mark to session copy that some change has been made */
        match.info->modified = SR_ERR_OK == rc ? true : match.info->modified;
    }
    free(data_tree_name);
    return rc;
}

int
rp_dt_set_item(dm_ctx_t *dm_ctx, dm_session_t *session, const xp_loc_id_t *loc_id, const sr_edit_flag_t options, const sr_val_t *value)
{
    CHECK_NULL_ARG4(dm_ctx, session, loc_id, loc_id->xpath);
    /* value can be NULL if the list is created */

    int rc = SR_ERR_INVAL_ARG;
    struct lyd_node *node = NULL;
    rp_dt_match_t m = {0,};

    /* to be freed during cleanup */
    struct lyd_node *created = NULL;
    char *new_value = NULL;
    char *node_name = NULL;
    char *module_name = NULL;

    rc = rp_dt_find_deepest_match_wrapper(dm_ctx, session, loc_id, &m);
    if (SR_ERR_NOT_FOUND == rc) {
        if (XP_GET_NODE_COUNT(loc_id) != 1 && (options & SR_EDIT_NON_RECURSIVE)) {
            SR_LOG_ERR("A preceding node is missing '%s' create it or omit the non recursive option", loc_id->xpath);
            rc = dm_report_error(session, "A preceding node is missing", XP_CPY_UP_TO_NODE(loc_id, 0), SR_ERR_DATA_MISSING);
            goto cleanup;
        } else if (NULL == m.info){
            SR_LOG_ERR_MSG("Data info has not been set");
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        } else {
            rc = SR_ERR_OK;
        }
    } else if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Find deepest match failed %s", loc_id->xpath);
        goto cleanup;
    }

    if (XP_IS_MODULE_XPATH(loc_id)) {
        SR_LOG_ERR("Module xpath %s can not be used wit set item operation", loc_id->xpath);
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }
    /* if the session is tied to running, check if the leaf is enabled*/
    if (dm_is_running_ds_session(session)) {
        if (!dm_is_enabled_check_recursively(m.schema_node)) {
            SR_LOG_ERR("Requested path '%s' is not enable in running data store", loc_id->xpath);
            rc = dm_report_error(session, "Requested path is not enable in running datastore", strdup(loc_id->xpath), SR_ERR_INVAL_ARG);
            goto cleanup;
        }
    }

    /* check if match is complete */
    if (XP_GET_NODE_COUNT(loc_id) != m.level) {
        if (XP_GET_NODE_COUNT(loc_id) != (m.level + 1)) {
            if (options & SR_EDIT_NON_RECURSIVE) {
                SR_LOG_ERR("A preceding item is missing '%s' create it or omit the non recursive option", loc_id->xpath);
                rc = dm_report_error(session, "A preceding node is missing", XP_CPY_UP_TO_NODE(loc_id, m.level-1), SR_ERR_DATA_MISSING);
                goto cleanup;
            }
        }
    } else if (options & SR_EDIT_STRICT) {
        SR_LOG_ERR("Item exists '%s' can not be created again with strict opt", loc_id->xpath);
        rc = dm_report_error(session, NULL, strdup(loc_id->xpath), SR_ERR_DATA_EXISTS);
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
            SR_LOG_ERR("NULL value passed %s", loc_id->xpath);
            rc = SR_ERR_INVAL_ARG;
            goto cleanup;
        }
    }

    /* module of the node to be created*/
    const struct lys_module *module = m.node != NULL ? m.node->schema->module : m.info->module;

    /* updating the value */
    if (XP_GET_NODE_COUNT(loc_id) == m.level && NULL != m.node) {
        /* leaf-list append at the end */
        if (LYS_LEAFLIST == m.node->schema->nodetype){
            if (NULL == sr_lyd_new_leaf(m.info, m.node->parent, module, m.node->schema->name, new_value)) {
                SR_LOG_ERR("Adding leaf-list item failed %s", loc_id->xpath);
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
                SR_LOG_ERR("Value of the key can not be updated %s", loc_id->xpath);
                rc = dm_report_error(session, "Value of the key node can not be update", strdup(loc_id->xpath), SR_ERR_INVAL_ARG);
                goto cleanup;
            }
            /* leaf - replace existing */
            if (NULL == sr_lyd_new_leaf(m.info, m.node->parent, module, m.node->schema->name, new_value)) {
                SR_LOG_ERR("Replacing existing leaf failed %s", loc_id->xpath);
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
            if (XP_GET_KEY_COUNT(loc_id, m.level - 1) == 0) {
                /* Set item for list can not be called without keys */
                SR_LOG_ERR("Can not create list without keys %s", loc_id->xpath);
                rc = SR_ERR_INVAL_ARG;
            }
            goto cleanup;
        }
    }

    node = m.node;
    /* create all preceding nodes*/
    for (size_t n = m.level; n < XP_GET_NODE_COUNT(loc_id); n++) {
        node_name = XP_CPY_TOKEN(loc_id, XP_GET_NODE_TOKEN(loc_id, n));
        if (XP_HAS_NODE_NS(loc_id, n) && !XP_EQ_NODE_NS(loc_id, n, module->name)) {
            module_name = XP_CPY_NODE_NS(loc_id, n);
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
        if (XP_GET_NODE_COUNT(loc_id) == (n + 1) && 0 == XP_GET_KEY_COUNT(loc_id, n)) {
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
                    SR_LOG_ERR("Value of the key can not be set %s", loc_id->xpath);
                    rc = dm_report_error(session, "Value of the key can not be set", XP_CPY_UP_TO_NODE(loc_id, n), SR_ERR_INVAL_ARG);
                    goto cleanup;
                }
                node = sr_lyd_new_leaf(m.info, node, module, node_name, new_value);
            } else {
                SR_LOG_ERR_MSG("Request to create unsupported node type (non-presence container, list without keys ...)");
                rc = SR_ERR_INVAL_ARG;
                goto cleanup;
            }

            if (NULL == node) {
                SR_LOG_ERR("Creating new leaf failed %s", loc_id->xpath);
                rc = ly_errno == LY_EINVAL ? SR_ERR_INVAL_ARG : SR_ERR_INTERNAL;
                goto cleanup;
            }

        } else {
            /* create container or list */
            node = sr_lyd_new(m.info, node, module, node_name);
            if (NULL == node) {
                SR_LOG_ERR("Creating container or list failed %s", loc_id->xpath);
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            rc = rp_dt_create_keys(&m, loc_id, node, n);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Creating keys failed %s", loc_id->xpath);
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
    free(new_value);
    free(node_name);
    if (SR_ERR_OK != rc && NULL != created) {
        sr_lyd_unlink(m.info, created);
        lyd_free(created);
    }
    return rc;
}

int
rp_dt_move_list(dm_ctx_t *dm_ctx, dm_session_t *session, const xp_loc_id_t *loc_id, sr_move_direction_t direction)
{
    CHECK_NULL_ARG4(dm_ctx, session, loc_id, loc_id->xpath);
    int rc = SR_ERR_OK;
    rp_dt_match_t match = {0,};

    rc = rp_dt_find_deepest_match_wrapper(dm_ctx, session, loc_id, &match);
    if (SR_ERR_NOT_FOUND == rc) {
        SR_LOG_ERR("List not found %s", loc_id->xpath);
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    } else if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Find deepest match failed %s", loc_id->xpath);
        goto cleanup;
    }

    if (XP_IS_MODULE_XPATH(loc_id)) {
        SR_LOG_ERR("Module xpath %s can not be used wit set item operation", loc_id->xpath);
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    /* check if match is complete */
    if (XP_GET_NODE_COUNT(loc_id) != match.level) {
        SR_LOG_ERR("List not found %s", loc_id->xpath);
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    if (LYS_LIST != match.schema_node->nodetype || (!(LYS_USERORDERED & match.schema_node->flags))) {
        SR_LOG_ERR ("Xpath %s does not identify the user ordered list", loc_id->xpath);
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    struct lyd_node *sibling = NULL;
    rc = rp_dt_find_closest_sibling_by_name(match.info, match.node, direction, &sibling);    if (SR_ERR_NOT_FOUND == rc) {
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
    return rc;
}

int
rp_dt_move_list_wrapper(rp_ctx_t *rp_ctx, rp_session_t *session, const char *xpath, sr_move_direction_t direction)
{
    CHECK_NULL_ARG5(rp_ctx, rp_ctx->dm_ctx, session, session->dm_session, xpath);

    int rc = SR_ERR_OK;
    xp_loc_id_t *loc_id = NULL;
    rc = xp_char_to_loc_id(xpath, &loc_id);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Converting xpath '%s' to loc_id failed.", xpath);
        return rc;
    }

    rc = ac_check_node_permissions(session->ac_session, loc_id, AC_OPER_READ_WRITE);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Access control check failed for xpath '%s'", xpath);
        xp_free_loc_id(loc_id);
        return rc;
    }

    rc = dm_add_operation(session->dm_session, direction == SR_MOVE_UP ? DM_MOVE_UP_OP: DM_MOVE_DOWN_OP ,loc_id, NULL, 0);
    if (SR_ERR_OK != rc){
        /* loc id is freed by dm_add_operation */
        SR_LOG_ERR_MSG("Adding operation to session op list failed");
        return rc;
    }

    rc = rp_dt_move_list(rp_ctx->dm_ctx, session->dm_session, loc_id, direction);
    if (SR_ERR_OK != rc){
        SR_LOG_ERR_MSG("List move failed");
        dm_remove_last_operation(session->dm_session);
    }
    return rc;

}

int
rp_dt_set_item_wrapper(rp_ctx_t *rp_ctx, rp_session_t *session, const char *xpath, sr_val_t *val, sr_edit_options_t opt)
{
    CHECK_NULL_ARG5(rp_ctx, rp_ctx->dm_ctx, session, session->dm_session, xpath);

    int rc = SR_ERR_OK;
    xp_loc_id_t *loc_id = NULL;
    rc = xp_char_to_loc_id(xpath, &loc_id);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Converting xpath '%s' to loc_id failed.", xpath);
        sr_free_val(val);
        return rc;
    }

    rc = ac_check_node_permissions(session->ac_session, loc_id, AC_OPER_READ_WRITE);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Access control check failed for xpath '%s'", xpath);
        xp_free_loc_id(loc_id);
        sr_free_val(val);
        return rc;
    }

    rc = dm_add_operation(session->dm_session, DM_SET_OP, loc_id, val, opt);
    if (SR_ERR_OK != rc){
        /* loc id and val is freed by dm_add_operation */
        SR_LOG_ERR_MSG("Adding operation to session op list failed");
        return rc;
    }

    rc = rp_dt_set_item(rp_ctx->dm_ctx, session->dm_session, loc_id, opt, val);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Set item failed");
        dm_remove_last_operation(session->dm_session);
    }
    return rc;
}

int
rp_dt_delete_item_wrapper(rp_ctx_t *rp_ctx, rp_session_t *session, const char *xpath, sr_edit_options_t opts)
{
    CHECK_NULL_ARG5(rp_ctx, rp_ctx->dm_ctx, session, session->dm_session, xpath);

    int rc = SR_ERR_OK;
    xp_loc_id_t *loc_id = NULL;
    rc = xp_char_to_loc_id(xpath, &loc_id);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Converting xpath '%s' to loc_id failed.", xpath);
        return rc;
    }

    rc = ac_check_node_permissions(session->ac_session, loc_id, AC_OPER_READ_WRITE);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Access control check failed for xpath '%s'", xpath);
        xp_free_loc_id(loc_id);
        return rc;
    }

    rc = dm_add_operation(session->dm_session, DM_DELETE_OP, loc_id, NULL, opts);
    if (SR_ERR_OK != rc){
        /* loc id is freed by dm_add_operation */
        SR_LOG_ERR_MSG("Adding operation to session op list failed");
        return rc;
    }

    rc = rp_dt_delete_item(rp_ctx->dm_ctx, session->dm_session, loc_id, opts);
    if (SR_ERR_OK != rc){
        SR_LOG_ERR_MSG("List move failed");
        dm_remove_last_operation(session->dm_session);
    }
    return rc;
}

/**
 * @brief Perform the list of provided operations on the session. Stops
 * on the first error, if continue on error is false. If the continue on error
 * is set to true, operation is marked with has_error flag.
 * @param [in] ctx
 * @param [in] session
 * @param [in] operations
 * @param [in] count
 * @param [in] continue_on_error flag denoting whether replay should be stopped on first error
 * @param [in] models_to_skip - set of model's name where the current modify timestamp
 * matches the timestamp of the session copy. Operation for this models skipped.
 * @return Error code (SR_ERR_OK on success)
 */
static int
rp_dt_replay_operations(dm_ctx_t *ctx, dm_session_t *session, dm_sess_op_t *operations, size_t count,
        bool continue_on_error, struct ly_set *models_to_skip)
{
    CHECK_NULL_ARG3(ctx, session, operations);
    int rc = SR_ERR_OK;
    bool err_occured = false; /* flag used in case of continue_on_err */

    for (size_t i = 0; i < count; i++) {
        dm_sess_op_t *op = &operations[i];
        if (op->has_error) {
            continue;
        }
        /* check if the operation should be skipped */
        bool match = false;
            for (unsigned int m = 0; m < models_to_skip->number; m++){
                if (0 == XP_CMP_FIRST_NS(op->loc_id, (char *) models_to_skip->set[m])){
                    SR_LOG_DBG("Skipping op for model %s", (char *) models_to_skip->set[m]);
                    match = true;
                    break;
                }
            }
        if (match){
            continue;
        }

        switch (op->op) {
        case DM_SET_OP:
            rc = rp_dt_set_item(ctx, session, op->loc_id, op->options, op->val);
            break;
        case DM_DELETE_OP:
            rc = rp_dt_delete_item(ctx, session, op->loc_id, op->options);
            break;
        case DM_MOVE_DOWN_OP:
            rc = rp_dt_move_list(ctx, session, op->loc_id, SR_MOVE_DOWN);
            break;
        case DM_MOVE_UP_OP:
            rc = rp_dt_move_list(ctx, session, op->loc_id, SR_MOVE_UP);
            break;
        }

        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Replay of operation %zu / %zu failed", i, count);
            if (!continue_on_error){
                return rc;
            } else {
                op->has_error = true;
                err_occured = true;
            }
        }
    }
    if (continue_on_error && err_occured){
        return SR_ERR_INTERNAL;
    } else{
        return rc;
    }
}

int
rp_dt_commit(rp_ctx_t *rp_ctx, rp_session_t *session, sr_error_info_t **errors, size_t *err_cnt)
{
    CHECK_NULL_ARG2(rp_ctx, session);
    int rc = SR_ERR_OK;
    dm_commit_context_t *commit_ctx = NULL;

    SR_LOG_DBG_MSG("Commit (1/6): process stared");

    //TODO send validate notifications

    /* YANG validation */
    rc = dm_validate_session_data_trees(rp_ctx->dm_ctx, session->dm_session, errors, err_cnt);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Data validation failed");
        return SR_ERR_VALIDATION_FAILED;
    }
    SR_LOG_DBG_MSG("Commit (2/6): validation succeeded");


    rc = dm_commit_prepare_context(rp_ctx->dm_ctx, session->dm_session, &commit_ctx);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("commit prepare context failed");
        return rc;
    } else if (0 == commit_ctx->modif_count) {
        SR_LOG_DBG_MSG("Commit: Finished - no model modified");
        dm_free_commit_context(rp_ctx->dm_ctx, commit_ctx);
        return SR_ERR_OK;
    }

    /* open all files */
    rc = dm_commit_load_modified_models(rp_ctx->dm_ctx, session->dm_session, commit_ctx);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Loading of modified models failed");
        goto cleanup;
    }
    SR_LOG_DBG_MSG("Commit (3/6): all modified models loaded successfully");

    /* replay operations */
    rc = rp_dt_replay_operations(rp_ctx->dm_ctx, commit_ctx->session, commit_ctx->operations,
            commit_ctx->oper_count, false, commit_ctx->up_to_date_models);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Replay of operations failed");
        goto cleanup;
    }
    SR_LOG_DBG_MSG("Commit (4/6): replay of operation succeeded");

    /* validate data trees after merge */
    rc = dm_validate_session_data_trees(rp_ctx->dm_ctx, commit_ctx->session, errors, err_cnt);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Validation after merging failed");
        rc = SR_ERR_VALIDATION_FAILED;
        goto cleanup;
    }
    SR_LOG_DBG_MSG("Commit (5/6): merged models validation succeeded");

    rc = dm_commit_write_files(session->dm_session, commit_ctx);

cleanup:
    dm_free_commit_context(rp_ctx->dm_ctx, commit_ctx);

    if (SR_ERR_OK == rc){
        /* discard changes in session in next get_data_tree call newly committed content will be loaded */
        rc = dm_discard_changes(rp_ctx->dm_ctx, session->dm_session);
        SR_LOG_DBG_MSG("Commit (6/6): finished successfully");
    }
    return rc;
}

static void
rp_dt_create_refresh_errors(const dm_sess_op_t *ops, size_t op_count, sr_error_info_t **errors, size_t *err_cnt)
{
    CHECK_NULL_ARG_VOID3(ops, errors, err_cnt);
    for (size_t i = 0; i < op_count; i++) {
        const dm_sess_op_t *op = &ops[i];
        if (!op->has_error) {
            continue;
        }
        sr_error_info_t *tmp_err = realloc(*errors, (*err_cnt +1)* sizeof (**errors));
        if (NULL == tmp_err) {
            SR_LOG_ERR_MSG("Memory allocation failed");
            return;
        }
        *errors = tmp_err;
        switch (op->op) {
            case DM_SET_OP:
                (*errors)[*err_cnt].message = strdup("SET operation can not be merged with current datastore state");
                break;
            case DM_DELETE_OP:
                (*errors)[*err_cnt].message = strdup("DELETE Operation can not be merged with current datastore state");
                break;
            case DM_MOVE_DOWN_OP:
            case DM_MOVE_UP_OP:
                (*errors)[*err_cnt].message = strdup("MOVE Operation can not be merged with current datastore state");
                break;
            default:
                (*errors)[*err_cnt].message = strdup("An operation can not be merged with current datastore state");
        }
        (*errors)[*err_cnt].path = strdup(op->loc_id->xpath);
        (*err_cnt)++;
    }
}

int
rp_dt_refresh_session(rp_ctx_t *rp_ctx, rp_session_t *session, sr_error_info_t **errors, size_t *err_cnt)
{
    CHECK_NULL_ARG2(rp_ctx, session);
    int rc = SR_ERR_OK;
    struct ly_set *up_to_date = NULL;
    dm_sess_op_t *ops = NULL;
    size_t op_count = 0;
    *err_cnt = 0;
    *errors = NULL;

    /* update models and retrieve list of data models-to be skipped in replay */
    rc = dm_update_session_data_trees(rp_ctx->dm_ctx, session->dm_session, &up_to_date);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Update of data trees failed");
        return rc;
    }

    dm_get_session_operations(session->dm_session, &ops, &op_count);

    if (0 == op_count) {
        SR_LOG_INF_MSG("No operation has been performed on this session so far");
        goto cleanup;
    }

    /* replay operations continue on error */
    rc = rp_dt_replay_operations(rp_ctx->dm_ctx, session->dm_session,
                ops, op_count, true, up_to_date);

    if (SR_ERR_OK != rc) {
        /* report errors for the ops that could not be performed */
        rp_dt_create_refresh_errors(ops, op_count, errors, err_cnt);
        /* remove operations that has an error */
        dm_remove_operations_with_error(session->dm_session);
        /* generate errors and remove ops with error */
        SR_LOG_ERR_MSG("Replay of some operations failed");
    }
    SR_LOG_DBG_MSG("End of session refresh");
cleanup:
    ly_set_free(up_to_date);
    return rc;
}
