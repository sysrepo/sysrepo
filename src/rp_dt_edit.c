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

#include <unistd.h>

#include "rp_dt_edit.h"
#include "rp_dt_lookup.h"
#include "rp_dt_xpath.h"
#include "sysrepo.h"
#include "sr_common.h"
#include "xpath_processor.h"

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

int
rp_dt_delete_item(dm_ctx_t *dm_ctx, dm_session_t *session, const sr_datastore_t datastore, const char *xpath, const sr_edit_flag_t options)
{
    CHECK_NULL_ARG3(dm_ctx, session, xpath);

    int rc = SR_ERR_INVAL_ARG;
    xp_loc_id_t *l = NULL;
    struct lyd_node *data_tree = NULL;
    struct lyd_node *node = NULL;
    struct lyd_node *parent = NULL;
    size_t level = 0;
    char *data_tree_name = NULL;

    rc = xp_char_to_loc_id(xpath, &l);

    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Converting xpath '%s' to loc_id failed.", xpath);
        return rc;
    }

    rc = rp_dt_validate_node_xpath(dm_ctx, l, NULL);
    if (SR_ERR_OK != rc){
        SR_LOG_ERR("Validation of loc_id failed %s", l->xpath);
        goto cleanup;
    }

    if (!XP_HAS_NODE_NS(l, 0)) {
        SR_LOG_ERR("Provided xpath's root doesn't contain a namespace '%s' ", xpath);
        goto cleanup;
    }

    data_tree_name = XP_CPY_NODE_NS(l, 0);
    if (NULL == data_tree_name) {
        SR_LOG_ERR("Copying module name failed for xpath '%s'", xpath);
        goto cleanup;
    }

    // TODO use data store argument

    dm_data_info_t *info = NULL;
    rc = dm_get_data_info(dm_ctx, session, data_tree_name, &info);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Getting data tree failed for xpath '%s'", xpath);
        goto cleanup;
    }
    data_tree = info->node;

    rc = rp_dt_find_deepest_match(data_tree, l, true, &level, &node);
    if (SR_ERR_NOT_FOUND == rc) {
        if (options & SR_EDIT_STRICT) {
            SR_LOG_ERR("No item exists '%s' deleted with strict opt", l->xpath);
            rc = SR_ERR_INVAL_ARG;
            goto cleanup;
        }
        rc = SR_ERR_OK;
        info->modified = true;
        goto cleanup;
    } else if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Find deepest match failed %s", l->xpath);
        goto cleanup;
    }

    /* check if match is complete */
    if (XP_GET_NODE_COUNT(l) != level) {
        if (options & SR_EDIT_STRICT) {
            SR_LOG_ERR("No item exists '%s' deleted with strict opt", l->xpath);
            rc = SR_ERR_INVAL_ARG;
            goto cleanup;
        }
        info->modified = true;
        rc = SR_ERR_OK;
        goto cleanup;
    }


    if (NULL == node->schema || NULL == node->schema->name) {
        SR_LOG_ERR_MSG("Missing schema information");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* save parent to delete empty containers */
    parent = node->parent;

    /* perform delete according to the node type */
    if (node->schema->nodetype == LYS_CONTAINER) {
        if (options & SR_EDIT_NON_RECURSIVE) {
            SR_LOG_ERR("Item for xpath %s is container deleted with non recursive opt", l->xpath);
            rc = SR_ERR_INVAL_ARG;
            goto cleanup;
        }
        //TODO log to operation queue
        rc = sr_lyd_unlink(info, node);
        if (0 != rc) {
            SR_LOG_ERR("Unlinking of the node %s failed", l->xpath);
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
        sr_free_datatree(node);
    } else if (node->schema->nodetype == LYS_LEAF) {
        bool is_key = false;
        rc = rp_dt_has_key(node->parent, node->schema->name, &is_key);
        if (SR_ERR_OK != rc){
            SR_LOG_ERR_MSG("Has key failed");
            goto cleanup;
        }
        if (is_key){
            SR_LOG_ERR("Key leaf can not be delete delete the list instead %s", l->xpath);
            rc = SR_ERR_INVAL_ARG;
            goto cleanup;
        }
        //TODO log to operation queue
        rc = sr_lyd_unlink(info, node);
        if (0 != rc) {
            SR_LOG_ERR("Unlinking of the node %s failed", l->xpath);
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
        lyd_free(node);
    } else if (node->schema->nodetype == LYS_LEAFLIST) {
        struct lyd_node **nodes = NULL;
        size_t count = 0;
        /* find all leaf-list records */
        rc = rp_dt_get_siblings_node_by_name(node, node->schema->name, &nodes, &count);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Get sibling by name failed for xpath %s ", l->xpath);
            goto cleanup;
        }

        /* delete leaf-list nodes */
        for (size_t i = 0; i < count; i++) {
            //TODO log to operation queue
            rc = sr_lyd_unlink(info, nodes[i]);
            if (0 != rc) {
                SR_LOG_ERR("Unlinking of the node %s failed", l->xpath);
                free(nodes);
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            lyd_free(nodes[i]);
        }
        free(nodes);
    } else if (node->schema->nodetype == LYS_LIST) {
        size_t last_node = XP_GET_NODE_COUNT(l) - 1;
        if (options & SR_EDIT_NON_RECURSIVE) {
            /* count children */
            struct lyd_node *child = node->child;
            size_t child_cnt = 0;
            while (NULL != child){
                child = child->next;
                child_cnt++;
            }
            if (XP_GET_KEY_COUNT(l, last_node) != child_cnt){
                SR_LOG_ERR("Item for xpath %s is non empty list. It can not be deleted with non recursive opt", l->xpath);
                rc = SR_ERR_INVAL_ARG;
                goto cleanup;
            }
        }
        if (0 != XP_GET_KEY_COUNT(l, last_node)) {
            /* delete list instance */
            rc = sr_lyd_unlink(info, node);
            if (0 != rc) {
                SR_LOG_ERR("Unlinking of the node %s failed", l->xpath);
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            sr_free_datatree(node);
        } else {
            /* delete all instances */
            struct lyd_node **nodes = NULL;
            size_t count = 0;
            /* find all list instances */
            rc = rp_dt_get_siblings_node_by_name(node, node->schema->name, &nodes, &count);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Get sibling by name failed for xpath %s ", l->xpath);
                goto cleanup;
            }

            /* delete list nodes*/
            for (size_t i = 0; i < count; i++) {
                //TODO log to operation queue
                rc = sr_lyd_unlink(info, nodes[i]);
                if (0 != rc) {
                    SR_LOG_ERR("Unlinking of the node %s failed", l->xpath);
                    free(nodes);
                    rc = SR_ERR_INTERNAL;
                    goto cleanup;
                }
                sr_free_datatree(nodes[i]);
            }
            free(nodes);
        }
    }

    /* delete all empty parent containers */
    node = parent;
    while (NULL != node){
        if (NULL == node->child && LYS_CONTAINER == node->schema->nodetype){
            parent = node->parent;
            sr_lyd_unlink(info, node);
            lyd_free(node);
            node = parent;
        }
        else{
            break;
        }
    }

    /* mark to session copy that some change has been made */
    info->modified = true;
cleanup:
    xp_free_loc_id(l);
    free(data_tree_name);
    return rc;
}

int
rp_dt_set_item(dm_ctx_t *dm_ctx, dm_session_t *session, const sr_datastore_t datastore, const char *xpath, const sr_edit_flag_t options, const sr_val_t *value)
{
    CHECK_NULL_ARG3(dm_ctx, session, xpath);
    /* value can be NULL if the list is created */

    int rc = SR_ERR_INVAL_ARG;
    struct lyd_node *data_tree = NULL;
    struct lyd_node *match = NULL;
    struct lyd_node *node = NULL;
    dm_data_info_t *info = NULL;
    struct lys_node *schema_node = NULL;

    /* to be freed during cleanup */
    xp_loc_id_t *l = NULL;
    struct lyd_node *created = NULL;
    size_t level = 0;
    char *data_tree_name = NULL;
    char *new_value = NULL;
    char *key_name = NULL;
    char *key_value = NULL;
    char *node_name = NULL;
    char *module_name = NULL;

    rc = xp_char_to_loc_id(xpath, &l);

    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Converting xpath '%s' to loc_id failed.", xpath);
        return rc;
    }

    rc = rp_dt_validate_node_xpath(dm_ctx, l, &schema_node);
    if (SR_ERR_OK != rc){
        SR_LOG_ERR("Requested node is not valid %s", xpath);
        goto cleanup;
    }

    if (!XP_HAS_NODE_NS(l, 0)) {
        SR_LOG_ERR("Provided xpath's root doesn't contain a namespace '%s' ", xpath);
        goto cleanup;
    }

    data_tree_name = XP_CPY_NODE_NS(l, 0);
    if (NULL == data_tree_name) {
        SR_LOG_ERR("Copying module name failed for xpath '%s'", xpath);
        goto cleanup;
    }

    // TODO use data store argument

    rc = dm_get_data_info(dm_ctx, session, data_tree_name, &info);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Getting data tree failed for xpath '%s'", xpath);
        goto cleanup;
    }
    data_tree = info->node;

    rc = rp_dt_find_deepest_match(data_tree, l, true, &level, &match);
    if (SR_ERR_NOT_FOUND == rc) {
        if (XP_GET_NODE_COUNT(l) != 1 && options & SR_EDIT_NON_RECURSIVE) {
            SR_LOG_ERR("A preceding node is missing '%s' create it or omit the non recursive option", xpath);
            rc = SR_ERR_INVAL_ARG;
            goto cleanup;
        }
    } else if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Find deepest match failed %s", xpath);
        goto cleanup;
    }

    /* check if match is complete */
    if (XP_GET_NODE_COUNT(l) != level) {
        if (XP_GET_NODE_COUNT(l) != (level + 1)) {
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

    if (NULL != match) {
        if (NULL == match->schema || NULL == match->schema->name || NULL == match->schema->module || NULL == match->schema->module->name) {
            SR_LOG_ERR_MSG("Missing schema information");
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
    }

    if (NULL != value){
        /* if the list is being created value is NULL*/
        rc = sr_val_to_str(value, &new_value);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Copy new value to string failed");
            goto cleanup;
        }
    }

    /* module of the node to be created*/
    const struct lys_module *module = match != NULL ? match->schema->module : info->module;

    /* updating the value */
    if (XP_GET_NODE_COUNT(l) == level && NULL != match) {
        /* leaf-list append at the end */
        if (LYS_LEAFLIST == match->schema->nodetype){
            if (NULL == sr_lyd_new_leaf(info, match->parent, module, match->schema->name, new_value)) {
                SR_LOG_ERR("Adding leaf-list item failed %s", xpath);
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
        }
        else if (LYS_LEAF == match->schema->nodetype){
            /* replacing existing key leaf is not allowed */
            bool is_key = false;
            rc = rp_dt_has_key(match->parent, match->schema->name, &is_key);
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
            if (NULL == sr_lyd_new_leaf(info, match->parent, module, match->schema->name, new_value)) {
                SR_LOG_ERR("Replacing existing leaf failed %s", l->xpath);
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            sr_lyd_unlink(info, match);
            lyd_free(match);
        }
        else if (LYS_CONTAINER == match->schema->nodetype){
            /* setting existing container - do nothing */
            goto cleanup;
        }
        else if (LYS_LIST == match->schema->nodetype){
            /* check if the set request match has keys set */
            if (XP_GET_KEY_COUNT(l, level-1) == 0){
                /* Set item for list can not be called without keys */
                SR_LOG_ERR("Can not create list without keys %s", l->xpath);
                rc = SR_ERR_INVAL_ARG;
            }
            goto cleanup;
        }
    }

    node = match;
    /* create all preceding nodes*/
    for (size_t n = level; n < XP_GET_NODE_COUNT(l); n++) {
        node_name = XP_CPY_TOKEN(l, XP_GET_NODE_TOKEN(l, n));
        if (XP_HAS_NODE_NS(l, n) && !XP_CMP_NODE_NS(l, n, module->name)) {
            module_name = XP_CPY_NODE_NS(l, n);
            if (NULL == module_name) {
                SR_LOG_ERR_MSG("Copy of module name failed");
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            rc = dm_get_module(dm_ctx, module_name, NULL, &module);
            if (SR_ERR_OK == rc) {
                goto cleanup;
            }
            free(module_name);
            module_name = NULL;
        }

        /* check whether node is a last node (leaf, leaflist, presence container) in xpath */
        if (XP_GET_NODE_COUNT(l) == (n + 1) && 0 == XP_GET_KEY_COUNT(l,n)) {
            bool is_key = false;
            rc = rp_dt_has_key(node, node_name, &is_key);
            if (SR_ERR_OK != rc){
                SR_LOG_ERR_MSG("Is key failed");
                goto cleanup;
            }
            if (is_key){
                SR_LOG_ERR("Value of the key can not be set %s", xpath);
                rc = SR_ERR_INVAL_ARG;
                goto cleanup;
            }

            if (LYS_CONTAINER == schema_node->nodetype && NULL != ((struct lys_node_container *) schema_node)->presence ){
                /* presence container */
                node = sr_lyd_new(info, node, module, node_name);
            }
            else if (LYS_LEAF == schema_node->nodetype || LYS_LEAFLIST == schema_node->nodetype){
                node = sr_lyd_new_leaf(info, node, module, node_name, new_value);
            }
            else {
                SR_LOG_ERR_MSG("Request to create unsupported node type (non-presence container, list without keys ...)");
                rc = SR_ERR_INVAL_ARG;
                goto cleanup;
            }

            if (NULL == node) {
                SR_LOG_ERR("Creating new leaf failed %s", xpath);
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }

        } else {
            size_t key_count = XP_GET_KEY_COUNT(l, n);
            /* create container or list */
            node = sr_lyd_new(info, node, module, node_name);
            if (NULL == node) {
                SR_LOG_ERR("Creating container or list failed %s", xpath);
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            if (key_count != 0) {
                for (size_t k = 0; k < key_count; k++) {
                    key_name = XP_CPY_KEY_NAME(l, n, k);
                    key_value = XP_CPY_KEY_VALUE(l, n, k);
                    if (NULL == key_name || NULL == key_value) {
                        SR_LOG_ERR("Copy of key name or key value failed %s", xpath);
                        rc = SR_ERR_INTERNAL;
                        goto cleanup;
                    }

                    if (NULL == sr_lyd_new_leaf(info, node, module, key_name, key_value)) {
                        SR_LOG_ERR("Adding key leaf failed %s", xpath);
                        rc = SR_ERR_INTERNAL;
                        goto cleanup;
                    }

                    free(key_name);
                    free(key_value);
                    key_name = NULL;
                    key_value = NULL;
                }
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
    if (NULL != info){
        info->modified = SR_ERR_OK == rc ? true : info->modified;
    }
    xp_free_loc_id(l);
    free(data_tree_name);
    free(new_value);
    free(node_name);
    free(key_value);
    free(key_name);
    if (SR_ERR_OK != rc && NULL != created) {
        sr_lyd_unlink(info, created);
        lyd_free(created);
    }
    return rc;
}
