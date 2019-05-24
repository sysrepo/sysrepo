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
#include "data_manager.h"
#include "sysrepo.h"
#include "sr_common.h"
#include "access_control.h"
#include <pthread.h>
#include <libyang/libyang.h>
#include <inttypes.h>
#include <time.h>

/**
 * @brief Checks if the schema node has a key node with the specified name
 * @param [in] node
 * @param [in] name
 * @param [out] res
 * @return Error code (SR_ERR_OK on success)
 */
static int
rp_dt_has_sch_key(const struct lys_node *node, const char *name, bool *res)
{
    CHECK_NULL_ARG2(name, res);
    if (NULL != node && LYS_LIST == node->nodetype) {
        struct lys_node_list *list = (struct lys_node_list *) node;
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
 * @brief Checks if the data node has a key with the name and sets res.
 * @param [in] node
 * @param [in] name
 * @param [out] res
 * @return Error code (SR_ERR_OK on success)
 */
static int
rp_dt_has_key(const struct lyd_node *node, const char *name, bool *res)
{
    CHECK_NULL_ARG2(name, res);

    if (NULL != node && NULL != node->schema && LYS_LIST == node->schema->nodetype) {
        return rp_dt_has_sch_key(node->schema, name, res);
    }
    *res = false;
    return SR_ERR_OK;
}

/**
 * @brief Checks whether node can be deleted. Node can not be delete if it is a list key
 * and the list content is not deleted.
 */
static int
rp_dt_check_node_deletion(struct lyd_node *node, struct ly_set *delete_nodes, bool *can_be_removed)
{
    CHECK_NULL_ARG3(node, delete_nodes, can_be_removed);
    int rc = SR_ERR_OK;
    if (NULL != node->schema &&
            LYS_LEAF == node->schema->nodetype) {
        bool is_key = false;
        rc = rp_dt_has_key(node->parent, node->schema->name, &is_key);
        CHECK_RC_MSG_RETURN(rc, "Has key failed");
        if (is_key) {
            //check if the whole list is to be deleted
            struct lyd_node *iter = NULL;

            LY_TREE_FOR(node->parent->child, iter)
            {
                bool found = false;
                for (size_t j = 0; j < delete_nodes->number; j++) {
                    if (iter == delete_nodes->set.d[j]) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    *can_be_removed = false;
                    return rc;
                }
            }

        }
    }
    *can_be_removed = true;
    return rc;
}

/**
 * @brief Checks whether all list's children are key nodes. In that case it can be remove
 * even with non-recursive flag.
 */
bool
rp_dt_has_only_keys(const struct lyd_node *node)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_ARG_NORET2(rc, node, node->schema);
    if (SR_ERR_OK != rc) {
        return false;
    }

    if (LYS_LIST == node->schema->nodetype) {
        struct lyd_node *child = node->child;
        struct lys_node_list *list = (struct lys_node_list *) node->schema;
        size_t child_cnt = 0;
        while (NULL != child) {
            child = child->next;
            child_cnt++;
        }
        return child_cnt == list->keys_size;
    }
    return false;
}
/**
 * @brief Tests whether the set of nodes contains a non default node
 */
static bool
rp_dt_contains_non_default_node(struct ly_set *nodes)
{
    if (NULL == nodes) {
        return false;
    }
    for (int i = 0; i < nodes->number; i++) {
        if ((LYS_LEAFLIST | LYS_LIST) & nodes->set.d[i]->schema->nodetype ||
            (LYS_CONTAINER == nodes->set.d[i]->schema->nodetype &&
                 NULL != ((struct lys_node_container *) nodes->set.d[i]->schema)->presence) ||
            (LYS_LEAF == nodes->set.d[i]->schema->nodetype && !nodes->set.d[i]->dflt) ||
            (LYS_ANYXML == nodes->set.d[i]->schema->nodetype && !nodes->set.d[i]->dflt) ||
            (LYS_ANYDATA == nodes->set.d[i]->schema->nodetype && !nodes->set.d[i]->dflt)) {
            return true;
        } else if (LYS_CONTAINER == nodes->set.d[i]->schema->nodetype) {
            struct lyd_node *next = NULL, *iter = NULL;
            LY_TREE_DFS_BEGIN(nodes->set.d[i], next, iter)
            {
                if ((LYS_LEAFLIST | LYS_LIST) & iter->schema->nodetype ||
                    (LYS_LEAF == iter->schema->nodetype && !iter->dflt) ||
                    (LYS_CONTAINER == iter->schema->nodetype &&
                        NULL != ((struct lys_node_container *) iter->schema)->presence)) {
                    return true;
                }
                LYD_TREE_DFS_END(nodes->set.d[i], next, iter);
            }
        }
    }
    return false;
}

int
rp_dt_delete_item(dm_ctx_t *dm_ctx, dm_session_t *session, const char *xpath, const sr_edit_flag_t options, bool is_state)
{
    CHECK_NULL_ARG3(dm_ctx, session, xpath);

    int rc = SR_ERR_INVAL_ARG;
    dm_data_info_t *info = NULL;
    struct ly_set *nodes = NULL;
    struct ly_set *parents = NULL;
    char *module_name = NULL;
    int ret = 0;

    rc = sr_copy_first_ns(xpath, &module_name);
    CHECK_RC_LOG_RETURN(rc, "Copying module name failed for xpath '%s'", xpath);

    rc = dm_get_data_info(dm_ctx, session, module_name, &info);
    free(module_name);
    CHECK_RC_LOG_RETURN(rc, "Getting data tree failed for xpath '%s'", xpath);

    /* find nodes nodes to be deleted */
    rc = rp_dt_find_nodes(dm_ctx, info->node, xpath, dm_is_running_ds_session(session), &nodes);
    if (SR_ERR_NOT_FOUND == rc) {
        rc = rp_dt_validate_node_xpath(dm_ctx, session, xpath, NULL, NULL);
        if (SR_ERR_OK != rc) {
            SR_LOG_WRN("Validation of xpath %s was not successful", xpath);
        }

        if (SR_EDIT_STRICT & options) {
            SR_LOG_ERR("No nodes to be deleted with strict option %s", xpath);
            return dm_report_error(session, NULL, xpath, SR_ERR_DATA_MISSING);
        } else {
            return SR_ERR_OK;
        }
    } else if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Find nodes failed %s", xpath);
        return rc;
    }

    /* if strict option is set, at least one non default node must be deleted */
    if (SR_EDIT_STRICT & options && !rp_dt_contains_non_default_node(nodes)) {
        SR_LOG_ERR("No nodes to be deleted with strict option %s", xpath);
        rc = dm_report_error(session, NULL, xpath, SR_ERR_DATA_MISSING);
        goto cleanup;
    }

    /* list key can be deleted only when the whole list is deleted */
    for (size_t i = 0; i < nodes->number; i++) {
        bool can_be_deleted = false;
        rc = rp_dt_check_node_deletion(nodes->set.d[i], nodes, &can_be_deleted);
        CHECK_RC_LOG_GOTO(rc, cleanup, "Check node deletion failed %s", xpath);

        if (!can_be_deleted) {
            SR_LOG_ERR("Key leaf can not be delete delete the list instead %s", xpath);
            rc = dm_report_error(session, "List key can not be deleted", xpath, SR_ERR_INVAL_ARG);
            goto cleanup;
        }
    }

    /* check edit flags */
    if (SR_EDIT_NON_RECURSIVE & options) {
        for (size_t i = 0; i < nodes->number; i++) {
            if ((nodes->set.d[i]->schema->nodetype & (LYS_LIST | LYS_CONTAINER)) &&
                    !rp_dt_has_only_keys(nodes->set.d[i])) {
                SR_LOG_ERR("List of the nodes to be deleted contains list or container with non recursive opt %s", xpath);
                rc = dm_report_error(session, NULL, xpath, SR_ERR_DATA_EXISTS);
                goto cleanup;
            }
        }
    }

    parents = ly_set_new();
    CHECK_NULL_NOMEM_GOTO(parents, rc, cleanup);

    /* unlink nodes and save their parents */
    for (size_t i = 0; i < nodes->number; i++) {
        if (NULL != nodes->set.d[i]->parent) {
            ly_set_add(parents, nodes->set.d[i]->parent, 0);
        }

        ret = sr_lyd_unlink(info, nodes->set.d[i]);
        CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_INTERNAL, cleanup, "Unlinking of the node %s failed", xpath);
    }

    /* remove parents that are to be deleted by query */
    for (size_t i = 0; i < parents->number; i++) {
        bool will_be_deleted = false;
        for (size_t j = 0; j < nodes->number; j++) {
            if (parents->set.d[i] == nodes->set.d[j]) {
                will_be_deleted = true;
                break;
            }
        }
        if (will_be_deleted) {
            ly_set_rm_index(parents, i);
            i--;
        }
    }

    /* free nodes */
    for (size_t i = 0; i < nodes->number; i++) {
        lyd_free_withsiblings(nodes->set.d[i]);
    }

    /* remove empty parent container/list nodes */
    for (size_t i = 0; i < parents->number; i++) {
        struct lyd_node *node = parents->set.d[i];
        struct lys_node *schema = node->schema;
        struct lyd_node *parent = NULL;

        while (NULL != node) {
            if (NULL == node->child &&
                ((LYS_LIST & node->schema->nodetype) ||
                 ((LYS_CONTAINER & node->schema->nodetype) && NULL == ((struct lys_node_container *)schema)->presence))) {
                /* list or non-presence container with no children */
                parent = node->parent;
                sr_lyd_unlink(info, node);
                lyd_free(node);
                node = parent;
            } else {
                break;
            }
        }
    }
cleanup:
    ly_set_free(parents);
    ly_set_free(nodes);
    /* mark to session copy that some change has been made */
    if (SR_ERR_OK == rc && !is_state) {
        info->modified = true;
    }
    return rc;
}

int
rp_dt_set_item(dm_ctx_t *dm_ctx, dm_session_t *session, const char *xpath, const sr_edit_flag_t options, const sr_val_t *value, const char *str_val, bool is_state)
{
    CHECK_NULL_ARG3(dm_ctx, session, xpath);
    /* value can be NULL if the list is created */
    int rc = SR_ERR_OK;
    char *new_value = NULL;

    const struct lys_module *module = NULL;
    struct lys_node *sch_node = NULL;
    dm_data_info_t *info = NULL;
    dm_schema_info_t *schema_info = NULL;
    struct lyd_node *node = NULL;
    char *module_name = NULL;

    /* validate xpath */
    rc = rp_dt_validate_node_xpath_lock(dm_ctx, session, xpath, &schema_info, &sch_node);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Requested node is not valid %s", xpath);
        return rc;
    }
    module = schema_info->module;
    if (NULL == sch_node) {
        SR_LOG_ERR("Node can not be created or update %s", xpath);
        pthread_rwlock_unlock(&schema_info->model_lock);
        return SR_ERR_INVAL_ARG;
    }
    module_name = strdup(module->name);
    pthread_rwlock_unlock(&schema_info->model_lock);
    CHECK_NULL_NOMEM_RETURN(module_name);


    /* get data tree to be update */
    rc = dm_get_data_info(dm_ctx, session, module_name, &info);
    free(module_name);
    module_name = NULL;
    CHECK_RC_LOG_RETURN(rc, "Getting data tree failed for xpath '%s'", xpath);

    /* check if node is enabled */
    if (dm_is_running_ds_session(session)) {
        if (!dm_is_enabled_check_recursively(sch_node)) {
            SR_LOG_ERR("The node is not enabled in running datastore %s", xpath);
            return dm_report_error(session, "The node is not enabled in running datastore", xpath, SR_ERR_INVAL_ARG);
        }
    }

    /* non-presence container can not be created */
    if (LYS_CONTAINER == sch_node->nodetype && NULL == ((struct lys_node_container *) sch_node)->presence) {
        SR_LOG_ERR("Non presence container can not be created %s", xpath);
        return dm_report_error(session, "Non presence container can not be created", xpath, SR_ERR_INVAL_ARG);
    }

    /* key node can not be created, create list instead*/
    if (LYS_LEAF == sch_node->nodetype) {
        bool is_key = false;
        rc = rp_dt_has_sch_key(sch_node->parent, sch_node->name, &is_key);
        CHECK_RC_MSG_RETURN(rc, "Has key failed");

        if (is_key) {
            SR_LOG_ERR("Value of the key can not be set %s", xpath);
            return dm_report_error(session, "Value of the key can not be set", xpath, SR_ERR_INVAL_ARG);
        }
    }

    /* transform new value from sr_val_t to string */
    if (NULL != value) {
        rc = sr_val_to_str_with_schema(value, sch_node, &new_value);
        CHECK_RC_MSG_RETURN(rc, "Copy new value to string failed");
    } else if (NULL != str_val) {
        new_value = strdup(str_val);
        CHECK_NULL_NOMEM_RETURN(new_value);
    } else if (!((LYS_CONTAINER | LYS_LIST) & sch_node->nodetype) &&
            !(LYS_LEAFLIST == sch_node->nodetype && (NULL != strstr(xpath, "[.='") || NULL != strstr(xpath, "[.=\"")) && ']' == xpath[strlen(xpath)-1])) {
        /* value can be NULL only if a presence container, list or leaf-list with predicated is being created */
        SR_LOG_ERR_MSG("Argument value not passed");
        return SR_ERR_INVAL_ARG;
    }

    /* non-recursive flag */
    if (SR_EDIT_NON_RECURSIVE & options) {
        if (NULL != sch_node->parent) {
            char *last_slash = rindex(xpath, '/');
            CHECK_NULL_NOMEM_GOTO(last_slash, rc, cleanup);
            char *parent_node = strndup(xpath, last_slash - xpath);
            CHECK_NULL_NOMEM_GOTO(parent_node, rc, cleanup);
            struct ly_set *res = lyd_find_path(info->node, parent_node);
            free(parent_node);
            if (NULL == res || 0 == res->number) {
                SR_LOG_ERR("A preceding node is missing '%s' create it or omit the non recursive option", xpath);
                ly_set_free(res);
                free(new_value);
                return dm_report_error(session, "A preceding node is missing", xpath, SR_ERR_DATA_MISSING);
            }
            ly_set_free(res);
        }
    }

    /* strict flag */
    int flags = (SR_EDIT_STRICT & options) ? 0 : LYD_PATH_OPT_UPDATE;

    /* setting a leaf with default value should pass even with SR_EDIT_STRICT */
    if ((SR_EDIT_STRICT & options) && sch_node->nodetype == LYS_LEAF && ((struct lys_node_leaf *) sch_node)->dflt != NULL) {
        rc = rp_dt_find_node(dm_ctx, info->node, xpath, dm_is_running_ds_session(session), &node);
        if (SR_ERR_NOT_FOUND != rc) {
            CHECK_RC_LOG_GOTO(rc, cleanup, "Default node %s not found", xpath);
        } else {
            /* if leaf does not exists, it is ok LYD_PATH_OPT_UPDATE doesn't need to be added */
            rc = SR_ERR_OK;
        }
        if (NULL != node && 0 == strcmp(((struct lyd_node_leaf_list *) node)->value_str, ((struct lys_node_leaf *) sch_node)->dflt)) {
            /* add update flag */
            flags |= LYD_PATH_OPT_UPDATE;
        }
    }


    /* create or update */
    ly_errno = LY_SUCCESS;
    node = dm_lyd_new_path(info, xpath, new_value, flags);
    if (NULL == node && LY_SUCCESS != ly_errno) {
        SR_LOG_ERR("Setting of item failed %s %d", xpath, ly_vecode(info->schema->module->ctx));
        if (LYVE_PATH_EXISTS == ly_vecode(info->schema->module->ctx)) {
            rc = SR_ERR_DATA_EXISTS;
        } else if (LY_EVALID == ly_errno) {
            rc = SR_ERR_INVAL_ARG;
        } else {
            rc = SR_ERR_INTERNAL;
        }
    }

    /* remove default tag if the default value has been explicitly set or overwritten */
    if (SR_ERR_OK == rc && sch_node->nodetype == LYS_LEAF && ((struct lys_node_leaf *) sch_node)->dflt != NULL) {
        if (NULL == node) {
            rc = rp_dt_find_node(dm_ctx, info->node, xpath, dm_is_running_ds_session(session), &node);
            CHECK_RC_LOG_GOTO(rc, cleanup, "Created node %s not found", xpath);
        }
        node->dflt = 0;
    }

cleanup:
    free(new_value);
    if (NULL != info) {
        if (SR_ERR_OK == rc && !is_state) {
            info->modified = true;
        }
    }
    return rc;
}

int
rp_dt_move_list(dm_ctx_t *dm_ctx, dm_session_t *session, const char *xpath, sr_move_position_t position, const char *relative_item)
{
    CHECK_NULL_ARG3(dm_ctx, session, xpath);
    int rc = SR_ERR_OK;
    struct lyd_node *node = NULL, *node2 = NULL;
    struct lyd_node *sibling = NULL;
    dm_schema_info_t *schema_info = NULL;
    dm_data_info_t *info = NULL;
    char *module_name = NULL;

    rc = rp_dt_validate_node_xpath_lock(dm_ctx, session, xpath, &schema_info, NULL);
    CHECK_RC_LOG_RETURN(rc, "Requested node is not valid %s", xpath);

    module_name = strdup(schema_info->module_name);
    pthread_rwlock_unlock(&schema_info->model_lock);
    CHECK_NULL_NOMEM_RETURN(module_name);

    rc = dm_get_data_info(dm_ctx, session, module_name, &info);
    free(module_name);
    module_name = NULL;
    CHECK_RC_LOG_RETURN(rc, "Getting data tree failed for xpath '%s'", xpath);


    rc = rp_dt_find_node(dm_ctx, info->node, xpath, dm_is_running_ds_session(session), &node);
    if (SR_ERR_NOT_FOUND == rc) {
        SR_LOG_ERR("List not found %s", xpath);
        return SR_ERR_INVAL_ARG;
    } else if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Find node failed %s", xpath);
        return rc;
    }

    if (!((LYS_LIST | LYS_LEAFLIST) & node->schema->nodetype) || (!(LYS_USERORDERED & node->schema->flags))) {
        SR_LOG_ERR("Xpath %s does not identify a user ordered list or leaf-list", xpath);
        return dm_report_error(session, "Path does not identify a user ordered list or leaf-list", xpath, SR_ERR_INVAL_ARG);
    }

    if ((SR_MOVE_AFTER == position || SR_MOVE_BEFORE == position) && NULL != relative_item) {
        rc = rp_dt_find_node(dm_ctx, info->node, relative_item, dm_is_running_ds_session(session), &sibling);
        if (SR_ERR_NOT_FOUND == rc) {
            rc = dm_report_error(session, "Relative item for move operation not found", relative_item, SR_ERR_INVAL_ARG);
            goto cleanup;
        } else if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Find the closest sibling failed");
            return rc;
        }
    } else {
        node2 = sibling = node;

        if (SR_MOVE_FIRST == position) {
            while (node2->prev->next) {
                node2 = node2->prev;
                if (node2->schema == node->schema) {
                    sibling = node2;
                }
            }
        } else if (SR_MOVE_LAST == position) {
            while (node2->next) {
                node2 = node2->next;
                if (node2->schema == node->schema) {
                    sibling = node2;
                }
            }
        }
    }

    if (NULL == sibling || !((LYS_LIST | LYS_LEAFLIST) & sibling->schema->nodetype) || (!(LYS_USERORDERED & sibling->schema->flags)) || (node->schema != sibling->schema)) {
        SR_LOG_ERR("Xpath %s does not identify the user ordered list or leaf-list or sibling node", xpath);
        return dm_report_error(session, "Path does not identify a user ordered list or leaf-list", xpath, SR_ERR_INVAL_ARG);
    }

    if (SR_MOVE_FIRST == position) {
        rc = sr_lyd_insert_before(info, sibling, node);
    } else if (SR_MOVE_LAST == position) {
        rc = sr_lyd_insert_after(info, sibling, node);
    } else if (SR_MOVE_BEFORE == position) {
        rc = sr_lyd_insert_before(info, sibling, node);
    } else if (SR_MOVE_AFTER == position) {
        rc = sr_lyd_insert_after(info, sibling, node);
    }

    CHECK_RC_MSG_GOTO(rc, cleanup, "Moving of the node failed");

cleanup:
    info->modified = SR_ERR_OK == rc ? true : info->modified;
    return rc;
}

int
rp_dt_move_list_wrapper(rp_ctx_t *rp_ctx, rp_session_t *session, const char *xpath, sr_move_position_t position, const char *relative_item)
{
    CHECK_NULL_ARG5(rp_ctx, rp_ctx->dm_ctx, session, session->dm_session, xpath);

    int rc = SR_ERR_OK;

    SR_LOG_INF("Move item request %s datastore, xpath: %s", sr_ds_to_str(session->datastore), xpath);

    rc = ac_check_node_permissions(session->ac_session, xpath, AC_OPER_READ_WRITE);
    CHECK_RC_LOG_RETURN(rc, "Access control check failed for xpath '%s'", xpath);

    rc = dm_add_move_operation(session->dm_session, xpath, position, relative_item);
    CHECK_RC_MSG_RETURN(rc, "Adding operation to session op list failed");

    rc = rp_dt_move_list(rp_ctx->dm_ctx, session->dm_session, xpath, position, relative_item);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("List move failed");
        dm_remove_last_operation(session->dm_session);
    }
    return rc;

}

int
rp_dt_set_item_wrapper(rp_ctx_t *rp_ctx, rp_session_t *session, const char *xpath, sr_val_t *val, char *str_val, sr_edit_options_t opt)
{
    CHECK_NULL_ARG5(rp_ctx, rp_ctx->dm_ctx, session, session->dm_session, xpath);

    int rc = SR_ERR_OK;

    SR_LOG_INF("Set item request %s datastore, xpath: %s", sr_ds_to_str(session->datastore), xpath);

    rc = ac_check_node_permissions(session->ac_session, xpath, AC_OPER_READ_WRITE);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Access control check failed for xpath '%s'", xpath);
        sr_free_val(val);
        free(str_val);
        return rc;
    }

    rc = dm_add_set_operation(session->dm_session, xpath, val, str_val, opt);
    /* val and str_val is freed by dm_add_operation */
    CHECK_RC_MSG_RETURN(rc, "Adding operation to session op list failed");

    rc = rp_dt_set_item(rp_ctx->dm_ctx, session->dm_session, xpath, opt, val, str_val, false);
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

    SR_LOG_INF("Delete item request %s datastore, xpath: %s", sr_ds_to_str(session->datastore), xpath);

    rc = ac_check_node_permissions(session->ac_session, xpath, AC_OPER_READ_WRITE);
    CHECK_RC_LOG_RETURN(rc, "Access control check failed for xpath '%s'", xpath);

    rc = dm_add_del_operation(session->dm_session, xpath, opts);
    CHECK_RC_MSG_RETURN(rc, "Adding operation to session op list failed");

    rc = rp_dt_delete_item(rp_ctx->dm_ctx, session->dm_session, xpath, opts, false);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("List delete failed");
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
 * @param [in] operations can be null in case of candidate session
 * @param [in] count
 * @param [in] continue_on_error flag denoting whether replay should be stopped on first error
 * @param [in] models_to_skip - set of model's name where the current modify timestamp
 * matches the timestamp of the session copy. Operation for this models skipped.
 * @return Error code (SR_ERR_OK on success)
 */
static int
rp_dt_replay_operations(dm_ctx_t *ctx, dm_session_t *session, dm_sess_op_t *operations, size_t count,
        bool continue_on_error, sr_list_t *models_to_skip)
{
    CHECK_NULL_ARG2(ctx, session);
    int rc = SR_ERR_OK;
    bool err_occured = false; /* flag used in case of continue_on_err */

    for (size_t i = 0; i < count; i++) {
        dm_sess_op_t *op = &operations[i];
        if (op->has_error) {
            continue;
        }
        /* check if the operation should be skipped */
        bool match = false;
        for (unsigned int m = 0; m < models_to_skip->count; m++) {
            if (0 == sr_cmp_first_ns(op->xpath, (char *) models_to_skip->data[m])) {
                SR_LOG_DBG("Skipping op for model %s", (char *) models_to_skip->data[m]);
                match = true;
                break;
            }
        }
        if (match) {
            continue;
        }

        switch (op->op) {
        case DM_SET_OP:
            rc = rp_dt_set_item(ctx, session, op->xpath, op->detail.set.options, op->detail.set.val, op->detail.set.str_val, false);
            break;
        case DM_DELETE_OP:
            rc = rp_dt_delete_item(ctx, session, op->xpath, op->detail.del.options, false);
            break;
        case DM_MOVE_OP:
            rc = rp_dt_move_list(ctx, session, op->xpath, op->detail.mov.position, op->detail.mov.relative_item);
            break;
        }

        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Replay of operation %zu / %zu failed", i, count);
            if (!continue_on_error) {
                return rc;
            } else {
                op->has_error = true;
                err_occured = true;
            }
        }
    }
    if (continue_on_error && err_occured) {
        return SR_ERR_INTERNAL;
    } else {
        return rc;
    }
}

static int
rp_dt_generate_config_change_notification (rp_ctx_t *rp_ctx, rp_session_t *session, dm_commit_context_t *c_ctx)
{
    int rc = SR_ERR_OK;
    sr_list_t *diff_lists = NULL;
    dm_model_subscription_t *ms = NULL;
    dm_data_info_t lookup_info = {0};
    dm_data_info_t *prev_info = NULL, *commit_info = NULL;
    struct lyd_difflist *diff = NULL;

    rc = sr_list_init(&diff_lists);
    CHECK_RC_MSG_RETURN(rc, "Failed to allocate list");

    if (SR_DS_STARTUP == session->datastore) {

        dm_data_info_t *info = NULL;
        size_t i = 0;
        sr_btree_t *session_models = NULL, *commit_session_models = NULL;

        rc = dm_get_session_datatrees(rp_ctx->dm_ctx, session->dm_session, &session_models);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed get session datatrees");

        rc = dm_get_session_datatrees(rp_ctx->dm_ctx, c_ctx->session, &commit_session_models);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed get session datatrees");

        while (NULL != (info = sr_btree_get_at(session_models, i++))) {
            if (!info->modified) {
                continue;
            }

            lookup_info.schema = info->schema;
            /* configuration before commit */
            prev_info = sr_btree_search(c_ctx->prev_data_trees, &lookup_info);
            if (NULL == prev_info) {
                SR_LOG_ERR("Current data tree for module %s not found", info->schema->module->name);
                continue;
            }
            /* configuration after commit */
            commit_info = sr_btree_search(commit_session_models, &lookup_info);
            if (NULL == commit_info) {
                SR_LOG_ERR("Commit data tree for module %s not found", info->schema->module->name);
                continue;
            }

            diff = lyd_diff(prev_info->node, commit_info->node, LYD_DIFFOPT_WITHDEFAULTS);
            if (NULL == diff) {
                continue;
            }

            rc = sr_list_add(diff_lists, diff);
            if (SR_ERR_OK != rc) {
                lyd_free_diff(diff);
            }
            CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to add item into the list");
        }
    } else {
        size_t index = 0;
        while (NULL != (ms = sr_btree_get_at(c_ctx->subscriptions, index))) {
            SR_LOG_DBG("Config changes for module %s", ms->schema_info->module_name);
            if (NULL != ms->difflist) {
                rc = sr_list_add(diff_lists, ms->difflist);
                CHECK_RC_MSG_GOTO(rc, cleanup, "List add failed");
            }
            index++;
        }
    }

    rc = rp_generate_config_change_notification(rp_ctx, session, diff_lists);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create config-change notification");

cleanup:
    if (SR_DS_STARTUP == session->datastore) {
        for (size_t i = 0; i < diff_lists->count; i++) {
            lyd_free_diff(diff_lists->data[i]);
        }
    }
    sr_list_cleanup(diff_lists);

    return rc;
}

/**
 * @brief Reload NACM configuration (sends a request to the request processor
 * and waits for it to be fully processed).
 */
static int
rp_dt_reload_nacm(rp_ctx_t *rp_ctx)
{
    Sr__Msg *req = NULL;
    int rc = SR_ERR_OK;
    struct timespec ts;
    CHECK_NULL_ARG(rp_ctx);

    /* setup the timer */
    rc = sr_gpb_internal_req_alloc(NULL, SR__OPERATION__NACM_RELOAD, &req);
    if (SR_ERR_OK == rc) {
        /* enqueue the message */
        rc = cm_msg_send(rp_ctx->cm_ctx, req);
    }
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Unable to send a request to reload the running NACM configuration.");
    }

    /* wait until the NACM ctx has been reloaded */
    while (cm_msg_search(rp_ctx->cm_ctx, req)) {
        ts.tv_sec = 0;
        ts.tv_nsec = 250000;
        nanosleep(&ts, NULL);
    }

    return rc;
}

int
rp_dt_commit(rp_ctx_t *rp_ctx, rp_session_t *session, dm_commit_context_t **c_ctx, bool copy_config,
        sr_error_info_t **errors, size_t *err_cnt)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_ARG_NORET5(rc, rp_ctx, session, c_ctx, errors, err_cnt);
    if (SR_ERR_OK != rc) {
        if (NULL != *c_ctx) {
            pthread_mutex_unlock(&(*c_ctx)->mutex);
        }
        return rc;
    }

    bool remove_ctx = false;
    bool free_ctx = false;
    uint32_t c_id = 0;
    dm_commit_context_t *commit_ctx = *c_ctx;
    dm_commit_state_t state = NULL != commit_ctx ? commit_ctx->state : DM_COMMIT_STARTED;
    nacm_ctx_t *nacm_ctx = NULL;

    while (state != DM_COMMIT_FINISHED) {
        switch (state) {
        case DM_COMMIT_STARTED:
            SR_LOG_DBG_MSG("Commit (1/10): process started");
            state = DM_COMMIT_LOAD_MODEL_DEPS;
            break;
        case DM_COMMIT_LOAD_MODEL_DEPS:
            rc = dm_commit_load_session_module_deps(rp_ctx->dm_ctx, session->dm_session);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR_MSG("Loading module dependencies failed.");
                return SR_ERR_INTERNAL;
            }
            SR_LOG_DBG_MSG("Commit (2/10): loading module dependencies succeeded");
            state = DM_COMMIT_LOAD_MODIFIED_MODELS;
            break;
        case DM_COMMIT_LOAD_MODIFIED_MODELS:
            rc = dm_commit_prepare_context(rp_ctx->dm_ctx, session->dm_session, &commit_ctx);
            CHECK_RC_MSG_RETURN(rc, "commit prepare context failed");
            commit_ctx->init_session = session;
            if (0 == commit_ctx->modif_count) {
                SR_LOG_DBG_MSG("Commit: Finished - no model modified");
                dm_free_commit_context(commit_ctx);
                if (SR_DS_CANDIDATE != session->datastore) {
                    /* we still need to discard changes (operations), it is possible there are some operations that
                     * did not modify the data (so no model was modified) */
                    dm_discard_changes(rp_ctx->dm_ctx, session->dm_session, NULL);
                }
                return SR_ERR_OK;
            }
            pthread_mutex_lock(&commit_ctx->mutex);
            commit_ctx->disabled_config_change = rp_ctx->do_not_generate_config_change;
            /* open all files */
            rc = dm_commit_load_modified_models(rp_ctx->dm_ctx, session->dm_session, commit_ctx, copy_config,
                    errors, err_cnt);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Loading of modified models failed");
            SR_LOG_DBG_MSG("Commit (3/10): all modified models loaded successfully");
            state = DM_COMMIT_REPLAY_OPS;
            break;
        case DM_COMMIT_REPLAY_OPS:
            rc = rp_dt_replay_operations(rp_ctx->dm_ctx, commit_ctx->session, commit_ctx->operations,
                commit_ctx->oper_count, false, commit_ctx->up_to_date_models);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Replay of operations failed");
            SR_LOG_DBG_MSG("Commit (4/10): replay of operation succeeded");
            state = DM_COMMIT_VALIDATE_MERGED;
            break;
        case DM_COMMIT_VALIDATE_MERGED:
            if (session->datastore == SR_DS_CANDIDATE) {
                SR_LOG_DBG_MSG("Commit (5/10): merged models validation skipped");
            } else {
                rc = dm_validate_session_data_trees(rp_ctx->dm_ctx, commit_ctx->session, errors, err_cnt);
                if (SR_ERR_OK != rc) {
                    SR_LOG_ERR_MSG("Validation after merging failed");
                    rc = SR_ERR_VALIDATION_FAILED;
                    goto cleanup;
                }
                SR_LOG_DBG_MSG("Commit (5/10): merged models validation succeeded");
            }
            state = DM_COMMIT_NACM;
            break;
        case DM_COMMIT_NACM:
            if (NULL != rp_ctx->dm_ctx->nacm_ctx && (commit_ctx->init_session->options & SR_SESS_ENABLE_NACM)) {
                rc = dm_commit_netconf_access_control(rp_ctx->dm_ctx->nacm_ctx, session->dm_session, commit_ctx,
                                                      copy_config, errors, err_cnt);
                if (SR_ERR_OK != rc) {
                    if (SR_ERR_UNAUTHORIZED != rc) {
                        SR_LOG_ERR_MSG("Failed to evaluate write access for the commit operation");
                    } else {
                        SR_LOG_ERR_MSG("Commit was aborted due to insufficient access rights");
                    }
                    goto cleanup;
                }
                SR_LOG_DBG_MSG("Commit (6/10): access granted by NACM");
            } else {
                SR_LOG_DBG_MSG("Commit (6/10): NACM access check skipped");
            }
            if (session->datastore == SR_DS_CANDIDATE) {
                /* we are finished for candidate, no changes are written */
                state = DM_COMMIT_FINISHED;
            } else {
                state = DM_COMMIT_NOTIFY_VERIFY;
            }
            break;
        case DM_COMMIT_NOTIFY_VERIFY:
            rc = dm_commit_notify(rp_ctx->dm_ctx, session->dm_session, SR_EV_VERIFY, commit_ctx);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Sending of verify notifications failed");
            state = commit_ctx->state;
            SR_LOG_DBG_MSG("Commit (7/10): verify phase done");
            break;
        case DM_COMMIT_WAIT_FOR_NOTIFICATIONS:
            SR_LOG_DBG("Commit %"PRIu32" processing paused waiting for replies from verifiers", commit_ctx->id);
            session->state = RP_REQ_WAITING_FOR_VERIFIERS;
            pthread_mutex_unlock(&commit_ctx->mutex);
            *c_ctx = commit_ctx;
            return SR_ERR_OK;
        case DM_COMMIT_WRITE:
            rc = dm_commit_writelock_fds(session->dm_session, commit_ctx);
            if (SR_ERR_OK == rc ) {
                rc = dm_commit_write_files(session->dm_session, commit_ctx);
                if (SR_ERR_OK == rc) {
                    SR_LOG_DBG_MSG("Commit (8/10): data write succeeded");
                }
            }
            if (SR_ERR_OK == rc && commit_ctx->nacm_edited) {
                /* request to reload NACM configuration if it was edited */
                rc = dm_get_nacm_ctx(rp_ctx->dm_ctx, &nacm_ctx);
                if (SR_ERR_OK != rc) {
                    SR_LOG_WRN_MSG("Failed to get NACM context");
                } else if (NULL != nacm_ctx) {
                    rc = rp_dt_reload_nacm(rp_ctx);
                }
            }
            state = DM_COMMIT_NOTIFY_APPLY;
            break;
        case DM_COMMIT_NOTIFY_APPLY:
            rc = dm_commit_notify(rp_ctx->dm_ctx, session->dm_session, SR_EV_APPLY, commit_ctx);
            if (SR_ERR_OK == rc && !rp_ctx->do_not_generate_config_change) {
                rc = rp_dt_generate_config_change_notification(rp_ctx, session, commit_ctx);
            }
            state = DM_COMMIT_FINISHED;
            SR_LOG_DBG_MSG("Commit (9/10): apply notifications sent");
            break;
        case DM_COMMIT_NOTIFY_ABORT:
            rc = dm_commit_notify(rp_ctx->dm_ctx, session->dm_session, SR_EV_ABORT, commit_ctx);
            session->state = RP_REQ_FINISHED;
            *errors = commit_ctx->errors;
            *err_cnt = commit_ctx->err_cnt;
            commit_ctx->errors = NULL;
            commit_ctx->err_cnt = 0;
            SR_LOG_DBG_MSG("Commit (9/10): abort notifications sent");
            rc = commit_ctx->result;
            goto cleanup;
        default:
            break;
        }
    }

cleanup:
    if (NULL != commit_ctx) {
        remove_ctx = commit_ctx->should_be_removed;
        c_id = commit_ctx->id;

        if (!commit_ctx->in_btree) {
            free_ctx = true;
        }
    }
    pthread_mutex_unlock(&commit_ctx->mutex);

    /* cleanup commit context that was already inserted into btree */
    if (remove_ctx) {
        dm_commit_notifications_complete(rp_ctx->dm_ctx, c_id);
        commit_ctx = NULL;
    }

    /* In case of running datastore, commit context will be freed when
     * all notifications session are closed.
     *
     * Commit context was not inserted into the btree can be freed
     */
    if (NULL != commit_ctx && free_ctx) {
        dm_free_commit_context(commit_ctx);
    }

    if (SR_ERR_OK == rc) {
        /* discard changes in session in next get_data_tree call newly committed content will be loaded */
        if (SR_DS_CANDIDATE != session->datastore) {
            dm_discard_changes(rp_ctx->dm_ctx, session->dm_session, NULL);
        }
        SR_LOG_DBG_MSG("Commit (10/10): finished successfully");
    } else {
        SR_LOG_DBG_MSG("Commit (10/10): finished with an error");
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
        sr_error_info_t *tmp_err = realloc(*errors, (*err_cnt + 1) * sizeof(**errors));
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
        case DM_MOVE_OP:
            (*errors)[*err_cnt].message = strdup("MOVE Operation can not be merged with current datastore state");
            break;
        default:
            (*errors)[*err_cnt].message = strdup("An operation can not be merged with current datastore state");
        }
        (*errors)[*err_cnt].xpath = strdup(op->xpath);
        (*err_cnt)++;
    }
}

int
rp_dt_refresh_session(rp_ctx_t *rp_ctx, rp_session_t *session, sr_error_info_t **errors, size_t *err_cnt)
{
    CHECK_NULL_ARG2(rp_ctx, session);
    int rc = SR_ERR_OK;
    sr_list_t *up_to_date = NULL;
    dm_sess_op_t *ops = NULL;
    size_t op_count = 0;
    *err_cnt = 0;
    *errors = NULL;

    SR_LOG_INF("Refresh session request %s datastore", sr_ds_to_str(session->datastore));

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
    sr_list_cleanup(up_to_date);
    return rc;
}

/**
 * @brief Performs copy config to running datastore. It is done by commit to perform
 * all validation and notifications as needed
 * @param [in] rp_ctx
 * @param [in] session
 * @param [in] module_name
 * @param [in] src
 * @param [in] errors
 * @param [in] err_cnt
 * @return Error code (SR_ERR_OK on success)
 */
static int
rp_dt_copy_config_to_running(rp_ctx_t *rp_ctx, rp_session_t *session, const char *module_name, sr_datastore_t src, sr_error_info_t **errors, size_t *err_cnt)
{
    CHECK_NULL_ARG2(rp_ctx, session);
    int rc = SR_ERR_OK;
    sr_list_t *modules = NULL;
    dm_session_t *backup = NULL;
    dm_commit_context_t *c_ctx = NULL;
    dm_data_info_t *info = NULL;
    bool enabled = false;

    assert(RP_REQ_RESUMED != session->state);

    /*
     * copy to running is running commit behind the scenes
     */

    /* backup the running ds changes to restore them if something goes wrong */
    rc = dm_session_start(rp_ctx->dm_ctx, session->user_credentials, src, &backup);
    CHECK_RC_MSG_GOTO(rc, cleanup1, "Session start of temporary session failed");

    rc = dm_move_session_tree_and_ops(rp_ctx->dm_ctx, session->dm_session, backup, SR_DS_RUNNING);
    CHECK_RC_MSG_GOTO(rc, cleanup2, "Moving session data trees failed");

    rp_dt_switch_datastore(rp_ctx, session, src);

    /* load models to be committed to the session */
    if (NULL != module_name) {
        /* is the module enabled? */
        rc = dm_has_enabled_subtree(rp_ctx->dm_ctx, module_name, NULL, &enabled);
        CHECK_RC_LOG_GOTO(rc, cleanup3, "Has enabled subtree failed %s", module_name);
        if (!enabled) {
            SR_LOG_ERR("Cannot copy module '%s', it is not enabled.", module_name);
            rc = SR_ERR_OPERATION_FAILED;
            goto cleanup3;
        }

        /* load data tree if it was not copied from backup session */
        rc = dm_get_data_info(rp_ctx->dm_ctx, session->dm_session, module_name, &info);
        CHECK_RC_MSG_GOTO(rc, cleanup3, "Get data info failed");
        info->modified = true;
    } else {
        /* load all enabled models */
        rc = dm_get_all_modules(rp_ctx->dm_ctx, session->dm_session, true, &modules);
        CHECK_RC_MSG_GOTO(rc, cleanup3, "Get all modules failed");
        for (size_t i = 0; i < modules->count; i++) {
            char *module = modules->data[i];
            rc = dm_get_data_info(rp_ctx->dm_ctx, session->dm_session, module, &info);
            CHECK_RC_LOG_GOTO(rc, cleanup3, "Get data info failed %s", module);
            info->modified = true;
        }
    }

    /* move changes to running datastore */
    rc = dm_move_session_trees_in_session(rp_ctx->dm_ctx, session->dm_session, src, SR_DS_RUNNING);
    CHECK_RC_MSG_GOTO(rc, cleanup3, "Data tree move failed");

    /* commit running changes */
    rp_dt_switch_datastore(rp_ctx, session, SR_DS_RUNNING);
    rc = rp_dt_commit(rp_ctx, session, &c_ctx, true, errors, err_cnt);

    if (c_ctx != NULL) {
        /* waiting for notifications, store backup session */
        c_ctx->backup_session = backup;
    }

    if (rc == SR_ERR_OK) {
        if (c_ctx != NULL) {
            goto cleanup1;
        } else {
            /* commit succeeded and finished */
            goto cleanup2;
        }
    }
    /* else fail */

    dm_move_session_trees_in_session(rp_ctx->dm_ctx, session->dm_session, SR_DS_RUNNING, src);
cleanup3:
    /* restore the session running changes if something went wrong */
    dm_move_session_tree_and_ops(rp_ctx->dm_ctx, session->dm_session, backup, SR_DS_RUNNING);
cleanup2:
    dm_session_stop(rp_ctx->dm_ctx, backup);
cleanup1:
    sr_list_cleanup(modules);
    return rc;
}

static int
rp_dt_copy_config_to_running_resume(rp_ctx_t *rp_ctx, rp_session_t *session, const char *module_name, sr_datastore_t src,
                                    sr_error_info_t **errors, size_t *err_cnt)
{
    CHECK_NULL_ARG2(rp_ctx, session);
    int rc = SR_ERR_OK;
    dm_session_t *backup = NULL;
    dm_commit_context_t *c_ctx = NULL;

    assert(RP_REQ_RESUMED == session->state);

    rc = dm_get_commit_context(rp_ctx->dm_ctx, session->commit_id, &c_ctx);
    CHECK_RC_LOG_RETURN(rc, "Failed to resume copy_config, commit ctx with id %"PRIu32" not found.", session->commit_id);
    pthread_mutex_lock(&c_ctx->mutex);

    backup = c_ctx->backup_session;
    c_ctx->backup_session = NULL;

    /* commit running changes */
    rp_dt_switch_datastore(rp_ctx, session, SR_DS_RUNNING);
    rc = rp_dt_commit(rp_ctx, session, &c_ctx, true, errors, err_cnt);

    if (rc != SR_ERR_OK) {
        /* restore the session running changes if something went wrong */
        dm_move_session_trees_in_session(rp_ctx->dm_ctx, session->dm_session, SR_DS_RUNNING, src);
        dm_move_session_tree_and_ops(rp_ctx->dm_ctx, session->dm_session, backup, SR_DS_RUNNING);
    } else {
        dm_move_session_tree_and_ops(rp_ctx->dm_ctx, backup, session->dm_session, SR_DS_RUNNING);
    }
    dm_session_stop(rp_ctx->dm_ctx, backup);
    return rc;
}

int
rp_dt_copy_config(rp_ctx_t *rp_ctx, rp_session_t *session, const char *module_name, sr_datastore_t src, sr_datastore_t dst, sr_error_info_t **errors, size_t *err_cnt)
{
    CHECK_NULL_ARG2(rp_ctx, session);
    SR_LOG_INF("Copy config: %s -> %s, model: %s", sr_ds_to_str(src), sr_ds_to_str(dst), module_name);
    int rc = SR_ERR_OK;
    int prev_ds = session->datastore;

    if (src == dst) {
        return rc;
    }

    if ((SR_DS_CANDIDATE == src || SR_DS_CANDIDATE == dst) && SR_DS_CANDIDATE != session->datastore) {
        rp_dt_switch_datastore(rp_ctx, session, SR_DS_CANDIDATE);
    }

    if (SR_DS_RUNNING != dst) {
        if (NULL != module_name) {
            /* copy module content in DM */
            rc = dm_copy_module(rp_ctx->dm_ctx, session->dm_session, module_name, src, dst, NULL,
                                session->options & SR_SESS_ENABLE_NACM, errors, err_cnt);
        } else {
            /* copy all enabled modules */
            rc = dm_copy_all_models(rp_ctx->dm_ctx, session->dm_session, src, dst,
                                    session->options & SR_SESS_ENABLE_NACM, errors, err_cnt);
        }

    } else {
        if (session->state == RP_REQ_RESUMED) {
            rc = rp_dt_copy_config_to_running_resume(rp_ctx, session, module_name, src, errors, err_cnt);
        } else {
            rc = rp_dt_copy_config_to_running(rp_ctx, session, module_name, src, errors, err_cnt);
        }
    }

    rp_dt_switch_datastore(rp_ctx, session, prev_ds);
    return rc;
}

void
rp_dt_switch_datastore(rp_ctx_t *rp_ctx, rp_session_t *session, sr_datastore_t ds)
{
    CHECK_NULL_ARG_VOID3(rp_ctx, session, session->dm_session);
    SR_LOG_INF("Switch datastore request %s -> %s", sr_ds_to_str(session->datastore), sr_ds_to_str(ds));
    session->datastore = ds;
    dm_session_switch_ds(session->dm_session, ds);
}

int
rp_dt_lock(const rp_ctx_t *rp_ctx, const rp_session_t *session, const char *module_name)
{
    CHECK_NULL_ARG2(rp_ctx, session);
    int rc = SR_ERR_OK;
    bool modif = false;

    SR_LOG_INF("Lock request module: '%s', datastore %s", module_name, sr_ds_to_str(session->datastore));

    sr_schema_t *schemas = NULL;
    size_t count = 0;

    if (NULL != module_name) {
        /* module-level lock */
        rc = dm_is_model_modified(rp_ctx->dm_ctx, session->dm_session, module_name, &modif);
        CHECK_RC_MSG_RETURN(rc, "is model modified failed");
        if (modif) {
            SR_LOG_ERR("Modified model %s can not be locked", module_name);
            return dm_report_error(session->dm_session, "Module has been modified, it can not be locked. Discard or commit changes", module_name, SR_ERR_OPERATION_FAILED);
        }
        rc = dm_lock_module(rp_ctx->dm_ctx, session->dm_session, module_name);
    } else {
        /* datastore-level lock */
        rc = dm_list_schemas(rp_ctx->dm_ctx, session->dm_session, &schemas, &count);
        CHECK_RC_MSG_GOTO(rc, cleanup, "List schemas failed");

        for (size_t i = 0; i < count; i++) {
            rc = dm_is_model_modified(rp_ctx->dm_ctx, session->dm_session, schemas[i].module_name, &modif);
            CHECK_RC_MSG_GOTO(rc, cleanup, "is model modified failed");

            if (modif) {
                SR_LOG_ERR("Modified model %s can not be locked", schemas[i].module_name);
                rc = dm_report_error(session->dm_session, "Module has been modified, it can not be locked. Discard or commit changes", schemas[i].module_name, SR_ERR_OPERATION_FAILED);
                goto cleanup;
            }
        }
        rc = dm_lock_datastore(rp_ctx->dm_ctx, session->dm_session);
    }
cleanup:
    sr_free_schemas(schemas, count);
    return rc;
}
