/**
 * @file private_candidate.c
 * @author Juraj Budai <budai@cesnet.cz>
 * @brief implementation of private candidate datastore
 *
 * @copyright
 * Copyright (c) 2025 Deutsche Telekom AG.
 * Copyright (c) 2025 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#define _GNU_SOURCE /* strdup */

#include "private_candidate.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "common.h"
#include "common_types.h"
#include "compat.h"
#include "context_change.h"
#include "edit_diff.h"
#include "log.h"
#include "ly_wrap.h"
#include "modinfo.h"
#include "shm_mod.h"

/**
 * @brief Recursively find the matching node.
 *
 * Special case: If a user-ordered list node is encountered that entire list node is considered as a match.
 *
 * @param[in] root Tree to search in.
 * @param[in] target Target node to find.
 * @param[out] match Can be NULL, otherwise the found data node.
 */
static sr_error_info_t *
pc_find_node_r(struct lyd_node *root, struct lyd_node *target, struct lyd_node **match)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *iter, *child, *parent;

    LY_LIST_FOR(root, iter) {
        /* special handling for user-ordered lists: consider entire list as match */
        if (lysc_is_userordered(iter->schema) && (iter->schema == root->schema)) {
            *match = iter;
            goto cleanup;
        }

        if ((err_info = sr_lyd_find_sibling_first(root, target, match))) {
            goto cleanup;
        }

        if (*match) {
            goto cleanup;
        }

        /* recurse into child nodes if any */
        if ((child = lyd_child(iter))) {
            if ((err_info = pc_find_node_r(child, target, match))) {
                goto cleanup;
            }

            if (*match) {
                goto cleanup;
            }
        }
    }

    /* parent is also needed to find the exact node */
    if ((parent = lyd_parent(target))) {
        if ((err_info = pc_find_node_r(root, parent, match))) {
            goto cleanup;
        }

        if (*match) {
            goto cleanup;
        }
    }

cleanup:
    return err_info;
}

/**
 * @brief Unlink and free the nodes from diff_tree which are same as conflicting nodes.
 *
 * The diff is prepared in a way that applying it to the private candidate only apply non-conflicting changes.
 * This ensures that the private candidate datastore remains according to the "prefer-candidate" resolution strategy.
 *
 * @param[in,out] diff_tree Diff tree to remove conflicts from.
 * @param[out] conflict_set List of conflicting trees which were unlinked from the @p diff_tree.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
pc_unlink_conflicting_nodes(struct lyd_node **diff_tree, sr_pc_conflict_set_t **conflict_set)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *conflict_node = NULL, *match = NULL, *match_iter;
    const struct lysc_node *current_schema;
    uint32_t i;

    if (!*conflict_set || !*diff_tree) {
        return NULL;
    }

    for (i = 0; i < (*conflict_set)->conflict_count; i++) {
        conflict_node = (*conflict_set)->conflicts[i].run_diff;

        if ((err_info = pc_find_node_r(*diff_tree, conflict_node, &match))) {
            goto cleanup;
        }

        if (match && lysc_is_userordered(match->schema)) {
            current_schema = match->schema;

            /* unlink whole list/leaflist */
            while (match && match->schema == current_schema) {
                match_iter = match->next;

                sr_lyd_free_tree_safe(match, diff_tree);

                match = match_iter;
            }
        } else {
            sr_lyd_free_tree_safe(match, diff_tree);
        }
    }

cleanup:
    return err_info;
}

/**
 * @brief Resolve data conflicts between the private candidate and running datastore.
 *
 * @param[in] running_ds_tree Tree of the current running datastore.
 * @param[in] privcand_ds_tree Tree of the current private candidate datastore.
 * @param[in,out] privcand Pointer to the private candidate datastore structure.
 * @param[in,out] conflict_set List of conflicts which will be resolved.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
pc_update_diff_privcand(const struct lyd_node *running_ds_tree, struct lyd_node *privcand_ds_tree, sr_priv_cand_t *privcand, sr_pc_conflict_set_t **conflict_set)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *final_diff = NULL, *running_vs_privcand = NULL, *privcand_vs_running = NULL;

    /* user resolves the conflicts by himself */
    if ((privcand->conflict_resolution == SR_PC_REVERT_ON_CONFLICT) && conflict_set && (*conflict_set)) {
        return NULL;
    }

    if ((err_info = sr_lyd_diff_siblings(privcand_ds_tree, running_ds_tree, 0, NULL, &privcand_vs_running))) {
        goto cleanup;
    }

    switch (privcand->conflict_resolution) {
    case SR_PC_REVERT_ON_CONFLICT:
        /* reset private candidate to match current running datastore */
        lyd_free_all(privcand->diff_backup);
        privcand->diff_backup = NULL;

        lyd_free_all(privcand->diff_privcand);
        privcand->diff_privcand = NULL;

        lyd_diff_reverse_all(privcand_vs_running, &running_vs_privcand);

        if ((err_info = sr_lyd_dup(running_vs_privcand, NULL, LYD_DUP_RECURSIVE, 1, &privcand->diff_privcand))) {
            goto cleanup;
        }
        break;
    case SR_PC_PREFER_RUNNING:
        if ((err_info = sr_lyd_diff_apply_all(&privcand_ds_tree, privcand_vs_running))) {
            goto cleanup;
        }

        /* reset private candidate to match current running datastore */
        lyd_free_all(privcand->diff_backup);
        privcand->diff_backup = NULL;
        lyd_free_all(privcand->diff_privcand);
        privcand->diff_privcand = NULL;

        /* The current running is now considered the baseline for the private candidate datastore.
         * Changes are stored in diff_privcand */
        if ((err_info = sr_lyd_diff_siblings(running_ds_tree, privcand_ds_tree, 0, NULL, &privcand->diff_privcand))) {
            goto cleanup;
        }

        sr_pc_free_conflicts(*conflict_set);
        (*conflict_set) = NULL;
        break;
    case SR_PC_PREFER_CANDIDATE:
        /*
         * Remove conflicting nodes from diff, This ensures that the corresponding
         * data from the private candidate is preserved
         */
        if ((err_info = pc_unlink_conflicting_nodes(&privcand_vs_running, conflict_set))) {
            goto cleanup;
        }

        /* merge nodes that are not in conflict */
        if ((err_info = sr_lyd_diff_apply_all(&privcand_ds_tree, privcand_vs_running))) {
            goto cleanup;
        }

        /* reset private candidate to match current running datastore */
        lyd_free_all(privcand->diff_backup);
        privcand->diff_backup = NULL;

        lyd_free_all(privcand->diff_privcand);
        privcand->diff_privcand = NULL;

        /* The current running is now considered the baseline for the private candidate datastore.
         * Changes are stored in diff_privcand */
        if ((err_info = sr_lyd_diff_siblings(running_ds_tree, privcand_ds_tree, 0, NULL, &privcand->diff_privcand))) {
            goto cleanup;
        }

        sr_pc_free_conflicts(*conflict_set);
        (*conflict_set) = NULL;
        break;
    default:
        /* should never happen */
        assert(0);
        break;
    }

cleanup:
    lyd_free_all(running_vs_privcand);
    lyd_free_all(final_diff);
    lyd_free_all(privcand_vs_running);

    return err_info;
}

/**
 * @brief Store a conflict between candidate and running datastore nodes.
 *
 * After resolving the conflicts, the private candidate's internal diff is rebuilt to reflect the resolved state.
 *
 * @param[in] cand_iter Pointer to the conflicting node from the private candidate datastore.
 * @param[in] run_iter Pointer to the conflicting node from the running datastore.
 * @param[in] type The type of conflict.
 * @param[in] dup Wheter to duplicate @p run_iter and @p cand_iter into conflicts.
 *                If zero, the function will assign pointers without duplication.
 * @param[out] conflict_set List of conflicts which are not resolved yet.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
pc_add_conflict(struct lyd_node *cand_iter, struct lyd_node *run_iter, sr_pc_conflict_type_t type, int dup, sr_pc_conflict_set_t **conflict_set)
{
    sr_error_info_t *err_info = NULL;
    sr_pc_conflict_info_t *c_info;

    if (conflict_set && !(*conflict_set)) {
        *conflict_set = calloc(1, sizeof(**conflict_set));
        SR_CHECK_MEM_GOTO(!(*conflict_set), err_info, cleanup);
    }

    // (*conflict_set)->conflicts = sr_realloc((*conflict_set)->conflicts, ((*conflict_set)->conflict_count + 1) * sizeof *(*conflict_set)->conflicts);
    // SR_CHECK_MEM_GOTO(!(*conflict_set)->conflicts, err_info, cleanup);

    /* allocate memory for new conflicts */
    sr_pc_conflict_info_t *tmp = realloc((*conflict_set)->conflicts, ((*conflict_set)->conflict_count + 1) * sizeof *tmp);

    SR_CHECK_MEM_GOTO(!tmp, err_info, cleanup);

    (*conflict_set)->conflicts = tmp;
    memset(&tmp[(*conflict_set)->conflict_count], 0, sizeof tmp[0]);

    c_info = &(*conflict_set)->conflicts[(*conflict_set)->conflict_count];

    /*
     * Save the conflicting trees into the conflict structure.
     *
     * For user-ordered lists (dup = 0), the diff nodes are already
     * allocated in the correct sibling structure, so we can simply assign
     * the pointers without duplicating the data.
     */
    if (dup) {
        if ((err_info = sr_lyd_dup(run_iter, NULL, LYD_DUP_WITH_PARENTS, 0, &c_info->run_diff))) {
            goto cleanup;
        }

        if ((err_info = sr_lyd_dup(cand_iter, NULL, LYD_DUP_WITH_PARENTS, 0, &c_info->pc_diff))) {
            goto cleanup;
        }
    } else {
        c_info->run_diff = run_iter;
        c_info->pc_diff = cand_iter;
    }

    /* store the type of conflict */
    c_info->type = type;

    (*conflict_set)->conflict_count++;

cleanup:
    if (err_info && !dup) {
        lyd_free_all(c_info->run_diff);
        lyd_free_all(c_info->pc_diff);
    }

    return err_info;
}

/**
 * @brief Determine the specific type of conflict between candidate and running nodes.
 *
 * @param[in] node_type The YANG schema node type.
 * @param[in] diff_op_cand The diff operation applied to the candidate node.
 * @param[in] diff_op_run The diff operation applied to the running node.
 * @return sr_pc_conflict_type_t The specific type of conflict identified between the two nodes.
 */
static sr_pc_conflict_type_t
pc_get_conflict_type(uint16_t node_type, enum edit_op diff_op_cand, enum edit_op diff_op_run)
{
    switch (node_type) {
    case LYS_LIST:
        if ((diff_op_cand == EDIT_REPLACE) && (diff_op_run == EDIT_REPLACE)) {
            return SR_PC_CONFLICT_LIST_ORDER;
        }
        return SR_PC_CONFLICT_LIST_ENTRY;

    case LYS_LEAF:
        if ((diff_op_cand == EDIT_REPLACE) && (diff_op_run == EDIT_REPLACE)) {
            return SR_PC_CONFLICT_VALUE_CHANGE;
        }
        return SR_PC_CONFLICT_LEAF_EXISTENCE;

    case LYS_LEAFLIST:
        if ((diff_op_cand == EDIT_REPLACE) && (diff_op_run == EDIT_REPLACE)) {
            return SR_PC_CONFLICT_LEAFLIST_ORDER;
        }
        return SR_PC_CONFLICT_LEAFLIST_ITEM;

    case LYS_ANYDATA:
    case LYS_ANYXML:
        return SR_PC_CONFLICT_VALUE_CHANGE;

    case LYS_CONTAINER:
        return SR_PC_CONFLICT_PRESENCE_CONTAINER;
    }

    /* should never happen */
    return 0;
}

/**
 * @brief Duplicate a data node and insert it into a sibling list.
 *
 * This function is used for adding list or leaf-list nodes,
 * duplicating the parent nodes only once when @p target is NULL.
 *
 * @param[in] src The source data node to duplicate.
 * @param[in,out] target Sibling list that receives the duplicated node.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
pc_dup_and_insert(const struct lyd_node *src, struct lyd_node **target)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *dup = NULL;

    if (!*target) {
        if ((err_info = sr_lyd_dup(src, NULL, LYD_DUP_WITH_PARENTS, 0, &dup))) {
            goto cleanup;
        }

        *target = dup;
    } else {
        if ((err_info = sr_lyd_dup(src, NULL, 0, 0, &dup))) {
            goto cleanup;
        }

        if ((err_info = sr_lyd_insert_sibling(*target, dup, target))) {
            goto cleanup;
        }
    }

cleanup:
    if (err_info) {
        lyd_free_tree(dup);
    }

    return err_info;
}

/**
 * @brief categorize nodes based on relevance to the conflict.
 *
 * - Nodes from @p run_diff are separated into:
 *      - @p list_entry_node : nodes representing create/delete operations.
 *      - @p list_order_node : nodes representing ordering modifications.
 * - Nodes from @p cand_diff that participate in the conflict are duplicated into
 *      - @p cand_conflict_node.
 *
 * @param[in] run_diff running datastore's diff subtree.
 * @param[in] cand_diff candidate's diff subtree.
 * @param[out] list_entry_node set of nodes that cause list entry conflict.
 * @param[out] list_order_node set of nodes that cause list order conflict.
 * @param[out] cand_conflict_node list of candidate nodes that are part of the detected conflict.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
pc_userord_conflict_management(struct lyd_node *run_diff, struct lyd_node *cand_diff, struct lyd_node **list_entry_node, struct lyd_node **list_order_node,
        struct lyd_node **cand_conflict_node)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *iter;
    const struct lysc_node *current_schema;
    enum edit_op node_op;

    *list_entry_node = NULL;
    *list_order_node = NULL;
    *cand_conflict_node = NULL;

    current_schema = run_diff->schema;

    /* sort individual nodes into categories based on conflict */
    LY_LIST_FOR_SAFE(run_diff, iter, run_diff) {
        /* check if there are any other nodes on the same level besides the current list/leaf-list */
        if (run_diff->schema != current_schema) {
            break;
        }

        node_op = sr_edit_diff_find_oper(run_diff, 0, NULL);

        if (node_op == EDIT_NONE) {
            continue;
        }

        /* separate nodes based on what type of conflict they cause */
        if ((node_op == EDIT_CREATE) || (node_op == EDIT_DELETE)) {
            if ((err_info = pc_dup_and_insert(run_diff, list_entry_node))) {
                goto cleanup;
            }
        } else {
            if ((err_info = pc_dup_and_insert(run_diff, list_order_node))) {
                goto cleanup;
            }
        }
    }

    current_schema = cand_diff->schema;

    /* skip nodes with operation none, unwanted in list/leaflist conflict */
    LY_LIST_FOR_SAFE(cand_diff, iter, cand_diff){
        if (cand_diff->schema != current_schema) {
            break;
        }

        node_op = sr_edit_diff_find_oper(cand_diff, 0, NULL);

        if (node_op == EDIT_NONE) {
            continue;
        }

        if ((err_info = pc_dup_and_insert(cand_diff, cand_conflict_node))) {
            goto cleanup;
        }
    }

cleanup:
    if (err_info) {
        lyd_free_all(*list_entry_node);
        lyd_free_all(*list_order_node);
        lyd_free_all(*cand_conflict_node);
    }

    return err_info;
}

/**
 * @brief Recursively detect and store conflicts between private candidate and running datastore.
 *
 * @param[in] privcand_diff_node Pointer to the candidate's diff subtree.
 * @param[in] running_diff_node Pointer to the running datastore's diff subtree.
 * @param[out] conflict_set List of conflicts which are not resolved yet.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
pc_generate_conflicts_r(const struct lyd_node *privcand_diff_node, const struct lyd_node *running_diff_node, sr_pc_conflict_set_t **conflict_set)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *cand_iter = NULL, *run_iter = NULL, *tmp;
    struct lyd_node *list_entry_node = NULL, *list_order_node = NULL, *cand_conflict_node = NULL, *cand_conflict_node_dup = NULL;
    const struct lysc_node *current_schema;
    enum edit_op run_op, cand_op;

    /* No conflicts can occur */
    if (!privcand_diff_node || !running_diff_node) {
        return err_info;
    }

    LY_LIST_FOR((struct lyd_node *)running_diff_node, run_iter) {
        /* try to find the corresponding node */
        if (run_iter->schema->nodetype & (LYS_LIST | LYS_LEAFLIST)) {
            if ((err_info = sr_lyd_find_sibling_first(privcand_diff_node, run_iter, &cand_iter))) {
                goto cleanup;
            }
        } else {
            if ((err_info = sr_lyd_find_sibling_val(privcand_diff_node, run_iter->schema, NULL, &cand_iter))) {
                goto cleanup;
            }
        }

        /* determine edit operations for both nodes */
        run_op = sr_edit_diff_find_oper(run_iter, 0, NULL);
        cand_op = sr_edit_diff_find_oper(cand_iter, 0, NULL);

        /* no conflict in node continue with its child */
        if (((run_op == EDIT_NONE) || (run_op == EDIT_CONTINUE)) && ((cand_op == EDIT_NONE) || (cand_op == EDIT_CONTINUE))) {
            if (run_iter->schema->nodetype & LYD_NODE_INNER) {
                if ((err_info = pc_generate_conflicts_r(lyd_child(cand_iter), lyd_child(run_iter), conflict_set))) {
                    goto cleanup;
                }
            }

            continue;
        }

        /* handle conflicts based on the type of the node */
        switch (run_iter->schema->nodetype) {
        case LYS_LIST:
        case LYS_LEAFLIST:

            current_schema = run_iter->schema;

            if (!cand_iter) {
                if ((err_info = sr_lyd_find_sibling_val(privcand_diff_node, current_schema, NULL, &cand_iter))) {
                    goto cleanup;
                }
            }

            /* node not found, there is no conflict */
            if (!cand_iter) {
                break;
            }

            if (lysc_is_userordered(run_iter->schema)) {
                if ((err_info = pc_userord_conflict_management(run_iter, cand_iter, &list_entry_node, &list_order_node, &cand_conflict_node))) {
                    goto cleanup;
                }

                /* create a duplicate for the second conflict only if we have both conflicts */
                if (list_entry_node && list_order_node) {
                    if ((err_info = sr_lyd_dup(cand_conflict_node, NULL, LYD_DUP_WITH_PARENTS, 1, &cand_conflict_node_dup))) {
                        goto cleanup;
                    }
                }

                if (list_order_node) {
                    if ((err_info = pc_add_conflict(cand_conflict_node, list_order_node, SR_PC_CONFLICT_LIST_ORDER, 0, conflict_set))) {
                        goto cleanup;
                    }
                }

                if (list_entry_node) {
                    /* use the duplicate only if it exists, otherwise use the original node */
                    tmp = cand_conflict_node_dup ? cand_conflict_node_dup : cand_conflict_node;
                    if ((err_info = pc_add_conflict(tmp, list_entry_node, SR_PC_CONFLICT_LIST_ENTRY, 0, conflict_set))) {
                        goto cleanup;
                    }
                }
            } else {
                if ((err_info = pc_add_conflict(cand_iter, run_iter,
                        pc_get_conflict_type(run_iter->schema->nodetype, cand_op, run_op), 1, conflict_set))) {
                    goto cleanup;
                }
            }

            /* check whether there are additional sibling nodes at the same level apart from the current list/leaf-list */
            LY_LIST_FOR(run_iter, run_iter) {
                if (run_iter->next && (run_iter->next->schema != current_schema)) {
                    current_schema = run_iter->next->schema;
                    break;
                }
            }

            list_entry_node = NULL;
            list_order_node = NULL;
            cand_conflict_node = NULL;
            cand_conflict_node_dup = NULL;

            /* there are no other siblings besides current list/leaflist */
            if (!run_iter) {
                goto cleanup;
            }
            break;
        case LYS_CONTAINER:
        case LYS_LEAF:
        case LYS_ANYDATA:
        case LYS_ANYXML:
            /* generic conflict handling for other types */
            if ((err_info = pc_add_conflict(cand_iter, run_iter,
                    pc_get_conflict_type(run_iter->schema->nodetype, cand_op, run_op), 1, conflict_set))) {
                goto cleanup;
            }
            break;
        default:
            /* should never happen */
            break;
        }
    }

cleanup:
    if (cand_conflict_node_dup) {
        lyd_free_all(cand_conflict_node_dup);
    }

    return err_info;
}

/**
 * @brief Subscription callback to save the state of current running datastore.
 *
 * Rollback to state of running datastore when it was created.
 *
 * @param[in] session Sysrepo session context.
 * @param[in] sub_id Subscription ID (unused).
 * @param[in] module_name Name of the YANG module that triggered the callback (unused).
 * @param[in] xpath Subscription XPath (unused).
 * @param[in] event Type of Sysrepo event. Only SR_EV_CHANGE is handled.
 * @param[in] request_id Request identifier (unused).
 * @param[in] private_data Pointer to user-defined data structure.
 * @return Error code (::SR_ERR_OK on success).
 */
static int
pc_update_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *UNUSED(xpath), sr_event_t UNUSED(event),
        uint32_t UNUSED(request_id), void *private_data)
{
    sr_error_info_t *err_info = NULL;
    sr_priv_cand_t *privcand = private_data;
    const struct lyd_node *diff;
    struct lyd_node *reversed_diff;
    sr_error_t ret = SR_ERR_OK;

    /* obtain the diff of changes applied to the running datastore */
    diff = sr_get_change_diff(session);

    /* reverse the diff so it can undo the changes from running */
    if ((err_info = sr_lyd_diff_reverse_all(diff, &reversed_diff))) {
        goto cleanup;
    }

    /* merge the reversed changes */
    if ((err_info = sr_lyd_diff_merge_all(&reversed_diff, privcand->diff_backup))) {
        goto cleanup;
    }

    lyd_free_tree(privcand->diff_backup);
    privcand->diff_backup = reversed_diff;
    reversed_diff = NULL;

cleanup:
    lyd_free_all(reversed_diff);

    if (err_info) {
        sr_session_set_error_message(session, err_info->err[0].error_format);
        ret = err_info->err[0].err_code;
        sr_errinfo_free(&err_info);
    }

    return ret;
}

API int
sr_pc_create_ds(sr_session_ctx_t *session, uint32_t subscription_opts, sr_subscription_ctx_t **subscription, sr_priv_cand_t **privcand)
{
    sr_error_info_t *err_info = NULL;
    struct lys_module *mod;
    int write_access = 0;
    uint32_t index = 0;
    sr_datastore_t datastore;

    SR_CHECK_ARG_APIRET(!session || !privcand ||
            (!subscription && subscription_opts) ||
            (subscription && (subscription_opts && subscription_opts != SR_SUBSCR_NO_THREAD)),
            session, err_info);

    /* allocate and initialize the private candidate structure */
    *privcand = calloc(1, sizeof(**privcand));
    SR_CHECK_MEM_GOTO(!*privcand, err_info, cleanup);

    /* temporarily switch to the running datastore to subscribe */
    datastore = session->ds;
    session->ds = SR_DS_RUNNING;

    /* get the subscription for each module of the running datastore */
    while ((mod = ly_ctx_get_module_iter(sr_yang_ctx.ly_ctx, &index))) {

        /* skip unimplemented modules and internal "sysrepo" module */
        if (!mod->implemented || !strcmp(mod->name, "sysrepo")) {
            continue;
        }

        /* check access permissions for the module */
        if (sr_check_module_ds_access(session->conn, mod->name, session->ds, NULL, &write_access)) {
            goto cleanup;
        }

        if (!write_access) {
            continue;
        }

        /* subscribe to changes in the module to track modifications */
        if (subscription) {
            if (sr_module_change_subscribe(session, mod->name, NULL, pc_update_cb, *privcand, 0, subscription_opts | SR_SUBSCR_DONE_ONLY, subscription)) {
                goto cleanup;
            }
        } else {
            /* using SR_SUBSCR_PASSIVE here may not be what the user wants. */
            if (sr_module_change_subscribe(session, mod->name, NULL, pc_update_cb, *privcand, 0, SR_SUBSCR_PASSIVE | SR_SUBSCR_DONE_ONLY, &(*privcand)->subscription)) {
                goto cleanup;
            }
        }
    }

    /* restore the original datastore */
    session->ds = datastore;
    return sr_api_ret(session, err_info);

cleanup:
    /* clean up on error: unsubscribe from any modules */
    if ((*privcand)->subscription) {
        sr_unsubscribe((*privcand)->subscription);
    }
    /* restore the original datastore */
    session->ds = datastore;
    return sr_api_ret(session, err_info);
}

API void
sr_pc_set_conflict_resolution(sr_priv_cand_t *privcand, sr_pc_conflict_resolution_t new_conflict_resolution)
{
    if (!privcand) {
        return;
    }

    privcand->conflict_resolution = new_conflict_resolution;
}

API int
sr_pc_destroy_ds(sr_priv_cand_t *privcand)
{
    int ret = SR_ERR_OK;

    if (!privcand) {
        return ret;
    }

    lyd_free_all(privcand->diff_backup);
    lyd_free_all(privcand->diff_privcand);
    if (privcand->subscription) {
        ret = sr_unsubscribe(privcand->subscription);
    }

    free(privcand);

    return ret;
}

API void
sr_pc_free_conflicts(sr_pc_conflict_set_t *conflict_set)
{
    uint32_t i;

    if (!conflict_set) {
        return;
    }

    for (i = 0; i < conflict_set->conflict_count; i++) {
        lyd_free_all(conflict_set->conflicts[i].run_diff);
        lyd_free_all(conflict_set->conflicts[i].pc_diff);
    }

    free(conflict_set->conflicts);
    free(conflict_set);
}

/**
 * @brief Updates the private candidate datastore.
 *
 * This function reconstructs the current private candidate by:
 *   1. Replaying the original `diff_backup` to restore the initial state of the private candidate.
 *   2. Re-applying the changes from `diff_privcand` on top.
 *   3. Detecting and resolving conflicts with the current running datastore based on conflict resolution method.
 *
 *
 * @param[in] session Sysrepo session.
 * @param[in,out] privcand Private candidate structure to update.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
_sr_pc_update(sr_session_ctx_t *session, sr_priv_cand_t *privcand, sr_pc_conflict_set_t **conflict_set)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_s mod_info;
    struct lyd_node *tree_privcand = NULL, *backup_vs_running = NULL;

    /* init modinfo */
    sr_modinfo_init(&mod_info, session->conn, session->ds, session->ds, 0);

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
        return err_info;
    }

    /* adding all modules from diffs into mod_info*/
    if ((err_info = sr_modinfo_collect_edit(privcand->diff_backup, &mod_info)) ||
            (err_info = sr_modinfo_collect_edit(privcand->diff_privcand, &mod_info))) {
        goto cleanup;
    }

    if ((err_info = sr_modinfo_consolidate(&mod_info, SR_LOCK_READ, SR_MI_PERM_NO, session, 0, 0, 0))) {
        goto cleanup;
    }

    /* duplicate the running datastore to reconstruct the private candidate backup */
    if ((err_info = sr_lyd_dup(mod_info.data, NULL, LYD_DUP_RECURSIVE, 1, &tree_privcand))) {
        goto cleanup;
    }

    /* apply the backup diff to restore the running datastore state at the time of private candidate creation */
    if ((err_info = sr_lyd_diff_apply_all(&tree_privcand, privcand->diff_backup))) {
        goto cleanup;
    }

    if ((err_info = sr_lyd_diff_siblings(tree_privcand, mod_info.data, 0, NULL, &backup_vs_running))) {
        goto cleanup;
    }

    /* apply the private candidate diff to reconstruct the private candidate datastore */
    if ((err_info = sr_lyd_diff_apply_all(&tree_privcand, privcand->diff_privcand))) {
        goto cleanup;
    }

    /* new update will discard old conflicts */
    if (conflict_set && *conflict_set) {
        sr_pc_free_conflicts(*conflict_set);
        (*conflict_set) = NULL;
    }

    /* conflicts are stored only if conflict resolution is revert on conflict */
    if ((err_info = pc_generate_conflicts_r(privcand->diff_privcand, backup_vs_running, conflict_set))) {
        goto cleanup;
    }

    /* resolve conflicts between running and updated private candidate changes. */
    if ((err_info = pc_update_diff_privcand(mod_info.data, tree_privcand, privcand, conflict_set))) {
        goto cleanup;
    }

cleanup:
    lyd_free_all(backup_vs_running);
    lyd_free_all(tree_privcand);

    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);
    sr_modinfo_erase(&mod_info);

    /* CONTEXT UNLOCK */
    sr_lycc_unlock(session->conn, SR_LOCK_READ, 0, __func__);

    if (conflict_set && (*conflict_set)) {
        sr_errinfo_new(&err_info, SR_ERR_OPERATION_FAILED, "Update failed. Unresolved conflicts.");
    }

    return err_info;
}

API int
sr_pc_update(sr_session_ctx_t *session, sr_priv_cand_t *privcand, sr_pc_conflict_set_t **conflict_set)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session || !privcand, NULL, err_info);

    err_info = _sr_pc_update(session, privcand, conflict_set);

    return sr_api_ret(session, err_info);
}

API int
sr_pc_commit(sr_session_ctx_t *session, sr_priv_cand_t *privcand, sr_pc_conflict_set_t **conflict_set)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_s mod_info;
    struct lyd_node *tree_privcand = NULL;
    int ret = SR_ERR_OK;

    SR_CHECK_ARG_APIRET(!session || !privcand, NULL, err_info);

    /* if there are no changes in the private candidate diff, nothing to commit */
    if (!privcand->diff_privcand) {
        goto cleanup;
    }

    /* check for conflicts before committing */
    if ((err_info = _sr_pc_update(session, privcand, conflict_set))) {
        goto cleanup;
    }

    /* resolved conflicts can result in empty diff_pricand*/
    if (!privcand->diff_privcand) {
        goto cleanup;
    }

    /* initialize mod_info structure to collect affected modules for the commit */
    sr_modinfo_init(&mod_info, session->conn, session->ds, session->ds, 0);

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
        goto cleanup_unclock;
    }

    /* adding all modules from diffs into mod_info*/
    if ((err_info = sr_modinfo_collect_edit(privcand->diff_privcand, &mod_info))) {
        goto cleanup_unclock;
    }

    if ((err_info = sr_modinfo_consolidate(&mod_info, SR_LOCK_READ, SR_MI_PERM_NO, session, 0, 0, 0))) {
        goto cleanup_unclock;
    }

    tree_privcand = mod_info.data;
    mod_info.data = NULL;

    if ((err_info = sr_lyd_diff_apply_all(&tree_privcand, privcand->diff_privcand))) {
        goto cleanup_unclock;
    }

    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    sr_modinfo_erase(&mod_info);

    /* CONTEXT UNLOCK */
    sr_lycc_unlock(session->conn, SR_LOCK_READ, 0, __func__);

    /* prepare edit tree for commit */
    if ((ret = sr_edit_batch(session, tree_privcand, "replace"))) {
        goto cleanup;
    }

    /* perform the actual commit in the datastore */
    if ((ret = sr_apply_changes(session, 0))) {
        goto cleanup;
    }

    lyd_free_all(privcand->diff_backup);
    privcand->diff_backup = NULL;

    lyd_free_all(privcand->diff_privcand);
    privcand->diff_privcand = NULL;

    goto cleanup;

cleanup_unclock:
    sr_shmmod_modinfo_unlock(&mod_info);
    sr_modinfo_erase(&mod_info);

    /* CONTEXT UNLOCK */
    sr_lycc_unlock(session->conn, SR_LOCK_READ, 0, __func__);

    return sr_api_ret(session, err_info);
cleanup:
    lyd_free_all(tree_privcand);

    if (ret) {
        return ret;
    }

    return sr_api_ret(session, err_info);
}

API int
sr_pc_edit_config(sr_session_ctx_t *session, sr_priv_cand_t *privcand, const struct lyd_node *edit, const char *default_operation)
{
    sr_error_info_t *err_info = NULL, *err_info2 = NULL;
    struct sr_mod_info_s mod_info = {0};
    struct lyd_node *dup_edit = NULL, *root;
    struct lyd_node *final_diff = NULL;
    enum edit_op op;
    const struct lyd_node *iter;

    SR_CHECK_ARG_APIRET(!session || !privcand || !edit || !default_operation, NULL, err_info);
    SR_CHECK_ARG_APIRET(strcmp(default_operation, "merge") && strcmp(default_operation, "replace"), session, err_info);

    /* verify that nodes are top-level */
    LY_LIST_FOR(edit, iter) {
        if (lysc_data_parent(iter->schema)) {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Edit must be a top-level data tree.");
            return sr_api_ret(session, err_info);
        }
    }

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    if (sr_yang_ctx.ly_ctx != LYD_CTX(edit)) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Data trees must be created using the session connection libyang context.");
        goto cleanup;
    }

    if ((err_info = sr_lyd_dup(edit, NULL, LYD_DUP_RECURSIVE, 1, &dup_edit))) {
        goto cleanup;
    }

    LY_LIST_FOR(dup_edit, root) {
        /* check operations and set the default operation if none set */
        if (!(op = sr_edit_diff_find_oper(root, 0, NULL))) {
            if ((err_info = sr_edit_set_oper(root, default_operation))) {
                goto cleanup;
            }
        }
    }

    /**
     * creation of the final diff. After application to running datastore,
     * a private candidate datastores will be constructed
     */
    if ((err_info = sr_lyd_diff_merge_all(&final_diff, privcand->diff_backup)) ||
            (err_info = sr_lyd_diff_merge_all(&final_diff, privcand->diff_privcand))) {
        goto cleanup;
    }

    /* init modinfo */
    sr_modinfo_init(&mod_info, session->conn, session->ds, session->ds, 0);

    /* collect affected modules into mod_info */
    if ((err_info = sr_modinfo_collect_edit(dup_edit, &mod_info))) {
        goto cleanup;
    }

    if ((err_info = sr_modinfo_consolidate(&mod_info, SR_LOCK_READ, SR_MI_PERM_NO, session, 0, 0, 0))) {
        goto cleanup;
    }

    /* reconstruct private candidate state by applying final diff */
    if ((err_info = sr_lyd_diff_apply_all(&mod_info.data, final_diff))) {
        goto cleanup;
    }

    /* apply user changes to private candidate datastore*/
    if ((err_info = sr_modinfo_edit_apply(&mod_info, dup_edit, 1, &err_info2))) {
        goto cleanup;
    }

    if ((err_info = sr_modinfo_add_defaults(&mod_info, 1))) {
        goto cleanup;
    }

    /* save the changes into diff */
    if ((err_info = sr_lyd_diff_merge_all(&privcand->diff_privcand, mod_info.ds_diff))) {
        goto cleanup;
    }

cleanup:
    sr_shmmod_modinfo_unlock(&mod_info);
    sr_modinfo_erase(&mod_info);

    lyd_free_all(final_diff);
    lyd_free_all(dup_edit);

    /* CONTEXT UNLOCK */
    sr_lycc_unlock(session->conn, SR_LOCK_READ, 0, __func__);

    if (err_info2) {
        sr_errinfo_merge(&err_info, err_info2);
    }

    return sr_api_ret(session, err_info);
}

API int
sr_pc_discard_changes(sr_priv_cand_t *privcand) // dat void
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!privcand, NULL, err_info);

    lyd_free_all(privcand->diff_privcand);
    privcand->diff_privcand = NULL;

    return sr_api_ret(NULL, err_info);
}

API int
sr_pc_get_data (sr_session_ctx_t *session, const char *xpath, uint32_t max_depth, const uint32_t opts,
        sr_priv_cand_t *privcand, sr_data_t **data)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *final_diff = NULL;
    struct sr_mod_info_s mod_info;
    struct ly_set *set = NULL;

    SR_CHECK_ARG_APIRET(!privcand || !session || !xpath || !data, NULL, err_info);

    *data = NULL;

    /* init modinfo */
    sr_modinfo_init(&mod_info, session->conn, session->ds, session->ds, 0);

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    /**
     * creation of the final diff. After application to running datastore,
     * a private candidate datastores will be constructed
     */
    if ((err_info = sr_lyd_diff_merge_all(&final_diff, privcand->diff_backup))) {
        goto cleanup;
    }

    if ((err_info = sr_lyd_diff_merge_all(&final_diff, privcand->diff_privcand))) {
        goto cleanup;
    }

    if ((err_info = _sr_acquire_data(session->conn, NULL, data))) {
        goto cleanup;
    }

    if (final_diff) {
        if ((err_info = sr_modinfo_collect_edit(final_diff, &mod_info))) {
            goto cleanup;
        }
    } else {
        /* collect all required modules */
        if ((err_info = sr_modinfo_collect_xpath(sr_yang_ctx.ly_ctx, xpath, session->ds, session,
                MOD_INFO_XPATH_STORE_SESSION_CHANGES, &mod_info))) {
            goto cleanup;
        }
    }

    if ((err_info = sr_modinfo_consolidate(&mod_info, SR_LOCK_READ, SR_MI_PERM_NO, session, 0, 0, 0))) {
        goto cleanup;
    }

    /* apply changes to create private candidate ds */
    if ((err_info = sr_lyd_diff_apply_all(&mod_info.data, final_diff))) {
        goto cleanup;
    }

    if ((err_info = sr_modinfo_get_filter(&mod_info, (opts & SR_GET_NO_FILTER) ? "/*" : xpath, session,
            opts & SR_OPER_NO_NEW_CHANGES, &set))) {
        goto cleanup;
    }

    if ((err_info = sr_xpath_set_filter_subtrees(set))) {
        goto cleanup;
    }

    if ((err_info = sr_get_data_prune(session, &mod_info.data, set, max_depth, opts))) {
        goto cleanup;
    }

    (*data)->tree = mod_info.data;
    mod_info.data = NULL;

cleanup:
    lyd_free_all(final_diff);
    ly_set_free(set, NULL);

    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);
    sr_modinfo_erase(&mod_info);

    if (err_info || !(*data)->tree) {
        sr_release_data(*data);
        *data = NULL;
    }

    return sr_api_ret(session, err_info);
}
