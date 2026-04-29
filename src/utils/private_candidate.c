/**
 * @file private_candidate.c
 * @author Juraj Budai <budai@cesnet.cz>
 * @brief Implementation of private candidate datastore
 *
 * @copyright
 * Copyright (c) 2025 - 2026 Deutsche Telekom AG.
 * Copyright (c) 2025 - 2026 CESNET, z.s.p.o.
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
 * @param[in] src_tree Tree to search in.
 * @param[in] target Target node to find.
 * @param[out] match Found data node.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
pc_find_node_r(const struct lyd_node *src_tree, const struct lyd_node *target, struct lyd_node **match)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *common_child;

    /* try to find target node in top-level */
    if ((err_info = sr_lyd_find_sibling_first(src_tree, target, match))) {
        goto cleanup;
    }

    /* the target node nested somewhere in src_tree*/
    if (!*match) {
        /* find common parent */
        if ((err_info = pc_find_node_r(src_tree, target->parent, match))) {
            goto cleanup;
        }

        /* traverse down from the common parent to the target node */
        common_child = lyd_child_no_keys(*match);

        if ((err_info = sr_lyd_find_sibling_first(common_child, target, match))) {
            goto cleanup;
        }
    }

cleanup:
    return err_info;
}

/**
 * @brief Find and unlink subtree based on target node.
 *
 * @param[in] target_node Node to search for in the source diff tree.
 * @param[in,out] source_diff Diff tree where the unlink happens. May be updated if the removed node was the first sibling.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
pc_find_and_unlink_node(const struct lyd_node *target_node, struct lyd_node **source_diff)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *match = NULL;

    if ((err_info = pc_find_node_r(*source_diff, target_node, &match))) {
        goto cleanup;
    }

    sr_lyd_free_tree_safe(match, source_diff);

cleanup:
    return err_info;
}

/**
 * @brief Store a conflict between candidate and running datastore nodes.
 *
 * @param[in] cand_node Conflicting node from the private candidate datastore.
 * @param[in] run_node Conflicting node from the running datastore.
 * @param[in] conflict_resolution Conflict resolution strategy.
 * @param[in] type Type of conflict.
 * @param[in] dup Wheter to duplicate @p run_node and @p cand_node into conflicts.
 *                If zero, the function will assign pointers without duplication.
 * @param[out] conflict_set List of conflicts to store into.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
pc_add_conflict(struct lyd_node *cand_node, struct lyd_node *run_node, sr_pc_conflict_resolution_t conflict_resolution,
        sr_pc_conflict_type_t type, int dup, sr_pc_conflict_set_t **conflict_set)
{
    sr_error_info_t *err_info = NULL;
    sr_pc_conflict_info_t *c_info = NULL, *tmp;

    /* no need to store conflicts for other resolutions */
    if (conflict_resolution != SR_PC_REVERT_ON_CONFLICT) {
        goto cleanup;
    }

    if (conflict_set && !(*conflict_set)) {
        *conflict_set = calloc(1, sizeof(**conflict_set));
        SR_CHECK_MEM_GOTO(!(*conflict_set), err_info, cleanup);
    }

    /* allocate memory for new conflicts */
    tmp = realloc((*conflict_set)->conflicts, ((*conflict_set)->conflict_count + 1) * sizeof *tmp);
    SR_CHECK_MEM_GOTO(!tmp, err_info, cleanup);

    (*conflict_set)->conflicts = tmp;
    c_info = &(*conflict_set)->conflicts[(*conflict_set)->conflict_count];
    memset(c_info, 0, sizeof *c_info);

    /*
     * Save the conflicting trees into the conflict structure.
     *
     * For user-ordered lists (dup = 0), the diff nodes are already
     * allocated in the correct sibling structure, so we can simply assign
     * the pointers without duplicating the data.
     */
    if (dup) {
        if ((err_info = sr_lyd_dup(run_node, NULL, LYD_DUP_WITH_PARENTS, 0, &c_info->run_diff))) {
            goto cleanup;
        }

        if ((err_info = sr_lyd_dup(cand_node, NULL, LYD_DUP_WITH_PARENTS, 0, &c_info->pc_diff))) {
            goto cleanup;
        }
    } else {
        c_info->run_diff = run_node;
        c_info->pc_diff = cand_node;
    }

    c_info->type = type;

    (*conflict_set)->conflict_count++;

cleanup:
    if (err_info) {
        if (dup) {
            if (c_info) {
                lyd_free_all(c_info->run_diff);
                lyd_free_all(c_info->pc_diff);
            }
        } else {
            lyd_free_all(run_node);
            lyd_free_all(cand_node);
        }
    }

    return err_info;
}

/**
 * @brief Determine the specific type of conflict between candidate and running nodes.
 *
 * @param[in] node_type YANG schema node type.
 * @param[in] cand_op Diff operation applied to the candidate node.
 * @param[in] run_op Diff operation applied to the running node.
 * @return sr_pc_conflict_type_t The specific type of conflict identified between the two nodes.
 */
static sr_pc_conflict_type_t
pc_get_conflict_type(uint16_t node_type, enum edit_op cand_op, enum edit_op run_op)
{
    switch (node_type) {
    case LYS_LIST:
        if ((cand_op == EDIT_REPLACE) && (run_op == EDIT_REPLACE)) {
            return SR_PC_CONFLICT_LIST_ORDER;
        }
        return SR_PC_CONFLICT_LIST_ENTRY;

    case LYS_LEAF:
        if ((cand_op == EDIT_REPLACE) && (run_op == EDIT_REPLACE)) {
            return SR_PC_CONFLICT_VALUE_CHANGE;
        }
        return SR_PC_CONFLICT_LEAF_EXISTENCE;

    case LYS_LEAFLIST:
        if ((cand_op == EDIT_REPLACE) && (run_op == EDIT_REPLACE)) {
            return SR_PC_CONFLICT_LEAFLIST_ORDER;
        }
        return SR_PC_CONFLICT_LEAFLIST_ITEM;

    case LYS_ANYDATA:
    case LYS_ANYXML:
        return SR_PC_CONFLICT_VALUE_CHANGE;

    case LYS_CONTAINER:
        return SR_PC_CONFLICT_PRESENCE_CONTAINER;

    default:
        assert(0);
        break;
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
 * @param[in] src Source data node to duplicate.
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
 * @brief Categorize nodes based on relevance to the conflict.
 *
 * - Nodes from @p run_diff are separated into:
 *      - @p list_entry_siblings : nodes representing create/delete operations.
 *      - @p list_order_siblings : nodes representing ordering modifications.
 * - Nodes from @p cand_diff that participate in the conflict are duplicated into
 *      - @p cand_conflict_siblings.
 *
 * @param[in] run_diff Running datastore's diff subtree.
 * @param[in] cand_diff Candidate's diff subtree.
 * @param[out] list_entry_siblings Siblings that cause list entry conflict.
 * @param[out] list_order_siblings Siblings that cause list order conflict.
 * @param[out] cand_conflict_siblings Siblings that are part of the detected conflict.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
pc_userord_conflict_types(struct lyd_node *run_diff, struct lyd_node *cand_diff, struct lyd_node **list_entry_siblings,
        struct lyd_node **list_order_siblings, struct lyd_node **cand_conflict_siblings)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *iter;
    const struct lysc_node *current_schema;
    enum edit_op node_op;

    *list_entry_siblings = NULL;
    *list_order_siblings = NULL;
    *cand_conflict_siblings = NULL;

    /* sort individual nodes into categories based on conflict */
    current_schema = run_diff->schema;
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
            if ((err_info = pc_dup_and_insert(run_diff, list_entry_siblings))) {
                goto cleanup;
            }
        } else {
            assert(node_op == EDIT_REPLACE);
            if ((err_info = pc_dup_and_insert(run_diff, list_order_siblings))) {
                goto cleanup;
            }
        }
    }

    /* skip nodes with operation none, unwanted in list/leaflist conflict */
    current_schema = cand_diff->schema;
    LY_LIST_FOR_SAFE(cand_diff, iter, cand_diff){
        if (cand_diff->schema != current_schema) {
            break;
        }

        node_op = sr_edit_diff_find_oper(cand_diff, 0, NULL);

        if (node_op == EDIT_NONE) {
            continue;
        }

        if ((err_info = pc_dup_and_insert(cand_diff, cand_conflict_siblings))) {
            goto cleanup;
        }
    }

cleanup:
    if (err_info) {
        lyd_free_all(*list_entry_siblings);
        list_entry_siblings = NULL;
        lyd_free_all(*list_order_siblings);
        list_order_siblings = NULL;
        lyd_free_all(*cand_conflict_siblings);
        cand_conflict_siblings = NULL;
    }

    return err_info;
}

/**
 * @brief Handle user-ordered list conflicts between running and candidate diffs according to the selected conflict
 * resolution mode.
 *
 * @param[in] run_diff Running datastore's diff subtree.
 * @param[in,out] cand_diff Candidate's diff subtree.
 * @param[in] conflict_resolution Conflict resolution strategy.
 * @param[out] conflict_set List of conflicts which are not resolved yet.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
pc_process_userord_conflict(struct lyd_node *run_diff, struct lyd_node **cand_diff,
        sr_pc_conflict_resolution_t conflict_resolution, sr_pc_conflict_set_t **conflict_set)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *tmp, *list_entry_siblings = NULL, *list_order_siblings = NULL;
    struct lyd_node *cand_conflict_siblings = NULL, *cand_conflict_siblings_dup = NULL;
    struct lyd_node *iter, *next;
    enum edit_op op;

    switch (conflict_resolution) {
    case SR_PC_REVERT_ON_CONFLICT:
        /* sort nodes into categories based on conflict they cause */
        if ((err_info = pc_userord_conflict_types(run_diff, *cand_diff, &list_entry_siblings, &list_order_siblings,
                &cand_conflict_siblings))) {
            goto cleanup;
        }

        /* create a duplicate for the second conflict only if we have both conflicts */
        if (list_entry_siblings && list_order_siblings) {
            if ((err_info = sr_lyd_dup(cand_conflict_siblings, NULL, LYD_DUP_WITH_PARENTS, 1, &cand_conflict_siblings_dup))) {
                goto cleanup;
            }
        }

        if (list_order_siblings) {
            if ((err_info = pc_add_conflict(cand_conflict_siblings, list_order_siblings, conflict_resolution,
                    pc_get_conflict_type(run_diff->schema->nodetype, EDIT_REPLACE, EDIT_REPLACE), 0, conflict_set))) {
                goto cleanup;
            }
        }

        if (list_entry_siblings) {
            /* use the duplicate only if it exists, otherwise use the original node */
            tmp = cand_conflict_siblings_dup ? cand_conflict_siblings_dup : cand_conflict_siblings;
            if ((err_info = pc_add_conflict(tmp, list_entry_siblings, conflict_resolution,
                    pc_get_conflict_type(run_diff->schema->nodetype, EDIT_CREATE, EDIT_CREATE), 0, conflict_set))) {
                goto cleanup;
            }
        }

        cand_conflict_siblings_dup = NULL;
        break;
    case SR_PC_PREFER_RUNNING:
        LY_LIST_FOR_SAFE(*cand_diff, next, iter) {
            /* conflicting node is removed from private candidate diff */
            if (run_diff->schema == iter->schema) {
                op = sr_edit_diff_find_oper(iter, 0, NULL);
                if ((op != EDIT_NONE) && (op != 0)) {
                    sr_lyd_free_tree_safe(iter, cand_diff);
                }
            } else {
                break;
            }
        }
        break;
    case SR_PC_PREFER_CANDIDATE:
        /* no conflict handling is needed here because the running configuration changes are ignored */
        break;
    default:
        assert(0);
        break;
    }

cleanup:
    lyd_free_all(cand_conflict_siblings_dup);

    return err_info;
}

/**
 * @brief Handle conflicts unrelated to user-ordered lists between running and candidate diffs according to the selected
 * conflict resolution mode.
 *
 * @param[in] run_diff Running datastore's diff subtree.
 * @param[in,out] cand_diff Candidate's diff subtree.
 * @param[in] cand_op Diff operation applied to the candidate node.
 * @param[in] run_op Diff operation applied to the running node.
 * @param[in] conflict_resolution Conflict resolution strategy.
 * @param[out] conflict_set List of conflicts which are not resolved yet.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
pc_resolve_conflict(struct lyd_node *run_diff, struct lyd_node **cand_diff, enum edit_op run_op, enum edit_op cand_op,
        sr_pc_conflict_resolution_t conflict_resolution, sr_pc_conflict_set_t **conflict_set)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *remove_node;

    /* no need to store conflicts besides revert_on_conflcit */
    switch (conflict_resolution) {
    case SR_PC_REVERT_ON_CONFLICT:
        if ((err_info = pc_add_conflict(*cand_diff, run_diff, conflict_resolution,
                pc_get_conflict_type(run_diff->schema->nodetype, cand_op, run_op), 1, conflict_set))) {
            goto cleanup;
        }
        break;
    case SR_PC_PREFER_RUNNING:
        /* conflicting node is removed from private candidate diff */
        remove_node = *cand_diff;
        *cand_diff = (*cand_diff)->next;
        lyd_free_tree(remove_node);
        break;
    case SR_PC_PREFER_CANDIDATE:
        /* no conflict handling is needed here because the running configuration changes are ignored */
        break;
    default:
        assert(0);
        break;
    }

cleanup:
    return err_info;
}

/**
 * @brief Process list and leaf-list nodes of the same schema from running and candidate diff subtrees and resolve
 * or store conflicts according to the conflict resolution mode.
 *
 * @param[in] run_diff Running datastore's diff subtree.
 * @param[in,out] cand_diff Candidate's diff subtree.
 * @param[in] cand_iter Node form cand_diff where the conflict occurs.
 * @param[in] run_op Diff operation applied to the running node.
 * @param[in] cand_op Diff operation applied to the candidate node.
 * @param[in,out] userord_conflict_stored Flag whether userdered list conflict was stored.
 * @param[in] conflict_resolution Conflict resolution strategy.
 * @param[out] conflict_set List of conflicts.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
pc_process_diff_trees_lists(struct lyd_node **run_diff, struct lyd_node **cand_diff, struct lyd_node *cand_iter,
        enum edit_op run_op, enum edit_op cand_op, int *userord_conflict_stored,
        sr_pc_conflict_resolution_t conflict_resolution, sr_pc_conflict_set_t **conflict_set)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node **cand_target;

    if (!lysc_is_userordered((*run_diff)->schema)) {
        cand_target = (cand_iter == *cand_diff) ? cand_diff : &cand_iter;
        if ((err_info = pc_resolve_conflict(*run_diff, cand_target, run_op, cand_op, conflict_resolution, conflict_set))) {
            goto cleanup;
        }
        goto cleanup;
    }

    /* process the whole userordered conflict */
    if (!*userord_conflict_stored) {
        /* move to the first sibling of the same schema */
        if ((err_info = sr_lyd_find_sibling_val(cand_iter, (*run_diff)->schema, NULL, &cand_iter))) {
            goto cleanup;
        }

        cand_target = (cand_iter == *cand_diff) ? cand_diff : &cand_iter;
        if ((err_info = pc_process_userord_conflict(*run_diff, cand_target, conflict_resolution, conflict_set))) {
            goto cleanup;
        }

        /* no more siblings of the same schema or schema changed */
        if (!*cand_target || ((*cand_target)->schema != (*run_diff)->schema)) {
            *userord_conflict_stored = 0;
            goto cleanup;
        }

        *userord_conflict_stored = 1;
    } else {
        /* skip conflicting nodes */
        while (*run_diff && (*run_diff)->next) {
            /* stop if the next node belongs to a different schema */
            if ((*run_diff)->next->schema != (*run_diff)->schema) {
                *userord_conflict_stored = 0;
                break;
            }

            run_op = sr_edit_diff_find_oper((*run_diff)->next, 0, NULL);

            /* the parent node was modified in one datastore, while in the other datastore the modification
             * happened on its child, this conflict is processed elsewhere */
            if (run_op == EDIT_NONE) {
                break;
            }

            *run_diff = (*run_diff)->next;
        }
    }

cleanup:
    return err_info;
}

/**
 * @brief Recursively process running and candidate diffs, detect conflicts, and resolve or store them according to the
 * conflict resolution mode.
 *
 * @param[in] run_diff Running datastore's diff tree.
 * @param[in,out] cand_diff Candidate's diff tree.
 * @param[in] privcand Private candidate datastore structure.
 * @param[in] conflict_resolution Conflict resolution strategy.
 * @param[out] conflict_set List of conflicts which are not resolved yet.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
pc_process_diff_trees_r(const struct lyd_node *run_diff, struct lyd_node **cand_diff, sr_priv_cand_t *privcand,
        sr_pc_conflict_resolution_t conflict_resolution, sr_pc_conflict_set_t **conflict_set)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *cand_iter = NULL, *run_iter, *cand_child, **cand_target;
    enum edit_op run_op, cand_op;
    int skip_outer_loop = 0, userord_conflict_stored = 0;

    LY_LIST_FOR((struct lyd_node *)run_diff, run_iter) {
        if (run_iter->schema->nodetype & (LYS_LIST | LYS_LEAFLIST)) {
            if ((err_info = sr_lyd_find_sibling_first(*cand_diff, run_iter, &cand_iter))) {
                goto cleanup;
            }
        } else {
            if ((err_info = sr_lyd_find_sibling_val(*cand_diff, run_iter->schema, NULL, &cand_iter))) {
                goto cleanup;
            }
        }

        /* determine edit operations for both nodes */
        run_op = sr_edit_diff_find_oper(run_iter, 0, NULL);
        cand_op = sr_edit_diff_find_oper(cand_iter, 0, NULL);

        /* no conflict in unchanged node continue with its child */
        if (((run_op == EDIT_NONE) || (run_op == 0)) && (((cand_op == EDIT_NONE) || (cand_op == 0)))) {
            if (cand_iter && (run_iter->schema->nodetype & LYD_NODE_INNER)) {
                cand_child = lyd_child_no_keys(cand_iter);
                if ((err_info = pc_process_diff_trees_r(lyd_child_no_keys(run_iter), &cand_child, privcand,
                        conflict_resolution, conflict_set))) {
                    goto cleanup;
                }
            } else {
                /* removing the node from diff_run means the original running datastore value will be used implicitly */
                if ((err_info = pc_find_and_unlink_node(run_iter, &privcand->diff_run))) {
                    goto cleanup;
                }
            }
            continue;
        } else if ((((run_op == EDIT_NONE) || (run_op == 0)) && (cand_iter && (cand_op == EDIT_DELETE))) ||
                ((run_op == EDIT_DELETE) && (cand_iter && ((cand_op == EDIT_NONE) || (cand_op == 0))))) {
            /* the parent node was deleted in one datastore, while in the other datastore the modification happened on its child */
            if (run_iter->schema->nodetype & LYD_NODE_INNER) {
                if (conflict_resolution == SR_PC_REVERT_ON_CONFLICT) {
                    cand_child = lyd_child_no_keys(cand_iter);
                    if ((err_info = pc_process_diff_trees_r(lyd_child_no_keys(run_iter), &cand_child, privcand,
                            conflict_resolution, conflict_set))) {
                        goto cleanup;
                    }
                } else {
                    /* no need to find child where conflict occurs */
                    if ((err_info = pc_resolve_conflict(run_iter, cand_diff, run_op, cand_op, conflict_resolution,
                            conflict_set))) {
                        goto cleanup;
                    }
                    cand_iter = NULL;
                }
                continue;
            }
        }

        /* handle conflicts based on the type of the node */
        switch (run_iter->schema->nodetype) {
        case LYS_LIST:
        case LYS_LEAFLIST:

            /* finding node based on value was not successful, try to find node based on schema */
            if (!cand_iter) {
                if ((err_info = sr_lyd_find_sibling_val(*cand_diff, run_iter->schema, NULL, &cand_iter))) {
                    goto cleanup;
                }
                cand_op = sr_edit_diff_find_oper(cand_iter, 0, NULL);
            }

            if (!cand_iter) {
                /* there is no conflict. Removing the node from diff_run means the original running datastore value will
                 * be used implicitly */
                if ((err_info = pc_find_and_unlink_node(run_iter, &privcand->diff_run))) {
                    goto cleanup;
                }
                break;
            }

            /* skip the nodes that do not cause the conflict till the new schema node */
            while (cand_iter && ((cand_op == 0) || (cand_op == EDIT_NONE))) {
                if (cand_iter->next && (cand_iter->next->schema == run_iter->schema)) {
                    cand_iter = cand_iter->next;
                    cand_op = sr_edit_diff_find_oper(cand_iter, 0, NULL);
                } else {
                    /* there is no other node with same schema */
                    skip_outer_loop = 1;
                    break;
                }
            }

            if (skip_outer_loop) {
                /* there is no conflict, continue */
                if ((err_info = pc_find_and_unlink_node(run_iter, &privcand->diff_run))) {
                    goto cleanup;
                }
                skip_outer_loop = 0;
                break;
            }

            if ((err_info = pc_process_diff_trees_lists(&run_iter, cand_diff, cand_iter, run_op, cand_op,
                    &userord_conflict_stored, conflict_resolution, conflict_set))) {
                goto cleanup;
            }

            break;
        case LYS_CONTAINER:
        case LYS_LEAF:
        case LYS_ANYDATA:
        case LYS_ANYXML:
            if (!cand_iter) {
                /* there is no conflict */
                if ((err_info = pc_find_and_unlink_node(run_iter, &privcand->diff_run))) {
                    goto cleanup;
                }
                break;
            }

            cand_target = (cand_iter == *cand_diff) ? cand_diff : &cand_iter;
            if ((err_info = pc_resolve_conflict(run_iter, cand_target, run_op, cand_op, conflict_resolution, conflict_set))) {
                goto cleanup;
            }

            break;
        default:
            assert(0);
            /* should never happen */
            break;
        }
    }

cleanup:
    return err_info;
}

/**
 * @brief Update private candidate datastore structure.
 *
 * @param[in,out] privcand Private candidate datastore structure.
 * @param[in] conflict_resolution Conflict resolution strategy.
 * @param[in,out] conflict_set List of conflicts which will be resolved.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
pc_update_diff_privcand(sr_priv_cand_t *privcand, sr_pc_conflict_resolution_t conflict_resolution,
        sr_pc_conflict_set_t **conflict_set)
{
    sr_error_info_t *err_info = NULL;

    /* user resolves the conflicts by himself */
    if ((conflict_resolution == SR_PC_REVERT_ON_CONFLICT) && conflict_set && (*conflict_set)) {
        goto cleanup;
    }

    /* already up to date */
    if ((conflict_resolution == SR_PC_REVERT_ON_CONFLICT) && !privcand->diff_run) {
        goto cleanup;
    }

    switch (conflict_resolution) {
    case SR_PC_PREFER_RUNNING:
        lyd_free_all(privcand->diff_run);
        privcand->diff_run = NULL;
        break;
    case SR_PC_REVERT_ON_CONFLICT:
    /* there is not a single node in conflict, merge datastores */
    case SR_PC_PREFER_CANDIDATE:
        if ((err_info = sr_lyd_diff_merge_all(&privcand->diff_run, privcand->diff_privcand))) {
            goto cleanup;
        }
        lyd_free_all(privcand->diff_privcand);
        privcand->diff_privcand = privcand->diff_run;
        privcand->diff_run = NULL;
        break;
    default:
        /* should never happen */
        assert(0);
        break;
    }

cleanup:
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
        const char *UNUSED(xpath), sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *private_data)
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
    if ((err_info = sr_lyd_diff_merge_all(&reversed_diff, privcand->diff_run))) {
        goto cleanup;
    }

    lyd_free_tree(privcand->diff_run);
    privcand->diff_run = reversed_diff;
    reversed_diff = NULL;

cleanup:
    lyd_free_all(reversed_diff);

    if (err_info) {
        sr_session_set_error_message(session, err_info->err[0].message);
        ret = err_info->err[0].err_code;
        sr_errinfo_free(&err_info);
    }

    return ret;
}

API int
sr_pc_create_ds(sr_session_ctx_t *session, uint32_t subscription_opts, sr_subscription_ctx_t **subscription,
        sr_priv_cand_t **privcand)
{
    sr_error_info_t *err_info = NULL;
    struct lys_module *mod;
    int write_access = 0;
    uint32_t index = 0;
    sr_datastore_t datastore;
    int ret = SR_ERR_OK;

    SR_CHECK_ARG_APIRET(!session || !privcand ||
            (!subscription && subscription_opts) ||
            (subscription && (subscription_opts && subscription_opts != SR_SUBSCR_NO_THREAD)),
            session, err_info);

    /* backup datastore */
    datastore = session->ds;

    /* allocate and initialize the private candidate structure */
    *privcand = calloc(1, sizeof(**privcand));
    SR_CHECK_MEM_GOTO(!*privcand, err_info, cleanup);

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
        goto cleanup;
    }

    (*privcand)->has_ctx_lock = 1;

    /* temporarily switch to the running datastore to subscribe */
    session->ds = SR_DS_RUNNING;

    /* get the subscription for each module of the running datastore */
    while ((mod = ly_ctx_get_module_iter(sr_yang_ctx.ly_ctx, &index))) {

        /* skip unimplemented modules and internal "sysrepo" module */
        if (!mod->implemented || !strcmp(mod->name, "sysrepo")) {
            continue;
        }

        /* skip mudules that has no data */
        if (!sr_module_has_data(mod, 0)) {
            continue;
        }

        /* check access permissions for the module */
        if (sr_check_module_ds_access(session->conn, mod->name, session->ds, NULL, &write_access)) {
            goto cleanup;
        }

        if (!write_access) {
            continue;
        }

        /* subscribe to changes in the module to track modifications
         * using SR_SUBSCR_PASSIVE here may not be what the user wants.
         */
        if (subscription) {
            if ((ret = sr_module_change_subscribe(session, mod->name, NULL, pc_update_cb, *privcand, 0,
                    subscription_opts | SR_SUBSCR_DONE_ONLY, subscription))) {
                goto cleanup;
            }
        } else {
            if ((ret = sr_module_change_subscribe(session, mod->name, NULL, pc_update_cb, *privcand, 0,
                    SR_SUBSCR_PASSIVE | SR_SUBSCR_DONE_ONLY, &(*privcand)->subscription))) {
                goto cleanup;
            }
        }
    }

cleanup:
    /* clean up on error: unsubscribe from any modules */
    if ((err_info || ret) && *privcand) {
        sr_pc_destroy_ds(session, *privcand);
        (*privcand) = NULL;
    }

    /* restore the original datastore */
    session->ds = datastore;
    return ret ? ret : sr_api_ret(session, err_info);
}

API int
sr_pc_destroy_ds(sr_session_ctx_t *session, sr_priv_cand_t *privcand)
{
    sr_error_info_t *err_info = NULL;
    int ret = SR_ERR_OK;

    SR_CHECK_ARG_APIRET(!session, session, err_info);

    if (!privcand) {
        return ret;
    }

    if (privcand->subscription) {
        if ((ret = sr_unsubscribe(privcand->subscription))) {
            goto cleanup;
        }
    }

    lyd_free_all(privcand->diff_run);
    lyd_free_all(privcand->diff_privcand);

    if (privcand->has_ctx_lock) {
        /* CONTEXT UNLOCK */
        sr_lycc_unlock(session->conn, SR_LOCK_READ, 0, __func__);
    }

    free(privcand);

cleanup:
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
 * @param[in,out] privcand Private candidate structure to update.
 * @param[in] conflict_resolution Conflict resolution strategy.
 * @param[out] conflict_set List of conflicts.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
_sr_pc_update(sr_priv_cand_t *privcand, sr_pc_conflict_resolution_t conflict_resolution, sr_pc_conflict_set_t **conflict_set)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *running_changes_diff = NULL;
    struct lyd_node *diff_run_backup = NULL, *diff_privcand_backup = NULL;

    /* new update will discard old conflicts */
    if (conflict_set && *conflict_set) {
        sr_pc_free_conflicts(*conflict_set);
        (*conflict_set) = NULL;
    }

    /* avoid unnecessary processing if no changes were made in the private candidate */
    if (!privcand->diff_privcand) {
        lyd_free_all(privcand->diff_run);
        privcand->diff_run = NULL;
        goto cleanup;
    }

    if ((err_info = sr_lyd_diff_reverse_all(privcand->diff_run, &running_changes_diff))) {
        goto cleanup;
    }

    if ((conflict_resolution == SR_PC_REVERT_ON_CONFLICT) && privcand->diff_run) {
        if ((err_info = sr_lyd_dup(privcand->diff_privcand, NULL, LYD_DUP_RECURSIVE, 1, &diff_privcand_backup))) {
            goto cleanup;
        }

        if ((err_info = sr_lyd_dup(privcand->diff_run, NULL, LYD_DUP_RECURSIVE, 1, &diff_run_backup))) {
            goto cleanup;
        }
    }

    /* prepare running and private candidate diff for merge */
    if ((err_info = pc_process_diff_trees_r(running_changes_diff, &privcand->diff_privcand, privcand, conflict_resolution,
            conflict_set))) {
        goto cleanup;
    }

    if (!(conflict_set && (*conflict_set))) {
        if ((err_info = pc_update_diff_privcand(privcand, conflict_resolution, conflict_set))) {
            goto cleanup;
        }
    } else {
        /* conflicts were found revert the state of run and cand diffs */
        lyd_free_all(privcand->diff_privcand);
        lyd_free_all(privcand->diff_run);
        privcand->diff_privcand = diff_privcand_backup;
        privcand->diff_run = diff_run_backup;
        diff_privcand_backup = NULL;
        diff_run_backup = NULL;
    }

cleanup:
    if (conflict_set && (*conflict_set)) {
        sr_errinfo_new(&err_info, SR_ERR_OPERATION_FAILED, "Update failed, there are unresolved conflicts.");
    }

    lyd_free_all(diff_privcand_backup);
    lyd_free_all(diff_run_backup);
    lyd_free_all(running_changes_diff);

    return err_info;
}

API int
sr_pc_update(sr_session_ctx_t *session, sr_priv_cand_t *privcand, sr_pc_conflict_resolution_t conflict_resolution,
        sr_pc_conflict_set_t **conflict_set)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!privcand || !conflict_set, NULL, err_info);

    err_info = _sr_pc_update(privcand, conflict_resolution, conflict_set);

    return sr_api_ret(session, err_info);
}

API int
sr_pc_commit(sr_session_ctx_t *session, sr_priv_cand_t *privcand, sr_pc_conflict_set_t **conflict_set)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_s mod_info;
    struct lyd_node *tree_privcand = NULL;
    sr_datastore_t datastore;
    int ret = SR_ERR_OK;

    SR_CHECK_ARG_APIRET(!session || !privcand || !conflict_set, NULL, err_info);

    /* backup datastore */
    datastore = session->ds;

    /* temporarily switch to the running datastore */
    session->ds = SR_DS_RUNNING;

    /* if there are no changes in the private candidate diff, nothing to commit */
    if (!privcand->diff_privcand) {
        goto cleanup;
    }

    /* check for conflicts before committing, implicit <update> operation always has a resolution of revert_on_conflict */
    if ((err_info = _sr_pc_update(privcand, SR_PC_REVERT_ON_CONFLICT, conflict_set))) {
        goto cleanup;
    }

    /* resolved conflicts can result in empty diff_pricand */
    if (!privcand->diff_privcand) {
        goto cleanup;
    }

    /* initialize mod_info structure to collect affected modules for the commit */
    sr_modinfo_init(&mod_info, session->conn, session->ds, session->ds, 0);

    /* adding all modules from diffs into mod_info */
    if ((err_info = sr_modinfo_collect_edit(privcand->diff_privcand, &mod_info))) {
        goto cleanup_unlock;
    }

    if ((err_info = sr_modinfo_consolidate(&mod_info, SR_LOCK_READ, SR_MI_PERM_NO, session, 0, 0, 0))) {
        goto cleanup_unlock;
    }

    tree_privcand = mod_info.data;
    mod_info.data = NULL;

    if ((err_info = sr_lyd_diff_apply_all(&tree_privcand, privcand->diff_privcand))) {
        goto cleanup_unlock;
    }

    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    sr_modinfo_erase(&mod_info);

    /* prepare edit tree for commit */
    if ((ret = sr_edit_batch(session, tree_privcand, "replace"))) {
        goto cleanup;
    }

    /* perform the actual commit in the datastore */
    if ((ret = sr_apply_changes(session, 0))) {
        goto cleanup;
    }

    goto cleanup;

cleanup_unlock:
    sr_shmmod_modinfo_unlock(&mod_info);
    sr_modinfo_erase(&mod_info);

cleanup:
    lyd_free_all(tree_privcand);
    lyd_free_all(privcand->diff_run);
    privcand->diff_run = NULL;
    lyd_free_all(privcand->diff_privcand);
    privcand->diff_privcand = NULL;
    /* restore the original datastore */
    session->ds = datastore;

    return ret ? ret : sr_api_ret(session, err_info);
}

API int
sr_pc_edit_config(sr_session_ctx_t *session, sr_priv_cand_t *privcand, const struct lyd_node *edit,
        const char *default_operation)
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

    /* creation of the final diff. After application to running datastore,
     * a private candidate datastores will be constructed */
    if ((err_info = sr_lyd_diff_merge_all(&final_diff, privcand->diff_run)) ||
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

    /* apply user changes to private candidate datastore */
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

    if (err_info2) {
        sr_errinfo_merge(&err_info, err_info2);
    }

    return sr_api_ret(session, err_info);
}

API void
sr_pc_discard_changes(sr_priv_cand_t *privcand)
{
    if (!privcand || !privcand->diff_privcand) {
        return;
    }

    lyd_free_all(privcand->diff_privcand);
    privcand->diff_privcand = NULL;
}

API int
sr_pc_get_data(sr_session_ctx_t *session, const char *xpath, uint32_t max_depth, const uint32_t opts,
        const sr_priv_cand_t *privcand, sr_data_t **data)
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

    /* creation of the final diff. After application to running datastore,
     * a private candidate datastores will be constructed */
    if ((err_info = sr_lyd_diff_merge_all(&final_diff, privcand->diff_run))) {
        goto cleanup;
    }

    if ((err_info = sr_lyd_diff_merge_all(&final_diff, privcand->diff_privcand))) {
        goto cleanup;
    }

    if ((err_info = _sr_acquire_data(session->conn, NULL, data))) {
        goto cleanup;
    }

    /* collect all required modules */
    if ((err_info = sr_modinfo_collect_xpath(sr_yang_ctx.ly_ctx, xpath, session->ds, session,
            MOD_INFO_XPATH_STORE_SESSION_CHANGES, &mod_info))) {
        goto cleanup;
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

API int
sr_pc_backup_privcand(sr_session_ctx_t *session, sr_priv_cand_t *privcand, sr_priv_cand_t **privcand_backup)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session || !privcand || !privcand_backup, session, err_info);

    *privcand_backup = calloc(1, sizeof(**privcand_backup));
    SR_CHECK_MEM_GOTO(!*privcand_backup, err_info, cleanup);

    /* subscription is not copied */
    (*privcand_backup)->subscription = NULL;

    if (privcand->diff_run) {
        if ((err_info = sr_lyd_dup(privcand->diff_run, NULL, LYD_DUP_RECURSIVE, 1, &(*privcand_backup)->diff_run))) {
            goto cleanup;
        }
    }

    if (privcand->diff_privcand) {
        if ((err_info = sr_lyd_dup(privcand->diff_privcand, NULL, LYD_DUP_RECURSIVE, 1, &(*privcand_backup)->diff_privcand))) {
            goto cleanup;
        }
    }

cleanup:
    return sr_api_ret(session, err_info);
}

API void
sr_pc_restore_privcand(sr_priv_cand_t *privcand_backup, sr_priv_cand_t *privcand_target)
{
    if (!privcand_backup || !privcand_target) {
        return;
    }

    /* free the existing data in the target */
    lyd_free_all(privcand_target->diff_run);
    lyd_free_all(privcand_target->diff_privcand);

    /* replace the data in the target */
    privcand_target->diff_run = privcand_backup->diff_run;
    privcand_target->diff_privcand = privcand_backup->diff_privcand;
    privcand_backup->diff_run = NULL;
    privcand_backup->diff_privcand = NULL;

    free(privcand_backup);
}

API int
sr_pc_validate(sr_session_ctx_t *session, const char *module_name, const sr_priv_cand_t *privcand)
{
    sr_error_info_t *err_info = NULL;
    sr_data_t *data = NULL;
    char *xpath = NULL;
    int ret = SR_ERR_OK;
    int r;

    SR_CHECK_ARG_APIRET(!session || !privcand, session, err_info);

    /* get filter xpath */
    if (module_name) {
        r = asprintf(&xpath, "/%s:*", module_name);
    } else {
        r = asprintf(&xpath, "/*");
    }
    SR_CHECK_MEM_GOTO(r == -1, err_info, cleanup);

    if ((ret = sr_pc_get_data(session, xpath, 0, 0, privcand, &data))) {
        goto cleanup;
    }

    if ((err_info = sr_lyd_validate_all(&data->tree, sr_yang_ctx.ly_ctx, LYD_VALIDATE_PRESENT | LYD_VALIDATE_NO_STATE))) {
        goto cleanup;
    }

cleanup:
    free(xpath);
    sr_release_data(data);

    return ret ? ret : sr_api_ret(session, err_info);
}

API int
sr_pc_replace_trg_config(sr_session_ctx_t *session, sr_priv_cand_t *privcand, const char *module_name,
        const struct lyd_node *src_config)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_s mod_info;
    const struct lys_module *ly_mod = NULL;
    struct lyd_node *iter, *next, *diff = NULL;

    SR_CHECK_ARG_APIRET(!session || !privcand, session, err_info);

    if (!src_config) {
        sr_pc_discard_changes(privcand);
        return sr_api_ret(session, NULL);
    }

    /* init modinfo */
    sr_modinfo_init(&mod_info, session->conn, SR_DS_RUNNING, SR_DS_RUNNING, 0);

    if (sr_yang_ctx.ly_ctx != LYD_CTX(src_config)) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Data trees must be created using the session connection libyang context.");
        goto cleanup;
    }

    /* find first sibling */
    src_config = lyd_first_sibling(src_config);

    if (module_name) {
        /* try to find this module */
        ly_mod = ly_ctx_get_module_implemented(sr_yang_ctx.ly_ctx, module_name);
        if (!ly_mod) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
            goto cleanup;
        } else if (!strcmp(ly_mod->name, "sysrepo")) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Data of internal module \"sysrepo\" cannot be modified.");
            goto cleanup;
        }

        /* check that all nodes are from the specified module */
        LY_LIST_FOR((struct lyd_node *)src_config, iter) {
            if (lyd_owner_module(iter) != ly_mod) {
                sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Data contain nodes from module \"%s\" but expected only \"%s\".",
                        lyd_owner_module(iter)->name, module_name);
                goto cleanup;
            }
        }
    }

    if (ly_mod) {
        if ((err_info = sr_modinfo_add(ly_mod, NULL, 0, 0, 0, &mod_info))) {
            goto cleanup;
        }

        /* add modules with dependencies into mod_info */
        if ((err_info = sr_modinfo_consolidate(&mod_info, SR_LOCK_READ, SR_MI_PERM_NO, session, 0, 0, 0))) {
            goto cleanup;
        }

        /* get data tree (of specific module) of running ds when private canidate was created */
        if ((err_info = sr_lyd_diff_apply_module(&mod_info.data, privcand->diff_run, ly_mod, NULL))) {
            goto cleanup;
        }

        /* unlink and free nodes of the specified module in private candidate */
        LY_LIST_FOR_SAFE(privcand->diff_privcand, next, iter) {
            if (lyd_owner_module(iter) == ly_mod) {
                sr_lyd_free_tree_safe(iter, &privcand->diff_privcand);
            }
        }

        if ((err_info = sr_lyd_diff_siblings(mod_info.data, src_config, LYD_DIFF_DEFAULTS, NULL, &diff))) {
            goto cleanup;
        }

        if ((err_info = sr_lyd_diff_merge_all(&privcand->diff_privcand, diff))) {
            goto cleanup;
        }

    } else {
        if ((err_info = sr_modinfo_add_all_modules_with_data(sr_yang_ctx.ly_ctx, 0, &mod_info))) {
            goto cleanup;
        }

        /* add modules with dependencies into mod_info */
        if ((err_info = sr_modinfo_consolidate(&mod_info, SR_LOCK_READ, SR_MI_PERM_NO, session, 0, 0, 0))) {
            goto cleanup;
        }

        /* get data tree of running ds when private canidate was created */
        if ((err_info = sr_lyd_diff_apply_all(&mod_info.data, privcand->diff_run))) {
            goto cleanup;
        }

        lyd_free_siblings(privcand->diff_privcand);
        privcand->diff_privcand = NULL;

        if ((err_info = sr_lyd_diff_siblings(mod_info.data, src_config, LYD_DIFF_DEFAULTS, NULL, &privcand->diff_privcand))) {
            goto cleanup;
        }
    }

cleanup:
    sr_shmmod_modinfo_unlock(&mod_info);
    sr_modinfo_erase(&mod_info);

    lyd_free_all(diff);

    return sr_api_ret(session, err_info);
}
