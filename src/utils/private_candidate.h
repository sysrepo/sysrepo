/**
 * @file private_candidate.h
 * @author Juraj Budai <budai@cesnet.cz>
 * @brief private candidate datastore header
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

#ifndef SYSREPO_PRIVATE_CANDIDATE_H_
#define SYSREPO_PRIVATE_CANDIDATE_H_

#include <libyang/libyang.h>

#include "sysrepo.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Strategies for resolving configuration conflicts when merging candidate and running datastores.
 *
 * The semantics of these conflict‑resolution strategies are defined in
 * [draft‑ietf‑netconf‑privcand](https://datatracker.ietf.org/doc/html/draft-ietf-netconf-privcand-07#name-conflict-resolution)
 */
typedef enum {
    SR_PC_REVERT_ON_CONFLICT,
    SR_PC_PREFER_RUNNING,
    SR_PC_PREFER_CANDIDATE
} sr_pc_conflict_resolution_t;

/**
 * @brief Types of conflicts that may occur during private candidate datastore <update>.
 *
 * [See draft: What is a conflict](https://datatracker.ietf.org/doc/html/draft-ietf-netconf-privcand-07#name-what-is-a-conflict)
 */
typedef enum {
    SR_PC_CONFLICT_VALUE_CHANGE,       /**< Conflict caused by different value changes
                                      *  on a single node (e.g., leaf, anydata, or anyxml).
                                      */
    SR_PC_CONFLICT_LIST_ENTRY,         /**<Conflict affecting a list instance; the list is treated
                                      * as a whole, not individual children or keys.
                                      */
    SR_PC_CONFLICT_LIST_ORDER,         /**< Conflict due to different ordering of user-ordered list entries. */
    SR_PC_CONFLICT_PRESENCE_CONTAINER, /**< Conflict caused by the presence or absence of a presence container node. */
    SR_PC_CONFLICT_LEAFLIST_ITEM,      /**< Conflict affecting a leaf-list instance; the entire
                                      *  leaf-list is considered, not individual items.
                                      */
    SR_PC_CONFLICT_LEAFLIST_ORDER,     /**< Conflict due to differing order of user-ordered leaf-list items. */
    SR_PC_CONFLICT_LEAF_EXISTENCE      /**< Conflict caused by addition or removal of a leaf node (existence differs). */
} sr_pc_conflict_type_t;

/**
 * @brief Stores information about conflicts.
 *
 * Each conflict is represented by a pair of diff trees — @p run_diff and @p pc_diff
 * showing the conflicting data and the operations that led to the conflict This makes
 * it possible to understand exactly why the conflict occurred.
 *
 * In case of a conflict on a list or leaf-list node, the entire list (including sibling instances)
 * is considered as the conflicting part.
 */
typedef struct {
    struct lyd_node *run_diff;  /**< Copy of diff tree or node from the running datastore where the conflict was detected. */
    struct lyd_node *pc_diff;   /**< Copy of diff tree or node from the private candidate datastore where the conflict was detected. */
    sr_pc_conflict_type_t type; /**< Type of conflict detected between the running and private candidate datastore */
} sr_pc_conflict_info_t;

/**
 * @brief Structure representing a set of detected conflicts between the running and private candidate datastores.
 */
typedef struct {
    sr_pc_conflict_info_t *conflicts;   /**< Array of detected conflicts */
    uint32_t conflict_count;            /**< Number of detected conflicts in the array. */
} sr_pc_conflict_set_t;

/**
 * @brief Creates a private candidate datastore structure.
 *
 * Sets up subscriptions for all YANG modules present in the running datastore.
 * The subscription structure follows the lifecycle of the private candidate datastore
 * as defined in the draft specification.
 *
 * @note The default value of ::sr_pc_conflict_resolution_t is ::SR_REVERT_ON_CONFLICT.
 * This behavior can be changed using ::sr_pc_set_conflict_resolution().
 *
 * @note The subscription is always tied to the @p session. Do not free the session
 * before calling ::sr_pc_destroy_ds().
 *
 * @param[in] session Sysrepo session.
 * @param[in] subscription_opts Options overriding default behavior of the subscription.
 *            If @p subscription is non-NULL, the only allowed value in @p subscription_opts is ::SR_SUBSCR_NO_THREAD (or 0).
 *            Ignored if @p subscription is NULL.
 * @param[in,out] subscription Optional pointer for managing the subscription context by the user.
 *                             If `NULL`, the subscription context is created and managed internally.
 *
 *                             If the user provides an existing subscription, it will be used,
 *                             but initialization and cleanup must be managed by the user.
 * @param[out] private_candidate_ds Created structure for private candidate datastore.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_pc_create_ds(sr_session_ctx_t *session, uint32_t subscription_opts, sr_subscription_ctx_t **subscription, sr_priv_cand_t **private_candidate_ds);

/**
 * @brief Destroys the private candidate datastore structure.
 *
 * @param[in] private_candidate_ds Pointer to the private candidate structure to be destroyed.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_pc_destroy_ds(sr_priv_cand_t *private_candidate_ds);

/**
 * @brief Remove and free all conflict data.
 *
 * @param[in] conflict_set List of conflicts generated by <update> or <commit>.
 */
void sr_pc_free_conflicts(sr_pc_conflict_set_t *conflict_set);

/**
 * @brief Change the conflict resolution strategy for the private candidate datastore.
 *
 * @param[in,out] private_candidate_ds Structure of the private candidate datastore.
 * @param[in] new_conflict_resolution The new conflict resolution policy to set. (see ::sr_pc_conflict_resolution_t for details).
 */
void sr_pc_set_conflict_resolution(sr_priv_cand_t *private_candidate_ds, sr_pc_conflict_resolution_t new_conflict_resolution);

/**
 * @brief Performs <update> operation on private candidate datastore.
 *
 * Applies any relevant changes from the running datastore to the private candidate,
 * according to the selected conflict resolution strategy (::sr_pc_conflict_resolution_t).
 * If no strategy is specified, the default is `SR_PC_REVERT_ON_CONFLICT`.
 * [See draft: Private candidate update behavior](https://datatracker.ietf.org/doc/html/draft-ietf-netconf-private_candidate_ds-07#name-when-is-a-private-candidate-u)
 *
 * @param[in] session Sysrepo session.
 * @param[in,out] private_candidate_ds Pointer to the private candidate structure to update.
 * @param[out] conflict_set List of found conflicts, if any.
 * @return ::SR_ERR_OK on success,
 * @return ::SR_ERR_OPERATION_FAILED if conflicts are unresolved (only possible with ::SR_PC_REVERT_ON_CONFLICT),
 * @return other error codes on failure.
 */
int sr_pc_update(sr_session_ctx_t *session, sr_priv_cand_t *private_candidate_ds, sr_pc_conflict_set_t **conflict_set);

/**
 * @brief Performs <commit> operation on private candidate datastore.
 *
 * It first calls the <update> operation.
 *
 * @param[in] session Sysrepo session.
 * @param[in,out] private_candidate_ds Pointer to the private candidate structure.
 * @param[out] conflict_set List of found conflicts, if any.
 *                  Conflicts are reported only when using
 *                      ::SR_PC_REVERT_ON_CONFLICT, because conflicts remain unresolved.
 *
 *                      When using ::SR_PC_PREFER_RUNNING or ::SR_PC_PREFER_CANDIDATE,
 *                      conflicts are automatically resolved according to the selected
 *                      strategy, and therefore no conflicts are returned.
 * @return ::SR_ERR_OK on success,
 * @return ::SR_ERR_OPERATION_FAILED if conflicts are unresolved (only possible with ::SR_PC_REVERT_ON_CONFLICT),
 * @return other error codes on failure.
 */
int sr_pc_commit(sr_session_ctx_t *session, sr_priv_cand_t *private_candidate_ds, sr_pc_conflict_set_t **conflict_set);

/**
 * @brief Performs <edit-config> operation on private candidate datastore.
 *
 * The semantics of the @p edit and @p default_operation parameters are the same as in ::sr_edit_batch.
 *
 * @param[in] session Sysrepo session.
 * @param[in,out] private_candidate_ds Private candidate datastore.
 * @param[in] edit Edit content (see ::sr_edit_batch for details).
 * @param[in] default_operation Default operation (see ::sr_edit_batch for details).
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_pc_edit_config(sr_session_ctx_t *session, sr_priv_cand_t *private_candidate_ds, const struct lyd_node *edit, const char *default_operation);

/**
 * @brief Retrieve a tree whose root nodes match the provided XPath.
 * Data are represented as _libyang_ subtrees.
 *
 * Top-level trees are always returned so if an inner node is selected, all of its descendants
 * and its direct parents (lists also with keys) are returned.
 *
 * @param[in] session Sysrepo session.
 * @param[in] xpath XPath expression used to filter data.
 * @param[in] max_depth Maximum depth of nodes to retrieve (0 = unlimited).
 * @param[in] opts Data retrieval options. (see ::sr_get_oper_flag_t and ::sr_get_flag_t)
 * @param[in] private_candidate_ds Private candidate structure.
 * @param[out] data SR data with connected top-level data trees of all the requested data. NULL if none found.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_pc_get_data(sr_session_ctx_t *session, const char *xpath, uint32_t max_depth, const uint32_t opts,
        sr_priv_cand_t *private_candidate_ds, sr_data_t **data);

/**
 * @brief Performs <discard-changes> operation on private candidate datastore.
 *
 * This operation removes all uncommitted changes made by the user in the
 * private candidate datastore, restoring it to its previous state.
 *
 * [See draft: Private candidate discard-changes behavior](https://datatracker.ietf.org/doc/html/draft-ietf-netconf-private_candidate_ds-07#section-4.8.2.11)
 *
 * @param[in,out] private_candidate_ds private candidate datastore structure.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_pc_discard_changes(sr_priv_cand_t *private_candidate_ds);

#ifdef __cplusplus
}
#endif

#endif /* SYSREPO_PRIVATE_CANDIDATE_H_ */
