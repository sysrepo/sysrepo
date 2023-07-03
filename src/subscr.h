/**
 * @file subscr.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief subscription common routines header
 *
 * @copyright
 * Copyright (c) 2023 Deutsche Telekom AG.
 * Copyright (c) 2023 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef _SUBSCR_H
#define _SUBSCR_H

#include <inttypes.h>

#include "common_types.h"
#include "shm_types.h"
#include "sysrepo_types.h"

/**
 * @brief Add a change subscription into a subscription structure.
 *
 * @param[in,out] subscr Subscription structure.
 * @param[in] sub_id Unique sub ID.
 * @param[in] sess Subscription session.
 * @param[in] mod_name Subscription module name.
 * @param[in] xpath Subscription XPath.
 * @param[in] change_cb Subscription callback.
 * @param[in] private_data Subscription callback private data.
 * @param[in] priority Subscription priority.
 * @param[in] sub_opts Subscription options.
 * @param[in] has_subs_lock What kind of SUBS lock is held.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_subscr_change_sub_add(sr_subscription_ctx_t *subscr, uint32_t sub_id, sr_session_ctx_t *sess,
        const char *mod_name, const char *xpath, sr_module_change_cb change_cb, void *private_data, uint32_t priority,
        sr_subscr_options_t sub_opts, sr_lock_mode_t has_subs_lock);

/**
 * @brief Delete a change subscription from a subscription structure.
 *
 * @param[in,out] subscr Subscription structure.
 * @param[in] sub_id Unique sub ID.
 */
void sr_subscr_change_sub_del(sr_subscription_ctx_t *subscr, uint32_t sub_id);

/**
 * @brief Add an operational get subscription into a subscription structure.
 *
 * @param[in,out] subscr Subscription structure.
 * @param[in] sub_id Unique sub ID.
 * @param[in] sess Subscription session.
 * @param[in] mod_name Subscription module name.
 * @param[in] path Subscription path.
 * @param[in] oper_cb Subscription callback.
 * @param[in] private_data Subscription callback private data.
 * @param[in] has_subs_lock What kind of SUBS lock is held.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_subscr_oper_get_sub_add(sr_subscription_ctx_t *subscr, uint32_t sub_id, sr_session_ctx_t *sess,
        const char *mod_name, const char *path, sr_oper_get_items_cb oper_cb, void *private_data,
        sr_lock_mode_t has_subs_lock, uint32_t prio);

/**
 * @brief Delete an operational get subscription from a subscription structure.
 *
 * @param[in,out] subscr Subscription structure.
 * @param[in] sub_id Unique sub ID.
 */
void sr_subscr_oper_get_sub_del(sr_subscription_ctx_t *subscr, uint32_t sub_id);

/**
 * @brief Add an operational poll subscription into a subscription structure.
 *
 * @param[in,out] subscr Subscription structure.
 * @param[in] sub_id Unique sub ID.
 * @param[in] sess Subscription session.
 * @param[in] mod_name Subscription module name.
 * @param[in] path Subscription path.
 * @param[in] valid_ms Cached operational data validity interval in ms.
 * @param[in] sub_opts Subscription options.
 * @param[in] has_subs_lock What kind of SUBS lock is held.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_subscr_oper_poll_sub_add(sr_subscription_ctx_t *subscr, uint32_t sub_id, sr_session_ctx_t *sess,
        const char *mod_name, const char *path, uint32_t valid_ms, sr_subscr_options_t sub_opts,
        sr_lock_mode_t has_subs_lock);

/**
 * @brief Delete an operational poll subscription from a subscription structure.
 *
 * @param[in,out] subscr Subscription structure.
 * @param[in] sub_id Unique sub ID.
 */
void sr_subscr_oper_poll_sub_del(sr_subscription_ctx_t *subscr, uint32_t sub_id);

/**
 * @brief Add a notification subscription into a subscription structure.
 *
 * @param[in,out] subscr Subscription structure.
 * @param[in] sub_id Unique sub ID.
 * @param[in] sess Subscription session.
 * @param[in] mod_name Subscription module name.
 * @param[in] xpath Subscription XPath.
 * @param[in] listen_since_mono Monotonic timestamp of the subscription starting to listen.
 * @param[in] listen_since_real Realtime timestamp of the subscription starting to listen.
 * @param[in] start_time Optional subscription start time.
 * @param[in] stop_time Optional subscription stop time.
 * @param[in] notif_cb Subscription value callback.
 * @param[in] notif_tree_cb Subscription tree callback.
 * @param[in] private_data Subscription callback private data.
 * @param[in] has_subs_lock What kind of SUBS lock is held.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_subscr_notif_sub_add(sr_subscription_ctx_t *subscr, uint32_t sub_id, sr_session_ctx_t *sess,
        const char *mod_name, const char *xpath, const struct timespec *listen_since_mono, const struct timespec *listen_since_real,
        const struct timespec *start_time, const struct timespec *stop_time, sr_event_notif_cb notif_cb,
        sr_event_notif_tree_cb notif_tree_cb, void *private_data, sr_lock_mode_t has_subs_lock);

/**
 * @brief Delete a notification subscription from a subscription structure.
 *
 * @param[in,out] subscr Subscription structure.
 * @param[in] sub_id Unique sub ID.
 * @param[in] notif_ev Generated notification event.
 */
void sr_subscr_notif_sub_del(sr_subscription_ctx_t *subscr, uint32_t sub_id, sr_ev_notif_type_t notif_ev);

/**
 * @brief Add an RPC subscription into a subscription structure.
 *
 * @param[in,out] subscr Subscription structure.
 * @param[in] sub_id Unique sub ID.
 * @param[in] sess Subscription session.
 * @param[in] path Subscription RPC path.
 * @param[in] is_ext Whether the RPC is in an extension or not.
 * @param[in] xpath Subscription XPath.
 * @param[in] rpc_cb Subscription value callback.
 * @param[in] rpc_tree_cb Subscription tree callback.
 * @param[in] private_data Subscription callback private data.
 * @param[in] priority Subscription priority.
 * @param[in] has_subs_lock What kind of SUBS lock is held.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_subscr_rpc_sub_add(sr_subscription_ctx_t *subscr, uint32_t sub_id, sr_session_ctx_t *sess,
        const char *path, int is_ext, const char *xpath, sr_rpc_cb rpc_cb, sr_rpc_tree_cb rpc_tree_cb, void *private_data,
        uint32_t priority, sr_lock_mode_t has_subs_lock);

/**
 * @brief Delete an RPC subscription from a subscription structure.
 *
 * @param[in,out] subscr Subscription structure.
 * @param[in] sub_id Unique sub ID.
 */
void sr_subscr_rpc_sub_del(sr_subscription_ctx_t *subscr, uint32_t sub_id);

/**
 * @brief Find a specific change subscription in a subscription structure.
 *
 * @param[in] subscr Subscription structure to use.
 * @param[in] sub_id Subscription ID to find.
 * @param[out] module_name Optional found subscription module name.
 * @param[out] ds Optional found subscription datastore.
 * @return Matching subscription, NULL if not found.
 */
struct modsub_changesub_s *sr_subscr_change_sub_find(const sr_subscription_ctx_t *subscr, uint32_t sub_id,
        const char **module_name, sr_datastore_t *ds);

/**
 * @brief Find a specific operational get subscription in a subscription structure.
 *
 * @param[in] subscr Subscription structure to use.
 * @param[in] sub_id Subscription ID to find.
 * @param[out] module_name Optional found subscription module name.
 * @return Matching subscription, NULL if not found.
 */
struct modsub_opergetsub_s *sr_subscr_oper_get_sub_find(const sr_subscription_ctx_t *subscr, uint32_t sub_id,
        const char **module_name);

/**
 * @brief Find a specific operational poll subscription in a subscription structure.
 *
 * @param[in] subscr Subscription structure to use.
 * @param[in] sub_id Subscription ID to find.
 * @param[out] module_name Optional found subscription module name.
 * @return Matching subscription, NULL if not found.
 */
struct modsub_operpollsub_s *sr_subscr_oper_poll_sub_find(const sr_subscription_ctx_t *subscr, uint32_t sub_id,
        const char **module_name);

/**
 * @brief Find a specific notification subscription in a subscription structure.
 *
 * @param[in] subscr Subscription structure to use.
 * @param[in] sub_id Subscription ID to find.
 * @param[out] module_name Optional found subscription module name.
 * @return Matching subscription, NULL if not found.
 */
struct modsub_notifsub_s *sr_subscr_notif_sub_find(const sr_subscription_ctx_t *subscr, uint32_t sub_id,
        const char **module_name);

/**
 * @brief Find a specific RPC/action subscription in a subscription structure.
 *
 * @param[in] subscr Subscription structure to use.
 * @param[in] sub_id Subscription ID to find.
 * @param[out] path Optional found subscription operation path.
 * @return Matching subscription, NULL if not found.
 */
struct opsub_rpcsub_s *sr_subscr_rpc_sub_find(const sr_subscription_ctx_t *subscr, uint32_t sub_id, const char **path);

/**
 * @brief Count subscriptions of session @p sess in subscriptions structure @p subscr.
 *
 * @param[in] subscr Session subscription.
 * @param[in] sess Subscription session.
 * @param[in] has_subs_lock What kind of SUBS lock is held.
 * @return Number of session subscriptions.
 */
int sr_subscr_session_count(sr_subscription_ctx_t *subscr, sr_session_ctx_t *sess, sr_lock_mode_t has_subs_lock);

/**
 * @brief Delete all subscriptions in @p subscr of session @p sess.
 *
 * @param[in,out] subscr Session subscription.
 * @param[in] sess Subscription session.
 * @param[in] has_subs_lock What kind of SUBS lock is held.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_subscr_del_session(sr_subscription_ctx_t *subscr, sr_session_ctx_t *sess, sr_lock_mode_t has_subs_lock);

/**
 * @brief Delete a specific subscription in @p subscr.
 *
 * @param[in,out] subscr Subscription structure.
 * @param[in] sub_id Subscription ID of the subscription to remove.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_subscr_del_id(sr_subscription_ctx_t *subscr, uint32_t sub_id);

/**
 * @brief Delete all subscriptions in @p subscr of all the sessions.
 *
 * @param[in,out] subscr Subscription structure.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_subscr_del_all(sr_subscription_ctx_t *subscr);

/**
 * @brief Delete a notification subscription from @p subscr because it's stop-time has been reached.
 *
 * @param[in,out] subscr Subscription structure to modify.
 * @param[in] idx1 Notif subscription index in @p subscr.
 * @param[in] idx2 Specific notif subscription index to remove.
 * @param[in] has_subs_lock What kind of SUBS lock is held.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_subscr_notif_del_stop_time(sr_subscription_ctx_t *subscr, uint32_t idx1, uint32_t idx2,
        sr_lock_mode_t has_subs_lock);

/**
 * @brief Find notifications subscribers for a module.
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_name Module name.
 * @param[out] notif_subs Notification subscriptions.
 * @param[out] notif_sub_count Number of subscribers.
 * @param[out] sub_cid Optional CID of the first subscriber.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_notif_find_subscriber(sr_conn_ctx_t *conn, const char *mod_name, sr_mod_notif_sub_t **notif_subs,
        uint32_t *notif_sub_count, sr_cid_t *sub_cid);

/**
 * @brief Call notification callback for a notification.
 *
 * @param[in] ev_sess Event session to provide for the callback.
 * @param[in] cb Value callback.
 * @param[in] tree_cb Tree callback.
 * @param[in] private_data Callback private data.
 * @param[in] notif_type Notification type.
 * @param[in] sub_id Subscription ID.
 * @param[in] notif_op Notification node of the notification (relevant for nested notifications).
 * @param[in] notif_ts Timestamp of when the notification was generated.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_notif_call_callback(sr_session_ctx_t *ev_sess, sr_event_notif_cb cb, sr_event_notif_tree_cb tree_cb,
        void *private_data, const sr_ev_notif_type_t notif_type, uint32_t sub_id, const struct lyd_node *notif_op,
        const struct timespec *notif_ts);

/**
 * @brief Check the XPath of a change subscription.
 *
 * @param[in] ly_ctx Context to use.
 * @param[in] xpath XPath to check.
 * @param[in,out] valid If set, does not log and sets to 0 if invalid, 1 if valid.
 * If not set, an error is returned if invalid, otherwise NULL.
 * @return err_info (if @p valid is not set), NULL on success.
 */
sr_error_info_t *sr_subscr_change_xpath_check(const struct ly_ctx *ly_ctx, const char *xpath, int *valid);

/**
 * @brief Check the path of an oper subscription. Optionally learn what kinds (config) of nodes are provided
 * by an operational subscription to determine its type.
 *
 * @param[in] ly_ctx Context to use.
 * @param[in] path Path to check.
 * @param[out] sub_type Optional learned subscription type.
 * @param[in,out] valid If set, does not log and sets to 0 if invalid, 1 if valid.
 * If not set, an error is returned if invalid, otherwise NULL.
 * @return err_info (if @p valid is not set), NULL on success.
 */
sr_error_info_t *sr_subscr_oper_path_check(const struct ly_ctx *ly_ctx, const char *path,
        sr_mod_oper_get_sub_type_t *sub_type, int *valid);

/**
 * @brief Check the XPath of a notif subscription.
 *
 * @param[in] ly_mod Module of the subscription.
 * @param[in] xpath XPath to check, may be NULL.
 * @param[in,out] valid If set, does not log and sets to 0 if invalid, 1 if valid.
 * If not set, an error is returned if invalid, otherwise NULL.
 * @return err_info (if @p valid is not set), NULL on success.
 */
sr_error_info_t *sr_subscr_notif_xpath_check(const struct lys_module *ly_mod, const char *xpath, int *valid);

/**
 * @brief Check the XPath of an RPC subscription.
 *
 * @param[in] ly_ctx Context to use.
 * @param[in] xpath XPath to check.
 * @param[out] path Optional simple path ot the RPC/action.
 * @param[out] is_ext Optional flag whether the operation is defined in a nested extension.
 * @param[in,out] valid If set, does not log and sets to 0 if invalid, 1 if valid.
 * If not set, an error is returned if invalid, otherwise NULL.
 * @return err_info (if @p valid is not set), NULL on success.
 */
sr_error_info_t *sr_subscr_rpc_xpath_check(const struct ly_ctx *ly_ctx, const char *xpath, char **path, int *is_ext,
        int *valid);

#endif /* _SUBSCR_H */
