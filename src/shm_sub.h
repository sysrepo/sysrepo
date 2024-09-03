/**
 * @file shm_sub.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for sub SHM routines
 *
 * @copyright
 * Copyright (c) 2018 - 2023 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2023 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef _SHM_SUB_H
#define _SHM_SUB_H

#include "shm_types.h"
#include "sysrepo_types.h"

struct lyd_node;
struct lys_module;
struct modsub_change_s;
struct modsub_notif_s;
struct modsub_oper_s;
struct opsub_rpc_s;
struct sr_mod_info_mod_s;
struct sr_mod_info_s;

/**
 * @brief Macro for getting a notify sub item on a specific index.
 *
 * @param[in] nsubs Notify subs array.
 * @param[in] i Index of the desired item.
 * @param[in] item_size Actual size of every item in @p nsubs.
 */
#define SR_NOTIFY_SUB_IDX(nsubs, i, item_size) (void *)(((char *)nsubs) + i * item_size)

/**
 * @brief Create and initialize a subscription SHM.
 *
 * @param[in] name Subscription name (module name).
 * @param[in] suffix1 First suffix.
 * @param[in] suffix2 Second suffix, none if set to -1.
 * @param[in] shm_struct_size Size of the used subscription SHM structure.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_create(const char *name, const char *suffix1, int64_t suffix2, size_t shm_struct_size);

/**
 * @brief Open and map an existing subscription SHM.
 *
 * @param[in] name Subscription name (module name).
 * @param[in] suffix1 First suffix.
 * @param[in] suffix2 Second suffix, none if set to -1.
 * @param[out] shm Mapped SHM.
 * @param[in] shm_struct_size Size of the used subscription SHM structure.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_open_map(const char *name, const char *suffix1, int64_t suffix2, sr_shm_t *shm);

/**
 * @brief Unlink a subscription SHM.
 *
 * @param[in] name Subscription name (module name).
 * @param[in] suffix1 First suffix.
 * @param[in] suffix2 Second suffix, none if set to -1.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_unlink(const char *name, const char *suffix1, int64_t suffix2);

/**
 * @brief Create a subscription data SHM.
 *
 * @param[in] name Subscription name (module name).
 * @param[in] suffix1 First suffix.
 * @param[in] suffix2 Second suffix, none if set to -1.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_data_create(const char *name, const char *suffix1, int64_t suffix2);

/**
 * @brief Unlink a subscription data SHM.
 *
 * @param[in] name Subscription name (module name).
 * @param[in] suffix1 First suffix.
 * @param[in] suffix2 Second suffix, none if set to -1.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_data_unlink(const char *name, const char *suffix1, int64_t suffix2);

/**
 * @brief Write into a subscriber event pipe to notify it there is a new event.
 *
 * @param[in] evpipe_num Subscriber event pipe number.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_notify_evpipe(uint32_t evpipe_num);

/**
 * @brief Notify about (generate) a change "update" event.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] orig_name Event originator name.
 * @param[in] orig_data Event originator data.
 * @param[in] timeout_ms Change callback timeout in milliseconds.
 * @param[out] update_edit Updated edit from subscribers, if any.
 * @param[out] cb_err_info Callback error information generated by a subscriber, if any.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_change_notify_update(struct sr_mod_info_s *mod_info, const char *orig_name,
        const void *orig_data, uint32_t timeout_ms, struct lyd_node **update_edit, sr_error_info_t **cb_err_info);

/**
 * @brief Clear a change event.
 *
 * @param[in] mod_info Mod info to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_change_notify_clear(struct sr_mod_info_s *mod_info);

/**
 * @brief Notify about (generate) a change "change" event.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] orig_name Event originator name.
 * @param[in] orig_data Event originator data.
 * @param[in] timeout_ms Change callback timeout in milliseconds.
 * @param[out] cb_err_info Callback error information generated by a subscriber, if any.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_change_notify_change(struct sr_mod_info_s *mod_info, const char *orig_name,
        const void *orig_data, uint32_t timeout_ms, sr_error_info_t **cb_err_info);

/**
 * @brief Notify about (generate) a change "done" event.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] orig_name Event originator name.
 * @param[in] orig_data Event originator data.
 * @param[in] timeout_ms Change callback timeout in milliseconds. Set to 0 if the event should not be waited for.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_change_notify_change_done(struct sr_mod_info_s *mod_info, const char *orig_name,
        const void *orig_data, uint32_t timeout_ms);

/**
 * @brief Notify about (generate) a change "abort" event.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] orig_name Event originator name.
 * @param[in] orig_data Event originator data.
 * @param[in] timeout_ms Change callback timeout in milliseconds. Set to 0 if the event should not be waited for.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_change_notify_change_abort(struct sr_mod_info_s *mod_info, const char *orig_name,
        const void *orig_data, uint32_t timeout_ms);

/**
 * @brief Notify about (generate) an operational get event.
 *
 * @param[in] mod Modinfo structure.
 * @param[in] xpath Subscription XPath.
 * @param[in] request_xpath Requested XPath.
 * @param[in] parent Existing parent to append the data to.
 * @param[in] orig_name Event originator name.
 * @param[in] orig_data Event originator data.
 * @param[in] oper_get_subs An array of operational get subscriptions.
 * @param[in] idx1 Index of the array where operational subscriptions with the same XPath are.
 * @param[in] timeout_ms Operational callback timeout in milliseconds.
 * @param[in] conn Connection.
 * @param[out] data Data provided by the subscriber.
 * @param[out] cb_err_info Callback error information generated by a subscriber, if any.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_oper_get_notify(struct sr_mod_info_mod_s *mod, const char *xpath, const char *request_xpath,
        const struct lyd_node *parent, const char *orig_name, const void *orig_data, sr_mod_oper_get_sub_t *oper_get_subs,
        uint32_t idx1, uint32_t timeout_ms, sr_conn_ctx_t *conn, struct lyd_node **data, sr_error_info_t **cb_err_info);

/**
 * @brief Notify about (generate) an RPC/action event.
 * Main SHM read lock must be held and may be temporarily unlocked!
 *
 * @param[in] conn Connection to use.
 * @param[in] sub_lock SHM RPC subs lock.
 * @param[in,out] subs Offset in ext SHM of RPC subs.
 * @param[in,out] sub_count Ext SHM RPC sub count.
 * @param[in] path RPC/action path.
 * @param[in] input Operation input tree.
 * @param[in] orig_name Event originator name.
 * @param[in] orig_data Event originator data.
 * @param[in] timeout_ms RPC/action callback timeout in milliseconds.
 * @param[in,out] request_id Generated request ID, set to 0 when passing.
 * @param[out] output Operation output returned by the last subscriber on success.
 * @param[out] cb_err_info Callback error information generated by a subscriber, if any.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_rpc_notify(sr_conn_ctx_t *conn, off_t *subs, uint32_t *sub_count, const char *path,
        const struct lyd_node *input, const char *orig_name, const void *orig_data, uint32_t timeout_ms,
        uint32_t *request_id, struct lyd_node **output, sr_error_info_t **cb_err_info);

/**
 * @brief Notify about (generate) an RPC/action abort event.
 *
 * @param[in] conn Connection to use.
 * @param[in,out] subs Offset in ext SHM of RPC subs.
 * @param[in,out] sub_count Ext SHM RPC sub count.
 * @param[in] path RPC/action path.
 * @param[in] input Operation input tree.
 * @param[in] orig_name Event originator name.
 * @param[in] orig_data Event originator data.
 * @param[in] timeout_ms RPC/action callback timeout in milliseconds.
 * @param[in] request_id Generated request ID from previous event.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_rpc_notify_abort(sr_conn_ctx_t *conn, off_t *subs, uint32_t *sub_count,
        const char *path, const struct lyd_node *input, const char *orig_name, const void *orig_data, uint32_t timeout_ms,
        uint32_t request_id);

/**
 * @brief Notify about (generate) a notification event.
 *
 * @param[in] conn Connection to use.
 * @param[in] notif Notification data tree.
 * @param[in] notif_ts_mono Notification monotonic timestamp.
 * @param[in] notif_ts_real Notification realtime timestamp.
 * @param[in] orig_name Event originator name.
 * @param[in] orig_data Event originator data.
 * @param[in] timeout_ms Notification callback timeout in milliseconds. Used only if @p wait is set.
 * @param[in] wait Whether to wait for the callbacks or not.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_notif_notify(sr_conn_ctx_t *conn, const struct lyd_node *notif, struct timespec notif_ts_mono,
        struct timespec notif_ts_real, const char *orig_name, const void *orig_data, uint32_t timeout_ms, int wait);

/**
 * @brief Write the result of having processed an event.
 *
 * @p shm_data_sub is remapped for the data to write.
 *
 * @param[in] sub_shm Subscription SHM to write to.
 * @param[in] valid_subscr_count Number of subscribers that processed the event.
 * @param[in] err_code Optional error code if a callback failed.
 * @param[in] shm_data_sub Opened sub data SHM, not needed if no @p data written.
 * @param[in] data Optional data to write after the structure.
 * @param[in] data_len Size of @p data.
 * @param[in] event_desc Specific event description for printing.
 * @param[in] result_str Result of processing the event in string.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_listen_write_event(sr_sub_shm_t *sub_shm, uint32_t valid_subscr_count,
        sr_error_t err_code, sr_shm_t *shm_data_sub, const char *data, uint32_t data_len, const char *event_desc,
        const char *result_str);

/**
 * @brief Process all module change events, if any.
 *
 * @param[in] change_subs Module change subscriptions.
 * @param[in] conn Connection to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_change_listen_process_module_events(struct modsub_change_s *change_subs, sr_conn_ctx_t *conn);

/**
 * @brief Write into evpipe of relevant operational poll subscriptions on an operational get subscription change (added/removed).
 *
 * @param[in] conn Connection to use.
 * @param[in] module_name Subscription module name.
 * @param[in] oper_get_path Operational get subscription path.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_oper_poll_get_sub_change_notify_evpipe(sr_conn_ctx_t *conn, const char *module_name,
        const char *oper_get_path);

/**
 * @brief Process all module get operational events, if any.
 *
 * @param[in] oper_get_subs Module get operational subscriptions.
 * @param[in] conn Connection to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_oper_get_listen_process_module_events(struct modsub_operget_s *oper_get_subs,
        sr_conn_ctx_t *conn);

/**
 * @brief Process all module poll operational events, if any.
 *
 * @param[in] oper_poll_subs Module poll operational subscriptions.
 * @param[in] conn Connection to use.
 * @param[in,out] wake_up_in Nearest cache update of a subscription. If none, left unmodified.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_oper_poll_listen_process_module_events(struct modsub_operpoll_s *oper_poll_subs,
        sr_conn_ctx_t *conn, struct timespec *wake_up_in);

/**
 * @brief Process all RPC/action events for one RPC/action, if any.
 *
 * @param[in] rpc_sub RPC/action subscriptions.
 * @param[in] conn Connection to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_rpc_listen_process_rpc_events(struct opsub_rpc_s *rpc_subs, sr_conn_ctx_t *conn);

/**
 * @brief Process all module notification events, if any.
 *
 * @param[in] notif_subs Module notification subscriptions.
 * @param[in] conn Connection to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_notif_listen_process_module_events(struct modsub_notif_s *notif_subs, sr_conn_ctx_t *conn);

/**
 * @brief Get nearest stop time of a subscription, if any.
 *
 * @param[in] notif_subs Module notification subscriptions.
 * @param[in,out] wake_up_in Nearest stop time of a subscription. If none, left unmodified.
 */
void sr_shmsub_notif_listen_module_get_stop_time_in(struct modsub_notif_s *notif_subs, struct timespec *wake_up_in);

/**
 * @brief Check notification subscriptions stop time and finish the subscription if it has elapsed.
 *
 * @param[in] notif_subs_idx Index of the notification subscriptions in @p subscr.
 * @param[in] has_subs_lock What kind of SUBS lock is held.
 * @param[in] subscr Subscriptions structure.
 * @param[out] module_finished Whether the last module notification subscription was finished.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_notif_listen_module_stop_time(uint32_t notif_subs_idx, sr_lock_mode_t has_subs_lock,
        sr_subscription_ctx_t *subscr, int *module_finished);

/**
 * @brief Check notification subscription replay state and perform it if requested.
 *
 * @param[in] notif_subs Module notification subscriptions.
 * @param[in] subscr Subscriptions structure.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_notif_listen_module_replay(struct modsub_notif_s *notif_subs, sr_subscription_ctx_t *subscr);

/**
 * @brief Listener handler thread of all subscriptions.
 *
 * @param[in] arg Pointer to the subscription structure.
 * @return Always NULL.
 */
void *sr_shmsub_listen_thread(void *arg);

#endif /* _SHM_SUB_H */
