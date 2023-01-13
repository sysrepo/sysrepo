/**
 * @file replay.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for notification replay routines
 *
 * @copyright
 * Copyright (c) 2018 - 2021 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef _REPLAY_H
#define _REPLAY_H

#include <time.h>

#include <libyang/libyang.h>

#include "sysrepo_types.h"

/**
 * @brief Store a notification for replay.
 *
 * @param[in] sess Session to use.
 * @param[in] notif Notification to store.
 * @param[in] notif_ts Notification timestamp to store.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_replay_store(sr_session_ctx_t *sess, const struct lyd_node *notif, struct timespec notif_ts);

/**
 * @brief Notification buffer thread.
 *
 * @param[in] arg Pointer to the session.
 * @return Always NULL.
 */
void *sr_notif_buf_thread(void *arg);

/**
 * @brief Replay valid notifications.
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_name Module name.
 * @param[in] sub_id Subscription ID.
 * @param[in] xpath Optional selected notifications.
 * @param[in] start_time Earliest notification of interest.
 * @param[in] stop_time Latest notification of interest.
 * @param[in] listen_since Timestamp of the subscription listening for notifications. There must be no notification
 * replayed with a later timestamp because it will be received as a realtime notification.
 * @param[in] callback Notification callback to call.
 * @param[in] tree_callback Notification tree callback to call.
 * @param[in] private_data Notification callback private data.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_replay_notify(sr_conn_ctx_t *conn, const char *mod_name, uint32_t sub_id, const char *xpath,
        const struct timespec *start_time, const struct timespec *stop_time, struct timespec *listen_since,
        sr_event_notif_cb callback, sr_event_notif_tree_cb tree_callback, void *private_data);

#endif
