/**
 * @file replay.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for notification replay routines
 *
 * @copyright
 * Copyright 2018 Deutsche Telekom AG.
 * Copyright 2018 - 2019 CESNET, z.s.p.o.
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

#ifndef _REPLAY_H
#define _REPLAY_H

#include <time.h>

#include <libyang/libyang.h>

#include "common.h"

/**
 * @brief Find specific replay notification file:
 * - from_ts = 0; to_ts = 0 - find latest file
 * - from_ts > 0; to_ts = 0 - find file possibly containing no-earlier-than from_ts (replay start_time)
 * - from_ts > 0; to_ts > 0 - find next file after this one
 *
 * @param[in] mod_name Module name.
 * @param[in] from_ts Earliest stored notification.
 * @param[in] to_ts Latest stored notification.
 * @param[out] file_from_ts Found file earliest notification.
 * @param[out] file_to_ts Found file latest notification.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_replay_find_file(const char *mod_name, time_t from_ts, time_t to_ts, time_t *file_from_ts,
        time_t *file_to_ts);

/**
 * @brief Store a notification for replay.
 *
 * @param[in] sess Session to use.
 * @param[in] notif Notification to store.
 * @param[in] notif_ts Notification timestamp to store.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_replay_store(sr_session_ctx_t *sess, const struct lyd_node *notif, time_t notif_ts);

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
 * @param[in] xpath Optional selected notifications.
 * @param[in] start_time Earliest notification of interest.
 * @param[in] stop_time Latest notification of interest.
 * @param[in] callback Notification callback to call.
 * @param[in] tree_callback Notification tree callback to call.
 * @param[in] private_data Notification callback private data.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_replay_notify(sr_conn_ctx_t *conn, const char *mod_name, const char *xpath, time_t start_time,
        time_t stop_time, sr_event_notif_cb callback, sr_event_notif_tree_cb tree_callback, void *private_data);

#endif
