/**
 * @file replay.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for notification replay routines
 *
 * @copyright
 * Copyright (c) 2019 CESNET, z.s.p.o.
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

sr_error_info_t *sr_replay_store(sr_conn_ctx_t *conn, const struct lyd_node *notif, time_t notif_ts);

sr_error_info_t *sr_replay_notify(sr_conn_ctx_t *conn, const char *mod_name, const char *xpath, time_t start_time,
        time_t stop_time, sr_event_notif_cb callback, sr_event_notif_tree_cb tree_callback, void *private_data);

#endif
