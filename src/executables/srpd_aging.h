/**
 * @file srpd_aging.h
 * @author Ondrej Kusnirik <Ondrej.Kusnirik@cesnet.cz>
 * @brief header of aging utility for sysrepo-plugind
 *
 * @copyright
 * Copyright (c) 2018 - 2022 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2022 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#include <sysrepo.h>

/**
 * @brief Internal struct for archivation purposes.
 *
 */
typedef struct {
    time_t rotation_time;
    char *archive;
    int compress;
    uint64_t archived_notif_count;
    sr_subscription_ctx_t *subscr;
    pthread_t tid;
    int running;
    int finish;
} srpd_aging_opts_t;

/**
 * @brief Internal aging notification plugin ::srp_init_cb_t callback.
 *
 */
int srpd_aging_init_cb(sr_session_ctx_t *session, void **private_data);

/**
 * @brief Internal aging notification plugin ::srp_cleanup_cb_t callback.
 *
 */
void srpd_aging_cleanup_cb(sr_session_ctx_t *session, void *private_data);

/**
 * @brief Internal operational ::sr_oper_get_items_cb callback.
 *
 */
int srpd_get_arch_count_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *path,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

/**
 * @brief Internal module change ::sr_module_change_cb callback.
 *
 */
int srpd_notif_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data);
