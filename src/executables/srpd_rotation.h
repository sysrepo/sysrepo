/**
 * @file srpd_rotation.h
 * @author Ondrej Kusnirik <Ondrej.Kusnirik@cesnet.cz>
 * @brief header of rotation utility for sysrepo-plugind
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

#include "compat/compat.h"

/**
 * @brief Internal struct for rotation purposes.
 *
 */
typedef struct {
    ATOMIC64_T rotation_time;
    ATOMIC_PTR_T output_folder;
    ATOMIC_T compress;
    ATOMIC64_T rotated_files_count;
    sr_subscription_ctx_t *subscr;
    pthread_t tid;
    ATOMIC_T running;
} srpd_rotation_opts_t;

/**
 * @brief Internal rotation notification plugin ::srp_init_cb_t callback.
 *
 */
int srpd_rotation_init_cb(sr_session_ctx_t *session, void **private_data);

/**
 * @brief Internal rotation notification plugin ::srp_cleanup_cb_t callback.
 *
 */
void srpd_rotation_cleanup_cb(sr_session_ctx_t *session, void *private_data);

/**
 * @brief Internal operational ::sr_oper_get_items_cb callback.
 *
 */
int srpd_get_rot_count_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *path,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

/**
 * @brief Internal module change ::sr_module_change_cb callback.
 *
 */
int srpd_rotation_change_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data);
