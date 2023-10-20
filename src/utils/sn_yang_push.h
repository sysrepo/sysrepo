/**
 * @file sn_yang_push.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-subscribed-notifications yang-push functions header
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

#ifndef SN_YANG_PUSH_H_
#define SN_YANG_PUSH_H_

#define _GNU_SOURCE

#include <signal.h>
#include <time.h>

#include "sysrepo.h"

struct srsn_sub;
struct srsn_timer;

/**
 * @brief Reset the patch ID of a yang-push on-change subscription.
 *
 * @param[in] sub Subscription to use.
 */
void srsn_yp_reset_patch_id(struct srsn_sub *sub);

/**
 * @brief Send a push-update yang-push notification.
 *
 * @param[in] sub Subscription to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srsn_yp_ntf_update_send(struct srsn_sub *sub);

/**
 * @brief Create a timer and schedule periodic updates of a subscription.
 *
 * @param[in] period_ms Update period in msec.
 * @param[in] anchor_time Anchor time to use with the period, if any.
 * @param[in] sub Subscription as the timer callback argument.
 * @param[in,out] sntimer Timer.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srsn_yp_schedule_periodic_update(uint32_t period_ms, const struct timespec *anchor_time,
        struct srsn_sub *sub, struct srsn_timer *sntimer);

/**
 * @brief Create all sysrepo subscriptions for a single yang-push on-change subscription.
 *
 * @param[in] sess Session to use for sysrepo calls.
 * @param[in] sub Subscription to SR subscribe.
 * @param[in] sub_no_thread Create the subscriptions without a managing thread.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srsn_yp_sr_subscribe(sr_session_ctx_t *sess, struct srsn_sub *sub, int sub_no_thread);

/**
 * @brief Modify a single yang-push periodic subscription.
 *
 * @param[in] sub Subscription to modify.
 * @param[in] period_ms Period in ms to set.
 * @param[in] anchor_time Anchor time to set, NULL to unset it.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srsn_yp_periodic_modify(struct srsn_sub *sub, uint32_t period_ms, const struct timespec *anchor_time);

/**
 * @brief Modify a single yang-push on-change subscription.
 *
 * @param[in] sub Subscription to modify.
 * @param[in] dampening_period_ms Dumpening period in ms to set.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srsn_yp_on_change_modify(struct srsn_sub *sub, uint32_t dampening_period_ms);

#endif /* SN_YANG_PUSH_H_ */
