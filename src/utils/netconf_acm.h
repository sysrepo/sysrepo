/**
 * @file netconf_acm.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief NACM functionality header
 *
 * @copyright
 * Copyright (c) 2019 - 2022 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2022 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef SYSREPO_NETCONF_ACM_H_
#define SYSREPO_NETCONF_ACM_H_

#include "../sysrepo.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize NACM and its callbacks.
 *
 * Needs to be called only **once** in each process. Subscriptions created in @p sub need to be unsubscribed separately
 * and before calling ::sr_nacm_destroy().
 *
 * @param[in] session Session to use.
 * @param[in] opts Optionally, ::SR_SUBSCR_NO_THREAD can be specified. No other flags are allowed.
 * @param[out] sub Subscription context.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_nacm_init(sr_session_ctx_t *session, sr_subscr_options_t opts, sr_subscription_ctx_t **sub);

/**
 * @brief Subscribe for providing global NACM stats. These include triggering subscriptions made by ::sr_nacm_init() so
 * another subscription structure is required.
 *
 * There can be only a single provider of these data on a system and in case there already is, this function
 * returns success but does not modify @p sub.
 *
 * @param[in] session Session to use.
 * @param[in] opts Optionally, ::SR_SUBSCR_NO_THREAD can be specified. No other flags are allowed.
 * @param[out] sub Subscription context, **must** be different from the one used in ::sr_nacm_init()!
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_nacm_glob_stats_subscribe(sr_session_ctx_t *session, sr_subscr_options_t opts, sr_subscription_ctx_t **sub);

/**
 * @brief Destroy NACM.
 */
void sr_nacm_destroy(void);

/**
 * @brief Set the NACM user for this session, which enables NACM for all operations on this session.
 *
 * Affected operations:
 *
 * - reading data - unaccesible data are silently filtered out from the returned data;
 * - editing data - on an attempt to edit data without the proper access NETCONF error is returned;
 * - sending RPC/action - on an attempt to send RPC/action without the proper access NETCONF error is returned;
 * - receiving notifications - notifications without the proper access are silently dropped.
 *
 * @param[in] session Session to use.
 * @param[in] user NACM username to use. If NULL, the username is cleared disabling NACM.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_nacm_set_user(sr_session_ctx_t *session, const char *user);

/**
 * @brief Get the NACM user of the session.
 *
 * @return Session NACM user.
 */
const char *sr_nacm_get_user(sr_session_ctx_t *session);

/**
 * @brief Get username of the NACM recovery user with unrestricted access.
 *
 * @return Username of NACM recovery session.
 */
const char *sr_nacm_get_recovery_user(void);

#ifdef __cplusplus
}
#endif

#endif /* SYSREPO_NETCONF_ACM_H_ */
