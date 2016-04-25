/**
 * @file notification_processor.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo Notification Processor API.
 *
 * @copyright
 * Copyright 2016 Cisco Systems, Inc.
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

#ifndef NOTIFICATION_PROCESSOR_H_
#define NOTIFICATION_PROCESSOR_H_

typedef struct rp_ctx_s rp_ctx_t;          /**< Forward-declaration of Request Processor context. */
typedef struct rp_session_s rp_session_t;  /**< Forward-declaration of Request Processor session context. */
typedef struct ac_ucred_s ac_ucred_t;      /**< Forward-declaration of user credentials context. */

/**
 * @defgroup np Notification Processor
 * @{
 *
 * @brief Notification Processor tracks all active notification subscriptions
 * and generates notificion messages to be delivered to subscibers.
 */

/**
 * @brief Notification Processor context.
 */
typedef struct np_ctx_s np_ctx_t;

/**
 * @brief Notification subscription information.
 */
typedef struct np_subscription_s {
    Sr__NotificationEvent event_type;  /**< Type of the event that this subscription subscribes to.  */
    const char *dst_address;           /**< Destination address where the notification should be delivered. */
    uint32_t dst_id;                   /**< Destination ID of the subscription (used locally, in the client library). */
    const char *xpath;                 /**< XPath to the subtree where the subscription is active (if applicable). */
    bool enable_running;               /**< TRUE if the subscription enables specified subtree in the running datastore. */
} np_subscription_t;

/**
 * @brief Initializes a Notification Processor instance.
 *
 * @param[in] rp_ctx Request Processor context.
 * @param[out] np_ctx Allocated Notification Processor context that can be used in subsequent NP API calls.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_init(rp_ctx_t *rp_ctx, np_ctx_t **np_ctx);

/**
 * @brief Cleans up the Notification Processor instance.
 *
 * @param[in] np_ctx Notification Processor context acquired by ::np_init call.
 */
void np_cleanup(np_ctx_t *np_ctx);

/**
 * @brief Subscribe the client to notifications on specified event.
 *
 * @param[in] np_ctx Notification Processor context acquired by ::np_init call.
 * @param[in] rp_session Request Processor session.
 * @param[in] event_type Type of the event to subscribe.
 * @param[in] dst_address Destination address of the subscriber.
 * @param[in] dst_id Destination subscription ID.
 * @param[in] module_name Name of the module which the subscription is active in (if applicable).
 * @param[in] path XPath to the subtree where the subscription is active (if applicable).
 * @param[in] enable_running TRUE if the subscription enables specified subtree in the running datastore.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_notification_subscribe(np_ctx_t *np_ctx, const rp_session_t *rp_session, Sr__NotificationEvent event_type,
        const char *dst_address, uint32_t dst_id, const char *module_name, const char *xpath, const bool enable_running);

/**
 * @brief Unsubscribe the client from notifications on specified event.
 *
 * @param[in] np_ctx Notification Processor context acquired by ::np_init call.
 * @param[in] rp_session Request Processor session.
 * @param[in] event_type  Type of the event of the subscription.
 * @param[in] dst_address Destination address of the subscriber.
 * @param[in] dst_id Destination subscription ID.
 * @param[in] module_name Name of the module which the subscription is active in (if applicable).
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_notification_unsubscribe(np_ctx_t *np_ctx, const rp_session_t *rp_session, Sr__NotificationEvent event_type,
        const char *dst_address, uint32_t dst_id, const char *module_name);

/**
 * @brief Unsubscribe the client from all notifications to be delivered on
 * specified destination address.
 *
 * @param[in] np_ctx Notification Processor context acquired by ::np_init call.
 * @param[in] dst_address Notification delivery destination address.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_unsubscribe_destination(np_ctx_t *np_ctx, const char *dst_address);

/**
 * @brief Notify all subscribers about the module (un)installation event.
 *
 * @param[in] np_ctx Notification Processor context acquired by ::np_init call.
 * @param[in] module_name Name of the module that has been (un)installed.
 * @param[in] revision Revision of the module that has been (un)installed.
 * @param[in] installed TRUE if the module has been installed, FALSE if uninstalled.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_module_install_notify(np_ctx_t *np_ctx, const char *module_name, const char *revision, bool installed);

/**
 * @brief Notify all subscribers about the feature enable/disable event.
 *
 * @param[in] np_ctx Notification Processor context acquired by ::np_init call.
 * @param[in] module_name Name of the module where feature has been enabled/disabled.
 * @param[in] feature_name Name of the feature that has been enabled/disabled.
 * @param[in] enabled TRUE if the feature has been enabled, FALSE if disabled.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_feature_enable_notify(np_ctx_t *np_ctx, const char *module_name, const char *feature_name, bool enabled);

/**
 * @brief Notify all subscribers about the change of data within a module.
 *
 * @param[in] np_ctx Notification Processor context acquired by ::np_init call.
 * @param[in] module_name Name of the module where the change has occurred.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_module_change_notify(np_ctx_t *np_ctx, const char *module_name);

/**
 * @brief Tests the subscription by sending of a hello notification.
 *
 * @param[in] np_ctx Notification Processor context acquired by ::np_init call.
 * @param[in] module_name Name of the module where the subscription is active.
 * @param[in] dst_address Destination address of the subscriber.
 * @param[in] dst_id Destination subscription ID.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_hello_notify(np_ctx_t *np_ctx, const char *module_name, const char *dst_address, uint32_t dst_id);

/**@} np */

#endif /* NOTIFICATION_PROCESSOR_H_ */
