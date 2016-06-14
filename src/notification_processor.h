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
    Sr__SubscriptionType type;         /**< Type of the subscription that this subscription subscribes to. */
    Sr__NotificationEvent notif_event; /**< Notification event which the notification subscriber is interested in. */
    const char *dst_address;           /**< Destination address where the notification should be delivered. */
    uint32_t dst_id;                   /**< Destination ID of the subscription (used locally, in the client library). */
    const char *module_name;           /**< Name of the module where the subscription is active. */
    const char *xpath;                 /**< XPath to the subtree where the subscription is active (if applicable). */
    uint32_t priority;                 /**< Priority of the subscription by delivering notifications (0 is the lowest priority). */
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
 * @brief Flags used to override default default handling by ::np_notification_subscribe call.
 */
typedef enum np_subscr_flag_e {
    NP_SUBSCR_DEFAULT = 0,
    NP_SUBSCR_ENABLE_RUNNING = 1,
    NP_SUBSCR_EXCLUSIVE = 2,
} np_subscr_flag_t;

/**
 * @brief Options overriding default handling by ::np_notification_subscribe call,
 * can be bitwise OR-ed value of any ::np_subscr_flag_t flags.
 */
typedef uint32_t np_subscr_options_t;

/**
 * @brief Subscribe the client to notifications on specified event.
 *
 * @param[in] np_ctx Notification Processor context acquired by ::np_init call.
 * @param[in] rp_session Request Processor session.
 * @param[in] type Type of the subscription to subscribe.
 * @param[in] dst_address Destination address of the subscriber.
 * @param[in] dst_id Destination subscription ID.
 * @param[in] module_name Name of the module which the subscription is active in (if applicable).
 * @param[in] xpath XPath to the subtree where the subscription is active (if applicable).
 * @param[in] notif_event Notification event which the notification subscriber is interested in.
 * @param[in] priority Priority of the subscribtion by delivering notifications (0 is the lowest priority).
 * @param[in] opts Options overriding default handling. Bitwise OR-ed value of any ::np_subscr_flag_t flags.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_notification_subscribe(np_ctx_t *np_ctx, const rp_session_t *rp_session, Sr__SubscriptionType type,
        const char *dst_address, uint32_t dst_id, const char *module_name, const char *xpath,
        Sr__NotificationEvent notif_event, uint32_t priority, const np_subscr_options_t opts);

/**
 * @brief Unsubscribe the client from notifications on specified event.
 *
 * @param[in] np_ctx Notification Processor context acquired by ::np_init call.
 * @param[in] rp_session Request Processor session.
 * @param[in] type Type of the subscription.
 * @param[in] dst_address Destination address of the subscriber.
 * @param[in] dst_id Destination subscription ID.
 * @param[in] module_name Name of the module which the subscription is active in (if applicable).
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_notification_unsubscribe(np_ctx_t *np_ctx, const rp_session_t *rp_session, Sr__SubscriptionType type,
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

/**
 * @brief Gets all subscriptions that subscibe for changes in specified module
 * or in a subtree within the specified module.
 *
 * @param[in] np_ctx Notification Processor context acquired by ::np_init call.
 * @param[in] module_name ame of the module where the subscription is active.
 * @param[out] subscriptions_arr Array of pointers to subscriptions matching the criteria.
 * @param[out] subscriptions_cnt Count of the matching subscriptions.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_get_module_change_subscriptions(np_ctx_t *np_ctx, const char *module_name,
        np_subscription_t ***subscriptions_arr, size_t *subscriptions_cnt);

/**
 * @brief Notify the subscriber about the change they are subscribed to.
 *
 * @param[in] np_ctx Notification Processor context acquired by ::np_init call.
 * @param[in] subscription Subscription context acquired by ::np_get_module_change_subscriptions call.
 * @param[in] commit_id ID of the commit to be used for starting a new notification session from client library.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_subscription_notify(np_ctx_t *np_ctx, np_subscription_t *subscription, uint32_t commit_id);

/**
 * @brief Notify given subscribers that the commit process has ended.
 *
 * @param[in] np_ctx Notification Processor context acquired by ::np_init call.
 * @param[in] commit_id Commit identifier.
 * @param[in] subscriptions List of subscriptions to be notified about commit end.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_commit_end_notify(np_ctx_t *np_ctx, uint32_t commit_id, sr_list_t *subscriptions);

/**
 * @brief Release the commit context related to specified commit ID.
 *
 * @param[in] np_ctx Notification Processor context acquired by ::np_init call.
 * @param[in] commit_id Commit identifier.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_commit_release(np_ctx_t *np_ctx, uint32_t commit_id);

/**
 * @brief
 *
 * @param[in] np_ctx Notification Processor context acquired by ::np_init call.
 * @param[in] commit_id Commit identifier.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_commit_notification_ack(np_ctx_t *np_ctx, uint32_t commit_id);

/**
 * @brief Cleans up a subscription context (including all its content).
 *
 * @param[in] subscription Subscription context to be freed.
 */
void np_free_subscription(np_subscription_t *subscription);

/**
 * @brief Cleans up the content of a subscription context, does not free the context itself.
 *
 * @param[in] subscription Subscription context to be freed.
 */
void np_free_subscription_content(np_subscription_t *subscription);

/**
 * @brief Cleans up an array of subscription contexts (including all its content).
 *
 * @param[in] subscriptions Array of subscription contexts to be freed.
 * @param[in] subscriptions_cnt Count of the subscriptions in the array.
 */
void np_free_subscriptions(np_subscription_t *subscriptions, size_t subscriptions_cnt);

/**@} np */

#endif /* NOTIFICATION_PROCESSOR_H_ */
