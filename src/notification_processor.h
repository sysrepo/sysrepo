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

#include "sysrepo.h"

typedef struct rp_ctx_s rp_ctx_t;          /**< Forward-declaration of Request Processor context. */
typedef struct rp_session_s rp_session_t;  /**< Forward-declaration of Request Processor session context. */
typedef struct ac_ucred_s ac_ucred_t;      /**< Forward-declaration of user credentials context. */

/**
 * @defgroup np Notification Processor
 * @{
 *
 * @brief Notification Processor tracks all active notification subscriptions
 * and generates notification messages to be delivered to subscribers.
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
    const char *username;              /**< Name of the user behind the subscription (for event notifications only). */
    uint32_t priority;                 /**< Priority of the subscription by delivering notifications (0 is the lowest priority). */
    bool enable_running;               /**< TRUE if the subscription enables specified subtree in the running datastore. */
    bool enable_nacm;                  /**< TRUE if the NETCONF Access Control is enabled for this subscription. */
    sr_api_variant_t api_variant;      /**< API variant -- values vs. trees (relevant for the callback type only). */
    size_t copy_cnt;                   /**< Count of other references to the primary structure. 0 means no other copies exist. */
} np_subscription_t;

/**
 * @brief Type of the event notification data stored within the ::np_ev_notification_t structure.
 */
typedef enum np_ev_notif_data_type_s {
    NP_EV_NOTIF_DATA_NONE,             /**< No data. */
    NP_EV_NOTIF_DATA_XML,              /**< Data in XML format. */
    NP_EV_NOTIF_DATA_STRING,           /**< Data in string xml format */
    NP_EV_NOTIF_DATA_JSON,             /**< Data in string JSON format */
    NP_EV_NOTIF_DATA_VALUES,           /**< Data in st_val_t format. */
    NP_EV_NOTIF_DATA_TREES,            /**< Data in sr_node_t format. */
    NP_EV_NOTIF_DATA_LYB,              /**< Data in LYB format. */
} np_ev_notif_data_type_t;

/**
 * @brief Event notification retrieved from the datastore.
 */
typedef struct np_ev_notification_s {
    const char *xpath;                  /**< XPath of the notification. */
    time_t timestamp;                   /**< Notification generation time. */
    np_ev_notif_data_type_t data_type;  /**< type of the notification data, if available. */
    union {
        struct lyxml_elem *xml;         /**< XML of the data as parsed by libyang. */
        const char *string;             /**< XML in string format */
        sr_val_t *values;               /**< Values with the notification data. */
        sr_node_t *trees;               /**< Trees with the notification data. */
    } data;
    size_t data_cnt;                    /**< Values of the data. */
} np_ev_notification_t;

/**
 * @brief Initializes a Notification Processor instance.
 *
 * @param[in] rp_ctx Request Processor context.
 * @param[in] schema_search_dir Directory containing PM's YANG module schema.
 * @param[in] data_search_dir Directory containing the data files.
 * @param[out] np_ctx Allocated Notification Processor context that can be used in subsequent NP API calls.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_init(rp_ctx_t *rp_ctx, const char *schema_search_dir, const char *data_search_dir, np_ctx_t **np_ctx);

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
    NP_SUBSCR_EV_EVENT = 4,
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
 * @param[in] username Effective user name used to authorize access to receive (event) notifications.
 * @param[in] notif_event Notification event which the notification subscriber is interested in.
 * @param[in] priority Priority of the subscribtion by delivering notifications (0 is the lowest priority).
 * @param[in] api_variant Variant of the subscription API which was used to create the subscription.
 * @param[in] opts Options overriding default handling. Bitwise OR-ed value of any ::np_subscr_flag_t flags.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_notification_subscribe(np_ctx_t *np_ctx, const rp_session_t *rp_session, Sr__SubscriptionType type,
        const char *dst_address, uint32_t dst_id, const char *module_name, const char *xpath, const char *username,
        Sr__NotificationEvent notif_event, uint32_t priority, sr_api_variant_t api_variant, const np_subscr_options_t opts);

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
 * @param[in] state The new state of the module (uninstalled/imported/implemented).
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_module_install_notify(np_ctx_t *np_ctx, const char *module_name, const char *revision,
        sr_module_state_t state);

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
 * @brief Gets all subscriptions that subscribe for changes in specified module
 * or in a subtree within the specified module.
 *
 * @param[in] np_ctx Notification Processor context acquired by ::np_init call.
 * @param[in] user_cred Credentials of the user requesting storing of the notification.
 * @param[in] module_name Name of the module where the subscription is active.
 * @param[out] subscriptions List of pointers to subscriptions matching the criteria. NULL can be returned in case that
 * no matching subscriptions has been found.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_get_module_change_subscriptions(np_ctx_t *np_ctx, const ac_ucred_t *user_cred, const char *module_name,
        sr_list_t **subscriptions);

/**
 * @brief Gets all operational data provider subscriptions in specified module
 * or in a subtree within the specified module.
 *
 * @param[in] np_ctx Notification Processor context acquired by ::np_init call.
 * @param[in] rp_session Request Processor session context.
 * @param[in] module_name Name of the module where the subscription is active.
 * @param[out] subscriptions List of pointers to subscriptions matching the criteria. NULL can be returned in case that
 * no matching subscriptions has been found.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_get_data_provider_subscriptions(np_ctx_t *np_ctx, const rp_session_t *rp_session, const char *module_name,
        sr_list_t **subscriptions);

/**
 * @brief Notify the subscriber about the change they are subscribed to.
 *
 * @param[in] np_ctx Notification Processor context acquired by ::np_init call.
 * @param[in] subscription Subscription context acquired by ::np_get_module_change_subscriptions call.
 * @param[in] event type of event to be sent to subscription
 * @param[in] commit_id ID of the commit to be used for starting a new notification session from client library.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_subscription_notify(np_ctx_t *np_ctx, np_subscription_t *subscription, sr_notif_event_t event, uint32_t commit_id);

/**
 * @brief Request operational data from a data provider subscription.
 *
 * @param[in] np_ctx Notification Processor context acquired by ::np_init call.
 * @param[in] subscription Subscription context acquired by ::np_get_data_provider_subscriptions call.
 * @param[in] session Request Processor session that is requesting the data.
 * @param[in] xpath XPath identifying requested operational data subtree.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_data_provider_request(np_ctx_t *np_ctx, np_subscription_t *subscription, rp_session_t *session, const char *xpath);

/**
 * @brief Notify NP that all notifications has been sent to the given subscribers.
 *
 * @param[in] np_ctx Notification Processor context acquired by ::np_init call.
 * @param[in] commit_id Commit identifier.
 * @param[in] commit_finished TRUE if commit has finished and can be released, FALSE if it will continue with another phase.
 * @param[in] subscriptions List of pointers to subscriptions to be notified about commit end.
 * NULL can be passed in case that commit_finished != true.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_commit_notifications_sent(np_ctx_t *np_ctx, uint32_t commit_id,  bool commit_finished, sr_list_t *subscriptions);

/**
 * @brief Release the commit context related to specified commit ID.
 *
 * @param[in] np_ctx Notification Processor context acquired by ::np_init call.
 * @param[in] commit_id Commit identifier.
 * @param[in] timeout_expired TRUE is commit timeout has expired.
 * @return Error code (SR_ERR_OK on success).
 */
int np_commit_notifications_complete(np_ctx_t *np_ctx, uint32_t commit_id, bool timeout_expired);

/**
 * @brief Track a response to a notification (notification acknowledgment).
 *
 * @param[in] np_ctx Notification Processor context acquired by ::np_init call.
 * @param[in] commit_id Commit identifier.
 * @param[in] subs_xpath XPath where the subscription is subscribed to.
 * @param[in] event Event that is currently being processed.
 * @param[in] result Result of the processing by the subscriber.
 * @param[in] do_not_send_abort if true the xpath will be added to the list of subscriptions that do no want abort
 * @param[in] err_msg Error message (in case that result != SR_ERR_OK and it was provided).
 * @param[in] err_xpath XPath to the node where the error occured (in case that result != SR_ERR_OK and it was provided).
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_commit_notification_ack(np_ctx_t *np_ctx, uint32_t commit_id, char *subs_xpath, sr_notif_event_t event,
        int result, bool do_not_send_abort, const char *err_msg, const char *err_xpath);

/**
 * @brief Cleans up a subscription context (including all its content).
 *
 * @param[in] subscription Subscription context to be freed.
 */
void np_subscription_cleanup(np_subscription_t *subscription);

/**
 * @brief Cleans up the content of a subscription context, does not free the context itself.
 *
 * @param[in] subscription Subscription context to be freed.
 */
void np_subscription_content_cleanup(np_subscription_t *subscription);

/**
 * @brief Cleans up a list of pointers to subscription contexts (including all the subscription contexts).
 *
 * @param[in] subscriptions_list List of subscription contexts to be freed.
 */
void np_subscriptions_list_cleanup(sr_list_t *subscriptions_list);

/**
 * @brief Stores an event notification in the notification datastore.
 *
 * @param[in] np_ctx Notification Processor context acquired by ::np_init call.
 * @param[in] user_cred Credentials of the user requesting storing of the notification.
 * @param[in] xpath XPath of the notification to be stored.
 * @param[in] generated_time Time when notification has been generated.
 * @param[in] data_tree Pointer to the data tree of the notification.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_store_event_notification(np_ctx_t *np_ctx, const ac_ucred_t *user_cred, const char *xpath,
        const time_t generated_time, struct lyd_node *data_tree);

/**
 * @brief Retrieves event notifications from the notification datastore.
 *
 * @param[in] np_ctx Notification Processor context acquired by ::np_init call.
 * @param[in] rp_session Request Processor session context.
 * @param[in] xpath XPath of the notification to be retrieved.
 * @param[in] start_time Start time of the time window.
 * @param[in] stop_time Stop time of the time window.
 * @param[in] api_variant Requested API variant (values/trees) of the data to be retrieved.
 * @param[out] notifications List with all notifications matching requested parameters.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_get_event_notifications(np_ctx_t *np_ctx, rp_session_t *rp_session, const char *xpath,
        const time_t start_time, const time_t stop_time, const sr_api_variant_t api_variant, sr_list_t **notifications);

/**
 * @brief Cleans up an event notification structure.
 *
 * @param[in] notification Event notification context to be destroyed.
 */
void np_event_notification_cleanup(np_ev_notification_t *notification);

/**
 * @brief Cleans up notification store - old notification data files.
 *
 * @param[in] np_ctx Notification Processor context acquired by ::np_init call.
 * @param[in] reschedule TRUE if cleanup should be rescheduled after some timeout again.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int np_notification_store_cleanup(np_ctx_t *np_ctx, bool reschedule);

/**@} np */

#endif /* NOTIFICATION_PROCESSOR_H_ */
