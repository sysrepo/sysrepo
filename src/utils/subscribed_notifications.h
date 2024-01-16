/**
 * @file subscribed_notifications.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief multi-module notification subscription functions header
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

#ifndef SYSREPO_SUBSCRIBED_NOTIFICATIONS_H_
#define SYSREPO_SUBSCRIBED_NOTIFICATIONS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/stat.h>

#include "sysrepo.h"

/**
 * @brief Type of the subscribed-notifications subscription.
 */
typedef enum {
    SRSN_SUB_NOTIF,             /**< standard subscribed-notifications subscription */
    SRSN_YANG_PUSH_PERIODIC,    /**< yang-push periodic subscription */
    SRSN_YANG_PUSH_ON_CHANGE    /**< yang-push on-change subscription */
} srsn_sub_type_t;

typedef enum {
    SRSN_YP_CHANGE_INVALID = -1,
    SRSN_YP_CHANGE_CREATE,
    SRSN_YP_CHANGE_DELETE,
    SRSN_YP_CHANGE_INSERT,
    SRSN_YP_CHANGE_MOVE,
    SRSN_YP_CHANGE_REPLACE,
    SRSN_COUNT_YP_CHANGE
} srsn_yp_change_t;

typedef struct {
    uint32_t sub_id;
    char *xpath_filter;
    struct timespec stop_time;
    uint32_t sent_count;
    uint32_t excluded_count;
    int suspended;

    srsn_sub_type_t type;

    union {
        struct {
            char *stream;
            struct timespec start_time;
        } sub_notif;
        struct {
            sr_datastore_t ds;
            uint32_t period;
            struct timespec anchor_time;
        } yp_periodic;
        struct {
            sr_datastore_t ds;
            uint32_t dampening_period;
            int sync_on_start;
            int excluded_change[SRSN_COUNT_YP_CHANGE];
        } yp_on_change;
    };
} srsn_state_sub_t;

/**
 * @brief Transform a subtree filter into an XPath filter.
 *
 * @param[in] subtree Subtree of the filter itself.
 * @param[in] session Optional session for storing errors.
 * @param[out] xpath_filter Generated XPath filter.
 * @return Error code (::SR_ERR_OK on success).
 */
int srsn_filter_subtree2xpath(const struct lyd_node *subtree, sr_session_ctx_t *session, char **xpath_filter);

/**
 * @brief Increase the sent-notifications counter in case of additional manually-generated notifications
 * (such as 'subscription-modified').
 *
 * @param[in] sub_id Subscription ID of the subscription.
 * @return Error code (::SR_ERR_OK on success).
 */
int srsn_notif_sent(uint32_t sub_id);

/**
 * @brief Subscribe for receiving notifications according to 'ietf-subscribed-notifications' YANG.
 *
 * @param[in] session Session to use for SR subscriptions.
 * @param[in] stream Stream to subscribe to.
 * @param[in] xpath_filter Optional XPath filter to use.
 * @param[in] stop_time Optional stop-time of the subscription. Once reached, the `subscription-terminated' notification
 * is generated.
 * @param[in] start_time Optional start-time of the subscription, requires the 'replay' feature.
 * @param[in] sub_no_thread Set if the created subscriptions should not create a separate handling thread.
 * @param[in,out] sub Optional subscription structure to use and add SR subscriptions to.
 * @param[out] replay_start_time Optional replay-start-time of the subscription if start-time was set.
 * @param[out] fd Pipe end for reading the generated notifications. Needs to be closed.
 * @param[out] sub_id Unique subscribed-notifications ID.
 * @return Error code (::SR_ERR_OK on success).
 */
int srsn_subscribe(sr_session_ctx_t *session, const char *stream, const char *xpath_filter, const struct timespec *stop_time,
        const struct timespec *start_time, int sub_no_thread, sr_subscription_ctx_t **sub,
        struct timespec *replay_start_time, int *fd, uint32_t *sub_id);

/**
 * @brief Subscribe for receiving notifications according to 'ietf-yang-push' YANG periodic subscriptions.
 *
 * @param[in] session Session to use for SR operations.
 * @param[in] ds Datastore to subscribe to.
 * @param[in] xpath_filter Optional XPath filter to use.
 * @param[in] period_ms Notification period in ms.
 * @param[in] anchor_time Optional anchor time of the period.
 * @param[in] stop_time Optional stop-time of the subscription. Once reached, the `subscription-terminated' notification
 * is generated.
 * @param[out] fd Pipe end for reading the generated notifications. Needs to be closed.
 * @param[out] sub_id Unique subscribed-notifications ID.
 * @return Error code (::SR_ERR_OK on success).
 */
int srsn_yang_push_periodic(sr_session_ctx_t *session, sr_datastore_t ds, const char *xpath_filter, uint32_t period_ms,
        const struct timespec *anchor_time, const struct timespec *stop_time, int *fd, uint32_t *sub_id);

/**
 * @brief Subscribe for receiving notifications according to 'ietf-yang-push' YANG on-change subscriptions.
 *
 * @param[in] session Session to use for SR subscriptions.
 * @param[in] ds Datastore to subscribe to.
 * @param[in] xpath_filter Optional XPath filter to use.
 * @param[in] dampening_period_ms Optional notification dampening period in ms.
 * @param[in] sync_on_start Whether to start the subscription with a full datastore content notification.
 * @param[in] excluded_changes Optional array of changes to be excluded. Set index of a ::srsn_yp_change_t to 1 for it
 * to be excluded, to 0 to be included.
 * @param[in] stop_time Optional stop-time of the subscription. Once reached, the `subscription-terminated' notification
 * is generated.
 * @param[in] sub_no_thread Set if the created subscriptions should not create a separate handling thread.
 * @param[in,out] sub Optional subscription structure to use and add SR subscriptions to.
 * @param[out] fd Pipe end for reading the generated notifications. Needs to be closed.
 * @param[out] sub_id Unique subscribed-notifications ID.
 * @return Error code (::SR_ERR_OK on success).
 */
int srsn_yang_push_on_change(sr_session_ctx_t *session, sr_datastore_t ds, const char *xpath_filter,
        uint32_t dampening_period_ms, int sync_on_start, int excluded_changes[SRSN_COUNT_YP_CHANGE],
        const struct timespec *stop_time, int sub_no_thread, sr_subscription_ctx_t **sub, int *fd, uint32_t *sub_id);

/**
 * @brief Resync a yang-push on-change subscription.
 *
 * @param[in] sub_id Subscription ID of the subscription to resync.
 * @return Error code (::SR_ERR_OK on success).
 */
int srsn_yang_push_on_change_resync(uint32_t sub_id);

/**
 * @brief Modify a generic subscription xpath-filter.
 *
 * Does NOT generate the 'subscription-modified' notification.
 *
 * @param[in] sub_id Subscription ID of the subscription to modify.
 * @param[in] xpath_filter New XPath filter to use, NULL to remove any previous filter.
 * @return Error code (::SR_ERR_OK on success).
 */
int srsn_modify_xpath_filter(uint32_t sub_id, const char *xpath_filter);

/**
 * @brief Modify a generic subscription stop-time.
 *
 * Does NOT generate the 'subscription-modified' notification.
 *
 * @param[in] sub_id Subscription ID of the subscription to modify.
 * @param[in] stop_time New stop-time of the subscription, NULL to unset the previous stop-time.
 * @return Error code (::SR_ERR_OK on success).
 */
int srsn_modify_stop_time(uint32_t sub_id, const struct timespec *stop_time);

/**
 * @brief Modify a yang-push periodic subscription.
 *
 * Does NOT generate the 'subscription-modified' notification.
 *
 * @param[in] sub_id Subscription ID of the subscription to modify.
 * @param[in] period_ms Period in ms to set.
 * @param[in] anchor_time Anchor time of the period to set, NULL to unset.
 * @return Error code (::SR_ERR_OK on success).
 */
int srsn_yang_push_modify_periodic(uint32_t sub_id, uint32_t period_ms, const struct timespec *anchor_time);

/**
 * @brief Modify a yang-push on-change subscription.
 *
 * Does NOT generate the 'subscription-modified' notification.
 *
 * @param[in] sub_id Subscription ID of the subscription to modify.
 * @param[in] dampening_period_ms Dampening period in ms to set.
 * @return Error code (::SR_ERR_OK on success).
 */
int srsn_yang_push_modify_on_change(uint32_t sub_id, uint32_t dampening_period_ms);

/**
 * @brief Suspend a subscribed-notifications subscription.
 *
 * Generates the 'subscription-suspended' notification.
 *
 * @param[in] sub_id Subscription ID of the subscription to suspend.
 * @param[in] reason Reason for the suspension as an identityref value. If not set, no notification is generated.
 * @return Error code (::SR_ERR_OK on success).
 */
int srsn_suspend(uint32_t sub_id, const char *reason);

/**
 * @brief Resume a subscribed-notifications subscription.
 *
 * Generates the 'subscription-resumed' notification.
 *
 * @param[in] sub_id Subscription ID of the subscription to resume.
 * @return Error code (::SR_ERR_OK on success).
 */
int srsn_resume(uint32_t sub_id);

/**
 * @brief Terminate a subscribed-notifications subscription.
 *
 * Generates the 'subscription-terminated' notification.
 *
 * @param[in] sub_id Subscription ID of the subscription to terminate.
 * @param[in] reason Reason for the termination as an identityref value. If not set, no notification is generated.
 * @return ::SR_ERR_OK on success,
 * @return ::SR_ERR_NOT_FOUND if a subscription with @p sub_id was not found.
 */
int srsn_terminate(uint32_t sub_id, const char *reason);

/**
 * @brief Sysrepo ::sr_oper_get_items_cb() providing data of the subtree '/ietf-subscribed-notification:streams'.
 */
int srsn_oper_data_streams_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *path,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

/**
 * @brief Get subscription state data with most of the information in the subtree
 * '/ietf-subscribed-notifications:subscriptions'.
 *
 * @param[out] subs Array of subscriptions.
 * @param[out] count Count of @p subs.
 * @return Error code (::SR_ERR_OK on success).
 */
int srsn_oper_data_subscriptions(srsn_state_sub_t **subs, uint32_t *count);

/**
 * @brief Get subscription state data of a single subscription.
 *
 * @param[in] sub_id Subscription ID.
 * @param[out] sub Subscription state.
 * @return Error code (::SR_ERR_OK on success).
 */
int srsn_oper_data_sub(uint32_t sub_id, srsn_state_sub_t **sub);

/**
 * @brief Free subscription state data.
 *
 * @param[in] subs Array of subscriptions.
 * @param[in] count Count of @p subs.
 */
void srsn_oper_data_subscriptions_free(srsn_state_sub_t *subs, uint32_t count);

/**
 * @brief Read a notification.
 *
 * @param[in] fd Opened file descriptor to read from, may be non-blocking.
 * @param[in] ly_ctx Libyang context to use for parsing the notification.
 * @param[out] timestamp Notification timestamp.
 * @param[out] notif Parsed notification.
 * @return ::SR_ERR_OK on success,
 * @return ::SR_ERR_TIME_OUT if reading would block,
 * @return ::SR_ERR_UNSUPPORTED on end-of-file (subscription terminated, the write end was closed),
 * @return ::SR_ERR_SYS on another error (logged).
 */
int srsn_read_notif(int fd, const struct ly_ctx *ly_ctx, struct timespec *timestamp, struct lyd_node **notif);

/**
 * @brief Poll a file descriptor for data to read.
 *
 * @param[in] fd File descriptor to poll.
 * @param[in] timeout_ms Timeout for the poll.
 * @return ::SR_ERR_OK on data to read,
 * @return ::SR_ERR_TIME_OUT if there were no data to read in the specified timeout,
 * @return ::SR_ERR_UNSUPPORTED on end-of-file (subscription terminated, the write end was closed),
 * @return ::SR_ERR_SYS on another error (logged).
 */
int srsn_poll(int fd, uint32_t timeout_ms);

/**
 * @brief Callback for reading notifications.
 *
 * @param[in] notif Read notification.
 * @param[in] timestamp Notification timestamp.
 * @param[in] cb_data User callback data for the FD the @p notif was received from.
 */
typedef void (*srsn_notif_cb)(const struct lyd_node *notif, const struct timespec *timestamp, void *cb_data);

/**
 * @brief Dispatch a per-process thread for reading notifications.
 *
 * Thread automatically terminates after all the @p fd subscriptions terminate by closing their pipes (more can be
 * added using ::srsn_read_dispatch_add()). In that case all the FD read ends are also automatically closed.
 *
 * @param[in] fd File descriptor to read from.
 * @param[in] conn Connection that must not be terminated while the notifications are being processed.
 * @param[in] cb Callback to be called for each notification.
 * @param[in] cb_data User @p cb callback data for the @p fd.
 * @return Error code (::SR_ERR_OK on success).
 */
int srsn_read_dispatch_start(int fd, sr_conn_ctx_t *conn, srsn_notif_cb cb, void *cb_data);

/**
 * @brief Add another subscription to be handled by the dispatched thread.
 *
 * @param[in] fd Subscription file descriptor to read from.
 * @param[in] cb_data User @p cb callback data for the @p fd.
 * @return Error code (::SR_ERR_OK on success).
 */
int srsn_read_dispatch_add(int fd, void *cb_data);

/**
 * @brief Get the number of subscriptions currently handled by the dispatched thread.
 *
 * @return Number of handled subscriptions, 0 means the dispatch thread is not running.
 */
uint32_t srsn_read_dispatch_count(void);

#ifdef __cplusplus
}
#endif

#endif /* SYSREPO_SUBSCRIBED_NOTIFICATIONS_H_ */
