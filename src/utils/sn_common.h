/**
 * @file sn_common.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-subscribed-notifications common functions header
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

#ifndef SN_COMMON_H_
#define SN_COMMON_H_

#define _GNU_SOURCE

#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>

#include <libyang/libyang.h>

#include "common.h"
#include "compat.h"
#include "subscribed_notifications.h"
#include "sysrepo.h"

/**
 * @brief Internal filter structure.
 */
struct srsn_filter {
    struct {
        char *str;      /**< filter string */
        int selection;  /**< selection or content filter */
    } *filters;
    uint32_t count;
};

/**
 * @brief Internal timer structure.
 */
struct srsn_timer {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    pthread_t tid;
    void (*cb)(void *arg, int *freed);
    void *arg;
    struct timespec trigger;
    struct timespec interval;
};

/**
 * @brief Stored realtime notifications.
 */
struct srsn_rt_notif {
    struct lyd_node *notif;
    struct timespec timestamp;
};

/**
 * @brief Dispatch thread argument.
 */
struct srsn_dispatch_arg {
    sr_conn_ctx_t *conn;
    srsn_notif_cb cb;
};

/**
 * @brief Complete operational information about the subscriptions.
 */
struct srsn_state {
    /* subscriptions */
    pthread_mutex_t sub_lock;
    struct srsn_sub {
        uint32_t id;
        int rfd;
        int wfd;
        sr_subscription_ctx_t *sr_sub;
        int unsub;
        uint32_t *sr_sub_ids;
        ATOMIC_T sr_sub_id_count;
        char *xpath_filter;
        struct timespec stop_time;
        struct srsn_timer stop_sntimer;
        sr_conn_ctx_t *conn;
        ATOMIC_T sent_count;

        srsn_sub_type_t type;
        union {
            char *stream;
            sr_datastore_t ds;
        };
        union {
            struct {
                struct timespec start_time;
                struct srsn_rt_notif *rt_notifs;    /* buffered realtime notifications received before replay complete */
                uint32_t rt_notif_count;
                ATOMIC_T replay_complete_count;     /* counter of special replay-complete notifications received */
            };
            struct {
                uint32_t period_ms;
                struct timespec anchor_time;
                struct srsn_timer update_sntimer;
                int suspended;
            };
            struct {
                uint32_t dampening_period_ms;
                int sync_on_start;
                int excluded_changes[SRSN_COUNT_YP_CHANGE];

                sr_data_t *change_ntf;
                uint32_t patch_id;
                uint32_t edit_id;
                struct timespec last_notif;
                struct srsn_timer damp_sntimer;
                uint32_t excluded_change_count; /* explicitly excluded changes */
            };
        };
    } **subs;
    uint32_t count;

    /* notification dispatch */
    pthread_mutex_t dispatch_lock;
    struct pollfd *pfds;
    void **cb_data;
    uint32_t pfd_count;
    uint32_t valid_pfds;    /**< count of current valid (fd > -1) pfd items */
};

/**
 * @brief Erase all members of a filter structure.
 *
 * @param[in] filter Filter to erase.
 */
void srsn_filter_erase(struct srsn_filter *filter);

/**
 * @brief Create a filter structure from a subtree filter.
 *
 * @param[in] node Subtree filter.
 * @param[in,out] ev_sess SR event session to set the error on.
 * @param[in,out] filter Generated filter structure.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srsn_filter_create_subtree(const struct lyd_node *node, struct srsn_filter *filter);

/**
 * @brief Transform a filter structure into XPath filter.
 *
 * @param[in] filter Filter structure.
 * @param[out] xpath Generated XPath filter.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srsn_filter_filter2xpath(const struct srsn_filter *filter, char **xpath);

/**
 * @brief Generate a new unique subscription ID.
 *
 * @return New sub ID.
 */
uint32_t srsn_new_id(void);

/**
 * @brief Lock the subscription state.
 *
 * @return err_info, NULL on success.
 */
sr_error_info_t *srsn_lock(void);

/**
 * @brief Unlock the subscription state.
 */
void srsn_unlock(void);

/**
 * @brief Prepare a new generic subscription structure.
 *
 * @param[in] xpath_filter XPath filter to use.
 * @param[in] stop_time Stop-time of the subscription.
 * @param[in] sr_sub User sub parameter.
 * @param[in] conn Connection to store.
 * @param[out] sub Created subscription.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srsn_sub_new(const char *xpath_filter, const struct timespec *stop_time, sr_subscription_ctx_t **sr_sub,
        sr_conn_ctx_t *conn, struct srsn_sub **sub);

/**
 * @brief Unsubscribe all notifications of a subscription.
 *
 * @param[in] sub Subscription to unsubscribe.
 */
void srsn_sub_free_unsubscribe(struct srsn_sub *sub);

/**
 * @brief Free a subscription.
 *
 * @param[in] sub Subscription to free.
 */
void srsn_sub_free(struct srsn_sub *sub);

/**
 * @brief Schedule the stop-time of a subscription, if any.
 *
 * @param[in] sub Subscription to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srsn_sub_schedule_stop(struct srsn_sub *sub);

/**
 * @brief Add a prepared and valid subscription into internal subscriptions.
 *
 * @param[in] sub Subscription to add.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srsn_sub_add(struct srsn_sub *sub);

/**
 * @brief Collect information about a single subscription state.
 *
 * @param[in] s Subscription to use.
 * @param[in,out] sub Subscription state.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srsn_state_collect_sub(const struct srsn_sub *s, srsn_state_sub_t *sub);

/**
 * @brief Collect information about the subscription state.
 *
 * @param[out] subs Array of subscriptions.
 * @param[out] count Count of @p subs.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srsn_state_collect(srsn_state_sub_t **subs, uint32_t *count);

/**
 * @brief Free the collected subscription state.
 *
 * @param[in] subs Array of subscriptions.
 * @param[in] count Count of @p subs.
 */
void srsn_state_free(srsn_state_sub_t *subs, uint32_t count);

/**
 * @brief Find a subscription wtih a specific sub ID.
 *
 * @param[in] sub_id Sub ID of the subscription to find.
 * @param[in] locked Whether the state lock is already held or not.
 * @return Found subscription, NULL if none found.
 */
struct srsn_sub *srsn_find(uint32_t sub_id, int locked);

/**
 * @brief Send a notification for a subscription.
 *
 * @param[in] sub Subscription to use.
 * @param[in] timestamp Notification timestamp.
 * @param[in] ly_ntf Notification data tree.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srsn_ntf_send(struct srsn_sub *sub, const struct timespec *timestamp, const struct lyd_node *ly_ntf);

/**
 * @brief Create a new SRSN timer.
 *
 * @param[in] cb Callback to call on a trigger.
 * @param[in] arg Argument to pass @p cb.
 * @param[in] trigger Timer trigger.
 * @param[in] interval Optional timer interval.
 * @param[out] sntimer Created timer.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srsn_create_timer(void (*cb)(void *arg, int *freed), void *arg, const struct timespec *trigger,
        const struct timespec *interval, struct srsn_timer *sntimer);

/**
 * @brief Update or stop a timer.
 *
 * @param[in] trigger New trigger of the timer, NULL to stop it instead.
 * @param[in] interval New interval of the timer.
 * @param[in] sntimer Timer to update.
 */
void srsn_update_timer(const struct timespec *trigger, const struct timespec *interval, struct srsn_timer *sntimer);

/**
 * @brief Send a 'subscription-terminated' notification on a subscription.
 *
 * @param[in] sub Subscription to use.
 * @param[in] reason Reason for the termination, as an identity.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srsn_ntf_send_terminated(struct srsn_sub *sub, const char *reason);

/**
 * @brief Modify the XPath filter of a subscription.
 *
 * @param[in] sub Subscription to modify.
 * @param[in] xpath_filter New filter to set, NULL clears the previous one.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srsn_modify_xpath(struct srsn_sub *sub, const char *xpath_filter);

/**
 * @brief Modify the stop-time of a subscription.
 *
 * @param[in] sub Subscription to modify.
 * @param[in] stop_time New stop-time to use, NULL to remove the previous one.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srsn_modify_stop(struct srsn_sub *sub, const struct timespec *stop_time);

/**
 * @brief Check whether a module defines any notifications.
 *
 * @param[in] mod Module to check.
 * @return Whether the module defines any notifications.
 */
int srsn_ly_mod_has_notif(const struct lys_module *mod);

/**
 * @brief Create all sysrepo subscriptions for a single sub-ntf subscription.
 *
 * @param[in] sess Session to use for sysrepo calls.
 * @param[in] sub Subscription to SR subscribe.
 * @param[in] sub_no_thread Create the subscriptions without a managing thread.
 * @param[out] replay_start When the replay was enabled for the whole subscription.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srsn_sn_sr_subscribe(sr_session_ctx_t *sess, struct srsn_sub *sub, int sub_no_thread,
        struct timespec *replay_start);

/**
 * @brief Initialize notification dispatch with a single FD.
 *
 * @param[in] fd Subscription FD.
 * @param[in] cb_data Callback data for @p fd.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srsn_dispatch_init(int fd, void *cb_data);

/**
 * @brief Add another FD handled by notification dispatch.
 *
 * @param[in] fd Subscription FD.
 * @param[in] cb_data Callback data for @p fd.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srsn_dispatch_add(int fd, void *cb_data);

/**
 * @brief Get the current count of subscriptions handled by dispatch.
 *
 * @return Subscription count.
 */
uint32_t srsn_dispatch_count(void);

/**
 * @brief Thread reading notifications from subscriptions.
 */
void *srsn_read_dispatch_thread(void *arg);

#endif /* SN_COMMON_H_ */
