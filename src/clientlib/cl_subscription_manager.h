/**
 * @file cl_subscription_manager.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Client Library's Subscription Manager API.
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

#ifndef CL_SUBSCRIPTION_MANAGER_H_
#define CL_SUBSCRIPTION_MANAGER_H_

#include <pthread.h>

#include "sysrepo.h"
#include "sr_common.h"

/**
 * @defgroup cl_sm Subscription Manager
 * @{
 *
 * @brief Internally tracks all subscriptions in CLient Library and provides
 * the notification communication channel between sysepo engine and the client library.
 */

/**
 * @brief Client Subscription manager context.
 */
typedef struct cl_sm_ctx_s cl_sm_ctx_t;

/**
 * @brief Subscription Manager server context.
 */
typedef struct cl_sm_server_ctx_s cl_sm_server_ctx_t;

typedef union cl_sm_callback_u {
        sr_feature_enable_cb feature_enable_cb;  /**< Callback to be called by feature enable/disable event. */
        sr_module_install_cb module_install_cb;  /**< Callback to be called by module (un)install event. */
        sr_module_change_cb module_change_cb;    /**< Callback to be called by module change event. */
        sr_subtree_change_cb subtree_change_cb;  /**< Callback to be called by subtree change event. */
        sr_dp_get_items_cb dp_get_items_cb;      /**< Callback to be called by operational data requests. */
        sr_rpc_cb rpc_cb;                        /**< Callback to be called by RPC delivery. */
        sr_rpc_tree_cb rpc_tree_cb;              /**< Callback to be called by RPC delivery -- the *tree* variant */
        sr_action_cb action_cb;                  /**< Callback to be called by Action delivery. */
        sr_action_tree_cb action_tree_cb;        /**< Callback to be called by Action delivery -- the *tree* variant */
        sr_event_notif_cb event_notif_cb;        /**< Callback to be called by event notification delivery. */
        sr_event_notif_tree_cb event_notif_tree_cb;  /**< Callback to be called by event notification delivery -- the *tree* variant. */
} cl_sm_callback_t;

/**
 * @brief Sysrepo subscription context.
 */
typedef struct cl_sm_subscription_ctx_s {
    Sr__SubscriptionType type;                   /**< Type of the subscription the subscriber is subscribed to. */
    const char *delivery_address;                /**< Address where the notification messages should be delivered. */
    uint32_t id;                                 /**< Library-local subscription identifier. */
    const char *module_name;                     /**< Name of the YANG module witch the subscription is tied to.*/
    cl_sm_callback_t callback;                   /**< Callback to be called when the associated notification/action triggers. */
    sr_api_variant_t api_variant;                /**< API variant -- values vs. trees (relevant for the callback type only) */
    cl_sm_ctx_t *sm_ctx;                         /**< Associated Subscription Manager context. */
    sr_session_ctx_t *data_session;              /**< Pointer to a data session that can be used from notification callbacks. */
    void *private_ctx;                           /**< Private context pointer, opaque to sysrepo. */
} cl_sm_subscription_ctx_t;

/**
 * @brief Initializes a Subscription Manager instance.
 *
 * @param[in] local_fd_watcher TRUE in case that the application wants to use an application-local file descriptor
 * watcher instead of auto-created thread and event loop.
 * @param[in] notify_pipe Pipe used for notifications about fd set changes towards application-local
 * file descriptor watcher.
 * @param[out] sm_ctx Subscription Manager context that can be used in subsequent SM API calls.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int cl_sm_init(bool local_fd_watcher, int notify_pipe[2], cl_sm_ctx_t **sm_ctx);

/**
 * @brief Cleans up the Subscription Manager.
 *
 * @param[in] sm_ctx Subscription Manager context acquired by ::cl_sm_init call.
 * @param[in] join If set to TRUE, joins the thread with the event loop and then does the cleanup.
 */
void cl_sm_cleanup(cl_sm_ctx_t *sm_ctx, bool join);

/**
 * @brief Prepares / assigns a unix-domain server context that can be used for
 * delivering notification messages related to specified module.
 *
 * If the server capable for handling subscriptions of specified module does not
 * exists yet, it will be created and stored within the Subscription Manager context.
 *
 * @param[in] sm_ctx Subscription Manager context acquired by ::cl_sm_init call.
 * @param[in] module_name Name of the YANG module the server will be serving notifications for.
 * @param[out] server_ctx Pointer to associated unix-domain server context.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int cl_sm_get_server_ctx(cl_sm_ctx_t *sm_ctx, const char *module_name, cl_sm_server_ctx_t **server_ctx);

/**
 * @brief Initializes a new subscription.
 *
 * @param[in] sm_ctx Subscription Manager context acquired by ::cl_sm_init call.
 * @param[in] server_ctx Unix-domain server context used for this subscription.
 * @param[out] subscription Allocated subscription context. Release by
 * ::cl_sm_subscription_cleanup call.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int cl_sm_subscription_init(cl_sm_ctx_t *sm_ctx, cl_sm_server_ctx_t *server_ctx, cl_sm_subscription_ctx_t **subscription);

/**
 * @brief Cleans up a subscription.
 *
 * @param[in] subscription Subscription context acquired by ::cl_sm_subscription_init call.
 */
void cl_sm_subscription_cleanup(cl_sm_subscription_ctx_t *subscription);

/**
 * @brief Processes an event of specified type on given file descriptor being watched by application-local
 * fd event watcher.
 *
 * @param[in] sm_ctx Subscription Manager context acquired by ::cl_sm_init call.
 * @param[in] fd File descriptor.
 * @param[in] event Event that occurred on the file descriptor.
 * @param[out] fd_change_set Array of file descriptor contexts that need to be added / removed from the set
 * of monitored file descriptors.
 * @param[out] fd_change_set_cnt Count of file descriptors in fd_change_set array.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int cl_sm_fd_event_process(cl_sm_ctx_t *sm_ctx, int fd, sr_fd_event_t event,
        sr_fd_change_t **fd_change_set, size_t *fd_change_set_cnt);

/**@} cl_sm */

#endif /* CL_SUBSCRIPTION_MANAGER_H_ */
