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

/**
 * @brief Sysrepo subscription context.
 */
typedef struct cl_sm_subscription_ctx_s {
    Sr__SubscriptionType type;                   /**< Type of the subscription the subscriber is subscribed to. */
    const char *delivery_address;                /**< Address where the notification messages should be delivered. */
    uint32_t id;                                 /**< Library-local subscription identifier. */
    const char *module_name;                     /**< Name of the YANG module witch the subscription is tied to.*/
    union {
        sr_feature_enable_cb feature_enable_cb;  /**< Callback to be called by feature enable/disable event. */
        sr_module_install_cb module_install_cb;  /**< Callback to be called by module (un)install event. */
        sr_module_change_cb module_change_cb;    /**< Callback to be called by module change event. */
        sr_subtree_change_cb subtree_change_cb;  /**< Callback to be called by subtree change event. */
        sr_rpc_cb rpc_cb;                        /**< Callback to be called by RPC delivery. */
    } callback;
    cl_sm_ctx_t *sm_ctx;                         /**< Associated Subscription Manager context. */
    sr_session_ctx_t *data_session;              /**< Pointer to a data session that can be used from notification callbacks. */
    void *private_ctx;                           /**< Private context pointer, opaque to sysrepo. */
} cl_sm_subscription_ctx_t;

/**
 * @brief Initializes a Subscription Manager instance.
 *
 * @param[out] sm_ctx Subscription Manager context that can be used in subsequent SM API calls.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int cl_sm_init(cl_sm_ctx_t **sm_ctx);

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
int cl_sm_subscription_init(cl_sm_ctx_t *sm_ctx,  cl_sm_server_ctx_t *server_ctx, cl_sm_subscription_ctx_t **subscription);

/**
 * @brief Cleans up a subscription.
 *
 * @param[in] subscription Subscription context acquired by ::cl_sm_subscription_init call.
 */
void cl_sm_subscription_cleanup(cl_sm_subscription_ctx_t *subscription);

/**@} cl_sm */

#endif /* CL_SUBSCRIPTION_MANAGER_H_ */
