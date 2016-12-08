/**
 * @file persistence_manager.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo's Persistence Manager API.
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

#ifndef PERSISTENCE_MANAGER_H_
#define PERSISTENCE_MANAGER_H_

#include "access_control.h"
#include "notification_processor.h"
#include "sr_common.h"

/**
 * @defgroup pm Persistence Manager
 * @{
 *
 * @brief Persistence Manager is responsible for storing YANG module-related data
 * that should survive the exit of the Sysrepo Engine, such as enabled features,
 * or active notification subscriptions.
 */

/**
 * @brief Persistence Manager context.
 */
typedef struct pm_ctx_s pm_ctx_t;

/**
 * @brief Initializes a Persistence Manager instance.
 *
 * @param[in] rp_ctx Request Processor context.
 * @param[in] schema_search_dir Directory containing PM's YANG module schema.
 * @param[in] data_search_dir Directory containing the data files.
 * @param[out] pm_ctx Allocated Persistence Manager context that can be used in subsequent PM API calls.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int pm_init(rp_ctx_t *rp_ctx, const char *schema_search_dir, const char *data_search_dir, pm_ctx_t **pm_ctx);

/**
 * @brief Cleans up the Persistence Manager instance.
 *
 * @param[in] pm_ctx Persistence Manager context acquired by ::pm_init call.
 */
void pm_cleanup(pm_ctx_t *pm_ctx);

/**
 * @brief Enables/disables the feature in module's persistent storage.
 *
 * @param[in] pm_ctx Persistence Manager context acquired by ::pm_init call.
 * @param[in] user_cred User credentials.
 * @param[in] module_name Name of the module.
 * @param[in] feature_name Name of the feature to be enabled/disabled.
 * @param[in] enable TRUE by enabling, FALSE by disabling the feature.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int pm_save_feature_state(pm_ctx_t *pm_ctx, const ac_ucred_t *user_cred, const char *module_name,
        const char *feature_name, bool enable);

/**
 * @brief Returns the information about the module from module's persistent data storage.
 *
 * @param[in] pm_ctx Persistence Manager context acquired by ::pm_init call.
 * @param[in] module_name Name of the module.
 * @paran[in] sr_mem_features Memory context to use to store the array of features. Can be NULL.
 * @param[out] module_enabled TRUE if running datastore is enabled for whole module.
 * @param[out] subtrees_enabled Array of subtrees (XPaths) that are enabled in running datastore.
 * @param[out] subtrees_enabled_cnt Count of enabled subtrees.
 * @param[out] features Array of enabled features.
 * @param[out] features_cnt Count of features in returned array.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int pm_get_module_info(pm_ctx_t *pm_ctx, const char *module_name, sr_mem_ctx_t *sr_mem_features,
        bool *module_enabled, char ***subtrees_enabled, size_t *subtrees_enabled_cnt,
        char ***features, size_t *features_cnt);

/**
 * @brief Adds a new subscription into module's persistent storage.
 *
 * @param[in] pm_ctx Persistence Manager context acquired by ::pm_init call.
 * @param[in] user_cred User credentials.
 * @param[in] module_name Name of the module.
 * @param[in] subscription Subscription to be added.
 * @param[in] exclusive TRUE if this is an exclusive subscription, which means
 * that any other subscriptions of the same type will be removed before adding new one).
 *
 * @return Error code (SR_ERR_OK on success).
 */
int pm_add_subscription(pm_ctx_t *pm_ctx, const ac_ucred_t *user_cred, const char *module_name,
        const np_subscription_t *subscription, const bool exclusive);

/**
 * @brief Removes the subscription from module's persistent storage.
 *
 * @param[in] pm_ctx Persistence Manager context acquired by ::pm_init call.
 * @param[in] user_cred User credentials.
 * @param[in] module_name Name of the module.
 * @param[in] subscription Subscription to be deleted.
 * @param[out] disable_running Set to TRUE if running datastore should be disabled
 * after this unsubscribe.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int pm_remove_subscription(pm_ctx_t *pm_ctx, const ac_ucred_t *user_cred, const char *module_name,
        const np_subscription_t *subscription, bool *disable_running);

/**
 * @brief Removes all subscriptions that are to be delivered to specified
 * destination address from module's persistent storage.
 *
 * @param[in] pm_ctx Persistence Manager context acquired by ::pm_init call.
 * @param[in] module_name Name of the module.
 * @param[in] dst_address Notification delivery destination address.
 * @param[out] disable_running Set to TRUE if running datastore should be disabled
 * after this unsubscribe.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int pm_remove_subscriptions_for_destination(pm_ctx_t *pm_ctx, const char *module_name, const char *dst_address,
        bool *disable_running);

/**
 * @brief Returns the array of active subscriptions of given type in module's persistent storage.
 *
 * @param[in] pm_ctx Persistence Manager context acquired by ::pm_init call.
 * @param[in] module_name Name of the module.
 * @param[in] notif_type Type of the notification.
 * @param[out] subscriptions Array of the active subscriptions.
 * @param[out] subscription_cnt Number of subscriptions in returned array.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int pm_get_subscriptions(pm_ctx_t *pm_ctx, const char *module_name, Sr__SubscriptionType notif_type,
        np_subscription_t **subscriptions, size_t *subscription_cnt);

/**@} pm */

#endif /* PERSISTENCE_MANAGER_H_ */
