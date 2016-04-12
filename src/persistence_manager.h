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
 * @param[in] ac_ctx Access Control module context.
 * @param[in] schema_search_dir Directory containing PM's YANG module schema.
 * @param[in] data_search_dir Directory containing the data files.
 * @param[out] pm_ctx Allocated Persistence Manager context that can be used in subsequent PM API calls.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int pm_init(ac_ctx_t *ac_ctx, const char *schema_search_dir, const char *data_search_dir, pm_ctx_t **pm_ctx);

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
int pm_feature_enable(pm_ctx_t *pm_ctx, const ac_ucred_t *user_cred, const char *module_name,
        const char *feature_name, bool enable);

/**
 * @brief Returns the array of features that should be enabled in specified module.
 *
 * @param[in] pm_ctx Persistence Manager context acquired by ::pm_init call.
 * @param[in] module_name Name of the module.
 * @param[out] features Array of features that should be enabled.
 * @param[out] feature_cnt Number of features in returned array.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int pm_get_features(pm_ctx_t *pm_ctx, const char *module_name, char ***features, size_t *feature_cnt);

/**
 * TODO
 */
int pm_subscribe(pm_ctx_t *pm_ctx, const ac_ucred_t *user_cred, const np_subscription_t *subscription,
        const bool subscribe);

/**
 * TODO
 */
int pm_get_subscriptions(pm_ctx_t *pm_ctx, Sr__NotificationEvent event_type, np_subscription_t **subscriptions,
        size_t *subscription_cnt);

/**@} pm */

#endif /* PERSISTENCE_MANAGER_H_ */
