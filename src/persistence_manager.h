/**
 * @file persistence_manager.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief TODO
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

/**
 * @brief Persistence Manager context.
 */
typedef struct pm_ctx_s pm_ctx_t;

/**
 * @brief Initializes a Persistence Manager instance.
 *
 * @param[out] np_ctx Allocated Persistence Manager context that can be used in subsequent PM API calls.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int pm_init(const char *schema_search_dir, pm_ctx_t **pm_ctx);

/**
 * @brief Cleans up the Persistence Manager instance.
 *
 * @param[in] pm_ctx Persistence Manager context acquired by ::pm_init call.
 */
void pm_cleanup(pm_ctx_t *pm_ctx);

#endif /* PERSISTENCE_MANAGER_H_ */
