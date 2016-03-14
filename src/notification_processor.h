/**
 * @file notification_processor.h
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

#ifndef NOTIFICATION_PROCESSOR_H_
#define NOTIFICATION_PROCESSOR_H_

/**
 *
 */
typedef struct np_ctx_s np_ctx_t;

typedef struct rp_ctx_s rp_ctx_t;

int np_init(rp_ctx_t *rp_ctx, np_ctx_t **np_ctx);

void np_cleanup(np_ctx_t *np_ctx);

int np_notification_subscribe(np_ctx_t *np_ctx, Sr__NotificationEvent event_type, const char *dst_address, uint32_t dst_id);

int np_notification_unsubscribe(np_ctx_t *np_ctx, Sr__NotificationEvent event_type, const char *dst_address, uint32_t dst_id);

int np_module_install_notify(np_ctx_t *np_ctx, const char *module_name, const char *revision, bool installed);

int np_feature_enable_notify(np_ctx_t *np_ctx, const char *module_name, const char *feature_name, bool enabled);

#endif /* NOTIFICATION_PROCESSOR_H_ */
