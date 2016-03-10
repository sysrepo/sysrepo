/**
 * @file cl_subscriptions.h
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

#ifndef CL_SUBSCRIPTIONS_H_
#define CL_SUBSCRIPTIONS_H_

#include <pthread.h>
#include "sysrepo.h"

/*
 * TODO
 */
typedef struct cl_sm_ctx_s cl_sm_ctx_t;

/**
 * TODO
 */
typedef enum sr_notification_event_e {
    SR_MODULE_INSTALL_EVENT,
    SR_FEATURE_ENABLE_EVENT,
} sr_notification_event_t;

/**
 * TODO
 */
typedef struct sr_subscription_ctx_s {
    uint32_t id;

    sr_notification_event_t event_type;
    union {
        sr_feature_enable_cb feature_enable_cb;
        sr_module_install_cb module_install_cb;
    } callback;

    cl_sm_ctx_t *sm_ctx;
    void *private_ctx;
} sr_subscription_ctx_t;

int cl_sm_init(cl_sm_ctx_t **sm_ctx);

void cl_sm_cleanup(cl_sm_ctx_t *sm_ctx);

int cl_sm_subscription_init(cl_sm_ctx_t *sm_ctx, char **destination, sr_subscription_ctx_t **subscription_p);

void cl_sm_subscription_cleanup(sr_subscription_ctx_t *subscription);

#endif /* CL_SUBSCRIPTIONS_H_ */
