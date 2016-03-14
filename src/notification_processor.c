/**
 * @file notification_processor.c
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

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "sr_common.h"
#include "rp_internal.h"
#include "notification_processor.h"

typedef struct np_subscription_s {
    const char *dst_address;
    uint32_t dst_id;
    Sr__NotificationEvent event_type;
} np_subscription_t;

typedef struct np_ctx_s {
    rp_ctx_t *rp_ctx;
    np_subscription_t **subscriptions;
    size_t subscription_cnt;
} np_ctx_t;

int
np_init(rp_ctx_t *rp_ctx, np_ctx_t **np_ctx_p)
{
    np_ctx_t *ctx = NULL;

    CHECK_NULL_ARG2(rp_ctx, np_ctx_p);

    ctx = calloc(1, sizeof(*ctx));
    CHECK_NULL_NOMEM_RETURN(ctx);

    ctx->rp_ctx = rp_ctx;

    *np_ctx_p = ctx;
    return SR_ERR_OK;
}

void
np_cleanup(np_ctx_t *np_ctx)
{
    for (size_t i = 0; i < np_ctx->subscription_cnt; i++) {
        free((void*)np_ctx->subscriptions[i]->dst_address);
        free(np_ctx->subscriptions[i]);
    }
    free(np_ctx->subscriptions);
    free(np_ctx);
}

int
np_notification_subscribe(np_ctx_t *np_ctx, Sr__NotificationEvent event_type, const char *dst_address, uint32_t dst_id)
{
    np_subscription_t *subscription = NULL;
    np_subscription_t **subscriptions_tmp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(np_ctx, dst_address);

    /* prepare new subscription entry */
    subscription = calloc(1, sizeof(*subscription));
    CHECK_NULL_NOMEM_RETURN(subscription);

    subscription->event_type = event_type;
    subscription->dst_id = dst_id;
    subscription->dst_address = strdup(dst_address);
    CHECK_NULL_NOMEM_GOTO(subscription->dst_address, rc, cleanup);

    /* put the new entry into subscription list */
    subscriptions_tmp = realloc(np_ctx->subscriptions, (np_ctx->subscription_cnt + 1) * sizeof(*subscriptions_tmp));
    CHECK_NULL_NOMEM_GOTO(subscriptions_tmp, rc, cleanup);

    np_ctx->subscriptions = subscriptions_tmp;
    np_ctx->subscriptions[np_ctx->subscription_cnt] = subscription;
    np_ctx->subscription_cnt += 1;

    return SR_ERR_OK;

cleanup:
    if (NULL != subscription) {
        free((void*)subscription->dst_address);
        free(subscription);
    }
    return rc;
}

int
np_notification_unsubscribe(np_ctx_t *np_ctx, Sr__NotificationEvent event_type, const char *dst_address, uint32_t dst_id)
{
    np_subscription_t *subscription = NULL;
    size_t i = 0;

    CHECK_NULL_ARG2(np_ctx, dst_address);

    /* find matching subscription */
    for (i = 0; i < np_ctx->subscription_cnt; i++) {
        if ((np_ctx->subscriptions[i]->event_type == event_type) && (np_ctx->subscriptions[i]->dst_id == dst_id) &&
                (0 == strcmp(np_ctx->subscriptions[i]->dst_address, dst_address))) {
            subscription = np_ctx->subscriptions[i];
        }
    }

    if (NULL == subscription) {
        SR_LOG_ERR("Subscription matching with dst_address='%s' and dst_id=%"PRIu32" not found.", dst_address, dst_id);
        return SR_ERR_INVAL_ARG;
    }

    /* remove the subscription from array */
    if (np_ctx->subscription_cnt > (i + 1)) {
        memmove(np_ctx->subscriptions + i, np_ctx->subscriptions + i + 1,
                (np_ctx->subscription_cnt - i - 1) * sizeof(*subscription));
    }
    np_ctx->subscription_cnt -= 1;

    return SR_ERR_OK;
}

int
np_module_install_notify(np_ctx_t *np_ctx, const char *module_name, const char *revision, bool installed)
{
    Sr__Msg *notif = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(np_ctx, module_name, revision);

    for (size_t i = 0; i < np_ctx->subscription_cnt; i++) {
        if (SR__NOTIFICATION_EVENT__MODULE_INSTALL_EV == np_ctx->subscriptions[i]->event_type) {
            /* allocate the notification */
            rc = sr_pb_notif_alloc(SR__NOTIFICATION_EVENT__MODULE_INSTALL_EV,
                    np_ctx->subscriptions[i]->dst_address, np_ctx->subscriptions[i]->dst_id, &notif);
            /* fill-in notification details */
            if (SR_ERR_OK == rc) {
                notif->notification->module_install_notif->installed = installed;
                notif->notification->module_install_notif->module_name = strdup(module_name);
                CHECK_NULL_NOMEM_ERROR(notif->notification->module_install_notif->module_name, rc);
            }
            if (SR_ERR_OK == rc) {
                notif->notification->module_install_notif->revision = strdup(revision);
                CHECK_NULL_NOMEM_ERROR(notif->notification->module_install_notif->revision, rc);
            }
            /* send the notification */
            if (SR_ERR_OK == rc) {
                rc = cm_msg_send(np_ctx->rp_ctx->cm_ctx, notif);
            } else {
                break;
            }
        }
    }

    return rc;
}

int
np_feature_enable_notify(np_ctx_t *np_ctx, const char *module_name, const char *feature_name, bool enabled)
{
    Sr__Msg *notif = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(np_ctx, module_name, feature_name);

    for (size_t i = 0; i < np_ctx->subscription_cnt; i++) {
        if (SR__NOTIFICATION_EVENT__FEATURE_ENABLE_EV == np_ctx->subscriptions[i]->event_type) {
            /* allocate the notification */
            rc = sr_pb_notif_alloc(SR__NOTIFICATION_EVENT__FEATURE_ENABLE_EV,
                    np_ctx->subscriptions[i]->dst_address, np_ctx->subscriptions[i]->dst_id, &notif);
            /* fill-in notification details */
            if (SR_ERR_OK == rc) {
                notif->notification->feature_enable_notif->enabled = enabled;
                notif->notification->feature_enable_notif->module_name = strdup(module_name);
                CHECK_NULL_NOMEM_ERROR(notif->notification->feature_enable_notif->module_name, rc);
            }
            if (SR_ERR_OK == rc) {
                notif->notification->feature_enable_notif->feature_name = strdup(feature_name);
                CHECK_NULL_NOMEM_ERROR(notif->notification->feature_enable_notif->feature_name, rc);
            }
            /* send the notification */
            if (SR_ERR_OK == rc) {
                rc = cm_msg_send(np_ctx->rp_ctx->cm_ctx, notif);
            } else {
                break;
            }
        }
    }

    return rc;
}
