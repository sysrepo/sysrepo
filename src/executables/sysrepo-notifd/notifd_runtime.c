/**
 * @file notifd_runtime.c
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief sysrepo notification daemon runtime: notification delivery, receiver connections, and dispatch
 *
 * @copyright
 * Copyright (c) 2026 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "compat.h"

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "notifd.h"
#include "notifd_common.h"
#include "utils/subscribed_notifications.h"

#include <libyang/libyang.h>

/*
 * ---------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------------
 */

int
timespec_cmp(const struct timespec *ts1, const struct timespec *ts2)
{
    if (ts1->tv_sec < ts2->tv_sec) {
        return -1;
    }
    if (ts1->tv_sec > ts2->tv_sec) {
        return 1;
    }
    if (ts1->tv_nsec < ts2->tv_nsec) {
        return -1;
    }
    if (ts1->tv_nsec > ts2->tv_nsec) {
        return 1;
    }
    return 0;
}

/*
 * ---------------------------------------------------------------------------
 * Notification construction (state-change notifications per RFC 8692)
 * ---------------------------------------------------------------------------
 */

static int
subscription_state_change_notif_new(const struct ly_ctx *ly_ctx, notif_sub_t *sub,
        const char *notif_path, uint32_t fields, const char *reason, struct lyd_node **notif)
{
    int rc = SR_ERR_OK;
    struct lyd_node *tree = NULL;
    char *id_str = NULL, *stop_time_str = NULL, *start_time_str = NULL;
    struct timespec *start_time, *stop_time;
    notif_encoding_t encoding;
    const notif_encoding_info_t *enc_info = NULL;

    *notif = NULL;

    /* create the notification */
    if (lyd_new_path(NULL, ly_ctx, notif_path, NULL, 0, &tree)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

    /* id */
    if (asprintf(&id_str, "%" PRIu32, sub->id) == -1) {
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }
    if (lyd_new_path(tree, ly_ctx, "id", id_str, 0, NULL)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

    /* stream */
    if (fields & NOTIF_FIELD_STREAM) {
        if (lyd_new_path(tree, ly_ctx, "stream", sub->stream, 0, NULL)) {
            rc = SR_ERR_LY;
            goto cleanup;
        }
    }

    /* filter: stream-filter-name (by-reference) or stream-xpath-filter (choice) */
    if ((fields & NOTIF_FIELD_FILTER_REF) && sub->filter_ref) {
        if (lyd_new_path(tree, ly_ctx, "stream-filter-name", sub->filter_ref, 0, NULL)) {
            rc = SR_ERR_LY;
            goto cleanup;
        }
    } else if ((fields & NOTIF_FIELD_XPATH_FILTER) && sub->xpath_filter) {
        if (lyd_new_path(tree, ly_ctx, "stream-xpath-filter", sub->xpath_filter, 0, NULL)) {
            rc = SR_ERR_LY;
            goto cleanup;
        }
    }

    /* stop time */
    if (fields & NOTIF_FIELD_STOP_TIME) {
        stop_time = (sub->stop_time.tv_sec || sub->stop_time.tv_nsec) ? &sub->stop_time : NULL;
        if (stop_time) {
            if (ly_time_ts2str(stop_time, &stop_time_str)) {
                rc = SR_ERR_LY;
                goto cleanup;
            }

            if (lyd_new_path(tree, ly_ctx, "stop-time", stop_time_str, 0, NULL)) {
                rc = SR_ERR_LY;
                goto cleanup;
            }
        }
    }

    /* replay start time */
    if (fields & NOTIF_FIELD_REPLAY_START) {
        start_time = (sub->replay_start_time.tv_sec || sub->replay_start_time.tv_nsec) ?
                &sub->replay_start_time : NULL;
        if (start_time) {
            if (ly_time_ts2str(start_time, &start_time_str)) {
                rc = SR_ERR_LY;
                goto cleanup;
            }
            if (lyd_new_path(tree, ly_ctx, "replay-start-time", start_time_str, 0, NULL)) {
                rc = SR_ERR_LY;
                goto cleanup;
            }
        }
    }

    /* transport */
    if ((fields & NOTIF_FIELD_TRANSPORT) && sub->ops) {
        if (lyd_new_path(tree, ly_ctx, "transport", sub->ops->transport_identity, 0, NULL)) {
            rc = SR_ERR_LY;
            goto cleanup;
        }
    }

    /* encoding */
    if (fields & NOTIF_FIELD_ENCODING) {
        /* resolve the encoding (shared path: transport default + feature check) */
        encoding = notif_encoding_resolve(sub->encoding, ly_ctx, sub->ops);
        enc_info = notif_encoding_info_find(encoding);
        if (!enc_info) {
            SRNTF_LOG_ERR("Failed to resolve encoding for subscription %" PRIu32 ".", sub->id);
            rc = SR_ERR_UNSUPPORTED;
            goto cleanup;
        }
        if (lyd_new_path(tree, ly_ctx, "encoding", enc_info->identityref, 0, NULL)) {
            rc = SR_ERR_LY;
            goto cleanup;
        }
    }

    /* purpose */
    if ((fields & NOTIF_FIELD_PURPOSE) && sub->purpose) {
        if (lyd_new_path(tree, ly_ctx, "purpose", sub->purpose, 0, NULL)) {
            rc = SR_ERR_LY;
            goto cleanup;
        }
    }

    /* reason */
    if (reason) {
        if (lyd_new_path(tree, ly_ctx, "reason", reason, 0, NULL)) {
            rc = SR_ERR_LY;
            goto cleanup;
        }
    }

    *notif = tree;
    tree = NULL;

cleanup:
    lyd_free_tree(tree);
    free(id_str);
    free(stop_time_str);
    free(start_time_str);
    return rc;
}

static int
subscription_started_notif_new(const struct ly_ctx *ly_ctx, notif_sub_t *sub, struct lyd_node **notif)
{
    return subscription_state_change_notif_new(ly_ctx, sub,
            "/ietf-subscribed-notifications:subscription-started",
            NOTIF_FIELD_STREAM | NOTIF_FIELD_XPATH_FILTER | NOTIF_FIELD_STOP_TIME | NOTIF_FIELD_REPLAY_START |
            NOTIF_FIELD_TRANSPORT | NOTIF_FIELD_ENCODING | NOTIF_FIELD_PURPOSE | NOTIF_FIELD_FILTER_REF,
            NULL, notif);
}

static int
subscription_terminated_notif_new(const struct ly_ctx *ly_ctx, notif_sub_t *sub, const char *reason,
        struct lyd_node **notif)
{
    return subscription_state_change_notif_new(ly_ctx, sub,
            "/ietf-subscribed-notifications:subscription-terminated", 0, reason, notif);
}

#if 0 /* not currently used, but may be needed in the future */

static int
subscription_modified_notif_new(const struct ly_ctx *ly_ctx, notif_sub_t *sub, struct lyd_node **notif)
{
    return subscription_state_change_notif_new(ly_ctx, sub,
            "/ietf-subscribed-notifications:subscription-modified",
            NOTIF_FIELD_STREAM | NOTIF_FIELD_XPATH_FILTER | NOTIF_FIELD_STOP_TIME | NOTIF_FIELD_REPLAY_START |
            NOTIF_FIELD_TRANSPORT | NOTIF_FIELD_ENCODING | NOTIF_FIELD_PURPOSE | NOTIF_FIELD_FILTER_REF,
            NULL, notif);
}

static int
subscription_completed_notif_new(const struct ly_ctx *ly_ctx, notif_sub_t *sub, struct lyd_node **notif)
{
    return subscription_state_change_notif_new(ly_ctx, sub,
            "/ietf-subscribed-notifications:subscription-completed", 0, NULL, notif);
}

#endif /* 0 */

/*
 * ---------------------------------------------------------------------------
 * Notification sending (to one or all receivers of a subscription)
 * ---------------------------------------------------------------------------
 */

static int
subscription_state_change_notif_send(notifd_ctx_t *notifd_ctx, notif_sub_t *sub,
        notif_receiver_t *receiver, const char *notif_path, uint32_t fields,
        const char *reason, const char *notif_name, int skip_inactive)
{
    int rc = SR_ERR_OK, r;
    const struct ly_ctx *ly_ctx;
    struct lyd_node *notif = NULL;
    LYA_COUNT_T i, start, end;

    if (!sub) {
        return SR_ERR_INVAL_ARG;
    }

    ly_ctx = sr_session_acquire_context(notifd_ctx->sr_sess);

    if ((rc = subscription_state_change_notif_new(ly_ctx, sub, notif_path, fields, reason, &notif))) {
        goto cleanup;
    }

    if (receiver) {
        start = receiver - sub->receivers;
        end = start + 1;
    } else {
        start = 0;
        end = LYA_COUNT(sub->receivers);
    }

    for (i = start; i < end; i++) {
        if (skip_inactive && (sub->receivers[i].state != NOTIF_RECV_STATE_ACTIVE)) {
            continue;
        }
        r = notif_receiver_send(notifd_ctx, &sub->receivers[i], notif, NULL, sub->encoding);
        if (r) {
            if (skip_inactive) {
                SRNTF_LOG_WRN("Failed to send %s to receiver \"%s\" (sub %" PRIu32 ").",
                        notif_name, sub->receivers[i].name, sub->id);
            } else {
                rc = r;
                goto cleanup;
            }
        }
    }

cleanup:
    lyd_free_all(notif);
    sr_session_release_context(notifd_ctx->sr_sess);
    return rc;
}

int
subscription_started_notif_send(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, notif_receiver_t *receiver)
{
    return subscription_state_change_notif_send(notifd_ctx, sub, receiver,
            "/ietf-subscribed-notifications:subscription-started",
            NOTIF_FIELD_STREAM | NOTIF_FIELD_XPATH_FILTER | NOTIF_FIELD_STOP_TIME | NOTIF_FIELD_REPLAY_START |
            NOTIF_FIELD_TRANSPORT | NOTIF_FIELD_ENCODING | NOTIF_FIELD_PURPOSE | NOTIF_FIELD_FILTER_REF,
            NULL, "subscription-started", 0);
}

int
subscription_terminated_notif_send(notifd_ctx_t *notifd_ctx, notif_sub_t *sub,
        notif_receiver_t *receiver, const char *reason)
{
    return subscription_state_change_notif_send(notifd_ctx, sub, receiver,
            "/ietf-subscribed-notifications:subscription-terminated", 0,
            reason, "subscription-terminated", 1);
}

int
subscription_modified_notif_send(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, notif_receiver_t *receiver)
{
    return subscription_state_change_notif_send(notifd_ctx, sub, receiver,
            "/ietf-subscribed-notifications:subscription-modified",
            NOTIF_FIELD_STREAM | NOTIF_FIELD_XPATH_FILTER | NOTIF_FIELD_STOP_TIME | NOTIF_FIELD_REPLAY_START |
            NOTIF_FIELD_TRANSPORT | NOTIF_FIELD_ENCODING | NOTIF_FIELD_PURPOSE | NOTIF_FIELD_FILTER_REF,
            NULL, "subscription-modified", 1);
}

int
subscription_completed_notif_send(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, notif_receiver_t *receiver)
{
    return subscription_state_change_notif_send(notifd_ctx, sub, receiver,
            "/ietf-subscribed-notifications:subscription-completed", 0,
            NULL, "subscription-completed", 1);
}

/*
 * ---------------------------------------------------------------------------
 * Receiver connection management
 * ---------------------------------------------------------------------------
 */

int
notif_receiver_is_connected(notif_receiver_t *receiver)
{
    if (!receiver || !receiver->ops) {
        return 0;
    }

    return receiver->ops->is_connected(receiver);
}

int
notif_receiver_resolve(notif_receiver_t *receiver)
{
    /* the receiver cannot be connected until it is resolved again */
    memset(&receiver->addr, 0, sizeof receiver->addr);
    receiver->addr_len = 0;

    if (!receiver->inst || !receiver->ops || !receiver->ops->resolve) {
        return SR_ERR_OK;
    }

    return receiver->ops->resolve(receiver, receiver->inst->transport_config);
}

int
notif_receiver_connect(notif_receiver_t *receiver)
{
    int rc = SR_ERR_OK;

    if (!receiver->inst || !receiver->ops) {
        return SR_ERR_OK;
    }

    if (notif_receiver_is_connected(receiver)) {
        return SR_ERR_OK;
    }

    rc = receiver->ops->connect(receiver, receiver->inst->transport_config);
    if (rc) {
        SRNTF_LOG_ERR("Failed to connect receiver \"%s\" via %s.", receiver->name, receiver->ops->name);
    }

    return rc;
}

void
notif_receiver_disconnect(notif_receiver_t *receiver)
{
    if (!notif_receiver_is_connected(receiver)) {
        return;
    }
    if (!receiver->inst || !receiver->ops) {
        return;
    }

    receiver->ops->disconnect(receiver);
}

/**
 * @brief Get the exponential reconnect backoff delay of a receiver.
 *
 * @param[in] receiver Receiver to use.
 * @return Backoff delay in seconds.
 */
static uint32_t
notif_receiver_backoff_sec(const notif_receiver_t *receiver)
{
    uint32_t backoff_sec, shift;

    shift = receiver->reconnect_attempts;
    if (shift > 30) {
        shift = 30;
    }
    backoff_sec = NOTIFD_RECV_RECONNECT_BASE_SEC << shift;
    if ((backoff_sec > NOTIFD_RECV_RECONNECT_MAX_SEC) || (backoff_sec < NOTIFD_RECV_RECONNECT_BASE_SEC)) {
        backoff_sec = NOTIFD_RECV_RECONNECT_MAX_SEC;
    }

    return backoff_sec;
}

int
notif_receiver_backoff_reconnect(notifd_ctx_t *notifd_ctx, notif_receiver_t *receiver)
{
    int rc = SR_ERR_OK;
    struct timespec now, event_ts;
    uint32_t backoff_sec;
    time_t elapsed;
    const struct ly_ctx *ly_ctx;
    struct lyd_node *start_notif = NULL;

    if (notif_receiver_is_connected(receiver)) {
        return SR_ERR_OK;
    }

    if (!receiver->inst) {
        return SR_ERR_OK;
    }

    if (!receiver->srsn_data.sub_id) {
        /* "active" means the receiver is being sent every applicable notification, which is false
         * without a notification pipe, so do not reconnect it at all */
        return SR_ERR_OPERATION_FAILED;
    }

    backoff_sec = notif_receiver_backoff_sec(receiver);

    /* check if enough time has passed since last reconnect attempt */
    clock_gettime(COMPAT_CLOCK_ID, &now);
    if (receiver->last_reconnect_attempt.tv_sec || receiver->last_reconnect_attempt.tv_nsec) {
        elapsed = now.tv_sec - receiver->last_reconnect_attempt.tv_sec;
        if (elapsed < (time_t)backoff_sec) {
            SRNTF_LOG_DBG("Receiver \"%s\" reconnect backoff not elapsed (%lds < %ds).",
                    receiver->name, (long)elapsed, (int)backoff_sec);
            return SR_ERR_OPERATION_FAILED;
        }
    }

    /* try to reconnect */
    receiver->last_reconnect_attempt = now;

    rc = notif_receiver_connect(receiver);
    if (rc) {
        receiver->reconnect_attempts++;
        SRNTF_LOG_WRN("Failed to reconnect receiver \"%s\" (attempt %" PRIu32 ").",
                receiver->name, receiver->reconnect_attempts);
        return rc;
    }

    /* reconnection succeeded */
    SRNTF_LOG_INF("Successfully reconnected receiver \"%s\".", receiver->name);
    receiver->reconnect_attempts = 0;

    /* send subscription-started after reconnecting as per RFC 8692 Section 2.1.2 */
    ly_ctx = sr_session_acquire_context(notifd_ctx->sr_sess);
    rc = subscription_started_notif_new(ly_ctx, receiver->sub, &start_notif);
    if (rc) {
        SRNTF_LOG_ERR("Failed to create subscription-started notification for receiver \"%s\".",
                receiver->name);
        sr_session_release_context(notifd_ctx->sr_sess);
        goto disconnect;
    }

    /* send the notification through the standard send path, resolving the default encoding as needed */
    clock_gettime(CLOCK_REALTIME, &event_ts);
    rc = notif_receiver_send(notifd_ctx, receiver, start_notif, &event_ts, receiver->sub->encoding);
    lyd_free_all(start_notif);
    sr_session_release_context(notifd_ctx->sr_sess);
    if (rc) {
        SRNTF_LOG_ERR("Failed to send notification to receiver \"%s\".", receiver->name);
        goto disconnect;
    }

    receiver->state = NOTIF_RECV_STATE_ACTIVE;

    return SR_ERR_OK;

disconnect:
    notif_receiver_disconnect(receiver);
    receiver->state = NOTIF_RECV_STATE_DISCONNECTED;
    return rc;
}

int
notifd_reconnect_due_receivers(notifd_ctx_t *notifd_ctx)
{
    notif_receiver_t *receiver;
    struct timespec now;
    LYA_COUNT_T i, j;
    int64_t remaining_ms, next_ms = -1;
    time_t deadline;

    clock_gettime(COMPAT_CLOCK_ID, &now);

    LYA_FOR(notifd_ctx->subs, i) {
        if (notifd_ctx->subs[i]->state != NOTIF_SUB_STATE_VALID) {
            continue;
        }

        LYA_FOR(notifd_ctx->subs[i]->receivers, j) {
            receiver = &notifd_ctx->subs[i]->receivers[j];

            /* skip the receivers that are connected or cannot be reconnected */
            if (!receiver->inst || !receiver->srsn_data.sub_id || notif_receiver_is_connected(receiver)) {
                continue;
            }
            assert((receiver->state == NOTIF_RECV_STATE_DISCONNECTED) ||
                    (receiver->state == NOTIF_RECV_STATE_CONNECTING));

            if (!receiver->last_reconnect_attempt.tv_sec && !receiver->last_reconnect_attempt.tv_nsec) {
                /* never attempted, retry immediately */
                deadline = now.tv_sec;
            } else {
                deadline = receiver->last_reconnect_attempt.tv_sec + (time_t)notif_receiver_backoff_sec(receiver);
            }

            if (deadline <= now.tv_sec) {
                notif_receiver_backoff_reconnect(notifd_ctx, receiver);

                /* the deadline must advance on every firing whether or not the attempt happened */
                receiver->last_reconnect_attempt = now;
                if (notif_receiver_is_connected(receiver)) {
                    continue;
                }
                deadline = now.tv_sec + (time_t)notif_receiver_backoff_sec(receiver);
            }

            remaining_ms = ((int64_t)(deadline - now.tv_sec)) * 1000;
            if (remaining_ms < 0) {
                remaining_ms = 0;
            }
            if ((next_ms == -1) || (remaining_ms < next_ms)) {
                next_ms = remaining_ms;
            }
        }
    }

    return (next_ms > INT32_MAX) ? INT32_MAX : (int)next_ms;
}

/**
 * @brief Learn whether a notification is a subscription state change and not an event record.
 *
 * @param[in] notif Notification to check.
 * @return Whether it is a subscription state change.
 */
static int
notif_is_subscription_state_change(const struct lyd_node *notif)
{
    const struct lys_module *mod;

    mod = notif->schema ? notif->schema->module : NULL;

    return mod && !strcmp(mod->name, "ietf-subscribed-notifications");
}

int
notif_receiver_send(notifd_ctx_t *UNUSED(notifd_ctx), notif_receiver_t *receiver, const struct lyd_node *notif,
        const struct timespec *timestamp, notif_encoding_t encoding)
{
    int rc = SR_ERR_OK;
    struct timespec ts = {0};
    int is_sub_started;
    char *notif_path = NULL;

    if (!receiver || !notif) {
        SRNTF_LOG_ERR("Invalid arguments to send notification.");
        return SR_ERR_INVAL_ARG;
    }

    if (!receiver->inst) {
        /* quietly ignore sending to receivers without an instance, since instance is not mandatory */
        return SR_ERR_OK;
    }

    notif_path = lyd_path(notif, LYD_PATH_STD, NULL, 0);
    if (!notif_path) {
        SRNTF_LOG_ERR("Failed to get path of notification to send.");
        return SR_ERR_LY;
    }

    is_sub_started = !strcmp(LYD_NAME(notif), "subscription-started");

    if (!notif_receiver_is_connected(receiver)) {
        SRNTF_LOG_WRN("Receiver \"%s\" is not connected, cannot send notification \"%s\".",
                receiver->name, notif_path);
        rc = SR_ERR_OPERATION_FAILED;
        goto cleanup;
    }

    if ((receiver->state != NOTIF_RECV_STATE_ACTIVE) && !is_sub_started) {
        SRNTF_LOG_ERR("Cannot send notification \"%s\" to receiver \"%s\" before sending subscription-started.",
                notif_path, receiver->name);
        rc = SR_ERR_OPERATION_FAILED;
        goto cleanup;
    }

    if (!timestamp) {
        /* get the current wall-clock time for the event timestamp */
        clock_gettime(CLOCK_REALTIME, &ts);
    } else {
        /* use the provided timestamp */
        ts = *timestamp;
    }

    SRNTF_LOG_INF("Sending notification \"%s\" to receiver \"%s\" over %s.", notif_path, receiver->name,
            receiver->ops ? receiver->ops->name : "unknown");

    if (!receiver->ops) {
        SRNTF_LOG_ERR("No transport ops for receiver \"%s\".", receiver->name);
        rc = SR_ERR_UNSUPPORTED;
        goto cleanup;
    }

    /* resolve the encoding, defaulting to the transport default and checking enabled features */
    encoding = notif_encoding_resolve(encoding, LYD_CTX(notif), receiver->ops);
    if (encoding == NOTIF_ENCODING_UNSET) {
        SRNTF_LOG_ERR("No usable encoding for notification \"%s\", all encoding features are disabled.", notif_path);
        rc = SR_ERR_UNSUPPORTED;
        goto cleanup;
    }

    rc = receiver->ops->send(receiver, receiver->inst->transport_config, notif, &ts, encoding);
    if (rc == SR_ERR_TIME_OUT) {
        /* the transport would have blocked, the notification was dropped, which is not an error of
         * the receiver, so it stays connected */
        SRNTF_LOG_WRN("Dropped notification \"%s\" for receiver \"%s\", its transport buffer is full.",
                notif_path, receiver->name);
        rc = SR_ERR_OK;
    } else if (!rc && !notif_is_subscription_state_change(notif)) {
        /* count the event records the transport accepted, not those written into the srsn pipe */
        ++receiver->sent_count;
    }

cleanup:
    free(notif_path);
    return rc;
}

int
notif_receiver_reconnect(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, notif_receiver_t *receiver, notif_receiver_inst_t *new_inst)
{
    int rc = SR_ERR_OK;
    struct lyd_node *term_notif = NULL, *start_notif = NULL;
    const struct ly_ctx *ly_ctx;

    ly_ctx = sr_session_acquire_context(notifd_ctx->sr_sess);

    if (notif_receiver_is_connected(receiver)) {
        /* create and send subscription-terminated notification before disconnecting */
        if ((rc = subscription_terminated_notif_new(ly_ctx, sub,
                "ietf-subscribed-notifications:no-such-subscription", &term_notif))) {
            goto cleanup;
        }
        if ((rc = notif_receiver_send(notifd_ctx, receiver, term_notif, NULL, sub->encoding))) {
            goto cleanup;
        }

        /* disconnect the receiver */
        notif_receiver_disconnect(receiver);
        receiver->state = NOTIF_RECV_STATE_DISCONNECTED;
    }

    if (new_inst) {
        /* update to the new instance */
        receiver->inst = new_inst;
        receiver->ops = new_inst->ops;
    }

    /* resolve the address, the configuration affecting it may have changed */
    if ((rc = notif_receiver_resolve(receiver))) {
        goto cleanup;
    }

    /* connect the receiver */
    if ((rc = notif_receiver_connect(receiver))) {
        goto cleanup;
    }

    /* create and send subscription-started notification after reconnecting */
    if ((rc = subscription_started_notif_new(ly_ctx, sub, &start_notif))) {
        goto cleanup;
    }
    if ((rc = notif_receiver_send(notifd_ctx, receiver, start_notif, NULL, sub->encoding))) {
        goto cleanup;
    }
    receiver->state = NOTIF_RECV_STATE_ACTIVE;
    receiver->reconnect_attempts = 0;
    memset(&receiver->last_reconnect_attempt, 0, sizeof receiver->last_reconnect_attempt);

cleanup:
    if (rc) {
        /* disconnect the receiver */
        notif_receiver_disconnect(receiver);
        receiver->state = NOTIF_RECV_STATE_DISCONNECTED;

        /* set reconnect timestamp so automatic backoff respects this attempt */
        clock_gettime(COMPAT_CLOCK_ID, &receiver->last_reconnect_attempt);
    }
    lyd_free_all(term_notif);
    lyd_free_all(start_notif);
    sr_session_release_context(notifd_ctx->sr_sess);
    return rc;
}

/*
 * ---------------------------------------------------------------------------
 * Notification dispatch (srsn integration)
 * ---------------------------------------------------------------------------
 */

/**
 * @brief Free the srsn subscription data of a receiver that failed to start.
 *
 * @param[in,out] receiver Receiver to clean up.
 */
static void
notif_receiver_srsn_free(notif_receiver_t *receiver)
{
    if (receiver->srsn_data.sub_id) {
        /* terminate the srsn subscription, which removes its subscriptions from the sysrepo context */
        srsn_terminate(receiver->srsn_data.sub_id, NULL);
        receiver->srsn_data.sub_id = 0;
    }

    /* unsubscribe only after srsn_terminate(), which still uses the subscription context */
    sr_unsubscribe(receiver->srsn_data.sr_subscr);
    receiver->srsn_data.sr_subscr = NULL;
}

int
notif_receiver_srsn_start(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, notif_receiver_t *receiver)
{
    int rc = SR_ERR_OK, fd = -1;
    struct timespec *stop_time, *start_time;

    stop_time = (sub->stop_time.tv_sec || sub->stop_time.tv_nsec) ? &sub->stop_time : NULL;
    start_time = (sub->start_time.tv_sec || sub->start_time.tv_nsec) ? &sub->start_time : NULL;

    /* subscribe for notifications */
    if ((rc = srsn_subscribe(notifd_ctx->sr_sess, sub->stream, sub->xpath_filter, stop_time, start_time, 0,
            &receiver->srsn_data.sr_subscr, &sub->replay_start_time, &fd, &receiver->srsn_data.sub_id))) {
        SRNTF_LOG_ERR("Failed to subscribe for notifications for subscription ID %" PRIu32 " and receiver \"%s\".",
                sub->id, receiver->name);
        goto cleanup;
    }

    /* hand the pipe over to the dispatch loop, which owns the FD from now on */
    if ((rc = notifd_dispatch_add(&notifd_ctx->dispatch, fd, receiver->srsn_data.sub_id))) {
        SRNTF_LOG_ERR("Failed to add notification dispatch for subscription ID %" PRIu32 " and receiver \"%s\".",
                sub->id, receiver->name);
        close(fd);
        goto cleanup;
    }

cleanup:
    if (rc) {
        notif_receiver_srsn_free(receiver);
        sub->modif_err_reason = "ietf-subscribed-notifications:no-such-subscription";
    }
    return rc;
}

void
notif_receiver_srsn_stop(notifd_ctx_t *notifd_ctx, notif_receiver_t *receiver)
{
    srsn_state_sub_t *state_sub = NULL;

    if (receiver->srsn_data.sub_id) {
        /* carry the excluded count over, the next srsn subscription starts counting from zero */
        if (!srsn_oper_data_sub(receiver->srsn_data.sub_id, &state_sub)) {
            receiver->excluded_base += state_sub->excluded_count;
            srsn_oper_data_subscriptions_free(state_sub, SRSN_FREE_SINGLE);
        }

        /* terminate the srsn subscription first, it flushes whatever it still wants to write */
        srsn_terminate(receiver->srsn_data.sub_id, NULL);

        /* stop dispatching, the loop closes the FD and drops the entry at its own pace */
        notifd_dispatch_detach(&notifd_ctx->dispatch, receiver->srsn_data.sub_id);
        receiver->srsn_data.sub_id = 0;
    }

    if (receiver->srsn_data.sr_subscr) {
        sr_unsubscribe(receiver->srsn_data.sr_subscr);
        receiver->srsn_data.sr_subscr = NULL;
    }
}

/*
 * ---------------------------------------------------------------------------
 * Notification delivery (called by the dispatch loop)
 * ---------------------------------------------------------------------------
 */

notif_receiver_t *
receiver_find_by_srsn_sub_id(notifd_ctx_t *notifd_ctx, uint32_t srsn_sub_id)
{
    LYA_COUNT_T i, j;

    LYA_FOR(notifd_ctx->subs, i) {
        LYA_FOR(notifd_ctx->subs[i]->receivers, j) {
            if (notifd_ctx->subs[i]->receivers[j].srsn_data.sub_id == srsn_sub_id) {
                return &notifd_ctx->subs[i]->receivers[j];
            }
        }
    }

    return NULL;
}

void
notifd_deliver_notif(notifd_ctx_t *notifd_ctx, notif_receiver_t *receiver, const struct lyd_node *notif,
        const struct timespec *timestamp)
{
    notif_sub_t *sub = receiver->sub;
    struct timespec now;

    if (sub->state != NOTIF_SUB_STATE_VALID) {
        /* only send notifications for valid subscriptions */
        return;
    }

    /*
     * Stop time reached - srsn generates subscription-terminated internally,
     * but per RFC 8692/YANG model, subscription-completed should be sent instead.
     */
    if (!strcmp(LYD_NAME(notif), "subscription-terminated")) {
        clock_gettime(CLOCK_REALTIME, &now);
        if ((sub->stop_time.tv_sec || sub->stop_time.tv_nsec) && (timespec_cmp(&sub->stop_time, &now) <= 0)) {
            if (sub->state != NOTIF_SUB_STATE_CONCLUDED) {
                sub->state = NOTIF_SUB_STATE_CONCLUDED;
                subscription_completed_notif_send(notifd_ctx, sub, NULL);
            }
            return;
        }
    }

    /* if the receiver is not active, try to reconnect if possible, otherwise skip sending the notification */
    if (receiver->state != NOTIF_RECV_STATE_ACTIVE) {
        /* try to reconnect with exponential backoff, on success the state is ACTIVE and
         * subscription-started was sent */
        notif_receiver_backoff_reconnect(notifd_ctx, receiver);
        if (receiver->state != NOTIF_RECV_STATE_ACTIVE) {
            return;
        }
    }

    notif_receiver_send(notifd_ctx, receiver, notif, timestamp, sub->encoding);
}
