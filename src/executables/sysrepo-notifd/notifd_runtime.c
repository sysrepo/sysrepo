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

#include "common.h"
#include "notifd.h"
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

    /* xpath filter */
    if ((fields & NOTIF_FIELD_XPATH_FILTER) && sub->xpath_filter) {
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
            NOTIF_FIELD_STREAM | NOTIF_FIELD_XPATH_FILTER | NOTIF_FIELD_STOP_TIME | NOTIF_FIELD_REPLAY_START,
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
            NOTIF_FIELD_STREAM | NOTIF_FIELD_XPATH_FILTER | NOTIF_FIELD_STOP_TIME | NOTIF_FIELD_REPLAY_START,
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
    LY_ARRAY_COUNT_TYPE i, start, end;

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
        end = LY_ARRAY_COUNT(sub->receivers);
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
            NOTIF_FIELD_STREAM | NOTIF_FIELD_XPATH_FILTER | NOTIF_FIELD_STOP_TIME | NOTIF_FIELD_REPLAY_START,
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
            NOTIF_FIELD_STREAM | NOTIF_FIELD_XPATH_FILTER | NOTIF_FIELD_STOP_TIME | NOTIF_FIELD_REPLAY_START,
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

int
notif_receiver_backoff_reconnect(notifd_ctx_t *notifd_ctx, notif_receiver_t *receiver)
{
    int rc = SR_ERR_OK;
    struct timespec now;
    uint32_t backoff_sec, shift;
    time_t elapsed;
    const struct ly_ctx *ly_ctx;
    struct lyd_node *start_notif = NULL;

    if (notif_receiver_is_connected(receiver)) {
        return SR_ERR_OK;
    }

    if (!receiver->inst) {
        return SR_ERR_OK;
    }

    /* calculate exponential backoff delay */
    shift = receiver->reconnect_attempts;
    if (shift > 30) {
        shift = 30;
    }
    backoff_sec = NOTIFD_RECV_RECONNECT_BASE_SEC << shift;
    if ((backoff_sec > NOTIFD_RECV_RECONNECT_MAX_SEC) || (backoff_sec < NOTIFD_RECV_RECONNECT_BASE_SEC)) {
        backoff_sec = NOTIFD_RECV_RECONNECT_MAX_SEC;
    }

    /* check if enough time has passed since last reconnect attempt */
    clock_gettime(COMPAT_CLOCK_ID, &now);
    if (receiver->last_reconnect_attempt.tv_sec || receiver->last_reconnect_attempt.tv_nsec) {
        elapsed = now.tv_sec - receiver->last_reconnect_attempt.tv_sec;
        if (elapsed < (time_t)backoff_sec) {
            SRNTF_LOG_WRN("Receiver \"%s\" reconnect backoff not elapsed (%lds < %ds).",
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

    /* send the notification directly via transport */
    if (receiver->ops) {
        rc = receiver->ops->send(receiver, receiver->inst->transport_config, start_notif, &now, receiver->cb_data.encoding);
    } else {
        SRNTF_LOG_ERR("No transport ops for receiver \"%s\".", receiver->name);
        rc = SR_ERR_UNSUPPORTED;
    }
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
        /* get the current time */
        clock_gettime(COMPAT_CLOCK_ID, &ts);
    } else {
        /* use the provided timestamp */
        ts = *timestamp;
    }

    SRNTF_LOG_INF("Sending notification \"%s\" to receiver \"%s\" over %s.", notif_path, receiver->name,
            receiver->ops ? receiver->ops->name : "unknown");

    if (receiver->ops) {
        rc = receiver->ops->send(receiver, receiver->inst->transport_config, notif, &ts, encoding);
    } else {
        SRNTF_LOG_ERR("No transport ops for receiver \"%s\".", receiver->name);
        rc = SR_ERR_UNSUPPORTED;
    }
    if (rc) {
        goto cleanup;
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

int
notification_dispatch_start(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, notif_receiver_t *receiver)
{
    int rc = SR_ERR_OK;
    struct timespec *stop_time, *start_time;

    stop_time = (sub->stop_time.tv_sec || sub->stop_time.tv_nsec) ? &sub->stop_time : NULL;
    start_time = (sub->start_time.tv_sec || sub->start_time.tv_nsec) ? &sub->start_time : NULL;

    /* subscribe for notifications */
    if ((rc = srsn_subscribe(notifd_ctx->sr_sess, sub->stream, sub->xpath_filter, stop_time, start_time, 0,
            &receiver->srsn_data.sr_subscr, &sub->replay_start_time, &receiver->srsn_data.fd, &receiver->srsn_data.sub_id))) {
        SRNTF_LOG_ERR("Failed to subscribe for notifications for subscription ID %" PRIu32 " and receiver \"%s\".",
                sub->id, receiver->name);
        sub->modif_err_reason = "ietf-subscribed-notifications:insufficient-resources";
        goto cleanup;
    }

    /* set up notif cb data */
    receiver->cb_data.ctx = notifd_ctx;
    receiver->cb_data.recv = receiver;
    receiver->cb_data.encoding = sub->encoding;

    /* add notification dispatch, set notifd_ctx and sub as user data - the pointer itself won't be
     * modified (stored as ** in notifd_ctx), but its content might be, so the callback will need to lock */
    if ((rc = srsn_read_dispatch_add(receiver->srsn_data.fd, &receiver->cb_data))) {
        SRNTF_LOG_ERR("Failed to add notification dispatch for subscription ID %" PRIu32 " and receiver \"%s\".",
                sub->id, receiver->name);
        sub->modif_err_reason = "ietf-subscribed-notifications:insufficient-resources";
        goto cleanup;
    }

cleanup:
    if (rc) {
        /* unsubscribe */
        sr_unsubscribe(receiver->srsn_data.sr_subscr);
        receiver->srsn_data.sr_subscr = NULL;
        if (receiver->srsn_data.fd != -1) {
            close(receiver->srsn_data.fd);
            receiver->srsn_data.fd = -1;
        }
    }
    return rc;
}

void
notification_dispatch_stop(notifd_ctx_t *notifd_ctx, notif_receiver_t *receiver)
{
    /* UNLOCK state lock, srsn_terminate will call notif cb, which will try to acquire the state lock to send
     * any remaining notifs. Nobody can steal our WR lock here, because the caller MUST hold config_apply_mutex,
     * which prevents another thread from acquiring the state WR lock in this window */
    notifd_rwlock_unlock(&notifd_ctx->state_rwlock, __func__);

    if (receiver->srsn_data.sub_id) {
        srsn_terminate(receiver->srsn_data.sub_id, NULL);
        receiver->srsn_data.sub_id = 0;
    }

    /* WR LOCK, reacquire to finish updating the config before checking retval of srsn_terminate */
    if (notifd_rwlock_lock(&notifd_ctx->state_rwlock, 1, NOTIFD_CONTEXT_LOCK_TIMEOUT_MS, __func__)) {
        SRNTF_LOG_ERR("Internal error: failed to acquire state lock to stop notification dispatch for receiver \"%s\".",
                receiver->name);
        return;
    }

    if (receiver->srsn_data.sr_subscr) {
        sr_unsubscribe(receiver->srsn_data.sr_subscr);
        receiver->srsn_data.sr_subscr = NULL;
    }
    if (receiver->srsn_data.fd != -1) {
        close(receiver->srsn_data.fd);
        receiver->srsn_data.fd = -1;
    }
}

/*
 * ---------------------------------------------------------------------------
 * Main notification callback (called by srsn dispatch thread)
 * ---------------------------------------------------------------------------
 */

void
notifd_notification_cb(const struct lyd_node *notif, const struct timespec *timestamp, void *cb_data)
{
    notif_cb_data_t *data = (notif_cb_data_t *)cb_data;
    notifd_ctx_t *notifd_ctx;
    notif_receiver_t *receiver;
    notif_encoding_t encoding;
    notif_sub_t *sub;
    struct timespec now;
    uint32_t sub_id;
    LY_ARRAY_COUNT_TYPE i;

    assert(data);
    notifd_ctx = data->ctx;
    receiver = data->recv;
    encoding = data->encoding;
    assert(notifd_ctx && receiver);

    /* STATE RD LOCK */
    if (notifd_rwlock_lock(&notifd_ctx->state_rwlock, 0, NOTIFD_CONTEXT_LOCK_TIMEOUT_MS, __func__)) {
        return;
    }

    sub = receiver->sub;
    if (sub->state != NOTIF_SUB_STATE_VALID) {
        /* only send notifications for valid subscriptions */
        goto unlock;
    }

    /* save ID before any lock upgrade, as sub may be freed by another thread */
    sub_id = sub->id;

    /*
     * Stop time reached - srsn generates subscription-terminated internally,
     * but per RFC 8692/YANG model, subscription-completed should be sent instead.
     * Need write lock for the state transition.
     */
    if (!strcmp(LYD_NAME(notif), "subscription-terminated")) {
        clock_gettime(CLOCK_REALTIME, &now);
        if ((sub->stop_time.tv_sec || sub->stop_time.tv_nsec) &&
                (timespec_cmp(&sub->stop_time, &now) <= 0)) {
            /* STATE UNLOCK */
            notifd_rwlock_unlock(&notifd_ctx->state_rwlock, __func__);

            /* STATE WR LOCK */
            if (notifd_rwlock_lock(&notifd_ctx->state_rwlock, 1, NOTIFD_CONTEXT_LOCK_TIMEOUT_MS, __func__)) {
                SRNTF_LOG_ERR("Internal error: failed to acquire state lock to handle subscription stop time.");
                return;
            }

            /* revalidate: subscription may have been deleted during lock upgrade */
            sub = subscription_find_by_id(notifd_ctx, sub_id);
            if (!sub) {
                goto unlock;
            }

            if (sub->state != NOTIF_SUB_STATE_CONCLUDED) {
                sub->state = NOTIF_SUB_STATE_CONCLUDED;
                subscription_completed_notif_send(notifd_ctx, sub, NULL);
            }

            goto unlock;
        }
    }

    /* if the receiver is not active, try to reconnect if possible, otherwise skip sending the notification */
    if (receiver->state != NOTIF_RECV_STATE_ACTIVE) {
        if (!notif_receiver_is_connected(receiver) &&
                ((receiver->state == NOTIF_RECV_STATE_DISCONNECTED) ||
                (receiver->state == NOTIF_RECV_STATE_CONNECTING))) {
            /* need write lock to reconnect and update state */
            /* STATE UNLOCK */
            notifd_rwlock_unlock(&notifd_ctx->state_rwlock, __func__);

            /* STATE WR LOCK */
            if (notifd_rwlock_lock(&notifd_ctx->state_rwlock, 1, NOTIFD_CONTEXT_LOCK_TIMEOUT_MS, __func__)) {
                SRNTF_LOG_ERR("Internal error: failed to acquire state lock to handle receiver reconnection.");
                return;
            }

            /* revalidate: subscription may have been deleted during lock upgrade */
            sub = subscription_find_by_id(notifd_ctx, sub_id);
            if (!sub || (sub->state != NOTIF_SUB_STATE_VALID)) {
                goto unlock;
            }

            /* re-find the receiver as it may have been moved in the array */
            receiver = NULL;
            LY_ARRAY_FOR(sub->receivers, i) {
                if (&sub->receivers[i].cb_data == data) {
                    receiver = &sub->receivers[i];
                    break;
                }
            }
            if (!receiver) {
                goto unlock;
            }

            /* recheck after reacquiring write lock */
            if ((receiver->state != NOTIF_RECV_STATE_ACTIVE) && !notif_receiver_is_connected(receiver) &&
                    ((receiver->state == NOTIF_RECV_STATE_DISCONNECTED) ||
                    (receiver->state == NOTIF_RECV_STATE_CONNECTING))) {
                /* try to reconnect with exponential backoff */
                notif_receiver_backoff_reconnect(notifd_ctx, receiver);
            }

            /* on success, state is now ACTIVE and subscription-started was sent */
            if (receiver->state != NOTIF_RECV_STATE_ACTIVE) {
                goto unlock;
            }
        } else {
            goto unlock;
        }
    }

    /* send the notification */
    notif_receiver_send(notifd_ctx, receiver, notif, timestamp, encoding);

unlock:
    /* STATE UNLOCK */
    notifd_rwlock_unlock(&notifd_ctx->state_rwlock, __func__);
}
