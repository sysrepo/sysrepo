/**
 * @file notifd_control.c
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief control thread of sysrepo-notifd starting and stopping the srsn subscriptions
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

#include <inttypes.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "notifd.h"
#include "notifd_common.h"
#include "utils/subscribed_notifications.h"

#include <libyang/libyang.h>

void
notif_receiver_srsn_start(notifd_ctx_t *notifd_ctx, notif_receiver_t *receiver)
{
    notifd_control_t *ctl = &notifd_ctx->control;

    /* queue the start */
    receiver->srsn_data.start = NOTIF_SRSN_START_QUEUED;

    /* CTL LOCK */
    pthread_mutex_lock(&ctl->lock);

    ctl->start_queued = 1;
    pthread_cond_signal(&ctl->cond);

    /* CTL UNLOCK */
    pthread_mutex_unlock(&ctl->lock);
}

void
notif_receiver_srsn_stop(notifd_ctx_t *notifd_ctx, notif_receiver_t *receiver)
{
    notifd_control_t *ctl = &notifd_ctx->control;
    srsn_state_sub_t *state_sub = NULL;
    uint32_t *stop_id;

    /* cancel a queued or running start */
    receiver->srsn_data.start = NOTIF_SRSN_START_NONE;

    if (!receiver->srsn_data.sub_id) {
        return;
    }

    /* carry the excluded count over, the next srsn subscription starts counting from zero */
    if (!srsn_oper_data_sub(receiver->srsn_data.sub_id, &state_sub)) {
        receiver->excluded_base += state_sub->excluded_count;
        srsn_oper_data_subscriptions_free(state_sub, SRSN_FREE_SINGLE);
    }

    /* stop dispatching at once, nothing of the old subscription may be delivered from now on */
    notifd_dispatch_detach(&notifd_ctx->dispatch, receiver->srsn_data.sub_id);

    /* CTL LOCK */
    pthread_mutex_lock(&ctl->lock);

    LYA_ADD_ITEM(ctl->stop_ids, stop_id, ERRMEM; goto cleanup_unlock);
    *stop_id = receiver->srsn_data.sub_id;
    pthread_cond_signal(&ctl->cond);

cleanup_unlock:
    /* CTL UNLOCK */
    pthread_mutex_unlock(&ctl->lock);

    receiver->srsn_data.sub_id = 0;
}

/**
 * @brief Invalidate a subscription whose srsn subscription cannot be started.
 *
 * @warning The caller MUST hold the state write lock.
 *
 * @param[in] notifd_ctx Daemon context.
 * @param[in] sub Subscription to invalidate.
 */
static void
notifd_ctl_start_fail(notifd_ctx_t *notifd_ctx, notif_sub_t *sub)
{
    notif_receiver_t *receiver;

    if (sub->state == NOTIF_SUB_STATE_VALID) {
        sub->state = NOTIF_SUB_STATE_INVALID;
        subscription_terminated_notif_send(notifd_ctx, sub, NULL, "ietf-subscribed-notifications:no-such-subscription");
    }

    /* the srsn subscriptions of the other receivers are not used either */
    LYA_FOR_EACH(sub->receivers, receiver) {
        notif_receiver_srsn_stop(notifd_ctx, receiver);
    }
}

/**
 * @brief Free the strings of a copy of the parameters of a subscription.
 *
 * @param[in] params Parameters to free.
 */
static void
notifd_ctl_params_free(notif_srsn_params_t *params)
{
    free(params->stream);
    free(params->xpath_filter);
}

/**
 * @brief Take the first queued start, with a copy of the parameters of its subscription.
 *
 * @param[in] notifd_ctx Daemon context.
 * @param[out] params Copy of the parameters, freed by ::notifd_ctl_params_free().
 * @return Whether a start was taken.
 */
static int
notifd_ctl_start_take(notifd_ctx_t *notifd_ctx, notif_srsn_params_t *params)
{
    notif_sub_t **sub;
    notif_receiver_t *receiver;
    int taken = 0;

    /* STATE WR LOCK */
    notifd_rwlock_lock(&notifd_ctx->state_rwlock, 1, 0, __func__);

    LYA_FOR_EACH(notifd_ctx->subs, sub) {
        LYA_FOR_EACH((*sub)->receivers, receiver) {
            if (receiver->srsn_data.start != NOTIF_SRSN_START_QUEUED) {
                continue;
            }

            /* the subscription is started without the state lock */
            *params = (*sub)->srsn_params;
            params->stream = NULL;
            params->xpath_filter = NULL;
            if ((*sub)->srsn_params.stream) {
                params->stream = strdup((*sub)->srsn_params.stream);
            }
            if ((*sub)->srsn_params.xpath_filter) {
                params->xpath_filter = strdup((*sub)->srsn_params.xpath_filter);
            }
            if (((*sub)->srsn_params.stream && !params->stream) ||
                    ((*sub)->srsn_params.xpath_filter && !params->xpath_filter)) {
                ERRMEM;
                notifd_ctl_params_free(params);

                /* no receiver of the subscription stays queued */
                notifd_ctl_start_fail(notifd_ctx, *sub);
                break;
            }

            receiver->srsn_data.start = NOTIF_SRSN_START_STARTING;
            taken = 1;
            goto cleanup_unlock;
        }
    }

cleanup_unlock:
    /* STATE UNLOCK */
    notifd_rwlock_unlock(&notifd_ctx->state_rwlock, __func__);

    return taken;
}

/**
 * @brief Subscribe an srsn subscription.
 *
 * @param[in] sess Session of the srsn subscriptions.
 * @param[in] p Parameters of the subscription.
 * @param[out] replay_start_time Actual replay start time of an event stream subscription.
 * @param[out] fd Notification pipe read end.
 * @param[out] srsn_sub_id srsn subscription ID.
 * @return ::SR_ERR_OK on success, error code on failure.
 */
static int
notifd_ctl_srsn_subscribe(sr_session_ctx_t *sess, const notif_srsn_params_t *p, struct timespec *replay_start_time,
        int *fd, uint32_t *srsn_sub_id)
{
    const struct timespec *stop_time, *start_time, *anchor_time;
    int r = SR_ERR_INTERNAL;

    stop_time = (p->stop_time.tv_sec || p->stop_time.tv_nsec) ? &p->stop_time : NULL;
    start_time = (p->start_time.tv_sec || p->start_time.tv_nsec) ? &p->start_time : NULL;
    anchor_time = (p->anchor_time.tv_sec || p->anchor_time.tv_nsec) ? &p->anchor_time : NULL;

    switch (p->type) {
    case SRSN_SUB_NOTIF:
        r = srsn_subscribe(sess, p->stream, p->xpath_filter, stop_time, start_time, 0, NULL, replay_start_time, fd,
                srsn_sub_id);
        break;
    case SRSN_YANG_PUSH_PERIODIC:
        /* the period is in centiseconds */
        r = srsn_yang_push_periodic(sess, p->ds, p->xpath_filter, p->period * 10, anchor_time, stop_time, fd,
                srsn_sub_id);
        break;
    case SRSN_YANG_PUSH_ON_CHANGE:
        /* the dampening period is in centiseconds, the push-update of sync-on-start is requested once active */
        r = srsn_yang_push_on_change(sess, p->ds, p->xpath_filter, p->dampening_period * 10, 0,
                (int *)p->excluded_changes, stop_time, 0, NULL, fd, srsn_sub_id);
        break;
    }

    return r;
}

/**
 * @brief Find the receiver being started.
 *
 * @param[in] notifd_ctx Daemon context.
 * @return Receiver in ::NOTIF_SRSN_START_STARTING, NULL if it was deleted, stopped or queued again since.
 */
static notif_receiver_t *
notifd_ctl_starting_find(notifd_ctx_t *notifd_ctx)
{
    notif_sub_t **sub;
    notif_receiver_t *receiver;

    LYA_FOR_EACH(notifd_ctx->subs, sub) {
        LYA_FOR_EACH((*sub)->receivers, receiver) {
            if (receiver->srsn_data.start == NOTIF_SRSN_START_STARTING) {
                return receiver;
            }
        }
    }

    return NULL;
}

/**
 * @brief Start the srsn subscription of a receiver and hand it over, unless the receiver no longer wants it.
 *
 * @param[in] notifd_ctx Daemon context.
 * @param[in] params Parameters of the subscription.
 */
static void
notifd_ctl_start(notifd_ctx_t *notifd_ctx, const notif_srsn_params_t *params)
{
    struct timespec replay_start_time = {0};
    uint32_t srsn_sub_id = 0;
    notif_sub_t *sub;
    notif_receiver_t *receiver;
    int r, fd = -1;

    /* started unlocked, it may wait for a change callback */
    r = notifd_ctl_srsn_subscribe(notifd_ctx->control.sess, params, &replay_start_time, &fd, &srsn_sub_id);

    /* STATE WR LOCK */
    notifd_rwlock_lock(&notifd_ctx->state_rwlock, 1, 0, __func__);

    if (!(receiver = notifd_ctl_starting_find(notifd_ctx))) {
        /* deleted, stopped or started again while being started */
        goto cleanup_unlock;
    }
    receiver->srsn_data.start = NOTIF_SRSN_START_NONE;
    sub = receiver->sub;

    if (r) {
        SRNTF_LOG_ERR("Failed to subscribe for notifications for subscription ID %" PRIu32 " and receiver \"%s\".",
                sub->id, receiver->name);
        notifd_ctl_start_fail(notifd_ctx, sub);
        goto cleanup_unlock;
    }

    receiver->srsn_data.sub_id = srsn_sub_id;
    sub->replay_start_time = replay_start_time;

    if ((receiver->state != NOTIF_RECV_STATE_ACTIVE) && receiver->addr_len && (sub->state == NOTIF_SUB_STATE_VALID)) {
        /* connect the receiver and send subscription-started */
        r = notif_receiver_connect(receiver);
        if (!r) {
            r = subscription_started_notif_send(notifd_ctx, sub, receiver);
        }
        if (!r) {
            receiver->state = NOTIF_RECV_STATE_ACTIVE;
        } else {
            notif_receiver_disconnect(receiver);
            receiver->state = NOTIF_RECV_STATE_DISCONNECTED;
        }
    } else if ((receiver->state == NOTIF_RECV_STATE_ACTIVE) && (sub->state == NOTIF_SUB_STATE_VALID)) {
        /* a resubscribed active receiver, send subscription-modified */
        subscription_modified_notif_send(notifd_ctx, sub, receiver);
    }

    /* only now may the notifications be delivered, after the state change notification */
    if (notifd_dispatch_add(&notifd_ctx->dispatch, fd, srsn_sub_id)) {
        SRNTF_LOG_ERR("Failed to add notification dispatch for subscription ID %" PRIu32 " and receiver \"%s\".",
                sub->id, receiver->name);
        receiver->srsn_data.sub_id = 0;
        notifd_ctl_start_fail(notifd_ctx, sub);
        goto cleanup_unlock;
    }
    fd = -1;
    srsn_sub_id = 0;

    if (receiver->state == NOTIF_RECV_STATE_ACTIVE) {
        /* an on-change subscription with sync-on-start starts with a push-update */
        notif_receiver_sync_on_start(receiver);
    }

cleanup_unlock:
    /* STATE UNLOCK */
    notifd_rwlock_unlock(&notifd_ctx->state_rwlock, __func__);

    /* close the read end before terminating the srsn subscription */
    if (fd > -1) {
        close(fd);
    }
    if (srsn_sub_id) {
        srsn_terminate(srsn_sub_id, NULL);
    }
}

/**
 * @brief Control thread.
 *
 * @param[in] arg Daemon context.
 * @return NULL.
 */
static void *
notifd_control_thread(void *arg)
{
    notifd_ctx_t *notifd_ctx = arg;
    notifd_control_t *ctl = &notifd_ctx->control;
    notif_srsn_params_t params;
    uint32_t *stop_ids;
    LYA_COUNT_T i;

    /* CTL LOCK */
    pthread_mutex_lock(&ctl->lock);

    while (ctl->thread_running || LYA_COUNT(ctl->stop_ids) || ctl->start_queued) {
        if (!LYA_COUNT(ctl->stop_ids) && !ctl->start_queued) {
            pthread_cond_wait(&ctl->cond, &ctl->lock);
            continue;
        }

        /* take the whole queue */
        stop_ids = ctl->stop_ids;
        ctl->stop_ids = NULL;
        ctl->start_queued = 0;

        /* CTL UNLOCK */
        pthread_mutex_unlock(&ctl->lock);

        LYA_FOR(stop_ids, i) {
            /* the subscription may have ended on its own */
            srsn_terminate(stop_ids[i], NULL);
        }
        LYA_FREE(stop_ids);

        /* one start at a time, the queued ones are looked up again after each */
        while (notifd_ctl_start_take(notifd_ctx, &params)) {
            notifd_ctl_start(notifd_ctx, &params);
            notifd_ctl_params_free(&params);
        }

        /* CTL LOCK */
        pthread_mutex_lock(&ctl->lock);
    }

    /* CTL UNLOCK */
    pthread_mutex_unlock(&ctl->lock);

    return NULL;
}

int
notifd_control_start(notifd_ctx_t *notifd_ctx)
{
    notifd_control_t *ctl = &notifd_ctx->control;
    int r;

    /* the session of the srsn subscriptions, every subscription made with it is gone before it is stopped */
    if ((r = sr_session_start(sr_session_get_connection(notifd_ctx->sr_sess), SR_DS_RUNNING, &ctl->sess))) {
        SRNTF_LOG_ERR("Failed to start the control session.");
        return r;
    }

    ctl->thread_running = 1;
    if ((r = pthread_create(&ctl->tid, NULL, notifd_control_thread, notifd_ctx))) {
        SRNTF_LOG_ERR("Failed to create the control thread (%s).", strerror(r));
        ctl->thread_running = 0;
        return SR_ERR_SYS;
    }

    return SR_ERR_OK;
}

void
notifd_control_stop(notifd_ctx_t *notifd_ctx)
{
    notifd_control_t *ctl = &notifd_ctx->control;
    int running;

    /* CTL LOCK */
    pthread_mutex_lock(&ctl->lock);

    running = ctl->thread_running;
    ctl->thread_running = 0;
    pthread_cond_signal(&ctl->cond);

    /* CTL UNLOCK */
    pthread_mutex_unlock(&ctl->lock);

    if (running) {
        /* the thread empties the queue before it ends */
        pthread_join(ctl->tid, NULL);
    }
}
