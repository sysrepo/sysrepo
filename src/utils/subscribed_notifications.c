/**
 * @file subscribed_notifications.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief multi-module notification subscription functions
 *
 * @copyright
 * Copyright (c) 2023 Deutsche Telekom AG.
 * Copyright (c) 2023 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#define _GNU_SOURCE

#include "subscribed_notifications.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "compat.h"
#include "config.h"
#include "log.h"
#include "sn_common.h"
#include "sn_yang_push.h"

API int
srsn_filter_subtree2xpath(const struct lyd_node *subtree, sr_session_ctx_t *session, char **xpath_filter)
{
    sr_error_info_t *err_info = NULL;
    struct srsn_filter filter = {0};

    *xpath_filter = NULL;

    /* create a filter structure first */
    if ((err_info = srsn_filter_create_subtree(subtree, &filter))) {
        goto cleanup;
    }

    /* transform into an XPath */
    if ((err_info = srsn_filter_filter2xpath(&filter, xpath_filter))) {
        goto cleanup;
    }

cleanup:
    srsn_filter_erase(&filter);
    return sr_api_ret(session, err_info);
}

API int
srsn_notif_sent(uint32_t sub_id)
{
    sr_error_info_t *err_info = NULL;
    struct srsn_sub *sub;

    if (!(sub = srsn_find(sub_id, 0))) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Subscription with ID %" PRIu32 " not found.", sub_id);
        goto cleanup;
    }

    ++sub->sent_count;

cleanup:
    return sr_api_ret(NULL, err_info);
}

API int
srsn_subscribe(sr_session_ctx_t *session, const char *stream, const char *xpath_filter, const struct timespec *stop_time,
        const struct timespec *start_time, int sub_no_thread, sr_subscription_ctx_t **sub,
        struct timespec *replay_start_time, int *fd, uint32_t *sub_id)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    struct srsn_sub *s = NULL;
    struct timespec cur_ts, replay_start;

    if (!(ly_mod = ly_ctx_get_module_implemented(session->conn->ly_ctx, "ietf-subscribed-notifications"))) {
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Module \"ietf-subscribed-notifications\" is not implemented.");
        goto cleanup;
    } else if (start_time && lys_feature_value(ly_mod, "replay")) {
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Module \"ietf-subscribed-notifications\" feature \"replay\" "
                "is not enabled.");
        goto cleanup;
    }

    /* check parameters */
    sr_realtime_get(&cur_ts);
    if (start_time && (sr_time_cmp(&cur_ts, start_time) < 0)) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Specified \"start-time\" is in the future.");
        goto cleanup;
    } else if (!start_time && stop_time && (sr_time_cmp(&cur_ts, stop_time) > 0)) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Specified \"stop-time\" is in the past.");
        goto cleanup;
    } else if (start_time && stop_time && (sr_time_cmp(start_time, stop_time) > 0)) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Specified \"stop-time\" is earlier than \"start-time\".");
        goto cleanup;
    }

    /* prepare the subscription structure */
    if ((err_info = srsn_sub_new(xpath_filter, stop_time, sub, sr_session_get_connection(session), &s))) {
        goto cleanup;
    }
    s->type = SRSN_SUB_NOTIF;
    s->stream = stream ? strdup(stream) : strdup("NETCONF");
    if (start_time) {
        s->start_time = *start_time;
    }

    /* subscribe to sysrepo notifications */
    if ((err_info = srsn_sn_sr_subscribe(session, s, sub_no_thread, &replay_start))) {
        goto cleanup;
    }

    /* add into subscriptions, is not accessible before */
    if ((err_info = srsn_sub_add(s))) {
        goto cleanup;
    }

    /* fill out params */
    if (sub) {
        /* managed by the caller now */
        *sub = s->sr_sub;
    }
    if (replay_start_time) {
        *replay_start_time = replay_start;
    }
    *fd = s->rfd;
    *sub_id = s->id;

    /* schedule the stop */
    if ((err_info = srsn_sub_schedule_stop(s))) {
        goto cleanup;
    }

cleanup:
    if (err_info) {
        if (s && (s->rfd > -1)) {
            close(s->rfd);
        }
        srsn_sub_free(s);
    }

    return sr_api_ret(session, err_info);
}

API int
srsn_yang_push_periodic(sr_session_ctx_t *session, sr_datastore_t ds, const char *xpath_filter, uint32_t period_ms,
        const struct timespec *anchor_time, const struct timespec *stop_time, int *fd, uint32_t *sub_id)
{
    sr_error_info_t *err_info = NULL;
    struct srsn_sub *s = NULL;

    if (!ly_ctx_get_module_implemented(session->conn->ly_ctx, "ietf-yang-push")) {
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Module \"ietf-yang-push\" is not implemented.");
        goto cleanup;
    }

    /* prepare the subscription structure */
    if ((err_info = srsn_sub_new(xpath_filter, stop_time, NULL, sr_session_get_connection(session), &s))) {
        goto cleanup;
    }
    s->type = SRSN_YANG_PUSH_PERIODIC;
    s->ds = ds;
    s->period_ms = period_ms;
    if (anchor_time) {
        s->anchor_time = *anchor_time;
    }
    pthread_mutex_init(&s->update_sntimer.lock, NULL);
    pthread_cond_init(&s->update_sntimer.cond, NULL);

    /* schedule the periodic updates */
    if ((err_info = srsn_yp_schedule_periodic_update(s->period_ms, anchor_time, s, &s->update_sntimer))) {
        goto cleanup;
    }

    /* add into subscriptions, is not accessible before */
    if ((err_info = srsn_sub_add(s))) {
        goto cleanup;
    }

    /* fill out params */
    *fd = s->rfd;
    *sub_id = s->id;

    /* schedule the stop */
    if ((err_info = srsn_sub_schedule_stop(s))) {
        goto cleanup;
    }

cleanup:
    if (err_info) {
        if (s && (s->rfd > -1)) {
            close(s->rfd);
        }
        srsn_sub_free(s);
    }

    return sr_api_ret(session, err_info);
}

API int
srsn_yang_push_on_change(sr_session_ctx_t *session, sr_datastore_t ds, const char *xpath_filter,
        uint32_t dampening_period_ms, int sync_on_start, int excluded_changes[SRSN_COUNT_YP_CHANGE],
        const struct timespec *stop_time, int sub_no_thread, sr_subscription_ctx_t **sub, int *fd, uint32_t *sub_id)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    struct srsn_sub *s = NULL;

    if (!(ly_mod = ly_ctx_get_module_implemented(session->conn->ly_ctx, "ietf-yang-push"))) {
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Module \"ietf-yang-push\" is not implemented.");
        goto cleanup;
    } else if (lys_feature_value(ly_mod, "on-change")) {
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Module \"ietf-yang-push\" feature \"on-change\" is not enabled.");
        goto cleanup;
    }

    /* prepare the subscription structure */
    if ((err_info = srsn_sub_new(xpath_filter, stop_time, sub, sr_session_get_connection(session), &s))) {
        goto cleanup;
    }
    s->type = SRSN_YANG_PUSH_ON_CHANGE;
    s->ds = ds;
    s->dampening_period_ms = dampening_period_ms;
    s->sync_on_start = sync_on_start;
    if (excluded_changes) {
        memcpy(s->excluded_changes, excluded_changes, sizeof s->excluded_changes);
    }
    s->patch_id = 1;
    pthread_mutex_init(&s->damp_sntimer.lock, NULL);
    pthread_cond_init(&s->damp_sntimer.cond, NULL);

    /* send the initial update notification */
    if (sync_on_start && (err_info = srsn_yp_ntf_update_send(s))) {
        goto cleanup;
    }

    /* subscribe to sysrepo module changes */
    if ((err_info = srsn_yp_sr_subscribe(session, s, sub_no_thread))) {
        goto cleanup;
    }

    /* add into subscriptions, is not accessible before */
    if ((err_info = srsn_sub_add(s))) {
        goto cleanup;
    }

    /* fill out params */
    if (sub) {
        /* managed by the caller now */
        *sub = s->sr_sub;
    }
    *fd = s->rfd;
    *sub_id = s->id;

    /* schedule the stop */
    if ((err_info = srsn_sub_schedule_stop(s))) {
        goto cleanup;
    }

cleanup:
    if (err_info) {
        if (s && (s->rfd > -1)) {
            close(s->rfd);
        }
        srsn_sub_free(s);
    }

    return sr_api_ret(session, err_info);
}

API int
srsn_yang_push_on_change_resync(uint32_t sub_id)
{
    sr_error_info_t *err_info = NULL;
    struct srsn_sub *sub;

    if (!(sub = srsn_find(sub_id, 0)) || (sub->type != SRSN_YANG_PUSH_ON_CHANGE)) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "YANG-push on-change subscription with ID %" PRIu32 " not found.",
                sub_id);
        goto cleanup;
    }

    /* reset patch ID */
    srsn_yp_reset_patch_id(sub);

    /* send the update notification */
    if ((err_info = srsn_yp_ntf_update_send(sub))) {
        goto cleanup;
    }

cleanup:
    return sr_api_ret(NULL, err_info);
}

API int
srsn_modify_xpath_filter(uint32_t sub_id, const char *xpath_filter)
{
    sr_error_info_t *err_info = NULL;
    struct srsn_sub *sub;

    if (!(sub = srsn_find(sub_id, 0))) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Subscription with ID %" PRIu32 " not found.", sub_id);
        goto cleanup;
    }

    if ((err_info = srsn_modify_xpath(sub, xpath_filter))) {
        goto cleanup;
    }

cleanup:
    return sr_api_ret(NULL, err_info);
}

API int
srsn_modify_stop_time(uint32_t sub_id, const struct timespec *stop_time)
{
    sr_error_info_t *err_info = NULL;
    struct srsn_sub *sub;

    if (!(sub = srsn_find(sub_id, 0))) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Subscription with ID %" PRIu32 " not found.", sub_id);
        goto cleanup;
    }

    if ((err_info = srsn_modify_stop(sub, stop_time))) {
        goto cleanup;
    }

cleanup:
    return sr_api_ret(NULL, err_info);
}

API int
srsn_yang_push_modify_periodic(uint32_t sub_id, uint32_t period_ms, const struct timespec *anchor_time)
{
    sr_error_info_t *err_info = NULL;
    struct srsn_sub *sub;

    if (!(sub = srsn_find(sub_id, 0)) || (sub->type != SRSN_YANG_PUSH_PERIODIC)) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "YANG-push periodic subscription with ID %" PRIu32 " not found.",
                sub_id);
        goto cleanup;
    }

    if ((err_info = srsn_yp_periodic_modify(sub, period_ms, anchor_time))) {
        goto cleanup;
    }

cleanup:
    return sr_api_ret(NULL, err_info);
}

API int
srsn_yang_push_modify_on_change(uint32_t sub_id, uint32_t dampening_period_ms)
{
    sr_error_info_t *err_info = NULL;
    struct srsn_sub *sub;

    if (!(sub = srsn_find(sub_id, 0)) || (sub->type != SRSN_YANG_PUSH_ON_CHANGE)) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "YANG-push on-change subscription with ID %" PRIu32 " not found.",
                sub_id);
        goto cleanup;
    }

    if ((err_info = srsn_yp_on_change_modify(sub, dampening_period_ms))) {
        goto cleanup;
    }

cleanup:
    return sr_api_ret(NULL, err_info);
}

API int
srsn_suspend(uint32_t sub_id, const char *reason)
{
    sr_error_info_t *err_info = NULL;
    struct srsn_sub *sub;
    struct lyd_node *ly_ntf = NULL;
    const struct ly_ctx *ly_ctx = NULL;
    uint32_t i, j;
    int r, suspended;
    char buf[26];
    struct timespec ts;

    if (!(sub = srsn_find(sub_id, 0))) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Subscription with ID %" PRIu32 " not found.", sub_id);
        goto cleanup;
    }

    switch (sub->type) {
    case SRSN_SUB_NOTIF:
    case SRSN_YANG_PUSH_ON_CHANGE:
        if (!sr_subscription_get_suspended(sub->sr_sub, sub->sr_sub_ids[0], &suspended) && suspended) {
            /* already suspended */
            goto cleanup;
        }

        /* suspend all SR subscriptions */
        for (i = 0; i < ATOMIC_LOAD_RELAXED(sub->sr_sub_id_count); ++i) {
            if ((r = sr_subscription_suspend(sub->sr_sub, sub->sr_sub_ids[i]))) {
                sr_errinfo_new(&err_info, r, "Failed to suspend a subscription.");

                /* revert */
                for (j = 0; j < i; ++j) {
                    sr_subscription_resume(sub->sr_sub, sub->sr_sub_ids[j]);
                }
                goto cleanup;
            }
        }
        break;
    case SRSN_YANG_PUSH_PERIODIC:
        if (sub->suspended) {
            /* already suspended */
            goto cleanup;
        }

        /* stop the update timer */
        srsn_update_timer(NULL, NULL, &sub->update_sntimer);
        sub->suspended = 1;
        break;
    }

    if (reason) {
        /* send the subscription-suspended notification */
        ly_ctx = sr_acquire_context(sub->conn);
        sprintf(buf, "%" PRIu32, sub->id);
        if (lyd_new_path(NULL, ly_ctx, "/ietf-subscribed-notifications:subscription-suspended/id", buf, 0, &ly_ntf)) {
            sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
        }
        if (lyd_new_path(ly_ntf, NULL, "reason", reason, 0, NULL)) {
            sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
        }
        sr_realtime_get(&ts);
        if ((err_info = srsn_ntf_send(sub, &ts, ly_ntf))) {
            goto cleanup;
        }
    }

cleanup:
    lyd_free_tree(ly_ntf);
    if (ly_ctx) {
        sr_release_context(sub->conn);
    }
    return sr_api_ret(NULL, err_info);
}

API int
srsn_resume(uint32_t sub_id)
{
    sr_error_info_t *err_info = NULL;
    struct srsn_sub *sub;
    struct lyd_node *ly_ntf = NULL;
    const struct ly_ctx *ly_ctx = NULL;
    uint32_t i, j;
    int r, suspended;
    char buf[26];
    struct timespec ts;

    if (!(sub = srsn_find(sub_id, 0))) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Subscription with ID %" PRIu32 " not found.", sub_id);
        goto cleanup;
    }

    switch (sub->type) {
    case SRSN_SUB_NOTIF:
    case SRSN_YANG_PUSH_ON_CHANGE:
        if (!sr_subscription_get_suspended(sub->sr_sub, sub->sr_sub_ids[0], &suspended) && !suspended) {
            /* already active */
            goto cleanup;
        }

        /* resume all SR subscriptions */
        for (i = 0; i < ATOMIC_LOAD_RELAXED(sub->sr_sub_id_count); ++i) {
            if ((r = sr_subscription_resume(sub->sr_sub, sub->sr_sub_ids[i]))) {
                sr_errinfo_new(&err_info, r, "Failed to resume a subscription.");

                /* revert */
                for (j = 0; j < i; ++j) {
                    sr_subscription_suspend(sub->sr_sub, sub->sr_sub_ids[j]);
                }
                goto cleanup;
            }
        }
        break;
    case SRSN_YANG_PUSH_PERIODIC:
        if (!sub->suspended) {
            /* already active */
            goto cleanup;
        }

        /* create the update timer */
        if ((err_info = srsn_yp_schedule_periodic_update(sub->period_ms, &sub->anchor_time, sub, &sub->update_sntimer))) {
            goto cleanup;
        }
        sub->suspended = 0;
        break;
    }

    /* send the subscription-resumed notification */
    ly_ctx = sr_acquire_context(sub->conn);
    sprintf(buf, "%" PRIu32, sub->id);
    if (lyd_new_path(NULL, ly_ctx, "/ietf-subscribed-notifications:subscription-resumed/id", buf, 0, &ly_ntf)) {
        sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
        goto cleanup;
    }
    sr_realtime_get(&ts);
    if ((err_info = srsn_ntf_send(sub, &ts, ly_ntf))) {
        goto cleanup;
    }

cleanup:
    lyd_free_tree(ly_ntf);
    if (ly_ctx) {
        sr_release_context(sub->conn);
    }
    return sr_api_ret(NULL, err_info);
}

API int
srsn_terminate(uint32_t sub_id, const char *reason)
{
    sr_error_info_t *err_info = NULL;
    int rc = SR_ERR_OK;
    struct srsn_sub *sub;

    /* LOCK */
    if ((err_info = srsn_lock())) {
        return sr_api_ret(NULL, err_info);
    }

    if (!(sub = srsn_find(sub_id, 1))) {
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    /* unsubscribe to prevent any more notifications to be sent */
    srsn_sub_free_unsubscribe(sub);

    if (reason) {
        /* send the subscription-terminated notification */
        if ((err_info = srsn_ntf_send_terminated(sub, reason))) {
            goto cleanup;
        }
    }

    /* free subscription */
    srsn_sub_free(sub);

cleanup:
    /* UNLOCK */
    srsn_unlock();

    return err_info ? sr_api_ret(NULL, err_info) : rc;
}

API int
srsn_oper_data_streams_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *UNUSED(path), const char *UNUSED(request_xpath), uint32_t UNUSED(request_id),
        struct lyd_node **parent, void *UNUSED(private_data))
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *root, *stream;
    sr_conn_ctx_t *conn;
    const struct ly_ctx *ly_ctx;
    const struct lys_module *ly_mod;
    uint32_t idx = 0;
    char *buf;
    int enabled, rc;
    struct timespec earliest_notif;

    /* context locked while the callback is executing */
    conn = sr_session_get_connection(session);
    ly_ctx = sr_acquire_context(conn);
    sr_release_context(conn);

    if (lyd_new_path(NULL, ly_ctx, "/ietf-subscribed-notifications:streams", NULL, 0, &root)) {
        sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
        goto cleanup;
    }

    /* generic stream */
    if (lyd_new_path(root, NULL, "/ietf-subscribed-notifications:streams/stream[name='NETCONF']", NULL, 0, &stream)) {
        sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
        goto cleanup;
    }
    if (lyd_new_term(stream, stream->schema->module, "description",
            "Default NETCONF stream containing notifications from all the modules."
            " Replays only notifications for modules that support replay.", 0, NULL)) {
        sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
        goto cleanup;
    }
    if (lyd_new_term(stream, stream->schema->module, "replay-support", NULL, 0, NULL)) {
        sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
        goto cleanup;
    }

    /* go through all the modules */
    while ((ly_mod = ly_ctx_get_module_iter(ly_ctx, &idx))) {
        if (!ly_mod->implemented || !srsn_ly_mod_has_notif(ly_mod)) {
            /* not implemented or no notifications in the module so do not consider it a stream */
            continue;
        }

        /* generate information about the stream/module */
        if (lyd_new_list(root, NULL, "stream", 0, &stream, ly_mod->name)) {
            sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
            goto cleanup;
        }
        if (lyd_new_term(stream, NULL, "description", "Stream with all notifications of a module.", 0, NULL)) {
            sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
            goto cleanup;
        }

        /* learn whether replay is supported */
        if (sr_get_module_replay_support(conn, ly_mod->name, &earliest_notif, &enabled)) {
            sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
            goto cleanup;
        }
        if (enabled) {
            if (lyd_new_term(stream, NULL, "replay-support", NULL, 0, NULL)) {
                sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
                goto cleanup;
            }
            ly_time_ts2str(&earliest_notif, &buf);
            if (lyd_new_term(stream, NULL, "replay-log-creation-time", buf, 0, NULL)) {
                free(buf);
                sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
                goto cleanup;
            }
            free(buf);
        }
    }

cleanup:
    if (err_info) {
        rc = err_info->err[0].err_code;
        sr_errinfo_free(&err_info);

        lyd_free_tree(root);
    } else {
        rc = SR_ERR_OK;

        *parent = root;
    }
    return rc;
}

API int
srsn_oper_data_subscriptions(srsn_state_sub_t **subs, uint32_t *count)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!subs || !count, NULL, err_info);

    /* LOCK */
    if ((err_info = srsn_lock())) {
        return sr_api_ret(NULL, err_info);
    }

    if ((err_info = srsn_state_collect(subs, count))) {
        goto cleanup;
    }

cleanup:
    /* UNLOCK */
    srsn_unlock();

    return sr_api_ret(NULL, err_info);
}

API int
srsn_oper_data_sub(uint32_t sub_id, srsn_state_sub_t **sub)
{
    sr_error_info_t *err_info = NULL;
    struct srsn_sub *s;

    SR_CHECK_ARG_APIRET(!sub_id || !sub, NULL, err_info);

    /* LOCK */
    if ((err_info = srsn_lock())) {
        return sr_api_ret(NULL, err_info);
    }

    /* find the subscription */
    if (!(s = srsn_find(sub_id, 1))) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Subscription with ID %" PRIu32 " not found.", sub_id);
        goto cleanup;
    }

    *sub = calloc(1, sizeof **sub);
    SR_CHECK_MEM_GOTO(!*sub, err_info, cleanup);

    if ((err_info = srsn_state_collect_sub(s, *sub))) {
        goto cleanup;
    }

cleanup:
    /* UNLOCK */
    srsn_unlock();

    return sr_api_ret(NULL, err_info);
}

API void
srsn_oper_data_subscriptions_free(srsn_state_sub_t *subs, uint32_t count)
{
    srsn_state_free(subs, count);
}

API int
srsn_read_notif(int fd, const struct ly_ctx *ly_ctx, struct timespec *timestamp, struct lyd_node **notif)
{
    sr_error_info_t *err_info = NULL;
    int rc = SR_ERR_OK;
    struct ly_in *in = NULL;
    uint32_t size;
    char *buf = NULL;
    ssize_t r;

    SR_CHECK_ARG_APIRET(!ly_ctx || !timestamp || !notif, NULL, err_info);

    /* 1) read the timestamp */
    if ((r = read(fd, timestamp, sizeof *timestamp)) != sizeof *timestamp) {
        if ((r == -1) && ((errno == EAGAIN) || (errno == EWOULDBLOCK))) {
            /* timed out */
            rc = SR_ERR_TIME_OUT;
        } else if (!r) {
            /* end-of-file */
            rc = SR_ERR_UNSUPPORTED;
        } else {
            /* error */
            sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to read notification timestamp (%s).", strerror(errno));
        }
        goto cleanup;
    }

    /* 2) read the notification size */
    if (read(fd, &size, sizeof size) != sizeof size) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to read notification size (%s).", strerror(errno));
        goto cleanup;
    }

    buf = malloc(size + 1);
    SR_CHECK_MEM_GOTO(!buf, err_info, cleanup);

    /* 3) read the notification LYB */
    if (read(fd, buf, size) != size) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to read a notification (%s).", strerror(errno));
        goto cleanup;
    }

    /* parse the notification */
    if (ly_in_new_memory(buf, &in)) {
        sr_errinfo_new(&err_info, SR_ERR_LY, "%s", ly_last_errmsg());
        goto cleanup;
    }
    if (lyd_parse_op(ly_ctx, NULL, in, LYD_LYB, LYD_TYPE_NOTIF_YANG, notif, NULL)) {
        sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
        goto cleanup;
    }

cleanup:
    free(buf);
    ly_in_free(in, 0);
    return err_info ? sr_api_ret(NULL, err_info) : rc;
}

API int
srsn_poll(int fd, uint32_t timeout_ms)
{
    int r;
    struct pollfd fds = {0};

    fds.fd = fd;
    fds.events = POLLIN;

    r = poll(&fds, 1, timeout_ms);
    if (r == -1) {
        return SR_ERR_SYS;
    } else if (!r) {
        return SR_ERR_TIME_OUT;
    } else if (fds.revents & POLLIN) {
        return SR_ERR_OK;
    } else if (fds.revents & (POLLERR | POLLHUP)) {
        /* probably the write end closed */
        return SR_ERR_UNSUPPORTED;
    }

    return SR_ERR_INTERNAL;
}

API int
srsn_read_dispatch_start(int fd, sr_conn_ctx_t *conn, srsn_notif_cb cb, void *cb_data)
{
    sr_error_info_t *err_info = NULL;
    struct srsn_dispatch_arg *arg = NULL;
    int r;
    pthread_t tid;

    SR_CHECK_ARG_APIRET(!fd || !conn || !cb, NULL, err_info);

    /* prepare the pollfd structure */
    if ((err_info = srsn_dispatch_init(fd, cb_data))) {
        goto cleanup;
    }

    /* prepare the argument */
    arg = malloc(sizeof *arg);
    SR_CHECK_MEM_GOTO(!arg, err_info, cleanup);

    arg->conn = conn;
    arg->cb = cb;

    /* create the thread */
    if ((r = pthread_create(&tid, NULL, srsn_read_dispatch_thread, arg))) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to create a thread (%s).", strerror(r));
        goto cleanup;
    }

    /* arg is freed by the thread */
    arg = NULL;

cleanup:
    free(arg);
    return sr_api_ret(NULL, err_info);
}

API int
srsn_read_dispatch_add(int fd, void *cb_data)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!fd, NULL, err_info);

    /* add into the pollfd structure */
    err_info = srsn_dispatch_add(fd, cb_data);

    return sr_api_ret(NULL, err_info);
}

API uint32_t
srsn_read_dispatch_count(void)
{
    return srsn_dispatch_count();
}
