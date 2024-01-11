/**
 * @file replay.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief notification replay routines
 *
 * @copyright
 * Copyright (c) 2018 - 2023 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2023 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "compat.h"
#include "replay.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "context_change.h"
#include "log.h"
#include "plugins_notification.h"
#include "shm_mod.h"
#include "subscr.h"
#include "sysrepo.h"

/**
 * @brief Store the notification for replay.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod Notification SHM module.
 * @param[in] notif Notification data tree.
 * @param[in] notif_ts Notification timestamp.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_notif_write(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, const struct lyd_node *notif, struct timespec notif_ts)
{
    sr_error_info_t *err_info = NULL;
    const struct sr_ntf_handle_s *ntf_handle;

    /* find handle */
    if ((err_info = sr_ntf_handle_find(conn->mod_shm.addr + shm_mod->plugins[SR_MOD_DS_NOTIF], conn, &ntf_handle))) {
        goto cleanup;
    }

    /* REPLAY WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_mod->replay_lock, SR_MOD_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__, NULL, NULL))) {
        goto cleanup;
    }

    /* store the notification */
    if ((err_info = ntf_handle->plugin->store_cb(lyd_owner_module(notif), notif, &notif_ts))) {
        goto cleanup_unlock;
    }

cleanup_unlock:
    /* REPLAY WRITE UNLOCK */
    sr_rwunlock(&shm_mod->replay_lock, SR_MOD_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__);
cleanup:
    return err_info;
}

/**
 * @brief Store the notification into the notification buffer.
 *
 * @param[in] sess Session with the buffer.
 * @param[in] notif Notification data tree.
 * @param[in] notif_ts Notification timestamp.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_notif_buf_store(sr_session_ctx_t *sess, const struct lyd_node *notif, struct timespec notif_ts)
{
    sr_error_info_t *err_info = NULL;
    struct sr_sess_notif_buf *notif_buf = &sess->notif_buf;
    struct sr_sess_notif_buf_node *node = NULL;

    /* create a new node while we do not have any lock */
    node = malloc(sizeof *node);
    SR_CHECK_MEM_GOTO(!node, err_info, cleanup);
    if (lyd_dup_siblings(notif, NULL, LYD_DUP_RECURSIVE | LYD_DUP_WITH_FLAGS, &node->notif)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(notif), NULL);
        goto cleanup;
    }
    node->notif_ts = notif_ts;
    node->next = NULL;

    /* store new notification */
    if (notif_buf->last) {
        assert(notif_buf->first);
        notif_buf->last->next = node;
        notif_buf->last = node;
    } else {
        /* CONTEXT LOCK */
        if ((err_info = sr_lycc_lock(sess->conn, SR_LOCK_READ, 0, __func__))) {
            goto cleanup;
        }

        assert(!notif_buf->first);
        notif_buf->first = node;
        notif_buf->last = node;
    }
    node = NULL;

cleanup:
    if (node) {
        lyd_free_siblings(node->notif);
        free(node);
    }
    return err_info;
}

sr_error_info_t *
sr_replay_store(sr_session_ctx_t *sess, const struct lyd_node *notif, struct timespec notif_ts)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    const struct lys_module *ly_mod;
    struct lyd_node *notif_op;
    struct timespec timeout_ts;
    int r, has_buf = 0;

    assert(notif && !notif->parent);

    ly_mod = lyd_owner_module(notif);
    notif_op = (struct lyd_node *)notif;
    if ((err_info = sr_ly_find_last_parent(&notif_op, LYS_NOTIF))) {
        return err_info;
    }
    SR_CHECK_INT_RET(notif_op->schema->nodetype != LYS_NOTIF, err_info);

    /* find SHM mod for replay lock and check if replay is even supported */
    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(sess->conn), ly_mod->name);
    SR_CHECK_INT_RET(!shm_mod, err_info);

    if (!shm_mod->replay_supp) {
        /* nothing to do */
        return NULL;
    }

    /* MUTEX LOCK */
    sr_timeouttime_get(&timeout_ts, SR_NOTIF_BUF_LOCK_TIMEOUT);
    if ((r = pthread_mutex_clocklock(&sess->notif_buf.lock.mutex, COMPAT_CLOCK_ID, &timeout_ts))) {
        SR_ERRINFO_LOCK(&err_info, __func__, r);
        return err_info;
    }

    if (sess->notif_buf.thread_running) {
        /* store the notification in the buffer */
        has_buf = 1;
        err_info = sr_notif_buf_store(sess, notif, notif_ts);

        /* broadcast condition */
        sr_cond_broadcast(&sess->notif_buf.lock.cond);
    }

    /* MUTEX UNLOCK */
    pthread_mutex_unlock(&sess->notif_buf.lock.mutex);

    if (err_info) {
        return err_info;
    }

    if (!has_buf) {
        /* write the notification to a replay file */
        if ((err_info = sr_notif_write(sess->conn, shm_mod, notif, notif_ts))) {
            return err_info;
        }
    }

    if (has_buf) {
        SR_LOG_INF("Notification \"%s\" buffered to be stored for replay.", notif_op->schema->name);
    } else {
        SR_LOG_INF("Notification \"%s\" stored for replay.", notif_op->schema->name);
    }

    return NULL;
}

/**
 * @brief Write all the buffered notifications.
 *
 * @param[in] conn Connection to use.
 * @param[in] first First notification structure to write, with all the following ones.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_notif_buf_thread_write_notifs(sr_conn_ctx_t *conn, struct sr_sess_notif_buf_node *first)
{
    sr_error_info_t *err_info = NULL;
    struct sr_sess_notif_buf_node *prev;
    sr_mod_t *shm_mod;

    while (first) {
        /* find SHM mod */
        shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(conn), lyd_owner_module(first->notif)->name);
        if (!shm_mod) {
            SR_ERRINFO_INT(&err_info);
            return err_info;
        }

        /* store the notification */
        if ((err_info = sr_notif_write(conn, shm_mod, first->notif, first->notif_ts))) {
            return err_info;
        }

        /* next iter */
        prev = first;
        first = first->next;

        /* free prev */
        lyd_free_siblings(prev->notif);
        free(prev);
    }

    return NULL;
}

void *
sr_notif_buf_thread(void *arg)
{
    sr_error_info_t *err_info = NULL;
    sr_session_ctx_t *sess = (sr_session_ctx_t *)arg;
    struct sr_sess_notif_buf_node *first;
    struct timespec timeout_ts;
    int r, last_check = 0;

    sr_timeouttime_get(&timeout_ts, SR_NOTIF_BUF_LOCK_TIMEOUT);

    while (!last_check) {
        /* MUTEX LOCK */
        if ((r = pthread_mutex_clocklock(&sess->notif_buf.lock.mutex, COMPAT_CLOCK_ID, &timeout_ts))) {
            SR_ERRINFO_LOCK(&err_info, __func__, r);
            goto cleanup;
        }

        /* write lock, wait for notifications */
        r = 0;
        while (!r && sess->notif_buf.thread_running && !sess->notif_buf.first) {
            /* COND WAIT */
            r = sr_cond_wait(&sess->notif_buf.lock.cond, &sess->notif_buf.lock.mutex);
        }
        if (r) {
            /* MUTEX UNLOCK */
            pthread_mutex_unlock(&sess->notif_buf.lock.mutex);

            SR_ERRINFO_COND(&err_info, __func__, r);
            goto cleanup;
        }

        /* remember and clear the buffer */
        first = sess->notif_buf.first;
        sess->notif_buf.first = NULL;
        sess->notif_buf.last = NULL;

        if (!sess->notif_buf.thread_running) {
            /* we are holding the mutex and thread should no longer be running meaning no more notifications
             * can be added */
            last_check = 1;
        }

        /* MUTEX UNLOCK */
        pthread_mutex_unlock(&sess->notif_buf.lock.mutex);

        /* store the notifications, if any */
        if (first) {
            err_info = sr_notif_buf_thread_write_notifs(sess->conn, first);

            /* CONTEXT UNLOCK */
            sr_lycc_unlock(sess->conn, SR_LOCK_READ, 0, __func__);

            if (err_info) {
                goto cleanup;
            }
        }
    }

cleanup:
    return err_info;
}

sr_error_info_t *
sr_replay_notify(sr_conn_ctx_t *conn, const char *mod_name, uint32_t sub_id, const char *xpath,
        const struct timespec *start_time, const struct timespec *stop_time, struct timespec *listen_since,
        sr_event_notif_cb cb, sr_event_notif_tree_cb tree_cb, void *private_data)
{
    sr_error_info_t *err_info = NULL;
    const struct sr_ntf_handle_s *ntf_handle;
    const struct lys_module *ly_mod;
    sr_mod_t *shm_mod;
    struct timespec notif_ts, stop_ts;
    struct ly_set *set = NULL;
    struct lyd_node *notif = NULL, *notif_op;
    sr_session_ctx_t *ev_sess = NULL;
    void *state = NULL;

    /* get the stop timestamp - only notifications with smaller timestamp can be replayed */
    if (!SR_TS_IS_ZERO(*stop_time) && (sr_time_cmp(stop_time, listen_since) < 1)) {
        stop_ts = *stop_time;
    } else {
        stop_ts = *listen_since;
    }

    /* find SHM mod for replay lock and check if replay is even supported */
    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(conn), mod_name);
    SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup);

    /* create event session */
    if ((err_info = _sr_session_start(conn, SR_DS_OPERATIONAL, SR_SUB_EV_NOTIF, NULL, &ev_sess))) {
        goto cleanup;
    }

    if (!shm_mod->replay_supp) {
        SR_LOG_WRN("Module \"%s\" does not support notification replay.", mod_name);
        goto replay_complete;
    }

    /* find module */
    ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, mod_name);
    assert(ly_mod);

    /* find handle */
    if ((err_info = sr_ntf_handle_find(conn->mod_shm.addr + shm_mod->plugins[SR_MOD_DS_NOTIF], conn, &ntf_handle))) {
        goto cleanup;
    }

    /* replay all notifications */
    while (!(err_info = ntf_handle->plugin->replay_next_cb(ly_mod, start_time, &stop_ts, &notif, &notif_ts, &state)) && state) {
        /* make sure the XPath filter matches something */
        if (xpath) {
            ly_set_free(set, NULL);
            SR_CHECK_INT_GOTO(lyd_find_xpath(notif, xpath, &set), err_info, cleanup);
        }

        if (!xpath || set->count) {
            /* find notification node */
            notif_op = notif;
            if ((err_info = sr_ly_find_last_parent(&notif_op, LYS_NOTIF))) {
                goto cleanup;
            }
            SR_CHECK_INT_GOTO(notif_op->schema->nodetype != LYS_NOTIF, err_info, cleanup);

            /* call callback */
            if ((err_info = sr_notif_call_callback(ev_sess, cb, tree_cb, private_data, SR_EV_NOTIF_REPLAY, sub_id,
                    notif_op, &notif_ts))) {
                goto cleanup;
            }
        }

        /* next */
        lyd_free_siblings(notif);
        notif = NULL;
    }
    if (err_info) {
        goto cleanup;
    }

replay_complete:
    /* replay is completed */
    if ((err_info = sr_notif_call_callback(ev_sess, cb, tree_cb, private_data, SR_EV_NOTIF_REPLAY_COMPLETE, sub_id,
            NULL, &stop_ts))) {
        goto cleanup;
    }

cleanup:
    sr_session_stop(ev_sess);
    lyd_free_all(notif);
    ly_set_free(set, NULL);
    return err_info;
}
