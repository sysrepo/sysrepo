/**
 * @file sysrepo.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief sysrepo API routines
 *
 * @copyright
 * Copyright (c) 2018 - 2025 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2025 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "compat.h"
#include "sysrepo.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <libyang/hash_table.h>
#include <libyang/libyang.h>

#include "common.h"
#include "config.h"
#include "context_change.h"
#include "edit_diff.h"
#include "log.h"
#include "ly_wrap.h"
#include "lyd_mods.h"
#include "modinfo.h"
#include "plugins_datastore.h"
#include "plugins_notification.h"
#include "replay.h"
#include "shm_ext.h"
#include "shm_main.h"
#include "shm_mod.h"
#include "shm_sub.h"
#include "subscr.h"
#include "utils/nacm.h"

static sr_error_info_t *sr_session_notif_buf_stop(sr_session_ctx_t *session);
static sr_error_info_t *_sr_session_stop(sr_session_ctx_t *session);
static int _sr_discard_oper_changes(sr_session_ctx_t *session, const char *module_name, int session_stopped,
        uint32_t timeout_ms);
static sr_error_info_t *_sr_unsubscribe(sr_subscription_ctx_t *subscription);

/**
 * @brief Allocate a new connection structure.
 *
 * @param[in] opts Connection options.
 * @param[out] conn_p Allocated connection.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_conn_new(const sr_conn_options_t opts, sr_conn_ctx_t **conn_p)
{
    sr_conn_ctx_t *conn;
    sr_error_info_t *err_info = NULL;

    conn = calloc(1, sizeof *conn);
    SR_CHECK_MEM_RET(!conn, err_info);

    conn->opts = opts;
    if ((err_info = sr_ly_ctx_init(conn, &conn->ly_ctx))) {
        goto error1;
    }

    if ((err_info = sr_mutex_init(&conn->ptr_lock, 0))) {
        goto error2;
    }

    if ((err_info = sr_rwlock_init(&conn->ly_ext_data_lock, 0))) {
        goto error3;
    }

    if ((err_info = sr_shmmain_createlock_open(&conn->create_lock))) {
        goto error4;
    }
    conn->main_shm.fd = -1;

    if ((err_info = sr_rwlock_init(&conn->mod_remap_lock, 0))) {
        goto error5;
    }
    conn->mod_shm.fd = -1;

    if ((err_info = sr_rwlock_init(&conn->ext_remap_lock, 0))) {
        goto error6;
    }
    conn->ext_shm.fd = -1;

    if ((err_info = sr_ds_handle_init(&conn->ds_handles, &conn->ds_handle_count))) {
        goto error7;
    }
    if ((err_info = sr_rwlock_init(&conn->run_cache_lock, 0))) {
        goto error8;
    }
    if ((err_info = sr_ntf_handle_init(&conn->ntf_handles, &conn->ntf_handle_count))) {
        goto error9;
    }
    if ((err_info = sr_rwlock_init(&conn->oper_cache_lock, 0))) {
        goto error10;
    }

    *conn_p = conn;
    return NULL;

error10:
    sr_ntf_handle_free(conn->ntf_handles, conn->ntf_handle_count);
error9:
    sr_rwlock_destroy(&conn->run_cache_lock);
error8:
    sr_ds_handle_free(conn->ds_handles, conn->ds_handle_count);
error7:
    sr_rwlock_destroy(&conn->ext_remap_lock);
error6:
    sr_rwlock_destroy(&conn->mod_remap_lock);
error5:
    close(conn->create_lock);
error4:
    sr_rwlock_destroy(&conn->ly_ext_data_lock);
error3:
    pthread_mutex_destroy(&conn->ptr_lock);
error2:
    ly_ctx_destroy(conn->ly_ctx);
error1:
    free(conn);
    return err_info;
}

/**
 * @brief Free a connection structure.
 *
 * @param[in] conn Connection to free.
 */
static void
sr_conn_free(sr_conn_ctx_t *conn)
{
    uint32_t i;

    if (!conn) {
        return;
    }

    /* destroy DS plugin data */
    sr_conn_ds_destroy(conn);

    assert(!conn->oper_caches);

    /* unlocked data destroy */
    lyd_free_siblings(conn->ly_ext_data);

    /* free run cache only if connection was fully setup */
    if (conn->cid) {
        sr_conn_run_cache_flush(conn);
    }

    for (i = 0; i < conn->oper_cache_count; ++i) {
        lyd_free_siblings(conn->oper_caches[i].data);
    }

    /* context destroy */
    ly_ctx_destroy(conn->ly_ctx);

    pthread_mutex_destroy(&conn->ptr_lock);
    sr_rwlock_destroy(&conn->ly_ext_data_lock);
    if (conn->create_lock > -1) {
        close(conn->create_lock);
    }
    sr_shm_clear(&conn->main_shm);
    sr_rwlock_destroy(&conn->mod_remap_lock);
    sr_shm_clear(&conn->mod_shm);
    sr_rwlock_destroy(&conn->ext_remap_lock);
    sr_shm_clear(&conn->ext_shm);
    sr_ds_handle_free(conn->ds_handles, conn->ds_handle_count);
    sr_rwlock_destroy(&conn->run_cache_lock);
    sr_ntf_handle_free(conn->ntf_handles, conn->ntf_handle_count);
    sr_rwlock_destroy(&conn->oper_cache_lock);

    free(conn);
}

API int
sr_connect(const sr_conn_options_t opts, sr_conn_ctx_t **conn_p)
{
    sr_error_info_t *err_info = NULL;
    sr_conn_ctx_t *conn = NULL;
    struct lyd_node *sr_mods = NULL;
    int created = 0, initialized = 0;
    sr_main_shm_t *main_shm;
    const char *rpc_path;
    sr_rpc_t *shm_rpc;

    SR_CHECK_ARG_APIRET(!conn_p, NULL, err_info);

    /* check that all required directories exist */
    if ((err_info = sr_shmmain_check_dirs())) {
        goto cleanup;
    }

    /* create basic connection structure */
    if ((err_info = sr_conn_new(opts, &conn))) {
        goto cleanup;
    }

    /* CREATE LOCK */
    if ((err_info = sr_shmmain_createlock(conn->create_lock))) {
        goto cleanup;
    }

    /* open the main SHM */
    if ((err_info = sr_shmmain_open(&conn->main_shm, &created))) {
        goto cleanup_unlock;
    }

    /* open the mod SHM */
    if ((err_info = sr_shmmod_open(&conn->mod_shm, created))) {
        goto cleanup_unlock;
    }

    /* open the ext SHM */
    if ((err_info = sr_shmext_open(&conn->ext_shm, created))) {
        goto cleanup_unlock;
    }

    main_shm = SR_CONN_MAIN_SHM(conn);

    /* allocate next unique connection ID */
    conn->cid = ATOMIC_INC_RELAXED(main_shm->new_sr_cid);

    /* track our connection */
    if ((err_info = sr_shmmain_conn_list_add(conn->cid))) {
        goto cleanup_unlock;
    }

    if (created) {
        /* parse SR mods */
        if ((err_info = sr_lydmods_parse(conn->ly_ctx, conn, &initialized, &sr_mods))) {
            goto cleanup_unlock;
        }

        /* get and store content-id in main SHM */
        assert(!strcmp(LYD_NAME(lyd_child(sr_mods)), "content-id"));
        main_shm->content_id = ((struct lyd_node_term *)lyd_child(sr_mods))->value.uint32;

        /* add all the modules in lydmods data into mod SHM */
        if ((err_info = sr_shmmod_store_modules(&conn->mod_shm, sr_mods))) {
            goto cleanup_unlock;
        }

        /* free sr_mods, conn ly_ctx may be recompiled later */
        lyd_free_all(sr_mods);
        sr_mods = NULL;

        /* add internal RPC subscription into ext SHM */
        rpc_path = SR_RPC_FACTORY_RESET_PATH;
        shm_rpc = sr_shmmod_find_rpc(SR_CONN_MOD_SHM(conn), rpc_path);
        SR_CHECK_INT_GOTO(!shm_rpc, err_info, cleanup_unlock);

        /* RPC SUB WRITE LOCK */
        if ((err_info = sr_rwlock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__, NULL,
                NULL))) {
            goto cleanup_unlock;
        }

        err_info = sr_shmext_rpc_sub_add(conn, &shm_rpc->subs, &shm_rpc->sub_count, rpc_path, 0,
                rpc_path, SR_RPC_FACTORY_RESET_INT_PRIO, 0, -1, 0);

        /* RPC SUB WRITE UNLOCK */
        sr_rwunlock(&shm_rpc->lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

        if (err_info) {
            goto cleanup_unlock;
        }
    }

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(conn, SR_LOCK_READ, 0, __func__))) {
        goto cleanup_unlock;
    }

    /* context was updated */

    /* CONTEXT UNLOCK */
    sr_lycc_unlock(conn, SR_LOCK_READ, 0, __func__);

    if (created) {
        /* initialize the datastores */
        if ((err_info = sr_shmmod_reboot_init(conn, initialized))) {
            goto cleanup_unlock;
        }
    }

    SR_LOG_INF("Connection %" PRIu32 " created.", conn->cid);

cleanup_unlock:
    /* CREATE UNLOCK */
    sr_shmmain_createunlock(conn->create_lock);

cleanup:
    lyd_free_all(sr_mods);
    if (err_info) {
        sr_conn_free(conn);
        if (created) {
            /* remove any created SHM so it is not considered properly created */
            sr_error_info_t *tmp_err = NULL;
            char *shm_name = NULL;

            if ((tmp_err = sr_path_main_shm(&shm_name))) {
                sr_errinfo_merge(&err_info, tmp_err);
            } else {
                unlink(shm_name);
                free(shm_name);
            }
            if ((tmp_err = sr_path_ext_shm(&shm_name))) {
                sr_errinfo_merge(&err_info, tmp_err);
            } else {
                unlink(shm_name);
                free(shm_name);
            }
        }
    } else {
        *conn_p = conn;
    }
    return sr_api_ret(NULL, err_info);
}

API int
sr_disconnect(sr_conn_ctx_t *conn)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;

    if (!conn) {
        return sr_api_ret(NULL, NULL);
    }

    /* stop all session notification buffer threads, they use read lock so they need conn state in SHM */
    for (i = 0; i < conn->session_count; ++i) {
        if ((err_info = sr_session_notif_buf_stop(conn->sessions[i]))) {
            return sr_api_ret(NULL, err_info);
        }
    }

    /* stop all subscriptions */
    for (i = 0; i < conn->session_count; ++i) {
        while (conn->sessions[i]->subscription_count && conn->sessions[i]->subscriptions[0]) {
            if ((err_info = _sr_unsubscribe(conn->sessions[i]->subscriptions[0]))) {
                return sr_api_ret(NULL, err_info);
            }
        }
    }

    /* stop all the sessions */
    while (conn->session_count) {
        if ((err_info = _sr_session_stop(conn->sessions[0]))) {
            return sr_api_ret(NULL, err_info);
        }
    }

    /* stop tracking this connection */
    if ((err_info = sr_shmmain_conn_list_del(conn->cid))) {
        return sr_api_ret(NULL, err_info);
    }

    SR_LOG_INF("Connection %" PRIu32 " destroyed.", conn->cid);
    /* free attributes */
    sr_conn_free(conn);

    return sr_api_ret(NULL, NULL);
}

API const struct ly_ctx *
sr_acquire_context(sr_conn_ctx_t *conn)
{
    sr_error_info_t *err_info = NULL;

    if (!conn) {
        return NULL;
    }

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(conn, SR_LOCK_READ, 0, __func__))) {
        sr_errinfo_free(&err_info);
        return NULL;
    }

    return conn->ly_ctx;
}

API const struct ly_ctx *
sr_session_acquire_context(sr_session_ctx_t *session)
{
    if (!session) {
        return NULL;
    }

    return sr_acquire_context(session->conn);
}

API void
sr_release_context(sr_conn_ctx_t *conn)
{
    if (!conn) {
        return;
    }

    /* CONTEXT UNLOCK */
    sr_lycc_unlock(conn, SR_LOCK_READ, 0, __func__);
}

API void
sr_session_release_context(sr_session_ctx_t *session)
{
    if (!session) {
        return;
    }

    sr_release_context(session->conn);
}

API uint32_t
sr_get_content_id(sr_conn_ctx_t *conn)
{
    sr_error_info_t *err_info = NULL;

    if (!conn) {
        return 0;
    }

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(conn, SR_LOCK_READ, 0, __func__))) {
        sr_errinfo_free(&err_info);
        return 0;
    }

    /* just so that the content ID is updated */

    /* CONTEXT UNLOCK */
    sr_lycc_unlock(conn, SR_LOCK_READ, 0, __func__);

    return conn->content_id;
}

API int
sr_get_plugins(sr_conn_ctx_t *conn, const char ***ds_plugins, const char ***ntf_plugins)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;

    SR_CHECK_ARG_APIRET(!conn, NULL, err_info);

    if (ds_plugins) {
        /* internal plugins are copied into every connection */
        *ds_plugins = malloc((conn->ds_handle_count + 1) * sizeof **ds_plugins);
        SR_CHECK_MEM_GOTO(!*ds_plugins, err_info, cleanup);

        for (i = 0; i < conn->ds_handle_count; ++i) {
            (*ds_plugins)[i] = conn->ds_handles[i].plugin->name;
        }
        (*ds_plugins)[i] = NULL;
    }

    if (ntf_plugins) {
        *ntf_plugins = malloc((conn->ntf_handle_count + 1) * sizeof **ntf_plugins);
        SR_CHECK_MEM_GOTO(!*ntf_plugins, err_info, cleanup);

        for (i = 0; i < conn->ntf_handle_count; ++i) {
            (*ntf_plugins)[i] = conn->ntf_handles[i].plugin->name;
        }
        (*ntf_plugins)[i] = NULL;
    }

cleanup:
    if (err_info) {
        if (ds_plugins) {
            free(*ds_plugins);
            *ds_plugins = NULL;
        }
        if (ntf_plugins) {
            free(*ntf_plugins);
            *ntf_plugins = NULL;
        }
    }
    return sr_api_ret(NULL, err_info);
}

API uid_t
sr_get_su_uid(void)
{
    return SR_SU_UID;
}

/**
 * @brief Set originator name and data for a session.
 *
 * @param[in] sess Session to use.
 * @param[in] orig_name Originator name.
 * @param[in] orig_data Originator data.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_session_set_orig(sr_session_ctx_t *sess, const char *orig_name, const void *orig_data)
{
    sr_error_info_t *err_info = NULL;
    const uint32_t empty_data[] = {0};

    if (!orig_name) {
        orig_name = "";
    }
    if (!orig_data) {
        orig_data = empty_data;
    }

    /* orig name */
    sess->ev_data.orig_name = strdup(orig_name);
    SR_CHECK_MEM_RET(!sess->ev_data.orig_name, err_info);

    /* orig data */
    sess->ev_data.orig_data = malloc(sr_ev_data_size(orig_data));
    SR_CHECK_MEM_RET(!sess->ev_data.orig_data, err_info);
    memcpy(sess->ev_data.orig_data, orig_data, sr_ev_data_size(orig_data));

    return NULL;
}

sr_error_info_t *
_sr_session_start(sr_conn_ctx_t *conn, const sr_datastore_t datastore, sr_sub_event_t event, char **shm_data_ptr,
        sr_session_ctx_t **session)
{
    sr_error_info_t *err_info = NULL;
    uid_t uid;

    assert(conn && session);
    assert((event != SR_SUB_EV_SUCCESS) && (event != SR_SUB_EV_ERROR));

    *session = calloc(1, sizeof **session);
    if (!*session) {
        SR_ERRINFO_MEM(&err_info);
        return err_info;
    }

    /* use new SR session ID and increment it (no lock needed, we are just reading and main SHM is never remapped) */
    (*session)->sid = ATOMIC_INC_RELAXED(SR_CONN_MAIN_SHM(conn)->new_sr_sid);

    /* remember current real process owner */
    uid = getuid();
    if ((err_info = sr_get_pwd(&uid, &(*session)->user))) {
        goto error;
    }

    /* add the session into conn */
    if ((err_info = sr_ptr_add(&conn->ptr_lock, (void ***)&conn->sessions, &conn->session_count, *session))) {
        goto error;
    }

    (*session)->conn = conn;
    (*session)->ds = datastore;
    (*session)->ev = event;
    if (shm_data_ptr) {
        if ((err_info = sr_session_set_orig(*session, *shm_data_ptr, (*shm_data_ptr) + sr_strshmlen(*shm_data_ptr)))) {
            goto error;
        }
        *shm_data_ptr += sr_strshmlen(*shm_data_ptr);
        *shm_data_ptr += SR_SHM_SIZE(sr_ev_data_size(*shm_data_ptr));
    }
    if ((err_info = sr_mutex_init(&(*session)->ptr_lock, 0))) {
        goto error;
    }
    if ((err_info = sr_rwlock_init(&(*session)->notif_buf.lock, 0))) {
        goto error;
    }

    return NULL;

error:
    free((*session)->user);
    free(*session);
    *session = NULL;
    return err_info;
}

API int
sr_session_start(sr_conn_ctx_t *conn, const sr_datastore_t datastore, sr_session_ctx_t **session)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!conn || !session, NULL, err_info);

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(conn, SR_LOCK_READ, 0, __func__))) {
        goto cleanup;
    }

    /* update LY ext data on every new explicit session creation */
    if ((err_info = sr_conn_ext_data_update(conn))) {
        goto cleanup;
    }

    /* start the session */
    if ((err_info = _sr_session_start(conn, datastore, SR_SUB_EV_NONE, NULL, session))) {
        goto cleanup;
    }

cleanup:
    /* CONTEXT UNLOCK */
    sr_lycc_unlock(conn, SR_LOCK_READ, 0, __func__);

    return sr_api_ret(NULL, err_info);
}

/**
 * @brief Stop session notif buffering thread.
 *
 * @param[in] session Session whose notif buf to stop.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_session_notif_buf_stop(sr_session_ctx_t *session)
{
    sr_error_info_t *err_info = NULL;
    struct timespec timeout_ts;
    struct sr_sess_notif_buf_node *next, *iter;
    int r, has_notif = 0;

    if (!session->notif_buf.tid) {
        return NULL;
    }

    sr_timeouttime_get(&timeout_ts, SR_NOTIF_BUF_LOCK_TIMEOUT);

    /* MUTEX LOCK */
    if ((r = pthread_mutex_clocklock(&session->notif_buf.lock.mutex, COMPAT_CLOCK_ID, &timeout_ts))) {
        SR_ERRINFO_LOCK(&err_info, __func__, r);
        return err_info;
    }

    /* signal the thread to terminate */
    session->notif_buf.thread_running = 0;

    /* wake up the thread */
    sr_cond_broadcast(&session->notif_buf.lock.cond);

    /* MUTEX UNLOCK */
    pthread_mutex_unlock(&session->notif_buf.lock.mutex);

    /* join the thread, it will make sure all the buffered notifications are stored */
    if ((r = pthread_join(session->notif_buf.tid, (void **)&err_info))) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Joining the notification buffer thread failed (%s).", strerror(r));
    } else if (err_info) {
        /* notif thread error, clean up the notifications */
        if (session->notif_buf.first) {
            has_notif = 1;
        }
        LY_LIST_FOR_SAFE(session->notif_buf.first, next, iter) {
            lyd_free_siblings(iter->notif);
            free(iter);
        }
        session->notif_buf.tid = 0;

        if (has_notif) {
            /* CONTEXT UNLOCK */
            sr_lycc_unlock(session->conn, SR_LOCK_READ, 0, __func__);
            sr_errinfo_new(&err_info, err_info->err[0].err_code, "Failed to store some buffered notifications.");
        }
    } else {
        /* all fine */
        session->notif_buf.tid = 0;
        assert(!session->notif_buf.first);
    }

    return err_info;
}

/**
 * @brief Unlocked stop (free) a session.
 *
 * @param[in] session Session to stop.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
_sr_session_stop(sr_session_ctx_t *session)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    sr_datastore_t ds;
    uint32_t i;

    /* subscriptions need to be freed before, with a WRITE lock */
    assert(!session->subscription_count && !session->subscriptions);

    /* stop notification buffering thread */
    tmp_err = sr_session_notif_buf_stop(session);
    sr_errinfo_merge(&err_info, tmp_err);

    /* drop all staged changes, they interfere with _sr_discard_oper_changes() below */
    for (ds = 0; ds < SR_DS_COUNT; ++ds) {
        sr_release_data(session->dt[ds].edit);
        lyd_free_all(session->dt[ds].diff);
        session->dt[ds].edit = NULL;
        session->dt[ds].diff = NULL;
    }

    if (session->oper_push_mod_count) {
        /* free any stored operational data and the SHM ext push oper data entries */
        _sr_discard_oper_changes(session, NULL, 1, 0);
    }

    /* remove ourselves from conn sessions */
    tmp_err = sr_ptr_del(&session->conn->ptr_lock, (void ***)&session->conn->sessions, &session->conn->session_count, session);
    sr_errinfo_merge(&err_info, tmp_err);

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
        return err_info;
    }

    /* release any held locks */
    sr_shmmod_release_locks(session->conn, session->sid);

    /* CONTEXT UNLOCK */
    sr_lycc_unlock(session->conn, SR_LOCK_READ, 0, __func__);

    /* free attributes */
    free(session->user);
    free(session->nacm_user);
    sr_errinfo_free(&session->err_info);
    free(session->orig_name);
    free(session->orig_data);
    free(session->ev_data.orig_name);
    free(session->ev_data.orig_data);
    sr_errinfo_free(&session->ev_err_info);
    pthread_mutex_destroy(&session->ptr_lock);

    /* free any push oper module names */
    for (i = 0; i < session->oper_push_mod_count; ++i) {
        free(session->oper_push_mods[i].name);
    }
    free(session->oper_push_mods);

    sr_rwlock_destroy(&session->notif_buf.lock);
    free(session);

    return err_info;
}

API int
sr_session_stop(sr_session_ctx_t *session)
{
    sr_error_info_t *err_info = NULL;
    int rc;

    if (!session) {
        return sr_api_ret(NULL, NULL);
    }

    /* stop all subscriptions of this session */
    if ((rc = sr_session_unsubscribe(session))) {
        return rc;
    }

    /* free the session itself */
    if ((err_info = _sr_session_stop(session))) {
        return sr_api_ret(NULL, err_info);
    }

    return sr_api_ret(NULL, NULL);
}

API int
sr_session_unsubscribe(sr_session_ctx_t *session)
{
    sr_error_info_t *err_info = NULL;

    if (!session) {
        return sr_api_ret(NULL, NULL);
    }

    while (session->subscription_count) {
        if ((err_info = sr_subscr_del_session(session->subscriptions[0], session, SR_LOCK_NONE))) {
            return sr_api_ret(NULL, err_info);
        }
    }

    return sr_api_ret(NULL, NULL);
}

API int
sr_session_notif_buffer(sr_session_ctx_t *session)
{
    sr_error_info_t *err_info = NULL;
    int r;

    if (!session || session->notif_buf.tid) {
        return sr_api_ret(NULL, NULL);
    }

    /* it could not be running */
    assert(!session->notif_buf.thread_running);
    session->notif_buf.thread_running = 1;

    /* start the buffering thread */
    if ((r = pthread_create(&session->notif_buf.tid, NULL, sr_notif_buf_thread, session))) {
        sr_errinfo_new(&err_info, SR_ERR_INTERNAL, "Creating a new thread failed (%s).", strerror(r));
        session->notif_buf.thread_running = 0;
        return sr_api_ret(session, err_info);
    }

    return sr_api_ret(NULL, NULL);
}

API int
sr_session_switch_ds(sr_session_ctx_t *session, sr_datastore_t ds)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session, session, err_info);

    session->ds = ds;
    return sr_api_ret(session, err_info);
}

API sr_datastore_t
sr_session_get_ds(sr_session_ctx_t *session)
{
    if (!session) {
        return 0;
    }

    return session->ds;
}

API int
sr_session_set_orig_name(sr_session_ctx_t *session, const char *orig_name)
{
    sr_error_info_t *err_info = NULL;
    char *new_orig_name;

    SR_CHECK_ARG_APIRET(!session, session, err_info);

    new_orig_name = orig_name ? strdup(orig_name) : NULL;
    if (!new_orig_name && orig_name) {
        SR_ERRINFO_MEM(&err_info);
        return sr_api_ret(session, err_info);
    }

    free(session->orig_name);
    session->orig_name = new_orig_name;

    return sr_api_ret(session, NULL);
}

API const char *
sr_session_get_orig_name(sr_session_ctx_t *session)
{
    if (!session || !session->ev) {
        return NULL;
    }

    return session->ev_data.orig_name ? session->ev_data.orig_name : "";
}

API int
sr_session_push_orig_data(sr_session_ctx_t *session, uint32_t size, const void *data)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session || !session->orig_name || !size || !data, session, err_info);

    err_info = sr_ev_data_push(&session->orig_data, size, data);
    return sr_api_ret(session, err_info);
}

API void
sr_session_del_orig_data(sr_session_ctx_t *session)
{
    if (!session) {
        return;
    }

    free(session->orig_data);
    session->orig_data = NULL;
}

API int
sr_session_get_orig_data(sr_session_ctx_t *session, uint32_t idx, uint32_t *size, const void **data)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session || !session->ev || !data, session, err_info);

    return sr_ev_data_get(session->ev_data.orig_data, idx, size, (void **)data);
}

API int
sr_session_get_error(sr_session_ctx_t *session, const sr_error_info_t **error_info)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session || !error_info, session, err_info);

    *error_info = session->err_info;

    /* do not modify session errors */
    return SR_ERR_OK;
}

API int
sr_session_dup_error(sr_session_ctx_t *src_session, sr_session_ctx_t *trg_session)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;

    SR_CHECK_ARG_APIRET(!src_session || !trg_session, NULL, err_info);

    if (!src_session->err_info) {
        /* no error info to duplicate */
        goto cleanup;
    }

    /* free any previous even error */
    sr_errinfo_free(&src_session->ev_err_info);

    /* duplicate all src errors */
    for (i = 0; i < src_session->err_info->err_count; ++i) {
        sr_errinfo_add(&trg_session->ev_err_info, src_session->err_info->err[i].err_code,
                src_session->err_info->err[i].error_format, src_session->err_info->err[i].error_data,
                src_session->err_info->err[i].message, NULL);
    }

cleanup:
    return sr_api_ret(trg_session, err_info);
}

API int
sr_session_set_error(sr_session_ctx_t *session, const char *err_format_name, sr_error_t err_code,
        const char *err_msg_format, ...)
{
    sr_error_info_t *err_info = NULL;
    va_list vargs;

    SR_CHECK_ARG_APIRET(!session || ((session->ev != SR_SUB_EV_CHANGE) && (session->ev != SR_SUB_EV_UPDATE) &&
            (session->ev != SR_SUB_EV_OPER) && (session->ev != SR_SUB_EV_RPC)) || !err_code || !err_msg_format,
            session, err_info);

    va_start(vargs, err_msg_format);
    sr_errinfo_add(&session->ev_err_info, err_code, err_format_name, NULL, err_msg_format, &vargs);
    va_end(vargs);

    return sr_api_ret(session, err_info);
}

API int
sr_session_set_error_message(sr_session_ctx_t *session, const char *format, ...)
{
    sr_error_info_t *err_info = NULL;
    va_list vargs;

    SR_CHECK_ARG_APIRET(!session || ((session->ev != SR_SUB_EV_CHANGE) && (session->ev != SR_SUB_EV_UPDATE) &&
            (session->ev != SR_SUB_EV_OPER) && (session->ev != SR_SUB_EV_RPC)) || !format, session, err_info);

    va_start(vargs, format);
    sr_errinfo_add(&session->ev_err_info, SR_ERR_OPERATION_FAILED, NULL, NULL, format, &vargs);
    va_end(vargs);

    return sr_api_ret(session, err_info);
}

API int
sr_session_set_error_format(sr_session_ctx_t *session, const char *error_format)
{
    sr_error_info_t *err_info = NULL;
    char *err_format;

    SR_CHECK_ARG_APIRET(!session || ((session->ev != SR_SUB_EV_CHANGE) && (session->ev != SR_SUB_EV_UPDATE) &&
            (session->ev != SR_SUB_EV_OPER) && (session->ev != SR_SUB_EV_RPC)) || !session->ev_err_info, session, err_info);

    if (error_format) {
        if (!(err_format = strdup(error_format))) {
            SR_ERRINFO_MEM(&err_info);
            return sr_api_ret(session, err_info);
        }
    } else {
        err_format = NULL;
    }

    free(session->ev_err_info->err[session->ev_err_info->err_count - 1].error_format);
    session->ev_err_info->err[session->ev_err_info->err_count - 1].error_format = err_format;

    return sr_api_ret(session, NULL);
}

API int
sr_session_push_error_data(sr_session_ctx_t *session, uint32_t size, const void *data)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session || ((session->ev != SR_SUB_EV_CHANGE) && (session->ev != SR_SUB_EV_UPDATE) &&
            (session->ev != SR_SUB_EV_OPER) && (session->ev != SR_SUB_EV_RPC)) || !session->ev_err_info ||
            !session->ev_err_info->err[session->ev_err_info->err_count - 1].error_format || !size || !data, session, err_info);

    err_info = sr_ev_data_push(&session->ev_err_info->err[session->ev_err_info->err_count - 1].error_data, size, data);
    return sr_api_ret(session, err_info);
}

API int
sr_get_error_data(const sr_error_info_err_t *err, uint32_t idx, uint32_t *size, const void **data)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!err || !data, NULL, err_info);

    return sr_ev_data_get(err->error_data, idx, size, (void **)data);
}

API uint32_t
sr_session_get_id(sr_session_ctx_t *session)
{
    if (!session) {
        return 0;
    }

    return session->sid;
}

API int
sr_session_set_user(sr_session_ctx_t *session, const char *user)
{
    sr_error_info_t *err_info = NULL;
    uid_t uid;

    SR_CHECK_ARG_APIRET(!session || !user, session, err_info);

    if (geteuid() != SR_SU_UID) {
        /* not the superuser */
        sr_errinfo_new(&err_info, SR_ERR_UNAUTHORIZED, "Superuser access required.");
        return sr_api_ret(session, err_info);
    }

    /* check that the user is valid */
    if ((err_info = sr_get_pwd(&uid, (char **)&user))) {
        return sr_api_ret(session, err_info);
    }

    /* replace the user */
    free(session->user);
    session->user = strdup(user);
    if (!session->user) {
        SR_ERRINFO_MEM(&err_info);
    }

    return sr_api_ret(session, err_info);
}

API const char *
sr_session_get_user(sr_session_ctx_t *session)
{
    if (!session) {
        return NULL;
    }

    return session->user;
}

API sr_conn_ctx_t *
sr_session_get_connection(sr_session_ctx_t *session)
{
    if (!session) {
        return NULL;
    }

    return session->conn;
}

API const char *
sr_get_repo_path(void)
{
    static char sr_repo_path[SR_PATH_MAX] = "";
    const char *value;

    if (sr_repo_path[0]) {
        return sr_repo_path;
    }

    /* env var */
    value = getenv(SR_REPO_PATH_ENV);
    if (value && (strlen(value) >= SR_PATH_MAX)) {
        SR_LOG_WRN(SR_REPO_PATH_ENV " \"%s\" canot be used, longer than %u characters.", value, SR_PATH_MAX);
        value = NULL;
    }

    /* compile var */
    if (!value) {
        value = SR_REPO_PATH;
        if (strlen(SR_REPO_PATH) >= SR_PATH_MAX) {
            SR_LOG_WRN("Repository path \"%s\" cannot be used, longer than %u characters.", value, SR_PATH_MAX);
            value = NULL;
        }
    }

    /* hard default */
    if (!value) {
        value = "/etc/sysrepo";
    }

    /* cache the value for the process */
    snprintf(sr_repo_path, SR_PATH_MAX, "%s", value);
    return sr_repo_path;
}

API const char *
sr_get_shm_path(void)
{
    static char sr_shm_dir_str[SR_PATH_MAX] = "";
    const char *value;

    if (sr_shm_dir_str[0]) {
        return sr_shm_dir_str;
    }

    /* env var */
    value = getenv(SR_SHM_PATH_ENV);
    if (value && (strlen(value) >= SR_PATH_MAX)) {
        SR_LOG_WRN(SR_SHM_PATH_ENV " \"%s\" cannot be used, longer than %u characters.", value, SR_PATH_MAX);
        value = NULL;
    }

    /* compile var */
    if (!value) {
        value = SR_SHM_PATH;
        if (strlen(value) >= SR_PATH_MAX) {
            SR_LOG_WRN("SHM path \"%s\" cannot be used, longer than %u characters.", value, SR_PATH_MAX);
            value = NULL;
        }
    }

    /* hard default */
    if (!value) {
        value = "/dev/shm";
    }

    /* cache the value for the process */
    snprintf(sr_shm_dir_str, SR_PATH_MAX, "%s", value);
    return sr_shm_dir_str;
}

API const char *
sr_get_shm_prefix(void)
{
    static char sr_shm_prefix_val[SR_PATH_MAX] = "";
    const char *value;

    if (sr_shm_prefix_val[0]) {
        return sr_shm_prefix_val;
    }

    /* env var */
    value = getenv(SR_SHM_PREFIX_ENV);
    if (value && (strlen(value) >= SR_PATH_MAX)) {
        SR_LOG_WRN(SR_SHM_PREFIX_ENV " \"%s\" cannot be used, longer than %u characters.", value, SR_PATH_MAX);
        value = NULL;
    }

    /* slashes check */
    if (value && strchr(value, '/')) {
        SR_LOG_WRN(SR_SHM_PREFIX_ENV " \"%s\" cannot be used, contains slashes.", value);
        value = NULL;
    }

    /* hard default */
    if (!value) {
        value = SR_SHM_PREFIX_DEFAULT;
    }

    /* cache the value for the process */
    snprintf(sr_shm_prefix_val, SR_PATH_MAX, "%s", value);
    return sr_shm_prefix_val;
}

/**
 * @brief Set all search dirs for a context.
 *
 * @param[in] new_ctx New context to modify.
 * @param[in] search_dirs String with all search dirs.
 * @param[out] search_dir_count Count of added search dirs.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_install_module_set_searchdirs(struct ly_ctx *new_ctx, const char *search_dirs, uint32_t *search_dir_count)
{
    sr_error_info_t *err_info = NULL;
    char *sdirs_str = NULL, *ptr, *ptr2 = NULL;

    *search_dir_count = 0;

    if (!search_dirs) {
        goto cleanup;
    }

    sdirs_str = strdup(search_dirs);
    SR_CHECK_MEM_GOTO(!sdirs_str, err_info, cleanup);

    /* add each search dir */
    for (ptr = strtok_r(sdirs_str, ":", &ptr2); ptr; ptr = strtok_r(NULL, ":", &ptr2)) {
        if (!ly_ctx_set_searchdir(new_ctx, ptr)) {
            /* added (it was not already there) */
            ++(*search_dir_count);
        }
    }

cleanup:
    free(sdirs_str);
    return err_info;
}

/**
 * @brief Check whether enabled features of a module match those specified.
 *
 * @param[in,out] new_mod New module to update.
 * @param[out] no_changes Set if all @p new_mod features are enabled.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_install_modules_check_features(sr_int_install_mod_t *new_mod, int *no_changes)
{
    sr_error_info_t *err_info = NULL;
    const struct lysp_feature *f = NULL;
    uint32_t i = 0, j, nm_feat_count = 0, en_feat_count = 0;
    const char *feature, **enabled_features = NULL;

    assert(!new_mod->enable_features);

    *no_changes = 1;

    if (!new_mod->features || !new_mod->features[0]) {
        /* no features to check/enable */
        goto cleanup;
    }

    if (strcmp(new_mod->features[0], "*")) {
        /* check feature existence */
        for (j = 0; new_mod->features[j]; ++j) {
            if (lys_feature_value(new_mod->ly_mod, new_mod->features[j]) == LY_ENOTFOUND) {
                sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Feature \"%s\" was not found in module \"%s\".",
                        new_mod->features[j], new_mod->ly_mod->name);
                goto cleanup;
            }
        }
    }

    /* check that all (selected) features are enabled */
    while ((f = lysp_feature_next(f, new_mod->ly_mod->parsed, &i))) {
        feature = NULL;
        for (j = 0; new_mod->features[j]; ++j) {
            if (!strcmp(f->name, new_mod->features[j])) {
                feature = new_mod->features[j];
                break;
            }
        }

        if ((f->flags & LYS_FENABLED) || feature) {
            /* enabled feature or a disabled one to be enabled */
            enabled_features = sr_realloc(enabled_features, (en_feat_count + 2) * sizeof *enabled_features);
            SR_CHECK_MEM_GOTO(!enabled_features, err_info, cleanup);
            enabled_features[en_feat_count] = feature;
            ++en_feat_count;
            enabled_features[en_feat_count] = NULL;
        }

        if (!(f->flags & LYS_FENABLED) && feature) {
            /* disabled feature to enable */
            new_mod->enable_features = sr_realloc(new_mod->enable_features, (nm_feat_count + 2) * sizeof *new_mod->enable_features);
            SR_CHECK_MEM_GOTO(!new_mod->enable_features, err_info, cleanup);
            new_mod->enable_features[nm_feat_count] = feature;
            ++nm_feat_count;
            new_mod->enable_features[nm_feat_count] = NULL;
        }
    }

    if (new_mod->enable_features) {
        /* features to enable */
        *no_changes = 0;

        /* use enabled_features with all the previously enabled and newly enabled features */
        if ((err_info = sr_lys_set_implemented((struct lys_module *)new_mod->ly_mod, enabled_features))) {
            goto cleanup;
        }
    }

cleanup:
    free(enabled_features);
    return err_info;
}

/**
 * @brief Prepare members of a new module to be installed.
 *
 * @param[in] new_ctx New context to use for parsing.
 * @param[in] conn Connection to use.
 * @param[in,out] new_mod New module to update.
 * @param[out] no_changes Set if the module is installed with the selected features enabled so no context changes needed.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_install_modules_prepare_mod(struct ly_ctx *new_ctx, sr_conn_ctx_t *conn, sr_int_install_mod_t *new_mod, int *no_changes)
{
    sr_error_info_t *err_info = NULL;
    const sr_module_ds_t sr_empty_module_ds = {0};
    sr_datastore_t ds;
    int mod_ds;

    *no_changes = 0;

    if (new_mod->ly_mod) {
        /* module already installed, check whether with all the features */
        err_info = sr_install_modules_check_features(new_mod, no_changes);
        goto cleanup;
    }

    if (!memcmp(&new_mod->module_ds, &sr_empty_module_ds, sizeof sr_empty_module_ds)) {
        /* use default plugins if none are set */
        for (mod_ds = 0; mod_ds < SR_MOD_DS_PLUGIN_COUNT; ++mod_ds) {
            new_mod->module_ds.plugin_name[mod_ds] = sr_module_ds_default.plugin_name[mod_ds];
        }
    } else {
        /* check plugin existence */
        for (ds = 0; ds < SR_DS_READ_COUNT; ++ds) {
            if ((ds == SR_DS_RUNNING) && !new_mod->module_ds.plugin_name[ds]) {
                /* disabled 'running' datastore, effectively mirroring 'startup' */
                continue;
            }

            if ((err_info = sr_ds_handle_find(new_mod->module_ds.plugin_name[ds], conn, NULL))) {
                goto cleanup;
            }
        }
        if ((err_info = sr_ntf_handle_find(new_mod->module_ds.plugin_name[SR_MOD_DS_NOTIF], conn, NULL))) {
            goto cleanup;
        }
    }

    /* parse the module with the features */
    if (new_mod->is_schema_yang) {
        if ((err_info = sr_lys_parse(new_ctx, new_mod->schema_yang, NULL, new_mod->format, new_mod->features,
                (struct lys_module **)&new_mod->ly_mod))) {
            goto cleanup;
        }
    } else {
        if ((err_info = sr_lys_parse(new_ctx, NULL, new_mod->schema_path, new_mod->format, new_mod->features,
                (struct lys_module **)&new_mod->ly_mod))) {
            goto cleanup;
        }
    }

    if (!new_mod->perm) {
        /* use default permissions */
        new_mod->perm = sr_module_default_mode(new_mod->ly_mod);
    } else {
        if (new_mod->perm & SR_UMASK) {
            SR_LOG_WRN("Ignoring permission bits %03o forbidden by Sysrepo umask.", (unsigned int)new_mod->perm & SR_UMASK);
            new_mod->perm &= ~SR_UMASK;
        }

        /* ignore execute bits */
        new_mod->perm &= 00666;
    }

    if (!new_mod->group && strlen(SR_GROUP)) {
        /* use default group */
        new_mod->group = SR_GROUP;
    }

cleanup:
    return err_info;
}

/**
 * @brief Install new modules described by an array of module info.
 *
 * @param[in] conn Connection to use.
 * @param[in] search_dirs String with search directories to use.
 * @param[in] data Optional initial module data as a string, do not set if @p data_path is set.
 * @param[in] data_path Optional initial module data as a file path, do not set if @p data is set.
 * @param[in] format YANG data format of @p data or @p data_path.
 * @param[in,out] new_mods Array of new modules to install, implemented dependencies are added, installed modules removed.
 * @param[in,out] new_mod_count Count of @p new_mods.
 * @return SR_ERR value.
 */
static int
_sr_install_modules(sr_conn_ctx_t *conn, const char *search_dirs, const char *data, const char *data_path,
        LYD_FORMAT format, sr_int_install_mod_t **new_mods, uint32_t *new_mod_count)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    struct ly_ctx *new_ctx = NULL, *old_ctx = NULL;
    ly_module_imp_clb imp_clb;
    void *imp_clb_data;
    struct lyd_node *mod_data = NULL, *sr_mods = NULL, *sr_del_mods = NULL;
    sr_int_install_mod_t *nmod;
    struct sr_data_update_s data_info = {0};
    sr_lock_mode_t ctx_mode = SR_LOCK_NONE;
    uint32_t i, j, search_dir_count = 0;
    int no_changes, mod_shm_changed = 0;
    struct ly_set mod_set = {0}, feat_set = {0};
    char *mod_name = NULL;

    /* create new temporary context */
    if ((err_info = sr_ly_ctx_init(conn, &new_ctx))) {
        goto cleanup;
    }

    /* use temporary context to load current modules */
    if ((err_info = sr_shmmod_ctx_load_modules(SR_CONN_MOD_SHM(conn), new_ctx, NULL))) {
        goto cleanup;
    }

    /* set search dirs */
    if ((err_info = sr_install_module_set_searchdirs(new_ctx, search_dirs, &search_dir_count))) {
        goto cleanup;
    }

    /* set import callback */
    imp_clb = ly_ctx_get_module_imp_clb(conn->ly_ctx, &imp_clb_data);
    ly_ctx_set_module_imp_clb(new_ctx, imp_clb, imp_clb_data);

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(conn, SR_LOCK_READ_UPGR, 1, __func__))) {
        goto cleanup;
    }
    ctx_mode = SR_LOCK_READ_UPGR;

    for (i = 0; i < *new_mod_count; ++i) {
        nmod = &(*new_mods)[i];

        /* learn module name and format */
        if ((err_info = sr_get_schema_name_format(nmod->schema_path, nmod->is_schema_yang, &mod_name, &nmod->format))) {
            goto cleanup;
        }

        /* try to find the module (before any are parsed to not get new modules) */
        nmod->ly_mod = ly_ctx_get_module_implemented(new_ctx, mod_name);

        free(mod_name);
        mod_name = NULL;
    }

    i = 0;
    while (i < *new_mod_count) {
        nmod = &(*new_mods)[i];

        /* process every new module and check/fill its info */
        if ((err_info = sr_install_modules_prepare_mod(new_ctx, conn, nmod, &no_changes))) {
            goto cleanup;
        }
        if (no_changes) {
            /* module already installed with the features, remove it from the array */
            if (i < (*new_mod_count) - 1) {
                memmove(nmod, nmod + 1, (*new_mod_count - i - 1) * sizeof *nmod);
            }
            if (!--(*new_mod_count)) {
                /* no modules left to install */
                free(*new_mods);
                *new_mods = NULL;
                goto cleanup;
            }
            continue;
        }

        ++i;
    }

    /* compile the final context */
    if ((err_info = sr_ly_ctx_compile(new_ctx))) {
        goto cleanup;
    }

    /* remove added search dirs */
    ly_ctx_unset_searchdir_last(new_ctx, search_dir_count);

    /* parse modules data, if any */
    if ((err_info = sr_lyd_parse_data(new_ctx, data, data_path, format, LYD_PARSE_ONLY | LYD_PARSE_STRICT, 0, &mod_data))) {
        goto cleanup;
    }

    /* check the new context can be used */
    if ((err_info = sr_lycc_check_add_modules(conn, new_ctx))) {
        goto cleanup;
    }

    /* CONTEXT UPGRADE */
    if ((err_info = sr_lycc_relock(conn, SR_LOCK_WRITE, __func__))) {
        goto cleanup;
    }
    ctx_mode = SR_LOCK_WRITE;

    /* update lydmods data */
    if ((err_info = sr_lydmods_change_add_modules(new_ctx, conn, new_mods, new_mod_count, &sr_mods))) {
        goto cleanup;
    }

    /* load all data and prepare their update, initial data are spent */
    err_info = sr_lycc_update_data(conn, new_ctx, mod_data, *new_mods, *new_mod_count, &data_info);
    mod_data = NULL;
    if (err_info) {
        goto error;
    }

    /* update SHM modules */
    if ((err_info = sr_shmmod_store_modules(&conn->mod_shm, sr_mods))) {
        goto error;
    }
    mod_shm_changed = 1;

    /* finish adding the modules */
    if ((err_info = sr_lycc_add_modules(conn, *new_mods, *new_mod_count))) {
        goto error;
    }

    /* store new data if they differ */
    if ((err_info = sr_lycc_store_data_if_differ(conn, new_ctx, sr_mods, &data_info))) {
        goto error;
    }

    /* update content ID and safely switch the context */
    SR_CONN_MAIN_SHM(conn)->content_id = ly_ctx_get_modules_hash(new_ctx);
    sr_conn_ctx_switch(conn, &new_ctx, &old_ctx);

    /* send the notification */
    sr_generate_notif_module_change_installed(conn, *new_mods, *new_mod_count);

    goto cleanup;

error:
    /* revert lydmods data */
    lyd_free_siblings(sr_mods);
    for (i = 0; i < *new_mod_count; ++i) {
        if ((*new_mods)[i].enable_features) {
            feat_set.objs = (void **)(*new_mods)[i].enable_features;
            for (j = 0; (*new_mods)[i].enable_features[j]; ++j) {}
            feat_set.count = j;

            if ((tmp_err = sr_lydmods_change_chng_feature(conn->ly_ctx, (*new_mods)[i].ly_mod, new_ctx, &feat_set,
                    0, conn, &sr_mods))) {
                sr_errinfo_merge(&err_info, tmp_err);
            }
            lyd_free_siblings(sr_mods);
        } else {
            ly_set_add(&mod_set, (*new_mods)[i].ly_mod, 1, NULL);
        }
    }
    if ((tmp_err = sr_lydmods_change_del_module(conn->ly_ctx, new_ctx, &mod_set, conn, &sr_del_mods, &sr_mods))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }
    ly_set_erase(&mod_set, NULL);
    lyd_free_siblings(sr_del_mods);

    /* revert SHM module changes */
    if (mod_shm_changed && (tmp_err = sr_shmmod_store_modules(&conn->mod_shm, sr_mods))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }

cleanup:
    /* revert adding the modules */
    if (err_info && (tmp_err = sr_lycc_add_modules_revert(conn, *new_mods, *new_mod_count))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }

    sr_lycc_update_data_clear(&data_info);
    lyd_free_siblings(mod_data);
    lyd_free_siblings(sr_mods);
    ly_ctx_destroy(old_ctx);
    ly_ctx_destroy(new_ctx);
    free(mod_name);

    /* CONTEXT UNLOCK */
    sr_lycc_unlock(conn, ctx_mode, 1, __func__);

    return sr_api_ret(NULL, err_info);
}

/**
 * @brief Free internal install_module modules.
 *
 * @param[in] new_mods Module array to free.
 * @param[in] new_mod_count Count of @p new_mods.
 */
static void
sr_free_int_install_mods(sr_int_install_mod_t *new_mods, uint32_t new_mod_count)
{
    uint32_t i;

    if (!new_mods || !new_mod_count) {
        return;
    }

    for (i = 0; i < new_mod_count; ++i) {
        free(new_mods[i].enable_features);
    }
    free(new_mods);
}

API int
sr_install_module(sr_conn_ctx_t *conn, const char *schema_path, const char *search_dirs, const char **features)
{
    return sr_install_module2(conn, schema_path, search_dirs, features, NULL, NULL, NULL, 0, NULL, NULL, 0);
}

API const sr_module_ds_t *
sr_get_module_ds_default(void)
{
    return &sr_module_ds_default;
}

API int
sr_install_module2(sr_conn_ctx_t *conn, const char *schema_path, const char *search_dirs, const char **features,
        const sr_module_ds_t *module_ds, const char *owner, const char *group, mode_t perm, const char *data,
        const char *data_path, LYD_FORMAT format)
{
    sr_error_info_t *err_info = NULL;
    sr_int_install_mod_t *new_mod;
    uint32_t new_mod_count;
    int rc;

    SR_CHECK_ARG_APIRET(!conn || !schema_path || (data && data_path), NULL, err_info);

    new_mod = calloc(1, sizeof *new_mod);
    if (!new_mod) {
        SR_ERRINFO_MEM(&err_info);
        return sr_api_ret(NULL, err_info);
    }
    new_mod_count = 1;

    new_mod->schema_path = schema_path;
    new_mod->features = features;
    if (module_ds) {
        new_mod->module_ds = *module_ds;
    }
    new_mod->owner = owner;
    new_mod->group = group;
    new_mod->perm = perm;

    rc = _sr_install_modules(conn, search_dirs, data, data_path, format, &new_mod, &new_mod_count);
    sr_free_int_install_mods(new_mod, new_mod_count);
    return rc;
}

API int
sr_install_modules(sr_conn_ctx_t *conn, const char **schema_paths, const char *search_dirs,
        const char ***features)
{
    sr_error_info_t *err_info = NULL;
    sr_int_install_mod_t *new_mods = NULL;
    uint32_t i, new_mod_count;
    int rc = SR_ERR_OK;

    SR_CHECK_ARG_APIRET(!conn || !schema_paths, NULL, err_info);

    /* learn count */
    for (new_mod_count = 0; schema_paths[new_mod_count]; ++new_mod_count) {}

    /* alloc */
    new_mods = calloc(new_mod_count, sizeof *new_mods);
    SR_CHECK_MEM_GOTO(!new_mods, err_info, cleanup);

    /* fill all the items */
    for (i = 0; i < new_mod_count; ++i) {
        new_mods[i].schema_path = schema_paths[i];
        new_mods[i].features = features ? features[i] : NULL;
    }

    /* install */
    rc = _sr_install_modules(conn, search_dirs, NULL, NULL, 0, &new_mods, &new_mod_count);

cleanup:
    sr_free_int_install_mods(new_mods, new_mod_count);
    if (err_info) {
        return sr_api_ret(NULL, err_info);
    } else {
        return rc;
    }
}

API int
sr_install_modules2(sr_conn_ctx_t *conn, const sr_install_mod_t *modules, uint32_t module_count,
        const char *search_dirs, const char *data, const char *data_path, LYD_FORMAT format)
{
    sr_error_info_t *err_info = NULL;
    sr_int_install_mod_t *new_mods = NULL;
    uint32_t i, new_mod_count = 0;
    int rc = SR_ERR_OK;

    SR_CHECK_ARG_APIRET(!conn || !modules || !module_count, NULL, err_info);

    /* alloc */
    new_mods = calloc(module_count, sizeof *new_mods);
    SR_CHECK_MEM_GOTO(!new_mods, err_info, cleanup);
    new_mod_count = module_count;

    /* copy all the items */
    for (i = 0; i < module_count; ++i) {
        memcpy(&new_mods[i], &modules[i], sizeof *modules);

        /* detect schema format */
        if (strchr(modules[i].schema_yang, '{')) {
            new_mods[i].is_schema_yang = 1;
        }
    }

    /* install */
    rc = _sr_install_modules(conn, search_dirs, data, data_path, format, &new_mods, &new_mod_count);

cleanup:
    sr_free_int_install_mods(new_mods, new_mod_count);
    if (err_info) {
        return sr_api_ret(NULL, err_info);
    } else {
        return rc;
    }
}

API int
sr_remove_module(sr_conn_ctx_t *conn, const char *module_name, int force)
{
    const char *module_names[] = {
        module_name,
        NULL
    };

    return sr_remove_modules(conn, module_names, force);
}

API int
sr_update_module(sr_conn_ctx_t *conn, const char *schema_path, const char *search_dirs)
{
    const char *schema_paths[] = {
        schema_path,
        NULL
    };

    return sr_update_modules(conn, schema_paths, search_dirs);
}

API int
sr_remove_modules(sr_conn_ctx_t *conn, const char **module_names, int force)
{
    sr_error_info_t *err_info = NULL;
    struct ly_ctx *new_ctx = NULL, *old_ctx = NULL;
    struct ly_set mod_set = {0};
    struct lyd_node *sr_mods = NULL, *sr_del_mods = NULL;
    struct sr_data_update_s data_info = {0};
    const struct lys_module *ly_mod;
    sr_lock_mode_t ctx_mode = SR_LOCK_NONE;
    uint32_t i, mod_state = 0;

    SR_CHECK_ARG_APIRET(!conn || !module_names, NULL, err_info);

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(conn, SR_LOCK_READ_UPGR, 1, __func__))) {
        goto cleanup;
    }
    ctx_mode = SR_LOCK_READ_UPGR;

    for (i = 0; module_names[i]; ++i) {
        /* try to find the modules */
        ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, module_names[i]);
        if (!ly_mod) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_names[i]);
            goto cleanup;
        }
        if (sr_is_module_internal(ly_mod)) {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Internal module \"%s\" cannot be uninstalled.", module_names[i]);
            goto cleanup;
        }

        if (force) {
            /* collect all the removed modules for this module to be deleted */
            if ((err_info = sr_collect_module_impl_deps(ly_mod, conn, &mod_set))) {
                goto cleanup;
            }
        } else {
            /* add only this module to the removed mod set */
            if (ly_set_add(&mod_set, (void *)ly_mod, 1, NULL)) {
                SR_ERRINFO_MEM(&err_info);
                goto cleanup;
            }
        }

        /* check write permission */
        if ((err_info = sr_perm_check(conn, ly_mod, SR_DS_STARTUP, 1, NULL))) {
            goto cleanup;
        }
    }

    /* create new temporary context */
    if ((err_info = sr_ly_ctx_init(conn, &new_ctx))) {
        goto cleanup;
    }

    /* use temporary context to load modules without the removed ones */
    if ((err_info = sr_shmmod_ctx_load_modules(SR_CONN_MOD_SHM(conn), new_ctx, &mod_set))) {
        goto cleanup;
    }

    /* check the new context can be used */
    if ((err_info = sr_lycc_check_del_module(conn, new_ctx, &mod_set))) {
        goto cleanup;
    }

    /* delete operational data of the modules that will be deleted */
    for (i = 0; i < mod_set.count; ++i) {
        if ((err_info = sr_shmmod_del_module_oper_data(conn, mod_set.objs[i], &mod_state, NULL, 0))) {
            goto cleanup;
        }
    }

    /* CONTEXT UPGRADE */
    if ((err_info = sr_lycc_relock(conn, SR_LOCK_WRITE, __func__))) {
        goto cleanup;
    }
    ctx_mode = SR_LOCK_WRITE;

    /* load all data and prepare their update */
    if ((err_info = sr_lycc_update_data(conn, new_ctx, NULL, NULL, 0, &data_info))) {
        goto cleanup;
    }

    /* update lydmods data */
    if ((err_info = sr_lydmods_change_del_module(conn->ly_ctx, new_ctx, &mod_set, conn, &sr_del_mods, &sr_mods))) {
        goto cleanup;
    }

    /* update SHM modules */
    if ((err_info = sr_shmmod_store_modules(&conn->mod_shm, sr_mods))) {
        goto cleanup;
    }

    /* finish removing the modules */
    if ((err_info = sr_lycc_del_module(conn, new_ctx, &mod_set, sr_del_mods))) {
        goto cleanup;
    }

    /* store new data if they differ */
    if ((err_info = sr_lycc_store_data_if_differ(conn, new_ctx, sr_mods, &data_info))) {
        goto cleanup;
    }

    /* update content ID and safely switch the context */
    SR_CONN_MAIN_SHM(conn)->content_id = ly_ctx_get_modules_hash(new_ctx);
    sr_conn_ctx_switch(conn, &new_ctx, &old_ctx);

    /* send the notification */
    sr_generate_notif_module_change_uninstalled(conn, &mod_set);

cleanup:
    sr_lycc_update_data_clear(&data_info);
    lyd_free_siblings(sr_mods);
    lyd_free_siblings(sr_del_mods);
    ly_ctx_destroy(old_ctx);
    ly_ctx_destroy(new_ctx);

    /* CONTEXT UNLOCK */
    sr_lycc_unlock(conn, ctx_mode, 1, __func__);

    ly_set_erase(&mod_set, NULL);
    return sr_api_ret(NULL, err_info);
}

/**
 * @brief Import module data free libyang callback.
 */
static void
sr_ly_update_module_imp_data_free_cb(void *module_data, void *UNUSED(user_data))
{
    free(module_data);
}

/**
 * @brief Import module libyang callback.
 */
static LY_ERR
sr_ly_update_module_imp_cb(const char *mod_name, const char *mod_rev, const char *submod_name, const char *UNUSED(submod_rev),
        void *user_data, LYS_INFORMAT *format, const char **module_data, ly_module_imp_data_free_clb *free_module_data)
{
    sr_error_info_t *err_info = NULL;
    sr_int_update_mod_t *upd_mods = user_data, *upd_mod = NULL;
    uint32_t i;

    for (i = 0; upd_mods[i].name; ++i) {
        if (!strcmp(mod_name, upd_mods[i].name) && !mod_rev && !submod_name) {
            /* found in the specific revision */
            upd_mod = &upd_mods[i];
            break;
        }
    }
    if (!upd_mod) {
        /* not found */
        return LY_ENOTFOUND;
    }

    /* read schema file contents */
    if ((err_info = sr_file_read(upd_mod->schema_path, (char **)module_data))) {
        sr_errinfo_free(&err_info);
        return LY_ESYS;
    }

    *format = upd_mod->format;
    *free_module_data = sr_ly_update_module_imp_data_free_cb;
    return LY_SUCCESS;
}

/**
 * @brief Prepare modules to be updated and load them into the new context.
 *
 * @param[in] new_ctx New context to use for parsing.
 * @param[in] conn Connection to use.
 * @param[in] schema_paths Array of schema paths to the updated modules.
 * @param[in,out] old_mod_set Set to add old (current) modules into, only the updated ones.
 * @param[in,out] upd_mod_set Set to add updated modules into.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_update_modules_prepare(struct ly_ctx *new_ctx, sr_conn_ctx_t *conn, const char **schema_paths,
        struct ly_set *old_mod_set, struct ly_set *upd_mod_set)
{
    sr_error_info_t *err_info = NULL;
    sr_int_update_mod_t *upd_mods = NULL;
    const struct lys_module *old_mod, *upd_mod;
    const char **features = NULL, *no_features[] = {NULL};
    struct lysp_feature *f = NULL;
    uint32_t i, j, schema_path_count = 0, feat_count = 0;

    /* get schema path count */
    for (i = 0; schema_paths[i]; ++i) {
        ++schema_path_count;
    }

    /* alloc import CB data */
    upd_mods = calloc(schema_path_count + 1, sizeof *upd_mods);
    SR_CHECK_MEM_GOTO(!upd_mods, err_info, cleanup);

    for (i = 0; i < schema_path_count; ++i) {
        /* learn about the module */
        upd_mods[i].schema_path = schema_paths[i];
        if ((err_info = sr_get_schema_name_format(upd_mods[i].schema_path, 0, &upd_mods[i].name, &upd_mods[i].format))) {
            goto cleanup;
        }

        /* try to find this module */
        old_mod = ly_ctx_get_module_implemented(conn->ly_ctx, upd_mods[i].name);
        if (!old_mod) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", upd_mods[i].name);
            goto cleanup;
        }

        /* check write permission */
        if ((err_info = sr_perm_check(conn, old_mod, SR_DS_STARTUP, 1, NULL))) {
            goto cleanup;
        }

        /* old module */
        if (ly_set_add(old_mod_set, (void *)old_mod, 1, NULL)) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }
    }

    /* set import callback in case a module would try to import this module to be updated, to not load the old revision */
    ly_ctx_set_module_imp_clb(new_ctx, sr_ly_update_module_imp_cb, upd_mods);

    /* load non-updated modules into the context */
    if ((err_info = sr_shmmod_ctx_load_modules(SR_CONN_MOD_SHM(conn), new_ctx, old_mod_set))) {
        goto cleanup;
    }
    ly_ctx_set_module_imp_clb(new_ctx, NULL, NULL);

    for (i = 0; i < schema_path_count; ++i) {
        old_mod = old_mod_set->objs[i];

        /* collect current enabled features */
        j = 0;
        while ((f = lysp_feature_next(f, old_mod->parsed, &j))) {
            if (f->flags & LYS_FENABLED) {
                features = sr_realloc(features, (feat_count + 2) * sizeof *features);
                SR_CHECK_MEM_GOTO(!features, err_info, cleanup);
                features[feat_count] = f->name;
                features[feat_count + 1] = NULL;
                ++feat_count;
            }
        }

        /* try to parse the updated module, if already an import, at least implement it and set the features */
        if ((err_info = sr_lys_parse(new_ctx, NULL, upd_mods[i].schema_path, upd_mods[i].format,
                features ? features : no_features, (struct lys_module **)&upd_mod))) {
            goto cleanup;
        }

        /* updated module */
        if (ly_set_add(upd_mod_set, (void *)upd_mod, 1, NULL)) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }

        free(features);
        features = NULL;
        feat_count = 0;
    }

cleanup:
    for (i = 0; i < schema_path_count; ++i) {
        free(upd_mods[i].name);
    }
    free(upd_mods);
    free(features);
    return err_info;
}

API int
sr_update_modules(sr_conn_ctx_t *conn, const char **schema_paths, const char *search_dirs)
{
    sr_error_info_t *err_info = NULL;
    struct ly_ctx *new_ctx = NULL, *old_ctx = NULL;
    struct ly_set old_mod_set = {0}, upd_mod_set = {0};
    struct lyd_node *sr_mods = NULL;
    struct sr_data_update_s data_info = {0};
    sr_lock_mode_t ctx_mode = SR_LOCK_NONE;
    uint32_t search_dir_count = 0;

    SR_CHECK_ARG_APIRET(!conn || !schema_paths, NULL, err_info);

    /* create new temporary context */
    if ((err_info = sr_ly_ctx_init(conn, &new_ctx))) {
        goto cleanup;
    }

    /* set search dirs */
    if ((err_info = sr_install_module_set_searchdirs(new_ctx, search_dirs, &search_dir_count))) {
        goto cleanup;
    }

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(conn, SR_LOCK_READ_UPGR, 1, __func__))) {
        goto cleanup;
    }
    ctx_mode = SR_LOCK_READ_UPGR;

    /* process every updated module and parse it */
    if ((err_info = sr_update_modules_prepare(new_ctx, conn, schema_paths, &old_mod_set, &upd_mod_set))) {
        goto cleanup;
    }

    /* compile the final context */
    if ((err_info = sr_ly_ctx_compile(new_ctx))) {
        goto cleanup;
    }

    /* remove added search dirs */
    ly_ctx_unset_searchdir_last(new_ctx, search_dir_count);

    /* check the new context can be used */
    if ((err_info = sr_lycc_check_upd_modules(conn, &old_mod_set, &upd_mod_set))) {
        goto cleanup;
    }

    /* CONTEXT UPGRADE */
    if ((err_info = sr_lycc_relock(conn, SR_LOCK_WRITE, __func__))) {
        goto cleanup;
    }
    ctx_mode = SR_LOCK_WRITE;

    /* load all data and prepare their update */
    if ((err_info = sr_lycc_update_data(conn, new_ctx, NULL, NULL, 0, &data_info))) {
        goto cleanup;
    }

    /* update lydmods data */
    if ((err_info = sr_lydmods_change_upd_modules(conn->ly_ctx, &upd_mod_set, conn, &sr_mods))) {
        goto cleanup;
    }

    /* update SHM modules */
    if ((err_info = sr_shmmod_store_modules(&conn->mod_shm, sr_mods))) {
        goto cleanup;
    }

    /* finish updating the modules */
    if ((err_info = sr_lycc_upd_modules(&old_mod_set, &upd_mod_set))) {
        goto cleanup;
    }

    /* store new data if they differ */
    if ((err_info = sr_lycc_store_data_if_differ(conn, new_ctx, sr_mods, &data_info))) {
        goto cleanup;
    }

    /* update content ID and safely switch the context */
    SR_CONN_MAIN_SHM(conn)->content_id = ly_ctx_get_modules_hash(new_ctx);
    sr_conn_ctx_switch(conn, &new_ctx, &old_ctx);

    /* send the notification */
    sr_generate_notif_module_change_updated(conn, &old_mod_set, &upd_mod_set);

cleanup:
    sr_lycc_update_data_clear(&data_info);
    lyd_free_siblings(sr_mods);
    ly_ctx_destroy(old_ctx);
    ly_ctx_destroy(new_ctx);

    /* CONTEXT UNLOCK */
    sr_lycc_unlock(conn, ctx_mode, 1, __func__);

    ly_set_erase(&old_mod_set, NULL);
    ly_set_erase(&upd_mod_set, NULL);
    return sr_api_ret(NULL, err_info);
}

API int
sr_set_module_replay_support(sr_conn_ctx_t *conn, const char *module_name, int enable)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod = NULL;
    struct lyd_node *sr_mods = NULL;
    struct ly_set mod_set = {0};

    SR_CHECK_ARG_APIRET(!conn, NULL, err_info);

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(conn, SR_LOCK_READ, 1, __func__))) {
        return sr_api_ret(NULL, err_info);
    }

    if (module_name) {
        /* try to find this module */
        ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, module_name);
        if (!ly_mod) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
            goto cleanup;
        }
    }

    /* update lydmods data */
    if ((err_info = sr_lydmods_change_chng_replay_support(ly_mod, enable, &mod_set, conn, &sr_mods))) {
        goto cleanup;
    }

    /* update mod SHM module replay support */
    if ((err_info = sr_shmmod_update_replay_support(SR_CONN_MOD_SHM(conn), &mod_set, enable))) {
        goto cleanup;
    }

    /* finish changing replay support */
    if ((err_info = sr_lycc_set_replay_support(conn, &mod_set, enable, sr_mods))) {
        goto cleanup;
    }

cleanup:
    lyd_free_siblings(sr_mods);

    /* CONTEXT UNLOCK */
    sr_lycc_unlock(conn, SR_LOCK_READ, 1, __func__);

    ly_set_erase(&mod_set, NULL);
    return sr_api_ret(NULL, err_info);
}

API int
sr_get_module_replay_support(sr_conn_ctx_t *conn, const char *module_name, struct timespec *earliest_notif, int *enabled)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    const struct lys_module *ly_mod;
    const struct sr_ntf_handle_s *ntf_handle;

    SR_CHECK_ARG_APIRET(!conn || !module_name || !enabled, NULL, err_info);

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(NULL, err_info);
    }

    /* try to find this module */
    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(conn), module_name);
    if (!shm_mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
        goto cleanup;
    }

    /* read replay support */
    *enabled = shm_mod->replay_supp;

    if (earliest_notif) {
        /* find LY module */
        ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, module_name);
        assert(ly_mod);

        /* find NTF plugin handle */
        if ((err_info = sr_ntf_handle_find(conn->mod_shm.addr + shm_mod->plugins[SR_MOD_DS_NOTIF], conn, &ntf_handle))) {
            goto cleanup;
        }

        /* get earliest notif timestamp */
        if ((err_info = ntf_handle->plugin->earliest_get_cb(ly_mod, earliest_notif))) {
            goto cleanup;
        }
    }

cleanup:
    /* CONTEXT UNLOCK */
    sr_lycc_unlock(conn, SR_LOCK_READ, 0, __func__);

    return sr_api_ret(NULL, err_info);
}

/**
 * @brief Set all permissions for a single module.
 *
 * @param[in] conn Connection to use.
 * @param[in] ly_mod libyang module.
 * @param[in] shm_mod SHM mod structure.
 * @param[in] mod_ds Module datastore.
 * @param[in] owner Module owner, NULL to keep unchanged.
 * @param[in] group Module group, NULL to keep unchanged.
 * @param[in] perm Module permissions, 0 to keep unchanged.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
_sr_set_module_ds_access(sr_conn_ctx_t *conn, const struct lys_module *ly_mod, sr_mod_t *shm_mod, int mod_ds,
        const char *owner, const char *group, mode_t perm)
{
    sr_error_info_t *err_info = NULL;
    const struct sr_ds_handle_s *ds_handle;
    const struct sr_ntf_handle_s *ntf_handle;

    assert(owner || group || perm);

    /* set owner and permissions of the DS */
    if (mod_ds == SR_MOD_DS_NOTIF) {
        if ((err_info = sr_ntf_handle_find(conn->mod_shm.addr + shm_mod->plugins[mod_ds], conn, &ntf_handle))) {
            goto cleanup;
        }
        if ((err_info = ntf_handle->plugin->access_set_cb(ly_mod, owner, group, perm))) {
            goto cleanup;
        }
    } else {
        if ((mod_ds == SR_DS_RUNNING) && !shm_mod->plugins[mod_ds]) {
            /* 'running' disabled, use 'startup' instead */
            mod_ds = SR_DS_STARTUP;
        }

        if ((err_info = sr_ds_handle_find(conn->mod_shm.addr + shm_mod->plugins[mod_ds], conn, &ds_handle))) {
            goto cleanup;
        }
        if ((err_info = ds_handle->plugin->access_set_cb(ly_mod, mod_ds, owner, group, perm, ds_handle->plg_data))) {
            goto cleanup;
        }
    }

cleanup:
    return err_info;
}

API int
sr_set_module_ds_access(sr_conn_ctx_t *conn, const char *module_name, int mod_ds, const char *owner, const char *group,
        mode_t perm)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    const struct lys_module *ly_mod;
    uint32_t i;
    sr_mod_shm_t *mod_shm;

    SR_CHECK_ARG_APIRET(!conn || (mod_ds >= SR_MOD_DS_PLUGIN_COUNT) || (mod_ds < 0) ||
            (!owner && !group && !perm) || (perm && (perm & 00111)), NULL, err_info);
    mod_shm = SR_CONN_MOD_SHM(conn);

    if (perm & SR_UMASK) {
        SR_LOG_WRN("Ignoring permission bits %03o forbidden by Sysrepo umask.", (unsigned int)perm & SR_UMASK);
        perm &= ~SR_UMASK;
    }
    if (group && strlen(SR_GROUP) && strcmp(group, SR_GROUP)) {
        SR_LOG_WRN("Ignoring group \"%s\" because it differs from the Sysrepo group \"%s\".", group, SR_GROUP);
        group = NULL;
    }
    if (!owner && !group && !perm) {
        /* nothing left to set */
        return sr_api_ret(NULL, NULL);
    }

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(NULL, err_info);
    }

    if (module_name) {
        /* find the module in SHM */
        shm_mod = sr_shmmod_find_module(mod_shm, module_name);
        if (!shm_mod) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
            goto cleanup;
        }

        /* get LY module */
        ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, module_name);
        assert(ly_mod);

        /* set access for the module */
        if ((err_info = _sr_set_module_ds_access(conn, ly_mod, shm_mod, mod_ds, owner, group, perm))) {
            goto cleanup;
        }
    } else {
        /* go through all the modules */
        for (i = 0; i < mod_shm->mod_count; ++i) {
            shm_mod = SR_SHM_MOD_IDX(mod_shm, i);

            /* get LY module */
            ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, ((char *)mod_shm) + shm_mod->name);
            assert(ly_mod);

            /* set permissions of this module */
            if ((err_info = _sr_set_module_ds_access(conn, ly_mod, shm_mod, mod_ds, owner, group, perm))) {
                goto cleanup;
            }
        }
    }

cleanup:
    /* CONTEXT UNLOCK */
    sr_lycc_unlock(conn, SR_LOCK_READ, 0, __func__);

    return sr_api_ret(NULL, err_info);
}

API int
sr_get_module_ds_access(sr_conn_ctx_t *conn, const char *module_name, int mod_ds, char **owner, char **group, mode_t *perm)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    const struct lys_module *ly_mod;
    const struct sr_ds_handle_s *ds_handle;
    const struct sr_ntf_handle_s *ntf_handle;

    SR_CHECK_ARG_APIRET(!conn || !module_name || (mod_ds >= SR_MOD_DS_PLUGIN_COUNT) || (mod_ds < 0) ||
            (!owner && !group && !perm), NULL, err_info);

    /* find the module in SHM */
    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(conn), module_name);
    if (!shm_mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
        goto cleanup;
    }

    /* get LY module */
    ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, module_name);
    assert(ly_mod);

    /* learn owner and permissions of the DS */
    if (mod_ds == SR_MOD_DS_NOTIF) {
        if ((err_info = sr_ntf_handle_find(conn->mod_shm.addr + shm_mod->plugins[mod_ds], conn, &ntf_handle))) {
            goto cleanup;
        }
        if ((err_info = ntf_handle->plugin->access_get_cb(ly_mod, owner, group, perm))) {
            goto cleanup;
        }
    } else {
        if ((mod_ds == SR_DS_RUNNING) && !shm_mod->plugins[mod_ds]) {
            /* 'running' disabled, use 'startup' instead */
            mod_ds = SR_DS_STARTUP;
        }

        if ((err_info = sr_ds_handle_find(conn->mod_shm.addr + shm_mod->plugins[mod_ds], conn, &ds_handle))) {
            goto cleanup;
        }
        if ((err_info = ds_handle->plugin->access_get_cb(ly_mod, mod_ds, ds_handle->plg_data, owner, group, perm))) {
            goto cleanup;
        }
    }

cleanup:
    return sr_api_ret(NULL, err_info);
}

API int
sr_check_module_ds_access(sr_conn_ctx_t *conn, const char *module_name, int mod_ds, int *read, int *write)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    const struct lys_module *ly_mod;
    const struct sr_ds_handle_s *ds_handle;
    const struct sr_ntf_handle_s *ntf_handle;

    SR_CHECK_ARG_APIRET(!conn || !module_name || (mod_ds >= SR_MOD_DS_PLUGIN_COUNT) || (mod_ds < 0) || (!read && !write),
            NULL, err_info);

    /* find the module in SHM */
    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(conn), module_name);
    if (!shm_mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
        goto cleanup;
    }

    /* get LY module */
    ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, module_name);
    assert(ly_mod);

    /* check access for the DS */
    if (mod_ds == SR_MOD_DS_NOTIF) {
        if ((err_info = sr_ntf_handle_find(conn->mod_shm.addr + shm_mod->plugins[mod_ds], conn, &ntf_handle))) {
            goto cleanup;
        }
        if ((err_info = ntf_handle->plugin->access_check_cb(ly_mod, read, write))) {
            goto cleanup;
        }
    } else {
        if ((mod_ds == SR_DS_RUNNING) && !shm_mod->plugins[mod_ds]) {
            /* 'running' disabled, use 'startup' instead */
            mod_ds = SR_DS_STARTUP;
        }

        if ((err_info = sr_ds_handle_find(conn->mod_shm.addr + shm_mod->plugins[mod_ds], conn, &ds_handle))) {
            goto cleanup;
        }
        if ((err_info = ds_handle->plugin->access_check_cb(ly_mod, mod_ds, ds_handle->plg_data, read, write))) {
            goto cleanup;
        }
    }

cleanup:
    return sr_api_ret(NULL, err_info);
}

/**
 * @brief Load a module with changed features into context.
 *
 * @param[in,out] ly_ctx Context to load the module to.
 * @param[in] old_mod Previous (current) module.
 * @param[in] feature_name Changed feature, "*" for all.
 * @param[in] enable Whether the feature was enabled or disabled.
 * @param[out] new_mod New loaded module.
 * @param[out] feat_set Set with all the changed features.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_load_module(struct ly_ctx *ly_ctx, const struct lys_module *old_mod, const char *feature_name, int enable,
        const struct lys_module **new_mod, struct ly_set *feat_set)
{
    sr_error_info_t *err_info = NULL;
    struct lysp_feature *f = NULL;
    const char **features = NULL;
    uint32_t i, feat_count = 0;

    *new_mod = NULL;

    /* collect enabled features */
    i = 0;
    while ((f = lysp_feature_next(f, old_mod->parsed, &i))) {
        if (f->flags & LYS_FENABLED) {
            if (enable || (strcmp(f->name, feature_name) && strcmp("*", feature_name))) {
                /* add already enabled features */
                features = sr_realloc(features, (feat_count + 1) * sizeof *features);
                SR_CHECK_MEM_GOTO(!features, err_info, cleanup);
                features[feat_count] = f->name;
                ++feat_count;
            } else {
                /* disabling the feature */
                if ((err_info = sr_ly_set_add(feat_set, (void *)f->name))) {
                    goto cleanup;
                }
            }
        } else {
            if (enable && (!strcmp(f->name, feature_name) || !strcmp("*", feature_name))) {
                /* add newly enabled feature */
                features = sr_realloc(features, (feat_count + 1) * sizeof *features);
                SR_CHECK_MEM_GOTO(!features, err_info, cleanup);
                features[feat_count] = f->name;
                ++feat_count;

                /* enabling the feature */
                if ((err_info = sr_ly_set_add(feat_set, (void *)f->name))) {
                    goto cleanup;
                }
            }
        }
    }

    if (features) {
        /* add terminating NULL */
        features = sr_realloc(features, (feat_count + 1) * sizeof *features);
        SR_CHECK_MEM_GOTO(!features, err_info, cleanup);
        features[feat_count] = NULL;
    }

    /* load the module */
    if ((err_info = sr_ly_ctx_load_module(ly_ctx, old_mod->name, old_mod->revision, features, new_mod))) {
        goto cleanup;
    }

    /* compile */
    if ((err_info = sr_ly_ctx_compile(ly_ctx))) {
        goto cleanup;
    }

cleanup:
    free(features);
    return err_info;
}

/**
 * @brief Enable/disable module feature.
 *
 * @param[in] conn Connection to use.
 * @param[in] module_name Module to change.
 * @param[in] feature_name Feature to change, "*" for all the features.
 * @param[in] enable Whether to enable or disable the feature.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_change_module_feature(sr_conn_ctx_t *conn, const char *module_name, const char *feature_name, int enable)
{
    sr_error_info_t *err_info = NULL;
    struct ly_ctx *new_ctx = NULL, *old_ctx = NULL;
    struct ly_set mod_set = {0}, feat_set = {0};
    struct lyd_node *sr_mods = NULL;
    struct sr_data_update_s data_info = {0};
    const struct lys_module *ly_mod, *upd_ly_mod;
    LY_ERR lyrc;
    sr_lock_mode_t ctx_mode = SR_LOCK_NONE;

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(conn, SR_LOCK_READ_UPGR, 1, __func__))) {
        goto cleanup;
    }
    ctx_mode = SR_LOCK_READ_UPGR;

    /* try to find this module */
    ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, module_name);
    if (!ly_mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
        goto cleanup;
    }

    /* check write perm */
    if ((err_info = sr_perm_check(conn, ly_mod, SR_DS_STARTUP, 1, NULL))) {
        goto cleanup;
    }

    if (strcmp(feature_name, "*")) {
        /* check feature in the current context */
        lyrc = lys_feature_value(ly_mod, feature_name);
        if (lyrc == LY_ENOTFOUND) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Feature \"%s\" was not found in module \"%s\".",
                    feature_name, module_name);
            goto cleanup;
        } else if ((lyrc == LY_SUCCESS) && enable) {
            sr_errinfo_new(&err_info, SR_ERR_EXISTS, "Feature \"%s\" is already enabled in module \"%s\".",
                    feature_name, module_name);
            goto cleanup;
        } else if ((lyrc == LY_ENOT) && !enable) {
            sr_errinfo_new(&err_info, SR_ERR_EXISTS, "Feature \"%s\" is already disabled in module \"%s\".",
                    feature_name, module_name);
            goto cleanup;
        }
    }

    /* create new temporary context */
    if ((err_info = sr_ly_ctx_init(conn, &new_ctx))) {
        goto cleanup;
    }

    /* use temporary context to load modules skipping the modified one */
    if (ly_set_add(&mod_set, (void *)ly_mod, 1, NULL)) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    if ((err_info = sr_shmmod_ctx_load_modules(SR_CONN_MOD_SHM(conn), new_ctx, &mod_set))) {
        goto cleanup;
    }

    /* load the module with changed features */
    if ((err_info = sr_load_module(new_ctx, ly_mod, feature_name, enable, &upd_ly_mod, &feat_set))) {
        goto cleanup;
    }

    /* check the subscriptions with the new context */
    if ((err_info = sr_lycc_check_chng_feature(conn, new_ctx))) {
        goto cleanup;
    }

    /* CONTEXT UPGRADE */
    if ((err_info = sr_lycc_relock(conn, SR_LOCK_WRITE, __func__))) {
        goto cleanup;
    }
    ctx_mode = SR_LOCK_WRITE;

    /* load all data and prepare their update */
    if ((err_info = sr_lycc_update_data(conn, new_ctx, NULL, NULL, 0, &data_info))) {
        goto cleanup;
    }

    /* update lydmods data */
    if ((err_info = sr_lydmods_change_chng_feature(conn->ly_ctx, ly_mod, new_ctx, &feat_set, enable, conn, &sr_mods))) {
        goto cleanup;
    }

    /* update SHM modules */
    if ((err_info = sr_shmmod_store_modules(&conn->mod_shm, sr_mods))) {
        goto cleanup;
    }

    /* store new data if they differ */
    if ((err_info = sr_lycc_store_data_if_differ(conn, new_ctx, sr_mods, &data_info))) {
        goto cleanup;
    }

    /* update content ID and safely switch the context */
    SR_CONN_MAIN_SHM(conn)->content_id = ly_ctx_get_modules_hash(new_ctx);
    sr_conn_ctx_switch(conn, &new_ctx, &old_ctx);

    /* send the notification */
    sr_generate_notif_module_change_feature(conn, ly_mod, &feat_set, enable);

cleanup:
    sr_lycc_update_data_clear(&data_info);
    lyd_free_siblings(sr_mods);
    ly_ctx_destroy(old_ctx);
    ly_ctx_destroy(new_ctx);

    /* CONTEXT UNLOCK */
    sr_lycc_unlock(conn, ctx_mode, 1, __func__);

    ly_set_erase(&mod_set, NULL);
    ly_set_erase(&feat_set, NULL);
    return err_info;
}

API int
sr_enable_module_feature(sr_conn_ctx_t *conn, const char *module_name, const char *feature_name)
{
    sr_error_info_t *err_info;

    SR_CHECK_ARG_APIRET(!conn || !module_name || !feature_name, NULL, err_info);

    err_info = sr_change_module_feature(conn, module_name, feature_name, 1);

    return sr_api_ret(NULL, err_info);
}

API int
sr_disable_module_feature(sr_conn_ctx_t *conn, const char *module_name, const char *feature_name)
{
    sr_error_info_t *err_info;

    SR_CHECK_ARG_APIRET(!conn || !module_name || !feature_name, NULL, err_info);

    err_info = sr_change_module_feature(conn, module_name, feature_name, 0);

    return sr_api_ret(NULL, err_info);
}

/**
 * @brief Acquire libyang data tree together with its context lock in a SR data structure.
 *
 * @param[in] conn Connection to use.
 * @param[in] tree libyang data tree, ownership is passed to @p data in all cases.
 * @param[out] data Created SR data.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
_sr_acquire_data(sr_conn_ctx_t *conn, struct lyd_node *tree, sr_data_t **data)
{
    sr_error_info_t *err_info = NULL;

    /* allocate structure */
    *data = calloc(1, sizeof **data);
    SR_CHECK_MEM_GOTO(!*data, err_info, cleanup);

    /* fill members */
    (*data)->conn = conn;
    (*data)->tree = tree;

cleanup:
    if (err_info) {
        lyd_free_all(tree);

        /* CONTEXT UNLOCK */
        sr_lycc_unlock(conn, SR_LOCK_READ, 0, __func__);
    }
    return err_info;
}

API int
sr_get_module_info(sr_conn_ctx_t *conn, sr_data_t **sysrepo_data)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!conn || !sysrepo_data, NULL, err_info);

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(NULL, err_info);
    }

    /* prepare data wrapper */
    if ((err_info = _sr_acquire_data(conn, NULL, sysrepo_data))) {
        goto cleanup;
    }

    /* get internal sysrepo data */
    if ((err_info = sr_lydmods_parse(conn->ly_ctx, conn, NULL, &(*sysrepo_data)->tree))) {
        goto cleanup;
    }

cleanup:
    if (err_info) {
        sr_release_data(*sysrepo_data);
        *sysrepo_data = NULL;
    }
    return sr_api_ret(NULL, err_info);
}

API int
sr_is_module_internal(const struct lys_module *ly_mod)
{
    if (!ly_mod->revision) {
        return 0;
    }

    if (sr_ly_module_is_internal(ly_mod)) {
        return 1;
    }

    if (!strcmp(ly_mod->name, "ietf-datastores") && !strcmp(ly_mod->revision, "2018-02-14")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "ietf-yang-schema-mount")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "ietf-yang-library")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "ietf-netconf")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "ietf-netconf-with-defaults") && !strcmp(ly_mod->revision, "2011-06-01")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "ietf-origin") && !strcmp(ly_mod->revision, "2018-02-14")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "ietf-netconf-notifications") && !strcmp(ly_mod->revision, "2012-02-06")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "sysrepo")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "sysrepo-monitoring")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "sysrepo-plugind")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "sysrepo-notifications")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "ietf-netconf-acm")) {
        return 1;
    }

    return 0;
}

API int
sr_get_item(sr_session_ctx_t *session, const char *path, uint32_t timeout_ms, sr_val_t **value)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set = NULL;
    struct sr_mod_info_s mod_info;

    SR_CHECK_ARG_APIRET(!session || !path || !value, session, err_info);

    if (!timeout_ms) {
        timeout_ms = SR_OPER_CB_TIMEOUT;
    }
    *value = NULL;
    /* for operational, use operational and running datastore */
    SR_MODINFO_INIT(mod_info, session->conn, session->ds, session->ds == SR_DS_OPERATIONAL ? SR_DS_RUNNING : session->ds, 0);

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    /* collect all required modules */
    if ((err_info = sr_modinfo_collect_xpath(session->conn->ly_ctx, path, session->ds, session,
            MOD_INFO_XPATH_STORE_SESSION_CHANGES, &mod_info))) {
        goto cleanup;
    }

    /* add modules into mod_info with deps, locking, and their data */
    if ((err_info = sr_modinfo_consolidate(&mod_info, SR_LOCK_READ, SR_MI_DATA_RO | SR_MI_PERM_READ, session,
            timeout_ms, 0, 0))) {
        goto cleanup;
    }

    /* filter the required data */
    if ((err_info = sr_modinfo_get_filter(&mod_info, path, session, &set))) {
        goto cleanup;
    }

    /* apply NACM */
    if ((err_info = sr_nacm_get_node_set_read_filter(session, set))) {
        goto cleanup;
    }

    if (set->count > 1) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "More subtrees match \"%s\".", path);
        goto cleanup;
    } else if (!set->count) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "No data found for \"%s\".", path);
        goto cleanup;
    }

    /* create return value */
    *value = malloc(sizeof **value);
    SR_CHECK_MEM_GOTO(!*value, err_info, cleanup);

    if ((err_info = sr_val_ly2sr(set->dnodes[0], 0, *value))) {
        goto cleanup;
    }

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    ly_set_free(set, NULL);
    sr_modinfo_erase(&mod_info);

    /* CONTEXT UNLOCK */
    sr_lycc_unlock(session->conn, SR_LOCK_READ, 0, __func__);
    if (err_info) {
        free(*value);
        *value = NULL;
    }
    return sr_api_ret(session, err_info);
}

API int
sr_session_acquire_data(sr_session_ctx_t *session, struct lyd_node *tree, sr_data_t **data)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session || !data, session, err_info);

    err_info = _sr_acquire_data(session->conn, tree, data);

    return sr_api_ret(session, err_info);
}

API int
sr_acquire_data(sr_conn_ctx_t *conn, struct lyd_node *tree, sr_data_t **data)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!conn || !data, NULL, err_info);

    err_info = _sr_acquire_data(conn, tree, data);

    return sr_api_ret(NULL, err_info);
}

API int
sr_get_items(sr_session_ctx_t *session, const char *xpath, uint32_t timeout_ms, const sr_get_options_t opts,
        sr_val_t **values, size_t *value_cnt)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set = NULL;
    struct sr_mod_info_s mod_info;
    struct lyd_node *node;
    uint32_t i;

    SR_CHECK_ARG_APIRET(!session || !xpath || !values || !value_cnt ||
            ((session->ds != SR_DS_OPERATIONAL) && (opts & SR_OPER_MASK)), session, err_info);

    if (!timeout_ms) {
        timeout_ms = SR_OPER_CB_TIMEOUT;
    }
    *values = NULL;
    *value_cnt = 0;
    /* for operational, use operational and running datastore */
    SR_MODINFO_INIT(mod_info, session->conn, session->ds, session->ds == SR_DS_OPERATIONAL ? SR_DS_RUNNING : session->ds, 0);

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    /* collect all required modules */
    if ((err_info = sr_modinfo_collect_xpath(session->conn->ly_ctx, xpath, session->ds, session,
            MOD_INFO_XPATH_STORE_SESSION_CHANGES, &mod_info))) {
        goto cleanup;
    }

    /* add modules into mod_info with deps, locking, and their data */
    if ((err_info = sr_modinfo_consolidate(&mod_info, SR_LOCK_READ, SR_MI_DATA_RO | SR_MI_PERM_READ, session,
            timeout_ms, 0, opts))) {
        goto cleanup;
    }

    /* filter the required data */
    if ((err_info = sr_modinfo_get_filter(&mod_info, (opts & SR_GET_NO_FILTER) ? "/*" : xpath, session, &set))) {
        goto cleanup;
    }

    /* ignore unwanted results */
    if (session->ds == SR_DS_OPERATIONAL) {
        i = 0;
        while (i < set->count) {
            node = set->dnodes[i];
            if ((node->schema->flags & LYS_CONFIG_R) && (opts & SR_OPER_NO_STATE)) {
                /* ignored state node */
                ly_set_rm_index_ordered(set, i, NULL);
            } else if ((node->schema->flags & LYS_CONFIG_W) && (opts & SR_OPER_NO_CONFIG)) {
                /* ignored config node */
                ly_set_rm_index_ordered(set, i, NULL);
            } else {
                ++i;
            }
        }
    }

    /* apply NACM */
    if ((err_info = sr_nacm_get_node_set_read_filter(session, set))) {
        goto cleanup;
    }

    if (set->count) {
        *values = calloc(set->count, sizeof **values);
        SR_CHECK_MEM_GOTO(!*values, err_info, cleanup);
    }

    for (i = 0; i < set->count; ++i) {
        if ((err_info = sr_val_ly2sr(set->dnodes[i], opts & SR_OPER_WITH_ORIGIN, (*values) + i))) {
            goto cleanup;
        }
        ++(*value_cnt);
    }

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    ly_set_free(set, NULL);
    sr_modinfo_erase(&mod_info);

    /* CONTEXT UNLOCK */
    sr_lycc_unlock(session->conn, SR_LOCK_READ, 0, __func__);
    if (err_info) {
        sr_free_values(*values, *value_cnt);
        *values = NULL;
        *value_cnt = 0;
    }
    return sr_api_ret(session, err_info);
}

/**
 * @brief Trim all configuration/state nodes/origin from the data, recursively.
 *
 * @param[in] subtree Subtree root of the data to trim.
 * @param[in] get_oper_opts Get oper data options.
 * @param[in,out] first First top-level sibling, may be adjusted.
 * @return 1 if @p subtree was trimmed;
 * @return 0 otherwise.
 */
static int
sr_oper_data_trim_r(struct lyd_node *subtree, sr_get_oper_flag_t get_oper_opts, struct lyd_node **first)
{
    struct lyd_node *next, *elem;

    if (!(get_oper_opts & (SR_OPER_NO_STATE | SR_OPER_NO_CONFIG))) {
        /* nothing to trim */
        return 0;
    }

    if (lysc_is_key(subtree->schema)) {
        return 0;
    }

    if (subtree->schema->flags & LYS_CONFIG_R) {
        /* state subtree */
        if (get_oper_opts & SR_OPER_NO_STATE) {
            /* free it whole */
            sr_lyd_free_tree_safe(subtree, first);
            return 1;
        }

        /* no need to go into state children */
        return 0;
    }

    /* trim all our children */
    LY_LIST_FOR_SAFE(lyd_child_no_keys(subtree), next, elem) {
        sr_oper_data_trim_r(elem, get_oper_opts, first);
    }

    if ((subtree->schema->flags & LYS_CONFIG_W) && (get_oper_opts & SR_OPER_NO_CONFIG) && !lyd_child_no_keys(subtree)) {
        /* config-only subtree (config node with no children) */
        sr_lyd_free_tree_safe(subtree, first);
        return 1;
    }

    return 0;
}

/**
 * @brief Trim all configuration/state nodes/origin from the data based on options.
 *
 * @param[in] set Set of results to consider.
 * @param[in] get_oper_opts Get oper data options.
 * @param[in,out] first First top-level sibling, may be adjusted.
 */
static void
sr_oper_data_trim(struct ly_set *set, sr_get_oper_flag_t get_oper_opts, struct lyd_node **first)
{
    uint32_t i = 0;

    while (i < set->count) {
        if (sr_oper_data_trim_r(set->dnodes[i], get_oper_opts, first)) {
            ly_set_rm_index_ordered(set, i, NULL);
        } else {
            ++i;
        }
    }
}

API int
sr_get_subtree(sr_session_ctx_t *session, const char *path, uint32_t timeout_ms, sr_data_t **subtree)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set = NULL;
    struct sr_mod_info_s mod_info;
    int denied;

    SR_CHECK_ARG_APIRET(!session || !path || !subtree, session, err_info);

    if (!timeout_ms) {
        timeout_ms = SR_OPER_CB_TIMEOUT;
    }
    /* for operational, use operational and running datastore */
    SR_MODINFO_INIT(mod_info, session->conn, session->ds, session->ds == SR_DS_OPERATIONAL ? SR_DS_RUNNING : session->ds, 0);

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    /* prepare data wrapper */
    if ((err_info = _sr_acquire_data(session->conn, NULL, subtree))) {
        goto cleanup;
    }

    /* collect all the required modules, do not store xpaths if some changes will be applied (we need all the base data then) */
    if ((err_info = sr_modinfo_collect_xpath(session->conn->ly_ctx, path, session->ds, session,
            MOD_INFO_XPATH_STORE_SESSION_CHANGES, &mod_info))) {
        goto cleanup;
    }

    /* add modules into mod_info with deps, locking, and their data */
    if ((err_info = sr_modinfo_consolidate(&mod_info, SR_LOCK_READ, SR_MI_DATA_RO | SR_MI_PERM_READ, session,
            timeout_ms, 0, 0))) {
        goto cleanup;
    }

    /* filter the required data */
    if ((err_info = sr_modinfo_get_filter(&mod_info, path, session, &set))) {
        goto cleanup;
    }

    /* apply NACM #1, get rid of whole denied results */
    if ((err_info = sr_nacm_get_node_set_read_filter(session, set))) {
        goto cleanup;
    }

    if (set->count > 1) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "More subtrees match \"%s\".", path);
        goto cleanup;
    } else if (!set->count) {
        goto cleanup;
    }

    /* trim unwanted data */
    if (session->ds == SR_DS_OPERATIONAL) {
        sr_oper_data_trim(set, 0, &mod_info.data);
    }

    /* set result, without origin */
    if ((err_info = sr_lyd_dup(set->dnodes[0], NULL, LYD_DUP_RECURSIVE | LYD_DUP_WITH_PARENTS | LYD_DUP_NO_META, 0,
            &(*subtree)->tree))) {
        goto cleanup;
    }

    /* apply NACM #2, filter out the selected subtree */
    if ((err_info = sr_nacm_get_subtree_read_filter(session, (*subtree)->tree, &denied))) {
        goto cleanup;
    }
    assert(!denied);

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    ly_set_free(set, NULL);
    sr_modinfo_erase(&mod_info);

    if (err_info || !(*subtree)->tree) {
        sr_release_data(*subtree);
        *subtree = NULL;
    }
    return sr_api_ret(session, err_info);
}

/**
 * @brief Get-data parent hash table record.
 */
struct sr_lyht_get_data_rec {
    struct lyd_node *input_parent;  /**< parent in the input (sysrepo) data */
    struct lyd_node *result_parent; /**< parent in the result (user returned) data */
};

/**
 * @brief Get-data dup parent hash table equal callback.
 */
static ly_bool
sr_lyht_get_data_dup_equal_cb(void *val1_p, void *val2_p, ly_bool UNUSED(mod), void *UNUSED(cb_data))
{
    struct sr_lyht_get_data_rec *val1, *val2;

    val1 = val1_p;
    val2 = val2_p;

    return val1->input_parent == val2->input_parent;
}

/**
 * @brief Duplicate a set of subtrees into a new data tree.
 *
 * @param[in] session Session to use.
 * @param[in] set Set with the selected (disjoint) subtrees.
 * @param[in] max_depth Max depth of the nodes to duplicate.
 * @param[in] opts Get options.
 * @param[out] tree Resulting data tree.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_get_data_dup(sr_session_ctx_t *session, const struct ly_set *set, uint32_t max_depth, const sr_get_options_t opts,
        struct lyd_node **tree)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, hash;
    int dup_opts, denied;
    struct ly_ht *ht = NULL;
    struct sr_lyht_get_data_rec rec, *rec_p;
    struct lyd_node *node, *parent, *node_parent, *input_node;

    /* create a hash table for finding existing parents */
    ht = lyht_new(1, sizeof rec, sr_lyht_get_data_dup_equal_cb, NULL, 1);
    SR_CHECK_MEM_GOTO(!ht, err_info, cleanup);

    /* prepare duplication options */
    dup_opts = (max_depth ? 0 : LYD_DUP_RECURSIVE) | LYD_DUP_WITH_PARENTS | LYD_DUP_WITH_FLAGS |
            ((opts & SR_OPER_WITH_ORIGIN) ? 0 : LYD_DUP_NO_META);

    for (i = 0; i < set->count; ++i) {
        /* check whether a parent does not exist yet in the result */
        for (parent = lyd_parent(set->dnodes[i]); parent; parent = lyd_parent(parent)) {
            hash = lyht_hash((void *)&parent, sizeof parent);
            rec.input_parent = parent;
            if (!lyht_find(ht, &rec, hash, (void **)&rec_p)) {
                /* parent exists, use the one in the result */
                parent = rec_p->result_parent;
                break;
            }
        }

        /* duplicate subtree and connect it to an existing parent, if any */
        if ((err_info = sr_lyd_dup(set->dnodes[i], parent, dup_opts, 0, &node))) {
            goto cleanup;
        }

        /* get first created node parent (can be node itself) */
        for (node_parent = node; lyd_parent(node_parent) != parent; node_parent = lyd_parent(node_parent)) {}

        /* duplicate only to the specified depth (the selected node was already duplicated, hence -1) */
        if (max_depth && (err_info = sr_lyd_dup_r(set->dnodes[i], max_depth - 1, dup_opts, node))) {
            lyd_free_tree(node_parent);
            goto cleanup;
        }

        /* apply NACM on the selected subtree */
        if ((err_info = sr_nacm_get_subtree_read_filter(session, node, &denied))) {
            goto cleanup;
        }
        if (denied) {
            /* the whole subtree was filtered out, remove it with any new parents */
            lyd_free_tree(node_parent);
            continue;
        }

        if (!parent) {
            /* connect to the result */
            if ((err_info = sr_lyd_insert_sibling(*tree, node_parent, tree))) {
                lyd_free_tree(node);
                goto cleanup;
            }
        }

        /* store all the new potential parents in the result */
        input_node = lyd_parent(set->dnodes[i]);
        for (node = lyd_parent(node); node != parent; node = lyd_parent(node)) {
            hash = lyht_hash((void *)&input_node, sizeof input_node);
            rec.input_parent = input_node;
            rec.result_parent = node;
            assert(rec.input_parent->schema == rec.result_parent->schema);
            if ((err_info = sr_lyht_insert(ht, &rec, hash))) {
                goto cleanup;
            }

            /* move input */
            input_node = lyd_parent(input_node);
        }
    }

cleanup:
    lyht_free(ht, NULL);
    return err_info;
}

/**
 * @brief Get-data prune hash table equal callback.
 */
static ly_bool
sr_lyht_get_data_prune_equal_cb(void *val1_p, void *val2_p, ly_bool UNUSED(mod), void *UNUSED(cb_data))
{
    struct lyd_node **val1, **val2;

    val1 = val1_p;
    val2 = val2_p;

    return *val1 == *val2;
}

/**
 * @brief Remove all the non-selected subtrees.
 *
 * @param[in] session Session to use.
 * @param[in,out] first First top-level node of the tree to prune, may be adjusted.
 * @param[in] set Set with the selected (disjoint) subtrees.
 * @param[in] max_depth Max depth of the selected nodes to prune.
 * @param[in] opts Get options.
 * @param[out] tree Resulting data tree.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_get_data_prune(sr_session_ctx_t *session, struct lyd_node **first, const struct ly_set *set, uint32_t max_depth,
        const sr_get_options_t opts)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    int denied;
    struct ly_ht *parent_ht = NULL, *set_ht = NULL;
    struct lyd_node *parent, *root, *node, *iter, *to_free;
    const struct lys_module *or_mod;
    struct lyd_meta *m;
    LY_ERR lyrc;

    /* find 'ietf-origin' module if we need to remove all 'origin' metadata */
    if (opts & SR_OPER_WITH_ORIGIN) {
        or_mod = NULL;
    } else {
        or_mod = ly_ctx_get_module_implemented(session->conn->ly_ctx, "ietf-origin");
        assert(or_mod);
    }

    /* create a hash table for checking parents and result set nodes */
    parent_ht = lyht_new(1, sizeof(struct lyd_node *), sr_lyht_get_data_prune_equal_cb, NULL, 1);
    SR_CHECK_MEM_GOTO(!parent_ht, err_info, cleanup);
    set_ht = lyht_new(lyht_get_fixed_size(set->count), sizeof(struct lyd_node *), sr_lyht_get_data_prune_equal_cb, NULL, 0);
    SR_CHECK_MEM_GOTO(!set_ht, err_info, cleanup);

    for (i = 0; i < set->count; ++i) {
        node = set->dnodes[i];

        /* trim the depth of the subtree */
        sr_lyd_trim_depth(node, max_depth);

        /* apply NACM on the selected subtree */
        if ((err_info = sr_nacm_get_subtree_read_filter(session, node, &denied))) {
            goto cleanup;
        }
        if (denied) {
            /* the whole subtree was filtered out */
            continue;
        }

        /* store the result in HT, cannot be there yet */
        lyrc = lyht_insert_no_check(set_ht, &node, (uintptr_t)node, NULL);
        SR_CHECK_MEM_GOTO(lyrc == LY_EMEM, err_info, cleanup);

        /* store all the parents, stop if they are there already */
        for (parent = lyd_parent(node); parent; parent = lyd_parent(parent)) {
            lyrc = lyht_insert(parent_ht, &parent, (uintptr_t)parent, NULL);
            SR_CHECK_MEM_GOTO(lyrc == LY_EMEM, err_info, cleanup);
            if (lyrc == LY_EEXIST) {
                /* all the parents inserted */
                break;
            }
        }
    }

    to_free = NULL;
    LY_LIST_FOR(*first, root) {
        LYD_TREE_DFS_BEGIN(root, node) {
            /* free any marked subtree, now it is safe */
            sr_lyd_free_tree_safe(to_free, first);
            to_free = NULL;

            /* ignore keys */
            if (!lysc_is_key(node->schema)) {
                /* check it's a parent of a result */
                lyrc = lyht_find(parent_ht, &node, (uintptr_t)node, NULL);

                if (lyrc == LY_ENOTFOUND) {
                    /* not a parent, check it's a result */
                    lyrc = lyht_find(set_ht, &node, (uintptr_t)node, NULL);

                    if (lyrc == LY_ENOTFOUND) {
                        /* not a parent nor result, free the whole subtree */
                        to_free = node;
                    } else if (or_mod) {
                        /* remove origin from the whole result subtree */
                        LYD_TREE_DFS_BEGIN(node, iter) {
                            m = lyd_find_meta(iter->meta, or_mod, "origin");
                            lyd_free_meta_single(m);

                            LYD_TREE_DFS_END(node, iter);
                        }
                    }

                    /* whether it's a result or not, continue with DFS */
                    LYD_TREE_DFS_continue = 1;
                } else if (or_mod) {
                    /* remove origin from the parent */
                    m = lyd_find_meta(node->meta, or_mod, "origin");
                    lyd_free_meta_single(m);
                }
            }

            LYD_TREE_DFS_END(root, node);
        }
    }
    sr_lyd_free_tree_safe(to_free, first);

cleanup:
    lyht_free(parent_ht, NULL);
    lyht_free(set_ht, NULL);
    return err_info;
}

API int
sr_get_data(sr_session_ctx_t *session, const char *xpath, uint32_t max_depth, uint32_t timeout_ms,
        const sr_get_options_t opts, sr_data_t **data)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_s mod_info;
    struct ly_set *set = NULL;

    SR_CHECK_ARG_APIRET(!session || !xpath || !data || ((session->ds != SR_DS_OPERATIONAL) && (opts & SR_OPER_MASK)),
            session, err_info);

    if (!timeout_ms) {
        timeout_ms = SR_OPER_CB_TIMEOUT;
    }

    /* for operational, use operational and running datastore */
    SR_MODINFO_INIT(mod_info, session->conn, session->ds, session->ds == SR_DS_OPERATIONAL ? SR_DS_RUNNING : session->ds, 0);

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    /* prepare data wrapper */
    if ((err_info = _sr_acquire_data(session->conn, NULL, data))) {
        goto cleanup;
    }

    /* collect all required modules */
    if ((err_info = sr_modinfo_collect_xpath(session->conn->ly_ctx, xpath, session->ds, session,
            MOD_INFO_XPATH_STORE_SESSION_CHANGES, &mod_info))) {
        goto cleanup;
    }

    /* add modules into mod_info with deps, locking, and their data */
    if ((err_info = sr_modinfo_consolidate(&mod_info, SR_LOCK_READ, SR_MI_DATA_RO | SR_MI_PERM_READ, session,
            timeout_ms, 0, opts))) {
        goto cleanup;
    }

    /* filter the required data */
    if ((err_info = sr_modinfo_get_filter(&mod_info, (opts & SR_GET_NO_FILTER) ? "/*" : xpath, session, &set))) {
        goto cleanup;
    }

    /* get rid of all redundant results that are descendants of another result */
    if ((err_info = sr_xpath_set_filter_subtrees(set))) {
        goto cleanup;
    }

    /* trim unwanted data, after filtering */
    if (session->ds == SR_DS_OPERATIONAL) {
        sr_oper_data_trim(set, opts, &mod_info.data);
    }

    if (mod_info.data_cached) {
        /* duplicate all the selected data */
        if ((err_info = sr_get_data_dup(session, set, max_depth, opts, &(*data)->tree))) {
            goto cleanup;
        }
    } else {
        /* prune all the non-selected data */
        if ((err_info = sr_get_data_prune(session, &mod_info.data, set, max_depth, opts))) {
            goto cleanup;
        }

        /* use the pruned data */
        (*data)->tree = mod_info.data;
        mod_info.data = NULL;
    }

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    ly_set_free(set, NULL);
    sr_modinfo_erase(&mod_info);

    if (err_info || !(*data)->tree) {
        sr_release_data(*data);
        *data = NULL;
    }
    return sr_api_ret(session, err_info);
}

API int
sr_get_node(sr_session_ctx_t *session, const char *path, uint32_t timeout_ms, sr_data_t **node)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set = NULL;
    struct sr_mod_info_s mod_info;
    struct lyd_node *n;

    SR_CHECK_ARG_APIRET(!session || !path || !node, session, err_info);

    if (!timeout_ms) {
        timeout_ms = SR_OPER_CB_TIMEOUT;
    }

    /* for operational, use operational and running datastore */
    SR_MODINFO_INIT(mod_info, session->conn, session->ds, session->ds == SR_DS_OPERATIONAL ? SR_DS_RUNNING : session->ds, 0);

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    /* prepare data wrapper */
    if ((err_info = _sr_acquire_data(session->conn, NULL, node))) {
        goto cleanup;
    }

    /* collect all required modules */
    if ((err_info = sr_modinfo_collect_xpath(session->conn->ly_ctx, path, session->ds, session,
            MOD_INFO_XPATH_STORE_SESSION_CHANGES, &mod_info))) {
        goto cleanup;
    }

    /* add modules into mod_info with deps, locking, and their data */
    if ((err_info = sr_modinfo_consolidate(&mod_info, SR_LOCK_READ, SR_MI_DATA_RO | SR_MI_PERM_READ, session,
            timeout_ms, 0, 0))) {
        goto cleanup;
    }

    /* filter the required data */
    if ((err_info = sr_modinfo_get_filter(&mod_info, path, session, &set))) {
        goto cleanup;
    }

    /* apply NACM */
    if ((err_info = sr_nacm_get_node_set_read_filter(session, set))) {
        goto cleanup;
    }

    if (set->count > 1) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "More nodes match \"%s\".", path);
        goto cleanup;
    } else if (!set->count) {
        /* not found */
        goto cleanup;
    }

    /* trim unwanted data */
    if (session->ds == SR_DS_OPERATIONAL) {
        sr_oper_data_trim(set, 0, &mod_info.data);
    }

    /* return found node */
    if ((err_info = sr_lyd_dup(set->dnodes[0], NULL, LYD_DUP_WITH_FLAGS, 0, &n))) {
        goto cleanup;
    }
    (*node)->tree = n;

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    ly_set_free(set, NULL);
    sr_modinfo_erase(&mod_info);

    if (err_info) {
        /* error */
        sr_release_data(*node);
        *node = NULL;
    } else if (!(*node)->tree) {
        /* not found */
        sr_release_data(*node);
        *node = NULL;

        sr_api_ret(session, err_info);
        return SR_ERR_NOT_FOUND;
    }
    return sr_api_ret(session, err_info);
}

API void
sr_release_data(sr_data_t *data)
{
    if (!data) {
        return;
    }

    lyd_free_all(data->tree);

    /* CONTEXT UNLOCK */
    sr_lycc_unlock((sr_conn_ctx_t *)data->conn, SR_LOCK_READ, 0, __func__);

    free(data);
}

API void
sr_free_val(sr_val_t *value)
{
    if (!value) {
        return;
    }

    free(value->xpath);
    free(value->origin);
    switch (value->type) {
    case SR_BINARY_T:
    case SR_BITS_T:
    case SR_ENUM_T:
    case SR_IDENTITYREF_T:
    case SR_INSTANCEID_T:
    case SR_STRING_T:
    case SR_ANYXML_T:
    case SR_ANYDATA_T:
        free(value->data.string_val);
        break;
    default:
        /* nothing to free */
        break;
    }

    free(value);
}

API void
sr_free_values(sr_val_t *values, size_t count)
{
    size_t i;

    if (!values || !count) {
        return;
    }

    for (i = 0; i < count; ++i) {
        free(values[i].xpath);
        free(values[i].origin);
        switch (values[i].type) {
        case SR_BINARY_T:
        case SR_BITS_T:
        case SR_ENUM_T:
        case SR_IDENTITYREF_T:
        case SR_INSTANCEID_T:
        case SR_STRING_T:
        case SR_ANYXML_T:
        case SR_ANYDATA_T:
            free(values[i].data.string_val);
            break;
        default:
            /* nothing to free */
            break;
        }
    }

    free(values);
}

API int
sr_set_item(sr_session_ctx_t *session, const char *path, const sr_val_t *value, const sr_edit_options_t opts)
{
    sr_error_info_t *err_info = NULL;
    char str[22], *str_val;

    SR_CHECK_ARG_APIRET(!session || (!path && (!value || !value->xpath)) || SR_EDIT_DS_API_CHECK(session->ds, opts),
            session, err_info);

    if (!path) {
        path = value->xpath;
    }

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    str_val = sr_val_sr2ly_str(session->conn->ly_ctx, value, path, str, 0);

    /* CONTEXT UNLOCK */
    sr_lycc_unlock(session->conn, SR_LOCK_READ, 0, __func__);

    /* API function */
    return sr_set_item_str(session, path, str_val, value ? value->origin : NULL, opts);
}

API int
sr_set_item_str(sr_session_ctx_t *session, const char *path, const char *value, const char *origin,
        const sr_edit_options_t opts)
{
    sr_error_info_t *err_info = NULL;
    char *pref_origin = NULL;
    const char *op, *def_op;
    struct lyd_node *node;
    int rc;

    SR_CHECK_ARG_APIRET(!session || !path || SR_EDIT_DS_API_CHECK(session->ds, opts), session, err_info);

    if (origin) {
        if (!strchr(origin, ':')) {
            /* add ietf-origin prefix if none used */
            pref_origin = malloc(11 + 1 + strlen(origin) + 1);
            sprintf(pref_origin, "ietf-origin:%s", origin);
        } else {
            pref_origin = strdup(origin);
        }
    }

    if (!session->oper_edit_fetched && (session->ds == SR_DS_OPERATIONAL)) {
        assert(!session->dt[session->ds].edit);

        /* prepare the current stored oper data to be modified */
        if ((rc = sr_get_oper_changes(session, NULL, &session->dt[session->ds].edit))) {
            goto cleanup;
        }

        /* remember that oper changes have been fetched */
        session->oper_edit_fetched = 1;

        /* set the default replace operation on top-level nodes */
        if (session->dt[session->ds].edit) {
            LY_LIST_FOR(session->dt[session->ds].edit->tree, node) {
                if ((err_info = sr_edit_set_oper(node, "replace"))) {
                    goto cleanup;
                }
            }
        }
    }
    if (!session->dt[session->ds].edit) {
        /* CONTEXT LOCK */
        if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
            goto cleanup;
        }

        /* prepare edit with context lock */
        if ((err_info = _sr_acquire_data(session->conn, NULL, &session->dt[session->ds].edit))) {
            goto cleanup;
        }
    }

    /* add the operation into edit */
    op = (opts & SR_EDIT_STRICT) ? "create" : "merge";
    def_op = (session->ds == SR_DS_OPERATIONAL) ? "replace" : ((opts & SR_EDIT_NON_RECURSIVE) ? "none" : "merge");
    err_info = sr_edit_add(session, path, value, op, def_op, NULL, NULL, NULL, pref_origin, opts & SR_EDIT_ISOLATE);

cleanup:
    if (session->dt[session->ds].edit && !session->dt[session->ds].edit->tree) {
        sr_release_data(session->dt[session->ds].edit);
        session->dt[session->ds].edit = NULL;
    }
    free(pref_origin);
    return sr_api_ret(session, err_info);
}

API int
sr_delete_item(sr_session_ctx_t *session, const char *path, const sr_edit_options_t opts)
{
    sr_error_info_t *err_info = NULL;
    const char *op;
    const struct lysc_node *snode;
    struct lyd_node *node;
    struct ly_set *set = NULL;
    uint32_t temp_lo = 0;
    uint32_t i;
    int rc;

    SR_CHECK_ARG_APIRET(!session || !path || !SR_IS_STANDARD_DS(session->ds) || (!SR_IS_CONVENTIONAL_DS(session->ds) &&
            (opts & (SR_EDIT_NON_RECURSIVE | SR_EDIT_ISOLATE))), session, err_info);

    if (!session->oper_edit_fetched && (session->ds == SR_DS_OPERATIONAL)) {
        assert(!session->dt[session->ds].edit);

        /* prepare the current stored oper data to be modified */
        if ((rc = sr_get_oper_changes(session, NULL, &session->dt[session->ds].edit))) {
            goto cleanup;
        }

        /* remember that oper changes have been fetched */
        session->oper_edit_fetched = 1;

        /* set the default replace operation on top-level nodes */
        if (session->dt[session->ds].edit) {
            LY_LIST_FOR(session->dt[session->ds].edit->tree, node) {
                if ((err_info = sr_edit_set_oper(node, "replace"))) {
                    goto cleanup;
                }
            }
        }
    }
    if (!session->dt[session->ds].edit) {
        /* CONTEXT LOCK */
        if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
            goto cleanup;
        }

        /* prepare edit with context lock */
        if ((err_info = _sr_acquire_data(session->conn, NULL, &session->dt[session->ds].edit))) {
            goto cleanup;
        }
    }

    if (session->ds == SR_DS_OPERATIONAL) {
        /* check that the xpath is valid */
        if ((err_info = sr_lys_find_xpath(session->conn->ly_ctx, path, LYS_FIND_NO_MATCH_ERROR, NULL, &set))) {
            goto cleanup;
        }

        ly_set_free(set, NULL);
        set = NULL;

        if (session->dt[session->ds].edit->tree &&
                (err_info = sr_lyd_find_xpath(session->dt[session->ds].edit->tree, path, &set))) {
            goto cleanup;
        }
        if (set && set->count) {
            for (i = 0; i < set->count; ++i) {
                sr_lyd_free_tree_safe(set->dnodes[i], &session->dt[session->ds].edit->tree);
            }
        } else if (opts & SR_EDIT_STRICT) {
            /* not found */
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "No nodes \"%s\" found in session push oper data.", path);
        }
        goto cleanup;
    }

    /* turn off logging */
    ly_temp_log_options(&temp_lo);
    if ((path[strlen(path) - 1] != ']') && (snode = lys_find_path(session->conn->ly_ctx, NULL, path, 0)) &&
            (snode->nodetype & (LYS_LEAFLIST | LYS_LIST)) &&
            !strcmp((path + strlen(path)) - strlen(snode->name), snode->name)) {
        op = "purge";
    } else if (opts & SR_EDIT_STRICT) {
        op = "delete";
    } else {
        op = "remove";
    }
    ly_temp_log_options(NULL);

    /* add the operation into edit */
    err_info = sr_edit_add(session, path, NULL, op, opts & SR_EDIT_STRICT ? "none" : "ether", NULL, NULL, NULL,
            NULL, opts & SR_EDIT_ISOLATE);

cleanup:
    ly_set_free(set, NULL);
    if (session->dt[session->ds].edit && !session->dt[session->ds].edit->tree) {
        sr_release_data(session->dt[session->ds].edit);
        session->dt[session->ds].edit = NULL;
    }

    return sr_api_ret(session, err_info);
}

API int
sr_oper_delete_item_str(sr_session_ctx_t *session, const char *path, const char *UNUSED(value), const sr_edit_options_t opts)
{
    return sr_delete_item(session, path, opts);
}

API int
sr_discard_items(sr_session_ctx_t *session, const char *xpath)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *node;
    int rc;

    SR_CHECK_ARG_APIRET(!session || (session->ds != SR_DS_OPERATIONAL) || !xpath, session, err_info);

    if (!session->oper_edit_fetched) {
        assert(!session->dt[session->ds].edit);

        /* prepare the current stored oper data to be modified */
        if ((rc = sr_get_oper_changes(session, NULL, &session->dt[session->ds].edit))) {
            goto cleanup;
        }

        /* remember that oper changes have been fetched */
        session->oper_edit_fetched = 1;

        /* set the default replace operation on top-level nodes */
        if (session->dt[session->ds].edit) {
            LY_LIST_FOR(session->dt[session->ds].edit->tree, node) {
                if ((err_info = sr_edit_set_oper(node, "replace"))) {
                    goto cleanup;
                }
            }
        }
    }
    if (!session->dt[session->ds].edit) {
        /* CONTEXT LOCK */
        if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
            goto cleanup;
        }

        /* prepare edit with context lock */
        if ((err_info = _sr_acquire_data(session->conn, NULL, &session->dt[session->ds].edit))) {
            goto cleanup;
        }
    }

    /* add the operation into edit */
    if ((err_info = sr_lyd_new_opaq(session->conn->ly_ctx, "discard-items", xpath, "sysrepo", "sysrepo", &node))) {
        goto cleanup;
    }
    if ((err_info = sr_edit_set_oper(node, "replace"))) {
        goto cleanup;
    }
    if ((err_info = sr_lyd_insert_sibling(session->dt[session->ds].edit->tree, node, &session->dt[session->ds].edit->tree))) {
        lyd_free_tree(node);
        goto cleanup;
    }

cleanup:
    if (session->dt[session->ds].edit && !session->dt[session->ds].edit->tree) {
        sr_release_data(session->dt[session->ds].edit);
        session->dt[session->ds].edit = NULL;
    }
    return sr_api_ret(session, err_info);
}

API int
sr_delete_discard_items(sr_session_ctx_t *session, const char *xpath, const sr_edit_options_t opts)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *node = NULL;
    const struct lys_module *ly_mod;
    int rc;

    SR_CHECK_ARG_APIRET(!session || (session->ds != SR_DS_OPERATIONAL) || !xpath || (opts && (opts != SR_EDIT_STRICT)),
            session, err_info);

    if (!session->oper_edit_fetched) {
        assert(!session->dt[session->ds].edit);

        /* prepare the current stored oper data to be modified */
        if ((rc = sr_get_oper_changes(session, NULL, &session->dt[session->ds].edit))) {
            goto cleanup;
        }

        /* remember that oper changes have been fetched */
        session->oper_edit_fetched = 1;

        /* set the default replace operation on top-level nodes */
        if (session->dt[session->ds].edit) {
            LY_LIST_FOR(session->dt[session->ds].edit->tree, node) {
                if ((err_info = sr_edit_set_oper(node, "replace"))) {
                    goto cleanup;
                }
            }
        }
    }
    if (session->dt[session->ds].edit) {
        /* find the specific 'discard-items' node */
        while (1) {
            if (!node) {
                /* first node */
                node = session->dt[session->ds].edit->tree;
            } else {
                /* next node */
                node = node->next;
            }
            if ((err_info = sr_lyd_find_sibling_opaq_next(node, "discard-items", &node))) {
                goto cleanup;
            }
            if (!node) {
                break;
            }

            /* module check */
            ly_mod = lyd_node_module(node);
            if (!ly_mod || strcmp(ly_mod->name, "sysrepo")) {
                continue;
            }

            /* value check */
            if (strcmp(lyd_get_value(node), xpath)) {
                continue;
            }

            /* found */
            break;
        }
    }

    if (node) {
        /* delete the found node */
        sr_lyd_free_tree_safe(node, &session->dt[session->ds].edit->tree);
    } else if (opts & SR_EDIT_STRICT) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "No 'discard-items' node for \"%s\" found in session push oper data.",
                xpath);
        goto cleanup;
    }

cleanup:
    if (session->dt[session->ds].edit && !session->dt[session->ds].edit->tree) {
        sr_release_data(session->dt[session->ds].edit);
        session->dt[session->ds].edit = NULL;
    }
    return sr_api_ret(session, err_info);
}

API int
sr_move_item(sr_session_ctx_t *session, const char *path, const sr_move_position_t position, const char *list_keys,
        const char *leaflist_value, const char *UNUSED(origin), const sr_edit_options_t opts)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session || !path || !SR_IS_CONVENTIONAL_DS(session->ds), session, err_info);

    if (!session->dt[session->ds].edit) {
        /* CONTEXT LOCK */
        if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
            goto cleanup;
        }

        /* prepare edit with context lock */
        if ((err_info = _sr_acquire_data(session->conn, NULL, &session->dt[session->ds].edit))) {
            goto cleanup;
        }
    }

    /* add the operation into edit */
    err_info = sr_edit_add(session, path, NULL, opts & SR_EDIT_STRICT ? "create" : "merge",
            opts & SR_EDIT_NON_RECURSIVE ? "none" : "merge", &position, list_keys, leaflist_value, NULL,
            opts & SR_EDIT_ISOLATE);

cleanup:
    if (session->dt[session->ds].edit && !session->dt[session->ds].edit->tree) {
        sr_release_data(session->dt[session->ds].edit);
        session->dt[session->ds].edit = NULL;
    }
    return sr_api_ret(session, err_info);
}

API int
sr_edit_batch(sr_session_ctx_t *session, const struct lyd_node *edit, const char *default_operation)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *iter;
    struct lyd_node *dup_edit = NULL, *root, *elem, *dup;
    struct lyd_node_opaq *opaq;
    enum edit_op op, def_op;
    char *val_json;

    SR_CHECK_ARG_APIRET(!session || !edit || !default_operation || !SR_IS_STANDARD_DS(session->ds), session, err_info);
    SR_CHECK_ARG_APIRET(strcmp(default_operation, "merge") && strcmp(default_operation, "replace") &&
            ((session->ds == SR_DS_OPERATIONAL) || strcmp(default_operation, "none")), session, err_info);
    LY_LIST_FOR(edit, iter) {
        if (lysc_data_parent(iter->schema)) {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Edit must be a top-level data tree.");
            goto cleanup;
        }
    }

    if (session->dt[session->ds].edit) {
        /* do not allow merging NETCONF edits into sysrepo ones, it can cause some unexpected results */
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "There are already some session changes.");
        goto cleanup;
    }

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
        goto cleanup;
    }

    if (session->conn->ly_ctx != LYD_CTX(edit)) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Data trees must be created using the session connection libyang context.");
        goto cleanup_unlock;
    }

    if ((err_info = sr_lyd_dup(edit, NULL, LYD_DUP_RECURSIVE, 1, &dup_edit))) {
        goto cleanup_unlock;
    }

    if (session->ds == SR_DS_OPERATIONAL) {
        /* check discard-items nodes */
        LY_LIST_FOR_SAFE(dup_edit, elem, root) {
            if (!lyd_node_module(root) || strcmp(lyd_node_module(root)->name, "sysrepo") ||
                    strcmp(LYD_NAME(root), "discard-items")) {
                continue;
            }

            opaq = (struct lyd_node_opaq *)root;
            if (opaq->format != LY_VALUE_JSON) {
                /* always have the xpath in JSON format, avoids hassle with later conversions */
                opaq = (struct lyd_node_opaq *)root;
                if ((err_info = sr_ly_canonize_xpath10_value(session->conn->ly_ctx, lyd_get_value(root),
                        opaq->format, opaq->val_prefix_data, &val_json))) {
                    goto cleanup_unlock;
                }

                /* insert the opaq node in JSON format and free the previous one */
                err_info = sr_lyd_new_opaq(session->conn->ly_ctx, LYD_NAME(root), val_json, NULL, "sysrepo", &dup);
                free(val_json);
                if (err_info) {
                    goto cleanup_unlock;
                }
                if ((err_info = sr_lyd_insert_sibling(dup_edit, dup, &dup_edit))) {
                    goto cleanup_unlock;
                }
                sr_lyd_free_tree_safe(root, &dup_edit);
            }
        }
    }

    /* add default operation and default origin */
    def_op = sr_edit_str2op(default_operation);
    LY_LIST_FOR(dup_edit, root) {
        /* check operations and set the default operation if none set */
        if (!(op = sr_edit_diff_find_oper(root, 0, NULL))) {
            if ((err_info = sr_edit_set_oper(root, default_operation))) {
                goto cleanup_unlock;
            }
        } else if ((session->ds == SR_DS_OPERATIONAL) && (op != def_op)) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Mixed operations for operational datastore changes.");
            goto cleanup_unlock;
        }

        if (session->ds == SR_DS_OPERATIONAL) {
            /* set origin */
            if ((err_info = sr_edit_diff_set_origin(root, SR_OPER_ORIGIN, 0))) {
                goto cleanup_unlock;
            }

            /* check that no nested operations are set */
            LYD_TREE_DFS_BEGIN(root, elem) {
                if ((elem != root) && sr_edit_diff_find_oper(elem, 0, NULL)) {
                    sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Nested operations are not allowed for operational "
                            "datastore changes.");
                    goto cleanup_unlock;
                }

                LYD_TREE_DFS_END(root, elem);
            }
        }
    }

    /* store edit in the session, keep context lock */
    if ((err_info = _sr_acquire_data(session->conn, dup_edit, &session->dt[session->ds].edit))) {
        goto cleanup;
    }
    dup_edit = NULL;
    goto cleanup;

cleanup_unlock:
    /* CONTEXT UNLOCK */
    sr_lycc_unlock(session->conn, SR_LOCK_READ, 0, __func__);

cleanup:
    if (session->ds == SR_DS_OPERATIONAL) {
        /* remember that oper changes have been fetched */
        session->oper_edit_fetched = !!session->dt[session->ds].edit;
    }

    lyd_free_siblings(dup_edit);
    return sr_api_ret(session, err_info);
}

API int
sr_validate(sr_session_ctx_t *session, const char *module_name, uint32_t timeout_ms)
{
    sr_error_info_t *err_info = NULL, *err_info2 = NULL;
    const struct lys_module *ly_mod = NULL;
    const struct lyd_node *node, *edit;
    struct sr_mod_info_s mod_info;

    SR_CHECK_ARG_APIRET(!session || !SR_IS_STANDARD_DS(session->ds), session, err_info);

    if (!timeout_ms) {
        timeout_ms = SR_OPER_CB_TIMEOUT;
    }
    /* for operational, use operational and running datastore */
    SR_MODINFO_INIT(mod_info, session->conn, session->ds, session->ds == SR_DS_OPERATIONAL ? SR_DS_RUNNING : session->ds, 0);

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }
    edit = session->dt[session->ds].edit ? session->dt[session->ds].edit->tree : NULL;

    if (module_name) {
        /* try to find this module */
        ly_mod = ly_ctx_get_module_implemented(session->conn->ly_ctx, module_name);
        if (!ly_mod) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
            goto cleanup;
        }
    }

    switch (session->ds) {
    case SR_DS_STARTUP:
    case SR_DS_RUNNING:
        if (!edit) {
            /* nothing to validate */
            goto cleanup;
        }

        if (ly_mod) {
            /* check that there are some changes for this module */
            LY_LIST_FOR(edit, node) {
                if (lyd_owner_module(node) == ly_mod) {
                    break;
                }
            }
            if (!node) {
                /* nothing to validate */
                goto cleanup;
            }

            if ((err_info = sr_modinfo_add(ly_mod, NULL, 0, 0, &mod_info))) {
                goto cleanup;
            }
        } else {
            /* collect all modified modules (other modules must be valid) */
            if ((err_info = sr_modinfo_collect_edit(edit, &mod_info))) {
                goto cleanup;
            }
        }
        break;
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        /* specific module/all modules */
        if (ly_mod) {
            if ((err_info = sr_modinfo_add(ly_mod, NULL, 0, 0, &mod_info))) {
                goto cleanup;
            }
        } else {
            if ((err_info = sr_modinfo_add_all_modules_with_data(session->conn->ly_ctx, 0, &mod_info))) {
                goto cleanup;
            }
        }
        break;
    case SR_DS_FACTORY_DEFAULT:
        SR_ERRINFO_INT(&err_info);
        goto cleanup;
    }

    /* add modules into mod_info with deps, locking, and their data (we need inverse dependencies because the data will
     * likely be changed) */
    if ((err_info = sr_modinfo_consolidate(&mod_info, SR_LOCK_READ, SR_MI_INV_DEPS | SR_MI_PERM_NO, session,
            timeout_ms, 0, 0))) {
        goto cleanup;
    }

    /* apply any changes */
    if ((err_info = sr_modinfo_edit_apply(&mod_info, edit, 0, &err_info2))) {
        goto cleanup;
    }

    /* collect dependencies for validation and add those to mod_info as well (after we have the final data that will
     * be validated) */
    if ((err_info = sr_modinfo_collect_deps(&mod_info))) {
        goto cleanup;
    }
    if ((err_info = sr_modinfo_consolidate(&mod_info, SR_LOCK_READ, SR_MI_NEW_DEPS | SR_MI_PERM_NO, session,
            timeout_ms, 0, 0))) {
        goto cleanup;
    }

    /* validate the data trees */
    switch (session->ds) {
    case SR_DS_STARTUP:
    case SR_DS_RUNNING:
        /* validate only changed modules and any that can become invalid because of the changes */
        if ((err_info = sr_modinfo_validate(&mod_info, MOD_INFO_CHANGED | MOD_INFO_INV_DEP, 0, &err_info2))) {
            goto cleanup;
        }
        break;
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        /* validate all the modules because they may be invalid without any changes */
        if ((err_info = sr_modinfo_validate(&mod_info, MOD_INFO_REQ | MOD_INFO_INV_DEP, 0, &err_info2))) {
            goto cleanup;
        }
        break;
    case SR_DS_FACTORY_DEFAULT:
        SR_ERRINFO_INT(&err_info);
        goto cleanup;
    }

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    sr_modinfo_erase(&mod_info);

    /* CONTEXT UNLOCK */
    sr_lycc_unlock(session->conn, SR_LOCK_READ, 0, __func__);

    if (err_info2) {
        /* return validation errors if some were generated */
        sr_errinfo_merge(&err_info, err_info2);
    }
    return sr_api_ret(session, err_info);
}

sr_error_info_t *
sr_changes_notify_store(struct sr_mod_info_s *mod_info, sr_session_ctx_t *session, int shmmod_session_del,
        uint32_t timeout_ms, sr_error_info_t **err_info2)
{
    sr_error_info_t *err_info = NULL;
    struct sr_denied denied = {0};
    sr_lock_mode_t change_sub_lock = SR_LOCK_NONE;
    uint32_t sid = 0, err_count;
    char *orig_name = NULL;
    void *orig_data = NULL;

    /* get session info */
    if (session) {
        sid = session->sid;
        orig_name = session->orig_name;
        orig_data = session->orig_data;
    }

    if (!mod_info->notify_diff) {
        /* Only log if called by sr_apply_changes not sr_session_stop and have no changes to apply */
        if (!sr_modinfo_is_changed(mod_info) && !shmmod_session_del) {
            SR_LOG_DBG("No \"%s\" datastore changes to apply.", sr_ds2str(mod_info->ds));
        }
        goto store;
    }

    if (session && session->nacm_user) {
        /* check NACM */
        if ((err_info = sr_nacm_check_diff(session->nacm_user, mod_info->ds_diff, &denied))) {
            goto cleanup;
        }

        if (denied.denied) {
            /* access denied, print detailed reason and generate more generic NETCONF error */
            if (denied.rule_name) {
                sr_log(SR_LL_ERR, "NACM access denied by the rule \"%s\".", denied.rule_name);
            } else if (denied.def) {
                sr_log(SR_LL_ERR, "NACM access denied by \"%s\" node extension \"%s\".", LYD_NAME(denied.node),
                        denied.def->name);
            } else {
                sr_log(SR_LL_ERR, "NACM access denied by the default NACM permissions.");
            }

            sr_errinfo_new_nacm(&err_info, "protocol", "access-denied", NULL, denied.node,
                    "Access to the data model \"%s\" is denied because \"%s\" NACM authorization failed.",
                    denied.node->schema->module->name, session->nacm_user);
            goto cleanup;
        }
    }

    /* validate new data trees */
    switch (mod_info->ds) {
    case SR_DS_STARTUP:
    case SR_DS_RUNNING:
        /* collect validation dependencies and add those to mod_info as well */
        if ((err_info = sr_modinfo_collect_deps(mod_info))) {
            goto cleanup;
        }
        if ((err_info = sr_modinfo_consolidate(mod_info, SR_LOCK_READ, SR_MI_NEW_DEPS | SR_MI_PERM_NO, session, 0, 0, 0))) {
            goto cleanup;
        }

        /* finish on validation errors */
        err_count = *err_info2 ? (*err_info2)->err_count : 0;
        if ((err_info = sr_modinfo_validate(mod_info, MOD_INFO_CHANGED | MOD_INFO_INV_DEP, 1, err_info2))) {
            goto cleanup;
        } else if (*err_info2 && ((*err_info2)->err_count > err_count)) {
            goto cleanup;
        }
        break;
    case SR_DS_CANDIDATE:
        /* does not have to be valid but we need all default values and no state data */
        if ((err_info = sr_modinfo_add_defaults(mod_info, 1))) {
            goto cleanup;
        }

        /* finish on validation errors */
        err_count = *err_info2 ? (*err_info2)->err_count : 0;
        if ((err_info = sr_modinfo_check_state_data(mod_info, err_info2))) {
            goto cleanup;
        } else if (*err_info2 && ((*err_info2)->err_count > err_count)) {
            goto cleanup;
        }
        break;
    case SR_DS_OPERATIONAL:
        /* does not need to be valid */
        break;
    case SR_DS_FACTORY_DEFAULT:
        SR_ERRINFO_INT(&err_info);
        goto cleanup;
    }

    if (!mod_info->notify_diff) {
        /* diff can disappear after validation */
        SR_LOG_DBG("No \"%s\" datastore changes to apply after validation.", sr_ds2str(mod_info->ds));
        goto store;
    }

    /* check write perm (we must wait until after validation, some additional modules can be modified) */
    if ((err_info = sr_modinfo_perm_check(mod_info, 1, 1))) {
        goto cleanup;
    }

    /* CHANGE SUB READ LOCK */
    if ((err_info = sr_modinfo_changesub_rdlock(mod_info))) {
        goto cleanup;
    }
    change_sub_lock = SR_LOCK_READ;

    /* first publish "update" event for the diff to be updated */
    if ((err_info = sr_modinfo_change_notify_update(mod_info, session, timeout_ms, &change_sub_lock, err_info2)) ||
            *err_info2) {
        goto cleanup;
    }

    if (!mod_info->notify_diff) {
        SR_LOG_DBG("No \"%s\" datastore changes to apply after update.", sr_ds2str(mod_info->ds));
        goto store;
    }

    /* publish final diff in a "change" event for any subscribers and wait for them */
    if ((err_info = sr_shmsub_change_notify_change(mod_info, orig_name, orig_data, timeout_ms, err_info2))) {
        goto cleanup;
    }
    if (*err_info2) {
        /* "change" event failed, publish "abort" event and finish */
        err_info = sr_shmsub_change_notify_change_abort(mod_info, orig_name, orig_data, timeout_ms);
        goto cleanup;
    }

store:
    if (!mod_info->notify_diff && !sr_modinfo_is_changed(mod_info) && !shmmod_session_del) {
        /* there is no diff and no changed modules, and we are not stopping the session, nothing to store */
        goto cleanup;
    }

    /* MODULES WRITE LOCK (upgrade) */
    if ((err_info = sr_shmmod_modinfo_rdlock_upgrade(mod_info, sid, timeout_ms, timeout_ms))) {
        goto cleanup;
    }

    /* store updated datastore or remove left over session in Ext SHM if deleting */
    if ((err_info = sr_modinfo_data_store(mod_info, session, shmmod_session_del))) {
        goto cleanup;
    }

    /* MODULES READ LOCK (downgrade) */
    if ((err_info = sr_shmmod_modinfo_wrlock_downgrade(mod_info, sid, timeout_ms))) {
        goto cleanup;
    }

    /* publish "done" event, all changes were applied */
    if ((err_info = sr_shmsub_change_notify_change_done(mod_info, orig_name, orig_data, timeout_ms))) {
        goto cleanup;
    }

    /* generate netconf-config-change notification */
    if (session && (err_info = sr_modinfo_generate_config_change_notif(mod_info, session))) {
        goto cleanup;
    }

cleanup:
    if (change_sub_lock) {
        assert(change_sub_lock == SR_LOCK_READ);

        /* CHANGE SUB READ UNLOCK */
        sr_modinfo_changesub_rdunlock(mod_info);
    }

    free(denied.rule_name);
    return err_info;
}

/**
 * @brief Apply operational DS changes.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] session Originator session.
 * @param[in] ly_mod Optional module to limit the operation to.
 * @param[in] timeout_ms Timeout in milliseconds.
 * @param[in] shmmod_session_del If set when discarding oper data, delete the push oper entry in mod SHM for this
 * session and module.
 * @param[out] err_info2 Validation errors or callback error information generated by a subscriber, if any.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_apply_oper_changes(struct sr_mod_info_s *mod_info, sr_session_ctx_t *session, const struct lys_module *ly_mod,
        int shmmod_session_del, uint32_t timeout_ms, sr_error_info_t **err_info2)
{
    sr_error_info_t *err_info = NULL;
    sr_data_t *old_oper_data = NULL;
    struct lyd_node *data_diff = NULL, *old_oper_ds = NULL, *new_oper_data = NULL;
    const struct lyd_node *oper_edit;
    uint32_t mi_opts, i;
    int update_sm_data = 0;

    assert(session && (session->ds == SR_DS_OPERATIONAL));

    *err_info2 = NULL;
    oper_edit = session->dt[session->ds].edit ? session->dt[session->ds].edit->tree : NULL;

    /* collect all the modules with push oper data */
    if ((err_info = sr_modinfo_collect_oper_sess(session, ly_mod, mod_info))) {
        goto cleanup;
    }
    if (oper_edit && (err_info = sr_modinfo_collect_edit(oper_edit, mod_info))) {
        goto cleanup;
    }

    /* add modules into mod_info, locking, and data */
    mi_opts = SR_MI_LOCK_UPGRADEABLE | SR_MI_PERM_NO;
    if ((err_info = sr_modinfo_consolidate(mod_info, SR_LOCK_READ, mi_opts, session, 0, 0, 0))) {
        goto cleanup;
    }

    /* generate the DS diff, data, and learn what modules are changed */
    if ((err_info = sr_modinfo_oper_ds_diff(mod_info, oper_edit))) {
        goto cleanup;
    }
    new_oper_data = mod_info->data;
    mod_info->data = NULL;

    /* get the operational DS data with the old push oper data */
    if ((err_info = sr_modinfo_get_oper_data(mod_info, session, NULL))) {
        goto cleanup;
    }

    /* now have old (current) relevant operational DS data */
    old_oper_ds = mod_info->data;
    mod_info->data = NULL;

    /* get the operational DS data with the new push oper data */
    if ((err_info = sr_modinfo_get_oper_data(mod_info, session, &new_oper_data))) {
        goto cleanup;
    }

    /* create the notify diff and use the new session oper data */
    if ((err_info = sr_modinfo_oper_notify_diff(mod_info, &old_oper_ds))) {
        goto cleanup;
    }
    lyd_free_siblings(mod_info->data);
    mod_info->data = new_oper_data;
    new_oper_data = NULL;

    /* check for oper changes in schema-mount data */
    for (i = 0; i < mod_info->mod_count; ++i) {
        if (!strcmp(mod_info->mods[i].ly_mod->name, "ietf-yang-schema-mount")) {
            update_sm_data = 1;
            break;
        }
    }

    /* notify all the subscribers and store the changes */
    if ((err_info = sr_changes_notify_store(mod_info, session, shmmod_session_del, timeout_ms, err_info2))) {
        goto cleanup;
    } else if (*err_info2) {
        goto cleanup;
    }

    if (update_sm_data) {
        /* operational schema-mount data were changed, update them in the connection */
        if ((err_info = sr_conn_ext_data_update(session->conn))) {
            goto cleanup;
        }
    }

cleanup:
    sr_release_data(old_oper_data);
    lyd_free_siblings(data_diff);
    lyd_free_siblings(old_oper_ds);
    lyd_free_siblings(new_oper_data);

    return err_info;
}

API int
sr_apply_changes(sr_session_ctx_t *session, uint32_t timeout_ms)
{
    sr_error_info_t *err_info = NULL, *err_info2 = NULL;
    struct sr_mod_info_s mod_info;
    uint32_t mi_opts;

    SR_CHECK_ARG_APIRET(!session || !SR_IS_STANDARD_DS(session->ds), session, err_info);

    if (session->ds == SR_DS_OPERATIONAL) {
        /* if no operational ds edit was fetched, we don't have any staged changes to apply */
        if (!session->oper_edit_fetched) {
            return sr_api_ret(session, NULL);
        }
    } else if (!session->dt[session->ds].edit) {
        return sr_api_ret(session, NULL);
    }

    if (!timeout_ms) {
        timeout_ms = SR_CHANGE_CB_TIMEOUT;
    }

    /* prepare mod_info */
    SR_MODINFO_INIT(mod_info, session->conn, session->ds, session->ds, 0);

    if (session->ds == SR_DS_OPERATIONAL) {
        /* handle specially */
        err_info = sr_apply_oper_changes(&mod_info, session, NULL, 0, timeout_ms, &err_info2);
        goto cleanup;
    }

    mi_opts = SR_MI_LOCK_UPGRADEABLE | SR_MI_PERM_NO;
    if (session->ds != SR_DS_CANDIDATE) {
        mi_opts |= SR_MI_INV_DEPS;
    } /* else candidate data are not validated so we do not need data from other modules */

    /* collect all required modules */
    if ((err_info = sr_modinfo_collect_edit(session->dt[session->ds].edit->tree, &mod_info))) {
        goto cleanup;
    }

    /* add modules into mod_info with deps, locking, and their data */
    if ((err_info = sr_modinfo_consolidate(&mod_info, SR_LOCK_READ, mi_opts, session, 0, 0, 0))) {
        goto cleanup;
    }

    /* create diff */
    if ((err_info = sr_modinfo_edit_apply(&mod_info, session->dt[session->ds].edit->tree, 1, &err_info2))) {
        goto cleanup;
    }

    /* notify all the subscribers and store the changes */
    if ((err_info = sr_changes_notify_store(&mod_info, session, 0, timeout_ms, &err_info2))) {
        goto cleanup;
    } else if (err_info2) {
        goto cleanup;
    }

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);
    sr_modinfo_erase(&mod_info);

    if (!err_info && !err_info2) {
        /* free applied edit */
        sr_release_data(session->dt[session->ds].edit);
        session->dt[session->ds].edit = NULL;
        if (session->ds == SR_DS_OPERATIONAL) {
            /* A new edit should call sr_get_oper_changes() to fetch pushed oper data */
            session->oper_edit_fetched = 0;
        }
    }
    if (err_info2) {
        /* return callback error if some was generated */
        sr_errinfo_merge(&err_info, err_info2);
    }
    SR_LOG_DBG("Applying \"%s\" datastore changes %s.", sr_ds2str(session->ds), err_info ? "failed" : "success");
    return sr_api_ret(session, err_info);
}

API int
sr_has_changes(sr_session_ctx_t *session)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session || !SR_IS_STANDARD_DS(session->ds), session, err_info);

    if (session->dt[session->ds].edit) {
        return 1;
    }

    return 0;
}

API const struct lyd_node *
sr_get_changes(sr_session_ctx_t *session)
{
    if (!session || !SR_IS_STANDARD_DS(session->ds)) {
        return NULL;
    }

    if (!session->dt[session->ds].edit) {
        return NULL;
    }

    return session->dt[session->ds].edit->tree;
}

API int
sr_discard_changes(sr_session_ctx_t *session)
{
    return sr_discard_changes_xpath(session, NULL);
}

API int
sr_discard_changes_xpath(sr_session_ctx_t *session, const char *xpath)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set = NULL;
    uint32_t i;

    SR_CHECK_ARG_APIRET(!session || !SR_IS_STANDARD_DS(session->ds), session, err_info);

    if (!session->dt[session->ds].edit) {
        /* nothing to do */
        goto cleanup;
    }

    if (!xpath) {
        /* discard all the changes */
        sr_release_data(session->dt[session->ds].edit);
        session->dt[session->ds].edit = NULL;
        goto cleanup;
    }

    /* select all the changes */
    if ((err_info = sr_lyd_find_xpath(session->dt[session->ds].edit->tree, xpath, &set))) {
        goto cleanup;
    }

    /* get rid of all redundant results that are descendants of another result */
    if ((err_info = sr_xpath_set_filter_subtrees(set))) {
        goto cleanup;
    }

    /* free the selected changes */
    for (i = 0; i < set->count; ++i) {
        sr_lyd_free_tree_safe(set->dnodes[i], &session->dt[session->ds].edit->tree);
    }
    if (!session->dt[session->ds].edit->tree) {
        /* free the envelope if no edit left */
        sr_release_data(session->dt[session->ds].edit);
        session->dt[session->ds].edit = NULL;
    }

cleanup:
    if ((session->ds == SR_DS_OPERATIONAL) && !session->dt[session->ds].edit) {
        /* no current stored data is fetched into the session */
        session->oper_edit_fetched = 0;
    }

    ly_set_free(set, NULL);
    return sr_api_ret(session, err_info);
}

/**
 * @brief Replace config data of all or some modules.
 *
 * @param[in] session Session to use.
 * @param[in] ly_mod Optional specific module.
 * @param[in] operation_id Operation ID.
 * @param[in,out] src_config Source data for the replace, they are spent.
 * @param[in] timeout_ms Change callback timeout in milliseconds.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
_sr_replace_config(sr_session_ctx_t *session, const struct lys_module *ly_mod, uint32_t operation_id,
        struct lyd_node **src_config, uint32_t timeout_ms)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    struct sr_mod_info_s mod_info;

    assert(!*src_config || !(*src_config)->prev->next);
    assert(session->ds != SR_DS_OPERATIONAL);
    SR_MODINFO_INIT(mod_info, session->conn, session->ds, session->ds, operation_id);

    /* single module/all modules */
    if (ly_mod) {
        if ((err_info = sr_modinfo_add(ly_mod, NULL, 0, 0, &mod_info))) {
            goto cleanup;
        }
    } else {
        if ((err_info = sr_modinfo_add_all_modules_with_data(session->conn->ly_ctx, 0, &mod_info))) {
            goto cleanup;
        }
    }

    /* add modules with dependencies into mod_info */
    if ((err_info = sr_modinfo_consolidate(&mod_info, SR_LOCK_READ, SR_MI_INV_DEPS | SR_MI_LOCK_UPGRADEABLE | SR_MI_PERM_NO,
            session, 0, 0, 0))) {
        goto cleanup;
    }

    /* update affected data and create corresponding diff, src_config is spent */
    if ((err_info = sr_modinfo_replace(&mod_info, src_config))) {
        goto cleanup;
    }

    /* notify all the subscribers and store the changes */
    err_info = sr_changes_notify_store(&mod_info, session, 0, timeout_ms, &cb_err_info);

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    sr_modinfo_erase(&mod_info);
    if (cb_err_info) {
        /* return callback error if some was generated */
        assert(!err_info);
        err_info = cb_err_info;
    }
    return err_info;
}

API int
sr_replace_config(sr_session_ctx_t *session, const char *module_name, struct lyd_node *src_config, uint32_t timeout_ms)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod = NULL;

    /* SR_CHECK_ARG_APIRET but we need to free src_config */
    if (!session || !SR_IS_CONVENTIONAL_DS(session->ds)) {
        sr_errinfo_new(&(err_info), SR_ERR_INVAL_ARG, "Invalid arguments for function \"%s\".", __func__);
        goto cleanup;
    }

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
        goto cleanup;
    }

    if (src_config && (session->conn->ly_ctx != LYD_CTX(src_config))) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Data trees must be created using the session connection libyang context.");
        goto cleanup_unlock;
    }

    if (!timeout_ms) {
        timeout_ms = SR_CHANGE_CB_TIMEOUT;
    }

    /* find first sibling */
    src_config = lyd_first_sibling(src_config);

    if (module_name) {
        /* try to find this module */
        ly_mod = ly_ctx_get_module_implemented(session->conn->ly_ctx, module_name);
        if (!ly_mod) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
            goto cleanup_unlock;
        } else if (!strcmp(ly_mod->name, "sysrepo")) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Data of internal module \"sysrepo\" cannot be modified.");
            goto cleanup_unlock;
        }
    }

    /* replace the data */
    if ((err_info = _sr_replace_config(session, ly_mod, 0, &src_config, timeout_ms))) {
        goto cleanup_unlock;
    }

cleanup_unlock:
    /* CONTEXT UNLOCK */
    sr_lycc_unlock(session->conn, SR_LOCK_READ, 0, __func__);

cleanup:
    lyd_free_all(src_config);
    return sr_api_ret(session, err_info);
}

API int
sr_copy_config(sr_session_ctx_t *session, const char *module_name, sr_datastore_t src_datastore, uint32_t timeout_ms)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_s mod_info;
    const struct lys_module *ly_mod = NULL;

    SR_CHECK_ARG_APIRET(!session || !SR_IS_CONVENTIONAL_DS(src_datastore) || !SR_IS_CONVENTIONAL_DS(session->ds),
            session, err_info);

    if (src_datastore == session->ds) {
        /* nothing to do */
        return sr_api_ret(session, NULL);
    }

    if (!timeout_ms) {
        timeout_ms = SR_CHANGE_CB_TIMEOUT;
    }
    if ((src_datastore == SR_DS_RUNNING) && (session->ds == SR_DS_CANDIDATE)) {
        /* discard-changes, need no data, but lock running for READ and candidate for WRITE */
        SR_MODINFO_INIT(mod_info, session->conn, session->ds, src_datastore, 0);
    } else {
        SR_MODINFO_INIT(mod_info, session->conn, src_datastore, src_datastore, 0);
    }

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    if (module_name) {
        /* try to find this module */
        ly_mod = ly_ctx_get_module_implemented(session->conn->ly_ctx, module_name);
        if (!ly_mod) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
            goto cleanup;
        } else if (!strcmp(ly_mod->name, "sysrepo")) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Data of internal module \"sysrepo\" cannot be modified.");
            goto cleanup;
        }
    }

    /* collect all required modules */
    if (ly_mod) {
        if ((err_info = sr_modinfo_add(ly_mod, NULL, 0, 0, &mod_info))) {
            goto cleanup;
        }
    } else {
        if ((err_info = sr_modinfo_add_all_modules_with_data(session->conn->ly_ctx, 0, &mod_info))) {
            goto cleanup;
        }
    }

    if ((src_datastore == SR_DS_RUNNING) && (session->ds == SR_DS_CANDIDATE)) {
        /* add modules into mod_info without data */
        if ((err_info = sr_modinfo_consolidate(&mod_info, SR_LOCK_WRITE, SR_MI_DATA_NO | SR_MI_PERM_NO, session, 0, 0, 0))) {
            goto cleanup;
        }

        /* special case, just reset candidate, no NACM checks (ref https://datatracker.ietf.org/doc/html/rfc8341#section-3.2.9) */
        err_info = sr_modinfo_candidate_reset(&mod_info);
        goto cleanup;
    }

    if ((src_datastore == SR_DS_CANDIDATE) && (session->ds == SR_DS_RUNNING)) {
        /* add modules into mod_info, WRITE lock */
        if ((err_info = sr_modinfo_consolidate(&mod_info, SR_LOCK_WRITE, SR_MI_PERM_NO, session, 0, 0, 0))) {
            goto cleanup;
        }

        /* replace the data */
        if ((err_info = _sr_replace_config(session, ly_mod, mod_info.operation_id, &mod_info.data, timeout_ms))) {
            goto cleanup;
        }

        /* reset candidate after it was applied in running */
        if ((err_info = sr_modinfo_candidate_reset(&mod_info))) {
            goto cleanup;
        }
    } else {
        /* add modules into mod_info, READ lock */
        if ((err_info = sr_modinfo_consolidate(&mod_info, SR_LOCK_READ, SR_MI_PERM_NO, session, 0, 0, 0))) {
            goto cleanup;
        }

        /* MODULES UNLOCK */
        sr_shmmod_modinfo_unlock(&mod_info);

        /* replace the data */
        if ((err_info = _sr_replace_config(session, ly_mod, mod_info.operation_id, &mod_info.data, timeout_ms))) {
            goto cleanup;
        }
    }

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    sr_modinfo_erase(&mod_info);

    /* CONTEXT UNLOCK */
    sr_lycc_unlock(session->conn, SR_LOCK_READ, 0, __func__);
    return sr_api_ret(session, err_info);
}

/**
 * @brief Discard push operational changes of a module for a session.
 *
 * @param[in] session Session to use.
 * @param[in] module_name Optional module name that limits the operation only to this module.
 * @param[in] shmmod_session_del Whether this discard should cause the push oper entry in mod SHM for this session and
 * module to be deleted.
 * @param[in] timeout_ms Module change callback timeout in millisecond. If 0, default is used.
 * @return Error code (::SR_ERR_OK on success).
 */
static int
_sr_discard_oper_changes(sr_session_ctx_t *session, const char *module_name, int shmmod_session_del, uint32_t timeout_ms)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    struct sr_mod_info_s mod_info;
    const struct lys_module *ly_mod = NULL;
    sr_datastore_t prev_ds;

    assert(session && (!shmmod_session_del || !module_name));

    if (!timeout_ms) {
        timeout_ms = SR_CHANGE_CB_TIMEOUT;
    }
    SR_MODINFO_INIT(mod_info, session->conn, SR_DS_OPERATIONAL, SR_DS_OPERATIONAL, 0);

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
        goto cleanup;
    }

    if (module_name) {
        /* try to find this module */
        ly_mod = ly_ctx_get_module_implemented(session->conn->ly_ctx, module_name);
        if (!ly_mod) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
            goto cleanup;
        }
    }

    /* discard oper changes */
    prev_ds = session->ds;
    session->ds = SR_DS_OPERATIONAL;
    err_info = sr_apply_oper_changes(&mod_info, session, ly_mod, shmmod_session_del, timeout_ms, &cb_err_info);
    session->ds = prev_ds;

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    sr_modinfo_erase(&mod_info);

    /* CONTEXT UNLOCK */
    sr_lycc_unlock(session->conn, SR_LOCK_READ, 0, __func__);
    if (cb_err_info) {
        /* return callback error if some was generated */
        assert(!err_info);
        err_info = cb_err_info;
    }
    return sr_api_ret(NULL, err_info);
}

API int
sr_discard_oper_changes(sr_conn_ctx_t *UNUSED(conn), sr_session_ctx_t *session, const char *module_name,
        uint32_t timeout_ms)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session, NULL, err_info);

    if (session->dt[SR_DS_OPERATIONAL].edit) {
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "There are already staged changes. Call 'sr_discard_changes()' to remove them first.");
        return sr_api_ret(session, err_info);
    }

    return _sr_discard_oper_changes(session, module_name, 0, timeout_ms);
}

API int
sr_get_oper_changes(sr_session_ctx_t *session, const char *module_name, sr_data_t **data)
{
    sr_error_info_t *err_info = NULL;
    sr_conn_ctx_t *conn = session->conn;
    struct sr_mod_info_s mod_info;
    const struct lys_module *ly_mod = NULL;

    SR_CHECK_ARG_APIRET(!session || !data, NULL, err_info);

    *data = NULL;

    if (!session->oper_push_mod_count) {
        return sr_api_ret(session, err_info);
    }

    SR_MODINFO_INIT(mod_info, conn, SR_DS_OPERATIONAL, SR_DS_OPERATIONAL, 0);

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    /* prepare data wrapper */
    if ((err_info = _sr_acquire_data(conn, NULL, data))) {
        goto cleanup;
    }

    if (module_name) {
        /* try to find this module */
        ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, module_name);
        if (!ly_mod) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
            goto cleanup;
        }
    }

    /* add only modules that this session has push oper data for */
    if ((err_info = sr_modinfo_collect_oper_sess(session, ly_mod, &mod_info))) {
        goto cleanup;
    }

    if (!mod_info.mod_count) {
        /* no modules with oper push data of this session */
        goto cleanup;
    }

    /* add modules and get data */
    if ((err_info = sr_modinfo_consolidate(&mod_info, SR_LOCK_READ, SR_MI_PERM_NO, session, 0, 0, 0))) {
        goto cleanup;
    }

    /* use the data */
    (*data)->tree = mod_info.data;
    mod_info.data = NULL;

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    sr_modinfo_erase(&mod_info);

    if (err_info || !(*data)->tree) {
        sr_release_data(*data);
        *data = NULL;
    }
    return sr_api_ret(session, err_info);
}

API int
sr_set_oper_changes_order(sr_session_ctx_t *session, const char *module_name, uint32_t order)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    uint32_t i;

    SR_CHECK_ARG_APIRET(!session || !module_name || !order, NULL, err_info);

    for (i = 0; i < session->oper_push_mod_count; i++) {
        if (session->oper_push_mods[i].has_data && !strcmp(module_name, session->oper_push_mods[i].name)) {
            sr_errinfo_new(&(err_info), SR_ERR_UNSUPPORTED, "Session already has push operational data for module \"%s\"."
                    " Cannot set oper changes order.", session->oper_push_mods[i].name);
            return sr_api_ret(session, err_info);
        }
    }

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    /* try to find this module */
    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(session->conn), module_name);
    if (!shm_mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
        goto cleanup;
    }

    /* store the order in Ext SHM */
    if ((err_info = sr_shmext_oper_push_update(session->conn, shm_mod, module_name, session->sid, order, 0, SR_LOCK_NONE))) {
        goto cleanup;
    }

cleanup:
    /* CONTEXT UNLOCK */
    sr_lycc_unlock(session->conn, SR_LOCK_READ, 0, __func__);

    return sr_api_ret(NULL, err_info);
}

API int
sr_get_oper_changes_order(sr_session_ctx_t *session, const char *module_name, uint32_t *order)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;

    SR_CHECK_ARG_APIRET(!session || !module_name || !order, NULL, err_info);

    *order = 0;

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    /* try to find this module */
    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(session->conn), module_name);
    if (!shm_mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
        goto cleanup;
    }

    if ((err_info = sr_shmext_oper_push_get(session->conn, shm_mod, module_name, session->sid, order,
            NULL, SR_LOCK_NONE))) {
        goto cleanup;
    }

cleanup:
    /* CONTEXT UNLOCK */
    sr_lycc_unlock(session->conn, SR_LOCK_READ, 0, __func__);

    return sr_api_ret(NULL, err_info);
}

/**
 * @brief (Un)lock datastore locks.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] sid Sysrepo session ID.
 * @param[in] lock Whether to lock or unlock.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_change_dslock(struct sr_mod_info_s *mod_info, uint32_t sid, int lock)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    uint32_t i, j;
    int ds_lock = 0, modified;
    struct sr_mod_info_mod_s *mod;
    struct sr_mod_lock_s *shm_lock;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        shm_lock = &mod->shm_mod->data_lock_info[mod_info->ds];

        assert(mod->state & MOD_INFO_REQ);

        /* DS LOCK */
        if ((err_info = sr_mlock(&shm_lock->ds_lock, SR_DS_LOCK_MUTEX_TIMEOUT, __func__, NULL, NULL))) {
            goto error;
        }
        ds_lock = 1;

        /* it was successfully WRITE-locked, check that DS lock state is as expected */
        if (shm_lock->ds_lock_sid && lock) {
            assert(shm_lock->ds_lock_sid == sid);
            sr_errinfo_new(&err_info, SR_ERR_LOCKED, "Module \"%s\" is already locked by this session %" PRIu32 ".",
                    mod->ly_mod->name, sid);
            goto error;
        } else if (!shm_lock->ds_lock_sid && !lock) {
            sr_errinfo_new(&err_info, SR_ERR_OPERATION_FAILED, "Module \"%s\" was not locked by this session %" PRIu32 ".",
                    mod->ly_mod->name, sid);
            goto error;
        } else if (lock && (mod_info->ds == SR_DS_CANDIDATE)) {
            /* learn whether candidate was modified */
            if ((err_info = mod->ds_handle[SR_DS_CANDIDATE]->plugin->candidate_modified_cb(mod->ly_mod,
                    mod->ds_handle[SR_DS_CANDIDATE]->plg_data, &modified))) {
                goto error;
            }

            if (modified) {
                sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Module \"%s\" candidate datastore data have "
                        "already been modified.", mod->ly_mod->name);
                goto error;
            }
        }

        /* change DS lock state and remember the time */
        if (lock) {
            shm_lock->ds_lock_cid = mod_info->conn->cid;
            shm_lock->ds_lock_sid = sid;
            sr_realtime_get(&shm_lock->ds_lock_ts);
        } else {
            shm_lock->ds_lock_cid = 0;
            shm_lock->ds_lock_sid = 0;
            memset(&shm_lock->ds_lock_ts, 0, sizeof shm_lock->ds_lock_ts);
        }

        /* DS UNLOCK */
        sr_munlock(&shm_lock->ds_lock);
        ds_lock = 0;
    }

    return NULL;

error:
    if (ds_lock) {
        /* DS UNLOCK */
        sr_munlock(&shm_lock->ds_lock);
    }

    /* reverse any DS lock state changes */
    for (j = 0; j < i; ++j) {
        shm_lock = &mod_info->mods[j].shm_mod->data_lock_info[mod_info->ds];

        assert(((shm_lock->ds_lock_sid == sid) && lock) || (!shm_lock->ds_lock_sid && !lock));

        /* DS LOCK */
        if ((tmp_err = sr_mlock(&shm_lock->ds_lock, SR_DS_LOCK_MUTEX_TIMEOUT, __func__, NULL, NULL))) {
            sr_errinfo_free(&tmp_err);
        } else {
            if (lock) {
                shm_lock->ds_lock_sid = 0;
                memset(&shm_lock->ds_lock_ts, 0, sizeof shm_lock->ds_lock_ts);
            } else {
                shm_lock->ds_lock_sid = sid;
                sr_realtime_get(&shm_lock->ds_lock_ts);
            }

            /* DS UNLOCK */
            sr_munlock(&shm_lock->ds_lock);
        }
    }

    return err_info;
}

/**
 * @brief (Un)lock a specific or all modules datastore locks.
 *
 * @param[in] session Session to use.
 * @param[in] module_name Optional specific module.
 * @param[in] lock Whether to lock or unlock.
 * @param[in] timeout_ms Timeout for waiting to get DS lock, only if @p lock is set.
 * @return err_code (SR_ERR_OK on success).
 */
static int
_sr_un_lock(sr_session_ctx_t *session, const char *module_name, int lock, uint32_t timeout_ms)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_s mod_info;
    const struct lys_module *ly_mod = NULL;

    SR_CHECK_ARG_APIRET(!session || !SR_IS_CONVENTIONAL_DS(session->ds), session, err_info);

    SR_MODINFO_INIT(mod_info, session->conn, session->ds, session->ds, 1);

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    if (module_name) {
        /* try to find this module */
        ly_mod = ly_ctx_get_module_implemented(session->conn->ly_ctx, module_name);
        if (!ly_mod) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
            goto cleanup;
        }
    }

    /* collect all required modules and lock to wait until other sessions finish working with the data */
    if (ly_mod) {
        if ((err_info = sr_modinfo_add(ly_mod, NULL, 0, 0, &mod_info))) {
            goto cleanup;
        }
    } else {
        if ((err_info = sr_modinfo_add_all_modules_with_data(session->conn->ly_ctx, 0, &mod_info))) {
            goto cleanup;
        }
    }
    if ((err_info = sr_modinfo_consolidate(&mod_info, SR_LOCK_WRITE, SR_MI_DATA_NO | SR_MI_PERM_READ | SR_MI_PERM_STRICT,
            session, 0, timeout_ms, 0))) {
        goto cleanup;
    }

    /* DS-(un)lock them */
    if ((err_info = sr_change_dslock(&mod_info, session->sid, lock))) {
        goto cleanup;
    }

    /* candidate datastore unlocked, reset its state */
    if (!lock && (mod_info.ds == SR_DS_CANDIDATE)) {
        if ((err_info = sr_modinfo_candidate_reset(&mod_info))) {
            goto cleanup;
        }
    }

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    sr_modinfo_erase(&mod_info);

    /* CONTEXT UNLOCK */
    sr_lycc_unlock(session->conn, SR_LOCK_READ, 0, __func__);
    return sr_api_ret(session, err_info);
}

API int
sr_lock(sr_session_ctx_t *session, const char *module_name, uint32_t timeout_ms)
{
    return _sr_un_lock(session, module_name, 1, timeout_ms);
}

API int
sr_unlock(sr_session_ctx_t *session, const char *module_name)
{
    return _sr_un_lock(session, module_name, 0, 0);
}

API int
sr_get_lock(sr_conn_ctx_t *conn, sr_datastore_t datastore, const char *module_name, int *is_locked, uint32_t *id,
        struct timespec *timestamp)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_s mod_info;
    const struct lys_module *ly_mod = NULL;
    struct sr_mod_lock_s *shm_lock = NULL;
    uint32_t i, sid;
    struct timespec ts;
    int ds_locked;

    SR_CHECK_ARG_APIRET(!conn || !SR_IS_CONVENTIONAL_DS(datastore) || !is_locked, NULL, err_info);

    if (id) {
        *id = 0;
    }
    if (timestamp) {
        memset(timestamp, 0, sizeof *timestamp);
    }
    SR_MODINFO_INIT(mod_info, conn, datastore, datastore, 1);

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(NULL, err_info);
    }

    if (module_name) {
        /* try to find this module */
        ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, module_name);
        if (!ly_mod) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
            goto cleanup;
        }
    }

    /* collect all required modules into mod_info */
    if (ly_mod) {
        if ((err_info = sr_modinfo_add(ly_mod, NULL, 0, 0, &mod_info))) {
            goto cleanup;
        }
    } else {
        if ((err_info = sr_modinfo_add_all_modules_with_data(conn->ly_ctx, 0, &mod_info))) {
            goto cleanup;
        }
    }
    if ((err_info = sr_modinfo_consolidate(&mod_info, SR_LOCK_NONE, SR_MI_DATA_NO | SR_MI_PERM_READ |
            SR_MI_PERM_STRICT, NULL, 0, 0, 0))) {
        goto cleanup;
    }

    /* check DS-lock of the module(s) */
    ds_locked = 1;
    sid = 0;
    for (i = 0; (i < mod_info.mod_count) && ds_locked; ++i) {
        shm_lock = &mod_info.mods[i].shm_mod->data_lock_info[mod_info.ds];

        /* DS LOCK */
        if ((err_info = sr_mlock(&shm_lock->ds_lock, SR_DS_LOCK_MUTEX_TIMEOUT, __func__, NULL, NULL))) {
            goto cleanup;
        }

        if (!shm_lock->ds_lock_sid) {
            /* there is at least one module that is not DS-locked */
            ds_locked = 0;
        }

        if (ds_locked) {
            if (!sid) {
                /* remember the first DS lock information, if full DS lock held, it will be equal for all the modules */
                sid = shm_lock->ds_lock_sid;
                ts = shm_lock->ds_lock_ts;
            } else if (sid != shm_lock->ds_lock_sid) {
                /* more DS module lock owners, not a full DS lock */
                ds_locked = 0;
            }
        }

        /* DS UNLOCK */
        sr_munlock(&shm_lock->ds_lock);
    }

    if (!ds_locked) {
        /* not full DS lock */
        *is_locked = 0;
    } else if (mod_info.mod_count) {
        /* the module or all modules is DS locked by a single SR session */
        *is_locked = 1;
        if (id) {
            *id = sid;
        }
        if (timestamp) {
            *timestamp = ts;
        }
    }

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    sr_modinfo_erase(&mod_info);

    /* CONTEXT UNLOCK */
    sr_lycc_unlock(conn, SR_LOCK_READ, 0, __func__);
    return sr_api_ret(NULL, err_info);
}

API int
sr_get_event_pipe(sr_subscription_ctx_t *subscription, int *event_pipe)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!subscription || !event_pipe, NULL, err_info);

    *event_pipe = subscription->evpipe;
    return SR_ERR_OK;
}

API int
sr_subscription_process_events(sr_subscription_ctx_t *subscription, sr_session_ctx_t *session, struct timespec *wake_up_in)
{
    sr_error_info_t *err_info = NULL;
    int ret, mod_finished;
    char buf[1];
    uint32_t i;
    sr_lock_mode_t ctx_mode = SR_LOCK_NONE;

    /* session does not have to be set */
    SR_CHECK_ARG_APIRET(!subscription, session, err_info);

    if (wake_up_in) {
        memset(wake_up_in, 0, sizeof *wake_up_in);
    }

    /* get only READ lock to allow event processing even during unsubscribe */

    /* SUBS READ LOCK */
    if ((err_info = sr_rwlock(&subscription->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, subscription->conn->cid,
            __func__, NULL, NULL))) {
        return sr_api_ret(session, err_info);
    }

    /* read all bytes from the pipe, there can be several events by now */
    do {
        ret = read(subscription->evpipe, buf, 1);
    } while (ret == 1);
    if ((ret == -1) && (errno != EAGAIN)) {
        SR_ERRINFO_SYSERRNO(&err_info, "read");
        sr_errinfo_new(&err_info, SR_ERR_INTERNAL, "Failed to read from an event pipe.");
        goto cleanup_unlock;
    }

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(subscription->conn, SR_LOCK_READ, 0, __func__))) {
        goto cleanup_unlock;
    }
    ctx_mode = SR_LOCK_READ;

    /* change subscriptions */
    for (i = 0; i < subscription->change_sub_count; ++i) {
        if ((err_info = sr_shmsub_change_listen_process_module_events(&subscription->change_subs[i], subscription->conn))) {
            goto cleanup_unlock;
        }
    }

    /* operational get subscriptions */
    for (i = 0; i < subscription->oper_get_sub_count; ++i) {
        if ((err_info = sr_shmsub_oper_get_listen_process_module_events(&subscription->oper_get_subs[i], subscription->conn))) {
            goto cleanup_unlock;
        }
    }

    /* operational poll subscriptions */
    for (i = 0; i < subscription->oper_poll_sub_count; ++i) {
        if ((err_info = sr_shmsub_oper_poll_listen_process_module_events(&subscription->oper_poll_subs[i],
                subscription->conn, wake_up_in))) {
            goto cleanup_unlock;
        }
    }

    /* RPC/action subscriptions */
    for (i = 0; i < subscription->rpc_sub_count; ++i) {
        if ((err_info = sr_shmsub_rpc_listen_process_rpc_events(&subscription->rpc_subs[i], subscription->conn))) {
            goto cleanup_unlock;
        }
    }

    /* notification subscriptions */
    i = 0;
    while (i < subscription->notif_sub_count) {
        /* perform any replays requested */
        if ((err_info = sr_shmsub_notif_listen_module_replay(&subscription->notif_subs[i], subscription))) {
            goto cleanup_unlock;
        }

        /* check whether a subscription did not finish */
        mod_finished = 0;
        if ((err_info = sr_shmsub_notif_listen_module_stop_time(i, SR_LOCK_READ, subscription, &mod_finished))) {
            goto cleanup_unlock;
        }

        if (mod_finished) {
            /* all subscriptions of this module have finished, try the next */
            continue;
        }

        /* standard event processing */
        if ((err_info = sr_shmsub_notif_listen_process_module_events(&subscription->notif_subs[i], subscription->conn))) {
            goto cleanup_unlock;
        }

        /* find nearest stop time */
        sr_shmsub_notif_listen_module_get_stop_time_in(&subscription->notif_subs[i], wake_up_in);

        /* next iteration */
        ++i;
    }

cleanup_unlock:
    if (ctx_mode) {
        /* CONTEXT UNLOCK */
        sr_lycc_unlock(subscription->conn, ctx_mode, 0, __func__);
    }

    /* SUBS READ UNLOCK */
    sr_rwunlock(&subscription->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, subscription->conn->cid, __func__);

    return sr_api_ret(session, err_info);
}

API uint32_t
sr_subscription_get_last_sub_id(const sr_subscription_ctx_t *subscription)
{
    if (!subscription) {
        return 0;
    }

    return subscription->last_sub_id;
}

API int
sr_subscription_get_suspended(sr_subscription_ctx_t *subscription, uint32_t sub_id, int *suspended)
{
    sr_error_info_t *err_info = NULL;
    const char *module_name, *path;
    sr_datastore_t ds;

    SR_CHECK_ARG_APIRET(!subscription || !sub_id || !suspended, NULL, err_info);

    /* SUBS READ LOCK */
    if ((err_info = sr_rwlock(&subscription->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, subscription->conn->cid,
            __func__, NULL, NULL))) {
        return sr_api_ret(NULL, err_info);
    }

    /* find the subscription in the subscription context and read its suspended from ext SHM */
    if (sr_subscr_change_sub_find(subscription, sub_id, &module_name, &ds)) {
        /* change sub */
        if ((err_info = sr_shmext_change_sub_suspended(subscription->conn, module_name, ds, sub_id, -1, suspended))) {
            goto cleanup_unlock;
        }
    } else if (sr_subscr_oper_get_sub_find(subscription, sub_id, &module_name)) {
        /* oper get sub */
        if ((err_info = sr_shmext_oper_get_sub_suspended(subscription->conn, module_name, sub_id, -1, suspended))) {
            goto cleanup_unlock;
        }
    } else if (sr_subscr_oper_poll_sub_find(subscription, sub_id, &module_name)) {
        /* oper poll sub */
        if ((err_info = sr_shmext_oper_poll_sub_suspended(subscription->conn, module_name, sub_id, -1, suspended))) {
            goto cleanup_unlock;
        }
    } else if (sr_subscr_notif_sub_find(subscription, sub_id, &module_name)) {
        /* notif sub */
        if ((err_info = sr_shmext_notif_sub_suspended(subscription->conn, module_name, sub_id, -1, suspended))) {
            goto cleanup_unlock;
        }
    } else if (sr_subscr_rpc_sub_find(subscription, sub_id, &path)) {
        /* RPC/action sub */
        if ((err_info = sr_shmext_rpc_sub_suspended(subscription->conn, path, sub_id, -1, suspended))) {
            goto cleanup_unlock;
        }
    } else {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Subscription with ID %" PRIu32 " was not found.", sub_id);
        goto cleanup_unlock;
    }

cleanup_unlock:
    /* SUBS READ UNLOCK */
    sr_rwunlock(&subscription->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, subscription->conn->cid, __func__);

    return sr_api_ret(NULL, err_info);
}

/**
 * @brief Change suspended state of a subscription.
 *
 * @param[in] subscription Subscription context to use.
 * @param[in] sub_id Subscription notification ID.
 * @param[in] suspend Whether to suspend or resume the subscription.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
_sr_subscription_suspend_change(sr_subscription_ctx_t *subscription, uint32_t sub_id, int suspend)
{
    sr_error_info_t *err_info = NULL;
    struct modsub_notifsub_s *notif_sub = NULL;
    struct modsub_opergetsub_s *oper_get_sub;
    struct modsub_changesub_s *change_sub = NULL;
    struct modsub_operpollsub_s *operpoll_sub = NULL;
    struct opsub_rpcsub_s *rpc_sub = NULL;

    const char *module_name, *path;
    sr_datastore_t ds;
    sr_session_ctx_t *ev_sess = NULL;
    struct timespec cur_time;

    assert(subscription && sub_id);

    /* find the subscription in the subscription context and read its suspended from ext SHM */
    if ((change_sub = sr_subscr_change_sub_find(subscription, sub_id, &module_name, &ds))) {
        /* change sub */
        if ((err_info = sr_shmext_change_sub_suspended(subscription->conn, module_name, ds, sub_id, suspend, NULL))) {
            goto cleanup;
        }
        /* mark this as suspended in the subscription context as well to prevent stealing events */
        ATOMIC_STORE_RELAXED(change_sub->suspended, suspend);
    } else if ((oper_get_sub = sr_subscr_oper_get_sub_find(subscription, sub_id, &module_name))) {
        /* oper get sub */
        if ((err_info = sr_shmext_oper_get_sub_suspended(subscription->conn, module_name, sub_id, suspend, NULL))) {
            goto cleanup;
        }

        /* operational get subscriptions change */
        if ((err_info = sr_shmsub_oper_poll_get_sub_change_notify_evpipe(subscription->conn, module_name,
                oper_get_sub->path))) {
            goto cleanup;
        }
        /* mark this as suspended in the subscription context as well to prevent stealing events */
        ATOMIC_STORE_RELAXED(oper_get_sub->suspended, suspend);
    } else if ((operpoll_sub = sr_subscr_oper_poll_sub_find(subscription, sub_id, &module_name))) {
        /* oper poll sub */
        if ((err_info = sr_shmext_oper_poll_sub_suspended(subscription->conn, module_name, sub_id, suspend, NULL))) {
            goto cleanup;
        }
        /* mark this as suspended in the subscription context as well to prevent stealing events */
        ATOMIC_STORE_RELAXED(operpoll_sub->suspended, suspend);
    } else if ((notif_sub = sr_subscr_notif_sub_find(subscription, sub_id, &module_name))) {
        /* notif sub */
        if ((err_info = sr_shmext_notif_sub_suspended(subscription->conn, module_name, sub_id, suspend, NULL))) {
            goto cleanup;
        }
    } else if ((rpc_sub = sr_subscr_rpc_sub_find(subscription, sub_id, &path))) {
        /* RPC/action sub */
        if ((err_info = sr_shmext_rpc_sub_suspended(subscription->conn, path, sub_id, suspend, NULL))) {
            goto cleanup;
        }
        /* mark this as suspended in the subscription context as well to prevent stealing events */
        ATOMIC_STORE_RELAXED(rpc_sub->suspended, suspend);
    } else {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Subscription with ID %" PRIu32 " was not found.", sub_id);
        goto cleanup;
    }

    if (notif_sub) {
        /* create event session */
        if ((err_info = _sr_session_start(subscription->conn, SR_DS_OPERATIONAL, SR_SUB_EV_NOTIF, NULL, &ev_sess))) {
            goto cleanup;
        }

        /* send the special notification */
        sr_realtime_get(&cur_time);
        if ((err_info = sr_notif_call_callback(ev_sess, notif_sub->cb, notif_sub->tree_cb, notif_sub->private_data,
                suspend ? SR_EV_NOTIF_SUSPENDED : SR_EV_NOTIF_RESUMED, sub_id, NULL, &cur_time))) {
            goto cleanup;
        }
        /* mark this as suspended in the subscription context as well to prevent stealing events */
        ATOMIC_STORE_RELAXED(notif_sub->suspended, suspend);
    }

cleanup:
    sr_session_stop(ev_sess);
    return err_info;
}

API int
sr_subscription_suspend(sr_subscription_ctx_t *subscription, uint32_t sub_id)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!subscription || !sub_id, NULL, err_info);

    /* SUBS READ LOCK */
    if ((err_info = sr_rwlock(&subscription->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, subscription->conn->cid,
            __func__, NULL, NULL))) {
        return sr_api_ret(NULL, err_info);
    }

    /* suspend */
    err_info = _sr_subscription_suspend_change(subscription, sub_id, 1);

    /* SUBS READ UNLOCK */
    sr_rwunlock(&subscription->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, subscription->conn->cid, __func__);

    return sr_api_ret(NULL, err_info);
}

API int
sr_subscription_resume(sr_subscription_ctx_t *subscription, uint32_t sub_id)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!subscription || !sub_id, NULL, err_info);

    /* SUBS READ LOCK */
    if ((err_info = sr_rwlock(&subscription->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, subscription->conn->cid,
            __func__, NULL, NULL))) {
        return sr_api_ret(NULL, err_info);
    }

    /* resume */
    err_info = _sr_subscription_suspend_change(subscription, sub_id, 0);

    /* SUBS READ UNLOCK */
    sr_rwunlock(&subscription->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, subscription->conn->cid, __func__);

    return sr_api_ret(NULL, err_info);
}

API int
sr_unsubscribe_sub(sr_subscription_ctx_t *subscription, uint32_t sub_id)
{
    sr_error_info_t *err_info = NULL;

    if (!subscription) {
        return sr_api_ret(NULL, NULL);
    }

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(subscription->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(NULL, err_info);
    }

    if (sub_id) {
        err_info = sr_subscr_del_id(subscription, sub_id);
    } else {
        err_info = sr_subscr_del_all(subscription);
    }

    /* CONTEXT UNLOCK */
    sr_lycc_unlock(subscription->conn, SR_LOCK_READ, 0, __func__);

    return sr_api_ret(NULL, err_info);
}

/**
 * @brief Suspend the default handler thread of a subscription.
 *
 * @param[in] subscription Subscription structure.
 * @return 0 on success.
 * @return 1 if the thread was already suspended.
 * @return 2 if there is no thread running.
 */
static int
_sr_subscription_thread_suspend(sr_subscription_ctx_t *subscription)
{
    uint_fast32_t exp;
    int result;

    /* expect 1 and set to 2 */
    exp = 1;
    ATOMIC_COMPARE_EXCHANGE_RELAXED(subscription->thread_running, exp, 2, result);
    if (!result) {
        if (exp == 0) {
            return 2;
        } else {
            return 1;
        }
    }

    /* let the thread continue normally, no point in notifying it */

    return 0;
}

API int
sr_subscription_thread_suspend(sr_subscription_ctx_t *subscription)
{
    sr_error_info_t *err_info = NULL;
    int ret;

    SR_CHECK_ARG_APIRET(!subscription, NULL, err_info);

    ret = _sr_subscription_thread_suspend(subscription);
    if (ret == 2) {
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Subscription has no handler thread.");
        return sr_api_ret(NULL, err_info);
    } else if (ret == 1) {
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Subscription handler thread is already suspended.");
        return sr_api_ret(NULL, err_info);
    }

    return sr_api_ret(NULL, NULL);
}

API int
sr_subscription_thread_resume(sr_subscription_ctx_t *subscription)
{
    sr_error_info_t *err_info = NULL;
    uint_fast32_t exp;
    int result;

    SR_CHECK_ARG_APIRET(!subscription, NULL, err_info);

    /* expect 2 and set to 1 */
    exp = 2;
    ATOMIC_COMPARE_EXCHANGE_RELAXED(subscription->thread_running, exp, 1, result);
    if (!result) {
        if (exp == 0) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Subscription has no handler thread.");
        } else {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Subscription handler thread was not suspended.");
        }
        return sr_api_ret(NULL, err_info);
    }

    /* generate a new event for the thread to wake up */
    if ((err_info = sr_shmsub_notify_evpipe(subscription->evpipe_num, 0, NULL))) {
        return sr_api_ret(NULL, err_info);
    }

    return sr_api_ret(NULL, NULL);
}

API int
sr_subscription_thread_notify(sr_subscription_ctx_t *subscription)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!subscription, NULL, err_info);

    err_info = sr_shmsub_notify_evpipe(subscription->evpipe_num, 0, NULL);

    return sr_api_ret(NULL, err_info);
}

/**
 * @brief Unlocked unsubscribe (free) of all the subscriptions in a subscription structure.
 *
 * @param[in] subscription Subscription to unsubscribe and free.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
_sr_unsubscribe(sr_subscription_ctx_t *subscription)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    char *path;
    int ret;

    assert(subscription);

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(subscription->conn, SR_LOCK_READ, 0, __func__))) {
        return err_info;
    }

    /* delete all subscriptions which also removes this subscription from all the sessions */
    err_info = sr_subscr_del_all(subscription);

    /* CONTEXT UNLOCK */
    sr_lycc_unlock(subscription->conn, SR_LOCK_READ, 0, __func__);

    if (err_info) {
        return err_info;
    }

    /* no new events can be generated at this point */

    if (ATOMIC_LOAD_RELAXED(subscription->thread_running)) {
        /* signal the thread to quit */
        ATOMIC_STORE_RELAXED(subscription->thread_running, 0);

        /* generate a new event for the thread to wake up */
        if ((tmp_err = sr_shmsub_notify_evpipe(subscription->evpipe_num, 0, NULL))) {
            sr_errinfo_merge(&err_info, tmp_err);
        } else {
            /* join the thread */
            ret = pthread_join(subscription->tid, NULL);
            if (ret) {
                sr_errinfo_new(&err_info, SR_ERR_SYS, "Joining the subscriber thread failed (%s).", strerror(ret));
            }
        }
    }

    /* unlink event pipe */
    if ((tmp_err = sr_path_evpipe(subscription->evpipe_num, &path))) {
        /* continue */
        sr_errinfo_merge(&err_info, tmp_err);
    } else {
        ret = unlink(path);
        free(path);
        if (ret == -1) {
            SR_ERRINFO_SYSERRNO(&err_info, "unlink");
        }
    }

    /* free attributes */
    close(subscription->evpipe);
    sr_rwlock_destroy(&subscription->subs_lock);
    free(subscription);
    return err_info;
}

API int
sr_unsubscribe(sr_subscription_ctx_t *subscription)
{
    sr_error_info_t *err_info = NULL;

    if (!subscription) {
        return sr_api_ret(NULL, NULL);
    }

    err_info = _sr_unsubscribe(subscription);
    return sr_api_ret(NULL, err_info);
}

API int
sr_module_change_set_order(sr_conn_ctx_t *conn, const char *module_name, sr_datastore_t ds, uint32_t priority)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;

    SR_CHECK_ARG_APIRET(!conn || !module_name, NULL, err_info);

    /* check module existence */
    if (!(ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, module_name))) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
        goto cleanup;
    }

    /* check write perm */
    if ((err_info = sr_perm_check(conn, ly_mod, ds, 1, NULL))) {
        goto cleanup;
    }

    /* update its priority (order) */
    err_info = sr_shmmod_change_prio(conn, ly_mod, ds, priority, NULL);

cleanup:
    return sr_api_ret(NULL, err_info);
}

API int
sr_module_change_get_order(sr_conn_ctx_t *conn, const char *module_name, sr_datastore_t ds, uint32_t *priority)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;

    SR_CHECK_ARG_APIRET(!conn || !module_name || !priority, NULL, err_info);

    /* check module existence */
    if (!(ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, module_name))) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
        goto cleanup;
    }

    /* check read perm */
    if ((err_info = sr_perm_check(conn, ly_mod, ds, 0, NULL))) {
        goto cleanup;
    }

    /* read its priority (order) */
    err_info = sr_shmmod_change_prio(conn, ly_mod, ds, 0, priority);

cleanup:
    return sr_api_ret(NULL, err_info);
}

/**
 * @brief Perform enabled event on a subscription.
 *
 * @param[in] session Session to use.
 * @param[in,out] mod_info Empty mod info structure to use. If any modules were locked, they are kept that way.
 * @param[in] ly_mod Specific module.
 * @param[in] xpath Optional subscription xpath.
 * @param[in] callback Callback to call.
 * @param[in] private_data Arbitrary callback data.
 * @param[in] sub_id Subscription ID.
 * @param[in] opts Subscription options.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_module_change_subscribe_enable(sr_session_ctx_t *session, struct sr_mod_info_s *mod_info,
        const struct lys_module *ly_mod, const char *xpath, sr_module_change_cb callback, void *private_data,
        uint32_t sub_id, int opts)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *enabled_data = NULL, *node;
    sr_session_ctx_t *ev_sess = NULL;
    sr_error_t err_code;

    /* create mod_info structure with this module only, do not use cache to allow reading data in the callback
     * (avoid dead-lock) */
    if ((err_info = sr_modinfo_add(ly_mod, NULL, 0, 0, mod_info))) {
        goto cleanup;
    }
    if ((err_info = sr_modinfo_consolidate(mod_info, SR_LOCK_READ, SR_MI_PERM_NO, session, 0, 0, SR_OPER_NO_SUBS))) {
        goto cleanup;
    }

    /* start with any existing config NP containers */
    if ((err_info = sr_lyd_dup_module_np_cont(mod_info->data, ly_mod, 0, &enabled_data))) {
        goto cleanup;
    }

    /* select only the subscribed-to subtree */
    if (mod_info->data) {
        if (xpath) {
            if ((err_info = sr_lyd_get_enabled_xpath(&mod_info->data, (char **)&xpath, 1, 1, &enabled_data))) {
                goto cleanup;
            }
        } else {
            if ((err_info = sr_lyd_get_module_data(&mod_info->data, ly_mod, 0, 1, &enabled_data))) {
                goto cleanup;
            }
        }
    }

    /* these data will be presented as newly created, make such a diff */
    LY_LIST_FOR(enabled_data, node) {
        /* top-level "create" operation that is inherited */
        if ((err_info = sr_diff_set_oper(node, "create"))) {
            goto cleanup;
        }

        /* user-ordered lists need information about position */
        if ((err_info = sr_edit_created_subtree_apply_move(node))) {
            goto cleanup;
        }
    }

    /* create event session */
    if ((err_info = _sr_session_start(session->conn, session->ds, SR_SUB_EV_ENABLED, NULL, &ev_sess))) {
        goto cleanup;
    }
    ev_sess->dt[ev_sess->ds].diff = enabled_data;
    enabled_data = NULL;

    if (!(opts & SR_SUBSCR_DONE_ONLY)) {
        SR_LOG_INF("Triggering \"%s\" \"%s\" event on enabled data.", ly_mod->name, sr_ev2str(ev_sess->ev));

        /* present all changes in an "enabled" event */
        err_code = callback(ev_sess, sub_id, ly_mod->name, xpath, sr_ev2api(ev_sess->ev), mod_info->operation_id,
                private_data);
        if (err_code != SR_ERR_OK) {
            /* callback failed but it is the only one so no "abort" event is necessary */
            if (ev_sess->ev_err_info) {
                /* remember callback error info */
                sr_errinfo_merge(&err_info, ev_sess->ev_err_info);
                ev_sess->ev_err_info = NULL;
            }
            sr_errinfo_new(&err_info, SR_ERR_CALLBACK_FAILED, "Subscribing to \"%s\" changes failed.", ly_mod->name);
            goto cleanup;
        }
    }

    /* finish with a "done" event just because this event should imitate a regular change */
    ev_sess->ev = SR_SUB_EV_DONE;
    SR_LOG_INF("Triggering \"%s\" \"%s\" event on enabled data.", ly_mod->name, sr_ev2str(ev_sess->ev));
    callback(ev_sess, sub_id, ly_mod->name, xpath, sr_ev2api(ev_sess->ev), 0, private_data);

cleanup:
    sr_session_stop(ev_sess);
    lyd_free_all(enabled_data);
    return err_info;
}

/**
 * @brief Allocate and start listening on a new subscription.
 *
 * @param[in] conn Connection to use.
 * @param[in] opts Subscription options.
 * @param[out] subs_p Allocated subscription.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_subscr_new(sr_conn_ctx_t *conn, sr_subscr_options_t opts, sr_subscription_ctx_t **subs_p)
{
    sr_error_info_t *err_info = NULL;
    char *path = NULL;
    int ret;

    assert(!*subs_p);

    /* allocate new subscription */
    *subs_p = calloc(1, sizeof **subs_p);
    SR_CHECK_MEM_RET(!*subs_p, err_info);
    if ((err_info = sr_rwlock_init(&(*subs_p)->subs_lock, 0))) {
        goto error;
    }
    (*subs_p)->conn = conn;
    (*subs_p)->evpipe = -1;

    /* get new event pipe number and increment it */
    (*subs_p)->evpipe_num = ATOMIC_INC_RELAXED(SR_CONN_MAIN_SHM((*subs_p)->conn)->new_evpipe_num);

    /* get event pipe name */
    if ((err_info = sr_path_evpipe((*subs_p)->evpipe_num, &path))) {
        goto error;
    }

    /* create the pipe */
    if ((err_info = sr_mkfifo(path, SR_EVPIPE_PERM))) {
        goto error;
    }

    /* open it for reading AND writing (just so that there always is a "writer", otherwise it is always ready
     * for reading by select() but returns just EOF on read) */
    (*subs_p)->evpipe = sr_open(path, O_RDWR | O_NONBLOCK, 0);
    if ((*subs_p)->evpipe == -1) {
        SR_ERRINFO_SYSERRPATH(&err_info, "open", path);
        goto error;
    }

    if (!(opts & SR_SUBSCR_NO_THREAD)) {
        /* set thread_running to non-zero so that thread does not immediately quit */
        if (opts & SR_SUBSCR_THREAD_SUSPEND) {
            ATOMIC_STORE_RELAXED((*subs_p)->thread_running, 2);
        } else {
            ATOMIC_STORE_RELAXED((*subs_p)->thread_running, 1);
        }

        /* start the listen thread */
        ret = pthread_create(&(*subs_p)->tid, NULL, sr_shmsub_listen_thread, *subs_p);
        if (ret) {
            sr_errinfo_new(&err_info, SR_ERR_INTERNAL, "Creating a new thread failed (%s).", strerror(ret));
            goto error;
        }
    }

    free(path);
    return NULL;

error:
    free(path);
    if ((*subs_p)->evpipe > -1) {
        close((*subs_p)->evpipe);
    }
    sr_rwlock_destroy(&(*subs_p)->subs_lock);
    free(*subs_p);
    *subs_p = NULL;
    return err_info;
}

API int
sr_module_change_subscribe(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        sr_module_change_cb callback, void *private_data, uint32_t priority, sr_subscr_options_t opts,
        sr_subscription_ctx_t **subscription)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    const struct lys_module *ly_mod;
    struct sr_mod_info_s mod_info;
    sr_conn_ctx_t *conn;
    uint32_t sub_id;
    sr_subscr_options_t sub_opts;
    sr_mod_t *shm_mod;
    uint16_t config_flag;

    SR_CHECK_ARG_APIRET(!session || !SR_IS_STANDARD_DS(session->ds) || SR_IS_EVENT_SESS(session) || !module_name ||
            !callback || !subscription, session, err_info);

    SR_MODINFO_INIT(mod_info, session->conn, session->ds, session->ds == SR_DS_OPERATIONAL ? SR_DS_RUNNING : session->ds, 0);

    conn = session->conn;
    /* only these options are relevant outside this function and will be stored */
    sub_opts = opts & (SR_SUBSCR_DONE_ONLY | SR_SUBSCR_PASSIVE | SR_SUBSCR_UPDATE | SR_SUBSCR_FILTER_ORIG |
            SR_SUBSCR_CHANGE_ALL_MODULES);

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    /* check module name and xpath */
    ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, module_name);
    if (!ly_mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
        goto cleanup;
    } else if (!strcmp(ly_mod->name, "sysrepo")) {
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Data of internal module \"sysrepo\" cannot be subscribed to.");
        goto cleanup;
    }
    if (session->ds == SR_DS_OPERATIONAL) {
        config_flag = (LYS_CONFIG_W | LYS_CONFIG_R);
    } else {
        config_flag = LYS_CONFIG_W;
    }
    if (xpath && (err_info = sr_subscr_change_xpath_check(conn->ly_ctx, xpath, config_flag, NULL))) {
        goto cleanup;
    }

    /* check write/read perm */
    if ((err_info = sr_perm_check(session->conn, ly_mod, session->ds, (opts & SR_SUBSCR_PASSIVE) ? 0 : 1, NULL))) {
        goto cleanup;
    }

    /* get new sub ID */
    sub_id = ATOMIC_INC_RELAXED(SR_CONN_MAIN_SHM(conn)->new_sub_id);

    /* find the module in SHM */
    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(conn), module_name);
    SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup);

    if (!*subscription) {
        /* create a new subscription */
        if ((err_info = sr_subscr_new(conn, opts, subscription))) {
            goto cleanup;
        }
    } else if (opts & SR_SUBSCR_THREAD_SUSPEND) {
        /* suspend the running thread */
        _sr_subscription_thread_suspend(*subscription);
    }

    /* keep lock order: CHANGE SUB, MODULES and CHANGE SUB, SUBS - for applying changes and processing events */

    /* CHANGE SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_mod->change_sub[session->ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE,
            conn->cid, __func__, NULL, NULL))) {
        goto cleanup;
    }

    if (opts & SR_SUBSCR_ENABLED) {
        /* call the callback with the current configuration, keep any used modules locked in mod_info */
        if ((err_info = sr_module_change_subscribe_enable(session, &mod_info, ly_mod, xpath, callback, private_data,
                sub_id, opts))) {
            goto cleanup_unlock1;
        }
    }

    /* SUBS WRITE LOCK */
    if ((err_info = sr_rwlock(&(*subscription)->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
            __func__, NULL, NULL))) {
        goto cleanup_unlock1;
    }

    /* add module subscription into ext SHM and create separate specific SHM segment */
    if ((err_info = sr_shmext_change_sub_add(conn, shm_mod, session->ds, sub_id, xpath, priority, sub_opts,
            (*subscription)->evpipe_num))) {
        goto cleanup_unlock2;
    }

    /* add subscription into structure */
    if ((err_info = sr_subscr_change_sub_add(*subscription, sub_id, session, module_name, xpath, callback, private_data,
            priority, sub_opts, SR_LOCK_WRITE))) {
        goto error1;
    }

    /* add the subscription into session */
    if ((err_info = sr_ptr_add(&session->ptr_lock, (void ***)&session->subscriptions, &session->subscription_count,
            *subscription))) {
        goto error2;
    }

    goto cleanup_unlock2;

error2:
    sr_subscr_change_sub_del(*subscription, sub_id);

error1:
    if ((tmp_err = sr_shmext_change_sub_del(conn, shm_mod, session->ds, sub_id))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }

cleanup_unlock2:
    /* SUBS WRITE UNLOCK */
    sr_rwunlock(&(*subscription)->subs_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

cleanup_unlock1:
    /* CHANGE SUB UNLOCK */
    sr_rwunlock(&shm_mod->change_sub[session->ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__);

    /* if there are any modules, unlock them after the enabled event was handled and the subscription was added
     * to avoid losing any changes */

    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    sr_modinfo_erase(&mod_info);

cleanup:
    /* CONTEXT UNLOCK */
    sr_lycc_unlock(conn, SR_LOCK_READ, 0, __func__);
    return sr_api_ret(session, err_info);
}

API int
sr_module_change_sub_get_info(sr_subscription_ctx_t *subscription, uint32_t sub_id, const char **module_name,
        sr_datastore_t *ds, const char **xpath, uint32_t *filtered_out)
{
    sr_error_info_t *err_info = NULL;
    struct modsub_changesub_s *change_sub;

    SR_CHECK_ARG_APIRET(!subscription || !sub_id, NULL, err_info);

    /* SUBS READ LOCK */
    if ((err_info = sr_rwlock(&subscription->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, subscription->conn->cid,
            __func__, NULL, NULL))) {
        return sr_api_ret(NULL, err_info);
    }

    /* find the subscription in the subscription context */
    change_sub = sr_subscr_change_sub_find(subscription, sub_id, module_name, ds);
    if (!change_sub) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Change subscription with ID \"%" PRIu32 "\" not found.", sub_id);
        goto cleanup_unlock;
    }

    /* fill parameters */
    if (xpath) {
        *xpath = change_sub->xpath;
    }
    if (filtered_out) {
        *filtered_out = ATOMIC_LOAD_RELAXED(change_sub->filtered_out);
    }

cleanup_unlock:
    /* SUBS READ UNLOCK */
    sr_rwunlock(&subscription->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, subscription->conn->cid, __func__);

    return sr_api_ret(NULL, err_info);
}

API int
sr_module_change_sub_modify_xpath(sr_subscription_ctx_t *subscription, uint32_t sub_id, const char *xpath)
{
    sr_error_info_t *err_info = NULL;
    struct modsub_changesub_s *change_sub;
    sr_mod_t *shm_mod;
    const char *module_name;
    sr_datastore_t ds;
    uint16_t config_flag;

    SR_CHECK_ARG_APIRET(!subscription || !sub_id, NULL, err_info);

    /* SUBS WRITE LOCK */
    if ((err_info = sr_rwlock(&subscription->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_WRITE, subscription->conn->cid,
            __func__, NULL, NULL))) {
        return sr_api_ret(NULL, err_info);
    }

    /* find the subscription in the subscription context */
    change_sub = sr_subscr_change_sub_find(subscription, sub_id, &module_name, &ds);
    if (!change_sub) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Change subscription with ID \"%" PRIu32 "\" not found.", sub_id);
        goto cleanup_unlock;
    }

    /* if the xpath is the same, there is nothing to modify */
    if (!xpath && !change_sub->xpath) {
        goto cleanup_unlock;
    } else if (xpath && change_sub->xpath && !strcmp(xpath, change_sub->xpath)) {
        goto cleanup_unlock;
    }

    /* check xpath */
    if (ds == SR_DS_OPERATIONAL) {
        config_flag = (LYS_CONFIG_W | LYS_CONFIG_R);
    } else {
        config_flag = LYS_CONFIG_W;
    }
    if (xpath && (err_info = sr_subscr_change_xpath_check(subscription->conn->ly_ctx, xpath, config_flag, NULL))) {
        goto cleanup_unlock;
    }

    /* update xpath in the subscription */
    free(change_sub->xpath);
    change_sub->xpath = NULL;
    if (xpath) {
        change_sub->xpath = strdup(xpath);
        SR_CHECK_MEM_GOTO(!change_sub->xpath, err_info, cleanup_unlock);
    }

    /* find the module in SHM */
    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(subscription->conn), module_name);
    SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup_unlock);

    /* modify the subscription in ext SHM */
    if ((err_info = sr_shmext_change_sub_modify(subscription->conn, shm_mod, ds, sub_id, xpath))) {
        goto cleanup_unlock;
    }

cleanup_unlock:
    /* SUBS WRITE UNLOCK */
    sr_rwunlock(&subscription->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_WRITE, subscription->conn->cid, __func__);

    return sr_api_ret(NULL, err_info);
}

static int
_sr_get_changes_iter(sr_session_ctx_t *session, const char *xpath, int dup, sr_change_iter_t **iter)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session || !SR_IS_EVENT_SESS(session) || !xpath || !iter, session, err_info);

    if ((session->ev != SR_SUB_EV_ENABLED) && (session->ev != SR_SUB_EV_DONE) && !session->dt[session->ds].diff) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Session without changes.");
        return sr_api_ret(session, err_info);
    }

    *iter = calloc(1, sizeof **iter);
    if (!*iter) {
        SR_ERRINFO_MEM(&err_info);
        return sr_api_ret(session, err_info);
    }

    if (session->dt[session->ds].diff) {
        if (dup) {
            if ((err_info = sr_lyd_dup(session->dt[session->ds].diff, NULL, LYD_DUP_RECURSIVE, 1, &(*iter)->diff))) {
                goto error;
            }
        }
        if ((err_info = sr_lyd_find_xpath(session->dt[session->ds].diff, xpath, &(*iter)->set))) {
            goto error;
        }
    } else {
        if (ly_set_new(&(*iter)->set)) {
            SR_ERRINFO_MEM(&err_info);
            goto error;
        }
    }
    (*iter)->idx = 0;

    return sr_api_ret(session, NULL);

error:
    sr_free_change_iter(*iter);
    /* prevent use after free */
    *iter = NULL;

    return sr_api_ret(session, err_info);
}

API int
sr_get_changes_iter(sr_session_ctx_t *session, const char *xpath, sr_change_iter_t **iter)
{
    return _sr_get_changes_iter(session, xpath, 0, iter);
}

API int
sr_dup_changes_iter(sr_session_ctx_t *session, const char *xpath, sr_change_iter_t **iter)
{
    return _sr_get_changes_iter(session, xpath, 1, iter);
}

/**
 * @brief Transform change from a libyang node tree into sysrepo value.
 *
 * @param[in] node libyang node.
 * @param[in] value_str Optional value to override.
 * @param[in] anchor Optional position/keys/value anchor to override.
 * @param[out] sr_val_p Transformed sysrepo value.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_change_ly2sr(const struct lyd_node *node, const char *value_str, const char *anchor, sr_val_t **sr_val_p)
{
    sr_error_info_t *err_info = NULL;
    uint32_t end;
    sr_val_t *sr_val;
    struct lyd_node *node_dup = NULL;
    const struct lyd_node *node_ptr;
    union lyd_any_value aval;

    sr_val = calloc(1, sizeof *sr_val);
    SR_CHECK_MEM_GOTO(!sr_val, err_info, cleanup);

    if (value_str) {
        /* replace the value in a node copy so that this new value is stored */
        if ((err_info = sr_lyd_dup(node, NULL, 0, 0, &node_dup))) {
            goto cleanup;
        }

        if (node->schema->nodetype & LYD_NODE_TERM) {
            if ((err_info = sr_lyd_change_term(node_dup, value_str, 1))) {
                goto cleanup;
            }
        } else {
            assert(node->schema->nodetype & LYD_NODE_ANY);
            aval.str = value_str;
            if ((err_info = sr_lyd_any_copy_value(node_dup, &aval, LYD_ANYDATA_STRING))) {
                goto cleanup;
            }
        }

        if (node->parent && (err_info = sr_lyd_insert_child(lyd_parent(node), node_dup))) {
            goto cleanup;
        }
        node_dup->flags |= node->flags & LYD_DEFAULT;

        node_ptr = node_dup;
    } else {
        node_ptr = node;
    }

    /* fill the sr value */
    if ((err_info = sr_val_ly2sr(node_ptr, 0, sr_val))) {
        goto cleanup;
    }

    /* adjust specific members for changes */
    if (lysc_is_dup_inst_list(node->schema)) {
        /* fix the xpath if needed */
        if (anchor) {
            /* get xpath without the predicate */
            free(sr_val->xpath);
            sr_val->xpath = lyd_path(node, LYD_PATH_STD_NO_LAST_PRED, NULL, 0);
            SR_CHECK_MEM_GOTO(!sr_val->xpath, err_info, cleanup);

            end = strlen(sr_val->xpath);

            /* original length + '[' + anchor + ']' + ending 0 */
            sr_val->xpath = sr_realloc(sr_val->xpath, end + 1 + strlen(anchor) + 2);
            SR_CHECK_MEM_GOTO(!sr_val->xpath, err_info, cleanup);

            /* concatenate the specific predicate */
            sprintf(sr_val->xpath + end, "[%s]", anchor);
        }
    } else if (node->schema->nodetype == LYS_LIST) {
        /* fix the xpath if needed */
        if (anchor) {
            /* get xpath without the keys predicate */
            free(sr_val->xpath);
            sr_val->xpath = lyd_path(node, LYD_PATH_STD_NO_LAST_PRED, NULL, 0);
            SR_CHECK_MEM_GOTO(!sr_val->xpath, err_info, cleanup);

            end = strlen(sr_val->xpath);

            /* original length + anchor + ending 0 */
            sr_val->xpath = sr_realloc(sr_val->xpath, end + strlen(anchor) + 1);
            SR_CHECK_MEM_GOTO(!sr_val->xpath, err_info, cleanup);

            /* concatenate the specific predicate */
            strcpy(sr_val->xpath + end, anchor);
        }
    } else if (node->schema->nodetype == LYS_LEAFLIST) {
        /* do not include the value predicate */
        free(sr_val->xpath);
        sr_val->xpath = lyd_path(node, LYD_PATH_STD_NO_LAST_PRED, NULL, 0);
        SR_CHECK_MEM_GOTO(!sr_val->xpath, err_info, cleanup);
    }

cleanup:
    lyd_free_tree(node_dup);
    if (err_info) {
        if (sr_val) {
            free(sr_val->xpath);
        }
        free(sr_val);
    } else {
        *sr_val_p = sr_val;
    }
    return err_info;
}

API int
sr_get_change_next(sr_session_ctx_t *session, sr_change_iter_t *iter, sr_change_oper_t *operation,
        sr_val_t **old_value, sr_val_t **new_value)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_meta *meta, *meta2;
    struct lyd_node *node;
    sr_change_oper_t op;

    SR_CHECK_ARG_APIRET(!session || !iter || !operation || !old_value || !new_value, session, err_info);

    /* get next change */
    if ((err_info = sr_diff_set_getnext(iter->set, &iter->idx, &node, &op))) {
        return sr_api_ret(session, err_info);
    }

    if (!node) {
        /* no more changes */
        return SR_ERR_NOT_FOUND;
    }

    /* create values */
    switch (op) {
    case SR_OP_DELETED:
        if ((err_info = sr_change_ly2sr(node, NULL, NULL, old_value))) {
            return sr_api_ret(session, err_info);
        }
        *new_value = NULL;
        break;
    case SR_OP_MODIFIED:
        /* "orig-value" metadata contains the previous value */
        meta = lyd_find_meta(node->meta, NULL, "yang:orig-value");

        /* "orig-default" holds the previous default flag value */
        meta2 = lyd_find_meta(node->meta, NULL, "yang:orig-default");

        if (!meta || !meta2) {
            SR_ERRINFO_INT(&err_info);
            return sr_api_ret(session, err_info);
        }
        if ((err_info = sr_change_ly2sr(node, lyd_get_meta_value(meta), NULL, old_value))) {
            return sr_api_ret(session, err_info);
        }
        if (meta2->value.boolean) {
            (*old_value)->dflt = 1;
        } else {
            (*old_value)->dflt = 0;
        }
        if ((err_info = sr_change_ly2sr(node, NULL, NULL, new_value))) {
            return sr_api_ret(session, err_info);
        }
        break;
    case SR_OP_CREATED:
        if (!lysc_is_userordered(node->schema)) {
            /* not a user-ordered list, so the operation is a simple creation */
            *old_value = NULL;
            if ((err_info = sr_change_ly2sr(node, NULL, NULL, new_value))) {
                return sr_api_ret(session, err_info);
            }
            break;
        }
    /* fallthrough */
    case SR_OP_MOVED:
        /* attribute contains the value of the node before in the order */
        meta = lyd_find_meta(node->meta, NULL, sr_userord_anchor_meta_name(node->schema));
        if (!meta) {
            SR_ERRINFO_INT(&err_info);
            return sr_api_ret(session, err_info);
        }

        if (lyd_get_meta_value(meta)[0]) {
            if (lysc_is_dup_inst_list(node->schema)) {
                err_info = sr_change_ly2sr(node, NULL, lyd_get_meta_value(meta), old_value);
            } else if (node->schema->nodetype == LYS_LEAFLIST) {
                err_info = sr_change_ly2sr(node, lyd_get_meta_value(meta), NULL, old_value);
            } else {
                err_info = sr_change_ly2sr(node, NULL, lyd_get_meta_value(meta), old_value);
            }
            if (err_info) {
                return sr_api_ret(session, err_info);
            }
        } else {
            /* inserted as the first item */
            *old_value = NULL;
        }
        if ((err_info = sr_change_ly2sr(node, NULL, NULL, new_value))) {
            return sr_api_ret(session, err_info);
        }
        break;
    }

    *operation = op;
    return sr_api_ret(session, NULL);
}

API int
sr_get_change_tree_next(sr_session_ctx_t *session, sr_change_iter_t *iter, sr_change_oper_t *operation,
        const struct lyd_node **node, const char **prev_value, const char **prev_list, int *prev_dflt)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_meta *meta, *meta2;

    SR_CHECK_ARG_APIRET(!session || !iter || !operation || !node, session, err_info);

    if (prev_value) {
        *prev_value = NULL;
    }
    if (prev_list) {
        *prev_list = NULL;
    }
    if (prev_dflt) {
        *prev_dflt = 0;
    }

    /* get next change */
    if ((err_info = sr_diff_set_getnext(iter->set, &iter->idx, (struct lyd_node **)node, operation))) {
        return sr_api_ret(session, err_info);
    }

    if (!*node) {
        /* no more changes */
        return SR_ERR_NOT_FOUND;
    }

    /* create values */
    switch (*operation) {
    case SR_OP_DELETED:
        /* nothing to do */
        break;
    case SR_OP_MODIFIED:
        /* "orig-value" metadata contains the previous value */
        meta = lyd_find_meta((*node)->meta, NULL, "yang:orig-value");

        /* "orig-default" holds the previous default flag value */
        meta2 = lyd_find_meta((*node)->meta, NULL, "yang:orig-default");

        if (!meta || !meta2) {
            SR_ERRINFO_INT(&err_info);
            return sr_api_ret(session, err_info);
        }
        if (prev_value) {
            *prev_value = lyd_get_meta_value(meta);
        }
        if (prev_dflt && meta2->value.boolean) {
            *prev_dflt = 1;
        }
        break;
    case SR_OP_CREATED:
        if (!lysc_is_userordered((*node)->schema)) {
            /* nothing to do */
            break;
        }
    /* fallthrough */
    case SR_OP_MOVED:
        /* attribute contains the value of the node before in the order */
        meta = lyd_find_meta((*node)->meta, NULL, sr_userord_anchor_meta_name((*node)->schema));
        if (!meta) {
            SR_ERRINFO_INT(&err_info);
            return sr_api_ret(session, err_info);
        }
        if (lysc_is_dup_inst_list((*node)->schema) || ((*node)->schema->nodetype == LYS_LEAFLIST)) {
            if (prev_value) {
                *prev_value = lyd_get_meta_value(meta);
            }
        } else {
            assert((*node)->schema->nodetype == LYS_LIST);
            if (prev_list) {
                *prev_list = lyd_get_meta_value(meta);
            }
        }
        break;
    }

    return sr_api_ret(session, NULL);
}

API void
sr_free_change_iter(sr_change_iter_t *iter)
{
    if (!iter) {
        return;
    }

    lyd_free_all(iter->diff);
    ly_set_free(iter->set, NULL);
    free(iter);
}

API const struct lyd_node *
sr_get_change_diff(sr_session_ctx_t *session)
{
    if (!session || !SR_IS_EVENT_SESS(session)) {
        return NULL;
    }

    return session->dt[session->ds].diff;
}

/**
 * @brief Subscribe to an RPC/action.
 *
 * @param[in] session Session to use.
 * @param[in] path Path to subscribe to.
 * @param[in] callback Callback.
 * @param[in] tree_callback Tree callback.
 * @param[in] private_data Arbitrary callback data.
 * @param[in] opts Subscription options.
 * @param[out] subscription Subscription structure.
 * @return err_code (SR_ERR_OK on success).
 */
static int
_sr_rpc_subscribe(sr_session_ctx_t *session, const char *xpath, sr_rpc_cb callback, sr_rpc_tree_cb tree_callback,
        void *private_data, uint32_t priority, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    char *module_name = NULL, *path = NULL;
    const struct lys_module *ly_mod;
    uint32_t sub_id;
    sr_conn_ctx_t *conn;
    sr_rpc_t *shm_rpc = NULL;
    sr_mod_t *shm_mod = NULL;
    int is_ext;

    SR_CHECK_ARG_APIRET(!session || SR_IS_EVENT_SESS(session) || !xpath || (!callback && !tree_callback) || !subscription,
            session, err_info);

    conn = session->conn;

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    module_name = sr_get_first_ns(xpath);
    if (!module_name) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Invalid xpath \"%s\".", xpath);
        goto cleanup;
    }

    /* is the module name valid? */
    ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, module_name);
    if (!ly_mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
        goto cleanup;
    }

    /* check write perm */
    if ((err_info = sr_perm_check(conn, ly_mod, SR_DS_STARTUP, 1, NULL))) {
        goto cleanup;
    }

    /* is the xpath valid? */
    if ((err_info = sr_subscr_rpc_xpath_check(conn->ly_ctx, xpath, &path, &is_ext, NULL))) {
        goto cleanup;
    }

    /* get new sub ID */
    sub_id = ATOMIC_INC_RELAXED(SR_CONN_MAIN_SHM(conn)->new_sub_id);

    if (is_ext) {
        /* find module */
        shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(conn), ly_mod->name);
        SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup);
    } else {
        /* find the RPC */
        shm_rpc = sr_shmmod_find_rpc(SR_CONN_MOD_SHM(conn), path);
        SR_CHECK_INT_GOTO(!shm_rpc, err_info, cleanup);
    }

    if (!*subscription) {
        /* create a new subscription */
        if ((err_info = sr_subscr_new(conn, opts, subscription))) {
            goto cleanup;
        }
    } else if (opts & SR_SUBSCR_THREAD_SUSPEND) {
        /* suspend the running thread */
        _sr_subscription_thread_suspend(*subscription);
    }

    /* RPC SUB WRITE LOCK */
    if (is_ext) {
        if ((err_info = sr_rwlock(&shm_mod->rpc_ext_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__,
                NULL, NULL))) {
            goto cleanup;
        }
    } else {
        if ((err_info = sr_rwlock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__,
                NULL, NULL))) {
            goto cleanup;
        }
    }

    /* SUBS WRITE LOCK */
    if ((err_info = sr_rwlock(&(*subscription)->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
            __func__, NULL, NULL))) {
        goto cleanup_unlock1;
    }

    /* add RPC/action subscription into ext SHM and create separate specific SHM segment */
    if (is_ext) {
        if ((err_info = sr_shmext_rpc_sub_add(conn, &shm_mod->rpc_ext_subs,
                &shm_mod->rpc_ext_sub_count, path, sub_id, xpath, priority, 0, (*subscription)->evpipe_num, conn->cid))) {
            goto cleanup_unlock2;
        }
    } else {
        if ((err_info = sr_shmext_rpc_sub_add(conn, &shm_rpc->subs, &shm_rpc->sub_count, path, sub_id,
                xpath, priority, 0, (*subscription)->evpipe_num, conn->cid))) {
            goto cleanup_unlock2;
        }
    }

    /* add subscription into structure */
    if ((err_info = sr_subscr_rpc_sub_add(*subscription, sub_id, session, path, is_ext, xpath, callback, tree_callback,
            private_data, priority, SR_LOCK_WRITE))) {
        goto error1;
    }

    /* add the subscription into session */
    if ((err_info = sr_ptr_add(&session->ptr_lock, (void ***)&session->subscriptions, &session->subscription_count,
            *subscription))) {
        goto error2;
    }

    goto cleanup_unlock2;

error2:
    sr_subscr_rpc_sub_del(*subscription, sub_id);

error1:
    if (is_ext) {
        if ((tmp_err = sr_shmext_rpc_sub_del(conn, &shm_mod->rpc_ext_subs, &shm_mod->rpc_ext_sub_count, path, sub_id))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    } else {
        if ((tmp_err = sr_shmext_rpc_sub_del(conn, &shm_rpc->subs, &shm_rpc->sub_count, path, sub_id))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }

cleanup_unlock2:
    /* SUBS WRITE UNLOCK */
    sr_rwunlock(&(*subscription)->subs_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

cleanup_unlock1:
    /* RPC SUB WRITE UNLOCK */
    if (is_ext) {
        sr_rwunlock(&shm_mod->rpc_ext_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);
    } else {
        sr_rwunlock(&shm_rpc->lock, 0, SR_LOCK_WRITE, conn->cid, __func__);
    }

cleanup:
    /* CONTEXT UNLOCK */
    sr_lycc_unlock(conn, SR_LOCK_READ, 0, __func__);
    free(module_name);
    free(path);
    return sr_api_ret(session, err_info);
}

API int
sr_rpc_subscribe(sr_session_ctx_t *session, const char *xpath, sr_rpc_cb callback, void *private_data,
        uint32_t priority, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription)
{
    return _sr_rpc_subscribe(session, xpath, callback, NULL, private_data, priority, opts, subscription);
}

API int
sr_rpc_subscribe_tree(sr_session_ctx_t *session, const char *xpath, sr_rpc_tree_cb callback, void *private_data,
        uint32_t priority, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription)
{
    return _sr_rpc_subscribe(session, xpath, NULL, callback, private_data, priority, opts, subscription);
}

API int
sr_rpc_send(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt, uint32_t timeout_ms,
        sr_val_t **output, size_t *output_cnt)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *input_tree = NULL, *elem;
    sr_data_t *output_data = NULL;
    char *val_str, buf[22];
    size_t i;
    int ret = SR_ERR_OK;

    SR_CHECK_ARG_APIRET(!session || !output || !output_cnt, session, err_info);

    if (!timeout_ms) {
        timeout_ms = SR_RPC_CB_TIMEOUT;
    }
    *output = NULL;
    *output_cnt = 0;

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    /* create the container */
    if ((err_info = sr_val_sr2ly(session->conn->ly_ctx, path, NULL, 0, 0, &input_tree))) {
        goto cleanup;
    }

    /* transform input into a data tree */
    for (i = 0; i < input_cnt; ++i) {
        val_str = sr_val_sr2ly_str(session->conn->ly_ctx, &input[i], input[i].xpath, buf, 0);
        if ((err_info = sr_val_sr2ly(session->conn->ly_ctx, input[i].xpath, val_str, input[i].dflt, 0, &input_tree))) {
            goto cleanup;
        }
    }

    /* API function */
    if ((ret = sr_rpc_send_tree(session, input_tree, timeout_ms, &output_data)) != SR_ERR_OK) {
        goto cleanup;
    }
    if (!output_data) {
        /* no output */
        goto cleanup;
    }

    /* transform data tree into an output */
    LYD_TREE_DFS_BEGIN(output_data->tree, elem) {
        if (elem != output_data->tree) {
            /* allocate new sr_val */
            *output = sr_realloc(*output, (*output_cnt + 1) * sizeof **output);
            SR_CHECK_MEM_GOTO(!*output, err_info, cleanup);

            /* fill it */
            if ((err_info = sr_val_ly2sr(elem, 0, &(*output)[*output_cnt]))) {
                goto cleanup;
            }

            /* now the new value is valid */
            ++(*output_cnt);
        }

        LYD_TREE_DFS_END(output_data->tree, elem);
    }

cleanup:
    lyd_free_all(input_tree);
    sr_release_data(output_data);

    /* CONTEXT UNLOCK */
    sr_lycc_unlock(session->conn, SR_LOCK_READ, 0, __func__);
    if (err_info) {
        sr_free_values(*output, *output_cnt);
    }
    return ret ? ret : sr_api_ret(session, err_info);
}

/**
 * @brief Update the input of an internal RPC factory-reset.
 *
 * @param[in] conn Connection to use.
 * @param[in] input_op Input operation of the RPC.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_rpc_internal_input_update(sr_conn_ctx_t *conn, struct lyd_node *input_op)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod, *ly_srfd_mod;
    uint32_t i = 0;
    struct lyd_node *node;

    assert(!strcmp(LYD_NAME(input_op), "factory-reset"));

    /* find sysrepo-factory-default module */
    ly_srfd_mod = ly_ctx_get_module_implemented(conn->ly_ctx, "sysrepo-factory-default");
    assert(ly_srfd_mod);

    /* check for explicitly defined modules */
    if ((err_info = sr_lyd_find_path(input_op, "sysrepo-factory-default:modules", 0, &node))) {
        goto cleanup;
    }

    if (!lyd_child(node)) {
        /* no explicit modules, all should be reset */
        while ((ly_mod = ly_ctx_get_module_iter(conn->ly_ctx, &i))) {
            if (!ly_mod->implemented) {
                continue;
            } else if (!strcmp(ly_mod->name, "sysrepo")) {
                /* sysrepo internal data will not be reset */
                continue;
            } else if (!strcmp(ly_mod->name, "ietf-netconf")) {
                /* ietf-netconf defines data but only internal that should be ignored */
                continue;
            } else if (!sr_module_has_data(ly_mod, 0)) {
                /* no configuration data */
                continue;
            }

            if ((err_info = sr_lyd_new_term(node, ly_srfd_mod, "module", ly_mod->name))) {
                goto cleanup;
            }
        }
    }

cleanup:
    return err_info;
}

/**
 * @brief Validate and notify about an RPC/action.
 *
 * @param[in] session Session to use.
 * @param[in] mod_info Mod info to use.
 * @param[in] path RPC/action path.
 * @param[in] input RPC/action input tree.
 * @param[in] input_op RPC/action input operation.
 * @param[in] timeout_ms RPC/action callback timeout in milliseconds.
 * @param[out] output SR data with the output data tree.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
_sr_rpc_send_tree(sr_session_ctx_t *session, struct sr_mod_info_s *mod_info, const char *path, struct lyd_node *input,
        struct lyd_node *input_op, uint32_t timeout_ms, sr_data_t **output)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    sr_rpc_t *shm_rpc;
    sr_dep_t *shm_deps;
    uint16_t shm_dep_count;
    uint32_t request_id = 0;

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
        goto cleanup;
    }

    /* prepare data wrapper */
    if ((err_info = _sr_acquire_data(session->conn, NULL, output))) {
        goto cleanup;
    }

    /* collect all required modules for input validation */
    if ((err_info = sr_shmmod_get_rpc_deps(SR_CONN_MOD_SHM(session->conn), path, 0, &shm_deps, &shm_dep_count))) {
        goto cleanup;
    }
    if ((err_info = sr_shmmod_collect_deps(SR_CONN_MOD_SHM(session->conn), shm_deps, shm_dep_count, input, mod_info))) {
        goto cleanup;
    }
    if ((err_info = sr_modinfo_consolidate(mod_info, SR_LOCK_READ, SR_MI_NEW_DEPS | SR_MI_DATA_RO | SR_MI_PERM_NO,
            session, SR_OPER_CB_TIMEOUT, 0, 0))) {
        goto cleanup;
    }

    /* validate the operation, must be valid only at the time of execution */
    if ((err_info = sr_modinfo_op_validate(mod_info, input_op, 0))) {
        goto cleanup;
    }

    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(mod_info);

    sr_modinfo_erase(mod_info);
    SR_MODINFO_INIT(*mod_info, session->conn, SR_DS_OPERATIONAL, SR_DS_RUNNING, 0);

    if (!strcmp(path, SR_RPC_FACTORY_RESET_PATH)) {
        /* update the input as needed */
        if ((err_info = sr_rpc_internal_input_update(session->conn, input_op))) {
            goto cleanup;
        }
    }

    /* find the RPC */
    shm_rpc = sr_shmmod_find_rpc(SR_CONN_MOD_SHM(session->conn), path);
    SR_CHECK_INT_GOTO(!shm_rpc, err_info, cleanup);

    /* RPC SUB READ LOCK */
    if ((err_info = sr_rwlock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, session->conn->cid, __func__,
            NULL, NULL))) {
        goto cleanup;
    }

    /* publish RPC in an event and wait for a reply from the last subscriber */
    if ((err_info = sr_shmsub_rpc_notify(session->conn, &shm_rpc->subs, &shm_rpc->sub_count, path, input,
            session->orig_name, session->orig_data, mod_info->operation_id, timeout_ms, &request_id, &(*output)->tree,
            &cb_err_info))) {
        goto cleanup_rpcsub_unlock;
    }

    if (cb_err_info) {
        /* "rpc" event failed, publish "abort" event and finish */
        err_info = sr_shmsub_rpc_notify_abort(session->conn, &shm_rpc->subs, &shm_rpc->sub_count, path,
                input, session->orig_name, session->orig_data, mod_info->operation_id, timeout_ms, request_id);
        goto cleanup_rpcsub_unlock;
    }

    /* RPC SUB READ UNLOCK */
    sr_rwunlock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, session->conn->cid, __func__);

    /* find operation */
    if ((err_info = sr_ly_find_last_parent(&(*output)->tree, LYS_RPC | LYS_ACTION))) {
        goto cleanup;
    }

    /* collect all required modules for output validation */
    if ((err_info = sr_shmmod_get_rpc_deps(SR_CONN_MOD_SHM(session->conn), path, 1, &shm_deps, &shm_dep_count))) {
        goto cleanup;
    }
    if ((err_info = sr_shmmod_collect_deps(SR_CONN_MOD_SHM(session->conn), shm_deps, shm_dep_count, input, mod_info))) {
        goto cleanup;
    }
    if ((err_info = sr_modinfo_consolidate(mod_info, SR_LOCK_READ, SR_MI_NEW_DEPS | SR_MI_DATA_RO | SR_MI_PERM_NO,
            session, SR_OPER_CB_TIMEOUT, 0, 0))) {
        goto cleanup;
    }

    /* validate the output */
    if ((err_info = sr_modinfo_op_validate(mod_info, (*output)->tree, 1))) {
        goto cleanup;
    }

    /* success */
    goto cleanup;

cleanup_rpcsub_unlock:
    /* RPC SUB READ UNLOCK */
    sr_rwunlock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, session->conn->cid, __func__);

cleanup:
    if (cb_err_info) {
        /* return callback error if some was generated */
        assert(!err_info);
        err_info = cb_err_info;
    }
    if (err_info) {
        sr_release_data(*output);
        *output = NULL;
    }
    return err_info;
}

/**
 * @brief Validate and notify about an extension RPC/action.
 *
 * @param[in] session Session to use.
 * @param[in] ext_parent Extension parent data node.
 * @param[in] mod_info Mod info to use.
 * @param[in] path RPC/action path.
 * @param[in] input RPC/action input tree.
 * @param[in] input_op RPC/action input operation.
 * @param[in] timeout_ms RPC/action callback timeout in milliseconds.
 * @param[out] output SR data with the output data tree.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
_sr_rpc_ext_send_tree(sr_session_ctx_t *session, const struct lyd_node *ext_parent, struct sr_mod_info_s *mod_info,
        const char *path, struct lyd_node *input, struct lyd_node *input_op, uint32_t timeout_ms, sr_data_t **output)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    sr_mod_t *shm_mod;
    uint32_t request_id = 0;

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
        goto cleanup;
    }

    /* prepare data wrapper */
    if ((err_info = _sr_acquire_data(session->conn, NULL, output))) {
        goto cleanup;
    }

    /* collect all mounted data and data mentioned in the parent-references */
    if ((err_info = sr_modinfo_collect_ext_deps(lyd_parent(ext_parent)->schema, mod_info))) {
        goto cleanup;
    }
    if ((err_info = sr_modinfo_consolidate(mod_info, SR_LOCK_READ, SR_MI_NEW_DEPS | SR_MI_DATA_RO | SR_MI_PERM_NO,
            session, SR_OPER_CB_TIMEOUT, 0, 0))) {
        goto cleanup;
    }

    /* validate the operation, must be valid only at the time of execution */
    if ((err_info = sr_modinfo_op_validate(mod_info, input_op, 0))) {
        goto cleanup;
    }

    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(mod_info);

    /* find the module */
    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(session->conn), lyd_owner_module(input)->name);
    SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup);

    /* RPC SUB READ LOCK */
    if ((err_info = sr_rwlock(&shm_mod->rpc_ext_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, session->conn->cid,
            __func__, NULL, NULL))) {
        goto cleanup;
    }

    /* publish RPC in an event and wait for a reply from the last subscriber */
    if ((err_info = sr_shmsub_rpc_notify(session->conn, &shm_mod->rpc_ext_subs, &shm_mod->rpc_ext_sub_count, path,
            input, session->orig_name, session->orig_data, mod_info->operation_id, timeout_ms, &request_id,
            &(*output)->tree, &cb_err_info))) {
        goto cleanup_rpcsub_unlock;
    }

    if (cb_err_info) {
        /* "rpc" event failed, publish "abort" event and finish */
        err_info = sr_shmsub_rpc_notify_abort(session->conn, &shm_mod->rpc_ext_subs, &shm_mod->rpc_ext_sub_count, path,
                input, session->orig_name, session->orig_data, mod_info->operation_id, timeout_ms, request_id);
        goto cleanup_rpcsub_unlock;
    }

    /* RPC SUB READ UNLOCK */
    sr_rwunlock(&shm_mod->rpc_ext_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, session->conn->cid, __func__);

    /* find operation */
    if ((err_info = sr_ly_find_last_parent(&(*output)->tree, LYS_RPC | LYS_ACTION))) {
        goto cleanup;
    }

    /* use the same mod info, just get READ lock again */

    /* MODULES READ LOCK */
    if ((err_info = sr_shmmod_modinfo_rdlock(mod_info, 0, session->sid, timeout_ms, SR_OPER_CB_TIMEOUT))) {
        return err_info;
    }

    /* validate the output */
    if ((err_info = sr_modinfo_op_validate(mod_info, (*output)->tree, 1))) {
        goto cleanup;
    }

    goto cleanup;

cleanup_rpcsub_unlock:
    /* RPC SUB READ UNLOCK */
    sr_rwunlock(&shm_mod->rpc_ext_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, session->conn->cid, __func__);

cleanup:
    if (cb_err_info) {
        /* return callback error if some was generated */
        assert(!err_info);
        err_info = cb_err_info;
    }
    if (err_info) {
        sr_release_data(*output);
        *output = NULL;
    }
    return err_info;
}

API int
sr_rpc_send_tree(sr_session_ctx_t *session, struct lyd_node *input, uint32_t timeout_ms, sr_data_t **output)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_s mod_info;
    struct lyd_node *input_top, *input_op, *ext_parent = NULL;
    char *path = NULL, *str, *parent_path = NULL;
    struct sr_denied denied = {0};

    SR_CHECK_ARG_APIRET(!session || !input || !output, session, err_info);

    for (input_top = input; input_top->parent; input_top = lyd_parent(input_top)) {}
    if (session->conn->ly_ctx != LYD_CTX(input_top)) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Data trees must be created using the session connection libyang context.");
        return sr_api_ret(session, err_info);
    }

    if (!timeout_ms) {
        timeout_ms = SR_RPC_CB_TIMEOUT;
    }
    SR_MODINFO_INIT(mod_info, session->conn, SR_DS_OPERATIONAL, SR_DS_RUNNING, 0);

    /* check input data tree */
    input_op = NULL;
    if (input->schema) {
        switch (input->schema->nodetype) {
        case LYS_ACTION:
        case LYS_RPC:
            input_op = input;
            break;
        case LYS_CONTAINER:
        case LYS_LIST:
            /* find the action (RPC in case of schema-mount) */
            input_op = input;
            if ((err_info = sr_ly_find_last_parent(&input_op, LYS_ACTION | LYS_RPC))) {
                goto cleanup;
            }
            if (!(input_op->schema->nodetype & (LYS_ACTION | LYS_RPC))) {
                input_op = NULL;
            }
            break;
        default:
            break;
        }
    }
    if (!input_op) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Provided input is not a valid RPC or action invocation.");
        goto cleanup;
    }

    /* check read perm */
    if ((err_info = sr_perm_check(session->conn, lyd_owner_module(input_top), SR_DS_STARTUP, 0, NULL))) {
        goto cleanup;
    }

    if (session->nacm_user) {
        /* check NACM */
        if ((err_info = sr_nacm_check_op(session->nacm_user, input_top, &denied))) {
            goto cleanup;
        }

        if (denied.denied) {
            /* access denied */
            if (denied.rule_name) {
                sr_log(SR_LL_ERR, "NACM access denied by the rule \"%s\".", denied.rule_name);
            } else if (denied.def) {
                sr_log(SR_LL_ERR, "NACM access denied by \"%s\" node extension \"%s\".", LYD_NAME(denied.node), denied.def->name);
            } else {
                sr_log(SR_LL_ERR, "NACM access denied by the default NACM permissions.");
            }

            sr_errinfo_new_nacm(&err_info, "protocol", "access-denied", NULL, denied.node,
                    "Executing the operation is denied because \"%s\" NACM authorization failed.", session->nacm_user);
            goto cleanup;
        }
    }

    /* get operation path (without predicates) */
    str = lyd_path(input_op, LYD_PATH_STD, NULL, 0);
    SR_CHECK_INT_GOTO(!str, err_info, cleanup);
    err_info = sr_get_trim_predicates(str, &path);
    free(str);
    if (err_info) {
        goto cleanup;
    }

    if (input_top != input_op) {
        /* we need the OP parent to check it exists */
        parent_path = lyd_path(lyd_parent(input_op), LYD_PATH_STD, NULL, 0);
        SR_CHECK_MEM_GOTO(!parent_path, err_info, cleanup);
        /* only reference to parent_path is stored, so it cannot be freed! */
        if ((err_info = sr_modinfo_add(lyd_owner_module(input_top), parent_path, 0, 0, &mod_info))) {
            goto cleanup;
        }
        if ((err_info = sr_modinfo_consolidate(&mod_info, SR_LOCK_READ, SR_MI_DATA_RO | SR_MI_PERM_NO, session,
                SR_OPER_CB_TIMEOUT, 0, 0))) {
            goto cleanup;
        }
    }

    if (LYD_CTX(input_top) != LYD_CTX(input_op)) {
        /* different contexts if these are data of an extension (schema-mount) */
        for (ext_parent = input_op; ext_parent && !(ext_parent->flags & LYD_EXT); ext_parent = lyd_parent(ext_parent)) {}
        SR_CHECK_INT_GOTO(!ext_parent, err_info, cleanup);

        err_info = _sr_rpc_ext_send_tree(session, ext_parent, &mod_info, path, input_top, input_op, timeout_ms, output);
    } else {
        err_info = _sr_rpc_send_tree(session, &mod_info, path, input_top, input_op, timeout_ms, output);
    }
    if (err_info) {
        goto cleanup;
    }

    /* no output nodes */
    if (!lyd_child((*output)->tree)) {
        sr_release_data(*output);
        *output = NULL;
    }

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    free(parent_path);
    free(path);
    sr_modinfo_erase(&mod_info);
    free(denied.rule_name);
    return sr_api_ret(session, err_info);
}

/**
 * @brief Subscribe to a notification.
 *
 * @param[in] session Session subscription.
 * @param[in] ly_mod Notification module.
 * @param[in] xpath XPath to subscribe to.
 * @param[in] start_time Optional subscription start time.
 * @param[in] stop_time Optional subscription stop time.
 * @param[in] callback Callback.
 * @param[in] tree_callback Tree callback.
 * @param[in] private_data Arbitrary callback data.
 * @param[in] opts Subscription options.
 * @param[out] subscription Subscription structure.
 * @return err_code (SR_ERR_OK on success).
 */
static int
_sr_notif_subscribe(sr_session_ctx_t *session, const char *mod_name, const char *xpath, const struct timespec *start_time,
        const struct timespec *stop_time, sr_event_notif_cb callback, sr_event_notif_tree_cb tree_callback,
        void *private_data, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    struct timespec listen_since_mono, listen_since_real, cur_ts;
    const struct lys_module *ly_mod;
    sr_conn_ctx_t *conn;
    uint32_t sub_id;
    sr_mod_t *shm_mod;

    sr_realtime_get(&cur_ts);

    SR_CHECK_ARG_APIRET(!session || SR_IS_EVENT_SESS(session) || !mod_name ||
            (start_time && (sr_time_cmp(start_time, &cur_ts) > 0)) ||
            (stop_time && ((start_time && (sr_time_cmp(stop_time, start_time) < 0)) ||
            (!start_time && (sr_time_cmp(stop_time, &cur_ts) < 0)))) ||
            (!callback && !tree_callback) || !subscription, session, err_info);
    conn = session->conn;

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    /* is the module name valid? */
    ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, mod_name);
    if (!ly_mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", mod_name);
        goto cleanup;
    } else if (!strcmp(ly_mod->name, "sysrepo")) {
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Notifications of internal module \"sysrepo\" cannot be subscribed to.");
        goto cleanup;
    }

    /* check write perm */
    if ((err_info = sr_perm_check(conn, ly_mod, SR_DS_STARTUP, 1, NULL))) {
        goto cleanup;
    }

    /* is the xpath/module valid? */
    if ((err_info = sr_subscr_notif_xpath_check(ly_mod, xpath, NULL))) {
        goto cleanup;
    }

    if (!*subscription) {
        /* create a new subscription */
        if ((err_info = sr_subscr_new(conn, opts, subscription))) {
            goto cleanup;
        }
    } else if (opts & SR_SUBSCR_THREAD_SUSPEND) {
        /* suspend the running thread */
        _sr_subscription_thread_suspend(*subscription);
    }

    /* get new sub ID */
    sub_id = ATOMIC_INC_RELAXED(SR_CONN_MAIN_SHM(conn)->new_sub_id);

    /* find module */
    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(conn), ly_mod->name);
    SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup);

    /* NOTIF SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__,
            NULL, NULL))) {
        goto cleanup;
    }

    /* SUBS WRITE LOCK */
    if ((err_info = sr_rwlock(&(*subscription)->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
            __func__, NULL, NULL))) {
        goto cleanup_unlock1;
    }

    /* if a notification is sent now, once it gets the lock, this subscription will already be listening */
    sr_timeouttime_get(&listen_since_mono, 0);
    sr_realtime_get(&listen_since_real);

    /* add notification subscription into ext SHM and create separate specific SHM segment */
    if ((err_info = sr_shmext_notif_sub_add(conn, shm_mod, sub_id, xpath, (*subscription)->evpipe_num))) {
        goto cleanup_unlock2;
    }

    /* add subscription into structure */
    if ((err_info = sr_subscr_notif_sub_add(*subscription, sub_id, session, ly_mod->name, xpath, &listen_since_mono,
            &listen_since_real, start_time, stop_time, callback, tree_callback, private_data, SR_LOCK_WRITE))) {
        goto error1;
    }

    /* add the subscription into session */
    if ((err_info = sr_ptr_add(&session->ptr_lock, (void ***)&session->subscriptions, &session->subscription_count,
            *subscription))) {
        goto error2;
    }

    if (start_time || stop_time) {
        /* notify subscription there are already some events (replay needs to be performed) or stop time needs to be checked */
        if ((err_info = sr_shmsub_notify_evpipe((*subscription)->evpipe_num, 0, NULL))) {
            goto error2;
        }
    }

    goto cleanup_unlock2;

error2:
    sr_subscr_notif_sub_del(*subscription, sub_id, SR_EV_NOTIF_TERMINATED);

error1:
    if ((tmp_err = sr_shmext_notif_sub_del(conn, shm_mod, sub_id))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }

cleanup_unlock2:
    /* SUBS WRITE UNLOCK */
    sr_rwunlock(&(*subscription)->subs_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

cleanup_unlock1:
    /* NOTIF SUB WRITE UNLOCK */
    sr_rwunlock(&shm_mod->notif_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

cleanup:
    /* CONTEXT UNLOCK */
    sr_lycc_unlock(conn, SR_LOCK_READ, 0, __func__);
    return sr_api_ret(session, err_info);
}

API int
sr_notif_subscribe(sr_session_ctx_t *session, const char *module_name, const char *xpath, const struct timespec *start_time,
        const struct timespec *stop_time, sr_event_notif_cb callback, void *private_data, sr_subscr_options_t opts,
        sr_subscription_ctx_t **subscription)
{
    return _sr_notif_subscribe(session, module_name, xpath, start_time, stop_time, callback, NULL, private_data, opts,
            subscription);
}

API int
sr_notif_subscribe_tree(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        const struct timespec *start_time, const struct timespec *stop_time, sr_event_notif_tree_cb callback,
        void *private_data, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription)
{
    return _sr_notif_subscribe(session, module_name, xpath, start_time, stop_time, NULL, callback, private_data, opts,
            subscription);
}

API int
sr_notif_send(sr_session_ctx_t *session, const char *path, const sr_val_t *values, const size_t values_cnt,
        uint32_t timeout_ms, int wait)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *notif_tree = NULL;
    char *val_str, buf[22];
    size_t i;
    int ret = SR_ERR_OK;

    SR_CHECK_ARG_APIRET(!session || !path, session, err_info);

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(session->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    /* create the container */
    if ((err_info = sr_val_sr2ly(session->conn->ly_ctx, path, NULL, 0, 0, &notif_tree))) {
        goto cleanup;
    }

    /* transform values into a data tree */
    for (i = 0; i < values_cnt; ++i) {
        val_str = sr_val_sr2ly_str(session->conn->ly_ctx, &values[i], values[i].xpath, buf, 0);
        if ((err_info = sr_val_sr2ly(session->conn->ly_ctx, values[i].xpath, val_str, values[i].dflt, 0, &notif_tree))) {
            goto cleanup;
        }
    }

    /* API function */
    if ((ret = sr_notif_send_tree(session, notif_tree, timeout_ms, wait)) != SR_ERR_OK) {
        goto cleanup;
    }

cleanup:
    lyd_free_all(notif_tree);

    /* CONTEXT UNLOCK */
    sr_lycc_unlock(session->conn, SR_LOCK_READ, 0, __func__);
    return ret ? ret : sr_api_ret(session, err_info);
}

API int
sr_notif_send_tree(sr_session_ctx_t *session, struct lyd_node *notif, uint32_t timeout_ms, int wait)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_s mod_info;
    struct lyd_node *notif_top, *notif_op, *parent;
    sr_dep_t *shm_deps;
    sr_mod_t *shm_mod;
    struct timespec notif_ts_mono, notif_ts_real;
    uint16_t shm_dep_count;
    char *parent_path = NULL;

    SR_CHECK_ARG_APIRET(!session || !notif, session, err_info);

    for (notif_top = notif; notif_top->parent; notif_top = lyd_parent(notif_top)) {}
    if (session->conn->ly_ctx != LYD_CTX(notif_top)) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Data trees must be created using the session connection libyang context.");
        return sr_api_ret(session, err_info);
    }

    if (!timeout_ms) {
        timeout_ms = SR_NOTIF_CB_TIMEOUT;
    }
    SR_MODINFO_INIT(mod_info, session->conn, SR_DS_OPERATIONAL, SR_DS_RUNNING, 0);

    /* check notif data tree */
    notif_op = NULL;
    if (notif->schema) {
        switch (notif->schema->nodetype) {
        case LYS_NOTIF:
            notif_op = notif;
            break;
        case LYS_CONTAINER:
        case LYS_LIST:
            /* find the notification */
            notif_op = notif;
            if ((err_info = sr_ly_find_last_parent(&notif_op, LYS_NOTIF))) {
                goto cleanup;
            }
            if (notif_op->schema->nodetype != LYS_NOTIF) {
                notif_op = NULL;
            }
            break;
        default:
            break;
        }
    }
    if (!notif_op) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Provided tree is not a valid notification invocation.");
        goto cleanup;
    }

    /* check write/read perm */
    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(session->conn), lyd_owner_module(notif_top)->name);
    SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup);
    if ((err_info = sr_perm_check(session->conn, lyd_owner_module(notif_top), SR_DS_STARTUP, shm_mod->replay_supp, NULL))) {
        goto cleanup;
    }

    if (notif_top != notif_op) {
        /* we need the OP parent to check it exists */
        parent_path = lyd_path(lyd_parent(notif_op), LYD_PATH_STD, NULL, 0);
        SR_CHECK_MEM_GOTO(!parent_path, err_info, cleanup);
        if ((err_info = sr_modinfo_add(lyd_owner_module(notif_top), parent_path, 0, 0, &mod_info))) {
            goto cleanup;
        }
        if ((err_info = sr_modinfo_consolidate(&mod_info, SR_LOCK_READ, SR_MI_DATA_RO | SR_MI_PERM_NO, session,
                SR_OPER_CB_TIMEOUT, 0, 0))) {
            goto cleanup;
        }
    }

    /* collect all required modules for OP validation */
    if (LYD_CTX(notif_top) != LYD_CTX(notif_op)) {
        /* different contexts if these are data of an extension (schema-mount) */
        for (parent = notif_op; parent && !(parent->flags & LYD_EXT); parent = lyd_parent(parent)) {}
        SR_CHECK_INT_GOTO(!parent, err_info, cleanup);

        /* collect all mounted data and data mentioned in the parent-references */
        if ((err_info = sr_modinfo_collect_ext_deps(lyd_parent(parent)->schema, &mod_info))) {
            goto cleanup;
        }
    } else {
        if ((err_info = sr_shmmod_get_notif_deps(SR_CONN_MOD_SHM(session->conn), lyd_owner_module(notif_top), notif_op,
                &shm_deps, &shm_dep_count))) {
            goto cleanup;
        }
        if ((err_info = sr_shmmod_collect_deps(SR_CONN_MOD_SHM(session->conn), shm_deps, shm_dep_count, notif_top, &mod_info))) {
            goto cleanup;
        }
    }
    if ((err_info = sr_modinfo_consolidate(&mod_info, SR_LOCK_READ, SR_MI_NEW_DEPS | SR_MI_DATA_RO | SR_MI_PERM_NO,
            session, SR_OPER_CB_TIMEOUT, 0, 0))) {
        goto cleanup;
    }

    /* validate the operation */
    if ((err_info = sr_modinfo_op_validate(&mod_info, notif_op, 0))) {
        goto cleanup;
    }

    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    /* NOTIF SUB READ LOCK */
    if ((err_info = sr_rwlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, session->conn->cid,
            __func__, NULL, NULL))) {
        goto cleanup;
    }

    /* remember when the notification was generated */
    sr_timeouttime_get(&notif_ts_mono, 0);
    sr_realtime_get(&notif_ts_real);

    /* publish notif in an event */
    err_info = sr_shmsub_notif_notify(session->conn, notif_top, notif_ts_mono, notif_ts_real, session->orig_name,
            session->orig_data, mod_info.operation_id, timeout_ms, wait);

    /* NOTIF SUB READ UNLOCK */
    sr_rwunlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, session->conn->cid, __func__);

    if (err_info) {
        goto cleanup;
    }

    /* store the notification for a replay */
    if ((err_info = sr_replay_store(session->conn, session, notif_top, notif_ts_real))) {
        goto cleanup;
    }

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    free(parent_path);
    sr_modinfo_erase(&mod_info);
    return sr_api_ret(session, err_info);
}

API int
sr_notif_sub_get_info(sr_subscription_ctx_t *subscription, uint32_t sub_id, const char **module_name,
        const char **xpath, struct timespec *start_time, struct timespec *stop_time, uint32_t *filtered_out)
{
    sr_error_info_t *err_info = NULL;
    struct modsub_notifsub_s *notif_sub;

    SR_CHECK_ARG_APIRET(!subscription || !sub_id, NULL, err_info);

    /* SUBS READ LOCK */
    if ((err_info = sr_rwlock(&subscription->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, subscription->conn->cid,
            __func__, NULL, NULL))) {
        return sr_api_ret(NULL, err_info);
    }

    /* find the subscription in the subscription context */
    notif_sub = sr_subscr_notif_sub_find(subscription, sub_id, module_name);
    if (!notif_sub) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Notification subscription with ID \"%" PRIu32 "\" not found.", sub_id);
        goto cleanup_unlock;
    }

    /* fill parameters */
    if (xpath) {
        *xpath = notif_sub->xpath;
    }
    if (start_time) {
        *start_time = notif_sub->start_time;
    }
    if (stop_time) {
        *stop_time = notif_sub->stop_time;
    }
    if (filtered_out) {
        *filtered_out = ATOMIC_LOAD_RELAXED(notif_sub->filtered_out);
    }

cleanup_unlock:
    /* SUBS READ UNLOCK */
    sr_rwunlock(&subscription->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, subscription->conn->cid, __func__);

    return sr_api_ret(NULL, err_info);
}

API int
sr_notif_sub_modify_xpath(sr_subscription_ctx_t *subscription, uint32_t sub_id, const char *xpath)
{
    sr_error_info_t *err_info = NULL;
    struct modsub_notifsub_s *notif_sub;
    const struct lys_module *ly_mod;
    sr_session_ctx_t *ev_sess = NULL;
    struct timespec cur_time;
    const char *mod_name;

    SR_CHECK_ARG_APIRET(!subscription || !sub_id, NULL, err_info);

    /* SUBS WRITE LOCK */
    if ((err_info = sr_rwlock(&subscription->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_WRITE, subscription->conn->cid,
            __func__, NULL, NULL))) {
        return sr_api_ret(NULL, err_info);
    }

    /* find the subscription in the subscription context */
    notif_sub = sr_subscr_notif_sub_find(subscription, sub_id, &mod_name);
    if (!notif_sub) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Notification subscription with ID \"%" PRIu32 "\" not found.", sub_id);
        goto cleanup_unlock;
    }

    /* if the xpath is the same, there is nothing to modify */
    if (!xpath && !notif_sub->xpath) {
        goto cleanup_unlock;
    } else if (xpath && notif_sub->xpath && !strcmp(xpath, notif_sub->xpath)) {
        goto cleanup_unlock;
    }

    /* find the module */
    ly_mod = ly_ctx_get_module_implemented(subscription->conn->ly_ctx, mod_name);
    assert(ly_mod);

    /* check xpath */
    if ((err_info = sr_subscr_notif_xpath_check(ly_mod, xpath, NULL))) {
        goto cleanup_unlock;
    }

    /* update xpath */
    free(notif_sub->xpath);
    notif_sub->xpath = NULL;
    if (xpath) {
        notif_sub->xpath = strdup(xpath);
        SR_CHECK_MEM_GOTO(!notif_sub->xpath, err_info, cleanup_unlock);
    }

    /* create event session */
    if ((err_info = _sr_session_start(subscription->conn, SR_DS_OPERATIONAL, SR_SUB_EV_NOTIF, NULL, &ev_sess))) {
        goto cleanup_unlock;
    }

    /* send the special notification */
    sr_realtime_get(&cur_time);
    if ((err_info = sr_notif_call_callback(ev_sess, notif_sub->cb, notif_sub->tree_cb, notif_sub->private_data,
            SR_EV_NOTIF_MODIFIED, sub_id, NULL, &cur_time))) {
        goto cleanup_unlock;
    }

cleanup_unlock:
    /* SUBS WRITE UNLOCK */
    sr_rwunlock(&subscription->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_WRITE, subscription->conn->cid, __func__);

    sr_session_stop(ev_sess);
    return sr_api_ret(NULL, err_info);
}

API int
sr_notif_sub_modify_stop_time(sr_subscription_ctx_t *subscription, uint32_t sub_id, const struct timespec *stop_time)
{
    sr_error_info_t *err_info = NULL;
    struct modsub_notifsub_s *notif_sub;
    sr_session_ctx_t *ev_sess = NULL;
    struct timespec cur_time;

    SR_CHECK_ARG_APIRET(!subscription || !sub_id, NULL, err_info);

    /* SUBS WRITE LOCK */
    if ((err_info = sr_rwlock(&subscription->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_WRITE, subscription->conn->cid,
            __func__, NULL, NULL))) {
        return sr_api_ret(NULL, err_info);
    }

    /* find the subscription in the subscription context */
    notif_sub = sr_subscr_notif_sub_find(subscription, sub_id, NULL);
    if (!notif_sub) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Notification subscription with ID \"%" PRIu32 "\" not found.", sub_id);
        goto cleanup_unlock;
    }

    /* check stop time validity */
    if (stop_time && SR_TS_IS_ZERO(notif_sub->start_time) && (sr_time_cmp(stop_time, &notif_sub->start_time) < 0)) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Stop time cannot be earlier than start time.");
        goto cleanup_unlock;
    }

    /* if the stop time is the same, there is nothing to modify */
    if (stop_time && (sr_time_cmp(stop_time, &notif_sub->stop_time) == 0)) {
        goto cleanup_unlock;
    }

    /* update stop time */
    if (stop_time) {
        notif_sub->stop_time = *stop_time;
    } else {
        memset(&notif_sub->stop_time, 0, sizeof notif_sub->stop_time);
    }

    /* create event session */
    if ((err_info = _sr_session_start(subscription->conn, SR_DS_OPERATIONAL, SR_SUB_EV_NOTIF, NULL, &ev_sess))) {
        goto cleanup_unlock;
    }

    /* send the special notification */
    sr_realtime_get(&cur_time);
    if ((err_info = sr_notif_call_callback(ev_sess, notif_sub->cb, notif_sub->tree_cb, notif_sub->private_data,
            SR_EV_NOTIF_MODIFIED, sub_id, NULL, &cur_time))) {
        goto cleanup_unlock;
    }

    /* generate a new event for the thread to wake up */
    if ((err_info = sr_shmsub_notify_evpipe(subscription->evpipe_num, 0, NULL))) {
        goto cleanup_unlock;
    }

cleanup_unlock:
    /* SUBS WRITE UNLOCK */
    sr_rwunlock(&subscription->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_WRITE, subscription->conn->cid, __func__);

    sr_session_stop(ev_sess);
    return sr_api_ret(NULL, err_info);
}

API int
sr_oper_get_subscribe(sr_session_ctx_t *session, const char *module_name, const char *path, sr_oper_get_items_cb callback,
        void *private_data, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    sr_conn_ctx_t *conn;
    const struct lys_module *ly_mod;
    sr_mod_oper_get_sub_type_t sub_type = 0;
    uint32_t sub_id;
    sr_subscr_options_t sub_opts;
    sr_mod_t *shm_mod;
    uint32_t prio = 0;

    SR_CHECK_ARG_APIRET(!session || SR_IS_EVENT_SESS(session) || !module_name || !path || !callback || !subscription,
            session, err_info);

    conn = session->conn;
    /* only these options are relevant outside this function and will be stored */
    sub_opts = opts & SR_SUBSCR_OPER_MERGE;

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, module_name);
    if (!ly_mod) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Module \"%s\" was not found in sysrepo.", module_name);
        goto cleanup;
    }

    /* check write perm */
    if ((err_info = sr_perm_check(conn, ly_mod, SR_DS_OPERATIONAL, 1, NULL))) {
        goto cleanup;
    }

    /* check path, find out what kinds of nodes are provided */
    if ((err_info = sr_subscr_oper_path_check(conn->ly_ctx, path, &sub_type, NULL))) {
        goto cleanup;
    }

    if (!*subscription) {
        /* create a new subscription */
        if ((err_info = sr_subscr_new(conn, opts, subscription))) {
            goto cleanup;
        }
    } else if (opts & SR_SUBSCR_THREAD_SUSPEND) {
        /* suspend the running thread */
        _sr_subscription_thread_suspend(*subscription);
    }

    /* get new sub ID */
    sub_id = ATOMIC_INC_RELAXED(SR_CONN_MAIN_SHM(conn)->new_sub_id);

    /* find module */
    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(conn), module_name);
    SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup);

    /* OPER GET SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_mod->oper_get_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__,
            NULL, NULL))) {
        goto cleanup;
    }

    /* SUBS WRITE LOCK */
    if ((err_info = sr_rwlock(&(*subscription)->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
            __func__, NULL, NULL))) {
        goto cleanup_unlock1;
    }

    /* add oper get subscription into ext SHM and create separate specific SHM segment */
    if ((err_info = sr_shmext_oper_get_sub_add(conn, shm_mod, sub_id, path, sub_type, sub_opts,
            (*subscription)->evpipe_num, &prio))) {
        goto cleanup_unlock2;
    }

    /* add subscription into structure */
    if ((err_info = sr_subscr_oper_get_sub_add(*subscription, sub_id, session, module_name, path, callback, private_data,
            SR_LOCK_WRITE, prio))) {
        goto error1;
    }

    /* add the subscription into session */
    if ((err_info = sr_ptr_add(&session->ptr_lock, (void ***)&session->subscriptions, &session->subscription_count,
            *subscription))) {
        goto error2;
    }

    /* operational get subscriptions change */
    if ((err_info = sr_shmsub_oper_poll_get_sub_change_notify_evpipe(conn, module_name, path))) {
        goto error3;
    }

    goto cleanup_unlock2;

error3:
    if ((tmp_err = sr_ptr_del(&session->ptr_lock, (void ***)&session->subscriptions, &session->subscription_count,
            *subscription))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }

error2:
    sr_subscr_oper_get_sub_del(*subscription, sub_id);

error1:
    if ((tmp_err = sr_shmext_oper_get_sub_del(conn, shm_mod, sub_id))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }

cleanup_unlock2:
    /* SUBS WRITE UNLOCK */
    sr_rwunlock(&(*subscription)->subs_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

cleanup_unlock1:
    /* OPER GET SUB WRITE UNLOCK */
    sr_rwunlock(&shm_mod->oper_get_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

cleanup:
    /* CONTEXT UNLOCK */
    sr_lycc_unlock(conn, SR_LOCK_READ, 0, __func__);
    return sr_api_ret(session, err_info);
}

API int
sr_oper_poll_subscribe(sr_session_ctx_t *session, const char *module_name, const char *path, uint32_t valid_ms,
        sr_subscr_options_t opts, sr_subscription_ctx_t **subscription)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    sr_conn_ctx_t *conn;
    const struct lys_module *ly_mod;
    uint32_t sub_id;
    sr_subscr_options_t sub_opts;
    sr_mod_t *shm_mod;
    struct modsub_operpoll_s *oper_poll_subs;

    SR_CHECK_ARG_APIRET(!session || SR_IS_EVENT_SESS(session) || !path || !valid_ms || !subscription, session, err_info);

    conn = session->conn;
    /* only these options are relevant outside this function and will be stored */
    sub_opts = opts & SR_SUBSCR_OPER_POLL_DIFF;

    /* CONTEXT LOCK */
    if ((err_info = sr_lycc_lock(conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, module_name);
    if (!ly_mod) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Module \"%s\" was not found in sysrepo.", module_name);
        goto cleanup;
    }

    /* check read perm */
    if ((err_info = sr_perm_check(conn, ly_mod, SR_DS_OPERATIONAL, 0, NULL))) {
        goto cleanup;
    }

    /* check the path */
    if ((err_info = sr_subscr_oper_path_check(conn->ly_ctx, path, NULL, NULL))) {
        goto cleanup;
    }

    if (!*subscription) {
        /* create a new subscription */
        if ((err_info = sr_subscr_new(conn, opts, subscription))) {
            goto cleanup;
        }
    } else if (opts & SR_SUBSCR_THREAD_SUSPEND) {
        /* suspend the running thread */
        _sr_subscription_thread_suspend(*subscription);
    }

    /* get new sub ID */
    sub_id = ATOMIC_INC_RELAXED(SR_CONN_MAIN_SHM(conn)->new_sub_id);

    /* find module */
    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(conn), module_name);
    SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup);

    /* OPER POLL SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_mod->oper_poll_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__,
            NULL, NULL))) {
        goto cleanup;
    }

    /* SUBS WRITE LOCK */
    if ((err_info = sr_rwlock(&(*subscription)->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
            __func__, NULL, NULL))) {
        goto cleanup_unlock1;
    }

    /* add new cache entry into the connection */
    if ((err_info = sr_conn_oper_cache_add(conn, sub_id, module_name, path))) {
        goto cleanup_unlock2;
    }

    /* add oper poll subscription into ext SHM */
    if ((err_info = sr_shmext_oper_poll_sub_add(conn, shm_mod, sub_id, path, sub_opts, (*subscription)->evpipe_num))) {
        goto error1;
    }

    /* add subscription into structure */
    if ((err_info = sr_subscr_oper_poll_sub_add(*subscription, sub_id, session, module_name, path, valid_ms, sub_opts,
            SR_LOCK_WRITE))) {
        goto error2;
    }

    /* add the subscription into session */
    if ((err_info = sr_ptr_add(&session->ptr_lock, (void ***)&session->subscriptions, &session->subscription_count,
            *subscription))) {
        goto error3;
    }

    /* perform the first cache update */
    oper_poll_subs = &(*subscription)->oper_poll_subs[(*subscription)->oper_poll_sub_count - 1];
    if ((err_info = sr_shmsub_oper_poll_listen_process_module_events(oper_poll_subs, conn, NULL))) {
        goto error4;
    }

    /* make sure the event handler updates its wake up period */
    if ((err_info = sr_shmsub_notify_evpipe((*subscription)->evpipe_num, 0, NULL))) {
        goto error4;
    }

    goto cleanup_unlock2;

error4:
    if ((tmp_err = sr_ptr_del(&session->ptr_lock, (void ***)&session->subscriptions, &session->subscription_count,
            *subscription))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }

error3:
    sr_subscr_oper_poll_sub_del(*subscription, sub_id);

error2:
    if ((tmp_err = sr_shmext_oper_poll_sub_del(conn, shm_mod, sub_id))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }

error1:
    sr_conn_oper_cache_del(conn, sub_id);

cleanup_unlock2:
    /* SUBS WRITE UNLOCK */
    sr_rwunlock(&(*subscription)->subs_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

cleanup_unlock1:
    /* OPER POLL SUB WRITE UNLOCK */
    sr_rwunlock(&shm_mod->oper_poll_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

cleanup:
    /* CONTEXT UNLOCK */
    sr_lycc_unlock(conn, SR_LOCK_READ, 0, __func__);
    return sr_api_ret(session, err_info);
}
