/**
 * @file sysrepo.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief sysrepo API routines
 *
 * @copyright
 * Copyright (c) 2018 - 2021 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

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

#include <libyang/libyang.h>

#include "common.h"
#include "compat.h"
#include "config.h"
#include "edit_diff.h"
#include "log.h"
#include "lyd_mods.h"
#include "modinfo.h"
#include "plugins_datastore.h"
#include "plugins_notification.h"
#include "replay.h"
#include "shm.h"

static sr_error_info_t *sr_session_notif_buf_stop(sr_session_ctx_t *session);
static sr_error_info_t *_sr_session_stop(sr_session_ctx_t *session);
static sr_error_info_t *sr_changes_notify_store(struct sr_mod_info_s *mod_info, sr_session_ctx_t *session,
        uint32_t timeout_ms, sr_error_info_t **cb_err_info);
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

    if ((err_info = sr_shmmain_ly_ctx_init(&conn->ly_ctx))) {
        goto error1;
    }

    conn->opts = opts;

    if ((err_info = sr_mutex_init(&conn->ptr_lock, 0))) {
        goto error2;
    }

    if ((err_info = sr_shmmain_createlock_open(&conn->main_create_lock))) {
        goto error3;
    }

    if ((err_info = sr_rwlock_init(&conn->ext_remap_lock, 0))) {
        goto error4;
    }

    conn->main_shm.fd = -1;
    conn->ext_shm.fd = -1;

    if ((err_info = sr_ds_handle_init(&conn->ds_handles, &conn->ds_handle_count))) {
        goto error5;
    }
    if ((err_info = sr_ntf_handle_init(&conn->ntf_handles, &conn->ntf_handle_count))) {
        goto error6;
    }

    if ((conn->opts & SR_CONN_CACHE_RUNNING) && (err_info = sr_rwlock_init(&conn->mod_cache.lock, 0))) {
        goto error7;
    }

    *conn_p = conn;
    return NULL;

error7:
    sr_ntf_handle_free(conn->ntf_handles, conn->ntf_handle_count);
error6:
    sr_ds_handle_free(conn->ds_handles, conn->ds_handle_count);
error5:
    sr_rwlock_destroy(&conn->ext_remap_lock);
error4:
    close(conn->main_create_lock);
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
    if (conn) {
        /* free cache before context */
        if (conn->opts & SR_CONN_CACHE_RUNNING) {
            sr_rwlock_destroy(&conn->mod_cache.lock);
            lyd_free_all(conn->mod_cache.data);
            free(conn->mod_cache.mods);
        }

        ly_ctx_destroy(conn->ly_ctx);
        pthread_mutex_destroy(&conn->ptr_lock);
        if (conn->main_create_lock > -1) {
            close(conn->main_create_lock);
        }
        sr_rwlock_destroy(&conn->ext_remap_lock);
        sr_shm_clear(&conn->main_shm);
        sr_shm_clear(&conn->ext_shm);
        sr_ds_handle_free(conn->ds_handles, conn->ds_handle_count);
        sr_ntf_handle_free(conn->ntf_handles, conn->ntf_handle_count);

        free(conn);
    }
}

API int
sr_connect(const sr_conn_options_t opts, sr_conn_ctx_t **conn_p)
{
    sr_error_info_t *err_info = NULL;
    sr_conn_ctx_t *conn = NULL;
    struct lyd_node *sr_mods = NULL;
    int created = 0, changed;
    sr_main_shm_t *main_shm;
    sr_ext_hole_t *hole;

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
    if ((err_info = sr_shmmain_createlock(conn->main_create_lock))) {
        goto cleanup;
    }

    /* open the main SHM */
    if ((err_info = sr_shmmain_main_open(&conn->main_shm, &created))) {
        goto cleanup_unlock;
    }

    /* open the ext SHM */
    if ((err_info = sr_shmmain_ext_open(&conn->ext_shm, created))) {
        goto cleanup_unlock;
    }

    main_shm = SR_CONN_MAIN_SHM(conn);

    /* allocate next unique Connection ID */
    conn->cid = ATOMIC_INC_RELAXED(main_shm->new_sr_cid);

    /* update connection context based on stored lydmods data */
    if ((err_info = sr_lydmods_conn_ctx_update(conn, &conn->ly_ctx, created || !(opts & SR_CONN_NO_SCHED_CHANGES),
            opts & SR_CONN_ERR_ON_SCHED_FAIL, &changed))) {
        goto cleanup_unlock;
    }

    if (changed || created) {
        /* recover anything left in ext SHM */
        sr_shmext_recover_sub_all(conn);

        /* clear all main SHM modules (if main SHM was just created, there aren't any anyway) */
        if ((err_info = sr_shm_remap(&conn->main_shm, sizeof(sr_main_shm_t)))) {
            goto cleanup_unlock;
        }
        main_shm = SR_CONN_MAIN_SHM(conn);
        main_shm->mod_count = 0;

        /* add all the modules in lydmods data into main SHM */
        if ((err_info = sr_lydmods_parse(conn->ly_ctx, &sr_mods))) {
            goto cleanup_unlock;
        }
        if ((err_info = sr_shmmain_store_modules(conn, lyd_child(sr_mods)))) {
            goto cleanup_unlock;
        }

        assert((conn->ext_shm.size == SR_SHM_SIZE(sizeof(sr_ext_shm_t))) || sr_ext_hole_next(NULL, SR_CONN_EXT_SHM(conn)));
        if ((hole = sr_ext_hole_next(NULL, SR_CONN_EXT_SHM(conn)))) {
            /* there is something in ext SHM, is it only a single memory hole? */
            if (conn->ext_shm.size != SR_SHM_SIZE(sizeof(sr_ext_shm_t)) + hole->size) {
                /* no, this should never happen */
                SR_ERRINFO_INT(&err_info);
            }

            /* clear ext SHM */
            if ((err_info = sr_shm_remap(&conn->ext_shm, SR_SHM_SIZE(sizeof(sr_ext_shm_t))))) {
                goto cleanup_unlock;
            }
            SR_CONN_EXT_SHM(conn)->first_hole_off = 0;
        }

        /* copy full datastore from <startup> to <running> */
        if ((err_info = sr_shmmain_files_startup2running(conn))) {
            goto cleanup_unlock;
        }
    }

    /* track our connections */
    if ((err_info = sr_shmmain_conn_list_add(conn->cid))) {
        goto cleanup_unlock;
    }

    SR_LOG_INF("Connection %" PRIu32 " created.", conn->cid);

cleanup_unlock:
    /* CREATE UNLOCK */
    sr_shmmain_createunlock(conn->main_create_lock);

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
    int rc;

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

    /* free any stored operational data (API function) */
    if ((rc = sr_discard_oper_changes(conn, NULL, NULL, 0))) {
        return rc;
    }

    /* stop tracking this connection */
    if ((err_info = sr_shmmain_conn_list_del(conn->cid))) {
        return sr_api_ret(NULL, err_info);
    }

    /* free attributes */
    sr_conn_free(conn);

    return sr_api_ret(NULL, NULL);
}

API int
sr_connection_count(uint32_t *conn_count)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!conn_count, NULL, err_info);

    if ((err_info = sr_conn_info(NULL, NULL, conn_count, NULL, NULL))) {
        return sr_api_ret(NULL, err_info);
    }

    return sr_api_ret(NULL, NULL);
}

API const struct ly_ctx *
sr_get_context(sr_conn_ctx_t *conn)
{
    if (!conn) {
        return NULL;
    }

    return conn->ly_ctx;
}

API uint32_t
sr_get_content_id(sr_conn_ctx_t *conn)
{
    sr_error_info_t *err_info = NULL;
    uint32_t content_id;

    if (!conn) {
        return 0;
    }

    if ((err_info = sr_lydmods_get_content_id(SR_CONN_MAIN_SHM(conn), conn->ly_ctx, &content_id))) {
        sr_errinfo_free(&err_info);
        return 0;
    }

    return content_id;
}

API uid_t
sr_get_su_uid(void)
{
    return SR_SU_UID;
}

API int
sr_set_diff_check_callback(sr_conn_ctx_t *conn, sr_diff_check_cb callback)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!conn, NULL, err_info);

    if (geteuid() != SR_SU_UID) {
        /* not the superuser */
        sr_errinfo_new(&err_info, SR_ERR_UNAUTHORIZED, "Superuser access required.");
        return sr_api_ret(NULL, err_info);
    }

    conn->diff_check_cb = callback;
    return sr_api_ret(NULL, NULL);
}

API int
sr_discard_oper_changes(sr_conn_ctx_t *conn, sr_session_ctx_t *session, const char *xpath, uint32_t timeout_ms)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    struct sr_mod_info_s mod_info;
    struct sr_mod_info_mod_s *mod;
    struct lyd_node *change_edit = NULL, *node;
    uint32_t i;

    SR_CHECK_ARG_APIRET(!conn, NULL, err_info);

    if (!timeout_ms) {
        timeout_ms = SR_CHANGE_CB_TIMEOUT;
    }
    SR_MODINFO_INIT(mod_info, conn, SR_DS_OPERATIONAL, SR_DS_OPERATIONAL);

    /* collect all required modules */
    if (xpath) {
        if ((err_info = sr_shmmod_collect_xpath(conn->ly_ctx, xpath, SR_DS_OPERATIONAL, 0, &mod_info))) {
            goto cleanup;
        }
    } else {
        if ((err_info = sr_modinfo_add_all_modules_with_data(conn->ly_ctx, 1, &mod_info))) {
            goto cleanup;
        }
    }

    /* add modules, lock, and get data */
    if ((err_info = sr_modinfo_consolidate(&mod_info, 0, SR_LOCK_READ, SR_MI_LOCK_UPGRADEABLE | SR_MI_PERM_WRITE, 0,
            NULL, NULL, 0, 0))) {
        goto cleanup;
    }

    /* get and apply edit together */
    if ((err_info = sr_edit_oper_del(&mod_info.data, conn->cid, xpath, &change_edit))) {
        goto cleanup;
    }

    /* set changed flags */
    for (i = 0; i < mod_info.mod_count; ++i) {
        mod = &mod_info.mods[i];
        LY_LIST_FOR(change_edit, node) {
            if (node->schema->module == mod->ly_mod) {
                mod->state |= MOD_INFO_CHANGED;
                break;
            }
        }
    }

    /* get diff */
    if ((err_info = sr_edit2diff(change_edit, &mod_info.diff))) {
        goto cleanup;
    }

    /* notify all the subscribers and store the changes */
    err_info = sr_changes_notify_store(&mod_info, session, timeout_ms, &cb_err_info);

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    lyd_free_all(change_edit);
    sr_modinfo_erase(&mod_info);
    if (cb_err_info) {
        /* return callback error if some was generated */
        sr_errinfo_merge(&err_info, cb_err_info);
        sr_errinfo_new(&err_info, SR_ERR_CALLBACK_FAILED, "User callback failed.");
    }
    return sr_api_ret(NULL, err_info);
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
    if ((*session)->sid == (uint32_t)(ATOMIC_T_MAX - 1)) {
        /* the value in the main SHM is actually ATOMIC_T_MAX and calling another INC would cause an overflow */
        ATOMIC_STORE_RELAXED(SR_CONN_MAIN_SHM(conn)->new_sr_sid, 1);
    }

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

    if (!event) {
        SR_LOG_INF("Session %" PRIu32 " (user \"%s\", CID %" PRIu32 ") created.", (*session)->sid, (*session)->user,
                conn->cid);
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

    err_info = _sr_session_start(conn, datastore, SR_SUB_EV_NONE, NULL, session);
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
    int ret;

    if (!session->notif_buf.tid) {
        return NULL;
    }

    /* signal the thread to terminate */
    ATOMIC_STORE_RELAXED(session->notif_buf.thread_running, 0);

    sr_time_get(&timeout_ts, SR_NOTIF_BUF_LOCK_TIMEOUT);

    /* MUTEX LOCK */
    ret = pthread_mutex_timedlock(&session->notif_buf.lock.mutex, &timeout_ts);
    if (ret) {
        SR_ERRINFO_LOCK(&err_info, __func__, ret);
        /* restore */
        ATOMIC_STORE_RELAXED(session->notif_buf.thread_running, 1);
        return err_info;
    }

    /* wake up the thread */
    pthread_cond_broadcast(&session->notif_buf.lock.cond);

    /* MUTEX UNLOCK */
    pthread_mutex_unlock(&session->notif_buf.lock.mutex);

    /* join the thread, it will make sure all the buffered notifications are stored */
    ret = pthread_join(session->notif_buf.tid, NULL);
    if (ret) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Joining the notification buffer thread failed (%s).", strerror(ret));
        return err_info;
    }

    session->notif_buf.tid = 0;
    assert(!session->notif_buf.first);

    return NULL;
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

    /* subscriptions need to be freed before, with a WRITE lock */
    assert(!session->subscription_count && !session->subscriptions);

    /* stop notification buffering thread */
    if ((err_info = sr_session_notif_buf_stop(session))) {
        return err_info;
    }

    /* remove ourselves from conn sessions */
    tmp_err = sr_ptr_del(&session->conn->ptr_lock, (void ***)&session->conn->sessions, &session->conn->session_count, session);
    sr_errinfo_merge(&err_info, tmp_err);

    /* release any held locks */
    sr_shmmod_release_locks(session->conn, session->sid);

    /* free attributes */
    free(session->user);
    sr_errinfo_free(&session->err_info);
    free(session->orig_name);
    free(session->orig_data);
    free(session->ev_data.orig_name);
    free(session->ev_data.orig_data);
    free(session->ev_error.message);
    free(session->ev_error.format);
    free(session->ev_error.data);
    pthread_mutex_destroy(&session->ptr_lock);
    for (ds = 0; ds < SR_DS_COUNT; ++ds) {
        lyd_free_all(session->dt[ds].edit);
        lyd_free_all(session->dt[ds].diff);
    }
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
        if ((err_info = sr_subscr_session_del(session->subscriptions[0], session, SR_LOCK_NONE))) {
            return sr_api_ret(NULL, err_info);
        }
    }

    return sr_api_ret(NULL, NULL);
}

API int
sr_session_notif_buffer(sr_session_ctx_t *session)
{
    sr_error_info_t *err_info = NULL;
    int ret;

    if (!session || session->notif_buf.tid) {
        return sr_api_ret(NULL, NULL);
    }

    /* it could not be running */
    ret = ATOMIC_INC_RELAXED(session->notif_buf.thread_running);
    assert(!ret);

    /* start the buffering thread */
    ret = pthread_create(&session->notif_buf.tid, NULL, sr_notif_buf_thread, session);
    if (ret) {
        sr_errinfo_new(&err_info, SR_ERR_INTERNAL, "Creating a new thread failed (%s).", strerror(ret));
        ATOMIC_STORE_RELAXED(session->notif_buf.thread_running, 0);
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

    return session->ev_data.orig_name;
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
    const void *err_data;
    int ret;

    SR_CHECK_ARG_APIRET(!src_session || !trg_session, NULL, err_info);

    if (!src_session->err_info) {
        /* no error info to duplicate */
        return sr_api_ret(trg_session, NULL);
    }

    /* message */
    ret = sr_session_set_error_message(trg_session, src_session->err_info->err[0].message);
    if (ret) {
        return ret;
    }

    /* format */
    ret = sr_session_set_error_format(trg_session, src_session->err_info->err[0].error_format);
    if (ret) {
        return ret;
    }

    /* data */
    free(trg_session->ev_error.data);
    trg_session->ev_error.data = NULL;
    err_data = src_session->err_info->err[0].error_data;
    if (err_data) {
        trg_session->ev_error.data = malloc(sr_ev_data_size(err_data));
        SR_CHECK_MEM_GOTO(!trg_session->ev_error.data, err_info, cleanup);
        memcpy(trg_session->ev_error.data, err_data, sr_ev_data_size(err_data));
    }

cleanup:
    return sr_api_ret(trg_session, err_info);
}

API int
sr_session_set_error_message(sr_session_ctx_t *session, const char *format, ...)
{
    sr_error_info_t *err_info = NULL;
    va_list vargs;
    char *err_msg;

    SR_CHECK_ARG_APIRET(!session || ((session->ev != SR_SUB_EV_CHANGE) && (session->ev != SR_SUB_EV_UPDATE) &&
            (session->ev != SR_SUB_EV_OPER) && (session->ev != SR_SUB_EV_RPC)) || !format, session, err_info);

    va_start(vargs, format);
    if (vasprintf(&err_msg, format, vargs) == -1) {
        SR_ERRINFO_MEM(&err_info);
    } else {
        free(session->ev_error.message);
        session->ev_error.message = err_msg;
    }
    va_end(vargs);

    return sr_api_ret(session, err_info);
}

API int
sr_session_set_error_format(sr_session_ctx_t *session, const char *error_format)
{
    sr_error_info_t *err_info = NULL;
    char *err_format;

    SR_CHECK_ARG_APIRET(!session || ((session->ev != SR_SUB_EV_CHANGE) && (session->ev != SR_SUB_EV_UPDATE) &&
            (session->ev != SR_SUB_EV_OPER) && (session->ev != SR_SUB_EV_RPC)), session, err_info);

    if (error_format) {
        if (!(err_format = strdup(error_format))) {
            SR_ERRINFO_MEM(&err_info);
            return sr_api_ret(session, err_info);
        }
    } else {
        err_format = NULL;
    }

    free(session->ev_error.format);
    session->ev_error.format = err_format;

    return sr_api_ret(session, NULL);
}

API int
sr_session_push_error_data(sr_session_ctx_t *session, uint32_t size, const void *data)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session || ((session->ev != SR_SUB_EV_CHANGE) && (session->ev != SR_SUB_EV_UPDATE) &&
            (session->ev != SR_SUB_EV_OPER) && (session->ev != SR_SUB_EV_RPC)) || !session->ev_error.format || !size ||
            !data, session, err_info);

    err_info = sr_ev_data_push(&session->ev_error.data, size, data);
    return sr_api_ret(session, err_info);
}

API int
sr_get_error_data(sr_error_info_err_t *err, uint32_t idx, uint32_t *size, const void **data)
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
    char *value;

    value = getenv(SR_REPO_PATH_ENV);
    if (value) {
        return value;
    }

    return SR_REPO_PATH;
}

/**
 * @brief Learn YANG module name and format.
 *
 * @param[in] schema_path Path to the module file.
 * @param[out] module_name Name of the module.
 * @param[out] format Module format.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_get_module_name_format(const char *schema_path, char **module_name, LYS_INFORMAT *format)
{
    sr_error_info_t *err_info = NULL;
    const char *ptr;
    int index;

    /* learn the format */
    if ((strlen(schema_path) > 4) && !strcmp(schema_path + strlen(schema_path) - 4, ".yin")) {
        *format = LYS_IN_YIN;
        ptr = schema_path + strlen(schema_path) - 4;
    } else if ((strlen(schema_path) > 5) && !strcmp(schema_path + strlen(schema_path) - 5, ".yang")) {
        *format = LYS_IN_YANG;
        ptr = schema_path + strlen(schema_path) - 5;
    } else {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Unknown format of module \"%s\".", schema_path);
        return err_info;
    }

    /* parse module name */
    for (index = 0; (ptr != schema_path) && (ptr[0] != '/'); ++index, --ptr) {}
    if (ptr[0] == '/') {
        ++ptr;
        --index;
    }
    *module_name = strndup(ptr, index);
    SR_CHECK_MEM_RET(!*module_name, err_info);
    ptr = strchr(*module_name, '@');
    if (ptr) {
        /* truncate revision */
        ((char *)ptr)[0] = '\0';
    }

    return NULL;
}

/**
 * @brief Parse a YANG module.
 *
 * @param[in] ly_ctx Context to use.
 * @param[in] schema_path Path to the module file.
 * @param[in] format Module format.
 * @param[in] features Features to enable.
 * @param[in] search_dirs Optional search dirs, in format <dir>[:<dir>]*.
 * @param[out] ly_mod Parsed libyang module.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_parse_module(struct ly_ctx *ly_ctx, const char *schema_path, LYS_INFORMAT format, const char **features,
        const char *search_dirs, const struct lys_module **ly_mod)
{
    sr_error_info_t *err_info = NULL;
    char *sdirs_str = NULL, *ptr, *ptr2 = NULL;
    size_t sdir_count = 0;
    struct ly_in *in = NULL;

    if (search_dirs) {
        sdirs_str = strdup(search_dirs);
        if (!sdirs_str) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }

        /* add each search dir */
        for (ptr = strtok_r(sdirs_str, ":", &ptr2); ptr; ptr = strtok_r(NULL, ":", &ptr2)) {
            if (!ly_ctx_set_searchdir(ly_ctx, ptr)) {
                /* added (it was not already there) */
                ++sdir_count;
            }
        }
    }

    /* parse the module */
    if (ly_in_new_filepath(schema_path, 0, &in)) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Failed to parse \"%s\".", schema_path);
        goto cleanup;
    }
    if (lys_parse(ly_ctx, in, format, features, (struct lys_module **)ly_mod)) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    /* compile */
    if (ly_ctx_compile(ly_ctx)) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

cleanup:
    /* remove added search dirs */
    ly_ctx_unset_searchdir_last(ly_ctx, sdir_count);

    ly_in_free(in, 0);
    free(sdirs_str);
    if (err_info) {
        *ly_mod = NULL;
    }
    return err_info;
}

API int
sr_install_module(sr_conn_ctx_t *conn, const char *schema_path, const char *search_dirs, const char **features)
{
    sr_module_ds_t mod_ds = {{"LYB DS file", "LYB DS file", "LYB DS file", "LYB DS file", "LYB notif"}};

    return sr_install_module_custom_ds(conn, schema_path, search_dirs, features, &mod_ds);
}

API int
sr_install_module_custom_ds(sr_conn_ctx_t *conn, const char *schema_path, const char *search_dirs, const char **features,
        const sr_module_ds_t *module_ds)
{
    sr_error_info_t *err_info = NULL;
    struct ly_ctx *tmp_ly_ctx = NULL;
    struct lyd_node *sr_mods = NULL;
    const struct lys_module *ly_mod, *ly_iter, *ly_iter2;
    LYS_INFORMAT format;
    char *mod_name = NULL;
    uint32_t i;

    SR_CHECK_ARG_APIRET(!conn || !schema_path || !module_ds, NULL, err_info);

    /* create new temporary context */
    if ((err_info = sr_shmmain_ly_ctx_init(&tmp_ly_ctx))) {
        goto cleanup;
    }
    /* parse sr_mods */
    if ((err_info = sr_lydmods_parse(tmp_ly_ctx, &sr_mods))) {
        goto cleanup;
    }
    /* use temporary context to load modules */
    if ((err_info = sr_lydmods_ctx_load_modules(sr_mods, tmp_ly_ctx, 1, 1, 0, NULL))) {
        goto cleanup;
    }

    /* learn module name and format */
    if ((err_info = sr_get_module_name_format(schema_path, &mod_name, &format))) {
        goto cleanup;
    }

    /* check whether the module is not already in the context */
    ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, mod_name);
    if (ly_mod) {
        /* it is currently in the context, try to parse it again to check revisions */
        if ((err_info = sr_parse_module(tmp_ly_ctx, schema_path, format, features, search_dirs, &ly_mod))) {
            sr_errinfo_new(&err_info, SR_ERR_EXISTS, "Module \"%s\" is already in sysrepo.", mod_name);
            goto cleanup;
        }

        /* same modules, so if it is scheduled for deletion, we can unschedule it */
        err_info = sr_lydmods_unsched_del_module_with_imps(SR_CONN_MAIN_SHM(conn), conn->ly_ctx, ly_mod);
        if (err_info && (err_info->err[0].err_code == SR_ERR_NOT_FOUND)) {
            sr_errinfo_free(&err_info);
            sr_errinfo_new(&err_info, SR_ERR_EXISTS, "Module \"%s\" is already in sysrepo.", ly_mod->name);
            goto cleanup;
        }
        goto cleanup;
    }

    /* check plugin existence */
    for (i = 0; i < SR_DS_COUNT; ++i) {
        if ((err_info = sr_ds_plugin_find(module_ds->plugin_name[i], conn, NULL))) {
            goto cleanup;
        }
    }
    if ((err_info = sr_ntf_plugin_find(module_ds->plugin_name[SR_MOD_DS_NOTIF], conn, NULL))) {
        goto cleanup;
    }

    /* parse the module with the features */
    if ((err_info = sr_parse_module(tmp_ly_ctx, schema_path, format, features, search_dirs, &ly_mod))) {
        goto cleanup;
    }

    /* check that the module does not implement some other modules in different revisions than already in the context */
    i = 0;
    while ((ly_iter = ly_ctx_get_module_iter(tmp_ly_ctx, &i))) {
        if (!ly_iter->implemented) {
            continue;
        }

        ly_iter2 = ly_ctx_get_module_implemented(conn->ly_ctx, ly_iter->name);
        if (!ly_iter2) {
            continue;
        }

        /* modules are implemented in both contexts, compare revisions */
        if ((!ly_iter->revision && ly_iter2->revision) || (ly_iter->revision && !ly_iter2->revision) ||
                (ly_iter->revision && ly_iter2->revision && strcmp(ly_iter->revision, ly_iter2->revision))) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Module \"%s\" implements module \"%s@%s\" that is already"
                    " in sysrepo in revision %s.", ly_mod->name, ly_iter->name,
                    ly_iter->revision ? ly_iter->revision : "<none>", ly_iter2->revision ? ly_iter2->revision : "<none>");
            goto cleanup;
        }
    }

    /* schedule module installation */
    if ((err_info = sr_lydmods_deferred_add_module(SR_CONN_MAIN_SHM(conn), conn->ly_ctx, ly_mod, features, module_ds))) {
        goto cleanup;
    }

    /* store new module imports */
    if ((err_info = sr_create_module_imps_incs_r(ly_mod, NULL))) {
        goto cleanup;
    }

    /* success */

cleanup:
    lyd_free_all(sr_mods);
    ly_ctx_destroy(tmp_ly_ctx);
    free(mod_name);
    return sr_api_ret(NULL, err_info);
}

API int
sr_install_module_data(sr_conn_ctx_t *conn, const char *module_name, const char *data, const char *data_path,
        LYD_FORMAT format)
{
    sr_error_info_t *err_info = NULL;
    struct ly_ctx *tmp_ly_ctx = NULL;

    SR_CHECK_ARG_APIRET(!conn || !module_name || (data && data_path) || (!data && !data_path) || !format, NULL, err_info);

    /* create new temporary context */
    if ((err_info = sr_shmmain_ly_ctx_init(&tmp_ly_ctx))) {
        goto cleanup;
    }

    /* set new startup data for the module */
    if ((err_info = sr_lydmods_deferred_add_module_data(SR_CONN_MAIN_SHM(conn), tmp_ly_ctx, module_name, data,
            data_path, format))) {
        goto cleanup;
    }

    /* success */

cleanup:
    ly_ctx_destroy(tmp_ly_ctx);
    return sr_api_ret(NULL, err_info);
}

API int
sr_remove_module(sr_conn_ctx_t *conn, const char *module_name)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;

    SR_CHECK_ARG_APIRET(!conn || !module_name, NULL, err_info);

    /* try to find this module */
    ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, module_name);
    if (!ly_mod) {
        /* if it is scheduled for installation, we can unschedule it */
        err_info = sr_lydmods_unsched_add_module(SR_CONN_MAIN_SHM(conn), conn->ly_ctx, module_name);
        if (err_info && (err_info->err[0].err_code == SR_ERR_NOT_FOUND)) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
        }
        goto cleanup;
    }

    if (sr_module_is_internal(ly_mod)) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Internal module \"%s\" cannot be uninstalled.", module_name);
        goto cleanup;
    }

    /* check write permission */
    if ((err_info = sr_perm_check(conn, ly_mod, SR_DS_STARTUP, 1, NULL))) {
        goto cleanup;
    }

    /* schedule module removal from sysrepo */
    if ((err_info = sr_lydmods_deferred_del_module(SR_CONN_MAIN_SHM(conn), conn->ly_ctx, module_name))) {
        goto cleanup;
    }

    /* success */

cleanup:
    return sr_api_ret(NULL, err_info);
}

API int
sr_update_module(sr_conn_ctx_t *conn, const char *schema_path, const char *search_dirs)
{
    sr_error_info_t *err_info = NULL;
    struct ly_ctx *tmp_ly_ctx = NULL;
    const struct lys_module *ly_mod, *upd_ly_mod;
    LYS_INFORMAT format;
    char *mod_name = NULL;

    SR_CHECK_ARG_APIRET(!conn || !schema_path, NULL, err_info);

    /* learn about the module */
    if ((err_info = sr_get_module_name_format(schema_path, &mod_name, &format))) {
        goto cleanup;
    }

    /* try to find this module */
    ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, mod_name);
    if (!ly_mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", mod_name);
        goto cleanup;
    }

    /* check write permission */
    if ((err_info = sr_perm_check(conn, ly_mod, SR_DS_STARTUP, 1, NULL))) {
        goto cleanup;
    }

    /* create new temporary context */
    if ((err_info = sr_ly_ctx_new(&tmp_ly_ctx))) {
        goto cleanup;
    }

    /* try to parse the update module */
    if ((err_info = sr_parse_module(tmp_ly_ctx, schema_path, format, NULL, search_dirs, &upd_ly_mod))) {
        goto cleanup;
    }

    /* it must have a revision */
    if (!upd_ly_mod->revision) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Update module \"%s\" does not have a revision.", mod_name);
        goto cleanup;
    }

    /* it must be a different and newer module than the installed one */
    if (ly_mod->revision) {
        if (!strcmp(upd_ly_mod->revision, ly_mod->revision)) {
            sr_errinfo_new(&err_info, SR_ERR_EXISTS, "Module \"%s@%s\" already installed.", mod_name,
                    ly_mod->revision);
            goto cleanup;
        } else if (strcmp(upd_ly_mod->revision, ly_mod->revision) < 0) {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Module \"%s@%s\" installed in a newer revision.",
                    mod_name, ly_mod->revision);
            goto cleanup;
        }
    }

    /* schedule module update */
    if ((err_info = sr_lydmods_deferred_upd_module(SR_CONN_MAIN_SHM(conn), conn->ly_ctx, upd_ly_mod))) {
        goto cleanup;
    }

    /* store update module imports */
    if ((err_info = sr_create_module_imps_incs_r(upd_ly_mod, NULL))) {
        goto cleanup;
    }

    /* success */

cleanup:
    ly_ctx_destroy(tmp_ly_ctx);
    free(mod_name);
    return sr_api_ret(NULL, err_info);
}

API int
sr_set_module_replay_support(sr_conn_ctx_t *conn, const char *module_name, int replay_support)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod = NULL;

    SR_CHECK_ARG_APIRET(!conn, NULL, err_info);

    if (module_name) {
        /* try to find this module */
        ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, module_name);
        if (!ly_mod) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
            goto cleanup;
        }
    }

    /* update replay-support flag both in LY data tree and in main SHM */
    if ((err_info = sr_lydmods_update_replay_support(conn, ly_mod, replay_support))) {
        goto cleanup;
    }
    if ((err_info = sr_shmmain_update_replay_support(SR_CONN_MAIN_SHM(conn), module_name, replay_support))) {
        goto cleanup;
    }

cleanup:
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
 * @param[in] perm Module permissions, -1 to keep unchanged.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
_sr_set_module_ds_access(sr_conn_ctx_t *conn, const struct lys_module *ly_mod, sr_mod_t *shm_mod, int mod_ds,
        const char *owner, const char *group, mode_t perm)
{
    sr_error_info_t *err_info = NULL;
    int rc;
    struct srplg_ds_s *ds_plg;
    struct srplg_ntf_s *ntf_plg;

    assert(owner || group || (perm != (mode_t)(-1)));

    /* set owner and permissions of the DS */
    if (mod_ds == SR_MOD_DS_NOTIF) {
        if ((err_info = sr_ntf_plugin_find(conn->main_shm.addr + shm_mod->plugins[mod_ds], conn, &ntf_plg))) {
            goto cleanup;
        }
        if ((rc = ntf_plg->access_set_cb(ly_mod, owner, group, perm))) {
            SR_ERRINFO_DSPLUGIN(&err_info, rc, "set_access", ntf_plg->name, ly_mod->name);
            goto cleanup;
        }
    } else {
        if ((err_info = sr_ds_plugin_find(conn->main_shm.addr + shm_mod->plugins[mod_ds], conn, &ds_plg))) {
            goto cleanup;
        }
        if ((rc = ds_plg->access_set_cb(ly_mod, mod_ds, owner, group, perm))) {
            SR_ERRINFO_DSPLUGIN(&err_info, rc, "set_access", ds_plg->name, ly_mod->name);
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
    sr_main_shm_t *main_shm;

    SR_CHECK_ARG_APIRET(!conn || (mod_ds >= SR_MOD_DS_PLUGIN_COUNT) || (mod_ds < 0) ||
            (!owner && !group && (perm == (mode_t)(-1))), NULL, err_info);
    main_shm = SR_CONN_MAIN_SHM(conn);

    if (module_name) {
        /* find the module in SHM */
        shm_mod = sr_shmmain_find_module(main_shm, module_name);
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
        for (i = 0; i < main_shm->mod_count; ++i) {
            shm_mod = SR_SHM_MOD_IDX(main_shm, i);

            /* get LY module */
            ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, ((char *)main_shm) + shm_mod->name);
            assert(ly_mod);

            /* set permissions of this module */
            if ((err_info = _sr_set_module_ds_access(conn, ly_mod, shm_mod, mod_ds, owner, group, perm))) {
                goto cleanup;
            }
        }
    }

cleanup:
    return sr_api_ret(NULL, err_info);
}

API int
sr_set_module_access(sr_conn_ctx_t *conn, const char *module_name, const char *owner, const char *group, mode_t perm)
{
    int ret;

    /* change access for all the datastores */
    if ((ret = sr_set_module_ds_access(conn, module_name, SR_DS_STARTUP, owner, group, perm))) {
        return ret;
    }
    if ((ret = sr_set_module_ds_access(conn, module_name, SR_DS_RUNNING, owner, group, perm))) {
        return ret;
    }
    if ((ret = sr_set_module_ds_access(conn, module_name, SR_DS_OPERATIONAL, owner, group, perm))) {
        return ret;
    }

    return SR_ERR_OK;
}

API int
sr_get_module_ds_access(sr_conn_ctx_t *conn, const char *module_name, int mod_ds, char **owner, char **group, mode_t *perm)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    const struct lys_module *ly_mod;
    sr_main_shm_t *main_shm;
    struct srplg_ds_s *ds_plg;
    struct srplg_ntf_s *ntf_plg;
    int rc;

    SR_CHECK_ARG_APIRET(!conn || !module_name || (mod_ds >= SR_MOD_DS_PLUGIN_COUNT) || (mod_ds < 0) ||
            (!owner && !group && !perm), NULL, err_info);
    main_shm = SR_CONN_MAIN_SHM(conn);

    /* find the module in SHM */
    shm_mod = sr_shmmain_find_module(main_shm, module_name);
    if (!shm_mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
        goto cleanup;
    }

    /* get LY module */
    ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, module_name);
    assert(ly_mod);

    /* learn owner and permissions of the DS */
    if (mod_ds == SR_MOD_DS_NOTIF) {
        if ((err_info = sr_ntf_plugin_find(conn->main_shm.addr + shm_mod->plugins[mod_ds], conn, &ntf_plg))) {
            goto cleanup;
        }
        if ((rc = ntf_plg->access_get_cb(ly_mod, owner, group, perm))) {
            SR_ERRINFO_DSPLUGIN(&err_info, rc, "get_access", ntf_plg->name, ly_mod->name);
            goto cleanup;
        }
    } else {
        if ((err_info = sr_ds_plugin_find(conn->main_shm.addr + shm_mod->plugins[mod_ds], conn, &ds_plg))) {
            goto cleanup;
        }
        if ((rc = ds_plg->access_get_cb(ly_mod, mod_ds, owner, group, perm))) {
            SR_ERRINFO_DSPLUGIN(&err_info, rc, "get_access", ds_plg->name, ly_mod->name);
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
    sr_main_shm_t *main_shm;
    struct srplg_ds_s *ds_plg;
    struct srplg_ntf_s *ntf_plg;
    int rc;

    SR_CHECK_ARG_APIRET(!conn || !module_name || (mod_ds >= SR_MOD_DS_PLUGIN_COUNT) || (mod_ds < 0) || (!read && !write),
            NULL, err_info);
    main_shm = SR_CONN_MAIN_SHM(conn);

    /* find the module in SHM */
    shm_mod = sr_shmmain_find_module(main_shm, module_name);
    if (!shm_mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
        goto cleanup;
    }

    /* get LY module */
    ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, module_name);
    assert(ly_mod);

    /* check access for the DS */
    if (mod_ds == SR_MOD_DS_NOTIF) {
        if ((err_info = sr_ntf_plugin_find(conn->main_shm.addr + shm_mod->plugins[mod_ds], conn, &ntf_plg))) {
            goto cleanup;
        }
        if ((rc = ntf_plg->access_check_cb(ly_mod, read, write))) {
            SR_ERRINFO_DSPLUGIN(&err_info, rc, "get_access", ntf_plg->name, ly_mod->name);
            goto cleanup;
        }
    } else {
        if ((err_info = sr_ds_plugin_find(conn->main_shm.addr + shm_mod->plugins[mod_ds], conn, &ds_plg))) {
            goto cleanup;
        }
        if ((rc = ds_plg->access_check_cb(ly_mod, mod_ds, read, write))) {
            SR_ERRINFO_DSPLUGIN(&err_info, rc, "get_access", ds_plg->name, ly_mod->name);
            goto cleanup;
        }
    }

cleanup:
    return sr_api_ret(NULL, err_info);
}

/**
 * @brief En/disable module feature.
 *
 * @param[in] conn Connection to use.
 * @param[in] module_name Module to change.
 * @param[in] feature_name Feature to change.
 * @param[in] enable Whether to enable or disable the feature.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_change_module_feature(sr_conn_ctx_t *conn, const char *module_name, const char *feature_name, int enable)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    LY_ERR lyrc;

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

    /* check feature in the current context */
    lyrc = lys_feature_value(ly_mod, feature_name);
    if (lyrc == LY_ENOTFOUND) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Feature \"%s\" was not found in module \"%s\".",
                feature_name, module_name);
        goto cleanup;
    }

    /* mark the change (if any) in LY data tree */
    if ((err_info = sr_lydmods_deferred_change_feature(SR_CONN_MAIN_SHM(conn), conn->ly_ctx, ly_mod, feature_name,
            enable, !lyrc))) {
        goto cleanup;
    }

    /* success */

cleanup:
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
    SR_MODINFO_INIT(mod_info, session->conn, session->ds, session->ds == SR_DS_OPERATIONAL ? SR_DS_RUNNING : session->ds);

    /* collect all required modules */
    if ((err_info = sr_shmmod_collect_xpath(session->conn->ly_ctx, path, session->ds, 1, &mod_info))) {
        goto cleanup;
    }

    /* add modules into mod_info with deps, locking, and their data */
    if ((err_info = sr_modinfo_consolidate(&mod_info, 0, SR_LOCK_READ, SR_MI_DATA_CACHE | SR_MI_PERM_READ,
            session->sid, session->orig_name, session->orig_data, timeout_ms, 0))) {
        goto cleanup;
    }

    /* filter the required data */
    if ((err_info = sr_modinfo_get_filter(&mod_info, path, session, &set))) {
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

    if ((err_info = sr_val_ly2sr(set->dnodes[0], *value))) {
        goto cleanup;
    }

    /* success */

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    ly_set_free(set, NULL);
    sr_modinfo_erase(&mod_info);
    if (err_info) {
        free(*value);
        *value = NULL;
    }
    return sr_api_ret(session, err_info);
}

API int
sr_get_items(sr_session_ctx_t *session, const char *xpath, uint32_t timeout_ms, const sr_get_oper_options_t opts,
        sr_val_t **values, size_t *value_cnt)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set = NULL;
    struct sr_mod_info_s mod_info;
    uint32_t i;

    SR_CHECK_ARG_APIRET(!session || !xpath || !values || !value_cnt || ((session->ds != SR_DS_OPERATIONAL) && opts),
            session, err_info);

    if (!timeout_ms) {
        timeout_ms = SR_OPER_CB_TIMEOUT;
    }
    *values = NULL;
    *value_cnt = 0;
    /* for operational, use operational and running datastore */
    SR_MODINFO_INIT(mod_info, session->conn, session->ds, session->ds == SR_DS_OPERATIONAL ? SR_DS_RUNNING : session->ds);

    /* collect all required modules */
    if ((err_info = sr_shmmod_collect_xpath(session->conn->ly_ctx, xpath, session->ds, 1, &mod_info))) {
        goto cleanup;
    }

    /* add modules into mod_info with deps, locking, and their data */
    if ((err_info = sr_modinfo_consolidate(&mod_info, 0, SR_LOCK_READ, SR_MI_DATA_CACHE | SR_MI_PERM_READ, session->sid,
            session->orig_name, session->orig_data, timeout_ms, 0))) {
        goto cleanup;
    }

    /* filter the required data */
    if ((err_info = sr_modinfo_get_filter(&mod_info, xpath, session, &set))) {
        goto cleanup;
    }

    if (set->count) {
        *values = calloc(set->count, sizeof **values);
        SR_CHECK_MEM_GOTO(!*values, err_info, cleanup);
    }

    for (i = 0; i < set->count; ++i) {
        if ((err_info = sr_val_ly2sr(set->dnodes[i], (*values) + i))) {
            goto cleanup;
        }
        ++(*value_cnt);
    }

    /* success */

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    ly_set_free(set, NULL);
    sr_modinfo_erase(&mod_info);
    if (err_info) {
        sr_free_values(*values, *value_cnt);
        *values = NULL;
        *value_cnt = 0;
    }
    return sr_api_ret(session, err_info);
}

API int
sr_get_subtree(sr_session_ctx_t *session, const char *path, uint32_t timeout_ms, struct lyd_node **subtree)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_s mod_info;
    struct ly_set *set = NULL;

    SR_CHECK_ARG_APIRET(!session || !path || !subtree, session, err_info);

    if (!timeout_ms) {
        timeout_ms = SR_OPER_CB_TIMEOUT;
    }
    /* for operational, use operational and running datastore */
    SR_MODINFO_INIT(mod_info, session->conn, session->ds, session->ds == SR_DS_OPERATIONAL ? SR_DS_RUNNING : session->ds);

    /* collect all required modules */
    if ((err_info = sr_shmmod_collect_xpath(session->conn->ly_ctx, path, session->ds, 1, &mod_info))) {
        goto cleanup;
    }

    /* add modules into mod_info with deps, locking, and their data */
    if ((err_info = sr_modinfo_consolidate(&mod_info, 0, SR_LOCK_READ, SR_MI_DATA_CACHE | SR_MI_PERM_READ, session->sid,
            session->orig_name, session->orig_data, timeout_ms, 0))) {
        goto cleanup;
    }

    /* filter the required data */
    if ((err_info = sr_modinfo_get_filter(&mod_info, path, session, &set))) {
        goto cleanup;
    }

    if (set->count > 1) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "More subtrees match \"%s\".", path);
        goto cleanup;
    }

    if (set->count == 1) {
        if (lyd_dup_single(set->dnodes[0], NULL, LYD_DUP_RECURSIVE, subtree)) {
            sr_errinfo_new_ly(&err_info, session->conn->ly_ctx);
            goto cleanup;
        }
    } else {
        *subtree = NULL;
    }

    /* success */

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    ly_set_free(set, NULL);
    sr_modinfo_erase(&mod_info);
    return sr_api_ret(session, err_info);
}

API int
sr_get_data(sr_session_ctx_t *session, const char *xpath, uint32_t max_depth, uint32_t timeout_ms,
        const sr_get_oper_options_t opts, struct lyd_node **data)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    int dup_opts;
    struct sr_mod_info_s mod_info;
    struct ly_set *subtrees = NULL;
    struct lyd_node *node;

    SR_CHECK_ARG_APIRET(!session || !xpath || !data || ((session->ds != SR_DS_OPERATIONAL) && opts), session, err_info);

    if (!timeout_ms) {
        timeout_ms = SR_OPER_CB_TIMEOUT;
    }
    *data = NULL;
    /* for operational, use operational and running datastore */
    SR_MODINFO_INIT(mod_info, session->conn, session->ds, session->ds == SR_DS_OPERATIONAL ? SR_DS_RUNNING : session->ds);

    /* collect all required modules */
    if ((err_info = sr_shmmod_collect_xpath(session->conn->ly_ctx, xpath, session->ds, 1, &mod_info))) {
        goto cleanup;
    }

    /* add modules into mod_info with deps, locking, and their data */
    if ((err_info = sr_modinfo_consolidate(&mod_info, 0, SR_LOCK_READ, SR_MI_DATA_CACHE | SR_MI_PERM_READ, session->sid,
            session->orig_name, session->orig_data, timeout_ms, opts))) {
        goto cleanup;
    }

    /* filter the required data */
    if ((err_info = sr_modinfo_get_filter(&mod_info, xpath, session, &subtrees))) {
        goto cleanup;
    }

    /* duplicate all returned subtrees with their parents and merge into one data tree */
    for (i = 0; i < subtrees->count; ++i) {
        dup_opts = (max_depth ? 0 : LYD_DUP_RECURSIVE) | LYD_DUP_WITH_PARENTS | LYD_DUP_WITH_FLAGS;
        if (lyd_dup_single(subtrees->dnodes[i], NULL, dup_opts, &node)) {
            sr_errinfo_new_ly(&err_info, session->conn->ly_ctx);
            lyd_free_all(*data);
            *data = NULL;
            goto cleanup;
        }

        /* duplicate only to the specified depth */
        if ((err_info = sr_lyd_dup(subtrees->dnodes[i], max_depth ? max_depth - 1 : 0, node))) {
            lyd_free_all(node);
            lyd_free_all(*data);
            *data = NULL;
            goto cleanup;
        }

        /* always find parent */
        while (node->parent) {
            node = lyd_parent(node);
        }

        /* connect to the result */
        if (!*data) {
            *data = node;
        } else {
            if (lyd_merge_tree(data, node, LYD_MERGE_DESTRUCT)) {
                sr_errinfo_new_ly(&err_info, session->conn->ly_ctx);
                lyd_free_tree(node);
                lyd_free_all(*data);
                *data = NULL;
                goto cleanup;
            }
        }
    }

    /* success */

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    ly_set_free(subtrees, NULL);
    sr_modinfo_erase(&mod_info);
    return sr_api_ret(session, err_info);
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

    SR_CHECK_ARG_APIRET(!session || (!path && (!value || !value->xpath)) || (!SR_IS_CONVENTIONAL_DS(session->ds) &&
            (opts & (SR_EDIT_STRICT | SR_EDIT_NON_RECURSIVE))), session, err_info);

    if (!path) {
        path = value->xpath;
    }
    str_val = sr_val_sr2ly_str(session->conn->ly_ctx, value, path, str, 0);

    /* API function */
    return sr_set_item_str(session, path, str_val, value ? value->origin : NULL, opts);
}

API int
sr_set_item_str(sr_session_ctx_t *session, const char *path, const char *value, const char *origin, const sr_edit_options_t opts)
{
    sr_error_info_t *err_info = NULL;
    char *pref_origin = NULL;

    SR_CHECK_ARG_APIRET(!session || !path || (!SR_IS_CONVENTIONAL_DS(session->ds) &&
            (opts & (SR_EDIT_STRICT | SR_EDIT_NON_RECURSIVE))), session, err_info);

    /* we do not need any lock, ext SHM is not accessed */

    if (origin) {
        if (!strchr(origin, ':')) {
            /* add ietf-origin prefix if none used */
            pref_origin = malloc(11 + 1 + strlen(origin) + 1);
            sprintf(pref_origin, "ietf-origin:%s", origin);
        } else {
            pref_origin = strdup(origin);
        }
    }

    /* add the operation into edit */
    err_info = sr_edit_add(session, path, value, opts & SR_EDIT_STRICT ? "create" : "merge",
            opts & SR_EDIT_NON_RECURSIVE ? "none" : "merge", NULL, NULL, NULL, pref_origin, opts & SR_EDIT_ISOLATE);

    free(pref_origin);
    return sr_api_ret(session, err_info);
}

API int
sr_delete_item(sr_session_ctx_t *session, const char *path, const sr_edit_options_t opts)
{
    sr_error_info_t *err_info = NULL;
    const char *operation;
    const struct lysc_node *snode;
    int ly_log_opts;

    SR_CHECK_ARG_APIRET(!session || !SR_IS_CONVENTIONAL_DS(session->ds) || !path, session, err_info);

    /* turn off logging */
    ly_log_opts = ly_log_options(0);
    if ((path[strlen(path) - 1] != ']') && (snode = lys_find_path(session->conn->ly_ctx, NULL, path, 0)) &&
            (snode->nodetype & (LYS_LEAFLIST | LYS_LIST)) && !strcmp((path + strlen(path)) - strlen(snode->name), snode->name)) {
        operation = "purge";
    } else if (opts & SR_EDIT_STRICT) {
        operation = "delete";
    } else {
        operation = "remove";
    }
    ly_log_options(ly_log_opts);

    /* add the operation into edit */
    err_info = sr_edit_add(session, path, NULL, operation, opts & SR_EDIT_STRICT ? "none" : "ether", NULL, NULL, NULL,
            NULL, opts & SR_EDIT_ISOLATE);

    return sr_api_ret(session, err_info);
}

API int
sr_oper_delete_item_str(sr_session_ctx_t *session, const char *path, const char *value, const sr_edit_options_t opts)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session || SR_IS_CONVENTIONAL_DS(session->ds) || !path, session, err_info);

    /* add the operation into edit */
    err_info = sr_edit_add(session, path, value, "remove", "ether", NULL, NULL, NULL, NULL, opts & SR_EDIT_ISOLATE);

    return sr_api_ret(session, err_info);
}

API int
sr_move_item(sr_session_ctx_t *session, const char *path, const sr_move_position_t position, const char *list_keys,
        const char *leaflist_value, const char *origin, const sr_edit_options_t opts)
{
    sr_error_info_t *err_info = NULL;
    char *pref_origin = NULL;

    SR_CHECK_ARG_APIRET(!session || !path || (!SR_IS_CONVENTIONAL_DS(session->ds) &&
            (opts & (SR_EDIT_STRICT | SR_EDIT_NON_RECURSIVE))), session, err_info);

    if (origin) {
        if (!strchr(origin, ':')) {
            /* add ietf-origin prefix if none used */
            pref_origin = malloc(11 + 1 + strlen(origin) + 1);
            sprintf(pref_origin, "ietf-origin:%s", origin);
        } else {
            pref_origin = strdup(origin);
        }
    }

    /* add the operation into edit */
    err_info = sr_edit_add(session, path, NULL, opts & SR_EDIT_STRICT ? "create" : "merge",
            opts & SR_EDIT_NON_RECURSIVE ? "none" : "merge", &position, list_keys, leaflist_value, pref_origin,
            opts & SR_EDIT_ISOLATE);

    free(pref_origin);
    return sr_api_ret(session, err_info);
}

API int
sr_edit_batch(sr_session_ctx_t *session, const struct lyd_node *edit, const char *default_operation)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *dup_edit = NULL, *root, *elem;
    enum edit_op op;

    SR_CHECK_ARG_APIRET(!session || !edit || !default_operation, session, err_info);
    SR_CHECK_ARG_APIRET(strcmp(default_operation, "merge") && strcmp(default_operation, "replace") &&
            strcmp(default_operation, "none"), session, err_info);

    if (session->conn->ly_ctx != LYD_CTX(edit)) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Data trees must be created using the session connection libyang context.");
        return sr_api_ret(session, err_info);
    } else if (session->dt[session->ds].edit) {
        /* do not allow merging NETCONF edits into sysrepo ones, it can cause some unexpected results */
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "There are already some session changes.");
        return sr_api_ret(session, err_info);
    }

    if (lyd_dup_siblings(edit, NULL, LYD_DUP_RECURSIVE, &dup_edit)) {
        sr_errinfo_new_ly(&err_info, session->conn->ly_ctx);
        goto error;
    }

    /* add default operation and default origin */
    LY_LIST_FOR(dup_edit, root) {
        if (!sr_edit_diff_find_oper(root, 0, NULL) && (err_info = sr_edit_set_oper(root, default_operation))) {
            goto error;
        }
        if (session->ds == SR_DS_OPERATIONAL) {
            if ((err_info = sr_edit_diff_set_origin(root, SR_OPER_ORIGIN, 0))) {
                goto error;
            }

            /* check that no forbidden operations are set */
            LYD_TREE_DFS_BEGIN(root, elem) {
                op = sr_edit_diff_find_oper(elem, 0, NULL);
                if (op && (op != EDIT_MERGE) && (op != EDIT_REMOVE) && (op != EDIT_PURGE) && (op != EDIT_ETHER)) {
                    sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Operation \"%s\" is not allowed for operational "
                            "datastore changes.", sr_edit_op2str(op));
                    return sr_api_ret(session, err_info);
                }

                LYD_TREE_DFS_END(root, elem);
            }
        }
    }

    session->dt[session->ds].edit = dup_edit;
    return sr_api_ret(session, NULL);

error:
    lyd_free_siblings(dup_edit);
    return sr_api_ret(session, err_info);
}

API int
sr_validate(sr_session_ctx_t *session, const char *module_name, uint32_t timeout_ms)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod = NULL;
    const struct lyd_node *node;
    struct sr_mod_info_s mod_info;

    SR_CHECK_ARG_APIRET(!session, session, err_info);

    if (!timeout_ms) {
        timeout_ms = SR_OPER_CB_TIMEOUT;
    }
    /* for operational, use operational and running datastore */
    SR_MODINFO_INIT(mod_info, session->conn, session->ds, session->ds == SR_DS_OPERATIONAL ? SR_DS_RUNNING : session->ds);

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
        if (!session->dt[session->ds].edit) {
            /* nothing to validate */
            goto cleanup;
        }

        if (ly_mod) {
            /* check that there are some changes for this module */
            LY_LIST_FOR(session->dt[session->ds].edit, node) {
                if (lyd_owner_module(node) == ly_mod) {
                    break;
                }
            }
            if (!node) {
                /* nothing to validate */
                goto cleanup;
            }

            if ((err_info = sr_modinfo_add(ly_mod, NULL, 0, &mod_info))) {
                goto cleanup;
            }
        } else {
            /* collect all modified modules (other modules must be valid) */
            if ((err_info = sr_shmmod_collect_edit(session->dt[session->ds].edit, &mod_info))) {
                goto cleanup;
            }
        }
        break;
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        /* specific module/all modules */
        if (ly_mod) {
            if ((err_info = sr_modinfo_add(ly_mod, NULL, 0, &mod_info))) {
                goto cleanup;
            }
        } else {
            if ((err_info = sr_modinfo_add_all_modules_with_data(session->conn->ly_ctx, 0, &mod_info))) {
                goto cleanup;
            }
        }
        break;
    }

    /* add modules into mod_info with deps, locking, and their data (we need inverse dependencies because the data will
     * likely be changed) */
    if ((err_info = sr_modinfo_consolidate(&mod_info, MOD_INFO_INV_DEP, SR_LOCK_READ, SR_MI_PERM_NO, session->sid,
            session->orig_name, session->orig_data, timeout_ms, 0))) {
        goto cleanup;
    }

    /* apply any changes */
    if ((err_info = sr_modinfo_edit_apply(&mod_info, session->dt[session->ds].edit, 0))) {
        goto cleanup;
    }

    /* collect dependencies for validation and add those to mod_info as well (after we have the final data that will
     * be validated) */
    if ((err_info = sr_shmmod_collect_deps_modinfo(&mod_info))) {
        goto cleanup;
    }
    if ((err_info = sr_modinfo_consolidate(&mod_info, 0, SR_LOCK_READ, SR_MI_NEW_DEPS | SR_MI_PERM_NO, session->sid,
            session->orig_name, session->orig_data, timeout_ms, 0))) {
        goto cleanup;
    }

    /* validate the data trees */
    switch (session->ds) {
    case SR_DS_STARTUP:
    case SR_DS_RUNNING:
        /* validate only changed modules and any that can become invalid because of the changes */
        if ((err_info = sr_modinfo_validate(&mod_info, MOD_INFO_CHANGED | MOD_INFO_INV_DEP, 0))) {
            goto cleanup;
        }
        break;
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        /* validate all the modules because they may be invalid without any changes */
        if ((err_info = sr_modinfo_validate(&mod_info, MOD_INFO_REQ | MOD_INFO_INV_DEP, 0))) {
            goto cleanup;
        }
        break;
    }

    /* success */

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    sr_modinfo_erase(&mod_info);
    return sr_api_ret(session, err_info);
}

/**
 * @brief Notify subscribers about the changes in diff and store the data in mod info.
 * Mod info modules are expected to be READ-locked with the ability to upgrade to WRITE-lock!
 *
 * @param[in] mod_info Read-locked mod info with diff and data.
 * @param[in] session Optional originator session.
 * @param[in] timeout_ms Timeout in milliseconds.
 * @param[out] cb_err_info Callback error information generated by a subscriber, if any.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_changes_notify_store(struct sr_mod_info_s *mod_info, sr_session_ctx_t *session, uint32_t timeout_ms,
        sr_error_info_t **cb_err_info)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *update_edit = NULL, *old_diff = NULL, *new_diff = NULL;
    sr_session_ctx_t *ev_sess = NULL;
    sr_lock_mode_t change_sub_lock = SR_LOCK_NONE;
    int ret;
    uint32_t sid = 0;
    char *orig_name = NULL;
    void *orig_data = NULL;

    *cb_err_info = NULL;

    /* get session info */
    if (session) {
        sid = session->sid;
        orig_name = session->orig_name;
        orig_data = session->orig_data;
    }

    if (!mod_info->diff) {
        SR_LOG_INF("No datastore changes to apply.");
        goto store;
    }

    /* call connection diff callback */
    if (mod_info->conn->diff_check_cb) {
        /* create event session */
        if ((err_info = _sr_session_start(mod_info->conn, mod_info->ds, SR_SUB_EV_CHANGE, NULL, &ev_sess))) {
            goto cleanup;
        }

        /* set originator data */
        if ((err_info = sr_session_set_orig(ev_sess, orig_name, orig_data))) {
            goto cleanup;
        }

        ret = mod_info->conn->diff_check_cb(ev_sess, mod_info->diff);
        if (ret) {
            /* create cb_err_info */
            if (ev_sess->ev_error.message) {
                sr_errinfo_new_data(cb_err_info, ret, ev_sess->ev_error.format, ev_sess->ev_error.data,
                        ev_sess->ev_error.message);
            } else {
                sr_errinfo_new_data(cb_err_info, ret, ev_sess->ev_error.format, ev_sess->ev_error.data,
                        "Diff check callback failed (%s).", sr_strerror(ret));
            }
            goto cleanup;
        }
    }

    /* validate new data trees */
    switch (mod_info->ds) {
    case SR_DS_STARTUP:
    case SR_DS_RUNNING:
        /* collect validation dependencies and add those to mod_info as well */
        if ((err_info = sr_shmmod_collect_deps_modinfo(mod_info))) {
            goto cleanup;
        }
        if ((err_info = sr_modinfo_consolidate(mod_info, 0, SR_LOCK_READ, SR_MI_NEW_DEPS | SR_MI_PERM_NO, sid,
                orig_name, orig_data, 0, 0))) {
            goto cleanup;
        }

        if ((err_info = sr_modinfo_validate(mod_info, MOD_INFO_CHANGED | MOD_INFO_INV_DEP, 1))) {
            goto cleanup;
        }
        break;
    case SR_DS_CANDIDATE:
        /* does not have to be valid but we need all default values */
        if ((err_info = sr_modinfo_add_defaults(mod_info, 1))) {
            goto cleanup;
        }
        break;
    case SR_DS_OPERATIONAL:
        /* not valid and just an edit, nothing more needed */
        break;
    }

    if (!mod_info->diff) {
        /* diff can disappear after validation */
        SR_LOG_INF("No datastore changes to apply.");
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

    /* publish current diff in an "update" event for the subscribers to update it */
    if ((err_info = sr_shmsub_change_notify_update(mod_info, orig_name, orig_data, timeout_ms,
            &update_edit, cb_err_info))) {
        goto cleanup;
    }
    if (*cb_err_info) {
        /* "update" event failed, just clear the sub SHM and finish */
        err_info = sr_shmsub_change_notify_clear(mod_info);
        goto cleanup;
    }

    /* create new diff if we have an update edit */
    if (update_edit) {
        /* backup the old diff */
        old_diff = mod_info->diff;
        mod_info->diff = NULL;

        /* get new diff using the updated edit */
        if ((err_info = sr_modinfo_edit_apply(mod_info, update_edit, 1))) {
            goto cleanup;
        }

        /* unlock so that we can lock after additonal modules were marked as changed */

        /* CHANGE SUB READ UNLOCK */
        sr_modinfo_changesub_rdunlock(mod_info);
        change_sub_lock = SR_LOCK_NONE;

        /* validate updated data trees and finish new diff */
        switch (mod_info->ds) {
        case SR_DS_STARTUP:
        case SR_DS_RUNNING:
            /* add new modules */
            if ((err_info = sr_shmmod_collect_deps_modinfo(mod_info))) {
                goto cleanup;
            }
            if ((err_info = sr_modinfo_consolidate(mod_info, 0, SR_LOCK_READ, SR_MI_NEW_DEPS | SR_MI_PERM_NO, sid,
                    orig_name, orig_data, 0, 0))) {
                goto cleanup;
            }

            /* validate */
            if ((err_info = sr_modinfo_validate(mod_info, MOD_INFO_CHANGED | MOD_INFO_INV_DEP, 1))) {
                goto cleanup;
            }
            break;
        case SR_DS_CANDIDATE:
            if ((err_info = sr_modinfo_add_defaults(mod_info, 1))) {
                goto cleanup;
            }
            break;
        case SR_DS_OPERATIONAL:
            break;
        }

        /* CHANGE SUB READ LOCK */
        if ((err_info = sr_modinfo_changesub_rdlock(mod_info))) {
            goto cleanup;
        }
        change_sub_lock = SR_LOCK_READ;

        /* put the old diff back */
        new_diff = mod_info->diff;
        mod_info->diff = old_diff;
        old_diff = NULL;

        /* merge diffs into one */
        if ((err_info = sr_modinfo_diff_merge(mod_info, new_diff))) {
            goto cleanup;
        }
    }

    if (!mod_info->diff) {
        SR_LOG_INF("No datastore changes to apply.");
        goto store;
    }

    /* publish final diff in a "change" event for any subscribers and wait for them */
    if ((err_info = sr_shmsub_change_notify_change(mod_info, orig_name, orig_data, timeout_ms, cb_err_info))) {
        goto cleanup;
    }
    if (*cb_err_info) {
        /* "change" event failed, publish "abort" event and finish */
        err_info = sr_shmsub_change_notify_change_abort(mod_info, orig_name, orig_data, timeout_ms);
        goto cleanup;
    }

store:
    if (!mod_info->diff && !sr_modinfo_is_changed(mod_info)) {
        /* there is no diff and no changed modules, nothing to store */
        goto cleanup;
    }

    /* MODULES WRITE LOCK (upgrade) */
    if ((err_info = sr_shmmod_modinfo_rdlock_upgrade(mod_info, sid))) {
        goto cleanup;
    }

    /* store updated datastore */
    if ((err_info = sr_modinfo_data_store(mod_info))) {
        goto cleanup;
    }

    /* MODULES READ LOCK (downgrade) */
    if ((err_info = sr_shmmod_modinfo_wrlock_downgrade(mod_info, sid))) {
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

    /* success */

cleanup:
    if (change_sub_lock) {
        assert(change_sub_lock == SR_LOCK_READ);

        /* CHANGE SUB READ UNLOCK */
        sr_modinfo_changesub_rdunlock(mod_info);
    }
    sr_session_stop(ev_sess);
    lyd_free_all(update_edit);
    lyd_free_all(old_diff);
    lyd_free_all(new_diff);
    return err_info;
}

API int
sr_apply_changes(sr_session_ctx_t *session, uint32_t timeout_ms)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    struct sr_mod_info_s mod_info;
    int mod_deps;

    SR_CHECK_ARG_APIRET(!session, session, err_info);

    if (!session->dt[session->ds].edit) {
        return sr_api_ret(session, NULL);
    }

    if (!timeout_ms) {
        timeout_ms = SR_CHANGE_CB_TIMEOUT;
    }
    /* even for operational datastore, we do not need any running data */
    SR_MODINFO_INIT(mod_info, session->conn, session->ds, session->ds);

    if ((session->ds == SR_DS_OPERATIONAL) || (session->ds == SR_DS_CANDIDATE)) {
        /* stored oper edit or candidate data are not validated so we do not need data from other modules */
        mod_deps = 0;
    } else {
        mod_deps = MOD_INFO_INV_DEP;
    }

    /* collect all required modules */
    if ((err_info = sr_shmmod_collect_edit(session->dt[session->ds].edit, &mod_info))) {
        goto cleanup;
    }

    /* add modules into mod_info with deps, locking, and their data */
    if ((err_info = sr_modinfo_consolidate(&mod_info, mod_deps, SR_LOCK_READ, SR_MI_LOCK_UPGRADEABLE | SR_MI_PERM_NO,
            session->sid, session->orig_name, session->orig_data, 0, 0))) {
        goto cleanup;
    }

    /* create diff */
    if ((err_info = sr_modinfo_edit_apply(&mod_info, session->dt[session->ds].edit, 1))) {
        goto cleanup;
    }

    /* notify all the subscribers and store the changes */
    err_info = sr_changes_notify_store(&mod_info, session, timeout_ms, &cb_err_info);

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    if (!err_info && !cb_err_info) {
        /* free applied edit */
        lyd_free_all(session->dt[session->ds].edit);
        session->dt[session->ds].edit = NULL;
    }

    sr_modinfo_erase(&mod_info);
    if (cb_err_info) {
        /* return callback error if some was generated */
        sr_errinfo_merge(&err_info, cb_err_info);
        sr_errinfo_new(&err_info, SR_ERR_CALLBACK_FAILED, "User callback failed.");
    }
    return sr_api_ret(session, err_info);
}

API int
sr_has_changes(sr_session_ctx_t *session)
{
    if (session && session->dt[session->ds].edit) {
        return 1;
    }

    return 0;
}

API int
sr_discard_changes(sr_session_ctx_t *session)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session, session, err_info);

    if (!session->dt[session->ds].edit) {
        return sr_api_ret(session, NULL);
    }

    lyd_free_all(session->dt[session->ds].edit);
    session->dt[session->ds].edit = NULL;
    return sr_api_ret(session, NULL);
}

/**
 * @brief Replace config data of all or some modules.
 *
 * @param[in] session Session to use.
 * @param[in] ly_mod Optional specific module.
 * @param[in] src_config Source data for the replace, they are spent.
 * @param[in] timeout_ms Change callback timeout in milliseconds.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
_sr_replace_config(sr_session_ctx_t *session, const struct lys_module *ly_mod, struct lyd_node **src_config,
        uint32_t timeout_ms)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    struct sr_mod_info_s mod_info;

    assert(!*src_config || !(*src_config)->prev->next);
    assert(session->ds != SR_DS_OPERATIONAL);
    SR_MODINFO_INIT(mod_info, session->conn, session->ds, session->ds);

    /* single module/all modules */
    if (ly_mod) {
        if ((err_info = sr_modinfo_add(ly_mod, NULL, 0, &mod_info))) {
            goto cleanup;
        }
    } else {
        if ((err_info = sr_modinfo_add_all_modules_with_data(session->conn->ly_ctx, 0, &mod_info))) {
            goto cleanup;
        }
    }

    /* add modules with dependencies into mod_info */
    if ((err_info = sr_modinfo_consolidate(&mod_info, MOD_INFO_INV_DEP, SR_LOCK_READ,
            SR_MI_LOCK_UPGRADEABLE | SR_MI_PERM_NO, session->sid, session->orig_name, session->orig_data, 0, 0))) {
        goto cleanup;
    }

    /* update affected data and create corresponding diff, src_config is spent */
    if ((err_info = sr_modinfo_replace(&mod_info, src_config))) {
        goto cleanup;
    }

    /* notify all the subscribers and store the changes */
    err_info = sr_changes_notify_store(&mod_info, session, timeout_ms, &cb_err_info);

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    sr_modinfo_erase(&mod_info);
    if (cb_err_info) {
        /* return callback error if some was generated */
        sr_errinfo_merge(&err_info, cb_err_info);
        sr_errinfo_new(&err_info, SR_ERR_CALLBACK_FAILED, "User callback failed.");
    }
    return err_info;
}

API int
sr_replace_config(sr_session_ctx_t *session, const char *module_name, struct lyd_node *src_config, uint32_t timeout_ms)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod = NULL;

    SR_CHECK_ARG_APIRET(!session || !SR_IS_CONVENTIONAL_DS(session->ds), session, err_info);

    if (src_config && (session->conn->ly_ctx != LYD_CTX(src_config))) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Data trees must be created using the session connection libyang context.");
        return sr_api_ret(session, err_info);
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
            goto cleanup;
        } else if (!strcmp(ly_mod->name, "sysrepo")) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Data of internal module \"sysrepo\" cannot be modified.");
            goto cleanup;
        }
    }

    /* replace the data */
    if ((err_info = _sr_replace_config(session, ly_mod, &src_config, timeout_ms))) {
        goto cleanup;
    }

    /* success */

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
    SR_MODINFO_INIT(mod_info, session->conn, src_datastore, src_datastore);

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
        if ((err_info = sr_modinfo_add(ly_mod, NULL, 0, &mod_info))) {
            goto cleanup;
        }
    } else {
        if ((err_info = sr_modinfo_add_all_modules_with_data(session->conn->ly_ctx, 0, &mod_info))) {
            goto cleanup;
        }
    }

    if ((src_datastore == SR_DS_RUNNING) && (session->ds == SR_DS_CANDIDATE)) {
        /* add modules into mod_info without data */
        if ((err_info = sr_modinfo_consolidate(&mod_info, 0, SR_LOCK_WRITE, SR_MI_DATA_NO | SR_MI_PERM_NO, session->sid,
                session->orig_name, session->orig_data, 0, 0))) {
            goto cleanup;
        }

        /* special case, just reset candidate */
        err_info = sr_modinfo_candidate_reset(&mod_info);
        goto cleanup;
    }

    /* add modules into mod_info */
    if ((err_info = sr_modinfo_consolidate(&mod_info, 0, SR_LOCK_READ, SR_MI_PERM_NO, session->sid, session->orig_name,
            session->orig_data, 0, 0))) {
        goto cleanup;
    }

    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    /* replace the data */
    if ((err_info = _sr_replace_config(session, ly_mod, &mod_info.data, timeout_ms))) {
        goto cleanup;
    }

    if ((src_datastore == SR_DS_CANDIDATE) && (session->ds == SR_DS_RUNNING)) {
        /* MODULES WRITE LOCK */
        if ((err_info = sr_shmmod_modinfo_wrlock(&mod_info, session->sid))) {
            goto cleanup;
        }

        /* reset candidate after it was applied in running */
        err_info = sr_modinfo_candidate_reset(&mod_info);
        goto cleanup;
    }

    /* success */

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    sr_modinfo_erase(&mod_info);
    return sr_api_ret(session, err_info);
}

/**
 * @brief (Un)lock datastore locks.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] lock Whether to lock or unlock.
 * @param[in] sid Sysrepo session ID.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_change_dslock(struct sr_mod_info_s *mod_info, int lock, uint32_t sid)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    uint32_t i, j;
    int rc, ds_lock = 0, modified;
    struct sr_mod_info_mod_s *mod;
    struct sr_mod_lock_s *shm_lock;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        shm_lock = &mod->shm_mod->data_lock_info[mod_info->ds];

        assert(mod->state & MOD_INFO_REQ);

        /* DS LOCK */
        if ((err_info = sr_mlock(&shm_lock->ds_lock, SR_DS_LOCK_TIMEOUT, __func__, NULL, NULL))) {
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
            if ((rc = mod->ds_plg->candidate_modified_cb(mod->ly_mod, &modified))) {
                SR_ERRINFO_DSPLUGIN(&err_info, rc, "candidate_modified", mod->ds_plg->name, mod->ly_mod->name);
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
            shm_lock->ds_lock_sid = sid;
            sr_time_get(&shm_lock->ds_lock_ts, 0);
        } else {
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
        if ((tmp_err = sr_mlock(&shm_lock->ds_lock, SR_DS_LOCK_TIMEOUT, __func__, NULL, NULL))) {
            sr_errinfo_free(&tmp_err);
        } else {
            if (lock) {
                shm_lock->ds_lock_sid = 0;
                memset(&shm_lock->ds_lock_ts, 0, sizeof shm_lock->ds_lock_ts);
            } else {
                shm_lock->ds_lock_sid = sid;
                sr_time_get(&shm_lock->ds_lock_ts, 0);
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
 * @return err_code (SR_ERR_OK on success).
 */
static int
_sr_un_lock(sr_session_ctx_t *session, const char *module_name, int lock)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_s mod_info;
    const struct lys_module *ly_mod = NULL;

    SR_CHECK_ARG_APIRET(!session || !SR_IS_CONVENTIONAL_DS(session->ds), session, err_info);

    SR_MODINFO_INIT(mod_info, session->conn, session->ds, session->ds);

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
        if ((err_info = sr_modinfo_add(ly_mod, NULL, 0, &mod_info))) {
            goto cleanup;
        }
    } else {
        if ((err_info = sr_modinfo_add_all_modules_with_data(session->conn->ly_ctx, 0, &mod_info))) {
            goto cleanup;
        }
    }
    if ((err_info = sr_modinfo_consolidate(&mod_info, 0, SR_LOCK_WRITE, SR_MI_DATA_NO | SR_MI_PERM_READ |
            SR_MI_PERM_STRICT, session->sid, session->orig_name, session->orig_data, 0, 0))) {
        goto cleanup;
    }

    /* DS-(un)lock them */
    if ((err_info = sr_change_dslock(&mod_info, lock, session->sid))) {
        goto cleanup;
    }

    /* candidate datastore unlocked, reset its state */
    if (!lock && (mod_info.ds == SR_DS_CANDIDATE)) {
        if ((err_info = sr_modinfo_candidate_reset(&mod_info))) {
            goto cleanup;
        }
    }

    /* success */

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    sr_modinfo_erase(&mod_info);
    return sr_api_ret(session, err_info);
}

API int
sr_lock(sr_session_ctx_t *session, const char *module_name)
{
    return _sr_un_lock(session, module_name, 1);
}

API int
sr_unlock(sr_session_ctx_t *session, const char *module_name)
{
    return _sr_un_lock(session, module_name, 0);
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
    SR_MODINFO_INIT(mod_info, conn, datastore, datastore);

    /* no lock required, accessing only main SHM (modules) */

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
        if ((err_info = sr_modinfo_add(ly_mod, NULL, 0, &mod_info))) {
            goto cleanup;
        }
    } else {
        if ((err_info = sr_modinfo_add_all_modules_with_data(conn->ly_ctx, 0, &mod_info))) {
            goto cleanup;
        }
    }
    if ((err_info = sr_modinfo_consolidate(&mod_info, 0, SR_LOCK_NONE, SR_MI_DATA_NO | SR_MI_PERM_READ |
            SR_MI_PERM_STRICT, 0, NULL, NULL, 0, 0))) {
        goto cleanup;
    }

    /* check DS-lock of the module(s) */
    ds_locked = 1;
    sid = 0;
    for (i = 0; (i < mod_info.mod_count) && ds_locked; ++i) {
        shm_lock = &mod_info.mods[i].shm_mod->data_lock_info[mod_info.ds];

        /* DS LOCK */
        if ((err_info = sr_mlock(&shm_lock->ds_lock, SR_DS_LOCK_TIMEOUT, __func__, NULL, NULL))) {
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

    /* success */

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    sr_modinfo_erase(&mod_info);
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
sr_subscription_process_events(sr_subscription_ctx_t *subscription, sr_session_ctx_t *session, struct timespec *stop_time_in)
{
    sr_error_info_t *err_info = NULL;
    int ret, mod_finished;
    char buf[1];
    uint32_t i;

    /* session does not have to be set */
    SR_CHECK_ARG_APIRET(!subscription, session, err_info);

    if (stop_time_in) {
        memset(stop_time_in, 0, sizeof *stop_time_in);
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

    /* change subscriptions */
    for (i = 0; i < subscription->change_sub_count; ++i) {
        if ((err_info = sr_shmsub_change_listen_process_module_events(&subscription->change_subs[i], subscription->conn))) {
            goto cleanup_unlock;
        }
    }

    /* operational subscriptions */
    for (i = 0; i < subscription->oper_sub_count; ++i) {
        if ((err_info = sr_shmsub_oper_listen_process_module_events(&subscription->oper_subs[i], subscription->conn))) {
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
        if ((err_info = sr_shmsub_notif_listen_module_stop_time(&subscription->notif_subs[i], SR_LOCK_READ,
                subscription, &mod_finished))) {
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
        sr_shmsub_notif_listen_module_get_stop_time_in(&subscription->notif_subs[i], stop_time_in);

        /* next iteration */
        ++i;
    }

cleanup_unlock:
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
    } else if (sr_subscr_oper_sub_find(subscription, sub_id, &module_name)) {
        /* oper sub */
        if ((err_info = sr_shmext_oper_sub_suspended(subscription->conn, module_name, sub_id, -1, suspended))) {
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
    const char *module_name, *path;
    sr_datastore_t ds;
    sr_session_ctx_t *ev_sess = NULL;
    struct timespec cur_time;

    assert(subscription && sub_id);

    /* find the subscription in the subscription context and read its suspended from ext SHM */
    if (sr_subscr_change_sub_find(subscription, sub_id, &module_name, &ds)) {
        /* change sub */
        if ((err_info = sr_shmext_change_sub_suspended(subscription->conn, module_name, ds, sub_id, suspend, NULL))) {
            goto cleanup;
        }
    } else if (sr_subscr_oper_sub_find(subscription, sub_id, &module_name)) {
        /* oper sub */
        if ((err_info = sr_shmext_oper_sub_suspended(subscription->conn, module_name, sub_id, suspend, NULL))) {
            goto cleanup;
        }
    } else if ((notif_sub = sr_subscr_notif_sub_find(subscription, sub_id, &module_name))) {
        /* notif sub */
        if ((err_info = sr_shmext_notif_sub_suspended(subscription->conn, module_name, sub_id, suspend, NULL))) {
            goto cleanup;
        }
    } else if (sr_subscr_rpc_sub_find(subscription, sub_id, &path)) {
        /* RPC/action sub */
        if ((err_info = sr_shmext_rpc_sub_suspended(subscription->conn, path, sub_id, suspend, NULL))) {
            goto cleanup;
        }
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
        sr_time_get(&cur_time, 0);
        if ((err_info = sr_notif_call_callback(ev_sess, notif_sub->cb, notif_sub->tree_cb, notif_sub->private_data,
                suspend ? SR_EV_NOTIF_SUSPENDED : SR_EV_NOTIF_RESUMED, sub_id, NULL, &cur_time))) {
            goto cleanup;
        }
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

    err_info = sr_subscr_del(subscription, sub_id, SR_LOCK_NONE);
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
    if ((err_info = sr_shmsub_notify_evpipe(subscription->evpipe_num))) {
        return sr_api_ret(NULL, err_info);
    }

    return sr_api_ret(NULL, NULL);
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

    /* delete a specific subscription or delete all subscriptions which also removes this subscription from all the sessions */
    if ((err_info = sr_subscr_del(subscription, 0, SR_LOCK_NONE))) {
        return err_info;
    }

    /* no new events can be generated at this point */

    if (ATOMIC_LOAD_RELAXED(subscription->thread_running)) {
        /* signal the thread to quit */
        ATOMIC_STORE_RELAXED(subscription->thread_running, 0);

        /* generate a new event for the thread to wake up */
        if ((tmp_err = sr_shmsub_notify_evpipe(subscription->evpipe_num))) {
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

    SR_MODINFO_INIT((*mod_info), session->conn, session->ds, session->ds == SR_DS_OPERATIONAL ? SR_DS_RUNNING : session->ds);

    /* create mod_info structure with this module only, do not use cache to allow reading data in the callback
     * (avoid dead-lock) */
    if ((err_info = sr_modinfo_add(ly_mod, NULL, 0, mod_info))) {
        goto cleanup;
    }
    if ((err_info = sr_modinfo_consolidate(mod_info, 0, SR_LOCK_READ, SR_MI_PERM_NO, session->sid, session->orig_name,
            session->orig_data, 0, 0))) {
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
        err_code = callback(ev_sess, sub_id, ly_mod->name, xpath, sr_ev2api(ev_sess->ev), 0, private_data);
        if (err_code != SR_ERR_OK) {
            /* callback failed but it is the only one so no "abort" event is necessary */
            if (ev_sess->ev_error.message || ev_sess->ev_error.format) {
                /* remember callback error info */
                sr_errinfo_new_data(&err_info, err_code, ev_sess->ev_error.format, ev_sess->ev_error.data,
                        ev_sess->ev_error.message ? ev_sess->ev_error.message : sr_strerror(err_code));
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
    mode_t um;

    /* allocate new subscription */
    *subs_p = calloc(1, sizeof **subs_p);
    SR_CHECK_MEM_RET(!*subs_p, err_info);
    sr_rwlock_init(&(*subs_p)->subs_lock, 0);
    (*subs_p)->conn = conn;
    (*subs_p)->evpipe = -1;

    /* get new event pipe number and increment it */
    (*subs_p)->evpipe_num = ATOMIC_INC_RELAXED(SR_CONN_MAIN_SHM((*subs_p)->conn)->new_evpipe_num);
    if ((*subs_p)->evpipe_num == (uint32_t)(ATOMIC_T_MAX - 1)) {
        /* the value in the main SHM is actually ATOMIC_T_MAX and calling another INC would cause an overflow */
        ATOMIC_STORE_RELAXED(SR_CONN_MAIN_SHM((*subs_p)->conn)->new_evpipe_num, 1);
    }

    /* get event pipe name */
    if ((err_info = sr_path_evpipe((*subs_p)->evpipe_num, &path))) {
        goto error;
    }

    /* set umask so that the correct permissions are really set */
    um = umask(SR_UMASK);

    /* create the event pipe */
    ret = mkfifo(path, SR_EVPIPE_PERM);
    umask(um);
    if (ret == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "mkfifo");
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
    free(*subs_p);
    return err_info;
}

API int
sr_module_change_subscribe(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        sr_module_change_cb callback, void *private_data, uint32_t priority, sr_subscr_options_t opts,
        sr_subscription_ctx_t **subscription)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    sr_lock_mode_t chsub_lock_mode = SR_LOCK_NONE;
    const struct lys_module *ly_mod;
    struct sr_mod_info_s mod_info;
    sr_conn_ctx_t *conn;
    uint32_t sub_id;
    sr_subscr_options_t sub_opts;
    sr_mod_t *shm_mod;

    SR_CHECK_ARG_APIRET(!session || SR_IS_EVENT_SESS(session) || !module_name || !callback ||
            ((opts & SR_SUBSCR_PASSIVE) && (opts & SR_SUBSCR_ENABLED)) || !subscription, session, err_info);

    if ((opts & SR_SUBSCR_CTX_REUSE) && !*subscription) {
        /* invalid option, remove */
        opts &= ~SR_SUBSCR_CTX_REUSE;
    }

    /* just make it valid */
    SR_MODINFO_INIT(mod_info, session->conn, SR_DS_RUNNING, SR_DS_RUNNING);

    conn = session->conn;
    /* only these options are relevant outside this function and will be stored */
    sub_opts = opts & (SR_SUBSCR_DONE_ONLY | SR_SUBSCR_PASSIVE | SR_SUBSCR_UPDATE);

    /* is the module name valid? */
    ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, module_name);
    if (!ly_mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
        goto cleanup;
    }

    /* check write/read perm */
    if ((err_info = sr_perm_check(session->conn, ly_mod, session->ds, (opts & SR_SUBSCR_PASSIVE) ? 0 : 1, NULL))) {
        goto cleanup;
    }

    /* get new sub ID */
    sub_id = ATOMIC_INC_RELAXED(SR_CONN_MAIN_SHM(conn)->new_sub_id);
    if (sub_id == (uint32_t)(ATOMIC_T_MAX - 1)) {
        /* the value in the main SHM is actually ATOMIC_T_MAX and calling another INC would cause an overflow */
        ATOMIC_STORE_RELAXED(SR_CONN_MAIN_SHM(conn)->new_sub_id, 1);
    }

    /* find the module in SHM */
    shm_mod = sr_shmmain_find_module(SR_CONN_MAIN_SHM(conn), module_name);
    SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup);

    if (opts & SR_SUBSCR_ENABLED) {
        /* we need to lock write subscriptions here to keep CHANGE SUB and MODULES lock order */

        /* CHANGE SUB WRITE LOCK */
        if ((err_info = sr_rwlock(&shm_mod->change_sub[session->ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE,
                conn->cid, __func__, NULL, NULL))) {
            goto cleanup;
        }
        chsub_lock_mode = SR_LOCK_WRITE;

        /* call the callback with the current configuration, keep any used modules locked in mod_info */
        if ((err_info = sr_module_change_subscribe_enable(session, &mod_info, ly_mod, xpath, callback, private_data,
                sub_id, opts))) {
            goto cleanup;
        }
    }

    if (!(opts & SR_SUBSCR_CTX_REUSE)) {
        /* create a new subscription */
        if ((err_info = sr_subscr_new(conn, opts, subscription))) {
            goto cleanup;
        }
    } else if (opts & SR_SUBSCR_THREAD_SUSPEND) {
        /* suspend the running thread */
        _sr_subscription_thread_suspend(*subscription);
    }

    /* add module subscription into ext SHM */
    if ((err_info = sr_shmext_change_sub_add(conn, shm_mod, chsub_lock_mode, session->ds, sub_id, xpath, priority,
            sub_opts, (*subscription)->evpipe_num))) {
        goto error1;
    }

    /* add subscription into structure and create separate specific SHM segment */
    if ((err_info = sr_subscr_change_sub_add(*subscription, sub_id, session, module_name, xpath, callback, private_data,
            priority, sub_opts, 0))) {
        goto error2;
    }

    /* add the subscription into session */
    if ((err_info = sr_ptr_add(&session->ptr_lock, (void ***)&session->subscriptions, &session->subscription_count,
            *subscription))) {
        goto error3;
    }

    /* success */
    goto cleanup;

error3:
    sr_subscr_change_sub_del(*subscription, sub_id, SR_LOCK_NONE);

error2:
    if ((tmp_err = sr_shmext_change_sub_del(conn, shm_mod, chsub_lock_mode, session->ds, sub_id))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }

error1:
    if (!(opts & SR_SUBSCR_CTX_REUSE)) {
        _sr_unsubscribe(*subscription);
        *subscription = NULL;
    }

cleanup:
    if (chsub_lock_mode != SR_LOCK_NONE) {
        /* CHANGE SUB UNLOCK */
        sr_rwunlock(&shm_mod->change_sub[session->ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, chsub_lock_mode, conn->cid, __func__);
    }

    /* if there are any modules, unlock them after the enabled event was handled and the subscription was added
     * to avoid losing any changes */

    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    sr_modinfo_erase(&mod_info);
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

    /* update xpath in the subscription */
    free(change_sub->xpath);
    change_sub->xpath = NULL;
    if (xpath) {
        change_sub->xpath = strdup(xpath);
        SR_CHECK_MEM_GOTO(!change_sub->xpath, err_info, cleanup_unlock);
    }

    /* find the module in SHM */
    shm_mod = sr_shmmain_find_module(SR_CONN_MAIN_SHM(subscription->conn), module_name);
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
            if (lyd_dup_siblings(session->dt[session->ds].diff, NULL, LYD_DUP_RECURSIVE, &(*iter)->diff)) {
                sr_errinfo_new_ly(&err_info, session->conn->ly_ctx);
                goto error;
            }
        }
        if (lyd_find_xpath(session->dt[session->ds].diff, xpath, &(*iter)->set)) {
            sr_errinfo_new_ly(&err_info, session->conn->ly_ctx);
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
    LY_ERR lyrc;

    sr_val = calloc(1, sizeof *sr_val);
    SR_CHECK_MEM_GOTO(!sr_val, err_info, cleanup);

    if (value_str) {
        /* replace the value in a node copy so that this specific one is stored */
        assert(node->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST));
        lyrc = lyd_dup_single(node, NULL, 0, &node_dup);
        if (lyrc) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(node));
            goto cleanup;
        }

        lyrc = lyd_change_term(node_dup, value_str);
        if (lyrc && (lyrc != LY_EEXIST) && (lyrc != LY_ENOT)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(node));
            goto cleanup;
        }
        node_dup->parent = node->parent;
        node_dup->flags |= node->flags & LYD_DEFAULT;

        node_ptr = node_dup;
    } else {
        node_ptr = node;
    }

    /* fill the sr value */
    if ((err_info = sr_val_ly2sr(node_ptr, sr_val))) {
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
    } else if (node->schema->nodetype & LYS_ANYDATA) {
        /* TODO */
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
    const char *meta_name;
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
        if (lysc_is_dup_inst_list(node->schema)) {
            meta_name = "yang:position";
        } else if (node->schema->nodetype == LYS_LEAFLIST) {
            meta_name = "yang:value";
        } else {
            assert(node->schema->nodetype == LYS_LIST);
            meta_name = "yang:key";
        }
        /* attribute contains the value of the node before in the order */
        meta = lyd_find_meta(node->meta, NULL, meta_name);
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
    const char *meta_name;

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
        for (meta = (*node)->meta;
                meta && (strcmp(meta->annotation->module->name, "yang") || strcmp(meta->name, "orig-value"));
                meta = meta->next) {}

        /* "orig-default" holds the previous default flag value */
        for (meta2 = (*node)->meta;
                meta2 && (strcmp(meta2->annotation->module->name, "yang") || strcmp(meta2->name, "orig-default"));
                meta2 = meta2->next) {}

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
        if ((*node)->schema->nodetype == LYS_LEAFLIST) {
            meta_name = "value";
        } else {
            assert((*node)->schema->nodetype == LYS_LIST);
            meta_name = "key";
        }

        /* attribute contains the value (predicates) of the preceding instance in the order */
        for (meta = (*node)->meta;
                meta && (strcmp(meta->annotation->module->name, "yang") || strcmp(meta->name, meta_name));
                meta = meta->next) {}
        if (!meta) {
            SR_ERRINFO_INT(&err_info);
            return sr_api_ret(session, err_info);
        }
        if ((*node)->schema->nodetype == LYS_LEAFLIST) {
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
    const struct lysc_node *op;
    const struct lys_module *ly_mod;
    uint32_t sub_id;
    sr_conn_ctx_t *conn;
    sr_rpc_t *shm_rpc;

    SR_CHECK_ARG_APIRET(!session || SR_IS_EVENT_SESS(session) || !xpath || (!callback && !tree_callback) || !subscription,
            session, err_info);

    if ((opts & SR_SUBSCR_CTX_REUSE) && !*subscription) {
        /* invalid option, remove */
        opts &= ~SR_SUBSCR_CTX_REUSE;
    }

    conn = session->conn;
    module_name = sr_get_first_ns(xpath);
    if (!module_name) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Invalid xpath \"%s\".", xpath);
        goto error1;
    }

    /* is the module name valid? */
    ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, module_name);
    if (!ly_mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", module_name);
        goto error1;
    }

    /* check write perm */
    if ((err_info = sr_perm_check(conn, ly_mod, SR_DS_STARTUP, 1, NULL))) {
        goto error1;
    }

    /* is the xpath valid? */
    if ((err_info = sr_get_trim_predicates(xpath, &path))) {
        goto error1;
    }

    if (!(op = lys_find_path(conn->ly_ctx, NULL, path, 0))) {
        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
        goto error1;
    }
    if (!(op->nodetype & (LYS_RPC | LYS_ACTION))) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Path \"%s\" does not identify an RPC nor an action.", path);
        goto error1;
    }

    if (!(opts & SR_SUBSCR_CTX_REUSE)) {
        /* create a new subscription */
        if ((err_info = sr_subscr_new(conn, opts, subscription))) {
            goto error1;
        }
    } else if (opts & SR_SUBSCR_THREAD_SUSPEND) {
        /* suspend the running thread */
        _sr_subscription_thread_suspend(*subscription);
    }

    /* get new sub ID */
    sub_id = ATOMIC_INC_RELAXED(SR_CONN_MAIN_SHM(conn)->new_sub_id);
    if (sub_id == (uint32_t)(ATOMIC_T_MAX - 1)) {
        /* the value in the main SHM is actually ATOMIC_T_MAX and calling another INC would cause an overflow */
        ATOMIC_STORE_RELAXED(SR_CONN_MAIN_SHM(conn)->new_sub_id, 1);
    }

    /* find the RPC */
    shm_rpc = sr_shmmain_find_rpc(SR_CONN_MAIN_SHM(conn), path);
    SR_CHECK_INT_GOTO(!shm_rpc, err_info, error2);

    /* add RPC/action subscription into ext SHM */
    if ((err_info = sr_shmext_rpc_sub_add(conn, shm_rpc, sub_id, xpath, priority, 0, (*subscription)->evpipe_num))) {
        goto error2;
    }

    /* add subscription into structure and create separate specific SHM segment */
    if ((err_info = sr_subscr_rpc_sub_add(*subscription, sub_id, session, path, xpath, callback, tree_callback,
            private_data, priority, 0))) {
        goto error3;
    }

    /* add the subscription into session */
    if ((err_info = sr_ptr_add(&session->ptr_lock, (void ***)&session->subscriptions, &session->subscription_count,
            *subscription))) {
        goto error4;
    }

    free(module_name);
    free(path);
    return sr_api_ret(session, err_info);

error4:
    sr_subscr_rpc_sub_del(*subscription, sub_id, SR_LOCK_NONE);

error3:
    if ((tmp_err = sr_shmext_rpc_sub_del(conn, shm_rpc, sub_id))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }

error2:
    if (!(opts & SR_SUBSCR_CTX_REUSE)) {
        _sr_unsubscribe(*subscription);
        *subscription = NULL;
    }

error1:
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
    struct lyd_node *input_tree = NULL, *output_tree = NULL, *elem;
    char *val_str, buf[22];
    size_t i;
    int ret;

    SR_CHECK_ARG_APIRET(!session || !output || !output_cnt, session, err_info);

    if (!timeout_ms) {
        timeout_ms = SR_RPC_CB_TIMEOUT;
    }
    *output = NULL;
    *output_cnt = 0;

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
    if ((ret = sr_rpc_send_tree(session, input_tree, timeout_ms, &output_tree)) != SR_ERR_OK) {
        lyd_free_all(input_tree);
        return ret;
    }

    /* transform data tree into an output */
    assert(output_tree && (output_tree->schema->nodetype & (LYS_RPC | LYS_ACTION)));
    *output_cnt = 0;
    *output = NULL;
    LYD_TREE_DFS_BEGIN(output_tree, elem) {
        if (elem != output_tree) {
            /* allocate new sr_val */
            *output = sr_realloc(*output, (*output_cnt + 1) * sizeof **output);
            SR_CHECK_MEM_GOTO(!*output, err_info, cleanup);

            /* fill it */
            if ((err_info = sr_val_ly2sr(elem, &(*output)[*output_cnt]))) {
                goto cleanup;
            }

            /* now the new value is valid */
            ++(*output_cnt);
        }

        LYD_TREE_DFS_END(output_tree, elem);
    }

    /* success */

cleanup:
    lyd_free_all(input_tree);
    lyd_free_all(output_tree);
    if (err_info) {
        sr_free_values(*output, *output_cnt);
    }
    return sr_api_ret(session, err_info);
}

API int
sr_rpc_send_tree(sr_session_ctx_t *session, struct lyd_node *input, uint32_t timeout_ms, struct lyd_node **output)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    struct sr_mod_info_s mod_info;
    sr_rpc_t *shm_rpc;
    struct lyd_node *input_op;
    sr_dep_t *shm_deps;
    uint16_t shm_dep_count;
    char *path = NULL, *str, *parent_path = NULL;
    uint32_t event_id = 0;

    SR_CHECK_ARG_APIRET(!session || !input || !output, session, err_info);
    if (session->conn->ly_ctx != input->schema->module->ctx) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Data trees must be created using the session connection libyang context.");
        return sr_api_ret(session, err_info);
    }

    if (!timeout_ms) {
        timeout_ms = SR_RPC_CB_TIMEOUT;
    }
    *output = NULL;
    SR_MODINFO_INIT(mod_info, session->conn, SR_DS_OPERATIONAL, SR_DS_RUNNING);

    /* check input data tree */
    switch (input->schema->nodetype) {
    case LYS_ACTION:
        for (input_op = input; input->parent; input = lyd_parent(input)) {}
        break;
    case LYS_RPC:
        input_op = input;
        break;
    case LYS_CONTAINER:
    case LYS_LIST:
        /* find the action */
        input_op = input;
        if ((err_info = sr_ly_find_last_parent(&input_op, LYS_ACTION))) {
            goto cleanup;
        }
        if (input_op->schema->nodetype == LYS_ACTION) {
            break;
        }
    /* fallthrough */
    default:
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Provided input is not a valid RPC or action invocation.");
        goto cleanup;
    }

    /* check read perm */
    if ((err_info = sr_perm_check(session->conn, lyd_owner_module(input), SR_DS_STARTUP, 0, NULL))) {
        goto cleanup;
    }

    /* get operation path (without predicates) */
    str = lyd_path(input_op, LYD_PATH_STD, NULL, 0);
    SR_CHECK_INT_GOTO(!str, err_info, cleanup);
    err_info = sr_get_trim_predicates(str, &path);
    free(str);
    if (err_info) {
        goto cleanup;
    }

    if (input != input_op) {
        /* we need the OP parent to check it exists */
        parent_path = lyd_path(lyd_parent(input_op), LYD_PATH_STD, NULL, 0);
        SR_CHECK_MEM_GOTO(!parent_path, err_info, cleanup);
        /* only reference to parent_path is stored, so it cannot be freed! */
        if ((err_info = sr_modinfo_add(lyd_owner_module(input), parent_path, 0, &mod_info))) {
            goto cleanup;
        }
        if ((err_info = sr_modinfo_consolidate(&mod_info, 0, SR_LOCK_READ, SR_MI_DATA_CACHE | SR_MI_PERM_NO,
                session->sid, session->orig_name, session->orig_data, SR_OPER_CB_TIMEOUT, 0))) {
            goto cleanup;
        }
    }

    /* collect all required module dependencies for input validation */
    if ((err_info = sr_shmmod_get_rpc_deps(SR_CONN_MAIN_SHM(session->conn), path, 0, &shm_deps, &shm_dep_count))) {
        goto cleanup;
    }
    if ((err_info = sr_shmmod_collect_deps(SR_CONN_MAIN_SHM(session->conn), shm_deps, shm_dep_count,
            session->conn->ly_ctx, input, &mod_info))) {
        goto cleanup;
    }
    if ((err_info = sr_modinfo_consolidate(&mod_info, 0, SR_LOCK_READ, SR_MI_NEW_DEPS | SR_MI_DATA_CACHE | SR_MI_PERM_NO,
            session->sid, session->orig_name, session->orig_data, SR_OPER_CB_TIMEOUT, 0))) {
        goto cleanup;
    }

    /* validate the operation, must be valid only at the time of execution */
    if ((err_info = sr_modinfo_op_validate(&mod_info, input_op, 0))) {
        goto cleanup;
    }

    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    sr_modinfo_erase(&mod_info);
    SR_MODINFO_INIT(mod_info, session->conn, SR_DS_OPERATIONAL, SR_DS_RUNNING);

    /* find the RPC */
    shm_rpc = sr_shmmain_find_rpc(SR_CONN_MAIN_SHM(session->conn), path);
    SR_CHECK_INT_GOTO(!shm_rpc, err_info, cleanup);

    /* RPC SUB READ LOCK */
    if ((err_info = sr_rwlock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, session->conn->cid, __func__,
            NULL, NULL))) {
        goto cleanup;
    }

    /* publish RPC in an event and wait for a reply from the last subscriber */
    if ((err_info = sr_shmsub_rpc_notify(session->conn, shm_rpc, path, input, session->orig_name, session->orig_data,
            timeout_ms, &event_id, output, &cb_err_info))) {
        goto cleanup_rpcsub_unlock;
    }

    if (cb_err_info) {
        /* "rpc" event failed, publish "abort" event and finish */
        err_info = sr_shmsub_rpc_notify_abort(session->conn, shm_rpc, path, input, session->orig_name, session->orig_data,
                timeout_ms, event_id);
        goto cleanup_rpcsub_unlock;
    }

    /* RPC SUB READ UNLOCK */
    sr_rwunlock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, session->conn->cid, __func__);

    /* find operation */
    if ((err_info = sr_ly_find_last_parent(output, LYS_RPC | LYS_ACTION))) {
        goto cleanup;
    }

    /* collect all required modules for output validation */
    if ((err_info = sr_shmmod_get_rpc_deps(SR_CONN_MAIN_SHM(session->conn), path, 1, &shm_deps, &shm_dep_count))) {
        goto cleanup;
    }
    if ((err_info = sr_shmmod_collect_deps(SR_CONN_MAIN_SHM(session->conn), shm_deps, shm_dep_count,
            session->conn->ly_ctx, input, &mod_info))) {
        goto cleanup;
    }
    if ((err_info = sr_modinfo_consolidate(&mod_info, 0, SR_LOCK_READ, SR_MI_NEW_DEPS | SR_MI_DATA_CACHE | SR_MI_PERM_NO,
            session->sid, session->orig_name, session->orig_data, SR_OPER_CB_TIMEOUT, 0))) {
        goto cleanup;
    }

    /* validate the output */
    if ((err_info = sr_modinfo_op_validate(&mod_info, *output, 1))) {
        goto cleanup;
    }

    /* success */
    goto cleanup;

cleanup_rpcsub_unlock:
    /* RPC SUB READ UNLOCK */
    sr_rwunlock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, session->conn->cid, __func__);

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    free(parent_path);
    free(path);
    sr_modinfo_erase(&mod_info);
    if (cb_err_info) {
        /* return callback error if some was generated */
        sr_errinfo_merge(&err_info, cb_err_info);
        sr_errinfo_new(&err_info, SR_ERR_CALLBACK_FAILED, "User callback failed.");
    }
    if (err_info) {
        /* free any received output in case of an error */
        lyd_free_all(*output);
        *output = NULL;
    }
    return sr_api_ret(session, err_info);
}

/**
 * @brief libyang callback for full module traversal when searching for a notification.
 */
static LY_ERR
sr_event_notif_lysc_dfs_cb(struct lysc_node *node, void *data, ly_bool *dfs_continue)
{
    int *found = (int *)data;

    (void)dfs_continue;

    if (node->nodetype == LYS_NOTIF) {
        *found = 1;

        /* just stop the traversal */
        return LY_EEXIST;
    }

    return LY_SUCCESS;
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
    struct ly_set *set;
    struct timespec listen_since, cur_ts;
    const struct lys_module *ly_mod;
    sr_conn_ctx_t *conn;
    uint32_t i, sub_id;
    sr_mod_t *shm_mod;
    LY_ERR lyrc;
    int found;

    sr_time_get(&cur_ts, 0);

    SR_CHECK_ARG_APIRET(!session || SR_IS_EVENT_SESS(session) || !mod_name ||
            (start_time && (sr_time_cmp(start_time, &cur_ts) > 0)) ||
            (stop_time && ((start_time && (sr_time_cmp(stop_time, start_time) < 0)) ||
            (!start_time && (sr_time_cmp(stop_time, &cur_ts) < 0)))) ||
            (!callback && !tree_callback) || !subscription, session, err_info);

    /* is the module name valid? */
    ly_mod = ly_ctx_get_module_implemented(session->conn->ly_ctx, mod_name);
    if (!ly_mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" was not found in sysrepo.", mod_name);
        return sr_api_ret(session, err_info);
    }

    /* check write perm */
    if ((err_info = sr_perm_check(session->conn, ly_mod, SR_DS_STARTUP, 1, NULL))) {
        return sr_api_ret(session, err_info);
    }

    if ((opts & SR_SUBSCR_CTX_REUSE) && !*subscription) {
        /* invalid option, remove */
        opts &= ~SR_SUBSCR_CTX_REUSE;
    }

    conn = session->conn;

    /* is the xpath/module valid? */
    found = 0;
    if (xpath) {
        lyrc = lys_find_xpath_atoms(conn->ly_ctx, NULL, xpath, 0, &set);
        if (lyrc) {
            sr_errinfo_new_ly(&err_info, ly_mod->ctx);
            return sr_api_ret(session, err_info);
        }

        /* there must be some notifications selected */
        for (i = 0; i < set->count; ++i) {
            if (set->snodes[i]->nodetype == LYS_NOTIF) {
                found = 1;
                break;
            }
        }
        ly_set_free(set, NULL);
    } else {
        lysc_module_dfs_full(ly_mod, sr_event_notif_lysc_dfs_cb, &found);
    }

    if (!found) {
        if (xpath) {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "XPath \"%s\" does not select any notifications.", xpath);
        } else {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" does not define any notifications.", ly_mod->name);
        }
        return sr_api_ret(session, err_info);
    }

    if (!(opts & SR_SUBSCR_CTX_REUSE)) {
        /* create a new subscription */
        if ((err_info = sr_subscr_new(conn, opts, subscription))) {
            return sr_api_ret(session, err_info);
        }
    } else if (opts & SR_SUBSCR_THREAD_SUSPEND) {
        /* suspend the running thread */
        _sr_subscription_thread_suspend(*subscription);
    }

    /* get new sub ID */
    sub_id = ATOMIC_INC_RELAXED(SR_CONN_MAIN_SHM(conn)->new_sub_id);
    if (sub_id == (uint32_t)(ATOMIC_T_MAX - 1)) {
        /* the value in the main SHM is actually ATOMIC_T_MAX and calling another INC would cause an overflow */
        ATOMIC_STORE_RELAXED(SR_CONN_MAIN_SHM(conn)->new_sub_id, 1);
    }

    /* find module */
    shm_mod = sr_shmmain_find_module(SR_CONN_MAIN_SHM(conn), ly_mod->name);
    SR_CHECK_INT_GOTO(!shm_mod, err_info, error1);

    /* add notification subscription into main SHM and create separate specific SHM segment */
    if ((err_info = sr_shmext_notif_sub_add(conn, shm_mod, sub_id, (*subscription)->evpipe_num, &listen_since))) {
        goto error1;
    }

    /* add subscription into structure */
    if ((err_info = sr_subscr_notif_sub_add(*subscription, sub_id, session, ly_mod->name, xpath, &listen_since,
            start_time, stop_time, callback, tree_callback, private_data, 0))) {
        goto error2;
    }

    /* add the subscription into session */
    if ((err_info = sr_ptr_add(&session->ptr_lock, (void ***)&session->subscriptions, &session->subscription_count,
            *subscription))) {
        goto error3;
    }

    if (start_time || stop_time) {
        /* notify subscription there are already some events (replay needs to be performed) or stop time needs to be checked */
        if ((err_info = sr_shmsub_notify_evpipe((*subscription)->evpipe_num))) {
            goto error3;
        }
    }

    return sr_api_ret(session, NULL);

error3:
    sr_subscr_notif_sub_del(*subscription, sub_id, SR_LOCK_NONE);

error2:
    if ((tmp_err = sr_shmext_notif_sub_del(conn, shm_mod, sub_id))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }

error1:
    if (!(opts & SR_SUBSCR_CTX_REUSE)) {
        _sr_unsubscribe(*subscription);
        *subscription = NULL;
    }

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
sr_event_notif_send(sr_session_ctx_t *session, const char *path, const sr_val_t *values, const size_t values_cnt,
        uint32_t timeout_ms, int wait)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *notif_tree = NULL;
    char *val_str, buf[22];
    size_t i;
    int ret;

    SR_CHECK_ARG_APIRET(!session || !path, session, err_info);

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
    if ((ret = sr_event_notif_send_tree(session, notif_tree, timeout_ms, wait)) != SR_ERR_OK) {
        lyd_free_all(notif_tree);
        return ret;
    }

    /* success */

cleanup:
    lyd_free_all(notif_tree);
    return sr_api_ret(session, err_info);
}

API int
sr_event_notif_send_tree(sr_session_ctx_t *session, struct lyd_node *notif, uint32_t timeout_ms, int wait)
{
    sr_error_info_t *err_info = NULL, *tmp_err = NULL;
    struct sr_mod_info_s mod_info;
    struct lyd_node *notif_op;
    sr_dep_t *shm_deps;
    sr_mod_t *shm_mod;
    struct timespec notif_ts;
    uint16_t shm_dep_count;
    char *path = NULL, *parent_path = NULL;

    SR_CHECK_ARG_APIRET(!session || !notif, session, err_info);
    if (session->conn->ly_ctx != notif->schema->module->ctx) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Data trees must be created using the session connection libyang context.");
        return sr_api_ret(session, err_info);
    }

    if (!timeout_ms) {
        timeout_ms = SR_NOTIF_CB_TIMEOUT;
    }
    SR_MODINFO_INIT(mod_info, session->conn, SR_DS_OPERATIONAL, SR_DS_RUNNING);

    /* remember when the notification was generated */
    sr_time_get(&notif_ts, 0);

    /* check notif data tree */
    switch (notif->schema->nodetype) {
    case LYS_NOTIF:
        for (notif_op = notif; notif->parent; notif = lyd_parent(notif)) {}
        break;
    case LYS_CONTAINER:
    case LYS_LIST:
        /* find the notification */
        notif_op = notif;
        if ((err_info = sr_ly_find_last_parent(&notif_op, LYS_NOTIF))) {
            goto cleanup;
        }
        if (notif_op->schema->nodetype == LYS_NOTIF) {
            break;
        }
    /* fallthrough */
    default:
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Provided tree is not a valid notification invocation.");
        goto cleanup;
    }

    /* check write/read perm */
    shm_mod = sr_shmmain_find_module(SR_CONN_MAIN_SHM(session->conn), lyd_owner_module(notif)->name);
    SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup);
    if ((err_info = sr_perm_check(session->conn, lyd_owner_module(notif), SR_DS_STARTUP,
            ATOMIC_LOAD_RELAXED(shm_mod->replay_supp), NULL))) {
        goto cleanup;
    }

    if (notif != notif_op) {
        /* we need the OP parent to check it exists */
        parent_path = lyd_path(lyd_parent(notif_op), LYD_PATH_STD, NULL, 0);
        SR_CHECK_MEM_GOTO(!parent_path, err_info, cleanup);
        /* only reference to parent_path is stored, so it cannot be freed! */
        if ((err_info = sr_modinfo_add(lyd_owner_module(notif), parent_path, 0, &mod_info))) {
            goto cleanup;
        }
        if ((err_info = sr_modinfo_consolidate(&mod_info, 0, SR_LOCK_READ, SR_MI_DATA_CACHE | SR_MI_PERM_NO,
                session->sid, session->orig_name, session->orig_data, SR_OPER_CB_TIMEOUT, 0))) {
            goto cleanup;
        }
    }

    /* collect all required modules for OP validation */
    path = lysc_path(notif_op->schema, LYSC_PATH_DATA, NULL, 0);
    SR_CHECK_MEM_GOTO(!path, err_info, cleanup);
    if ((err_info = sr_shmmod_get_notif_deps(SR_CONN_MAIN_SHM(session->conn), lyd_owner_module(notif), path,
            &shm_deps, &shm_dep_count))) {
        goto cleanup;
    }
    if ((err_info = sr_shmmod_collect_deps(SR_CONN_MAIN_SHM(session->conn), shm_deps, shm_dep_count,
            session->conn->ly_ctx, notif, &mod_info))) {
        goto cleanup;
    }
    if ((err_info = sr_modinfo_consolidate(&mod_info, 0, SR_LOCK_READ, SR_MI_NEW_DEPS | SR_MI_DATA_CACHE | SR_MI_PERM_NO,
            session->sid, session->orig_name, session->orig_data, SR_OPER_CB_TIMEOUT, 0))) {
        goto cleanup;
    }

    /* validate the operation */
    if ((err_info = sr_modinfo_op_validate(&mod_info, notif_op, 0))) {
        goto cleanup;
    }

    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    /* store the notification for a replay, we continue on failure */
    err_info = sr_replay_store(session, notif, notif_ts);

    /* NOTIF SUB READ LOCK */
    if ((tmp_err = sr_rwlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, session->conn->cid, __func__,
            NULL, NULL))) {
        goto cleanup;
    }

    /* publish notif in an event */
    if ((tmp_err = sr_shmsub_notif_notify(session->conn, notif, notif_ts, session->orig_name, session->orig_data,
            timeout_ms, wait))) {
        goto cleanup_notifsub_unlock;
    }

    /* success */

cleanup_notifsub_unlock:
    /* NOTIF SUB READ UNLOCK */
    sr_rwunlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, session->conn->cid, __func__);

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info);

    free(parent_path);
    free(path);
    sr_modinfo_erase(&mod_info);
    if (tmp_err) {
        sr_errinfo_merge(&err_info, tmp_err);
    }
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
sr_event_notif_sub_modify_xpath(sr_subscription_ctx_t *subscription, uint32_t sub_id, const char *xpath)
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

    /* if the xpath is the same, there is nothing to modify */
    if (!xpath && !notif_sub->xpath) {
        goto cleanup_unlock;
    } else if (xpath && notif_sub->xpath && !strcmp(xpath, notif_sub->xpath)) {
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
    sr_time_get(&cur_time, 0);
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
    if (stop_time && !notif_sub->start_time.tv_sec && (sr_time_cmp(stop_time, &notif_sub->start_time) < 0)) {
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
    sr_time_get(&cur_time, 0);
    if ((err_info = sr_notif_call_callback(ev_sess, notif_sub->cb, notif_sub->tree_cb, notif_sub->private_data,
            SR_EV_NOTIF_MODIFIED, sub_id, NULL, &cur_time))) {
        goto cleanup_unlock;
    }

    /* generate a new event for the thread to wake up */
    if ((err_info = sr_shmsub_notify_evpipe(subscription->evpipe_num))) {
        goto cleanup_unlock;
    }

cleanup_unlock:
    /* SUBS WRITE UNLOCK */
    sr_rwunlock(&subscription->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_WRITE, subscription->conn->cid, __func__);

    sr_session_stop(ev_sess);
    return sr_api_ret(NULL, err_info);
}

/**
 * @brief Learn what kinds (config) of nodes are provided by an operational subscription
 * to determine its type.
 *
 * @param[in] ly_ctx libyang context to use.
 * @param[in] path Subscription path.
 * @param[out] sub_type Learned subscription type.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_oper_sub_get_type(const struct ly_ctx *ly_ctx, const char *path, sr_mod_oper_sub_type_t *sub_type)
{
    sr_error_info_t *err_info = NULL;
    struct lysc_node *elem;
    struct ly_set *set = NULL;
    uint32_t i;

    if (lys_find_xpath(ly_ctx, NULL, path, 0, &set)) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    } else if (!set->count) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "XPath \"%s\" does not point to any nodes.", path);
        goto cleanup;
    }

    *sub_type = SR_OPER_SUB_NONE;
    for (i = 0; i < set->count; ++i) {
        LYSC_TREE_DFS_BEGIN(set->snodes[i], elem) {
            switch (elem->nodetype) {
            case LYS_CONTAINER:
            case LYS_LEAF:
            case LYS_LEAFLIST:
            case LYS_LIST:
            case LYS_ANYXML:
            case LYS_ANYDATA:
                /* data node - check config */
                if ((elem->flags & LYS_CONFIG_MASK) == LYS_CONFIG_R) {
                    if (*sub_type == SR_OPER_SUB_CONFIG) {
                        *sub_type = SR_OPER_SUB_MIXED;
                    } else {
                        *sub_type = SR_OPER_SUB_STATE;
                    }
                } else {
                    assert((elem->flags & LYS_CONFIG_MASK) == LYS_CONFIG_W);
                    if (*sub_type == SR_OPER_SUB_STATE) {
                        *sub_type = SR_OPER_SUB_MIXED;
                    } else {
                        *sub_type = SR_OPER_SUB_CONFIG;
                    }
                }
                break;
            case LYS_CHOICE:
            case LYS_CASE:
                /* go into */
                break;
            default:
                /* should not be reachable */
                SR_ERRINFO_INT(&err_info);
                goto cleanup;
            }

            if ((*sub_type == SR_OPER_SUB_STATE) || (*sub_type == SR_OPER_SUB_MIXED)) {
                /* redundant to look recursively */
                break;
            }

            LYSC_TREE_DFS_END(set->snodes[i], elem);
        }

        if (*sub_type == SR_OPER_SUB_MIXED) {
            /* we found both config type nodes, nothing more to look for */
            break;
        }
    }

cleanup:
    ly_set_free(set, NULL);
    return err_info;
}

API int
sr_oper_get_items_subscribe(sr_session_ctx_t *session, const char *module_name, const char *path,
        sr_oper_get_items_cb callback, void *private_data, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    sr_conn_ctx_t *conn;
    const struct lys_module *ly_mod;
    sr_mod_oper_sub_type_t sub_type = 0;
    uint32_t sub_id;
    sr_subscr_options_t sub_opts;
    sr_mod_t *shm_mod;

    SR_CHECK_ARG_APIRET(!session || SR_IS_EVENT_SESS(session) || !module_name || !path || !callback || !subscription,
            session, err_info);

    if ((opts & SR_SUBSCR_CTX_REUSE) && !*subscription) {
        /* invalid option, remove */
        opts &= ~SR_SUBSCR_CTX_REUSE;
    }

    conn = session->conn;
    /* only these options are relevant outside this function and will be stored */
    sub_opts = opts & SR_SUBSCR_OPER_MERGE;

    ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, module_name);
    if (!ly_mod) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Module \"%s\" was not found in sysrepo.", module_name);
        return sr_api_ret(session, err_info);
    }

    /* check write perm */
    if ((err_info = sr_perm_check(conn, ly_mod, SR_DS_OPERATIONAL, 1, NULL))) {
        return sr_api_ret(session, err_info);
    }

    /* find out what kinds of nodes are provided */
    if ((err_info = sr_oper_sub_get_type(conn->ly_ctx, path, &sub_type))) {
        return sr_api_ret(session, err_info);
    }

    if (!(opts & SR_SUBSCR_CTX_REUSE)) {
        /* create a new subscription */
        if ((err_info = sr_subscr_new(conn, opts, subscription))) {
            return sr_api_ret(session, err_info);
        }
    } else if (opts & SR_SUBSCR_THREAD_SUSPEND) {
        /* suspend the running thread */
        _sr_subscription_thread_suspend(*subscription);
    }

    /* get new sub ID */
    sub_id = ATOMIC_INC_RELAXED(SR_CONN_MAIN_SHM(conn)->new_sub_id);
    if (sub_id == (uint32_t)(ATOMIC_T_MAX - 1)) {
        /* the value in the main SHM is actually ATOMIC_T_MAX and calling another INC would cause an overflow */
        ATOMIC_STORE_RELAXED(SR_CONN_MAIN_SHM(conn)->new_sub_id, 1);
    }

    /* find module */
    shm_mod = sr_shmmain_find_module(SR_CONN_MAIN_SHM(conn), module_name);
    SR_CHECK_INT_GOTO(!shm_mod, err_info, error1);

    /* add oper subscription into main SHM */
    if ((err_info = sr_shmext_oper_sub_add(conn, shm_mod, sub_id, path, sub_type, sub_opts,
            (*subscription)->evpipe_num))) {
        goto error1;
    }

    /* add subscription into structure and create separate specific SHM segment */
    if ((err_info = sr_subscr_oper_sub_add(*subscription, sub_id, session, module_name, path, callback, private_data, 0))) {
        goto error2;
    }

    /* add the subscription into session */
    if ((err_info = sr_ptr_add(&session->ptr_lock, (void ***)&session->subscriptions, &session->subscription_count,
            *subscription))) {
        goto error3;
    }

    return sr_api_ret(session, err_info);

error3:
    sr_subscr_oper_sub_del(*subscription, sub_id, SR_LOCK_NONE);

error2:
    if ((tmp_err = sr_shmext_oper_sub_del(conn, shm_mod, sub_id))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }

error1:
    if (!(opts & SR_SUBSCR_CTX_REUSE)) {
        _sr_unsubscribe(*subscription);
        *subscription = NULL;
    }
    return sr_api_ret(session, err_info);
}
