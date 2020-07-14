/**
 * @file sysrepo.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief sysrepo API routines
 *
 * @copyright
 * Copyright 2018 Deutsche Telekom AG.
 * Copyright 2018 - 2019 CESNET, z.s.p.o.
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
#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

#include <libyang/libyang.h>

static sr_error_info_t *sr_session_notif_buf_stop(sr_session_ctx_t *session);
static sr_error_info_t *_sr_session_stop(sr_session_ctx_t *session);
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

    if ((conn->opts & SR_CONN_CACHE_RUNNING) && (err_info = sr_rwlock_init(&conn->mod_cache.lock, 0))) {
        goto error5;
    }

    *conn_p = conn;
    return NULL;

error5:
    sr_rwlock_destroy(&conn->ext_remap_lock);
error4:
    close(conn->main_create_lock);
error3:
    pthread_mutex_destroy(&conn->ptr_lock);
error2:
    ly_ctx_destroy(conn->ly_ctx, NULL);
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
            lyd_free_withsiblings(conn->mod_cache.data);
            free(conn->mod_cache.mods);
        }

        ly_ctx_destroy(conn->ly_ctx, NULL);
        pthread_mutex_destroy(&conn->ptr_lock);
        if (conn->main_create_lock > -1) {
            close(conn->main_create_lock);
        }
        sr_rwlock_destroy(&conn->ext_remap_lock);
        sr_shm_clear(&conn->main_shm);
        sr_shm_clear(&conn->ext_shm);

        free(conn);
    }
}

/**
 * @brief Load stored lydmods data, apply any scheduled changes if possible, and update connection context.
 *
 * LYDMODS lock is expected to be held.
 *
 * @param[in,out] ly_ctx libyang context to use, may be destroyed and created anew.
 * @param[in] main_shm_addr Main SHM address.
 * @param[in] apply_sched Whether we can attempt to apply scheduled changes.
 * @param[in] err_on_sched_fail Whether to return an error if applying scheduled changes fails.
 * @param[out] sr_mods Parsed lydmods data.
 * @param[out] changed Whether stored lydmods data were changed (created or scheduled changes applied).
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_conn_lydmods_ctx_update(struct ly_ctx **ly_ctx, char *main_shm_addr, int apply_sched, int err_on_sched_fail,
        struct lyd_node **sr_mods, int *changed)
{
    sr_error_info_t *err_info = NULL;
    sr_main_shm_t *main_shm = (sr_main_shm_t *)main_shm_addr;
    int chng, exists, fail, ctx_updated = 0;

    *sr_mods = NULL;
    chng = 0;

    /* check whether any internal module data exist */
    if ((err_info = sr_lydmods_exists(&exists))) {
        goto cleanup;
    }
    if (!exists) {
        /* create new persistent module data file */
        if ((err_info = sr_lydmods_create(*ly_ctx, sr_mods))) {
            goto cleanup;
        }
        chng = 1;
    } else {
        /* parse sysrepo module data */
        if ((err_info = sr_lydmods_parse(*ly_ctx, sr_mods))) {
            goto cleanup;
        }
        if (apply_sched) {
            /* apply scheduled changes if we can */
            if (!main_shm->conn_count) {
                if ((err_info = sr_lydmods_sched_apply(*sr_mods, *ly_ctx, &chng, &fail))) {
                    goto cleanup;
                }
                if (fail) {
                    if (err_on_sched_fail) {
                        sr_errinfo_new(&err_info, SR_ERR_OPERATION_FAILED, NULL, "Applying scheduled changes failed.");
                        goto cleanup;
                    }

                    /* the context is not valid anymore, we have to create it from scratch in the connection
                     * but also update sr_mods, because it was parsed with the context */
                    lyd_free_withsiblings(*sr_mods);
                    ly_ctx_destroy(*ly_ctx, NULL);
                    if ((err_info = sr_shmmain_ly_ctx_init(ly_ctx))) {
                        goto cleanup;
                    }
                    if ((err_info = sr_lydmods_parse(*ly_ctx, sr_mods))) {
                        goto cleanup;
                    }
                } else {
                    ctx_updated = 1;
                }
            } else {
                SR_LOG_INFMSG("Scheduled changes not applied because of other existing connections.");
            }
        }
    }

    /* update the connection context modules */
    if (!ctx_updated) {
        if ((err_info = sr_lydmods_ctx_load_modules(*sr_mods, *ly_ctx, 1, 1, NULL))) {
            goto cleanup;
        }
    }

    if (chng) {
        /* store updated internal sysrepo data */
        if ((err_info = sr_lydmods_print(sr_mods))) {
            goto cleanup;
        }
    }

    /* success */
    if (changed) {
        *changed = chng;
    }

cleanup:
    if (err_info) {
        lyd_free_withsiblings(*sr_mods);
        *sr_mods = NULL;
    }
    return err_info;
}

API int
sr_connect(const sr_conn_options_t opts, sr_conn_ctx_t **conn_p)
{
    sr_error_info_t *err_info = NULL;
    sr_conn_ctx_t *conn = NULL;
    struct lyd_node *sr_mods = NULL;
    int created = 0, changed;
    sr_main_shm_t *main_shm;
    uint32_t conn_count;

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

    main_shm = (sr_main_shm_t *)conn->main_shm.addr;

    /* LYDMODS LOCK */
    if ((err_info = sr_mlock(&main_shm->lydmods_lock, SR_MAIN_LOCK_TIMEOUT * 1000, __func__))) {
        goto cleanup_unlock;
    }

    /* update connection context based on stored lydmods data */
    err_info = sr_conn_lydmods_ctx_update(&conn->ly_ctx, conn->main_shm.addr,
            created || !(opts & SR_CONN_NO_SCHED_CHANGES), opts & SR_CONN_ERR_ON_SCHED_FAIL, &sr_mods, &changed);

    /* LYDMODS UNLOCK */
    sr_munlock(&main_shm->lydmods_lock);

    if (err_info) {
        goto cleanup_unlock;
    }

    if (changed || created) {
        /* clear all main SHM modules (if main SHM was just created, there aren't any anyway) */
        if ((err_info = sr_shm_remap(&conn->main_shm, sizeof(sr_main_shm_t)))) {
            goto cleanup_unlock;
        }
        main_shm = (sr_main_shm_t *)conn->main_shm.addr;
        main_shm->mod_count = 0;

        /* clear ext SHM (there can be no connections and no modules) */
        if ((err_info = sr_shm_remap(&conn->ext_shm, sizeof(size_t)))) {
            goto cleanup_unlock;
        }
        /* set wasted mem to 0 */
        *((size_t *)conn->ext_shm.addr) = 0;

        /* add all the modules in lydmods data into main SHM */
        if ((err_info = sr_shmmain_add(conn, sr_mods->child))) {
            goto cleanup_unlock;
        }

        /* copy full datastore from <startup> to <running> */
        if ((err_info = sr_shmmain_files_startup2running(conn, created))) {
            goto cleanup_unlock;
        }

        /* check data file existence and owner/permissions of all installed modules */
        if ((err_info = sr_shmmain_check_data_files(conn))) {
            goto cleanup_unlock;
        }
    }

    /* remember connection count */
    main_shm = (sr_main_shm_t *)conn->main_shm.addr;
    conn_count = main_shm->conn_count;

    /* CREATE UNLOCK */
    sr_shmmain_createunlock(conn->main_create_lock);

    /* SHM LOCK (writing into connections) */
    if ((err_info = sr_shmmain_lock_remap(conn, SR_LOCK_WRITE, 1, __func__))) {
        goto cleanup;
    }

    if (conn_count && !(opts & SR_CONN_NO_SCHED_CHANGES) && !main_shm->conn_count) {
        /* all the connections were stale so we actually can apply scheduled changes, recreate the whole connection */

        /* SHM UNLOCK */
        sr_shmmain_unlock(conn, SR_LOCK_WRITE, 1, __func__);

        assert(!err_info);
        lyd_free_withsiblings(sr_mods);
        sr_conn_free(conn);
        return sr_connect(opts, conn_p);
    }

    /* add connection into main SHM */
    err_info = sr_shmmain_conn_add(conn);

    /* SHM UNLOCK */
    sr_shmmain_unlock(conn, SR_LOCK_WRITE, 1, __func__);

    goto cleanup;

cleanup_unlock:
    /* CREATE UNLOCK */
    sr_shmmain_createunlock(conn->main_create_lock);

cleanup:
    lyd_free_withsiblings(sr_mods);
    if (err_info) {
        sr_conn_free(conn);
        if (created) {
            /* remove any created SHM so it is not considered properly created */
            sr_error_info_t *tmp_err = NULL;
            char *shm_name = NULL;
            if ((tmp_err = sr_path_main_shm(&shm_name))) {
                sr_errinfo_merge(&err_info, tmp_err);
            } else {
                shm_unlink(shm_name);
                free(shm_name);
            }
            if ((tmp_err = sr_path_ext_shm(&shm_name))) {
                sr_errinfo_merge(&err_info, tmp_err);
            } else {
                shm_unlink(shm_name);
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
    sr_error_info_t *err_info = NULL, *lock_err = NULL, *tmp_err;
    uint32_t i;

    if (!conn) {
        return sr_api_ret(NULL, NULL);
    }

    /* stop all session notification buffer threads, they use read lock so they need conn state in SHM */
    for (i = 0; i < conn->session_count; ++i) {
        tmp_err = sr_session_notif_buf_stop(conn->sessions[i]);
        sr_errinfo_merge(&err_info, tmp_err);
    }

    /* SHM LOCK (maybe unsubscribing, always writing into connections) */
    lock_err = sr_shmmain_lock_remap(conn, SR_LOCK_WRITE, 1, __func__);
    sr_errinfo_merge(&err_info, lock_err);

    /* stop all subscriptions */
    for (i = 0; i < conn->session_count; ++i) {
        while (conn->sessions[i]->subscription_count && conn->sessions[i]->subscriptions[0]) {
            tmp_err = _sr_unsubscribe(conn->sessions[i]->subscriptions[0]);
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }

    /* remove from state */
    sr_shmmain_conn_del((sr_main_shm_t *)conn->main_shm.addr, conn->ext_shm.addr, conn, getpid());

    if (!lock_err) {
        /* SHM UNLOCK */
        sr_shmmain_unlock(conn, SR_LOCK_WRITE, 1, __func__);
    }

    /* stop all the sessions */
    while (conn->session_count) {
        tmp_err = _sr_session_stop(conn->sessions[0]);
        sr_errinfo_merge(&err_info, tmp_err);
    }

    /* free any stored operational data */
    tmp_err = sr_shmmod_oper_stored_del_conn(conn, conn, getpid());
    sr_errinfo_merge(&err_info, tmp_err);

    /* free attributes */
    sr_conn_free(conn);

    return sr_api_ret(NULL, err_info);
}

API int
sr_connection_count(uint32_t *conn_count)
{
    sr_error_info_t *err_info = NULL;
    sr_main_shm_t *main_shm;
    sr_shm_t shm = SR_SHM_INITIALIZER;
    int shm_lock = -1;

    SR_CHECK_ARG_APIRET(!conn_count, NULL, err_info);

    /* check that all required directories exist */
    if ((err_info = sr_shmmain_check_dirs())) {
        goto cleanup;
    }

    if ((err_info = sr_shmmain_createlock_open(&shm_lock))) {
        goto cleanup;
    }

    /* CREATE LOCK */
    if ((err_info = sr_shmmain_createlock(shm_lock))) {
        goto cleanup;
    }

    /* open the main SHM */
    err_info = sr_shmmain_main_open(&shm, NULL);

    /* CREATE UNLOCK */
    sr_shmmain_createunlock(shm_lock);

    if (err_info) {
        goto cleanup;
    }
    if (shm.fd == -1) {
        /* main SHM does not even exist yet */
        *conn_count = 0;
        goto cleanup;
    }

    main_shm = (sr_main_shm_t *)shm.addr;
    *conn_count = main_shm->conn_count;

    /* success */

cleanup:
    if (shm_lock > -1) {
        close(shm_lock);
    }
    sr_shm_clear(&shm);
    return sr_api_ret(NULL, err_info);
}

API const struct ly_ctx *
sr_get_context(sr_conn_ctx_t *conn)
{
    if (!conn) {
        return NULL;
    }

    return conn->ly_ctx;
}

API void
sr_set_diff_check_callback(sr_conn_ctx_t *conn, sr_diff_check_cb callback)
{
    sr_error_info_t *err_info = NULL;

    if (!conn) {
        return;
    }

    if (geteuid()) {
        /* not a root */
        sr_errinfo_new(&err_info, SR_ERR_UNAUTHORIZED, NULL, "Root access required.");
        sr_errinfo_free(&err_info);
        return;
    }

    conn->diff_check_cb = callback;
}

API int
sr_session_start(sr_conn_ctx_t *conn, const sr_datastore_t datastore, sr_session_ctx_t **session)
{
    sr_error_info_t *err_info = NULL;
    sr_main_shm_t *main_shm;
    uid_t uid;

    SR_CHECK_ARG_APIRET(!conn || !session, NULL, err_info);

    *session = calloc(1, sizeof **session);
    if (!*session) {
        SR_ERRINFO_MEM(&err_info);
        return sr_api_ret(NULL, err_info);
    }

    /* use new SR session ID and increment it (no lock needed, we are just reading and main SHM is never remapped) */
    main_shm = (sr_main_shm_t *)conn->main_shm.addr;
    (*session)->sid.sr = ATOMIC_INC_RELAXED(main_shm->new_sr_sid);
    if ((*session)->sid.sr == (uint32_t)(ATOMIC_T_MAX - 1)) {
        /* the value in the main SHM is actually ATOMIC_T_MAX and calling another INC would cause an overflow */
        ATOMIC_STORE_RELAXED(main_shm->new_sr_sid, 1);
    }

    /* remember current real process owner */
    uid = getuid();
    if ((err_info = sr_get_pwd(&uid, &(*session)->sid.user))) {
        goto error;
    }

    /* add the session into conn */
    if ((err_info = sr_ptr_add(&conn->ptr_lock, (void ***)&conn->sessions, &conn->session_count, *session))) {
        goto error;
    }

    (*session)->conn = conn;
    (*session)->ds = datastore;
    if ((err_info = sr_mutex_init(&(*session)->ptr_lock, 0))) {
        goto error;
    }
    if ((err_info = sr_rwlock_init(&(*session)->notif_buf.lock, 0))) {
        goto error;
    }

    SR_LOG_INF("Session %u (user \"%s\") created.", (*session)->sid.sr, (*session)->sid.user);

    return sr_api_ret(NULL, NULL);

error:
    free((*session)->sid.user);
    free(*session);
    *session = NULL;
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
    int ret;

    if (!session->notif_buf.tid) {
        return NULL;
    }

    /* signal the thread */
    ATOMIC_STORE_RELAXED(session->notif_buf.thread_running, 0);

    /* wake up the thread (by fake unlocking a read lock) */
    ++session->notif_buf.lock.readers;
    sr_rwunlock(&session->notif_buf.lock, SR_LOCK_READ, __func__);

    /* join the thread, it will make sure all the buffered notifications are stored */
    ret = pthread_join(session->notif_buf.tid, NULL);
    if (ret) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Joining the notification buffer thread failed (%s).", strerror(ret));
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
    uint32_t i;

    /* subscriptions need to be freed before, with a WRITE lock */
    assert(!session->subscription_count && !session->subscriptions);

    /* remove ourselves from conn sessions */
    tmp_err = sr_ptr_del(&session->conn->ptr_lock, (void ***)&session->conn->sessions, &session->conn->session_count, session);
    sr_errinfo_merge(&err_info, tmp_err);

    /* release any held locks */
    sr_shmmod_release_locks(session->conn, session->sid);

    /* stop notification buffering thread */
    sr_session_notif_buf_stop(session);

    /* free attributes */
    free(session->sid.user);
    for (i = 0; i < SR_DS_COUNT; ++i) {
        lyd_free_withsiblings(session->dt[i].edit);
    }
    sr_errinfo_free(&session->err_info);
    pthread_mutex_destroy(&session->ptr_lock);
    sr_rwlock_destroy(&session->notif_buf.lock);
    free(session);

    return err_info;
}

API int
sr_session_stop(sr_session_ctx_t *session)
{
    sr_error_info_t *err_info = NULL, *lock_err = NULL, *tmp_err;
    sr_conn_ctx_t *conn;
    int wr_lock = 0;

    if (!session) {
        return sr_api_ret(NULL, NULL);
    }

    conn = session->conn;

    /* stop all subscriptions of this session */
    while (session->subscription_count) {
        if (!wr_lock) {
            /* SHM LOCK (writing into subscriptions) */
            lock_err = sr_shmmain_lock_remap(conn, SR_LOCK_WRITE, 1, __func__);
            sr_errinfo_merge(&err_info, lock_err);

            wr_lock = 1;
        }

        tmp_err = sr_subs_session_del(session, session->subscriptions[0]);
        sr_errinfo_merge(&err_info, tmp_err);
    }

    /* SHM UNLOCK */
    if (wr_lock && !lock_err) {
        sr_shmmain_unlock(conn, SR_LOCK_WRITE, 1, __func__);
    }

    /* no lock needed, we are just reading main SHM */
    tmp_err = _sr_session_stop(session);
    sr_errinfo_merge(&err_info, tmp_err);

    return sr_api_ret(NULL, err_info);
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
        sr_errinfo_new(&err_info, SR_ERR_INTERNAL, NULL, "Creating a new thread failed (%s).", strerror(ret));
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
sr_get_error(sr_session_ctx_t *session, const sr_error_info_t **error_info)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session || !error_info, session, err_info);

    *error_info = session->err_info;

    /* do not modify session errors */
    return SR_ERR_OK;
}

API int
sr_set_error(sr_session_ctx_t *session, const char *path, const char *format, ...)
{
    sr_error_info_t *err_info = NULL;
    va_list vargs;

    SR_CHECK_ARG_APIRET(!session || ((session->ev != SR_SUB_EV_CHANGE) && (session->ev != SR_SUB_EV_UPDATE)
            && (session->ev != SR_SUB_EV_OPER) && (session->ev != SR_SUB_EV_RPC)) || !format, session, err_info);

    va_start(vargs, format);
    sr_errinfo_add(&err_info, SR_ERR_OK, path, format, &vargs);
    va_end(vargs);

    /* set the error and return its return code (SR_ERR_OK) */
    return sr_api_ret(session, err_info);
}

API uint32_t
sr_session_get_id(sr_session_ctx_t *session)
{
    if (!session) {
        return 0;
    }

    return session->sid.sr;
}

API void
sr_session_set_nc_id(sr_session_ctx_t *session, uint32_t nc_sid)
{
    if (!session) {
        return;
    }

    session->sid.nc = nc_sid;
}

API uint32_t
sr_session_get_nc_id(sr_session_ctx_t *session)
{
    if (!session) {
        return 0;
    }

    return session->sid.nc;
}

API int
sr_session_set_user(sr_session_ctx_t *session, const char *user)
{
    sr_error_info_t *err_info = NULL;
    uid_t uid;

    SR_CHECK_ARG_APIRET(!session || !user, session, err_info);

    if (geteuid()) {
        /* not a root */
        sr_errinfo_new(&err_info, SR_ERR_UNAUTHORIZED, NULL, "Root access required.");
        return sr_api_ret(session, err_info);
    }

    /* check that the user is valid */
    if ((err_info = sr_get_pwd(&uid, (char **)&user))) {
        return sr_api_ret(session, err_info);
    }

    /* replace the user */
    free(session->sid.user);
    session->sid.user = strdup(user);
    if (!session->sid.user) {
        SR_ERRINFO_MEM(&err_info);
    }

    return sr_api_ret(session, err_info);
}

API const char *
sr_session_get_user(sr_session_ctx_t *session)
{
    sr_error_info_t *err_info = NULL;

    if (!session) {
        return NULL;
    }

    if (geteuid()) {
        /* not a root */
        sr_errinfo_new(&err_info, SR_ERR_UNAUTHORIZED, NULL, "Root access required.");
        sr_api_ret(session, err_info);
        return NULL;
    }

    /* return the user */
    return session->sid.user;
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
        *format = LYS_YIN;
        ptr = schema_path + strlen(schema_path) - 4;
    } else if ((strlen(schema_path) > 5) && !strcmp(schema_path + strlen(schema_path) - 5, ".yang")) {
        *format = LYS_YANG;
        ptr = schema_path + strlen(schema_path) - 5;
    } else {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Unknown format of module \"%s\".", schema_path);
        return err_info;
    }

    /* parse module name */
    for (index = 0; (ptr != schema_path) && (ptr[0] != '/'); ++index, --ptr);
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
 * @param[in] search_dirs Optional search dirs, in format <dir>[:<dir>]*.
 * @return err_info, NULL on success.
 */
static const struct lys_module *
sr_parse_module(struct ly_ctx *ly_ctx, const char *schema_path, LYS_INFORMAT format, const char *search_dirs)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod = NULL;
    const char * const *cur_dirs;
    char *sdirs_str = NULL, *ptr, *ptr2 = NULL;
    struct {
        char *dir;
        int index;
    } *sdirs = NULL;
    size_t i, j, sdir_count = 0;

    if (search_dirs) {
        sdirs_str = strdup(search_dirs);
        if (!sdirs_str) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }

        /* parse search dirs */
        for (ptr = strtok_r(sdirs_str, ":", &ptr2); ptr; ptr = strtok_r(NULL, ":", &ptr2)) {
            sdirs = sr_realloc(sdirs, (sdir_count + 1) * sizeof *sdirs);
            if (!sdirs) {
                SR_ERRINFO_MEM(&err_info);
                goto cleanup;
            }

            sdirs[sdir_count].dir = ptr;
            sdirs[sdir_count].index = -1;
            ++sdir_count;
        }
    }

    /* add searchdir if not already there */
    cur_dirs = ly_ctx_get_searchdirs(ly_ctx);
    for (i = 0; i < sdir_count; ++i) {
        for (j = 0; cur_dirs[j]; ++j) {
            if (!strcmp(cur_dirs[j], sdirs[i].dir)) {
                break;
            }
        }
        if (!cur_dirs[j]) {
            ly_ctx_set_searchdir(ly_ctx, sdirs[i].dir);
            sdirs[i].index = j;

            /* it could have been moved on realloc */
            cur_dirs = ly_ctx_get_searchdirs(ly_ctx);
        }
    }

    /* parse the module */
    ly_mod = lys_parse_path(ly_ctx, schema_path, format);

    if (sdir_count) {
        /* remove search dirs in descending order for the libyang searchdir indices to be correct */
        i = sdir_count;
        do {
            --i;
            if (sdirs[i].index > -1) {
                ly_ctx_unset_searchdirs(ly_ctx, sdirs[i].index);
            }
        } while (i);
    }

cleanup:
    free(sdirs_str);
    free(sdirs);
    sr_errinfo_free(&err_info);
    return ly_mod;
}

API int
sr_install_module(sr_conn_ctx_t *conn, const char *schema_path, const char *search_dirs, const char **features,
        int feat_count)
{
    sr_error_info_t *err_info = NULL;
    struct ly_ctx *tmp_ly_ctx = NULL;
    const struct lys_module *ly_mod, *ly_iter, *ly_iter2;
    LYS_INFORMAT format;
    char *mod_name = NULL;
    uint32_t i;

    SR_CHECK_ARG_APIRET(!conn || !schema_path, NULL, err_info);

    /* create new temporary context */
    if ((err_info = sr_ly_ctx_new(&tmp_ly_ctx))) {
        return sr_api_ret(NULL, err_info);
    }

    /* learn module name and format */
    if ((err_info = sr_get_module_name_format(schema_path, &mod_name, &format))) {
        goto cleanup;
    }

    /* LYDMODS LOCK (not accessing ext SHM) */
    if ((err_info = sr_mlock(&SR_SHM_LYDMODS_LOCK(conn), SR_MAIN_LOCK_TIMEOUT * 1000, __func__))) {
        goto cleanup;
    }

    /* check whether the module is not already in the context */
    ly_mod = ly_ctx_get_module(conn->ly_ctx, mod_name, NULL, 1);
    if (ly_mod && ly_mod->implemented) {
        /* it is currently in the context, try to parse it again to check revisions */
        ly_mod = sr_parse_module(tmp_ly_ctx, schema_path, format, search_dirs);
        if (!ly_mod) {
            sr_errinfo_new_ly_first(&err_info, tmp_ly_ctx);
            sr_errinfo_new(&err_info, SR_ERR_EXISTS, NULL, "Module \"%s\" is already in sysrepo.", mod_name);
            goto cleanup_unlock;
        }

        /* same modules, so if it is scheduled for deletion, we can unschedule it */
        err_info = sr_lydmods_unsched_del_module_with_imps(conn->ly_ctx, ly_mod);
        if (err_info && (err_info->err_code == SR_ERR_NOT_FOUND)) {
            sr_errinfo_free(&err_info);
            sr_errinfo_new(&err_info, SR_ERR_EXISTS, NULL, "Module \"%s\" is already in sysrepo.", ly_mod->name);
            goto cleanup_unlock;
        }
        goto cleanup_unlock;
    }

    /* parse the module */
    if (!(ly_mod = sr_parse_module(tmp_ly_ctx, schema_path, format, search_dirs))) {
        sr_errinfo_new_ly(&err_info, tmp_ly_ctx);
        goto cleanup_unlock;
    }

    /* enable all features to check their existence */
    for (i = 0; i < (unsigned)feat_count; ++i) {
        if (lys_features_enable(ly_mod, features[i])) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" does not define feature \"%s\".",
                    ly_mod->name, features[i]);
            goto cleanup_unlock;
        }
    }

    /* check that the module does not implement some other modules in different revisions than already in the context */
    i = 0;
    while ((ly_iter = ly_ctx_get_module_iter(tmp_ly_ctx, &i))) {
        if (!ly_iter->implemented) {
            continue;
        }

        ly_iter2 = ly_ctx_get_module(conn->ly_ctx, ly_iter->name, NULL, 1);
        if (!ly_iter2) {
            continue;
        }

        /* modules are implemented in both contexts, compare revisions */
        if ((!ly_iter->rev_size && ly_iter2->rev_size) || (ly_iter->rev_size && !ly_iter2->rev_size)
                || (ly_iter->rev_size && ly_iter2->rev_size && strcmp(ly_iter->rev[0].date, ly_iter2->rev[0].date))) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, NULL, "Module \"%s\" implements module \"%s@%s\" that is already"
                    " in sysrepo in revision %s.", ly_mod->name, ly_iter->name,
                    ly_iter->rev_size ? ly_iter->rev[0].date : "<none>", ly_iter2->rev_size ? ly_iter2->rev[0].date : "<none>");
            goto cleanup_unlock;
        }
    }

    /* schedule module installation */
    if ((err_info = sr_lydmods_deferred_add_module(conn->ly_ctx, ly_mod, features, feat_count))) {
        goto cleanup_unlock;
    }

    /* store new module imports */
    if ((err_info = sr_create_module_imps_incs_r(ly_mod))) {
        goto cleanup_unlock;
    }

    /* success */

cleanup_unlock:
    /* LYDMODS UNLOCK */
    sr_munlock(&SR_SHM_LYDMODS_LOCK(conn));

cleanup:
    ly_ctx_destroy(tmp_ly_ctx, NULL);
    free(mod_name);
    return sr_api_ret(NULL, err_info);
}

API int
sr_install_module_data(sr_conn_ctx_t *conn, const char *module_name, const char *data, const char *data_path,
        LYD_FORMAT format)
{
    sr_error_info_t *err_info = NULL;
    struct ly_ctx *tmp_ly_ctx = NULL;
    struct lyd_node *sr_mods = NULL, *mod_data = NULL, *node;
    const struct lys_module *ly_mod;

    SR_CHECK_ARG_APIRET(!conn || !module_name || (data && data_path) || (!data && !data_path) || !format, NULL, err_info);

    /* create new temporary context */
    if ((err_info = sr_shmmain_ly_ctx_init(&tmp_ly_ctx))) {
        goto cleanup;
    }

    /* LYDMODS LOCK (not accessing ext SHM) */
    if ((err_info = sr_mlock(&SR_SHM_LYDMODS_LOCK(conn), SR_MAIN_LOCK_TIMEOUT * 1000, __func__))) {
        goto cleanup;
    }

    /* fill it with current modules */
    if ((err_info = sr_conn_lydmods_ctx_update(&tmp_ly_ctx, conn->main_shm.addr, 0, 0, &sr_mods, NULL))) {
        goto cleanup_unlock;
    }

    /* load the module to be installed */
    if ((err_info = sr_lydmods_ctx_load_installed_module_all(sr_mods, tmp_ly_ctx, module_name, &ly_mod))) {
        goto cleanup_unlock;
    }

    /* parse module data */
    ly_errno = 0;
    if (data_path) {
        mod_data = lyd_parse_path(tmp_ly_ctx, data_path, format, LYD_OPT_CONFIG | LYD_OPT_STRICT | LYD_OPT_TRUSTED);
    } else {
        mod_data = lyd_parse_mem(tmp_ly_ctx, data, format, LYD_OPT_CONFIG | LYD_OPT_STRICT | LYD_OPT_TRUSTED);
    }
    if (ly_errno) {
        sr_errinfo_new_ly(&err_info, tmp_ly_ctx);
        goto cleanup_unlock;
    }

    /* check that there are only this module data */
    LY_TREE_FOR(mod_data, node) {
        if (!node->dflt && (lyd_node_module(node) != ly_mod)) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, NULL, "Only data for the module \"%s\" can be set.", module_name);
            goto cleanup_unlock;
        }
    }

    /* set new startup data for the module */
    if ((err_info = sr_lydmods_deferred_add_module_data(sr_mods, module_name, mod_data))) {
        goto cleanup_unlock;
    }

    /* store updated sysrepo module data */
    if ((err_info = sr_lydmods_print(&sr_mods))) {
        goto cleanup_unlock;
    }

    /* success */

cleanup_unlock:
    /* LYDMODS UNLOCK */
    sr_munlock(&SR_SHM_LYDMODS_LOCK(conn));

cleanup:
    lyd_free_withsiblings(sr_mods);
    lyd_free_withsiblings(mod_data);
    ly_ctx_destroy(tmp_ly_ctx, NULL);
    return sr_api_ret(NULL, err_info);
}

API int
sr_remove_module(sr_conn_ctx_t *conn, const char *module_name)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;

    SR_CHECK_ARG_APIRET(!conn || !module_name, NULL, err_info);

    /* LYDMODS LOCK (not accessing ext SHM) */
    if ((err_info = sr_mlock(&SR_SHM_LYDMODS_LOCK(conn), SR_MAIN_LOCK_TIMEOUT * 1000, __func__))) {
        return sr_api_ret(NULL, err_info);
    }

    /* try to find this module */
    ly_mod = ly_ctx_get_module(conn->ly_ctx, module_name, NULL, 1);
    if (!ly_mod || !ly_mod->implemented) {
        /* if it is scheduled for installation, we can unschedule it */
        err_info = sr_lydmods_unsched_add_module(conn->ly_ctx, module_name);
        if (err_info && (err_info->err_code == SR_ERR_NOT_FOUND)) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" was not found in sysrepo.", module_name);
        }
        goto cleanup_unlock;
    }

    if (sr_module_is_internal(ly_mod)) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Internal module \"%s\" cannot be uninstalled.", module_name);
        goto cleanup_unlock;
    }

    /* check write permission */
    if ((err_info = sr_perm_check(module_name, 1, NULL))) {
        goto cleanup_unlock;
    }

    /* schedule module removal from sysrepo */
    if ((err_info = sr_lydmods_deferred_del_module(conn->ly_ctx, module_name))) {
        goto cleanup_unlock;
    }

    /* success */

cleanup_unlock:
    /* LYDMODS UNLOCK */
    sr_munlock(&SR_SHM_LYDMODS_LOCK(conn));
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
        return sr_api_ret(NULL, err_info);
    }

    /* LYDMODS LOCK (not accessing ext SHM) */
    if ((err_info = sr_mlock(&SR_SHM_LYDMODS_LOCK(conn), SR_MAIN_LOCK_TIMEOUT * 1000, __func__))) {
        goto cleanup;
    }

    /* try to find this module */
    ly_mod = ly_ctx_get_module(conn->ly_ctx, mod_name, NULL, 1);
    if (!ly_mod || !ly_mod->implemented) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" was not found in sysrepo.", mod_name);
        goto cleanup_unlock;
    }

    /* check write permission */
    if ((err_info = sr_perm_check(mod_name, 1, NULL))) {
        goto cleanup_unlock;
    }

    /* create new temporary context */
    if ((err_info = sr_ly_ctx_new(&tmp_ly_ctx))) {
        goto cleanup_unlock;
    }

    /* try to parse the update module */
    if (!(upd_ly_mod = sr_parse_module(tmp_ly_ctx, schema_path, format, search_dirs))) {
        sr_errinfo_new_ly(&err_info, tmp_ly_ctx);
        goto cleanup_unlock;
    }

    /* it must have a revision */
    if (!upd_ly_mod->rev_size) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Update module \"%s\" does not have a revision.", mod_name);
        goto cleanup_unlock;
    }

    /* it must be a different module from the installed one */
    if (ly_mod->rev_size && !strcmp(upd_ly_mod->rev[0].date, ly_mod->rev[0].date)) {
        sr_errinfo_new(&err_info, SR_ERR_EXISTS, NULL, "Module \"%s@%s\" already installed.", mod_name, ly_mod->rev[0].date);
        goto cleanup_unlock;
    }

    /* schedule module update */
    if ((err_info = sr_lydmods_deferred_upd_module(conn->ly_ctx, upd_ly_mod))) {
        goto cleanup_unlock;
    }

    /* store update module imports */
    if ((err_info = sr_create_module_imps_incs_r(upd_ly_mod))) {
        goto cleanup_unlock;
    }

    /* success */

cleanup_unlock:
    /* LYDMODS UNLOCK */
    sr_munlock(&SR_SHM_LYDMODS_LOCK(conn));

cleanup:
    ly_ctx_destroy(tmp_ly_ctx, NULL);
    free(mod_name);
    return sr_api_ret(NULL, err_info);
}

API int
sr_cancel_update_module(sr_conn_ctx_t *conn, const char *module_name)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    char *path = NULL;

    SR_CHECK_ARG_APIRET(!conn || !module_name, NULL, err_info);

    /* LYDMODS LOCK (not accessing ext SHM) */
    if ((err_info = sr_mlock(&SR_SHM_LYDMODS_LOCK(conn), SR_MAIN_LOCK_TIMEOUT * 1000, __func__))) {
        return sr_api_ret(NULL, err_info);
    }

    /* try to find this module */
    ly_mod = ly_ctx_get_module(conn->ly_ctx, module_name, NULL, 1);
    if (!ly_mod || !ly_mod->implemented) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" was not found in sysrepo.", module_name);
        goto cleanup_unlock;
    }

    /* check write permission */
    if ((err_info = sr_perm_check(module_name, 1, NULL))) {
        goto cleanup_unlock;
    }

    /* unschedule module update */
    if ((err_info = sr_lydmods_unsched_upd_module(conn->ly_ctx, module_name))) {
        goto cleanup_unlock;
    }

    /* success */

cleanup_unlock:
    /* LYDMODS UNLOCK */
    sr_munlock(&SR_SHM_LYDMODS_LOCK(conn));

    free(path);
    return sr_api_ret(NULL, err_info);
}

API int
sr_set_module_replay_support(sr_conn_ctx_t *conn, const char *module_name, int replay_support)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;

    SR_CHECK_ARG_APIRET(!conn, NULL, err_info);

    /* LYDMODS LOCK */
    if ((err_info = sr_mlock(&SR_SHM_LYDMODS_LOCK(conn), SR_MAIN_LOCK_TIMEOUT * 1000, __func__))) {
        return sr_api_ret(NULL, err_info);
    }

    if (module_name) {
        /* try to find this module */
        ly_mod = ly_ctx_get_module(conn->ly_ctx, module_name, NULL, 1);
        if (!ly_mod || !ly_mod->implemented) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" was not found in sysrepo.", module_name);
            goto cleanup_unlock;
        }
    }

    /* SHM LOCK (writing into replay support, but that cannot remap ext SHM) */
    if ((err_info = sr_shmmain_lock_remap(conn, SR_LOCK_WRITE, 0, __func__))) {
        goto cleanup_unlock;
    }

    /* update replay-support flag both in LY data tree and in main SHM */
    if ((err_info = sr_lydmods_update_replay_support(conn->ly_ctx, module_name, replay_support))) {
        goto cleanup_shm_unlock;
    }
    if ((err_info = sr_shmmain_update_replay_support(&conn->main_shm, conn->ext_shm.addr, module_name, replay_support))) {
        goto cleanup_shm_unlock;
    }

    /* success */

cleanup_shm_unlock:
    /* SHM UNLOCK */
    sr_shmmain_unlock(conn, SR_LOCK_WRITE, 0, __func__);

cleanup_unlock:
    /* LYDMODS UNLOCK */
    sr_munlock(&SR_SHM_LYDMODS_LOCK(conn));
    return sr_api_ret(NULL, err_info);
}

API int
sr_set_module_access(sr_conn_ctx_t *conn, const char *module_name, const char *owner, const char *group, mode_t perm)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    time_t from_ts, to_ts;
    char *path;

    SR_CHECK_ARG_APIRET(!conn || !module_name || (!owner && !group && ((int)perm == -1)), NULL, err_info);

    /* LYDMODS LOCK (we just need this function not to be called simultaneously, use lyd_mods lock for this) */
    if ((err_info = sr_mlock(&SR_SHM_LYDMODS_LOCK(conn), SR_MAIN_LOCK_TIMEOUT * 1000, __func__))) {
        return sr_api_ret(NULL, err_info);
    }

    /* try to find this module in main SHM */
    shm_mod = sr_shmmain_find_module(&conn->main_shm, conn->ext_shm.addr, module_name, 0);
    if (!shm_mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" was not found in sysrepo.", module_name);
        goto cleanup_unlock;
    }

    /* get startup file path */
    if ((err_info = sr_path_startup_file(module_name, &path))) {
        goto cleanup_unlock;
    }

    /* update startup file permissions and owner */
    err_info = sr_chmodown(path, owner, group, perm);
    free(path);
    if (err_info) {
        goto cleanup_unlock;
    }

    /* get running SHM file path */
    if ((err_info = sr_path_ds_shm(module_name, SR_DS_RUNNING, 1, &path))) {
        goto cleanup_unlock;
    }

    /* update running file permissions and owner */
    err_info = sr_chmodown(path, owner, group, perm);
    free(path);
    if (err_info) {
        goto cleanup_unlock;
    }

    /* get operational SHM file path */
    if ((err_info = sr_path_ds_shm(module_name, SR_DS_OPERATIONAL, 1, &path))) {
        goto cleanup_unlock;
    }

    /* update operational file permissions and owner */
    err_info = sr_chmodown(path, owner, group, perm);
    free(path);
    if (err_info) {
        goto cleanup_unlock;
    }

    if (shm_mod->flags & SR_MOD_REPLAY_SUPPORT) {
        if ((err_info = sr_replay_find_file(module_name, 1, 1, &from_ts, &to_ts))) {
            goto cleanup_unlock;
        }
        while (from_ts && to_ts) {
            /* get next notification file path */
            if ((err_info = sr_path_notif_file(module_name, from_ts, to_ts, &path))) {
                goto cleanup_unlock;
            }

            /* update notification file permissions and owner */
            err_info = sr_chmodown(path, owner, group, perm);
            free(path);
            if (err_info) {
                goto cleanup_unlock;
            }
        }
    }

    /* success */

cleanup_unlock:
    /* LYDMODS UNLOCK */
    sr_munlock(&SR_SHM_LYDMODS_LOCK(conn));
    return sr_api_ret(NULL, err_info);
}

API int
sr_get_module_access(sr_conn_ctx_t *conn, const char *module_name, char **owner, char **group, mode_t *perm)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;

    SR_CHECK_ARG_APIRET(!conn || !module_name || (!owner && !group && !perm), NULL, err_info);

    /* try to find this module */
    ly_mod = ly_ctx_get_module(conn->ly_ctx, module_name, NULL, 1);
    if (!ly_mod || !ly_mod->implemented) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" was not found in sysrepo.", module_name);
        return sr_api_ret(NULL, err_info);
    }

    /* learn owner and permissions */
    if ((err_info = sr_perm_get(module_name, SR_DS_STARTUP, owner, group, perm))) {
        return sr_api_ret(NULL, err_info);
    }

    return sr_api_ret(NULL, NULL);
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
    int ret;

    /* LYDMODS LOCK (not accessing ext SHM) */
    if ((err_info = sr_mlock(&SR_SHM_LYDMODS_LOCK(conn), SR_MAIN_LOCK_TIMEOUT * 1000, __func__))) {
        return err_info;
    }

    /* try to find this module */
    ly_mod = ly_ctx_get_module(conn->ly_ctx, module_name, NULL, 1);
    if (!ly_mod || !ly_mod->implemented) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" was not found in sysrepo.", module_name);
        goto cleanup;
    }

    /* check write perm */
    if ((err_info = sr_perm_check(module_name, 1, NULL))) {
        goto cleanup;
    }

    /* check feature in the current context */
    ret = lys_features_state(ly_mod, feature_name);
    if (ret == -1) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Feature \"%s\" was not found in module \"%s\".",
                feature_name, module_name);
        goto cleanup;
    }

    /* mark the change (if any) in LY data tree */
    if ((err_info = sr_lydmods_deferred_change_feature(conn->ly_ctx, ly_mod, feature_name, enable, ret))) {
        goto cleanup;
    }

    /* success */

cleanup:
    /* LYDMODS UNLOCK */
    sr_munlock(&SR_SHM_LYDMODS_LOCK(conn));
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
sr_get_module_info(sr_conn_ctx_t *conn, struct lyd_node **sysrepo_data)
{
    sr_error_info_t *err_info;

    SR_CHECK_ARG_APIRET(!conn || !sysrepo_data, NULL, err_info);

    /* LYDMODS LOCK (not accessing ext SHM) */
    if ((err_info = sr_mlock(&SR_SHM_LYDMODS_LOCK(conn), SR_MAIN_LOCK_TIMEOUT * 1000, __func__))) {
        return sr_api_ret(NULL, err_info);
    }

    err_info = sr_lydmods_parse(conn->ly_ctx, sysrepo_data);

    /* LYDMODS UNLOCK */
    sr_munlock(&SR_SHM_LYDMODS_LOCK(conn));

    return sr_api_ret(NULL, err_info);
}

API int
sr_get_item(sr_session_ctx_t *session, const char *path, uint32_t timeout_ms, sr_val_t **value)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    struct ly_set *set = NULL;
    struct sr_mod_info_s mod_info;

    SR_CHECK_ARG_APIRET(!session || !path || !value, session, err_info);

    if (!timeout_ms) {
        timeout_ms = SR_OPER_CB_TIMEOUT;
    }
    *value = NULL;
    /* for operational, use operational and running datastore */
    SR_MODINFO_INIT(mod_info, session->conn, session->ds, session->ds == SR_DS_OPERATIONAL ? SR_DS_RUNNING : session->ds);

    /* SHM LOCK (reading subscriptions if using oper data) */
    if ((err_info = sr_shmmain_lock_remap(session->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    /* collect all required modules */
    if ((err_info = sr_shmmod_modinfo_collect_xpath(&mod_info, path))) {
        goto cleanup_shm_unlock;
    }

    /* check read perm */
    if ((err_info = sr_modinfo_perm_check(&mod_info, 0, 0))) {
        goto cleanup_shm_unlock;
    }

    /* MODULES READ LOCK */
    if ((err_info = sr_shmmod_modinfo_rdlock(&mod_info, 0, session->sid))) {
        goto cleanup_mods_unlock;
    }

    /* load modules data */
    if ((err_info = sr_modinfo_data_load(&mod_info, MOD_INFO_REQ, 1, &session->sid, path, timeout_ms, 0, &cb_err_info))
            || cb_err_info) {
        goto cleanup_mods_unlock;
    }

    /* filter the required data */
    if ((err_info = sr_modinfo_get_filter(&mod_info, path, session, &set))) {
        goto cleanup_mods_unlock;
    }

    if (set->number > 1) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "More subtrees match \"%s\".", path);
        goto cleanup_mods_unlock;
    } else if (!set->number) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "No data found for \"%s\".", path);
        goto cleanup_mods_unlock;
    }

    /* create return value */
    *value = malloc(sizeof **value);
    SR_CHECK_MEM_GOTO(!*value, err_info, cleanup_mods_unlock);

    if ((err_info = sr_val_ly2sr(set->set.d[0], *value))) {
        goto cleanup_mods_unlock;
    }

    /* success */

cleanup_mods_unlock:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info, 0);

cleanup_shm_unlock:
    /* SHM UNLOCK */
    sr_shmmain_unlock(session->conn, SR_LOCK_READ, 0, __func__);

    ly_set_free(set);
    sr_modinfo_free(&mod_info);
    if (cb_err_info) {
        /* return callback error if some was generated */
        sr_errinfo_merge(&err_info, cb_err_info);
        err_info->err_code = SR_ERR_CALLBACK_FAILED;
    }
    return sr_api_ret(session, err_info);
}

API int
sr_get_items(sr_session_ctx_t *session, const char *xpath, uint32_t timeout_ms, const sr_get_oper_options_t opts,
        sr_val_t **values, size_t *value_cnt)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
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

    /* SHM LOCK (reading subscriptions if using oper data) */
    if ((err_info = sr_shmmain_lock_remap(session->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    /* collect all required modules */
    if ((err_info = sr_shmmod_modinfo_collect_xpath(&mod_info, xpath))) {
        goto cleanup_shm_unlock;
    }

    /* check read perm */
    if ((err_info = sr_modinfo_perm_check(&mod_info, 0, 0))) {
        goto cleanup_shm_unlock;
    }

    /* MODULES READ LOCK */
    if ((err_info = sr_shmmod_modinfo_rdlock(&mod_info, 0, session->sid))) {
        goto cleanup_mods_unlock;
    }

    /* load modules data */
    if ((err_info = sr_modinfo_data_load(&mod_info, MOD_INFO_REQ, 1, &session->sid, xpath, timeout_ms, opts, &cb_err_info))
            || cb_err_info) {
        goto cleanup_mods_unlock;
    }

    /* filter the required data */
    if ((err_info = sr_modinfo_get_filter(&mod_info, xpath, session, &set))) {
        goto cleanup_mods_unlock;
    }

    if (set->number) {
        *values = calloc(set->number, sizeof **values);
        SR_CHECK_MEM_GOTO(!*values, err_info, cleanup_mods_unlock);
    }

    for (i = 0; i < set->number; ++i) {
        if ((err_info = sr_val_ly2sr(set->set.d[i], (*values) + i))) {
            goto cleanup_mods_unlock;
        }
        ++(*value_cnt);
    }

    /* success */

cleanup_mods_unlock:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info, 0);

cleanup_shm_unlock:
    /* SHM UNLOCK */
    sr_shmmain_unlock(session->conn, SR_LOCK_READ, 0, __func__);

    ly_set_free(set);
    sr_modinfo_free(&mod_info);
    if (cb_err_info) {
        /* return callback error if some was generated */
        sr_errinfo_merge(&err_info, cb_err_info);
        err_info->err_code = SR_ERR_CALLBACK_FAILED;
    }
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
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    struct sr_mod_info_s mod_info;
    struct ly_set *set = NULL;

    SR_CHECK_ARG_APIRET(!session || !path || !subtree, session, err_info);

    if (!timeout_ms) {
        timeout_ms = SR_OPER_CB_TIMEOUT;
    }
    /* for operational, use operational and running datastore */
    SR_MODINFO_INIT(mod_info, session->conn, session->ds, session->ds == SR_DS_OPERATIONAL ? SR_DS_RUNNING : session->ds);

    /* SHM LOCK (reading subscriptions if using oper data) */
    if ((err_info = sr_shmmain_lock_remap(session->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    /* collect all required modules */
    if ((err_info = sr_shmmod_modinfo_collect_xpath(&mod_info, path))) {
        goto cleanup_shm_unlock;
    }

    /* check read perm */
    if ((err_info = sr_modinfo_perm_check(&mod_info, 0, 0))) {
        goto cleanup_shm_unlock;
    }

    /* MODULES READ LOCK */
    if ((err_info = sr_shmmod_modinfo_rdlock(&mod_info, 0, session->sid))) {
        goto cleanup_mods_unlock;
    }

    /* load modules data */
    if ((err_info = sr_modinfo_data_load(&mod_info, MOD_INFO_REQ, 1, &session->sid, path, timeout_ms, 0, &cb_err_info))
            || cb_err_info) {
        goto cleanup_mods_unlock;
    }

    /* filter the required data */
    if ((err_info = sr_modinfo_get_filter(&mod_info, path, session, &set))) {
        goto cleanup_mods_unlock;
    }

    if (set->number > 1) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "More subtrees match \"%s\".", path);
        goto cleanup_mods_unlock;
    }

    if (set->number == 1) {
        *subtree = lyd_dup(set->set.d[0], LYD_DUP_OPT_RECURSIVE);
        if (!*subtree) {
            sr_errinfo_new_ly(&err_info, session->conn->ly_ctx);
            goto cleanup_mods_unlock;
        }
    } else {
        *subtree = NULL;
    }

    /* success */

cleanup_mods_unlock:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info, 0);

cleanup_shm_unlock:
    /* SHM UNLOCK */
    sr_shmmain_unlock(session->conn, SR_LOCK_READ, 0, __func__);

    ly_set_free(set);
    sr_modinfo_free(&mod_info);
    if (cb_err_info) {
        /* return callback error if some was generated */
        sr_errinfo_merge(&err_info, cb_err_info);
        err_info->err_code = SR_ERR_CALLBACK_FAILED;
    }
    return sr_api_ret(session, err_info);
}

API int
sr_get_data(sr_session_ctx_t *session, const char *xpath, uint32_t max_depth, uint32_t timeout_ms,
        const sr_get_oper_options_t opts, struct lyd_node **data)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
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

    /* SHM LOCK (reading subscriptions if using oper data) */
    if ((err_info = sr_shmmain_lock_remap(session->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    /* collect all required modules */
    if ((err_info = sr_shmmod_modinfo_collect_xpath(&mod_info, xpath))) {
        goto cleanup_shm_unlock;
    }

    /* check read perm */
    if ((err_info = sr_modinfo_perm_check(&mod_info, 0, 0))) {
        goto cleanup_shm_unlock;
    }

    /* MODULES READ LOCK */
    if ((err_info = sr_shmmod_modinfo_rdlock(&mod_info, 0, session->sid))) {
        goto cleanup_mods_unlock;
    }

    /* load modules data */
    if ((err_info = sr_modinfo_data_load(&mod_info, MOD_INFO_REQ, 1, &session->sid, xpath, timeout_ms, opts, &cb_err_info))
            || cb_err_info) {
        goto cleanup_mods_unlock;
    }

    /* filter the required data */
    if ((err_info = sr_modinfo_get_filter(&mod_info, xpath, session, &subtrees))) {
        goto cleanup_mods_unlock;
    }

    /* duplicate all returned subtrees with their parents and merge into one data tree */
    for (i = 0; i < subtrees->number; ++i) {
        dup_opts = (max_depth ? 0 : LYD_DUP_OPT_RECURSIVE) | LYD_DUP_OPT_WITH_PARENTS | LYD_DUP_OPT_WITH_KEYS | LYD_DUP_OPT_WITH_WHEN;
        node = lyd_dup(subtrees->set.d[i], dup_opts);
        if (!node) {
            sr_errinfo_new_ly(&err_info, session->conn->ly_ctx);
            lyd_free_withsiblings(*data);
            *data = NULL;
            goto cleanup_mods_unlock;
        }

        /* duplicate only to the specified depth */
        if ((err_info = sr_lyd_dup(subtrees->set.d[i], max_depth ? max_depth - 1 : 0, node))) {
            lyd_free_withsiblings(node);
            lyd_free_withsiblings(*data);
            *data = NULL;
            goto cleanup_mods_unlock;
        }

        /* always find parent */
        while (node->parent) {
            node = node->parent;
        }

        /* connect to the result */
        if (!*data) {
            *data = node;
        } else {
            if (lyd_merge(*data, node, LYD_OPT_DESTRUCT | LYD_OPT_EXPLICIT)) {
                sr_errinfo_new_ly(&err_info, session->conn->ly_ctx);
                lyd_free_withsiblings(node);
                lyd_free_withsiblings(*data);
                *data = NULL;
                goto cleanup_mods_unlock;
            }
        }
    }

    /* success */

cleanup_mods_unlock:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info, 0);

cleanup_shm_unlock:
    /* SHM UNLOCK */
    sr_shmmain_unlock(session->conn, SR_LOCK_READ, 0, __func__);

    ly_set_free(subtrees);
    sr_modinfo_free(&mod_info);
    if (cb_err_info) {
        /* return callback error if some was generated */
        sr_errinfo_merge(&err_info, cb_err_info);
        err_info->err_code = SR_ERR_CALLBACK_FAILED;
    }
    return sr_api_ret(session, err_info);
}

API void
sr_free_val(sr_val_t *value)
{
    if (!value) {
        return;
    }

    free(value->xpath);
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

    SR_CHECK_ARG_APIRET(!session || (!path && (!value || !value->xpath)), session, err_info);

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

    SR_CHECK_ARG_APIRET(!session || !path, session, err_info);

    /* we do not need any lock, ext SHM is not accessed */

    /* add the operation into edit */
    err_info = sr_edit_add(session, path, value, opts & SR_EDIT_STRICT ? "create" : "merge",
            opts & SR_EDIT_NON_RECURSIVE ? "none" : "merge", NULL, NULL, NULL, origin, opts & SR_EDIT_ISOLATE);

    return sr_api_ret(session, err_info);
}

API int
sr_delete_item(sr_session_ctx_t *session, const char *path, const sr_edit_options_t opts)
{
    sr_error_info_t *err_info = NULL;
    const char *operation;
    const struct lys_node *snode;
    int ly_log_opts;

    SR_CHECK_ARG_APIRET(!session || !path, session, err_info);

    /* turn off logging */
    ly_log_opts = ly_log_options(0);

    if ((path[strlen(path) - 1] != ']') && (snode = ly_ctx_get_node(session->conn->ly_ctx, NULL, path, 0)) &&
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
sr_move_item(sr_session_ctx_t *session, const char *path, const sr_move_position_t position, const char *list_keys,
        const char *leaflist_value, const char *origin, const sr_edit_options_t opts)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session || !path, session, err_info);

    /* add the operation into edit */
    err_info = sr_edit_add(session, path, NULL, opts & SR_EDIT_STRICT ? "create" : "merge",
            opts & SR_EDIT_NON_RECURSIVE ? "none" : "merge", &position, list_keys, leaflist_value, origin, opts & SR_EDIT_ISOLATE);

    return sr_api_ret(session, err_info);
}

API int
sr_edit_batch(sr_session_ctx_t *session, const struct lyd_node *edit, const char *default_operation)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *dup_edit = NULL, *node;

    SR_CHECK_ARG_APIRET(!session || !edit || !default_operation, session, err_info);
    SR_CHECK_ARG_APIRET(strcmp(default_operation, "merge") && strcmp(default_operation, "replace")
            && strcmp(default_operation, "none"), session, err_info);

    if (session->conn->ly_ctx != edit->schema->module->ctx) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Data trees must be created using the session connection libyang context.");
        return sr_api_ret(session, err_info);
    } else if (session->dt[session->ds].edit) {
        /* do not allow merging NETCONF edits into sysrepo ones, it can cause some unexpected results */
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, NULL, "There are already some session changes.");
        return sr_api_ret(session, err_info);
    }

    dup_edit = lyd_dup_withsiblings(edit, LYD_DUP_OPT_RECURSIVE);
    if (!dup_edit) {
        sr_errinfo_new_ly(&err_info, session->conn->ly_ctx);
        goto error;
    }

    /* add default operation and default origin */
    LY_TREE_FOR(dup_edit, node) {
        if (!sr_edit_find_oper(node, 0, NULL) && (err_info = sr_edit_set_oper(node, default_operation))) {
            goto error;
        }
        if ((session->ds == SR_DS_OPERATIONAL) && (err_info = sr_edit_diff_set_origin(node, SR_OPER_ORIGIN, 0))) {
            goto error;
        }
    }

    session->dt[session->ds].edit = dup_edit;
    return sr_api_ret(session, NULL);

error:
    lyd_free_withsiblings(dup_edit);
    return sr_api_ret(session, err_info);
}

API int
sr_validate(sr_session_ctx_t *session, const char *module_name, uint32_t timeout_ms)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    const struct lys_module *ly_mod = NULL;
    const struct lyd_node *node;
    struct sr_mod_info_s mod_info;

    SR_CHECK_ARG_APIRET(!session, session, err_info);

    if (!timeout_ms) {
        timeout_ms = SR_OPER_CB_TIMEOUT;
    }
    /* for operational, use operational and running datastore */
    SR_MODINFO_INIT(mod_info, session->conn, session->ds, session->ds == SR_DS_OPERATIONAL ? SR_DS_RUNNING : session->ds);

    /* SHM LOCK (reading subscriptions if using oper data) */
    if ((err_info = sr_shmmain_lock_remap(session->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    if (module_name) {
        /* try to find this module */
        ly_mod = ly_ctx_get_module(session->conn->ly_ctx, module_name, NULL, 1);
        if (!ly_mod) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" was not found in sysrepo.", module_name);
            goto cleanup_shm_unlock;
        }
    }

    switch (session->ds) {
    case SR_DS_STARTUP:
    case SR_DS_RUNNING:
        if (!session->dt[session->ds].edit) {
            /* nothing to validate */
            goto cleanup_shm_unlock;
        }

        if (ly_mod) {
            /* check that there are some changes for this module */
            LY_TREE_FOR(session->dt[session->ds].edit, node) {
                if (lyd_node_module(node) == ly_mod) {
                    break;
                }
            }
            if (!ly_mod) {
                /* nothing to validate */
                goto cleanup_shm_unlock;
            }

            err_info = sr_shmmod_modinfo_collect_modules(&mod_info, ly_mod, MOD_INFO_DEP | MOD_INFO_INV_DEP);
        } else {
            /* collect all modified modules (other modules must be valid) */
            err_info = sr_shmmod_modinfo_collect_edit(&mod_info, session->dt[session->ds].edit);
        }
        break;
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        /* specific module/all modules */
        err_info = sr_shmmod_modinfo_collect_modules(&mod_info, ly_mod, MOD_INFO_DEP | MOD_INFO_INV_DEP);
        break;
    }
    if (err_info) {
        goto cleanup_shm_unlock;
    }

    /* MODULES READ LOCK */
    if ((err_info = sr_shmmod_modinfo_rdlock(&mod_info, 0, session->sid))) {
        goto cleanup_mods_unlock;
    }

    /* load all modules data (we need dependencies for validation) */
    if ((err_info = sr_modinfo_data_load(&mod_info, MOD_INFO_TYPE_MASK, 0, &session->sid, NULL, timeout_ms, 0,
            &cb_err_info)) || cb_err_info) {
        goto cleanup_mods_unlock;
    }

    /* apply any changes */
    if ((err_info = sr_modinfo_edit_apply(&mod_info, session->dt[session->ds].edit, 0))) {
        goto cleanup_mods_unlock;
    }

    /* validate the data trees */
    if ((err_info = sr_modinfo_validate(&mod_info, 0, &session->sid, &cb_err_info)) || cb_err_info) {
        goto cleanup_mods_unlock;
    }

    /* success */

cleanup_mods_unlock:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info, 0);

cleanup_shm_unlock:
    /* SHM UNLOCK */
    sr_shmmain_unlock(session->conn, SR_LOCK_READ, 0, __func__);

    sr_modinfo_free(&mod_info);
    if (cb_err_info) {
        /* return callback error if some was generated */
        sr_errinfo_merge(&err_info, cb_err_info);
        err_info->err_code = SR_ERR_CALLBACK_FAILED;
    }
    return sr_api_ret(session, err_info);
}

/**
 * @brief Notify subscribers about the changes in diff and store the data in mod info.
 * Main SHM is expected to be READ-locked!
 * Mod info modules are expected to be READ-locked with the ability to upgrade to WRITE-lock!
 *
 * @param[in] mod_info Read-locked mod info with diff and data.
 * @param[in] session Originator session.
 * @param[in] timeout_ms Timeout in milliseconds.
 * @param[in] wait Whether to wait for DONE/ABORT events as well.
 * @param[out] cb_err_info Callback error information generated by a subscriber, if any.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_changes_notify_store(struct sr_mod_info_s *mod_info, sr_session_ctx_t *session, uint32_t timeout_ms, int wait,
        sr_error_info_t **cb_err_info)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *update_edit = NULL, *old_diff = NULL, *new_diff = NULL;
    sr_session_ctx_t tmp_sess;
    int ret;

    memset(&tmp_sess, 0, sizeof tmp_sess);
    *cb_err_info = NULL;

    /* call connection diff callback */
    if (mod_info->diff && session->conn->diff_check_cb) {
        /* create temporary session */
        tmp_sess.conn = session->conn;
        tmp_sess.ds = session->ds;
        tmp_sess.ev = SR_SUB_EV_CHANGE;
        tmp_sess.sid = session->sid;

        ret = session->conn->diff_check_cb(&tmp_sess, mod_info->diff);
        if (ret) {
            /* create cb_err_info */
            if (tmp_sess.err_info && (tmp_sess.err_info->err_code == SR_ERR_OK)) {
                sr_errinfo_new(cb_err_info, ret, tmp_sess.err_info->err[0].xpath, tmp_sess.err_info->err[0].message);
            } else {
                sr_errinfo_new(cb_err_info, ret, NULL, "Diff check callback failed (%s).", sr_strerror(ret));
            }
            goto cleanup;
        }
    }

    /* validate new data trees */
    switch (session->ds) {
    case SR_DS_STARTUP:
    case SR_DS_RUNNING:
        if ((err_info = sr_modinfo_validate(mod_info, 1, NULL, NULL))) {
            goto cleanup;
        }
        break;
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        /* these do not have to be valid but at least add default values */
        if ((err_info = sr_modinfo_add_defaults(mod_info, 1))) {
            goto cleanup;
        }
        break;
    }

    /* check write perm (we must wait until after validation, some additional modules can be modified) */
    if ((err_info = sr_modinfo_perm_check(mod_info, 1, 1))) {
        goto cleanup;
    }

    if (!mod_info->diff) {
        SR_LOG_INFMSG("No datastore changes to apply.");
        goto cleanup;
    }

    /* publish current diff in an "update" event for the subscribers to update it */
    if ((err_info = sr_shmsub_change_notify_update(mod_info, session->sid, timeout_ms, &update_edit, cb_err_info))) {
        goto cleanup;
    }
    if (*cb_err_info) {
        /* "update" event failed, just clear the sub SHM and finish */
        err_info = sr_shmsub_change_notify_clear(mod_info, SR_SUB_EV_UPDATE);
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

        /* validate updated data trees and finish new diff */
        switch (session->ds) {
        case SR_DS_STARTUP:
        case SR_DS_RUNNING:
            if ((err_info = sr_modinfo_validate(mod_info, 1, NULL, NULL))) {
                goto cleanup;
            }
            break;
        case SR_DS_CANDIDATE:
        case SR_DS_OPERATIONAL:
            if ((err_info = sr_modinfo_add_defaults(mod_info, 1))) {
                goto cleanup;
            }
            break;
        }

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
        SR_LOG_INFMSG("No datastore changes to apply.");
        goto cleanup;
    }

    /* publish final diff in a "change" event for any subscribers and wait for them */
    if ((err_info = sr_shmsub_change_notify_change(mod_info, session->sid, timeout_ms, cb_err_info))) {
        goto cleanup;
    }
    if (*cb_err_info) {
        /* "change" event failed, publish "abort" event and finish */
        err_info = sr_shmsub_change_notify_change_abort(mod_info, session->sid, wait ? timeout_ms : 0);
        goto cleanup;
    }

    /* MODULES WRITE LOCK (upgrade) */
    if ((err_info = sr_shmmod_modinfo_rdlock_upgrade(mod_info, session->sid))) {
        goto cleanup;
    }

    /* store updated datastore */
    if ((err_info = sr_modinfo_data_store(mod_info))) {
        goto cleanup;
    }

    /* MODULES READ LOCK (downgrade) */
    if ((err_info = sr_shmmod_modinfo_wrlock_downgrade(mod_info, session->sid))) {
        goto cleanup;
    }

    /* publish "done" event, all changes were applied */
    if ((err_info = sr_shmsub_change_notify_change_done(mod_info, session->sid, wait ? timeout_ms : 0))) {
        goto cleanup;
    }

    /* generate netconf-config-change notification */
    if ((err_info = sr_modinfo_generate_config_change_notif(mod_info, session))) {
        goto cleanup;
    }

    /* success */

cleanup:
    lyd_free_withsiblings(update_edit);
    lyd_free_withsiblings(old_diff);
    lyd_free_withsiblings(new_diff);
    sr_errinfo_free(&tmp_sess.err_info);
    return err_info;
}

API int
sr_apply_changes(sr_session_ctx_t *session, uint32_t timeout_ms, int wait)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    struct sr_mod_info_s mod_info;
    sr_get_oper_options_t get_opts;

    SR_CHECK_ARG_APIRET(!session, session, err_info);

    if (!session->dt[session->ds].edit) {
        return sr_api_ret(session, NULL);
    }

    if (!timeout_ms) {
        timeout_ms = SR_CHANGE_CB_TIMEOUT;
    }
    /* for operational, use operational and running datastore */
    SR_MODINFO_INIT(mod_info, session->conn, session->ds, session->ds == SR_DS_OPERATIONAL ? SR_DS_RUNNING : session->ds);

    if (session->ds == SR_DS_OPERATIONAL) {
        /* when updating stored oper data, we will not validate them so we do not need data from oper subscribers */
        get_opts = SR_OPER_NO_SUBS;
    } else {
        get_opts = 0;
    }

    /* SHM LOCK (reading subscriptions) */
    if ((err_info = sr_shmmain_lock_remap(session->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    /* collect all required modules */
    if ((err_info = sr_shmmod_modinfo_collect_edit(&mod_info, session->dt[session->ds].edit))) {
        goto cleanup_shm_unlock;
    }

    /* MODULES READ LOCK (but setting flag for guaranteed later upgrade success) */
    if ((err_info = sr_shmmod_modinfo_rdlock(&mod_info, 1, session->sid))) {
        goto cleanup_mods_unlock;
    }

    /* load all modules data (we need dependencies for validation) */
    if ((err_info = sr_modinfo_data_load(&mod_info, MOD_INFO_TYPE_MASK, 0, NULL, NULL, 0, get_opts, NULL))) {
        goto cleanup_mods_unlock;
    }

    /* create diff */
    if ((err_info = sr_modinfo_edit_apply(&mod_info, session->dt[session->ds].edit, 1))) {
        goto cleanup_mods_unlock;
    }

    /* notify all the subscribers and store the changes */
    err_info = sr_changes_notify_store(&mod_info, session, timeout_ms, wait, &cb_err_info);

cleanup_mods_unlock:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info, 1);

cleanup_shm_unlock:
    /* SHM UNLOCK */
    sr_shmmain_unlock(session->conn, SR_LOCK_READ, 0, __func__);

    if (!err_info && !cb_err_info) {
        /* free applied edit */
        lyd_free_withsiblings(session->dt[session->ds].edit);
        session->dt[session->ds].edit = NULL;
    }

    sr_modinfo_free(&mod_info);
    if (cb_err_info) {
        /* return callback error if some was generated */
        sr_errinfo_merge(&err_info, cb_err_info);
        err_info->err_code = SR_ERR_CALLBACK_FAILED;
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

    lyd_free_withsiblings(session->dt[session->ds].edit);
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
 * @param[in] wait Whether to wait for DONE/ABORT events as well.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
_sr_replace_config(sr_session_ctx_t *session, const struct lys_module *ly_mod, struct lyd_node **src_config,
        uint32_t timeout_ms, int wait)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    struct sr_mod_info_s mod_info;

    assert(!*src_config || !(*src_config)->prev->next);
    assert(session->ds != SR_DS_OPERATIONAL);
    SR_MODINFO_INIT(mod_info, session->conn, session->ds, session->ds);

    /* collect all required modules */
    if ((err_info = sr_shmmod_modinfo_collect_modules(&mod_info, ly_mod, MOD_INFO_DEP | MOD_INFO_INV_DEP))) {
        return err_info;
    }

    /* check write perm */
    if ((err_info = sr_modinfo_perm_check(&mod_info, 1, 1))) {
        return err_info;
    }

    /* MODULES READ LOCK (but setting flag for guaranteed later upgrade success) */
    if ((err_info = sr_shmmod_modinfo_rdlock(&mod_info, 1, session->sid))) {
        return err_info;
    }

    /* load all current modules data */
    if ((err_info = sr_modinfo_data_load(&mod_info, MOD_INFO_TYPE_MASK, 0, NULL, NULL, 0, 0, NULL))) {
        goto cleanup_mods_unlock;
    }

    /* update affected data and create corresponding diff, src_config is spent */
    if ((err_info = sr_modinfo_replace(&mod_info, src_config))) {
        goto cleanup_mods_unlock;
    }

    /* notify all the subscribers and store the changes */
    err_info = sr_changes_notify_store(&mod_info, session, timeout_ms, wait, &cb_err_info);

cleanup_mods_unlock:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info, 1);

    sr_modinfo_free(&mod_info);
    if (cb_err_info) {
        /* return callback error if some was generated */
        sr_errinfo_merge(&err_info, cb_err_info);
        err_info->err_code = SR_ERR_CALLBACK_FAILED;
    }
    return err_info;
}

API int
sr_replace_config(sr_session_ctx_t *session, const char *module_name, struct lyd_node *src_config, uint32_t timeout_ms,
        int wait)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod = NULL;

    SR_CHECK_ARG_APIRET(!session || !SR_IS_CONVENTIONAL_DS(session->ds), session, err_info);
    if (src_config && (session->conn->ly_ctx != src_config->schema->module->ctx)) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Data trees must be created using the session connection libyang context.");
        return sr_api_ret(session, err_info);
    }

    if (!timeout_ms) {
        timeout_ms = SR_CHANGE_CB_TIMEOUT;
    }

    /* find first sibling */
    for (; src_config && src_config->prev->next; src_config = src_config->prev);

    /* SHM LOCK (reading subscriptions) */
    if ((err_info = sr_shmmain_lock_remap(session->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    if (module_name) {
        /* try to find this module */
        ly_mod = ly_ctx_get_module(session->conn->ly_ctx, module_name, NULL, 1);
        if (!ly_mod) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" was not found in sysrepo.", module_name);
            goto cleanup_shm_unlock;
        }
    }

    /* replace the data */
    if ((err_info = _sr_replace_config(session, ly_mod, &src_config, timeout_ms, wait))) {
        goto cleanup_shm_unlock;
    }

    /* success */

cleanup_shm_unlock:
    /* SHM UNLOCK */
    sr_shmmain_unlock(session->conn, SR_LOCK_READ, 0, __func__);

    lyd_free_withsiblings(src_config);
    return sr_api_ret(session, err_info);
}

API int
sr_copy_config(sr_session_ctx_t *session, const char *module_name, sr_datastore_t src_datastore, uint32_t timeout_ms,
        int wait)
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

    /* SHM LOCK (reading subscriptions) */
    if ((err_info = sr_shmmain_lock_remap(session->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    if (module_name) {
        /* try to find this module */
        ly_mod = ly_ctx_get_module(session->conn->ly_ctx, module_name, NULL, 1);
        if (!ly_mod) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" was not found in sysrepo.", module_name);
            goto cleanup_shm_unlock;
        }
    }

    /* collect all required modules (dependencies are not needed for a single module, otherwise all of them are there) */
    if ((err_info = sr_shmmod_modinfo_collect_modules(&mod_info, ly_mod, 0))) {
        goto cleanup_shm_unlock;
    }

    if ((src_datastore == SR_DS_RUNNING) && (session->ds == SR_DS_CANDIDATE)) {
        /* MODULES WRITE LOCK */
        if ((err_info = sr_shmmod_modinfo_wrlock(&mod_info, session->sid))) {
            goto cleanup_shm_unlock;
        }

        /* special case, just reset candidate */
        err_info = sr_modinfo_candidate_reset(&mod_info);
        goto cleanup_modules_unlock;
    }

    /* MODULES READ LOCK */
    if ((err_info = sr_shmmod_modinfo_rdlock(&mod_info, 0, session->sid))) {
        goto cleanup_shm_unlock;
    }

    /* get their data */
    if ((err_info = sr_modinfo_data_load(&mod_info, MOD_INFO_REQ, 0, NULL, NULL, 0, 0, NULL))) {
        goto cleanup_modules_unlock;
    }

    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info, 0);

    /* replace the data */
    if ((err_info = _sr_replace_config(session, ly_mod, &mod_info.data, timeout_ms, wait))) {
        goto cleanup_shm_unlock;
    }

    if ((src_datastore == SR_DS_CANDIDATE) && (session->ds == SR_DS_RUNNING)) {
        /* MODULES WRITE LOCK */
        if ((err_info = sr_shmmod_modinfo_wrlock(&mod_info, session->sid))) {
            goto cleanup_shm_unlock;
        }

        /* reset candidate after it was applied in running */
        err_info = sr_modinfo_candidate_reset(&mod_info);
        goto cleanup_modules_unlock;
    } else {
        /* success */
        goto cleanup_shm_unlock;
    }

cleanup_modules_unlock:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info, 0);

cleanup_shm_unlock:
    /* SHM UNLOCK */
    sr_shmmain_unlock(session->conn, SR_LOCK_READ, 0, __func__);

    sr_modinfo_free(&mod_info);
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
sr_change_dslock(struct sr_mod_info_s *mod_info, int lock, sr_sid_t sid)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, j;
    char *path;
    int r;
    struct sr_mod_info_mod_s *mod;
    struct sr_mod_lock_s *shm_lock;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        shm_lock = &mod->shm_mod->data_lock_info[mod_info->ds];

        assert(mod->state & MOD_INFO_REQ);

        /* we assume these modules are write-locked by this session */
        assert(shm_lock->write_locked && (shm_lock->sid.sr == sid.sr));

        /* it was successfully WRITE-locked, check that DS lock state is as expected */
        if (shm_lock->ds_locked && lock) {
            assert(shm_lock->sid.sr == sid.sr);
            sr_errinfo_new(&err_info, SR_ERR_LOCKED, NULL, "Module \"%s\" is already locked by this session %u (NC SID %u).",
                    mod->ly_mod->name, sid.sr, sid.nc);
            goto error;
        } else if (!shm_lock->ds_locked && !lock) {
            assert(shm_lock->sid.sr == sid.sr);
            sr_errinfo_new(&err_info, SR_ERR_OPERATION_FAILED, NULL, "Module \"%s\" was not locked by this session %u (NC SID %u).",
                    mod->ly_mod->name, sid.sr, sid.nc);
            goto error;
        } else if (lock && (mod_info->ds == SR_DS_CANDIDATE)) {
            /* candidate DS file cannot exist */
            if ((err_info = sr_path_ds_shm(mod->ly_mod->name, SR_DS_CANDIDATE, 1, &path))) {
                goto error;
            }
            r = access(path, F_OK);
            free(path);
            if ((r == -1) && (errno != ENOENT)) {
                SR_ERRINFO_SYSERRNO(&err_info, "access");
                goto error;
            } else if (!r) {
                sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, NULL, "Module \"%s\" candidate datastore data have "
                        "already been modified.", mod->ly_mod->name);
                goto error;
            }
        }

        /* change DS lock state and remember the time */
        shm_lock->ds_locked = lock;
        if (lock) {
            shm_lock->ds_ts = time(NULL);
        } else {
            shm_lock->ds_ts = 0;
        }
    }

    return NULL;

error:
    /* reverse any DS lock state changes */
    for (j = 0; j < i; ++j) {
        shm_lock = &mod_info->mods[j].shm_mod->data_lock_info[mod_info->ds];

        assert((shm_lock->ds_locked && lock) || (!shm_lock->ds_locked && !lock));

        if (lock) {
            shm_lock->ds_locked = 0;
        } else {
            shm_lock->ds_locked = 1;
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

    /* no lock required, accessing only main SHM (modules) */

    if (module_name) {
        /* try to find this module */
        ly_mod = ly_ctx_get_module(session->conn->ly_ctx, module_name, NULL, 1);
        if (!ly_mod) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" was not found in sysrepo.", module_name);
            goto cleanup;
        }
    }

    /* collect all required modules */
    if ((err_info = sr_shmmod_modinfo_collect_modules(&mod_info, ly_mod, 0))) {
        goto cleanup;
    }

    /* check read perm */
    if (lock && (err_info = sr_modinfo_perm_check(&mod_info, 0, 1))) {
        goto cleanup;
    }

    /* MODULES READ LOCK (but setting flag to forbid write locking) */
    if ((err_info = sr_shmmod_modinfo_rdlock(&mod_info, 1, session->sid))) {
        goto cleanup_mods_unlock;
    }

    /* DS-(un)lock them */
    if ((err_info = sr_change_dslock(&mod_info, lock, session->sid))) {
        goto cleanup_mods_unlock;
    }

    /* candidate datastore unlocked, reset its state */
    if (!lock && (mod_info.ds == SR_DS_CANDIDATE)) {
        /* MODULES WRITE LOCK (upgrade) */
        if ((err_info = sr_shmmod_modinfo_rdlock_upgrade(&mod_info, session->sid))) {
            goto cleanup_mods_unlock;
        }

        if ((err_info = sr_modinfo_candidate_reset(&mod_info))) {
            goto cleanup_mods_unlock;
        }
    }

    /* success */

cleanup_mods_unlock:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info, 1);

cleanup:
    sr_modinfo_free(&mod_info);
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
        uint32_t *nc_id, time_t *timestamp)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_s mod_info;
    const struct lys_module *ly_mod = NULL;
    struct sr_mod_lock_s *shm_lock;
    uint32_t i;
    sr_sid_t sid;

    SR_CHECK_ARG_APIRET(!conn || !SR_IS_CONVENTIONAL_DS(datastore) || !is_locked, NULL, err_info);

    if (id) {
        *id = 0;
    }
    if (nc_id) {
        *nc_id = 0;
    }
    if (timestamp) {
        *timestamp = 0;
    }
    SR_MODINFO_INIT(mod_info, conn, datastore, datastore);
    memset(&sid, 0, sizeof sid);

    /* no lock required, accessing only main SHM (modules) */

    if (module_name) {
        /* try to find this module */
        ly_mod = ly_ctx_get_module(conn->ly_ctx, module_name, NULL, 1);
        if (!ly_mod) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" was not found in sysrepo.", module_name);
            goto cleanup;
        }
    }

    /* collect all required modules */
    if ((err_info = sr_shmmod_modinfo_collect_modules(&mod_info, ly_mod, 0))) {
        goto cleanup;
    }

    /* check read perm */
    if ((err_info = sr_modinfo_perm_check(&mod_info, 0, 1))) {
        goto cleanup;
    }

    /* check DS-lock of the module(s) */
    for (i = 0; i < mod_info.mod_count; ++i) {
        shm_lock = &mod_info.mods[i].shm_mod->data_lock_info[mod_info.ds];

        if (!shm_lock->ds_locked) {
            /* there is at least one module that is not DS-locked */
            break;
        }

        if (!sid.sr) {
            /* remember the first DS lock owner */
            sid = shm_lock->sid;
        } else if (sid.sr != shm_lock->sid.sr) {
            /* more DS module lock owners, not a full DS lock */
            break;
        }
    }

    if (i < mod_info.mod_count) {
        /* not full DS lock */
        *is_locked = 0;
    } else if (mod_info.mod_count) {
        /* the module or all modules is DS locked by a single SR session */
        *is_locked = 1;
        if (id) {
            *id = sid.sr;
        }
        if (nc_id) {
            *nc_id = sid.nc;
        }
        if (timestamp) {
            *timestamp = shm_lock->ds_ts;
        }
    }

    /* success */

cleanup:
    sr_modinfo_free(&mod_info);
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

/**
 * @brief Process special notification events on a subscription involving
 * changing ext SHM.
 *
 * @param[in] subscription Subscription to process.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_process_events_notif_replay_stop(sr_subscription_ctx_t *subscription)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    int mod_finished;

    /* SHM LOCK (writing into subscriptions) */
    if ((err_info = sr_shmmain_lock_remap(subscription->conn, SR_LOCK_WRITE, 1, __func__))) {
        return err_info;
    }

    /* SUBS LOCK */
    if ((err_info = sr_mlock(&subscription->subs_lock, SR_SUB_SUBS_LOCK_TIMEOUT, __func__))) {
        goto cleanup_unlock;
    }

    i = 0;
    while (i < subscription->notif_sub_count) {
        /* perform any replays requested */
        if ((err_info = sr_shmsub_notif_listen_module_replay(&subscription->notif_subs[i], subscription))) {
            goto cleanup_subs_unlock;
        }

        /* check whether a subscription did not finish */
        if ((err_info = sr_shmsub_notif_listen_module_stop_time(&subscription->notif_subs[i], subscription,
                &mod_finished))) {
            goto cleanup_subs_unlock;
        }
        if (mod_finished) {
            /* all subscriptions of this module have finished, try the next */
            continue;
        }

        /* next iteration */
        ++i;
    }

    /* success */

cleanup_subs_unlock:
    /* SUBS UNLOCK */
    sr_munlock(&subscription->subs_lock);

cleanup_unlock:
    /* SHM UNLOCK */
    sr_shmmain_unlock(subscription->conn, SR_LOCK_WRITE, 1, __func__);
    return err_info;
}

API int
sr_process_events(sr_subscription_ctx_t *subscription, sr_session_ctx_t *session, time_t *stop_time_in)
{
    sr_error_info_t *err_info = NULL;
    int ret;
    char buf[1];
    uint32_t i;

    /* session does not have to be set */
    SR_CHECK_ARG_APIRET(!subscription, session, err_info);

    if (stop_time_in) {
        *stop_time_in = 0;
    }

process_events:
    /* SUBS LOCK */
    if ((err_info = sr_mlock(&subscription->subs_lock, SR_SUB_SUBS_LOCK_TIMEOUT, __func__))) {
        return sr_api_ret(session, err_info);
    }

    /* read all bytes from the pipe, there can be several events by now */
    do {
        ret = read(subscription->evpipe, buf, 1);
    } while (ret == 1);
    if ((ret == -1) && (errno != EAGAIN)) {
        SR_ERRINFO_SYSERRNO(&err_info, "read");
        sr_errinfo_new(&err_info, SR_ERR_INTERNAL, NULL, "Failed to read from an event pipe.");
        goto cleanup_unlock;
    }

    /* first check whether there are any pending replays or finished subscriptions ... */
    for (i = 0; i < subscription->notif_sub_count; ++i) {
        if (sr_shmsub_notif_listen_module_has_replay_or_stop(&subscription->notif_subs[i])) {
            break;
        }
    }
    if (i < subscription->notif_sub_count) {
        /* ... there are, prepare for handling them (keep lock order) */

        /* SUBS UNLOCK */
        sr_munlock(&subscription->subs_lock);

        if ((err_info = sr_process_events_notif_replay_stop(subscription))) {
            return sr_api_ret(session, err_info);
        }

        /* start from the beginning again, anything could have changed */
        goto process_events;
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
    for (i = 0; i < subscription->notif_sub_count; ++i) {
        if ((err_info = sr_shmsub_notif_listen_process_module_events(&subscription->notif_subs[i], subscription->conn))) {
            goto cleanup_unlock;
        }

        /* find nearest stop time */
        sr_shmsub_notif_listen_module_get_stop_time_in(&subscription->notif_subs[i], stop_time_in);
    }

cleanup_unlock:
    /* SUBS UNLOCK */
    sr_munlock(&subscription->subs_lock);
    return sr_api_ret(session, err_info);
}

/**
 * @brief Unlocked unsubscribe (free) a subscription.
 *
 * @param[in] subscription Subscription to free.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
_sr_unsubscribe(sr_subscription_ctx_t *subscription)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    char *path;
    int ret;

    assert(subscription);

    if (ATOMIC_LOAD_RELAXED(subscription->thread_running)) {
        /* signal the thread to quit */
        ATOMIC_STORE_RELAXED(subscription->thread_running, 0);

        /* generate a new event for the thread to wake up */
        err_info = sr_shmsub_notify_evpipe(subscription->evpipe_num);

        if (!err_info) {
            /* join the thread */
            ret = pthread_join(subscription->tid, NULL);
            if (ret) {
                sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Joining the subscriber thread failed (%s).", strerror(ret));
            }
        }
    }

    /* delete all subscriptions (also removes this subscription from all the sessions) */
    if ((tmp_err = sr_subs_del_all(subscription))) {
        /* continue */
        sr_errinfo_merge(&err_info, tmp_err);
    }

    /* remove subscription from main SHM state */
    sr_shmmain_conn_del_evpipe(subscription->conn, subscription->evpipe_num);

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
    pthread_mutex_destroy(&subscription->subs_lock);
    free(subscription);
    return err_info;
}

API int
sr_unsubscribe(sr_subscription_ctx_t *subscription)
{
    sr_error_info_t *err_info = NULL;
    sr_conn_ctx_t *conn;

    if (!subscription) {
        return sr_api_ret(NULL, NULL);
    }

    conn = subscription->conn;

    /* SHM LOCK (writing into subscriptions) */
    if ((err_info = sr_shmmain_lock_remap(conn, SR_LOCK_WRITE, 1, __func__))) {
        return sr_api_ret(NULL, err_info);
    }

    err_info = _sr_unsubscribe(subscription);

    /* SHM UNLOCK */
    sr_shmmain_unlock(conn, SR_LOCK_WRITE, 1, __func__);

    return sr_api_ret(NULL, err_info);
}

/**
 * @brief Perform enabled event on a subscription.
 *
 * @param[in] session Session to use.
 * @param[in] ly_mod Specific module.
 * @param[in] xpath Optional subscription xpath.
 * @param[in] callback Callback to call.
 * @param[in] private_data Arbitrary callback data.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_module_change_subscribe_running_enable(sr_session_ctx_t *session, const struct lys_module *ly_mod, const char *xpath,
        sr_module_change_cb callback, void *private_data, int opts)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *enabled_data = NULL, *node;
    struct sr_mod_info_s mod_info;
    sr_session_ctx_t tmp_sess;
    sr_error_t err_code;

    SR_MODINFO_INIT(mod_info, session->conn, SR_DS_RUNNING, SR_DS_RUNNING);
    memset(&tmp_sess, 0, sizeof tmp_sess);

    /* create mod_info structure with this module only */
    if ((err_info = sr_shmmod_modinfo_collect_modules(&mod_info, ly_mod, 0))) {
        return err_info;
    }

    /* MODULES READ LOCK */
    if ((err_info = sr_shmmod_modinfo_rdlock(&mod_info, 0, session->sid))) {
        sr_modinfo_free(&mod_info);
        return err_info;
    }

    /* get the current running datastore data */
    if ((err_info = sr_modinfo_data_load(&mod_info, MOD_INFO_REQ, 1, NULL, NULL, 0, 0, NULL))) {
        goto error_mods_unlock;
    }

    /* select only the subscribed-to subtree */
    if (mod_info.data) {
        if (xpath) {
            if ((err_info = sr_lyd_xpath_dup(mod_info.data, (char **)&xpath, 1, ly_mod, &enabled_data))) {
                goto error_mods_unlock;
            }
        } else {
            if (!(enabled_data = lyd_dup_withsiblings(mod_info.data, LYD_DUP_OPT_RECURSIVE))) {
                sr_errinfo_new_ly(&err_info, session->conn->ly_ctx);
                goto error_mods_unlock;
            }
        }
    }

    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info, 0);

    sr_modinfo_free(&mod_info);

    /* these data will be presented as newly created, make such a diff */
    LY_TREE_FOR(enabled_data, node) {
        /* top-level "create" operation that is inherited */
        if ((err_info = sr_edit_set_oper(node, "create"))) {
            goto cleanup;
        }

        /* user-ordered lists need information about position */
        if ((err_info = sr_edit_created_subtree_apply_move(node))) {
            goto cleanup;
        }
    }

    tmp_sess.conn = session->conn;
    tmp_sess.ds = SR_DS_RUNNING;
    tmp_sess.dt[tmp_sess.ds].diff = enabled_data;

    if (!(opts & SR_SUBSCR_DONE_ONLY)) {
        tmp_sess.ev = SR_SUB_EV_ENABLED;
        SR_LOG_INF("Triggering \"%s\" \"%s\" event on enabled data.", ly_mod->name, sr_ev2str(tmp_sess.ev));

        /* present all changes in an "enabled" event */
        err_code = callback(&tmp_sess, ly_mod->name, xpath, sr_ev2api(tmp_sess.ev), 0, private_data);
        if (err_code != SR_ERR_OK) {
            /* callback failed but it is the only one so no "abort" event is necessary */
            sr_errinfo_new(&err_info, SR_ERR_CALLBACK_FAILED, NULL, "Subscribing to \"%s\" changes failed.", ly_mod->name);
            if (tmp_sess.err_info && (tmp_sess.err_info->err_code == SR_ERR_OK)) {
                /* remember callback error info */
                sr_errinfo_merge(&err_info, tmp_sess.err_info);
            }
            goto cleanup;
        }
    }

    /* finish with a "done" event just because this event should imitate a regular change */
    tmp_sess.ev = SR_SUB_EV_DONE;
    SR_LOG_INF("Triggering \"%s\" \"%s\" event on enabled data.", ly_mod->name, sr_ev2str(tmp_sess.ev));
    callback(&tmp_sess, ly_mod->name, xpath, sr_ev2api(tmp_sess.ev), 0, private_data);

cleanup:
    lyd_free_withsiblings(enabled_data);
    return NULL;

error_mods_unlock:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info, 0);

    sr_modinfo_free(&mod_info);
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
sr_subs_new(sr_conn_ctx_t *conn, sr_subscr_options_t opts, sr_subscription_ctx_t **subs_p)
{
    sr_error_info_t *err_info = NULL;
    sr_main_shm_t *main_shm;
    char *path = NULL;
    int ret;
    mode_t um;

    /* allocate new subscription */
    *subs_p = calloc(1, sizeof **subs_p);
    SR_CHECK_MEM_RET(!*subs_p, err_info);
    sr_mutex_init(&(*subs_p)->subs_lock, 0);
    (*subs_p)->conn = conn;
    (*subs_p)->evpipe = -1;

    /* get new event pipe number and increment it */
    main_shm = (sr_main_shm_t *)(*subs_p)->conn->main_shm.addr;
    (*subs_p)->evpipe_num = ATOMIC_INC_RELAXED(main_shm->new_evpipe_num);
    if ((*subs_p)->evpipe_num == (uint32_t)(ATOMIC_T_MAX - 1)) {
        /* the value in the main SHM is actually ATOMIC_T_MAX and calling another INC would cause an overflow */
        ATOMIC_STORE_RELAXED(main_shm->new_evpipe_num, 1);
    }

    /* get event pipe name */
    if ((err_info = sr_path_evpipe((*subs_p)->evpipe_num, &path))) {
        goto error;
    }

    /* set umask so that the correct permissions are really set */
    um = umask(00000);

    /* create the event pipe */
    ret = mkfifo(path, SR_EVPIPE_PERM);
    umask(um);
    if (ret == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "mkfifo");
        goto error;
    }

    /* open it for reading AND writing (just so that there always is a "writer", otherwise it is always ready
     * for reading by select() but returns just EOF on read) */
    (*subs_p)->evpipe = open(path, O_RDWR | O_NONBLOCK);
    if ((*subs_p)->evpipe == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "open");
        goto error;
    }

    /* add the new subscription into main SHM */
    if ((err_info = sr_shmmain_conn_add_evpipe(conn, (*subs_p)->evpipe_num))) {
        goto error;
    }

    if (!(opts & SR_SUBSCR_NO_THREAD)) {
        /* set thread_running to non-zero so that thread does not immediately quit */
        ATOMIC_STORE_RELAXED((*subs_p)->thread_running, 1);

        /* start the listen thread */
        ret = pthread_create(&(*subs_p)->tid, NULL, sr_shmsub_listen_thread, *subs_p);
        if (ret) {
            sr_errinfo_new(&err_info, SR_ERR_INTERNAL, NULL, "Creating a new thread failed (%s).", strerror(ret));
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
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    sr_conn_ctx_t *conn;
    sr_subscr_options_t sub_opts;
    sr_mod_change_sub_t *shm_sub;
    sr_mod_t *shm_mod;
    uint16_t i;

    SR_CHECK_ARG_APIRET(!session || SR_IS_EVENT_SESS(session) || !module_name || !callback
            || ((opts & SR_SUBSCR_PASSIVE) && (opts & SR_SUBSCR_ENABLED)) || !subscription, session, err_info);

    if ((opts & SR_SUBSCR_CTX_REUSE) && !*subscription) {
        /* invalid option, remove */
        opts &= ~SR_SUBSCR_CTX_REUSE;
    }

    conn = session->conn;
    /* only these options are relevant outside this function and will be stored */
    sub_opts = opts & (SR_SUBSCR_DONE_ONLY | SR_SUBSCR_PASSIVE | SR_SUBSCR_UPDATE | SR_SUBSCR_UNLOCKED);

    /* is the module name valid? */
    ly_mod = ly_ctx_get_module(conn->ly_ctx, module_name, NULL, 1);
    if (!ly_mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" was not found in sysrepo.", module_name);
        return sr_api_ret(session, err_info);
    }

    /* check write/read perm */
    if ((err_info = sr_perm_check(module_name, (opts & SR_SUBSCR_PASSIVE) ? 0 : 1, NULL))) {
        return sr_api_ret(session, err_info);
    }

    /* call the callback with the current running configuration so that it is properly applied */
    if ((session->ds == SR_DS_RUNNING) && (opts & SR_SUBSCR_ENABLED)) {
        /* do not hold write lock here, would block callback from calling API functions (we are only reading running data anyway) */
        if ((err_info = sr_module_change_subscribe_running_enable(session, ly_mod, xpath, callback, private_data, opts))) {
            return sr_api_ret(session, err_info);
        }
    }

    /* SHM LOCK (writing into subscriptions) */
    if ((err_info = sr_shmmain_lock_remap(conn, SR_LOCK_WRITE, 1, __func__))) {
        return sr_api_ret(session, err_info);
    }

    /* find module */
    shm_mod = sr_shmmain_find_module(&conn->main_shm, conn->ext_shm.addr, module_name, 0);
    SR_CHECK_INT_GOTO(!shm_mod, err_info, error_unlock);

    if (opts & SR_SUBSCR_UPDATE) {
        /* check that there is not already an update subscription with the same priority */
        shm_sub = (sr_mod_change_sub_t *)(conn->ext_shm.addr + shm_mod->change_sub[session->ds].subs);
        for (i = 0; i < shm_mod->change_sub[session->ds].sub_count; ++i) {
            if ((shm_sub[i].opts & SR_SUBSCR_UPDATE) && (shm_sub[i].priority == priority)) {
                sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "There already is an \"update\" subscription on"
                        " module \"%s\" with priority %u for %s DS.", module_name, priority, sr_ds2str(session->ds));
                goto error_unlock;
            }
        }
    }

    if (!(opts & SR_SUBSCR_CTX_REUSE)) {
        /* create a new subscription */
        if ((err_info = sr_subs_new(conn, opts, subscription))) {
            goto error_unlock;
        }
    }

    /* add module subscription into main SHM */
    if ((err_info = sr_shmmod_change_subscription_add(&conn->ext_shm, shm_mod, xpath, session->ds, priority, sub_opts,
            (*subscription)->evpipe_num))) {
        goto error_unlock_unsub;
    }

    /* add subscription into structure and create separate specific SHM segment */
    if ((err_info = sr_sub_change_add(session, module_name, xpath, callback, private_data, priority, sub_opts,
            *subscription))) {
        goto error_unlock_unsub_unmod;
    }

    /* add the subscription into session */
    if ((err_info = sr_ptr_add(&session->ptr_lock, (void ***)&session->subscriptions, &session->subscription_count,
                *subscription))) {
        goto error_unlock_unsub_unmod;
    }

    /* SHM UNLOCK */
    sr_shmmain_unlock(conn, SR_LOCK_WRITE, 1, __func__);

    return sr_api_ret(session, NULL);

error_unlock_unsub_unmod:
    sr_shmmod_change_subscription_del(conn->ext_shm.addr, shm_mod, xpath, session->ds, priority, sub_opts,
            (*subscription)->evpipe_num, 0, NULL);

error_unlock_unsub:
    if (opts & SR_SUBSCR_CTX_REUSE) {
        sr_sub_change_del(module_name, xpath, session->ds, callback, private_data, priority, sub_opts, *subscription);
    } else {
        _sr_unsubscribe(*subscription);
        *subscription = NULL;
    }

error_unlock:
    /* SHM UNLOCK */
    sr_shmmain_unlock(conn, SR_LOCK_WRITE, 1, __func__);

    return sr_api_ret(session, err_info);
}

static int
_sr_get_changes_iter(sr_session_ctx_t *session, const char *xpath, int dup, sr_change_iter_t **iter)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session || !SR_IS_EVENT_SESS(session) || !xpath || !iter, session, err_info);

    if ((session->ev != SR_SUB_EV_ENABLED) && (session->ev != SR_SUB_EV_DONE) && !session->dt[session->ds].diff) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Session without changes.");
        return sr_api_ret(session, err_info);
    }

    *iter = calloc(1, sizeof **iter);
    if (!*iter) {
        SR_ERRINFO_MEM(&err_info);
        return sr_api_ret(session, err_info);
    }

    if (session->dt[session->ds].diff) {
        if (dup) {
            (*iter)->diff = lyd_dup_withsiblings(session->dt[session->ds].diff, LYD_DUP_OPT_RECURSIVE);
            SR_CHECK_MEM_GOTO(!(*iter)->diff, err_info, error);
        }
        (*iter)->set = lyd_find_path(session->dt[session->ds].diff, xpath);
    } else {
        (*iter)->set = ly_set_new();
    }
    SR_CHECK_MEM_GOTO(!(*iter)->set, err_info, error);
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
 * @brief Transform libyang node into sysrepo value.
 *
 * @param[in] node libyang node.
 * @param[in] value_str Optional value to override.
 * @param[in] keys_predicate Optional keys predicate to override.
 * @param[out] sr_val_p Transformed sysrepo value.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lyd_node2sr_val(const struct lyd_node *node, const char *value_str, const char *keys_predicate, sr_val_t **sr_val_p)
{
    char *ptr;
    sr_error_info_t *err_info = NULL;
    uint32_t start, end;
    sr_val_t *sr_val;
    LY_DATA_TYPE value_type;
    const struct lyd_node_leaf_list *leaf;
    struct lys_type *type;
    struct lys_node_list *slist;

    sr_val = calloc(1, sizeof *sr_val);
    SR_CHECK_MEM_GOTO(!sr_val, err_info, error);

    sr_val->xpath = lyd_path(node);
    SR_CHECK_MEM_GOTO(!sr_val->xpath, err_info, error);

    switch (node->schema->nodetype) {
    case LYS_LIST:
        /* fix the xpath if needed */
        if (keys_predicate) {
            slist = (struct lys_node_list *)node->schema;

            end = slist->keys_size;
            start = strlen(sr_val->xpath);
            do {
                --end;

                /* going backwards, skip the value */
                start -= 2;
                assert(sr_val->xpath[start + 1] == ']');
                for (ptr = sr_val->xpath + start - 1; ptr[0] != sr_val->xpath[start]; --ptr) {
                    SR_CHECK_INT_GOTO(ptr == sr_val->xpath, err_info, error);
                }
                start = (ptr - sr_val->xpath) - 2;
                assert(sr_val->xpath[start + 1] == '=');
                /* skip the key name */
                start -= strlen(slist->keys[end]->name);
                assert(sr_val->xpath[start] == '[');
            } while (end);
            assert(!strncmp((sr_val->xpath + start) - strlen(slist->name), slist->name, strlen(slist->name)));
            end = strlen(sr_val->xpath);

            /* enlarge string if needed */
            if (strlen(keys_predicate) > end - start) {
                /* original length + the difference + ending 0 */
                sr_val->xpath = sr_realloc(sr_val->xpath, end + (strlen(keys_predicate) - (end - start)) + 1);
                SR_CHECK_MEM_GOTO(!sr_val->xpath, err_info, error);
            }

            /* replace the predicates */
            strcpy(sr_val->xpath + start, keys_predicate);
        }
        sr_val->type = SR_LIST_T;
        break;
    case LYS_CONTAINER:
        if (((struct lys_node_container *)node->schema)->presence) {
            sr_val->type = SR_CONTAINER_PRESENCE_T;
        } else {
            sr_val->type = SR_CONTAINER_T;
        }
        break;
    case LYS_NOTIF:
        sr_val->type = SR_NOTIFICATION_T;
        break;
    case LYS_ANYXML:
        sr_val->type = SR_ANYXML_T;
        break;
    case LYS_ANYDATA:
        sr_val->type = SR_ANYDATA_T;
        break;
    case LYS_LEAFLIST:
        /* fix the xpath, we do not want the value in the predicate */
        end = strlen(sr_val->xpath) - 1;
        assert(((sr_val->xpath[end - 1] == '\'') || (sr_val->xpath[end - 1] == '\"')) && (sr_val->xpath[end] == ']'));

        for (ptr = sr_val->xpath + end - 2; ptr[0] != sr_val->xpath[end - 1]; --ptr) {
            SR_CHECK_INT_GOTO(ptr == sr_val->xpath, err_info, error);
        }
        assert((ptr[-1] == '=') && (ptr[-2] == '.') && (ptr[-3] == '['));
        ptr[-3] = '\0';

        /* fallthrough */
    case LYS_LEAF:
        /* find the actual leaf */
        leaf = (const struct lyd_node_leaf_list *)node;
        while (leaf->value_type == LY_TYPE_LEAFREF) {
            leaf = (const struct lyd_node_leaf_list *)leaf->value.leafref;
        }

        if (value_str) {
            /* learn value_str value_type */
            SR_CHECK_INT_GOTO(lyd_value_type(node->schema, value_str, &type), err_info, error);
            value_type = type->base;
        } else {
            /* use attributes from the leaf */
            value_str = leaf->value_str;
            value_type = leaf->value_type;
        }

        switch (value_type) {
        case LY_TYPE_BINARY:
            sr_val->type = SR_BINARY_T;
            sr_val->data.binary_val = strdup(value_str);
            break;
        case LY_TYPE_BITS:
            sr_val->type = SR_BITS_T;
            sr_val->data.bits_val = strdup(value_str);
            break;
        case LY_TYPE_BOOL:
            sr_val->type = SR_BOOL_T;
            if (!strcmp(value_str, "true")) {
                sr_val->data.bool_val = true;
            } else {
                sr_val->data.bool_val = false;
            }
            break;
        case LY_TYPE_DEC64:
            sr_val->type = SR_DECIMAL64_T;
            sr_val->data.decimal64_val = strtod(value_str, &ptr);
            if (ptr[0]) {
                sr_errinfo_new(&err_info, SR_ERR_INTERNAL, NULL, "Conversion of \"%s\" to double failed (%s).",
                        value_str, strerror(errno));
                goto error;
            }
            break;
        case LY_TYPE_EMPTY:
            sr_val->type = SR_LEAF_EMPTY_T;
            break;
        case LY_TYPE_ENUM:
            sr_val->type = SR_ENUM_T;
            sr_val->data.enum_val = strdup(value_str);
            break;
        case LY_TYPE_IDENT:
            sr_val->type = SR_IDENTITYREF_T;
            sr_val->data.identityref_val = strdup(value_str);
            break;
        case LY_TYPE_INST:
            sr_val->type = SR_INSTANCEID_T;
            sr_val->data.instanceid_val = strdup(value_str);
            break;
        case LY_TYPE_STRING:
            sr_val->type = SR_STRING_T;
            sr_val->data.string_val = strdup(value_str);
            break;
        case LY_TYPE_INT8:
            sr_val->type = SR_INT8_T;
            sr_val->data.int8_val = strtoll(value_str, &ptr, 10);
            SR_CHECK_INT_GOTO(ptr[0], err_info, error);
            break;
        case LY_TYPE_INT16:
            sr_val->type = SR_INT16_T;
            sr_val->data.int16_val = strtoll(value_str, &ptr, 10);
            SR_CHECK_INT_GOTO(ptr[0], err_info, error);
            break;
        case LY_TYPE_INT32:
            sr_val->type = SR_INT32_T;
            sr_val->data.int32_val = strtoll(value_str, &ptr, 10);
            SR_CHECK_INT_GOTO(ptr[0], err_info, error);
            break;
        case LY_TYPE_INT64:
            sr_val->type = SR_INT64_T;
            sr_val->data.int64_val = strtoll(value_str, &ptr, 10);
            SR_CHECK_INT_GOTO(ptr[0], err_info, error);
            break;
        case LY_TYPE_UINT8:
            sr_val->type = SR_UINT8_T;
            sr_val->data.uint8_val = strtoull(value_str, &ptr, 10);
            SR_CHECK_INT_GOTO(ptr[0], err_info, error);
            break;
        case LY_TYPE_UINT16:
            sr_val->type = SR_UINT16_T;
            sr_val->data.uint16_val = strtoull(value_str, &ptr, 10);
            SR_CHECK_INT_GOTO(ptr[0], err_info, error);
            break;
        case LY_TYPE_UINT32:
            sr_val->type = SR_UINT32_T;
            sr_val->data.uint32_val = strtoull(value_str, &ptr, 10);
            SR_CHECK_INT_GOTO(ptr[0], err_info, error);
            break;
        case LY_TYPE_UINT64:
            sr_val->type = SR_UINT64_T;
            sr_val->data.uint64_val = strtoull(value_str, &ptr, 10);
            SR_CHECK_INT_GOTO(ptr[0], err_info, error);
            break;
        default:
            SR_ERRINFO_INT(&err_info);
            goto error;
        }
        break;
    default:
        SR_ERRINFO_INT(&err_info);
            goto error;
    }

    sr_val->dflt = node->dflt;
    *sr_val_p = sr_val;
    return NULL;

error:
    if (sr_val) {
        free(sr_val->xpath);
    }
    free(sr_val);
    return err_info;
}

API int
sr_get_change_next(sr_session_ctx_t *session, sr_change_iter_t *iter, sr_change_oper_t *operation,
        sr_val_t **old_value, sr_val_t **new_value)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_attr *attr, *attr2;
    struct lyd_node *node;
    const char *attr_name;
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
        if ((err_info = sr_lyd_node2sr_val(node, NULL, NULL, old_value))) {
            return sr_api_ret(session, err_info);
        }
        *new_value = NULL;
        break;
    case SR_OP_MODIFIED:
        /* "orig-value" attribute contains the previous value */
        for (attr = node->attr;
             attr && (strcmp(attr->annotation->module->name, SR_YANG_MOD) || strcmp(attr->name, "orig-value"));
             attr = attr->next);
        if (!attr) {
            SR_ERRINFO_INT(&err_info);
            return sr_api_ret(session, err_info);
        }

        /* "orig-dflt" is present only if the previous value was default */
        for (attr2 = node->attr;
             attr2 && (strcmp(attr2->annotation->module->name, SR_YANG_MOD) || strcmp(attr2->name, "orig-dflt"));
             attr2 = attr2->next);

        if ((err_info = sr_lyd_node2sr_val(node, attr->value_str, NULL, old_value))) {
            return sr_api_ret(session, err_info);
        }
        if (attr2) {
            (*old_value)->dflt = 1;
        } else {
            (*old_value)->dflt = 0;
        }
        if ((err_info = sr_lyd_node2sr_val(node, NULL, NULL, new_value))) {
            return sr_api_ret(session, err_info);
        }
        break;
    case SR_OP_CREATED:
        if (!sr_ly_is_userord(node)) {
            /* not a user-ordered list, so the operation is a simple creation */
            *old_value = NULL;
            if ((err_info = sr_lyd_node2sr_val(node, NULL, NULL, new_value))) {
                return sr_api_ret(session, err_info);
            }
            break;
        }
        /* fallthrough */
    case SR_OP_MOVED:
        if (node->schema->nodetype == LYS_LEAFLIST) {
            attr_name = "value";
        } else {
            assert(node->schema->nodetype == LYS_LIST);
            attr_name = "key";
        }
        /* attribute contains the value of the node before in the order */
        for (attr = node->attr;
             attr && (strcmp(attr->annotation->module->name, "yang") || strcmp(attr->name, attr_name));
             attr = attr->next);
        if (!attr) {
            SR_ERRINFO_INT(&err_info);
            return sr_api_ret(session, err_info);
        }

        if (attr->value_str[0]) {
            if (node->schema->nodetype == LYS_LEAFLIST) {
                err_info = sr_lyd_node2sr_val(node, attr->value_str, NULL, old_value);
            } else {
                err_info = sr_lyd_node2sr_val(node, NULL, attr->value_str, old_value);
            }
            if (err_info) {
                return sr_api_ret(session, err_info);
            }
        } else {
            /* inserted as the first item */
            *old_value = NULL;
        }
        if ((err_info = sr_lyd_node2sr_val(node, NULL, NULL, new_value))) {
            return sr_api_ret(session, err_info);
        }
        break;
    }

    *operation = op;
    return sr_api_ret(session, NULL);
}

API int
sr_get_change_tree_next(sr_session_ctx_t *session, sr_change_iter_t *iter, sr_change_oper_t *operation,
        const struct lyd_node **node, const char **prev_value, const char **prev_list, bool *prev_dflt)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_attr *attr, *attr2;
    const char *attr_name;

    SR_CHECK_ARG_APIRET(!session || !iter || !operation || !node || !prev_value || !prev_list || !prev_dflt, session, err_info);

    *prev_value = NULL;
    *prev_list = NULL;
    *prev_dflt = 0;

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
        /* "orig-value" attribute contains the previous value */
        for (attr = (*node)->attr;
             attr && (strcmp(attr->annotation->module->name, SR_YANG_MOD) || strcmp(attr->name, "orig-value"));
             attr = attr->next);
        if (!attr) {
            SR_ERRINFO_INT(&err_info);
            return sr_api_ret(session, err_info);
        }
        *prev_value = attr->value_str;

        /* "orig-dflt" is present only if the previous value was default */
        for (attr2 = (*node)->attr;
             attr2 && (strcmp(attr2->annotation->module->name, SR_YANG_MOD) || strcmp(attr2->name, "orig-dflt"));
             attr2 = attr2->next);
        if (attr2) {
            *prev_dflt = 1;
        }
        break;
    case SR_OP_CREATED:
        if (!sr_ly_is_userord(*node)) {
            /* nothing to do */
            break;
        }
        /* fallthrough */
    case SR_OP_MOVED:
        if ((*node)->schema->nodetype == LYS_LEAFLIST) {
            attr_name = "value";
        } else {
            assert((*node)->schema->nodetype == LYS_LIST);
            attr_name = "key";
        }

        /* attribute contains the value (predicates) of the preceding instance in the order */
        for (attr = (*node)->attr;
             attr && (strcmp(attr->annotation->module->name, "yang") || strcmp(attr->name, attr_name));
             attr = attr->next);
        if (!attr) {
            SR_ERRINFO_INT(&err_info);
            return sr_api_ret(session, err_info);
        }
        if ((*node)->schema->nodetype == LYS_LEAFLIST) {
            *prev_value = attr->value_str;
        } else {
            assert((*node)->schema->nodetype == LYS_LIST);
            *prev_list = attr->value_str;
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

    if (iter->diff) {
        lyd_free_withsiblings(iter->diff);
    }
    ly_set_free(iter->set);
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
    sr_error_info_t *err_info = NULL;
    char *module_name = NULL, *op_path = NULL;
    const struct lys_node *op;
    const struct lys_module *ly_mod;
    sr_conn_ctx_t *conn;
    sr_subscr_options_t sub_opts;
    sr_rpc_t *shm_rpc;
    off_t shm_rpc_off;
    int last_removed;

    SR_CHECK_ARG_APIRET(!session || SR_IS_EVENT_SESS(session) || !xpath || (!callback && !tree_callback) || !subscription,
            session, err_info);

    if ((opts & SR_SUBSCR_CTX_REUSE) && !*subscription) {
        /* invalid option, remove */
        opts &= ~SR_SUBSCR_CTX_REUSE;
    }

    conn = session->conn;
    /* only these options are relevant outside this function and will be stored */
    sub_opts = opts & SR_SUBSCR_UNLOCKED;

    module_name = sr_get_first_ns(xpath);
    if (!module_name) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Invalid xpath \"%s\".", xpath);
        goto error;
    }

    /* is the module name valid? */
    ly_mod = ly_ctx_get_module(conn->ly_ctx, module_name, NULL, 1);
    if (!ly_mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" was not found in sysrepo.", module_name);
        goto error;
    }

    /* check write perm */
    if ((err_info = sr_perm_check(module_name, 1, NULL))) {
        goto error;
    }

    /* is the xpath valid? */
    if ((err_info = sr_get_trim_predicates(xpath, &op_path))) {
        goto error;
    }

    if (!(op = ly_ctx_get_node(conn->ly_ctx, NULL, op_path, 0))) {
        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
        goto error;
    }
    if (!(op->nodetype & (LYS_RPC | LYS_ACTION))) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Path \"%s\" does not identify an RPC nor an action.", op_path);
        goto error;
    }

    /* SHM LOCK (writing into subscriptions) */
    if ((err_info = sr_shmmain_lock_remap(conn, SR_LOCK_WRITE, 1, __func__))) {
        goto error;
    }

    if (!(opts & SR_SUBSCR_CTX_REUSE)) {
        /* create a new subscription */
        if ((err_info = sr_subs_new(conn, opts, subscription))) {
            goto error_unlock;
        }
    }

    /* find RPC struct or add a new one */
    shm_rpc = sr_shmmain_find_rpc((sr_main_shm_t *)conn->main_shm.addr, conn->ext_shm.addr, op_path, 0);
    if (!shm_rpc && (err_info = sr_shmmain_add_rpc(conn, op_path, &shm_rpc))) {
        goto error_unlock_unsub;
    }
    shm_rpc_off = ((char *)shm_rpc) - conn->ext_shm.addr;

    /* add RPC/action subscription into main SHM (which may be remapped) */
    if ((err_info = sr_shmmain_rpc_subscription_add(&conn->ext_shm, shm_rpc_off, xpath, priority, sub_opts,
                (*subscription)->evpipe_num))) {
        goto error_unlock_unsub;
    }
    shm_rpc = (sr_rpc_t *)(conn->ext_shm.addr + shm_rpc_off);

    /* add subscription into structure and create separate specific SHM segment */
    if ((err_info = sr_sub_rpc_add(session, op_path, xpath, callback, tree_callback, private_data, priority, *subscription))) {
        goto error_unlock_unsub_unrpc;
    }

    /* add the subscription into session */
    if ((err_info = sr_ptr_add(&session->ptr_lock, (void ***)&session->subscriptions, &session->subscription_count,
                *subscription))) {
        goto error_unlock_unsub_unrpc;
    }

    /* SHM UNLOCK */
    sr_shmmain_unlock(conn, SR_LOCK_WRITE, 1, __func__);

    free(module_name);
    free(op_path);
    return sr_api_ret(session, NULL);

error_unlock_unsub_unrpc:
    sr_shmmain_rpc_subscription_del(conn->ext_shm.addr, shm_rpc, xpath, priority, (*subscription)->evpipe_num, 0, &last_removed);
    if (last_removed) {
        sr_shmmain_del_rpc((sr_main_shm_t *)conn->main_shm.addr, conn->ext_shm.addr, NULL, shm_rpc->op_path);
    }

error_unlock_unsub:
    if (opts & SR_SUBSCR_CTX_REUSE) {
        sr_sub_rpc_del(op_path, xpath, callback, tree_callback, private_data, priority, *subscription);
    } else {
        _sr_unsubscribe(*subscription);
        *subscription = NULL;
    }

error_unlock:
    /* SHM UNLOCK */
    sr_shmmain_unlock(conn, SR_LOCK_WRITE, 1, __func__);

error:
    free(module_name);
    free(op_path);
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
    struct lyd_node *input_tree = NULL, *output_tree = NULL, *next, *elem;
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
        lyd_free_withsiblings(input_tree);
        return ret;
    }

    /* transform data tree into an output */
    assert(output_tree && (output_tree->schema->nodetype & (LYS_RPC | LYS_ACTION)));
    *output_cnt = 0;
    *output = NULL;
    LY_TREE_DFS_BEGIN(output_tree, next, elem) {
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

        LY_TREE_DFS_END(output_tree, next, elem);
    }

    /* success */

cleanup:
    lyd_free_withsiblings(input_tree);
    lyd_free_withsiblings(output_tree);
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
    struct lyd_node *input_op;
    sr_mod_data_dep_t *shm_deps;
    uint16_t shm_dep_count;
    char *op_path = NULL, *str;
    uint32_t event_id = 0;

    SR_CHECK_ARG_APIRET(!session || !input || !output, session, err_info);
    if (session->conn->ly_ctx != input->schema->module->ctx) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Data trees must be created using the session connection libyang context.");
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
        for (input_op = input; input->parent; input = input->parent);
        break;
    case LYS_RPC:
        input_op = input;
        break;
    case LYS_CONTAINER:
    case LYS_LIST:
        /* find the action */
        input_op = input;
        if ((err_info = sr_ly_find_last_parent(&input_op, LYS_ACTION))) {
            return sr_api_ret(session, err_info);
        }
        if (input_op->schema->nodetype == LYS_ACTION) {
            break;
        }
        /* fallthrough */
    default:
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Provided input is not a valid RPC or action invocation.");
        return sr_api_ret(session, err_info);
    }

    /* SHM LOCK (reading subscriptions) */
    if ((err_info = sr_shmmain_lock_remap(session->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    /* check read perm */
    if ((err_info = sr_perm_check(lyd_node_module(input)->name, 0, NULL))) {
        goto cleanup_shm_unlock;
    }

    /* get operation path (without predicates) */
    str = lyd_path(input_op);
    SR_CHECK_INT_GOTO(!str, err_info, cleanup_shm_unlock);
    err_info = sr_get_trim_predicates(str, &op_path);
    free(str);
    if (err_info) {
        goto cleanup_shm_unlock;
    }

    /* collect all required modules for input validation (including checking that the nested action
     * can be invoked meaning its parent data node exists) */
    if ((err_info = sr_shmmod_modinfo_collect_op(&mod_info, op_path, input_op, 0, &shm_deps, &shm_dep_count))) {
        goto cleanup_shm_unlock;
    }

    /* MODULES READ LOCK */
    if ((err_info = sr_shmmod_modinfo_rdlock(&mod_info, 0, session->sid))) {
        goto cleanup_mods_unlock;
    }

    /* load all input dependency modules data */
    if ((err_info = sr_modinfo_data_load(&mod_info, MOD_INFO_TYPE_MASK, 1, &session->sid, NULL, SR_OPER_CB_TIMEOUT, 0,
            &cb_err_info)) || cb_err_info) {
        goto cleanup_mods_unlock;
    }

    /* validate the operation, must be valid only at the time of execution */
    if ((err_info = sr_modinfo_op_validate(&mod_info, input_op, shm_deps, shm_dep_count, 0, &session->sid,
            SR_OPER_CB_TIMEOUT, &cb_err_info)) || cb_err_info) {
        goto cleanup_mods_unlock;
    }

    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info, 0);

    sr_modinfo_free(&mod_info);
    SR_MODINFO_INIT(mod_info, session->conn, SR_DS_OPERATIONAL, SR_DS_RUNNING);

    /* publish RPC in an event and wait for a reply from the last subscriber */
    if ((err_info = sr_shmsub_rpc_notify(session->conn, op_path, input, session->sid, timeout_ms, &event_id, output,
            &cb_err_info))) {
        goto cleanup_shm_unlock;
    }

    if (cb_err_info) {
        /* "rpc" event failed, publish "abort" event and finish */
        err_info = sr_shmsub_rpc_notify_abort(session->conn, op_path, input, session->sid, event_id);
        goto cleanup_shm_unlock;
    }

    /* find operation */
    if ((err_info = sr_ly_find_last_parent(output, LYS_RPC | LYS_ACTION))) {
        goto cleanup_shm_unlock;
    }

    /* collect all required modules for output validation */
    if ((err_info = sr_shmmod_modinfo_collect_op(&mod_info, op_path, *output, 1, &shm_deps, &shm_dep_count))) {
        goto cleanup_shm_unlock;
    }

    /* MODULES READ LOCK */
    if ((err_info = sr_shmmod_modinfo_rdlock(&mod_info, 0, session->sid))) {
        goto cleanup_mods_unlock;
    }

    /* load all output dependency modules data */
    if ((err_info = sr_modinfo_data_load(&mod_info, MOD_INFO_TYPE_MASK, 1, &session->sid, NULL, SR_OPER_CB_TIMEOUT, 0,
            &cb_err_info)) || cb_err_info) {
        goto cleanup_mods_unlock;
    }

    /* validate the operation */
    if ((err_info = sr_modinfo_op_validate(&mod_info, *output, shm_deps, shm_dep_count, 1, &session->sid,
            SR_OPER_CB_TIMEOUT, &cb_err_info))) {
        goto cleanup_mods_unlock;
    }
    if (cb_err_info) {
        goto cleanup_mods_unlock;
    }

    /* success */

cleanup_mods_unlock:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info, 0);

cleanup_shm_unlock:
    /* SHM UNLOCK */
    sr_shmmain_unlock(session->conn, SR_LOCK_READ, 0, __func__);

    free(op_path);
    sr_modinfo_free(&mod_info);
    if (cb_err_info) {
        /* return callback error if some was generated */
        sr_errinfo_merge(&err_info, cb_err_info);
        err_info->err_code = SR_ERR_CALLBACK_FAILED;
    }
    if (err_info) {
        /* free any received output in case of an error */
        lyd_free_withsiblings(*output);
        *output = NULL;
    }
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
_sr_event_notif_subscribe(sr_session_ctx_t *session, const char *mod_name, const char *xpath, time_t start_time,
        time_t stop_time, sr_event_notif_cb callback, sr_event_notif_tree_cb tree_callback, void *private_data,
        sr_subscr_options_t opts, sr_subscription_ctx_t **subscription)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set;
    const struct lys_node *ctx_node;
    time_t cur_ts = time(NULL);
    const struct lys_module *ly_mod;
    sr_conn_ctx_t *conn;
    uint32_t i;
    sr_mod_t *shm_mod;

    SR_CHECK_ARG_APIRET(!session || SR_IS_EVENT_SESS(session) || !mod_name || (start_time && (start_time > cur_ts)) || (stop_time
            && (!start_time || (stop_time < start_time))) || (!callback && !tree_callback) || !subscription, session, err_info);

    /* is the module name valid? */
    ly_mod = ly_ctx_get_module(session->conn->ly_ctx, mod_name, NULL, 1);
    if (!ly_mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" was not found in sysrepo.", mod_name);
        return sr_api_ret(session, err_info);
    }

    /* check write perm */
    if ((err_info = sr_perm_check(mod_name, 1, NULL))) {
        return sr_api_ret(session, err_info);
    }

    if ((opts & SR_SUBSCR_CTX_REUSE) && !*subscription) {
        /* invalid option, remove */
        opts &= ~SR_SUBSCR_CTX_REUSE;
    }

    conn = session->conn;

    /* is the xpath valid, if any? */
    if (xpath) {
        ctx_node = lys_getnext(NULL, NULL, ly_mod, 0);
        if (!ctx_node) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" does not define any notifications.", ly_mod->name);
            return sr_api_ret(session, err_info);
        }

        set = lys_xpath_atomize(ctx_node, LYXP_NODE_ELEM, xpath, 0);
    } else {
        set = lys_find_path(ly_mod, NULL, "//.");
    }
    if (!set) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        return sr_api_ret(session, err_info);
    }

    /* there must be some notifications selected */
    for (i = 0; i < set->number; ++i) {
        if (set->set.s[i]->nodetype == LYS_NOTIF) {
            break;
        }
    }
    if (i == set->number) {
        if (xpath) {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "XPath \"%s\" does not select any notifications.", xpath);
        } else {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" does not define any notifications.", ly_mod->name);
        }
        ly_set_free(set);
        return sr_api_ret(session, err_info);
    }
    ly_set_free(set);

    /* SHM LOCK (writing into subscriptions) */
    if ((err_info = sr_shmmain_lock_remap(conn, SR_LOCK_WRITE, 1, __func__))) {
        return sr_api_ret(session, err_info);
    }

    if (!(opts & SR_SUBSCR_CTX_REUSE)) {
        /* create a new subscription */
        if ((err_info = sr_subs_new(conn, opts, subscription))) {
            goto error_unlock;
        }
    }

    /* find module */
    shm_mod = sr_shmmain_find_module(&conn->main_shm, conn->ext_shm.addr, ly_mod->name, 0);
    SR_CHECK_INT_GOTO(!shm_mod, err_info, error_unlock_unsub);

    if (!start_time) {
        /* add notification subscription into main SHM now if replay was not requested */
        if ((err_info = sr_shmmod_notif_subscription_add(&conn->ext_shm, shm_mod, (*subscription)->evpipe_num))) {
            goto error_unlock_unsub;
        }
    }

    /* add subscription into structure and create separate specific SHM segment */
    if ((err_info = sr_sub_notif_add(session, ly_mod->name, xpath, start_time, stop_time, callback, tree_callback,
                private_data, *subscription))) {
        goto error_unlock_unsub_unmod;
    }

    if (start_time) {
        /* notify subscription there are already some events (replay needs to be performed) */
        if ((err_info = sr_shmsub_notify_evpipe((*subscription)->evpipe_num))) {
            goto error_unlock_unsub;
        }
    }

    /* add the subscription into session */
    if ((err_info = sr_ptr_add(&session->ptr_lock, (void ***)&session->subscriptions, &session->subscription_count,
                *subscription))) {
        goto error_unlock_unsub_unmod;
    }

    /* SHM UNLOCK */
    sr_shmmain_unlock(conn, SR_LOCK_WRITE, 1, __func__);

    return sr_api_ret(session, NULL);

error_unlock_unsub_unmod:
    if (!start_time) {
        sr_shmmod_notif_subscription_del(conn->ext_shm.addr, shm_mod, (*subscription)->evpipe_num, NULL);
    }

error_unlock_unsub:
    if (opts & SR_SUBSCR_CTX_REUSE) {
        sr_sub_notif_del(ly_mod->name, xpath, start_time, stop_time, callback, tree_callback, private_data, *subscription, 0);
    } else {
        _sr_unsubscribe(*subscription);
        *subscription = NULL;
    }

error_unlock:
    /* SHM UNLOCK */
    sr_shmmain_unlock(conn, SR_LOCK_WRITE, 1, __func__);

    return sr_api_ret(session, err_info);
}

API int
sr_event_notif_subscribe(sr_session_ctx_t *session, const char *module_name, const char *xpath, time_t start_time,
        time_t stop_time, sr_event_notif_cb callback, void *private_data, sr_subscr_options_t opts,
        sr_subscription_ctx_t **subscription)
{
    return _sr_event_notif_subscribe(session, module_name, xpath, start_time, stop_time, callback, NULL, private_data,
            opts, subscription);
}

API int
sr_event_notif_subscribe_tree(sr_session_ctx_t *session, const char *module_name, const char *xpath, time_t start_time,
        time_t stop_time, sr_event_notif_tree_cb callback, void *private_data, sr_subscr_options_t opts,
        sr_subscription_ctx_t **subscription)
{
    return _sr_event_notif_subscribe(session, module_name, xpath, start_time, stop_time, NULL, callback, private_data,
            opts, subscription);
}

API int
sr_event_notif_send(sr_session_ctx_t *session, const char *path, const sr_val_t *values, const size_t values_cnt)
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
    if ((ret = sr_event_notif_send_tree(session, notif_tree)) != SR_ERR_OK) {
        lyd_free_withsiblings(notif_tree);
        return ret;
    }

    /* success */

cleanup:
    lyd_free_withsiblings(notif_tree);
    return sr_api_ret(session, err_info);
}

API int
sr_event_notif_send_tree(sr_session_ctx_t *session, struct lyd_node *notif)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL, *tmp_err_info = NULL;
    struct sr_mod_info_s mod_info;
    struct lyd_node *notif_op;
    sr_mod_data_dep_t *shm_deps;
    sr_mod_t *shm_mod;
    time_t notif_ts;
    uint16_t shm_dep_count;
    sr_mod_notif_sub_t *notif_subs;
    uint32_t notif_sub_count;
    char *xpath = NULL;

    SR_CHECK_ARG_APIRET(!session || !notif, session, err_info);
    if (session->conn->ly_ctx != notif->schema->module->ctx) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Data trees must be created using the session connection libyang context.");
        return sr_api_ret(session, err_info);
    }

    SR_MODINFO_INIT(mod_info, session->conn, SR_DS_OPERATIONAL, SR_DS_RUNNING);

    /* remember when the notification was generated */
    notif_ts = time(NULL);

    /* check notif data tree */
    switch (notif->schema->nodetype) {
    case LYS_NOTIF:
        for (notif_op = notif; notif->parent; notif = notif->parent);
        break;
    case LYS_CONTAINER:
    case LYS_LIST:
        /* find the notification */
        notif_op = notif;
        if ((err_info = sr_ly_find_last_parent(&notif_op, LYS_NOTIF))) {
            return sr_api_ret(session, err_info);
        }
        if (notif_op->schema->nodetype == LYS_NOTIF) {
            break;
        }
        /* fallthrough */
    default:
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Provided tree is not a valid notification invocation.");
        return sr_api_ret(session, err_info);
    }

    /* SHM LOCK (reading subscriptions) */
    if ((err_info = sr_shmmain_lock_remap(session->conn, SR_LOCK_READ, 0, __func__))) {
        return sr_api_ret(session, err_info);
    }

    /* check write/read perm */
    shm_mod = sr_shmmain_find_module(&session->conn->main_shm, session->conn->ext_shm.addr, lyd_node_module(notif)->name, 0);
    SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup_shm_unlock);
    if ((err_info = sr_perm_check(lyd_node_module(notif)->name, (shm_mod->flags & SR_MOD_REPLAY_SUPPORT) ? 1 : 0, NULL))) {
        goto cleanup_shm_unlock;
    }

    /* collect all required modules for validation (including checking that the nested notification
     * can be invoked meaning its parent data node exists) */
    xpath = lys_data_path(notif_op->schema);
    SR_CHECK_MEM_GOTO(!xpath, err_info, cleanup_shm_unlock);
    if ((err_info = sr_shmmod_modinfo_collect_op(&mod_info, xpath, notif_op, 0, &shm_deps, &shm_dep_count))) {
        goto cleanup_shm_unlock;
    }

    /* MODULES READ LOCK */
    if ((err_info = sr_shmmod_modinfo_rdlock(&mod_info, 0, session->sid))) {
        goto cleanup_mods_unlock;
    }

    /* load all input dependency modules data */
    if ((err_info = sr_modinfo_data_load(&mod_info, MOD_INFO_TYPE_MASK, 1, &session->sid, NULL, SR_OPER_CB_TIMEOUT, 0,
            &cb_err_info)) || cb_err_info) {
        goto cleanup_mods_unlock;
    }

    /* validate the operation */
    if ((err_info = sr_modinfo_op_validate(&mod_info, notif_op, shm_deps, shm_dep_count, 0, &session->sid,
            SR_OPER_CB_TIMEOUT, &cb_err_info))) {
        goto cleanup_mods_unlock;
    }
    if (cb_err_info) {
        goto cleanup_mods_unlock;
    }

    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info, 0);

    /* store the notification for a replay, we continue on failure */
    err_info = sr_replay_store(session, notif, notif_ts);

    /* check that there is a subscriber */
    if ((tmp_err_info = sr_notif_find_subscriber(session->conn, lyd_node_module(notif)->name, &notif_subs, &notif_sub_count))) {
        goto cleanup_shm_unlock;
    }

    if (notif_sub_count) {
        /* publish notif in an event, do not wait for subscribers */
        if ((tmp_err_info = sr_shmsub_notif_notify(notif, notif_ts, session->sid, (uint32_t *)notif_subs, notif_sub_count))) {
            goto cleanup_shm_unlock;
        }
    } else {
        SR_LOG_INF("There are no subscribers for \"%s\" notifications.", lyd_node_module(notif)->name);
    }

    /* success */
    goto cleanup_shm_unlock;

cleanup_mods_unlock:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info, 0);

cleanup_shm_unlock:
    /* SHM UNLOCK */
    sr_shmmain_unlock(session->conn, SR_LOCK_READ, 0, __func__);

    free(xpath);
    sr_modinfo_free(&mod_info);
    if (tmp_err_info) {
        sr_errinfo_merge(&err_info, tmp_err_info);
    }
    if (cb_err_info) {
        /* return callback error if some was generated */
        sr_errinfo_merge(&err_info, cb_err_info);
        err_info->err_code = SR_ERR_CALLBACK_FAILED;
    }
    return sr_api_ret(session, err_info);
}

/**
 * @brief Learn what kinds (config) of nodes are provided by an operational subscription
 * to determine its type.
 *
 * @param[in] ly_mod Module with the nodes.
 * @param[in] path Subscription path.
 * @param[out] sub_type Learned subscription type.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_oper_sub_get_type(const struct lys_module *ly_mod, const char *path, sr_mod_oper_sub_type_t *sub_type)
{
    sr_error_info_t *err_info = NULL;
    char *schema_path;
    struct lys_node *next, *elem;
    struct ly_set *set = NULL;
    uint16_t i;

    schema_path = ly_path_data2schema(ly_mod->ctx, path);
    set = lys_find_path(ly_mod, NULL, schema_path);
    free(schema_path);
    if (!set) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        goto cleanup;
    } else if (!set->number) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "XPath \"%s\" does not point to any nodes.", path);
        goto cleanup;
    }

    *sub_type = SR_OPER_SUB_NONE;
    for (i = 0; i < set->number; ++i) {
        LY_TREE_DFS_BEGIN(set->set.s[i], next, elem) {
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
            case LYS_USES:
                /* go into */
                break;
            case LYS_NOTIF:
            case LYS_RPC:
            case LYS_ACTION:
            case LYS_GROUPING:
                /* skip */
                goto next_sibling;
            default:
                /* should not be reachable */
                SR_ERRINFO_INT(&err_info);
                goto cleanup;
            }

            if ((*sub_type == SR_OPER_SUB_STATE) || (*sub_type == SR_OPER_SUB_MIXED)) {
                /* redundant to look recursively */
                break;
            }

            /* LY_TREE_DFS_END(set->set.s[i], next, elem); */
            if (elem->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYDATA)) {
                next = NULL;
            } else {
                next = elem->child;
            }

            if (!next) {
next_sibling:
                /* no children */
                if (elem == set->set.s[i]) {
                    /* we are done, (START) has no children */
                    break;
                }
                /* try siblings */
                next = elem->next;
            }
            while (!next) {
                /* parent is already processed, go to its sibling */
                if (elem->parent->nodetype == LYS_AUGMENT) {
                    elem = elem->parent->prev;
                } else {
                    elem = elem->parent;
                }
                /* no siblings, go back through parents */
                if (lys_parent(elem) == lys_parent(set->set.s[i])) {
                    /* we are done, no next element to process */
                    break;
                }
                next = elem->next;
            }
        }

        if (*sub_type == SR_OPER_SUB_MIXED) {
            /* we found both config type nodes, nothing more to look for */
            break;
        }
    }

cleanup:
    ly_set_free(set);
    return err_info;
}

API int
sr_oper_get_items_subscribe(sr_session_ctx_t *session, const char *module_name, const char *path,
        sr_oper_get_items_cb callback, void *private_data, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription)
{
    sr_error_info_t *err_info = NULL;
    sr_conn_ctx_t *conn;
    const struct lys_module *ly_mod;
    sr_mod_oper_sub_type_t sub_type;
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

    ly_mod = ly_ctx_get_module(conn->ly_ctx, module_name, NULL, 1);
    if (!ly_mod) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Module \"%s\" was not found in sysrepo.", module_name);
        return sr_api_ret(session, err_info);
    }

    /* check write perm */
    if ((err_info = sr_perm_check(module_name, 1, NULL))) {
        return sr_api_ret(session, err_info);
    }

    /* find out what kinds of nodes are provided */
    if ((err_info = sr_oper_sub_get_type(ly_mod, path, &sub_type))) {
        return sr_api_ret(session, err_info);
    }

    /* SHM LOCK (writing into subscriptions) */
    if ((err_info = sr_shmmain_lock_remap(conn, SR_LOCK_WRITE, 1, __func__))) {
        return sr_api_ret(session, err_info);
    }

    if (!(opts & SR_SUBSCR_CTX_REUSE)) {
        /* create a new subscription */
        if ((err_info = sr_subs_new(conn, opts, subscription))) {
            goto cleanup_unlock;
        }
    }

    /* find module */
    shm_mod = sr_shmmain_find_module(&conn->main_shm, conn->ext_shm.addr, module_name, 0);
    SR_CHECK_INT_GOTO(!shm_mod, err_info, error_unlock_unsub);

    /* add oper subscription into main SHM */
    if ((err_info = sr_shmmod_oper_subscription_add(&conn->ext_shm, shm_mod, path, sub_type, sub_opts,
            (*subscription)->evpipe_num))) {
        goto error_unlock_unsub;
    }

    /* add subscription into structure and create separate specific SHM segment */
    if ((err_info = sr_sub_oper_add(session, module_name, path, callback, private_data, *subscription))) {
        goto error_unlock_unsub_unmod;
    }

    /* add the subscription into session */
    if ((err_info = sr_ptr_add(&session->ptr_lock, (void ***)&session->subscriptions, &session->subscription_count,
                *subscription))) {
        goto error_unlock_unsub_unmod;
    }

    /* success */
    goto cleanup_unlock;

error_unlock_unsub_unmod:
    sr_shmmod_oper_subscription_del(conn->ext_shm.addr, shm_mod, path, (*subscription)->evpipe_num, 0, NULL);

error_unlock_unsub:
    if (opts & SR_SUBSCR_CTX_REUSE) {
        sr_sub_oper_del(module_name, path, *subscription);
    } else {
        _sr_unsubscribe(*subscription);
        *subscription = NULL;
    }

cleanup_unlock:
    /* SHM UNLOCK */
    sr_shmmain_unlock(conn, SR_LOCK_WRITE, 1, __func__);

    return sr_api_ret(session, err_info);
}
