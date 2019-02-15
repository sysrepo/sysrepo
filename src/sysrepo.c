/**
 * @file sysrepo.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief sysrepo API routines
 *
 * @copyright
 * Copyright (c) 2019 CESNET, z.s.p.o.
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

static sr_error_info_t *
sr_conn_new(const char *app_name, sr_conn_ctx_t **conn_p)
{
    sr_conn_ctx_t *conn;
    sr_error_info_t *err_info = NULL;
    int ret;

    conn = calloc(1, sizeof *conn);
    SR_CHECK_MEM_RET(!conn, err_info);

    conn->app_name = strdup(app_name);
    if (!conn->app_name) {
        free(conn);
        SR_ERRINFO_MEM(&err_info);
        return err_info;
    }

    if ((ret = pthread_mutex_init(&conn->ptr_lock, NULL))) {
        free(conn->app_name);
        free(conn);
        sr_errinfo_new(&err_info, SR_ERR_INIT_FAILED, NULL, "Initializing pthread mutex failed (%s).", strerror(ret));
        return err_info;
    }

    if ((ret = pthread_rwlock_init(&conn->main_tlock, NULL))) {
        pthread_mutex_destroy(&conn->ptr_lock);
        free(conn->app_name);
        free(conn);
        sr_errinfo_new(&err_info, SR_ERR_INIT_FAILED, NULL, "Initializing pthread rwlock failed (%s).", strerror(ret));
        return err_info;
    }

    if ((err_info = sr_shmmain_pidlock_open(&conn->main_plock))) {
        pthread_rwlock_destroy(&conn->main_tlock);
        pthread_mutex_destroy(&conn->ptr_lock);
        free(conn->app_name);
        free(conn);
        return err_info;
    }

    conn->main_shm.fd = -1;

    *conn_p = conn;
    return NULL;
}

API int
sr_connect(const char *app_name, const sr_conn_options_t opts, sr_conn_ctx_t **conn_p)
{
    sr_conn_ctx_t *conn;
    sr_error_info_t *err_info = NULL;
    int nonexistent;

    SR_CHECK_ARG_APIRET(!app_name || !conn_p, NULL, err_info);

    /* check that all required directories exist */
    if ((err_info = sr_shmmain_check_dirs())) {
        goto error_unlock;
    }

    if ((err_info = sr_conn_new(app_name, &conn))) {
        goto error;
    }

    /* READ LOCK */
    if ((err_info = sr_shmmain_pidlock(conn, 0))) {
        goto error;
    }

    /* try to open the shared memory */
    if ((err_info = sr_shmmain_open(conn, &nonexistent))) {
        goto error_unlock;
    }
    if (nonexistent) {
        /* shared memory does not exist yet, try to create it */

        /* UNLOCK (to prevent deadlocks) */
        sr_shmmain_pidunlock(conn);

        /* WRITE LOCK */
        if ((err_info = sr_shmmain_pidlock(conn, 1))) {
            goto error;
        }

        /* only when holding the write lock there can be no race condition, check again */
        if ((err_info = sr_shmmain_open(conn, &nonexistent))) {
            goto error_unlock;
        }
        if (nonexistent) {
            /* we can now create the shared memory safely */
            if ((err_info = sr_shmmain_create(conn))) {
                goto error_unlock;
            }
        }
    }

    /* UNLOCK */
    sr_shmmain_pidunlock(conn);

    *conn_p = conn;
    return sr_api_ret(NULL, NULL);

error_unlock:
    /* UNLOCK */
    sr_shmmain_pidunlock(conn);
error:
    sr_disconnect(conn);
    return sr_api_ret(NULL, err_info);
}

API void
sr_disconnect(sr_conn_ctx_t *conn)
{
    if (!conn) {
        return;
    }

    /* stop all subscriptions */
    while (conn->subscription_count) {
        sr_unsubscribe(conn->subscriptions[0]);
    }

    /* stop all the sessions */
    while (conn->session_count) {
        sr_session_stop(conn->sessions[0]);
    }

    free(conn->app_name);
    ly_ctx_destroy(conn->ly_ctx, NULL);
    pthread_mutex_destroy(&conn->ptr_lock);
    if (conn->main_plock > -1) {
        close(conn->main_plock);
    }
    pthread_rwlock_destroy(&conn->main_tlock);
    if (conn->main_shm.fd > -1) {
        close(conn->main_shm.fd);
    }
    if (conn->main_shm.addr) {
        munmap(conn->main_shm.addr, conn->main_shm.size);
    }
    free(conn);
}

static sr_error_info_t *
sr_conn_ptr_add(void ***ptrs, uint32_t *ptr_count, void *add_ptr)
{
    sr_error_info_t *err_info = NULL;
    void *mem;

    /* add the session into conn */
    mem = realloc(*ptrs, (*ptr_count + 1) * sizeof(void *));
    if (!mem) {
        SR_ERRINFO_MEM(&err_info);
        return err_info;
    }
    *ptrs = mem;
    (*ptrs)[*ptr_count] = add_ptr;
    ++(*ptr_count);

    return NULL;
}

static void
sr_conn_ptr_del(void ***ptrs, uint32_t *ptr_count, void *del_ptr)
{
    uint32_t i;
    int found;
    sr_error_info_t *err_info = NULL;

    for (i = 0; i < *ptr_count; ++i) {
        if ((*ptrs)[i] == del_ptr) {
            if (i < *ptr_count - 1) {
                /* this session was not the last, move the last in its place */
                (*ptrs)[i] = (*ptrs)[*ptr_count - 1];
            }
            --(*ptr_count);
            if (!*ptr_count) {
                /* there are no more sessions */
                free(*ptrs);
                *ptrs = NULL;
            }
            found = 1;
            break;
        }
    }
    if (!found) {
        /* it is written at least */
        SR_ERRINFO_INT(&err_info);
        sr_errinfo_free(&err_info);
    }
}

API int
sr_session_start(sr_conn_ctx_t *conn, const sr_datastore_t datastore, const sr_sess_options_t opts,
        sr_session_ctx_t **session)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!conn || !session, NULL, err_info);

    *session = calloc(1, sizeof **session);
    if (!*session) {
        SR_ERRINFO_MEM(&err_info);
        return sr_api_ret(NULL, err_info);
    }

    /* PTR LOCK */
    if ((err_info = sr_lock(&conn->ptr_lock, __func__))) {
        return sr_api_ret(NULL, err_info);
    }

    /* add the session into conn */
    if ((err_info = sr_conn_ptr_add((void ***)&conn->sessions, &conn->session_count, *session))) {
        free(*session);
        *session = NULL;
        return sr_api_ret(NULL, err_info);
    }

    /* PTR UNLOCK */
    sr_unlock(&conn->ptr_lock);

    (*session)->conn = conn;
    (*session)->ds = datastore;

    return sr_api_ret(NULL, NULL);
}

API int
sr_session_stop(sr_session_ctx_t *session)
{
    uint32_t i;
    sr_error_info_t *err_info = NULL;

    if (!session) {
        return sr_api_ret(NULL, NULL);
    }

    /* PTR LOCK */
    if ((err_info = sr_lock(&session->conn->ptr_lock, __func__))) {
        return sr_api_ret(NULL, err_info);
    }

    /* remove ourselves from conn sessions */
    sr_conn_ptr_del((void ***)&session->conn->sessions, &session->conn->session_count, session);

    /* PTR UNLOCK */
    sr_unlock(&session->conn->ptr_lock);

    for (i = 0; i < SR_DS_COUNT; ++i) {
        lyd_free_withsiblings(session->dt[i].edit);
    }
    sr_errinfo_free(&session->err_info);
    free(session);
    return sr_api_ret(NULL, err_info);
}

API int
sr_session_switch_ds(sr_session_ctx_t *session, sr_datastore_t ds)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session || (ds == SR_DS_COUNT), session, err_info);

    session->ds = ds;
    return sr_api_ret(session, err_info);
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
sr_set_error(sr_session_ctx_t *session, const char *message, const char *xpath)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session || ((session->ev != SR_EV_CHANGE) && (session->ev != SR_EV_UPDATE)) || !message, session, err_info);

    sr_errinfo_new(&err_info, SR_ERR_OK, xpath, message);

    /* set the error and return its return code (SR_ERR_OK) */
    return sr_api_ret(session, err_info);
}

API sr_conn_ctx_t *
sr_session_get_connection(sr_session_ctx_t *session)
{
    if (!session) {
        return NULL;
    }

    return session->conn;
}

API int
sr_get_item(sr_session_ctx_t *session, const char *xpath, sr_val_t **value)
{
    struct lyd_node *subtree = NULL;
    sr_error_info_t *err_info = NULL;
    int ret;

    SR_CHECK_ARG_APIRET(!session || !xpath || !value, session, err_info);

    *value = NULL;

    /* API function */
    if ((ret = sr_get_subtree(session, xpath, &subtree)) != SR_ERR_OK) {
        return ret;
    }

    *value = malloc(sizeof **value);
    SR_CHECK_MEM_GOTO(!*value, err_info, cleanup);

    if ((err_info = sr_val_ly2sr(subtree, *value))) {
        goto cleanup;
    }

    /* success */

cleanup:
    lyd_free(subtree);
    if (err_info) {
        free(*value);
    }
    return sr_api_ret(session, err_info);
}

API int
sr_get_items(sr_session_ctx_t *session, const char *xpath, sr_val_t **values, size_t *value_cnt)
{
    struct ly_set *subtrees = NULL;
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    int ret;

    SR_CHECK_ARG_APIRET(!session || !xpath || !values || !value_cnt, session, err_info);

    *values = NULL;
    *value_cnt = 0;

    /* API function */
    if ((ret = sr_get_subtrees(session, xpath, &subtrees)) != SR_ERR_OK) {
        return ret;
    }

    if (subtrees->number) {
        *values = malloc(subtrees->number * sizeof **values);
        SR_CHECK_MEM_GOTO(!*values, err_info, cleanup);
    }

    for (i = 0; i < subtrees->number; ++i) {
        if ((err_info = sr_val_ly2sr(subtrees->set.d[i], (*values) + i))) {
            goto cleanup;
        }
        ++(*value_cnt);
    }

    /* success */

cleanup:
    for (i = 0; i < subtrees->number; ++i) {
        lyd_free(subtrees->set.d[i]);
    }
    ly_set_free(subtrees);

    if (err_info) {
        sr_free_values(*values, *value_cnt);
        *values = NULL;
        *value_cnt = 0;
    }
    return sr_api_ret(session, err_info);
}

static sr_error_info_t *
sr_subs_new(sr_conn_ctx_t *conn, sr_subscription_ctx_t **subs_p)
{
    sr_error_info_t *err_info = NULL;
    pthread_t tid;
    int ret;

    /* allocate new subscription */
    *subs_p = calloc(1, sizeof **subs_p);
    SR_CHECK_MEM_RET(!*subs_p, err_info);
    pthread_mutex_init(&(*subs_p)->subs_lock, NULL);
    (*subs_p)->conn = conn;

    /* set TID to non-zero so that thread does not immediatelly quit */
    (*subs_p)->tid = (pthread_t)1;

    /* start the listen thread */
    ret = pthread_create(&tid, NULL, sr_shmsub_listen_thread, *subs_p);
    if (ret) {
        sr_errinfo_new(&err_info, SR_ERR_INTERNAL, NULL, "Creating a new thread failed (%s).", strerror(ret));
        return err_info;
    }

    (*subs_p)->tid = tid;
    return NULL;
}

API int
sr_dp_get_items_subscribe(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        sr_dp_get_items_cb callback, void *private_data, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription)
{
    sr_error_info_t *err_info = NULL;
    sr_conn_ctx_t *conn;
    char *schema_path = NULL;
    const struct lys_module *mod;
    struct ly_set *set = NULL;
    sr_mod_dp_sub_type_t sub_type;
    uint16_t i;

    SR_CHECK_ARG_APIRET(!session || !module_name || !xpath || !callback || !subscription, session, err_info);

    conn = session->conn;

    /* SHM WRITE LOCK */
    if ((err_info = sr_shmmain_lock_remap(conn, 1))) {
        return sr_api_ret(session, err_info);
    }

    mod = ly_ctx_get_module(conn->ly_ctx, module_name, NULL, 1);
    if (!mod) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Module \"%s\" was not found in sysrepo.", module_name);
        sr_shmmain_unlock(conn);
        return sr_api_ret(session, err_info);
    }

    schema_path = ly_path_data2schema(conn->ly_ctx, xpath);
    set = lys_find_path(mod, NULL, schema_path);
    if (!set) {
        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
        sr_shmmain_unlock(conn);
        return sr_api_ret(session, err_info);
    } else if (!set->number) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "XPath \"%s\" does not point to any nodes.", xpath);
        sr_shmmain_unlock(conn);
        return sr_api_ret(session, err_info);
    }

    /* find out what kinds of nodes are provided */
    sub_type = SR_DP_SUB_NONE;
    for (i = 0; i < set->number; ++i) {
        switch (set->set.s[i]->flags & LYS_CONFIG_MASK) {
        case LYS_CONFIG_R:
            if (sub_type == SR_DP_SUB_CONFIG) {
                sub_type = SR_DP_SUB_MIXED;
            } else {
                sub_type = SR_DP_SUB_STATE;
            }
            break;
        case LYS_CONFIG_W:
            if (sub_type == SR_DP_SUB_STATE) {
                sub_type = SR_DP_SUB_MIXED;
            } else {
                sub_type = SR_DP_SUB_CONFIG;
            }
            break;
        default:
            SR_ERRINFO_INT(&err_info);
            sr_shmmain_unlock(conn);
            return sr_api_ret(session, err_info);
        }

        if (sub_type == SR_DP_SUB_MIXED) {
            /* we found both config type nodes, nothing more to look for */
            break;
        }
    }

    /* add DP subscription into main SHM */
    if ((err_info = sr_shmmod_dp_subscription(conn, module_name, xpath, sub_type, 1))) {
        sr_shmmain_unlock(conn);
        return sr_api_ret(session, err_info);
    }

    if (!(opts & SR_SUBSCR_CTX_REUSE)) {
        /* create a new subscription */
        if ((err_info = sr_subs_new(conn, subscription))) {
            sr_shmmod_dp_subscription(conn, module_name, xpath, SR_DP_SUB_NONE, 0);
            sr_shmmain_unlock(conn);
            return sr_api_ret(session, err_info);
        }
    }

    /* add subscription into structure and create separate specific SHM segment */
    if ((err_info = sr_sub_dp_add(module_name, xpath, callback, private_data, *subscription))) {
        sr_shmmain_unlock(conn);
        goto error_unsubscribe;
    }

    /* SHM UNLOCK */
    sr_shmmain_unlock(conn);

    if (!(opts & SR_SUBSCR_CTX_REUSE)) {
        /* PTR LOCK */
        if ((err_info = sr_lock(&conn->ptr_lock, __func__))) {
            goto error_unsubscribe;
        }

        /* add the subscription into conn */
        if ((err_info = sr_conn_ptr_add((void ***)&conn->subscriptions, &conn->subscription_count, *subscription))) {
            sr_unlock(&conn->ptr_lock);
            goto error_unsubscribe;
        }

        /* PTR UNLOCK */
        sr_unlock(&conn->ptr_lock);
    }

    free(schema_path);
    ly_set_free(set);
    return sr_api_ret(session, NULL);

error_unsubscribe:
    free(schema_path);
    ly_set_free(set);
    if (opts & SR_SUBSCR_CTX_REUSE) {
        sr_sub_dp_del(module_name, xpath, *subscription);
    } else {
        sr_unsubscribe(*subscription);
    }
    sr_shmmod_dp_subscription(conn, module_name, xpath, SR_DP_SUB_NONE, 0);
    return sr_api_ret(session, err_info);
}

API const struct ly_ctx *
sr_get_context(sr_conn_ctx_t *conn)
{
    if (!conn) {
        return NULL;
    }

    return conn->ly_ctx;
}

static sr_error_info_t *
sr_store_module_file(const struct lys_module *mod)
{
    char *path;
    sr_error_info_t *err_info = NULL;

    if (asprintf(&path, "%s/yang/%s%s%s.yang", sr_get_repo_path(), mod->name,
                 mod->rev_size ? "@" : "", mod->rev_size ? mod->rev[0].date : "") == -1) {
        SR_ERRINFO_MEM(&err_info);
        return err_info;
    }

    if (!access(path, R_OK)) {
        /* already exists */
        SR_LOG_INF("Module file \"%s%s%s\" already exists.",
                mod->name, mod->rev_size ? "@" : "", mod->rev_size ? mod->rev[0].date : "");
        free(path);
        return NULL;
    }

    if (lys_print_path(path, mod, LYS_YANG, NULL, 0, 0)) {
        free(path);
        sr_errinfo_new_ly(&err_info, mod->ctx);
        return err_info;
    }

    SR_LOG_INF("Module file \"%s%s%s\" installed.",
            mod->name, mod->rev_size ? "@" : "", mod->rev_size ? mod->rev[0].date : "");
    free(path);
    return NULL;
}

static sr_error_info_t *
sr_create_data_files(const struct lys_module *mod)
{
    struct lyd_node *root = NULL;
    char *path = NULL;
    sr_error_info_t *err_info = NULL;

    /* get default values */
    if (lyd_validate_modules(&root, &mod, 1, LYD_OPT_CONFIG)) {
        sr_errinfo_new_ly(&err_info, mod->ctx);
        SR_ERRINFO_VALID(&err_info);
        return err_info;
    }

    /* print them into a file */
    if (asprintf(&path, "%s/data/%s.startup", sr_get_repo_path(), mod->name) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    if (lyd_print_path(path, root, LYD_LYB, LYP_WITHSIBLINGS)) {
        sr_errinfo_new_ly(&err_info, mod->ctx);
        sr_errinfo_new(&err_info, SR_ERR_INTERNAL, NULL, "Failed to write data into \"%s\".", path);
        goto cleanup;
    }

    /* set permissions */
    if (chmod(path, 00660)) {
        SR_ERRINFO_SYSERRNO(&err_info, "chmod");
        goto cleanup;
    }

    /* repeat for running DS */
    free(path);
    path = NULL;
    if (asprintf(&path, "%s/data/%s.running", sr_get_repo_path(),  mod->name) == -1) {
        SR_ERRINFO_MEM(&err_info);
        return err_info;
    }
    if (lyd_print_path(path, root, LYD_LYB, LYP_WITHSIBLINGS)) {
        sr_errinfo_new_ly(&err_info, mod->ctx);
        sr_errinfo_new(&err_info, SR_ERR_INTERNAL, NULL, "Failed to write data into \"%s\".", path);
        goto cleanup;
    }

    /* set permissions */
    if (chmod(path, 00660)) {
        SR_ERRINFO_SYSERRNO(&err_info, "chmod");
        goto cleanup;
    }

cleanup:
    free(path);
    lyd_free_withsiblings(root);
    return err_info;
}

static sr_error_info_t *
sr_create_module_files_with_imps_r(const struct lys_module *mod)
{
    struct lys_module *imp_mod;
    sr_error_info_t *err_info = NULL;
    uint16_t i;

    if ((err_info = sr_store_module_file(mod))) {
        return err_info;
    }

    if (mod->implemented && (err_info = sr_create_data_files(mod))) {
        return err_info;
    }

    for (i = 0; i < mod->imp_size; ++i) {
        imp_mod = mod->imp[i].module;
        if (!strcmp(imp_mod->name, "ietf-yang-types") || !strcmp(imp_mod->name, "ietf-inet-types")) {
            /* internal modules */
            continue;
        }

        if ((err_info = sr_create_module_files_with_imps_r(imp_mod))) {
            return err_info;
        }
    }

    return NULL;
}

API int
sr_install_module(sr_conn_ctx_t *conn, const char *module_path, const char *search_dir,
        const char **features, int feat_count, int replay_support)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *mod;
    LYS_INFORMAT format;
    const char * const *search_dirs;
    const char *ptr;
    char *mod_name = NULL;
    int index;

    SR_CHECK_ARG_APIRET(!conn || !module_path, NULL, err_info);

    /* learn the format */
    if ((strlen(module_path) > 4) && !strcmp(module_path + strlen(module_path) - 4, ".yin")) {
        format = LYS_YIN;
        ptr = module_path + strlen(module_path) - 4;
    } else if ((strlen(module_path) > 5) && !strcmp(module_path + strlen(module_path) - 5, ".yang")) {
        format = LYS_YANG;
        ptr = module_path + strlen(module_path) - 5;
    } else {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Unknown format of module \"%s\".", module_path);
        return sr_api_ret(NULL, err_info);
    }

    /* parse module name */
    for (index = 0; (ptr != module_path) && (ptr[0] != '/'); ++index, --ptr);
    if (ptr[0] == '/') {
        ++ptr;
        --index;
    }
    mod_name = strndup(ptr, index);
    if (!mod_name) {
        return sr_api_ret(NULL, err_info);
    }
    ptr = strchr(mod_name, '@');
    if (ptr) {
        /* truncate revision */
        ((char *)ptr)[0] = '\0';
    }

    /* SHM WRITE LOCK */
    if ((err_info = sr_shmmain_lock_remap(conn, 1))) {
        free(mod_name);
        return sr_api_ret(NULL, err_info);
    }

    /* check whether the module is not already in the context */
    mod = ly_ctx_get_module(conn->ly_ctx, mod_name, NULL, 1);
    if (mod) {
        /* it is currently in the context, but maybe marked for deletion? */
        err_info = sr_shmmain_unsched_del_module_with_imps(conn, mod, replay_support);
        if (err_info && (err_info->err_code == SR_ERR_NOT_FOUND)) {
            sr_errinfo_free(&err_info);
            sr_errinfo_new(&err_info, SR_ERR_EXISTS, NULL, "Module \"%s\" is already in sysrepo.", mod->name);
            goto cleanup_unlock;
        }
        goto cleanup_unlock;
    }
    free(mod_name);
    mod_name = NULL;

    /* add searchdir if not already there */
    if (search_dir) {
        search_dirs = ly_ctx_get_searchdirs(conn->ly_ctx);
        for (index = 0; search_dirs[index]; ++index) {
            if (!strcmp(search_dirs[index], search_dir)) {
                break;
            }
        }
        if (!search_dirs[index]) {
            ly_ctx_set_searchdir(conn->ly_ctx, search_dir);
            /* it could have been moved on realloc */
            search_dirs = ly_ctx_get_searchdirs(conn->ly_ctx);
        }
    }

    /* parse the module */
    mod = lys_parse_path(conn->ly_ctx, module_path, format);

    /* remove search dir */
    if (search_dir && search_dirs[index]) {
        ly_ctx_unset_searchdirs(conn->ly_ctx, index);
    }

    /* invalid module */
    if (!mod) {
        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
        goto cleanup_unlock;
    }

    /* enable all features */
    for (index = 0; index < feat_count; ++index) {
        if (lys_features_enable(mod, features[index])) {
            ly_ctx_remove_module(mod, NULL);
            goto cleanup_unlock;
        }
    }

    /* add into main SHM */
    if ((err_info = sr_shmmain_add_module_with_imps(conn, mod, replay_support))) {
        goto cleanup_unlock;
    }

    /* update version */
    if ((err_info = sr_shmmain_update_ver(conn))) {
        goto cleanup_unlock;
    }

    /* SHM UNLOCK */
    sr_shmmain_unlock(conn);

    /* store the model file and create data files for module and all of its imports */
    if ((err_info = sr_create_module_files_with_imps_r(mod))) {
        return sr_api_ret(NULL, err_info);
    }

    return sr_api_ret(NULL, NULL);

cleanup_unlock:
    sr_shmmain_unlock(conn);
    free(mod_name);
    return sr_api_ret(NULL, err_info);
}

API int
sr_remove_module(sr_conn_ctx_t *conn, const char *module_name)
{
    const struct lys_module *mod;
    uint32_t ver;
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!conn || !module_name, NULL, err_info);

    /* SHM READ LOCK */
    if ((err_info = sr_shmmain_lock_remap(conn, 0))) {
        return sr_api_ret(NULL, err_info);
    }

    /* try to find this module */
    mod = ly_ctx_get_module(conn->ly_ctx, module_name, NULL, 1);
    if (!mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" was not found in sysrepo.", module_name);
        goto error_unlock;
    }

    /* remember current SHM version */
    ver = conn->main_ver;

    /* SHM UNLOCK (to prevent deadlocks) */
    sr_shmmain_unlock(conn);

    /* SHM WRITE LOCK */
    if ((err_info = sr_shmmain_lock_remap(conn, 1))) {
        return sr_api_ret(NULL, err_info);
    }

    /* get module again if context has changed */
    if (ver != conn->main_ver) {
        mod = ly_ctx_get_module(conn->ly_ctx, module_name, NULL, 1);
        if (!mod) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" was not found in sysrepo.", module_name);
            goto error_unlock;
        }
    }

    /* remove module from sysrepo */
    if ((err_info = sr_shmmain_deferred_del_module(conn, module_name))) {
        goto error_unlock;
    }

    /* SHM UNLOCK */
    sr_shmmain_unlock(conn);

    return sr_api_ret(NULL, NULL);

error_unlock:
    sr_shmmain_unlock(conn);
    return sr_api_ret(NULL, err_info);
}

static sr_error_info_t *
sr_change_feature(sr_conn_ctx_t *conn, const char *module_name, const char *feature_name, int enable)
{
    const struct lys_module *mod;
    sr_error_info_t *err_info = NULL;
    int ret;

    /* SHM READ LOCK */
    if ((err_info = sr_shmmain_lock_remap(conn, 0))) {
        return err_info;
    }

    /* try to find this module */
    mod = ly_ctx_get_module(conn->ly_ctx, module_name, NULL, 1);
    if (!mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" was not found in sysrepo.", module_name);
        goto cleanup;
    }

    /* check feature in the current context */
    ret = lys_features_state(mod, feature_name);
    if (ret == -1) {
        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
        goto cleanup;
    }

    /* mark the change in LY data tree */
    if ((err_info = sr_shmmain_deferred_change_feature(conn, mod->name, feature_name, enable))) {
        goto cleanup;
    }

    /* success */

cleanup:
    /* SHM UNLOCK */
    sr_shmmain_unlock(conn);
    return err_info;
}

API int
sr_enable_feature(sr_conn_ctx_t *conn, const char *module_name, const char *feature_name)
{
    sr_error_info_t *err_info;

    SR_CHECK_ARG_APIRET(!conn || !module_name || !feature_name, NULL, err_info);

    err_info = sr_change_feature(conn, module_name, feature_name, 1);

    return sr_api_ret(NULL, err_info);
}

API int
sr_disable_feature(sr_conn_ctx_t *conn, const char *module_name, const char *feature_name)
{
    sr_error_info_t *err_info;

    SR_CHECK_ARG_APIRET(!conn || !module_name || !feature_name, NULL, err_info);

    err_info = sr_change_feature(conn, module_name, feature_name, 0);

    return sr_api_ret(NULL, err_info);
}

static void
sr_modinfo_free(struct sr_mod_info_s *mod_info)
{
    uint32_t i;

    lyd_free_withsiblings(mod_info->diff);
    for (i = 0; i < mod_info->mod_count; ++i) {
        lyd_free_withsiblings(mod_info->mods[i].mod_data);
        if (mod_info->mods[i].shm_sub_cache.addr) {
            munmap(mod_info->mods[i].shm_sub_cache.addr, mod_info->mods[i].shm_sub_cache.size);
        }
        if (mod_info->mods[i].shm_sub_cache.fd > -1) {
            close(mod_info->mods[i].shm_sub_cache.fd);
        }
    }

    free(mod_info->mods);
}

API int
sr_get_subtree(sr_session_ctx_t *session, const char *xpath, struct lyd_node **subtree)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    uint32_t i;
    struct sr_mod_info_s mod_info;
    struct ly_set *set = NULL;

    SR_CHECK_ARG_APIRET(!session || !xpath || !subtree, session, err_info);

    memset(&mod_info, 0, sizeof mod_info);

    /* SHM READ LOCK */
    if ((err_info = sr_shmmain_lock_remap(session->conn, 0))) {
        return sr_api_ret(session, err_info);
    }

    /* collect all required modules */
    if ((err_info = sr_shmmod_collect_xpath(session->conn, xpath, session->ds, &mod_info))) {
        goto cleanup_shm_unlock;
    }

    /* MODULES READ LOCK */
    if ((err_info = sr_shmmod_multilock(&mod_info, 0, 0))) {
        goto cleanup_mods_unlock;
    }

    /* load modules data */
    if ((err_info = sr_modinfo_data_update(&mod_info, MOD_INFO_REQ, &cb_err_info)) || cb_err_info) {
        goto cleanup_mods_unlock;
    }

    /* filter the required data */
    if ((err_info = sr_modinfo_get_filter(session, xpath, &mod_info, &set))) {
        goto cleanup_mods_unlock;
    }

    if (set->number > 1) {
        for (i = 0; i < set->number; ++i) {
            lyd_free(set->set.d[i]);
        }
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "More subtrees match \"%s\".", xpath);
        goto cleanup_mods_unlock;
    }

    if (set->number == 1) {
        *subtree = set->set.d[0];
    } else {
        *subtree = NULL;
    }
    /* success */

cleanup_mods_unlock:
    /* MODULES UNLOCK */
    sr_shmmod_multiunlock(&mod_info, 0);

cleanup_shm_unlock:
    /* SHM UNLOCK */
    sr_shmmain_unlock(session->conn);

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
sr_get_subtrees(sr_session_ctx_t *session, const char *xpath, struct ly_set **subtrees)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    struct sr_mod_info_s mod_info;

    SR_CHECK_ARG_APIRET(!session || !xpath || !subtrees, session, err_info);

    memset(&mod_info, 0, sizeof mod_info);

    /* SHM READ LOCK */
    if ((err_info = sr_shmmain_lock_remap(session->conn, 0))) {
        return sr_api_ret(session, err_info);
    }

    /* collect all required modules */
    if ((err_info = sr_shmmod_collect_xpath(session->conn, xpath, session->ds, &mod_info))) {
        goto cleanup_shm_unlock;
    }

    /* MODULES READ LOCK */
    if ((err_info = sr_shmmod_multilock(&mod_info, 0, 0))) {
        goto cleanup_mods_unlock;
    }

    /* load modules data */
    if ((err_info = sr_modinfo_data_update(&mod_info, MOD_INFO_REQ, &cb_err_info)) || cb_err_info) {
        goto cleanup_mods_unlock;
    }

    /* filter the required data */
    if ((err_info = sr_modinfo_get_filter(session, xpath, &mod_info, subtrees))) {
        goto cleanup_mods_unlock;
    }

    /* success */

cleanup_mods_unlock:
    /* MODULES UNLOCK */
    sr_shmmod_multiunlock(&mod_info, 0);

cleanup_shm_unlock:
    /* SHM UNLOCK */
    sr_shmmain_unlock(session->conn);

    sr_modinfo_free(&mod_info);
    if (cb_err_info) {
        /* return callback error if some was generated */
        sr_errinfo_merge(&err_info, cb_err_info);
        err_info->err_code = SR_ERR_CALLBACK_FAILED;
    }
    return sr_api_ret(session, err_info);
}

static sr_error_info_t *
sr_edit_item(sr_session_ctx_t *session, const char *xpath, const char *value, const char *operation,
        const char *def_operation, const sr_move_position_t *position, const char *keys, const char *val)
{
    sr_error_info_t *err_info = NULL;

    assert(session && xpath && operation);

    /* SHM READ LOCK */
    if ((err_info = sr_shmmain_lock_remap(session->conn, 0)) != SR_ERR_OK) {
        return err_info;
    }

    /* SHM UNLOCK */
    sr_shmmain_unlock(session->conn);

    /* add the operation into edit */
    if ((err_info = sr_ly_edit_add(session, xpath, value, operation, def_operation, position, keys, val))) {
        return err_info;
    }

    return NULL;
}

API int
sr_set_item_str(sr_session_ctx_t *session, const char *xpath, const char *value, const sr_edit_options_t opts)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session || (session->ds == SR_DS_OPERATIONAL) || !xpath, session, err_info);

    err_info = sr_edit_item(session, xpath, value, opts & SR_EDIT_STRICT ? "create" : "merge",
            opts & SR_EDIT_NON_RECURSIVE ? "none" : "merge", NULL, NULL, NULL);

    return sr_api_ret(session, err_info);
}

API int
sr_set_item(sr_session_ctx_t *session, const char *xpath, const sr_val_t *value, const sr_edit_options_t opts)
{
    sr_error_info_t *err_info = NULL;
    char str[22], *str_val;

    SR_CHECK_ARG_APIRET(!session || (session->ds == SR_DS_OPERATIONAL) || !value || (!xpath && !value->xpath), session, err_info);

    str_val = sr_val_sr2ly_str(session->conn->ly_ctx, value, str);
    if (!xpath) {
        xpath = value->xpath;
    }

    /* API function */
    return sr_set_item_str(session, xpath, str_val, opts);
}

API int
sr_delete_item(sr_session_ctx_t *session, const char *xpath, const sr_edit_options_t opts)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session || (session->ds == SR_DS_OPERATIONAL) || !xpath, session, err_info);

    err_info = sr_edit_item(session, xpath, NULL, opts & SR_EDIT_STRICT ? "delete" : "remove",
            opts & SR_EDIT_STRICT ? "none" : "ether", NULL, NULL, NULL);

    return sr_api_ret(session, err_info);
}

API int
sr_move_item(sr_session_ctx_t *session, const char *xpath, const sr_move_position_t position, const char *list_keys,
        const char *leaflist_value)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session || (session->ds == SR_DS_OPERATIONAL) || !xpath, session, err_info);

    err_info = sr_edit_item(session, xpath, NULL, "merge", "none", &position, list_keys, leaflist_value);

    return sr_api_ret(session, err_info);
}

API int
sr_edit_batch(sr_session_ctx_t *session, const struct lyd_node *edit, const char *default_operation)
{
    sr_error_info_t *err_info = NULL;
    const char *attr_full_name;
    struct lyd_node *valid_edit = NULL;

    SR_CHECK_ARG_APIRET(!session || (session->ds == SR_DS_OPERATIONAL) || !edit || !default_operation, session, err_info);

    if (strcmp(default_operation, "merge") && strcmp(default_operation, "replace") && strcmp(default_operation, "none")) {
        /* TODO */
        return SR_ERR_INVAL_ARG;
    }
    if (session->dt[session->ds].edit) {
        /* do not allow merging NETCONF edits into sysrepo ones, it can cause some unexpected results */
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, NULL, "There are already some session changes.");
        return sr_api_ret(session, err_info);
    }

    /* SHM READ LOCK */
    if ((err_info = sr_shmmain_lock_remap(session->conn, 0))) {
        return sr_api_ret(session, err_info);
    }

    /* SHM UNLOCK */
    sr_shmmain_unlock(session->conn);

    valid_edit = lyd_dup_withsiblings(edit, LYD_DUP_OPT_RECURSIVE);
    if (!valid_edit) {
        sr_errinfo_new_ly(&err_info, session->conn->ly_ctx);
        goto error;
    }

    /* validate the input data tree first */
    if (lyd_validate(&valid_edit, LYD_OPT_EDIT, NULL)) {
        SR_ERRINFO_VALID(&err_info);
        goto error;
    }

    /* add default operation */
    if (!strcmp(default_operation, "none")) {
        attr_full_name = SR_YANG_MOD ":operation";
    } else {
        attr_full_name = "ietf-netconf:operation";
    }
    if (!lyd_insert_attr(valid_edit, NULL, attr_full_name, default_operation)) {
        sr_errinfo_new_ly(&err_info, session->conn->ly_ctx);
        goto error;
    }

    session->dt[session->ds].edit = valid_edit;
    return sr_api_ret(session, NULL);

error:
    lyd_free_withsiblings(valid_edit);
    return sr_api_ret(session, err_info);
}

API int
sr_apply_changes(sr_session_ctx_t *session)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    struct lyd_node *update_edit;
    struct sr_mod_info_s mod_info;

    SR_CHECK_ARG_APIRET(!session || (session->ds == SR_DS_OPERATIONAL), session, err_info);

    if (!session->dt[session->ds].edit) {
        return sr_api_ret(session, NULL);
    }

    memset(&mod_info, 0, sizeof mod_info);

    /* SHM READ LOCK */
    if ((err_info = sr_shmmain_lock_remap(session->conn, 0))) {
        return sr_api_ret(session, err_info);
    }

    /* collect all required modules */
    if ((err_info = sr_shmmod_collect_edit(session->conn, session->dt[session->ds].edit, session->ds, &mod_info))) {
        goto cleanup_shm_unlock;
    }

    /* MODULES READ LOCK (but setting flag for guaranteed later upgrade success) */
    if ((err_info = sr_shmmod_multilock(&mod_info, 0, 1))) {
        goto cleanup_mods_unlock;
    }

    /* load all modules data (we need dependencies for validation) */
    if ((err_info = sr_modinfo_data_update(&mod_info, MOD_INFO_TYPE_MASK, NULL))) {
        goto cleanup_mods_unlock;
    }

    /* create diff */
    if ((err_info = sr_modinfo_edit_diff(session->dt[session->ds].edit, &mod_info))) {
        goto cleanup_mods_unlock;
    }

    /* validate new data trees */
    if ((err_info = sr_modinfo_validate(&mod_info, 1))) {
        goto cleanup_mods_unlock;
    }

    if (!mod_info.diff) {
        SR_LOG_INFMSG("No datastore changes to apply.");
        if (!mod_info.dflt_change) {
            goto cleanup_mods_unlock;
        }
        /* while there are no changes for callbacks, some default flags changed so we must store them */
    }

    if (mod_info.diff) {
        /* publish current diff in an "update" event for the subscribers to update it */
        if ((err_info = sr_shmsub_conf_notify_update(&mod_info, &update_edit, &cb_err_info))) {
            goto cleanup_mods_unlock;
        }
        if (cb_err_info) {
            /* "update" event failed, just clear the sub SHM and finish */
            err_info = sr_shmsub_conf_notify_clear(&mod_info, SR_EV_UPDATE);
            goto cleanup_mods_unlock;
        }

        /* create new diff if we have an update edit */
        if (update_edit) {
            /* merge edits */
            if (lyd_merge(session->dt[session->ds].edit, update_edit, LYD_OPT_DESTRUCT)) {
                sr_errinfo_new_ly(&err_info, session->conn->ly_ctx);
                sr_errinfo_new(&err_info, SR_ERR_INTERNAL, NULL, "Merging edits failed.");
                goto cleanup_mods_unlock;
            }

            /* reload possibly changed data */
            if ((err_info = sr_modinfo_data_update(&mod_info, MOD_INFO_REQ, NULL))) {
                goto cleanup_mods_unlock;
            }

            /* get updated diff */
            lyd_free_withsiblings(mod_info.diff);
            mod_info.diff = NULL;
            mod_info.dflt_change = 0;
            if ((err_info = sr_modinfo_edit_diff(session->dt[session->ds].edit, &mod_info))) {
                goto cleanup_mods_unlock;
            }

            /* validate updated data trees */
            if ((err_info = sr_modinfo_validate(&mod_info, 1))) {
                goto cleanup_mods_unlock;
            }

            if (!mod_info.diff) {
                SR_LOG_INFMSG("No datastore changes to apply.");
                if (!mod_info.dflt_change) {
                    goto cleanup_mods_unlock;
                }
                /* while there are no changes for callbacks, some default flags changed so we must store them */
            }
        }

        if (mod_info.diff) {
            /* publish final diff in a "change" event for any subscribers and wait for them */
            if ((err_info = sr_shmsub_conf_notify_change(&mod_info, &cb_err_info))) {
                goto cleanup_mods_unlock;
            }
            if (cb_err_info) {
                /* "change" event failed, publish "abort" event and finish */
                err_info = sr_shmsub_conf_notify_change_abort(&mod_info);
                goto cleanup_mods_unlock;
            }
        }
    }

    /* MODULES WRITE LOCK (upgrade) */
    if ((err_info = sr_shmmod_multirelock(&mod_info, 1))) {
        goto cleanup_mods_unlock;
    }

    /* store updated datastore */
    if ((err_info = sr_modinfo_store(&mod_info))) {
        goto cleanup_mods_unlock;
    }

    if (mod_info.diff) {
        /* publish "done" event, all changes were applied */
        if ((err_info = sr_shmsub_conf_notify_change_done(&mod_info))) {
            goto cleanup_mods_unlock;
        }
    }

    /* success */

cleanup_mods_unlock:
    /* MODULES UNLOCK */
    sr_shmmod_multiunlock(&mod_info, 1);

cleanup_shm_unlock:
    /* SHM UNLOCK */
    sr_shmmain_unlock(session->conn);

    if (!err_info) {
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
sr_discard_changes(sr_session_ctx_t *session)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session || (session->ds == SR_DS_OPERATIONAL), session, err_info);

    if (!session->dt[session->ds].edit) {
        return sr_api_ret(session, NULL);
    }

    lyd_free_withsiblings(session->dt[session->ds].edit);
    session->dt[session->ds].edit = NULL;
    return sr_api_ret(session, NULL);
}

API int
sr_copy_config(sr_session_ctx_t *session, const char *module_name, sr_datastore_t src_datastore, sr_datastore_t dst_datastore)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    struct sr_mod_info_s src_mod_info, dst_mod_info;
    const struct lys_module *mod = NULL;

    SR_CHECK_ARG_APIRET(!session || (src_datastore == SR_DS_OPERATIONAL) || (dst_datastore == SR_DS_OPERATIONAL), session, err_info);

    if (src_datastore == dst_datastore) {
        /* nothing to do */
        return sr_api_ret(session, NULL);
    }

    memset(&src_mod_info, 0, sizeof src_mod_info);
    memset(&dst_mod_info, 0, sizeof dst_mod_info);

    /* SHM READ LOCK */
    if ((err_info = sr_shmmain_lock_remap(session->conn, 0))) {
        return sr_api_ret(session, err_info);
    }

    if (module_name) {
        /* try to find this module */
        mod = ly_ctx_get_module(session->conn->ly_ctx, module_name, NULL, 1);
        if (!mod) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" was not found in sysrepo.", module_name);
            goto cleanup_shm_unlock;
        }
    }

    /* collect all required modules for src and dst datastores */
    if ((err_info = sr_shmmod_collect_modules(session->conn, mod, src_datastore, 0, &src_mod_info))) {
        goto cleanup_shm_unlock;
    }
    if ((err_info = sr_shmmod_collect_modules(session->conn, mod, dst_datastore, 0, &dst_mod_info))) {
        goto cleanup_shm_unlock;
    }

    /* MODULES READ LOCK (but setting flag for guaranteed later upgrade success) */
    if ((err_info = sr_shmmod_multilock(&dst_mod_info, 0, 1))) {
        goto cleanup_shm_unlock;
    }

    /* load modules data */
    if ((err_info = sr_modinfo_data_update(&src_mod_info, MOD_INFO_REQ, NULL))) {
        goto cleanup_mods_unlock;
    }
    if ((err_info = sr_modinfo_data_update(&dst_mod_info, MOD_INFO_REQ, NULL))) {
        goto cleanup_mods_unlock;
    }

    /* create diff between the 2 mod_infos and their modules */
    if ((err_info = sr_modinfo_diff(&src_mod_info, &dst_mod_info))) {
        goto cleanup_mods_unlock;
    }

    if (!dst_mod_info.diff) {
        SR_LOG_INFMSG("No datastore changes to apply.");
        if (!dst_mod_info.dflt_change) {
            goto cleanup_mods_unlock;
        }
        /* while there are no changes for callbacks, some default flags changed so we must store them */
    }

    if (dst_mod_info.diff) {
        /* publish final diff in a "change" event for any subscribers and wait for them */
        if ((err_info = sr_shmsub_conf_notify_change(&dst_mod_info, &cb_err_info))) {
            goto cleanup_mods_unlock;
        }
        if (cb_err_info) {
            /* "change" event failed, publish "abort" event and finish */
            err_info = sr_shmsub_conf_notify_change_abort(&dst_mod_info);
            goto cleanup_mods_unlock;
        }
    }

    /* MODULES WRITE LOCK (upgrade) */
    if ((err_info = sr_shmmod_multirelock(&dst_mod_info, 1))) {
        goto cleanup_mods_unlock;
    }

    /* store updated datastore */
    if ((err_info = sr_modinfo_store(&dst_mod_info))) {
        goto cleanup_mods_unlock;
    }

    if (dst_mod_info.diff) {
        /* publish "done" event, all changes were applied */
        if ((err_info = sr_shmsub_conf_notify_change_done(&dst_mod_info))) {
            goto cleanup_mods_unlock;
        }
    }

    /* success */

cleanup_mods_unlock:
    /* MODULES UNLOCK */
    sr_shmmod_multiunlock(&dst_mod_info, 1);

cleanup_shm_unlock:
    /* SHM UNLOCK */
    sr_shmmain_unlock(session->conn);

    sr_modinfo_free(&src_mod_info);
    sr_modinfo_free(&dst_mod_info);
    if (cb_err_info) {
        /* return callback error if some was generated */
        sr_errinfo_merge(&err_info, cb_err_info);
        err_info->err_code = SR_ERR_CALLBACK_FAILED;
    }
    return sr_api_ret(session, err_info);
}

static sr_error_info_t *
sr_module_change_subscribe_running_enable(sr_conn_ctx_t *conn, const struct lys_module *ly_mod, const char *xpath,
        sr_module_change_cb callback, void *private_data)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *enabled_data, *node;
    struct sr_mod_info_s mod_info;
    sr_session_ctx_t tmp_sess;
    sr_error_t err_code;

    memset(&mod_info, 0, sizeof mod_info);
    memset(&tmp_sess, 0, sizeof tmp_sess);

    /* create mod_info structure with this module only */
    if ((err_info = sr_shmmod_collect_modules(conn, ly_mod, SR_DS_RUNNING, 0, &mod_info))) {
        return err_info;
    }

    /* MODULES READ LOCK */
    if ((err_info = sr_shmmod_multilock(&mod_info, 0, 0))) {
        sr_modinfo_free(&mod_info);
        return err_info;
    }

    /* get the current running datastore data */
    if ((err_info = sr_modinfo_data_update(&mod_info, MOD_INFO_REQ, NULL))) {
        goto cleanup_mods_unlock;
    }

    /* select only the subscribed-to subtree */
    if (mod_info.mods[0].mod_data) {
        if (xpath) {
            if ((err_info = sr_ly_data_dup_xpath_select(mod_info.mods[0].mod_data, (char **)&xpath, 1, &enabled_data))) {
                goto cleanup_mods_unlock;
            }
        } else {
            enabled_data = mod_info.mods[0].mod_data;
            mod_info.mods[0].mod_data = NULL;
        }
    }

    /* these data will be presented as newly created, make such a diff */
    if (enabled_data) {
        mod_info.diff = enabled_data;
        mod_info.mods[0].state |= MOD_INFO_CHANGED;

        LY_TREE_FOR(enabled_data, node) {
            if ((err_info = sr_edit_set_oper(node, "create"))) {
                goto cleanup_mods_unlock;
            }
        }
    }

    if (mod_info.diff) {
        tmp_sess.conn = conn;
        tmp_sess.ds = mod_info.ds;
        tmp_sess.dt[tmp_sess.ds].diff = mod_info.diff;

        tmp_sess.ev = SR_EV_CHANGE;
        SR_LOG_INF("Triggering \"%s\" \"%s\" event on enabled data.", ly_mod->name, sr_ev2str(tmp_sess.ev));

        /* present all changes in a regular "change" event */
        err_code = callback(&tmp_sess, ly_mod->name, xpath, tmp_sess.ev, private_data);
        if (err_code != SR_ERR_OK) {
            /* callback failed but it is the only one so no "abort" event is necessary */
            sr_errinfo_new(&err_info, SR_ERR_CALLBACK_FAILED, NULL, "Subscribing to \"%s\" changes failed.", ly_mod->name);
            if (tmp_sess.err_info && (tmp_sess.err_info->err_code == SR_ERR_OK)) {
                /* remember callback error info */
                sr_errinfo_merge(&err_info, tmp_sess.err_info);
            }
            goto cleanup_mods_unlock;
        }

        /* finish with a "done" event just because this event should imitate a regular configuration change */
        tmp_sess.ev = SR_EV_DONE;
        SR_LOG_INF("Triggering \"%s\" \"%s\" event on enabled data.", ly_mod->name, sr_ev2str(tmp_sess.ev));

        callback(&tmp_sess, ly_mod->name, xpath, tmp_sess.ev, private_data);
    }

    /* success */

cleanup_mods_unlock:
    /* MODULES UNLOCK */
    sr_shmmod_multiunlock(&mod_info, 0);

    sr_modinfo_free(&mod_info);
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
    sr_datastore_t ds = SR_DS_COUNT;
    sr_subscr_options_t sub_opts;

    SR_CHECK_ARG_APIRET(!session || (session->ds == SR_DS_OPERATIONAL) || !module_name || !callback ||
            ((opts & SR_SUBSCR_PASSIVE) && (opts & SR_SUBSCR_ENABLED)) || !subscription, session, err_info);

    conn = session->conn;
    /* only these options are relevant outside this function and will be stored */
    sub_opts = opts & (SR_SUBSCR_DONE_ONLY | SR_SUBSCR_PASSIVE | SR_SUBSCR_UPDATE);
    if (opts & SR_SUBSCR_UPDATE) {
        /* we must subscribe to both <running> and <startup> */
        ds = (session->ds == SR_DS_RUNNING) ? SR_DS_STARTUP : SR_DS_RUNNING;
        SR_LOG_INF("Subscription to \"%s\" changing data will be triggered for both running and startup DS.",
                xpath ? xpath : module_name);
    }

    /* SHM WRITE LOCK */
    if ((err_info = sr_shmmain_lock_remap(conn, 1))) {
        return sr_api_ret(session, err_info);
    }

    /* is the module name valid? */
    ly_mod = ly_ctx_get_module(conn->ly_ctx, module_name, NULL, 1);
    if (!ly_mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" was not found in sysrepo.", module_name);
        sr_shmmain_unlock(conn);
        return sr_api_ret(session, err_info);
    }

    /* add module subscription into main SHM */
    if ((err_info = sr_shmmod_conf_subscription(conn, module_name, xpath, session->ds, priority, sub_opts, 1))) {
        sr_shmmain_unlock(conn);
        return sr_api_ret(session, err_info);
    }
    if (ds != SR_DS_COUNT) {
        if ((err_info = sr_shmmod_conf_subscription(conn, module_name, xpath, ds, priority, sub_opts, 1))) {
            sr_shmmain_unlock(conn);
            sr_shmmod_conf_subscription(conn, module_name, xpath, session->ds, priority, sub_opts, 0);
            return sr_api_ret(session, err_info);
        }
    }

    if (!(opts & SR_SUBSCR_CTX_REUSE)) {
        /* create a new subscription */
        if ((err_info = sr_subs_new(conn, subscription))) {
            sr_shmmod_conf_subscription(conn, module_name, xpath, session->ds, priority, sub_opts, 0);
            if (ds != SR_DS_COUNT) {
                sr_shmmod_conf_subscription(conn, module_name, xpath, ds, priority, sub_opts, 0);
            }
            sr_shmmain_unlock(conn);
            return sr_api_ret(session, err_info);
        }
    }

    /* add subscription into structure and create separate specific SHM segment */
    if ((err_info = sr_sub_conf_add(module_name, xpath, session->ds, callback, private_data, priority, sub_opts,
            *subscription))) {
        sr_shmmain_unlock(conn);
        goto error_unsubscribe;
    }
    if (ds != SR_DS_COUNT) {
        if ((err_info = sr_sub_conf_add(module_name, xpath, ds, callback, private_data, priority, sub_opts,
                *subscription))) {
            sr_shmmain_unlock(conn);
            goto error_unsubscribe;
        }
    }

    /* call the callback with the current running configuration so that it is properly applied */
    if (((session->ds == SR_DS_RUNNING) || (ds == SR_DS_RUNNING)) && (opts & SR_SUBSCR_ENABLED)) {
        if ((err_info = sr_module_change_subscribe_running_enable(conn, ly_mod, xpath, callback, private_data))) {
            sr_shmmain_unlock(conn);
            goto error_unsubscribe;
        }
    }

    /* SHM UNLOCK */
    sr_shmmain_unlock(conn);

    if (!(opts & SR_SUBSCR_CTX_REUSE)) {
        /* PTR LOCK */
        if ((err_info = sr_lock(&conn->ptr_lock, __func__))) {
            goto error_unsubscribe;
        }

        /* add the subscription into conn */
        if ((err_info = sr_conn_ptr_add((void ***)&conn->subscriptions, &conn->subscription_count, *subscription))) {
            sr_unlock(&conn->ptr_lock);
            goto error_unsubscribe;
        }

        /* PTR UNLOCK */
        sr_unlock(&conn->ptr_lock);
    }

    return sr_api_ret(session, NULL);

error_unsubscribe:
    if (opts & SR_SUBSCR_CTX_REUSE) {
        sr_sub_conf_del(module_name, xpath, session->ds, callback, private_data, priority, sub_opts, *subscription);
    } else {
        sr_unsubscribe(*subscription);
    }
    sr_shmmod_conf_subscription(conn, module_name, xpath, session->ds, priority, sub_opts, 0);
    if (ds != SR_DS_COUNT) {
        sr_shmmod_conf_subscription(conn, module_name, xpath, ds, priority, sub_opts, 0);
    }
    return sr_api_ret(session, err_info);
}

API int
sr_unsubscribe(sr_subscription_ctx_t *subscription)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    int ret;
    struct timespec ts;
    pthread_t tid;

    if (!subscription) {
        return sr_api_ret(NULL, NULL);
    }

    /* PTR LOCK */
    if ((err_info = sr_lock(&subscription->conn->ptr_lock, __func__))) {
        return sr_api_ret(NULL, err_info);
    }

    /* remove ourselves from conn sessions */
    sr_conn_ptr_del((void ***)&subscription->conn->subscriptions, &subscription->conn->subscription_count, subscription);

    /* PTR UNLOCK */
    sr_unlock(&subscription->conn->ptr_lock);

    if (subscription->tid) {
        tid = subscription->tid;

        /* signal the thread to quit */
        subscription->tid = 0;

        /* join the thread */
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += SR_SUBSCR_JOIN_TIMEOUT;
        ret = pthread_timedjoin_np(tid, NULL, &ts);
        if (ret) {
            sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Waiting for the subscriber thread failed (%s).", strerror(ret));
            pthread_detach(tid);
            pthread_cancel(tid);
        }
    }

    /* SHM WRITE LOCK */
    if ((tmp_err = sr_shmmain_lock_remap(subscription->conn, 1))) {
        sr_errinfo_merge(&err_info, tmp_err);
        return sr_api_ret(NULL, err_info);
    }

    if ((tmp_err = sr_subs_del_all(subscription->conn, subscription))) {
        /* SHM UNLOCK */
        sr_shmmain_unlock(subscription->conn);
        sr_errinfo_merge(&err_info, tmp_err);
        return sr_api_ret(NULL, err_info);
    }

    /* SHM UNLOCK */
    sr_shmmain_unlock(subscription->conn);

    pthread_mutex_destroy(&subscription->subs_lock);
    free(subscription);
    return sr_api_ret(NULL, err_info);
}

API int
sr_get_changes_iter(sr_session_ctx_t *session, const char *xpath, sr_change_iter_t **iter)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session || (session->ds == SR_DS_OPERATIONAL) || !xpath || !iter, session, err_info);

    if (session->ev == SR_EV_NONE) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Trying to get changes from an invalid session.");
        return sr_api_ret(session, err_info);
    }

    if (!session->dt[session->ds].diff) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Session without changes.");
        return sr_api_ret(session, err_info);
    }

    *iter = malloc(sizeof **iter);
    if (!*iter) {
        SR_ERRINFO_MEM(&err_info);
        return sr_api_ret(session, err_info);
    }

    (*iter)->set = lyd_find_path(session->dt[session->ds].diff, xpath);
    SR_CHECK_MEM_GOTO(!(*iter)->set, err_info, error);
    (*iter)->idx = 0;
    if (session->ev == SR_EV_ABORT) {
        (*iter)->reverse_changes = 1;
    } else {
        (*iter)->reverse_changes = 0;
    }

    return sr_api_ret(session, NULL);

error:
    free(*iter);
    return sr_api_ret(session, err_info);
}

static sr_error_info_t *
sr_lyd_node2sr_val(const struct lyd_node *node, const char *llist_value_str, const char *keys_predicate, sr_val_t **sr_val_p)
{
    char *ptr;
    sr_error_info_t *err_info = NULL;
    uint32_t start, end;
    sr_val_t *sr_val;
    struct lyd_node_leaf_list *leaf;
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
        /* fix the xpath if needed */
        if (llist_value_str) {
            end = strlen(sr_val->xpath) - 1;
            assert(((sr_val->xpath[end - 1] == '\'') || (sr_val->xpath[end - 1] == '\"')) && (sr_val->xpath[end] == ']'));

            for (ptr = sr_val->xpath + end - 2; ptr[0] != sr_val->xpath[end - 1]; --ptr) {
                SR_CHECK_INT_GOTO(ptr == sr_val->xpath, err_info, error);
            }
            start = ptr - sr_val->xpath;

            /* enlarge string if needed */
            if (strlen(llist_value_str) + 2 > end - start) {
                /* original length + the difference + ending 0 */
                sr_val->xpath = sr_realloc(sr_val->xpath, (end + 1) + ((strlen(llist_value_str) + 2) - (end - start)) + 1);
                SR_CHECK_MEM_GOTO(!sr_val->xpath, err_info, error);
            }

            /* replace the value */
            if (strchr(llist_value_str, '\'')) {
                sprintf(sr_val->xpath + start, "\"%s\"]", llist_value_str);
            } else {
                sprintf(sr_val->xpath + start, "'%s']", llist_value_str);
            }
        }
        /* fallthrough */
    case LYS_LEAF:
        leaf = (struct lyd_node_leaf_list *)node;
        if (!llist_value_str) {
            llist_value_str = leaf->value_str;
        }

        switch (leaf->value_type) {
        case LY_TYPE_BINARY:
            sr_val->type = SR_BINARY_T;
            sr_val->data.binary_val = strdup(llist_value_str);
            break;
        case LY_TYPE_BITS:
            sr_val->type = SR_BITS_T;
            sr_val->data.bits_val = strdup(llist_value_str);
            break;
        case LY_TYPE_BOOL:
            sr_val->type = SR_BOOL_T;
            if (!strcmp(llist_value_str, "true")) {
                sr_val->data.bool_val = true;
            } else {
                sr_val->data.bool_val = false;
            }
            break;
        case LY_TYPE_DEC64:
            sr_val->type = SR_DECIMAL64_T;
            sr_val->data.decimal64_val = strtod(llist_value_str, &ptr);
            if (ptr[0]) {
                sr_errinfo_new(&err_info, SR_ERR_INTERNAL, NULL, "Conversion of \"%s\" to double failed (%s).",
                        llist_value_str, strerror(errno));
                goto error;
            }
            break;
        case LY_TYPE_EMPTY:
            sr_val->type = SR_LEAF_EMPTY_T;
            break;
        case LY_TYPE_ENUM:
            sr_val->type = SR_ENUM_T;
            sr_val->data.enum_val = strdup(llist_value_str);
            break;
        case LY_TYPE_IDENT:
            sr_val->type = SR_IDENTITYREF_T;
            sr_val->data.identityref_val = strdup(llist_value_str);
            break;
        case LY_TYPE_INST:
            sr_val->type = SR_INSTANCEID_T;
            sr_val->data.instanceid_val = strdup(llist_value_str);
            break;
        case LY_TYPE_STRING:
            sr_val->type = SR_STRING_T;
            sr_val->data.string_val = strdup(llist_value_str);
            break;
        case LY_TYPE_INT8:
            sr_val->type = SR_INT8_T;
            sr_val->data.int8_val = strtoll(llist_value_str, &ptr, 10);
            SR_CHECK_INT_GOTO(ptr[0], err_info, error);
            break;
        case LY_TYPE_INT16:
            sr_val->type = SR_INT16_T;
            sr_val->data.int16_val = strtoll(llist_value_str, &ptr, 10);
            SR_CHECK_INT_GOTO(ptr[0], err_info, error);
            break;
        case LY_TYPE_INT32:
            sr_val->type = SR_INT32_T;
            sr_val->data.int32_val = strtoll(llist_value_str, &ptr, 10);
            SR_CHECK_INT_GOTO(ptr[0], err_info, error);
            break;
        case LY_TYPE_INT64:
            sr_val->type = SR_INT64_T;
            sr_val->data.int64_val = strtoll(llist_value_str, &ptr, 10);
            SR_CHECK_INT_GOTO(ptr[0], err_info, error);
            break;
        case LY_TYPE_UINT8:
            sr_val->type = SR_UINT8_T;
            sr_val->data.uint8_val = strtoull(llist_value_str, &ptr, 10);
            SR_CHECK_INT_GOTO(ptr[0], err_info, error);
            break;
        case LY_TYPE_UINT16:
            sr_val->type = SR_UINT16_T;
            sr_val->data.uint16_val = strtoull(llist_value_str, &ptr, 10);
            SR_CHECK_INT_GOTO(ptr[0], err_info, error);
            break;
        case LY_TYPE_UINT32:
            sr_val->type = SR_UINT32_T;
            sr_val->data.uint32_val = strtoull(llist_value_str, &ptr, 10);
            SR_CHECK_INT_GOTO(ptr[0], err_info, error);
            break;
        case LY_TYPE_UINT64:
            sr_val->type = SR_UINT64_T;
            sr_val->data.uint64_val = strtoull(llist_value_str, &ptr, 10);
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
    struct lyd_node *node, *parent;
    const char *attr_name, *attr_mod_name;
    sr_change_oper_t op;

    SR_CHECK_ARG_APIRET(!session || (session->ds == SR_DS_OPERATIONAL) || !iter || !operation || !old_value || !new_value,
            session, err_info);

next_item:
    if (iter->idx == iter->set->number) {
        return SR_ERR_NOT_FOUND;
    }
    node = iter->set->set.d[iter->idx];

    /* find the (inherited) operation of the current edit node */
    attr = NULL;
    for (parent = node; parent; parent = parent->parent) {
        for (attr = parent->attr; attr && strcmp(attr->name, "operation"); attr = attr->next);
        if (attr) {
            break;
        }
    }
    if (!attr) {
        SR_ERRINFO_INT(&err_info);
        return sr_api_ret(session, err_info);
    }

    if (lys_is_key((struct lys_node_leaf *)node->schema, NULL) && sr_ly_is_userord(node->parent) && (attr->value_str[0] == 'r')) {
        /* skip keys of list move operations */
        ++iter->idx;
        goto next_item;
    }

    /* decide operation */
    if (attr->value_str[0] == 'n') {
        assert(!strcmp(attr->annotation->module->name, SR_YANG_MOD));
        assert(!strcmp(attr->value_str, "none"));
        /* skip the node */
        ++iter->idx;

        /* in case of lists we want to also skip all their keys */
        if (node->schema->nodetype == LYS_LIST) {
            iter->idx += ((struct lys_node_list *)node->schema)->keys_size;
        }
        goto next_item;
    } else if (attr->value_str[0] == 'c') {
        assert(!strcmp(attr->annotation->module->name, "ietf-netconf"));
        assert(!strcmp(attr->value_str, "create"));
        op = SR_OP_CREATED;
    } else if (attr->value_str[0] == 'd') {
        assert(!strcmp(attr->annotation->module->name, "ietf-netconf"));
        assert(!strcmp(attr->value_str, "delete"));
        op = SR_OP_DELETED;
    } else if (attr->value_str[0] == 'r') {
        assert(!strcmp(attr->annotation->module->name, "ietf-netconf"));
        assert(!strcmp(attr->value_str, "replace"));
        if (node->schema->nodetype == LYS_LEAF) {
            op = SR_OP_MODIFIED;
        } else if (node->schema->nodetype & (LYS_LIST | LYS_LEAFLIST)) {
            op = SR_OP_MOVED;
        } else {
            SR_ERRINFO_INT(&err_info);
            return sr_api_ret(session, err_info);
        }
    }
    if (iter->reverse_changes) {
        /* we are in an abort */
        if (op == SR_OP_CREATED) {
            op = SR_OP_DELETED;
        } else if (op == SR_OP_DELETED) {
            op = SR_OP_CREATED;
        }
    }

    /* create values */
    switch (op) {
    case SR_OP_CREATED:
        *old_value = NULL;
        if ((err_info = sr_lyd_node2sr_val(node, NULL, NULL, new_value))) {
            return sr_api_ret(session, err_info);
        }
        break;
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

        if (iter->reverse_changes) {
            if ((err_info = sr_lyd_node2sr_val(node, NULL, NULL, old_value))) {
                return sr_api_ret(session, err_info);
            }
            if ((err_info = sr_lyd_node2sr_val(node, attr->value_str, NULL, new_value))) {
                return sr_api_ret(session, err_info);
            }
            if (attr2) {
                (*new_value)->dflt = 1;
            } else {
                (*new_value)->dflt = 0;
            }
        } else {
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
        }
        break;
    case SR_OP_MOVED:
        if (node->schema->nodetype == LYS_LEAFLIST) {
            if (iter->reverse_changes) {
                attr_mod_name = SR_YANG_MOD;
                attr_name = "orig-value";
            } else {
                attr_mod_name = "yang";
                attr_name = "value";
            }
        } else {
            assert(node->schema->nodetype == LYS_LIST);
            if (iter->reverse_changes) {
                attr_mod_name = SR_YANG_MOD;
                attr_name = "orig-key";
            } else {
                attr_mod_name = "yang";
                attr_name = "key";
            }
        }
        /* attribute contains the value of the node before in the order */
        for (attr = node->attr;
             attr && (strcmp(attr->annotation->module->name, attr_mod_name) || strcmp(attr->name, attr_name));
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
    ++iter->idx;
    return sr_api_ret(session, NULL);
}

static int
_sr_rpc_subscribe(sr_session_ctx_t *session, const char *xpath, sr_rpc_cb callback, sr_rpc_tree_cb tree_callback,
        void *private_data, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_node *op;
    const char *module_name;
    sr_conn_ctx_t *conn;

    SR_CHECK_ARG_APIRET(!session || !xpath || (!callback && !tree_callback) || !subscription, session, err_info);

    conn = session->conn;

    /* SHM WRITE LOCK */
    if ((err_info = sr_shmmain_lock_remap(conn, 1))) {
        return sr_api_ret(session, err_info);
    }

    /* is the xpath valid? */
    op = ly_ctx_get_node(conn->ly_ctx, NULL, xpath, 0);
    if (!op) {
        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
        sr_shmmain_unlock(conn);
        return sr_api_ret(session, err_info);
    }
    if (!(op->nodetype & (LYS_RPC | LYS_ACTION))) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "XPath \"%s\" does not identify an RPC nor an action.", xpath);
        sr_shmmain_unlock(conn);
        return sr_api_ret(session, err_info);
    }
    module_name = lys_node_module(op)->name;

    /* add RPC/action subscription into main SHM */
    if ((err_info = sr_shmmod_rpc_subscription(conn, module_name, xpath, 1))) {
        sr_shmmain_unlock(conn);
        return sr_api_ret(session, err_info);
    }

    if (!(opts & SR_SUBSCR_CTX_REUSE)) {
        /* create a new subscription */
        if ((err_info = sr_subs_new(conn, subscription))) {
            sr_shmmod_rpc_subscription(conn, module_name, xpath, 0);
            sr_shmmain_unlock(conn);
            return sr_api_ret(session, err_info);
        }
    }

    /* add subscription into structure and create separate specific SHM segment */
    if ((err_info = sr_sub_rpc_add(module_name, xpath, callback, tree_callback, private_data, *subscription))) {
        sr_shmmain_unlock(conn);
        goto error_unsubscribe;
    }

    /* SHM UNLOCK */
    sr_shmmain_unlock(conn);

    if (!(opts & SR_SUBSCR_CTX_REUSE)) {
        /* PTR LOCK */
        if ((err_info = sr_lock(&conn->ptr_lock, __func__))) {
            goto error_unsubscribe;
        }

        /* add the subscription into conn */
        if ((err_info = sr_conn_ptr_add((void ***)&conn->subscriptions, &conn->subscription_count, *subscription))) {
            sr_unlock(&conn->ptr_lock);
            goto error_unsubscribe;
        }

        /* PTR UNLOCK */
        sr_unlock(&conn->ptr_lock);
    }

    return sr_api_ret(session, NULL);

error_unsubscribe:
    if (opts & SR_SUBSCR_CTX_REUSE) {
        sr_sub_rpc_del(xpath, *subscription);
    } else {
        sr_unsubscribe(*subscription);
    }
    sr_shmmod_rpc_subscription(conn, module_name, xpath, 0);
    return sr_api_ret(session, err_info);
}

API int
sr_rpc_subscribe(sr_session_ctx_t *session, const char *xpath, sr_rpc_cb callback, void *private_data,
        sr_subscr_options_t opts, sr_subscription_ctx_t **subscription)
{
    return _sr_rpc_subscribe(session, xpath, callback, NULL, private_data, opts, subscription);
}

API int
sr_rpc_subscribe_tree(sr_session_ctx_t *session, const char *xpath, sr_rpc_tree_cb callback, void *private_data,
        sr_subscr_options_t opts, sr_subscription_ctx_t **subscription)
{
    return _sr_rpc_subscribe(session, xpath, NULL, callback, private_data, opts, subscription);
}

API int
sr_rpc_send(sr_session_ctx_t *session, const char *xpath, const sr_val_t *input, const size_t input_cnt,
        sr_val_t **output, size_t *output_cnt)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *input_tree = NULL, *output_tree, *next, *elem;
    char *val_str, buf[22];
    size_t i;
    int ret;

    SR_CHECK_ARG_APIRET(!session || !output || !output_cnt, session, err_info);

    *output = NULL;
    *output_cnt = 0;

    /* create the container */
    if ((err_info = sr_val_sr2ly(session->conn->ly_ctx, xpath, NULL, 0, 0, &input_tree))) {
        goto cleanup;
    }

    /* transform input into a data tree */
    for (i = 0; i < input_cnt; ++i) {
        val_str = sr_val_sr2ly_str(session->conn->ly_ctx, &input[i], buf);
        if ((err_info = sr_val_sr2ly(session->conn->ly_ctx, input[i].xpath, val_str, input[i].dflt, 0, &input_tree))) {
            goto cleanup;
        }
    }

    /* API function */
    if ((ret = sr_rpc_send_tree(session, input_tree, &output_tree)) != SR_ERR_OK) {
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

static sr_error_info_t *
sr_rpc_find_subscriber(sr_conn_ctx_t *conn, const struct lys_node *rpc, char **xpath)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    sr_mod_rpc_sub_t *shm_subs;
    char *rpc_xpath;
    uint16_t i;

    shm_mod = sr_shmmain_find_module(conn->main_shm.addr, lys_node_module(rpc)->name, 0);
    SR_CHECK_INT_RET(!shm_mod, err_info);

    /* get the path that could be subscribed to */
    rpc_xpath = lys_data_path(rpc);
    SR_CHECK_MEM_RET(!rpc_xpath, err_info);

    /* try to find a subscription */
    shm_subs = (sr_mod_rpc_sub_t *)(conn->main_shm.addr + shm_mod->rpc_subs);
    for (i = 0; i < shm_mod->rpc_sub_count; ++i) {
        if (!strcmp(rpc_xpath, conn->main_shm.addr + shm_subs[i].xpath)) {
            break;
        }
    }

    if (i < shm_mod->rpc_sub_count) {
        *xpath = rpc_xpath;
    } else {
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, NULL, "There is no subscriber to \"%s\" %s.", rpc_xpath,
                (rpc->nodetype == LYS_RPC) ? "RPC" : "action");
        free(rpc_xpath);
    }
    return err_info;
}

API int
sr_rpc_send_tree(sr_session_ctx_t *session, struct lyd_node *input, struct lyd_node **output)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    struct sr_mod_info_s mod_info;
    struct lyd_node *input_op;
    sr_mod_data_dep_t *shm_deps;
    uint16_t shm_dep_count;
    char *xpath = NULL;

    SR_CHECK_ARG_APIRET(!session || !input || !output, session, err_info);

    *output = NULL;
    memset(&mod_info, 0, sizeof mod_info);

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

    /* SHM READ LOCK */
    if ((err_info = sr_shmmain_lock_remap(session->conn, 0))) {
        return sr_api_ret(session, err_info);
    }

    /* check that there is a subscriber */
    if ((err_info = sr_rpc_find_subscriber(session->conn, input_op->schema, &xpath))) {
        goto cleanup_shm_unlock;
    }

    /* collect all required modules for input validation (including checking that the nested action
     * can be invoked meaning its parent data node exists) */
    if ((err_info = sr_shmmod_collect_op(session->conn, xpath, input_op, 0, &shm_deps, &shm_dep_count, &mod_info))) {
        goto cleanup_shm_unlock;
    }

    /* MODULES READ LOCK */
    if ((err_info = sr_shmmod_multilock(&mod_info, 0, 0))) {
        goto cleanup_mods_unlock;
    }

    /* load all input dependency modules data */
    if ((err_info = sr_modinfo_data_update(&mod_info, MOD_INFO_TYPE_MASK, &cb_err_info)) || cb_err_info) {
        goto cleanup_mods_unlock;
    }

    /* validate the operation */
    if ((err_info = sr_modinfo_op_validate(&mod_info, input_op, shm_deps, shm_dep_count, 0))) {
        goto cleanup_mods_unlock;
    }

    /* publish RPC in an event for a subscriber and wait for a reply */
    if ((err_info = sr_shmsub_rpc_notify(xpath, input, output, &cb_err_info)) || cb_err_info) {
        goto cleanup_mods_unlock;
    }

    /* MODULES UNLOCK */
    sr_shmmod_multiunlock(&mod_info, 0);

    /* find operation */
    if ((err_info = sr_ly_find_last_parent(output, LYS_RPC | LYS_ACTION))) {
        goto cleanup_shm_unlock;
    }

    /* collect all required modules for output validation */
    sr_modinfo_free(&mod_info);
    memset(&mod_info, 0, sizeof mod_info);
    if ((err_info = sr_shmmod_collect_op(session->conn, xpath, *output, 1, &shm_deps, &shm_dep_count, &mod_info))) {
        goto cleanup_shm_unlock;
    }

    /* MODULES READ LOCK */
    if ((err_info = sr_shmmod_multilock(&mod_info, 0, 0))) {
        goto cleanup_mods_unlock;
    }

    /* load all output dependency modules data */
    if ((err_info = sr_modinfo_data_update(&mod_info, MOD_INFO_TYPE_MASK, &cb_err_info)) || cb_err_info) {
        goto cleanup_mods_unlock;
    }

    /* validate the operation */
    if ((err_info = sr_modinfo_op_validate(&mod_info, *output, shm_deps, shm_dep_count, 1))) {
        goto cleanup_mods_unlock;
    }

    /* success */

cleanup_mods_unlock:
    /* MODULES UNLOCK */
    sr_shmmod_multiunlock(&mod_info, 0);

cleanup_shm_unlock:
    /* SHM UNLOCK */
    sr_shmmain_unlock(session->conn);

    free(xpath);
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

static sr_error_info_t *
_sr_event_notif_subscribe(sr_conn_ctx_t *conn, const struct lys_module *ly_mod, const char *xpath, time_t start_time,
        time_t stop_time, sr_event_notif_cb callback, sr_event_notif_tree_cb tree_callback, void *private_data,
        sr_subscr_options_t opts, sr_subscription_ctx_t **subscription)
{
    sr_error_info_t *err_info = NULL, *tmp_err_info;
    struct ly_set *set;
    const struct lys_node *ctx_node;
    uint32_t i;
    int shm_locked = 0;

    assert((callback && !tree_callback) || (!callback && tree_callback));

    /* is the xpath valid, if any? */
    if (xpath) {
        ctx_node = lys_getnext(NULL, NULL, ly_mod, 0);
        if (!ctx_node) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" does not define any notifications.", ly_mod->name);
            return err_info;
        }

        set = lys_xpath_atomize(ctx_node, LYXP_NODE_ELEM, xpath, 0);
    } else {
        set = lys_find_path(ly_mod, NULL, "//.");
    }
    if (!set) {
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

    /* there must be some notifications selected */
    for (i = 0; i < set->number; ++i) {
        if (set->set.s[i]->nodetype == LYS_NOTIF) {
            break;
        }
    }
    if (i == set->number) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "XPath \"%s\" does not select any notifications.", xpath);
        ly_set_free(set);
        return err_info;
    }
    ly_set_free(set);

    /* SHM WRITE LOCK */
    if ((err_info = sr_shmmain_lock_remap(conn, 1))) {
        return err_info;
    }
    shm_locked = 1;

    if (!start_time) {
        /* add notification subscription into main SHM if replay was not requested */
        if ((err_info = sr_shmmod_notif_subscription(conn, ly_mod->name, 1))) {
            sr_shmmain_unlock(conn);
            return err_info;
        }
    }

    if (!(opts & SR_SUBSCR_CTX_REUSE)) {
        /* create a new subscription */
        if ((err_info = sr_subs_new(conn, subscription))) {
            sr_shmmod_notif_subscription(conn, ly_mod->name, 0);
            sr_shmmain_unlock(conn);
            return err_info;
        }
    }

    /* add subscription into structure and create separate specific SHM segment */
    if ((err_info = sr_sub_notif_add(ly_mod->name, xpath, start_time, stop_time, callback, tree_callback, private_data,
            *subscription))) {
        goto error_unsubscribe;
    }

    /* SHM UNLOCK */
    sr_shmmain_unlock(conn);
    shm_locked = 0;

    if (!(opts & SR_SUBSCR_CTX_REUSE)) {
        /* PTR LOCK */
        if ((err_info = sr_lock(&conn->ptr_lock, __func__))) {
            goto error_unsubscribe;
        }

        /* add the subscription into conn */
        if ((err_info = sr_conn_ptr_add((void ***)&conn->subscriptions, &conn->subscription_count, *subscription))) {
            sr_unlock(&conn->ptr_lock);
            goto error_unsubscribe;
        }

        /* PTR UNLOCK */
        sr_unlock(&conn->ptr_lock);
    }

    return NULL;

error_unsubscribe:
    if (!shm_locked) {
        /* SHM WRITE LOCK */
        tmp_err_info = sr_shmmain_lock_remap(conn, 1);
        sr_errinfo_free(&tmp_err_info);
    }

    sr_shmmod_notif_subscription(conn, ly_mod->name, 0);

    /* SHM UNLOCK */
    sr_shmmain_unlock(conn);

    if (opts & SR_SUBSCR_CTX_REUSE) {
        sr_sub_notif_del(ly_mod->name, xpath, start_time, stop_time, callback, tree_callback, private_data, *subscription, 0);
    } else {
        sr_unsubscribe(*subscription);
    }
    return err_info;
}

API int
sr_event_notif_subscribe(sr_session_ctx_t *session, const char *module_name, const char *xpath, time_t start_time,
        time_t stop_time, sr_event_notif_cb callback, void *private_data, sr_subscr_options_t opts,
        sr_subscription_ctx_t **subscription)
{
    sr_error_info_t *err_info = NULL;
    time_t cur_ts = time(NULL);
    const struct lys_module *ly_mod;

    SR_CHECK_ARG_APIRET(!session || !module_name || (start_time && (start_time > cur_ts))
            || (stop_time && (!start_time || (stop_time < start_time))) || !callback || !subscription, session, err_info);

    /* SHM READ LOCK */
    if ((err_info = sr_shmmain_lock_remap(session->conn, 0))) {
        return sr_api_ret(session, err_info);
    }

    /* is the module name valid? */
    ly_mod = ly_ctx_get_module(session->conn->ly_ctx, module_name, NULL, 1);
    if (!ly_mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" was not found in sysrepo.", module_name);
        sr_shmmain_unlock(session->conn);
        return sr_api_ret(session, err_info);
    }

    /* SHM UNLOCK */
    sr_shmmain_unlock(session->conn);

    /* subscribe */
    err_info = _sr_event_notif_subscribe(session->conn, ly_mod, xpath, start_time, stop_time, callback, NULL,
            private_data, opts, subscription);
    return sr_api_ret(session, err_info);
}

API int
sr_event_notif_subscribe_tree(sr_session_ctx_t *session, const char *module_name, const char *xpath, time_t start_time,
        time_t stop_time, sr_event_notif_tree_cb callback, void *private_data, sr_subscr_options_t opts,
        sr_subscription_ctx_t **subscription)
{
    sr_error_info_t *err_info = NULL;
    time_t cur_ts = time(NULL);
    const struct lys_module *ly_mod;

    SR_CHECK_ARG_APIRET(!session || !module_name || (start_time && (start_time > cur_ts))
            || (stop_time && (!start_time || (stop_time < start_time))) || !callback || !subscription, session, err_info);

    /* SHM READ LOCK */
    if ((err_info = sr_shmmain_lock_remap(session->conn, 0))) {
        return sr_api_ret(session, err_info);
    }

    /* is the module name valid? */
    ly_mod = ly_ctx_get_module(session->conn->ly_ctx, module_name, NULL, 1);
    if (!ly_mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" was not found in sysrepo.", module_name);
        sr_shmmain_unlock(session->conn);
        return sr_api_ret(session, err_info);
    }

    /* SHM UNLOCK */
    sr_shmmain_unlock(session->conn);

    /* subscribe */
    err_info = _sr_event_notif_subscribe(session->conn, ly_mod, xpath, start_time, stop_time, NULL, callback,
            private_data, opts, subscription);
    return sr_api_ret(session, err_info);
}

API int
sr_event_notif_send(sr_session_ctx_t *session, const char *xpath, const sr_val_t *values, const size_t values_cnt,
        sr_ev_notif_flag_t opts)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *notif_tree = NULL;
    char *val_str, buf[22];
    size_t i;
    int ret;

    SR_CHECK_ARG_APIRET(!session || !xpath, session, err_info);

    /* create the container */
    if ((err_info = sr_val_sr2ly(session->conn->ly_ctx, xpath, NULL, 0, 0, &notif_tree))) {
        goto cleanup;
    }

    /* transform values into a data tree */
    for (i = 0; i < values_cnt; ++i) {
        val_str = sr_val_sr2ly_str(session->conn->ly_ctx, &values[i], buf);
        if ((err_info = sr_val_sr2ly(session->conn->ly_ctx, values[i].xpath, val_str, values[i].dflt, 0, &notif_tree))) {
            goto cleanup;
        }
    }

    /* API function */
    if ((ret = sr_event_notif_send_tree(session, notif_tree, opts)) != SR_ERR_OK) {
        lyd_free_withsiblings(notif_tree);
        return ret;
    }

    /* success */

cleanup:
    lyd_free_withsiblings(notif_tree);
    return sr_api_ret(session, err_info);
}

static sr_error_info_t *
sr_notif_find_subscriber(sr_conn_ctx_t *conn, const char *mod_name, uint32_t *notif_sub_count)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;

    shm_mod = sr_shmmain_find_module(conn->main_shm.addr, mod_name, 0);
    SR_CHECK_INT_RET(!shm_mod, err_info);

    *notif_sub_count = shm_mod->notif_sub_count;
    return NULL;
}

API int
sr_event_notif_send_tree(sr_session_ctx_t *session, struct lyd_node *notif, sr_ev_notif_flag_t opts)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL, *tmp_err_info = NULL;
    struct sr_mod_info_s mod_info;
    struct lyd_node *notif_op;
    sr_mod_data_dep_t *shm_deps;
    time_t notif_ts;
    uint16_t shm_dep_count;
    uint32_t notif_sub_count;
    char *xpath = NULL;

    SR_CHECK_ARG_APIRET(!session || !notif, session, err_info);

    memset(&mod_info, 0, sizeof mod_info);

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

    /* SHM READ LOCK */
    if ((err_info = sr_shmmain_lock_remap(session->conn, 0))) {
        return sr_api_ret(session, err_info);
    }

    /* collect all required modules for validation (including checking that the nested notification
     * can be invoked meaning its parent data node exists) */
    xpath = lys_data_path(notif_op->schema);
    SR_CHECK_MEM_GOTO(!xpath, err_info, cleanup_shm_unlock);
    if ((err_info = sr_shmmod_collect_op(session->conn, xpath, notif_op, 0, &shm_deps, &shm_dep_count, &mod_info))) {
        goto cleanup_shm_unlock;
    }

    /* MODULES READ LOCK */
    if ((err_info = sr_shmmod_multilock(&mod_info, 0, 0))) {
        goto cleanup_mods_unlock;
    }

    /* load all input dependency modules data */
    if ((err_info = sr_modinfo_data_update(&mod_info, MOD_INFO_TYPE_MASK, &cb_err_info)) || cb_err_info) {
        goto cleanup_mods_unlock;
    }

    /* validate the operation */
    if ((err_info = sr_modinfo_op_validate(&mod_info, notif_op, shm_deps, shm_dep_count, 0))) {
        goto cleanup_mods_unlock;
    }

    /* MODULES UNLOCK */
    sr_shmmod_multiunlock(&mod_info, 0);

    /* store the notification for a replay, we continue on failure */
    err_info = sr_replay_store(session->conn, notif, notif_ts);

    /* check that there is a subscriber */
    if ((tmp_err_info = sr_notif_find_subscriber(session->conn, lyd_node_module(notif)->name, &notif_sub_count))) {
        goto cleanup_shm_unlock;
    }

    if (notif_sub_count) {
        /* publish notif in an event, do not wait for subscribers */
        if ((tmp_err_info = sr_shmsub_notif_notify(notif, notif_ts, notif_sub_count))) {
            goto cleanup_shm_unlock;
        }
    } else {
        SR_LOG_INF("There are no subscribers for \"%s\" notifications.", lyd_node_module(notif)->name);
    }

    /* success */
    goto cleanup_shm_unlock;

cleanup_mods_unlock:
    /* MODULES UNLOCK */
    sr_shmmod_multiunlock(&mod_info, 0);

cleanup_shm_unlock:
    /* SHM UNLOCK */
    sr_shmmain_unlock(session->conn);

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

API void
sr_free_change_iter(sr_change_iter_t *iter)
{
    if (!iter) {
        return;
    }

    ly_set_free(iter->set);
    free(iter);
}
