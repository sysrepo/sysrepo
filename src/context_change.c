/**
 * @file context_change.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Sysrepo context change routines
 *
 * @copyright
 * Copyright (c) 2021 - 2022 Deutsche Telekom AG.
 * Copyright (c) 2021 - 2022 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "compat.h"
#include "context_change.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include <libyang/libyang.h>

#include "common.h"
#include "common_types.h"
#include "config.h"
#include "log.h"
#include "ly_wrap.h"
#include "lyd_mods.h"
#include "modinfo.h"
#include "plugins_datastore.h"
#include "plugins_notification.h"
#include "shm_ext.h"
#include "shm_mod.h"
#include "sysrepo.h"
#include "sysrepo_types.h"

/**
 * @brief Replace the current global libyang context with a new one.
 *
 * @param[in] conn Connection to use.
 * @param[in] new_ctx New context to replace the current one with.
 */
static void
sr_ly_ctx_switch(sr_conn_ctx_t *conn, struct ly_ctx *new_ctx)
{
    /* update content ID */
    sr_yang_ctx.content_id = SR_CONN_MAIN_SHM(conn)->content_id;

    /* update schema mount data ID */
    sr_yang_ctx.sm_data_id = SR_CONN_MAIN_SHM(conn)->schema_mount_data_id;

    /* replace the global context */
    sr_yang_ctx.ly_ctx = new_ctx;
}

/**
 * @brief Load all modules from mod SHM into a context.
 *
 * @param[in,out] ly_ctx Context to use.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_ly_ctx_init(struct ly_ctx *ly_ctx)
{
    sr_error_info_t *err_info = NULL, *tmp_err = NULL;
    char *path = NULL;

    /* load modules from the SHM */
    if ((err_info = sr_shmmod_ctx_load_modules(SR_CTX_MOD_SHM(sr_yang_ctx), ly_ctx, NULL))) {
        if (!strcmp(err_info->err[err_info->err_count - 1].message, "Loading \"ietf-datastores\" module failed.")) {
            if (!(tmp_err = sr_path_yang_dir(&path))) {
                sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED,
                        "YANG modules directory \"%s\" is different than the one used when creating the SHM state. "
                        "Either change the SHM state files prefix, too, or clear the current SHM state.",
                        path);
                free(path);
            } else {
                sr_errinfo_merge(&err_info, tmp_err);
            }
        }
    }

    return err_info;
}

/**
 * @brief Check whether the current context is up to date, i.e., it has the same content ID and schema mount data ID.
 *
 * @param[in] main_shm Main SHM.
 * @param[in] content_id Content ID of the context to check.
 * @param[in] schema_mount_data_id Schema mount data ID of the context to check.
 * @return 1 if the context is up to date, 0 otherwise.
 */
static int
context_is_up_to_date(sr_main_shm_t *main_shm, uint32_t content_id, uint32_t schema_mount_data_id)
{
    if (main_shm->content_id != content_id) {
        /* always a different context */
        return 0;
    }

    if (!SR_PRINTED_LYCTX_ADDRESS || (ATOMIC_LOAD_RELAXED(sr_yang_ctx.sr_opts) & SR_CTX_NO_PRINTED)) {
        /* only YANG modules matter, schema-mount contexts can be created as needed for dynamic contexts */
        return 1;
    }

    if (main_shm->schema_mount_data_id != schema_mount_data_id) {
        /* printed context needs its schema-mount shared contexts updated */
        return 0;
    }

    return 1;
}

sr_error_info_t *
sr_lycc_lock(sr_conn_ctx_t *conn, sr_lock_mode_t mode, int lydmods_lock, const char *func)
{
    sr_error_info_t *err_info = NULL;
    sr_main_shm_t *main_shm = SR_CONN_MAIN_SHM(conn);
    sr_lock_mode_t remap_mode = SR_LOCK_NONE;
    struct ly_ctx *new_ctx = NULL;

    /* CONTEXT LOCK */
    if ((err_info = sr_rwlock(&main_shm->context_lock, SR_CONTEXT_LOCK_TIMEOUT, mode, conn->cid, func, NULL, NULL))) {
        return err_info;
    }

    /* MOD REMAP LOCK */
    if ((err_info = sr_rwlock(&sr_yang_ctx.remap_lock, SR_REMAP_LOCK_TIMEOUT, SR_LOCK_READ_UPGR, conn->cid, func, NULL, NULL))) {
        goto cleanup_unlock;
    }
    remap_mode = SR_LOCK_READ_UPGR;

    if (mode == SR_LOCK_READ_UPGR) {
        /* flush caches so that the lock can actually be upgraded */
        sr_run_cache_flush(conn, &sr_run_cache);
        sr_oper_cache_flush(conn, &sr_oper_cache);
    }

    /* check whether the context is current and does not need to be updated */
    if (!context_is_up_to_date(main_shm, sr_yang_ctx.content_id, sr_yang_ctx.sm_data_id)) {
        /* MOD REMAP UPGRADE */
        if ((err_info = sr_rwrelock(&sr_yang_ctx.remap_lock, SR_REMAP_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, func, NULL, NULL))) {
            goto cleanup_unlock;
        }
        remap_mode = SR_LOCK_WRITE;

        /* check the context again, another thread may have already updated it */
        if (context_is_up_to_date(main_shm, sr_yang_ctx.content_id, sr_yang_ctx.sm_data_id)) {
            /* context is current, abort the switch */

            /* MOD REMAP DOWNGRADE */
            if ((err_info = sr_rwrelock(&sr_yang_ctx.remap_lock, SR_REMAP_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, func, NULL, NULL))) {
                goto cleanup_unlock;
            }
            remap_mode = SR_LOCK_READ;
            goto cleanup_unlock;
        }

        /* remap mod SHM */
        if ((err_info = sr_shm_remap(&sr_yang_ctx.mod_shm, 0))) {
            goto cleanup_unlock;
        }

        /* flush caches */
        sr_run_cache_flush(conn, &sr_run_cache);
        sr_oper_cache_flush(conn, &sr_oper_cache);

        /* destroy the old context, because if it was printed then another process could have
         * been the one that printed it = this process did not destroy the old context while printing the new one,
         * so it needs to be done now to avoid context data collision, see ::sr_lycc_store_context() */
        sr_yang_ctx.content_id = 0;
        sr_yang_ctx.sm_data_id = 0;
        ly_ctx_destroy(sr_yang_ctx.ly_ctx);
        sr_yang_ctx.ly_ctx = NULL;

        /* get the printed context from the SHM if it is supported/available */
        if ((err_info = sr_lycc_load_context(&sr_yang_ctx.ly_ctx_shm, &new_ctx))) {
            goto cleanup_unlock;
        }
        if (!new_ctx) {
            /* failed to get the printed context, create a new non-printed one */
            if ((err_info = sr_ly_ctx_new(&new_ctx))) {
                goto cleanup_unlock;
            }

            /* load all modules into the new context */
            if ((err_info = sr_ly_ctx_init(new_ctx))) {
                goto cleanup_unlock;
            }
        }

        /* set the ext callback */
        ly_ctx_set_ext_data_clb(new_ctx, sr_ly_ext_data_clb, NULL);

        /* use the new context */
        sr_ly_ctx_switch(conn, new_ctx);

        /* context successfully switched */
        new_ctx = NULL;

        /* initialize new DS plugins not used by any modules before */
        if ((err_info = sr_conn_ds_init(conn))) {
            goto cleanup_unlock;
        }
    }

    /* MOD REMAP DOWNGRADE */
    if ((err_info = sr_rwrelock(&sr_yang_ctx.remap_lock, SR_REMAP_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, func, NULL, NULL))) {
        goto cleanup_unlock;
    }
    remap_mode = SR_LOCK_READ;

    /* LYDMODS LOCK */
    if (lydmods_lock && (err_info = sr_mlock(&main_shm->lydmods_lock, SR_CONTEXT_LOCK_TIMEOUT, func, NULL, NULL))) {
        goto cleanup_unlock;
    }

    sr_available_conn = conn;

cleanup_unlock:
    ly_ctx_destroy(new_ctx);
    if (err_info) {
        if (remap_mode) {
            /* MOD REMAP UNLOCK */
            sr_rwunlock(&sr_yang_ctx.remap_lock, SR_REMAP_LOCK_TIMEOUT, remap_mode, conn->cid, func);
        }
        /* CONTEXT UNLOCK */
        sr_rwunlock(&main_shm->context_lock, SR_CONTEXT_LOCK_TIMEOUT, mode, conn->cid, func);
    }
    return err_info;
}

sr_error_info_t *
sr_lycc_relock(sr_conn_ctx_t *conn, sr_lock_mode_t mode, const char *func)
{
    sr_error_info_t *err_info = NULL;
    sr_main_shm_t *main_shm = SR_CONN_MAIN_SHM(conn);
    sr_rwlock_t *rwlock = &main_shm->context_lock;
    struct timespec timeout_abs;
    int rc, r;

    /* when upgrading the context lock (changing the context), make sure there are no cached data left in any process */
    if (mode == SR_LOCK_WRITE) {
        sr_timeouttime_get(&timeout_abs, SR_CONTEXT_LOCK_TIMEOUT);

        /* CONTEXT MUTEX LOCK */
        rc = pthread_mutex_clocklock(&rwlock->mutex, COMPAT_CLOCK_ID, &timeout_abs);
        if (rc == EOWNERDEAD) {
            /* make it consistent */
            rc = pthread_mutex_consistent(&rwlock->mutex);
            SR_CHECK_INT_RET(rc, err_info);
        } else if (rc) {
            sr_errinfo_new_lock(&err_info, func, rc, rwlock);
            return err_info;
        }

        if (main_shm->run_cache_pids[0] || main_shm->oper_cache_pids[0] || main_shm->oper_push_cache_cids[0]) {
            /* instead of waiting, try to recover the PIDs immediately */
            sr_pid_array_recover(main_shm->run_cache_pids, SR_MAIN_SHM_CACHE_PID_SIZE);
            sr_pid_array_recover(main_shm->oper_cache_pids, SR_MAIN_SHM_CACHE_PID_SIZE);
            sr_cid_array_recover(main_shm->oper_push_cache_cids, SR_MAIN_SHM_CACHE_PID_SIZE);
        }

        /* wait until there are no cached data stored */
        rc = 0;
        while (!rc && (main_shm->run_cache_pids[0] || main_shm->oper_cache_pids[0] || main_shm->oper_push_cache_cids[0])) {
            /* COND WAIT */
            rc = sr_cond_clockwait(&rwlock->cond, &rwlock->mutex, COMPAT_CLOCK_ID, &timeout_abs);
        }
        if (rc == ETIMEDOUT) {
            /* recover the PIDs again, the owners may have died while processing */
            sr_pid_array_recover(main_shm->run_cache_pids, SR_MAIN_SHM_CACHE_PID_SIZE);
            sr_pid_array_recover(main_shm->oper_cache_pids, SR_MAIN_SHM_CACHE_PID_SIZE);
            sr_cid_array_recover(main_shm->oper_push_cache_cids, SR_MAIN_SHM_CACHE_PID_SIZE);
            if (!main_shm->run_cache_pids[0] && !main_shm->oper_cache_pids[0] && !main_shm->oper_push_cache_cids[0]) {
                /* recovered */
                rc = 0;
            }
        }

        /* CONTEXT MUTEX UNLOCK */
        r = pthread_mutex_unlock(&rwlock->mutex);
        if (r) {
            sr_errinfo_new(&err_info, SR_ERR_INTERNAL, "Unlocking a mutex in %s() failed (%s).", func, strerror(r));
            sr_errinfo_free(&err_info);
        }

        if (rc) {
            sr_errinfo_new_lock(&err_info, func, rc, rwlock);
            return err_info;
        }
    }

    /* RELOCK */
    if ((err_info = sr_rwrelock(&main_shm->context_lock, SR_CONTEXT_LOCK_TIMEOUT, mode, conn->cid, func, NULL, NULL))) {
        return err_info;
    }

    return NULL;
}

void
sr_lycc_unlock(sr_conn_ctx_t *conn, sr_lock_mode_t mode, int lydmods_lock, const char *func)
{
    sr_main_shm_t *main_shm = SR_CONN_MAIN_SHM(conn);

    if (mode == SR_LOCK_NONE) {
        return;
    }

    /* LYDMODS UNLOCK */
    if (lydmods_lock) {
        sr_munlock(&main_shm->lydmods_lock);
    }

    if ((mode == SR_LOCK_READ) && main_shm->context_lock.upgr) {
        /* flush caches so that the lock can actually be upgraded */
        sr_run_cache_flush(conn, &sr_run_cache);
        sr_oper_cache_flush(conn, &sr_oper_cache);
    }

    /* MOD REMAP UNLOCK */
    sr_rwunlock(&sr_yang_ctx.remap_lock, SR_REMAP_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, func);

    /* CONTEXT UNLOCK */
    sr_rwunlock(&main_shm->context_lock, SR_CONTEXT_LOCK_TIMEOUT, mode, conn->cid, func);
}

sr_error_info_t *
sr_lycc_append_data(sr_conn_ctx_t *conn, const struct ly_ctx *ctx, struct sr_lycc_ds_data_set_s *data)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    sr_mod_t *shm_mod;
    const struct sr_ds_handle_s *ds_handle[SR_DS_READ_COUNT] = {0};
    sr_datastore_t ds;
    uint32_t idx = 0;

    while ((ly_mod = ly_ctx_get_module_iter(ctx, &idx))) {
        if (!ly_mod->implemented || !strcmp(ly_mod->name, "sysrepo")) {
            /* we need data of only implemented modules and never from internal SR module */
            continue;
        }

        /* get SHM mod */
        shm_mod = sr_shmmod_find_module(SR_CTX_MOD_SHM(sr_yang_ctx), ly_mod->name);
        SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup);

        /* find startup plugin and append data */
        ds = SR_DS_STARTUP;
        if ((err_info = sr_ds_handle_find(sr_yang_ctx.mod_shm.addr + shm_mod->plugins[ds], conn, &ds_handle[ds]))) {
            goto cleanup;
        }
        if ((err_info = sr_module_file_data_append(ly_mod, ds_handle, ds, 0, 0, NULL, 0, &data->start))) {
            goto cleanup;
        }

        /* find running plugin and append data, if not disabled */
        ds = SR_DS_RUNNING;
        if (shm_mod->plugins[ds]) {
            if ((err_info = sr_ds_handle_find(sr_yang_ctx.mod_shm.addr + shm_mod->plugins[ds], conn, &ds_handle[ds]))) {
                goto cleanup;
            }
            if ((err_info = sr_module_file_data_append(ly_mod, ds_handle, ds, 0, 0, NULL, 0, &data->run))) {
                goto cleanup;
            }
        }

        /* find factory-default plugin and append data */
        ds = SR_DS_FACTORY_DEFAULT;
        if ((err_info = sr_ds_handle_find(sr_yang_ctx.mod_shm.addr + shm_mod->plugins[ds], conn, &ds_handle[ds]))) {
            goto cleanup;
        }
        if ((err_info = sr_module_file_data_append(ly_mod, ds_handle, ds, 0, 0, NULL, 0, &data->fdflt))) {
            goto cleanup;
        }
    }

cleanup:
    return err_info;
}

/**
 * @brief Update data parsed with old context to be parsed with a new context.
 *
 * @param[in] old_data Old data to update.
 * @param[in] parse_opts Parse options to use for parsing back @p old_data.
 * @param[in] new_ctx New context to use.
 * @param[in,out] append_data Optional data to append, are spent.
 * @param[out] new_data Data tree in @p new_ctx with optional @p append_data.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lycc_update_data_tree(const struct lyd_node *old_data, uint32_t parse_opts, const struct ly_ctx *new_ctx,
        struct lyd_node **append_data, struct lyd_node **new_data)
{
    sr_error_info_t *err_info = NULL;
    char *data_json = NULL;

    *new_data = NULL;

    /* print the data of all the modules into JSON */
    if ((err_info = sr_lyd_print_data(old_data, LYD_JSON, LYD_PRINT_SHRINK, -1, &data_json, NULL))) {
        goto cleanup;
    }

    /* try to load it into the new updated context skipping any unknown nodes */
    if ((err_info = sr_lyd_parse_data(new_ctx, data_json, NULL, LYD_JSON, parse_opts, 0, new_data))) {
        goto cleanup;
    }

    if (append_data && *append_data) {
        /* link to the new data */
        if (!(*new_data)) {
            *new_data = *append_data;
        } else if ((err_info = sr_lyd_merge(new_data, *append_data, 1, LYD_MERGE_DESTRUCT))) {
            goto cleanup;
        }
        *append_data = NULL;
    }

cleanup:
    free(data_json);
    return err_info;
}

/**
 * @brief Install a module by calling all its required callbacks.
 *
 * @param[in] conn Connection to use.
 * @param[in] new_mod New module to install.
 * @param[in] ds Datastore.
 * @param[out] ds_handle Optional, module DS handle.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lycc_add_module_cb_install(sr_conn_ctx_t *conn, sr_int_install_mod_t *new_mod, sr_datastore_t ds,
        struct sr_ds_handle_s **ds_handle)
{
    sr_error_info_t *err_info = NULL;
    struct sr_ds_handle_s *dh = NULL;

    if (new_mod->installed[ds] && !ds_handle) {
        /* nothing to do */
        goto cleanup;
    }

    /* find plugin */
    if ((err_info = sr_ds_handle_find(new_mod->module_ds.plugin_name[ds], conn, (const struct sr_ds_handle_s **)&dh))) {
        goto cleanup;
    }

    if (new_mod->installed[ds]) {
        /* just return the DS handle */
        goto cleanup;
    }

    if (!dh->init) {
        /* call conn_init */
        if ((err_info = dh->plugin->conn_init_cb(conn, &dh->plg_data))) {
            goto cleanup;
        }
        dh->init = 1;
    }

    /* call install */
    if ((err_info = dh->plugin->install_cb(new_mod->ly_mod, ds, new_mod->owner, new_mod->group, new_mod->perm, dh->plg_data))) {
        goto cleanup;
    }
    new_mod->installed[ds] = 1;

    /* call init */
    if ((err_info = dh->plugin->init_cb(new_mod->ly_mod, ds, dh->plg_data))) {
        goto cleanup;
    }

cleanup:
    if (ds_handle) {
        *ds_handle = dh;
    }
    return err_info;
}

/**
 * @brief Get initial data for a datastore using a DS plugin load() callback.
 *
 * @param[in] conn Connection to use.
 * @param[in] new_mods New modules with DS plugins.
 * @param[in] new_mod_count Count of @p new_mods.
 * @param[in] ds Datastore to handle.
 * @param[out] init_data Initial data for the datastore for all the @p new_mods.
 * @param[in,out] old_data Current old data to add to, since we are technically loading old data.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lycc_update_data_init_ds_load(sr_conn_ctx_t *conn, sr_int_install_mod_t *new_mods, uint32_t new_mod_count,
        sr_datastore_t ds, struct lyd_node **init_data, struct lyd_node **old_data)
{
    sr_error_info_t *err_info = NULL;
    struct sr_ds_handle_s *ds_handle;
    struct lyd_node *mod_data = NULL, *dup_data = NULL;
    uint32_t i;

    assert(ds != SR_DS_OPERATIONAL);

    *init_data = NULL;

    for (i = 0; i < new_mod_count; ++i) {
        if (!new_mods[i].module_ds.plugin_name[ds] || new_mods[i].enable_features) {
            /* disabled or only new features enabled */
            continue;
        }

        /* properly init the module */
        if ((err_info = sr_lycc_add_module_cb_install(conn, &new_mods[i], ds, &ds_handle))) {
            goto cleanup;
        }

        /* load the initial data of the module */
        if ((err_info = ds_handle->plugin->load_cb(new_mods[i].ly_mod, ds, 0, 0, NULL, 0, ds_handle->plg_data, &mod_data))) {
            goto cleanup;
        }
        if (!mod_data) {
            continue;
        }

        /* copy into old data */
        if ((err_info = sr_lyd_dup(mod_data, NULL, LYD_DUP_RECURSIVE, 1, &dup_data))) {
            goto cleanup;
        }
        if (!(*old_data)) {
            *old_data = dup_data;
        } else if ((err_info = sr_lyd_insert_sibling(*old_data, dup_data, old_data))) {
            goto cleanup;
        }
        dup_data = NULL;

        /* merge into the initial data */
        if (!(*init_data)) {
            *init_data = mod_data;
        } else if ((err_info = sr_lyd_merge(init_data, mod_data, 1, LYD_MERGE_DESTRUCT))) {
            goto cleanup;
        }
        mod_data = NULL;
    }

cleanup:
    lyd_free_siblings(mod_data);
    lyd_free_siblings(dup_data);
    return err_info;
}

/**
 * @brief Check whether a module DS is enabled when updating its data.
 *
 * @param[in] ly_mod Module to use.
 * @param[in] ds Datastore to use.
 * @param[in] new_mods Array of new modules.
 * @param[in] new_mod_count Count of @p new_mods.
 * @param[in] sr_mods SR mods data.
 * @return Whether the module DS is enabled or not.
 */
static int
sr_lycc_update_data_is_enabled(const struct lys_module *ly_mod, sr_datastore_t ds, sr_int_install_mod_t *new_mods,
        uint32_t new_mod_count, const struct lyd_node *sr_mods)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    LY_ERR lyrc;
    char *path;

    /* check new modules */
    for (i = 0; i < new_mod_count; ++i) {
        if (new_mods[i].ly_mod == ly_mod) {
            if (new_mods[i].module_ds.plugin_name[ds]) {
                return 1;
            } else {
                return 0;
            }
        }
    }

    /* check internal SR module data */
    if (asprintf(&path, "/sysrepo:sysrepo-modules/module[name='%s']/plugin[datastore='%s']",
            ly_mod->name, sr_ds2ident(ds)) == -1) {
        SR_ERRINFO_MEM(&err_info);
        sr_errinfo_free(&err_info);
        return 1;
    }

    lyrc = lyd_find_path(sr_mods, path, 0, NULL);
    free(path);
    if (lyrc) {
        return 0;
    } else {
        return 1;
    }
}

sr_error_info_t *
sr_lycc_update_ds_data(const struct ly_ctx *new_ctx, sr_int_install_mod_t *new_mods, uint32_t new_mod_count,
        const struct lyd_node *sr_mods_old, struct sr_lycc_ds_data_set_s *data_old,
        struct sr_lycc_ds_data_set_s *data_init, struct sr_lycc_ds_data_set_s *data_new)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    uint32_t parse_opts, idx;

    /* update data for the new context */
    parse_opts = LYD_PARSE_NO_STATE | LYD_PARSE_STORE_ONLY | LYD_PARSE_ORDERED;
    if ((err_info = sr_lycc_update_data_tree(data_old->start, parse_opts, new_ctx, data_init ? &data_init->start : NULL,
            &data_new->start))) {
        goto cleanup;
    }
    if ((err_info = sr_lycc_update_data_tree(data_old->run, parse_opts, new_ctx, data_init ? &data_init->run : NULL,
            &data_new->run))) {
        goto cleanup;
    }
    if ((err_info = sr_lycc_update_data_tree(data_old->fdflt, parse_opts, new_ctx, data_init ? &data_init->fdflt : NULL,
            &data_new->fdflt))) {
        goto cleanup;
    }

    /* fully validate complete startup, running (what is enabled), and factory-default datastore */
    if ((err_info = sr_lyd_validate_all(&data_new->start, new_ctx, LYD_VALIDATE_NO_STATE))) {
        sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, "Invalid startup datastore data.");
        goto cleanup;
    }
    idx = 0;
    while ((ly_mod = ly_ctx_get_module_iter(new_ctx, &idx))) {
        if (!ly_mod->implemented || !strcmp(ly_mod->name, "sysrepo") ||
                !sr_lycc_update_data_is_enabled(ly_mod, SR_DS_RUNNING, new_mods, new_mod_count, sr_mods_old)) {
            continue;
        }

        if ((err_info = sr_lyd_validate_module(&data_new->run, ly_mod, LYD_VALIDATE_NO_STATE | LYD_VALIDATE_NOT_FINAL,
                NULL))) {
            sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, "Invalid running datastore data.");
            goto cleanup;
        }
    }
    idx = 0;
    while ((ly_mod = ly_ctx_get_module_iter(new_ctx, &idx))) {
        if (!ly_mod->implemented || !strcmp(ly_mod->name, "sysrepo") ||
                !sr_lycc_update_data_is_enabled(ly_mod, SR_DS_RUNNING, new_mods, new_mod_count, sr_mods_old)) {
            continue;
        }

        if ((err_info = sr_lyd_validate_module_final(data_new->run, ly_mod, LYD_VALIDATE_NO_STATE))) {
            sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, "Invalid running datastore data.");
            goto cleanup;
        }
    }
    if ((err_info = sr_lyd_validate_all(&data_new->fdflt, new_ctx, LYD_VALIDATE_NO_STATE))) {
        sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, "Invalid factory-default datastore data.");
        goto cleanup;
    }

cleanup:
    return err_info;
}

sr_error_info_t *
sr_lycc_prepare_data(sr_conn_ctx_t *conn, struct ly_ctx *ly_ctx_old, struct ly_ctx *ly_ctx_new,
        struct lyd_node **init_data, sr_int_install_mod_t *new_mods, uint32_t new_mod_count, struct sr_lycc_info_s *cc_info)
{
    sr_error_info_t *err_info = NULL;
    struct sr_lycc_ds_data_set_s data_init = {0};

    cc_info->ly_ctx_old = ly_ctx_old;
    cc_info->ly_ctx_new = ly_ctx_new;

    /* parse current (old) module information, needed for schema mount data update */
    if ((err_info = sr_lydmods_parse(cc_info->ly_ctx_old, conn, NULL, &cc_info->sr_mods_old))) {
        goto cleanup;
    }

    /* parse all the startup/running/operational/factory-default data using the old context (that must succeed) */
    if ((err_info = sr_lycc_append_data(conn, sr_yang_ctx.ly_ctx, &cc_info->data_info.old))) {
        goto cleanup;
    }

    /* prepare initial data for each relevant datastore */
    if (init_data && *init_data) {
        if ((err_info = sr_lyd_dup(*init_data, NULL, LYD_DUP_RECURSIVE, 1, &data_init.start))) {
            goto cleanup;
        }
    } else if ((err_info = sr_lycc_update_data_init_ds_load(conn, new_mods, new_mod_count, SR_DS_STARTUP,
            &data_init.start, &cc_info->data_info.old.start))) {
        goto cleanup;
    }
    if (init_data && *init_data) {
        if ((err_info = sr_lyd_dup(*init_data, NULL, LYD_DUP_RECURSIVE, 1, &data_init.run))) {
            goto cleanup;
        }
    } else if ((err_info = sr_lycc_update_data_init_ds_load(conn, new_mods, new_mod_count, SR_DS_RUNNING,
            &data_init.run, &cc_info->data_info.old.run))) {
        goto cleanup;
    }
    if (init_data && *init_data) {
        data_init.fdflt = *init_data;
        *init_data = NULL;
    } else if ((err_info = sr_lycc_update_data_init_ds_load(conn, new_mods, new_mod_count, SR_DS_FACTORY_DEFAULT,
            &data_init.fdflt, &cc_info->data_info.old.fdflt))) {
        goto cleanup;
    }

    /* load all data and prepare their update */
    if ((err_info = sr_lycc_update_ds_data(cc_info->ly_ctx_new, new_mods, new_mod_count, cc_info->sr_mods_old,
            &cc_info->data_info.old, &data_init, &cc_info->data_info.new))) {
        goto cleanup;
    }

cleanup:
    sr_lycc_ds_data_set_clear(&data_init);
    return err_info;
}

void
sr_lycc_ds_data_set_clear(struct sr_lycc_ds_data_set_s *data)
{
    lyd_free_siblings(data->start);
    lyd_free_siblings(data->run);
    lyd_free_siblings(data->fdflt);

    memset(data, 0, sizeof *data);
}

void
sr_lycc_clear_data(struct sr_lycc_info_s *cc_info)
{
    int sr_mods_equal = (cc_info->sr_mods_old == cc_info->sr_mods_new);

    sr_lycc_ds_data_set_clear(&cc_info->data_info.old);
    sr_lycc_ds_data_set_clear(&cc_info->data_info.new);

    lyd_free_siblings(cc_info->sr_mods_old);
    if (!sr_mods_equal) {
        lyd_free_siblings(cc_info->sr_mods_new);
    }

    memset(cc_info, 0, sizeof *cc_info);
}

/**
 * @brief Print data if they differ, are completely new, or their LYB metadata differ (augment/deviation module was removed).
 * Is evaluated for each module data separately.
 *
 * @param[in] conn Connection to use.
 * @param[in] new_ctx New context to iterate over.
 * @param[in] ds Affected datastore.
 * @param[in] sr_mods SR internal module data.
 * @param[in,out] old_data Previous (current) data, are freed for each module.
 * @param[in,out] new_data New data, are freed for each module.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lycc_store_ds_data_if_differ_ds(sr_conn_ctx_t *conn, const struct ly_ctx *new_ctx, sr_datastore_t ds,
        const struct lyd_node *sr_mods, struct lyd_node **old_data, struct lyd_node **new_data)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *new_ly_mod, *old_ly_mod;
    struct lyd_node *new_mod_data = NULL, *old_mod_data = NULL, *mod_diff = NULL;
    const struct sr_ds_handle_s *ds_handle;
    struct ly_set *set;
    char *xpath;
    uint32_t idx = 0;
    int snode_not_found;

    assert(ds != SR_DS_OPERATIONAL);

    while ((new_ly_mod = ly_ctx_get_module_iter(new_ctx, &idx))) {
        if (!new_ly_mod->implemented || !strcmp(new_ly_mod->name, "sysrepo")) {
            continue;
        }

        old_ly_mod = ly_ctx_get_module_implemented(sr_yang_ctx.ly_ctx, new_ly_mod->name);
        if (old_ly_mod && !sr_module_has_data(old_ly_mod, 0) && !sr_module_has_data(new_ly_mod, 0)) {
            /* neither of the modules have configuration data so they cannot be changed */
            continue;
        }

        /* get old and new data of the module */
        lyd_free_siblings(new_mod_data);
        lyd_free_siblings(old_mod_data);
        new_mod_data = sr_module_data_unlink(new_data, new_ly_mod, 0);
        old_mod_data = sr_module_data_unlink(old_data, old_ly_mod ? old_ly_mod : new_ly_mod, 0);

        /* get plugin name */
        if (asprintf(&xpath, "module[name='%s']/plugin[datastore='%s']/name", new_ly_mod->name, sr_ds2ident(ds)) == -1) {
            SR_ERRINFO_MEM(&err_info);
            break;
        }
        err_info = sr_lyd_find_xpath(sr_mods, xpath, &set);
        free(xpath);
        if (err_info) {
            break;
        } else if (!set->count && (ds == SR_DS_RUNNING)) {
            /* 'running' disabled */
            ly_set_free(set, NULL);
            continue;
        } else if (set->count != 1) {
            SR_ERRINFO_INT(&err_info);
            break;
        }

        /* get plugin */
        err_info = sr_ds_handle_find(lyd_get_value(set->dnodes[0]), conn, &ds_handle);
        ly_set_free(set, NULL);
        if (err_info) {
            break;
        }

        /* generate a diff of old and new data */
        lyd_free_siblings(mod_diff);
        if ((err_info = sr_lyd_diff_siblings(old_mod_data, new_mod_data, LYD_DIFF_DEFAULTS, &snode_not_found, &mod_diff))) {
            break;
        }

        /* schema node may not be found because nodes can be added/removed with default values added/removed, even in a
         * single module so neither old nor new context can be used for all the cases */
        if (mod_diff || snode_not_found) {
            /* store new data */
            if ((err_info = ds_handle->plugin->store_prepare_cb(new_ly_mod, ds, 0, 0, mod_diff, new_mod_data,
                    ds_handle->plg_data))) {
                break;
            }

            if ((err_info = ds_handle->plugin->store_commit_cb(new_ly_mod, ds, 0, 0, mod_diff, new_mod_data,
                    ds_handle->plg_data))) {
                break;
            }
        }
    }

    lyd_free_siblings(new_mod_data);
    lyd_free_siblings(old_mod_data);
    lyd_free_siblings(mod_diff);
    return err_info;
}

sr_error_info_t *
sr_lycc_store_ds_data_if_differ(sr_conn_ctx_t *conn, const struct ly_ctx *new_ctx, const struct lyd_node *sr_mods,
        struct sr_lycc_ds_data_s *data_info)
{
    sr_error_info_t *err_info = NULL;

    /* startup */
    if ((err_info = sr_lycc_store_ds_data_if_differ_ds(conn, new_ctx, SR_DS_STARTUP, sr_mods, &data_info->old.start,
            &data_info->new.start))) {
        return err_info;
    }

    /* running */
    if ((err_info = sr_lycc_store_ds_data_if_differ_ds(conn, new_ctx, SR_DS_RUNNING, sr_mods, &data_info->old.run,
            &data_info->new.run))) {
        return err_info;
    }

    /* factory-default */
    if ((err_info = sr_lycc_store_ds_data_if_differ_ds(conn, new_ctx, SR_DS_FACTORY_DEFAULT, sr_mods, &data_info->old.fdflt,
            &data_info->new.fdflt))) {
        return err_info;
    }

    return NULL;
}

sr_error_info_t *
sr_lycc_update_data(sr_conn_ctx_t *conn, struct sr_lycc_info_s *cc_info, sr_shm_t *mod_shm,
        sr_run_cache_t *sr_run_cache, sr_oper_cache_t *sr_oper_cache)
{
    sr_error_info_t *err_info = NULL, *tmp_err;

    if (mod_shm) {
        /* update SHM modules */
        if ((err_info = sr_shmmod_store_modules(mod_shm, cc_info->sr_mods_new))) {
            goto cleanup;
        }
    }

    /* store new data if they differ */
    if ((err_info = sr_lycc_store_ds_data_if_differ(conn, cc_info->ly_ctx_new, cc_info->sr_mods_new, &cc_info->data_info))) {
        goto cleanup;
    }

    /* flush caches */
    sr_run_cache_flush(conn, sr_run_cache);
    sr_oper_cache_flush(conn, sr_oper_cache);

    /* destroy any current nested schema mount contexts */
    if ((err_info = sr_schema_mount_destroy_contexts(cc_info->ly_ctx_old, cc_info->sr_mods_old))) {
        goto cleanup;
    }

    /* create new nested schema mount contexts so they can be printed */
    if ((err_info = sr_schema_mount_create_contexts(cc_info->ly_ctx_new, cc_info->sr_mods_new))) {
        goto cleanup;
    }

    /* free the data trees */
    sr_lycc_clear_data(cc_info);

cleanup:
    if (err_info) {
        /* revert SHM module changes */
        if (mod_shm && (tmp_err = sr_shmmod_store_modules(mod_shm, cc_info->sr_mods_new))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }
    return err_info;
}

sr_error_info_t *
sr_lycc_check_add_modules(sr_conn_ctx_t *conn, const struct ly_ctx *new_ctx)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod, *ly_mod2;
    uint32_t i = 0;

    while ((ly_mod = ly_ctx_get_module_iter(new_ctx, &i))) {
        if (!ly_mod->implemented) {
            continue;
        }

        ly_mod2 = ly_ctx_get_module_implemented(sr_yang_ctx.ly_ctx, ly_mod->name);
        if (!ly_mod2) {
            continue;
        }

        /* modules are implemented in both contexts, compare revisions */
        if ((!ly_mod->revision && ly_mod2->revision) || (ly_mod->revision && !ly_mod2->revision) ||
                (ly_mod->revision && ly_mod2->revision && strcmp(ly_mod->revision, ly_mod2->revision))) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Module \"%s\" implements module \"%s@%s\" that is already"
                    " in sysrepo in revision %s.", ly_mod->name, ly_mod->name,
                    ly_mod->revision ? ly_mod->revision : "<none>", ly_mod2->revision ? ly_mod2->revision : "<none>");
            return err_info;
        }
    }

    /* check subscriptions in the new context */
    if ((err_info = sr_shmext_check_sub_all(conn, new_ctx))) {
        return err_info;
    }

    return NULL;
}

sr_error_info_t *
sr_lycc_add_modules(sr_conn_ctx_t *conn, sr_int_install_mod_t *new_mods, uint32_t new_mod_count)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    uint32_t i;
    sr_datastore_t ds;

    for (i = 0; i < new_mod_count; ++i) {
        if (new_mods[i].enable_features) {
            /* only enabling new features */
            continue;
        }

        /* init module for all DS plugins */
        for (ds = 0; ds < SR_DS_READ_COUNT; ++ds) {
            if ((ds == SR_DS_RUNNING) && !new_mods[i].module_ds.plugin_name[ds]) {
                /* disabled */
                continue;
            }

            /* find DS handle and call all the callbacks */
            if ((err_info = sr_lycc_add_module_cb_install(conn, &new_mods[i], ds, NULL))) {
                goto cleanup;
            }
        }

        /* store module YANG with all submodules and imports */
        if ((err_info = sr_store_module_yang_r(new_mods[i].ly_mod))) {
            goto cleanup;
        }
        new_mods[i].yangs_stored = 1;
    }

cleanup:
    if (err_info && (tmp_err = sr_lycc_add_modules_revert(conn, new_mods, new_mod_count))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }
    return err_info;
}

sr_error_info_t *
sr_lycc_add_modules_revert(sr_conn_ctx_t *conn, sr_int_install_mod_t *new_mods, uint32_t new_mod_count)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    uint32_t i;
    sr_datastore_t ds;
    struct sr_ds_handle_s *ds_handle;
    struct ly_set del_set = {0};

    for (i = 0; i < new_mod_count; ++i) {
        ly_mod = new_mods[i].ly_mod;

        /* uninstall module for all DS plugins */
        for (ds = 0; ds < SR_DS_READ_COUNT; ++ds) {
            if (!new_mods[i].installed[ds]) {
                continue;
            }

            /* find plugin */
            if ((err_info = sr_ds_handle_find(new_mods[i].module_ds.plugin_name[ds], conn,
                    (const struct sr_ds_handle_s **)&ds_handle))) {
                goto cleanup;
            }

            /* call uninstall */
            if ((err_info = ds_handle->plugin->uninstall_cb(ly_mod, ds, ds_handle->plg_data))) {
                goto cleanup;
            }

            new_mods[i].installed[ds] = 0;
        }

        if (new_mods[i].yangs_stored) {
            /* remove YANG module(s) */
            if ((err_info = sr_remove_module_yang_r(ly_mod, sr_yang_ctx.ly_ctx, &del_set))) {
                goto cleanup;
            }
            new_mods[i].yangs_stored = 0;
        }
    }

cleanup:
    ly_set_erase(&del_set, NULL);
    return err_info;
}

sr_error_info_t *
sr_lycc_check_del_module(sr_conn_ctx_t *conn, const struct ly_ctx *new_ctx, const struct ly_set *mod_set)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *del_mod, *ly_mod;
    uint32_t i;

    for (i = 0; i < mod_set->count; ++i) {
        del_mod = mod_set->objs[i];

        ly_mod = ly_ctx_get_module(new_ctx, del_mod->name, del_mod->revision);
        if (ly_mod && ly_mod->implemented) {
            /* this module cannot be removed */
            sr_errinfo_new(&err_info, SR_ERR_OPERATION_FAILED, "Module \"%s\" cannot be removed because "
                    "some other installed module depends on it.", del_mod->name);
            return err_info;
        }
    }

    /* check subscriptions in the new context */
    if ((err_info = sr_shmext_check_sub_all(conn, new_ctx))) {
        return err_info;
    }

    return NULL;
}

sr_error_info_t *
sr_lycc_del_module(sr_conn_ctx_t *conn, const struct ly_ctx *ly_ctx, const struct ly_set *mod_set,
        const struct lyd_node *sr_del_mods)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    const struct lyd_node *sr_mod = NULL;
    struct lyd_node *sr_plg_name, *sr_rpl_sup;
    struct ly_set del_set = {0};
    char *path;
    uint32_t i;
    sr_datastore_t ds;
    const struct sr_ds_handle_s *ds_handle;
    const struct sr_ntf_handle_s *ntf_handle;
    int r;

    for (i = 0; i < mod_set->count; ++i) {
        ly_mod = mod_set->objs[i];
        if (!sr_mod) {
            sr_mod = lyd_child(sr_del_mods);
        } else {
            sr_mod = sr_mod->next;
        }
        assert(!strcmp(ly_mod->name, lyd_get_value(lyd_child(sr_mod))));

        /* destroy module for all DS plugins */
        for (ds = 0; ds < SR_DS_READ_COUNT; ++ds) {
            /* get plugin name */
            r = asprintf(&path, "plugin[datastore='%s']/name", sr_mod_ds2ident(ds));
            SR_CHECK_MEM_GOTO(r == -1, err_info, cleanup);
            err_info = sr_lyd_find_path(sr_mod, path, 0, &sr_plg_name);
            free(path);
            if (err_info) {
                goto cleanup;
            }

            if ((ds == SR_DS_RUNNING) && !sr_plg_name) {
                /* 'running' disabled */
                continue;
            }
            SR_CHECK_INT_GOTO(!sr_plg_name, err_info, cleanup);

            /* find plugin */
            if ((err_info = sr_ds_handle_find(lyd_get_value(sr_plg_name), conn, &ds_handle))) {
                goto cleanup;
            }

            /* call uninstall */
            if ((err_info = ds_handle->plugin->uninstall_cb(ly_mod, ds, ds_handle->plg_data))) {
                goto cleanup;
            }
        }

        /* destroy notifications if replay support was enabled */
        if ((err_info = sr_lyd_find_path(sr_mod, "replay-support", 0, &sr_rpl_sup))) {
            goto cleanup;
        }
        if (sr_rpl_sup) {
            /* find plugin */
            r = asprintf(&path, "plugin[datastore='%s']/name", sr_mod_ds2ident(SR_MOD_DS_NOTIF));
            SR_CHECK_MEM_GOTO(r == -1, err_info, cleanup);
            err_info = sr_lyd_find_path(sr_mod, path, 0, &sr_plg_name);
            free(path);
            if (err_info) {
                goto cleanup;
            }

            SR_CHECK_INT_GOTO(!sr_plg_name, err_info, cleanup);
            if ((err_info = sr_ntf_handle_find(lyd_get_value(sr_plg_name), conn, &ntf_handle))) {
                goto cleanup;
            }

            /* call disable */
            if ((err_info = ntf_handle->plugin->disable_cb(ly_mod))) {
                goto cleanup;
            }
        }

        /* remove module YANG files and of all its imports */
        if ((err_info = sr_remove_module_yang_r(ly_mod, ly_ctx, &del_set))) {
            goto cleanup;
        }
    }

cleanup:
    ly_set_erase(&del_set, NULL);
    return err_info;
}

sr_error_info_t *
sr_lycc_check_upd_modules(sr_conn_ctx_t *conn, const struct ly_set *old_mod_set, const struct ly_set *upd_mod_set)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *upd_mod = NULL, *old_mod;
    uint32_t i;

    assert(upd_mod_set->count);
    for (i = 0; i < upd_mod_set->count; ++i) {
        upd_mod = upd_mod_set->objs[i];
        old_mod = old_mod_set->objs[i];

        /* it must have a revision */
        if (!upd_mod->revision) {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Update module \"%s\" does not have a revision.", upd_mod->name);
            return err_info;
        }

        /* it must be a different and newer module than the installed one */
        if (old_mod->revision) {
            if (!strcmp(upd_mod->revision, old_mod->revision)) {
                sr_errinfo_new(&err_info, SR_ERR_EXISTS, "Module \"%s@%s\" already installed.", upd_mod->name,
                        old_mod->revision);
                return err_info;
            } else if (strcmp(upd_mod->revision, old_mod->revision) < 0) {
                sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Module \"%s@%s\" installed in a newer revision.",
                        upd_mod->name, old_mod->revision);
                return err_info;
            }
        }
    }

    assert(upd_mod);

    /* check subscriptions in the new context */
    if ((err_info = sr_shmext_check_sub_all(conn, upd_mod->ctx))) {
        return err_info;
    }

    return NULL;
}

sr_error_info_t *
sr_lycc_upd_modules(const struct ly_set *old_mod_set, const struct ly_set *upd_mod_set)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *upd_mod, *old_mod;
    uint32_t i;
    struct ly_set del_set = {0};

    for (i = 0; i < upd_mod_set->count; ++i) {
        upd_mod = upd_mod_set->objs[i];
        old_mod = old_mod_set->objs[i];

        /* remove old module files */
        if ((err_info = sr_remove_module_yang_r(old_mod, upd_mod->ctx, &del_set))) {
            goto cleanup;
        }

        /* store updated module files */
        if ((err_info = sr_store_module_yang_r(upd_mod))) {
            goto cleanup;
        }
    }

cleanup:
    ly_set_erase(&del_set, NULL);
    return err_info;
}

sr_error_info_t *
sr_lycc_check_chng_feature(sr_conn_ctx_t *conn, const struct ly_ctx *new_ctx)
{
    sr_error_info_t *err_info = NULL;

    /* check subscriptions in the new context */
    if ((err_info = sr_shmext_check_sub_all(conn, new_ctx))) {
        return err_info;
    }

    return NULL;
}

sr_error_info_t *
sr_lycc_set_replay_support(sr_conn_ctx_t *conn, const struct ly_set *mod_set, int enable, const struct lyd_node *sr_mods)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    char *path;
    struct lyd_node *sr_ntf_name;
    const struct sr_ntf_handle_s *ntf_handle;
    uint32_t i;

    for (i = 0; i < mod_set->count; ++i) {
        ly_mod = mod_set->objs[i];

        /* get plugin name */
        if (asprintf(&path, "module[name='%s']/plugin[datastore='notification']/name", ly_mod->name) == -1) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }
        err_info = sr_lyd_find_path(sr_mods, path, 0, &sr_ntf_name);
        free(path);
        if (err_info) {
            goto cleanup;
        }
        SR_CHECK_INT_GOTO(!sr_ntf_name, err_info, cleanup);

        /* find plugin */
        if ((err_info = sr_ntf_handle_find(lyd_get_value(sr_ntf_name), conn, &ntf_handle))) {
            goto cleanup;
        }

        if (enable) {
            /* call enable */
            if ((err_info = ntf_handle->plugin->enable_cb(ly_mod))) {
                goto cleanup;
            }
        } else {
            /* call disable */
            if ((err_info = ntf_handle->plugin->disable_cb(ly_mod))) {
                goto cleanup;
            }
        }
    }

cleanup:
    return err_info;
}

sr_error_info_t *
sr_lycc_store_context(sr_conn_ctx_t *conn, sr_shm_t *shm, struct ly_ctx *ctx)
{
    sr_error_info_t *err_info = NULL;
    int ctx_size, fd = -1;
    void *mem = NULL, *mem_end;
    char *shm_name = NULL;

    if (!SR_PRINTED_LYCTX_ADDRESS) {
        /* printed context not supported */
        return NULL;
    }

    /* flush caches */
    sr_run_cache_flush(conn, &sr_run_cache);
    sr_oper_cache_flush(conn, &sr_oper_cache);

    if ((err_info = sr_path_ctx_shm(&shm_name))) {
        goto cleanup;
    }

    fd = sr_open(shm_name, O_RDWR | O_CREAT | O_TRUNC, SR_SHM_PERM);
    if (fd == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to open ctx shared memory (%s).", strerror(errno));
        goto cleanup;
    }

    /* get the size of the compiled context */
    ctx_size = ly_ctx_compiled_size(ctx);

    /* truncate the shared memory to the size of the printed context */
    if (ftruncate(fd, ctx_size)) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to truncate the printed context (%s).", strerror(errno));
        goto cleanup;
    }

    /* unmap to avoid collision */
    if (shm->addr) {
        munmap(shm->addr, shm->size);
        shm->addr = NULL;
        shm->size = 0;
    }

    /* allocate memory for the printed context, use the same address as the resulting address,
     * so that when this context is used, the pointers in the printed context will point to the right place */
    mem = mmap((void *)SR_PRINTED_LYCTX_ADDRESS, ctx_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED_NOREPLACE, fd, 0);
    if (mem == MAP_FAILED) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to map the printed context (%s).", strerror(errno));
        mem = NULL;
        goto cleanup;
    }

    /* print the context into the allocated memory */
    if ((err_info = sr_ly_ctx_compiled_print(ctx, mem, &mem_end))) {
        goto cleanup;
    }
    assert(((char *)mem_end - (char *)mem) == ctx_size);

    /* destroy the old printed context, it will be unmapped anyways,
     * doing it now avoids a context data collision with the new context */
    sr_yang_ctx.content_id = 0;
    sr_yang_ctx.sm_data_id = 0;
    ly_ctx_destroy(sr_yang_ctx.ly_ctx);
    sr_yang_ctx.ly_ctx = NULL;

cleanup:
    if (err_info && shm_name) {
        unlink(shm_name);
    }
    free(shm_name);
    if (fd > -1) {
        close(fd);
    }
    if (mem) {
        munmap(mem, ctx_size);
    }
    return err_info;
}

sr_error_info_t *
sr_lycc_load_context(sr_shm_t *shm, struct ly_ctx **ctx)
{
    sr_error_info_t *err_info;
    size_t shm_file_size = 0;
    char *shm_name = NULL;

    *ctx = NULL;

    if (!SR_PRINTED_LYCTX_ADDRESS || (ATOMIC_LOAD_RELAXED(sr_yang_ctx.sr_opts) & SR_CTX_NO_PRINTED)) {
        /* printed context not supported */
        return NULL;
    }

    if ((err_info = sr_path_ctx_shm(&shm_name))) {
        goto cleanup;
    }

    /* check if the file exists */
    if (!sr_file_exists(shm_name)) {
        /* no context stored */
        goto cleanup;
    }

    /* open the shared memory if not open */
    if (shm->fd == -1) {
        shm->fd = sr_open(shm_name, O_RDONLY, SR_SHM_PERM);
        if (shm->fd == -1) {
            sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to open context shared memory (%s).", strerror(errno));
            goto cleanup;
        }
    }

    /* read the new shm size if not set */
    if ((err_info = sr_file_get_size(shm->fd, &shm_file_size))) {
        goto cleanup;
    }

    if (shm_file_size != shm->size) {
        if (shm->addr) {
            munmap(shm->addr, shm->size);
            shm->addr = NULL;
            shm->size = 0;
        }

        /* map the shared memory to the address the context was printed to */
        shm->addr = mmap((void *)SR_PRINTED_LYCTX_ADDRESS, shm_file_size, PROT_READ, MAP_PRIVATE | MAP_FIXED_NOREPLACE, shm->fd, 0);
        if (shm->addr == MAP_FAILED) {
            sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to map the printed context (%s).", strerror(errno));
            shm->addr = NULL;
            goto cleanup;
        }
        shm->size = shm_file_size;
    }

    /* get the printed context */
    if ((err_info = sr_ly_ctx_new_printed(shm->addr, ctx))) {
        goto cleanup;
    }

    /* set the ext callback */
    ly_ctx_set_ext_data_clb(*ctx, sr_ly_ext_data_clb, NULL);

cleanup:
    free(shm_name);
    return err_info;
}
