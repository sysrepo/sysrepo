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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <libyang/libyang.h>

#include "common.h"
#include "common_types.h"
#include "config.h"
#include "log.h"
#include "plugins_datastore.h"
#include "plugins_notification.h"
#include "shm_ext.h"
#include "shm_mod.h"
#include "sysrepo.h"
#include "sysrepo_types.h"

sr_error_info_t *
sr_lycc_lock(sr_conn_ctx_t *conn, sr_lock_mode_t mode, int lydmods_lock, const char *func)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    sr_main_shm_t *main_shm = SR_CONN_MAIN_SHM(conn);
    sr_lock_mode_t remap_mode = SR_LOCK_NONE;
    struct sr_shmmod_recover_cb_s cb_data;
    struct ly_ctx *new_ctx = NULL;
    char *path;

    cb_data.ly_ctx_p = &conn->ly_ctx;
    cb_data.ds = SR_DS_STARTUP;

    /* CONTEXT LOCK */
    if ((err_info = sr_rwlock(&main_shm->context_lock, SR_CONTEXT_LOCK_TIMEOUT, mode, conn->cid, func,
            sr_shmmod_recover_cb, &cb_data))) {
        return err_info;
    }

    /* MOD REMAP LOCK */
    if ((err_info = sr_rwlock(&conn->mod_remap_lock, SR_CONN_REMAP_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, func,
            NULL, NULL))) {
        goto cleanup_unlock;
    }
    remap_mode = SR_LOCK_READ;

    /* check whether the context is current and does not need to be updated */
    if (main_shm->content_id != conn->content_id) {
        /* MOD REMAP UNLOCK */
        sr_rwunlock(&conn->mod_remap_lock, SR_CONN_REMAP_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, func);
        remap_mode = SR_LOCK_NONE;

        /* MOD REMAP LOCK */
        if ((err_info = sr_rwlock(&conn->mod_remap_lock, SR_CONN_REMAP_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, func,
                NULL, NULL))) {
            goto cleanup_unlock;
        }
        remap_mode = SR_LOCK_WRITE;

        /* remap mod SHM */
        if ((err_info = sr_shm_remap(&conn->mod_shm, 0))) {
            goto cleanup_unlock;
        }

        /* context was updated, create a new one with the current modules */
        if ((err_info = sr_ly_ctx_init(conn, &new_ctx))) {
            goto cleanup_unlock;
        }
        if ((err_info = sr_shmmod_ctx_load_modules(SR_CONN_MOD_SHM(conn), new_ctx, NULL))) {
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
            goto cleanup_unlock;
        }

        /* use the new context */
        sr_conn_ctx_switch(conn, &new_ctx, NULL);

        /* initialize new DS plugins */
        if ((err_info = sr_conn_ds_init(conn))) {
            goto cleanup_unlock;
        }

        /* MOD REMAP DOWNGRADE */
        if ((err_info = sr_rwrelock(&conn->mod_remap_lock, SR_CONN_REMAP_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, func,
                NULL, NULL))) {
            goto cleanup_unlock;
        }
        remap_mode = SR_LOCK_READ;
    }

    /* LYDMODS LOCK */
    if (lydmods_lock && (err_info = sr_mlock(&main_shm->lydmods_lock, SR_CONTEXT_LOCK_TIMEOUT, func, NULL, NULL))) {
        goto cleanup_unlock;
    }

cleanup_unlock:
    ly_ctx_destroy(new_ctx);
    if (err_info) {
        if (remap_mode) {
            /* MOD REMAP UNLOCK */
            sr_rwunlock(&conn->mod_remap_lock, SR_CONN_REMAP_LOCK_TIMEOUT, remap_mode, conn->cid, func);
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
    struct sr_shmmod_recover_cb_s cb_data;

    cb_data.ly_ctx_p = &conn->ly_ctx;
    cb_data.ds = SR_DS_STARTUP;

    /* RELOCK */
    if ((err_info = sr_rwrelock(&main_shm->context_lock, SR_CONTEXT_LOCK_TIMEOUT, mode, conn->cid, func,
            sr_shmmod_recover_cb, &cb_data))) {
        return err_info;
    }
    assert(main_shm->content_id == conn->content_id);

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

    /* MOD REMAP UNLOCK */
    sr_rwunlock(&conn->mod_remap_lock, SR_CONN_REMAP_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, func);

    /* CONTEXT UNLOCK */
    sr_rwunlock(&main_shm->context_lock, SR_CONTEXT_LOCK_TIMEOUT, mode, conn->cid, func);
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

        ly_mod2 = ly_ctx_get_module_implemented(conn->ly_ctx, ly_mod->name);
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
sr_lycc_add_modules(sr_conn_ctx_t *conn, const sr_int_install_mod_t *new_mods, uint32_t new_mod_count)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    uint32_t i;
    sr_datastore_t ds;
    struct sr_ds_handle_s *ds_handle;

    for (i = 0; i < new_mod_count; ++i) {
        ly_mod = new_mods[i].ly_mod;

        /* init module for all DS plugins */
        for (ds = 0; ds < SR_DS_READ_COUNT; ++ds) {
            if ((ds == SR_DS_RUNNING) && !new_mods[i].module_ds.plugin_name[ds]) {
                /* disabled */
                continue;
            }

            /* find plugin */
            if ((err_info = sr_ds_handle_find(new_mods[i].module_ds.plugin_name[ds], conn,
                    (const struct sr_ds_handle_s **)&ds_handle))) {
                return err_info;
            }

            if (!ds_handle->init) {
                /* call conn_init */
                if ((err_info = ds_handle->plugin->conn_init_cb(conn, &ds_handle->plg_data))) {
                    return err_info;
                }
                ds_handle->init = 1;
            }

            /* call install */
            if ((err_info = ds_handle->plugin->install_cb(ly_mod, ds, new_mods[i].owner, new_mods[i].group,
                    new_mods[i].perm, ds_handle->plg_data))) {
                return err_info;
            }

            /* call init */
            if ((err_info = ds_handle->plugin->init_cb(ly_mod, ds, ds_handle->plg_data))) {
                return err_info;
            }
        }

        /* store module YANG with all submodules and imports */
        if ((err_info = sr_store_module_yang_r(ly_mod))) {
            return err_info;
        }
    }

    return NULL;
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
    struct lyd_node *sr_plg_name;
    struct ly_set del_set = {0};
    char *path;
    uint32_t i;
    sr_datastore_t ds;
    const struct sr_ds_handle_s *ds_handle;
    const struct sr_ntf_handle_s *ntf_handle;
    LY_ERR lyrc;
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
            lyrc = lyd_find_path(sr_mod, path, 0, &sr_plg_name);
            free(path);
            if ((ds == SR_DS_RUNNING) && lyrc) {
                /* 'running' disabled */
                continue;
            }
            SR_CHECK_INT_GOTO(lyrc, err_info, cleanup);

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
        if (!lyd_find_path(sr_mod, "replay-support", 0, NULL)) {
            /* find plugin */
            r = asprintf(&path, "plugin[datastore='%s']/name", sr_mod_ds2ident(SR_MOD_DS_NOTIF));
            SR_CHECK_MEM_GOTO(r == -1, err_info, cleanup);
            lyrc = lyd_find_path(sr_mod, path, 0, &sr_plg_name);
            free(path);
            SR_CHECK_INT_GOTO(lyrc, err_info, cleanup);
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
    LY_ERR lyrc;

    for (i = 0; i < mod_set->count; ++i) {
        ly_mod = mod_set->objs[i];

        /* get plugin name */
        if (asprintf(&path, "module[name='%s']/plugin[datastore='notification']/name", ly_mod->name) == -1) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }
        lyrc = lyd_find_path(sr_mods, path, 0, &sr_ntf_name);
        free(path);
        if (lyrc) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(sr_mods), NULL);
            goto cleanup;
        }

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

/**
 * @brief Append all stored DS data by implemented modules from context.
 *
 * @param[in] conn Connection to use.
 * @param[in] new_ctx New context to iterate over.
 * @param[out] data Data of each datastore.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lycc_append_data(sr_conn_ctx_t *conn, const struct ly_ctx *new_ctx, struct sr_data_update_set_s *data)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    sr_mod_t *shm_mod;
    const struct sr_ds_handle_s *ds_handle[SR_DS_READ_COUNT] = {0};
    sr_datastore_t ds;
    uint32_t idx = 0;

    while ((ly_mod = ly_ctx_get_module_iter(new_ctx, &idx))) {
        if (!ly_mod->implemented || !strcmp(ly_mod->name, "sysrepo")) {
            /* we need data of only implemented modules and never from internal SR module */
            continue;
        }

        /* get SHM mod */
        shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(conn), ly_mod->name);
        SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup);

        /* find startup plugin and append data */
        ds = SR_DS_STARTUP;
        if ((err_info = sr_ds_handle_find(conn->mod_shm.addr + shm_mod->plugins[ds], conn, &ds_handle[ds]))) {
            goto cleanup;
        }
        if ((err_info = sr_module_file_data_append(ly_mod, ds_handle, ds, NULL, 0, &data->start))) {
            goto cleanup;
        }

        /* find running plugin and append data, if not disabled */
        ds = SR_DS_RUNNING;
        if (shm_mod->plugins[ds]) {
            if ((err_info = sr_ds_handle_find(conn->mod_shm.addr + shm_mod->plugins[ds], conn, &ds_handle[ds]))) {
                goto cleanup;
            }
            if ((err_info = sr_module_file_data_append(ly_mod, ds_handle, ds, NULL, 0, &data->run))) {
                goto cleanup;
            }
        } else {
            data->run_disabled = 1;
        }

        /* find operational plugin and append data */
        ds = SR_DS_OPERATIONAL;
        if ((err_info = sr_ds_handle_find(conn->mod_shm.addr + shm_mod->plugins[ds], conn, &ds_handle[ds]))) {
            goto cleanup;
        }
        if ((err_info = sr_module_file_data_append(ly_mod, ds_handle, ds, NULL, 0, &data->oper))) {
            goto cleanup;
        }

        /* find factory-default plugin and append data */
        ds = SR_DS_FACTORY_DEFAULT;
        if ((err_info = sr_ds_handle_find(conn->mod_shm.addr + shm_mod->plugins[ds], conn, &ds_handle[ds]))) {
            goto cleanup;
        }
        if ((err_info = sr_module_file_data_append(ly_mod, ds_handle, ds, NULL, 0, &data->fdflt))) {
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
 * @param[in] append_data Optional data to append.
 * @param[out] new_data Data tree in @p new_ctx with optional @p append_data.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lycc_update_data_tree(const struct lyd_node *old_data, uint32_t parse_opts, const struct ly_ctx *new_ctx,
        const struct lyd_node *append_data, struct lyd_node **new_data)
{
    sr_error_info_t *err_info = NULL;
    char *data_json = NULL;

    *new_data = NULL;

    /* print the data of all the modules into JSON */
    if (lyd_print_mem(&data_json, old_data, LYD_JSON, LYD_PRINT_SHRINK | LYD_PRINT_WITHSIBLINGS)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(old_data), NULL);
        goto cleanup;
    }

    /* try to load it into the new updated context skipping any unknown nodes */
    if (lyd_parse_data_mem(new_ctx, data_json, LYD_JSON, parse_opts, 0, new_data)) {
        sr_errinfo_new_ly(&err_info, new_ctx, NULL);
        goto cleanup;
    }

    if (append_data) {
        /* link to the new data */
        if (!(*new_data)) {
            if (lyd_dup_siblings(append_data, NULL, LYD_DUP_RECURSIVE, new_data)) {
                sr_errinfo_new_ly(&err_info, new_ctx, NULL);
                goto cleanup;
            }
        } else if (lyd_merge_siblings(new_data, append_data, 0)) {
            sr_errinfo_new_ly(&err_info, new_ctx, NULL);
            goto cleanup;
        }
    }

cleanup:
    free(data_json);
    return err_info;
}

sr_error_info_t *
sr_lycc_update_data(sr_conn_ctx_t *conn, const struct ly_ctx *new_ctx, const struct lyd_node *mod_data,
        struct sr_data_update_s *data_info)
{
    sr_error_info_t *err_info = NULL;
    uint32_t parse_opts;

    memset(data_info, 0, sizeof *data_info);

    /* parse all the startup/running/operational/factory-default data using the old context (that must succeed) */
    if ((err_info = sr_lycc_append_data(conn, conn->ly_ctx, &data_info->old))) {
        goto cleanup;
    }

    /* update data for the new context */
    parse_opts = LYD_PARSE_NO_STATE | LYD_PARSE_ONLY;
    if ((err_info = sr_lycc_update_data_tree(data_info->old.start, parse_opts, new_ctx, mod_data, &data_info->new.start))) {
        goto cleanup;
    }
    if (data_info->old.run_disabled) {
        data_info->new.run_disabled = 1;
    } else {
        if ((err_info = sr_lycc_update_data_tree(data_info->old.run, parse_opts, new_ctx, mod_data, &data_info->new.run))) {
            goto cleanup;
        }
    }
    if ((err_info = sr_lycc_update_data_tree(data_info->old.fdflt, parse_opts, new_ctx, mod_data, &data_info->new.fdflt))) {
        goto cleanup;
    }
    parse_opts &= ~LYD_PARSE_NO_STATE;
    if ((err_info = sr_lycc_update_data_tree(data_info->old.oper, parse_opts, new_ctx, NULL, &data_info->new.oper))) {
        goto cleanup;
    }

    /* fully validate complete startup, running, and factory-default datastore */
    if (lyd_validate_all(&data_info->new.start, new_ctx, LYD_VALIDATE_NO_STATE, NULL)) {
        sr_errinfo_new_ly(&err_info, new_ctx, NULL);
        err_info->err[0].err_code = SR_ERR_VALIDATION_FAILED;
        sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, "Invalid startup datastore data.");
        goto cleanup;
    }
    if (!data_info->new.run_disabled && lyd_validate_all(&data_info->new.run, new_ctx, LYD_VALIDATE_NO_STATE, NULL)) {
        sr_errinfo_new_ly(&err_info, new_ctx, NULL);
        err_info->err[0].err_code = SR_ERR_VALIDATION_FAILED;
        sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, "Invalid running datastore data.");
        goto cleanup;
    }
    if (lyd_validate_all(&data_info->new.fdflt, new_ctx, LYD_VALIDATE_NO_STATE, NULL)) {
        sr_errinfo_new_ly(&err_info, new_ctx, NULL);
        err_info->err[0].err_code = SR_ERR_VALIDATION_FAILED;
        sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, "Invalid factory-default datastore data.");
        goto cleanup;
    }

cleanup:
    return err_info;
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
sr_lycc_store_data_ds_if_differ(sr_conn_ctx_t *conn, const struct ly_ctx *new_ctx, sr_datastore_t ds,
        const struct lyd_node *sr_mods, struct lyd_node **old_data, struct lyd_node **new_data)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *new_ly_mod, *old_ly_mod;
    struct lyd_node *new_mod_data = NULL, *old_mod_data = NULL, *mod_diff = NULL;
    const struct sr_ds_handle_s *ds_handle;
    struct ly_set *set;
    char *xpath;
    uint32_t idx = 0, ly_log_opts = 0;
    int diff;
    LY_ERR lyrc;

    while ((new_ly_mod = ly_ctx_get_module_iter(new_ctx, &idx))) {
        if (!new_ly_mod->implemented || !strcmp(new_ly_mod->name, "sysrepo")) {
            continue;
        }

        old_ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, new_ly_mod->name);
        if (old_ly_mod && !sr_module_has_data(old_ly_mod, 0) && !sr_module_has_data(new_ly_mod, 0)) {
            /* neither of the modules has configuration data so they cannot be changed */
            continue;
        }

        /* get old and new data of the module */
        lyd_free_siblings(new_mod_data);
        lyd_free_siblings(old_mod_data);
        new_mod_data = sr_module_data_unlink(new_data, new_ly_mod);
        if (old_ly_mod) {
            old_mod_data = sr_module_data_unlink(old_data, old_ly_mod);
        } else {
            old_mod_data = NULL;
        }

        /* get plugin name */
        if (asprintf(&xpath, "module[name='%s']/plugin[datastore='%s']/name", new_ly_mod->name, sr_ds2ident(ds)) == -1) {
            SR_ERRINFO_MEM(&err_info);
            break;
        }
        lyrc = lyd_find_xpath(sr_mods, xpath, &set);
        free(xpath);
        if (lyrc) {
            sr_errinfo_new_ly(&err_info, conn->ly_ctx, NULL);
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
        diff = 0;
        ly_temp_log_options(&ly_log_opts);
        if (lyd_diff_siblings(old_mod_data, new_mod_data, LYD_DIFF_DEFAULTS, &mod_diff)) {
            /* assume it is because a schema node was not found in a context but there is a diff,
             * this can always happen because nodes can be added wtih default values/removed, even in a single
             * module so neither old nor new context can be used for all the cases */
            diff = 1;
        } else if (mod_diff) {
            diff = 1;
        }
        ly_temp_log_options(NULL);

        if (diff) {
            /* store new data */
            if ((err_info = ds_handle->plugin->store_cb(new_ly_mod, ds, mod_diff, new_mod_data, ds_handle->plg_data))) {
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
sr_lycc_store_data_if_differ(sr_conn_ctx_t *conn, const struct ly_ctx *new_ctx, const struct lyd_node *sr_mods,
        struct sr_data_update_s *data_info)
{
    sr_error_info_t *err_info = NULL;

    /* startup */
    if ((err_info = sr_lycc_store_data_ds_if_differ(conn, new_ctx, SR_DS_STARTUP, sr_mods, &data_info->old.start,
            &data_info->new.start))) {
        return err_info;
    }

    /* running */
    if ((err_info = sr_lycc_store_data_ds_if_differ(conn, new_ctx, SR_DS_RUNNING, sr_mods, &data_info->old.run,
            &data_info->new.run))) {
        return err_info;
    }

    /* operational */
    if ((err_info = sr_lycc_store_data_ds_if_differ(conn, new_ctx, SR_DS_OPERATIONAL, sr_mods, &data_info->old.oper,
            &data_info->new.oper))) {
        return err_info;
    }

    /* factory-default */
    if ((err_info = sr_lycc_store_data_ds_if_differ(conn, new_ctx, SR_DS_FACTORY_DEFAULT, sr_mods, &data_info->old.fdflt,
            &data_info->new.fdflt))) {
        return err_info;
    }

    return NULL;
}

void
sr_lycc_update_data_clear(struct sr_data_update_s *data_info)
{
    lyd_free_siblings(data_info->old.start);
    lyd_free_siblings(data_info->old.run);
    lyd_free_siblings(data_info->old.oper);
    lyd_free_siblings(data_info->old.fdflt);

    lyd_free_siblings(data_info->new.start);
    lyd_free_siblings(data_info->new.run);
    lyd_free_siblings(data_info->new.oper);
    lyd_free_siblings(data_info->new.fdflt);
}
