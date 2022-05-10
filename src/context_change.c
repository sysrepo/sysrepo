/**
 * @file context_change.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Sysrepo context change routines
 *
 * @copyright
 * Copyright (c) 2021 Deutsche Telekom AG.
 * Copyright (c) 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "context_change.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <libyang/libyang.h>

#include "common.h"
#include "common_types.h"
#include "compat.h"
#include "config.h"
#include "log.h"
#include "plugins_datastore.h"
#include "plugins_notification.h"
#include "shm_ext.h"
#include "shm_mod.h"
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

    /* check whether the context is current and does not need to be udpated */
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

        /* context will be destroyed, free the cache */
        sr_conn_flush_cache(conn);

        /* remap mod SHM */
        if ((err_info = sr_shm_remap(&conn->mod_shm, 0))) {
            goto cleanup_unlock;
        }

        /* context was updated, create a new one with the current modules */
        if ((err_info = sr_ly_ctx_init(conn->opts, conn->ext_cb, conn->ext_cb_data, &new_ctx))) {
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
        ly_ctx_destroy(conn->ly_ctx);
        conn->ly_ctx = new_ctx;
        new_ctx = NULL;
        conn->content_id = main_shm->content_id;

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
sr_lycc_check_add_module(sr_conn_ctx_t *conn, const struct ly_ctx *new_ctx)
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
sr_lycc_add_module(sr_conn_ctx_t *conn, const struct ly_set *mod_set, const sr_module_ds_t *module_ds, const char *owner,
        const char *group, mode_t perm)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    uint32_t i;
    sr_datastore_t ds;
    const struct srplg_ds_s *ds_plg;
    mode_t mod_perm;
    int rc;

    if (!group && strlen(SR_GROUP)) {
        /* set default group */
        group = SR_GROUP;
    }

    for (i = 0; i < mod_set->count; ++i) {
        ly_mod = mod_set->objs[i];

        /* init module for all DS plugins */
        for (ds = 0; ds < SR_DS_COUNT; ++ds) {
            /* find plugin */
            if (module_ds == &sr_default_module_ds) {
                ds_plg = (struct srplg_ds_s *)sr_internal_ds_plugins[0];
            } else if ((err_info = sr_ds_plugin_find(module_ds->plugin_name[ds], conn, &ds_plg))) {
                return err_info;
            }

            /* get module permissions */
            mod_perm = perm ? perm : sr_module_default_mode(ly_mod);

            /* call init */
            if ((rc = ds_plg->init_cb(ly_mod, ds, owner, group, mod_perm))) {
                SR_ERRINFO_DSPLUGIN(&err_info, rc, "init", ds_plg->name, ly_mod->name);
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
    const struct srplg_ds_s *ds_plg;
    const struct srplg_ntf_s *ntf_plg;
    int rc;
    LY_ERR lyrc;

    for (i = 0; i < mod_set->count; ++i) {
        ly_mod = mod_set->objs[i];
        if (!sr_mod) {
            sr_mod = lyd_child(sr_del_mods);
        } else {
            sr_mod = sr_mod->next;
        }
        assert(!strcmp(ly_mod->name, lyd_get_value(lyd_child(sr_mod))));

        /* destroy module for all DS plugins */
        for (ds = 0; ds < SR_DS_COUNT; ++ds) {
            /* find plugin */
            rc = asprintf(&path, "plugin[datastore='%s']/name", sr_mod_ds2str(ds));
            SR_CHECK_MEM_GOTO(rc == -1, err_info, cleanup);
            lyrc = lyd_find_path(sr_mod, path, 0, &sr_plg_name);
            free(path);
            SR_CHECK_INT_GOTO(lyrc, err_info, cleanup);
            if ((err_info = sr_ds_plugin_find(lyd_get_value(sr_plg_name), conn, &ds_plg))) {
                goto cleanup;
            }

            /* call destroy */
            if ((rc = ds_plg->destroy_cb(ly_mod, ds))) {
                SR_ERRINFO_DSPLUGIN(&err_info, rc, "destroy", ds_plg->name, ly_mod->name);
                goto cleanup;
            }
        }

        /* destroy notifications if replay support was enabled */
        if (!lyd_find_path(sr_mod, "replay-support", 0, NULL)) {
            /* find plugin */
            rc = asprintf(&path, "plugin[datastore='%s']/name", sr_mod_ds2str(SR_MOD_DS_NOTIF));
            SR_CHECK_MEM_GOTO(rc == -1, err_info, cleanup);
            lyrc = lyd_find_path(sr_mod, path, 0, &sr_plg_name);
            free(path);
            SR_CHECK_INT_GOTO(lyrc, err_info, cleanup);
            if ((err_info = sr_ntf_plugin_find(lyd_get_value(sr_plg_name), conn, &ntf_plg))) {
                goto cleanup;
            }

            /* call destroy */
            if ((rc = ntf_plg->destroy_cb(ly_mod))) {
                SR_ERRINFO_DSPLUGIN(&err_info, rc, "destroy", ntf_plg->name, ly_mod->name);
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

static void
sr_ly_update_module_imp_data_free_cb(void *module_data, void *UNUSED(user_data))
{
    free(module_data);
}

static LY_ERR
sr_ly_update_module_imp_cb(const char *mod_name, const char *mod_rev, const char *submod_name, const char *UNUSED(submod_rev),
        void *user_data, LYS_INFORMAT *format, const char **module_data, ly_module_imp_data_free_clb *free_module_data)
{
    sr_error_info_t *err_info = NULL;
    struct sr_ly_upd_mod_imp_data *data = user_data;

    if (strcmp(mod_name, data->name) || mod_rev || submod_name) {
        /* not this module, in specific revision (presumably the old), or a submodule requested */
        return LY_ENOTFOUND;
    }

    /* read schema file contents */
    if ((err_info = sr_file_read(data->schema_path, (char **)module_data))) {
        sr_errinfo_free(&err_info);
        return LY_ESYS;
    }

    *format = data->format;
    *free_module_data = sr_ly_update_module_imp_data_free_cb;
    return LY_SUCCESS;
}

sr_error_info_t *
sr_lycc_upd_module_new_context(sr_conn_ctx_t *conn, const char *schema_path, LYS_INFORMAT format, const char *search_dirs,
        const struct lys_module *old_mod, struct ly_ctx **new_ctx, const struct lys_module **upd_mod)
{
    sr_error_info_t *err_info = NULL;
    char *sdirs_str = NULL, *ptr, *ptr2 = NULL;
    const char **features = NULL;
    size_t sdir_count = 0, feat_count = 0;
    struct ly_in *in = NULL;
    struct ly_set mod_set = {0};
    struct sr_ly_upd_mod_imp_data imp_cb_data;
    struct lysp_feature *f = NULL;
    uint32_t i;

    /* create new context */
    if ((err_info = sr_ly_ctx_init(conn->opts, conn->ext_cb, conn->ext_cb_data, new_ctx))) {
        goto cleanup;
    }

    if (search_dirs) {
        sdirs_str = strdup(search_dirs);
        SR_CHECK_MEM_GOTO(!sdirs_str, err_info, cleanup);

        /* add each search dir */
        for (ptr = strtok_r(sdirs_str, ":", &ptr2); ptr; ptr = strtok_r(NULL, ":", &ptr2)) {
            if (!ly_ctx_set_searchdir(*new_ctx, ptr)) {
                /* added (it was not already there) */
                ++sdir_count;
            }
        }
    }

    /* prepare CB data */
    imp_cb_data.name = old_mod->name;
    imp_cb_data.schema_path = schema_path;
    imp_cb_data.format = format;

    /* set import callback in case a module would try to import this module to be updated, to not load the old revision */
    ly_ctx_set_module_imp_clb(*new_ctx, sr_ly_update_module_imp_cb, &imp_cb_data);

    /* use context to load modules without the updated one */
    if (ly_set_add(&mod_set, (void *)old_mod, 1, NULL)) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    if ((err_info = sr_shmmod_ctx_load_modules(SR_CONN_MOD_SHM(conn), *new_ctx, &mod_set))) {
        goto cleanup;
    }

    /* by default all features are disabled */
    features = malloc(sizeof *features);
    SR_CHECK_MEM_GOTO(!features, err_info, cleanup);
    features[feat_count] = NULL;
    feat_count = 1;

    /* collect current enabled features */
    i = 0;
    while ((f = lysp_feature_next(f, old_mod->parsed, &i))) {
        if (f->flags & LYS_FENABLED) {
            features = sr_realloc(features, (feat_count + 1) * sizeof *features);
            SR_CHECK_MEM_GOTO(!features, err_info, cleanup);
            features[feat_count - 1] = f->name;
            features[feat_count] = NULL;
            ++feat_count;
        }
    }

    /* try to parse the updated module, if already an import, at least implement it and set the features */
    if (ly_in_new_filepath(schema_path, 0, &in)) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Failed to parse \"%s\".", schema_path);
        goto cleanup;
    }
    if (lys_parse(*new_ctx, in, format, features, (struct lys_module **)upd_mod)) {
        sr_errinfo_new_ly(&err_info, *new_ctx);
        goto cleanup;
    }

    /* compile */
    if (ly_ctx_compile(*new_ctx)) {
        sr_errinfo_new_ly(&err_info, *new_ctx);
        goto cleanup;
    }

cleanup:
    if (sdir_count) {
        /* remove added search dirs */
        ly_ctx_unset_searchdir_last(*new_ctx, sdir_count);
    }

    free(sdirs_str);
    free(features);
    ly_set_erase(&mod_set, NULL);
    ly_in_free(in, 0);
    if (err_info) {
        ly_ctx_destroy(*new_ctx);
        *new_ctx = NULL;
    }
    return err_info;
}

sr_error_info_t *
sr_lycc_check_upd_module(sr_conn_ctx_t *conn, const struct lys_module *upd_mod, const struct lys_module *old_mod)
{
    sr_error_info_t *err_info = NULL;

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

    /* check subscriptions in the new context */
    if ((err_info = sr_shmext_check_sub_all(conn, upd_mod->ctx))) {
        return err_info;
    }

    return NULL;
}

sr_error_info_t *
sr_lycc_upd_module(const struct lys_module *upd_mod, const struct lys_module *old_mod)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set del_set = {0};

    /* remove old module files */
    if ((err_info = sr_remove_module_yang_r(old_mod, upd_mod->ctx, &del_set))) {
        goto cleanup;
    }

    /* store updated module files */
    if ((err_info = sr_store_module_yang_r(upd_mod))) {
        goto cleanup;
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
    const struct srplg_ntf_s *ntf_plg;
    uint32_t i;
    int rc;
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
            sr_errinfo_new_ly(&err_info, LYD_CTX(sr_mods));
            goto cleanup;
        }

        /* find plugin */
        if ((err_info = sr_ntf_plugin_find(lyd_get_value(sr_ntf_name), conn, &ntf_plg))) {
            goto cleanup;
        }

        if (enable) {
            /* call init */
            if ((rc = ntf_plg->init_cb(ly_mod))) {
                SR_ERRINFO_DSPLUGIN(&err_info, rc, "init", ntf_plg->name, ly_mod->name);
                goto cleanup;
            }
        } else {
            /* call destroy */
            if ((rc = ntf_plg->destroy_cb(ly_mod))) {
                SR_ERRINFO_DSPLUGIN(&err_info, rc, "destroy", ntf_plg->name, ly_mod->name);
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
 * @param[in] ly_ctx New context to iterate over.
 * @param[out] start_data Startup data tree.
 * @param[out] run_data Running data tree.
 * @param[out] oper_data Operational stored edit.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lycc_append_data(sr_conn_ctx_t *conn, const struct ly_ctx *ly_ctx, struct lyd_node **start_data,
        struct lyd_node **run_data, struct lyd_node **oper_data)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    sr_mod_t *shm_mod;
    const struct srplg_ds_s *ds_plg[SR_DS_COUNT] = {0};
    sr_datastore_t ds;
    uint32_t idx = 0;

    while ((ly_mod = ly_ctx_get_module_iter(ly_ctx, &idx))) {
        if (!ly_mod->implemented || !strcmp(ly_mod->name, "sysrepo")) {
            /* we need data of only implemented modules and never from internal SR module */
            continue;
        }

        /* get SHM mod */
        shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(conn), ly_mod->name);
        SR_CHECK_INT_RET(!shm_mod, err_info);

        /* find startup plugin and append data */
        ds = SR_DS_STARTUP;
        if ((err_info = sr_ds_plugin_find(conn->mod_shm.addr + shm_mod->plugins[ds], conn, &ds_plg[ds]))) {
            return err_info;
        }
        if ((err_info = sr_module_file_data_append(ly_mod, ds_plg, ds, NULL, 0, start_data))) {
            return err_info;
        }

        /* find running plugin and append data */
        ds = SR_DS_RUNNING;
        if ((err_info = sr_ds_plugin_find(conn->mod_shm.addr + shm_mod->plugins[ds], conn, &ds_plg[ds]))) {
            return err_info;
        }
        if ((err_info = sr_module_file_data_append(ly_mod, ds_plg, ds, NULL, 0, run_data))) {
            return err_info;
        }

        /* find operational plugin and append data */
        ds = SR_DS_OPERATIONAL;
        if ((err_info = sr_ds_plugin_find(conn->mod_shm.addr + shm_mod->plugins[ds], conn, &ds_plg[ds]))) {
            return err_info;
        }
        if ((err_info = sr_module_file_data_append(ly_mod, ds_plg, ds, NULL, 0, oper_data))) {
            return err_info;
        }
    }

    return err_info;
}

/**
 * @brief Update data parsed with old context to be parsed with a new context.
 *
 * @param[in] old_data Old data to update.
 * @param[in] parse_opts Parse options to use for parsing back @p old_data.
 * @param[in] ly_ctx New context to use.
 * @param[in] append_data Optional data to append.
 * @param[out] new_data Data tree in @p ly_ctx with optional @p append_data.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lycc_update_data_tree(const struct lyd_node *old_data, uint32_t parse_opts, const struct ly_ctx *ly_ctx,
        const struct lyd_node *append_data, struct lyd_node **new_data)
{
    sr_error_info_t *err_info = NULL;
    char *data_json = NULL;

    *new_data = NULL;

    /* print the data of all the modules into JSON */
    if (lyd_print_mem(&data_json, old_data, LYD_JSON, LYD_PRINT_SHRINK | LYD_PRINT_WITHSIBLINGS)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(old_data));
        goto cleanup;
    }

    /* try to load it into the new updated context skipping any unknown nodes */
    if (lyd_parse_data_mem(ly_ctx, data_json, LYD_JSON, parse_opts, 0, new_data)) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    if (append_data) {
        /* link to the new data */
        if (!(*new_data)) {
            if (lyd_dup_siblings(append_data, NULL, LYD_DUP_RECURSIVE, new_data)) {
                sr_errinfo_new_ly(&err_info, ly_ctx);
                goto cleanup;
            }
        } else if (lyd_merge_siblings(new_data, append_data, 0)) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            goto cleanup;
        }
    }

cleanup:
    free(data_json);
    return err_info;
}

sr_error_info_t *
sr_lycc_update_data(sr_conn_ctx_t *conn, const struct ly_ctx *ly_ctx, const struct lyd_node *mod_data,
        struct lyd_node **old_s_data, struct lyd_node **new_s_data, struct lyd_node **old_r_data,
        struct lyd_node **new_r_data, struct lyd_node **old_o_data, struct lyd_node **new_o_data)
{
    sr_error_info_t *err_info = NULL;
    uint32_t parse_opts;

    *old_s_data = NULL;
    *new_s_data = NULL;
    *old_r_data = NULL;
    *new_r_data = NULL;
    *old_o_data = NULL;
    *new_o_data = NULL;

    /* parse all the startup/running data using the old context (that must succeed) */
    if ((err_info = sr_lycc_append_data(conn, conn->ly_ctx, old_s_data, old_r_data, old_o_data))) {
        goto cleanup;
    }

    /* update data for the new context */
    parse_opts = LYD_PARSE_NO_STATE | LYD_PARSE_ONLY;
    if ((err_info = sr_lycc_update_data_tree(*old_s_data, parse_opts, ly_ctx, mod_data, new_s_data))) {
        goto cleanup;
    }
    if ((err_info = sr_lycc_update_data_tree(*old_r_data, parse_opts, ly_ctx, mod_data, new_r_data))) {
        goto cleanup;
    }
    parse_opts &= ~LYD_PARSE_NO_STATE;
    if ((err_info = sr_lycc_update_data_tree(*old_o_data, parse_opts, ly_ctx, NULL, new_o_data))) {
        goto cleanup;
    }

    /* fully validate complete startup and running datastore */
    if (lyd_validate_all(new_s_data, ly_ctx, LYD_VALIDATE_NO_STATE, NULL) ||
            lyd_validate_all(new_r_data, ly_ctx, LYD_VALIDATE_NO_STATE, NULL)) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        err_info->err[0].err_code = SR_ERR_VALIDATION_FAILED;
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
sr_lycc_store_data_ds_if_differ(sr_conn_ctx_t *conn, const struct ly_ctx *ly_ctx, sr_datastore_t ds,
        const struct lyd_node *sr_mods, struct lyd_node **old_data, struct lyd_node **new_data)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *new_ly_mod, *old_ly_mod;
    struct lyd_node *new_mod_data = NULL, *old_mod_data = NULL;
    const struct srplg_ds_s *ds_plg;
    struct ly_set *set;
    char *xpath;
    uint32_t idx = 0;
    int rc, differ;
    LY_ERR lyrc;

    while ((new_ly_mod = ly_ctx_get_module_iter(ly_ctx, &idx))) {
        if (!new_ly_mod->implemented || sr_module_is_internal(new_ly_mod)) {
            continue;
        }

        old_ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, new_ly_mod->name);

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
        if (asprintf(&xpath, "module[name='%s']/plugin[datastore='%s']/name", new_ly_mod->name, sr_ds2str(ds)) == -1) {
            SR_ERRINFO_MEM(&err_info);
            break;
        }
        lyrc = lyd_find_xpath(sr_mods, xpath, &set);
        free(xpath);
        if (lyrc) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(sr_mods));
            break;
        } else if (set->count != 1) {
            SR_ERRINFO_INT(&err_info);
            break;
        }

        /* get plugin */
        err_info = sr_ds_plugin_find(lyd_get_value(set->dnodes[0]), conn, &ds_plg);
        ly_set_free(set, NULL);
        if (err_info) {
            break;
        }

        /* check whether the data differs and needs to be stored */
        if ((rc = ds_plg->update_differ_cb(old_ly_mod, old_mod_data, new_ly_mod, new_mod_data, &differ))) {
            SR_ERRINFO_DSPLUGIN(&err_info, rc, "update_differ", ds_plg->name, new_ly_mod->name);
            break;
        }

        if (differ) {
            /* store data */
            if ((rc = ds_plg->store_cb(new_ly_mod, ds, new_mod_data))) {
                SR_ERRINFO_DSPLUGIN(&err_info, rc, "store", ds_plg->name, new_ly_mod->name);
                break;
            }
        }
    }

    lyd_free_siblings(new_mod_data);
    lyd_free_siblings(old_mod_data);
    return err_info;
}

sr_error_info_t *
sr_lycc_store_data_if_differ(sr_conn_ctx_t *conn, const struct ly_ctx *ly_ctx, const struct lyd_node *sr_mods,
        struct lyd_node **old_s_data, struct lyd_node **new_s_data, struct lyd_node **old_r_data,
        struct lyd_node **new_r_data, struct lyd_node **old_o_data, struct lyd_node **new_o_data)
{
    sr_error_info_t *err_info = NULL;

    /* startup */
    if ((err_info = sr_lycc_store_data_ds_if_differ(conn, ly_ctx, SR_DS_STARTUP, sr_mods, old_s_data, new_s_data))) {
        return err_info;
    }

    /* running */
    if ((err_info = sr_lycc_store_data_ds_if_differ(conn, ly_ctx, SR_DS_RUNNING, sr_mods, old_r_data, new_r_data))) {
        return err_info;
    }

    /* operational */
    if ((err_info = sr_lycc_store_data_ds_if_differ(conn, ly_ctx, SR_DS_OPERATIONAL, sr_mods, old_o_data, new_o_data))) {
        return err_info;
    }

    return NULL;
}
