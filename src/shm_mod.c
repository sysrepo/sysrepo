/**
 * @file shm_mod.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief main SHM routines modifying module information
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

#include "shm.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
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
#include "log.h"
#include "modinfo.h"
#include "plugins_datastore.h"

sr_error_info_t *
sr_shmmod_collect_edit(const struct lyd_node *edit, struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    const struct lyd_node *root;

    /* add all the modules from the edit into our array */
    ly_mod = NULL;
    LY_LIST_FOR(edit, root) {
        if (lyd_owner_module(root) == ly_mod) {
            continue;
        } else if (!strcmp(lyd_owner_module(root)->name, "sysrepo")) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Data of internal module \"sysrepo\" cannot be modified.");
            return err_info;
        }

        /* remember last mod, good chance it will also be the module of some next data nodes */
        ly_mod = lyd_owner_module(root);

        /* remember the module */
        if ((err_info = sr_modinfo_add(ly_mod, NULL, 0, mod_info))) {
            return err_info;
        }
    }

    return NULL;
}

sr_error_info_t *
sr_shmmod_collect_xpath(const struct ly_ctx *ly_ctx, const char *xpath, sr_datastore_t ds, int store_xpath,
        struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    const struct lysc_node *snode;
    struct ly_set *set = NULL;
    uint32_t i;

    /* learn what nodes are needed for evaluation */
    if (lys_find_xpath_atoms(ly_ctx, NULL, xpath, 0, &set)) {
        sr_errinfo_new_ly(&err_info, (struct ly_ctx *)ly_ctx);
        goto cleanup;
    }

    /* add all the modules of the nodes */
    ly_mod = NULL;
    for (i = 0; i < set->count; ++i) {
        snode = set->snodes[i];

        /* skip uninteresting nodes */
        if ((snode->nodetype & (LYS_RPC | LYS_NOTIF)) || ((snode->flags & LYS_CONFIG_R) && SR_IS_CONVENTIONAL_DS(ds))) {
            continue;
        }

        if (snode->module == ly_mod) {
            /* skip already-added modules */
            continue;
        }
        ly_mod = snode->module;

        if (!ly_mod->implemented || !strcmp(ly_mod->name, "sysrepo") || !strcmp(ly_mod->name, "ietf-netconf")) {
            /* skip import-only modules, the internal sysrepo module, and ietf-netconf (as it has no data, only in libyang) */
            continue;
        }

        if ((err_info = sr_modinfo_add(ly_mod, store_xpath ? xpath : NULL, 0, mod_info))) {
            goto cleanup;
        }
    }

cleanup:
    ly_set_free(set, NULL);
    return err_info;
}

sr_error_info_t *
sr_shmmod_get_rpc_deps(sr_main_shm_t *main_shm, const char *path, int output, sr_dep_t **shm_deps, uint16_t *shm_dep_count)
{
    sr_error_info_t *err_info = NULL;
    sr_rpc_t *shm_rpc;

    /* find the RPC in SHM */
    shm_rpc = sr_shmmain_find_rpc(main_shm, path);
    SR_CHECK_INT_RET(!shm_rpc, err_info);

    /* collect dependencies */
    *shm_deps = (sr_dep_t *)(((char *)main_shm) + (output ? shm_rpc->out_deps : shm_rpc->in_deps));
    *shm_dep_count = (output ? shm_rpc->out_dep_count : shm_rpc->in_dep_count);

    return NULL;
}

sr_error_info_t *
sr_shmmod_get_notif_deps(sr_main_shm_t *main_shm, const struct lys_module *notif_mod, const char *path,
        sr_dep_t **shm_deps, uint16_t *shm_dep_count)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    sr_notif_t *shm_notif;
    uint32_t i;

    /* find the module in SHM */
    shm_mod = sr_shmmain_find_module(main_shm, notif_mod->name);
    SR_CHECK_INT_RET(!shm_mod, err_info);

    /* find the notification in SHM */
    shm_notif = (sr_notif_t *)(((char *)main_shm) + shm_mod->notifs);
    for (i = 0; i < shm_mod->notif_count; ++i) {
        if (!strcmp(path, ((char *)main_shm) + shm_notif[i].path)) {
            break;
        }
    }
    SR_CHECK_INT_RET(i == shm_mod->notif_count, err_info);

    /* collect dependencies */
    *shm_deps = (sr_dep_t *)(((char *)main_shm) + shm_notif[i].deps);
    *shm_dep_count = shm_notif[i].dep_count;

    return NULL;
}

/**
 * @brief Collect dependent modules from a leafref dependency.
 *
 * @param[in] taregt_path Target leafref path.
 * @param[in] target_module Target module name.
 * @param[in] ly_ctx libyang context.
 * @param[in,out] mod_info Mod info to add to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmod_collect_deps_lref(const char *target_path, const char *target_module, struct ly_ctx *ly_ctx,
        struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;

    /* find ly module */
    ly_mod = ly_ctx_get_module_implemented(ly_ctx, target_module);
    SR_CHECK_INT_RET(!ly_mod, err_info);

    /* add dependency */
    if ((err_info = sr_modinfo_add(ly_mod, target_path, 0, mod_info))) {
        return err_info;
    }

    return NULL;
}

/**
 * @brief Collect dependent modules from an instance-identifier dependency.
 *
 * @param[in] source_path Source inst-id path.
 * @param[in] default_target_path Optional inst-id default value.
 * @param[in] ly_ctx libyang context.
 * @param[in] data Instantiated data.
 * @param[in,out] mod_info Mod info to add to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmod_collect_deps_instid(const char *source_path, const char *default_target_path, struct ly_ctx *ly_ctx,
        const struct lyd_node *data, struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    struct ly_set *set = NULL;
    const char *val_str;
    char *str;
    uint32_t i;
    LY_ERR lyrc;

    if (data) {
        lyrc = lyd_find_xpath(data, source_path, &set);
    } else {
        /* no data, just fake empty set */
        lyrc = ly_set_new(&set);
    }
    if (lyrc) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    if (set->count) {
        /* extract module names from all the existing instance-identifiers */
        for (i = 0; i < set->count; ++i) {
            assert(set->dnodes[i]->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST));
            /* it can be a union and a non-instid value stored */
            if (((struct lyd_node_term *)set->dnodes[i])->value.realtype->basetype != LY_TYPE_INST) {
                continue;
            }

            /* get target module name from the value */
            val_str = lyd_get_value(set->dnodes[i]);
            str = sr_get_first_ns(val_str);
            ly_mod = ly_ctx_get_module_implemented(ly_ctx, str);
            free(str);
            SR_CHECK_INT_GOTO(!ly_mod, err_info, cleanup);

            /* add module */
            if ((err_info = sr_modinfo_add(ly_mod, val_str, 0, mod_info))) {
                goto cleanup;
            }
        }
    } else if (default_target_path) {
        /* assume a default value will be used even though it may not be */
        str = sr_get_first_ns(default_target_path);
        ly_mod = ly_ctx_get_module_implemented(ly_ctx, str);
        free(str);
        SR_CHECK_INT_GOTO(!ly_mod, err_info, cleanup);

        if ((err_info = sr_modinfo_add(ly_mod, default_target_path, 0, mod_info))) {
            goto cleanup;
        }
    }

cleanup:
    ly_set_free(set, NULL);
    return err_info;
}

/**
 * @brief Collect dependent modules from an XPath dependency.
 *
 * @param[in] expr XPath expression itself.
 * @param[in] main_shm_addr Main SHM address.
 * @param[in] target_modules Module names array.
 * @param[in] mod_name_count Module name count.
 * @param[in] ly_ctx libyang context.
 * @param[in,out] mod_info Mod info to add to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmod_collect_deps_xpath(const char *expr, char *main_shm_addr, off_t *target_modules, uint16_t target_mod_count,
        struct ly_ctx *ly_ctx, struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    uint16_t i;

    /* add dependencies for all the modules */
    for (i = 0; i < target_mod_count; ++i) {
        /* find ly module */
        ly_mod = ly_ctx_get_module_implemented(ly_ctx, main_shm_addr + target_modules[i]);
        SR_CHECK_INT_RET(!ly_mod, err_info);

        /* add dependency */
        if ((err_info = sr_modinfo_add(ly_mod, expr, 0, mod_info))) {
            return err_info;
        }
    }

    return NULL;
}

sr_error_info_t *
sr_shmmod_collect_deps(sr_main_shm_t *main_shm, sr_dep_t *shm_deps, uint16_t shm_dep_count, struct ly_ctx *ly_ctx,
        const struct lyd_node *data, struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    const char *str1, *str2;
    off_t *mod_names;

    /* collect all possibly required modules (because of inst-ids) into a set */
    for (i = 0; i < shm_dep_count; ++i) {
        switch (shm_deps[i].type) {
        case SR_DEP_LREF:
            str1 = (char *)main_shm + shm_deps[i].lref.target_path;
            str2 = (char *)main_shm + shm_deps[i].lref.target_module;
            if ((err_info = sr_shmmod_collect_deps_lref(str1, str2, ly_ctx, mod_info))) {
                goto cleanup;
            }
            break;
        case SR_DEP_INSTID:
            str1 = (char *)main_shm + shm_deps[i].instid.source_path;
            str2 = shm_deps[i].instid.default_target_path ? (char *)main_shm +
                    shm_deps[i].instid.default_target_path : NULL;
            if ((err_info = sr_shmmod_collect_deps_instid(str1, str2, ly_ctx, data, mod_info))) {
                goto cleanup;
            }
            break;
        case SR_DEP_XPATH:
            str1 = (char *)main_shm + shm_deps[i].xpath.expr;
            mod_names = (off_t *)((char *)main_shm + shm_deps[i].xpath.target_modules);
            if ((err_info = sr_shmmod_collect_deps_xpath(str1, (char *)main_shm, mod_names,
                    shm_deps[i].xpath.target_mod_count, ly_ctx, mod_info))) {
                goto cleanup;
            }
            break;
        default:
            SR_ERRINFO_INT(&err_info);
            goto cleanup;
        }
    }

    /* success */

cleanup:
    return err_info;
}

sr_error_info_t *
sr_shmmod_collect_deps_modinfo(struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    uint32_t i;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        switch (mod->state & MOD_INFO_TYPE_MASK) {
        case MOD_INFO_REQ:
            if (!(mod->state & MOD_INFO_CHANGED)) {
                /* data were not changed so no reason to validate them */
                break;
            }
        /* fallthrough */
        case MOD_INFO_INV_DEP:
            /* this module data will be validated */
            assert(mod->state & MOD_INFO_DATA);
            if ((err_info = sr_shmmod_collect_deps(SR_CONN_MAIN_SHM(mod_info->conn),
                    (sr_dep_t *)(mod_info->conn->main_shm.addr + mod->shm_mod->deps),
                    mod->shm_mod->dep_count, mod_info->conn->ly_ctx, mod_info->data, mod_info))) {
                return err_info;
            }
            break;
        case MOD_INFO_DEP:
            /* this module will not be validated */
            break;
        default:
            SR_CHECK_INT_RET(0, err_info);
        }
    }

    return NULL;
}

void
sr_shmmod_recover_cb(sr_lock_mode_t mode, sr_cid_t cid, void *data)
{
    struct sr_shmmod_recover_cb_s *cb_data = data;

    (void)cid;

    if (mode != SR_LOCK_WRITE) {
        /* nothing to recover */
        return;
    }

    /* recovery specific for the plugin */
    cb_data->ds_plg->recover_cb(cb_data->ly_mod, cb_data->ds);
}

/**
 * @brief Lock or relock a main SHM module.
 *
 * @param[in] ly_mod libyang module.
 * @param[in] ds Datastore.
 * @param[in] shm_lock Main SHM module lock.
 * @param[in] timeout_ms Timeout in ms.
 * @param[in] mode Lock mode of the module.
 * @param[in] cid Connection ID.
 * @param[in] sid Sysrepo session ID to store.
 * @param[in] ds_plg DS plugin.
 * @param[in] relock Whether some lock is already held or not.
 */
static sr_error_info_t *
sr_shmmod_lock(const struct lys_module *ly_mod, sr_datastore_t ds, struct sr_mod_lock_s *shm_lock, int timeout_ms,
        sr_lock_mode_t mode, sr_cid_t cid, uint32_t sid, struct srplg_ds_s *ds_plg, int relock)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    struct sr_shmmod_recover_cb_s cb_data;
    int ds_locked = 0;

    /* fill recovery callback information */
    cb_data.ly_mod = ly_mod;
    cb_data.ds = ds;
    cb_data.ds_plg = ds_plg;

    if (relock) {
        /* RELOCK */
        err_info = sr_rwrelock(&shm_lock->data_lock, timeout_ms, mode, cid, __func__, sr_shmmod_recover_cb, &cb_data);
    } else {
        /* LOCK */
        err_info = sr_rwlock(&shm_lock->data_lock, timeout_ms, mode, cid, __func__, sr_shmmod_recover_cb, &cb_data);
    }
    if (err_info) {
        return err_info;
    }

    if ((mode == SR_LOCK_READ_UPGR) || (mode == SR_LOCK_WRITE)) {
        /* DS LOCK */
        if ((err_info = sr_mlock(&shm_lock->ds_lock, SR_DS_LOCK_TIMEOUT, __func__, NULL, NULL))) {
            goto revert_lock;
        }

        /* DS lock cannot be held for these lock modes */
        if (shm_lock->ds_lock_sid && (shm_lock->ds_lock_sid != sid)) {
            sr_errinfo_new(&err_info, SR_ERR_LOCKED, "Module \"%s\" is DS-locked by session %" PRIu32 ".",
                    ly_mod->name, shm_lock->ds_lock_sid);
            ds_locked = 1;
        }

        /* DS UNLOCK */
        sr_munlock(&shm_lock->ds_lock);

        if (ds_locked) {
            goto revert_lock;
        }
    }

    return NULL;

revert_lock:
    if (relock) {
        /* RELOCK */
        if ((mode == SR_LOCK_READ) || (mode == SR_LOCK_READ_UPGR)) {
            /* is downgraded, upgrade */
            tmp_err = sr_rwrelock(&shm_lock->data_lock, timeout_ms, SR_LOCK_WRITE, cid, __func__, NULL, NULL);
        } else {
            /* is upgraded, downgrade */
            tmp_err = sr_rwrelock(&shm_lock->data_lock, timeout_ms, SR_LOCK_READ_UPGR, cid, __func__, NULL, NULL);
        }
        if (tmp_err) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    } else {
        /* UNLOCK */
        sr_rwunlock(&shm_lock->data_lock, timeout_ms, mode, cid, __func__);
    }
    return err_info;
}

/**
 * @brief Lock all modules in a mod info.
 *
 * @param[in] mod_info Mod info with modules to lock.
 * @param[in] ds Datastore to lock.
 * @param[in] skip_state Flags (bits) of module state, which should be skipped.
 * @param[in] req_bit Required bits of module state, which should be locked.
 * @param[in] mode Lock mode.
 * @param[in] lock_bit Bit to set for all locked modules.
 * @param[in] sid Session ID.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmod_modinfo_lock(struct sr_mod_info_s *mod_info, sr_datastore_t ds, uint32_t skip_state, uint32_t req_bit,
        sr_lock_mode_t mode, uint32_t lock_bit, uint32_t sid)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    struct sr_mod_info_mod_s *mod;
    struct sr_mod_lock_s *shm_lock;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        shm_lock = &mod->shm_mod->data_lock_info[ds];

        if (mod->state & skip_state) {
            /* module was already locked, do not change it */
            continue;
        }

        if (req_bit && !(mod->state & req_bit)) {
            /* skip this module */
            continue;
        }

        /* MOD LOCK */
        if ((err_info = sr_shmmod_lock(mod->ly_mod, ds, shm_lock, SR_MOD_LOCK_TIMEOUT, mode, mod_info->conn->cid, sid,
                mod->ds_plg, 0))) {
            return err_info;
        }

        /* set the flag for unlocking */
        mod->state |= lock_bit;
    }

    return NULL;
}

sr_error_info_t *
sr_shmmod_modinfo_rdlock(struct sr_mod_info_s *mod_info, int upgradeable, uint32_t sid)
{
    sr_error_info_t *err_info = NULL;

    if (upgradeable) {
        /* read-upgr-lock main DS */
        if ((err_info = sr_shmmod_modinfo_lock(mod_info, mod_info->ds, MOD_INFO_RLOCK | MOD_INFO_RLOCK_UPGR |
                MOD_INFO_WLOCK, 0, SR_LOCK_READ_UPGR, MOD_INFO_RLOCK_UPGR, sid))) {
            return err_info;
        }
    }

    /* read-lock main DS */
    if ((err_info = sr_shmmod_modinfo_lock(mod_info, mod_info->ds, MOD_INFO_RLOCK | MOD_INFO_RLOCK_UPGR |
            MOD_INFO_WLOCK, 0, SR_LOCK_READ, MOD_INFO_RLOCK, sid))) {
        return err_info;
    }

    if (mod_info->ds2 != mod_info->ds) {
        /* read-lock the secondary DS */
        if ((err_info = sr_shmmod_modinfo_lock(mod_info, mod_info->ds2, MOD_INFO_RLOCK2, 0, SR_LOCK_READ,
                MOD_INFO_RLOCK2, sid))) {
            return err_info;
        }
    }

    return NULL;
}

sr_error_info_t *
sr_shmmod_modinfo_wrlock(struct sr_mod_info_s *mod_info, uint32_t sid)
{
    sr_error_info_t *err_info = NULL;

    /* write-lock main DS */
    if ((err_info = sr_shmmod_modinfo_lock(mod_info, mod_info->ds, MOD_INFO_RLOCK | MOD_INFO_RLOCK_UPGR |
            MOD_INFO_WLOCK, 0, SR_LOCK_WRITE, MOD_INFO_WLOCK, sid))) {
        return err_info;
    }

    if (mod_info->ds2 != mod_info->ds) {
        /* read-lock the secondary DS */
        if ((err_info = sr_shmmod_modinfo_lock(mod_info, mod_info->ds2, MOD_INFO_RLOCK2, 0, SR_LOCK_READ,
                MOD_INFO_RLOCK2, sid))) {
            return err_info;
        }
    }

    return NULL;
}

sr_error_info_t *
sr_shmmod_modinfo_rdlock_upgrade(struct sr_mod_info_s *mod_info, uint32_t sid)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    struct sr_mod_info_mod_s *mod;
    struct sr_mod_lock_s *shm_lock;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        shm_lock = &mod->shm_mod->data_lock_info[mod_info->ds];

        /* upgrade only required read-upgr-locked modules and leave others read-upgr-locked to prevent their locking
         * causing potential dead-lock */
        if ((mod->state & (MOD_INFO_RLOCK_UPGR | MOD_INFO_REQ)) == (MOD_INFO_RLOCK_UPGR | MOD_INFO_REQ)) {
            /* MOD WRITE UPGRADE */
            if ((err_info = sr_shmmod_lock(mod->ly_mod, mod_info->ds, shm_lock, SR_MOD_LOCK_TIMEOUT, SR_LOCK_WRITE,
                    mod_info->conn->cid, sid, mod->ds_plg, 1))) {
                return err_info;
            }

            /* update the flag for unlocking */
            mod->state &= ~MOD_INFO_RLOCK_UPGR;
            mod->state |= MOD_INFO_WLOCK;
        }
    }

    return NULL;
}

sr_error_info_t *
sr_shmmod_modinfo_wrlock_downgrade(struct sr_mod_info_s *mod_info, uint32_t sid)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    struct sr_mod_info_mod_s *mod;
    struct sr_mod_lock_s *shm_lock;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        shm_lock = &mod->shm_mod->data_lock_info[mod_info->ds];

        /* downgrade only write-locked modules */
        if (mod->state & MOD_INFO_WLOCK) {
            /* MOD READ DOWNGRADE */
            if ((err_info = sr_shmmod_lock(mod->ly_mod, mod_info->ds, shm_lock, SR_MOD_LOCK_TIMEOUT, SR_LOCK_READ_UPGR,
                    mod_info->conn->cid, sid, mod->ds_plg, 1))) {
                return err_info;
            }

            /* update the flag for unlocking */
            mod->state &= ~MOD_INFO_WLOCK;
            mod->state |= MOD_INFO_RLOCK_UPGR;
        }
    }

    return NULL;
}

void
sr_shmmod_modinfo_unlock(struct sr_mod_info_s *mod_info)
{
    uint32_t i;
    struct sr_mod_info_mod_s *mod;
    struct sr_mod_lock_s *shm_lock;
    sr_lock_mode_t mode;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];

        if (mod->state & (MOD_INFO_RLOCK | MOD_INFO_RLOCK_UPGR | MOD_INFO_WLOCK)) {
            /* main DS */
            shm_lock = &mod->shm_mod->data_lock_info[mod_info->ds];

            /* learn lock mode */
            if (mod->state & MOD_INFO_RLOCK) {
                mode = SR_LOCK_READ;
            } else if (mod->state & MOD_INFO_RLOCK_UPGR) {
                mode = SR_LOCK_READ_UPGR;
            } else {
                mode = SR_LOCK_WRITE;
            }

            /* MOD UNLOCK */
            sr_rwunlock(&shm_lock->data_lock, SR_MOD_LOCK_TIMEOUT, mode, mod_info->conn->cid, __func__);
        }

        if (mod->state & MOD_INFO_RLOCK2) {
            /* secondary DS */
            shm_lock = &mod->shm_mod->data_lock_info[mod_info->ds2];

            /* MOD READ UNLOCK */
            sr_rwunlock(&shm_lock->data_lock, SR_MOD_LOCK_TIMEOUT, SR_LOCK_READ, mod_info->conn->cid, __func__);
        }

        /* clear all flags */
        mod->state &= ~(MOD_INFO_RLOCK | MOD_INFO_RLOCK_UPGR | MOD_INFO_WLOCK | MOD_INFO_RLOCK2);
    }
}

void
sr_shmmod_release_locks(sr_conn_ctx_t *conn, uint32_t sid)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    const struct lys_module *ly_mod;
    struct sr_mod_lock_s *shm_lock;
    struct srplg_ds_s *ds_plg;
    sr_datastore_t ds;
    int ds_locked, rc;
    uint32_t i;

    for (i = 0; i < SR_CONN_MAIN_SHM(conn)->mod_count; ++i) {
        shm_mod = SR_SHM_MOD_IDX(conn->main_shm.addr, i);
        ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, conn->main_shm.addr + shm_mod->name);
        for (ds = 0; ds < SR_DS_COUNT; ++ds) {
            shm_lock = &shm_mod->data_lock_info[ds];

            /* DS LOCK */
            if ((err_info = sr_mlock(&shm_lock->ds_lock, SR_DS_LOCK_TIMEOUT, __func__, NULL, NULL))) {
                sr_errinfo_free(&err_info);
                continue;
            }

            ds_locked = 0;
            if (shm_lock->ds_lock_sid == sid) {
                /* DS lock held */
                ds_locked = 1;

                /* clear DS lock information */
                shm_lock->ds_lock_sid = 0;
                memset(&shm_lock->ds_lock_ts, 0, sizeof shm_lock->ds_lock_ts);
            }

            /* DS UNLOCK */
            sr_munlock(&shm_lock->ds_lock);

            if (ds_locked && (ds == SR_DS_CANDIDATE)) {
                /* find DS plugin */
                if ((err_info = sr_ds_plugin_find(conn->main_shm.addr + shm_mod->plugins[ds], conn, &ds_plg))) {
                    sr_errinfo_free(&err_info);
                    continue;
                }

                /* MOD WRITE LOCK */
                if ((err_info = sr_shmmod_lock(ly_mod, ds, shm_lock, SR_MOD_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
                        sid, ds_plg, 0))) {
                    sr_errinfo_free(&err_info);
                } else {
                    /* reset candidate */
                    if ((rc = ds_plg->candidate_reset_cb(ly_mod))) {
                        SR_ERRINFO_DSPLUGIN(&err_info, rc, "candidate_reset", ds_plg->name, ly_mod->name);
                        sr_errinfo_free(&err_info);
                    }

                    /* MOD WRITE UNLOCK */
                    sr_rwunlock(&shm_lock->data_lock, SR_MOD_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__);
                }
            }
        }
    }
}
