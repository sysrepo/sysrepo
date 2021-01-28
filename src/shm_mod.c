/**
 * @file shm_mod.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief main SHM routines modifying module information
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

#include <assert.h>
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

sr_error_info_t *
sr_shmmod_collect_edit(const struct lyd_node *edit, struct ly_set *mod_set)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *mod;
    const struct lyd_node *root;
    char *str;

    /* add all the modules from the edit into our array */
    mod = NULL;
    LY_TREE_FOR(edit, root) {
        if (lyd_node_module(root) == mod) {
            continue;
        } else if (!strcmp(lyd_node_module(root)->name, SR_YANG_MOD)) {
            str = lyd_path(root);
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, str, "Data of internal module \"%s\" cannot be modified.", SR_YANG_MOD);
            free(str);
            return err_info;
        }

        /* remember last mod, good chance it will also be the module of some next data nodes */
        mod = lyd_node_module(root);

        /* remember the module */
        ly_set_add(mod_set, (void *)mod, 0);
    }

    return NULL;
}

sr_error_info_t *
sr_shmmod_collect_xpath(const struct ly_ctx *ly_ctx, const char *xpath, sr_datastore_t ds, struct ly_set *mod_set)
{
    sr_error_info_t *err_info = NULL;
    char *module_name;
    const struct lys_module *ly_mod;
    const struct lys_node *ctx_node;
    struct ly_set *set = NULL;
    uint32_t i;

    /* get the module */
    module_name = sr_get_first_ns(xpath);
    if (!module_name) {
        /* there is no module name, use sysrepo module */
        module_name = strdup(SR_YANG_MOD);
        SR_CHECK_MEM_RET(!module_name, err_info);
    }

    ly_mod = ly_ctx_get_module(ly_ctx, module_name, NULL, 1);
    if (!ly_mod) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Module \"%s\" was not found in sysrepo.", module_name);
        free(module_name);
        return err_info;
    }
    free(module_name);

    /* take any valid node */
    ctx_node = lys_getnext(NULL, NULL, ly_mod, 0);
    if (!ctx_node) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "No data in module \"%s\".", ly_mod->name);
        return err_info;
    }

    set = lys_xpath_atomize(ctx_node, LYXP_NODE_ELEM, xpath, 0);
    if (!set) {
        sr_errinfo_new_ly(&err_info, (struct ly_ctx *)ly_ctx);
        return err_info;
    }

    /* add all the other modules */
    ly_mod = NULL;
    for (i = 0; i < set->number; ++i) {
        /* skip uninteresting nodes */
        if ((set->set.s[i]->nodetype & (LYS_RPC | LYS_NOTIF)) ||
                ((set->set.s[i]->flags & LYS_CONFIG_R) && SR_IS_CONVENTIONAL_DS(ds))) {
            continue;
        }

        if (lys_node_module(set->set.s[i]) == ly_mod) {
            /* skip already-added modules */
            continue;
        }
        ly_mod = lys_node_module(set->set.s[i]);

        if (!ly_mod->implemented || !strcmp(ly_mod->name, SR_YANG_MOD) || !strcmp(ly_mod->name, "ietf-netconf")) {
            /* skip import-only modules, the internal sysrepo module, and ietf-netconf (as it has no data, only in libyang) */
            continue;
        }

        ly_set_add(mod_set, (void *)ly_mod, 0);
    }

    ly_set_free(set);
    return NULL;
}

sr_error_info_t *
sr_shmmod_collect_rpc_deps(sr_main_shm_t *main_shm, const struct ly_ctx *ly_ctx, const char *path, int output,
        struct ly_set *mod_set, sr_dep_t **shm_deps, uint16_t *shm_dep_count)
{
    sr_error_info_t *err_info = NULL;
    sr_rpc_t *shm_rpc;
    const struct lys_module *ly_mod;
    uint16_t i;

    /* find the RPC in SHM */
    shm_rpc = sr_shmmain_find_rpc(main_shm, path);
    SR_CHECK_INT_RET(!shm_rpc, err_info);

    /* collect dependencies */
    *shm_deps = (sr_dep_t *)(((char *)main_shm) + (output ? shm_rpc->out_deps : shm_rpc->in_deps));
    *shm_dep_count = (output ? shm_rpc->out_dep_count : shm_rpc->in_dep_count);
    for (i = 0; i < *shm_dep_count; ++i) {
        if ((*shm_deps)[i].type == SR_DEP_INSTID) {
            /* we will handle those just before validation */
            continue;
        }

        /* find ly module */
        ly_mod = ly_ctx_get_module(ly_ctx, ((char *)main_shm) + (*shm_deps)[i].module, NULL, 1);
        SR_CHECK_INT_RET(!ly_mod, err_info);

        /* add dependency */
        ly_set_add(mod_set, (void *)ly_mod, 0);
    }

    return NULL;
}

sr_error_info_t *
sr_shmmod_collect_notif_deps(sr_main_shm_t *main_shm, const struct lys_module *notif_mod, const char *path,
        struct ly_set *mod_set, sr_dep_t **shm_deps, uint16_t *shm_dep_count)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    sr_notif_t *shm_notif;
    const struct lys_module *ly_mod;
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
    for (i = 0; i < *shm_dep_count; ++i) {
        if ((*shm_deps)[i].type == SR_DEP_INSTID) {
            /* we will handle those just before validation */
            continue;
        }

        /* find ly module */
        ly_mod = ly_ctx_get_module(notif_mod->ctx, ((char *)main_shm) + (*shm_deps)[i].module, NULL, 1);
        SR_CHECK_INT_RET(!ly_mod, err_info);

        /* add dependency */
        ly_set_add(mod_set, (void *)ly_mod, 0);
    }

    return NULL;
}

sr_error_info_t *
sr_shmmod_collect_instid_deps_data(sr_main_shm_t *main_shm, sr_dep_t *shm_deps, uint16_t shm_dep_count,
        struct ly_ctx *ly_ctx, const struct lyd_node *data, struct ly_set *mod_set)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    struct ly_set *set = NULL;
    const char *val_str;
    char *mod_name;
    uint32_t i, j;

    /* collect all possibly required modules (because of inst-ids) into a set */
    for (i = 0; i < shm_dep_count; ++i) {
        if (shm_deps[i].type == SR_DEP_INSTID) {
            if (data) {
                set = lyd_find_path(data, ((char *)main_shm) + shm_deps[i].path);
            } else {
                /* no data, just fake empty set */
                set = ly_set_new();
            }
            if (!set) {
                sr_errinfo_new_ly(&err_info, ly_ctx);
                goto cleanup;
            }

            if (set->number) {
                /* extract module names from all the existing instance-identifiers */
                for (j = 0; j < set->number; ++j) {
                    assert(set->set.d[j]->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST));
                    val_str = sr_ly_leaf_value_str(set->set.d[j]);

                    mod_name = sr_get_first_ns(val_str);
                    ly_mod = ly_ctx_get_module(ly_ctx, mod_name, NULL, 1);
                    free(mod_name);
                    SR_CHECK_INT_GOTO(!ly_mod, err_info, cleanup);

                    /* add module into set */
                    if (ly_set_add(mod_set, (void *)ly_mod, 0) == -1) {
                        sr_errinfo_new_ly(&err_info, ly_ctx);
                        goto cleanup;
                    }
                }
            } else if (shm_deps[i].module) {
                /* assume a default value will be used even though it may not be */
                ly_mod = ly_ctx_get_module(ly_ctx, ((char *)main_shm) + shm_deps[i].module, NULL, 1);
                SR_CHECK_INT_GOTO(!ly_mod, err_info, cleanup);

                if (ly_set_add(mod_set, (void *)ly_mod, 0) == -1) {
                    sr_errinfo_new_ly(&err_info, ly_ctx);
                    goto cleanup;
                }
            }
            ly_set_free(set);
            set = NULL;
        }
    }

    /* success */

cleanup:
    ly_set_free(set);
    return err_info;
}

sr_error_info_t *
sr_shmmod_collect_instid_deps_modinfo(const struct sr_mod_info_s *mod_info, struct ly_set *mod_set)
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
            if ((err_info = sr_shmmod_collect_instid_deps_data(SR_CONN_MAIN_SHM(mod_info->conn),
                    (sr_dep_t *)(mod_info->conn->main_shm.addr + mod->shm_mod->deps),
                    mod->shm_mod->dep_count, mod_info->conn->ly_ctx, mod_info->data, mod_set))) {
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
    sr_error_info_t *err_info = NULL;
    struct sr_shmmod_recover_cb_s *cb_data = data;
    char *path = NULL, *bck_path = NULL;
    struct lyd_node *mod_data = NULL;
    (void)cid;

    if (mode != SR_LOCK_WRITE) {
        /* nothing to recover */
        return;
    }

    /* learn standard path */
    switch (cb_data->ds) {
    case SR_DS_STARTUP:
        err_info = sr_path_startup_file(cb_data->ly_mod->name, &path);
        break;
    case SR_DS_RUNNING:
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        err_info = sr_path_ds_shm(cb_data->ly_mod->name, cb_data->ds, &path);
        break;
    }
    if (err_info) {
        goto cleanup;
    }

    /* check whether the file is valid */
    err_info = sr_module_file_data_append(cb_data->ly_mod, cb_data->ds, &mod_data);
    if (!err_info) {
        /* data are valid, nothing to do */
        goto cleanup;
    }
    sr_errinfo_free(&err_info);

    if (cb_data->ds == SR_DS_STARTUP) {
        /* there must be a backup file for startup data */
        SR_LOG_WRN("Recovering \"%s\" startup data from a backup.", cb_data->ly_mod->name);

        /* generate the backup path */
        if (asprintf(&bck_path, "%s%s", path, SR_FILE_BACKUP_SUFFIX) == -1) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }

        /* restore the backup data, avoid changing permissions of the target file */
        if ((err_info = sr_cp_path(path, bck_path, 0))) {
            SR_ERRINFO_SYSERRNO(&err_info, "rename");
            goto cleanup;
        }

        /* remove the backup file */
        if (unlink(bck_path) == -1) {
            SR_ERRINFO_SYSERRNO(&err_info, "unlink");
            goto cleanup;
        }
    } else if (cb_data->ds == SR_DS_RUNNING) {
        /* perform startup->running data file copy */
        SR_LOG_WRN("Recovering \"%s\" running data from the startup data.", cb_data->ly_mod->name);

        /* generate the startup data file path */
        if ((err_info = sr_path_startup_file(cb_data->ly_mod->name, &bck_path))) {
            goto cleanup;
        }

        /* copy startup data to running */
        if ((err_info = sr_cp_path(path, bck_path, 0))) {
            SR_ERRINFO_SYSERRNO(&err_info, "rename");
            goto cleanup;
        }
    } else {
        /* there is not much to do but remove the corrupted file */
        SR_LOG_WRN("Recovering \"%s\" %s data by removing the corrupted data file.", cb_data->ly_mod->name,
                sr_ds2str(cb_data->ds));

        if (unlink(path) == -1) {
            SR_ERRINFO_SYSERRNO(&err_info, "unlink");
            goto cleanup;
        }
    }

cleanup:
    free(path);
    free(bck_path);
    lyd_free_withsiblings(mod_data);
    sr_errinfo_free(&err_info);
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
 * @param[in] relock Whether some lock is already held or not.
 */
static sr_error_info_t *
sr_shmmod_lock(const struct lys_module *ly_mod, sr_datastore_t ds, struct sr_mod_lock_s *shm_lock, int timeout_ms,
        sr_lock_mode_t mode, sr_cid_t cid, sr_sid_t sid, int relock)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    struct sr_shmmod_recover_cb_s cb_data;

    /* fill recovery callback information */
    cb_data.ly_mod = ly_mod;
    cb_data.ds = ds;

    if (relock) {
        assert(!memcmp(&shm_lock->sid, &sid, sizeof sid));

        /* RELOCK */
        err_info = sr_rwrelock(&shm_lock->lock, timeout_ms, mode, cid, __func__, sr_shmmod_recover_cb, &cb_data);
    } else {
        /* LOCK */
        err_info = sr_rwlock(&shm_lock->lock, timeout_ms, mode, cid, __func__, sr_shmmod_recover_cb, &cb_data);
    }
    if (err_info) {
        if (err_info->err_code == SR_ERR_TIME_OUT) {
            sr_errinfo_new(&err_info, SR_ERR_LOCKED, NULL, "Module \"%s\" is %s by session %u (NC SID %u).",
                    ly_mod->name, ATOMIC_LOAD_RELAXED(shm_lock->ds_locked) ? "locked" : "being used", shm_lock->sid.sr,
                    shm_lock->sid.nc);
        }
        return err_info;
    }

    /* store our SID if it has the highest priority */
    if ((mode == SR_LOCK_READ_UPGR) || (mode == SR_LOCK_WRITE)) {
        /* check held DS lock */
        if (ATOMIC_LOAD_RELAXED(shm_lock->ds_locked)) {
            assert(shm_lock->sid.sr);
            if (shm_lock->sid.sr != sid.sr) {
                sr_errinfo_new(&err_info, SR_ERR_LOCKED, NULL, "Module \"%s\" is locked by session %u (NC SID %u).",
                        ly_mod->name, shm_lock->sid.sr, shm_lock->sid.nc);
                goto revert_lock;
            }
            /* we hold DS lock */
            assert(!memcmp(&shm_lock->sid, &sid, sizeof sid));
        } else {
            /* read-upgr-lock or write-lock, store */
            shm_lock->sid = sid;
        }
    } else if (!ATOMIC_LOAD_RELAXED(shm_lock->ds_locked) && !shm_lock->lock.upgr) {
        /* there is no other lock, so store our SID */
        shm_lock->sid = sid;
    }

    return NULL;

revert_lock:
    if (relock) {
        /* RELOCK */
        if ((mode == SR_LOCK_READ) || (mode == SR_LOCK_READ_UPGR)) {
            /* is downgraded, upgrade */
            tmp_err = sr_rwrelock(&shm_lock->lock, timeout_ms, SR_LOCK_WRITE, cid, __func__, NULL, NULL);
        } else {
            /* is upgraded, downgrade */
            tmp_err = sr_rwrelock(&shm_lock->lock, timeout_ms, SR_LOCK_READ_UPGR, cid, __func__, NULL, NULL);
        }
        if (tmp_err) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    } else {
        /* UNLOCK */
        sr_rwunlock(&shm_lock->lock, timeout_ms, mode, cid, __func__);
    }
    return err_info;
}

/**
 * @brief Unlock a main SHM module.
 *
 * @param[in] shm_lock Main SHM module lock.
 * @param[in] timeout_ms Timeout in ms.
 * @param[in] mode Lock mode of the module.
 * @param[in] cid Connection ID.
 * @param[in] sid Sysrepo session ID of the lock owner.
 */
static void
sr_shmmod_unlock(struct sr_mod_lock_s *shm_lock, int timeout_ms, sr_lock_mode_t mode, sr_cid_t cid, sr_sid_t sid)
{
    /* UNLOCK */
    sr_rwunlock(&shm_lock->lock, timeout_ms, mode, cid, __func__);

    /* remove our SID */
    if ((mode == SR_LOCK_READ_UPGR) || (mode == SR_LOCK_WRITE)) {
        assert(!memcmp(&shm_lock->sid, &sid, sizeof sid));

        /* if we still have DS lock, keep our SID set */
        if (!ATOMIC_LOAD_RELAXED(shm_lock->ds_locked)) {
            memset(&shm_lock->sid, 0, sizeof shm_lock->sid);
        }
    } else if (!ATOMIC_LOAD_RELAXED(shm_lock->ds_locked) && !shm_lock->lock.upgr) {
        /* there is no other higher-priority lock (recursive locks) so set SID 0 even if there are other readers
         * (rather print SID 0 than our since we have just released the lock) */
        if (!memcmp(&shm_lock->sid, &sid, sizeof sid)) {
            memset(&shm_lock->sid, 0, sizeof shm_lock->sid);
        }
    }
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
        sr_lock_mode_t mode, uint32_t lock_bit, sr_sid_t sid)
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
        if ((err_info = sr_shmmod_lock(mod->ly_mod, ds, shm_lock, SR_MOD_LOCK_TIMEOUT, mode, mod_info->conn->cid, sid, 0))) {
            return err_info;
        }

        /* set the flag for unlocking */
        mod->state |= lock_bit;
    }

    return NULL;
}

sr_error_info_t *
sr_shmmod_modinfo_rdlock(struct sr_mod_info_s *mod_info, int upgradeable, sr_sid_t sid)
{
    sr_error_info_t *err_info = NULL;

    if (upgradeable) {
        /* read-upgr-lock main DS */
        if ((err_info = sr_shmmod_modinfo_lock(mod_info, mod_info->ds, MOD_INFO_RLOCK | MOD_INFO_RLOCK_UPGR
                | MOD_INFO_WLOCK, MOD_INFO_REQ, SR_LOCK_READ_UPGR, MOD_INFO_RLOCK_UPGR, sid))) {
            return err_info;
        }
    }

    /* read-lock main DS */
    if ((err_info = sr_shmmod_modinfo_lock(mod_info, mod_info->ds, MOD_INFO_RLOCK | MOD_INFO_RLOCK_UPGR
            | MOD_INFO_WLOCK, 0, SR_LOCK_READ, MOD_INFO_RLOCK, sid))) {
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
sr_shmmod_modinfo_wrlock(struct sr_mod_info_s *mod_info, sr_sid_t sid)
{
    sr_error_info_t *err_info = NULL;

    /* write-lock main DS */
    if ((err_info = sr_shmmod_modinfo_lock(mod_info, mod_info->ds, MOD_INFO_RLOCK | MOD_INFO_RLOCK_UPGR
            | MOD_INFO_WLOCK, 0, SR_LOCK_WRITE, MOD_INFO_WLOCK, sid))) {
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
sr_shmmod_modinfo_rdlock_upgrade(struct sr_mod_info_s *mod_info, sr_sid_t sid)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    struct sr_mod_info_mod_s *mod;
    struct sr_mod_lock_s *shm_lock;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        shm_lock = &mod->shm_mod->data_lock_info[mod_info->ds];

        /* upgrade only read-upgr-locked modules */
        if (mod->state & MOD_INFO_RLOCK_UPGR) {
            /* MOD WRITE UPGRADE */
            if ((err_info = sr_shmmod_lock(mod->ly_mod, mod_info->ds, shm_lock, SR_MOD_LOCK_TIMEOUT, SR_LOCK_WRITE,
                    mod_info->conn->cid, sid, 1))) {
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
sr_shmmod_modinfo_wrlock_downgrade(struct sr_mod_info_s *mod_info, sr_sid_t sid)
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
                    mod_info->conn->cid, sid, 1))) {
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
sr_shmmod_modinfo_unlock(struct sr_mod_info_s *mod_info, sr_sid_t sid)
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
            sr_shmmod_unlock(shm_lock, SR_MOD_LOCK_TIMEOUT, mode, mod_info->conn->cid, sid);
        }

        if (mod->state & MOD_INFO_RLOCK2) {
            /* secondary DS */
            shm_lock = &mod->shm_mod->data_lock_info[mod_info->ds2];

            /* MOD READ UNLOCK */
            sr_shmmod_unlock(shm_lock, SR_MOD_LOCK_TIMEOUT, SR_LOCK_READ, mod_info->conn->cid, sid);
        }

        /* clear all flags */
        mod->state &= ~(MOD_INFO_RLOCK | MOD_INFO_RLOCK_UPGR | MOD_INFO_WLOCK | MOD_INFO_RLOCK2);
    }
}

void
sr_shmmod_release_locks(sr_conn_ctx_t *conn, sr_sid_t sid)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    struct sr_mod_lock_s *shm_lock;
    struct sr_mod_info_s mod_info;
    struct ly_set mod_set = {0};
    sr_datastore_t ds;
    uint32_t i;

    for (i = 0; i < SR_CONN_MAIN_SHM(conn)->mod_count; ++i) {
        shm_mod = SR_SHM_MOD_IDX(conn->main_shm.addr, i);
        for (ds = 0; ds < SR_DS_COUNT; ++ds) {
            shm_lock = &shm_mod->data_lock_info[ds];
            if (shm_lock->sid.sr == sid.sr) {
                if (shm_lock->lock.upgr) {
                    /* this should never happen, write lock is held during some API calls */
                    sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Session %u (NC SID %u) was working with"
                            " module \"%s\"!", sid.sr, sid.nc, conn->main_shm.addr + shm_mod->name);
                    sr_errinfo_free(&err_info);
                    shm_lock->lock.upgr = 0;
                }
                if (!shm_lock->ds_locked) {
                    /* why our SID matched then? */
                    SR_ERRINFO_INT(&err_info);
                    sr_errinfo_free(&err_info);
                    continue;
                }

                if (ds == SR_DS_CANDIDATE) {
                    /* collect all modules */
                    SR_MODINFO_INIT(mod_info, conn, ds, ds);
                    if ((err_info = sr_modinfo_add_modules(&mod_info, &mod_set, 0, SR_LOCK_WRITE,
                            SR_MI_DATA_NO | SR_MI_PERM_NO, sid, NULL, 0, 0))) {
                        goto cleanup_modules;
                    }

                    /* reset candidate */
                    if ((err_info = sr_modinfo_candidate_reset(&mod_info))) {
                        goto cleanup_modules;
                    }

cleanup_modules:
                    /* MODULES UNLOCK */
                    sr_shmmod_modinfo_unlock(&mod_info, sid);

                    sr_modinfo_free(&mod_info);
                    sr_errinfo_free(&err_info);
                }

                /* DS unlock */
                shm_lock->ds_locked = 0;
                memset(&shm_lock->sid, 0, sizeof shm_lock->sid);
                shm_lock->ds_ts = 0;
            }
        }
    }
}

sr_error_info_t *
sr_shmmod_oper_stored_del_conn(sr_conn_ctx_t *conn, sr_cid_t cid)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_s mod_info;
    struct ly_set mod_set = {0};
    struct sr_mod_info_mod_s *mod;
    sr_sid_t sid;
    struct lyd_node *diff = NULL;
    char *path = NULL;
    uint32_t i;

    /* we really need to write lock only stored operational data */
    SR_MODINFO_INIT(mod_info, conn, SR_DS_OPERATIONAL, SR_DS_OPERATIONAL);
    memset(&sid, 0, sizeof sid);

    if ((err_info = sr_modinfo_add_modules(&mod_info, &mod_set, 0, SR_LOCK_WRITE, SR_MI_DATA_NO | SR_MI_PERM_NO, sid,
            NULL, 0, 0))) {
        goto cleanup;
    }

    for (i = 0; i < mod_info.mod_count; ++i) {
        mod = &mod_info.mods[i];

        /* check we have permissions to open operational file */
        free(path);
        if ((err_info = sr_path_ds_shm(mod->ly_mod->name, SR_DS_OPERATIONAL, &path))) {
            goto cleanup;
        }
        errno = 0;
        if (eaccess(path, R_OK) == -1) {
            if ((errno == EACCES) || (errno == ENOENT)) {
                /* file does not exist or we cannot access it, there cannot be any data of this connection stored anyway */
                continue;
            }

            /* error */
            SR_ERRINFO_SYSERRNO(&err_info, "eaccess");
            goto cleanup;
        }

        /* trim diff of the module */
        if ((err_info = sr_module_file_data_append(mod->ly_mod, SR_DS_OPERATIONAL, &diff))) {
            goto cleanup;
        }

        if (diff) {
            if ((err_info = sr_diff_del_conn(&diff, cid))) {
                goto cleanup;
            }
            if ((err_info = sr_module_file_data_set(mod->ly_mod->name, SR_DS_OPERATIONAL, diff, 0, SR_FILE_PERM))) {
                goto cleanup;
            }
            lyd_free_withsiblings(diff);
            diff = NULL;
        }
    }

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info, sid);

    free(path);
    lyd_free_withsiblings(diff);
    sr_modinfo_free(&mod_info);
    return err_info;
}
