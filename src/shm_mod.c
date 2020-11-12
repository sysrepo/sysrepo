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

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <libyang/libyang.h>

/**
 * @brief READ/WRITE lock a main SHM module.
 *
 * @param[in] mod_name Module name.
 * @param[in] shm_lock Main SHM module lock.
 * @param[in] timeout_ms Timeout in ms.
 * @param[in] mode Whether to WRITE or READ lock the module.
 * @param[in] sid Sysrepo session ID.
 */
static sr_error_info_t *
sr_shmmod_lock(const char *mod_name, struct sr_mod_lock_s *shm_lock, int timeout_ms, sr_lock_mode_t mode, sr_sid_t sid)
{
    sr_error_info_t *err_info = NULL;
    struct timespec timeout_ts;
    int ret;

    assert(timeout_ms > 0);
    assert((mode == SR_LOCK_READ) || (mode == SR_LOCK_WRITE));

    sr_time_get(&timeout_ts, timeout_ms);

    /* MUTEX LOCK */
    ret = pthread_mutex_timedlock(&shm_lock->lock.mutex, &timeout_ts);
    if (ret) {
        SR_ERRINFO_LOCK(&err_info, __func__, ret);
        return err_info;
    }

    if (mode == SR_LOCK_WRITE) {
        /* write lock */
        ret = 0;
        while (!ret && (shm_lock->lock.readers || ((shm_lock->write_locked || shm_lock->ds_locked) && (shm_lock->sid.sr != sid.sr)))) {
            /* COND WAIT */
            ret = pthread_cond_timedwait(&shm_lock->lock.cond, &shm_lock->lock.mutex, &timeout_ts);
        }

        if (ret) {
            /* MUTEX UNLOCK */
            pthread_mutex_unlock(&shm_lock->lock.mutex);

            if ((ret == ETIMEDOUT) && (shm_lock->write_locked || shm_lock->ds_locked)) {
                /* timeout */
                sr_errinfo_new(&err_info, SR_ERR_LOCKED, NULL, "Module \"%s\" is %s by session %u (NC SID %u).",
                        mod_name, shm_lock->ds_locked ? "locked" : "being used", shm_lock->sid.sr, shm_lock->sid.nc);
            } else {
                /* other error */
                SR_ERRINFO_COND(&err_info, __func__, ret);
            }
            return err_info;
        }
    } else {
        /* read lock */
        ++shm_lock->lock.readers;

        /* MUTEX UNLOCK */
        pthread_mutex_unlock(&shm_lock->lock.mutex);
    }

    return NULL;
}

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
        if ((set->set.s[i]->nodetype & (LYS_RPC | LYS_NOTIF))
                || ((set->set.s[i]->flags & LYS_CONFIG_R) && SR_IS_CONVENTIONAL_DS(ds))) {
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
sr_shmmod_collect_op_deps(sr_conn_ctx_t *conn, const struct lys_module *op_mod, const char *op_path, int output,
        struct ly_set *mod_set, sr_mod_data_dep_t **shm_deps, uint16_t *shm_dep_count)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    sr_mod_op_dep_t *shm_op_deps;
    const struct lys_module *ly_mod;
    uint16_t i;

    /* find the module in SHM */
    shm_mod = sr_shmmain_find_module(&conn->main_shm, conn->ext_shm.addr, op_mod->name, 0);
    SR_CHECK_INT_RET(!shm_mod, err_info);

    /* find this operation dependencies */
    shm_op_deps = (sr_mod_op_dep_t *)(conn->ext_shm.addr + shm_mod->op_deps);
    for (i = 0; i < shm_mod->op_dep_count; ++i) {
        if (!strcmp(op_path, conn->ext_shm.addr + shm_op_deps[i].xpath)) {
            break;
        }
    }
    SR_CHECK_INT_RET(i == shm_mod->op_dep_count, err_info);

    /* collect dependencies */
    *shm_deps = (sr_mod_data_dep_t *)(conn->ext_shm.addr + (output ? shm_op_deps[i].out_deps : shm_op_deps[i].in_deps));
    *shm_dep_count = (output ? shm_op_deps[i].out_dep_count : shm_op_deps[i].in_dep_count);
    for (i = 0; i < *shm_dep_count; ++i) {
        if ((*shm_deps)[i].type == SR_DEP_INSTID) {
            /* we will handle those just before validation */
            continue;
        }

        /* find ly module */
        ly_mod = ly_ctx_get_module(conn->ly_ctx, conn->ext_shm.addr + (*shm_deps)[i].module, NULL, 1);
        SR_CHECK_INT_RET(!ly_mod, err_info);

        /* add dependency */
        ly_set_add(mod_set, (void *)ly_mod, 0);
    }

    return NULL;
}

sr_error_info_t *
sr_shmmod_collect_instid_deps_data(sr_conn_ctx_t *conn, sr_mod_data_dep_t *shm_deps, uint16_t shm_dep_count,
        const struct lyd_node *data, struct ly_set *mod_set)
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
                set = lyd_find_path(data, conn->ext_shm.addr + shm_deps[i].xpath);
            } else {
                /* no data, just fake empty set */
                set = ly_set_new();
            }
            if (!set) {
                sr_errinfo_new_ly(&err_info, conn->ly_ctx);
                goto cleanup;
            }

            if (set->number) {
                /* extract module names from all the existing instance-identifiers */
                for (j = 0; j < set->number; ++j) {
                    assert(set->set.d[j]->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST));
                    val_str = sr_ly_leaf_value_str(set->set.d[j]);

                    mod_name = sr_get_first_ns(val_str);
                    ly_mod = ly_ctx_get_module(conn->ly_ctx, mod_name, NULL, 1);
                    free(mod_name);
                    SR_CHECK_INT_GOTO(!ly_mod, err_info, cleanup);

                    /* add module into set */
                    if (ly_set_add(mod_set, (void *)ly_mod, 0) == -1) {
                        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
                        goto cleanup;
                    }
                }
            } else if (shm_deps[i].module) {
                /* assume a default value will be used even though it may not be */
                ly_mod = ly_ctx_get_module(conn->ly_ctx, conn->ext_shm.addr + shm_deps[i].module, NULL, 1);
                SR_CHECK_INT_GOTO(!ly_mod, err_info, cleanup);

                if (ly_set_add(mod_set, (void *)ly_mod, 0) == -1) {
                    sr_errinfo_new_ly(&err_info, conn->ly_ctx);
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
            if ((err_info = sr_shmmod_collect_instid_deps_data(mod_info->conn,
                    (sr_mod_data_dep_t *)(mod_info->conn->ext_shm.addr + mod->shm_mod->data_deps),
                    mod->shm_mod->data_dep_count, mod_info->data, mod_set))) {
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

/**
 * @brief Update information about held module locks in SHM for the connection state.
 * Real WRITE lock (that a lock is WRITE-locked) is not covered and so is not recoverable.
 *
 * @param[in] conn Connection and its state to update.
 * @param[in] shm_mod SHM module.
 * @param[in] ds Datastore.
 * @param[in] mode Whether the modules is/was READ or (fake) WRITE-locked.
 * @param[in] lock Whether to lock or unlock.
 */
static void
sr_shmmod_conn_lock_update(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, sr_datastore_t ds, sr_lock_mode_t mode, int lock)
{
    sr_error_info_t *err_info = NULL;
    uint32_t shm_mod_idx;
    sr_conn_shm_lock_t (*mod_locks)[SR_DS_COUNT];
    sr_conn_shm_t *conn_s;

    assert((mode == SR_LOCK_READ) || (mode == SR_LOCK_WRITE));

    conn_s = sr_shmmain_conn_find(conn->main_shm.addr, conn->ext_shm.addr, conn, getpid());
    if (!conn_s) {
        SR_ERRINFO_INT(&err_info);
        goto cleanup;
    }

    mod_locks = (sr_conn_shm_lock_t (*)[SR_DS_COUNT])(conn->ext_shm.addr + conn_s->mod_locks);
    shm_mod_idx = SR_SHM_MOD_IDX(shm_mod, conn->main_shm);
    sr_shmlock_update(&mod_locks[shm_mod_idx][ds], mode, lock);

cleanup:
    sr_errinfo_free(&err_info);
}

sr_error_info_t *
sr_shmmod_modinfo_rdlock(struct sr_mod_info_s *mod_info, int upgradable, sr_sid_t sid)
{
    sr_error_info_t *err_info = NULL;
    sr_lock_mode_t mod_lock;
    uint32_t i;
    uint8_t rlock_bit, lock_mask;
    sr_datastore_t ds;
    struct sr_mod_info_mod_s *mod;
    struct sr_mod_lock_s *shm_lock;

    /* lock main DS normally */
    ds = mod_info->ds;
    rlock_bit = MOD_INFO_RLOCK;
    lock_mask = MOD_INFO_RLOCK | MOD_INFO_WLOCK;
lock:
    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        shm_lock = &mod->shm_mod->data_lock_info[ds];

        if (mod->state & lock_mask) {
            /* module was already fully locked, do not change it */
            continue;
        }

        /* WRITE-lock data-required modules, READ-lock dependency modules */
        mod_lock = upgradable && (mod->state & MOD_INFO_REQ) ? SR_LOCK_WRITE : SR_LOCK_READ;

        /* MOD READ/WRITE LOCK */
        if ((err_info = sr_shmmod_lock(mod->ly_mod->name, shm_lock, SR_MOD_LOCK_TIMEOUT * 1000, mod_lock, sid))) {
            return err_info;
        }

        if (mod_lock == SR_LOCK_WRITE) {
            /* set flag, store SID, and downgrade lock to the required read lock for now */
            assert(!shm_lock->write_locked);
            shm_lock->write_locked = 1;
            shm_lock->sid = sid;

            /* MOD WRITE UNLOCK */
            sr_rwunlock(&shm_lock->lock, SR_LOCK_WRITE, __func__);

            /* MOD READ LOCK */
            if ((err_info = sr_shmmod_lock(mod->ly_mod->name, shm_lock, SR_MOD_LOCK_TIMEOUT * 1000, SR_LOCK_READ, sid))) {
                /* this lock should never fail because we are holding the (fake) write lock */
                SR_ERRINFO_INT(&err_info);
                return err_info;
            }

            /* remember this lock in SHM (fake WRITE lock - write_locked is set to 1
             * but actual module lock is only SR_LOCK_READ) */
            sr_shmmod_conn_lock_update(mod_info->conn, mod->shm_mod, ds, SR_LOCK_WRITE, 1);
        }

        /* remember this lock in SHM (always have READ lock) */
        sr_shmmod_conn_lock_update(mod_info->conn, mod->shm_mod, ds, SR_LOCK_READ, 1);

        /* set the flag for unlocking (it is always READ locked now) */
        mod->state |= rlock_bit;
    }

    if (mod_info->ds2 != ds) {
        /* read lock the secondary DS */
        upgradable = 0;
        ds = mod_info->ds2;
        rlock_bit = MOD_INFO_RLOCK2;
        lock_mask = MOD_INFO_RLOCK2;
        goto lock;
    }

    return NULL;
}

sr_error_info_t *
sr_shmmod_modinfo_wrlock(struct sr_mod_info_s *mod_info, sr_sid_t sid)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    struct sr_mod_info_mod_s *mod;
    struct sr_mod_lock_s *shm_lock;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        shm_lock = &mod->shm_mod->data_lock_info[mod_info->ds];

        if (mod->state & (MOD_INFO_RLOCK | MOD_INFO_WLOCK)) {
            /* module was already fully locked, do not change it */
            continue;
        }

        /* MOD WRITE LOCK */
        if ((err_info = sr_shmmod_lock(mod->ly_mod->name, shm_lock, SR_MOD_LOCK_TIMEOUT * 1000, SR_LOCK_WRITE, sid))) {
            return err_info;
        }

        /* real WRITE locks are not stored in SHM */

        /* set the flag for unlocking */
        mod->state |= MOD_INFO_WLOCK;

        if (mod_info->ds2 != mod_info->ds) {
            /* secondary DS */
            shm_lock = &mod->shm_mod->data_lock_info[mod_info->ds2];

            /* MOD READ LOCK */
            if ((err_info = sr_shmmod_lock(mod->ly_mod->name, shm_lock, SR_MOD_LOCK_TIMEOUT * 1000, SR_LOCK_READ, sid))) {
                return err_info;
            }

            /* remember this lock in SHM */
            sr_shmmod_conn_lock_update(mod_info->conn, mod->shm_mod, mod_info->ds2, SR_LOCK_READ, 1);

            /* set the flag for unlocking */
            mod->state |= MOD_INFO_RLOCK2;
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

        /* upgrade only required modules */
        if ((mod->state & MOD_INFO_REQ) && (mod->state & MOD_INFO_RLOCK)) {
            assert(shm_lock->write_locked);
            assert(!memcmp(&shm_lock->sid, &sid, sizeof sid));

            /* MOD READ UNLOCK */
            sr_rwunlock(&shm_lock->lock, SR_LOCK_READ, __func__);

            /* remove flag for correct error recovery */
            mod->state &= ~MOD_INFO_RLOCK;

            /* update this lock in SHM (real WRITE lock no longer covered) */
            sr_shmmod_conn_lock_update(mod_info->conn, mod->shm_mod, mod_info->ds, SR_LOCK_WRITE, 0);
            sr_shmmod_conn_lock_update(mod_info->conn, mod->shm_mod, mod_info->ds, SR_LOCK_READ, 0);

            /* MOD WRITE LOCK */
            if ((err_info = sr_shmmod_lock(mod->ly_mod->name, shm_lock, SR_MOD_LOCK_TIMEOUT * 1000, SR_LOCK_WRITE, sid))) {
                /* clear the lock */
                shm_lock->write_locked = 0;
                if (!shm_lock->ds_locked) {
                    memset(&shm_lock->sid, 0, sizeof shm_lock->sid);
                }
                return err_info;
            }
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

        /* downgrade only required modules */
        if ((mod->state & MOD_INFO_REQ) && (mod->state & MOD_INFO_WLOCK)) {
            assert(shm_lock->write_locked);
            assert(!memcmp(&shm_lock->sid, &sid, sizeof sid));

            /* MOD WRITE UNLOCK */
            sr_rwunlock(&shm_lock->lock, SR_LOCK_WRITE, __func__);

            /* remove flag for correct error recovery */
            mod->state &= ~MOD_INFO_WLOCK;

            /* update this lock in SHM (we have again a fake WRITE lock) */
            sr_shmmod_conn_lock_update(mod_info->conn, mod->shm_mod, mod_info->ds, SR_LOCK_WRITE, 1);
            sr_shmmod_conn_lock_update(mod_info->conn, mod->shm_mod, mod_info->ds, SR_LOCK_READ, 1);

            /* MOD READ LOCK */
            if ((err_info = sr_shmmod_lock(mod->ly_mod->name, shm_lock, SR_MOD_LOCK_TIMEOUT * 1000, SR_LOCK_READ, sid))) {
                /* this should always succeed due to having write_lock flag set */
                SR_ERRINFO_INT(&err_info);
                return err_info;
            }
            mod->state |= MOD_INFO_RLOCK;
        }
    }

    return NULL;
}

void
sr_shmmod_modinfo_unlock(struct sr_mod_info_s *mod_info, int upgradable)
{
    uint32_t i;
    struct sr_mod_info_mod_s *mod;
    struct sr_mod_lock_s *shm_lock;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];

        if (mod->state & (MOD_INFO_RLOCK | MOD_INFO_WLOCK)) {
            /* main DS */
            shm_lock = &mod->shm_mod->data_lock_info[mod_info->ds];

            if ((mod->state & MOD_INFO_REQ) && upgradable) {
                /* this module's lock was upgraded (WRITE-locked), correctly clean everything */
                assert(shm_lock->write_locked);
                shm_lock->write_locked = 0;
                if (!shm_lock->ds_locked) {
                    memset(&shm_lock->sid, 0, sizeof shm_lock->sid);
                }

                /* update this lock in SHM (only unupgraded fake WRITE lock is covered) */
                if (mod->state & MOD_INFO_RLOCK) {
                    sr_shmmod_conn_lock_update(mod_info->conn, mod->shm_mod, mod_info->ds, SR_LOCK_WRITE, 0);
                }
            }

            if (mod->state & MOD_INFO_WLOCK) {
                /* MOD WRITE UNLOCK */
                sr_rwunlock(&shm_lock->lock, SR_LOCK_WRITE, __func__);

                /* real WRITE lock not stored in SHM */
            } else if (mod->state & MOD_INFO_RLOCK) {
                /* MOD READ UNLOCK */
                sr_rwunlock(&shm_lock->lock, SR_LOCK_READ, __func__);

                /* update this lock in SHM */
                sr_shmmod_conn_lock_update(mod_info->conn, mod->shm_mod, mod_info->ds, SR_LOCK_READ, 0);
            }
        }

        if (mod->state & MOD_INFO_RLOCK2) {
            /* secondary DS */
            shm_lock = &mod->shm_mod->data_lock_info[mod_info->ds2];

            /* MOD READ UNLOCK */
            sr_rwunlock(&shm_lock->lock, SR_LOCK_READ, __func__);

            /* update this lock in SHM */
            sr_shmmod_conn_lock_update(mod_info->conn, mod->shm_mod, mod_info->ds2, SR_LOCK_READ, 0);
        }

        /* clear flags */
        mod->state &= ~(MOD_INFO_RLOCK | MOD_INFO_WLOCK | MOD_INFO_RLOCK2);
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
    uint32_t i;

    SR_SHM_MOD_FOR(conn->main_shm.addr, conn->main_shm.size, shm_mod) {
        for (i = 0; i < SR_DS_COUNT; ++i) {
            shm_lock = &shm_mod->data_lock_info[i];
            if (shm_lock->sid.sr == sid.sr) {
                if (shm_lock->write_locked) {
                    /* this should never happen, write lock is held during some API calls */
                    sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Session %u (NC SID %u) was working with"
                            " module \"%s\"!", sid.sr, sid.nc, conn->ext_shm.addr + shm_mod->name);
                    sr_errinfo_free(&err_info);
                    shm_lock->write_locked = 0;
                }
                if (!shm_lock->ds_locked) {
                    /* why our SID matched then? */
                    SR_ERRINFO_INT(&err_info);
                    sr_errinfo_free(&err_info);
                    continue;
                }

                if (i == SR_DS_CANDIDATE) {
                    /* collect all modules */
                    SR_MODINFO_INIT(mod_info, conn, i, i);
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
                    sr_shmmod_modinfo_unlock(&mod_info, 0);

                    sr_modinfo_free(&mod_info);
                    sr_errinfo_free(&err_info);
                }

                /* unlock */
                shm_lock->ds_locked = 0;
                memset(&shm_lock->sid, 0, sizeof shm_lock->sid);
                shm_lock->ds_ts = 0;
            }
        }
    }
}

sr_error_info_t *
sr_shmmod_change_subscription_add(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, const char *xpath, sr_datastore_t ds,
        uint32_t priority, int sub_opts, uint32_t evpipe_num)
{
    sr_error_info_t *err_info = NULL;
    off_t xpath_off;
    sr_mod_change_sub_t *shm_sub;

    /* allocate new subscription and its xpath, if any */
    if ((err_info = sr_shmrealloc_add(&conn->ext_shm, &shm_mod->change_sub[ds].subs, &shm_mod->change_sub[ds].sub_count, 0,
            sizeof *shm_sub, -1, (void **)&shm_sub, xpath ? sr_strshmlen(xpath) : 0, &xpath_off))) {
        return err_info;
    }

    /* fill new subscription */
    if (xpath) {
        strcpy(conn->ext_shm.addr + xpath_off, xpath);
        shm_sub->xpath = xpath_off;
    } else {
        shm_sub->xpath = 0;
    }
    shm_sub->priority = priority;
    shm_sub->opts = sub_opts;
    shm_sub->evpipe_num = evpipe_num;

    if (ds == SR_DS_RUNNING) {
        /* technically, operational data may have changed */
        if ((err_info = sr_module_update_oper_diff(conn, conn->ext_shm.addr + shm_mod->name))) {
            return err_info;
        }
    }

    return NULL;
}

int
sr_shmmod_change_subscription_del(char *ext_shm_addr, sr_mod_t *shm_mod, const char *xpath, sr_datastore_t ds,
        uint32_t priority, int sub_opts, uint32_t evpipe_num, int only_evpipe, int *last_removed)
{
    sr_mod_change_sub_t *shm_sub;
    uint16_t i;

    if (last_removed) {
        *last_removed = 0;
    }

    /* find the subscription(s) */
    shm_sub = (sr_mod_change_sub_t *)(ext_shm_addr + shm_mod->change_sub[ds].subs);
    for (i = 0; i < shm_mod->change_sub[ds].sub_count; ++i) {
        if (only_evpipe) {
            if (shm_sub[i].evpipe_num == evpipe_num) {
                break;
            }
        } else if ((!xpath && !shm_sub[i].xpath)
                    || (xpath && shm_sub[i].xpath && !strcmp(ext_shm_addr + shm_sub[i].xpath, xpath))) {
            if ((shm_sub[i].priority == priority) && (shm_sub[i].opts == sub_opts) && (shm_sub[i].evpipe_num == evpipe_num)) {
                break;
            }
        }
    }
    if (i == shm_mod->change_sub[ds].sub_count) {
        /* subscription not found */
        return 1;
    }

    /* remove the subscription and its xpath, if any */
    sr_shmrealloc_del(ext_shm_addr, &shm_mod->change_sub[ds].subs, &shm_mod->change_sub[ds].sub_count, sizeof *shm_sub,
            i, shm_sub[i].xpath ? sr_strshmlen(ext_shm_addr + shm_sub[i].xpath) : 0);

    if (!shm_mod->change_sub[ds].subs && last_removed) {
        *last_removed = 1;
    }

    return 0;
}

sr_error_info_t *
sr_shmmod_change_subscription_stop(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, const char *xpath, sr_datastore_t ds,
        uint32_t priority, int sub_opts, uint32_t evpipe_num, int all_evpipe)
{
    sr_error_info_t *err_info = NULL;
    const char *mod_name;
    char *path;
    int last_removed;

    mod_name = conn->ext_shm.addr + shm_mod->name;

    do {
        /* remove the subscription from the main SHM */
        if (sr_shmmod_change_subscription_del(conn->ext_shm.addr, shm_mod, xpath, ds, priority, sub_opts, evpipe_num,
                all_evpipe, &last_removed)) {
            if (!all_evpipe) {
                /* error in this case */
                SR_ERRINFO_INT(&err_info);
            }
            break;
        }

        if (ds == SR_DS_RUNNING) {
            /* technically, operational data changed */
            if ((err_info = sr_module_update_oper_diff(conn, mod_name))) {
                break;
            }
        }

        if (last_removed) {
            /* delete the SHM file itself so that there is no leftover event */
            if ((err_info = sr_path_sub_shm(mod_name, sr_ds2str(ds), -1, &path))) {
                break;
            }
            if (unlink(path) == -1) {
                SR_LOG_WRN("Failed to unlink SHM \"%s\" (%s).", path, strerror(errno));
            }
            free(path);
        }
    } while (all_evpipe);

    return err_info;
}

sr_error_info_t *
sr_shmmod_oper_subscription_add(sr_shm_t *shm_ext, sr_mod_t *shm_mod, const char *xpath, sr_mod_oper_sub_type_t sub_type,
        int sub_opts, uint32_t evpipe_num)
{
    sr_error_info_t *err_info = NULL;
    off_t xpath_off;
    sr_mod_oper_sub_t *shm_sub;
    size_t new_len, cur_len;
    uint16_t i;

    assert(xpath && sub_type);

    /* check that this exact subscription does not exist yet while finding its position */
    new_len = sr_xpath_len_no_predicates(xpath);
    shm_sub = (sr_mod_oper_sub_t *)(shm_ext->addr + shm_mod->oper_subs);
    for (i = 0; i < shm_mod->oper_sub_count; ++i) {
        cur_len = sr_xpath_len_no_predicates(shm_ext->addr + shm_sub[i].xpath);
        if (cur_len > new_len) {
            /* we can insert it at i-th position */
            break;
        }

        if ((cur_len == new_len) && !strcmp(shm_ext->addr + shm_sub[i].xpath, xpath)) {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL,
                    "Data provider subscription for \"%s\" on \"%s\" already exists.", shm_ext->addr + shm_mod->name, xpath);
            return err_info;
        }
    }

    /* allocate new subscription and its xpath, if any */
    if ((err_info = sr_shmrealloc_add(shm_ext, &shm_mod->oper_subs, &shm_mod->oper_sub_count, 0, sizeof *shm_sub,
            i, (void **)&shm_sub, xpath ? sr_strshmlen(xpath) : 0, &xpath_off))) {
        return err_info;
    }

    /* fill new subscription */
    if (xpath) {
        strcpy(shm_ext->addr + xpath_off, xpath);
        shm_sub->xpath = xpath_off;
    } else {
        shm_sub->xpath = 0;
    }
    shm_sub->sub_type = sub_type;
    shm_sub->opts = sub_opts;
    shm_sub->evpipe_num = evpipe_num;

    return NULL;
}

int
sr_shmmod_oper_subscription_del(char *ext_shm_addr, sr_mod_t *shm_mod, const char *xpath, uint32_t evpipe_num,
        int only_evpipe, const char **xpath_p)
{
    sr_mod_oper_sub_t *shm_sub;
    uint16_t i;

    /* find the subscription */
    shm_sub = (sr_mod_oper_sub_t *)(ext_shm_addr + shm_mod->oper_subs);
    for (i = 0; i < shm_mod->oper_sub_count; ++i) {
        if (only_evpipe) {
            if (shm_sub[i].evpipe_num == evpipe_num) {
                break;
            }
        } else if (shm_sub[i].xpath && !strcmp(ext_shm_addr + shm_sub[i].xpath, xpath)) {
            break;
        }
    }
    if (i == shm_mod->oper_sub_count) {
        /* no matching subscription found */
        return 1;
    }

    if (xpath_p) {
        *xpath_p = ext_shm_addr + shm_sub[i].xpath;
    }

    /* delete the subscription */
    sr_shmrealloc_del(ext_shm_addr, &shm_mod->oper_subs, &shm_mod->oper_sub_count, sizeof *shm_sub, i,
            shm_sub[i].xpath ? sr_strshmlen(ext_shm_addr + shm_sub[i].xpath) : 0);

    return 0;
}

sr_error_info_t *
sr_shmmod_oper_subscription_stop(char *ext_shm_addr, sr_mod_t *shm_mod, const char *xpath, uint32_t evpipe_num,
        int all_evpipe)
{
    sr_error_info_t *err_info = NULL;
    const char *mod_name;
    char *path;

    mod_name = ext_shm_addr + shm_mod->name;

    do {
        /* remove the subscriptions from the main SHM */
        if (sr_shmmod_oper_subscription_del(ext_shm_addr, shm_mod, xpath, evpipe_num, all_evpipe, &xpath)) {
            if (!all_evpipe) {
                SR_ERRINFO_INT(&err_info);
            }
            break;
        }

        /* delete the SHM file itself so that there is no leftover event */
        if ((err_info = sr_path_sub_shm(mod_name, "oper", sr_str_hash(xpath), &path))) {
            break;
        }
        if (unlink(path) == -1) {
            SR_LOG_WRN("Failed to unlink SHM \"%s\" (%s).", path, strerror(errno));
        }
        free(path);
    } while (all_evpipe);

    return err_info;
}

sr_error_info_t *
sr_shmmod_notif_subscription_add(sr_shm_t *shm_ext, sr_mod_t *shm_mod, uint32_t sub_id, uint32_t evpipe_num)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_notif_sub_t *shm_sub;

    /* add new item */
    if ((err_info = sr_shmrealloc_add(shm_ext, &shm_mod->notif_subs, &shm_mod->notif_sub_count, 0, sizeof *shm_sub, -1,
            (void **)&shm_sub, 0, NULL))) {
        return err_info;
    }

    /* fill new subscription */
    shm_sub->sub_id = sub_id;
    shm_sub->evpipe_num = evpipe_num;

    return NULL;
}

int
sr_shmmod_notif_subscription_del(char *ext_shm_addr, sr_mod_t *shm_mod, uint32_t sub_id, uint32_t evpipe_num,
        int *last_removed)
{
    sr_mod_notif_sub_t *shm_sub;
    uint16_t i;

    assert((sub_id || evpipe_num) && (!sub_id || !evpipe_num));

    if (last_removed) {
        *last_removed = 0;
    }

    /* find the subscription */
    shm_sub = (sr_mod_notif_sub_t *)(ext_shm_addr + shm_mod->notif_subs);
    for (i = 0; i < shm_mod->notif_sub_count; ++i) {
        if (sub_id && (shm_sub[i].sub_id == sub_id)) {
            break;
        } else if (shm_sub[i].evpipe_num == evpipe_num) {
            break;
        }
    }
    if (i == shm_mod->notif_sub_count) {
        /* no matching subscription found */
        return 1;
    }

    /* remove the subscription */
    sr_shmrealloc_del(ext_shm_addr, &shm_mod->notif_subs, &shm_mod->notif_sub_count, sizeof *shm_sub, i, 0);

    if (!shm_mod->notif_subs && last_removed) {
        *last_removed = 1;
    }

    return 0;
}

sr_error_info_t *
sr_shmmod_notif_subscription_stop(char *ext_shm_addr, sr_mod_t *shm_mod, uint32_t sub_id, uint32_t evpipe_num)
{
    sr_error_info_t *err_info = NULL;
    const char *mod_name;
    char *path;
    int last_removed;

    assert((sub_id || evpipe_num) && (!sub_id || !evpipe_num));

    mod_name = ext_shm_addr + shm_mod->name;

    do {
        /* remove the subscriptions from the main SHM */
        if (sr_shmmod_notif_subscription_del(ext_shm_addr, shm_mod, sub_id, evpipe_num, &last_removed)) {
            if (sub_id) {
                SR_ERRINFO_INT(&err_info);
            }
            break;
        }

        if (last_removed) {
            /* delete the SHM file itself so that there is no leftover event */
            if ((err_info = sr_path_sub_shm(mod_name, "notif", -1, &path))) {
                break;
            }
            if (unlink(path) == -1) {
                SR_LOG_WRN("Failed to unlink SHM \"%s\" (%s).", path, strerror(errno));
            }
            free(path);
        }
    } while (evpipe_num);

    return err_info;
}

sr_error_info_t *
sr_shmmod_oper_stored_del_conn(sr_conn_ctx_t *conn, sr_conn_ctx_t *del_conn, pid_t del_pid)
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
            if ((err_info = sr_diff_del_conn(&diff, del_conn, del_pid))) {
                goto cleanup;
            }
            if ((err_info = sr_module_file_data_set(mod->ly_mod->name, SR_DS_OPERATIONAL, diff, 0, 0))) {
                goto cleanup;
            }
            lyd_free_withsiblings(diff);
            diff = NULL;
        }
    }

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info, 0);

    free(path);
    lyd_free_withsiblings(diff);
    sr_modinfo_free(&mod_info);
    return err_info;
}
