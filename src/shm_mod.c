/**
 * @file shm_mod.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief main SHM routines modifying module information
 *
 * @copyright
 * Copyright (c) 2018 - 2023 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2023 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "compat.h"
#include "shm_mod.h"

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
#include "config.h"
#include "log.h"
#include "modinfo.h"
#include "plugins_datastore.h"

sr_error_info_t *
sr_shmmod_open(sr_shm_t *shm, int zero)
{
    sr_error_info_t *err_info = NULL;
    char *shm_name = NULL, buf[8], *ret = NULL;
    FILE *f;

    err_info = sr_path_mod_shm(&shm_name);
    if (err_info) {
        return err_info;
    }

    shm->fd = sr_open(shm_name, O_RDWR | O_CREAT, SR_SHM_PERM);
    free(shm_name);
    if (shm->fd == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to open mod shared memory (%s).", strerror(errno));
        if ((errno == EACCES) && !geteuid()) {
            /* check kernel parameter value of fs.protected_regular */
            f = fopen("/proc/sys/fs/protected_regular", "r");
            if (f) {
                ret = fgets(buf, sizeof(buf), f);
                fclose(f);
            }
        }
        if (ret && (atoi(buf) != 0)) {
            sr_errinfo_new(&err_info, SR_ERR_SYS, "Caused by kernel parameter \"fs.protected_regular\", "
                    "which must be \"0\" (currently \"%d\").", atoi(buf));
        }
        goto error;
    }

    /* either zero the memory or keep it exactly the way it was */
    if ((err_info = sr_shm_remap(shm, zero ? SR_SHM_SIZE(sizeof(sr_mod_shm_t)) : 0))) {
        goto error;
    }
    if (zero) {
        ((sr_mod_shm_t *)shm->addr)->mod_count = 0;
    }

    return NULL;

error:
    sr_shm_clear(shm);
    return err_info;
}

sr_mod_t *
sr_shmmod_find_module(sr_mod_shm_t *mod_shm, const char *name)
{
    sr_mod_t *shm_mod;
    uint32_t i;

    assert(name);

    for (i = 0; i < mod_shm->mod_count; ++i) {
        shm_mod = SR_SHM_MOD_IDX(mod_shm, i);
        if (!strcmp(((char *)mod_shm) + shm_mod->name, name)) {
            return shm_mod;
        }
    }

    return NULL;
}

sr_rpc_t *
sr_shmmod_find_rpc(sr_mod_shm_t *mod_shm, const char *path)
{
    sr_mod_t *shm_mod;
    sr_rpc_t *shm_rpc;
    char *mod_name;
    uint16_t i;

    assert(path);

    /* find module first */
    mod_name = sr_get_first_ns(path);
    shm_mod = sr_shmmod_find_module(mod_shm, mod_name);
    free(mod_name);
    if (!shm_mod) {
        return NULL;
    }

    /* find the RPC */
    shm_rpc = (sr_rpc_t *)(((char *)mod_shm) + shm_mod->rpcs);
    for (i = 0; i < shm_mod->rpc_count; ++i) {
        if (!strcmp(((char *)mod_shm) + shm_rpc[i].path, path)) {
            return &shm_rpc[i];
        }
    }

    /* not found */
    return NULL;
}

/**
 * @brief Fill a new SHM module and add its name and enabled features into mod SHM.
 * Does not add data/op/inverse dependencies.
 *
 * @param[in] shm_mod Mod SHM structure to remap and add name/features at its end.
 * @param[in] shm_mod_idx Mod SHM index to fill.
 * @param[in] sr_mod Module to read the information from.
 * @param[in] old_smod Optional previous SHM mod to copy all module subscriptions from.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmod_fill(sr_shm_t *shm_mod, size_t shm_mod_idx, const struct lyd_node *sr_mod, const sr_mod_t *old_smod)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *smod;
    struct lyd_node *sr_child;
    off_t *shm_features;
    const char *name;
    char *shm_end;
    size_t feat_i, feat_names_len, ds_plugin_names_len, old_shm_size;
    sr_datastore_t ds;

    smod = SR_SHM_MOD_IDX(shm_mod->addr, shm_mod_idx);

    /* init SHM module structure */
    memset(smod, 0, sizeof *smod);
    for (ds = 0; ds < SR_DS_COUNT; ++ds) {
        if ((err_info = sr_rwlock_init(&smod->data_lock_info[ds].data_lock, 1))) {
            return err_info;
        }
        if ((err_info = sr_mutex_init(&smod->data_lock_info[ds].ds_lock, 1))) {
            return err_info;
        }
    }
    if ((err_info = sr_rwlock_init(&smod->replay_lock, 1))) {
        return err_info;
    }
    for (ds = 0; ds < SR_DS_COUNT; ++ds) {
        if ((err_info = sr_rwlock_init(&smod->change_sub[ds].lock, 1))) {
            return err_info;
        }
    }
    if ((err_info = sr_rwlock_init(&smod->oper_get_lock, 1))) {
        return err_info;
    }
    if ((err_info = sr_rwlock_init(&smod->oper_poll_lock, 1))) {
        return err_info;
    }
    if ((err_info = sr_rwlock_init(&smod->notif_lock, 1))) {
        return err_info;
    }

    /* remember name, set fields from sr_mod, and count enabled features */
    name = NULL;
    feat_names_len = 0;
    ds_plugin_names_len = 0;
    LY_LIST_FOR(lyd_child(sr_mod), sr_child) {
        if (!strcmp(sr_child->schema->name, "name")) {
            /* rememeber name */
            name = lyd_get_value(sr_child);
        } else if (!strcmp(sr_child->schema->name, "revision")) {
            /* copy revision */
            strcpy(smod->rev, lyd_get_value(sr_child));
        } else if (!strcmp(sr_child->schema->name, "replay-support")) {
            /* set replay-support flag */
            smod->replay_supp = 1;
        } else if (!strcmp(sr_child->schema->name, "enabled-feature")) {
            /* count features and ther names length */
            ++smod->feat_count;
            feat_names_len += sr_strshmlen(lyd_get_value(sr_child));
        } else if (!strcmp(sr_child->schema->name, "plugin")) {
            /* count the length of all datastore plugin names */
            ds_plugin_names_len += sr_strshmlen(lyd_get_value(lyd_child(sr_child)->next));
        }
    }
    assert(name);

    /* remember mod SHM size */
    old_shm_size = shm_mod->size;

    /* enlarge and possibly remap main SHM */
    if ((err_info = sr_shm_remap(shm_mod, shm_mod->size + sr_strshmlen(name) +
            SR_SHM_SIZE(smod->feat_count * sizeof(off_t)) + feat_names_len + ds_plugin_names_len))) {
        return err_info;
    }
    smod = SR_SHM_MOD_IDX(shm_mod->addr, shm_mod_idx);
    shm_end = shm_mod->addr + old_shm_size;

    /* store module name */
    smod->name = sr_shmstrcpy(shm_mod->addr, name, &shm_end);

    /* store feature array */
    smod->features = sr_shmcpy(shm_mod->addr, NULL, smod->feat_count * sizeof(off_t), &shm_end);

    /* store feature and datastore plugin names */
    shm_features = (off_t *)(shm_mod->addr + smod->features);
    feat_i = 0;
    LY_LIST_FOR(lyd_child(sr_mod), sr_child) {
        if (!strcmp(sr_child->schema->name, "enabled-feature")) {
            /* copy feature name */
            shm_features[feat_i] = sr_shmstrcpy(shm_mod->addr, lyd_get_value(sr_child), &shm_end);

            ++feat_i;
        } else if (!strcmp(sr_child->schema->name, "plugin")) {
            /* get DS */
            ds = sr_ident2mod_ds(lyd_get_value(lyd_child(sr_child)));

            /* copy DS plugin name */
            smod->plugins[ds] = sr_shmstrcpy(shm_mod->addr, lyd_get_value(lyd_child(sr_child)->next), &shm_end);
        }
    }
    SR_CHECK_INT_RET(feat_i != smod->feat_count, err_info);
    /* not all DS plugins must be set, 'running' may be disabled and without a plugin */

    /* mod SHM size must be exactly what we allocated */
    assert(shm_end == shm_mod->addr + shm_mod->size);

    if (old_smod) {
        /* copy change subscriptions */
        for (ds = 0; ds < SR_DS_COUNT; ++ds) {
            smod->change_sub[ds].subs = old_smod->change_sub[ds].subs;
            smod->change_sub[ds].sub_count = old_smod->change_sub[ds].sub_count;
        }

        /* copy oper get subscriptions */
        smod->oper_get_subs = old_smod->oper_get_subs;
        smod->oper_get_sub_count = old_smod->oper_get_sub_count;

        /* copy oper poll subscriptions */
        smod->oper_poll_subs = old_smod->oper_poll_subs;
        smod->oper_poll_sub_count = old_smod->oper_poll_sub_count;

        /* copy notif subscriptions */
        smod->notif_subs = old_smod->notif_subs;
        smod->notif_sub_count = old_smod->notif_sub_count;
    }

    return NULL;
}

/**
 * @brief Fill mod SHM dependency information based on internal sysrepo data.
 *
 * @param[in] mod_shm Mod SHM.
 * @param[in] sr_dep_parent Dependencies in internal sysrepo data.
 * @param[in] shm_deps Mod SHM dependencies to fill.
 * @param[out] dep_i Number of dependencies filled.
 * @param[in,out] shm_end Current SHM end.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmod_fill_deps(sr_mod_shm_t *mod_shm, struct lyd_node *sr_dep_parent, sr_dep_t *shm_deps, size_t *dep_i,
        char **shm_end)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *ref_smod = NULL;
    struct lyd_node *node, *sr_dep;
    struct ly_set *tmods = NULL;
    off_t *mod_names;
    uint32_t i;

    assert(!*dep_i);

    LY_LIST_FOR(lyd_child(sr_dep_parent), sr_dep) {
        if (!strcmp(sr_dep->schema->name, "lref")) {
            /* set dep type */
            shm_deps[*dep_i].type = SR_DEP_LREF;

            /* store path */
            lyd_find_path(sr_dep, "target-path", 0, &node);
            assert(node);
            shm_deps[*dep_i].lref.target_path = sr_shmstrcpy((char *)mod_shm, lyd_get_value(node), shm_end);

            /* copy module name offset */
            lyd_find_path(sr_dep, "target-module", 0, &node);
            assert(node);
            ref_smod = sr_shmmod_find_module(mod_shm, lyd_get_value(node));
            SR_CHECK_INT_GOTO(!ref_smod, err_info, cleanup);
            shm_deps[*dep_i].lref.target_module = ref_smod->name;

            ++(*dep_i);
        } else if (!strcmp(sr_dep->schema->name, "inst-id")) {
            /* set dep type */
            shm_deps[*dep_i].type = SR_DEP_INSTID;

            /* store path */
            lyd_find_path(sr_dep, "source-path", 0, &node);
            assert(node);
            shm_deps[*dep_i].instid.source_path = sr_shmstrcpy((char *)mod_shm, lyd_get_value(node), shm_end);

            /* copy module name offset */
            lyd_find_path(sr_dep, "default-target-path", 0, &node);
            if (node) {
                shm_deps[*dep_i].instid.default_target_path = sr_shmstrcpy((char *)mod_shm, lyd_get_value(node), shm_end);
            }

            ++(*dep_i);
        } else if (!strcmp(sr_dep->schema->name, "xpath")) {
            /* set dep type */
            shm_deps[*dep_i].type = SR_DEP_XPATH;

            /* store xpath */
            lyd_find_path(sr_dep, "expression", 0, &node);
            assert(node);
            shm_deps[*dep_i].xpath.expr = sr_shmstrcpy((char *)mod_shm, lyd_get_value(node), shm_end);

            /* get all target modules */
            if (lyd_find_xpath(sr_dep, "target-module", &tmods)) {
                sr_errinfo_new_ly(&err_info, LYD_CTX(sr_dep), NULL);
                goto cleanup;
            }

            if (tmods->count) {
                /* allocate array of offsets */
                shm_deps[*dep_i].xpath.target_modules = sr_shmcpy((char *)mod_shm, NULL,
                        tmods->count * sizeof(off_t), shm_end);
                shm_deps[*dep_i].xpath.target_mod_count = tmods->count;
                mod_names = (off_t *)(((char *)mod_shm) + shm_deps[*dep_i].xpath.target_modules);

                /* copy module name offsets */
                for (i = 0; i < tmods->count; ++i) {
                    ref_smod = sr_shmmod_find_module(mod_shm, lyd_get_value(tmods->dnodes[i]));
                    SR_CHECK_INT_GOTO(!ref_smod, err_info, cleanup);
                    mod_names[i] = ref_smod->name;
                }
            }
            ly_set_free(tmods, NULL);
            tmods = NULL;

            ++(*dep_i);
        }
    }

cleanup:
    ly_set_free(tmods, NULL);
    return err_info;
}

/**
 * @brief Count the SHM length of all the strings and arrays in a dependency list instance.
 *
 * @param[in] sr_dep Dependency in internal sysrepo data.
 * @param[in,out] shm_size Size of SHM to add to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmod_add_dep_size(const struct lyd_node *sr_dep, size_t *shm_size)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set = NULL;
    uint32_t i;

    /* get all the strings */
    if (lyd_find_xpath(sr_dep, "target-path | source-path | default-target-path | expression", &set)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(sr_dep), NULL);
        goto cleanup;
    }

    /* add their SHM sizes */
    for (i = 0; i < set->count; ++i) {
        *shm_size += sr_strshmlen(lyd_get_value(set->dnodes[i]));
    }

    /* find all target modules */
    if (!strcmp(sr_dep->schema->name, "xpath")) {
        ly_set_free(set, NULL);
        if (lyd_find_xpath(sr_dep, "target-module", &set)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(sr_dep), NULL);
            goto cleanup;
        }

        /* add all arrays SHM size */
        *shm_size += SR_SHM_SIZE(set->count * sizeof(off_t));
    }

cleanup:
    ly_set_free(set, NULL);
    return err_info;
}

/**
 * @brief Add module (data and inverse) dependencies into mod SHM.
 *
 * @param[in] shm_mod Mod SHM structure to remap and append the data to.
 * @param[in] shm_mod_idx Mod SHM mod index of @p sr_mod.
 * @param[in] sr_mod Module to read the information from.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmod_add_deps(sr_shm_t *shm_mod, size_t shm_mod_idx, const struct lyd_node *sr_mod)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_child, *sr_dep;
    sr_mod_t *smod, *ref_smod;
    sr_dep_t *shm_deps;
    off_t *shm_inv_deps;
    sr_mod_shm_t *mod_shm;
    char *shm_end;
    size_t paths_len, dep_i, inv_dep_i, old_shm_size;

    smod = SR_SHM_MOD_IDX(shm_mod->addr, shm_mod_idx);

    assert(!smod->dep_count);
    assert(!smod->inv_dep_count);

    /* count arrays and paths length */
    paths_len = 0;
    LY_LIST_FOR(lyd_child(sr_mod), sr_child) {
        if (!strcmp(sr_child->schema->name, "deps")) {
            LY_LIST_FOR(lyd_child(sr_child), sr_dep) {
                /* another data dependency and additional strings */
                ++smod->dep_count;
                if ((err_info = sr_shmmod_add_dep_size(sr_dep, &paths_len))) {
                    return err_info;
                }
            }
        } else if (!strcmp(sr_child->schema->name, "inverse-deps")) {
            /* another inverse data dependency */
            ++smod->inv_dep_count;
        }
    }

    /* remember main SHM size */
    old_shm_size = shm_mod->size;

    /* enlarge and possibly remap mod SHM */
    if ((err_info = sr_shm_remap(shm_mod, shm_mod->size + paths_len + SR_SHM_SIZE(smod->dep_count * sizeof(sr_dep_t)) +
            SR_SHM_SIZE(smod->inv_dep_count * sizeof(off_t))))) {
        return err_info;
    }
    smod = SR_SHM_MOD_IDX(shm_mod->addr, shm_mod_idx);
    shm_end = shm_mod->addr + old_shm_size;
    mod_shm = (sr_mod_shm_t *)shm_mod->addr;

    /* allocate dependencies */
    smod->deps = sr_shmcpy(shm_mod->addr, NULL, smod->dep_count * sizeof(sr_dep_t), &shm_end);
    shm_deps = (sr_dep_t *)(shm_mod->addr + smod->deps);
    dep_i = 0;

    smod->inv_deps = sr_shmcpy(shm_mod->addr, NULL, smod->inv_dep_count * sizeof(off_t), &shm_end);
    shm_inv_deps = (off_t *)(shm_mod->addr + smod->inv_deps);
    inv_dep_i = 0;

    LY_LIST_FOR(lyd_child(sr_mod), sr_child) {
        if (!strcmp(sr_child->schema->name, "deps")) {
            /* now fill the dependency array */
            if ((err_info = sr_shmmod_fill_deps(mod_shm, sr_child, shm_deps, &dep_i, &shm_end))) {
                return err_info;
            }
        } else if (!strcmp(sr_child->schema->name, "inverse-deps")) {
            /* now fill module references */
            ref_smod = sr_shmmod_find_module(mod_shm, lyd_get_value(sr_child));
            SR_CHECK_INT_RET(!ref_smod, err_info);
            shm_inv_deps[inv_dep_i] = ref_smod->name;

            ++inv_dep_i;
        }
    }
    SR_CHECK_INT_RET(dep_i != smod->dep_count, err_info);
    SR_CHECK_INT_RET(inv_dep_i != smod->inv_dep_count, err_info);

    /* mod SHM size must be exactly what we allocated */
    assert(shm_end == shm_mod->addr + shm_mod->size);
    return NULL;
}

/**
 * @brief Add module RPCs/actions with dependencies into mod SHM.
 *
 * @param[in] shm_mod Mod SHM structure to remap and append the data to.
 * @param[in] shm_mod_idx Mod SHM mod index of @p sr_mod.
 * @param[in] sr_mod Module to read the information from.
 * @param[in] shm_mod_old Optional previous mod SHM to copy all RPC subscriptions from.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmod_add_rpcs(sr_shm_t *shm_mod, size_t shm_mod_idx, const struct lyd_node *sr_mod, char *shm_mod_old)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_child, *sr_dep, *sr_op, *sr_op_dep;
    sr_mod_t *smod;
    sr_dep_t *shm_deps;
    sr_rpc_t *shm_rpcs, *old_shm_rpc;
    sr_mod_shm_t *mod_shm;
    char *shm_end;
    size_t paths_len, in_out_deps_len, dep_i, rpc_i, old_shm_size;

    smod = SR_SHM_MOD_IDX(shm_mod->addr, shm_mod_idx);

    assert(!smod->rpc_count);

    /* count arrays and paths length */
    paths_len = 0;
    in_out_deps_len = 0;
    LY_LIST_FOR(lyd_child(sr_mod), sr_child) {
        if (!strcmp(sr_child->schema->name, "rpc")) {
            /* another RPC/action */
            ++smod->rpc_count;

            LY_LIST_FOR(lyd_child(sr_child), sr_op_dep) {
                if (!strcmp(sr_op_dep->schema->name, "path")) {
                    /* operation path (a string) */
                    paths_len += sr_strshmlen(lyd_get_value(sr_op_dep));
                } else if (!strcmp(sr_op_dep->schema->name, "in") || !strcmp(sr_op_dep->schema->name, "out")) {
                    dep_i = 0;
                    LY_LIST_FOR(lyd_child(sr_op_dep), sr_dep) {
                        /* another dependency */
                        ++dep_i;
                        if ((err_info = sr_shmmod_add_dep_size(sr_dep, &paths_len))) {
                            return err_info;
                        }
                    }

                    /* all RPC input/output dependencies (must be counted this way to align all the arrays individually) */
                    in_out_deps_len += SR_SHM_SIZE(dep_i * sizeof *shm_deps);
                }
            }
        }
    }

    /* remember mod SHM size */
    old_shm_size = shm_mod->size;

    /* enlarge and possibly remap mod SHM */
    if ((err_info = sr_shm_remap(shm_mod, shm_mod->size + paths_len + SR_SHM_SIZE(smod->rpc_count * sizeof *shm_rpcs) +
            in_out_deps_len))) {
        return err_info;
    }
    smod = SR_SHM_MOD_IDX(shm_mod->addr, shm_mod_idx);
    shm_end = shm_mod->addr + old_shm_size;
    mod_shm = (sr_mod_shm_t *)shm_mod->addr;

    /* allocate RPCs */
    smod->rpcs = sr_shmcpy(shm_mod->addr, NULL, smod->rpc_count * sizeof *shm_rpcs, &shm_end);
    shm_rpcs = (sr_rpc_t *)(shm_mod->addr + smod->rpcs);
    rpc_i = 0;

    LY_LIST_FOR(lyd_child(sr_mod), sr_child) {
        if (!strcmp(sr_child->schema->name, "rpc")) {
            /* init lock */
            if ((err_info = sr_rwlock_init(&shm_rpcs[rpc_i].lock, 1))) {
                return err_info;
            }

            old_shm_rpc = NULL;
            LY_LIST_FOR(lyd_child(sr_child), sr_op) {
                if (!strcmp(sr_op->schema->name, "path")) {
                    /* copy path */
                    shm_rpcs[rpc_i].path = sr_shmstrcpy(shm_mod->addr, lyd_get_value(sr_op), &shm_end);

                    if (shm_mod_old) {
                        /* try to find the RPC in old RPCs */
                        old_shm_rpc = sr_shmmod_find_rpc((sr_mod_shm_t *)shm_mod_old, lyd_get_value(sr_op));
                    }
                } else if (!strcmp(sr_op->schema->name, "in")) {
                    LY_LIST_FOR(lyd_child(sr_op), sr_op_dep) {
                        /* count input deps first */
                        ++shm_rpcs[rpc_i].in_dep_count;
                    }

                    /* allocate array */
                    shm_rpcs[rpc_i].in_deps = sr_shmcpy(shm_mod->addr, NULL,
                            shm_rpcs[rpc_i].in_dep_count * sizeof *shm_deps, &shm_end);

                    /* fill the array */
                    shm_deps = (sr_dep_t *)(shm_mod->addr + shm_rpcs[rpc_i].in_deps);
                    dep_i = 0;
                    if ((err_info = sr_shmmod_fill_deps(mod_shm, sr_op, shm_deps, &dep_i, &shm_end))) {
                        return err_info;
                    }
                    SR_CHECK_INT_RET(dep_i != shm_rpcs[rpc_i].in_dep_count, err_info);
                } else if (!strcmp(sr_op->schema->name, "out")) {
                    LY_LIST_FOR(lyd_child(sr_op), sr_op_dep) {
                        /* count op output data deps first */
                        ++shm_rpcs[rpc_i].out_dep_count;
                    }

                    /* allocate array */
                    shm_rpcs[rpc_i].out_deps = sr_shmcpy(shm_mod->addr, NULL,
                            shm_rpcs[rpc_i].out_dep_count * sizeof *shm_deps, &shm_end);

                    /* fill the array */
                    shm_deps = (sr_dep_t *)(shm_mod->addr + shm_rpcs[rpc_i].out_deps);
                    dep_i = 0;
                    if ((err_info = sr_shmmod_fill_deps(mod_shm, sr_op, shm_deps, &dep_i, &shm_end))) {
                        return err_info;
                    }
                    SR_CHECK_INT_RET(dep_i != shm_rpcs[rpc_i].out_dep_count, err_info);
                }
            }

            if (old_shm_rpc) {
                /* copy RPC subscriptions */
                shm_rpcs[rpc_i].subs = old_shm_rpc->subs;
                shm_rpcs[rpc_i].sub_count = old_shm_rpc->sub_count;
            }

            ++rpc_i;
        }
    }
    SR_CHECK_INT_RET(rpc_i != smod->rpc_count, err_info);

    /* mod SHM size must be exactly what we allocated */
    assert(shm_end == shm_mod->addr + shm_mod->size);
    return NULL;
}

/**
 * @brief Add module notifications with dependencies into mod SHM.
 *
 * @param[in] shm_mod Mod SHM structure to remap and append the data to.
 * @param[in] shm_mod_idx Mod SHM mod index of @p sr_mod.
 * @param[in] sr_mod Module to read the information from.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmod_add_notifs(sr_shm_t *shm_mod, size_t shm_mod_idx, const struct lyd_node *sr_mod)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_child, *sr_dep, *sr_op, *sr_op_dep;
    sr_mod_t *smod;
    sr_dep_t *shm_deps;
    sr_notif_t *shm_notifs;
    sr_mod_shm_t *mod_shm;
    char *shm_end;
    size_t paths_len, deps_len, dep_i, notif_i, old_shm_size;

    smod = SR_SHM_MOD_IDX(shm_mod->addr, shm_mod_idx);

    assert(!smod->notif_count);

    /* count arrays and paths length */
    paths_len = 0;
    deps_len = 0;
    LY_LIST_FOR(lyd_child(sr_mod), sr_child) {
        if (!strcmp(sr_child->schema->name, "notification")) {
            /* another notification */
            ++smod->notif_count;

            LY_LIST_FOR(lyd_child(sr_child), sr_op_dep) {
                if (!strcmp(sr_op_dep->schema->name, "path")) {
                    /* operation path (a string) */
                    paths_len += sr_strshmlen(lyd_get_value(sr_op_dep));
                } else if (!strcmp(sr_op_dep->schema->name, "deps")) {
                    dep_i = 0;
                    LY_LIST_FOR(lyd_child(sr_op_dep), sr_dep) {
                        /* another dependency */
                        ++dep_i;
                        if ((err_info = sr_shmmod_add_dep_size(sr_dep, &paths_len))) {
                            return err_info;
                        }
                    }

                    /* all notification dependencies (must be counted this way to align all the arrays individually) */
                    deps_len += SR_SHM_SIZE(dep_i * sizeof(sr_dep_t));
                }
            }
        }
    }

    /* remember mod SHM size */
    old_shm_size = shm_mod->size;

    /* enlarge and possibly remap mod SHM */
    if ((err_info = sr_shm_remap(shm_mod, shm_mod->size + paths_len + SR_SHM_SIZE(smod->notif_count * sizeof(sr_notif_t)) +
            deps_len))) {
        return err_info;
    }
    smod = SR_SHM_MOD_IDX(shm_mod->addr, shm_mod_idx);
    shm_end = shm_mod->addr + old_shm_size;
    mod_shm = (sr_mod_shm_t *)shm_mod->addr;

    /* allocate notifications */
    smod->notifs = sr_shmcpy(shm_mod->addr, NULL, smod->notif_count * sizeof(sr_notif_t), &shm_end);
    shm_notifs = (sr_notif_t *)(shm_mod->addr + smod->notifs);
    notif_i = 0;

    LY_LIST_FOR(lyd_child(sr_mod), sr_child) {
        if (!strcmp(sr_child->schema->name, "notification")) {
            LY_LIST_FOR(lyd_child(sr_child), sr_op) {
                if (!strcmp(sr_op->schema->name, "path")) {
                    /* copy xpath name */
                    shm_notifs[notif_i].path = sr_shmstrcpy(shm_mod->addr, lyd_get_value(sr_op), &shm_end);
                } else if (!strcmp(sr_op->schema->name, "deps")) {
                    LY_LIST_FOR(lyd_child(sr_op), sr_op_dep) {
                        /* count deps first */
                        ++shm_notifs[notif_i].dep_count;
                    }

                    /* allocate array */
                    shm_notifs[notif_i].deps = sr_shmcpy(shm_mod->addr, NULL,
                            shm_notifs[notif_i].dep_count * sizeof(sr_dep_t), &shm_end);

                    /* fill the array */
                    shm_deps = (sr_dep_t *)(shm_mod->addr + shm_notifs[notif_i].deps);
                    dep_i = 0;
                    if ((err_info = sr_shmmod_fill_deps(mod_shm, sr_op, shm_deps, &dep_i, &shm_end))) {
                        return err_info;
                    }
                    SR_CHECK_INT_RET(dep_i != shm_notifs[notif_i].dep_count, err_info);
                }
            }

            ++notif_i;
        }
    }
    SR_CHECK_INT_RET(notif_i != smod->notif_count, err_info);

    /* mod SHM size must be exactly what we allocated */
    assert(shm_end == shm_mod->addr + shm_mod->size);
    return NULL;
}

sr_error_info_t *
sr_shmmod_store_modules(sr_shm_t *shm_mod, const struct lyd_node *sr_mods)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *sr_mod;
    sr_mod_t *smod;
    char *shm_mod_old = NULL;
    uint32_t i, mod_count;

    /* backup current SHM mod */
    shm_mod_old = malloc(shm_mod->size);
    SR_CHECK_MEM_GOTO(!shm_mod_old, err_info, cleanup);
    memcpy(shm_mod_old, shm_mod->addr, shm_mod->size);

    /* count how many modules are we going to store */
    mod_count = 0;
    LY_LIST_FOR(lyd_child(sr_mods), sr_mod) {
        if (!strcmp(sr_mod->schema->name, "module")) {
            ++mod_count;
        }
    }

    /* enlarge mod SHM for all the modules */
    if ((err_info = sr_shm_remap(shm_mod, SR_SHM_SIZE(sizeof(sr_mod_shm_t)) + mod_count * sizeof *smod))) {
        goto cleanup;
    }

    /* set module count */
    ((sr_mod_shm_t *)shm_mod->addr)->mod_count = mod_count;

    /* add all modules into SHM */
    i = 0;
    sr_mod = lyd_child(sr_mods);
    while (i < mod_count) {
        if (!strcmp(sr_mod->schema->name, "module")) {
            /* find this module in the SHM mod backup (removed modules will not be found) */
            smod = sr_shmmod_find_module((sr_mod_shm_t *)shm_mod_old, lyd_get_value(lyd_child(sr_mod)));

            /* fill the new module */
            if ((err_info = sr_shmmod_fill(shm_mod, i, sr_mod, smod))) {
                goto cleanup;
            }

            ++i;
        }

        sr_mod = sr_mod->next;
    }

    /*
     * Dependencies of old modules are rebuild because of possible
     * 1) new inverse dependencies when new modules depend on the old ones;
     * 2) new dependencies in the old modules in case they were added by foreign augments in the new modules.
     * Checking these cases would probably be more costly than just always rebuilding all dependencies.
     */

    /* add all dependencies/operations with dependencies for all modules in SHM, in separate loop because
     * all modules must have their name set so that it can be referenced */
    i = 0;
    sr_mod = lyd_child(sr_mods);
    while (i < mod_count) {
        if (!strcmp(sr_mod->schema->name, "module")) {
            if ((err_info = sr_shmmod_add_deps(shm_mod, i, sr_mod))) {
                goto cleanup;
            }
            if ((err_info = sr_shmmod_add_rpcs(shm_mod, i, sr_mod, shm_mod_old))) {
                goto cleanup;
            }
            if ((err_info = sr_shmmod_add_notifs(shm_mod, i, sr_mod))) {
                goto cleanup;
            }

            ++i;
        }

        sr_mod = sr_mod->next;
    }

cleanup:
    free(shm_mod_old);
    return err_info;
}

/**
 * @brief Create feature array ended with NULL from SHM features.
 *
 * @param[in] mod_shm_addr Mod SHM address.
 * @param[in] shm_features Mod SHM features.
 * @param[in] feat_count Number of @p shm_features.
 * @param[out] features Array of features.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmod_features2array(char *mod_shm_addr, off_t *shm_features, uint16_t feat_count, const char ***features)
{
    sr_error_info_t *err_info = NULL;
    uint16_t i;

    /* alloc array */
    *features = calloc(feat_count + 1, sizeof **features);
    SR_CHECK_MEM_RET(!*features, err_info);

    /* set all the features */
    for (i = 0; i < feat_count; ++i) {
        (*features)[i] = mod_shm_addr + shm_features[i];
    }

    return NULL;
}

sr_error_info_t *
sr_shmmod_ctx_load_modules(sr_mod_shm_t *mod_shm, struct ly_ctx *ly_ctx, const struct ly_set *skip_mod_set)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *smod;
    const struct lys_module *skip_mod, *ly_mod;
    off_t *shm_features;
    const char *mod_name, **features;
    uint32_t i, j;

    for (i = 0; i < mod_shm->mod_count; ++i) {
        smod = SR_SHM_MOD_IDX((char *)mod_shm, i);
        mod_name = (char *)mod_shm + smod->name;

        if (skip_mod_set) {
            for (j = 0; j < skip_mod_set->count; ++j) {
                skip_mod = skip_mod_set->objs[j];
                if (!strcmp(skip_mod->name, mod_name)) {
                    break;
                }
            }
            if (j < skip_mod_set->count) {
                /* this module should be skipped */
                continue;
            }
        }

        /* create the features array */
        shm_features = (off_t *)((char *)mod_shm + smod->features);
        if ((err_info = sr_shmmod_features2array((char *)mod_shm, shm_features, smod->feat_count, &features))) {
            return err_info;
        }

        /* load the module */
        ly_mod = ly_ctx_load_module(ly_ctx, mod_name, smod->rev[0] ? smod->rev : NULL, features);
        free(features);
        if (!ly_mod) {
            sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
            return err_info;
        }
    }

    /* compile */
    if (ly_ctx_compile(ly_ctx)) {
        sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
        return err_info;
    }

    return NULL;
}

sr_error_info_t *
sr_shmmod_get_rpc_deps(sr_mod_shm_t *mod_shm, const char *path, int output, sr_dep_t **shm_deps, uint16_t *shm_dep_count)
{
    sr_error_info_t *err_info = NULL;
    sr_rpc_t *shm_rpc;

    /* find the RPC in SHM */
    shm_rpc = sr_shmmod_find_rpc(mod_shm, path);
    SR_CHECK_INT_RET(!shm_rpc, err_info);

    /* collect dependencies */
    *shm_deps = (sr_dep_t *)(((char *)mod_shm) + (output ? shm_rpc->out_deps : shm_rpc->in_deps));
    *shm_dep_count = (output ? shm_rpc->out_dep_count : shm_rpc->in_dep_count);

    return NULL;
}

sr_error_info_t *
sr_shmmod_get_notif_deps(sr_mod_shm_t *mod_shm, const struct lys_module *notif_mod, const struct lyd_node *notif_op,
        sr_dep_t **shm_deps, uint16_t *shm_dep_count)
{
    sr_error_info_t *err_info = NULL;
    char *path = NULL;
    sr_mod_t *smod;
    sr_notif_t *shm_notif;
    uint32_t i;

    /* get the path */
    path = lysc_path(notif_op->schema, LYSC_PATH_DATA, NULL, 0);
    SR_CHECK_MEM_GOTO(!path, err_info, cleanup);

    /* find the module in SHM */
    smod = sr_shmmod_find_module(mod_shm, notif_mod->name);
    SR_CHECK_INT_GOTO(!smod, err_info, cleanup);

    /* find the notification in SHM */
    shm_notif = (sr_notif_t *)(((char *)mod_shm) + smod->notifs);
    for (i = 0; i < smod->notif_count; ++i) {
        if (!strcmp(path, ((char *)mod_shm) + shm_notif[i].path)) {
            break;
        }
    }
    SR_CHECK_INT_GOTO(i == smod->notif_count, err_info, cleanup);

    /* collect dependencies */
    *shm_deps = (sr_dep_t *)(((char *)mod_shm) + shm_notif[i].deps);
    *shm_dep_count = shm_notif[i].dep_count;

cleanup:
    free(path);
    return err_info;
}

sr_error_info_t *
sr_shmmod_collect_deps_lref(const char *target_path, const char *target_module, struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;

    /* find ly module */
    ly_mod = ly_ctx_get_module_implemented(mod_info->conn->ly_ctx, target_module);
    SR_CHECK_INT_RET(!ly_mod, err_info);

    /* add dependency */
    if ((err_info = sr_modinfo_add(ly_mod, target_path, 0, 0, mod_info))) {
        return err_info;
    }

    return NULL;
}

sr_error_info_t *
sr_shmmod_collect_deps_instid(const char *source_path, const char *default_target_path, const struct lyd_node *data,
        struct sr_mod_info_s *mod_info)
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
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
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
            ly_mod = ly_ctx_get_module_implemented(mod_info->conn->ly_ctx, str);
            free(str);
            SR_CHECK_INT_GOTO(!ly_mod, err_info, cleanup);

            /* add module */
            if ((err_info = sr_modinfo_add(ly_mod, val_str, 0, 0, mod_info))) {
                goto cleanup;
            }
        }
    } else if (default_target_path) {
        /* assume a default value will be used even though it may not be */
        str = sr_get_first_ns(default_target_path);
        ly_mod = ly_ctx_get_module_implemented(mod_info->conn->ly_ctx, str);
        free(str);
        SR_CHECK_INT_GOTO(!ly_mod, err_info, cleanup);

        if ((err_info = sr_modinfo_add(ly_mod, default_target_path, 0, 0, mod_info))) {
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
 * @param[in] mod_shm_addr Main SHM address.
 * @param[in] target_modules Module names array.
 * @param[in] mod_name_count Module name count.
 * @param[in,out] mod_info Mod info to add to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmod_collect_deps_xpath(const char *expr, char *mod_shm_addr, off_t *target_modules, uint16_t target_mod_count,
        struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    uint16_t i;

    /* add dependencies for all the modules */
    for (i = 0; i < target_mod_count; ++i) {
        /* find ly module */
        ly_mod = ly_ctx_get_module_implemented(mod_info->conn->ly_ctx, mod_shm_addr + target_modules[i]);
        SR_CHECK_INT_RET(!ly_mod, err_info);

        /* add dependency */
        if ((err_info = sr_modinfo_add(ly_mod, expr, 0, 0, mod_info))) {
            return err_info;
        }
    }

    return NULL;
}

sr_error_info_t *
sr_shmmod_collect_deps(sr_mod_shm_t *mod_shm, sr_dep_t *shm_deps, uint16_t shm_dep_count, const struct lyd_node *data,
        struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    const char *str1, *str2;
    off_t *mod_names;

    /* collect all possibly required modules (because of inst-ids) into a set */
    for (i = 0; i < shm_dep_count; ++i) {
        switch (shm_deps[i].type) {
        case SR_DEP_LREF:
            str1 = (char *)mod_shm + shm_deps[i].lref.target_path;
            str2 = (char *)mod_shm + shm_deps[i].lref.target_module;
            if ((err_info = sr_shmmod_collect_deps_lref(str1, str2, mod_info))) {
                goto cleanup;
            }
            break;
        case SR_DEP_INSTID:
            str1 = (char *)mod_shm + shm_deps[i].instid.source_path;
            str2 = shm_deps[i].instid.default_target_path ? (char *)mod_shm +
                    shm_deps[i].instid.default_target_path : NULL;
            if ((err_info = sr_shmmod_collect_deps_instid(str1, str2, data, mod_info))) {
                goto cleanup;
            }
            break;
        case SR_DEP_XPATH:
            str1 = (char *)mod_shm + shm_deps[i].xpath.expr;
            mod_names = (off_t *)((char *)mod_shm + shm_deps[i].xpath.target_modules);
            if ((err_info = sr_shmmod_collect_deps_xpath(str1, (char *)mod_shm, mod_names,
                    shm_deps[i].xpath.target_mod_count, mod_info))) {
                goto cleanup;
            }
            break;
        default:
            SR_ERRINFO_INT(&err_info);
            goto cleanup;
        }
    }

cleanup:
    return err_info;
}

void
sr_shmmod_recover_cb(sr_lock_mode_t mode, sr_cid_t cid, void *data)
{
    struct sr_shmmod_recover_cb_s *cb_data = data;
    const struct lys_module *ly_mod;

    (void)cid;

    if (mode != SR_LOCK_WRITE) {
        /* nothing to recover */
        return;
    }

    /* get sysrepo module from the context now that it cannot change */
    ly_mod = ly_ctx_get_module_implemented(*cb_data->ly_ctx_p, "sysrepo");
    assert(ly_mod);

    /* recovery specific for the plugin */
    cb_data->ds_handle->plugin->recover_cb(ly_mod, cb_data->ds, cb_data->ds_handle->plg_data);
}

/**
 * @brief Lock or relock a mod SHM module.
 *
 * @param[in] ly_mod libyang module.
 * @param[in] ds Datastore.
 * @param[in] shm_lock Main SHM module lock.
 * @param[in] timeout_ms Timeout in ms. If 0, the default timeout is used.
 * @param[in] mode Lock mode of the module.
 * @param[in] ds_timeout_ms Timeout in ms for DS-lock in case it is required and locked, if 0 no waiting is performed.
 * @param[in] cid Connection ID.
 * @param[in] sid Sysrepo session ID to store.
 * @param[in] ds_handle DS plugin handle.
 * @param[in] relock Whether some lock is already held or not.
 */
static sr_error_info_t *
sr_shmmod_lock(const struct lys_module *ly_mod, sr_datastore_t ds, struct sr_mod_lock_s *shm_lock, uint32_t timeout_ms,
        sr_lock_mode_t mode, uint32_t ds_timeout_ms, sr_cid_t cid, uint32_t sid, const struct sr_ds_handle_s *ds_handle,
        int relock)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    struct sr_shmmod_recover_cb_s cb_data;
    int ds_locked;
    uint32_t sleep_ms;

    if (!timeout_ms) {
        /* default timeout */
        timeout_ms = SR_MOD_LOCK_TIMEOUT;
    }

    /* fill recovery callback information, context cannot be changed */
    cb_data.ly_ctx_p = (struct ly_ctx **)&ly_mod->ctx;
    cb_data.ds = ds;
    cb_data.ds_handle = ds_handle;

ds_lock_retry:
    ds_locked = 0;

    if (relock) {
        /* RELOCK */
        err_info = sr_rwrelock(&shm_lock->data_lock, timeout_ms, mode, cid, __func__, sr_shmmod_recover_cb, &cb_data);
    } else {
        /* LOCK */
        err_info = sr_rwlock(&shm_lock->data_lock, timeout_ms, mode, cid, __func__, sr_shmmod_recover_cb, &cb_data);
    }
    if (err_info) {
        goto cleanup;
    }

    if ((mode == SR_LOCK_READ_UPGR) || (mode == SR_LOCK_WRITE) || (mode == SR_LOCK_WRITE_URGE)) {
        /* DS LOCK */
        if ((err_info = sr_mlock(&shm_lock->ds_lock, SR_DS_LOCK_MUTEX_TIMEOUT, __func__, NULL, NULL))) {
            goto revert_lock;
        }

        /* DS lock cannot be held for these lock modes */
        if (shm_lock->ds_lock_sid && (shm_lock->ds_lock_sid != sid)) {
            ds_locked = 1;
        }

        /* DS UNLOCK */
        sr_munlock(&shm_lock->ds_lock);
    }

    if (ds_locked) {
        goto revert_lock;
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

    if (err_info) {
        /* error */
        goto cleanup;
    }

    assert(ds_locked);
    if (ds_timeout_ms) {
        /* sleep for the step/whatever is left and retry */
        sleep_ms = (ds_timeout_ms >= SR_DS_LOCK_TIMEOUT_STEP) ? SR_DS_LOCK_TIMEOUT_STEP : ds_timeout_ms;
        sr_msleep(sleep_ms);
        ds_timeout_ms -= sleep_ms;
        goto ds_lock_retry;
    } else {
        /* timeout elapsed */
        sr_errinfo_new(&err_info, SR_ERR_LOCKED, "Module \"%s\" is DS-locked by session %" PRIu32 ".",
                ly_mod->name, shm_lock->ds_lock_sid);
    }

cleanup:
    return err_info;
}

/**
 * @brief Lock all modules in a mod info.
 *
 * @param[in] mod_info Mod info with modules to lock.
 * @param[in] ds Datastore to lock.
 * @param[in] mode Lock mode.
 * @param[in] lock_bit Bit to set for all locked modules.
 * @param[in] sid Session ID.
 * @param[in] timeout_ms Timeout in ms for mod lock.
 * @param[in] ds_timeout_ms Timeout in ms for DS-lock in case it is required and locked, if 0 no waiting is performed.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmod_modinfo_lock(struct sr_mod_info_s *mod_info, sr_datastore_t ds, sr_lock_mode_t mode, uint32_t lock_bit,
        uint32_t sid, uint32_t timeout_ms, uint32_t ds_timeout_ms)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, cur_bit;
    struct sr_mod_info_mod_s *mod;
    struct sr_mod_lock_s *shm_lock;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        shm_lock = &mod->shm_mod->data_lock_info[ds];

        if (lock_bit == MOD_INFO_RLOCK2) {
            if (mod->state & MOD_INFO_RLOCK2) {
                /* already locked */
                continue;
            }
        } else {
            cur_bit = mod->state & (MOD_INFO_RLOCK | MOD_INFO_RLOCK_UPGR | MOD_INFO_WLOCK);
            if (cur_bit >= lock_bit) {
                /* already locked */
                continue;
            }
            assert(!cur_bit);
        }

        /* MOD LOCK */
        if ((err_info = sr_shmmod_lock(mod->ly_mod, ds, shm_lock, timeout_ms, mode, ds_timeout_ms,
                mod_info->conn->cid, sid, mod->ds_handle[ds], 0))) {
            return err_info;
        }

        /* set the flag for unlocking */
        mod->state |= lock_bit;
    }

    return NULL;
}

sr_error_info_t *
sr_shmmod_modinfo_rdlock(struct sr_mod_info_s *mod_info, int upgradeable, uint32_t sid, uint32_t timeout_ms,
        uint32_t ds_timeout_ms)
{
    sr_error_info_t *err_info = NULL;

    if (upgradeable) {
        /* read-upgr-lock main DS */
        if ((err_info = sr_shmmod_modinfo_lock(mod_info, mod_info->ds, SR_LOCK_READ_UPGR, MOD_INFO_RLOCK_UPGR, sid,
                timeout_ms, ds_timeout_ms))) {
            return err_info;
        }
    } else {
        /* read-lock main DS */
        if ((err_info = sr_shmmod_modinfo_lock(mod_info, mod_info->ds, SR_LOCK_READ, MOD_INFO_RLOCK, sid, timeout_ms, 0))) {
            return err_info;
        }
    }

    if (mod_info->ds2 != mod_info->ds) {
        /* read-lock the secondary DS */
        if ((err_info = sr_shmmod_modinfo_lock(mod_info, mod_info->ds2, SR_LOCK_READ, MOD_INFO_RLOCK2, sid,
                timeout_ms, 0))) {
            return err_info;
        }
    }

    return NULL;
}

sr_error_info_t *
sr_shmmod_modinfo_wrlock(struct sr_mod_info_s *mod_info, uint32_t sid, uint32_t timeout_ms, uint32_t ds_timeout_ms)
{
    sr_error_info_t *err_info = NULL;

    /* urge write-lock main DS (to prevent starvation) */
    if ((err_info = sr_shmmod_modinfo_lock(mod_info, mod_info->ds, SR_LOCK_WRITE_URGE, MOD_INFO_WLOCK, sid, timeout_ms,
            ds_timeout_ms))) {
        return err_info;
    }

    if (mod_info->ds2 != mod_info->ds) {
        /* read-lock the secondary DS */
        if ((err_info = sr_shmmod_modinfo_lock(mod_info, mod_info->ds2, SR_LOCK_READ, MOD_INFO_RLOCK2, sid,
                timeout_ms, 0))) {
            return err_info;
        }
    }

    return NULL;
}

sr_error_info_t *
sr_shmmod_modinfo_rdlock_upgrade(struct sr_mod_info_s *mod_info, uint32_t sid, uint32_t timeout_ms, uint32_t ds_timeout_ms)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    struct sr_mod_info_mod_s *mod;
    struct sr_mod_lock_s *shm_lock;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        shm_lock = &mod->shm_mod->data_lock_info[mod_info->ds];

        /* upgrade only required read-upgr-locked modules and leave others read-upgr-locked to prevent their locking
         * causing potential dead-lock with other apply_changes using the same modules */
        if ((mod->state & (MOD_INFO_RLOCK_UPGR | MOD_INFO_REQ)) == (MOD_INFO_RLOCK_UPGR | MOD_INFO_REQ)) {
            /* MOD WRITE UPGRADE */
            if ((err_info = sr_shmmod_lock(mod->ly_mod, mod_info->ds, shm_lock, timeout_ms, SR_LOCK_WRITE_URGE,
                    ds_timeout_ms, mod_info->conn->cid, sid, mod->ds_handle[mod_info->ds], 1))) {
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
sr_shmmod_modinfo_wrlock_downgrade(struct sr_mod_info_s *mod_info, uint32_t sid, uint32_t timeout_ms)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    struct sr_mod_info_mod_s *mod;
    struct sr_mod_lock_s *shm_lock;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        shm_lock = &mod->shm_mod->data_lock_info[mod_info->ds];

        /* downgrade write-locked and read-upgr modules */
        if (mod->state & (MOD_INFO_WLOCK | MOD_INFO_RLOCK_UPGR)) {
            /* MOD READ DOWNGRADE */
            if ((err_info = sr_shmmod_lock(mod->ly_mod, mod_info->ds, shm_lock, timeout_ms, SR_LOCK_READ,
                    0, mod_info->conn->cid, sid, mod->ds_handle[mod_info->ds], 1))) {
                return err_info;
            }

            /* update the flag for unlocking */
            mod->state &= ~(MOD_INFO_WLOCK | MOD_INFO_RLOCK_UPGR);
            mod->state |= MOD_INFO_RLOCK;
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
    sr_mod_t *smod;
    const struct lys_module *ly_mod;
    struct sr_mod_lock_s *shm_lock;
    const struct sr_ds_handle_s *ds_handle;
    sr_datastore_t ds;
    int ds_locked;
    uint32_t i;

    for (i = 0; i < SR_CONN_MOD_SHM(conn)->mod_count; ++i) {
        smod = SR_SHM_MOD_IDX(conn->mod_shm.addr, i);
        ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, conn->mod_shm.addr + smod->name);
        assert(ly_mod);
        for (ds = 0; ds < SR_DS_COUNT; ++ds) {
            shm_lock = &smod->data_lock_info[ds];

            /* DS LOCK */
            if ((err_info = sr_mlock(&shm_lock->ds_lock, SR_DS_LOCK_MUTEX_TIMEOUT, __func__, NULL, NULL))) {
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
                if ((err_info = sr_ds_handle_find(conn->mod_shm.addr + smod->plugins[ds], conn, &ds_handle))) {
                    sr_errinfo_free(&err_info);
                    continue;
                }

                /* MOD WRITE LOCK */
                if ((err_info = sr_shmmod_lock(ly_mod, ds, shm_lock, SR_MOD_LOCK_TIMEOUT, SR_LOCK_WRITE, 0, conn->cid,
                        sid, ds_handle, 0))) {
                    sr_errinfo_free(&err_info);
                } else {
                    /* reset candidate */
                    if ((err_info = ds_handle->plugin->candidate_reset_cb(ly_mod, ds_handle->plg_data))) {
                        sr_errinfo_free(&err_info);
                    }

                    /* MOD WRITE UNLOCK */
                    sr_rwunlock(&shm_lock->data_lock, SR_MOD_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__);
                }
            }
        }
    }
}

sr_error_info_t *
sr_shmmod_update_replay_support(sr_mod_shm_t *mod_shm, const struct ly_set *mod_set, int enable)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    sr_mod_t *smod;
    uint32_t i;

    for (i = 0; i < mod_set->count; ++i) {
        ly_mod = mod_set->objs[i];

        /* find SHM module */
        smod = sr_shmmod_find_module(mod_shm, ly_mod->name);
        SR_CHECK_INT_RET(!smod, err_info);

        /* update flag */
        smod->replay_supp = enable;
    }

    return NULL;
}

/**
 * @brief Copy data of a module.
 *
 * @param[in] ly_mod Module.
 * @param[in] sds_handle Source data plugin handle.
 * @param[in] sds Source datastore.
 * @param[in] tds_handle Target data plugin handle.
 * @param[in] tds Target datastore.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmod_copy_mod(const struct lys_module *ly_mod, const struct sr_ds_handle_s *sds_handle, sr_datastore_t sds,
        const struct sr_ds_handle_s *tds_handle, sr_datastore_t tds)
{
    sr_error_info_t *err_info = NULL;
    LY_ERR lyrc;
    struct lyd_node *s_mod_data = NULL, *r_mod_data = NULL, *mod_diff = NULL;

    if (sds_handle == tds_handle) {
        /* same plugin, we can use the copy callback */
        err_info = sds_handle->plugin->copy_cb(ly_mod, tds, sds, sds_handle->plg_data);
        goto cleanup;
    }

    /* load source data */
    assert(sds != SR_DS_CANDIDATE);
    if ((err_info = sds_handle->plugin->load_cb(ly_mod, sds, NULL, 0, sds_handle->plg_data, &s_mod_data))) {
        goto cleanup;
    }

    /* load also current target data */
    assert(tds != SR_DS_CANDIDATE);
    if ((err_info = tds_handle->plugin->load_cb(ly_mod, tds, NULL, 0, tds_handle->plg_data, &r_mod_data))) {
        goto cleanup;
    }

    /* get data diff */
    lyrc = lyd_diff_siblings(r_mod_data, s_mod_data, LYD_DIFF_DEFAULTS, &mod_diff);
    if (lyrc) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(r_mod_data), NULL);
        goto cleanup;
    } else if (!mod_diff) {
        /* no data changes */
        goto cleanup;
    }

    /* write data to target */
    if ((err_info = tds_handle->plugin->store_cb(ly_mod, tds, mod_diff, s_mod_data, tds_handle->plg_data))) {
        goto cleanup;
    }

cleanup:
    lyd_free_siblings(s_mod_data);
    lyd_free_siblings(r_mod_data);
    lyd_free_siblings(mod_diff);
    return err_info;
}

/**
 * @brief qsort(3) compar callback implementation.
 */
static int
sr_shmmod_prio_cmp(const void *i1, const void *i2)
{
    const sr_mod_t *smod1 = *(sr_mod_t **)i1, *smod2 = *(sr_mod_t **)i2;

    if (smod1->data_lock_info[SR_DS_RUNNING].prio > smod2->data_lock_info[SR_DS_RUNNING].prio) {
        return 1;
    } else if (smod1->data_lock_info[SR_DS_RUNNING].prio < smod2->data_lock_info[SR_DS_RUNNING].prio) {
        return -1;
    }
    return 0;
}

sr_error_info_t *
sr_shmmod_reboot_init(sr_conn_ctx_t *conn, int initialized)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_shm_t *mod_shm;
    sr_mod_t **smods = NULL;
    const struct lys_module *ly_mod;
    const struct sr_ds_handle_s *ds_handle[SR_DS_READ_COUNT];
    sr_datastore_t ds;
    uint32_t i;

    mod_shm = SR_CONN_MOD_SHM(conn);
    smods = malloc(mod_shm->mod_count * sizeof *smods);
    SR_CHECK_MEM_GOTO(!smods, err_info, cleanup);

    /* prepare SHM mod array */
    for (i = 0; i < mod_shm->mod_count; ++i) {
        smods[i] = SR_SHM_MOD_IDX(mod_shm, i);
    }

    /* sort it based on the change priority */
    qsort(smods, mod_shm->mod_count, sizeof *smods, sr_shmmod_prio_cmp);

    for (i = 0; i < mod_shm->mod_count; ++i) {
        /* find LY module */
        ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, ((char *)mod_shm) + smods[i]->name);
        assert(ly_mod);

        /* find DS plugins and init them */
        for (ds = 0; ds < SR_DS_READ_COUNT; ++ds) {
            if ((ds == SR_DS_RUNNING) && !smods[i]->plugins[ds]) {
                /* disabled */
                continue;
            }

            if ((err_info = sr_ds_handle_find(((char *)mod_shm) + smods[i]->plugins[ds], conn, &ds_handle[ds]))) {
                goto cleanup;
            }
            if (!initialized && (err_info = ds_handle[ds]->plugin->init_cb(ly_mod, ds, ds_handle[ds]->plg_data))) {
                goto cleanup;
            }
        }

        if (!sr_module_has_data(ly_mod, 0) || !ds_handle[SR_DS_RUNNING]) {
            /* skip copying for modules without configuration data or with 'running' disabled */
            continue;
        }

        /* copy startup to running */
        if ((err_info = sr_shmmod_copy_mod(ly_mod, ds_handle[SR_DS_STARTUP], SR_DS_STARTUP, ds_handle[SR_DS_RUNNING],
                SR_DS_RUNNING))) {
            goto cleanup;
        }
    }

    SR_LOG_INF("Datastore copied from <startup> to <running>.");

cleanup:
    free(smods);
    return err_info;
}

sr_error_info_t *
sr_shmmod_change_prio(sr_conn_ctx_t *conn, const struct lys_module *ly_mod, sr_datastore_t ds, uint32_t prio,
        uint32_t *prio_p)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    const struct sr_ds_handle_s *ds_handle;
    struct sr_mod_lock_s *shm_lock;

    assert((!prio && prio_p) || !prio_p);

    /* find the module in SHM */
    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(conn), ly_mod->name);
    SR_CHECK_INT_RET(!shm_mod, err_info);

    /* get DS plugin handle */
    if ((err_info = sr_ds_handle_find(conn->mod_shm.addr + shm_mod->plugins[ds], conn, &ds_handle))) {
        return err_info;
    }

    /* use read lock for getting, write lock for setting */
    shm_lock = &shm_mod->data_lock_info[ds];

    /* SHM MOD LOCK */
    if ((err_info = sr_shmmod_lock(ly_mod, ds, shm_lock, SR_CHANGE_CB_TIMEOUT, prio_p ? SR_LOCK_READ : SR_LOCK_WRITE,
            SR_CHANGE_CB_TIMEOUT, conn->cid, 0, ds_handle, 0))) {
        return err_info;
    }

    if (prio_p) {
        /* get the priority */
        *prio_p = shm_lock->prio;
    } else {
        /* set the priority */
        shm_lock->prio = prio;
    }

    /* SHM MOD UNLOCK */
    sr_rwunlock(&shm_lock->data_lock, SR_MOD_LOCK_TIMEOUT, prio_p ? SR_LOCK_READ : SR_LOCK_WRITE, conn->cid, __func__);

    return NULL;
}
