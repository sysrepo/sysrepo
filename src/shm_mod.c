/**
 * @file shm_mod.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief main SHM routines modifying module information
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

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include <libyang/libyang.h>

sr_error_info_t *
sr_shmmod_lock(sr_mod_t *shm_mod, sr_datastore_t ds, int wr)
{
    struct timespec abs_ts;
    sr_error_info_t *err_info = NULL;
    int ret;

    if (clock_gettime(CLOCK_REALTIME, &abs_ts) == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "clock_gettime");
        return err_info;
    }

    abs_ts.tv_sec += SR_MODULE_LOCK_TIMEOUT;

    if (wr) {
        ret = pthread_rwlock_timedwrlock(&shm_mod->lock[ds], &abs_ts);
    } else {
        ret = pthread_rwlock_timedrdlock(&shm_mod->lock[ds], &abs_ts);
    }
    if (ret) {
        SR_ERRINFO_RWLOCK(&err_info, wr, __func__, ret);
        return err_info;
    }

    return NULL;
}

void
sr_shmmod_unlock(sr_mod_t *shm_mod, sr_datastore_t ds)
{
    int ret;

    ret = pthread_rwlock_unlock(&shm_mod->lock[ds]);
    if (ret) {
        SR_LOG_WRN("Unlocking a rwlock failed (%s).", strerror(ret));
    }
}

static sr_error_info_t *
sr_modinfo_add_mod(sr_mod_t *shm_mod, const struct lys_module *ly_mod, int mod_type, int mod_req_deps,
        struct sr_mod_info_s *mod_info)
{
    sr_mod_t *dep_mod;
    sr_mod_data_dep_t *shm_deps;
    uint16_t i, cur_i;
    int prev_mod_type = 0;
    sr_error_info_t *err_info = NULL;

    assert((mod_type == MOD_INFO_REQ) || (mod_type == MOD_INFO_DEP) || (mod_type == MOD_INFO_INV_DEP));
    assert(!mod_req_deps || (mod_req_deps == MOD_INFO_DEP) || (mod_req_deps == (MOD_INFO_DEP | MOD_INFO_INV_DEP)));

    /* check that it is not already added */
    for (i = 0; i < mod_info->mod_count; ++i) {
        if (mod_info->mods[i].shm_mod == shm_mod) {
            /* already there */
            if ((mod_info->mods[i].state & MOD_INFO_TYPE_MASK) < mod_type) {
                /* update module type and remember the previous one, add whatever new dependencies are necessary */
                prev_mod_type = mod_info->mods[i].state;
                mod_info->mods[i].state = mod_type;
                break;
            }
            return NULL;
        }
    }
    cur_i = i;

    if (prev_mod_type < MOD_INFO_DEP) {
        /* add it */
        ++mod_info->mod_count;
        mod_info->mods = sr_realloc(mod_info->mods, mod_info->mod_count * sizeof *mod_info->mods);
        SR_CHECK_MEM_RET(!mod_info->mods, err_info);
        memset(&mod_info->mods[cur_i], 0, sizeof *mod_info->mods);

        /* fill basic attributes */
        mod_info->mods[cur_i].shm_mod = shm_mod;
        mod_info->mods[cur_i].state = mod_type;
        mod_info->mods[cur_i].ly_mod = ly_mod;
        mod_info->mods[cur_i].shm_sub_cache.fd = -1;
    }

    if (!(mod_req_deps & MOD_INFO_DEP) || (mod_info->mods[cur_i].state < MOD_INFO_INV_DEP)) {
        /* we do not need recursive dependencies of this module */
        return NULL;
    }

    if (prev_mod_type < MOD_INFO_INV_DEP) {
        /* add all its dependencies, recursively */
        shm_deps = (sr_mod_data_dep_t *)(mod_info->conn->main_shm.addr + shm_mod->data_deps);
        for (i = 0; i < shm_mod->data_dep_count; ++i) {
            if (shm_deps[i].type == SR_DEP_INSTID) {
                /* we will handle those once we have the final data tree */
                continue;
            }

            /* find the dependency */
            dep_mod = sr_shmmain_find_module(mod_info->conn->main_shm.addr, NULL, shm_deps[i].module);
            SR_CHECK_INT_RET(!dep_mod, err_info);

            /* find ly module */
            ly_mod = ly_ctx_get_module(ly_mod->ctx, mod_info->conn->main_shm.addr + dep_mod->name, NULL, 1);
            SR_CHECK_INT_RET(!ly_mod, err_info);

            /* add dependency */
            if ((err_info = sr_modinfo_add_mod(dep_mod, ly_mod, MOD_INFO_DEP, mod_req_deps, mod_info))) {
                return err_info;
            }
        }
    }

    if (!(mod_req_deps & MOD_INFO_INV_DEP) || (mod_info->mods[cur_i].state < MOD_INFO_REQ)) {
        /* we do not need inverse dependencies of this module, its data will not be changed */
        return NULL;
    }

    if (prev_mod_type < MOD_INFO_REQ) {
        /* add all inverse dependencies (modules dependening on this module) TODO create this list when creating SHM */
        dep_mod = NULL;
        while ((dep_mod = sr_shmmain_getnext(mod_info->conn->main_shm.addr, dep_mod))) {
            shm_deps = (sr_mod_data_dep_t *)(mod_info->conn->main_shm.addr + dep_mod->data_deps);
            for (i = 0; i < dep_mod->data_dep_count; ++i) {
                if (shm_deps[i].module == shm_mod->name) {
                    /* find ly module */
                    ly_mod = ly_ctx_get_module(ly_mod->ctx, mod_info->conn->main_shm.addr + dep_mod->name, NULL, 1);
                    SR_CHECK_INT_RET(!ly_mod, err_info);

                    /* add inverse dependency */
                    if ((err_info = sr_modinfo_add_mod(dep_mod, ly_mod, MOD_INFO_INV_DEP, mod_req_deps, mod_info))) {
                        return err_info;
                    }
                }
            }
        }
    }

    return NULL;
}

static int
sr_modinfo_qsort_cmp(const void *ptr1, const void *ptr2)
{
    struct sr_mod_info_mod_s *mod1, *mod2;

    mod1 = (struct sr_mod_info_mod_s *)ptr1;
    mod2 = (struct sr_mod_info_mod_s *)ptr2;

    if (mod1->shm_mod > mod2->shm_mod) {
        return 1;
    }
    if (mod1->shm_mod < mod2->shm_mod) {
        return -1;
    }
    return 0;
}

sr_error_info_t *
sr_shmmod_collect_edit(sr_conn_ctx_t *conn, const struct lyd_node *edit, sr_datastore_t ds, struct sr_mod_info_s *mod_info)
{
    sr_mod_t *shm_mod;
    const struct lys_module *mod;
    const struct lyd_node *root;
    sr_error_info_t *err_info = NULL;

    mod_info->ds = ds;
    mod_info->conn = conn;

    /* add all the modules from the edit into our array */
    mod = NULL;
    LY_TREE_FOR(edit, root) {
        if (lyd_node_module(root) == mod) {
            continue;
        }

        /* remember last mod, good chance it will also be the module of some next data nodes */
        mod = lyd_node_module(root);

        /* find the module in SHM and add it with any dependencies */
        shm_mod = sr_shmmain_find_module(conn->main_shm.addr, mod->name, 0);
        SR_CHECK_INT_RET(!shm_mod, err_info);
        if ((err_info = sr_modinfo_add_mod(shm_mod, mod, MOD_INFO_REQ, MOD_INFO_DEP | MOD_INFO_INV_DEP, mod_info))) {
            return err_info;
        }
    }

    /* sort the modules based on their offsets in the SHM so that we have a uniform order for locking */
    qsort(mod_info->mods, mod_info->mod_count, sizeof *mod_info->mods, sr_modinfo_qsort_cmp);

    return NULL;
}

sr_error_info_t *
sr_shmmod_collect_xpath(sr_conn_ctx_t *conn, const char *xpath, sr_datastore_t ds, struct sr_mod_info_s *mod_info)
{
    sr_mod_t *shm_mod;
    char *module_name;
    const struct lys_module *ly_mod;
    const struct lys_node *ctx_node;
    struct ly_set *set = NULL;
    sr_error_info_t *err_info = NULL;
    uint32_t i;

    mod_info->ds = ds;
    mod_info->conn = conn;

    /* get the module */
    module_name = sr_get_first_ns(xpath);
    if (!module_name) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "XPath missing module name of the first node (%s).", xpath);
        return err_info;
    }

    ly_mod = ly_ctx_get_module(conn->ly_ctx, module_name, NULL, 1);
    if (!ly_mod) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Module \"%s\" not found in sysrepo.", module_name);
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
        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

    /* find the context node module in SHM and add it with any dependencies */
    assert(set->set.s[0] == ctx_node);
    shm_mod = sr_shmmain_find_module(mod_info->conn->main_shm.addr, ly_mod->name, 0);
    SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup);
    if ((err_info = sr_modinfo_add_mod(shm_mod, ly_mod, MOD_INFO_REQ, MOD_INFO_DEP | MOD_INFO_INV_DEP, mod_info))) {
        goto cleanup;
    }

    /* add all the other modules */
    for (i = 1; i < set->number; ++i) {
        if (lys_node_module(set->set.s[i]) == ly_mod) {
            continue;
        }

        /* remember last mod, good chance it will also be the module of some next schema nodes */
        ly_mod = lys_node_module(set->set.s[i]);

        /* find the module in SHM and add it with any dependencies */
        shm_mod = sr_shmmain_find_module(mod_info->conn->main_shm.addr, ly_mod->name, 0);
        SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup);
        if ((err_info = sr_modinfo_add_mod(shm_mod, ly_mod, MOD_INFO_REQ, MOD_INFO_DEP | MOD_INFO_INV_DEP, mod_info))) {
            goto cleanup;
        }
    }

    /* sort the modules based on their offsets in the SHM so that we have a uniform order for locking */
    qsort(mod_info->mods, mod_info->mod_count, sizeof *mod_info->mods, sr_modinfo_qsort_cmp);

    /* success */

cleanup:
    ly_set_free(set);
    return err_info;
}

sr_error_info_t *
sr_shmmod_collect_modules(sr_conn_ctx_t *conn, const struct lys_module *ly_mod, sr_datastore_t ds, int mod_req_deps,
        struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;

    mod_info->ds = ds;
    mod_info->conn = conn;

    if (ly_mod) {
        /* only one module */
        shm_mod = sr_shmmain_find_module(conn->main_shm.addr, ly_mod->name, 0);
        SR_CHECK_INT_RET(!shm_mod, err_info);

        if ((err_info = sr_modinfo_add_mod(shm_mod, ly_mod, MOD_INFO_REQ, mod_req_deps, mod_info))) {
            return err_info;
        }

        return NULL;
    }

    /* all modules */
    shm_mod = NULL;
    while ((shm_mod = sr_shmmain_getnext(conn->main_shm.addr, shm_mod))) {
        ly_mod = ly_ctx_get_module(conn->ly_ctx, conn->main_shm.addr + shm_mod->name, NULL, 1);
        SR_CHECK_INT_RET(!ly_mod, err_info);

        /* do not collect dependencies, all the modules are added anyway */
        if ((err_info = sr_modinfo_add_mod(shm_mod, ly_mod, MOD_INFO_REQ, 0, mod_info))) {
            return err_info;
        }
    }

    /* we do not need to sort the modules, they were added in the correct order */

    return NULL;
}

sr_error_info_t *
sr_shmmod_collect_op(sr_conn_ctx_t *conn, const char *xpath, const struct lyd_node *op, int output,
        sr_mod_data_dep_t **shm_deps, uint16_t *shm_dep_count, struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod, *dep_mod;
    sr_mod_op_dep_t *shm_op_deps;
    const struct lys_module *ly_mod;
    uint16_t i;

    mod_info->ds = SR_DS_OPERATIONAL;
    mod_info->conn = conn;

    /* find the module in SHM */
    shm_mod = sr_shmmain_find_module(conn->main_shm.addr, lyd_node_module(op)->name, 0);
    SR_CHECK_INT_RET(!shm_mod, err_info);

    /* if this is a nested action/notification, we will also need this module's data */
    if (!output && lys_parent(op->schema)) {
        if ((err_info = sr_modinfo_add_mod(shm_mod, lyd_node_module(op), MOD_INFO_REQ, 0, mod_info))) {
            return err_info;
        }
    }

    /* find this operation dependencies */
    shm_op_deps = (sr_mod_op_dep_t *)(conn->main_shm.addr + shm_mod->op_deps);
    for (i = 0; i < shm_mod->op_dep_count; ++i) {
        if (!strcmp(xpath, conn->main_shm.addr + shm_op_deps[i].xpath)) {
            break;
        }
    }
    SR_CHECK_INT_RET(i == shm_mod->op_dep_count, err_info);

    /* collect dependencies */
    *shm_deps = (sr_mod_data_dep_t *)(conn->main_shm.addr + (output ? shm_op_deps[i].out_deps : shm_op_deps[i].in_deps));
    *shm_dep_count = (output ? shm_op_deps[i].out_dep_count : shm_op_deps[i].in_dep_count);
    for (i = 0; i < *shm_dep_count; ++i) {
        if ((*shm_deps)[i].type == SR_DEP_INSTID) {
            /* we will handle those just before validation */
            continue;
        }

        /* find the dependency */
        dep_mod = sr_shmmain_find_module(mod_info->conn->main_shm.addr, NULL, (*shm_deps)[i].module);
        SR_CHECK_INT_RET(!dep_mod, err_info);

        /* find ly module */
        ly_mod = ly_ctx_get_module(conn->ly_ctx, mod_info->conn->main_shm.addr + dep_mod->name, NULL, 1);
        SR_CHECK_INT_RET(!ly_mod, err_info);

        /* add dependency */
        if ((err_info = sr_modinfo_add_mod(dep_mod, ly_mod, MOD_INFO_DEP, MOD_INFO_DEP, mod_info))) {
            return err_info;
        }
    }

    /* sort the modules based on their offsets in the SHM so that we have a uniform order for locking */
    qsort(mod_info->mods, mod_info->mod_count, sizeof *mod_info->mods, sr_modinfo_qsort_cmp);

    return NULL;
}

sr_error_info_t *
sr_shmmod_multilock(struct sr_mod_info_s *mod_info, int wr, int upgradable)
{
    int mod_wr;
    uint32_t i, steps;
    sr_error_info_t *err_info = NULL;

    assert(!wr || !upgradable);

    for (i = 0; i < mod_info->mod_count; ++i) {
        /* write-lock data-required modules (if write lock even required), read-lock dependency modules */
        mod_wr = (wr || upgradable) && (mod_info->mods[i].state & MOD_INFO_REQ) ? 1 : 0;
        steps = SR_SUB_EVENT_STEP_COUNT;
        while (steps) {
            if ((err_info = sr_shmmod_lock(mod_info->mods[i].shm_mod, mod_info->ds, mod_wr))) {
                return err_info;
            }

            if (!upgradable || !mod_info->mods[i].shm_mod->conf_sub[mod_info->ds].upgradable) {
                break;
            }

            sr_shmmod_unlock(mod_info->mods[i].shm_mod, mod_info->ds);

            /* sleep */
            sr_msleep(SR_SUB_EVENT_STEP_TIMEOUT);
            --steps;
        }
        if (!steps) {
            sr_errinfo_new(&err_info, SR_ERR_TIME_OUT, NULL, "Locking module \"%s\" in %s DS for applying changes timed out.",
                    mod_info->mods[i].ly_mod->name, sr_ds2str(mod_info->ds));
            return err_info;
        }

        if (upgradable && mod_wr) {
            /* set upgradable and downgrade lock to the required read lock for now */
            mod_info->mods[i].shm_mod->conf_sub[mod_info->ds].upgradable = 1;

            sr_shmmod_unlock(mod_info->mods[i].shm_mod, mod_info->ds);
            if ((err_info = sr_shmmod_lock(mod_info->mods[i].shm_mod, mod_info->ds, 0))) {
                return err_info;
            }
        }

        mod_info->mods[i].state |= MOD_INFO_LOCK;
    }

    return NULL;
}

sr_error_info_t *
sr_shmmod_multirelock(struct sr_mod_info_s *mod_info, int upgrade)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;

    for (i = 0; i < mod_info->mod_count; ++i) {
        if ((mod_info->mods[i].state & (MOD_INFO_REQ | MOD_INFO_LOCK)) == (MOD_INFO_REQ | MOD_INFO_LOCK)) {
            /* when relocking, the flag must always be set so that a success is guaranteed */
            SR_CHECK_INT_RET(!mod_info->mods[i].shm_mod->conf_sub[mod_info->ds].upgradable, err_info);

            /* properly unlock the module for possible error recovery */
            sr_shmmod_unlock(mod_info->mods[i].shm_mod, mod_info->ds);
            mod_info->mods[i].state &= ~MOD_INFO_LOCK;

            if ((err_info = sr_shmmod_lock(mod_info->mods[i].shm_mod, mod_info->ds, upgrade))) {
                return err_info;
            }
            mod_info->mods[i].state |= MOD_INFO_LOCK;
        }
    }

    return NULL;
}

void
sr_shmmod_multiunlock(struct sr_mod_info_s *mod_info, int upgradable)
{
    uint32_t i;

    for (i = 0; i < mod_info->mod_count; ++i) {
        if (mod_info->mods[i].state & MOD_INFO_LOCK) {
            if ((mod_info->mods[i].state & MOD_INFO_REQ) && upgradable) {
                assert(mod_info->mods[i].shm_mod->conf_sub[mod_info->ds].upgradable);
                mod_info->mods[i].shm_mod->conf_sub[mod_info->ds].upgradable = 0;
            }
            sr_shmmod_unlock(mod_info->mods[i].shm_mod, mod_info->ds);
        }
    }
}

sr_error_info_t *
sr_shmmod_conf_subscription(sr_conn_ctx_t *conn, const char *mod_name, const char *xpath, sr_datastore_t ds,
        uint32_t priority, int sub_opts, int add)
{
    sr_mod_t *shm_mod;
    off_t shm_mod_off, xpath_off, conf_subs_off;
    sr_mod_conf_sub_t *shm_sub;
    uint32_t new_shm_size;
    uint16_t i;
    sr_error_info_t *err_info = NULL;

    assert((ds == SR_DS_RUNNING) || (ds == SR_DS_STARTUP));

    shm_mod = sr_shmmain_find_module(conn->main_shm.addr, mod_name, 0);
    SR_CHECK_INT_RET(!shm_mod, err_info);
    /* remember the relative offset to use after main SHM remap */
    shm_mod_off = ((char *)shm_mod) - conn->main_shm.addr;

    if (add) {
        /* moving all existing subscriptions (if any) and adding a new one */
        conf_subs_off = conn->main_shm.size;
        xpath_off = conf_subs_off + (shm_mod->conf_sub[ds].sub_count + 1) * sizeof *shm_sub;
        new_shm_size = xpath_off + (xpath ? strlen(xpath) + 1 : 0);

        /* remap main SHM */
        if ((err_info = sr_shm_remap(&conn->main_shm, new_shm_size))) {
            return err_info;
        }
        shm_mod = (sr_mod_t *)(conn->main_shm.addr + shm_mod_off);

        /* move subscriptions */
        memcpy(conn->main_shm.addr + conf_subs_off, conn->main_shm.addr + shm_mod->conf_sub[ds].subs,
                shm_mod->conf_sub[ds].sub_count * sizeof *shm_sub);
        shm_mod->conf_sub[ds].subs = conf_subs_off;

        /* fill new subscription */
        shm_sub = (sr_mod_conf_sub_t *)(conn->main_shm.addr + shm_mod->conf_sub[ds].subs);
        shm_sub += shm_mod->conf_sub[ds].sub_count;
        ++shm_mod->conf_sub[ds].sub_count;

        if (xpath) {
            strcpy(conn->main_shm.addr + xpath_off, xpath);
            shm_sub->xpath = xpath_off;
        } else {
            shm_sub->xpath = 0;
        }
        shm_sub->priority = priority;
        shm_sub->opts = sub_opts;
    } else {
        /* find the subscription */
        shm_sub = (sr_mod_conf_sub_t *)(conn->main_shm.addr + shm_mod->conf_sub[ds].subs);
        for (i = 0; i < shm_mod->conf_sub[ds].sub_count; ++i) {
            if ((!xpath && !shm_sub[i].xpath)
                    || (xpath && shm_sub[i].xpath && !strcmp(conn->main_shm.addr + shm_sub[i].xpath, xpath))) {
                if ((shm_sub[i].priority == priority) && (shm_sub[i].opts == sub_opts)) {
                    break;
                }
            }
        }
        SR_CHECK_INT_RET(i == shm_mod->conf_sub[ds].sub_count, err_info);

        --shm_mod->conf_sub[ds].sub_count;
        if (!shm_mod->conf_sub[ds].sub_count) {
            /* the only subscription removed */
            shm_mod->conf_sub[ds].subs = 0;
        } else if (i < shm_mod->conf_sub[ds].sub_count) {
            /* replace the deleted subscription with the last one */
            memcpy(&shm_sub[i], &shm_sub[shm_mod->conf_sub[ds].sub_count], sizeof *shm_sub);
        }
    }

    return NULL;
}

sr_error_info_t *
sr_shmmod_dp_subscription(sr_conn_ctx_t *conn, const char *mod_name, const char *xpath, sr_mod_dp_sub_type_t sub_type, int add)
{
    sr_mod_t *shm_mod;
    off_t shm_mod_off, xpath_off, dp_subs_off;
    sr_mod_dp_sub_t *shm_sub;
    size_t new_shm_size, new_len, cur_len;
    uint16_t i;
    sr_error_info_t *err_info = NULL;

    assert(mod_name && xpath && (!add || sub_type));

    shm_mod = sr_shmmain_find_module(conn->main_shm.addr, mod_name, 0);
    SR_CHECK_INT_RET(!shm_mod, err_info);
    /* remember the relative offset to use after main SHM remap */
    shm_mod_off = ((char *)shm_mod) - conn->main_shm.addr;

    if (add) {
        /* check that this exact subscription does not exist yet while finding its position */
        new_len = sr_xpath_len_no_predicates(xpath);
        shm_sub = (sr_mod_dp_sub_t *)(conn->main_shm.addr + shm_mod->dp_subs);
        for (i = 0; i < shm_mod->dp_sub_count; ++i) {
            cur_len = sr_xpath_len_no_predicates(conn->main_shm.addr + shm_sub[i].xpath);
            if (cur_len > new_len) {
                /* we can insert it at i-th position */
                break;
            }

            if ((cur_len == new_len) && !strcmp(conn->main_shm.addr + shm_sub[i].xpath, xpath)) {
                sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL,
                        "Data provider subscription for \"%s\" on \"%s\" already exists.", mod_name, xpath);
                return err_info;
            }
        }

        /* get new offsets and SHM size */
        dp_subs_off = conn->main_shm.size;
        xpath_off = dp_subs_off + (shm_mod->dp_sub_count + 1) * sizeof *shm_sub;
        new_shm_size = xpath_off + (xpath ? strlen(xpath) + 1 : 0);

        /* remap main SHM */
        if ((err_info = sr_shm_remap(&conn->main_shm, new_shm_size))) {
            return err_info;
        }
        shm_mod = (sr_mod_t *)(conn->main_shm.addr + shm_mod_off);

        /* move preceding and succeeding subscriptions leaving place for the new one */
        if (i) {
            memcpy(conn->main_shm.addr + dp_subs_off, conn->main_shm.addr + shm_mod->dp_subs,
                    i * sizeof *shm_sub);
        }
        if (i < shm_mod->dp_sub_count) {
            memcpy(conn->main_shm.addr + dp_subs_off + (i + 1) * sizeof *shm_sub,
                    conn->main_shm.addr + shm_mod->dp_subs + i * sizeof *shm_sub, (shm_mod->dp_sub_count - i) * sizeof *shm_sub);
        }
        shm_mod->dp_subs = dp_subs_off;

        /* fill new subscription */
        shm_sub = (sr_mod_dp_sub_t *)(conn->main_shm.addr + shm_mod->dp_subs);
        shm_sub += i;
        if (xpath) {
            strcpy(conn->main_shm.addr + xpath_off, xpath);
            shm_sub->xpath = xpath_off;
        } else {
            shm_sub->xpath = 0;
        }
        shm_sub->sub_type = sub_type;

        ++shm_mod->dp_sub_count;
    } else {
        /* find the subscription */
        shm_sub = (sr_mod_dp_sub_t *)(conn->main_shm.addr + shm_mod->dp_subs);
        for (i = 0; i < shm_mod->dp_sub_count; ++i) {
            if (shm_sub[i].xpath && !strcmp(conn->main_shm.addr + shm_sub[i].xpath, xpath)) {
                break;
            }
        }
        SR_CHECK_INT_RET(i == shm_mod->dp_sub_count, err_info);

        --shm_mod->dp_sub_count;
        if (!shm_mod->dp_sub_count) {
            /* the only subscription removed */
            shm_mod->dp_subs = 0;
        } else {
            /* move all following subscriptions */
            if (i < shm_mod->dp_sub_count) {
                memmove(&shm_sub[i], &shm_sub[i + 1], (shm_mod->dp_sub_count - i) * sizeof *shm_sub);
            }
        }
    }

    return NULL;
}

sr_error_info_t *
sr_shmmod_rpc_subscription(sr_conn_ctx_t *conn, const char *mod_name, const char *xpath, int add)
{
    sr_mod_t *shm_mod;
    off_t shm_mod_off, xpath_off, rpc_subs_off;
    sr_mod_rpc_sub_t *shm_sub;
    size_t new_shm_size;
    uint16_t i;
    sr_error_info_t *err_info = NULL;

    assert(mod_name && xpath);

    shm_mod = sr_shmmain_find_module(conn->main_shm.addr, mod_name, 0);
    SR_CHECK_INT_RET(!shm_mod, err_info);
    /* remember the relative offset to use after main SHM remap */
    shm_mod_off = ((char *)shm_mod) - conn->main_shm.addr;

    if (add) {
        /* check that this exact subscription does not exist yet */
        shm_sub = (sr_mod_rpc_sub_t *)(conn->main_shm.addr + shm_mod->rpc_subs);
        for (i = 0; i < shm_mod->rpc_sub_count; ++i) {
            if (!strcmp(conn->main_shm.addr + shm_sub[i].xpath, xpath)) {
                sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL,
                        "RPC/action handler subscription for \"%s\" already exists.", xpath);
                return err_info;
            }
        }

        /* moving all existing subscriptions (if any) and adding a new one */
        rpc_subs_off = conn->main_shm.size;
        xpath_off = rpc_subs_off + (shm_mod->rpc_sub_count + 1) * sizeof *shm_sub;
        new_shm_size = xpath_off + strlen(xpath) + 1;

        /* remap main SHM */
        if ((err_info = sr_shm_remap(&conn->main_shm, new_shm_size))) {
            return err_info;
        }
        shm_mod = (sr_mod_t *)(conn->main_shm.addr + shm_mod_off);

        /* move subscriptions */
        memcpy(conn->main_shm.addr + rpc_subs_off, conn->main_shm.addr + shm_mod->rpc_subs,
                shm_mod->rpc_sub_count * sizeof *shm_sub);
        shm_mod->rpc_subs = rpc_subs_off;

        /* fill new subscription */
        shm_sub = (sr_mod_rpc_sub_t *)(conn->main_shm.addr + shm_mod->rpc_subs);
        shm_sub += i;
        strcpy(conn->main_shm.addr + xpath_off, xpath);
        shm_sub->xpath = xpath_off;

        ++shm_mod->rpc_sub_count;
    } else {
        /* find the subscription */
        shm_sub = (sr_mod_rpc_sub_t *)(conn->main_shm.addr + shm_mod->rpc_subs);
        for (i = 0; i < shm_mod->rpc_sub_count; ++i) {
            if (!strcmp(conn->main_shm.addr + shm_sub[i].xpath, xpath)) {
                break;
            }
        }
        SR_CHECK_INT_RET(i == shm_mod->rpc_sub_count, err_info);

        --shm_mod->rpc_sub_count;
        if (!shm_mod->rpc_sub_count) {
            /* the only subscription removed */
            shm_mod->rpc_subs = 0;
        } else if (i < shm_mod->rpc_sub_count) {
            /* replace the removed subscription with the last one */
            memcpy(&shm_sub[i], &shm_sub[shm_mod->rpc_sub_count], sizeof *shm_sub);
        }
    }

    return NULL;
}
