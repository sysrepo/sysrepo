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
sr_modinfo_add_mod_with_deps(sr_mod_t *shm_mod, const struct lys_module *ly_mod, int mod_type,
        struct sr_mod_info_s *mod_info)
{
    sr_mod_t *dep_mod;
    sr_mod_dep_t *shm_deps;
    uint16_t i, cur_i;
    int prev_mod_type = 0;
    sr_error_info_t *err_info = NULL;

    assert((mod_type == MOD_INFO_DEP) || (mod_type == MOD_INFO_INV_DEP) || (mod_type == MOD_INFO_REQ));

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

        mod_info->mods[cur_i].shm_sub_fd = -1;
        mod_info->mods[cur_i].shm_sub_size = 0;
        mod_info->mods[cur_i].shm_sub = NULL;
    }

    if (mod_info->mods[cur_i].state < MOD_INFO_INV_DEP) {
        /* we do not need recursive dependencies of this module */
        return NULL;
    }

    if (prev_mod_type < MOD_INFO_INV_DEP) {
        /* add all its dependencies, recursively */
        shm_deps = (sr_mod_dep_t *)(mod_info->conn->shm + shm_mod->deps);
        for (i = 0; i < shm_mod->dep_count; ++i) {
            if (shm_deps[i].type == SR_DEP_INSTID) {
                /* we will handle those once we have the final data tree */
                continue;
            }

            /* find the dependency */
            dep_mod = sr_shmmain_find_module(mod_info->conn->shm, NULL, shm_deps[i].module);
            SR_CHECK_INT_RET(!dep_mod, err_info);

            /* find ly module */
            ly_mod = ly_ctx_get_module(ly_mod->ctx, mod_info->conn->shm + dep_mod->name, NULL, 1);
            SR_CHECK_INT_RET(!ly_mod, err_info);

            /* add dependency */
            if ((err_info = sr_modinfo_add_mod_with_deps(dep_mod, ly_mod, MOD_INFO_DEP, mod_info))) {
                return err_info;
            }
        }
    }

    if (mod_info->mods[cur_i].state < MOD_INFO_REQ) {
        /* we do not need inverse dependencies of this module, its data will not be changed */
        return NULL;
    }

    if (prev_mod_type < MOD_INFO_REQ) {
        /* add all inverse dependencies (modules dependening on this module) TODO create this list when creating SHM */
        dep_mod = NULL;
        while ((dep_mod = sr_shmmain_getnext(mod_info->conn->shm, dep_mod))) {
            shm_deps = (sr_mod_dep_t *)(mod_info->conn->shm + dep_mod->deps);
            for (i = 0; i < dep_mod->dep_count; ++i) {
                if (shm_deps[i].module == shm_mod->name) {
                    /* find ly module */
                    ly_mod = ly_ctx_get_module(ly_mod->ctx, mod_info->conn->shm + dep_mod->name, NULL, 1);
                    SR_CHECK_INT_RET(!ly_mod, err_info);

                    /* add inverse dependency */
                    if ((err_info = sr_modinfo_add_mod_with_deps(dep_mod, ly_mod, MOD_INFO_INV_DEP, mod_info))) {
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
        shm_mod = sr_shmmain_find_module(conn->shm, mod->name, 0);
        SR_CHECK_INT_RET(!shm_mod, err_info);
        if ((err_info = sr_modinfo_add_mod_with_deps(shm_mod, mod, MOD_INFO_REQ, mod_info))) {
            return err_info;
        }
    }

    /* sort the modules based on their offsets in the SHM so that we have a uniform order for locking */
    qsort(mod_info->mods, mod_info->mod_count, sizeof *mod_info->mods, sr_modinfo_qsort_cmp);

    return NULL;
}

sr_error_info_t *
sr_shmmod_collect_xpath(sr_conn_ctx_t *conn, struct ly_ctx *ly_ctx, const char *xpath, sr_datastore_t ds,
        struct sr_mod_info_s *mod_info)
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

    ly_mod = ly_ctx_get_module(ly_ctx, module_name, NULL, 1);
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
        sr_errinfo_new_ly(&err_info, ly_ctx);
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

    /* find the context node module in SHM and add it with any dependencies */
    assert(set->set.s[0] == ctx_node);
    shm_mod = sr_shmmain_find_module(mod_info->conn->shm, ly_mod->name, 0);
    SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup);
    if ((err_info = sr_modinfo_add_mod_with_deps(shm_mod, ly_mod, MOD_INFO_REQ, mod_info))) {
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
        shm_mod = sr_shmmain_find_module(mod_info->conn->shm, ly_mod->name, 0);
        SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup);
        if ((err_info = sr_modinfo_add_mod_with_deps(shm_mod, ly_mod, MOD_INFO_REQ, mod_info))) {
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
sr_shmmod_multilock(struct sr_mod_info_s *mod_info, int wr, int applying_changes)
{
    int mod_wr;
    uint32_t i, steps;
    sr_error_info_t *err_info = NULL;

    assert(!wr || !applying_changes);

    for (i = 0; i < mod_info->mod_count; ++i) {
        /* write-lock data-required modules (if write lock even required), read-lock dependency modules */
        mod_wr = (wr || applying_changes) && (mod_info->mods[i].state & MOD_INFO_REQ) ? 1 : 0;
        steps = SR_SUB_COMMIT_STEP_COUNT;
        while (steps) {
            if ((err_info = sr_shmmod_lock(mod_info->mods[i].shm_mod, mod_info->ds, mod_wr))) {
                return err_info;
            }

            if (!applying_changes || !mod_info->mods[i].shm_mod->sub_info[mod_info->ds].applying_changes) {
                break;
            }

            sr_shmmod_unlock(mod_info->mods[i].shm_mod, mod_info->ds);

            /* sleep */
            sr_msleep(SR_SUB_COMMIT_STEP_TIMEOUT);
            --steps;
        }
        if (!steps) {
            sr_errinfo_new(&err_info, SR_ERR_TIME_OUT, NULL, "Locking module \"%s\" in %s DS for applying changes timed out.",
                    mod_info->mods[i].ly_mod->name, sr_ds2str(mod_info->ds));
            return err_info;
        }

        if (applying_changes && mod_wr) {
            /* set applying_changes and downgrade lock to the required read lock for now */
            mod_info->mods[i].shm_mod->sub_info[mod_info->ds].applying_changes = 1;

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
            SR_CHECK_INT_RET(!mod_info->mods[i].shm_mod->sub_info[mod_info->ds].applying_changes, err_info);

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
sr_shmmod_multiunlock(struct sr_mod_info_s *mod_info, int applying_changes)
{
    uint32_t i;

    for (i = 0; i < mod_info->mod_count; ++i) {
        if (mod_info->mods[i].state & MOD_INFO_LOCK) {
            if ((mod_info->mods[i].state & MOD_INFO_REQ) && applying_changes) {
                assert(mod_info->mods[i].shm_mod->sub_info[mod_info->ds].applying_changes);
                mod_info->mods[i].shm_mod->sub_info[mod_info->ds].applying_changes = 0;
            }
            sr_shmmod_unlock(mod_info->mods[i].shm_mod, mod_info->ds);
        }
    }
}

static sr_error_info_t *
sr_ly_module_data_get(struct ly_ctx *ly_ctx, const char *mod_name, sr_datastore_t ds, struct lyd_node **data)
{
    sr_error_info_t *err_info = NULL;
    char *path;

    if (asprintf(&path, "%s/data/%s.%s", sr_get_repo_path(), mod_name, sr_ds2str(ds)) == -1) {
        SR_ERRINFO_MEM(&err_info);
        return err_info;
    }

    ly_errno = LYVE_SUCCESS;
    *data = lyd_parse_path(ly_ctx, path, LYD_LYB, LYD_OPT_CONFIG | LYD_OPT_NOEXTDEPS);
    free(path);
    if (ly_errno) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        return err_info;
    }

    return NULL;
}

static sr_error_info_t *
sr_ly_module_data_set(sr_datastore_t ds, const char *mod_name, struct lyd_node *data)
{
    char *path;
    sr_error_info_t *err_info = NULL;

    if (asprintf(&path, "%s/data/%s.%s", sr_get_repo_path(), mod_name, sr_ds2str(ds)) == -1) {
        SR_ERRINFO_MEM(&err_info);
        return err_info;
    }

    if (lyd_print_path(path, data, LYD_LYB, LYP_WITHSIBLINGS)) {
        sr_errinfo_new_ly(&err_info, lyd_node_module(data)->ctx);
        sr_errinfo_new(&err_info, SR_ERR_INTERNAL, NULL, "Failed to store data file \"%s\".", path);
        free(path);
        return err_info;
    }
    free(path);

    return NULL;
}

sr_error_info_t *
sr_shmmod_get_filter(sr_session_ctx_t *session, const char *xpath, struct sr_mod_info_s *mod_info, struct ly_set **result)
{
    struct lyd_node *root = NULL, *mod_data = NULL;
    uint32_t i, j;
    sr_error_info_t *err_info = NULL;

    *result = NULL;

    /* merge data trees of all the referenced modules (without dependency modules) */
    for (i = 0; i < mod_info->mod_count; ++i) {
        if (mod_info->mods[i].state & MOD_INFO_REQ) {
            /* get currently stored module data */
            if ((err_info = sr_ly_module_data_get(mod_info->mods[i].ly_mod->ctx, mod_info->mods[i].ly_mod->name,
                        session->ds, &mod_data))) {
                goto cleanup;
            }

            /* apply any temporary/commit changes to get the new data tree */
            switch (session->ev) {
            case SR_EV_NONE:
                /* edit */
                err_info = sr_ly_edit_mod_apply(session->dt[session->ds].edit, &mod_info->mods[i], &mod_data, NULL);
                break;
            case SR_EV_UPDATE:
                /* both */
                err_info = sr_ly_diff_mod_apply(session->dt[session->ds].diff, &mod_info->mods[i], &mod_data);
                if (!err_info) {
                    err_info = sr_ly_edit_mod_apply(session->dt[session->ds].edit, &mod_info->mods[i], &mod_data, NULL);
                }
                break;
            case SR_EV_CHANGE:
                /* diff */
                err_info = sr_ly_diff_mod_apply(session->dt[session->ds].diff, &mod_info->mods[i], &mod_data);
                break;
            case SR_EV_DONE:
                /* we have diff stored in the session, but it was already applied to the datastore */
                break;
            case SR_EV_ABORT:
                /* the stored diff was actually not applied */
                break;
            }
            if (err_info) {
                goto cleanup;
            }

            /* attach to result */
            if (!root) {
                root = mod_data;
            } else {
                sr_ly_link(root, mod_data);
            }
            mod_data = NULL;
        }
    }

    /* filter return data */
    if (root) {
        *result = lyd_find_path(root, xpath);
    } else {
        *result = ly_set_new();
    }
    if (!*result) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }

    /* duplicate all returned subtrees (they should not have any intersection, if they do, we are wasting some memory) */
    for (i = 0; i < (*result)->number; ++i) {
        (*result)->set.d[i] = lyd_dup((*result)->set.d[i], LYD_DUP_OPT_RECURSIVE);
        if (!(*result)->set.d[i]) {
            for (j = 0; j < i; ++j) {
                lyd_free((*result)->set.d[j]);
            }
            sr_errinfo_new_ly(&err_info, session->conn->ly_ctx);
            goto cleanup;
        }
    }

    /* success */

cleanup:
    lyd_free_withsiblings(mod_data);
    lyd_free_withsiblings(root);
    if (err_info) {
        ly_set_free(*result);
        *result = NULL;
    }
    return err_info;
}

sr_error_info_t *
sr_shmmod_create_diff(const struct lyd_node *edit, struct sr_mod_info_s *mod_info)
{
    struct lyd_node *diff = NULL;
    struct sr_mod_info_mod_s *mod;
    uint32_t i;
    sr_error_info_t *err_info = NULL;

    for (i = 0; i < mod_info->mod_count; ++i) {
        if (mod_info->mods[i].state & MOD_INFO_REQ) {
            mod = &mod_info->mods[i];

            /* get this module's current data (there can be old data for UPDATE event, we must work with the current data) */
            if (mod->mod_data) {
                lyd_free_withsiblings(mod->mod_data);
            }
            if ((err_info = sr_ly_module_data_get(mod->ly_mod->ctx, mod->ly_mod->name, mod_info->ds, &mod->mod_data))) {
                goto error;
            }

            /* apply relevant edit changes */
            if ((err_info = sr_ly_edit_mod_apply(edit, mod, &mod->mod_data, &diff))) {
                goto error;
            }

            if (diff) {
                /* there is a diff for this module */
                mod->state |= MOD_INFO_CHANGED;

                /* merge all diffs into one */
                if (!mod_info->diff) {
                    mod_info->diff = diff;
                } else {
                    sr_ly_link(mod_info->diff, diff);
                }
                diff = NULL;

            }
        }
    }

    return NULL;

error:
    lyd_free_withsiblings(diff);
    return err_info;
}

static sr_error_info_t *
sr_modinfo_add_instid_deps(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, const struct lyd_node *mod_data, struct ly_set *dep_set)
{
    sr_mod_dep_t *shm_deps;
    sr_mod_t *dep_mod;
    struct ly_set *set = NULL;
    const char *val_str;
    char *mod_name;
    uint32_t i, j;
    sr_error_info_t *err_info = NULL;

    shm_deps = (sr_mod_dep_t *)(conn->shm + shm_mod->deps);
    for (i = 0; i < shm_mod->dep_count; ++i) {
        if (shm_deps[i].type == SR_DEP_INSTID) {
            if (mod_data) {
                set = lyd_find_path(mod_data, conn->shm + shm_deps[i].xpath);
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
                    dep_mod = sr_shmmain_find_module(conn->shm, mod_name, 0);
                    free(mod_name);
                    SR_CHECK_INT_GOTO(!dep_mod, err_info, cleanup);

                    /* add module name offset so that duplicities can be found easily */
                    if (ly_set_add(dep_set, (void *)dep_mod->name, 0) == -1) {
                        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
                        goto cleanup;
                    }
                }
            } else if (shm_deps[i].module) {
                /* assume a default value will be used even though it may not be */
                if (ly_set_add(dep_set, (void *)shm_deps[i].module, 0) == -1) {
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
sr_shmmod_validate(struct sr_mod_info_s *mod_info, int finish_diff)
{
    struct lyd_node *first_root = NULL, *first_dep = NULL, *mod_data = NULL, *iter;
    struct sr_mod_info_mod_s *mod;
    struct lyd_difflist *diff = NULL;
    struct ly_set *dep_set;
    const struct lys_module **valid_mods;
    uint32_t i, j, valid_mod_count = 0;
    const char *mod_name;
    int ret, flags;
    sr_error_info_t *err_info = NULL;

    dep_set = ly_set_new();
    SR_CHECK_MEM_RET(!dep_set, err_info);

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        switch (mod->state & MOD_INFO_TYPE_MASK) {
        case MOD_INFO_REQ:
            /* this module was changed, needs to be validated */
            ++valid_mod_count;

            /* check instids and add their target modules as deps */
            if ((err_info = sr_modinfo_add_instid_deps(mod_info->conn, mod->shm_mod, mod->mod_data, dep_set))) {
                goto cleanup;
            }

            if (!mod->mod_data) {
                /* nothing to connect */
                continue;
            }

            /* connect all modified data trees together */
            if (!first_root) {
                first_root = mod->mod_data;
            } else {
                sr_ly_link(first_root, mod->mod_data);
            }
            mod->mod_data = NULL;
            break;
        case MOD_INFO_INV_DEP:
            /* this module reference targets could have been changed, needs to be validated */
            ++valid_mod_count;
            /* fallthrough */
        case MOD_INFO_DEP:
            /* this module data are required because there are references to them, but they do not need to be revalidated */
            assert(!mod->mod_data);

            /* get these data and connect them */
            if ((err_info = sr_ly_module_data_get(mod_info->conn->ly_ctx, mod->ly_mod->name, mod_info->ds, &mod->mod_data))) {
                goto cleanup;
            }
            if (!first_root) {
                first_root = mod->mod_data;
            } else {
                sr_ly_link(first_root, mod->mod_data);
            }
            mod->mod_data = NULL;
            break;
        default:
            SR_CHECK_INT_GOTO(0, err_info, cleanup);
        }
    }

    /* get and connect new dep data */
    for (i = 0; i < dep_set->number; ++i) {
        for (j = 0; j < mod_info->mod_count; ++j) {
            if ((off_t)dep_set->set.g[i] == mod_info->mods[j].shm_mod->name) {
                break;
            }
        }
        if (j < mod_info->mod_count) {
            /* we already have this module data */
            continue;
        }

        /* get the data */
        mod_name = mod_info->conn->shm + (off_t)dep_set->set.g[i];
        if ((err_info = sr_ly_module_data_get(mod_info->conn->ly_ctx, mod_name, mod_info->ds, &mod_data))) {
            goto cleanup;
        }
        /* remember first dep mod data for freeing */
        if (!first_dep) {
            first_dep = mod_data;
        }
        /* connect to one data tree */
        if (!first_root) {
            first_root = mod_data;
        } else {
            sr_ly_link(first_root, mod_data);
        }
        mod_data = NULL;
    }

    /* create an array of all the modules that will be validated */
    valid_mods = malloc(valid_mod_count * sizeof *valid_mods);
    SR_CHECK_MEM_GOTO(!valid_mods, err_info, cleanup);
    for (i = 0, j = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        switch (mod->state & MOD_INFO_TYPE_MASK) {
        case MOD_INFO_REQ:
        case MOD_INFO_INV_DEP:
            valid_mods[j] = mod->ly_mod;
            ++j;
            break;
        case MOD_INFO_DEP:
            /* is not validated */
            break;
        }
    }
    assert(j == valid_mod_count);

    /* validate */
    if (finish_diff) {
        flags = LYD_OPT_CONFIG | LYD_OPT_WHENAUTODEL | LYD_OPT_VAL_DIFF;
        ret = lyd_validate_modules(&first_root, valid_mods, valid_mod_count, flags, &diff);
    } else {
        flags = LYD_OPT_CONFIG | LYD_OPT_WHENAUTODEL;
        ret = lyd_validate_modules(&first_root, valid_mods, valid_mod_count, flags);
    }
    if (ret) {
        sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx);
        SR_ERRINFO_VALID(&err_info);
        goto cleanup;
    }

    if (finish_diff) {
        /* merge the changes made by the validation into our diff */
        if ((err_info = sr_ly_diff_merge(&mod_info->diff, mod_info->conn->ly_ctx, diff, &mod_info->dflt_change))) {
            goto cleanup;
        }

        /* additional modules can be modified */
        for (i = 0; i < mod_info->mod_count; ++i) {
            mod = &mod_info->mods[i];
            if (mod->state & MOD_INFO_INV_DEP) {
                LY_TREE_FOR(mod_info->diff, iter) {
                    if (lyd_node_module(iter) == mod->ly_mod) {
                        mod->state |= MOD_INFO_CHANGED;
                        break;
                    }
                }
            }
        }
    }

    /* success */

cleanup:
    /* disconnect all the data trees */
    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];

        if (lyd_node_module(first_root) != mod->ly_mod) {
            /* this module has no data */
            continue;
        }

        /* these modules could have changed, separate them into modules again */
        for (iter = first_root->next; iter && (lyd_node_module(iter) == mod->ly_mod); iter = iter->next);
        mod->mod_data = first_root;
        if (iter) {
            sr_ly_split(iter);
        }
        first_root = iter;
    }

    /* disconnect and free dep data */
    assert(first_root == first_dep);
    sr_ly_split(first_dep);
    lyd_free_withsiblings(first_dep);

    /* other cleanup */
    lyd_free_val_diff(diff);
    lyd_free_withsiblings(mod_data);
    ly_set_free(dep_set);
    free(valid_mods);
    return err_info;
}

sr_error_info_t *
sr_shmmod_store(struct sr_mod_info_s *mod_info)
{
    struct sr_mod_info_mod_s *mod;
    uint32_t i;
    sr_error_info_t *err_info = NULL;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & MOD_INFO_CHANGED) {
            /* set the new data */
            if ((err_info = sr_ly_module_data_set(mod_info->ds, mod->ly_mod->name, mod->mod_data))) {
                return err_info;
            }
        }
    }

    return NULL;
}

sr_error_info_t *
sr_shmmod_subscription(sr_conn_ctx_t *conn, const char *mod_name, const char *xpath, sr_datastore_t ds,
        uint32_t priority, int subscr_opts, int add)
{
    sr_mod_t *shm_mod;
    off_t shm_mod_off, xpath_off;
    sr_mod_sub_t *shm_msub;
    uint32_t new_shm_size, old_shm_size = 0;
    uint16_t i;
    sr_error_info_t *err_info = NULL;

    assert((ds == SR_DS_RUNNING) || (ds == SR_DS_STARTUP));

    shm_mod = sr_shmmain_find_module(conn->shm, mod_name, 0);
    SR_CHECK_INT_RET(!shm_mod, err_info);
    /* remember the relative offset to use after main SHM remap */
    shm_mod_off = ((char *)shm_mod) - conn->shm;

    if (add) {
        if (shm_mod->sub_info[ds].subs + shm_mod->sub_info[ds].sub_count * sizeof *shm_msub == conn->shm_size) {
            /* adding just one subscription at the very SHM end, optionally with an xpath */
            xpath_off = conn->shm_size + sizeof *shm_msub;
            new_shm_size = xpath_off + (xpath ? strlen(xpath) + 1 : 0);
        } else {
            /* moving all existing subscriptions (if any) and adding a new one */
            xpath_off = conn->shm_size + (shm_mod->sub_info[ds].sub_count + 1) * sizeof *shm_msub;
            new_shm_size = xpath_off + (xpath ? strlen(xpath) + 1 : 0);
            old_shm_size = conn->shm_size;
        }

        /* remap main SHM */
        if ((err_info = sr_shmmain_remap(conn, new_shm_size))) {
            return err_info;
        }
        shm_mod = (sr_mod_t *)(conn->shm + shm_mod_off);

        /* move subscriptions */
        if (old_shm_size) {
            memcpy(conn->shm + old_shm_size, conn->shm + shm_mod->sub_info[ds].subs,
                    shm_mod->sub_info[ds].sub_count * sizeof *shm_msub);
            shm_mod->sub_info[ds].subs = (off_t)old_shm_size;
        }

        /* add new subscription */
        shm_msub = (sr_mod_sub_t *)(conn->shm + shm_mod->sub_info[ds].subs);
        shm_msub += shm_mod->sub_info[ds].sub_count;
        ++shm_mod->sub_info[ds].sub_count;

        if (xpath) {
            strcpy(conn->shm + xpath_off, xpath);
            shm_msub->xpath = xpath_off;
        } else {
            shm_msub->xpath = 0;
        }
        shm_msub->priority = priority;
        shm_msub->opts = subscr_opts;
    } else {
        /* find the subscription */
        shm_msub = (sr_mod_sub_t *)(conn->shm + shm_mod->sub_info[ds].subs);
        for (i = 0; i < shm_mod->sub_info[ds].sub_count; ++i) {
            if ((!xpath && !shm_msub[i].xpath) || (xpath && shm_msub[i].xpath && !strcmp(conn->shm + shm_msub[i].xpath, xpath))) {
                if ((shm_msub[i].priority == priority) && (shm_msub[i].opts == subscr_opts)) {
                    break;
                }
            }
        }
        SR_CHECK_INT_RET(i == shm_mod->sub_info[ds].sub_count, err_info);

        new_shm_size = conn->shm_size;
        if (xpath && (shm_msub[i].xpath + strlen(xpath) + 1 == new_shm_size)) {
            /* xpath was stored at the SHM end, we can shorten SHM */
            new_shm_size -= strlen(xpath) + 1;
        }

        /* replace the deleted subscription with the last one */
        if (i < shm_mod->sub_info[ds].sub_count - 1) {
            memcpy(&shm_msub[i], &shm_msub[shm_mod->sub_info[ds].sub_count - 1], sizeof *shm_msub);
        }

        if (shm_mod->sub_info[ds].subs + shm_mod->sub_info[ds].sub_count * sizeof *shm_msub == new_shm_size) {
            /* subscriptions are stored at the very SHM end, we can shorten SHM */
            new_shm_size -= sizeof *shm_msub;
        }

        if (conn->shm_size > new_shm_size) {
            /* remap main SHM */
            if ((err_info = sr_shmmain_remap(conn, new_shm_size))) {
                return err_info;
            }
            shm_mod = (sr_mod_t *)(conn->shm + shm_mod_off);
        }

        --shm_mod->sub_info[ds].sub_count;
        if (!shm_mod->sub_info[ds].sub_count) {
            /* the only subscription removed */
            shm_mod->sub_info[ds].subs = 0;
        }
    }

    return NULL;
}
