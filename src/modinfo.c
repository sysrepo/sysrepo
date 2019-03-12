/**
 * @file modinfo.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief routines for working with modinfo structure
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

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>

#include <libyang/libyang.h>

sr_error_info_t *
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

sr_error_info_t *
sr_modinfo_perm_check(struct sr_mod_info_s *mod_info, int wr)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    uint32_t i;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];

        /* check also modules additionaly modified by validation */
        if (mod->state & (MOD_INFO_REQ | MOD_INFO_CHANGED)) {
            /* check perm */
            if ((err_info = sr_perm_check(mod->ly_mod->name, wr))) {
                return err_info;
            }
        }
    }

    return NULL;
}

sr_error_info_t *
sr_modinfo_edit_apply(struct sr_mod_info_s *mod_info, const struct lyd_node *edit, int create_diff)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *mod_diff;
    struct sr_mod_info_mod_s *mod;
    uint32_t i;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];

        if (mod->state & MOD_INFO_REQ) {
            mod_diff = NULL;

            /* apply relevant edit changes */
            if ((err_info = sr_ly_edit_mod_apply(edit, mod->ly_mod, &mod_info->data, create_diff ? &mod_diff : NULL))) {
                lyd_free_withsiblings(mod_diff);
                return err_info;
            }

            if (mod_diff) {
                /* there is a diff for this module */
                mod->state |= MOD_INFO_CHANGED;

                /* merge all diffs into one */
                if (!mod_info->diff) {
                    mod_info->diff = mod_diff;
                } else {
                    sr_ly_link(mod_info->diff, mod_diff);
                }
            }
        }
    }

    return NULL;
}

sr_error_info_t *
sr_modinfo_diff(struct sr_mod_info_s *src_mod_info, struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_difflist *ly_diff;
    struct lys_module *last_mod;
    struct lyd_node *node;
    uint16_t i;

    assert(!mod_info->diff);

    /* get libyang diff */
    ly_diff = lyd_diff(mod_info->data, src_mod_info->data, LYD_DIFFOPT_WITHDEFAULTS);
    if (!ly_diff) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
        return err_info;
    }

    /* create sysrepo diff */
    err_info = sr_ly_diff_ly2sr(ly_diff, &mod_info->diff);
    lyd_free_diff(ly_diff);
    if (err_info) {
        return err_info;
    }

    /* make the source data the new data */
    lyd_free_withsiblings(mod_info->data);
    mod_info->data = src_mod_info->data;
    src_mod_info->data = NULL;

    /* remember all modules that were changed */
    last_mod = NULL;
    LY_TREE_FOR(mod_info->diff, node) {
        if (lyd_node_module(node) == last_mod) {
            /* flag already set */
            continue;
        }

        last_mod = lyd_node_module(node);

        for (i = 0; i < mod_info->mod_count; ++i) {
            if (mod_info->mods[i].ly_mod == last_mod) {
                /* there is a diff for this module */
                mod_info->mods[i].state |= MOD_INFO_CHANGED;
                break;
            }
        }
    }

    return NULL;
}

static sr_error_info_t *
sr_module_config_data_append(struct ly_ctx *ly_ctx, char *main_shm_addr, sr_mod_t *shm_mod, sr_datastore_t ds,
        struct lyd_node **data)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_conf_sub_t *shm_confsubs;
    sr_datastore_t file_ds;
    struct lyd_node *tmp, *mod_data = NULL;
    uint16_t i, xp_i;
    char *path, **xpaths;

    if (ds == SR_DS_OPERATIONAL) {
        if (!shm_mod->conf_sub[SR_DS_RUNNING].sub_count) {
            /* there are no "running" subscriptions, the module is not enabled */
            return NULL;
        }
        file_ds = SR_DS_RUNNING;
    } else {
        file_ds = ds;
    }

    /* prepare correct file path */
    if (file_ds == SR_DS_RUNNING) {
        err_info = sr_path_running_file(main_shm_addr + shm_mod->name, &path);
    } else {
        err_info = sr_path_startup_file(main_shm_addr + shm_mod->name, &path);
    }
    if (err_info) {
        goto error;
    }

    /* load data from a persistent storage */
    ly_errno = LYVE_SUCCESS;
    mod_data = lyd_parse_path(ly_ctx, path, LYD_LYB, LYD_OPT_CONFIG | LYD_OPT_STRICT | LYD_OPT_NOEXTDEPS);
    free(path);
    if (ly_errno) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto error;
    }

    switch (ds) {
    case SR_DS_STARTUP:
    case SR_DS_RUNNING:
        /* we have the final data tree */
        break;
    case SR_DS_OPERATIONAL:
        if (mod_data) {
            /* first try to find a subscription for the whole module */
            shm_confsubs = (sr_mod_conf_sub_t *)(main_shm_addr + shm_mod->conf_sub[SR_DS_RUNNING].subs);
            for (i = 0; i < shm_mod->conf_sub[SR_DS_RUNNING].sub_count; ++i) {
                if (!shm_confsubs[i].xpath && !(shm_confsubs[i].opts & SR_SUBSCR_PASSIVE)) {
                    break;
                }
            }

            if (i == shm_mod->conf_sub[SR_DS_RUNNING].sub_count) {
                /* collect all enabled subtress in the form of xpaths */
                xpaths = NULL;
                for (i = 0, xp_i = 0; i < shm_mod->conf_sub[SR_DS_RUNNING].sub_count; ++i) {
                    if (shm_confsubs[i].xpath && !(shm_confsubs[i].opts & SR_SUBSCR_PASSIVE)) {
                        xpaths = sr_realloc(xpaths, (xp_i + 1) * sizeof *xpaths);
                        SR_CHECK_MEM_GOTO(!xpaths, err_info, error);

                        xpaths[xp_i] = main_shm_addr + shm_confsubs[i].xpath;
                        ++xp_i;
                    }
                }

                /* filter out disabled subtrees */
                err_info = sr_ly_data_dup_xpath_select(mod_data, xpaths, xp_i, &tmp);
                free(xpaths);
                if (err_info) {
                    goto error;
                }

                /* replace the returned data to be the filtered tree */
                lyd_free_withsiblings(mod_data);
                mod_data = tmp;
            }
        }
        break;
    }

    if (mod_data) {
        if (*data) {
            sr_ly_link(*data, mod_data);
        } else {
            *data = mod_data;
        }
    }
    return NULL;

error:
    lyd_free_withsiblings(mod_data);
    return err_info;
}

static sr_error_info_t *
sr_modinfo_add_instid_deps_data(struct sr_mod_info_s *mod_info, sr_mod_data_dep_t *shm_deps, uint16_t shm_dep_count,
        const struct lyd_node *data)
{
    sr_error_info_t *err_info = NULL;
    sr_conn_ctx_t *conn;
    sr_mod_t *dep_mod;
    const struct lys_module *ly_mod;
    struct ly_set *set = NULL, *dep_set = NULL;
    const char *val_str;
    char *mod_name;
    uint32_t i, j;

    conn = mod_info->conn;

    dep_set = ly_set_new();
    if (!dep_set) {
        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
        goto cleanup;
    }

    /* collect all possibly required modules (because of inst-ids) into a set */
    for (i = 0; i < shm_dep_count; ++i) {
        if (shm_deps[i].type == SR_DEP_INSTID) {
            if (data) {
                set = lyd_find_path(data, conn->main_shm.addr + shm_deps[i].xpath);
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
                    dep_mod = sr_shmmain_find_module(conn->main_shm.addr, mod_name, 0);
                    free(mod_name);
                    SR_CHECK_INT_GOTO(!dep_mod, err_info, cleanup);

                    /* add module name offset so that duplicities can be found easily */
                    if (ly_set_add(dep_set, (void *)dep_mod, 0) == -1) {
                        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
                        goto cleanup;
                    }
                }
            } else if (shm_deps[i].module) {
                /* assume a default value will be used even though it may not be */
                dep_mod = sr_shmmain_find_module(conn->main_shm.addr, NULL, shm_deps[i].module);
                SR_CHECK_INT_GOTO(!dep_mod, err_info, cleanup);

                if (ly_set_add(dep_set, (void *)dep_mod, 0) == -1) {
                    sr_errinfo_new_ly(&err_info, conn->ly_ctx);
                    goto cleanup;
                }
            }
            ly_set_free(set);
            set = NULL;
        }
    }

    /* add new modules to mod_info */
    for (i = 0; i < dep_set->number; ++i) {
        dep_mod = (sr_mod_t *)dep_set->set.g[i];

        ly_mod = ly_ctx_get_module(mod_info->conn->ly_ctx, conn->main_shm.addr + dep_mod->name, NULL, 1);
        SR_CHECK_INT_GOTO(!ly_mod, err_info, cleanup);

        /* remember how many modules there were and add this one */
        j = mod_info->mod_count;
        if ((err_info = sr_modinfo_add_mod(dep_mod, ly_mod, MOD_INFO_DEP, 0, mod_info))) {
            goto cleanup;
        }

        /* add this module data if not already there */
        if ((j < mod_info->mod_count) && (err_info = sr_module_config_data_append(conn->ly_ctx, conn->main_shm.addr,
                dep_mod, mod_info->ds, &mod_info->data))) {
            goto cleanup;
        }
    }

    /* success */

cleanup:
    ly_set_free(set);
    ly_set_free(dep_set);
    return err_info;
}

sr_error_info_t *
sr_modinfo_validate(struct sr_mod_info_s *mod_info, int finish_diff)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *iter;
    struct sr_mod_info_mod_s *mod;
    struct lyd_difflist *diff = NULL;
    const struct lys_module **valid_mods;
    uint32_t i, j, valid_mod_count = 0;
    int flags;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        switch (mod->state & MOD_INFO_TYPE_MASK) {
        case MOD_INFO_REQ:
            /* this module will be validated */
            ++valid_mod_count;

            if (mod->state & MOD_INFO_CHANGED) {
                assert(mod_info->diff);

                /* check instids in diff and add their target modules as deps, other inst-ids do not need to be revalidated */
                if ((err_info = sr_modinfo_add_instid_deps_data(mod_info,
                        (sr_mod_data_dep_t *)(mod_info->conn->main_shm.addr + mod->shm_mod->data_deps),
                        mod->shm_mod->data_dep_count, mod_info->diff))) {
                    goto cleanup;
                }
            }
            break;
        case MOD_INFO_INV_DEP:
            /* this module reference targets could have been changed, needs to be validated */
            ++valid_mod_count;
            /* fallthrough */
        case MOD_INFO_DEP:
            /* this module will not be validated */
            break;
        default:
            SR_CHECK_INT_GOTO(0, err_info, cleanup);
        }
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
    flags = LYD_OPT_CONFIG | LYD_OPT_WHENAUTODEL | LYD_OPT_VAL_DIFF;
    if (lyd_validate_modules(&mod_info->data, valid_mods, valid_mod_count, flags, &diff)) {
        sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx);
        SR_ERRINFO_VALID(&err_info);
        goto cleanup;
    }

    if (finish_diff) {
        /* merge the changes made by the validation into our diff */
        if ((err_info = sr_ly_val_diff_merge(&mod_info->diff, mod_info->conn->ly_ctx, diff, &mod_info->dflt_change))) {
            goto cleanup;
        }
    }

    /* additional modules can be modified */
    if (diff->type[0] != LYD_DIFF_END) {
        for (iter = mod_info->diff; iter; iter = iter->next) {
            /* keep just the last node from one module */
            while (iter->next && (lyd_node_module(iter) == lyd_node_module(iter->next))) {
                iter = iter->next;
            }

            for (i = 0; i < mod_info->mod_count; ++i) {
                mod = &mod_info->mods[i];
                if (lyd_node_module(iter) == mod->ly_mod) {
                    mod->state |= MOD_INFO_CHANGED;
                    break;
                }
            }
            assert(i < mod_info->mod_count);
        }
    }

    /* success */

cleanup:
    lyd_free_val_diff(diff);
    free(valid_mods);
    return err_info;
}

sr_error_info_t *
sr_modinfo_op_validate(struct sr_mod_info_s *mod_info, struct lyd_node *op, sr_mod_data_dep_t *shm_deps,
        uint16_t shm_dep_count, int output)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *top_op;
    struct ly_set *set = NULL;
    struct sr_mod_info_mod_s *mod;
    uint32_t i;
    char *parent_xpath = NULL;
    int flags;

    assert(op->schema->nodetype & (LYS_RPC | LYS_ACTION | LYS_NOTIF));

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        switch (mod->state & MOD_INFO_TYPE_MASK) {
        case MOD_INFO_REQ:
            /* this is the module of the nested operation and we need to check that operation's parent data node exists */
            assert((mod->ly_mod == lyd_node_module(op)) && lys_parent(op->schema) && op->parent);
            parent_xpath = lyd_path(op->parent);
            SR_CHECK_MEM_GOTO(!parent_xpath, err_info, cleanup);

            if (mod_info->data) {
                set = lyd_find_path(mod_info->data, parent_xpath);
            } else {
                set = ly_set_new();
            }
            if (!set) {
                sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
                goto cleanup;
            }
            SR_CHECK_INT_GOTO(set->number > 1, err_info, cleanup);

            if (!set->number) {
                sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, parent_xpath,
                        "Nested operation \"%s\" data parent does not exist in the operational datastore.", op->schema->name);
                goto cleanup;
            }
            break;
        case MOD_INFO_DEP:
            /* this module data are required because there are references to them, but they do not need to be revalidated */
            break;
        default:
            SR_ERRINFO_INT(&err_info);
            goto cleanup;
        }
    }

    /* check instids and add their target modules as deps */
    if ((err_info = sr_modinfo_add_instid_deps_data(mod_info, shm_deps, shm_dep_count, op))) {
        goto cleanup;
    }

    /* validate */
    flags = ((op->schema->nodetype & (LYS_RPC | LYS_ACTION)) ? (output ? LYD_OPT_RPCREPLY : LYD_OPT_RPC) : LYD_OPT_NOTIF)
            | LYD_OPT_WHENAUTODEL;
    for (top_op = op; top_op->parent; top_op = top_op->parent);
    if (lyd_validate(&top_op, flags, mod_info->data)) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
        sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, NULL, "%s %svalidation failed.",
                (op->schema->nodetype == LYS_NOTIF) ? "Notification" : ((op->schema->nodetype == LYS_RPC) ? "RPC" : "Action"),
                (op->schema->nodetype == LYS_NOTIF) ? "" : (output ? "output " : "input "));
        goto cleanup;
    }

    /* success */

cleanup:
    free(parent_xpath);
    ly_set_free(set);
    return err_info;
}

static sr_error_info_t *
sr_xpath_dp_append(const struct lys_module *ly_mod, const char *xpath, sr_sid_t sid, const struct lyd_node *parent,
        struct lyd_node **data, sr_error_info_t **cb_error_info)
{
    uint32_t i;
    sr_error_info_t *err_info = NULL;
    struct lyd_node *dp_data = NULL, *parent_dup = NULL, *key, *key_dup;

    if (parent) {
        /* duplicate parent so that it is a stand-alone subtree */
        parent_dup = lyd_dup(parent, LYD_DUP_OPT_WITH_PARENTS);
        if (!parent_dup) {
            sr_errinfo_new_ly(&err_info, ly_mod->ctx);
            return err_info;
        }

        /* duplicate also keys if needed */
        if (parent->schema->nodetype == LYS_LIST) {
            for (i = 0, key = parent->child; i < ((struct lys_node_list *)parent->schema)->keys_size; ++i) {
                assert(key);
                assert((struct lys_node_leaf *)key->schema == ((struct lys_node_list *)parent->schema)->keys[i]);

                key_dup = lyd_dup(key, 0);
                if (!key_dup) {
                    lyd_free_withsiblings(parent_dup);
                    sr_errinfo_new_ly(&err_info, ly_mod->ctx);
                    return err_info;
                }

                if (lyd_insert(parent_dup, key_dup)) {
                    lyd_free_withsiblings(key_dup);
                    lyd_free_withsiblings(parent_dup);
                    sr_errinfo_new_ly(&err_info, ly_mod->ctx);
                    return err_info;
                }
            }
        }

        /* go top-level */
        while (parent_dup->parent) {
            parent_dup = parent_dup->parent;
        }
    }

    /* get data from client */
    err_info = sr_shmsub_dp_notify(ly_mod, xpath, parent_dup, sid, &dp_data, cb_error_info);
    lyd_free_withsiblings(parent_dup);
    if (err_info) {
        return err_info;
    }

    /* merge into full data tree */
    if (dp_data) {
        if (!*data) {
            *data = dp_data;
        } else if (lyd_merge(*data, dp_data, LYD_OPT_DESTRUCT | LYD_OPT_EXPLICIT)) {
            lyd_free_withsiblings(dp_data);
            sr_errinfo_new_ly(&err_info, ly_mod->ctx);
            return err_info;
        }
    }

    /* add default state data so that parents exist and we ask for data that could exist */
    if (lyd_validate_modules(data, &ly_mod, 1, LYD_OPT_DATA)) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        return err_info;
    }

    return NULL;
}

static sr_error_info_t *
sr_xpath_dp_remove(const char *xpath, struct lyd_node *parent, struct lyd_node **data)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *del_set;
    uint16_t i;

    if (!parent) {
        /* no data so nothing to remove */
        return NULL;
    }

    del_set = lyd_find_path(parent, xpath);
    if (!del_set) {
        sr_errinfo_new_ly(&err_info, lyd_node_module(parent)->ctx);
        return err_info;
    }
    for (i = 0; i < del_set->number; ++i) {
        if (*data == del_set->set.d[i]) {
            /* removing first top-level node, do not lose the rest of data */
            *data = (*data)->next;
        }
        lyd_free(del_set->set.d[i]);
    }
    ly_set_free(del_set);

    return NULL;
}

static sr_error_info_t *
sr_module_dp_append(struct sr_mod_info_mod_s *mod, sr_sid_t sid, char *main_shm_addr, struct lyd_node **data,
        sr_error_info_t **cb_error_info)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_dp_sub_t *shm_msub;
    const char *xpath;
    char *parent_xpath, *last_node_xpath;
    uint16_t i, j;
    struct ly_set *set;

    /* XPaths are ordered based on depth */
    for (i = 0; i < mod->shm_mod->dp_sub_count; ++i) {
        shm_msub = &((sr_mod_dp_sub_t *)(main_shm_addr + mod->shm_mod->dp_subs))[i];
        xpath = main_shm_addr + shm_msub->xpath;

        /* trim the last node to get the parent */
        if ((err_info = sr_xpath_trim_last_node(xpath, &parent_xpath, &last_node_xpath))) {
            return err_info;
        }

        if (parent_xpath) {
            set = NULL;

            if (!*data) {
                /* parent does not exist for sure */
                goto next_iter;
            }

            set = lyd_find_path(*data, parent_xpath);
            if (!set) {
                sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx);
                goto error;
            }

            if (!set->number) {
                /* data parent does not exist */
                goto next_iter;
            }

            /* nested data */
            for (j = 0; j < set->number; ++j) {
                if ((shm_msub->sub_type == SR_DP_SUB_CONFIG) || (shm_msub->sub_type == SR_DP_SUB_MIXED)) {
                    /* remove any currently present nodes */
                    if ((err_info = sr_xpath_dp_remove(last_node_xpath, set->set.d[j], data))) {
                        goto error;
                    }
                }

                /* replace them with the ones retrieved from a client */
                if ((err_info = sr_xpath_dp_append(mod->ly_mod, xpath, sid, set->set.d[j], data, cb_error_info))) {
                    goto error;
                }
            }

next_iter:
            /* cleanup for next iteration */
            free(parent_xpath);
            free(last_node_xpath);
            ly_set_free(set);
        } else {
            /* top-level data */
            if ((shm_msub->sub_type == SR_DP_SUB_CONFIG) || (shm_msub->sub_type == SR_DP_SUB_MIXED)) {
                /* remove any currently present nodes */
                if ((err_info = sr_xpath_dp_remove(xpath, *data, data))) {
                    return err_info;
                }
            }

            if ((err_info = sr_xpath_dp_append(mod->ly_mod, xpath, sid, NULL, data, cb_error_info))) {
                return err_info;
            }
        }
    }

    return NULL;

error:
    free(parent_xpath);
    free(last_node_xpath);
    ly_set_free(set);
    return err_info;
}

sr_error_info_t *
sr_modinfo_data_update(struct sr_mod_info_s *mod_info, uint8_t mod_type, sr_sid_t *sid, sr_error_info_t **cb_error_info)
{
    struct sr_mod_info_mod_s *mod;
    uint32_t i;
    sr_error_info_t *err_info = NULL;

    assert((mod_info->ds != SR_DS_OPERATIONAL) || sid);

    /* free any old data */
    if (mod_info->data) {
        lyd_free_withsiblings(mod_info->data);
        mod_info->data = NULL;
    }

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & mod_type) {
            /* get current persistent data */
            if ((err_info = sr_module_config_data_append(mod->ly_mod->ctx, mod_info->conn->main_shm.addr, mod->shm_mod,
                        mod_info->ds, &mod_info->data))) {
                return err_info;
            }

            if (mod_info->ds == SR_DS_OPERATIONAL) {
                /* append any valid data provided by clients */
                if ((err_info = sr_module_dp_append(mod, *sid, mod_info->conn->main_shm.addr, &mod_info->data, cb_error_info))) {
                    return err_info;
                }
            }
        }
    }

    return NULL;
}

sr_error_info_t *
sr_modinfo_get_filter(struct sr_mod_info_s *mod_info, const char *xpath, sr_session_ctx_t *session, struct ly_set **result)
{
    struct lyd_node *root = NULL;
    struct sr_mod_info_mod_s *mod;
    uint32_t i, j;
    sr_error_info_t *err_info = NULL;

    *result = NULL;

    /* merge data trees of all the referenced modules (without dependency modules) */
    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & MOD_INFO_REQ) {
            /* apply any performed changes to get the session-specific data */
            if ((session->ev == SR_SUB_EV_NONE) && (session->ds != SR_DS_OPERATIONAL)) {
                if ((err_info = sr_ly_edit_mod_apply(session->dt[session->ds].edit, mod->ly_mod, &mod_info->data, NULL))) {
                    goto cleanup;
                }
            }
        }
    }

    /* filter return data */
    if (mod_info->data) {
        *result = lyd_find_path(mod_info->data, xpath);
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
    lyd_free_withsiblings(root);
    if (err_info) {
        ly_set_free(*result);
        *result = NULL;
    }
    return err_info;
}

sr_error_info_t *
sr_modinfo_generate_config_change_notif(struct sr_mod_info_s *mod_info, sr_session_ctx_t *session)
{
    sr_error_info_t *err_info = NULL, *tmp_err_info = NULL;
    struct lyd_node *root, *next, *elem, *notif = NULL;
    struct ly_set *set;
    sr_mod_t *shm_mod;
    time_t notif_ts;
    uint32_t idx = 0, notif_sub_count;
    char *xpath, nc_str[11];
    const char *op_enum;
    sr_change_oper_t op;

    assert(mod_info->diff);

    /* remember when the notification was generated */
    notif_ts = time(NULL);

    /* get subscriber count */
    if ((err_info = sr_notif_find_subscriber(session->conn, "ietf-netconf-notifications", &notif_sub_count))) {
        return err_info;
    }

    /* get this module and check replay support */
    shm_mod = sr_shmmain_find_module(mod_info->conn->main_shm.addr, "ietf-netconf-notifications", 0);
    SR_CHECK_INT_RET(!shm_mod, err_info);
    if (!(shm_mod->flags & SR_MOD_REPLAY_SUPPORT) && !notif_sub_count) {
        /* nothing to do */
        return NULL;
    }

    set = ly_set_new();
    SR_CHECK_MEM_GOTO(!set, err_info, cleanup);

    /* just put all the nodes into a set */
    LY_TREE_FOR(mod_info->diff, root) {
        LY_TREE_DFS_BEGIN(root, next, elem) {
            if (ly_set_add(set, elem, LY_SET_OPT_USEASLIST) == -1) {
                SR_ERRINFO_INT(&err_info);
                goto cleanup;
            }

            LY_TREE_DFS_END(root, next, elem);
        }
    }

    /* generate notifcation with all the changes */
    notif = lyd_new_path(NULL, mod_info->conn->ly_ctx, "/ietf-netconf-notifications:netconf-config-change", NULL, 0, 0);
    if (!notif) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
        goto cleanup;
    }

    /* changed-by (everything was caused by user, we do not know what changes are implicit) */
    root = lyd_new(notif, NULL, "changed-by");
    if (!root) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
        goto cleanup;
    }

    /* changed-by username */
    next = lyd_new_leaf(root, NULL, "username", session->sid.user);
    if (!next) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
        goto cleanup;
    }

    /* changed-by session-id */
    sprintf(nc_str, "%u", session->sid.nc);
    next = lyd_new_leaf(root, NULL, "session-id", nc_str);
    if (!next) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
        goto cleanup;
    }

    /* datastore */
    next = lyd_new_leaf(notif, NULL, "datastore", sr_ds2str(mod_info->ds));
    if (!next) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
        goto cleanup;
    }

    while (!(err_info = sr_diff_set_getnext(set, &idx, &elem, &op)) && elem) {
        /* edit (list instance) */
        root = lyd_new(notif, NULL, "edit");
        if (!root) {
            sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
            goto cleanup;
        }

        /* edit target */
        xpath = lyd_path(elem);
        if (!xpath) {
            sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
            goto cleanup;
        }
        next = lyd_new_leaf(root, NULL, "target", xpath);
        free(xpath);
        if (!next) {
            sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
            goto cleanup;
        }

        /* operation */
        switch (op) {
        case SR_OP_CREATED:
            op_enum = "create";
            break;
        case SR_OP_MODIFIED:
            op_enum = "replace";
            break;
        case SR_OP_DELETED:
            op_enum = "delete";
            break;
        case SR_OP_MOVED:
            /* exact move position will not be known */
            op_enum = "merge";
            break;
        }
        next = lyd_new_leaf(root, NULL, "operation", op_enum);
        if (!next) {
            sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
            goto cleanup;
        }
    }

    /* store the notification for a replay, we continue on failure */
    tmp_err_info = sr_replay_store(session->conn, notif, notif_ts);

    /* send the notification (non-validated, if everything works correctly it must be valid) */
    if (notif_sub_count && (err_info = sr_shmsub_notif_notify(notif, notif_ts, session->sid, notif_sub_count))) {
        goto cleanup;
    }

    /* success */

cleanup:
    ly_set_free(set);
    lyd_free_withsiblings(notif);
    if (err_info) {
        /* write this only if the notification failed to be created/sent */
        sr_errinfo_new(&err_info, err_info->err_code, NULL, "Failed to generate netconf-config-change notification, "
                "but configuration changes were applied.");
    }
    if (tmp_err_info) {
        sr_errinfo_merge(&err_info, tmp_err_info);
    }
    return err_info;
}

static sr_error_info_t *
sr_module_config_data_set(const char *mod_name, sr_datastore_t ds, struct lyd_node *data)
{
    char *path;
    sr_error_info_t *err_info = NULL;

    assert(ds != SR_DS_OPERATIONAL);

    if (ds == SR_DS_RUNNING) {
        err_info = sr_path_running_file(mod_name, &path);
    } else {
        err_info = sr_path_startup_file(mod_name, &path);
    }
    if (err_info) {
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
sr_modinfo_store(struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    struct lyd_node *next, *node, *mod_data;
    uint32_t i;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & MOD_INFO_CHANGED) {
            mod_data = NULL;

            /* separate data of this module, always search all the top-level nodes */
            LY_TREE_FOR_SAFE(mod_info->data, next, node) {
                if (lyd_node_module(node) == mod->ly_mod) {
                    /* properly unlink this node */
                    if (node == mod_info->data) {
                        mod_info->data = next;
                    }
                    sr_ly_split(node);
                    if (next) {
                        sr_ly_split(next);
                        if (mod_info->data && (mod_info->data != next)) {
                            sr_ly_link(mod_info->data, next);
                        }
                    }

                    /* connect it to other data from this module */
                    if (mod_data) {
                        sr_ly_link(mod_data, node);
                    } else {
                        mod_data = node;
                    }
                }
            }

            /* store the new data */
            if ((err_info = sr_module_config_data_set(mod->ly_mod->name, mod_info->ds, mod_data))) {
                return err_info;
            }

            /* connect them back */
            if (mod_info->data) {
                sr_ly_link(mod_info->data, mod_data);
            } else {
                mod_info->data = mod_data;
            }
        }
    }

    return NULL;
}

void
sr_modinfo_free(struct sr_mod_info_s *mod_info)
{
    uint32_t i;

    lyd_free_withsiblings(mod_info->diff);
    lyd_free_withsiblings(mod_info->data);
    for (i = 0; i < mod_info->mod_count; ++i) {
        if (mod_info->mods[i].shm_sub_cache.addr) {
            munmap(mod_info->mods[i].shm_sub_cache.addr, mod_info->mods[i].shm_sub_cache.size);
        }
        if (mod_info->mods[i].shm_sub_cache.fd > -1) {
            close(mod_info->mods[i].shm_sub_cache.fd);
        }
    }

    free(mod_info->mods);
}
