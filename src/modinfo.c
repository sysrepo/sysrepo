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

#include <libyang/libyang.h>

sr_error_info_t *
sr_modinfo_edit_diff(const struct lyd_node *edit, struct sr_mod_info_s *mod_info)
{
    struct lyd_node *mod_diff;
    struct sr_mod_info_mod_s *mod;
    uint32_t i;
    sr_error_info_t *err_info = NULL;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];

        if (mod->state & MOD_INFO_REQ) {
            mod_diff = NULL;

            /* apply relevant edit changes */
            if ((err_info = sr_ly_edit_mod_apply(edit, mod, &mod_diff))) {
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
    struct sr_mod_info_mod_s *src_mod, *mod;
    struct lyd_node *mod_diff;
    uint16_t i, j;

    assert(!mod_info->diff);

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];

        /* only these modules can be changed */
        if (mod->state & MOD_INFO_REQ) {
            /* find the module in the other mod_info */
            for (j = 0; j < src_mod_info->mod_count; ++j) {
                src_mod = &src_mod_info->mods[j];
                if (mod->ly_mod == src_mod->ly_mod) {
                    assert(src_mod->state & MOD_INFO_REQ);
                    break;
                }
            }
            assert(j < src_mod_info->mod_count);

            /* get libyang diff */
            ly_diff = lyd_diff(mod->mod_data, src_mod->mod_data, LYD_DIFFOPT_WITHDEFAULTS);
            if (!ly_diff) {
                sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
                return err_info;
            }

            /* create sysrepo diff */
            err_info = sr_ly_diff_ly2sr(ly_diff, &mod_diff);
            lyd_free_diff(ly_diff);
            if (err_info) {
                return err_info;
            }

            /* make the source data the new data */
            lyd_free_withsiblings(mod->mod_data);
            mod->mod_data = src_mod->mod_data;
            src_mod_info->mods[i].mod_data = NULL;

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

static sr_error_info_t *
sr_modinfo_add_data_instid_deps(sr_conn_ctx_t *conn, sr_mod_data_dep_t *shm_deps, uint16_t shm_dep_count,
        const struct lyd_node *data, struct ly_set *dep_set)
{
    sr_mod_t *dep_mod;
    struct ly_set *set = NULL;
    const char *val_str;
    char *mod_name;
    uint32_t i, j;
    sr_error_info_t *err_info = NULL;

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

static sr_error_info_t *
sr_module_config_data_get(struct ly_ctx *ly_ctx, char *main_shm_addr, sr_mod_t *shm_mod, sr_datastore_t ds,
        struct lyd_node **data)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_conf_sub_t *shm_confsubs;
    sr_datastore_t file_ds;
    struct lyd_node *tmp;
    uint16_t i, xp_i;
    char *path, **xpaths;

    *data = NULL;

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
    if (asprintf(&path, "%s/data/%s.%s", sr_get_repo_path(), main_shm_addr + shm_mod->name, sr_ds2str(file_ds)) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto error;
    }

    /* load data from a persistent storage */
    ly_errno = LYVE_SUCCESS;
    *data = lyd_parse_path(ly_ctx, path, LYD_LYB, LYD_OPT_CONFIG | LYD_OPT_STRICT | LYD_OPT_NOEXTDEPS);
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
        if (*data) {
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
                err_info = sr_ly_data_dup_xpath_select(*data, xpaths, xp_i, &tmp);
                free(xpaths);
                if (err_info) {
                    goto error;
                }

                /* replace the returned data to be the filtered tree */
                lyd_free_withsiblings(*data);
                *data = tmp;
            }
        }
        break;
    }

    return NULL;

error:
    lyd_free_withsiblings(*data);
    return err_info;
}

sr_error_info_t *
sr_modinfo_validate(struct sr_mod_info_s *mod_info, int finish_diff)
{
    struct lyd_node *first_root = NULL, *mod_data, *iter;
    struct sr_mod_info_mod_s *mod;
    struct lyd_difflist *diff = NULL;
    struct ly_set *dep_set;
    const struct lys_module **valid_mods;
    uint32_t i, j, valid_mod_count = 0;
    sr_mod_t *shm_mod;
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
            if ((err_info = sr_modinfo_add_data_instid_deps(mod_info->conn,
                    (sr_mod_data_dep_t *)(mod_info->conn->main_shm.addr + mod->shm_mod->data_deps),
                    mod->shm_mod->data_dep_count, mod->mod_data, dep_set))) {
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
        shm_mod = sr_shmmain_find_module(mod_info->conn->main_shm.addr, NULL, (off_t)dep_set->set.g[i]);
        SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup);
        if ((err_info = sr_module_config_data_get(mod_info->conn->ly_ctx, mod_info->conn->main_shm.addr, shm_mod,
                mod_info->ds, &mod_data))) {
            goto cleanup;
        }
        /* connect to one data tree */
        if (!first_root) {
            first_root = mod_data;
        } else {
            sr_ly_link(first_root, mod_data);
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
        if ((err_info = sr_ly_val_diff_merge(&mod_info->diff, mod_info->conn->ly_ctx, diff, &mod_info->dflt_change))) {
            goto cleanup;
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
    }

    /* success */

cleanup:
    /* disconnect all the data trees and split them back into modules removing any leftover instid-dependency data */
    sr_modinfo_data_replace(mod_info, MOD_INFO_TYPE_MASK, &first_root);
    assert(!first_root);

    /* other cleanup */
    lyd_free_val_diff(diff);
    ly_set_free(dep_set);
    free(valid_mods);
    return err_info;
}

sr_error_info_t *
sr_modinfo_op_validate(struct sr_mod_info_s *mod_info, struct lyd_node *op, sr_mod_data_dep_t *shm_deps,
        uint16_t shm_dep_count, int output)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *first_root = NULL, *mod_data, *iter, *top_op;
    struct sr_mod_info_mod_s *mod;
    struct ly_set *dep_set = NULL;
    uint32_t i, j;
    char *parent_xpath = NULL;
    sr_mod_t *shm_mod;
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

            if (mod->mod_data) {
                dep_set = lyd_find_path(mod->mod_data, parent_xpath);
            } else {
                dep_set = ly_set_new();
            }
            if (!dep_set) {
                sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
                goto cleanup;
            }
            SR_CHECK_INT_GOTO(dep_set->number > 1, err_info, cleanup);

            if (!dep_set->number) {
                sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, parent_xpath,
                        "Nested operation \"%s\" data parent does not exist in the operational datastore.", op->schema->name);
                goto cleanup;
            }
            ly_set_free(dep_set);
            dep_set = NULL;

            break;
        case MOD_INFO_DEP:
            /* this module data are required because there are references to them, but they do not need to be revalidated */
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

    dep_set = ly_set_new();
    SR_CHECK_MEM_GOTO(!dep_set, err_info, cleanup);

    /* check instids and add their target modules as deps */
    if ((err_info = sr_modinfo_add_data_instid_deps(mod_info->conn, shm_deps, shm_dep_count, op, dep_set))) {
        goto cleanup;
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
        shm_mod = sr_shmmain_find_module(mod_info->conn->main_shm.addr, NULL, (off_t)dep_set->set.g[i]);
        SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup);
        if ((err_info = sr_module_config_data_get(mod_info->conn->ly_ctx, mod_info->conn->main_shm.addr, shm_mod,
                mod_info->ds, &mod_data))) {
            goto cleanup;
        }
        /* connect to one data tree */
        if (!first_root) {
            first_root = mod_data;
        } else {
            sr_ly_link(first_root, mod_data);
        }
    }

    /* validate */
    flags = ((op->schema->nodetype & (LYS_RPC | LYS_ACTION)) ? (output ? LYD_OPT_RPCREPLY : LYD_OPT_RPC) : LYD_OPT_NOTIF)
            | LYD_OPT_WHENAUTODEL;
    for (top_op = op; top_op->parent; top_op = top_op->parent);
    if (lyd_validate(&top_op, flags, first_root)) {
        sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx);
        sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, NULL, "%s %svalidation failed.",
                (op->schema->nodetype == LYS_NOTIF) ? "Notification" : ((op->schema->nodetype == LYS_RPC) ? "RPC" : "Action"),
                (op->schema->nodetype == LYS_NOTIF) ? "" : (output ? "output " : "input "));
        goto cleanup;
    }

    /* success */

cleanup:
    /* disconnect all the data trees and split them back into modules removing any instid-dependency data */
    while (first_root) {
        for (i = 0; i < mod_info->mod_count; ++i) {
            mod = &mod_info->mods[i];

            if (lyd_node_module(first_root) != mod->ly_mod) {
                /* wrong module */
                continue;
            }

            /* find all the succeeding siblings from one module */
            for (iter = first_root->next; iter && (lyd_node_module(iter) == mod->ly_mod); iter = iter->next);

            /* unlink and connect them to their module */
            if (iter) {
                sr_ly_split(iter);
            }
            if (!mod->mod_data) {
                mod->mod_data = first_root;
            } else {
                sr_ly_link(mod->mod_data, first_root);
            }

            /* continue with the leftover data */
            first_root = iter;
            break;
        }

        if (i == mod_info->mod_count) {
            /* we have not found this data module, it must be data from an instid dependency, just free them and continue */
            for (iter = first_root->next; iter && (lyd_node_module(iter) == lyd_node_module(first_root)); iter = iter->next);
            if (iter) {
                sr_ly_split(iter);
            }
            lyd_free_withsiblings(first_root);
            first_root = iter;
        }
    }

    /* other cleanup */
    free(parent_xpath);
    ly_set_free(dep_set);
    return err_info;
}

static sr_error_info_t *
sr_xpath_dp_append(struct sr_mod_info_mod_s *mod, const char *xpath, const struct lyd_node *parent,
        sr_error_info_t **cb_error_info)
{
    uint32_t i;
    sr_error_info_t *err_info = NULL;
    struct lyd_node *data = NULL, *parent_dup = NULL, *key, *key_dup;

    if (parent) {
        /* duplicate parent so that it is a stand-alone subtree */
        parent_dup = lyd_dup(parent, LYD_DUP_OPT_WITH_PARENTS);
        if (!parent_dup) {
            sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx);
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
                    sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx);
                    return err_info;
                }

                if (lyd_insert(parent_dup, key_dup)) {
                    lyd_free_withsiblings(key_dup);
                    lyd_free_withsiblings(parent_dup);
                    sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx);
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
    err_info = sr_shmsub_dp_notify(mod->ly_mod, xpath, parent_dup, &data, cb_error_info);
    lyd_free_withsiblings(parent_dup);
    if (err_info) {
        return err_info;
    }

    /* merge into full data tree */
    if (data) {
        if (!mod->mod_data) {
            mod->mod_data = data;
        } else if (lyd_merge(mod->mod_data, data, LYD_OPT_DESTRUCT | LYD_OPT_EXPLICIT)) {
            lyd_free_withsiblings(data);
            sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx);
            return err_info;
        }
    }

    /* add default state data so that parents exist and we ask for data that could exist */
    if (lyd_validate_modules(&mod->mod_data, &mod->ly_mod, 1, LYD_OPT_DATA)) {
        sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx);
        return err_info;
    }

    return NULL;
}

static sr_error_info_t *
sr_xpath_dp_remove(struct lyd_node **mod_data, struct lyd_node *parent, const char *xpath)
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
        if (*mod_data == del_set->set.d[i]) {
            /* removing first top-level node, do not lose the rest of data */
            *mod_data = (*mod_data)->next;
        }
        lyd_free(del_set->set.d[i]);
    }
    ly_set_free(del_set);

    return NULL;
}

static sr_error_info_t *
sr_module_dp_append(struct sr_mod_info_mod_s *mod, char *main_shm_addr, sr_error_info_t **cb_error_info)
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

            if (!mod->mod_data) {
                /* parent does not exist for sure */
                goto next_iter;
            }

            set = lyd_find_path(mod->mod_data, parent_xpath);
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
                    if ((err_info = sr_xpath_dp_remove(&mod->mod_data, set->set.d[j], last_node_xpath))) {
                        goto error;
                    }
                }

                /* replace them with the ones retrieved from a client */
                if ((err_info = sr_xpath_dp_append(mod, xpath, set->set.d[j], cb_error_info))) {
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
                if ((err_info = sr_xpath_dp_remove(&mod->mod_data, mod->mod_data, xpath))) {
                    return err_info;
                }
            }

            if ((err_info = sr_xpath_dp_append(mod, xpath, NULL, cb_error_info))) {
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
sr_modinfo_data_update(struct sr_mod_info_s *mod_info, uint8_t mod_type, sr_error_info_t **cb_error_info)
{
    struct sr_mod_info_mod_s *mod;
    uint32_t i;
    sr_error_info_t *err_info = NULL;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & mod_type) {
            /* free any old data */
            if (mod->mod_data) {
                lyd_free_withsiblings(mod->mod_data);
            }

            /* get current persistent data */
            if ((err_info = sr_module_config_data_get(mod->ly_mod->ctx, mod_info->conn->main_shm.addr, mod->shm_mod,
                        mod_info->ds, &mod->mod_data))) {
                return err_info;
            }

            if (mod_info->ds == SR_DS_OPERATIONAL) {
                /* append any valid data provided by clients */
                if ((err_info = sr_module_dp_append(mod, mod_info->conn->main_shm.addr, cb_error_info))) {
                    return err_info;
                }
            }
        }
    }

    return NULL;
}

void
sr_modinfo_data_replace(struct sr_mod_info_s *mod_info, uint8_t mod_type, struct lyd_node **config_p)
{
    struct sr_mod_info_mod_s *mod;
    uint32_t i;
    struct lyd_node *config, *iter;

    assert(config_p);

    config = *config_p;
    while (config) {
        for (i = 0; i < mod_info->mod_count; ++i) {
            mod = &mod_info->mods[i];
            if (!(mod->state & mod_type)) {
                /* we ignore this module completely */
                continue;
            }

            if (lyd_node_module(config) != mod->ly_mod) {
                /* wrong module */
                continue;
            }

            /* find all the succeeding siblings from one module */
            for (iter = config->next; iter && (lyd_node_module(iter) == mod->ly_mod); iter = iter->next);

            /* unlink and connect them to their module */
            if (iter) {
                sr_ly_split(iter);
            }
            if (!mod->mod_data) {
                mod->mod_data = config;
            } else {
                sr_ly_link(mod->mod_data, config);
            }

            /* continue with the leftover data */
            config = iter;
            break;
        }

        if (i == mod_info->mod_count) {
            /* we have not found this data module, so just free it and continue */
            for (iter = config->next; iter && (lyd_node_module(iter) == lyd_node_module(config)); iter = iter->next);
            if (iter) {
                sr_ly_split(iter);
            }
            lyd_free_withsiblings(config);
            config = iter;
        }
    }

    *config_p = NULL;
}

sr_error_info_t *
sr_modinfo_get_filter(sr_session_ctx_t *session, const char *xpath, struct sr_mod_info_s *mod_info, struct ly_set **result)
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
            /* apply any performed changes to get the session-specific data tree */
            if (session->ev == SR_EV_NONE) {
                if ((err_info = sr_ly_edit_mod_apply(session->dt[session->ds].edit, mod, NULL))) {
                    goto cleanup;
                }
            }

            /* attach to result */
            if (!root) {
                root = mod->mod_data;
            } else {
                sr_ly_link(root, mod->mod_data);
            }
            mod->mod_data = NULL;
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
    lyd_free_withsiblings(root);
    if (err_info) {
        ly_set_free(*result);
        *result = NULL;
    }
    return err_info;
}

static sr_error_info_t *
sr_module_config_data_set(const char *mod_name, sr_datastore_t ds, struct lyd_node *data)
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
sr_modinfo_store(struct sr_mod_info_s *mod_info)
{
    struct sr_mod_info_mod_s *mod;
    uint32_t i;
    sr_error_info_t *err_info = NULL;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & MOD_INFO_CHANGED) {
            /* set the new data */
            if ((err_info = sr_module_config_data_set(mod->ly_mod->name, mod_info->ds, mod->mod_data))) {
                return err_info;
            }
        }
    }

    return NULL;
}
