/**
 * @file modinfo.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief routines for working with modinfo structure
 *
 * @copyright
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
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
    off_t *shm_inv_deps;
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
         /* add all inverse dependencies (modules dependening on this module) */
         shm_inv_deps = (off_t *)(mod_info->conn->main_shm.addr + shm_mod->inv_data_deps);
         for (i = 0; i < shm_mod->inv_data_dep_count; ++i) {
            /* find ly module */
            ly_mod = ly_ctx_get_module(ly_mod->ctx, mod_info->conn->main_shm.addr + shm_inv_deps[i], NULL, 1);
            SR_CHECK_INT_RET(!ly_mod, err_info);

            /* find SHM module */
            dep_mod = sr_shmmain_find_module(mod_info->conn->main_shm.addr, NULL, shm_inv_deps[i]);
            SR_CHECK_INT_RET(!dep_mod, err_info);

            /* add inverse dependency */
            if ((err_info = sr_modinfo_add_mod(dep_mod, ly_mod, MOD_INFO_INV_DEP, mod_req_deps, mod_info))) {
                return err_info;
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

    assert(!mod_info->data_cached);

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & MOD_INFO_REQ) {
            mod_diff = NULL;

            /* apply relevant edit changes */
            if ((err_info = sr_edit_mod_apply(edit, mod->ly_mod, &mod_info->data, create_diff ? &mod_diff : NULL))) {
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

/**
 * @brief Duplicate data of a specific module in a data tree.
 *
 * @param[in] data Data tree.
 * @param[in] ly_mod libyang module of interest.
 * @param[out] mod_data Duplicated module data.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_module_data_dup(const struct lyd_node *data, const struct lys_module *ly_mod, struct lyd_node **mod_data)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *dup;
    const struct lyd_node *node;

    assert(ly_mod && mod_data);
    *mod_data = NULL;

    LY_TREE_FOR(data, node) {
        if (lyd_node_module(node) == ly_mod) {
            /* duplicate node */
            dup = lyd_dup(node, LYD_DUP_OPT_RECURSIVE | LYD_DUP_OPT_WITH_WHEN);
            if (!dup) {
                sr_errinfo_new_ly(&err_info, ly_mod->ctx);
                goto error;
            }

            /* connect it to other data from this module */
            if (*mod_data) {
                sr_ly_link(*mod_data, dup);
            } else {
                *mod_data = dup;
            }
        }
    }

    return NULL;

error:
    lyd_free_withsiblings(*mod_data);
    *mod_data = NULL;
    return err_info;
}

sr_error_info_t *
sr_modinfo_replace(struct sr_mod_info_s *mod_info, struct lyd_node **src_data)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_difflist *ly_diff;
    struct sr_mod_info_mod_s *mod;
    struct lyd_node *src_mod_data, *dst_mod_data;
    uint32_t i;

    assert(!mod_info->diff && !mod_info->data_cached);

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & MOD_INFO_REQ) {
            dst_mod_data = sr_module_data_unlink(&mod_info->data, mod->ly_mod);
            src_mod_data = sr_module_data_unlink(src_data, mod->ly_mod);

            /* get libyang diff on only this module's data */
            if (!(ly_diff = lyd_diff(dst_mod_data, src_mod_data, LYD_DIFFOPT_WITHDEFAULTS))) {
                sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
                lyd_free_withsiblings(dst_mod_data);
                lyd_free_withsiblings(src_mod_data);
                return err_info;
            }

            if (ly_diff->type[0] != LYD_DIFF_END) {
                /* there is a diff */
                mod->state |= MOD_INFO_CHANGED;

                /* create a single sysrepo diff */
                err_info = sr_diff_ly2sr(ly_diff, &mod_info->diff);

                /* update data */
                if (mod_info->data) {
                    sr_ly_link(mod_info->data, src_mod_data);
                } else {
                    mod_info->data = src_mod_data;
                }
                lyd_free_withsiblings(dst_mod_data);
            } else {
                /* keep old data (for validation) */
                if (mod_info->data) {
                    sr_ly_link(mod_info->data, dst_mod_data);
                } else {
                    mod_info->data = dst_mod_data;
                }
                lyd_free_withsiblings(src_mod_data);
            }

            /* next iteration */
            lyd_free_diff(ly_diff);
            if (err_info) {
                return err_info;
            }
        }
    }

    return NULL;
}

/**
 * @brief Append specific operational data retrieved from a client to a data tree.
 *
 * @param[in] ly_mod libyang module of the data.
 * @param[in] xpath XPath of the provided data.
 * @param[in] sid Sysrepo session ID.
 * @param[in] parent Data parent required for the subscription, NULL if top-level.
 * @param[in,out] data Data tree with appended operational data.
 * @param[out] cb_error_info Callback error info returned by the client, if any.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_xpath_oper_data_append(const struct lys_module *ly_mod, const char *xpath, sr_sid_t sid, const struct lyd_node *parent,
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

/**
 * @brief Remove configuration data that will be provided by a client.
 *
 * @param[in] xpath XPath of the provided data to be removed.
 * @param[in] parent Parent of the operational data.
 * @param[in,out] data Whole data tree to be adjusted in case top-level nodes are removed.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_xpath_oper_data_remove(const char *xpath, struct lyd_node *parent, struct lyd_node **data)
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

/**
 * @brief Update (replace or append) operation data for a specific module.
 *
 * @param[in] mod Mod info module to process.
 * @param[in] sid Sysrepo session ID.
 * @param[in] main_shm_addr Main SHM mapping address.
 * @param[in,out] data Operation data tree.
 * @param[out] cb_error_info Callback error info returned by the client, if any.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_module_oper_data_update(struct sr_mod_info_mod_s *mod, sr_sid_t sid, char *main_shm_addr, struct lyd_node **data,
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
                    if ((err_info = sr_xpath_oper_data_remove(last_node_xpath, set->set.d[j], data))) {
                        goto error;
                    }
                }

                /* replace them with the ones retrieved from a client */
                if ((err_info = sr_xpath_oper_data_append(mod->ly_mod, xpath, sid, set->set.d[j], data, cb_error_info))) {
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
                if ((err_info = sr_xpath_oper_data_remove(xpath, *data, data))) {
                    return err_info;
                }
            }

            if ((err_info = sr_xpath_oper_data_append(mod->ly_mod, xpath, sid, NULL, data, cb_error_info))) {
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

/**
 * @brief Duplicate operational (enabled) data from configuration data tree.
 *
 * @param[in] data Configuration data.
 * @param[in] main_shm_addr Main SHM mapping address.
 * @param[in] mod Mod info module to process.
 * @param[out] enabled_mod_data Enabled operational data of the module.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_module_oper_data_dup_enabled(const struct lyd_node *data, char *main_shm_addr, struct sr_mod_info_mod_s *mod,
        struct lyd_node **enabled_mod_data)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_conf_sub_t *shm_confsubs;
    uint16_t i, xp_i;
    char **xpaths;

    *enabled_mod_data = NULL;

    if (!data) {
        return NULL;
    }

    /* first try to find a subscription for the whole module */
    shm_confsubs = (sr_mod_conf_sub_t *)(main_shm_addr + mod->shm_mod->conf_sub[SR_DS_RUNNING].subs);
    for (i = 0; i < mod->shm_mod->conf_sub[SR_DS_RUNNING].sub_count; ++i) {
        if (!shm_confsubs[i].xpath && !(shm_confsubs[i].opts & SR_SUBSCR_PASSIVE)) {
            /* the whole module is enabled */
            if ((err_info = sr_module_data_dup(data, mod->ly_mod, enabled_mod_data))) {
                return err_info;
            }
            return NULL;
        }
    }

    /* collect all enabled subtress in the form of xpaths */
    xpaths = NULL;
    for (i = 0, xp_i = 0; i < mod->shm_mod->conf_sub[SR_DS_RUNNING].sub_count; ++i) {
        if (shm_confsubs[i].xpath && !(shm_confsubs[i].opts & SR_SUBSCR_PASSIVE)) {
            xpaths = sr_realloc(xpaths, (xp_i + 1) * sizeof *xpaths);
            SR_CHECK_MEM_RET(!xpaths, err_info);

            xpaths[xp_i] = main_shm_addr + shm_confsubs[i].xpath;
            ++xp_i;
        }
    }

    /* duplicate only enabled subtrees */
    err_info = sr_ly_data_dup_xpath_select(data, xpaths, xp_i, enabled_mod_data);
    free(xpaths);
    if (err_info) {
        return err_info;
    }

    return NULL;
}

/**
 * @brief Update cached module data (if required).
 *
 * @param[in] mod_cache Module cache.
 * @param[in] mod Mod info module to process.
 * @param[in] ds Datastore.
 * @param[in] upd_mod_data Optional current (updated) module data to store in cache.
 * @param[in] read_locked Whether the cache is READ locked.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modcache_module_update(struct sr_mod_cache_s *mod_cache, struct sr_mod_info_mod_s *mod, sr_datastore_t ds,
        struct lyd_node **upd_mod_data, int read_locked)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    void *mem;

    /* find the module in the cache */
    for (i = 0; i < mod_cache->mod_count; ++i) {
        if (mod->ly_mod == mod_cache->mods[i].ly_mod) {
            break;
        }
    }

    if (i < mod_cache->mod_count) {
        /* this module data are already in the cache */
        assert(mod->shm_mod->ver >= mod_cache->mods[i].ver);
        if (mod->shm_mod->ver > mod_cache->mods[i].ver) {
            if (read_locked) {
                /* CACHE READ UNLOCK */
                sr_rwunlock(&mod_cache->lock, 0);
            }

            /* CACHE WRITE LOCK */
            if ((err_info = sr_rwlock(&mod_cache->lock, SR_MOD_CACHE_LOCK_TIMEOUT * 1000, 1, __func__))) {
                return err_info;
            }

            /* data needs to be updated, remove old data */
            lyd_free_withsiblings(sr_module_data_unlink(&mod_cache->data, mod->ly_mod));
            mod_cache->mods[i].ver = 0;
        }
    } else {
        if (read_locked) {
            /* CACHE READ UNLOCK */
            sr_rwunlock(&mod_cache->lock, 0);
        }

        /* CACHE WRITE LOCK */
        if ((err_info = sr_rwlock(&mod_cache->lock, SR_MOD_CACHE_LOCK_TIMEOUT * 1000, 1, __func__))) {
            return err_info;
        }

        /* module is not in cache yet, add an item */
        mem = realloc(mod_cache->mods, (i + 1) * sizeof *mod_cache->mods);
        SR_CHECK_MEM_RET(!mem, err_info);
        mod_cache->mods = mem;
        ++mod_cache->mod_count;

        mod_cache->mods[i].ly_mod = mod->ly_mod;
        mod_cache->mods[i].ver = 0;
    }

    /* append current data */
    if (!mod_cache->mods[i].ver) {
        if (upd_mod_data) {
            /* current data were provided */
            if (mod_cache->data) {
                sr_ly_link(mod_cache->data, *upd_mod_data);
            } else {
                mod_cache->data = *upd_mod_data;
            }
            *upd_mod_data = NULL;
        } else {
            /* we need to load current data from persistent storage */
            if ((err_info = sr_module_config_data_append(mod->ly_mod, ds, &mod_cache->data))) {
                return err_info;
            }
        }
        mod_cache->mods[i].ver = mod->shm_mod->ver;

        /* CACHE WRITE UNLOCK */
        sr_rwunlock(&mod_cache->lock, 1);

        if (read_locked) {
            /* CACHE READ LOCK */
            if ((err_info = sr_rwlock(&mod_cache->lock, SR_MOD_CACHE_LOCK_TIMEOUT * 1000, 0, __func__))) {
                return err_info;
            }
        }
    }

    return NULL;
}

/**
 * @brief Load module data of a specific module.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] mod Mod info module to process.
 * @param[in] sid Sysrepo session ID.
 * @param[out] cb_error_info Callback error info returned by data-provide subscribers, if any.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_module_data_load(struct sr_mod_info_s *mod_info, struct sr_mod_info_mod_s *mod, sr_sid_t *sid,
        sr_error_info_t **cb_error_info)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_cache_s *mod_cache = NULL;
    struct lyd_node *mod_data;

    if (((mod_info->ds == SR_DS_RUNNING) || (mod_info->ds == SR_DS_OPERATIONAL))
            && (mod_info->conn->opts & SR_CONN_CACHE_RUNNING)) {
        /* we are caching, so in all cases load the module into cache if not yet there */
        mod_cache = &mod_info->conn->mod_cache;
        if ((err_info = sr_modcache_module_update(mod_cache, mod, mod_info->ds, NULL, mod_info->data_cached))) {
            return err_info;
        }
    }

    if (!mod_info->data_cached) {
        if (mod_cache) {
            assert((mod_info->ds == SR_DS_RUNNING) || (mod_info->ds == SR_DS_OPERATIONAL));

            /* we are caching, copy module data from the cache and link it */
            if (mod_info->ds == SR_DS_OPERATIONAL) {
                /* copy only enabled module data */
                if ((err_info = sr_module_oper_data_dup_enabled(mod_cache->data, mod_info->conn->main_shm.addr, mod, &mod_data))) {
                    return err_info;
                }
            } else {
                /* copy all module data */
                if ((err_info = sr_module_data_dup(mod_cache->data, mod->ly_mod, &mod_data))) {
                    return err_info;
                }
            }
            if (mod_info->data) {
                sr_ly_link(mod_info->data, mod_data);
            } else {
                mod_info->data = mod_data;
            }
        } else {
            /* get current persistent data */
            if ((err_info = sr_module_config_data_append(mod->ly_mod, mod_info->ds, &mod_info->data))) {
                return err_info;
            }

            if (mod_info->ds == SR_DS_OPERATIONAL) {
                /* keep only enabled module data */
                if ((err_info = sr_module_oper_data_dup_enabled(mod_info->data, mod_info->conn->main_shm.addr, mod, &mod_data))) {
                    return err_info;
                }
                lyd_free_withsiblings(sr_module_data_unlink(&mod_info->data, mod->ly_mod));
                if (mod_info->data) {
                    sr_ly_link(mod_info->data, mod_data);
                } else {
                    mod_info->data = mod_data;
                }
            }
        }

        if (mod_info->ds == SR_DS_OPERATIONAL) {
            /* append any operational data provided by clients */
            if ((err_info = sr_module_oper_data_update(mod, *sid, mod_info->conn->main_shm.addr, &mod_info->data, cb_error_info))) {
                return err_info;
            }
        }
    } else {
        assert(mod_cache && (mod_info->ds != SR_DS_OPERATIONAL));

        /* just use cached data */
        mod_info->data = mod_cache->data;
    }

    return NULL;
}

/**
 * @brief Add modules and data dependencies of instance-identifiers to mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] shm_deps SHM dependencies of relevant instance-identifiers.
 * @param[in] shm_dep_count SHM dependency count.
 * @param[in] sid Sysrepo session ID.
 * @param[out] cb_error_info Callback error info returned by data-rpovide subscribers, if any.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_add_instid_deps_data(struct sr_mod_info_s *mod_info, sr_mod_data_dep_t *shm_deps, uint16_t shm_dep_count,
        const struct lyd_node *data, sr_sid_t *sid, sr_error_info_t **cb_error_info)
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
        if ((j < mod_info->mod_count) && (err_info = sr_modinfo_module_data_load(mod_info, &mod_info->mods[j], sid,
                cb_error_info))) {
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
sr_modinfo_validate(struct sr_mod_info_s *mod_info, int finish_diff, sr_sid_t *sid, sr_error_info_t **cb_error_info)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *iter;
    struct sr_mod_info_mod_s *mod;
    struct lyd_difflist *diff = NULL;
    const struct lys_module **valid_mods;
    uint32_t i, j, valid_mod_count = 0;
    int flags;

    assert((mod_info->ds != SR_DS_OPERATIONAL) || (sid && cb_error_info));
    assert(!mod_info->data_cached);

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        switch (mod->state & MOD_INFO_TYPE_MASK) {
        case MOD_INFO_REQ:
            /* this module will be validated */
            ++valid_mod_count;

            if (mod->state & MOD_INFO_CHANGED) {
                /* check all instids and add their target modules as deps, other inst-ids do not need to be revalidated */
                if ((err_info = sr_modinfo_add_instid_deps_data(mod_info,
                        (sr_mod_data_dep_t *)(mod_info->conn->main_shm.addr + mod->shm_mod->data_deps),
                        mod->shm_mod->data_dep_count, mod_info->data, sid, cb_error_info))) {
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
        uint16_t shm_dep_count, int output, sr_sid_t *sid, sr_error_info_t **cb_error_info)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *top_op;
    struct ly_set *set = NULL;
    struct sr_mod_info_mod_s *mod;
    uint32_t i;
    char *parent_xpath = NULL;
    int flags;

    assert(op->schema->nodetype & (LYS_RPC | LYS_ACTION | LYS_NOTIF));
    assert((mod_info->ds == SR_DS_OPERATIONAL) && sid && cb_error_info);

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
    if ((err_info = sr_modinfo_add_instid_deps_data(mod_info, shm_deps, shm_dep_count, op, sid, cb_error_info))) {
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

sr_error_info_t *
sr_modinfo_data_load(struct sr_mod_info_s *mod_info, uint8_t mod_type, int cache, sr_sid_t *sid, sr_error_info_t **cb_error_info)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    uint32_t i;

    assert(!mod_info->data);
    assert((mod_info->ds != SR_DS_OPERATIONAL) || (sid && cb_error_info));

    if (cache && (mod_info->conn->opts & SR_CONN_CACHE_RUNNING) && (mod_info->ds == SR_DS_RUNNING)) {
        /* CACHE READ LOCK */
        if ((err_info = sr_rwlock(&mod_info->conn->mod_cache.lock, SR_MOD_CACHE_LOCK_TIMEOUT * 1000, 0, __func__))) {
            return err_info;
        }

        /* we can cache the data */
        mod_info->data_cached = 1;
    }

    /* load data for each module */
    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & mod_type) {
            if ((err_info = sr_modinfo_module_data_load(mod_info, mod, sid, cb_error_info))) {
                /* if cached, we keep both cache lock and flag, so it is fine */
                return err_info;
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

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & MOD_INFO_REQ) {
            if ((session->ev == SR_SUB_EV_NONE) && (session->ds != SR_DS_OPERATIONAL)) {
                if (mod_info->data_cached && (session->ds == SR_DS_RUNNING) && session->dt[SR_DS_RUNNING].edit) {
                    /* data will be changed, we cannot use the cache anymore */
                    mod_info->data = lyd_dup_withsiblings(mod_info->data, LYD_DUP_OPT_RECURSIVE | LYD_DUP_OPT_WITH_WHEN);
                    mod_info->data_cached = 0;

                    /* CACHE READ UNLOCK */
                    sr_rwunlock(&mod_info->conn->mod_cache.lock, 0);
                }

                /* apply any performed changes to get the session-specific data */
                if ((err_info = sr_edit_mod_apply(session->dt[session->ds].edit, mod->ly_mod, &mod_info->data, NULL))) {
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

sr_error_info_t *
sr_modinfo_data_store(struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL, *tmp_err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    struct lyd_node *mod_data;
    uint32_t i;

    assert(!mod_info->data_cached);

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & MOD_INFO_CHANGED) {
            /* separate data of this module */
            mod_data = sr_module_data_unlink(&mod_info->data, mod->ly_mod);

            /* store the new data */
            if ((tmp_err_info = sr_module_config_data_set(mod->ly_mod->name, mod_info->ds, mod_data))) {
                goto cleanup;
            }

            /* update module data version */
            ++mod->shm_mod->ver;

            if ((mod_info->conn->opts & SR_CONN_CACHE_RUNNING) && (mod_info->ds == SR_DS_RUNNING)) {
                /* we are caching so update cache with these data
                 * HACK data are simply removed from mod_info because they are no longer needed anyway (in current use-cases!) */
                tmp_err_info = sr_modcache_module_update(&mod_info->conn->mod_cache, mod, mod_info->ds, &mod_data, 0);
                if (tmp_err_info) {
                    /* always store all changed modules, if possible */
                    sr_errinfo_merge(&err_info, tmp_err_info);
                    tmp_err_info = NULL;
                }
            }

            /* connect them back */
            if (mod_info->data) {
                sr_ly_link(mod_info->data, mod_data);
            } else {
                mod_info->data = mod_data;
            }
        }
    }

cleanup:
    if (tmp_err_info) {
        sr_errinfo_merge(&err_info, tmp_err_info);
    }
    return err_info;

}

void
sr_modinfo_free(struct sr_mod_info_s *mod_info)
{
    lyd_free_withsiblings(mod_info->diff);
    if (mod_info->data_cached) {
        mod_info->data_cached = 0;

        /* CACHE READ UNLOCK */
        sr_rwunlock(&mod_info->conn->mod_cache.lock, 0);
    } else {
        lyd_free_withsiblings(mod_info->data);
    }

    free(mod_info->mods);
}
