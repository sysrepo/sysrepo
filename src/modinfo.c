/**
 * @file modinfo.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief routines for working with modinfo structure
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
#include <sys/cdefs.h>

#include "modinfo.h"

#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "common.h"
#include "edit_diff.h"
#include "log.h"
#include "lyd_mods.h"
#include "replay.h"
#include "shm.h"

sr_error_info_t *
sr_modinfo_perm_check(struct sr_mod_info_s *mod_info, int wr, int strict)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    uint32_t i;
    int has_access;

    /* it is simply not covered because we would have to also remove the failed permission check module data */
    assert(!mod_info->data || strict);

    i = 0;
    while (i < mod_info->mod_count) {
        mod = &mod_info->mods[i];

        /* check also modules additionally modified by validation */
        if (mod->state & (MOD_INFO_REQ | MOD_INFO_CHANGED)) {
            /* check perm */
            if ((err_info = sr_perm_check(mod->ly_mod->name, wr, strict ? NULL : &has_access))) {
                return err_info;
            }

            if (!strict && !has_access) {
                /* remove this module from mod_info by moving all succeding modules */
                SR_LOG_INF("No %s permission for the module \"%s\", skipping.", wr ? "write" : "read", mod->ly_mod->name);
                --mod_info->mod_count;
                if (!mod_info->mod_count) {
                    free(mod_info->mods);
                    mod_info->mods = NULL;
                } else if (i < mod_info->mod_count) {
                    memmove(&mod_info->mods[i], &mod_info->mods[i + 1], (mod_info->mod_count - i) * sizeof *mod);
                }
                continue;
            }
        }

        ++i;
    }

    return NULL;
}

struct sr_mod_info_mod_s *
sr_modinfo_next_mod(struct sr_mod_info_mod_s *last, struct sr_mod_info_s *mod_info, const struct lyd_node *data,
        uint32_t **aux)
{
    struct sr_mod_info_mod_s *mod;
    const struct lyd_node *node;
    uint32_t i;

    if (!last) {
        node = data;

        /* allocate aux array */
        *aux = calloc(mod_info->mod_count, sizeof **aux);
    } else {
        assert(data);

        /* find the last edit node */
        for (node = data; lyd_owner_module(node) != last->ly_mod; node = node->next) {}

next_mod:
        /* skip all edit nodes from this module */
        for ( ; node && (lyd_owner_module(node) == last->ly_mod); node = node->next) {}
    }

    if (node) {
        /* find mod of this edit node */
        mod = NULL;
        for (i = 0; i < mod_info->mod_count; ++i) {
            if (mod_info->mods[i].ly_mod == lyd_owner_module(node)) {
                mod = &mod_info->mods[i];
                break;
            }
        }

        if (!mod) {
            /* possible only for unknown opaque nodes, free the auxiliary array */
            free(*aux);
            *aux = NULL;
        } else if ((*aux)[i]) {
            /* already returned, continue search */
            last = mod;
            goto next_mod;
        } else {
            /* mark this mod as returned */
            (*aux)[i] = 1;
        }
    } else {
        mod = NULL;

        /* free the auxiliary array */
        free(*aux);
        *aux = NULL;
    }

    return mod;
}

sr_error_info_t *
sr_modinfo_edit_apply(struct sr_mod_info_s *mod_info, const struct lyd_node *edit, int create_diff)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    struct sr_mod_info_mod_s *mod = NULL;
    const struct lyd_node *node;
    uint32_t *aux = NULL;
    int change;
    struct sr_lyd_merge_cb_data cb_data;

    assert(!mod_info->data_cached);

    LY_LIST_FOR(edit, node) {
        ly_mod = lyd_owner_module(node);
        if (ly_mod && !strcmp(ly_mod->name, SR_YANG_MOD)) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Data of internal module \"%s\" cannot be modified.", SR_YANG_MOD);
            return err_info;
        }
    }

    while ((mod = sr_modinfo_next_mod(mod, mod_info, edit, &aux))) {
        assert(mod->state & MOD_INFO_REQ);

        if (mod_info->ds == SR_DS_OPERATIONAL) {
            /* prepare callback data */
            cb_data.cid = mod_info->conn->cid;
            cb_data.diff = create_diff ? &mod_info->diff : NULL;
            cb_data.changed = 0;
            cb_data.err_info = NULL;

            /* merge edit */
            if (lyd_merge_module(&mod_info->data, edit, mod->ly_mod, sr_lyd_merge_cb, &cb_data, 0)) {
                if (cb_data.err_info) {
                    err_info = cb_data.err_info;
                } else {
                    sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
                }
                goto cleanup;
            }

            if (cb_data.changed) {
                /* there is a diff for this module */
                mod->state |= MOD_INFO_CHANGED;
            }
        } else {
            /* apply relevant edit changes */
            if ((err_info = sr_edit_mod_apply(edit, mod->ly_mod, &mod_info->data, create_diff ? &mod_info->diff : NULL,
                    &change))) {
                goto cleanup;
            }

            if (change) {
                /* there is a diff for this module */
                mod->state |= MOD_INFO_CHANGED;
            }
        }
    }

cleanup:
    free(aux);
    return err_info;
}

sr_error_info_t *
sr_modinfo_diff_merge(struct sr_mod_info_s *mod_info, const struct lyd_node *new_diff)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    uint32_t i;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & MOD_INFO_REQ) {
            /* merge relevant diff part */
            if (lyd_diff_merge_module(&mod_info->diff, new_diff, mod->ly_mod, NULL, NULL, 0)) {
                sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
                return err_info;
            }
        }
    }

    return NULL;
}

sr_error_info_t *
sr_modinfo_replace(struct sr_mod_info_s *mod_info, struct lyd_node **src_data)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    struct lyd_node *src_mod_data, *dst_mod_data, *diff;
    uint32_t i;

    assert(!mod_info->diff && !mod_info->data_cached);

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & MOD_INFO_REQ) {
            dst_mod_data = sr_module_data_unlink(&mod_info->data, mod->ly_mod);
            src_mod_data = sr_module_data_unlink(src_data, mod->ly_mod);

            /* get diff on only this module's data */
            if (lyd_diff_siblings(dst_mod_data, src_mod_data, LYD_DIFF_DEFAULTS, &diff)) {
                sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
                lyd_free_all(dst_mod_data);
                lyd_free_all(src_mod_data);
                return err_info;
            }

            if (diff) {
                /* there is a diff */
                mod->state |= MOD_INFO_CHANGED;

                /* merge the diff */
                lyd_insert_sibling(mod_info->diff, diff, &mod_info->diff);

                /* update data */
                if (src_mod_data) {
                    lyd_insert_sibling(mod_info->data, src_mod_data, &mod_info->data);
                }
                lyd_free_all(dst_mod_data);
            } else {
                /* keep old data (for validation) */
                if (dst_mod_data) {
                    lyd_insert_sibling(mod_info->data, dst_mod_data, &mod_info->data);
                }
                lyd_free_all(src_mod_data);
            }
        }
    }

    return NULL;
}

sr_error_info_t *
sr_modinfo_changesub_rdlock(struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    uint32_t i, j;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & MOD_INFO_CHANGED) {
            /* CHANGE SUB READ LOCK */
            if ((err_info = sr_rwlock(&mod->shm_mod->change_sub[mod_info->ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT,
                    SR_LOCK_READ, mod_info->conn->cid, __func__, NULL, NULL))) {
                goto error;
            }
        }
    }

    return NULL;

error:
    for (j = 0; j < i; ++j) {
        mod = &mod_info->mods[i];
        if (mod->state & MOD_INFO_CHANGED) {
            /* CHANGE SUB READ UNLOCK */
            sr_rwunlock(&mod->shm_mod->change_sub[mod_info->ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ,
                    mod_info->conn->cid, __func__);
        }
    }
    return err_info;
}

void
sr_modinfo_changesub_rdunlock(struct sr_mod_info_s *mod_info)
{
    struct sr_mod_info_mod_s *mod;
    uint32_t i;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & MOD_INFO_CHANGED) {
            /* CHANGE SUB READ UNLOCK */
            sr_rwunlock(&mod->shm_mod->change_sub[mod_info->ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ,
                    mod_info->conn->cid, __func__);
        }
    }
}

/**
 * @brief Check whether operational data are required based on a predicate.
 *
 * @param[in] pred1 First predicate.
 * @param[in] len1 First predicate length.
 * @param[in] pred2 Second predicate.
 * @param[in] len2 Second predicate length.
 * @return 0 if not required, non-zero if required.
 */
static int
sr_xpath_oper_data_predicate_required(const char *pred1, int len1, const char *pred2, int len2)
{
    char quot1, quot2;
    const char *val1, *val2;

    /* node names */
    while (len1 && len2) {
        if (pred1[0] != pred2[0]) {
            /* different node names */
            return 1;
        }

        ++pred1;
        --len1;
        ++pred2;
        --len2;

        if ((pred1[0] == '=') && (pred2[0] == '=')) {
            break;
        }
    }
    if (!len1 || !len2) {
        /* not an equality expression */
        return 1;
    }

    ++pred1;
    --len1;
    ++pred2;
    --len2;

    /* we expect quotes now */
    if ((pred1[0] != '\'') && (pred1[0] != '\"')) {
        return 1;
    }
    if ((pred2[0] != '\'') && (pred2[0] != '\"')) {
        return 1;
    }
    quot1 = pred1[0];
    quot2 = pred2[0];

    ++pred1;
    --len1;
    ++pred2;
    --len2;

    /* values */
    val1 = pred1;
    while (len1) {
        if (pred1[0] == quot1) {
            break;
        }

        ++pred1;
        --len1;
    }

    val2 = pred2;
    while (len2) {
        if (pred2[0] == quot2) {
            break;
        }

        ++pred2;
        --len2;
    }

    if ((len1 != 1) || (len2 != 1)) {
        /* the predicate is not finished, leave it */
        return 1;
    }

    /* just compare values, we can decide based on that */
    if (!strncmp(val1, val2, (pred1 - val1 > pred2 - val2) ? pred1 - val1 : pred2 - val2)) {
        /* values match, we need this data */
        return 1;
    }

    /* values fo not match, these data would be flitered out */
    return 0;
}

/**
 * @brief Check whether operational data are required based on one request path and subscription path.
 *
 * @param[in] request_path Get request single path.
 * @param[in] sub_xpath Operational subscription XPath.
 * @return 0 if not required, non-zero if required.
 */
static int
sr_xpath_oper_data_path_required(const char *request_path, const char *sub_xpath)
{
    const char *path1, *path2, *mod1, *mod2, *name1, *name2, *pred1, *pred2;
    int wildc1, wildc2, mlen1, mlen2, len1, len2, dslash1, dslash2, has_pred1, has_pred2;

    path1 = request_path;
    path2 = sub_xpath;

    do {
        path1 = sr_xpath_next_name(path1, &mod1, &mlen1, &name1, &len1, &dslash1, &has_pred1);
        path2 = sr_xpath_next_name(path2, &mod2, &mlen2, &name2, &len2, &dslash2, &has_pred2);

        /* double-slash */
        if ((dslash1 && !dslash2) || (!dslash1 && dslash2)) {
            /* only one xpath includes '//', unable to check further */
            return 1;
        }
        if (dslash1 && dslash2) {
            if ((len1 == 1) && (name1[0] == '.')) {
                /* always matches all */
                return 1;
            }
            if ((len2 == 1) && (name2[0] == '.')) {
                /* always matches all */
                return 1;
            }
        }

        /* wildcards */
        if ((len1 == 1) && (name1[0] == '*')) {
            wildc1 = 1;
        } else {
            wildc1 = 0;
        }
        if ((len2 == 1) && (name2[0] == '*')) {
            wildc2 = 1;
        } else {
            wildc2 = 0;
        }

        /* module name */
        if ((mlen1 && mlen2) && ((mlen1 != mlen2) || strncmp(mod1, mod2, mlen1))) {
            /* different modules */
            return 0;
        }

        /* node name */
        if (!wildc1 && !wildc2 && ((len1 != len2) || strncmp(name1, name2, len1))) {
            /* different node names */
            return 0;
        }

        while (has_pred1 && has_pred2) {
            path1 = sr_xpath_next_predicate(path1, &pred1, &len1, &has_pred1);
            path2 = sr_xpath_next_predicate(path2, &pred2, &len2, &has_pred2);

            /* predicate */
            if (!sr_xpath_oper_data_predicate_required(pred1, len1, pred2, len2)) {
                /* not required based on the predicate */
                return 0;
            }
        }

        /* skip any leftover predicates */
        while (has_pred1) {
            path1 = sr_xpath_next_predicate(path1, NULL, NULL, &has_pred1);
        }
        while (has_pred2) {
            path2 = sr_xpath_next_predicate(path2, NULL, NULL, &has_pred2);
        }
    } while ((path1[0] == '/') && (path2[0] == '/'));

    /* whole path matches */
    return 1;
}

/**
 * @brief Check whether operational data are required.
 *
 * @param[in] request_xpath Get request full XPath.
 * @param[in] sub_xpath Operational subscription XPath.
 * @return 0 if not required, non-zero if required.
 */
static int
sr_xpath_oper_data_required(const char *request_xpath, const char *sub_xpath)
{
    int has_pred;

    assert(sub_xpath);

    if (!request_xpath) {
        /* we do not know, say it is required */
        return 1;
    }

    goto next_path;
    do {
        /* only union can be used to specify more paths, no? */
        assert(request_xpath[0] == '|');
        ++request_xpath;

next_path:
        /* skip whitespaces */
        while (isspace(request_xpath[0])) {
            ++request_xpath;
        }

        /* oper data are required for this path */
        if (sr_xpath_oper_data_path_required(request_xpath, sub_xpath)) {
            return 1;
        }

        /* skip this path */
        do {
            request_xpath = sr_xpath_next_name(request_xpath, NULL, NULL, NULL, NULL, NULL, &has_pred);
            while (has_pred) {
                request_xpath = sr_xpath_next_predicate(request_xpath, NULL, NULL, &has_pred);
            }
        } while (request_xpath[0] == '/');

        /* skip whitespaces */
        while (isspace(request_xpath[0])) {
            ++request_xpath;
        }

        /* no more paths */
    } while (request_xpath[0]);

    /* oper data not required for any single path, so not at all */
    return 0;
}

/**
 * @brief Get specific operational data from a subscriber.
 *
 * @param[in] ly_mod libyang module of the data.
 * @param[in] xpath XPath of the provided data.
 * @param[in] request_xpath XPath of the data request.
 * @param[in] orig_name Event originator name.
 * @param[in] orig_data Event originator data.
 * @param[in] evpipe_num Subscriber event pipe number.
 * @param[in] parent Data parent required for the subscription, NULL if top-level.
 * @param[in] timeout_ms Operational callback timeout in milliseconds.
 * @param[in] cid Connection ID.
 * @param[out] data Data tree with appended operational data.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_xpath_oper_data_get(const struct lys_module *ly_mod, const char *xpath, const char *request_xpath, const char *orig_name,
        const void *orig_data, uint32_t evpipe_num, const struct lyd_node *parent, uint32_t timeout_ms, sr_cid_t cid,
        struct lyd_node **oper_data)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    struct lyd_node *parent_dup = NULL, *last_parent;
    char *parent_path = NULL;

    *oper_data = NULL;

    if (parent) {
        /* duplicate parent so that it is a stand-alone subtree */
        if (lyd_dup_single(parent, NULL, LYD_DUP_WITH_PARENTS, &last_parent)) {
            sr_errinfo_new_ly(&err_info, ly_mod->ctx);
            return err_info;
        }

        /* go top-level */
        for (parent_dup = last_parent; parent_dup->parent; parent_dup = lyd_parent(parent_dup)) {}

        if (request_xpath) {
            /* check whether the parent would not be filtered out */
            parent_path = lyd_path(last_parent, LYD_PATH_STD, NULL, 0);
            SR_CHECK_MEM_GOTO(!parent_path, err_info, cleanup);

            if (!sr_xpath_oper_data_required(request_xpath, parent_path)) {
                goto cleanup;
            }
        }
    }

    /* get data from client */
    if ((err_info = sr_shmsub_oper_notify(ly_mod, xpath, request_xpath, parent_dup, orig_name, orig_data, evpipe_num,
            timeout_ms, cid, oper_data, &cb_err_info))) {
        goto cleanup;
    }

    /* return callback error if some was generated */
    if (cb_err_info) {
        sr_errinfo_merge(&err_info, cb_err_info);
        sr_errinfo_new(&err_info, SR_ERR_CALLBACK_FAILED, "User callback failed.");
        goto cleanup;
    }

    if (*oper_data) {
        /* add any missing NP containers, redundant to add top-level containers */
        if (lyd_new_implicit_tree(*oper_data, LYD_IMPLICIT_NO_DEFAULTS, NULL)) {
            sr_errinfo_new_ly(&err_info, ly_mod->ctx);
            goto cleanup;
        }
    }

cleanup:
    lyd_free_tree(parent_dup);
    free(parent_path);
    return err_info;
}

/**
 * @brief Update (replace or append) operational data for a specific module.
 *
 * @param[in] mod Mod info module to process.
 * @param[in] oper_mode Current lock mode of @p mod for ::SR_DS_OPERATIONAL.
 * @param[in] orig_name Event originator name.
 * @param[in] orig_data Event originator data.
 * @param[in] conn Connection to use.
 * @param[in] request_xpath XPath of the data request.
 * @param[in] timeout_ms Operational callback timeout in milliseconds.
 * @param[in] opts Get oper data options.
 * @param[in,out] data Operational data tree.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_module_oper_data_update(struct sr_mod_info_mod_s *mod, const char *orig_name, const void *orig_data, sr_conn_ctx_t *conn,
        const char *request_xpath, uint32_t timeout_ms, sr_get_oper_options_t opts, struct lyd_node **data)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_oper_sub_t *shm_sub;
    const char *sub_xpath;
    char *parent_xpath = NULL;
    uint32_t i, j;
    struct ly_set *set = NULL;
    struct lyd_node *edit = NULL, *oper_data;

    if (!(opts & SR_OPER_NO_STORED)) {
        /* apply stored operational edit */
        if ((err_info = sr_module_file_oper_data_load(mod, &edit))) {
            return err_info;
        }
        err_info = sr_edit_mod_apply(edit, mod->ly_mod, data, NULL, NULL);
        lyd_free_all(edit);
        if (err_info) {
            return err_info;
        }
    }

    if (opts & SR_OPER_NO_SUBS) {
        /* do not get data from subscribers */
        return NULL;
    }

    assert(timeout_ms);

    /* OPER SUB READ LOCK */
    if ((err_info = sr_rwlock(&mod->shm_mod->oper_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__,
            NULL, NULL))) {
        return err_info;
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        goto cleanup_opersub_unlock;
    }

    /* XPaths are ordered based on depth */
    i = 0;
    while (i < mod->shm_mod->oper_sub_count) {
        shm_sub = &((sr_mod_oper_sub_t *)(conn->ext_shm.addr + mod->shm_mod->oper_subs))[i];
        sub_xpath = conn->ext_shm.addr + shm_sub->xpath;

        /* check subscription aliveness */
        if (!sr_conn_is_alive(shm_sub->cid)) {
            /* recover the subscription */
            if ((err_info = sr_shmext_oper_sub_stop(conn, mod->shm_mod, i, 1, SR_LOCK_READ, 1))) {
                sr_errinfo_free(&err_info);
            }
            continue;
        }

        /* skip suspsended subscriptions */
        if (ATOMIC_LOAD_RELAXED(shm_sub->suspended)) {
            continue;
        }

        /* useless to retrieve configuration data, state data, or filtered out data */
        if (((shm_sub->sub_type == SR_OPER_SUB_CONFIG) && (opts & SR_OPER_NO_CONFIG)) ||
                ((shm_sub->sub_type == SR_OPER_SUB_STATE) && (opts & SR_OPER_NO_STATE)) ||
                !sr_xpath_oper_data_required(request_xpath, sub_xpath)) {
            ++i;
            continue;
        }

        /* remove any present data */
        if (!(shm_sub->opts & SR_SUBSCR_OPER_MERGE) && (err_info = sr_lyd_xpath_complement(data, sub_xpath))) {
            goto cleanup_opersub_ext_unlock;
        }

        /* trim the last node to get the parent */
        if ((err_info = sr_xpath_trim_last_node(sub_xpath, &parent_xpath))) {
            goto cleanup_opersub_ext_unlock;
        }

        if (parent_xpath) {
            if (!*data) {
                /* parent does not exist for sure */
                goto next_iter;
            }

            if (lyd_find_xpath(*data, parent_xpath, &set)) {
                sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx);
                goto cleanup_opersub_ext_unlock;
            }

            if (!set->count) {
                /* data parent does not exist */
                goto next_iter;
            }

            /* nested data */
            for (j = 0; j < set->count; ++j) {
                /* get oper data from the client */
                if ((err_info = sr_xpath_oper_data_get(mod->ly_mod, sub_xpath, request_xpath, orig_name, orig_data,
                        shm_sub->evpipe_num, set->dnodes[j], timeout_ms, conn->cid, &oper_data))) {
                    goto cleanup_opersub_ext_unlock;
                }

                /* merge into one data tree */
                if (lyd_merge_siblings(data, oper_data, LYD_MERGE_DESTRUCT)) {
                    lyd_free_all(oper_data);
                    sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx);
                    goto cleanup_opersub_ext_unlock;
                }
            }

next_iter:
            /* cleanup for next iteration */
            free(parent_xpath);
            parent_xpath = NULL;
            ly_set_free(set, NULL);
            set = NULL;
        } else {
            /* top-level data */
            if ((err_info = sr_xpath_oper_data_get(mod->ly_mod, sub_xpath, request_xpath, orig_name, orig_data,
                    shm_sub->evpipe_num, NULL, timeout_ms, conn->cid, &oper_data))) {
                goto cleanup_opersub_ext_unlock;
            }

            if (lyd_merge_siblings(data, oper_data, LYD_MERGE_DESTRUCT)) {
                lyd_free_all(oper_data);
                sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx);
                goto cleanup_opersub_ext_unlock;
            }
        }

        ++i;
    }

    /* success */

cleanup_opersub_ext_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

cleanup_opersub_unlock:
    /* OPER SUB READ UNLOCK */
    sr_rwunlock(&mod->shm_mod->oper_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

    free(parent_xpath);
    ly_set_free(set, NULL);
    return err_info;
}

/**
 * @brief Get operational (enabled) data from configuration data tree.
 *
 * @param[in] conn Connection to use.
 * @param[in,out] data Configuration data, are unlinked from if @p dup is 0.
 * @param[in] mod Mod info module to process.
 * @param[in] opts Get oper data options.
 * @param[in] dup Whether to duplicate data or only unlink.
 * @param[out] enabled_mod_data Enabled operational data of the module.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_module_oper_data_get_enabled(sr_conn_ctx_t *conn, struct lyd_node **data, struct sr_mod_info_mod_s *mod,
        sr_get_oper_options_t opts, int dup, struct lyd_node **enabled_mod_data)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_change_sub_t *shm_changesubs;
    struct lyd_node *root, *elem;
    uint32_t i, xp_i;
    int data_ready = 0;
    char **xpaths;
    const char *origin;

    /* start with NP containers, which cannot effectively be disabled */
    *enabled_mod_data = NULL;
    if ((err_info = sr_lyd_dup_module_np_cont(*data, mod->ly_mod, 1, enabled_mod_data))) {
        return err_info;
    }

    if (!*data) {
        /* no enabled data */
        data_ready = 1;
    }

    /* CHANGE SUB READ LOCK */
    if ((err_info = sr_rwlock(&mod->shm_mod->change_sub[SR_DS_RUNNING].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT,
            SR_LOCK_READ, conn->cid, __func__, NULL, NULL))) {
        return err_info;
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        goto error_sub_unlock;
    }

    if (!data_ready) {
        /* try to find a subscription for the whole module */
        shm_changesubs = (sr_mod_change_sub_t *)(conn->ext_shm.addr + mod->shm_mod->change_sub[SR_DS_RUNNING].subs);
        for (i = 0; i < mod->shm_mod->change_sub[SR_DS_RUNNING].sub_count; ++i) {
            if (!shm_changesubs[i].xpath && !(shm_changesubs[i].opts & SR_SUBSCR_PASSIVE)) {
                /* the whole module is enabled */
                if ((err_info = sr_lyd_get_module_data(data, mod->ly_mod, 1, dup, enabled_mod_data))) {
                    goto error_ext_sub_unlock;
                }
                data_ready = 1;
                break;
            }
        }
    }

    if (!data_ready) {
        /* collect all enabled subtress in the form of xpaths */
        xpaths = NULL;
        for (i = 0, xp_i = 0; i < mod->shm_mod->change_sub[SR_DS_RUNNING].sub_count; ++i) {
            if (shm_changesubs[i].xpath && !(shm_changesubs[i].opts & SR_SUBSCR_PASSIVE)) {
                xpaths = sr_realloc(xpaths, (xp_i + 1) * sizeof *xpaths);
                SR_CHECK_MEM_GOTO(!xpaths, err_info, error_ext_sub_unlock);

                xpaths[xp_i] = conn->ext_shm.addr + shm_changesubs[i].xpath;
                ++xp_i;
            }
        }

        /* get only enabled subtrees */
        err_info = sr_lyd_get_enabled_xpath(data, xpaths, xp_i, dup, enabled_mod_data);
        free(xpaths);
        if (err_info) {
            goto error_ext_sub_unlock;
        }
    }

    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

    /* CHANGE SUB READ UNLOCK */
    sr_rwunlock(&mod->shm_mod->change_sub[SR_DS_RUNNING].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

    if (opts & SR_OPER_WITH_ORIGIN) {
        LY_LIST_FOR(*enabled_mod_data, root) {
            /* add origin of all top-level nodes */
            origin = (root->schema->flags & LYS_CONFIG_W) ? SR_CONFIG_ORIGIN : SR_OPER_ORIGIN;
            if ((err_info = sr_edit_diff_set_origin(root, origin, 1))) {
                return err_info;
            }

            LYD_TREE_DFS_BEGIN(root, elem) {
                /* add origin of default nodes instead of the default flag */
                if ((elem->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST)) && (elem->flags & LYD_DEFAULT)) {
                    if ((err_info = sr_edit_diff_set_origin(elem, "ietf-origin:default", 1))) {
                        return err_info;
                    }
                    elem->flags &= ~LYD_DEFAULT;
                }
                LYD_TREE_DFS_END(root, elem);
            }
        }
    }

    return NULL;

error_ext_sub_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

error_sub_unlock:
    /* CHANGE SUB READ UNLOCK */
    sr_rwunlock(&mod->shm_mod->change_sub[SR_DS_RUNNING].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

    return err_info;
}

/**
 * @brief Update cached running module data (if required).
 *
 * @param[in] mod_cache Module cache.
 * @param[in] mod Mod info module to process.
 * @param[in] upd_mod_data Optional current (updated) module data to store in cache.
 * @param[in] read_locked Whether the cache is READ locked.
 * @param[in] cid Connection ID.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modcache_module_running_update(struct sr_mod_cache_s *mod_cache, struct sr_mod_info_mod_s *mod,
        const struct lyd_node *upd_mod_data, int read_locked, sr_cid_t cid)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *mod_data;
    sr_lock_mode_t cur_mode = SR_LOCK_NONE;
    uint32_t i;
    void *mem;

    if (read_locked) {
        /* CACHE READ UNLOCK */
        sr_rwunlock(&mod_cache->lock, SR_MOD_CACHE_LOCK_TIMEOUT, SR_LOCK_READ, cid, __func__);
    }

    /* CACHE READ UPGR LOCK */
    if ((err_info = sr_rwlock(&mod_cache->lock, SR_MOD_CACHE_LOCK_TIMEOUT, SR_LOCK_READ_UPGR, cid, __func__,
            NULL, NULL))) {
        goto cleanup;
    }
    cur_mode = SR_LOCK_READ_UPGR;

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
            /* CACHE WRITE LOCK UPGRADE */
            if ((err_info = sr_rwrelock(&mod_cache->lock, SR_MOD_CACHE_LOCK_TIMEOUT, SR_LOCK_WRITE, cid, __func__,
                    NULL, NULL))) {
                goto cleanup;
            }
            cur_mode = SR_LOCK_WRITE;

            /* data needs to be updated, remove old data */
            lyd_free_all(sr_module_data_unlink(&mod_cache->data, mod->ly_mod));
            mod_cache->mods[i].ver = 0;
        }
    } else {
        /* CACHE WRITE LOCK UPGRADE */
        if ((err_info = sr_rwrelock(&mod_cache->lock, SR_MOD_CACHE_LOCK_TIMEOUT, SR_LOCK_WRITE, cid, __func__,
                NULL, NULL))) {
            goto cleanup;
        }
        cur_mode = SR_LOCK_WRITE;

        /* module is not in cache yet, add an item */
        mem = realloc(mod_cache->mods, (i + 1) * sizeof *mod_cache->mods);
        SR_CHECK_MEM_GOTO(!mem, err_info, cleanup);
        mod_cache->mods = mem;
        ++mod_cache->mod_count;

        mod_cache->mods[i].ly_mod = mod->ly_mod;
        mod_cache->mods[i].ver = 0;
    }

    /* append current data */
    if (!mod_cache->mods[i].ver) {
        if (upd_mod_data) {
            /* current data were provided, use them */
            if (lyd_dup_siblings(upd_mod_data, NULL, LYD_DUP_RECURSIVE | LYD_DUP_WITH_FLAGS, &mod_data)) {
                sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx);
                goto cleanup;
            }
            lyd_insert_sibling(mod_cache->data, mod_data, &mod_cache->data);
        } else {
            /* we need to load current data from persistent storage */
            if ((err_info = sr_module_file_data_append(mod->ly_mod, SR_DS_RUNNING, &mod_cache->data))) {
                goto cleanup;
            }
        }
        mod_cache->mods[i].ver = mod->shm_mod->ver;
    }

cleanup:
    if (cur_mode != SR_LOCK_NONE) {
        /* CACHE UNLOCK */
        sr_rwunlock(&mod_cache->lock, SR_MOD_CACHE_LOCK_TIMEOUT, cur_mode, cid, __func__);
    }

    if (read_locked) {
        /* CACHE READ LOCK */
        if ((err_info = sr_rwlock(&mod_cache->lock, SR_MOD_CACHE_LOCK_TIMEOUT, SR_LOCK_READ, cid, __func__,
                NULL, NULL))) {
            return err_info;
        }
    }

    return err_info;
}

/**
 * @brief Trim all configuration/state nodes/origin from the data based on options.
 *
 * @param[in,out] data Data to trim.
 * @param[in] sibling First sibling of the current data to trim.
 * @param[in] opts Get oper data options.
 */
static void
sr_oper_data_trim_r(struct lyd_node **data, struct lyd_node *sibling, sr_get_oper_options_t opts)
{
    struct lyd_node *next, *elem;
    struct lyd_meta *meta;

    if (!(opts & (SR_OPER_NO_STATE | SR_OPER_NO_CONFIG)) && (opts & SR_OPER_WITH_ORIGIN)) {
        /* nothing to trim */
        return;
    }

    LY_LIST_FOR_SAFE(sibling, next, elem) {
        assert((elem->schema->nodetype != LYS_LEAF) || !(elem->schema->flags & LYS_KEY));
        if (elem->schema->flags & LYS_CONFIG_R) {
            /* state subtree */
            if (opts & SR_OPER_NO_STATE) {
                /* free it whole */
                if (*data == elem) {
                    *data = (*data)->next;
                }
                lyd_free_tree(elem);
                continue;
            }

            if (opts & SR_OPER_WITH_ORIGIN) {
                /* no need to go into state children */
                continue;
            }
        }

        /* trim all our children */
        sr_oper_data_trim_r(data, lyd_child_no_keys(elem), opts);

        if ((elem->schema->flags & LYS_CONFIG_W) && (opts & SR_OPER_NO_CONFIG) && !lyd_child_no_keys(elem)) {
            /* config-only subtree (config node with no children) */
            if (*data == elem) {
                *data = (*data)->next;
            }
            lyd_free_tree(elem);
            continue;
        }

        if (!(opts & SR_OPER_WITH_ORIGIN)) {
            /* trim origin */
            LY_LIST_FOR(elem->meta, meta) {
                if (!strcmp(meta->name, "origin") && !strcmp(meta->annotation->module->name, "ietf-origin")) {
                    lyd_free_meta_single(meta);
                    break;
                }
            }
        }
    }
}

/**
 * @brief Load module data of the ietf-yang-library module. They are actually generated.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] mod Mod info module to use.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_module_data_load_yanglib(struct sr_mod_info_s *mod_info, struct sr_mod_info_mod_s *mod)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *mod_data;
    uint32_t content_id;

    /* get content-id */
    if ((err_info = sr_lydmods_get_content_id(SR_CONN_MAIN_SHM(mod_info->conn), mod_info->conn->ly_ctx, &content_id))) {
        return err_info;
    }

    /* get the data from libyang */
    SR_CHECK_LY_RET(ly_ctx_get_yanglib_data(mod_info->conn->ly_ctx, &mod_data, "%" PRIu32, content_id),
            mod_info->conn->ly_ctx, err_info);

    if (!strcmp(mod->ly_mod->revision, "2019-01-04")) {
        assert(!strcmp(mod_data->schema->name, "yang-library"));

        /* add supported datastores */
        if (lyd_new_path(mod_data, NULL, "datastore[name='ietf-datastores:running']/schema", "complete", 0, 0) ||
                lyd_new_path(mod_data, NULL, "datastore[name='ietf-datastores:candidate']/schema", "complete", 0, 0) ||
                lyd_new_path(mod_data, NULL, "datastore[name='ietf-datastores:startup']/schema", "complete", 0, 0) ||
                lyd_new_path(mod_data, NULL, "datastore[name='ietf-datastores:operational']/schema", "complete", 0, 0)) {
            sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
            return err_info;
        }
    } else if (!strcmp(mod->ly_mod->revision, "2016-06-21")) {
        assert(!strcmp(mod_data->schema->name, "modules-state"));

        /* all data should already be there */
    } else {
        /* no other revision is supported */
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

    /* connect to the rest of data */
    if (lyd_merge_siblings(&mod_info->data, mod_data, LYD_MERGE_DESTRUCT)) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
        return err_info;
    }

    return NULL;
}

/**
 * @brief Add held datastore-specific lock nodes to a data tree.
 *
 * @param[in] rwlock Lock to read CIDs from.
 * @param[in] skip_read_cid Sysrepo CID to skip a read lock once for, no skipped if 0.
 * @param[in] path_format Path string used for lyd_new_path() after printing specific CID into it.
 * @param[in] ctx_node Context node to use for lyd_new_path().
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_module_srmon_locks_ds(sr_rwlock_t *rwlock, uint32_t skip_read_cid, const char *path_format,
        struct lyd_node *ctx_node)
{
    sr_error_info_t *err_info = NULL;
    sr_cid_t cid;
    uint32_t i;
    int ret;

#define PATH_LEN 128
    char path[PATH_LEN];
    struct ly_ctx *ly_ctx;

    ly_ctx = (struct ly_ctx *)LYD_CTX(ctx_node);

    if ((cid = rwlock->writer)) {
        snprintf(path, PATH_LEN, path_format, cid);
        SR_CHECK_LY_RET(lyd_new_path(ctx_node, NULL, path, "write", 0, NULL), ly_ctx, err_info);
    }
    if ((cid = rwlock->upgr)) {
        snprintf(path, PATH_LEN, path_format, cid);
        SR_CHECK_LY_RET(lyd_new_path(ctx_node, NULL, path, "read-upgr", 0, NULL), ly_ctx, err_info);
    }

    /* READ MUTEX LOCK */
    ret = pthread_mutex_lock(&rwlock->r_mutex);
    if (ret) {
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

    for (i = 0; (i < SR_RWLOCK_READ_LIMIT) && rwlock->readers[i]; ++i) {
        if (skip_read_cid == rwlock->readers[i]) {
            skip_read_cid = 0;
            continue;
        }

        snprintf(path, PATH_LEN, path_format, rwlock->readers[i]);
        if (lyd_new_path(ctx_node, NULL, path, "read", 0, NULL)) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            break;
        }
    }

    /* READ MUTEX UNLOCK */
    pthread_mutex_unlock(&rwlock->r_mutex);

    return err_info;
#undef PATH_LEN
}

/**
 * @brief Add held lock nodes (cid, mode) to a data tree.
 *
 * @param[in] rwlock Lock to read CIDs from.
 * @param[in] list_name List node name to create.
 * @param[in] parent Parent node of the new node @p list_name\.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_module_srmon_locks(sr_rwlock_t *rwlock, const char *list_name, struct lyd_node *parent)
{
    sr_error_info_t *err_info = NULL;
    sr_cid_t cid;
    uint32_t i;
    int ret;

#define CID_STR_LEN 64
    char cid_str[CID_STR_LEN];
    struct lyd_node *list;
    struct ly_ctx *ly_ctx;

    ly_ctx = (struct ly_ctx *)LYD_CTX(parent);

    if ((cid = rwlock->writer)) {
        /* list instance */
        SR_CHECK_LY_RET(lyd_new_list(parent, NULL, list_name, 0, &list), ly_ctx, err_info);

        /* cid */
        snprintf(cid_str, CID_STR_LEN, "%" PRIu32, cid);
        SR_CHECK_LY_RET(lyd_new_term(list, NULL, "cid", cid_str, 0, NULL), ly_ctx, err_info);

        /* mode */
        SR_CHECK_LY_RET(lyd_new_term(list, NULL, "mode", "write", 0, NULL), ly_ctx, err_info);
    }
    if ((cid = rwlock->upgr)) {
        SR_CHECK_LY_RET(lyd_new_list(parent, NULL, list_name, 0, &list), ly_ctx, err_info);

        snprintf(cid_str, CID_STR_LEN, "%" PRIu32, cid);
        SR_CHECK_LY_RET(lyd_new_term(list, NULL, "cid", cid_str, 0, NULL), ly_ctx, err_info);

        SR_CHECK_LY_RET(lyd_new_term(list, NULL, "mode", "read-upgr", 0, NULL), ly_ctx, err_info);
    }

    /* READ MUTEX LOCK */
    ret = pthread_mutex_lock(&rwlock->r_mutex);
    if (ret) {
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

    for (i = 0; (i < SR_RWLOCK_READ_LIMIT) && rwlock->readers[i]; ++i) {
        SR_CHECK_LY_GOTO(lyd_new_list(parent, NULL, list_name, 0, &list), ly_ctx, err_info, cleanup);

        snprintf(cid_str, CID_STR_LEN, "%" PRIu32, rwlock->readers[i]);
        SR_CHECK_LY_GOTO(lyd_new_term(list, NULL, "cid", cid_str, 0, NULL), ly_ctx, err_info, cleanup);

        SR_CHECK_LY_GOTO(lyd_new_term(list, NULL, "mode", "read", 0, NULL), ly_ctx, err_info, cleanup);
    }

cleanup:
    /* READ MUTEX UNLOCK */
    pthread_mutex_unlock(&rwlock->r_mutex);

    return err_info;
#undef CID_STR_LEN
}

/**
 * @brief Append a "module" data node with its subscriptions to sysrepo-monitoring data.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module to read from.
 * @param[in,out] sr_state Main container node of sysrepo-monitoring.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_module_srmon_module(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, struct lyd_node *sr_state)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mod, *sr_subs, *sr_sub, *sr_ds_lock;
    sr_datastore_t ds;
    sr_mod_change_sub_t *change_sub;
    sr_mod_oper_sub_t *oper_sub;
    sr_mod_notif_sub_t *notif_sub;
    struct sr_mod_lock_s *shm_lock;
    uint32_t i;

#define BUF_LEN 128
    char buf[BUF_LEN], *str = NULL;
    const struct ly_ctx *ly_ctx;

    ly_ctx = LYD_CTX(sr_state);

    /* module with name */
    SR_CHECK_LY_RET(lyd_new_list(sr_state, NULL, "module", 0, &sr_mod, conn->main_shm.addr + shm_mod->name), ly_ctx,
            err_info);

    for (ds = 0; ds < SR_DS_COUNT; ++ds) {
        shm_lock = &shm_mod->data_lock_info[ds];

        /* MOD READ LOCK */
        if ((err_info = sr_rwlock(&shm_lock->data_lock, SR_MOD_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__, NULL,
                NULL))) {
            return err_info;
        }

        /* data-lock */
        snprintf(buf, BUF_LEN, "data-lock[cid='%%" PRIu32 "'][datastore='%s']/mode", sr_ds2ident(ds));
        err_info = sr_modinfo_module_srmon_locks_ds(&shm_lock->data_lock, conn->cid, buf, sr_mod);

        /* MOD READ UNLOCK */
        sr_rwunlock(&shm_lock->data_lock, SR_MOD_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

        if (err_info) {
            return err_info;
        }

        /* DS LOCK */
        if ((err_info = sr_mlock(&shm_lock->ds_lock, SR_DS_LOCK_TIMEOUT, __func__, NULL, NULL))) {
            return err_info;
        }

        if (shm_lock->ds_lock_sid) {
            /* ds-lock (list instance with datastore) */
            SR_CHECK_LY_GOTO(lyd_new_list(sr_mod, NULL, "ds-lock", 0, &sr_ds_lock, sr_ds2ident(ds)), ly_ctx, err_info,
                    ds_unlock);

            /* sid */
            sprintf(buf, "%" PRIu32, shm_lock->ds_lock_sid);
            SR_CHECK_LY_GOTO(lyd_new_term(sr_ds_lock, NULL, "sid", buf, 0, NULL), ly_ctx, err_info, ds_unlock);

            /* timestamp */
            if (ly_time_ts2str(&shm_lock->ds_lock_ts, &str)) {
                SR_ERRINFO_MEM(&err_info);
                goto ds_unlock;
            }
            SR_CHECK_LY_GOTO(lyd_new_term(sr_ds_lock, NULL, "timestamp", str, 0, NULL), ly_ctx, err_info, ds_unlock);
        }

ds_unlock:
        /* DS UNLOCK */
        sr_munlock(&shm_lock->ds_lock);

        free(str);
        str = NULL;
        if (err_info) {
            return err_info;
        }
    }

    /* change-sub-lock */
    for (ds = 0; ds < SR_DS_COUNT; ++ds) {
        snprintf(buf, BUF_LEN, "change-sub-lock[cid='%%" PRIu32 "'][datastore='%s']/mode", sr_ds2ident(ds));
        if ((err_info = sr_modinfo_module_srmon_locks_ds(&shm_mod->change_sub[ds].lock, 0, buf, sr_mod))) {
            return err_info;
        }
    }
#undef BUF_LEN

    /* oper-sub-lock */
    if ((err_info = sr_modinfo_module_srmon_locks(&shm_mod->oper_lock, "oper-sub-lock", sr_mod))) {
        return err_info;
    }

    /* notif-sub-lock */
    if ((err_info = sr_modinfo_module_srmon_locks(&shm_mod->notif_lock, "notif-sub-lock", sr_mod))) {
        return err_info;
    }

    /* subscriptions, make implicit */
    SR_CHECK_LY_RET(lyd_new_inner(sr_mod, NULL, "subscriptions", 0, &sr_subs), ly_ctx, err_info);
    sr_subs->flags |= LYD_DEFAULT;

    for (ds = 0; ds < SR_DS_COUNT; ++ds) {
        change_sub = (sr_mod_change_sub_t *)(conn->ext_shm.addr + shm_mod->change_sub[ds].subs);
        for (i = 0; i < shm_mod->change_sub[ds].sub_count; ++i) {
            /* change-sub */
            SR_CHECK_LY_RET(lyd_new_list(sr_subs, NULL, "change-sub", 0, &sr_sub), ly_ctx, err_info);

            /* datastore */
            SR_CHECK_LY_RET(lyd_new_term(sr_sub, NULL, "datastore", sr_ds2ident(ds), 0, NULL), ly_ctx, err_info);

            /* xpath */
            if (change_sub[i].xpath) {
                SR_CHECK_LY_RET(lyd_new_term(sr_sub, NULL, "xpath", conn->ext_shm.addr + change_sub[i].xpath, 0, NULL),
                        ly_ctx, err_info);
            }

            /* priority */
            sprintf(buf, "%" PRIu32, change_sub[i].priority);
            SR_CHECK_LY_RET(lyd_new_term(sr_sub, NULL, "priority", buf, 0, NULL), ly_ctx, err_info);

            /* cid */
            sprintf(buf, "%" PRIu32, change_sub[i].cid);
            SR_CHECK_LY_RET(lyd_new_term(sr_sub, NULL, "cid", buf, 0, NULL), ly_ctx, err_info);
        }
    }

    oper_sub = (sr_mod_oper_sub_t *)(conn->ext_shm.addr + shm_mod->oper_subs);
    for (i = 0; i < shm_mod->oper_sub_count; ++i) {
        /* operational-sub with xpath */
        SR_CHECK_LY_RET(lyd_new_list(sr_subs, NULL, "operational-sub", 0, &sr_sub, conn->ext_shm.addr + oper_sub[i].xpath),
                ly_ctx, err_info);

        /* cid */
        sprintf(buf, "%" PRIu32, oper_sub[i].cid);
        SR_CHECK_LY_RET(lyd_new_term(sr_sub, NULL, "cid", buf, 0, NULL), ly_ctx, err_info);
    }

    notif_sub = (sr_mod_notif_sub_t *)(conn->ext_shm.addr + shm_mod->notif_subs);
    for (i = 0; i < shm_mod->notif_sub_count; ++i) {
        /* notification-sub with cid */
        sprintf(buf, "%" PRIu32, notif_sub[i].cid);
        SR_CHECK_LY_RET(lyd_new_term(sr_subs, NULL, "notification-sub", buf, 0, NULL), ly_ctx, err_info);
    }

    return NULL;
}

/**
 * @brief Append an "rpc" data node with its subscriptions to sysrepo-monitoring data.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_rpc SHM RPC to read from.
 * @param[in,out] sr_state Main container node of sysrepo-monitoring.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_module_srmon_rpc(sr_conn_ctx_t *conn, sr_rpc_t *shm_rpc, struct lyd_node *sr_state)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_rpc, *sr_sub;
    sr_mod_rpc_sub_t *rpc_sub;
    uint32_t i;
    char buf[22];
    const struct ly_ctx *ly_ctx;

    ly_ctx = LYD_CTX(sr_state);

    /* rpc with path */
    SR_CHECK_LY_RET(lyd_new_list(sr_state, NULL, "rpc", 0, &sr_rpc, conn->main_shm.addr + shm_rpc->path), ly_ctx, err_info);

    /* sub-lock */
    if ((err_info = sr_modinfo_module_srmon_locks(&shm_rpc->lock, "sub-lock", sr_rpc))) {
        return err_info;
    }

    rpc_sub = (sr_mod_rpc_sub_t *)(conn->ext_shm.addr + shm_rpc->subs);
    for (i = 0; i < shm_rpc->sub_count; ++i) {
        /* rpc-sub */
        SR_CHECK_LY_RET(lyd_new_list(sr_rpc, NULL, "rpc-sub", 0, &sr_sub), ly_ctx, err_info);

        /* xpath */
        SR_CHECK_LY_RET(lyd_new_term(sr_sub, NULL, "xpath", conn->ext_shm.addr + rpc_sub[i].xpath, 0, NULL),
                ly_ctx, err_info);

        /* priority */
        sprintf(buf, "%" PRIu32, rpc_sub[i].priority);
        SR_CHECK_LY_RET(lyd_new_term(sr_sub, NULL, "priority", buf, 0, NULL), ly_ctx, err_info);

        /* cid */
        sprintf(buf, "%" PRIu32, rpc_sub[i].cid);
        SR_CHECK_LY_RET(lyd_new_term(sr_sub, NULL, "cid", buf, 0, NULL), ly_ctx, err_info);
    }

    if (!lyd_child(sr_rpc)->next) {
        /* there are no locks or subscriptions for the RPC, redundant */
        lyd_free_tree(sr_rpc);
    }

    return NULL;
}

/**
 * @brief Append all "connection" data nodes to sysrepo-monitoring data.
 *
 * @param[in,out] sr_state Main container node of sysrepo-monitoring.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_module_srmon_connections(struct lyd_node *sr_state)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_conn;
    char buf[22];
    const struct ly_ctx *ly_ctx;
    sr_cid_t *cids;
    pid_t *pids;
    uint32_t conn_count, i;

    ly_ctx = LYD_CTX(sr_state);

    /* get basic information about connections */
    if ((err_info = sr_conn_info(&cids, &pids, &conn_count, NULL, NULL))) {
        return err_info;
    }

    for (i = 0; i < conn_count; ++i) {
        /* connection with cid */
        sprintf(buf, "%" PRIu32, cids[i]);
        SR_CHECK_LY_RET(lyd_new_list(sr_state, NULL, "connection", 0, &sr_conn, buf), ly_ctx, err_info);

        /* pid */
        sprintf(buf, "%" PRIu32, pids[i]);
        SR_CHECK_LY_RET(lyd_new_term(sr_conn, NULL, "pid", buf, 0, NULL), ly_ctx, err_info);
    }

    free(cids);
    free(pids);
    return NULL;
}

/**
 * @brief Load module data of the sysrepo-monitoring module. They are actually generated.
 *
 * SHM READ lock is expected to be held.
 *
 * @param[in] mod_info Mod info to use.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_module_data_load_srmon(struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *mod_data;
    sr_mod_t *shm_mod;
    sr_rpc_t *shm_rpc;
    const struct lys_module *ly_mod;
    sr_main_shm_t *main_shm;
    uint32_t i, j;

    main_shm = SR_CONN_MAIN_SHM(mod_info->conn);
    ly_mod = ly_ctx_get_module_implemented(mod_info->conn->ly_ctx, "sysrepo-monitoring");
    assert(ly_mod);

    /* main container */
    SR_CHECK_LY_GOTO(lyd_new_inner(NULL, ly_mod, "sysrepo-state", 0, &mod_data), mod_info->conn->ly_ctx, err_info, cleanup);

    /* modules */
    for (i = 0; i < main_shm->mod_count; ++i) {
        shm_mod = SR_SHM_MOD_IDX(main_shm, i);
        if ((err_info = sr_modinfo_module_srmon_module(mod_info->conn, shm_mod, mod_data))) {
            goto cleanup;
        }
    }

    /* RPCs */
    for (i = 0; i < main_shm->mod_count; ++i) {
        shm_mod = SR_SHM_MOD_IDX(main_shm, i);
        shm_rpc = (sr_rpc_t *)(mod_info->conn->main_shm.addr + shm_mod->rpcs);
        for (j = 0; j < shm_mod->rpc_count; ++j) {
            if ((err_info = sr_modinfo_module_srmon_rpc(mod_info->conn, &shm_rpc[j], mod_data))) {
                goto cleanup;
            }
        }
    }

    /* connections */
    if ((err_info = sr_modinfo_module_srmon_connections(mod_data))) {
        goto cleanup;
    }

    /* connect to the rest of data */
    if (lyd_merge_siblings(&mod_info->data, mod_data, LYD_MERGE_DESTRUCT)) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
        goto cleanup;
    }
    mod_data = NULL;

cleanup:
    lyd_free_siblings(mod_data);
    return err_info;
}

/**
 * @brief Load module data of a specific module.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] mod Mod info module to process.
 * @param[in] load_diff Whether to load stored operational diff of the module.
 * @param[in] orig_name Event originator name.
 * @param[in] orig_data Event originator data.
 * @param[in] request_xpath XPath of the data request.
 * @param[in] timeout_ms Operational callback timeout in milliseconds.
 * @param[in] opts Get oper data options.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_module_data_load(struct sr_mod_info_s *mod_info, struct sr_mod_info_mod_s *mod, const char *orig_name,
        const void *orig_data, const char *request_xpath, uint32_t timeout_ms, sr_get_oper_options_t opts)
{
    sr_error_info_t *err_info = NULL;
    sr_conn_ctx_t *conn = mod_info->conn;
    struct sr_mod_cache_s *mod_cache = NULL;
    struct lyd_node *mod_data = NULL;

    assert((mod_info->ds != SR_DS_OPERATIONAL) || (mod_info->ds2 != SR_DS_OPERATIONAL));

    if (((mod_info->ds == SR_DS_RUNNING) || (mod_info->ds2 == SR_DS_RUNNING)) && (conn->opts & SR_CONN_CACHE_RUNNING)) {
        /* we are caching running data we will use, so in all cases load the module into cache if not yet there */
        mod_cache = &conn->mod_cache;
        if ((err_info = sr_modcache_module_running_update(mod_cache, mod, NULL, mod_info->data_cached, mod_info->conn->cid))) {
            return err_info;
        }
    }

    if (!mod_info->data_cached) {
        /* we cannot use cached data directly for this operation... */
        if (mod_cache) {
            /* ...but they are cached */

            /* CACHE READ LOCK */
            if ((err_info = sr_rwlock(&mod_cache->lock, SR_MOD_CACHE_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid,
                    __func__, NULL, NULL))) {
                return err_info;
            }

            if (mod_info->ds == SR_DS_OPERATIONAL) {
                /* copy only enabled module data */
                err_info = sr_module_oper_data_get_enabled(conn, &mod_cache->data, mod, opts, 1, &mod_data);
            } else {
                /* copy all module data */
                err_info = sr_lyd_get_module_data(&mod_cache->data, mod->ly_mod, 0, 1, &mod_data);
            }

            /* CACHE READ UNLOCK */
            sr_rwunlock(&mod_cache->lock, SR_MOD_CACHE_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

            if (err_info) {
                return err_info;
            }
            if (mod_data) {
                lyd_insert_sibling(mod_info->data, mod_data, &mod_info->data);
            }
        } else {
            /* ...and they are not cached */

            /* get current persistent data (ds2 is running when getting operational data) */
            if ((err_info = sr_module_file_data_append(mod->ly_mod, mod_info->ds2, &mod_info->data))) {
                return err_info;
            }

            if (mod_info->ds == SR_DS_OPERATIONAL) {
                /* keep only enabled module data */
                if ((err_info = sr_module_oper_data_get_enabled(conn, &mod_info->data, mod, opts, 0, &mod_data))) {
                    return err_info;
                }
                lyd_free_siblings(sr_module_data_unlink(&mod_info->data, mod->ly_mod));
                if (mod_data) {
                    lyd_insert_sibling(mod_info->data, mod_data, &mod_info->data);
                }
            }
        }

        if (mod_info->ds == SR_DS_OPERATIONAL) {
            if (!strcmp(mod->ly_mod->name, "ietf-yang-library")) {
                /* append ietf-yang-library state data - internal */
                if ((err_info = sr_modinfo_module_data_load_yanglib(mod_info, mod))) {
                    return err_info;
                }
            } else if (!strcmp(mod->ly_mod->name, "sysrepo-monitoring")) {
                /* append sysrepo-monitoring state data - internal */
                if ((err_info = sr_modinfo_module_data_load_srmon(mod_info))) {
                    return err_info;
                }
            }

            /* append any operational data provided by clients */
            if ((err_info = sr_module_oper_data_update(mod, orig_name, orig_data, conn, request_xpath, timeout_ms, opts,
                    &mod_info->data))) {
                return err_info;
            }

            /* trim any data according to options (they could not be trimmed before oper subscriptions) */
            sr_oper_data_trim_r(&mod_info->data, mod_info->data, opts);
        }
    } else {
        /* we can use cached data and hence they must be cached */
        assert(mod_cache && SR_IS_CONVENTIONAL_DS(mod_info->ds));

        mod_info->data = mod_cache->data;
    }

    return NULL;
}

/**
 * @brief Add a module into mod info.
 *
 * @param[in] ly_mod Module libyang structure.
 * @param[in] mod_type Module type.
 * @param[in] mod_req_deps Which dependencies are also to be added.
 * @param[in] mod_info Modified mod info.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_add_mod(const struct lys_module *ly_mod, uint32_t mod_type, int mod_req_deps, struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    sr_dep_t *shm_deps;
    off_t *shm_inv_deps;
    uint32_t i, cur_i;
    int prev_mod_type = 0;

    assert((mod_type == MOD_INFO_REQ) || (mod_type == MOD_INFO_DEP) || (mod_type == MOD_INFO_INV_DEP));
    assert(!mod_req_deps || (mod_req_deps == MOD_INFO_DEP) || (mod_req_deps == (MOD_INFO_DEP | MOD_INFO_INV_DEP)));

    /* check that it is not already added */
    for (i = 0; i < mod_info->mod_count; ++i) {
        if (mod_info->mods[i].ly_mod == ly_mod) {
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

    /* find module in SHM */
    shm_mod = sr_shmmain_find_module(SR_CONN_MAIN_SHM(mod_info->conn), ly_mod->name);
    SR_CHECK_INT_RET(!shm_mod, err_info);

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
        shm_deps = (sr_dep_t *)(mod_info->conn->main_shm.addr + shm_mod->deps);
        for (i = 0; i < shm_mod->dep_count; ++i) {
            if (shm_deps[i].type == SR_DEP_INSTID) {
                /* we will handle those once we have the final data tree */
                continue;
            }

            /* find ly module */
            ly_mod = ly_ctx_get_module_implemented(ly_mod->ctx, mod_info->conn->main_shm.addr + shm_deps[i].module);
            SR_CHECK_INT_RET(!ly_mod, err_info);

            /* add dependency */
            if ((err_info = sr_modinfo_add_mod(ly_mod, MOD_INFO_DEP, mod_req_deps, mod_info))) {
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
        shm_inv_deps = (off_t *)(mod_info->conn->main_shm.addr + shm_mod->inv_deps);
        for (i = 0; i < shm_mod->inv_dep_count; ++i) {
            /* find ly module */
            ly_mod = ly_ctx_get_module_implemented(ly_mod->ctx, mod_info->conn->main_shm.addr + shm_inv_deps[i]);
            SR_CHECK_INT_RET(!ly_mod, err_info);

            /* add inverse dependency */
            if ((err_info = sr_modinfo_add_mod(ly_mod, MOD_INFO_INV_DEP, mod_req_deps, mod_info))) {
                return err_info;
            }
        }
    }

    return NULL;
}

/**
 * @brief Comparator function for qsort of mod info modules.
 *
 * @param[in] ptr1 First value pointer.
 * @param[in] ptr2 Second value pointer.
 * @return Less than, equal to, or greater than 0 if the first value is found
 * to be less than, equal to, or greater to the second value.
 */
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
sr_modinfo_data_load(struct sr_mod_info_s *mod_info, int cache, const char *orig_name, const void *orig_data,
        const char *request_xpath, uint32_t timeout_ms, sr_get_oper_options_t opts)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    uint32_t i;

    /* we can use cache only if we are working with the running datastore (as the main datastore) */
    if (!mod_info->data_cached && cache && (mod_info->conn->opts & SR_CONN_CACHE_RUNNING) &&
            (mod_info->ds == SR_DS_RUNNING)) {
        /* CACHE READ LOCK */
        if ((err_info = sr_rwlock(&mod_info->conn->mod_cache.lock, SR_MOD_CACHE_LOCK_TIMEOUT, SR_LOCK_READ,
                mod_info->conn->cid, __func__, NULL, NULL))) {
            return err_info;
        }

        /* we can cache the data */
        mod_info->data_cached = 1;
    }

    /* load data for each module */
    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & MOD_INFO_DATA) {
            /* module data were already loaded */
            continue;
        }

        if ((mod_info->ds == SR_DS_OPERATIONAL) && (mod_info->ds2 == SR_DS_OPERATIONAL)) {
            /* special case when we are not working with data but with edit */
            if ((err_info = sr_module_file_data_append(mod->ly_mod, SR_DS_OPERATIONAL, &mod_info->data))) {
                return err_info;
            }
        } else {
            if ((err_info = sr_modinfo_module_data_load(mod_info, mod, orig_name, orig_data, request_xpath, timeout_ms,
                    opts))) {
                /* if cached, we keep both cache lock and flag, so it is fine */
                return err_info;
            }
        }
        mod->state |= MOD_INFO_DATA;
    }

    return NULL;
}

sr_error_info_t *
sr_modinfo_add_modules(struct sr_mod_info_s *mod_info, const struct ly_set *mod_set, int mod_deps,
        sr_lock_mode_t mod_lock, int mi_opts, uint32_t sid, const char *orig_name, const void *orig_data,
        const char *request_xpath, uint32_t timeout_ms, sr_get_oper_options_t get_opts)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *mod;
    int mod_type;
    uint32_t i, prev_mod_count;

    assert(mi_opts & (SR_MI_PERM_NO | SR_MI_PERM_READ | SR_MI_PERM_WRITE));

    if (!mod_set->count) {
        /* nothing to add */
        return NULL;
    }

    if (mi_opts & SR_MI_MOD_DEPS) {
        mod_type = MOD_INFO_DEP;
    } else {
        mod_type = MOD_INFO_REQ;
    }

    prev_mod_count = mod_info->mod_count;
    if (mod_set->count) {
        /* add all the new modules into mod_info */
        for (i = 0; i < mod_set->count; ++i) {
            if ((err_info = sr_modinfo_add_mod(mod_set->objs[i], mod_type, mod_deps, mod_info))) {
                return err_info;
            }
        }
    } else {
        /* redundant to check dependencies if all the modules are added */
        mod_deps = 0;

        /* add all (implemented) modules into mod_info */
        i = 0;
        while ((mod = ly_ctx_get_module_iter(mod_info->conn->ly_ctx, &i))) {
            if (!mod->implemented || !strcmp(mod->name, SR_YANG_MOD)) {
                continue;
            }

            if ((err_info = sr_modinfo_add_mod(mod, mod_type, mod_deps, mod_info))) {
                return err_info;
            }
        }
    }
    if (prev_mod_count == mod_info->mod_count) {
        /* no module changes, we are done */
        return NULL;
    }

    if (!(mi_opts & SR_MI_PERM_NO)) {
        /* check permissions */
        if ((err_info = sr_modinfo_perm_check(mod_info, mi_opts & SR_MI_PERM_WRITE ? 1 : 0, mi_opts & SR_MI_PERM_STRICT))) {
            return err_info;
        }
    }

    /* all modules could have been removed by the permission check */
    if (mod_info->mod_count) {
        /* sort the modules based on their offsets in the SHM so that we have a uniform order for locking */
        qsort(mod_info->mods, mod_info->mod_count, sizeof *mod_info->mods, sr_modinfo_qsort_cmp);
    }

    if (mod_lock) {
        if (mod_lock == SR_LOCK_READ) {
            /* MODULES READ LOCK */
            if ((err_info = sr_shmmod_modinfo_rdlock(mod_info, mi_opts & SR_MI_LOCK_UPGRADEABLE, sid))) {
                return err_info;
            }
        } else {
            /* MODULES WRITE LOCK */
            if ((err_info = sr_shmmod_modinfo_wrlock(mod_info, sid))) {
                return err_info;
            }
        }
    }

    if (!(mi_opts & SR_MI_DATA_NO)) {
        /* load all modules data */
        if ((err_info = sr_modinfo_data_load(mod_info, mi_opts & SR_MI_DATA_CACHE, orig_name, orig_data, request_xpath,
                timeout_ms, get_opts))) {
            return err_info;
        }
    }

    return NULL;
}

sr_error_info_t *
sr_modinfo_validate(struct sr_mod_info_s *mod_info, int mod_state, int finish_diff)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    struct lyd_node *diff = NULL;
    uint32_t i;
    int val_opts;

    assert(!mod_info->data_cached);
    assert(SR_IS_CONVENTIONAL_DS(mod_info->ds) || !finish_diff);

    /* validate all the modules individually */
    if (SR_IS_CONVENTIONAL_DS(mod_info->ds)) {
        val_opts = LYD_VALIDATE_NO_STATE;
    } else {
        val_opts = 0;
    }
    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & mod_state) {
            /* validate this module */
            if (lyd_validate_module(&mod_info->data, mod->ly_mod, val_opts, finish_diff ? &diff : NULL)) {
                sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
                SR_ERRINFO_VALID(&err_info);
                goto cleanup;
            }

            if (diff) {
                /* it may not have been modified before */
                mod->state |= MOD_INFO_CHANGED;

                /* merge the changes made by the validation into our diff */
                if (lyd_diff_merge_all(&mod_info->diff, diff, 0)) {
                    sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
                    goto cleanup;
                }

                lyd_free_all(diff);
                diff = NULL;
            }
        }
    }

cleanup:
    lyd_free_all(diff);
    return err_info;
}

sr_error_info_t *
sr_modinfo_add_defaults(struct sr_mod_info_s *mod_info, int finish_diff)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    struct lyd_node *diff = NULL;
    uint32_t i;

    assert(!mod_info->data_cached && SR_IS_CONVENTIONAL_DS(mod_info->ds));

    /* create an array of all the modules that will be processed */
    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        switch (mod->state & MOD_INFO_TYPE_MASK) {
        case MOD_INFO_REQ:
            /* add default values for this module */
            if (lyd_new_implicit_module(&mod_info->data, mod->ly_mod, LYD_IMPLICIT_NO_STATE, finish_diff ? &diff : NULL)) {
                sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
                SR_ERRINFO_VALID(&err_info);
                goto cleanup;
            }
            mod_info->data = lyd_first_sibling(mod_info->data);

            if (diff) {
                /* it may not have been modified before */
                mod->state |= MOD_INFO_CHANGED;

                /* merge the changes made by the validation into our diff */
                if (lyd_diff_merge_all(&mod_info->diff, diff, 0)) {
                    sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
                    goto cleanup;
                }

                lyd_free_all(diff);
                diff = NULL;
            }
            break;
        case MOD_INFO_INV_DEP:
        case MOD_INFO_DEP:
            /* this module will not be validated */
            break;
        default:
            SR_CHECK_INT_GOTO(0, err_info, cleanup);
        }
    }

cleanup:
    lyd_free_all(diff);
    return err_info;
}

sr_error_info_t *
sr_modinfo_op_validate(struct sr_mod_info_s *mod_info, struct lyd_node *op, int output)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *top_op;
    struct ly_set *set = NULL;
    struct sr_mod_info_mod_s *mod;
    uint32_t i;
    char *parent_xpath = NULL;
    enum lyd_type op_type;

    assert(op->schema->nodetype & (LYS_RPC | LYS_ACTION | LYS_NOTIF));

    /* find top-level node */
    for (top_op = op; top_op->parent; top_op = lyd_parent(top_op)) {}

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        switch (mod->state & MOD_INFO_TYPE_MASK) {
        case MOD_INFO_REQ:
            /* this is the module of the nested operation and we need to check that operation's parent data node exists */
            assert((mod->ly_mod == lyd_owner_module(top_op)) && op->schema->parent && op->parent);
            parent_xpath = lyd_path(lyd_parent(op), LYD_PATH_STD, NULL, 0);
            SR_CHECK_MEM_GOTO(!parent_xpath, err_info, cleanup);

            if (mod_info->data) {
                if (lyd_find_xpath(mod_info->data, parent_xpath, &set)) {
                    sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
                    goto cleanup;
                }
            } else {
                if (ly_set_new(&set)) {
                    sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
                    goto cleanup;
                }
            }
            SR_CHECK_INT_GOTO(set->count > 1, err_info, cleanup);

            if (!set->count) {
                sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED,
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

    /* validate */
    op_type = ((op->schema->nodetype & (LYS_RPC | LYS_ACTION)) ?
            (output ? LYD_TYPE_REPLY_YANG : LYD_TYPE_RPC_YANG) : LYD_TYPE_NOTIF_YANG);
    if (lyd_validate_op(top_op, mod_info->data, op_type, NULL)) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
        sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, "%s %svalidation failed.",
                (op->schema->nodetype == LYS_NOTIF) ? "Notification" : ((op->schema->nodetype == LYS_RPC) ? "RPC" : "Action"),
                (op->schema->nodetype == LYS_NOTIF) ? "" : (output ? "output " : "input "));
        goto cleanup;
    }

    /* success */

cleanup:
    free(parent_xpath);
    ly_set_free(set, NULL);
    return err_info;
}

sr_error_info_t *
sr_modinfo_get_filter(struct sr_mod_info_s *mod_info, const char *xpath, sr_session_ctx_t *session, struct ly_set **result)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    struct lyd_node *edit, *diff;
    uint32_t i;

    *result = NULL;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & MOD_INFO_REQ) {
            edit = NULL;
            diff = NULL;

            /* collect edit/diff to be applied based on the handled event */
            switch (session->ev) {
            case SR_SUB_EV_CHANGE:
            case SR_SUB_EV_UPDATE:
                diff = session->dt[session->ds].diff;
                if (session->ev != SR_SUB_EV_UPDATE) {
                    break;
                }
            /* fallthrough */
            case SR_SUB_EV_NONE:
                edit = session->dt[session->ds].edit;
                break;
            case SR_SUB_EV_ENABLED:
            case SR_SUB_EV_DONE:
            case SR_SUB_EV_ABORT:
            case SR_SUB_EV_OPER:
            case SR_SUB_EV_RPC:
            case SR_SUB_EV_NOTIF:
                /* no changes to apply for these events */
                break;
            default:
                SR_ERRINFO_INT(&err_info);
                goto cleanup;
            }

            if (mod_info->data_cached && (session->ds == SR_DS_RUNNING) && (edit || diff)) {
                /* data will be changed, we cannot use the cache anymore */
                lyd_dup_siblings(mod_info->data, NULL, LYD_DUP_RECURSIVE | LYD_DUP_WITH_FLAGS, &mod_info->data);
                mod_info->data_cached = 0;

                /* CACHE READ UNLOCK */
                sr_rwunlock(&mod_info->conn->mod_cache.lock, SR_MOD_CACHE_LOCK_TIMEOUT, SR_LOCK_READ,
                        session->conn->cid, __func__);
            }

            /* apply any currently handled changes (diff) or additional performed ones (edit) to get
             * the session-specific data tree */
            if (lyd_diff_apply_module(&mod_info->data, diff, mod->ly_mod,
                    (session->ds == SR_DS_OPERATIONAL) ? sr_lyd_diff_apply_cb : NULL, NULL)) {
                sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
                goto cleanup;
            }
            if ((err_info = sr_edit_mod_apply(edit, mod->ly_mod, &mod_info->data, NULL, NULL))) {
                goto cleanup;
            }
        }
    }

    /* filter return data */
    if (mod_info->data) {
        if (lyd_find_xpath(mod_info->data, xpath, result)) {
            sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
            goto cleanup;
        }
    } else {
        if (ly_set_new(result)) {
            sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
            goto cleanup;
        }
    }

    /* success */

cleanup:
    return err_info;
}

sr_error_info_t *
sr_modinfo_generate_config_change_notif(struct sr_mod_info_s *mod_info, sr_session_ctx_t *session)
{
    sr_error_info_t *err_info = NULL, *tmp_err_info = NULL;
    struct lyd_node *root, *elem, *notif = NULL;
    struct ly_set *set;
    sr_mod_t *shm_mod;
    struct timespec notif_ts;
    sr_mod_notif_sub_t *notif_subs;
    uint32_t idx = 0, notif_sub_count;
    char *xpath;
    const char *op_enum;
    sr_change_oper_t op;
    enum edit_op edit_op;
    int changes;
    LY_ERR lyrc;

    /* make sure there are some actual node changes */
    changes = 0;
    LY_LIST_FOR(mod_info->diff, root) {
        LYD_TREE_DFS_BEGIN(root, elem) {
            edit_op = sr_edit_diff_find_oper(elem, 0, NULL);
            if (edit_op && (edit_op != EDIT_NONE)) {
                changes = 1;
                break;
            }
            LYD_TREE_DFS_END(root, elem);
        }
        if (changes) {
            break;
        }
    }
    if (!changes) {
        /* no actual changes to notify about */
        return NULL;
    }

    if ((mod_info->ds == SR_DS_CANDIDATE) || (mod_info->ds == SR_DS_OPERATIONAL)) {
        /* not supported */
        return NULL;
    }

    /* remember when the notification was generated */
    sr_time_get(&notif_ts, 0);

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(mod_info->conn, SR_LOCK_READ, 0, __func__))) {
        return err_info;
    }

    /* get subscriber count */
    err_info = sr_notif_find_subscriber(mod_info->conn, "ietf-netconf-notifications", &notif_subs, &notif_sub_count);

    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(mod_info->conn, SR_LOCK_READ, 0, __func__);

    if (err_info) {
        return err_info;
    }

    /* get this module and check replay support */
    shm_mod = sr_shmmain_find_module(SR_CONN_MAIN_SHM(mod_info->conn), "ietf-netconf-notifications");
    SR_CHECK_INT_RET(!shm_mod, err_info);
    if (!ATOMIC_LOAD_RELAXED(shm_mod->replay_supp) && !notif_sub_count) {
        /* nothing to do */
        return NULL;
    }

    lyrc = ly_set_new(&set);
    SR_CHECK_MEM_GOTO(lyrc, err_info, cleanup);

    /* just put all the nodes into a set */
    LY_LIST_FOR(mod_info->diff, root) {
        LYD_TREE_DFS_BEGIN(root, elem) {
            if (ly_set_add(set, elem, 1, NULL)) {
                SR_ERRINFO_INT(&err_info);
                goto cleanup;
            }

            LYD_TREE_DFS_END(root, elem);
        }
    }

    /* generate notifcation with all the changes */
    if (lyd_new_path(NULL, mod_info->conn->ly_ctx, "/ietf-netconf-notifications:netconf-config-change", NULL, 0, &notif)) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
        goto cleanup;
    }

    /* changed-by (everything was caused by user, we do not know what changes are implicit) */
    if (lyd_new_inner(notif, NULL, "changed-by", 0, &root)) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
        goto cleanup;
    }

    /* changed-by username */
    if (lyd_new_term(root, NULL, "username", session->user, 0, NULL)) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
        goto cleanup;
    }

    /* changed-by NETCONF session-id (unknown) */
    if (lyd_new_term(root, NULL, "session-id", "0", 0, NULL)) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
        goto cleanup;
    }

    /* datastore */
    if (lyd_new_term(notif, NULL, "datastore", sr_ds2str(mod_info->ds), 0, NULL)) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
        goto cleanup;
    }

    while (!(err_info = sr_diff_set_getnext(set, &idx, &elem, &op)) && elem) {
        /* edit (list instance) */
        if (lyd_new_list(notif, NULL, "edit", 0, &root)) {
            sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
            goto cleanup;
        }

        /* edit target */
        xpath = lyd_path(elem, LYD_PATH_STD, NULL, 0);
        if (!xpath) {
            sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
            goto cleanup;
        }
        lyrc = lyd_new_term(root, NULL, "target", xpath, 0, NULL);
        free(xpath);
        if (lyrc) {
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
        default:
            SR_ERRINFO_INT(&err_info);
            goto cleanup;
        }
        if (lyd_new_term(root, NULL, "operation", op_enum, 0, NULL)) {
            sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
            goto cleanup;
        }
    }

    /* store the notification for a replay, we continue on failure */
    tmp_err_info = sr_replay_store(session, notif, notif_ts);

    /* send the notification (non-validated, if everything works correctly it must be valid) */
    if ((err_info = sr_shmsub_notif_notify(mod_info->conn, notif, notif_ts, session->orig_name, session->orig_data, 0, 0))) {
        goto cleanup;
    }

    /* success */

cleanup:
    ly_set_free(set, NULL);
    lyd_free_siblings(notif);
    if (err_info) {
        /* write this only if the notification failed to be created/sent */
        sr_errinfo_new(&err_info, err_info->err[0].err_code, "Failed to generate netconf-config-change notification, "
                "but changes were applied.");
    }
    if (tmp_err_info) {
        sr_errinfo_merge(&err_info, tmp_err_info);
    }
    return err_info;
}

sr_error_info_t *
sr_modinfo_data_store(struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    struct sr_mod_info_mod_s *mod;
    struct lyd_node *mod_data;
    uint32_t i;
    int create_flags;

    assert(!mod_info->data_cached);

    /* candidate file may need to be created */
    if (mod_info->ds == SR_DS_CANDIDATE) {
        create_flags = O_CREAT;
    } else {
        create_flags = 0;
    }

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & MOD_INFO_CHANGED) {
            /* separate data of this module */
            mod_data = sr_module_data_unlink(&mod_info->data, mod->ly_mod);

            /* store the new data */
            if ((err_info = sr_module_file_data_set(mod->ly_mod->name, mod_info->ds, mod_data, create_flags,
                    SR_FILE_PERM))) {
                goto cleanup;
            }

            if (mod_info->ds == SR_DS_RUNNING) {
                /* update module running data version */
                ++mod->shm_mod->ver;

                if (mod_info->conn->opts & SR_CONN_CACHE_RUNNING) {
                    /* we are caching so update cache with these data */
                    tmp_err = sr_modcache_module_running_update(&mod_info->conn->mod_cache, mod, mod_data, 0,
                            mod_info->conn->cid);
                    if (tmp_err) {
                        /* always store all changed modules, if possible */
                        sr_errinfo_merge(&err_info, tmp_err);
                        tmp_err = NULL;
                    }
                }
            }

            /* connect them back */
            if (mod_data) {
                lyd_insert_sibling(mod_info->data, mod_data, &mod_info->data);
            }
        }
    }

cleanup:
    return err_info;

}

sr_error_info_t *
sr_modinfo_candidate_reset(struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    uint32_t i;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & MOD_INFO_REQ) {
            /* just remove the candidate SHM files */
            if ((err_info = sr_remove_candidate_file(mod->ly_mod->name))) {
                return err_info;
            }
        }
    }

    return NULL;
}

int
sr_modinfo_is_changed(struct sr_mod_info_s *mod_info)
{
    struct sr_mod_info_mod_s *mod;
    uint32_t i;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & MOD_INFO_CHANGED) {
            /* changed module */
            return 1;
        }
    }

    return 0;
}

void
sr_modinfo_free(struct sr_mod_info_s *mod_info)
{
    lyd_free_siblings(mod_info->diff);
    if (mod_info->data_cached) {
        mod_info->data_cached = 0;

        /* CACHE READ UNLOCK */
        sr_rwunlock(&mod_info->conn->mod_cache.lock, SR_MOD_CACHE_LOCK_TIMEOUT, SR_LOCK_READ,
                mod_info->conn->cid, __func__);
    } else {
        lyd_free_siblings(mod_info->data);
    }

    free(mod_info->mods);
}
