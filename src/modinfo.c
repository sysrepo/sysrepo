/**
 * @file modinfo.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief routines for working with modinfo structure
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

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <inttypes.h>
#include <fcntl.h>
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
        shm_deps = (sr_mod_data_dep_t *)(mod_info->conn->ext_shm.addr + shm_mod->data_deps);
        for (i = 0; i < shm_mod->data_dep_count; ++i) {
            if (shm_deps[i].type == SR_DEP_INSTID) {
                /* we will handle those once we have the final data tree */
                continue;
            }

            /* find the dependency */
            dep_mod = sr_shmmain_find_module(&mod_info->conn->main_shm, NULL, NULL, shm_deps[i].module);
            SR_CHECK_INT_RET(!dep_mod, err_info);

            /* find ly module */
            ly_mod = ly_ctx_get_module(ly_mod->ctx, mod_info->conn->ext_shm.addr + dep_mod->name, NULL, 1);
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
         shm_inv_deps = (off_t *)(mod_info->conn->ext_shm.addr + shm_mod->inv_data_deps);
         for (i = 0; i < shm_mod->inv_data_dep_count; ++i) {
            /* find ly module */
            ly_mod = ly_ctx_get_module(ly_mod->ctx, mod_info->conn->ext_shm.addr + shm_inv_deps[i], NULL, 1);
            SR_CHECK_INT_RET(!ly_mod, err_info);

            /* find SHM module */
            dep_mod = sr_shmmain_find_module(&mod_info->conn->main_shm, NULL, NULL, shm_inv_deps[i]);
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
        for (node = data; lyd_node_module(node) != last->ly_mod; node = node->next);

next_mod:
        /* skip all edit nodes from this module */
        for (; node && (lyd_node_module(node) == last->ly_mod); node = node->next);
    }

    if (node) {
        /* find mod of this edit node */
        mod = NULL;
        for (i = 0; i < mod_info->mod_count; ++i) {
            if (mod_info->mods[i].ly_mod == lyd_node_module(node)) {
                mod = &mod_info->mods[i];
                break;
            }
        }

        assert(mod);

        /* mark this mod as returned if not already */
        if ((*aux)[i]) {
            /* continue search */
            last = mod;
            goto next_mod;
        } else {
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
    struct sr_mod_info_mod_s *mod = NULL;
    const struct lyd_node *node;
    char *str;
    uint32_t *aux;
    int change;

    assert(!mod_info->data_cached);

    LY_TREE_FOR(edit, node) {
        if (!strcmp(lyd_node_module(node)->name, SR_YANG_MOD)) {
            str = lyd_path(node);
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, str, "Data of internal module \"%s\" cannot be modified.", SR_YANG_MOD);
            free(str);
            return err_info;
        }
    }

    while ((mod = sr_modinfo_next_mod(mod, mod_info, edit, &aux))) {
        assert(mod->state & MOD_INFO_REQ);

        /* apply relevant edit changes */
        if ((err_info = sr_edit_mod_apply(edit, mod->ly_mod, &mod_info->data, create_diff ? &mod_info->diff : NULL, &change))) {
            free(aux);
            return err_info;
        }

        if (change) {
            /* there is a diff for this module */
            mod->state |= MOD_INFO_CHANGED;
        }
    }

    return NULL;
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
            if ((err_info = sr_diff_mod_merge(new_diff, mod_info->ds == SR_DS_OPERATIONAL ? mod_info->conn : NULL,
                    mod->ly_mod, &mod_info->diff, NULL))) {
                return err_info;
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
    struct lyd_node *src_mod_data, *dst_mod_data, *diff;
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
                err_info = sr_diff_ly2sr(ly_diff, &diff);
                if (mod_info->diff) {
                    sr_ly_link(mod_info->diff, diff);
                } else {
                    mod_info->diff = diff;
                }

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
 * @brief Check whether operational data are required.
 *
 * @param[in] request_xpath Get request XPath.
 * @param[in] sub_xpath Operational subscription XPath.
 * @return 0 if not required, non-zero if required.
 */
static int
sr_xpath_oper_data_required(const char *request_xpath, const char *sub_xpath)
{
    const char *xpath1, *xpath2, *mod1, *mod2, *name1, *name2, *pred1, *pred2;
    int wildc1, wildc2, mlen1, mlen2, len1, len2, dslash1, dslash2, has_pred1, has_pred2;

    assert(sub_xpath);

    if (!request_xpath) {
        /* we do not know, say it is required */
        return 1;
    }

    xpath1 = request_xpath;
    xpath2 = sub_xpath;
    do {
        xpath1 = sr_xpath_next_name(xpath1, &mod1, &mlen1, &name1, &len1, &dslash1, &has_pred1);
        xpath2 = sr_xpath_next_name(xpath2, &mod2, &mlen2, &name2, &len2, &dslash2, &has_pred2);

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
            xpath1 = sr_xpath_next_predicate(xpath1, &pred1, &len1, &has_pred1);
            xpath2 = sr_xpath_next_predicate(xpath2, &pred2, &len2, &has_pred2);

            /* predicate */
            if (!sr_xpath_oper_data_predicate_required(pred1, len1, pred2, len2)) {
                /* not required based on the predicate */
                return 0;
            }
        }

        /* skip any leftover predicates */
        while (has_pred1) {
            xpath1 = sr_xpath_next_predicate(xpath1, NULL, NULL, &has_pred1);
        }
        while (has_pred2) {
            xpath2 = sr_xpath_next_predicate(xpath2, NULL, NULL, &has_pred2);
        }
    } while (xpath1[0] && xpath2[0]);

    /* whole xpath matches */
    return 1;
}

/**
 * @brief Get specific operational data from a subscriber.
 *
 * @param[in] ly_mod libyang module of the data.
 * @param[in] xpath XPath of the provided data.
 * @param[in] request_xpath XPath of the data request.
 * @param[in] sid Sysrepo session ID.
 * @param[in] evpipe_num Subscriber event pipe number.
 * @param[in] parent Data parent required for the subscription, NULL if top-level.
 * @param[in] timeout_ms Operational callback timeout in milliseconds.
 * @param[out] data Data tree with appended operational data.
 * @param[out] cb_error_info Callback error info returned by the client, if any.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_xpath_oper_data_get(const struct lys_module *ly_mod, const char *xpath, const char *request_xpath, sr_sid_t sid,
        uint32_t evpipe_num, const struct lyd_node *parent, uint32_t timeout_ms, struct lyd_node **oper_data,
        sr_error_info_t **cb_error_info)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *parent_dup = NULL, *last_parent;
    char *parent_path = NULL;

    *oper_data = NULL;

    if (parent) {
        /* duplicate parent so that it is a stand-alone subtree */
        last_parent = lyd_dup(parent, LYD_DUP_OPT_WITH_PARENTS | LYD_DUP_OPT_WITH_KEYS);
        if (!last_parent) {
            sr_errinfo_new_ly(&err_info, ly_mod->ctx);
            return err_info;
        }

        /* go top-level */
        for (parent_dup = last_parent; parent_dup->parent; parent_dup = parent_dup->parent);

        if (request_xpath) {
            /* check whether the parent would not be filtered out */
            parent_path = lyd_path(last_parent);
            SR_CHECK_MEM_GOTO(!parent_path, err_info, cleanup);

            if (!sr_xpath_oper_data_required(request_xpath, parent_path)) {
                goto cleanup;
            }
        }
    }

    /* get data from client */
    if ((err_info = sr_shmsub_oper_notify(ly_mod, xpath, request_xpath, parent_dup, sid, evpipe_num, timeout_ms,
            oper_data, cb_error_info))) {
        goto cleanup;
    }

    /* add default state data so that parents exist and we ask for descendants
     * that can exist (it should not fail with TRUSTED flag, we do not care even if it does) */
    lyd_validate_modules(oper_data, &ly_mod, 1, LYD_OPT_DATA | LYD_OPT_TRUSTED);

cleanup:
    lyd_free_withsiblings(parent_dup);
    free(parent_path);
    return err_info;
}

/**
 * @brief Append operational data for a specific XPath.
 *
 * @param[in] shm_msub SHM subscription.
 * @param[in] ly_mod Module of the data to get.
 * @param[in] sub_xpath Subscription XPath.
 * @param[in] request_xpath XPath of the specific data request.
 * @param[in] oper_parent Operational parent of the data to retrieve. NULL for top-level.
 * @param[in] sid Sysrepo session ID.
 * @param[in] timeout_ms Operational callback timeout in milliseconds.
 * @param[in,out] data Operational data tree.
 * @param[out] cb_error_info Callback error info returned by the client, if any.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_xpath_oper_data_append(sr_mod_oper_sub_t *shm_msub, const struct lys_module *ly_mod, const char *sub_xpath,
        const char *request_xpath, struct lyd_node *oper_parent, sr_sid_t sid, uint32_t timeout_ms,
        struct lyd_node **data, sr_error_info_t **cb_error_info)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *oper_data;

    /* get oper data from the client */
    if ((err_info = sr_xpath_oper_data_get(ly_mod, sub_xpath, request_xpath, sid, shm_msub->evpipe_num,
            oper_parent, timeout_ms, &oper_data, cb_error_info))) {
        return err_info;
    }

    /* merge into one data tree */
    if (!*data) {
        *data = oper_data;
    } else if (oper_data && lyd_merge(*data, oper_data, LYD_OPT_DESTRUCT | LYD_OPT_EXPLICIT)) {
        lyd_free_withsiblings(oper_data);
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        return err_info;
    }

    return NULL;
}

/**
 * @brief Update (replace or append) operational data for a specific module.
 *
 * @param[in] mod Mod info module to process.
 * @param[in] sid Sysrepo session ID.
 * @param[in] request_xpath XPath of the data request.
 * @param[in] ext_shm_addr Ext SHM address.
 * @param[in] timeout_ms Operational callback timeout in milliseconds.
 * @param[in] opts Get oper data options.
 * @param[in,out] data Operational data tree.
 * @param[out] cb_error_info Callback error info returned by the client, if any.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_module_oper_data_update(struct sr_mod_info_mod_s *mod, sr_sid_t *sid, const char *request_xpath, char *ext_shm_addr,
        uint32_t timeout_ms, sr_get_oper_options_t opts, struct lyd_node **data, sr_error_info_t **cb_error_info)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_oper_sub_t *shm_msub;
    const char *sub_xpath;
    char *parent_xpath = NULL;
    uint16_t i, j;
    struct ly_set *set = NULL;
    struct lyd_node *diff = NULL;

    if (!(opts & SR_OPER_NO_STORED)) {
        /* apply stored operational diff */
        if ((err_info = sr_module_file_data_append(mod->ly_mod, SR_DS_OPERATIONAL, &diff))) {
            return err_info;
        }
        err_info = sr_diff_mod_apply(diff, mod->ly_mod, opts & SR_OPER_WITH_ORIGIN, data);
        lyd_free_withsiblings(diff);
        if (err_info) {
            return err_info;
        }

        if (!*data) {
            /* add possible default state data nodes */
            lyd_validate_modules(data, &mod->ly_mod, 1, LYD_OPT_DATA | LYD_OPT_TRUSTED);
        }
    }

    if (opts & SR_OPER_NO_SUBS) {
        /* do not get data from subscribers */
        return NULL;
    }

    assert(sid && timeout_ms && cb_error_info);

    /* XPaths are ordered based on depth */
    for (i = 0; i < mod->shm_mod->oper_sub_count; ++i) {
        shm_msub = &((sr_mod_oper_sub_t *)(ext_shm_addr + mod->shm_mod->oper_subs))[i];
        sub_xpath = ext_shm_addr + shm_msub->xpath;

        if ((shm_msub->sub_type == SR_OPER_SUB_CONFIG) && (opts & SR_OPER_NO_CONFIG)) {
            /* useless to retrieve configuration data */
            continue;
        } else if ((shm_msub->sub_type == SR_OPER_SUB_STATE) && (opts & SR_OPER_NO_STATE)) {
            /* useless to retrieve state data */
            continue;
        } else if (!sr_xpath_oper_data_required(request_xpath, sub_xpath)) {
            /* useless to retrieve this data because they would be filtered out anyway */
            continue;
        }

        /* remove any present data */
        if (!(shm_msub->opts & SR_SUBSCR_OPER_MERGE) && (err_info = sr_lyd_xpath_complement(data, sub_xpath))) {
            return err_info;
        }

        /* trim the last node to get the parent */
        if ((err_info = sr_xpath_trim_last_node(sub_xpath, &parent_xpath))) {
            return err_info;
        }

        if (parent_xpath) {
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
                if ((err_info = sr_xpath_oper_data_append(shm_msub, mod->ly_mod, sub_xpath, request_xpath, set->set.d[j],
                        *sid, timeout_ms, data, cb_error_info))) {
                    goto error;
                }
            }

next_iter:
            /* cleanup for next iteration */
            free(parent_xpath);
            ly_set_free(set);
            set = NULL;
        } else {
            /* top-level data */
            if ((err_info = sr_xpath_oper_data_append(shm_msub, mod->ly_mod, sub_xpath, request_xpath, NULL, *sid,
                    timeout_ms, data, cb_error_info))) {
                goto error;
            }
        }
    }

    return NULL;

error:
    free(parent_xpath);
    ly_set_free(set);
    return err_info;
}

static sr_error_info_t *
sr_module_oper_data_add_state_default(struct lyd_node **data, const struct lys_module *ly_mod)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *node, *val_node, *sibling;
    struct lyd_difflist *val_diff;
    struct ly_set *set;
    uint32_t i;

    if (lyd_validate_modules(data, &ly_mod, 1, LYD_OPT_DATA | LYD_OPT_TRUSTED | LYD_OPT_VAL_DIFF, &val_diff)) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        SR_ERRINFO_VALID(&err_info);
        return err_info;
    }

    /* remove added config nodes */
    assert(val_diff);
    for (i = 0; val_diff->type[i] != LYD_DIFF_END; ++i) {
        if (val_diff->type[i] == LYD_DIFF_CREATED) {
            /* get the sibling in the data */
            if (val_diff->first[i]) {
                set = lyd_find_path(*data, (char *)val_diff->first[i]);
                if (!set) {
                    sr_errinfo_new_ly(&err_info, ly_mod->ctx);
                    return err_info;
                }
                assert(set->number == 1);
                sibling = set->set.d[0]->child;
                ly_set_free(set);
            } else {
                sibling = *data;
            }

            LY_TREE_FOR(val_diff->second[i], val_node) {
                if (val_node->schema->flags & LYS_CONFIG_R) {
                    continue;
                }

                /* find the created node in the data and free it */
                LY_TREE_FOR(sibling, node) {
                    if (node->schema == val_node->schema) {
                        lyd_free(node);
                        break;
                    }
                }
            }
        }
    }

    lyd_free_val_diff(val_diff);
    return NULL;
}

/**
 * @brief Duplicate operational (enabled) data from configuration data tree.
 *
 * @param[in] data Configuration data.
 * @param[in] ext_shm_addr Main SHM address.
 * @param[in] mod Mod info module to process.
 * @param[in] opts Get oper data options.
 * @param[out] enabled_mod_data Enabled operational data of the module.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_module_oper_data_dup_enabled(const struct lyd_node *data, char *ext_shm_addr, struct sr_mod_info_mod_s *mod,
        sr_get_oper_options_t opts, struct lyd_node **enabled_mod_data)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_change_sub_t *shm_changesubs;
    struct lyd_node *root, *elem, *next;
    uint16_t i, xp_i;
    int data_duplicated = 0;
    char **xpaths;
    const char *origin;

    *enabled_mod_data = NULL;

    if (!data) {
        /* no enabled data to duplicate */
        data_duplicated = 1;
    }

    if (!data_duplicated) {
        /* try to find a subscription for the whole module */
        shm_changesubs = (sr_mod_change_sub_t *)(ext_shm_addr + mod->shm_mod->change_sub[SR_DS_RUNNING].subs);
        for (i = 0; i < mod->shm_mod->change_sub[SR_DS_RUNNING].sub_count; ++i) {
            if (!shm_changesubs[i].xpath && !(shm_changesubs[i].opts & SR_SUBSCR_PASSIVE)) {
                /* the whole module is enabled */
                if ((err_info = sr_module_data_dup(data, mod->ly_mod, enabled_mod_data))) {
                    return err_info;
                }
                data_duplicated = 1;
                break;
            }
        }
    }

    if (!data_duplicated) {
        /* collect all enabled subtress in the form of xpaths */
        xpaths = NULL;
        for (i = 0, xp_i = 0; i < mod->shm_mod->change_sub[SR_DS_RUNNING].sub_count; ++i) {
            if (shm_changesubs[i].xpath && !(shm_changesubs[i].opts & SR_SUBSCR_PASSIVE)) {
                xpaths = sr_realloc(xpaths, (xp_i + 1) * sizeof *xpaths);
                SR_CHECK_MEM_RET(!xpaths, err_info);

                xpaths[xp_i] = ext_shm_addr + shm_changesubs[i].xpath;
                ++xp_i;
            }
        }

        /* duplicate only enabled subtrees */
        err_info = sr_lyd_xpath_dup(data, xpaths, xp_i, mod->ly_mod, enabled_mod_data);
        free(xpaths);
        if (err_info) {
            return err_info;
        }
    }

    /* add existing (valid) state NP containers and default values */
    if ((err_info = sr_module_oper_data_add_state_default(enabled_mod_data, mod->ly_mod))) {
        return err_info;
    }

    if (opts & SR_OPER_WITH_ORIGIN) {
        LY_TREE_FOR(*enabled_mod_data, root) {
            /* add origin of all top-level nodes */
            origin = (root->schema->flags & LYS_CONFIG_W) ? SR_CONFIG_ORIGIN : SR_OPER_ORIGIN;
            if ((err_info = sr_edit_diff_set_origin(root, origin, 1))) {
                return err_info;
            }

            LY_TREE_DFS_BEGIN(root, next, elem) {
                /* add origin of default nodes */
                if ((elem->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST)) && elem->dflt) {
                    if ((err_info = sr_edit_diff_set_origin(elem, "default", 1))) {
                        return err_info;
                    }
                }
                LY_TREE_DFS_END(root, next, elem);
            }
        }
    }

    return NULL;
}

/**
 * @brief Update cached running module data (if required).
 *
 * @param[in] mod_cache Module cache.
 * @param[in] mod Mod info module to process.
 * @param[in] upd_mod_data Optional current (updated) module data to store in cache.
 * @param[in] read_locked Whether the cache is READ locked.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modcache_module_running_update(struct sr_mod_cache_s *mod_cache, struct sr_mod_info_mod_s *mod,
        const struct lyd_node *upd_mod_data, int read_locked)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *mod_data;
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
                sr_rwunlock(&mod_cache->lock, SR_LOCK_READ, __func__);
            }

            /* CACHE WRITE LOCK */
            if ((err_info = sr_rwlock(&mod_cache->lock, SR_MOD_CACHE_LOCK_TIMEOUT * 1000, SR_LOCK_WRITE, __func__))) {
                goto error_rlock;
            }

            /* data needs to be updated, remove old data */
            lyd_free_withsiblings(sr_module_data_unlink(&mod_cache->data, mod->ly_mod));
            mod_cache->mods[i].ver = 0;
        }
    } else {
        if (read_locked) {
            /* CACHE READ UNLOCK */
            sr_rwunlock(&mod_cache->lock, SR_LOCK_READ, __func__);
        }

        /* CACHE WRITE LOCK */
        if ((err_info = sr_rwlock(&mod_cache->lock, SR_MOD_CACHE_LOCK_TIMEOUT * 1000, SR_LOCK_WRITE, __func__))) {
            goto error_rlock;
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
            /* current data were provided, use them */
            mod_data = lyd_dup_withsiblings(upd_mod_data, LYD_DUP_OPT_RECURSIVE | LYD_DUP_OPT_WITH_WHEN);
            if (!mod_data) {
                sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx);
                goto error_wrunlock;
            }
            if (mod_cache->data) {
                sr_ly_link(mod_cache->data, mod_data);
            } else {
                mod_cache->data = mod_data;
            }
        } else {
            /* we need to load current data from persistent storage */
            if ((err_info = sr_module_file_data_append(mod->ly_mod, SR_DS_RUNNING, &mod_cache->data))) {
                goto error_wrunlock;
            }
        }
        mod_cache->mods[i].ver = mod->shm_mod->ver;

error_wrunlock:
        /* CACHE WRITE UNLOCK */
        sr_rwunlock(&mod_cache->lock, SR_LOCK_WRITE, __func__);

error_rlock:
        if (read_locked) {
            /* CACHE READ LOCK */
            if ((err_info = sr_rwlock(&mod_cache->lock, SR_MOD_CACHE_LOCK_TIMEOUT * 1000, SR_LOCK_READ, __func__))) {
                return err_info;
            }
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
    struct lyd_attr *attr;

    if (!(opts & (SR_OPER_NO_STATE | SR_OPER_NO_CONFIG)) && (opts & SR_OPER_WITH_ORIGIN)) {
        /* nothing to trim */
        return;
    }

    LY_TREE_FOR_SAFE(sibling, next, elem) {
        assert((elem->schema->nodetype != LYS_LEAF) || !lys_is_key((struct lys_node_leaf *)elem->schema, NULL));
        if (elem->schema->flags & LYS_CONFIG_R) {
            /* state subtree */
            if (opts & SR_OPER_NO_STATE) {
                /* free it whole */
                if (*data == elem) {
                    *data = (*data)->next;
                }
                lyd_free(elem);
                continue;
            }

            if (opts & SR_OPER_WITH_ORIGIN) {
                /* no need to go into state children */
                continue;
            }
        }

        /* trim all our children */
        sr_oper_data_trim_r(data, sr_lyd_child(elem, 1), opts);

        if ((elem->schema->flags & LYS_CONFIG_W) && (opts & SR_OPER_NO_CONFIG) && !sr_lyd_child(elem, 1)) {
            /* config-only subtree (config node with no children) */
            if (*data == elem) {
                *data = (*data)->next;
            }
            lyd_free(elem);
            continue;
        }

        if (!(opts & SR_OPER_WITH_ORIGIN)) {
            /* trim origin */
            LY_TREE_FOR(elem->attr, attr) {
                if (!strcmp(attr->name, "origin") && !strcmp(attr->annotation->module->name, "ietf-origin")) {
                    lyd_free_attr(elem->schema->module->ctx, elem, attr, 0);
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

    /* get the data from libyang */
    mod_data = ly_ctx_info(mod_info->conn->ly_ctx);
    SR_CHECK_LY_RET(!mod_data, mod_info->conn->ly_ctx, err_info);

    if (!strcmp(mod->ly_mod->rev[0].date, "2019-01-04")) {
        assert(!strcmp(mod_data->schema->name, "yang-library"));

        /* add supported datastores */
        if (!lyd_new_path(mod_data, NULL, "datastore[name='ietf-datastores:running']/schema", "complete", 0, 0)
                || !lyd_new_path(mod_data, NULL, "datastore[name='ietf-datastores:candidate']/schema", "complete", 0, 0)
                || !lyd_new_path(mod_data, NULL, "datastore[name='ietf-datastores:startup']/schema", "complete", 0, 0)
                || !lyd_new_path(mod_data, NULL, "datastore[name='ietf-datastores:operational']/schema", "complete", 0, 0)) {
            sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
            return err_info;
        }
    } else if (!strcmp(mod->ly_mod->rev[0].date, "2016-06-21")) {
        assert(!strcmp(mod_data->schema->name, "modules-state"));

        /* all data should already be there */
    } else {
        /* no other revision is supported */
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

    /* connect to the rest of data */
    if (!mod_info->data) {
        mod_info->data = mod_data;
    } else if (lyd_merge(mod_info->data, mod_data, LYD_OPT_DESTRUCT | LYD_OPT_EXPLICIT)) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
        return err_info;
    }

    return NULL;
}

static sr_error_info_t *
sr_modinfo_module_srmon_evpipe2pid(sr_main_shm_t *main_shm, char *ext_shm_addr, uint32_t evpipe_num, uint32_t *pid)
{
    sr_error_info_t *err_info = NULL;
    sr_conn_shm_t *shm_conn;
    uint32_t *evpipe;
    uint16_t i, j;

    shm_conn = (sr_conn_shm_t *)(ext_shm_addr + main_shm->conns);
    for (i = 0; i < main_shm->conn_count; ++i) {
        evpipe = (uint32_t *)(ext_shm_addr + shm_conn[i].evpipes);
        for (j = 0; j < shm_conn[i].evpipe_count; ++j) {
            if (evpipe[j] == evpipe_num) {
                /* matching evpipe num found */
                *pid = shm_conn[i].pid;
                return NULL;
            }
        }
    }

    SR_ERRINFO_INT(&err_info);
    return err_info;
}

/**
 * @brief Append a "module" data node with its subscriptions to sysrepo-monitoring data.
 *
 * @param[in] main_shm Main SHM structure.
 * @param[in] ext_shm_addr Ext SHM address.
 * @param[in] shm_mod SHM module to read from.
 * @param[in,out] sr_state Main container node of sysrepo-monitoring.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_module_srmon_module(sr_main_shm_t *main_shm, char *ext_shm_addr, sr_mod_t *shm_mod, struct lyd_node *sr_state)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mod, *sr_subs, *sr_sub;
    sr_datastore_t ds;
    sr_mod_change_sub_t *change_sub;
    sr_mod_oper_sub_t *oper_sub;
    sr_mod_notif_sub_t *notif_sub;
    uint16_t i;
    char buf[22];
    uint32_t pid;
    struct ly_ctx *ly_ctx;

    ly_ctx = lyd_node_module(sr_state)->ctx;

    /* module */
    sr_mod = lyd_new(sr_state, NULL, "module");
    SR_CHECK_LY_RET(!sr_mod, ly_ctx, err_info);

    /* name */
    SR_CHECK_LY_RET(!lyd_new_leaf(sr_mod, NULL, "name", ext_shm_addr + shm_mod->name), ly_ctx, err_info);

    /* subscriptions, make implicit */
    sr_subs = lyd_new(sr_mod, NULL, "subscriptions");
    SR_CHECK_LY_RET(!sr_subs, ly_ctx, err_info);
    sr_subs->dflt = 1;

    for (ds = 0; ds < SR_DS_COUNT; ++ds) {
        change_sub = (sr_mod_change_sub_t *)(ext_shm_addr + shm_mod->change_sub[ds].subs);
        for (i = 0; i < shm_mod->change_sub[ds].sub_count; ++i) {
            /* change-sub */
            sr_sub = lyd_new(sr_subs, NULL, "change-sub");
            SR_CHECK_LY_RET(!sr_sub, ly_ctx, err_info);

            /* datastore */
            SR_CHECK_LY_RET(!lyd_new_leaf(sr_sub, NULL, "datastore", sr_ds2ident(ds)), ly_ctx, err_info);

            /* xpath */
            if (change_sub[i].xpath) {
                SR_CHECK_LY_RET(!lyd_new_leaf(sr_sub, NULL, "xpath", ext_shm_addr + change_sub[i].xpath),
                        ly_ctx, err_info);
            }

            /* priority */
            sprintf(buf, "%"PRIu32, change_sub[i].priority);
            SR_CHECK_LY_RET(!lyd_new_leaf(sr_sub, NULL, "priority", buf), ly_ctx, err_info);

            /* pid */
            if ((err_info = sr_modinfo_module_srmon_evpipe2pid(main_shm, ext_shm_addr, change_sub[i].evpipe_num, &pid))) {
                return err_info;
            }
            sprintf(buf, "%"PRIu32, pid);
            SR_CHECK_LY_RET(!lyd_new_leaf(sr_sub, NULL, "pid", buf), ly_ctx, err_info);
        }
    }

    oper_sub = (sr_mod_oper_sub_t *)(ext_shm_addr + shm_mod->oper_subs);
    for (i = 0; i < shm_mod->oper_sub_count; ++i) {
        /* operational-sub */
        sr_sub = lyd_new(sr_subs, NULL, "operational-sub");
        SR_CHECK_LY_RET(!sr_sub, ly_ctx, err_info);

        /* xpath */
        SR_CHECK_LY_RET(!lyd_new_leaf(sr_sub, NULL, "xpath", ext_shm_addr + oper_sub[i].xpath),
                ly_ctx, err_info);

        /* pid */
        if ((err_info = sr_modinfo_module_srmon_evpipe2pid(main_shm, ext_shm_addr, oper_sub[i].evpipe_num, &pid))) {
            return err_info;
        }
        sprintf(buf, "%"PRIu32, pid);
        SR_CHECK_LY_RET(!lyd_new_leaf(sr_sub, NULL, "pid", buf), ly_ctx, err_info);
    }

    notif_sub = (sr_mod_notif_sub_t *)(ext_shm_addr + shm_mod->notif_subs);
    for (i = 0; i < shm_mod->notif_sub_count; ++i) {
        /* notification-sub with pid */
        if ((err_info = sr_modinfo_module_srmon_evpipe2pid(main_shm, ext_shm_addr, notif_sub[i].evpipe_num, &pid))) {
            return err_info;
        }
        sprintf(buf, "%"PRIu32, pid);
        SR_CHECK_LY_RET(!lyd_new_leaf(sr_subs, NULL, "notification-sub", buf), ly_ctx, err_info);
    }

    return NULL;
}

/**
 * @brief Append an "rpc" data node with its subscriptions to sysrepo-monitoring data.
 *
 * @param[in] main_shm Main SHM structure.
 * @param[in] ext_shm_addr Ext SHM address.
 * @param[in] shm_rpc SHM RPC to read from.
 * @param[in,out] sr_state Main container node of sysrepo-monitoring.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_module_srmon_rpc(sr_main_shm_t *main_shm, char *ext_shm_addr, sr_rpc_t *shm_rpc, struct lyd_node *sr_state)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_rpc, *sr_sub;
    sr_rpc_sub_t *rpc_sub;
    uint16_t i;
    char buf[22];
    uint32_t pid;
    struct ly_ctx *ly_ctx;

    ly_ctx = lyd_node_module(sr_state)->ctx;

    /* rpc */
    sr_rpc = lyd_new(sr_state, NULL, "rpc");
    SR_CHECK_LY_RET(!sr_rpc, ly_ctx, err_info);

    /* path */
    SR_CHECK_LY_RET(!lyd_new_leaf(sr_rpc, NULL, "path", ext_shm_addr + shm_rpc->op_path), ly_ctx, err_info);

    rpc_sub = (sr_rpc_sub_t *)(ext_shm_addr + shm_rpc->subs);
    for (i = 0; i < shm_rpc->sub_count; ++i) {
        /* rpc-sub */
        sr_sub = lyd_new(sr_rpc, NULL, "rpc-sub");
        SR_CHECK_LY_RET(!sr_sub, ly_ctx, err_info);

        /* xpath */
        SR_CHECK_LY_RET(!lyd_new_leaf(sr_sub, NULL, "xpath", ext_shm_addr + rpc_sub[i].xpath),
                ly_ctx, err_info);

        /* priority */
        sprintf(buf, "%"PRIu32, rpc_sub[i].priority);
        SR_CHECK_LY_RET(!lyd_new_leaf(sr_sub, NULL, "priority", buf), ly_ctx, err_info);

        /* pid */
        if ((err_info = sr_modinfo_module_srmon_evpipe2pid(main_shm, ext_shm_addr, rpc_sub[i].evpipe_num, &pid))) {
            return err_info;
        }
        sprintf(buf, "%"PRIu32, pid);
        SR_CHECK_LY_RET(!lyd_new_leaf(sr_sub, NULL, "pid", buf), ly_ctx, err_info);
    }

    return NULL;
}

/**
 * @brief Append a "connection" data node with its locks to sysrepo-monitoring data.
 *
 * @param[in] main_shm Main SHM structure.
 * @param[in] ext_shm_addr Ext SHM address.
 * @param[in] shm_conn SHM connection to read from.
 * @param[in,out] sr_state Main container node of sysrepo-monitoring.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_module_srmon_connection(sr_main_shm_t *main_shm, char *ext_shm_addr, sr_conn_shm_t *shm_conn,
        struct lyd_node *sr_state)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_conn, *sr_modlock;
    sr_mod_t *shm_mod;
    sr_conn_shm_lock_t (*mod_locks)[SR_DS_COUNT];
    uint16_t i;
    sr_datastore_t ds;
    char buf[22];
    struct ly_ctx *ly_ctx;

    ly_ctx = lyd_node_module(sr_state)->ctx;

    /* connection */
    sr_conn = lyd_new(sr_state, NULL, "connection");
    SR_CHECK_LY_RET(!sr_conn, ly_ctx, err_info);

    /* pid */
    sprintf(buf, "%ld", (long)shm_conn->pid);
    SR_CHECK_LY_RET(!lyd_new_leaf(sr_conn, NULL, "pid", buf), ly_ctx, err_info);

    /* main-lock */
    if (shm_conn->main_lock.mode) {
        if (shm_conn->main_lock.mode == SR_LOCK_READ) {
            sprintf(buf, "read");
        } else {
            sprintf(buf, "write");
        }
        SR_CHECK_LY_RET(!lyd_new_leaf(sr_conn, NULL, "main-lock", buf), ly_ctx, err_info);
    }

    mod_locks = (sr_conn_shm_lock_t (*)[SR_DS_COUNT])(ext_shm_addr + shm_conn->mod_locks);
    shm_mod = SR_FIRST_SHM_MOD(main_shm);
    for (i = 0; i < main_shm->mod_count; ++i) {
        for (ds = 0; ds < SR_DS_COUNT; ++ds) {
            if (!mod_locks[i][ds].mode) {
                continue;
            }

            /* module-lock */
            sr_modlock = lyd_new(sr_conn, NULL, "module-lock");
            SR_CHECK_LY_RET(!sr_modlock, ly_ctx, err_info);

            /* name */
            SR_CHECK_LY_RET(!lyd_new_leaf(sr_modlock, NULL, "name", ext_shm_addr + shm_mod[i].name), ly_ctx, err_info);

            /* datastore */
            SR_CHECK_LY_RET(!lyd_new_leaf(sr_modlock, NULL, "datastore", sr_ds2ident(ds)), ly_ctx, err_info);

            /* lock */
            if (mod_locks[i][ds].mode == SR_LOCK_READ) {
                sprintf(buf, "read");
            } else {
                sprintf(buf, "write");
            }
            SR_CHECK_LY_RET(!lyd_new_leaf(sr_modlock, NULL, "lock", buf), ly_ctx, err_info);
        }
    }

    return NULL;
}

/**
 * @brief Load module data of the sysrepo-monitoring module. They are actually generated.
 *
 * SHM READ lock is expected to be held.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] mod Mod info module to use.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_module_data_load_srmon(struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *mod_data;
    sr_mod_t *shm_mod;
    sr_rpc_t *shm_rpc;
    sr_conn_shm_t *shm_conn;
    const struct lys_module *ly_mod;
    sr_main_shm_t *main_shm;
    uint16_t i;

    main_shm = (sr_main_shm_t *)mod_info->conn->main_shm.addr;
    ly_mod = ly_ctx_get_module(mod_info->conn->ly_ctx, "sysrepo-monitoring", NULL, 1);
    assert(ly_mod);

    /* main container */
    mod_data = lyd_new(NULL, ly_mod, "sysrepo-state");
    SR_CHECK_LY_GOTO(!mod_data, mod_info->conn->ly_ctx, err_info, cleanup);

    /* modules */
    SR_SHM_MOD_FOR(mod_info->conn->main_shm.addr, mod_info->conn->main_shm.size, shm_mod) {
        if ((err_info = sr_modinfo_module_srmon_module(main_shm, mod_info->conn->ext_shm.addr, shm_mod, mod_data))) {
            goto cleanup;
        }
    }

    /* RPCs */
    shm_rpc = (sr_rpc_t *)(mod_info->conn->ext_shm.addr + main_shm->rpc_subs);
    for (i = 0; i < main_shm->rpc_sub_count; ++i) {
        if ((err_info = sr_modinfo_module_srmon_rpc(main_shm, mod_info->conn->ext_shm.addr, &shm_rpc[i], mod_data))) {
            goto cleanup;
        }
    }

    /* connections */
    shm_conn = (sr_conn_shm_t *)(mod_info->conn->ext_shm.addr + main_shm->conns);
    for (i = 0; i < main_shm->conn_count; ++i) {
        if ((err_info = sr_modinfo_module_srmon_connection(main_shm, mod_info->conn->ext_shm.addr, &shm_conn[i], mod_data))) {
            goto cleanup;
        }
    }

    /* connect to the rest of data */
    if (!mod_info->data) {
        mod_info->data = mod_data;
    } else if (lyd_merge(mod_info->data, mod_data, LYD_OPT_DESTRUCT | LYD_OPT_EXPLICIT)) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
        goto cleanup;
    }
    mod_data = NULL;

cleanup:
    lyd_free_withsiblings(mod_data);
    return err_info;
}

/**
 * @brief Load module data of a specific module.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] mod Mod info module to process.
 * @param[in] load_diff Whether to load stored operational diff of the module.
 * @param[in] sid Sysrepo session ID.
 * @param[in] request_xpath XPath of the data request.
 * @param[in] timeout_ms Operational callback timeout in milliseconds.
 * @param[in] opts Get oper data options.
 * @param[out] cb_error_info Callback error info returned by operational subscribers, if any.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_module_data_load(struct sr_mod_info_s *mod_info, struct sr_mod_info_mod_s *mod, sr_sid_t *sid,
        const char *request_xpath, uint32_t timeout_ms, sr_get_oper_options_t opts, sr_error_info_t **cb_error_info)
{
    sr_error_info_t *err_info = NULL;
    sr_conn_ctx_t *conn = mod_info->conn;
    struct sr_mod_cache_s *mod_cache = NULL;
    struct lyd_node *mod_data;
    sr_datastore_t conf_ds;

    if (((mod_info->ds == SR_DS_RUNNING) || (mod_info->ds2 == SR_DS_RUNNING)) && (conn->opts & SR_CONN_CACHE_RUNNING)) {
        /* we are caching running data we will use, so in all cases load the module into cache if not yet there */
        mod_cache = &conn->mod_cache;
        if ((err_info = sr_modcache_module_running_update(mod_cache, mod, NULL, mod_info->data_cached))) {
            return err_info;
        }
    }

    if (!mod_info->data_cached) {
        /* we cannot use cached data directly for this operation... */
        if (mod_cache) {
            /* ...but they are cached */

            /* CACHE READ LOCK */
            if ((err_info = sr_rwlock(&mod_cache->lock, SR_MOD_CACHE_LOCK_TIMEOUT * 1000, SR_LOCK_READ, __func__))) {
                return err_info;
            }

            if (mod_info->ds == SR_DS_OPERATIONAL) {
                /* copy only enabled module data */
                err_info = sr_module_oper_data_dup_enabled(mod_cache->data, conn->ext_shm.addr, mod, opts, &mod_data);
            } else {
                /* copy all module data */
                err_info = sr_module_data_dup(mod_cache->data, mod->ly_mod, &mod_data);
            }

            /* CACHE READ UNLOCK */
            sr_rwunlock(&mod_cache->lock, SR_LOCK_READ, __func__);

            if (err_info) {
                return err_info;
            }
            if (mod_info->data) {
                sr_ly_link(mod_info->data, mod_data);
            } else {
                mod_info->data = mod_data;
            }
        } else {
            /* ...and they are not cached */
            if (mod_info->ds == SR_DS_OPERATIONAL) {
                conf_ds = SR_DS_RUNNING;
            } else {
                conf_ds = mod_info->ds;
            }
            /* get current persistent data */
            if ((err_info = sr_module_file_data_append(mod->ly_mod, conf_ds, &mod_info->data))) {
                return err_info;
            }

            if (mod_info->ds == SR_DS_OPERATIONAL) {
                /* keep only enabled module data */
                if ((err_info = sr_module_oper_data_dup_enabled(mod_info->data, conn->ext_shm.addr, mod, opts,
                            &mod_data))) {
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
            if ((err_info = sr_module_oper_data_update(mod, sid, request_xpath, conn->ext_shm.addr,
                        timeout_ms, opts, &mod_info->data, cb_error_info))) {
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
 * @brief Add modules and data dependencies of instance-identifiers to mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] shm_deps SHM dependencies of relevant instance-identifiers.
 * @param[in] shm_dep_count SHM dependency count.
 * @param[in] sid Sysrepo session ID.
 * @param[in] timeout_ms Operational callback timeout in milliseconds.
 * @param[out] cb_error_info Callback error info returned by oper subscribers, if any.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_add_instid_deps_data(struct sr_mod_info_s *mod_info, sr_mod_data_dep_t *shm_deps, uint16_t shm_dep_count,
        const struct lyd_node *data, sr_sid_t *sid, uint32_t timeout_ms, sr_error_info_t **cb_error_info)
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
                    dep_mod = sr_shmmain_find_module(&conn->main_shm, conn->ext_shm.addr, mod_name, 0);
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
                dep_mod = sr_shmmain_find_module(&conn->main_shm, NULL, NULL, shm_deps[i].module);
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

        ly_mod = ly_ctx_get_module(mod_info->conn->ly_ctx, conn->ext_shm.addr + dep_mod->name, NULL, 1);
        SR_CHECK_INT_GOTO(!ly_mod, err_info, cleanup);

        /* remember how many modules there were and add this one */
        j = mod_info->mod_count;
        if ((err_info = sr_modinfo_add_mod(dep_mod, ly_mod, MOD_INFO_DEP, 0, mod_info))) {
            goto cleanup;
        }

        /* add this module data if not already there */
        if ((j < mod_info->mod_count) && (err_info = sr_modinfo_module_data_load(mod_info, &mod_info->mods[j], sid,
                    NULL, timeout_ms, 0, cb_error_info))) {
            goto cleanup;
        }
    }

    /* success */

cleanup:
    ly_set_free(set);
    ly_set_free(dep_set);
    return err_info;
}

static sr_error_info_t *
sr_modinfo_ly_val_diff_merge(struct sr_mod_info_s *mod_info, struct lyd_difflist *val_diff)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *node;
    struct lys_node *snode;
    uint32_t i, j;
    int change;

    assert(val_diff);

    for (i = 0; val_diff->type[i] != LYD_DIFF_END; ++i) {
        if ((err_info = sr_ly_val_diff_merge(&mod_info->diff, val_diff->type[i], val_diff->first[i],
                val_diff->second[i], mod_info->conn->ly_ctx, &change))) {
            return err_info;
        }

        /* additional modules can be modified */
        if (change) {
            if (val_diff->type[i] == LYD_DIFF_CREATED) {
                node = val_diff->second[i];
            } else {
                node = val_diff->first[i];
            }

            /* get the module that actually owns the data (handle augments) */
            for (snode = node->schema; lys_parent(snode); snode = lys_parent(snode));
            for (j = 0; j < mod_info->mod_count; ++j) {
                if (lys_node_module(snode) == mod_info->mods[j].ly_mod) {
                    mod_info->mods[j].state |= MOD_INFO_CHANGED;
                    break;
                }
            }
            assert(j < mod_info->mod_count);
        }
    }

    return NULL;
}

sr_error_info_t *
sr_modinfo_validate(struct sr_mod_info_s *mod_info, int finish_diff, sr_sid_t *sid, sr_error_info_t **cb_error_info)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    struct lyd_difflist *diff = NULL;
    const struct lys_module **valid_mods = NULL;
    uint32_t i, j, valid_mod_count = 0;
    int flags;

    assert(SR_IS_CONVENTIONAL_DS(mod_info->ds) || (sid && cb_error_info));
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
                        (sr_mod_data_dep_t *)(mod_info->conn->ext_shm.addr + mod->shm_mod->data_deps),
                        mod->shm_mod->data_dep_count, mod_info->data, sid, 0, cb_error_info))) {
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
    if (SR_IS_CONVENTIONAL_DS(mod_info->ds)) {
        flags = LYD_OPT_CONFIG | LYD_OPT_WHENAUTODEL | LYD_OPT_VAL_DIFF;
    } else {
        flags = LYD_OPT_DATA | LYD_OPT_WHENAUTODEL | LYD_OPT_VAL_DIFF;
    }
    if (lyd_validate_modules(&mod_info->data, valid_mods, valid_mod_count, flags, &diff)) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
        SR_ERRINFO_VALID(&err_info);
        goto cleanup;
    }

    if (finish_diff) {
        /* merge the changes made by the validation into our diff */
        if ((err_info = sr_modinfo_ly_val_diff_merge(mod_info, diff))) {
            goto cleanup;
        }
    }

    /* success */

cleanup:
    lyd_free_val_diff(diff);
    free(valid_mods);
    return err_info;
}

sr_error_info_t *
sr_modinfo_add_defaults(struct sr_mod_info_s *mod_info, int finish_diff)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    struct lyd_difflist *diff = NULL;
    const struct lys_module **valid_mods = NULL;
    uint32_t i, valid_mod_count = 0;
    int flags;

    assert(!mod_info->data_cached);

    /* create an array of all the modules that will be processed */
    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        switch (mod->state & MOD_INFO_TYPE_MASK) {
        case MOD_INFO_REQ:
            /* this module will be validated */
            valid_mods = sr_realloc(valid_mods, (valid_mod_count + 1) * sizeof *valid_mods);
            SR_CHECK_MEM_GOTO(!valid_mods, err_info, cleanup);
            valid_mods[valid_mod_count] = mod->ly_mod;
            ++valid_mod_count;
            break;
        case MOD_INFO_INV_DEP:
        case MOD_INFO_DEP:
            /* this module will not be validated */
            break;
        default:
            SR_CHECK_INT_GOTO(0, err_info, cleanup);
        }
    }

    /* just add default values and generate diff */
    flags = (mod_info->ds == SR_DS_OPERATIONAL ? LYD_OPT_DATA : LYD_OPT_CONFIG) | LYD_OPT_TRUSTED | LYD_OPT_VAL_DIFF;
    if (lyd_validate_modules(&mod_info->data, valid_mods, valid_mod_count, flags, &diff)) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
        goto cleanup;
    }

    if (finish_diff) {
        /* merge the changes made by the validation into our diff */
        if ((err_info = sr_modinfo_ly_val_diff_merge(mod_info, diff))) {
            goto cleanup;
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
        uint16_t shm_dep_count, int output, sr_sid_t *sid, uint32_t timeout_ms, sr_error_info_t **cb_error_info)
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

    /* find top-level node */
    for (top_op = op; top_op->parent; top_op = top_op->parent);

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        switch (mod->state & MOD_INFO_TYPE_MASK) {
        case MOD_INFO_REQ:
            /* this is the module of the nested operation and we need to check that operation's parent data node exists */
            assert((mod->ly_mod == lyd_node_module(top_op)) && lys_parent(op->schema) && op->parent);
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
                sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, parent_xpath,
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
    if ((err_info = sr_modinfo_add_instid_deps_data(mod_info, shm_deps, shm_dep_count, op, sid, timeout_ms, cb_error_info))) {
        goto cleanup;
    }

    /* validate */
    flags = ((op->schema->nodetype & (LYS_RPC | LYS_ACTION)) ? (output ? LYD_OPT_RPCREPLY : LYD_OPT_RPC) : LYD_OPT_NOTIF);
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
sr_modinfo_data_load(struct sr_mod_info_s *mod_info, uint8_t mod_type, int cache, sr_sid_t *sid,
        const char *request_xpath, uint32_t timeout_ms, sr_get_oper_options_t opts, sr_error_info_t **cb_error_info)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    uint32_t i;

    assert(!mod_info->data);

    /* we can use cache only if we are working with the running datastore (as the main datastore) */
    if (cache && (mod_info->conn->opts & SR_CONN_CACHE_RUNNING) && (mod_info->ds == SR_DS_RUNNING)) {
        /* CACHE READ LOCK */
        if ((err_info = sr_rwlock(&mod_info->conn->mod_cache.lock, SR_MOD_CACHE_LOCK_TIMEOUT * 1000, SR_LOCK_READ, __func__))) {
            return err_info;
        }

        /* we can cache the data */
        mod_info->data_cached = 1;
    }

    /* load data for each module */
    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & mod_type) {
            if ((err_info = sr_modinfo_module_data_load(mod_info, mod, sid, request_xpath, timeout_ms, opts, cb_error_info))) {
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
                mod_info->data = lyd_dup_withsiblings(mod_info->data, LYD_DUP_OPT_RECURSIVE | LYD_DUP_OPT_WITH_WHEN);
                mod_info->data_cached = 0;

                /* CACHE READ UNLOCK */
                sr_rwunlock(&mod_info->conn->mod_cache.lock, SR_LOCK_READ, __func__);
            }

            /* apply any currently handled changes (diff) or additional performed ones (edit) to get
             * the session-specific data tree */
            if ((err_info = sr_diff_mod_apply(diff, mod->ly_mod, session->ds == SR_DS_OPERATIONAL ? 1 : 0, &mod_info->data))) {
                goto cleanup;
            }
            if ((err_info = sr_edit_mod_apply(edit, mod->ly_mod, &mod_info->data, NULL, NULL))) {
                goto cleanup;
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

    /* success */

cleanup:
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
    sr_mod_notif_sub_t *notif_subs;
    uint32_t idx = 0, notif_sub_count;
    char *xpath, nc_str[11];
    const char *op_enum;
    sr_change_oper_t op;
    enum edit_op edit_op;
    int changes;

    /* make sure there are some actual node changes */
    changes = 0;
    LY_TREE_FOR(mod_info->diff, root) {
        LY_TREE_DFS_BEGIN(root, next, elem) {
            edit_op = sr_edit_find_oper(elem, 0, NULL);
            if (edit_op && (edit_op != EDIT_NONE)) {
                changes = 1;
                break;
            }
            LY_TREE_DFS_END(root, next, elem);
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
    notif_ts = time(NULL);

    /* get subscriber count */
    if ((err_info = sr_notif_find_subscriber(session->conn, "ietf-netconf-notifications", &notif_subs, &notif_sub_count))) {
        return err_info;
    }

    /* get this module and check replay support */
    shm_mod = sr_shmmain_find_module(&mod_info->conn->main_shm, mod_info->conn->ext_shm.addr, "ietf-netconf-notifications", 0);
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
        default:
            SR_ERRINFO_INT(&err_info);
            goto cleanup;
        }
        next = lyd_new_leaf(root, NULL, "operation", op_enum);
        if (!next) {
            sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
            goto cleanup;
        }
    }

    /* store the notification for a replay, we continue on failure */
    tmp_err_info = sr_replay_store(session, notif, notif_ts);

    /* send the notification (non-validated, if everything works correctly it must be valid) */
    if (notif_sub_count && (err_info = sr_shmsub_notif_notify(notif, notif_ts, session->sid, (uint32_t *)notif_subs,
            notif_sub_count))) {
        goto cleanup;
    }

    /* success */

cleanup:
    ly_set_free(set);
    lyd_free_withsiblings(notif);
    if (err_info) {
        /* write this only if the notification failed to be created/sent */
        sr_errinfo_new(&err_info, err_info->err_code, NULL, "Failed to generate netconf-config-change notification, "
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
    sr_error_info_t *err_info = NULL, *tmp_err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    struct lyd_node *mod_data, *diff = NULL;
    uint32_t i;
    int change, create_flags;

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
            if (mod_info->ds == SR_DS_OPERATIONAL) {
                /* load current diff and merge it with the new diff */
                if ((err_info = sr_module_file_data_append(mod->ly_mod, SR_DS_OPERATIONAL, &diff))) {
                    goto cleanup;
                }
                if ((err_info = sr_diff_mod_merge(mod_info->diff, mod_info->conn, mod->ly_mod, &diff, &change))) {
                    goto cleanup;
                }

                /* store the new diff */
                if (change && (err_info = sr_module_file_data_set(mod->ly_mod->name, SR_DS_OPERATIONAL, diff, 0, 0))) {
                    goto cleanup;
                }
                lyd_free_withsiblings(diff);
                diff = NULL;
            } else {
                /* separate data of this module */
                mod_data = sr_module_data_unlink(&mod_info->data, mod->ly_mod);

                /* store the new data */
                if ((err_info = sr_module_file_data_set(mod->ly_mod->name, mod_info->ds, mod_data, create_flags, SR_FILE_PERM))) {
                    goto cleanup;
                }

                if (mod_info->ds == SR_DS_RUNNING) {
                    /* update module running data version */
                    ++mod->shm_mod->ver;

                    if (mod_info->conn->opts & SR_CONN_CACHE_RUNNING) {
                        /* we are caching so update cache with these data */
                        tmp_err_info = sr_modcache_module_running_update(&mod_info->conn->mod_cache, mod, mod_data, 0);
                        if (tmp_err_info) {
                            /* always store all changed modules, if possible */
                            sr_errinfo_merge(&err_info, tmp_err_info);
                            tmp_err_info = NULL;
                        }
                    }
                }

                /* connect them back */
                if (mod_info->data) {
                    sr_ly_link(mod_info->data, mod_data);
                } else {
                    mod_info->data = mod_data;
                }

                if (mod_info->ds == SR_DS_RUNNING) {
                    /* add possible default state data nodes so that stored diff can be properly applied */
                    lyd_validate_modules(&mod_data, &mod->ly_mod, 1, LYD_OPT_DATA | LYD_OPT_TRUSTED);

                    /* update diffs of stored operational data, if any */
                    if ((err_info = sr_module_file_data_append(mod->ly_mod, SR_DS_OPERATIONAL, &diff))) {
                        goto cleanup;
                    }
                    if ((err_info = sr_diff_mod_update(&diff, mod->ly_mod, mod_data))) {
                        goto cleanup;
                    }
                    if ((err_info = sr_module_file_data_set(mod->ly_mod->name, SR_DS_OPERATIONAL, diff, 0, 0))) {
                        goto cleanup;
                    }
                    lyd_free_withsiblings(diff);
                    diff = NULL;
                }
            }
        }
    }

cleanup:
    if (tmp_err_info) {
        sr_errinfo_merge(&err_info, tmp_err_info);
    }
    lyd_free_withsiblings(diff);
    return err_info;

}

sr_error_info_t *
sr_modinfo_candidate_reset(struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    char *path;
    uint32_t i;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & MOD_INFO_REQ) {
            /* just remove the candidate SHM files */
            if ((err_info = sr_path_ds_shm(mod->ly_mod->name, SR_DS_CANDIDATE, 0, &path))) {
                return err_info;
            }

            if ((shm_unlink(path) == -1) && (errno != ENOENT)) {
                SR_LOG_WRN("Failed to unlink \"%s\" (%s).", path, strerror(errno));
            }
            free(path);
        }
    }

    return NULL;
}

void
sr_modinfo_free(struct sr_mod_info_s *mod_info)
{
    lyd_free_withsiblings(mod_info->diff);
    if (mod_info->data_cached) {
        mod_info->data_cached = 0;

        /* CACHE READ UNLOCK */
        sr_rwunlock(&mod_info->conn->mod_cache.lock, SR_LOCK_READ, __func__);
    } else {
        lyd_free_withsiblings(mod_info->data);
    }

    free(mod_info->mods);
}
