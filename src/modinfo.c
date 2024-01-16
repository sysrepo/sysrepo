/**
 * @file modinfo.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief routines for working with modinfo structure
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
#include "modinfo.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include <libyang/libyang.h>
#include <libyang/plugins_exts.h>
#include <libyang/plugins_types.h>

#include "common.h"
#include "edit_diff.h"
#include "log.h"
#include "lyd_mods.h"
#include "plugins_datastore.h"
#include "replay.h"
#include "shm_ext.h"
#include "shm_mod.h"
#include "shm_sub.h"
#include "subscr.h"
#include "utils/nacm.h"

static sr_error_info_t *sr_modinfo_data_load(struct sr_mod_info_s *mod_info, int cache, const char *orig_name,
        const void *orig_data, uint32_t timeout_ms, sr_get_oper_flag_t get_oper_opts);

sr_error_info_t *
sr_modinfo_add(const struct lys_module *ly_mod, const char *xpath, int dup_xpath, int no_dup_check,
        struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod = NULL;
    uint32_t i;
    void *mem;

    if (!no_dup_check) {
        /* try to find the module */
        for (i = 0; i < mod_info->mod_count; ++i) {
            if (mod_info->mods[i].ly_mod == ly_mod) {
                mod = &mod_info->mods[i];
                break;
            }
        }
    }

    if (!mod) {
        /* add new mod */
        mem = realloc(mod_info->mods, (mod_info->mod_count + 1) * sizeof *mod_info->mods);
        SR_CHECK_MEM_RET(!mem, err_info);
        mod_info->mods = mem;

        mod = &mod_info->mods[mod_info->mod_count];
        memset(mod, 0, sizeof *mod);
        ++mod_info->mod_count;

        mod->ly_mod = ly_mod;
        mod->state |= MOD_INFO_NEW;
    } else if (!mod->xpath_count) {
        /* mod is present with no xpaths (full data tree), nothing to add */
        return NULL;
    }

    if (xpath) {
        for (i = 0; i < mod->xpath_count; ++i) {
            if (!strcmp(mod->xpaths[i], xpath)) {
                /* xpath has already been added */
                return NULL;
            }
        }

        if (dup_xpath && !(mod->state & MOD_INFO_XPATH_DYN)) {
            /* duplicate all the current xpaths, they cannot be mixed */
            for (i = 0; i < mod->xpath_count; ++i) {
                mod->xpaths[i] = strdup(mod->xpaths[i]);
                SR_CHECK_MEM_RET(!mod->xpaths[i], err_info);
            }
            mod->state |= MOD_INFO_XPATH_DYN;
        }

        /* add xpath for mod */
        mem = realloc(mod->xpaths, (mod->xpath_count + 1) * sizeof *mod->xpaths);
        SR_CHECK_MEM_RET(!mem, err_info);
        mod->xpaths = mem;

        mod->xpaths[mod->xpath_count] = dup_xpath ? strdup(xpath) : xpath;
        ++mod->xpath_count;
    }

    return NULL;
}

sr_error_info_t *
sr_modinfo_add_all_modules_with_data(const struct ly_ctx *ly_ctx, int state_data, struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    uint32_t i = 0;

    while ((ly_mod = ly_ctx_get_module_iter(ly_ctx, &i))) {
        if (!ly_mod->implemented) {
            continue;
        } else if (!strcmp(ly_mod->name, "sysrepo")) {
            /* sysrepo module cannot be locked because it is not in SHM with other modules */
            continue;
        } else if (!strcmp(ly_mod->name, "ietf-netconf")) {
            /* ietf-netconf defines data but only internal that should be ignored */
            continue;
        } else if (!sr_module_has_data(ly_mod, state_data)) {
            /* no data */
            continue;
        }

        if ((err_info = sr_modinfo_add(ly_mod, NULL, 0, 1, mod_info))) {
            return err_info;
        }
    }

    return err_info;
}

sr_error_info_t *
sr_modinfo_collect_edit(const struct lyd_node *edit, struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    const struct lyd_node *root;
    const char *xpath;
    uint32_t i;

    /* add all the modules from the edit into our array */
    ly_mod = NULL;
    LY_LIST_FOR(edit, root) {
        if (!lyd_owner_module(root) || (lyd_owner_module(root) == ly_mod)) {
            continue;
        } else if (!strcmp(lyd_owner_module(root)->name, "sysrepo")) {
            if (root->schema || strcmp(LYD_NAME(root), "discard-items") || (mod_info->ds != SR_DS_OPERATIONAL)) {
                sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Data of internal module \"sysrepo\" cannot be modified.");
                return err_info;
            }

            xpath = lyd_get_value(root);
            if (xpath && xpath[0]) {
                /* collect xpath to discard */
                if ((err_info = sr_modinfo_collect_xpath(mod_info->conn->ly_ctx, xpath, SR_DS_OPERATIONAL, 0, 0, mod_info))) {
                    return err_info;
                }
            } else {
                /* add all the cached modules */
                for (i = 0; i < mod_info->conn->oper_push_mod_count; ++i) {
                    ly_mod = ly_ctx_get_module_implemented(mod_info->conn->ly_ctx, mod_info->conn->oper_push_mods[i]);
                    if (!ly_mod) {
                        /* could have been removed */
                        continue;
                    }
                    if ((err_info = sr_modinfo_add(ly_mod, NULL, 0, 0, mod_info))) {
                        return err_info;
                    }
                }
            }
            continue;
        }

        /* remember last mod, good chance it will also be the module of some next data nodes */
        ly_mod = lyd_owner_module(root);

        /* remember the module */
        if ((err_info = sr_modinfo_add(ly_mod, NULL, 0, 0, mod_info))) {
            return err_info;
        }
    }

    return NULL;
}

sr_error_info_t *
sr_modinfo_collect_xpath(const struct ly_ctx *ly_ctx, const char *xpath, sr_datastore_t ds, int store_xpath,
        int dup_xpath, struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *prev_ly_mod, *ly_mod;
    const struct lysc_node *snode;
    struct ly_set *set = NULL;
    struct ly_ctx *sm_ctx = NULL;
    uint32_t i;
    LY_ERR r;

    /* learn what nodes are needed for evaluation */
    if ((r = lys_find_xpath_atoms(ly_ctx, NULL, xpath, LYS_FIND_NO_MATCH_ERROR | LYS_FIND_SCHEMAMOUNT, &set))) {
        if (r == LY_ENOTFOUND) {
            /* no error message */
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL);
        } else {
            sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
            sr_errinfo_new(&err_info, SR_ERR_LY, "Invalid XPath \"%s\".", xpath);
        }
        goto cleanup;
    }

    /* add all the modules of the nodes */
    prev_ly_mod = NULL;
    for (i = 0; i < set->count; ++i) {
        snode = set->snodes[i];
        if (snode->module->ctx != ly_ctx) {
            /* skip mounted schema nodes and destroy the context */
            assert(!sm_ctx || (sm_ctx == snode->module->ctx));
            sm_ctx = snode->module->ctx;
            continue;
        } else if ((snode->nodetype & (LYS_RPC | LYS_NOTIF)) || ((snode->flags & LYS_CONFIG_R) && SR_IS_CONVENTIONAL_DS(ds))) {
            /* skip uninteresting nodes */
            continue;
        }

        ly_mod = lysc_owner_module(snode);
        if (ly_mod == prev_ly_mod) {
            /* skip already-added modules */
            continue;
        }
        prev_ly_mod = ly_mod;

        if (!ly_mod->implemented || !strcmp(ly_mod->name, "sysrepo") || !strcmp(ly_mod->name, "ietf-netconf")) {
            /* skip import-only modules, the internal sysrepo module, and ietf-netconf (as it has no data, only in libyang) */
            continue;
        }

        if ((err_info = sr_modinfo_add(ly_mod, store_xpath ? xpath : NULL, dup_xpath, 0, mod_info))) {
            goto cleanup;
        }
    }

cleanup:
    ly_ctx_destroy(sm_ctx);
    ly_set_free(set, NULL);
    return err_info;
}

sr_error_info_t *
sr_modinfo_collect_deps(struct sr_mod_info_s *mod_info)
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
            if ((err_info = sr_shmmod_collect_deps(SR_CONN_MOD_SHM(mod_info->conn),
                    (sr_dep_t *)(mod_info->conn->mod_shm.addr + mod->shm_mod->deps), mod->shm_mod->dep_count,
                    mod_info->data, mod_info))) {
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

sr_error_info_t *
sr_modinfo_collect_ext_deps(const struct lysc_node *mp_node, struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    char *path = NULL, *str_val = NULL, *mod_name;
    LY_ARRAY_COUNT_TYPE u;
    struct lysc_ext_instance *sm_ext = NULL;
    struct ly_set *set = NULL;
    struct lyd_node_term *term;
    struct lyd_value_xpath10 *xp_val;
    const struct lys_module *mod;
    struct ly_err_item *err;
    uint32_t i;

    /* check there is a mount-point defined */
    LY_ARRAY_FOR(mp_node->exts, u) {
        if (!strcmp(mp_node->exts[u].def->module->name, "ietf-yang-schema-mount") &&
                !strcmp(mp_node->exts[u].def->name, "mount-point")) {
            sm_ext = &mp_node->exts[u];
            break;
        }
    }
    if (!sm_ext) {
        goto cleanup;
    }

    /*
     * 1) collect all the mounted data, which can always be referenced
     */

    /* get path to the mount-point */
    path = lysc_path(mp_node, LYSC_PATH_DATA, NULL, 0);

    /* collect all the mounted data */
    if ((err_info = sr_modinfo_collect_xpath(mod_info->conn->ly_ctx, path, mod_info->ds, 1, 1, mod_info))) {
        goto cleanup;
    }

    /*
     * 2) collect all data in parent-references of the mount-point
     */

    if (!mod_info->conn->ly_ext_data) {
        /* no parent references for sure */
        goto cleanup;
    }

    /* get all parent references of this mount point */
    free(path);
    if (asprintf(&path, "/ietf-yang-schema-mount:schema-mounts/mount-point[module='%s'][label='%s']"
            "/shared-schema/parent-reference", sm_ext->module->name, sm_ext->argument) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    if (lyd_find_xpath(mod_info->conn->ly_ext_data, path, &set)) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
        goto cleanup;
    }

    for (i = 0; i < set->count; ++i) {
        term = (struct lyd_node_term *)set->dnodes[i];
        LYD_VALUE_GET(&term->value, xp_val);

        /* transform reference into JSON */
        free(str_val);
        str_val = NULL;
        if (lyplg_type_print_xpath10_value(xp_val, LY_VALUE_JSON, NULL, &str_val, &err)) {
            if (err) {
                sr_errinfo_new(&err_info, SR_ERR_LY, "%s", err->msg);
                ly_err_free(err);
            } else {
                sr_errinfo_new(&err_info, SR_ERR_LY, "Failed to print parent reference value.");
            }
            goto cleanup;
        }

        /* get the module */
        mod_name = sr_get_first_ns(str_val);
        mod = ly_ctx_get_module_implemented(mod_info->conn->ly_ctx, mod_name);
        free(mod_name);
        SR_CHECK_INT_GOTO(!mod, err_info, cleanup);

        /* collect the XPath and the module */
        if ((err_info = sr_modinfo_add(mod, str_val, 1, 0, mod_info))) {
            goto cleanup;
        }
    }

cleanup:
    free(path);
    free(str_val);
    ly_set_free(set, NULL);
    return err_info;
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
            if ((err_info = sr_perm_check(mod_info->conn, mod->ly_mod, mod_info->ds, wr, strict ? NULL : &has_access))) {
                return err_info;
            }

            if (!strict && !has_access) {
                /* remove this module from mod_info by moving all succeding modules */
                SR_LOG_INF("No %s permission for the module \"%s\", skipping.", wr ? "write" : "read", mod->ly_mod->name);
                free(mod->xpaths);
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
    struct sr_mod_info_mod_s *mod;
    const struct lyd_node *node;
    uint32_t *aux = NULL;
    int change;

    assert(!mod_info->data_cached);

    LY_LIST_FOR(edit, node) {
        ly_mod = lyd_owner_module(node);
        if (!ly_mod && !node->schema) {
            lyd_parse_opaq_error(node);
            sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
            return err_info;
        }

        /* invalid edit */
        assert(ly_mod);
        if (!strcmp(ly_mod->name, "sysrepo")) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Data of internal module \"sysrepo\" cannot be modified.");
            return err_info;
        }
    }

    mod = NULL;
    while ((mod = sr_modinfo_next_mod(mod, mod_info, edit, &aux))) {
        assert(mod->state & MOD_INFO_REQ);

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

cleanup:
    free(aux);
    return err_info;
}

sr_error_info_t *
sr_modinfo_edit_merge(struct sr_mod_info_s *mod_info, const struct lyd_node *edit, int create_diff)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod, *prev_mod;
    struct sr_mod_info_mod_s *mod;
    const struct lyd_node *node, *iter;
    struct lyd_node *change_edit = NULL, *diff = NULL;
    uint32_t *aux = NULL, i;
    const char *xpath;
    int change;

    assert(!mod_info->data_cached);

    LY_LIST_FOR(edit, node) {
        ly_mod = lyd_owner_module(node);
        if (!ly_mod && !node->schema) {
            lyd_parse_opaq_error(node);
            sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
            return err_info;
        }

        assert(ly_mod);
        if (strcmp(ly_mod->name, "sysrepo")) {
            continue;
        }

        /* invalid edit */
        if (node->schema || strcmp(LYD_NAME(node), "discard-items")) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Data of internal module \"sysrepo\" cannot be modified.");
            return err_info;
        }

        /* discard the selected edit nodes */
        xpath = lyd_get_value(node);
        if (xpath && !xpath[0]) {
            xpath = NULL;
        }
        if ((err_info = sr_edit_oper_del(&mod_info->data, mod_info->conn->cid, xpath, &change_edit))) {
            goto cleanup;
        }
    }

    if (change_edit) {
        /* set changed flags */
        prev_mod = NULL;
        LY_LIST_FOR(change_edit, iter) {
            ly_mod = lyd_owner_module(iter);
            if (ly_mod == prev_mod) {
                continue;
            }
            prev_mod = ly_mod;

            for (i = 0; i < mod_info->mod_count; ++i) {
                mod = &mod_info->mods[i];
                if (ly_mod == mod->ly_mod) {
                    mod->state |= MOD_INFO_CHANGED;
                    break;
                }
            }
        }

        if (create_diff) {
            /* create and merge diffs */
            if ((err_info = sr_edit2diff(change_edit, &diff))) {
                goto cleanup;
            }
            assert(!mod_info->diff);
            mod_info->diff = diff;
            diff = NULL;
        }
    }

    mod = NULL;
    while ((mod = sr_modinfo_next_mod(mod, mod_info, edit, &aux))) {
        assert(mod->state & MOD_INFO_REQ);

        /* merge relevant edit changes */
        if ((err_info = sr_edit_mod_merge(edit, mod_info->conn->cid, mod->ly_mod, &mod_info->data,
                create_diff ? &mod_info->diff : NULL, &change))) {
            goto cleanup;
        }

        if (change) {
            /* there is a diff for this module */
            mod->state |= MOD_INFO_CHANGED;
        }
    }

cleanup:
    lyd_free_siblings(change_edit);
    lyd_free_siblings(diff);
    free(aux);
    return err_info;
}

/**
 * @brief Merge sysrepo diff to mod info diff.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] new_diff New diff to merge into existing diff in mod_info.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_diff_merge(struct sr_mod_info_s *mod_info, const struct lyd_node *new_diff)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    uint32_t i;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & (MOD_INFO_REQ | MOD_INFO_INV_DEP)) {
            /* merge relevant diff part */
            if (lyd_diff_merge_module(&mod_info->diff, new_diff, mod->ly_mod, NULL, NULL, 0)) {
                sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
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
                sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, src_mod_data);
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
        mod = &mod_info->mods[j];
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
 * @brief Check whether operational data are required based on single request and subscription atom.
 *
 * @param[in] request_atom Request text atom.
 * @param[in] sub_atom Subscription text atom.
 * @return 0 data are not required based on the atoms;
 * @return 1 data are required;
 * @return 2 data are not required (would be filtered out).
 */
static int
sr_xpath_oper_data_text_atoms_required(const char *request_atom, const char *sub_atom)
{
    const char *req_ptr, *sub_ptr, *mod1, *name1, *val1, *mod2, *name2, *val2;
    int mlen1, mlen2, len1, len2, wildc1, wildc2;

    req_ptr = request_atom;
    sub_ptr = sub_atom;

    do {
        /* parse nodes */
        req_ptr = sr_xpath_next_qname(req_ptr + 1, &mod1, &mlen1, &name1, &len1);
        sub_ptr = sr_xpath_next_qname(sub_ptr + 1, &mod2, &mlen2, &name2, &len2);

        /* wildcards */
        if (((len1 == 1) && (name1[0] == '*')) || ((len1 == 2) && !strncmp(name1, "/.", 2))) {
            wildc1 = 1;
        } else {
            wildc1 = 0;
        }
        if (((len2 == 1) && (name2[0] == '*')) || ((len2 == 2) && !strncmp(name2, "/.", 2))) {
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

        /* value */
        if ((req_ptr[0] == '[') && (sub_ptr[0] == '[')) {
            val1 = req_ptr + 4;
            len1 = strchr(val1, req_ptr[3]) - val1;
            val2 = sub_ptr + 4;
            len2 = strchr(val2, sub_ptr[3]) - val2;
            if ((len1 != len2) || strncmp(val1, val2, len1)) {
                /* different values, filtered out */
                return 2;
            }
        }

        /* parse until the subscription path ends */
    } while (req_ptr[0] && sub_ptr[0]);

    /* atom match */
    return 1;
}

/**
 * @brief Check whether operational data are required.
 *
 * @param[in] request_xpath Get request full XPath.
 * @param[in] sub_xpath Operational subscription XPath.
 * @param[out] required Whether the oper data are required or not.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_xpath_oper_data_required(const char *request_xpath, const char *sub_xpath, int *required)
{
    sr_error_info_t *err_info = NULL;
    sr_xp_atoms_t *req_atoms = NULL, *sub_atoms = NULL;
    uint32_t i, j, k;
    int r;

    assert(sub_xpath);

    *required = 1;

    if (!request_xpath) {
        /* we do not know, say it is required */
        goto cleanup;
    }

    /* get text atoms for both xpaths */
    if ((err_info = sr_xpath_get_text_atoms(request_xpath, &req_atoms)) || !req_atoms) {
        goto cleanup;
    }
    if ((err_info = sr_xpath_get_text_atoms(sub_xpath, &sub_atoms)) || !sub_atoms) {
        goto cleanup;
    }
    assert(sub_atoms->union_count == 1);

    /* check whether any atoms match */
    *required = 0;
    for (i = 0; i < req_atoms->union_count; ++i) {
        for (j = 0; j < req_atoms->unions[i].atom_count; ++j) {
            for (k = 0; k < sub_atoms->unions[0].atom_count; ++k) {
                r = sr_xpath_oper_data_text_atoms_required(req_atoms->unions[i].atoms[j], sub_atoms->unions[0].atoms[k]);
                if (r == 1) {
                    /* required but need to check all atoms */
                    *required = 1;
                } else if (r == 2) {
                    /* not required for the union */
                    *required = 0;
                    break;
                }
            }
            if (k < sub_atoms->unions[0].atom_count) {
                break;
            }
        }

        if (*required) {
            /* required for a union */
            goto cleanup;
        }
    }

cleanup:
    sr_xpath_atoms_free(req_atoms);
    sr_xpath_atoms_free(sub_atoms);
    return err_info;
}

/**
 * @brief Get specific operational data from a subscriber.
 *
 * @param[in] mod Modinfo structure of the data.
 * @param[in] xpath XPath of the provided data.
 * @param[in] request_xpaths XPaths based on which these data are required, if NULL the complete module data are needed.
 * @param[in] req_xpath_count Count of @p request_xpaths.
 * @param[in] orig_name Event originator name.
 * @param[in] orig_data Event originator data.
 * @param[in] shm_subs Subscription array.
 * @param[in] idx1 Index of the subscription array from where to read subscriptions with the same XPath.
 * @param[in] parent Data parent required for the subscription, NULL if top-level.
 * @param[in] timeout_ms Operational callback timeout in milliseconds.
 * @param[in] conn Connection.
 * @param[out] oper_data Data tree with appended operational data.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_xpath_oper_data_get(struct sr_mod_info_mod_s *mod, const char *xpath, const char **request_xpaths,
        uint32_t req_xpath_count, const char *orig_name, const void *orig_data, sr_mod_oper_get_sub_t *shm_subs,
        uint32_t idx1, const struct lyd_node *parent, uint32_t timeout_ms, sr_conn_ctx_t *conn,
        struct lyd_node **oper_data)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    struct lyd_node *parent_dup = NULL, *last_parent;
    const char *request_xpath;
    char *parent_path = NULL;
    uint32_t i;
    int required;

    *oper_data = NULL;

    if (parent) {
        /* duplicate parent so that it is a stand-alone subtree */
        if (lyd_dup_single(parent, NULL, LYD_DUP_WITH_PARENTS, &last_parent)) {
            sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx, NULL);
            return err_info;
        }

        /* go top-level */
        for (parent_dup = last_parent; parent_dup->parent; parent_dup = lyd_parent(parent_dup)) {}

        if (req_xpath_count) {
            /* check whether the parent would not be filtered out */
            parent_path = lyd_path(last_parent, LYD_PATH_STD, NULL, 0);
            SR_CHECK_MEM_GOTO(!parent_path, err_info, cleanup);

            for (i = 0; i < req_xpath_count; ++i) {
                if ((err_info = sr_xpath_oper_data_required(request_xpaths[i], parent_path, &required))) {
                    goto cleanup;
                }
                if (required) {
                    break;
                }
            }
            if (i == req_xpath_count) {
                goto cleanup;
            }
        }
    }

    /* provide request XPath for the client, if possible */
    request_xpath = (req_xpath_count == 1) ? request_xpaths[0] : NULL;

    /* get data from client */
    if ((err_info = sr_shmsub_oper_get_notify(mod, xpath, request_xpath, parent_dup, orig_name, orig_data, shm_subs,
            idx1, timeout_ms, conn, oper_data, &cb_err_info))) {
        sr_errinfo_merge(&err_info, cb_err_info);
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
            sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx, NULL);
            goto cleanup;
        }
    }

cleanup:
    lyd_free_tree(parent_dup);
    free(parent_path);
    return err_info;
}

/**
 * @brief Try to merge operational get cached data of a subscription.
 *
 * @param[in] mod Mod info module.
 * @param[in] sub_xpath Subscription XPath.
 * @param[in] conn Connection to use.
 * @param[in,out] data Operational data tree to merge into.
 * @param[out] merged Whether the cached data were found and merged or not.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_module_oper_data_update_cached(struct sr_mod_info_mod_s *mod, const char *sub_xpath, sr_conn_ctx_t *conn,
        struct lyd_node **data, int *merged)
{
    sr_error_info_t *err_info = NULL;
    struct sr_oper_poll_cache_s *cache = NULL;
    uint32_t i;

    *merged = 0;

    /* CONN OPER CACHE READ LOCK */
    if ((err_info = sr_rwlock(&conn->oper_cache_lock, SR_CONN_OPER_CACHE_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid,
            __func__, NULL, NULL))) {
        goto cleanup;
    }

    /* try to get data from the cache */
    for (i = 0; i < conn->oper_cache_count; ++i) {
        if (!strcmp(conn->oper_caches[i].module_name, mod->ly_mod->name) &&
                !strcmp(conn->oper_caches[i].path, sub_xpath)) {
            cache = &conn->oper_caches[i];
            break;
        }
    }
    if (!cache) {
        goto cleanup_cache_unlock;
    }

    /* CACHE DATA READ LOCK */
    if ((err_info = sr_rwlock(&cache->data_lock, SR_CONN_OPER_CACHE_DATA_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid,
            __func__, NULL, NULL))) {
        goto cleanup_cache_unlock;
    }

    /* merge cached data */
    if (lyd_merge_siblings(data, cache->data, 0)) {
        sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx, NULL);
        goto cleanup_data_cache_unlock;
    }
    *merged = 1;

cleanup_data_cache_unlock:
    /* CACHE DATA UNLOCK */
    sr_rwunlock(&cache->data_lock, SR_CONN_OPER_CACHE_DATA_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

cleanup_cache_unlock:
    /* CONN OPER CACHE UNLOCK */
    sr_rwunlock(&conn->oper_cache_lock, SR_CONN_OPER_CACHE_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

cleanup:
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
 * @param[in] timeout_ms Operational callback timeout in milliseconds.
 * @param[in] get_oper_opts Get oper data options.
 * @param[in,out] data Operational data tree.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_module_oper_data_update(struct sr_mod_info_mod_s *mod, const char *orig_name, const void *orig_data, sr_conn_ctx_t *conn,
        uint32_t timeout_ms, sr_get_oper_flag_t get_oper_opts, struct lyd_node **data)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_oper_get_sub_t *shm_subs;
    sr_mod_oper_get_xpath_sub_t *xpath_subs;
    const char *sub_xpath, **request_xpaths = NULL;
    char *parent_xpath = NULL;
    uint32_t i, j, req_xpath_count = 0;
    int required, merged;
    struct ly_set *set = NULL;
    struct lyd_node *edit = NULL, *oper_data;

    if (!(get_oper_opts & SR_OPER_NO_STORED)) {
        /* get stored operational edit */
        if ((err_info = sr_module_file_oper_data_load(mod, &edit))) {
            return err_info;
        }
    }
    if (edit) {
        /* apply the edit */
        err_info = sr_edit_mod_apply(edit, mod->ly_mod, data, NULL, NULL);
        lyd_free_all(edit);
        if (err_info) {
            return err_info;
        }

        /* add any missing NP containers in the data */
        if (lyd_new_implicit_module(data, mod->ly_mod, LYD_IMPLICIT_NO_DEFAULTS, NULL)) {
            sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx, *data);
            return err_info;
        }
    }

    if (get_oper_opts & SR_OPER_NO_SUBS) {
        /* do not get data from subscribers */
        return NULL;
    }

    assert(timeout_ms);

    /* OPER GET SUB READ LOCK */
    if ((err_info = sr_rwlock(&mod->shm_mod->oper_get_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid,
            __func__, NULL, NULL))) {
        return err_info;
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        goto cleanup_opergetsub_unlock;
    }

    /* XPaths are ordered based on depth */
    shm_subs = (sr_mod_oper_get_sub_t *)(conn->ext_shm.addr + mod->shm_mod->oper_get_subs);
    for (i = 0; i < mod->shm_mod->oper_get_sub_count; ++i) {
        sub_xpath = conn->ext_shm.addr + shm_subs[i].xpath;
        xpath_subs = (sr_mod_oper_get_xpath_sub_t *)(conn->ext_shm.addr + shm_subs[i].xpath_subs);

        /* useless to retrieve configuration data, state data */
        if (((shm_subs[i].sub_type == SR_OPER_GET_SUB_CONFIG) && (get_oper_opts & SR_OPER_NO_CONFIG)) ||
                ((shm_subs[i].sub_type == SR_OPER_GET_SUB_STATE) && (get_oper_opts & SR_OPER_NO_STATE))) {
            continue;
        }

        if (mod->xpath_count) {
            /* check whether these data are even required */
            for (j = 0; j < mod->xpath_count; ++j) {
                if ((err_info = sr_xpath_oper_data_required(mod->xpaths[j], sub_xpath, &required))) {
                    goto cleanup_opergetsub_ext_unlock;
                }
                if (required) {
                    /* remember all xpaths causing these data to be required */
                    request_xpaths = sr_realloc(request_xpaths, (req_xpath_count + 1) * sizeof *request_xpaths);
                    SR_CHECK_MEM_GOTO(!request_xpaths, err_info, cleanup_opergetsub_ext_unlock);
                    request_xpaths[req_xpath_count] = mod->xpaths[j];
                    ++req_xpath_count;
                }
            }

            if (!req_xpath_count) {
                /* not required */
                continue;
            }
        }

        /* remove any present data */
        if (!(xpath_subs[0].opts & SR_SUBSCR_OPER_MERGE) && (err_info = sr_lyd_xpath_complement(data, sub_xpath))) {
            goto cleanup_opergetsub_ext_unlock;
        }

        if (!(get_oper_opts & SR_OPER_NO_POLL_CACHED)) {
            /* try to get data from the cache */
            if ((err_info = sr_module_oper_data_update_cached(mod, sub_xpath, conn, data, &merged))) {
                goto cleanup_opergetsub_ext_unlock;
            }
            if (merged) {
                /* we have the data */
                goto next_iter;
            }
        }

        /* trim the last node to get the parent */
        if ((err_info = sr_xpath_trim_last_node(sub_xpath, &parent_xpath))) {
            goto cleanup_opergetsub_ext_unlock;
        }

        if (parent_xpath) {
            if (!*data) {
                /* parent does not exist for sure */
                goto next_iter;
            }

            if (lyd_find_xpath(*data, parent_xpath, &set)) {
                sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx, NULL);
                goto cleanup_opergetsub_ext_unlock;
            }

            if (!set->count) {
                /* data parent does not exist */
                goto next_iter;
            }

            /* nested data */
            for (j = 0; j < set->count; ++j) {
                /* get oper data from the client */
                if ((err_info = sr_xpath_oper_data_get(mod, sub_xpath, request_xpaths, req_xpath_count, orig_name,
                        orig_data, shm_subs, i, set->dnodes[j], timeout_ms, conn, &oper_data))) {
                    goto cleanup_opergetsub_ext_unlock;
                }

                /* merge into one data tree */
                if (lyd_merge_siblings(data, oper_data, LYD_MERGE_DESTRUCT)) {
                    lyd_free_all(oper_data);
                    sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx, NULL);
                    goto cleanup_opergetsub_ext_unlock;
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
            if ((err_info = sr_xpath_oper_data_get(mod, sub_xpath, request_xpaths, req_xpath_count, orig_name,
                    orig_data, shm_subs, i, NULL, timeout_ms, conn, &oper_data))) {
                goto cleanup_opergetsub_ext_unlock;
            }

            if (lyd_merge_siblings(data, oper_data, LYD_MERGE_DESTRUCT)) {
                lyd_free_all(oper_data);
                sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx, NULL);
                goto cleanup_opergetsub_ext_unlock;
            }
        }

        free(request_xpaths);
        request_xpaths = NULL;
        req_xpath_count = 0;
    }

cleanup_opergetsub_ext_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

cleanup_opergetsub_unlock:
    /* OPER GET SUB READ UNLOCK */
    sr_rwunlock(&mod->shm_mod->oper_get_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

    free(request_xpaths);
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
 * @param[in] get_oper_opts Get oper data options.
 * @param[in] dup Whether to duplicate data or only unlink.
 * @param[out] enabled_mod_data Enabled operational data of the module.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_module_oper_data_get_enabled(sr_conn_ctx_t *conn, struct lyd_node **data, struct sr_mod_info_mod_s *mod,
        sr_get_oper_flag_t get_oper_opts, int dup, struct lyd_node **enabled_mod_data)
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

    shm_changesubs = (sr_mod_change_sub_t *)(conn->ext_shm.addr + mod->shm_mod->change_sub[SR_DS_RUNNING].subs);

    if (!data_ready) {
        /* try to find a subscription for the whole module */
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

    if (get_oper_opts & SR_OPER_WITH_ORIGIN) {
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
 * @brief Trim all configuration/state nodes/origin from the data based on options.
 *
 * @param[in,out] data Data to trim.
 * @param[in] sibling First sibling of the current data to trim.
 * @param[in] get_oper_opts Get oper data options.
 */
static void
sr_oper_data_trim_r(struct lyd_node **data, struct lyd_node *sibling, sr_get_oper_flag_t get_oper_opts)
{
    struct lyd_node *next, *elem;
    struct lyd_meta *meta;

    if (!(get_oper_opts & (SR_OPER_NO_STATE | SR_OPER_NO_CONFIG)) && (get_oper_opts & SR_OPER_WITH_ORIGIN)) {
        /* nothing to trim */
        return;
    }

    LY_LIST_FOR_SAFE(sibling, next, elem) {
        assert((elem->schema->nodetype != LYS_LEAF) || !(elem->schema->flags & LYS_KEY));
        if (elem->schema->flags & LYS_CONFIG_R) {
            /* state subtree */
            if (get_oper_opts & SR_OPER_NO_STATE) {
                /* free it whole */
                sr_lyd_free_tree_safe(elem, data);
                continue;
            }

            if (get_oper_opts & SR_OPER_WITH_ORIGIN) {
                /* no need to go into state children */
                continue;
            }
        }

        /* trim all our children */
        sr_oper_data_trim_r(data, lyd_child_no_keys(elem), get_oper_opts);

        if ((elem->schema->flags & LYS_CONFIG_W) && (get_oper_opts & SR_OPER_NO_CONFIG) && !lyd_child_no_keys(elem)) {
            /* config-only subtree (config node with no children) */
            sr_lyd_free_tree_safe(elem, data);
            continue;
        }

        if (!(get_oper_opts & SR_OPER_WITH_ORIGIN)) {
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
    content_id = SR_CONN_MAIN_SHM(mod_info->conn)->content_id;

    /* get the data from libyang */
    SR_CHECK_LY_RET(ly_ctx_get_yanglib_data(mod_info->conn->ly_ctx, &mod_data, "0x%08x", content_id),
            mod_info->conn->ly_ctx, err_info);

    if (!strcmp(mod->ly_mod->revision, "2019-01-04")) {
        assert(!strcmp(mod_data->schema->name, "yang-library"));

        /* add supported datastores */
        if (lyd_new_path(mod_data, NULL, "datastore[name='ietf-datastores:running']/schema", "complete", 0, 0) ||
                lyd_new_path(mod_data, NULL, "datastore[name='ietf-datastores:candidate']/schema", "complete", 0, 0) ||
                lyd_new_path(mod_data, NULL, "datastore[name='ietf-datastores:startup']/schema", "complete", 0, 0) ||
                lyd_new_path(mod_data, NULL, "datastore[name='ietf-datastores:operational']/schema", "complete", 0, 0)) {
            sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
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
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
        return err_info;
    }

    return NULL;
}

/**
 * @brief Add last datastore modification time nodes to a data tree.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module.
 * @param[in] ds Datastore.
 * @param[in,out] sr_state SR state data node to apend to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_module_srmon_datastore(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, sr_datastore_t ds, struct lyd_node *sr_state)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    const struct sr_ds_handle_s *ds_handle;
    struct lyd_node *sr_store;
    struct timespec mtime;
    char *buf = NULL;

    /* get LY module */
    ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, conn->mod_shm.addr + shm_mod->name);
    assert(ly_mod);

    if (!sr_module_has_data(ly_mod, 0)) {
        /* skip modules without configuration data */
        goto cleanup;
    }

    if ((err_info = sr_ds_handle_find(conn->mod_shm.addr + shm_mod->plugins[ds], conn, &ds_handle))) {
        goto cleanup;
    }

    if ((ds_handle->plugin->last_modif_cb(ly_mod, ds, ds_handle->plg_data, &mtime) == 0) && (mtime.tv_sec > 0)) {
        /* datastore with name */
        SR_CHECK_LY_RET(lyd_new_list(sr_state, NULL, "datastore", 0, &sr_store, sr_ds2ident(ds)), conn->ly_ctx,
                err_info);

        ly_time_ts2str(&mtime, &buf);
        SR_CHECK_LY_GOTO(lyd_new_term(sr_store, NULL, "last-modified", buf, 0, NULL), conn->ly_ctx, err_info, cleanup);
    }

cleanup:
    free(buf);
    return err_info;
}

/**
 * @brief Add held datastore-specific lock nodes to a data tree.
 *
 * @param[in] rwlock Lock to read CIDs from.
 * @param[in] skip_read_cid Sysrepo CID to skip a read lock once for, no skipped if 0.
 * @param[in] path_format Path string used for lyd_new_path() after printing specific CID and lock mode into it.
 * @param[in] ctx_node Context node to use for lyd_new_path().
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_module_srmon_locks_ds(sr_rwlock_t *rwlock, uint32_t skip_read_cid, const char *path_format,
        struct lyd_node *ctx_node)
{
    sr_error_info_t *err_info = NULL;
    sr_cid_t cid, skip_read_upgr_cid = 0;
    uint32_t i;

#define PATH_LEN 128
    char path[PATH_LEN];
    struct ly_ctx *ly_ctx;

    ly_ctx = (struct ly_ctx *)LYD_CTX(ctx_node);

    /* unlocked access to the lock, possible wrong/stale values should not matter */

    if ((cid = rwlock->upgr)) {
        snprintf(path, PATH_LEN, path_format, cid, "read-upgr");
        SR_CHECK_LY_GOTO(lyd_new_path(ctx_node, NULL, path, NULL, 0, NULL), ly_ctx, err_info, cleanup);

        /* read-upgr lock also holds a read lock, we need to skip it */
        skip_read_upgr_cid = cid;
    }

    for (i = 0; (i < SR_RWLOCK_READ_LIMIT) && rwlock->readers[i]; ++i) {
        cid = rwlock->readers[i];
        if ((cid == skip_read_cid) && (rwlock->read_count[i] == 1)) {
            skip_read_cid = 0;
            continue;
        } else if ((cid == skip_read_upgr_cid) && (rwlock->read_count[i] == 1)) {
            skip_read_upgr_cid = 0;
            continue;
        }

        snprintf(path, PATH_LEN, path_format, cid, "read");
        if (lyd_new_path(ctx_node, NULL, path, NULL, 0, NULL)) {
            sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
            goto cleanup;
        }
    }

    /* if there is a read-lock and the writer is set, it is just an urged write-lock being waited on, ignore it */
    if (!i && (cid = rwlock->writer)) {
        snprintf(path, PATH_LEN, path_format, cid, "write");
        SR_CHECK_LY_GOTO(lyd_new_path(ctx_node, NULL, path, NULL, 0, NULL), ly_ctx, err_info, cleanup);
    }

cleanup:
    return NULL;
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

#define CID_STR_LEN 64
    char cid_str[CID_STR_LEN];
    struct lyd_node *list;
    struct ly_ctx *ly_ctx;

    ly_ctx = (struct ly_ctx *)LYD_CTX(parent);

    /* unlocked access to the lock, possible wrong/stale values should not matter */

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

    for (i = 0; (i < SR_RWLOCK_READ_LIMIT) && rwlock->readers[i]; ++i) {
        SR_CHECK_LY_GOTO(lyd_new_list(parent, NULL, list_name, 0, &list), ly_ctx, err_info, cleanup);

        snprintf(cid_str, CID_STR_LEN, "%" PRIu32, rwlock->readers[i]);
        SR_CHECK_LY_GOTO(lyd_new_term(list, NULL, "cid", cid_str, 0, NULL), ly_ctx, err_info, cleanup);

        SR_CHECK_LY_GOTO(lyd_new_term(list, NULL, "mode", "read", 0, NULL), ly_ctx, err_info, cleanup);
    }

cleanup:
    return err_info;
#undef CID_STR_LEN
}

/**
 * @brief Append a "subscriptions" data node with the specific subscriptions to sysrepo-monitoring module data.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module to read from.
 * @param[in,out] sr_mod Module list node of sysrepo-monitoring.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_module_srmon_module_subs(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, struct lyd_node *sr_mod)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_subs, *sr_xpath_sub, *sr_sub;
    sr_datastore_t ds;
    sr_mod_change_sub_t *change_subs;
    sr_mod_oper_get_sub_t *oper_get_subs;
    sr_mod_oper_get_xpath_sub_t *xpath_sub;
    sr_mod_oper_poll_sub_t *oper_poll_subs;
    sr_mod_notif_sub_t *notif_subs;
    uint32_t i, j;
    char buf[128];
    const struct ly_ctx *ly_ctx = LYD_CTX(sr_mod);

    /* subscriptions, make implicit */
    SR_CHECK_LY_RET(lyd_new_inner(sr_mod, NULL, "subscriptions", 0, &sr_subs), ly_ctx, err_info);
    sr_subs->flags |= LYD_DEFAULT;

    /*
     * change subscriptions
     */

    for (ds = 0; ds < SR_DS_COUNT; ++ds) {
        /* CHANGE SUB READ LOCK */
        if ((err_info = sr_rwlock(&shm_mod->change_sub[ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid,
                __func__, NULL, NULL))) {
            return err_info;
        }

        /* EXT READ LOCK */
        if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
            goto change_sub_unlock;
        }

        change_subs = (sr_mod_change_sub_t *)(conn->ext_shm.addr + shm_mod->change_sub[ds].subs);
        for (i = 0; i < shm_mod->change_sub[ds].sub_count; ++i) {
            /* ignore dead subscriptions */
            if (!sr_conn_is_alive(change_subs[i].cid)) {
                continue;
            }

            /* change-sub */
            SR_CHECK_LY_GOTO(lyd_new_list(sr_subs, NULL, "change-sub", 0, &sr_sub), ly_ctx, err_info, change_ext_sub_unlock);

            /* datastore */
            SR_CHECK_LY_GOTO(lyd_new_term(sr_sub, NULL, "datastore", sr_ds2ident(ds), 0, NULL), ly_ctx, err_info,
                    change_ext_sub_unlock);

            /* xpath */
            if (change_subs[i].xpath) {
                SR_CHECK_LY_GOTO(lyd_new_term(sr_sub, NULL, "xpath", conn->ext_shm.addr + change_subs[i].xpath, 0, NULL),
                        ly_ctx, err_info, change_ext_sub_unlock);
            }

            /* priority */
            sprintf(buf, "%" PRIu32, change_subs[i].priority);
            SR_CHECK_LY_GOTO(lyd_new_term(sr_sub, NULL, "priority", buf, 0, NULL), ly_ctx, err_info, change_ext_sub_unlock);

            /* cid */
            sprintf(buf, "%" PRIu32, change_subs[i].cid);
            SR_CHECK_LY_GOTO(lyd_new_term(sr_sub, NULL, "cid", buf, 0, NULL), ly_ctx, err_info, change_ext_sub_unlock);

            /* suspended */
            sprintf(buf, "%s", ATOMIC_LOAD_RELAXED(change_subs[i].suspended) ? "true" : "false");
            SR_CHECK_LY_GOTO(lyd_new_term(sr_sub, NULL, "suspended", buf, 0, NULL), ly_ctx, err_info, change_ext_sub_unlock);
        }

change_ext_sub_unlock:
        /* EXT READ UNLOCK */
        sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

change_sub_unlock:
        /* CHANGE SUB READ UNLOCK */
        sr_rwunlock(&shm_mod->change_sub[ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

        if (err_info) {
            return err_info;
        }
    }

    /*
     * oper get subscriptions
     */

    /* OPER GET SUB READ LOCK */
    if ((err_info = sr_rwlock(&shm_mod->oper_get_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid,
            __func__, NULL, NULL))) {
        return err_info;
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        goto operget_sub_unlock;
    }

    oper_get_subs = (sr_mod_oper_get_sub_t *)(conn->ext_shm.addr + shm_mod->oper_get_subs);
    for (i = 0; i < shm_mod->oper_get_sub_count; ++i) {
        /* operational-get-sub with xpath */
        SR_CHECK_LY_GOTO(lyd_new_list(sr_subs, NULL, "operational-get-sub", 0, &sr_xpath_sub,
                conn->ext_shm.addr + oper_get_subs[i].xpath), ly_ctx, err_info, operget_ext_sub_unlock);

        for (j = 0; j < oper_get_subs[i].xpath_sub_count; ++j) {
            xpath_sub = &((sr_mod_oper_get_xpath_sub_t *)(conn->ext_shm.addr + oper_get_subs[i].xpath_subs))[j];

            /* ignore dead subscriptions */
            if (!sr_conn_is_alive(xpath_sub->cid)) {
                continue;
            }

            SR_CHECK_LY_GOTO(lyd_new_list(sr_xpath_sub, NULL, "xpath-sub", 0, &sr_sub), ly_ctx, err_info, operget_ext_sub_unlock);

            /* cid */
            sprintf(buf, "%" PRIu32, xpath_sub->cid);
            SR_CHECK_LY_GOTO(lyd_new_term(sr_sub, NULL, "cid", buf, 0, NULL), ly_ctx, err_info, operget_ext_sub_unlock);

            /* suspended */
            sprintf(buf, "%s", ATOMIC_LOAD_RELAXED(xpath_sub->suspended) ? "true" : "false");
            SR_CHECK_LY_GOTO(lyd_new_term(sr_sub, NULL, "suspended", buf, 0, NULL), ly_ctx, err_info, operget_ext_sub_unlock);
        }
    }

operget_ext_sub_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

operget_sub_unlock:
    /* OPER GET SUB READ UNLOCK */
    sr_rwunlock(&shm_mod->oper_get_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

    if (err_info) {
        return err_info;
    }

    /*
     * oper poll subscriptions
     */

    /* OPER POLL SUB READ LOCK */
    if ((err_info = sr_rwlock(&shm_mod->oper_poll_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid,
            __func__, NULL, NULL))) {
        return err_info;
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        goto operpoll_sub_unlock;
    }

    oper_poll_subs = (sr_mod_oper_poll_sub_t *)(conn->ext_shm.addr + shm_mod->oper_poll_subs);
    for (i = 0; i < shm_mod->oper_poll_sub_count; ++i) {
        /* ignore dead subscriptions */
        if (!sr_conn_is_alive(oper_poll_subs[i].cid)) {
            continue;
        }

        /* operational-poll-sub with xpath */
        SR_CHECK_LY_GOTO(lyd_new_list(sr_subs, NULL, "operational-poll-sub", 0, &sr_sub,
                conn->ext_shm.addr + oper_poll_subs[i].xpath), ly_ctx, err_info, operpoll_ext_sub_unlock);

        /* cid */
        sprintf(buf, "%" PRIu32, oper_poll_subs[i].cid);
        SR_CHECK_LY_GOTO(lyd_new_term(sr_sub, NULL, "cid", buf, 0, NULL), ly_ctx, err_info, operpoll_ext_sub_unlock);

        /* suspended */
        sprintf(buf, "%s", ATOMIC_LOAD_RELAXED(oper_poll_subs[i].suspended) ? "true" : "false");
        SR_CHECK_LY_GOTO(lyd_new_term(sr_sub, NULL, "suspended", buf, 0, NULL), ly_ctx, err_info, operpoll_ext_sub_unlock);
    }

operpoll_ext_sub_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

operpoll_sub_unlock:
    /* OPER POLL SUB READ UNLOCK */
    sr_rwunlock(&shm_mod->oper_poll_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

    if (err_info) {
        return err_info;
    }

    /*
     * notification subscriptions
     */

    /* NOTIF SUB READ LOCK */
    if ((err_info = sr_rwlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid,
            __func__, NULL, NULL))) {
        return err_info;
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        goto notif_sub_unlock;
    }

    notif_subs = (sr_mod_notif_sub_t *)(conn->ext_shm.addr + shm_mod->notif_subs);
    for (i = 0; i < shm_mod->notif_sub_count; ++i) {
        /* ignore dead subscriptions */
        if (!sr_conn_is_alive(notif_subs[i].cid)) {
            continue;
        }

        /* notification-sub */
        SR_CHECK_LY_GOTO(lyd_new_list(sr_subs, NULL, "notification-sub", 0, &sr_sub), ly_ctx, err_info, notif_ext_sub_unlock);

        /* cid */
        sprintf(buf, "%" PRIu32, notif_subs[i].cid);
        SR_CHECK_LY_GOTO(lyd_new_term(sr_sub, NULL, "cid", buf, 0, NULL), ly_ctx, err_info, notif_ext_sub_unlock);

        /* suspended */
        sprintf(buf, "%s", ATOMIC_LOAD_RELAXED(notif_subs[i].suspended) ? "true" : "false");
        SR_CHECK_LY_GOTO(lyd_new_term(sr_sub, NULL, "suspended", buf, 0, NULL), ly_ctx, err_info, notif_ext_sub_unlock);
    }

notif_ext_sub_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

notif_sub_unlock:
    /* NOTIF SUB READ UNLOCK */
    sr_rwunlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

    return err_info;
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
    struct lyd_node *sr_mod, *sr_ds_lock;
    sr_datastore_t ds;
    struct sr_mod_lock_s *shm_lock;

#define BUF_LEN 128
    char buf[BUF_LEN], *str = NULL;
    const struct ly_ctx *ly_ctx = LYD_CTX(sr_state);

    /* module with name */
    SR_CHECK_LY_RET(lyd_new_list(sr_state, NULL, "module", 0, &sr_mod, conn->mod_shm.addr + shm_mod->name), ly_ctx,
            err_info);

    /* last-modified */
    for (ds = 0; ds < SR_DS_COUNT; ++ds) {
        if ((err_info = sr_modinfo_module_srmon_datastore(conn, shm_mod, ds, sr_mod))) {
            return err_info;
        }
    }

    for (ds = 0; ds < SR_DS_COUNT; ++ds) {
        shm_lock = &shm_mod->data_lock_info[ds];

        /* data-lock */
        snprintf(buf, BUF_LEN, "data-lock[cid='%%" PRIu32 "'][datastore='%s'][mode='%%s']", sr_ds2ident(ds));
        err_info = sr_modinfo_module_srmon_locks_ds(&shm_lock->data_lock, conn->cid, buf, sr_mod);

        if (err_info) {
            return err_info;
        }

        /* DS LOCK */
        if ((err_info = sr_mlock(&shm_lock->ds_lock, SR_DS_LOCK_MUTEX_TIMEOUT, __func__, NULL, NULL))) {
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
        snprintf(buf, BUF_LEN, "change-sub-lock[cid='%%" PRIu32 "'][datastore='%s'][mode='%%s']", sr_ds2ident(ds));
        if ((err_info = sr_modinfo_module_srmon_locks_ds(&shm_mod->change_sub[ds].lock, 0, buf, sr_mod))) {
            return err_info;
        }
    }
#undef BUF_LEN

    /* oper-get-sub-lock */
    if ((err_info = sr_modinfo_module_srmon_locks(&shm_mod->oper_get_lock, "oper-get-sub-lock", sr_mod))) {
        return err_info;
    }

    /* oper-poll-sub-lock */
    if ((err_info = sr_modinfo_module_srmon_locks(&shm_mod->oper_poll_lock, "oper-poll-sub-lock", sr_mod))) {
        return err_info;
    }

    /* notif-sub-lock */
    if ((err_info = sr_modinfo_module_srmon_locks(&shm_mod->notif_lock, "notif-sub-lock", sr_mod))) {
        return err_info;
    }

    /* module subscriptions */
    if ((err_info = sr_modinfo_module_srmon_module_subs(conn, shm_mod, sr_mod))) {
        return err_info;
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
    SR_CHECK_LY_RET(lyd_new_list(sr_state, NULL, "rpc", 0, &sr_rpc, conn->mod_shm.addr + shm_rpc->path), ly_ctx, err_info);

    /* sub-lock */
    if ((err_info = sr_modinfo_module_srmon_locks(&shm_rpc->lock, "sub-lock", sr_rpc))) {
        return err_info;
    }

    rpc_sub = (sr_mod_rpc_sub_t *)(conn->ext_shm.addr + shm_rpc->subs);
    for (i = 0; i < shm_rpc->sub_count; ++i) {
        /* ignore dead subscriptions */
        if (rpc_sub[i].cid && !sr_conn_is_alive(rpc_sub[i].cid)) {
            continue;
        }

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

        /* suspended */
        sprintf(buf, "%s", ATOMIC_LOAD_RELAXED(rpc_sub[i].suspended) ? "true" : "false");
        SR_CHECK_LY_RET(lyd_new_term(sr_sub, NULL, "suspended", buf, 0, NULL), ly_ctx, err_info);
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
 * @brief Check whether specific operational data are required for a module.
 *
 * @param[in] mod Module with all requested XPaths.
 * @param[out] required Whether the oper data are required or not.
 * @param[in] sub_xpath_fmt Operational subscription XPath format.
 * @param[in] ... Format parameters of @p sub_xpath_fmt.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_module_data_oper_required(struct sr_mod_info_mod_s *mod, int *required, const char *sub_xpath_fmt, ...)
{
    sr_error_info_t *err_info = NULL;
    va_list ap;
    char *xpath = NULL;
    uint32_t i;
    int req;

    *required = 1;

    /* print sub_xpath */
    va_start(ap, sub_xpath_fmt);
    if (vasprintf(&xpath, sub_xpath_fmt, ap) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }

    /* check all the xpaths */
    for (i = 0; i < mod->xpath_count; ++i) {
        if ((err_info = sr_xpath_oper_data_required(mod->xpaths[i], xpath, &req))) {
            goto cleanup;
        }
        if (req) {
            /* required */
            goto cleanup;
        }
    }

    /* not required */
    *required = 0;

cleanup:
    va_end(ap);
    free(xpath);
    return err_info;
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
sr_modinfo_module_data_load_srmon(struct sr_mod_info_s *mod_info, struct sr_mod_info_mod_s *mod)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *mod_data;
    sr_mod_t *shm_mod;
    sr_rpc_t *shm_rpc;
    const struct lys_module *ly_mod;
    sr_mod_shm_t *mod_shm;
    uint32_t i, j;
    int req;

    mod_shm = SR_CONN_MOD_SHM(mod_info->conn);
    ly_mod = ly_ctx_get_module_implemented(mod_info->conn->ly_ctx, "sysrepo-monitoring");
    assert(ly_mod);

    /* main container */
    SR_CHECK_LY_GOTO(lyd_new_inner(NULL, ly_mod, "sysrepo-state", 0, &mod_data), mod_info->conn->ly_ctx, err_info, cleanup);

    /* modules */
    if ((err_info = sr_modinfo_module_data_oper_required(mod, &req, "/sysrepo-monitoring:sysrepo-state/module"))) {
        goto cleanup;
    }
    if (req) {
        for (i = 0; i < mod_shm->mod_count; ++i) {
            shm_mod = SR_SHM_MOD_IDX(mod_shm, i);
            if ((err_info = sr_modinfo_module_data_oper_required(mod, &req,
                    "/sysrepo-monitoring:sysrepo-state/module[name='%s']", mod_info->conn->mod_shm.addr + shm_mod->name))) {
                goto cleanup;
            }

            if (req && (err_info = sr_modinfo_module_srmon_module(mod_info->conn, shm_mod, mod_data))) {
                goto cleanup;
            }
        }
    }

    /* RPCs */
    if ((err_info = sr_modinfo_module_data_oper_required(mod, &req, "/sysrepo-monitoring:sysrepo-state/rpc"))) {
        goto cleanup;
    }
    if (req) {
        for (i = 0; i < mod_shm->mod_count; ++i) {
            shm_mod = SR_SHM_MOD_IDX(mod_shm, i);
            shm_rpc = (sr_rpc_t *)(mod_info->conn->mod_shm.addr + shm_mod->rpcs);
            for (j = 0; j < shm_mod->rpc_count; ++j) {
                if ((err_info = sr_modinfo_module_data_oper_required(mod, &req,
                        "/sysrepo-monitoring:sysrepo-state/rpc[path='%s']", mod_info->conn->mod_shm.addr + shm_rpc[j].path))) {
                    goto cleanup;
                }

                if (req && (err_info = sr_modinfo_module_srmon_rpc(mod_info->conn, &shm_rpc[j], mod_data))) {
                    goto cleanup;
                }
            }
        }
    }

    /* connections */
    if ((err_info = sr_modinfo_module_data_oper_required(mod, &req, "/sysrepo-monitoring:sysrepo-state/connection"))) {
        goto cleanup;
    }
    if (req && (err_info = sr_modinfo_module_srmon_connections(mod_data))) {
        goto cleanup;
    }

    /* connect to the rest of data */
    if (lyd_merge_siblings(&mod_info->data, mod_data, LYD_MERGE_DESTRUCT)) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
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
 * @param[in] orig_name Event originator name.
 * @param[in] orig_data Event originator data.
 * @param[in] timeout_ms Operational callback timeout in milliseconds.
 * @param[in] get_oper_opts Get oper data options.
 * @param[in] run_cached_data_cur Whether any cached running data in @p conn are usable and current.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_module_data_load(struct sr_mod_info_s *mod_info, struct sr_mod_info_mod_s *mod, const char *orig_name,
        const void *orig_data, uint32_t timeout_ms, sr_get_oper_flag_t get_oper_opts, int run_cached_data_cur)
{
    sr_error_info_t *err_info = NULL;
    sr_conn_ctx_t *conn = mod_info->conn;
    struct lyd_node *mod_data = NULL;
    int modified;

    assert(!mod_info->data_cached);
    assert((mod_info->ds != SR_DS_OPERATIONAL) || (mod_info->ds2 != SR_DS_OPERATIONAL));

    if (run_cached_data_cur) {
        /* there are cached data */
        switch (mod_info->ds) {
        case SR_DS_STARTUP:
        case SR_DS_FACTORY_DEFAULT:
            /* running data are of no use */
            run_cached_data_cur = 0;
            break;
        case SR_DS_CANDIDATE:
            if ((err_info = mod->ds_handle[mod_info->ds]->plugin->candidate_modified_cb(mod->ly_mod,
                    mod->ds_handle[mod_info->ds]->plg_data, &modified))) {
                break;
            } else if (modified) {
                /* running data are of no use */
                run_cached_data_cur = 0;
                break;
            }
        /* fallthrough */
        case SR_DS_RUNNING:
            /* copy all module data */
            err_info = sr_lyd_get_module_data(&mod_info->conn->run_cache_data, mod->ly_mod, 0, 1, &mod_data);
            break;
        case SR_DS_OPERATIONAL:
            /* copy only enabled module data */
            err_info = sr_module_oper_data_get_enabled(conn, &mod_info->conn->run_cache_data, mod, get_oper_opts,
                    1, &mod_data);
            break;
        }
        if (err_info) {
            return err_info;
        }

        if (mod_data) {
            lyd_insert_sibling(mod_info->data, mod_data, &mod_info->data);
        }
    }
    if (!run_cached_data_cur) {
        /* no cached data or unusable */

        /* get current DS data (ds2 is running when getting operational data) */
        if ((err_info = sr_module_file_data_append(mod->ly_mod, mod->ds_handle, mod_info->ds2, mod->xpaths,
                mod->xpath_count, &mod_info->data))) {
            return err_info;
        }

        if (mod_info->ds == SR_DS_OPERATIONAL) {
            /* keep only enabled module data */
            if ((err_info = sr_module_oper_data_get_enabled(conn, &mod_info->data, mod, get_oper_opts, 0, &mod_data))) {
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
            if ((err_info = sr_modinfo_module_data_load_srmon(mod_info, mod))) {
                return err_info;
            }
        }

        /* append any operational data provided by clients */
        if ((err_info = sr_module_oper_data_update(mod, orig_name, orig_data, conn, timeout_ms, get_oper_opts,
                &mod_info->data))) {
            return err_info;
        }

        /* trim any data according to options (they could not be trimmed before oper subscriptions) */
        sr_oper_data_trim_r(&mod_info->data, mod_info->data, get_oper_opts);
    }

    return NULL;
}

/**
 * @brief Consolidate a new module (update and fill) in mod info.
 *
 * @param[in] ly_mod Module libyang structure.
 * @param[in] mod_type Actual module type.
 * @param[in] mod_info Modified mod info.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_mod_new(const struct lys_module *ly_mod, uint32_t mod_type, struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    const struct sr_ds_handle_s *ds_handle[SR_DS_READ_COUNT] = {0};
    struct sr_mod_info_mod_s *mod = NULL;
    uint32_t i;
    int new = 0;

    assert((mod_type == MOD_INFO_REQ) || (mod_type == MOD_INFO_DEP) || (mod_type == MOD_INFO_INV_DEP));

    /* check that it is not already added */
    for (i = 0; i < mod_info->mod_count; ++i) {
        if (mod_info->mods[i].ly_mod == ly_mod) {
            /* already there, update module type if needed */
            mod = &mod_info->mods[i];
            if (mod->state & MOD_INFO_NEW) {
                new = 1;
            }
            if ((mod->state & MOD_INFO_TYPE_MASK) < mod_type) {
                mod->state &= ~MOD_INFO_TYPE_MASK;
                mod->state |= mod_type;
            }
            if (new) {
                /* new module, needs its members filled */
                break;
            }
            return NULL;
        }
    }

    /* find module in SHM */
    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(mod_info->conn), ly_mod->name);
    SR_CHECK_INT_RET(!shm_mod, err_info);

    /* find main DS handle */
    if ((mod_info->ds == SR_DS_RUNNING) && !shm_mod->plugins[mod_info->ds]) {
        /* 'running' is disabled, we will be using the 'startup' plugin */
        if ((err_info = sr_ds_handle_find(mod_info->conn->mod_shm.addr + shm_mod->plugins[SR_DS_STARTUP], mod_info->conn,
                &ds_handle[SR_DS_STARTUP]))) {
            return err_info;
        }
    } else {
        if ((err_info = sr_ds_handle_find(mod_info->conn->mod_shm.addr + shm_mod->plugins[mod_info->ds], mod_info->conn,
                &ds_handle[mod_info->ds]))) {
            return err_info;
        }
    }
    switch (mod_info->ds) {
    case SR_DS_STARTUP:
    case SR_DS_FACTORY_DEFAULT:
        /* plugin for this datastore is enough */
        break;
    case SR_DS_RUNNING:
        /* get candidate as well if we need to reset it */
        if ((err_info = sr_ds_handle_find(mod_info->conn->mod_shm.addr + shm_mod->plugins[SR_DS_CANDIDATE],
                mod_info->conn, &ds_handle[SR_DS_CANDIDATE]))) {
            return err_info;
        }
        break;
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        /* get running plugin as well */
        if ((err_info = sr_ds_handle_find(mod_info->conn->mod_shm.addr + shm_mod->plugins[SR_DS_RUNNING],
                mod_info->conn, &ds_handle[SR_DS_RUNNING]))) {
            return err_info;
        }
        break;
    }

    if (!mod) {
        /* add it */
        mod_info->mods = sr_realloc(mod_info->mods, (mod_info->mod_count + 1) * sizeof *mod_info->mods);
        SR_CHECK_MEM_RET(!mod_info->mods, err_info);

        mod = &mod_info->mods[mod_info->mod_count];
        memset(mod, 0, sizeof *mod);
        ++mod_info->mod_count;
    }

    /* fill basic attributes */
    mod->shm_mod = shm_mod;
    mod->ly_mod = ly_mod;
    memcpy(&mod->ds_handle, &ds_handle, sizeof ds_handle);
    mod->state &= ~MOD_INFO_TYPE_MASK;
    mod->state |= mod_type;

    return NULL;
}

/**
 * @brief Add inverse dependencies for a module in mod info.
 *
 * @param[in] shm_mod SHM mod.
 * @param[in] mod_info Modified mod info.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_mod_inv_deps(sr_mod_t *shm_mod, struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    off_t *shm_inv_deps;
    uint32_t i;

    /* add all inverse dependencies (modules dependening on this module) */
    shm_inv_deps = (off_t *)(mod_info->conn->mod_shm.addr + shm_mod->inv_deps);
    for (i = 0; i < shm_mod->inv_dep_count; ++i) {
        /* find ly module */
        ly_mod = ly_ctx_get_module_implemented(mod_info->conn->ly_ctx, mod_info->conn->mod_shm.addr + shm_inv_deps[i]);
        SR_CHECK_INT_RET(!ly_mod, err_info);

        /* add inverse dependency */
        if ((err_info = sr_modinfo_mod_new(ly_mod, MOD_INFO_INV_DEP, mod_info))) {
            return err_info;
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

/**
 * @brief Load data for modules in mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] cache Whether it makes sense to use cached data, if available.
 * @param[in] orig_name Event originator name.
 * @param[in] orig_data Event originator data.
 * @param[in] timeout_ms Operational callback timeout in milliseconds.
 * @param[in] get_oper_opts Get oper data options, ignored if getting only ::SR_DS_OPERATIONAL data (edit).
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_data_load(struct sr_mod_info_s *mod_info, int cache, const char *orig_name, const void *orig_data,
        uint32_t timeout_ms, sr_get_oper_flag_t get_oper_opts)
{
    sr_error_info_t *err_info = NULL;
    sr_conn_ctx_t *conn;
    struct sr_mod_info_mod_s *mod;
    uint32_t i;
    int run_data_cache_cur = 0;

    conn = mod_info->conn;

    /* CACHE READ LOCK */
    if ((err_info = sr_rwlock(&conn->run_cache_lock, SR_CONN_RUN_CACHE_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid,
            __func__, NULL, NULL))) {
        return err_info;
    }

    /* cache may be useful only for some datastores */
    if (!mod_info->data_cached && cache && mod_info->mod_count && (conn->opts & SR_CONN_CACHE_RUNNING) &&
            !(get_oper_opts & SR_OPER_NO_RUN_CACHED) &&
            ((mod_info->ds == SR_DS_RUNNING) || (mod_info->ds == SR_DS_CANDIDATE) || (mod_info->ds2 == SR_DS_RUNNING))) {

        /* update the data in the cache */
        if ((err_info = sr_conn_run_cache_update(conn, mod_info, SR_LOCK_READ))) {
            goto cleanup;
        }
        run_data_cache_cur = 1;

        if (mod_info->ds == SR_DS_RUNNING) {
            /* we can use the cache directly only if we are working with the running datastore (as the main datastore) */
            mod_info->data_cached = 1;
            mod_info->data = conn->run_cache_data;
            for (i = 0; i < mod_info->mod_count; ++i) {
                mod = &mod_info->mods[i];
                mod->state |= MOD_INFO_DATA;
            }
            goto cleanup;
        }
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
            assert(!mod->xpath_count);
            if ((err_info = sr_module_file_data_append(mod->ly_mod, mod->ds_handle, SR_DS_OPERATIONAL, NULL, 0,
                    &mod_info->data))) {
                goto cleanup;
            }
        } else {
            if ((err_info = sr_modinfo_module_data_load(mod_info, mod, orig_name, orig_data, timeout_ms, get_oper_opts,
                    run_data_cache_cur))) {
                goto cleanup;
            }
        }
        if (!mod->xpath_count) {
            /* remember only if we request all the data */
            mod->state |= MOD_INFO_DATA;
        }
    }

cleanup:
    if (!mod_info->data_cached) {
        /* CACHE READ UNLOCK */
        sr_rwunlock(&conn->run_cache_lock, SR_CONN_RUN_CACHE_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);
    } /* else the flag marks held READ lock */
    return err_info;
}

sr_error_info_t *
sr_modinfo_consolidate(struct sr_mod_info_s *mod_info, sr_lock_mode_t mod_lock, int mi_opts, uint32_t sid,
        const char *orig_name, const void *orig_data, uint32_t timeout_ms, uint32_t ds_lock_timeout_ms,
        sr_get_oper_flag_t get_oper_opts)
{
    sr_error_info_t *err_info = NULL;
    int mod_type, new = 0;
    uint32_t i;

    assert(mi_opts & (SR_MI_PERM_NO | SR_MI_PERM_READ | SR_MI_PERM_WRITE));

    if (!mod_info->mod_count) {
        goto cleanup;
    }

    if (mi_opts & SR_MI_NEW_DEPS) {
        mod_type = MOD_INFO_DEP;
    } else {
        mod_type = MOD_INFO_REQ;
    }

    /* check for new modules in mod_info */
    for (i = 0; i < mod_info->mod_count; ++i) {
        if (mod_info->mods[i].state & MOD_INFO_NEW) {
            /* new module */
            new = 1;

            /* consolidate without inverse dependencies to not lose track of new modules */
            if ((err_info = sr_modinfo_mod_new(mod_info->mods[i].ly_mod, mod_type, mod_info))) {
                goto cleanup;
            }
        }
    }
    if (!new) {
        /* no module changes, we are done */
        return NULL;
    }

    if (mi_opts & SR_MI_INV_DEPS) {
        /* add inverse dependencies for added modules */
        for (i = 0; i < mod_info->mod_count; ++i) {
            if (mod_info->mods[i].state & mod_type) {
                if ((err_info = sr_modinfo_mod_inv_deps(mod_info->mods[i].shm_mod, mod_info))) {
                    goto cleanup;
                }
            }
        }
    }

    if (!(mi_opts & SR_MI_PERM_NO)) {
        /* check permissions */
        if ((err_info = sr_modinfo_perm_check(mod_info, mi_opts & SR_MI_PERM_WRITE ? 1 : 0, mi_opts & SR_MI_PERM_STRICT))) {
            goto cleanup;
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
            if ((err_info = sr_shmmod_modinfo_rdlock(mod_info, mi_opts & SR_MI_LOCK_UPGRADEABLE, sid, timeout_ms,
                    ds_lock_timeout_ms))) {
                goto cleanup;
            }
        } else {
            /* MODULES WRITE LOCK */
            if ((err_info = sr_shmmod_modinfo_wrlock(mod_info, sid, timeout_ms, ds_lock_timeout_ms))) {
                goto cleanup;
            }
        }
    }

    if (!(mi_opts & SR_MI_DATA_NO)) {
        /* load all modules data */
        if ((err_info = sr_modinfo_data_load(mod_info, mi_opts & SR_MI_DATA_CACHE, orig_name, orig_data, timeout_ms,
                get_oper_opts))) {
            goto cleanup;
        }
    }

cleanup:
    return err_info;
}

sr_error_info_t *
sr_modinfo_validate(struct sr_mod_info_s *mod_info, uint32_t mod_state, int finish_diff)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    struct lyd_node *diff = NULL, *iter;
    uint32_t i;
    int val_opts;

    assert(!mod_info->data_cached);
    assert(SR_IS_CONVENTIONAL_DS(mod_info->ds) || !finish_diff);

    /* validate all the modules individually */
    if (SR_IS_CONVENTIONAL_DS(mod_info->ds)) {
        val_opts = LYD_VALIDATE_NO_STATE;
    } else {
        val_opts = LYD_VALIDATE_OPERATIONAL | LYD_VALIDATE_NO_DEFAULTS;
    }
    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & mod_state) {
            /* validate this module */
            if (lyd_validate_module(&mod_info->data, mod->ly_mod, val_opts | LYD_VALIDATE_NOT_FINAL,
                    finish_diff ? &diff : NULL)) {
                sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
                SR_ERRINFO_VALID(&err_info);
                goto cleanup;
            }

            if (diff) {
                /* it may not have been modified before */
                mod->state |= MOD_INFO_CHANGED;

                /* merge the changes made by the validation into our diff */
                if (lyd_diff_merge_all(&mod_info->diff, diff, 0)) {
                    sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
                    goto cleanup;
                }

                lyd_free_all(diff);
                diff = NULL;

                LY_LIST_FOR(mod_info->diff, iter) {
                    if (lyd_owner_module(iter) == mod->ly_mod) {
                        break;
                    }
                }
                if (!iter) {
                    /* the previous changes have actually been reverted */
                    mod->state &= ~MOD_INFO_CHANGED;
                }
            }
        }
    }

    /* finish each module validation now */
    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & mod_state) {
            if (lyd_validate_module_final(mod_info->data, mod->ly_mod, val_opts)) {
                sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
                SR_ERRINFO_VALID(&err_info);
                goto cleanup;
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
    struct lyd_node *diff = NULL, *iter;
    uint32_t i;

    assert(!mod_info->data_cached && SR_IS_CONVENTIONAL_DS(mod_info->ds));

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        switch (mod->state & MOD_INFO_TYPE_MASK) {
        case MOD_INFO_REQ:
            /* add default values for this module */
            if (lyd_new_implicit_module(&mod_info->data, mod->ly_mod, LYD_IMPLICIT_NO_STATE, finish_diff ? &diff : NULL)) {
                sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
                SR_ERRINFO_VALID(&err_info);
                goto cleanup;
            }
            mod_info->data = lyd_first_sibling(mod_info->data);

            if (diff) {
                /* it may not have been modified before */
                mod->state |= MOD_INFO_CHANGED;

                /* merge the changes made by the validation into our diff */
                if (lyd_diff_merge_all(&mod_info->diff, diff, 0)) {
                    sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
                    goto cleanup;
                }

                lyd_free_all(diff);
                diff = NULL;

                LY_LIST_FOR(mod_info->diff, iter) {
                    if (lyd_owner_module(iter) == mod->ly_mod) {
                        break;
                    }
                }
                if (!iter) {
                    /* the previous changes have actually been reverted */
                    mod->state &= ~MOD_INFO_CHANGED;
                }
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
sr_modinfo_check_state_data(struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    struct lyd_node *root, *node;
    uint32_t i;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (!(mod->state & MOD_INFO_REQ)) {
            continue;
        }

        /* check this module data for state nodes */
        LY_LIST_FOR(mod_info->data, root) {
            if (lyd_owner_module(root) == mod->ly_mod) {
                break;
            }
        }
        LY_LIST_FOR(root, root) {
            if (lyd_owner_module(root) != mod->ly_mod) {
                break;
            }

            LYD_TREE_DFS_BEGIN(root, node) {
                if (node->schema->flags & LYS_CONFIG_R) {
                    sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, "Unexpected data state node \"%s\" found.",
                            LYD_NAME(node));
                    SR_ERRINFO_VALID(&err_info);
                    goto cleanup;
                }
                LYD_TREE_DFS_END(root, node);
            }
        }
    }

cleanup:
    return err_info;
}

sr_error_info_t *
sr_modinfo_op_validate(struct sr_mod_info_s *mod_info, struct lyd_node *op, int output)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *top_op, *op_ext_parent = NULL, *data_ext_parent = NULL, *node;
    struct ly_set *set = NULL;
    struct sr_mod_info_mod_s *mod;
    uint32_t i;
    char *parent_xpath = NULL, *ext_parent_path = NULL;
    enum lyd_type op_type;

    assert(op->schema->nodetype & (LYS_RPC | LYS_ACTION | LYS_NOTIF));

    /* find top-level node */
    for (top_op = op; top_op->parent; top_op = lyd_parent(top_op)) {
        if (top_op->flags & LYD_EXT) {
            /* the operation is from extension data */
            op_ext_parent = lyd_parent(top_op);
        }
    }

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        switch (mod->state & MOD_INFO_TYPE_MASK) {
        case MOD_INFO_REQ:
            /* this is the module of the nested operation and we need to check that operation's parent data node exists */
            assert((mod->ly_mod == lyd_owner_module(top_op)) && op->parent);
            free(parent_xpath);
            parent_xpath = lyd_path(lyd_parent(op), LYD_PATH_STD, NULL, 0);
            SR_CHECK_MEM_GOTO(!parent_xpath, err_info, cleanup);

            if (mod_info->data) {
                if (lyd_find_xpath(mod_info->data, parent_xpath, &set)) {
                    sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
                    goto cleanup;
                }
            } else {
                if (ly_set_new(&set)) {
                    sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
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

    /* free set */
    ly_set_free(set, NULL);
    set = NULL;

    if (op_ext_parent) {
        /* get the ext parent in mod_info data */
        ext_parent_path = lyd_path(op_ext_parent, LYD_PATH_STD, NULL, 0);
        SR_CHECK_MEM_GOTO(!ext_parent_path, err_info, cleanup);
        lyd_find_path(mod_info->data, ext_parent_path, 0, &data_ext_parent);

        /* get all the parent children nodes, which represent top-level nodes in the mount-jail */
        if (lyd_find_xpath(data_ext_parent, "*", &set)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(data_ext_parent), NULL);
            goto cleanup;
        }

        /* reconnect them into the dependency tree used for validation */
        for (i = 0; i < set->count; ++i) {
            node = set->dnodes[i];
            lyd_unlink_tree(node);
            if (lyd_insert_sibling(mod_info->data, node, &mod_info->data)) {
                sr_errinfo_new_ly(&err_info, LYD_CTX(mod_info->data), NULL);
                goto cleanup;
            }
        }
    }

    /* validate */
    op_type = ((op->schema->nodetype & (LYS_RPC | LYS_ACTION)) ?
            (output ? LYD_TYPE_REPLY_YANG : LYD_TYPE_RPC_YANG) : LYD_TYPE_NOTIF_YANG);
    if (lyd_validate_op(top_op, mod_info->data, op_type, NULL)) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, top_op);
        sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, "%s %svalidation failed.",
                (op->schema->nodetype == LYS_NOTIF) ? "Notification" : ((op->schema->nodetype == LYS_RPC) ? "RPC" : "Action"),
                (op->schema->nodetype == LYS_NOTIF) ? "" : (output ? "output " : "input "));
        goto cleanup;
    }

cleanup:
    if (set && data_ext_parent) {
        for (i = 0; i < set->count; ++i) {
            node = set->dnodes[i];
            lyd_unlink_tree(node);
            if (lyplg_ext_insert(data_ext_parent, node)) {
                sr_errinfo_new_ly(&err_info, LYD_CTX(data_ext_parent), node);
            }
        }
    }

    free(parent_xpath);
    free(ext_parent_path);
    ly_set_free(set, NULL);
    return err_info;
}

sr_error_info_t *
sr_modinfo_get_filter(struct sr_mod_info_s *mod_info, const char *xpath, sr_session_ctx_t *session,
        struct ly_set **result)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    struct lyd_node *edit = NULL, *diff = NULL;
    uint32_t i;
    int is_oper_ds = (session->ds == SR_DS_OPERATIONAL) ? 1 : 0;

    if (session->ds < SR_DS_COUNT) {
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
            if (session->dt[session->ds].edit) {
                edit = session->dt[session->ds].edit->tree;
            }
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
    }

    if (diff || edit) {
        if (mod_info->data_cached) {
            /* data will be changed, we cannot use the cache anymore */
            lyd_dup_siblings(mod_info->data, NULL, LYD_DUP_RECURSIVE | LYD_DUP_WITH_FLAGS, &mod_info->data);
            mod_info->data_cached = 0;

            /* CACHE READ UNLOCK */
            sr_rwunlock(&mod_info->conn->run_cache_lock, SR_CONN_RUN_CACHE_LOCK_TIMEOUT, SR_LOCK_READ,
                    mod_info->conn->cid, __func__);
        }

        for (i = 0; (i < mod_info->mod_count) && (session->ds < SR_DS_COUNT); ++i) {
            mod = &mod_info->mods[i];
            if (mod->state & MOD_INFO_REQ) {
                /* apply any currently handled changes (diff) or additional performed ones (edit) to get
                 * the session-specific data tree */
                if (lyd_diff_apply_module(&mod_info->data, diff, mod->ly_mod, is_oper_ds ? sr_lyd_diff_apply_cb : NULL, NULL)) {
                    sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
                    goto cleanup;
                }
                if ((err_info = sr_edit_mod_apply(edit, mod->ly_mod, &mod_info->data, NULL, NULL))) {
                    goto cleanup;
                }
            }
        }
    }

    if (mod_info->data) {
        /* filter return data using the xpath */
        if (lyd_find_xpath3(NULL, mod_info->data, xpath, NULL, result)) {
            sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
            goto cleanup;
        }
    } else {
        /* empty set */
        if (ly_set_new(result)) {
            sr_errinfo_new(&err_info, SR_ERR_LY, "%s", ly_last_errmsg());
            goto cleanup;
        }
    }

cleanup:
    return err_info;
}

sr_error_info_t *
sr_modinfo_change_notify_update(struct sr_mod_info_s *mod_info, sr_session_ctx_t *session, uint32_t timeout_ms,
        sr_lock_mode_t *change_sub_lock, sr_error_info_t **cb_err_info)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *update_edit = NULL, *old_diff = NULL, *new_diff = NULL;
    uint32_t sid = 0;
    char *orig_name = NULL;
    void *orig_data = NULL;

    assert(mod_info->diff);
    assert(*change_sub_lock == SR_LOCK_READ);

    *cb_err_info = NULL;

    /* get session info */
    if (session) {
        sid = session->sid;
        orig_name = session->orig_name;
        orig_data = session->orig_data;
    }

    /* publish current diff in an "update" event for the subscribers to update it */
    if ((err_info = sr_shmsub_change_notify_update(mod_info, orig_name, orig_data, timeout_ms, &update_edit, cb_err_info))) {
        goto cleanup;
    }
    if (*cb_err_info) {
        /* "update" event failed, just clear the sub SHM and finish */
        err_info = sr_shmsub_change_notify_clear(mod_info);
        goto cleanup;
    }

    /* create new diff if we have an update edit */
    if (update_edit) {
        /* backup the old diff */
        old_diff = mod_info->diff;
        mod_info->diff = NULL;

        /* get new diff using the updated edit */
        if (mod_info->ds == SR_DS_OPERATIONAL) {
            err_info = sr_modinfo_edit_merge(mod_info, update_edit, 1);
        } else {
            err_info = sr_modinfo_edit_apply(mod_info, update_edit, 1);
        }
        if (err_info) {
            goto cleanup;
        }

        /* unlock so that we can lock after additonal modules were marked as changed */

        /* CHANGE SUB READ UNLOCK */
        sr_modinfo_changesub_rdunlock(mod_info);
        *change_sub_lock = SR_LOCK_NONE;

        /* validate updated data trees and finish new diff */
        switch (mod_info->ds) {
        case SR_DS_STARTUP:
        case SR_DS_RUNNING:
            /* add new modules */
            if ((err_info = sr_modinfo_collect_deps(mod_info))) {
                goto cleanup;
            }
            if ((err_info = sr_modinfo_consolidate(mod_info, SR_LOCK_READ, SR_MI_NEW_DEPS | SR_MI_PERM_NO, sid,
                    orig_name, orig_data, 0, 0, 0))) {
                goto cleanup;
            }

            /* validate */
            if ((err_info = sr_modinfo_validate(mod_info, MOD_INFO_CHANGED | MOD_INFO_INV_DEP, 1))) {
                goto cleanup;
            }
            break;
        case SR_DS_CANDIDATE:
            if ((err_info = sr_modinfo_add_defaults(mod_info, 1))) {
                goto cleanup;
            }
            if ((err_info = sr_modinfo_check_state_data(mod_info))) {
                goto cleanup;
            }
            break;
        case SR_DS_OPERATIONAL:
            break;
        case SR_DS_FACTORY_DEFAULT:
            SR_ERRINFO_INT(&err_info);
            goto cleanup;
        }

        /* CHANGE SUB READ LOCK */
        if ((err_info = sr_modinfo_changesub_rdlock(mod_info))) {
            goto cleanup;
        }
        *change_sub_lock = SR_LOCK_READ;

        /* put the old diff back */
        new_diff = mod_info->diff;
        mod_info->diff = old_diff;
        old_diff = NULL;

        /* merge diffs into one */
        if ((err_info = sr_modinfo_diff_merge(mod_info, new_diff))) {
            goto cleanup;
        }
    }

cleanup:
    lyd_free_all(update_edit);
    lyd_free_all(old_diff);
    lyd_free_all(new_diff);
    return err_info;
}

sr_error_info_t *
sr_modinfo_generate_config_change_notif(struct sr_mod_info_s *mod_info, sr_session_ctx_t *session)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *root, *elem, *notif = NULL;
    struct ly_set *set;
    sr_mod_t *shm_mod;
    struct timespec notif_ts_mono, notif_ts_real;
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

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(mod_info->conn, SR_LOCK_READ, 0, __func__))) {
        return err_info;
    }

    /* get subscriber count */
    err_info = sr_notif_find_subscriber(mod_info->conn, "ietf-netconf-notifications", &notif_subs, &notif_sub_count, NULL);

    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(mod_info->conn, SR_LOCK_READ, 0, __func__);

    if (err_info) {
        return err_info;
    }

    /* get this module and check replay support */
    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(mod_info->conn), "ietf-netconf-notifications");
    SR_CHECK_INT_RET(!shm_mod, err_info);
    if (!shm_mod->replay_supp && !notif_sub_count) {
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
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
        goto cleanup;
    }

    /* changed-by (everything was caused by user, we do not know what changes are implicit) */
    if (lyd_new_inner(notif, NULL, "changed-by", 0, &root)) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
        goto cleanup;
    }

    /* changed-by username */
    if (lyd_new_term(root, NULL, "username", session->user, 0, NULL)) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
        goto cleanup;
    }

    /* changed-by NETCONF session-id (unknown) */
    if (lyd_new_term(root, NULL, "session-id", "0", 0, NULL)) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
        goto cleanup;
    }

    /* datastore */
    if (lyd_new_term(notif, NULL, "datastore", sr_ds2str(mod_info->ds), 0, NULL)) {
        sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
        goto cleanup;
    }

    while (!(err_info = sr_diff_set_getnext(set, &idx, &elem, &op)) && elem) {
        /* edit (list instance) */
        if (lyd_new_list(notif, NULL, "edit", 0, &root)) {
            sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
            goto cleanup;
        }

        /* edit target */
        xpath = lyd_path(elem, LYD_PATH_STD, NULL, 0);
        if (!xpath) {
            sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
            goto cleanup;
        }
        lyrc = lyd_new_term(root, NULL, "target", xpath, 0, NULL);
        free(xpath);
        if (lyrc) {
            sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
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
            sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx, NULL);
            goto cleanup;
        }
    }
    if (err_info) {
        goto cleanup;
    }

    /* NOTIF SUB READ LOCK */
    if ((err_info = sr_rwlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, mod_info->conn->cid,
            __func__, NULL, NULL))) {
        goto cleanup;
    }

    /* remember when the notification was generated */
    sr_timeouttime_get(&notif_ts_mono, 0);
    sr_realtime_get(&notif_ts_real);

    /* send the notification (non-validated, if everything works correctly it must be valid) */
    err_info = sr_shmsub_notif_notify(mod_info->conn, notif, notif_ts_mono, notif_ts_real, session->orig_name,
            session->orig_data, 0, 0);

    /* NOTIF SUB READ UNLOCK */
    sr_rwunlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, mod_info->conn->cid, __func__);

    if (err_info) {
        goto cleanup;
    }

    /* store the notification for a replay */
    if ((err_info = sr_replay_store(session, notif, notif_ts_real))) {
        goto cleanup;
    }

cleanup:
    ly_set_free(set, NULL);
    lyd_free_siblings(notif);
    if (err_info) {
        /* write this only if the notification failed to be created/sent */
        sr_errinfo_new(&err_info, err_info->err[0].err_code, "Failed to generate netconf-config-change notification, "
                "but changes were applied.");
    }
    return err_info;
}

sr_error_info_t *
sr_modinfo_data_store(struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    struct lyd_node *mod_diff, *mod_data;
    sr_datastore_t store_ds;
    uint32_t i;

    assert(!mod_info->data_cached);

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & MOD_INFO_CHANGED) {
            /* separate diff and data of this module */
            mod_diff = (mod_info->ds == SR_DS_OPERATIONAL) ? NULL : sr_module_data_unlink(&mod_info->diff, mod->ly_mod);
            mod_data = sr_module_data_unlink(&mod_info->data, mod->ly_mod);

            if ((mod_info->ds == SR_DS_RUNNING) && !mod->ds_handle[mod_info->ds]) {
                /* 'running' disabled, use 'startup' */
                store_ds = SR_DS_STARTUP;
            } else {
                store_ds = mod_info->ds;
            }

            /* store the new data */
            if ((err_info = mod->ds_handle[store_ds]->plugin->store_cb(mod->ly_mod, store_ds, mod_diff, mod_data,
                    mod->ds_handle[store_ds]->plg_data))) {
                goto cleanup;
            }

            /* update the cache ID because data were modified */
            mod->shm_mod->run_cache_id++;

            /* connect them back */
            if (mod_diff) {
                lyd_insert_sibling(mod_info->diff, mod_diff, &mod_info->diff);
            }
            if (mod_data) {
                lyd_insert_sibling(mod_info->data, mod_data, &mod_info->data);
            }

            if ((mod_info->ds == SR_DS_OPERATIONAL) && (mod_info->ds2 == SR_DS_OPERATIONAL)) {
                /* stored oper data, update cache of the modified modules in the connection */
                if (mod_data) {
                    if ((err_info = sr_conn_push_oper_mod_add(mod_info->conn, mod->ly_mod->name))) {
                        goto cleanup;
                    }
                } else {
                    if ((err_info = sr_conn_push_oper_mod_del(mod_info->conn, mod->ly_mod->name))) {
                        goto cleanup;
                    }
                }
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
            /* reset candidate */
            if ((err_info = mod->ds_handle[SR_DS_CANDIDATE]->plugin->candidate_reset_cb(mod->ly_mod,
                    mod->ds_handle[SR_DS_CANDIDATE]->plg_data))) {
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
sr_modinfo_erase(struct sr_mod_info_s *mod_info)
{
    struct sr_mod_info_mod_s *mod;
    uint32_t i, j;

    lyd_free_siblings(mod_info->diff);
    if (mod_info->data_cached) {
        /* CACHE READ UNLOCK */
        sr_rwunlock(&mod_info->conn->run_cache_lock, SR_CONN_RUN_CACHE_LOCK_TIMEOUT, SR_LOCK_READ,
                mod_info->conn->cid, __func__);
    } else {
        lyd_free_siblings(mod_info->data);
    }

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        assert(!(mod->state & (MOD_INFO_RLOCK | MOD_INFO_RLOCK_UPGR | MOD_INFO_WLOCK | MOD_INFO_RLOCK2)));

        if (mod->state & MOD_INFO_XPATH_DYN) {
            for (j = 0; j < mod->xpath_count; ++j) {
                free((char *)mod->xpaths[j]);
            }
        }
        free(mod->xpaths);
    }

    free(mod_info->mods);
}
