/**
 * @file modinfo.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief routines for working with modinfo structure
 *
 * @copyright
 * Copyright (c) 2018 - 2025 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2025 CESNET, z.s.p.o.
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
#include "ly_wrap.h"
#include "lyd_mods.h"
#include "plugins_datastore.h"
#include "replay.h"
#include "shm_ext.h"
#include "shm_mod.h"
#include "shm_sub.h"
#include "subscr.h"
#include "utils/nacm.h"

static sr_error_info_t *sr_modinfo_smdata_parse(void);
static void sr_modinfo_smdata_free(void);

sr_error_info_t *
sr_modinfo_init(struct sr_mod_info_s *mod_info, sr_conn_ctx_t *conn,
        sr_datastore_t ds, sr_datastore_t ds2, int init_sm, uint32_t op_id)
{
    sr_error_info_t *err_info = NULL;

    /* init mod info */
    memset(mod_info, 0, sizeof *mod_info);
    mod_info->ds = ds;
    mod_info->ds2 = ds2;
    mod_info->conn = conn;
    mod_info->operation_id = op_id ? op_id : ATOMIC_INC_RELAXED(SR_CONN_MAIN_SHM(conn)->new_operation_id);

    if (init_sm) {
        /* parse schema mount data, the data is usable until the end of the operation */
        err_info = sr_modinfo_smdata_parse();
    }

    return err_info;
}

sr_error_info_t *
sr_modinfo_add(const struct lys_module *ly_mod, const char *xpath, int dyn, int parent_only, int no_dup_check,
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
    } else if (!(mod->state & MOD_INFO_REQ)) {
        /* different type, re-add */
        mod->state |= MOD_INFO_NEW;
    } else if (!mod->xpath_count) {
        /* mod is present with no xpaths (full data tree), nothing to add */
        return NULL;
    }

    if (xpath) {
        for (i = 0; i < mod->xpath_count; ++i) {
            if (!strcmp(mod->xpaths[i].xpath, xpath)) {
                /* xpath has already been added */
                return NULL;
            }
        }

        /* add xpath for mod */
        mem = realloc(mod->xpaths, (mod->xpath_count + 1) * sizeof *mod->xpaths);
        SR_CHECK_MEM_RET(!mem, err_info);
        mod->xpaths = mem;

        mod->xpaths[mod->xpath_count].xpath = dyn ? strdup(xpath) : xpath;
        mod->xpaths[mod->xpath_count].dyn = dyn ? 1 : 0;
        mod->xpaths[mod->xpath_count].parent_only = parent_only;
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

        if ((err_info = sr_modinfo_add(ly_mod, NULL, 0, 0, 1, mod_info))) {
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

    /* add all the modules from the edit into our array */
    ly_mod = NULL;
    LY_LIST_FOR(edit, root) {
        if (!lyd_owner_module(root) || (lyd_owner_module(root) == ly_mod)) {
            continue;
        } else if (!strcmp(lyd_owner_module(root)->name, "sysrepo")) {
            if (root->schema || strcmp(LYD_NAME(root), "discard-items") || (mod_info->ds != SR_DS_OPERATIONAL)) {
                sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Data of internal module \"sysrepo\" cannot be modified.");
                goto cleanup;
            }

            xpath = lyd_get_value(root);
            if (!xpath || !xpath[0]) {
                sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "An XPath is required for \"discard-items\" node.");
                goto cleanup;
            }

            /* collect xpath to discard */
            if ((err_info = sr_modinfo_collect_xpath(sr_yang_ctx.ly_ctx, xpath, SR_DS_OPERATIONAL, NULL, 0,
                    mod_info))) {
                goto cleanup;
            }
            continue;
        }

        /* remember last mod, good chance it will also be the module of some next data nodes */
        ly_mod = lyd_owner_module(root);

        /* remember the module */
        if ((err_info = sr_modinfo_add(ly_mod, NULL, 0, 0, 0, mod_info))) {
            goto cleanup;
        }
    }

cleanup:
    return err_info;
}

/**
 * @brief Check that a session has some changes for a module for the current DS based on the event.
 *
 * @param[in] session Session to use.
 * @param[in] ly_mod Specific module to check.
 * @return Whether there are some changes or not.
 */
static int
sr_modinfo_session_has_data_changes(sr_session_ctx_t *session, const struct lys_module *ly_mod)
{
    const struct lyd_node *root;

    assert(session);

    if (session->ds >= SR_DS_COUNT) {
        /* factory-default DS */
        return 0;
    }

    /* check edit/diff to be applied based on the handled event */
    switch (session->ev) {
    case SR_SUB_EV_CHANGE:
    case SR_SUB_EV_UPDATE:
        LY_LIST_FOR(session->dt[session->ds].diff, root) {
            if (lyd_owner_module(root) == ly_mod) {
                return 1;
            }
        }
        if (session->ev != SR_SUB_EV_UPDATE) {
            break;
        }
    /* fallthrough */
    case SR_SUB_EV_NONE:
        if (session->dt[session->ds].edit) {
            LY_LIST_FOR(session->dt[session->ds].edit->tree, root) {
                if (lyd_owner_module(root) == ly_mod) {
                    return 1;
                }
            }
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
        break;
    }

    return 0;
}

sr_error_info_t *
sr_modinfo_collect_xpath(const struct ly_ctx *ly_ctx, const char *xpath, sr_datastore_t ds, sr_session_ctx_t *session,
        uint32_t xpath_opts, struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *prev_ly_mod, *ly_mod;
    const struct lysc_node *snode;
    struct ly_set *set = NULL;
    uint32_t i;
    int store_xpath, xp_dyn;

    /* process (simple) xpath options */
    if (xpath_opts & MOD_INFO_XPATH_STORE_ALL) {
        store_xpath = 1;
    } else {
        store_xpath = 0;
    }
    if (xpath_opts & MOD_INFO_XPATH_STORE_DUP) {
        xp_dyn = 1;
    } else {
        xp_dyn = 0;
    }

    /* learn what nodes are needed for evaluation */
    if (((err_info = sr_lys_find_xpath_atoms(ly_ctx, xpath, LYS_FIND_NO_MATCH_ERROR | LYS_FIND_SCHEMAMOUNT, NULL, &set)))) {
        goto cleanup;
    }

    /* add all the modules of the nodes */
    prev_ly_mod = NULL;
    for (i = 0; i < set->count; ++i) {
        snode = set->snodes[i];
        if (snode->module->ctx != ly_ctx) {
            /* skip mounted schema nodes */
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

        if (xpath_opts & MOD_INFO_XPATH_STORE_SESSION_CHANGES) {
            /* decide for each module */
            store_xpath = !sr_modinfo_session_has_data_changes(session, ly_mod);
        }

        if ((err_info = sr_modinfo_add(ly_mod, store_xpath ? xpath : NULL, xp_dyn, 0, 0, mod_info))) {
            goto cleanup;
        }
    }

cleanup:
    ly_set_free(set, NULL);
    return err_info;
}

sr_error_info_t *
sr_modinfo_collect_oper_sess(sr_session_ctx_t *sess, const struct lys_module *ly_mod, struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod2;
    uint32_t i;

    /* add only the cached modules */
    for (i = 0; i < sess->oper_push_mod_count; ++i) {
        if (ly_mod && strcmp(ly_mod->name, sess->oper_push_mods[i].name)) {
            continue;
        }

        if (!sess->oper_push_mods[i].has_data) {
            continue;
        }

        ly_mod2 = ly_ctx_get_module_implemented(sr_yang_ctx.ly_ctx, sess->oper_push_mods[i].name);
        if (!ly_mod2) {
            /* could have been removed */
            continue;
        }
        if ((err_info = sr_modinfo_add(ly_mod2, NULL, 0, 0, 0, mod_info))) {
            return err_info;
        }

        if (ly_mod) {
            break;
        }
    }

    return NULL;
}

sr_error_info_t *
sr_modinfo_collect_deps(struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    uint32_t i;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];

        /* validate only changed required modules or inverse dependency modules */
        if (((mod->state & MOD_INFO_REQ) && (mod->state & MOD_INFO_CHANGED)) || (mod->state & MOD_INFO_INV_DEP)) {
            assert(mod->state & MOD_INFO_DATA);
            if ((err_info = sr_shmmod_collect_deps(SR_CTX_MOD_SHM(sr_yang_ctx),
                    (sr_dep_t *)(sr_yang_ctx.mod_shm.addr + mod->shm_mod->deps), mod->shm_mod->dep_count,
                    mod_info->data, mod_info))) {
                return err_info;
            }
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
    uint32_t i;
    sr_lock_mode_t sm_lock = SR_LOCK_NONE;

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
    if ((err_info = sr_modinfo_collect_xpath(sr_yang_ctx.ly_ctx, path, mod_info->ds, NULL,
            MOD_INFO_XPATH_STORE_ALL | MOD_INFO_XPATH_STORE_DUP, mod_info))) {
        goto cleanup;
    }

    /*
     * 2) collect all data in parent-references of the mount-point
     */

    /* SM DATA LOCK */
    if ((err_info = sr_mlock(&sr_schema_mount_cache.lock, SR_SM_CTX_LOCK_TIMEOUT, __func__, NULL, NULL))) {
        goto cleanup;
    }
    sm_lock = SR_LOCK_WRITE;

    if (!sr_schema_mount_cache.data) {
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
    if ((err_info = sr_lyd_find_xpath(sr_schema_mount_cache.data, path, &set))) {
        goto cleanup;
    }

    for (i = 0; i < set->count; ++i) {
        term = (struct lyd_node_term *)set->dnodes[i];
        LYD_VALUE_GET(&term->value, xp_val);

        /* transform reference into JSON */
        free(str_val);
        str_val = NULL;
        if ((err_info = sr_ly_print_xpath10_value(xp_val, &str_val))) {
            goto cleanup;
        }

        /* get the module */
        mod_name = sr_get_first_ns(str_val);
        mod = ly_ctx_get_module_implemented(sr_yang_ctx.ly_ctx, mod_name);
        free(mod_name);
        SR_CHECK_INT_GOTO(!mod, err_info, cleanup);

        /* collect the XPath and the module */
        if ((err_info = sr_modinfo_add(mod, str_val, 1, 0, 0, mod_info))) {
            goto cleanup;
        }
    }

cleanup:
    if (sm_lock == SR_LOCK_WRITE) {
        /* SM DATA UNLOCK */
        sr_munlock(&sr_schema_mount_cache.lock);
    }
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
sr_modinfo_edit_apply(struct sr_mod_info_s *mod_info, const struct lyd_node *edit, int create_diff,
        sr_error_info_t **val_err_info)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    struct sr_mod_info_mod_s *mod;
    const struct lyd_node *node;
    uint32_t *aux = NULL;
    int change = 0;

    assert(!mod_info->data_cached && ((mod_info->ds != SR_DS_OPERATIONAL) || (mod_info->ds2 != SR_DS_OPERATIONAL)));

    LY_LIST_FOR(edit, node) {
        ly_mod = lyd_node_module(node);
        if (!ly_mod) {
            /* invalid opaque data */
            sr_errinfo_merge(val_err_info, sr_lyd_parse_opaq_error(node));
            continue;
        }

        /* invalid sysrepo data */
        if (!strcmp(ly_mod->name, "sysrepo")) {
            sr_errinfo_new(val_err_info, SR_ERR_UNSUPPORTED, "Data of internal module \"sysrepo\" cannot be modified.");
        }
    }

    mod = NULL;
    while ((mod = sr_modinfo_next_mod(mod, mod_info, edit, &aux))) {
        assert(mod->state & MOD_INFO_REQ);

        /* apply relevant edit changes */
        if ((err_info = sr_edit_mod_apply(edit, mod->ly_mod, &mod_info->data, create_diff ? &mod_info->notify_diff : NULL,
                &change, val_err_info))) {
            goto cleanup;
        }

        if (change) {
            /* there is a diff for this module */
            mod->state |= MOD_INFO_CHANGED;
        }
    }

    if (create_diff) {
        /* diff is the same except for oper DS */
        mod_info->ds_diff = mod_info->notify_diff;
    }

cleanup:
    free(aux);
    return err_info;
}

sr_error_info_t *
sr_modinfo_oper_ds_diff(struct sr_mod_info_s *mod_info, const struct lyd_node *oper_data)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    struct sr_mod_info_mod_s *mod;
    const struct lyd_node *node;
    uint32_t i;
    int change;

    assert(!mod_info->data_cached && (mod_info->ds == SR_DS_OPERATIONAL) && (mod_info->ds2 == SR_DS_OPERATIONAL));

    LY_LIST_FOR(oper_data, node) {
        ly_mod = lyd_node_module(node);
        if (!ly_mod) {
            /* invalid opaque data */
            return sr_lyd_parse_opaq_error(node);
        }

        /* invalid sysrepo data */
        if (!strcmp(ly_mod->name, "sysrepo") && strcmp(LYD_NAME(node), "discard-items")) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Data of internal module \"sysrepo\" cannot be modified.");
            return err_info;
        }
    }

    /* all modules/data are relevant, merge the new data */
    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        assert(mod->state & MOD_INFO_REQ);

        /* merge relevant data */
        if ((err_info = sr_oper_edit_mod_apply(oper_data, mod->ly_mod, &mod_info->data, &mod_info->ds_diff, &change))) {
            goto cleanup;
        }

        if (change) {
            /* there is a diff for this module */
            mod->state |= MOD_INFO_CHANGED;
        }
    }

cleanup:
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
            if ((err_info = sr_lyd_diff_merge_module(&mod_info->notify_diff, new_diff, mod->ly_mod))) {
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

    assert(!mod_info->notify_diff && !mod_info->data_cached &&
            ((mod_info->ds != SR_DS_OPERATIONAL) || (mod_info->ds2 != SR_DS_OPERATIONAL)));

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (!(mod->state & MOD_INFO_REQ)) {
            continue;
        }

        dst_mod_data = sr_module_data_unlink(&mod_info->data, mod->ly_mod, 0);
        src_mod_data = sr_module_data_unlink(src_data, mod->ly_mod, 0);

        /* get diff on only this module's data */
        if ((err_info = sr_lyd_diff_siblings(dst_mod_data, src_mod_data, LYD_DIFF_DEFAULTS, &diff))) {
            lyd_free_all(dst_mod_data);
            lyd_free_all(src_mod_data);
            return err_info;
        }

        if (diff) {
            /* there is a diff */
            mod->state |= MOD_INFO_CHANGED;

            /* merge the diff */
            lyd_insert_sibling(mod_info->notify_diff, diff, &mod_info->notify_diff);

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

    /* diff is the same except for oper DS */
    mod_info->ds_diff = mod_info->notify_diff;

    return NULL;
}

/**
 * @brief Merge all subtrees in a set into a diff with 'none' operation, if did not exist before.
 *
 * @param[in] set Subtrees to merge.
 * @param[in,out] diff Diff to merge into.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_merge_xpath_pred_diff_path(const struct ly_set *set, struct lyd_node **diff)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *top_parent, *node_parent, *match;
    uint32_t i;

    for (i = 0; i < set->count; ++i) {
        /* create parents and/or find the subtree parent */
        if ((err_info = sr_edit_diff_create_parents(set->dnodes[i], diff, &top_parent, &node_parent))) {
            goto cleanup;
        }

        if (top_parent) {
            /* first created parent, set 'none' operation */
            if ((err_info = sr_diff_set_oper(top_parent, "none"))) {
                goto cleanup;
            }
        }

        /* try to find the node */
        if ((err_info = sr_lyd_find_sibling_first(node_parent ? lyd_child(node_parent) : *diff, set->dnodes[i], &match))) {
            goto cleanup;
        }

        if (match) {
            /* already exists */
            continue;
        }

        /* create the node, the subtree (if any) is not needed */
        if ((err_info = sr_lyd_dup(set->dnodes[i], node_parent, 0, 0, &match))) {
            goto cleanup;
        }
        if (!node_parent) {
            if ((err_info = sr_lyd_insert_sibling(*diff, match, diff))) {
                goto cleanup;
            }
        }

        if (!top_parent) {
            /* first created node, set 'none' operation */
            if ((err_info = sr_diff_set_oper(match, "none"))) {
                goto cleanup;
            }
        }

        /* set 'orig-default' if a term node */
        if (match->schema->nodetype & LYD_NODE_TERM) {
            if ((err_info = sr_lyd_new_meta(match, NULL, "yang:orig-default", (match->flags & LYD_DEFAULT) ? "true" : "false"))) {
                goto cleanup;
            }
        }
    }

cleanup:
    return err_info;
}

/**
 * @brief Merge all data subtrees required for evaluating predicates in XPaths into a diff with 'none' operation.
 *
 * @param[in] mod_data All data of a module.
 * @param[in] xpaths Array of XPaths terminated by NULL.
 * @param[in,out] diff Diff to merge into.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_merge_xpath_pred_diff(const struct lyd_node *mod_data, const char **xpaths, struct lyd_node **diff)
{
    sr_error_info_t *err_info = NULL;
    sr_xp_atoms_t *xp_atoms = NULL;
    struct ly_set *set = NULL;
    uint32_t i, j, k;

    if (!mod_data || !xpaths) {
        /* nothing to merge */
        goto cleanup;
    }

    for (i = 0; xpaths[i]; ++i) {
        /* free previous atoms */
        sr_xpath_atoms_free(xp_atoms);
        xp_atoms = NULL;

        /* get text atoms of the xpath */
        if ((err_info = sr_xpath_get_text_atoms(xpaths[i], &xp_atoms))) {
            goto cleanup;
        }

        for (j = 0; j < xp_atoms->union_count; ++j) {
            for (k = 0; k < xp_atoms->unions[j].atom_count; ++k) {
                if (xp_atoms->unions[j].atoms[k].selected) {
                    /* skip */
                    continue;
                }

                /* get the data required to evaluate this atom */
                ly_set_free(set, NULL);
                if ((err_info = sr_lyd_find_xpath(mod_data, xp_atoms->unions[j].atoms[k].atom, &set))) {
                    goto cleanup;
                }

                /* merge the required data into diff */
                if ((err_info = sr_modinfo_merge_xpath_pred_diff_path(set, diff))) {
                    goto cleanup;
                }
            }
        }
    }

cleanup:
    sr_xpath_atoms_free(xp_atoms);
    ly_set_free(set, NULL);
    return err_info;
}

sr_error_info_t *
sr_modinfo_oper_notify_diff(struct sr_mod_info_s *mod_info, struct lyd_node **old_data)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    struct lyd_node *new_mod_data = NULL, *old_mod_data = NULL, *diff;
    uint32_t i, j;
    char **xpaths = NULL;

    assert(!mod_info->notify_diff && !mod_info->data_cached);

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (!(mod->state & MOD_INFO_REQ)) {
            continue;
        }

        /* unlink data */
        new_mod_data = sr_module_data_unlink(&mod_info->data, mod->ly_mod, 0);
        old_mod_data = sr_module_data_unlink(old_data, mod->ly_mod, 0);

        /* get diff on only this module's data */
        if ((err_info = sr_lyd_diff_siblings(old_mod_data, new_mod_data, LYD_DIFF_DEFAULTS, &diff))) {
            goto cleanup;
        }

        if (diff) {
            /* merge the diff */
            lyd_insert_sibling(mod_info->notify_diff, diff, &mod_info->notify_diff);

            /* free previous xpaths */
            if (xpaths) {
                for (j = 0; xpaths[j]; ++j) {
                    free(xpaths[j]);
                }
                free(xpaths);
            }

            /* merge also any stored data used in change subscription xpath filters so they can be correctly evaluated */
            if ((err_info = sr_shmsub_change_notify_collect_xpaths(mod_info->conn, mod, SR_DS_OPERATIONAL, &xpaths))) {
                goto cleanup;
            }
            if ((err_info = sr_modinfo_merge_xpath_pred_diff(new_mod_data, (const char **)xpaths, &mod_info->notify_diff))) {
                goto cleanup;
            }
        }

        /* relink data */
        if (new_mod_data) {
            lyd_insert_sibling(mod_info->data, new_mod_data, &mod_info->data);
            new_mod_data = NULL;
        }
        if (old_mod_data) {
            lyd_insert_sibling(*old_data, old_mod_data, old_data);
            old_mod_data = NULL;
        }
    }

cleanup:
    lyd_free_all(new_mod_data);
    lyd_free_all(old_mod_data);
    if (xpaths) {
        for (j = 0; xpaths[j]; ++j) {
            free(xpaths[j]);
        }
        free(xpaths);
    }
    return err_info;
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
 * @brief Check whether operational data request and subscription predicate match.
 *
 * @param[in] request_pred Request predicate.
 * @param[in] sub_pred Subscription predicate.
 * @return 0 predicate for different nodes, not applicable;
 * @return 1 predicate for the same nodes with the same value, matches;
 * @return 2 predicate for the same nodes with different values, does not match.
 */
static int
sr_xpath_oper_data_text_atom_pred_match(const char *request_pred, const char *sub_pred)
{
    const char *req_ptr, *sub_ptr, *mod1, *name1, *val1, *mod2, *name2, *val2;
    int mlen1, mlen2, len1, len2;

    req_ptr = request_pred;
    sub_ptr = sub_pred;

    do {
        /* parse nodes */
        req_ptr = sr_xpath_next_qname(req_ptr + 1, &mod1, &mlen1, &name1, &len1);
        sub_ptr = sr_xpath_next_qname(sub_ptr + 1, &mod2, &mlen2, &name2, &len2);

        /* module name */
        if ((mlen1 && mlen2) && ((mlen1 != mlen2) || strncmp(mod1, mod2, mlen1))) {
            /* different modules */
            return 0;
        }

        /* node name */
        if ((len1 != len2) || strncmp(name1, name2, len1)) {
            /* different node names */
            return 0;
        }
    } while ((req_ptr[0] != '=') && (sub_ptr[0] != '='));

    if ((req_ptr[0] != '=') || (sub_ptr[0] != '=')) {
        /* path continues */
        return 0;
    }

    ++req_ptr;
    ++sub_ptr;

    /* compare values */
    val1 = req_ptr + 1;
    len1 = strchr(val1, req_ptr[0]) - val1;
    val2 = sub_ptr + 1;
    len2 = strchr(val2, sub_ptr[0]) - val2;
    if (len1 != len2) {
        return 2;
    }
    return strncmp(val1, val2, len1) ? 2 : 1;
}

/**
 * @brief Check whether operational data are required based on a single request and subscription atom.
 *
 * @param[in] request_atom Request text atom.
 * @param[in] sub_atom Subscription text atom.
 * @param[in] req_parent_only Request text atom is only for the parent node, without subtree data.
 * @return 0 data are not required based on the atoms;
 * @return 1 data are required;
 * @return 2 data are not required (would be filtered out).
 */
static int
sr_xpath_oper_data_text_atoms_required(const char *request_atom, const char *sub_atom, int req_parent_only)
{
    const char *req_ptr, *sub_ptr, *mod1, *name1, *mod2, *name2;
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

        /* predicate, always at the end and so decides the match */
        if ((req_ptr[0] == '[') && (sub_ptr[0] == '[')) {
            if (sr_xpath_oper_data_text_atom_pred_match(req_ptr + 1, sub_ptr + 1) == 2) {
                /* filtered out */
                return 2;
            } else {
                /* different nodes or the value matches */
                return 1;
            }
        } else if ((req_ptr[0] == '[') || (sub_ptr[0] == '[')) {
            /* predicate only in one atom and it must end after the predicate */
            break;
        }

        /* parse until the subscription path ends */
    } while (req_ptr[0] && sub_ptr[0]);

    if (!req_ptr[0] && sub_ptr[0] && req_parent_only) {
        /* subscription is for request subtree, not needed */
        return 0;
    } else {
        /* atom match */
        return 1;
    }
}

/**
 * @brief Check whether operational data are required.
 *
 * @param[in] request_xpath Get request full XPath.
 * @param[in] sub_xpath Operational subscription XPath.
 * @param[in] request_parent_only Get request xpath is only for the parent node, without subtree data.
 * @param[out] required Whether the oper data are required or not.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_xpath_oper_data_required(const char *request_xpath, const char *sub_xpath, int request_parent_only, int *required)
{
    sr_error_info_t *err_info = NULL;
    sr_xp_atoms_t *req_atoms = NULL, *sub_atoms = NULL;
    uint32_t i, j, k, l;
    sr_xp_atoms_atom_t *req_atom, *sub_atom;
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

    /* check whether any atoms match */
    *required = 0;
    for (i = 0; i < req_atoms->union_count; ++i) {
        for (j = 0; j < sub_atoms->union_count; ++j) {
            for (k = 0; k < req_atoms->unions[i].atom_count; ++k) {
                req_atom = &req_atoms->unions[i].atoms[k];
                for (l = 0; l < sub_atoms->unions[j].atom_count; ++l) {
                    sub_atom = &sub_atoms->unions[j].atoms[l];

                    /* check atoms */
                    r = sr_xpath_oper_data_text_atoms_required(req_atom->atom, sub_atom->atom, request_parent_only);
                    if ((r == 0) && req_atom->selected && sub_atom->selected) {
                        /* specific selected nodes do not match, not required for the whole union */
                        *required = 0;
                        break;
                    } else if (r == 1) {
                        /* required but need to check all the atoms */
                        *required = 1;
                    } else if (r == 2) {
                        /* values do not match, not required for the whole union */
                        *required = 0;
                        break;
                    }
                }
                if (l < sub_atoms->unions[j].atom_count) {
                    /* not required for the whole union */
                    break;
                }
            }

            if (*required) {
                /* required for the union */
                goto cleanup;
            }
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
 * @param[in] operation_id Operation ID.
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
        uint32_t req_xpath_count, const char *orig_name, const void *orig_data, uint32_t operation_id,
        sr_mod_oper_get_sub_t *shm_subs, uint32_t idx1, const struct lyd_node *parent, uint32_t timeout_ms,
        sr_conn_ctx_t *conn, struct lyd_node **oper_data)
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
        if ((err_info = sr_lyd_dup(parent, NULL, LYD_DUP_WITH_PARENTS, 0, &last_parent))) {
            return err_info;
        }

        /* go top-level */
        for (parent_dup = last_parent; parent_dup->parent; parent_dup = lyd_parent(parent_dup)) {}

        if (req_xpath_count) {
            /* check whether the parent would not be filtered out */
            parent_path = lyd_path(last_parent, LYD_PATH_STD, NULL, 0);
            SR_CHECK_MEM_GOTO(!parent_path, err_info, cleanup);

            for (i = 0; i < req_xpath_count; ++i) {
                if ((err_info = sr_xpath_oper_data_required(request_xpaths[i], parent_path, 0, &required))) {
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
    if ((err_info = sr_shmsub_oper_get_notify(mod, xpath, request_xpath, parent_dup, orig_name, orig_data, operation_id,
            shm_subs, idx1, timeout_ms, conn, oper_data, &cb_err_info))) {
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
        if ((err_info = sr_lyd_new_implicit_tree(*oper_data, LYD_IMPLICIT_NO_DEFAULTS))) {
            goto cleanup;
        }
    }

cleanup:
    lyd_free_tree(parent_dup);
    free(parent_path);
    if (err_info) {
        lyd_free_all(*oper_data);
        *oper_data = NULL;
    }
    return err_info;
}

/**
 * @brief Try to merge operational get cached data of a subscription.
 *
 * @param[in] conn Connection to use.
 * @param[in] mod Mod info module.
 * @param[in] sub_xpath Subscription XPath.
 * @param[in,out] data Operational data tree to merge into.
 * @param[out] merged Whether the cached data were found and merged or not.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_module_oper_data_update_cached(sr_conn_ctx_t *conn, struct sr_mod_info_mod_s *mod, const char *sub_xpath,
        struct lyd_node **data, int *merged)
{
    sr_error_info_t *err_info = NULL;
    struct sr_oper_cache_sub_s *cache = NULL;
    uint32_t i;
    int len;

    *merged = 0;

    /* OPER CACHE READ LOCK */
    if ((err_info = sr_rwlock(&sr_oper_cache.lock, SR_OPER_CACHE_LOCK_TIMEOUT, SR_LOCK_READ,
            conn->cid, __func__, NULL, NULL))) {
        goto cleanup;
    }

    /* try to get data from the cache */
    for (i = 0; i < sr_oper_cache.sub_count; ++i) {
        /* module name */
        if (strcmp(sr_oper_cache.subs[i].module_name, mod->ly_mod->name)) {
            continue;
        }

        /* this subscription or any nested subscriptions are cached */
        len = strlen(sr_oper_cache.subs[i].path);
        if (strncmp(sr_oper_cache.subs[i].path, sub_xpath, len)) {
            continue;
        }
        if ((sub_xpath[len] != '\0') && (sub_xpath[len] != '/')) {
            continue;
        }

        /* cached subscription */
        cache = &sr_oper_cache.subs[i];
        break;
    }
    if (!cache) {
        goto cleanup_cache_unlock;
    }

    /* CACHE DATA READ LOCK */
    if ((err_info = sr_rwlock(&cache->data_lock, SR_OPER_CACHE_DATA_LOCK_TIMEOUT, SR_LOCK_READ,
            conn->cid, __func__, NULL, NULL))) {
        goto cleanup_cache_unlock;
    }

    /* merge cached data */
    if ((err_info = sr_lyd_merge(data, cache->data, 1, 0))) {
        goto cleanup_data_cache_unlock;
    }
    *merged = 1;

cleanup_data_cache_unlock:
    /* CACHE DATA UNLOCK */
    sr_rwunlock(&cache->data_lock, SR_OPER_CACHE_DATA_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

cleanup_cache_unlock:
    /* OPER CACHE UNLOCK */
    sr_rwunlock(&sr_oper_cache.lock, SR_OPER_CACHE_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

cleanup:
    return err_info;
}

/**
 * @brief Callback for merging operational data.
 */
static LY_ERR
sr_oper_data_merge_cb(struct lyd_node *trg_node, const struct lyd_node *src_node, void *UNUSED(cb_data))
{
    sr_error_info_t *err_info = NULL;
    const char *or = NULL;

    if (!src_node) {
        /* trg_node subtree is merged with metadata */
        return LY_SUCCESS;
    }

    /* get explicit origin, if any set */
    sr_edit_diff_get_origin(src_node, 0, &or, NULL);

    if (or) {
        /* ovewrite any previous origin */
        if ((err_info = sr_edit_diff_set_origin(trg_node, or, 1))) {
            sr_errinfo_free(&err_info);
            return LY_EOTHER;
        }
    }

    return LY_SUCCESS;
}

/**
 * @brief Check whether the session has pushed any operational data to this module.
 *        If data exists, get it from cache if available.
 *
 * @param[in] sess Session to check.
 * @param[in] mod_name module name to search.
 * @param[in] dup Flag to duplicate data and not consume it.
 * @param[out] has_data Flag whether session has push operational data for this module.
 * @param[out] mod_data Cached module data if available.
 * @return err_info if an error occurs during duplication, NULL otherwise.
 */
static sr_error_info_t *
sr_modinfo_module_data_cache_get(sr_session_ctx_t *sess, const char *mod_name, int dup, int *has_data, struct lyd_node **mod_data)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;

    *mod_data = NULL;
    *has_data = 0;

    for (i = 0; i < sess->oper_push_mod_count; ++i) {
        if (!strcmp(sess->oper_push_mods[i].name, mod_name)) {
            break;
        }
    }

    /* module not found */
    if (i == sess->oper_push_mod_count) {
        return NULL;
    }

    *has_data = sess->oper_push_mods[i].has_data;

    /* no cache available for use */
    if (!sess->oper_push_mods[i].cache) {
        return NULL;
    }

    if (dup) {
        /* duplicate the cached data for use */
        if ((err_info = sr_lyd_dup(sess->oper_push_mods[i].cache, NULL, LYD_DUP_RECURSIVE | LYD_DUP_WITH_FLAGS, 1, mod_data))) {
            return err_info;
        }
    } else {
        /* consume the cache */
        *mod_data = sess->oper_push_mods[i].cache;
        sess->oper_push_mods[i].cache = NULL;
    }

    return NULL;
}

/**
 * @brief Load and merge/process all the oper push data stored for a module.
 *
 * @param[in] mod Mod info module.
 * @param[in] conn Connection to use.
 * @param[in] sess Session whose oper push data should be loaded, if NULL, load data of all sessions with oper push data for this module.
 * @param[in,out] data Operational data tree.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_module_oper_data_load(struct sr_mod_info_mod_s *mod, sr_conn_ctx_t *conn, sr_session_ctx_t *sess,
        struct lyd_node **mod_oper_data, struct lyd_node **data)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_oper_push_t *oper_push_dup = NULL, *oper_push_ext;
    struct lyd_node *mod_data = NULL, *next, *node;
    const struct lys_module *ly_mod;
    const char *xpath;
    struct ly_set *set;
    uint32_t i, j, merge_opts, oper_push_count = 0;
    int last_sid = 0, dead_cid = 0, has_data = 0;
    uint32_t sid = sess ? sess->sid : 0;

    /* oper_push_data_count is protected by operational DS module data locks */
    if (mod->shm_mod->oper_push_data_count) {
        /* EXT READ LOCK */
        if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
            goto cleanup;
        }

        /* make a local copy of the array, with only alive connections */
        oper_push_dup = malloc(mod->shm_mod->oper_push_data_count * sizeof *oper_push_dup);
        if (!oper_push_dup) {
            SR_ERRINFO_MEM(&err_info);
        } else {
            oper_push_ext = (sr_mod_oper_push_t *)(conn->ext_shm.addr + mod->shm_mod->oper_push_data);
            for (i = 0; i < mod->shm_mod->oper_push_data_count; ++i) {
                if (!sr_conn_is_alive(oper_push_ext[i].cid)) {
                    /* remember to remove the dead connections */
                    dead_cid = 1;
                } else {
                    oper_push_dup[oper_push_count] = oper_push_ext[i];
                    ++oper_push_count;
                }
            }
        }
        /* EXT READ UNLOCK */
        sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);
    }

    if (err_info) {
        goto cleanup;
    }

    if (dead_cid) {
        /* recover oper push data of all dead connections */
        if ((err_info = sr_shmmod_del_module_oper_data(conn, mod->ly_mod, &mod->state, mod->shm_mod, 1))) {
            goto cleanup;
        }
    }

    for (i = 0; i < oper_push_count; ++i) {
        if (!oper_push_dup[i].has_data) {
            /* no push oper data */
            continue;
        }

        /* push data entries are ordered */
        assert(!i || (oper_push_dup[i].order > oper_push_dup[i - 1].order));

        if (oper_push_dup[i].sid == sid) {
            last_sid = 1;
        }
        if (!last_sid || !mod_oper_data) {
            if (oper_push_dup[i].sid == sid) {
                /* load push oper data from the session cache (consume it) */
                if ((err_info = sr_modinfo_module_data_cache_get(sess, mod->ly_mod->name, 0, &has_data, &mod_data))) {
                    goto cleanup;
                }
            }
            /* load push oper data for the session from the datastore plugin if cache was empty */
            if (!mod_data && (err_info = sr_module_file_data_append(mod->ly_mod, mod->ds_handle, SR_DS_OPERATIONAL,
                    oper_push_dup[i].cid, oper_push_dup[i].sid, mod->xpaths, mod->xpath_count, &mod_data))) {
                goto cleanup;
            }
        } else {
use_mod_oper_data:
            /* use the provided oper data of the session */
            mod_data = *mod_oper_data;
        }

        /* process XPath removals first */
        LY_LIST_FOR_SAFE(mod_data, next, node) {
            if (node->schema) {
                continue;
            }

            ly_mod = lyd_owner_module(node);
            if (!ly_mod || strcmp(ly_mod->name, "sysrepo") || strcmp(LYD_NAME(node), "discard-items")) {
                /* other opaque nodes */
                continue;
            }

            xpath = lyd_get_value(node);
            if (!xpath || !xpath[0]) {
                /* invalid XPath */
                continue;
            }

            /* select the nodes to remove */
            if ((err_info = sr_lyd_find_xpath(*data, xpath, &set))) {
                goto cleanup;
            }

            /* get rid of all redundant results that are descendants of another result */
            if ((err_info = sr_xpath_set_filter_subtrees(set))) {
                goto cleanup;
            }

            /* free all the selected subtrees */
            for (j = 0; j < set->count; ++j) {
                sr_lyd_free_tree_safe(set->dnodes[j], data);
            }
            ly_set_free(set, NULL);
        }

        /* merge into the oper data tree, use callback to merge metadata */
        if (!last_sid || !mod_oper_data) {
            merge_opts = LYD_MERGE_DESTRUCT | LYD_MERGE_WITH_FLAGS;
        } else {
            merge_opts = LYD_MERGE_WITH_FLAGS;
        }
        if ((err_info = sr_lyd_merge_module(data, mod_data, mod->ly_mod, sr_oper_data_merge_cb, NULL, merge_opts))) {
            goto cleanup;
        }
        mod_data = NULL;

        if (last_sid) {
            /* the last session to process */
            break;
        }
    }

    if (!last_sid && mod_oper_data) {
        /* there were no data for this session, use them now */
        last_sid = 1;
        goto use_mod_oper_data;
    }

cleanup:
    free(oper_push_dup);
    lyd_free_siblings(mod_data);
    return err_info;
}

sr_error_info_t *
sr_modinfo_get_oper_data(struct sr_mod_info_s *mod_info, sr_session_ctx_t *sess, struct lyd_node **oper_data)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    struct lyd_node *mod_oper_data = NULL;
    uint32_t i;

    assert((mod_info->ds == SR_DS_OPERATIONAL) && (mod_info->ds2 == SR_DS_OPERATIONAL) && !mod_info->data && sess);

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];

        if (oper_data) {
            /* get oper data for the specific module */
            mod_oper_data = sr_module_data_unlink(oper_data, mod->ly_mod, 1);
        }

        /* load the requested oper data */
        if ((err_info = sr_module_oper_data_load(mod, mod_info->conn, sess, oper_data ? &mod_oper_data : NULL,
                &mod_info->data))) {
            goto cleanup;
        }

        if (mod_oper_data) {
            /* relink module oper data */
            lyd_insert_sibling(*oper_data, mod_oper_data, oper_data);

            mod_oper_data = NULL;
        }
    }

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
 * @param[in] operation_id Operation ID.
 * @param[in] conn Connection to use.
 * @param[in] timeout_ms Operational callback timeout in milliseconds.
 * @param[in] get_oper_opts Get oper data options.
 * @param[in,out] data Operational data tree.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_module_oper_data_update(struct sr_mod_info_mod_s *mod, const char *orig_name, const void *orig_data,
        uint32_t operation_id, sr_conn_ctx_t *conn, uint32_t timeout_ms, sr_get_oper_flag_t get_oper_opts,
        struct lyd_node **data)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_oper_get_sub_t *shm_subs;
    sr_mod_oper_get_xpath_sub_t *xpath_subs;
    const char *sub_xpath, **request_xpaths = NULL;
    char *parent_xpath = NULL;
    uint32_t i, j, req_xpath_count = 0;
    int required, merged;
    struct ly_set *set = NULL;
    struct lyd_node *oper_data;

    if (!(get_oper_opts & SR_OPER_NO_STORED)) {
        /* process stored operational data */
        if ((err_info = sr_module_oper_data_load(mod, conn, NULL, NULL, data))) {
            return err_info;
        }

        if (!(get_oper_opts & SR_OPER_NO_PUSH_NP_CONT)) {
            /* add any missing NP containers in the data */
            if ((err_info = sr_lyd_new_implicit_module(data, mod->ly_mod, LYD_IMPLICIT_NO_DEFAULTS, NULL))) {
                return err_info;
            }
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
                if ((err_info = sr_xpath_oper_data_required(mod->xpaths[j].xpath, sub_xpath, mod->xpaths[j].parent_only,
                        &required))) {
                    goto cleanup_opergetsub_ext_unlock;
                }
                if (required) {
                    /* remember all xpaths causing these data to be required */
                    request_xpaths = sr_realloc(request_xpaths, (req_xpath_count + 1) * sizeof *request_xpaths);
                    SR_CHECK_MEM_GOTO(!request_xpaths, err_info, cleanup_opergetsub_ext_unlock);
                    request_xpaths[req_xpath_count] = mod->xpaths[j].xpath;
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
            if ((err_info = sr_module_oper_data_update_cached(conn, mod, sub_xpath, data, &merged))) {
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

            if ((err_info = sr_lyd_find_xpath(*data, parent_xpath, &set))) {
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
                        orig_data, operation_id, shm_subs, i, set->dnodes[j], timeout_ms, conn, &oper_data))) {
                    goto cleanup_opergetsub_ext_unlock;
                }

                /* merge into one data tree */
                if ((err_info = sr_lyd_merge(data, oper_data, 1, LYD_MERGE_DESTRUCT))) {
                    lyd_free_all(oper_data);
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
                    orig_data, operation_id, shm_subs, i, NULL, timeout_ms, conn, &oper_data))) {
                goto cleanup_opergetsub_ext_unlock;
            }

            if ((err_info = sr_lyd_merge(data, oper_data, 1, LYD_MERGE_DESTRUCT))) {
                lyd_free_all(oper_data);
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
        /* try to find an "alive" and "active" subscription for the whole module */
        for (i = 0; i < mod->shm_mod->change_sub[SR_DS_RUNNING].sub_count; ++i) {
            if (!shm_changesubs[i].xpath && !(shm_changesubs[i].opts & SR_SUBSCR_PASSIVE) &&
                    sr_conn_is_alive(shm_changesubs[i].cid)) {
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
            if (shm_changesubs[i].xpath && !(shm_changesubs[i].opts & SR_SUBSCR_PASSIVE) &&
                    sr_conn_is_alive(shm_changesubs[i].cid)) {
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
 * @brief Load module data of the ietf-yang-library module. They are actually generated.
 *
 * @note YANG library data are created for the context that the @p mod->ly_mod was loaded in.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] mod ietf-yang-library module to load data for.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_module_data_load_yanglib(struct sr_mod_info_s *mod_info, struct sr_mod_info_mod_s *mod)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *mod_data;
    uint32_t content_id, i;
    struct ly_set *set = NULL;

    /* get content-id */
    content_id = ly_ctx_get_modules_hash(mod->ly_mod->ctx);

    /* get the data from libyang */
    if ((err_info = sr_ly_ctx_get_yanglib_data(mod->ly_mod->ctx, &mod_data, content_id))) {
        goto cleanup;
    }

    if (!strcmp(mod->ly_mod->revision, "2019-01-04")) {
        assert(!strcmp(mod_data->schema->name, "yang-library"));

        /* add supported datastores */
        if ((err_info = sr_lyd_new_path(mod_data, NULL, "datastore[name='ietf-datastores:running']/schema", "complete",
                0, NULL, NULL))) {
            goto cleanup;
        }
        if ((err_info = sr_lyd_new_path(mod_data, NULL, "datastore[name='ietf-datastores:candidate']/schema", "complete",
                0, NULL, NULL))) {
            goto cleanup;
        }
        if ((err_info = sr_lyd_new_path(mod_data, NULL, "datastore[name='ietf-datastores:startup']/schema", "complete",
                0, NULL, NULL))) {
            goto cleanup;
        }
        if ((err_info = sr_lyd_new_path(mod_data, NULL, "datastore[name='ietf-datastores:operational']/schema", "complete",
                0, NULL, NULL))) {
            goto cleanup;
        }
    } else if (!strcmp(mod->ly_mod->revision, "2016-06-21")) {
        assert(!strcmp(mod_data->schema->name, "modules-state"));

        /* all data should already be there */
    } else {
        /* no other revision is supported */
        SR_ERRINFO_INT(&err_info);
        goto cleanup;
    }

    /* add missing 'location' and 'schema' nodes */
    if ((err_info = sr_lyd_find_xpath(mod_data, "/ietf-yang-library:yang-library/module-set/module[not(location)] | "
            "/ietf-yang-library:yang-library/module-set/import-only-module[not(location)]", &set))) {
        goto cleanup;
    }
    for (i = 0; i < set->count; ++i) {
        if ((err_info = sr_lyd_new_term(set->dnodes[i], NULL, "location", "file://@internal"))) {
            goto cleanup;
        }
    }
    ly_set_free(set, NULL);
    if ((err_info = sr_lyd_find_xpath(mod_data, "/ietf-yang-library:modules-state/module[not(schema)]", &set))) {
        goto cleanup;
    }
    for (i = 0; i < set->count; ++i) {
        if ((err_info = sr_lyd_new_term(set->dnodes[i], NULL, "schema", "file://@internal"))) {
            goto cleanup;
        }
    }

    /* connect to the rest of data */
    if ((err_info = sr_lyd_merge(&mod_info->data, mod_data, 1, LYD_MERGE_DESTRUCT))) {
        goto cleanup;
    }

cleanup:
    ly_set_free(set, NULL);
    return err_info;
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
    ly_mod = ly_ctx_get_module_implemented(sr_yang_ctx.ly_ctx, sr_yang_ctx.mod_shm.addr + shm_mod->name);
    assert(ly_mod);

    if (!strcmp(ly_mod->name, "ietf-netconf") || !sr_module_has_data(ly_mod, 0)) {
        /* skip modules without configuration data */
        goto cleanup;
    }

    if ((err_info = sr_ds_handle_find(sr_yang_ctx.mod_shm.addr + shm_mod->plugins[ds], conn, &ds_handle))) {
        goto cleanup;
    }

    if ((err_info = ds_handle->plugin->last_modif_cb(ly_mod, ds, ds_handle->plg_data, &mtime))) {
        goto cleanup;
    }

    if (mtime.tv_sec > 0) {
        /* datastore with name */
        if ((err_info = sr_lyd_new_list(sr_state, "datastore", sr_ds2ident(ds), &sr_store))) {
            goto cleanup;
        }

        ly_time_ts2str(&mtime, &buf);
        if ((err_info = sr_lyd_new_term(sr_store, NULL, "last-modified", buf))) {
            goto cleanup;
        }
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

    /* unlocked access to the lock, possible wrong/stale values should not matter */

    if ((cid = rwlock->upgr)) {
        snprintf(path, PATH_LEN, path_format, cid, "read-upgr");
        if ((err_info = sr_lyd_new_path(ctx_node, NULL, path, NULL, 0, NULL, NULL))) {
            goto cleanup;
        }

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
        /* use LYD_NEW_PATH_UPDATE to ignore duplicates due to unlocked access racing with reader_del */
        if ((err_info = sr_lyd_new_path(ctx_node, NULL, path, NULL, LYD_NEW_PATH_UPDATE, NULL, NULL))) {
            goto cleanup;
        }
    }

    /* if there is a read-lock and the writer is set, it is just an urged write-lock being waited on, ignore it */
    if (!i && (cid = rwlock->writer)) {
        snprintf(path, PATH_LEN, path_format, cid, "write");
        if ((err_info = sr_lyd_new_path(ctx_node, NULL, path, NULL, 0, NULL, NULL))) {
            goto cleanup;
        }
    }

cleanup:
    return err_info;
#undef PATH_LEN
}

/**
 * @brief Add held lock nodes (cid, mode) to a data tree.
 *
 * @param[in] rwlock Lock to read CIDs from.
 * @param[in] list_name List node name to create.
 * @param[in] parent Parent node of the new node @p list_name.
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

    /* unlocked access to the lock, possible wrong/stale values should not matter */

    if ((cid = rwlock->writer)) {
        /* list instance */
        if ((err_info = sr_lyd_new_list(parent, list_name, NULL, &list))) {
            goto cleanup;
        }

        /* cid */
        snprintf(cid_str, CID_STR_LEN, "%" PRIu32, cid);
        if ((err_info = sr_lyd_new_term(list, NULL, "cid", cid_str))) {
            goto cleanup;
        }

        /* mode */
        if ((err_info = sr_lyd_new_term(list, NULL, "mode", "write"))) {
            goto cleanup;
        }
    }
    if ((cid = rwlock->upgr)) {
        if ((err_info = sr_lyd_new_list(parent, list_name, NULL, &list))) {
            goto cleanup;
        }

        snprintf(cid_str, CID_STR_LEN, "%" PRIu32, cid);
        if ((err_info = sr_lyd_new_term(list, NULL, "cid", cid_str))) {
            goto cleanup;
        }

        if ((err_info = sr_lyd_new_term(list, NULL, "mode", "read-upgr"))) {
            goto cleanup;
        }
    }

    for (i = 0; (i < SR_RWLOCK_READ_LIMIT) && rwlock->readers[i]; ++i) {
        if ((err_info = sr_lyd_new_list(parent, list_name, NULL, &list))) {
            goto cleanup;
        }

        snprintf(cid_str, CID_STR_LEN, "%" PRIu32, rwlock->readers[i]);
        if ((err_info = sr_lyd_new_term(list, NULL, "cid", cid_str))) {
            goto cleanup;
        }

        if ((err_info = sr_lyd_new_term(list, NULL, "mode", "read"))) {
            goto cleanup;
        }
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

    /* subscriptions, make implicit */
    if ((err_info = sr_lyd_new_inner(sr_mod, NULL, "subscriptions", &sr_subs))) {
        return err_info;
    }
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
            if ((err_info = sr_lyd_new_list(sr_subs, "change-sub", NULL, &sr_sub))) {
                goto change_ext_sub_unlock;
            }

            /* datastore */
            if ((err_info = sr_lyd_new_term(sr_sub, NULL, "datastore", sr_ds2ident(ds)))) {
                goto change_ext_sub_unlock;
            }

            /* xpath */
            if (change_subs[i].xpath) {
                if ((err_info = sr_lyd_new_term(sr_sub, NULL, "xpath", conn->ext_shm.addr + change_subs[i].xpath))) {
                    goto change_ext_sub_unlock;
                }
            }

            /* priority */
            sprintf(buf, "%" PRIu32, change_subs[i].priority);
            if ((err_info = sr_lyd_new_term(sr_sub, NULL, "priority", buf))) {
                goto change_ext_sub_unlock;
            }

            /* cid */
            sprintf(buf, "%" PRIu32, change_subs[i].cid);
            if ((err_info = sr_lyd_new_term(sr_sub, NULL, "cid", buf))) {
                goto change_ext_sub_unlock;
            }

            /* suspended */
            sprintf(buf, "%s", ATOMIC_LOAD_RELAXED(change_subs[i].suspended) ? "true" : "false");
            if ((err_info = sr_lyd_new_term(sr_sub, NULL, "suspended", buf))) {
                goto change_ext_sub_unlock;
            }
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
        if ((err_info = sr_lyd_new_list(sr_subs, "operational-get-sub",
                conn->ext_shm.addr + oper_get_subs[i].xpath, &sr_xpath_sub))) {
            goto operget_ext_sub_unlock;
        }

        for (j = 0; j < oper_get_subs[i].xpath_sub_count; ++j) {
            xpath_sub = &((sr_mod_oper_get_xpath_sub_t *)(conn->ext_shm.addr + oper_get_subs[i].xpath_subs))[j];

            /* ignore dead subscriptions */
            if (!sr_conn_is_alive(xpath_sub->cid)) {
                continue;
            }

            if ((err_info = sr_lyd_new_list(sr_xpath_sub, "xpath-sub", NULL, &sr_sub))) {
                goto operget_ext_sub_unlock;
            }

            /* cid */
            sprintf(buf, "%" PRIu32, xpath_sub->cid);
            if ((err_info = sr_lyd_new_term(sr_sub, NULL, "cid", buf))) {
                goto operget_ext_sub_unlock;
            }

            /* suspended */
            sprintf(buf, "%s", ATOMIC_LOAD_RELAXED(xpath_sub->suspended) ? "true" : "false");
            if ((err_info = sr_lyd_new_term(sr_sub, NULL, "suspended", buf))) {
                goto operget_ext_sub_unlock;
            }
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
        if ((err_info = sr_lyd_new_list(sr_subs, "operational-poll-sub",
                conn->ext_shm.addr + oper_poll_subs[i].xpath, &sr_sub))) {
            goto operpoll_ext_sub_unlock;
        }

        /* cid */
        sprintf(buf, "%" PRIu32, oper_poll_subs[i].cid);
        if ((err_info = sr_lyd_new_term(sr_sub, NULL, "cid", buf))) {
            goto operpoll_ext_sub_unlock;
        }

        /* suspended */
        sprintf(buf, "%s", ATOMIC_LOAD_RELAXED(oper_poll_subs[i].suspended) ? "true" : "false");
        if ((err_info = sr_lyd_new_term(sr_sub, NULL, "suspended", buf))) {
            goto operpoll_ext_sub_unlock;
        }
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
        if ((err_info = sr_lyd_new_list(sr_subs, "notification-sub", NULL, &sr_sub))) {
            goto notif_ext_sub_unlock;
        }

        /* cid */
        sprintf(buf, "%" PRIu32, notif_subs[i].cid);
        if ((err_info = sr_lyd_new_term(sr_sub, NULL, "cid", buf))) {
            goto notif_ext_sub_unlock;
        }

        /* suspended */
        sprintf(buf, "%s", ATOMIC_LOAD_RELAXED(notif_subs[i].suspended) ? "true" : "false");
        if ((err_info = sr_lyd_new_term(sr_sub, NULL, "suspended", buf))) {
            goto notif_ext_sub_unlock;
        }
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

    /* module with name */
    if ((err_info = sr_lyd_new_list(sr_state, "module", sr_yang_ctx.mod_shm.addr + shm_mod->name, &sr_mod))) {
        return err_info;
    }

    /* last-modified */
    for (ds = 0; ds < SR_DS_COUNT; ++ds) {
        if ((ds == SR_DS_RUNNING) && !shm_mod->plugins[ds]) {
            /* runnig disabled */
            continue;
        }

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
            if ((err_info = sr_lyd_new_list(sr_mod, "ds-lock", sr_ds2ident(ds), &sr_ds_lock))) {
                goto ds_unlock;
            }

            /* sid */
            sprintf(buf, "%" PRIu32, shm_lock->ds_lock_sid);
            if ((err_info = sr_lyd_new_term(sr_ds_lock, NULL, "sid", buf))) {
                goto ds_unlock;
            }

            /* timestamp */
            if (ly_time_ts2str(&shm_lock->ds_lock_ts, &str)) {
                SR_ERRINFO_MEM(&err_info);
                goto ds_unlock;
            }
            if ((err_info = sr_lyd_new_term(sr_ds_lock, NULL, "timestamp", str))) {
                goto ds_unlock;
            }
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

    /* rpc with path */
    if ((err_info = sr_lyd_new_list(sr_state, "rpc", sr_yang_ctx.mod_shm.addr + shm_rpc->path, &sr_rpc))) {
        return err_info;
    }

    /* sub-lock */
    if ((err_info = sr_modinfo_module_srmon_locks(&shm_rpc->lock, "sub-lock", sr_rpc))) {
        return err_info;
    }

    /* RPC SUB READ LOCK */
    if ((err_info = sr_rwlock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid,
            __func__, NULL, NULL))) {
        return err_info;
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        goto rpc_sub_unlock;
    }

    rpc_sub = (sr_mod_rpc_sub_t *)(conn->ext_shm.addr + shm_rpc->subs);
    for (i = 0; i < shm_rpc->sub_count; ++i) {
        /* ignore dead subscriptions */
        if (rpc_sub[i].cid && !sr_conn_is_alive(rpc_sub[i].cid)) {
            continue;
        }

        /* rpc-sub */
        if ((err_info = sr_lyd_new_list(sr_rpc, "rpc-sub", NULL, &sr_sub))) {
            goto ext_sub_unlock;
        }

        /* xpath */
        if ((err_info = sr_lyd_new_term(sr_sub, NULL, "xpath", conn->ext_shm.addr + rpc_sub[i].xpath))) {
            goto ext_sub_unlock;
        }

        /* priority */
        sprintf(buf, "%" PRIu32, rpc_sub[i].priority);
        if ((err_info = sr_lyd_new_term(sr_sub, NULL, "priority", buf))) {
            goto ext_sub_unlock;
        }

        /* cid */
        sprintf(buf, "%" PRIu32, rpc_sub[i].cid);
        if ((err_info = sr_lyd_new_term(sr_sub, NULL, "cid", buf))) {
            goto ext_sub_unlock;
        }

        /* suspended */
        sprintf(buf, "%s", ATOMIC_LOAD_RELAXED(rpc_sub[i].suspended) ? "true" : "false");
        if ((err_info = sr_lyd_new_term(sr_sub, NULL, "suspended", buf))) {
            goto ext_sub_unlock;
        }
    }

    if (!lyd_child(sr_rpc)->next) {
        /* there are no locks or subscriptions for the RPC, redundant */
        lyd_free_tree(sr_rpc);
    }

ext_sub_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

rpc_sub_unlock:
    /* RPC SUB READ UNLOCK */
    sr_rwunlock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

    return err_info;
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
    sr_cid_t *cids = NULL;
    pid_t *pids = NULL;
    uint32_t conn_count, i;

    /* get basic information about connections */
    if ((err_info = sr_conn_info(&cids, &pids, &conn_count, NULL, NULL))) {
        return err_info;
    }

    for (i = 0; i < conn_count; ++i) {
        /* connection with cid */
        sprintf(buf, "%" PRIu32, cids[i]);
        if ((err_info = sr_lyd_new_list(sr_state, "connection", buf, &sr_conn))) {
            goto cleanup;
        }

        /* pid */
        sprintf(buf, "%d", (int)pids[i]);
        if ((err_info = sr_lyd_new_term(sr_conn, NULL, "pid", buf))) {
            goto cleanup;
        }
    }

cleanup:
    free(cids);
    free(pids);
    return err_info;
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
        if ((err_info = sr_xpath_oper_data_required(mod->xpaths[i].xpath, xpath, mod->xpaths[i].parent_only, &req))) {
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

    mod_shm = SR_CTX_MOD_SHM(sr_yang_ctx);
    ly_mod = ly_ctx_get_module_implemented(sr_yang_ctx.ly_ctx, "sysrepo-monitoring");
    assert(ly_mod);

    /* main container */
    if ((err_info = sr_lyd_new_inner(NULL, ly_mod, "sysrepo-state", &mod_data))) {
        goto cleanup;
    }

    /* modules */
    if ((err_info = sr_modinfo_module_data_oper_required(mod, &req, "/sysrepo-monitoring:sysrepo-state/module"))) {
        goto cleanup;
    }
    if (req) {
        for (i = 0; i < mod_shm->mod_count; ++i) {
            shm_mod = SR_SHM_MOD_IDX(mod_shm, i);
            if ((err_info = sr_modinfo_module_data_oper_required(mod, &req,
                    "/sysrepo-monitoring:sysrepo-state/module[name='%s']", sr_yang_ctx.mod_shm.addr + shm_mod->name))) {
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
            shm_rpc = (sr_rpc_t *)(sr_yang_ctx.mod_shm.addr + shm_mod->rpcs);
            for (j = 0; j < shm_mod->rpc_count; ++j) {
                if ((err_info = sr_modinfo_module_data_oper_required(mod, &req,
                        "/sysrepo-monitoring:sysrepo-state/rpc[path='%s']", sr_yang_ctx.mod_shm.addr + shm_rpc[j].path))) {
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
    if ((err_info = sr_lyd_merge(&mod_info->data, mod_data, 1, LYD_MERGE_DESTRUCT))) {
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
 * @param[in] sess Session ot use and read orig info from.
 * @param[in] timeout_ms Operational callback timeout in milliseconds.
 * @param[in] get_oper_opts Get oper data options.
 * @param[in] run_cached_data_cur Whether any cached running data in @p conn are usable and current.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_module_data_load(struct sr_mod_info_s *mod_info, struct sr_mod_info_mod_s *mod, sr_session_ctx_t *sess,
        uint32_t timeout_ms, sr_get_oper_flag_t get_oper_opts, int run_cached_data_cur)
{
    sr_error_info_t *err_info = NULL;
    sr_conn_ctx_t *conn = mod_info->conn;
    struct lyd_node *mod_data = NULL;
    struct sr_mod_info_xpath_s *xpaths;
    uint32_t xpath_count;
    int modified, has_data;
    char *orig_name = NULL;
    void *orig_data = NULL;

    assert(!mod_info->data_cached);

    /* retrieving only stored operational data of a session */
    if ((mod_info->ds == SR_DS_OPERATIONAL) && (mod_info->ds2 == SR_DS_OPERATIONAL)) {
        assert(sess);

        /* check if we have any push data (and duplicate it if it's already in the cache) */
        if ((err_info = sr_modinfo_module_data_cache_get(sess, mod->ly_mod->name, 1, &has_data, &mod_data))) {
            return err_info;
        }

        if (has_data) {
            if (mod_data) {
                err_info = sr_lyd_insert_sibling(mod_info->data, mod_data, &mod_info->data);
            } else {
                /* load module data from the ds plugin because cache is empty */
                err_info = sr_module_file_data_append(mod->ly_mod, mod->ds_handle, mod_info->ds2,
                        conn->cid, sess->sid, mod->xpaths, mod->xpath_count, &mod_info->data);
            }
        }
        return err_info;
    }

    /* get session info */
    if (sess) {
        orig_name = sess->orig_name;
        orig_data = sess->orig_data;
    }

    if (run_cached_data_cur) {
        /* CACHE READ LOCK */
        if ((err_info = sr_rwlock(&sr_run_cache.lock, SR_RUN_CACHE_LOCK_TIMEOUT, SR_LOCK_READ,
                conn->cid, __func__, NULL, NULL))) {
            return err_info;
        }

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
            err_info = sr_lyd_get_module_data(&sr_run_cache.data, mod->ly_mod, 0, 1, &mod_data);
            break;
        case SR_DS_OPERATIONAL:
            /* copy only enabled module data */
            err_info = sr_module_oper_data_get_enabled(conn, &sr_run_cache.data, mod, get_oper_opts,
                    1, &mod_data);
            break;
        }

        /* CACHE READ UNLOCK */
        sr_rwunlock(&sr_run_cache.lock, SR_RUN_CACHE_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

        if (err_info) {
            return err_info;
        }

        if (mod_data) {
            lyd_insert_sibling(mod_info->data, mod_data, &mod_info->data);
        }
    }
    if (!run_cached_data_cur) {
        /* no cached data or unusable */

        if ((mod_info->ds == SR_DS_OPERATIONAL) && (mod_info->ds2 == SR_DS_RUNNING)) {
            /* we need the whole running DS to avoid not getting parents of oper pull subscriptions and so considering
             * them incorrectly as non-existent */
            xpaths = NULL;
            xpath_count = 0;
        } else {
            xpaths = mod->xpaths;
            xpath_count = mod->xpath_count;
        }

        /* get current DS data */
        assert(mod_info->ds2 != SR_DS_OPERATIONAL);
        if ((err_info = sr_module_file_data_append(mod->ly_mod, mod->ds_handle, mod_info->ds2, 0, 0, xpaths,
                xpath_count, &mod_info->data))) {
            return err_info;
        }

        if (mod_info->ds == SR_DS_OPERATIONAL) {
            /* keep only enabled module data */
            if ((err_info = sr_module_oper_data_get_enabled(conn, &mod_info->data, mod, get_oper_opts, 0, &mod_data))) {
                return err_info;
            }
            lyd_free_siblings(sr_module_data_unlink(&mod_info->data, mod->ly_mod, 0));
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
        if ((err_info = sr_module_oper_data_update(mod, orig_name, orig_data, mod_info->operation_id, conn, timeout_ms,
                get_oper_opts, &mod_info->data))) {
            return err_info;
        }
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
    sr_datastore_t ds;
    struct sr_mod_info_mod_s *mod = NULL;
    uint32_t i;

    assert((mod_type == MOD_INFO_REQ) || (mod_type == MOD_INFO_DEP) || (mod_type == MOD_INFO_INV_DEP));

    /* check that it is not already added */
    for (i = 0; i < mod_info->mod_count; ++i) {
        if (mod_info->mods[i].ly_mod == ly_mod) {
            /* already there, update module type if needed */
            mod = &mod_info->mods[i];
            mod->state |= mod_type;

            if (mod->state & MOD_INFO_NEW) {
                /* new module, needs its members filled */
                mod->state &= ~MOD_INFO_NEW;
                break;
            }
            return NULL;
        }
    }

    /* find module in SHM */
    shm_mod = sr_shmmod_find_module(SR_CTX_MOD_SHM(sr_yang_ctx), ly_mod->name);
    SR_CHECK_INT_RET(!shm_mod, err_info);

    /* find main DS handle */
    if ((mod_info->ds == SR_DS_RUNNING) && !shm_mod->plugins[mod_info->ds]) {
        /* 'running' is disabled, we will be using the 'startup' plugin */
        ds = SR_DS_STARTUP;
    } else {
        ds = mod_info->ds;
    }
    if ((err_info = sr_ds_handle_find(sr_yang_ctx.mod_shm.addr + shm_mod->plugins[ds], mod_info->conn, &ds_handle[ds]))) {
        return err_info;
    }

    switch (mod_info->ds) {
    case SR_DS_STARTUP:
    case SR_DS_FACTORY_DEFAULT:
        /* plugin for this datastore is enough */
        break;
    case SR_DS_RUNNING:
        /* get candidate as well if we need to reset it */
        if ((err_info = sr_ds_handle_find(sr_yang_ctx.mod_shm.addr + shm_mod->plugins[SR_DS_CANDIDATE],
                mod_info->conn, &ds_handle[SR_DS_CANDIDATE]))) {
            return err_info;
        }
        break;
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        /* get running plugin as well (if not disabled) */
        if (!shm_mod->plugins[SR_DS_RUNNING]) {
            ds = SR_DS_STARTUP;
        } else {
            ds = SR_DS_RUNNING;
        }
        if ((err_info = sr_ds_handle_find(sr_yang_ctx.mod_shm.addr + shm_mod->plugins[ds], mod_info->conn,
                &ds_handle[ds]))) {
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
    shm_inv_deps = (off_t *)(sr_yang_ctx.mod_shm.addr + shm_mod->inv_deps);
    for (i = 0; i < shm_mod->inv_dep_count; ++i) {
        /* find ly module */
        ly_mod = ly_ctx_get_module_implemented(sr_yang_ctx.ly_ctx, sr_yang_ctx.mod_shm.addr + shm_inv_deps[i]);
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
 * @param[in] read_only Whether we will be only reading the data or modifying it as well, affects cache.
 * @param[in] sess Session to use and read orig info from.
 * @param[in] timeout_ms Operational callback timeout in milliseconds.
 * @param[in] get_oper_opts Get oper data options, ignored if getting only ::SR_DS_OPERATIONAL data (edit).
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_data_load(struct sr_mod_info_s *mod_info, int read_only, sr_session_ctx_t *sess, uint32_t timeout_ms,
        sr_get_oper_flag_t get_oper_opts)
{
    sr_error_info_t *err_info = NULL;
    sr_conn_ctx_t *conn;
    sr_lock_mode_t cache_lock_mode = SR_LOCK_NONE;
    struct sr_mod_info_mod_s *mod;
    uint32_t i;
    int run_data_cache_cur = 0;

    conn = mod_info->conn;

    /* cache may be useful only for some datastores */
    if (!mod_info->data_cached && mod_info->mod_count && (conn->opts & SR_CONN_CACHE_RUNNING) &&
            !(get_oper_opts & SR_OPER_NO_RUN_CACHED) &&
            ((mod_info->ds == SR_DS_RUNNING) || (mod_info->ds == SR_DS_CANDIDATE) || (mod_info->ds2 == SR_DS_RUNNING))) {

        /* CACHE READ LOCK */
        if ((err_info = sr_rwlock(&sr_run_cache.lock, SR_RUN_CACHE_LOCK_TIMEOUT, SR_LOCK_READ,
                conn->cid, __func__, NULL, NULL))) {
            return err_info;
        }
        cache_lock_mode = SR_LOCK_READ;

        /* update the data in the cache */
        if ((err_info = sr_run_cache_update(conn, &sr_run_cache, mod_info, SR_LOCK_READ))) {
            goto cleanup;
        }
        run_data_cache_cur = 1;

        if (mod_info->ds == SR_DS_RUNNING) {
            if (read_only) {
                /* we can use the cache directly only if we are working with the running datastore (as the main datastore)
                 * and not modifying the data */
                mod_info->data_cached = 1;
                mod_info->data = sr_run_cache.data;

                for (i = 0; i < mod_info->mod_count; ++i) {
                    mod = &mod_info->mods[i];
                    assert(!(mod->state & MOD_INFO_CHANGED));
                    mod->state |= MOD_INFO_DATA;
                }
            } else {
                /* duplicate data of all the modules, they will be modified */
                for (i = 0; i < mod_info->mod_count; ++i) {
                    mod = &mod_info->mods[i];
                    if (mod->state & MOD_INFO_DATA) {
                        continue;
                    }

                    if ((err_info = sr_lyd_get_module_data(&sr_run_cache.data, mod->ly_mod, 0, 1, &mod_info->data))) {
                        goto cleanup;
                    }

                    mod->state |= MOD_INFO_DATA;
                }
            }
            goto cleanup;
        }

        /* CACHE READ UNLOCK */
        sr_rwunlock(&sr_run_cache.lock, SR_RUN_CACHE_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);
        cache_lock_mode = SR_LOCK_NONE;
    }

    /* load data for each module */
    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & MOD_INFO_DATA) {
            /* module data were already loaded */
            continue;
        }

        /* load module data */
        if ((err_info = sr_modinfo_module_data_load(mod_info, mod, sess, timeout_ms, get_oper_opts, run_data_cache_cur))) {
            goto cleanup;
        }
        if (!mod->xpath_count) {
            /* remember only if we request all the data */
            mod->state |= MOD_INFO_DATA;
        }
    }

cleanup:
    if ((cache_lock_mode != SR_LOCK_NONE) && !mod_info->data_cached) {
        /* CACHE READ UNLOCK */
        sr_rwunlock(&sr_run_cache.lock, SR_RUN_CACHE_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);
    } /* else the flag marks held READ lock */

    return err_info;
}

sr_error_info_t *
sr_modinfo_consolidate(struct sr_mod_info_s *mod_info, sr_lock_mode_t mod_lock, int mi_opts, sr_session_ctx_t *sess,
        uint32_t timeout_ms, uint32_t ds_lock_timeout_ms, sr_get_oper_flag_t get_oper_opts)
{
    sr_error_info_t *err_info = NULL;
    int mod_type, new = 0;
    uint32_t i, sid;

    assert(mi_opts & (SR_MI_PERM_NO | SR_MI_PERM_READ | SR_MI_PERM_WRITE));

    if (!mod_info->mod_count) {
        goto cleanup;
    }

    if ((get_oper_opts & SR_OPER_NO_PUSH_NP_CONT) && !(get_oper_opts & SR_OPER_NO_SUBS)) {
        /* NP containers are required as existing parents of oper get subscriptions, ignore the flag */
        get_oper_opts &= ~SR_OPER_NO_PUSH_NP_CONT;
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
        sid = sess ? sess->sid : 0;
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
        if ((err_info = sr_modinfo_data_load(mod_info, mi_opts & SR_MI_DATA_RO, sess, timeout_ms, get_oper_opts))) {
            goto cleanup;
        }
    }

cleanup:
    return err_info;
}

sr_error_info_t *
sr_modinfo_validate(struct sr_mod_info_s *mod_info, uint32_t mod_state, int finish_diff, sr_error_info_t **val_err_info)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    struct sr_mod_info_mod_s *mod;
    struct lyd_node *diff = NULL, *iter;
    uint32_t i;
    int val_opts;

    assert(!mod_info->data_cached);
    assert(SR_IS_CONVENTIONAL_DS(mod_info->ds) || !finish_diff);

    /* validate all the modules individually */
    if (SR_IS_CONVENTIONAL_DS(mod_info->ds)) {
        val_opts = LYD_VALIDATE_NO_STATE | LYD_VALIDATE_MULTI_ERROR;
    } else {
        val_opts = LYD_VALIDATE_OPERATIONAL | LYD_VALIDATE_NO_DEFAULTS | LYD_VALIDATE_MULTI_ERROR;
    }
    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & mod_state) {
            /* validate this module */
            if ((tmp_err = sr_lyd_validate_module(&mod_info->data, mod->ly_mod, val_opts | LYD_VALIDATE_NOT_FINAL,
                    finish_diff ? &diff : NULL))) {
                sr_errinfo_merge(val_err_info, tmp_err);
            }

            if (diff) {
                /* it may not have been modified before */
                mod->state |= MOD_INFO_CHANGED;

                /* merge the changes made by the validation into our diff */
                if ((err_info = sr_lyd_diff_merge_all(&mod_info->notify_diff, diff))) {
                    goto cleanup;
                }
                mod_info->ds_diff = mod_info->notify_diff;

                lyd_free_all(diff);
                diff = NULL;

                LY_LIST_FOR(mod_info->notify_diff, iter) {
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
            if ((tmp_err = sr_lyd_validate_module_final(mod_info->data, mod->ly_mod, val_opts))) {
                sr_errinfo_merge(val_err_info, tmp_err);
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

        if (mod->state & MOD_INFO_REQ) {
            /* add default values for this module */
            if ((err_info = sr_lyd_new_implicit_module(&mod_info->data, mod->ly_mod, LYD_IMPLICIT_NO_STATE,
                    finish_diff ? &diff : NULL))) {
                goto cleanup;
            }
            mod_info->data = lyd_first_sibling(mod_info->data);

            if (diff) {
                /* it may not have been modified before */
                mod->state |= MOD_INFO_CHANGED;

                /* merge the changes made by the validation into our diff */
                if ((err_info = sr_lyd_diff_merge_all(&mod_info->notify_diff, diff))) {
                    goto cleanup;
                }

                lyd_free_all(diff);
                diff = NULL;

                LY_LIST_FOR(mod_info->notify_diff, iter) {
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

cleanup:
    lyd_free_all(diff);
    return err_info;
}

sr_error_info_t *
sr_modinfo_check_state_data(struct sr_mod_info_s *mod_info, sr_error_info_t **val_err_info)
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
                    sr_errinfo_new(val_err_info, SR_ERR_VALIDATION_FAILED, "Unexpected data state node \"%s\" found.",
                            LYD_NAME(node));
                }
                LYD_TREE_DFS_END(root, node);
            }
        }
    }

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

        if (mod->state & MOD_INFO_REQ) {
            /* this is the module of the nested operation and we need to check that operation's parent data node exists */
            assert((mod->ly_mod == lyd_owner_module(top_op)) && op->parent);
            free(parent_xpath);
            parent_xpath = lyd_path(lyd_parent(op), LYD_PATH_STD, NULL, 0);
            SR_CHECK_MEM_GOTO(!parent_xpath, err_info, cleanup);

            if (mod_info->data) {
                if ((err_info = sr_lyd_find_xpath(mod_info->data, parent_xpath, &set))) {
                    goto cleanup;
                }
            } else {
                if ((err_info = sr_ly_set_new(&set))) {
                    goto cleanup;
                }
            }
            SR_CHECK_INT_GOTO(set->count > 1, err_info, cleanup);

            if (!set->count) {
                sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED,
                        "Nested operation \"%s\" data parent does not exist in the operational datastore.", op->schema->name);
                goto cleanup;
            }
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
        if ((err_info = sr_lyd_find_xpath(data_ext_parent, "*", &set))) {
            goto cleanup;
        }

        /* reconnect them into the dependency tree used for validation */
        for (i = 0; i < set->count; ++i) {
            node = set->dnodes[i];
            lyd_unlink_tree(node);
            if ((err_info = sr_lyd_insert_sibling(mod_info->data, node, &mod_info->data))) {
                goto cleanup;
            }
        }
    }

    /* validate */
    op_type = ((op->schema->nodetype & (LYS_RPC | LYS_ACTION)) ?
            (output ? LYD_TYPE_REPLY_YANG : LYD_TYPE_RPC_YANG) : LYD_TYPE_NOTIF_YANG);
    if ((err_info = sr_lyd_validate_op(top_op, mod_info->data, op_type))) {
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
            lyplg_ext_insert(data_ext_parent, node);
        }
    }

    free(parent_xpath);
    free(ext_parent_path);
    ly_set_free(set, NULL);
    return err_info;
}

sr_error_info_t *
sr_modinfo_get_filter(struct sr_mod_info_s *mod_info, const char *xpath, sr_session_ctx_t *session,
        int ignore_new_changes, struct ly_set **result)
{
    sr_error_info_t *err_info = NULL, *val_err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    struct lyd_node *edit = NULL, *diff = NULL;
    uint32_t i;
    int is_oper_ds = (session->ds == SR_DS_OPERATIONAL) ? 1 : 0;

    if (!ignore_new_changes && (session->ds < SR_DS_COUNT)) {
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
            sr_rwunlock(&sr_run_cache.lock,  SR_RUN_CACHE_LOCK_TIMEOUT, SR_LOCK_READ, mod_info->conn->cid, __func__);
        }

        for (i = 0; (i < mod_info->mod_count) && (session->ds < SR_DS_COUNT); ++i) {
            mod = &mod_info->mods[i];
            if (mod->state & MOD_INFO_REQ) {
                /* apply any currently handled changes (diff) or additional performed ones (edit) to get
                 * the session-specific data tree */
                if ((err_info = sr_lyd_diff_apply_module(&mod_info->data, diff, mod->ly_mod,
                        is_oper_ds ? sr_lyd_diff_apply_cb : NULL))) {
                    goto cleanup;
                }
                if ((err_info = sr_edit_mod_apply(edit, mod->ly_mod, &mod_info->data, NULL, NULL, &val_err_info))) {
                    goto cleanup;
                } else if (val_err_info) {
                    sr_errinfo_merge(&err_info, val_err_info);
                    goto cleanup;
                }
            }
        }
    }

    if (mod_info->data) {
        /* filter return data using the xpath */
        if ((err_info = sr_lyd_find_xpath(mod_info->data, xpath, result))) {
            goto cleanup;
        }
    } else {
        /* empty set */
        if ((err_info = sr_ly_set_new(result))) {
            goto cleanup;
        }
    }

cleanup:
    return err_info;
}

/**
 * @brief Check whether an updated edit includes data from modules not in mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] update_edit Updated edit to check.
 * @return 0 if there are no foreign module data.
 * @return non-zero if there are foreign module data.
 */
static int
sr_modinfo_update_is_foreign(const struct sr_mod_info_s *mod_info, const struct lyd_node *update_edit)
{
    struct sr_mod_info_mod_s *mod;
    const struct lyd_node *iter;
    const struct lys_module *ly_mod = NULL;
    uint32_t i;

    LY_LIST_FOR(update_edit, iter) {
        if (lyd_owner_module(iter) == ly_mod) {
            /* still the same module */
            continue;
        }
        ly_mod = lyd_owner_module(iter);

        /* check this node */
        for (i = 0; i < mod_info->mod_count; ++i) {
            mod = &mod_info->mods[i];
            if (!(mod->state & MOD_INFO_REQ)) {
                /* skip dependency modules */
                continue;
            }

            if (mod->ly_mod == ly_mod) {
                break;
            }
        }

        if (i == mod_info->mod_count) {
            /* foreign module data */
            return 1;
        }
    }

    return 0;
}

sr_error_info_t *
sr_modinfo_change_notify_update(struct sr_mod_info_s *mod_info, sr_session_ctx_t *session, uint32_t timeout_ms,
        sr_lock_mode_t *change_sub_lock, sr_error_info_t **err_info2)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *update_edit = NULL, *old_diff = NULL, *new_diff = NULL;
    char *orig_name = NULL;
    void *orig_data = NULL;
    uint32_t mi_opts, err_count;

    assert(mod_info->notify_diff);
    assert(*change_sub_lock == SR_LOCK_READ);

    /* get session info */
    if (session) {
        orig_name = session->orig_name;
        orig_data = session->orig_data;
    }

    /* publish current diff in an "update" event for the subscribers to update it */
    err_count = *err_info2 ? (*err_info2)->err_count : 0;
    if ((err_info = sr_shmsub_change_notify_update(mod_info, orig_name, orig_data, timeout_ms, &update_edit, err_info2))) {
        goto cleanup;
    }
    if (*err_info2 && ((*err_info2)->err_count > err_count)) {
        /* "update" event failed, just clear the sub SHM and finish */
        err_info = sr_shmsub_change_notify_clear(mod_info);
        goto cleanup;
    }

    /* create new diff if we have an update edit */
    if (update_edit) {
        /* unsupported */
        SR_CHECK_INT_GOTO(mod_info->ds == SR_DS_OPERATIONAL, err_info, cleanup);

        /* unlock so that we can lock after additonal modules were marked as changed */

        /* CHANGE SUB READ UNLOCK */
        sr_modinfo_changesub_rdunlock(mod_info);
        *change_sub_lock = SR_LOCK_NONE;

        if (sr_modinfo_update_is_foreign(mod_info, update_edit)) {
            /* data of a foreign module, update mod info */
            if ((err_info = sr_modinfo_collect_edit(update_edit, mod_info))) {
                goto cleanup;
            }

            mi_opts = SR_MI_LOCK_UPGRADEABLE | SR_MI_PERM_NO;
            if ((mod_info->ds != SR_DS_OPERATIONAL) && (mod_info->ds != SR_DS_CANDIDATE)) {
                mi_opts |= SR_MI_INV_DEPS;
            } /* else stored oper edit or candidate data are not validated so we do not need data from other modules */

            /* add modules into mod_info with deps, locking, and their data */
            if ((err_info = sr_modinfo_consolidate(mod_info, SR_LOCK_READ, mi_opts, session, 0, 0, 0))) {
                goto cleanup;
            }
        }

        /* backup the old diff */
        old_diff = mod_info->notify_diff;
        mod_info->notify_diff = NULL;
        mod_info->ds_diff = NULL;

        /* get new diff using the updated edit */
        if ((err_info = sr_modinfo_edit_apply(mod_info, update_edit, 1, err_info2))) {
            goto cleanup;
        }

        /* validate updated data trees and finish new diff */
        switch (mod_info->ds) {
        case SR_DS_STARTUP:
        case SR_DS_RUNNING:
            /* update the modules */
            if ((err_info = sr_modinfo_collect_deps(mod_info))) {
                goto cleanup;
            }
            if ((err_info = sr_modinfo_consolidate(mod_info, SR_LOCK_READ, SR_MI_NEW_DEPS | SR_MI_PERM_NO, session,
                    0, 0, 0))) {
                goto cleanup;
            }

            /* validate */
            if ((err_info = sr_modinfo_validate(mod_info, MOD_INFO_CHANGED | MOD_INFO_INV_DEP, 1, err_info2))) {
                goto cleanup;
            }
            break;
        case SR_DS_CANDIDATE:
            if ((err_info = sr_modinfo_add_defaults(mod_info, 1))) {
                goto cleanup;
            }
            if ((err_info = sr_modinfo_check_state_data(mod_info, err_info2))) {
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
        new_diff = mod_info->notify_diff;
        mod_info->notify_diff = old_diff;
        old_diff = NULL;

        /* merge diffs into one */
        if ((err_info = sr_modinfo_diff_merge(mod_info, new_diff))) {
            goto cleanup;
        }
        mod_info->ds_diff = mod_info->notify_diff;
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
    char *xpath, nc_sid_str[22];
    const char *op_enum, *nc_user;
    sr_change_oper_t op;
    enum edit_op edit_op;
    int changes;
    LY_ERR lyrc;

    /* make sure there are some actual node changes */
    changes = 0;
    LY_LIST_FOR(mod_info->notify_diff, root) {
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
    shm_mod = sr_shmmod_find_module(SR_CTX_MOD_SHM(sr_yang_ctx), "ietf-netconf-notifications");
    SR_CHECK_INT_RET(!shm_mod, err_info);
    if (!shm_mod->replay_supp && !notif_sub_count) {
        /* nothing to do */
        return NULL;
    }

    lyrc = ly_set_new(&set);
    SR_CHECK_MEM_GOTO(lyrc, err_info, cleanup);

    /* just put all the nodes into a set */
    LY_LIST_FOR(mod_info->notify_diff, root) {
        LYD_TREE_DFS_BEGIN(root, elem) {
            if (ly_set_add(set, elem, 1, NULL)) {
                SR_ERRINFO_INT(&err_info);
                goto cleanup;
            }

            LYD_TREE_DFS_END(root, elem);
        }
    }

    /* generate notifcation with all the changes */
    if ((err_info = sr_lyd_new_path(NULL, sr_yang_ctx.ly_ctx, "/ietf-netconf-notifications:netconf-config-change",
            NULL, 0, NULL, &notif))) {
        goto cleanup;
    }

    /* changed-by (everything was caused by user, we do not know what changes are implicit) */
    if ((err_info = sr_lyd_new_inner(notif, NULL, "changed-by", &root))) {
        goto cleanup;
    }

    /* changed-by username */
    if (session->orig_name && !strcmp(session->orig_name, "netopeer2")) {
        /* 2 data chunks, NCID and user name */
        assert(((uint32_t *)session->orig_data)[0] == 2);

        /* number of chunks (uint32_t); length of chunk #1 (uint32_t), chunk #1 NCID (uint32_t),
         * length of chunk #2 (uint32_t), chunk #2 NC user terminated by 0 (char *) */
        nc_user = ((char *)session->orig_data) + 16;
    } else {
        /* use SR user */
        nc_user = session->user;
    }
    if ((err_info = sr_lyd_new_term(root, NULL, "username", nc_user))) {
        goto cleanup;
    }

    /* changed-by NETCONF session-id */
    if (session->orig_name && !strcmp(session->orig_name, "netopeer2")) {
        sprintf(nc_sid_str, "%" PRIu32, ((uint32_t *)session->orig_data)[2]);
    } else {
        /* unknown */
        strcpy(nc_sid_str, "0");
    }
    if ((err_info = sr_lyd_new_term(root, NULL, "session-id", nc_sid_str))) {
        goto cleanup;
    }

    /* datastore */
    if ((err_info = sr_lyd_new_term(notif, NULL, "datastore", sr_ds2str(mod_info->ds)))) {
        goto cleanup;
    }

    while (!(err_info = sr_diff_set_getnext(set, &idx, &elem, &op)) && elem) {
        /* edit (list instance) */
        if ((err_info = sr_lyd_new_list(notif, "edit", NULL, &root))) {
            goto cleanup;
        }

        /* edit target */
        if (!(xpath = lyd_path(elem, LYD_PATH_STD, NULL, 0))) {
            LOGMEM(&err_info);
            goto cleanup;
        }
        err_info = sr_lyd_new_term(root, NULL, "target", xpath);
        free(xpath);
        if (err_info) {
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
        if ((err_info = sr_lyd_new_term(root, NULL, "operation", op_enum))) {
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
            session->orig_data, mod_info->operation_id, 0, 0);

    /* NOTIF SUB READ UNLOCK */
    sr_rwunlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, mod_info->conn->cid, __func__);

    if (err_info) {
        goto cleanup;
    }

    /* store the notification for a replay */
    if ((err_info = sr_replay_store(mod_info->conn, session, notif, notif_ts_real))) {
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

/**
 * @brief Learn if a new oper push entry must be created for this session and module in Ext SHM.
 *        If entry already exists, learn if has_data flag needs to be changed.
 *
 * @param[in] sess Session to use.
 * @param[in] mod_name Module name for which operational data is being pushed.
 * @param[in] has_data Whether this session has data for this module.
 * @param[out] create Learn whether oper push data for module must be created in Ext SHM.
 * @param[out] change_has_data Learn whether has_data for module changed from the previous value.
 */
static void
sr_modinfo_push_oper_mod_learn_changes(sr_session_ctx_t *sess, const char *mod_name, int has_data, int *create, int *change_has_data)
{
    uint32_t i;

    for (i = 0; i < sess->oper_push_mod_count; ++i) {
        if (!strcmp(sess->oper_push_mods[i].name, mod_name)) {
            /* don't need to create in Ext SHM */
            *create = 0;
            /* learn whether has_data flag is being changed */
            *change_has_data = (sess->oper_push_mods[i].has_data != has_data);
            return;
        }
    }

    /* create in Ext SHM */
    *create = 1;
    /* not a change */
    *change_has_data = 0;
}

/**
 * @brief Update push oper mod data cache in the session, add new module if not yet present.
 *
 * @param[in] sess Session to update.
 * @param[in] mod_name Module name.
 * @param[in] data module data to store.
 * @return err_info, NULL on success, only fails if out of memory.
 */
static sr_error_info_t *
sr_modinfo_push_oper_mod_update_cache(sr_session_ctx_t *sess, const char *mod_name, struct lyd_node *data)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    void *mem;

    for (i = 0; i < sess->oper_push_mod_count; ++i) {
        if (!strcmp(sess->oper_push_mods[i].name, mod_name)) {
            /* cache must already be consumed by sr_modinfo_get_oper_data() */
            assert(!sess->oper_push_mods[i].cache);
            break;
        }
    }

    if (i == sess->oper_push_mod_count) {
        /* add new module */
        mem = realloc(sess->oper_push_mods, (i + 1) * sizeof *(sess->oper_push_mods));
        SR_CHECK_MEM_GOTO(!mem, err_info, cleanup);
        sess->oper_push_mods = mem;

        /* zero the memory to prevent any uninitialized access */
        memset(&sess->oper_push_mods[i], 0, sizeof *(sess->oper_push_mods));

        sess->oper_push_mods[i].name = strdup(mod_name);
        SR_CHECK_MEM_GOTO(!sess->oper_push_mods[i].name, err_info, cleanup);
        ++sess->oper_push_mod_count;
    }

    sess->oper_push_mods[i].has_data = !!data;
    sess->oper_push_mods[i].cache = data;

cleanup:
    return err_info;
}

sr_error_info_t *
sr_modinfo_data_store(struct sr_mod_info_s *mod_info, sr_session_ctx_t *session, int shmmod_session_del, int commit)
{
    sr_error_info_t *err_info = NULL;
    struct sr_mod_info_mod_s *mod;
    struct lyd_node *mod_diff, *mod_data;
    sr_datastore_t store_ds;
    uint32_t i, sid;
    int create, change;
    const char *mod_name = NULL;
    sr_mod_t *shm_mod;

    assert(!mod_info->data_cached);

    sid = session ? session->sid : 0;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (mod->state & MOD_INFO_CHANGED) {
            /* separate diff and data of this module */
            mod_diff = sr_module_data_unlink(&mod_info->ds_diff, mod->ly_mod, 1);
            mod_data = sr_module_data_unlink(&mod_info->data, mod->ly_mod, 1);

            if ((mod_info->ds == SR_DS_RUNNING) && !mod->ds_handle[mod_info->ds]) {
                /* 'running' disabled, use 'startup' */
                store_ds = SR_DS_STARTUP;
            } else {
                store_ds = mod_info->ds;
            }

            if (commit) {
                /* store the new data */
                err_info = mod->ds_handle[store_ds]->plugin->store_commit_cb(mod->ly_mod, store_ds, mod_info->conn->cid,
                        sid, mod_diff, mod_data, mod->ds_handle[store_ds]->plg_data);
            } else {
                /* prepare to store the new data */
                err_info = mod->ds_handle[store_ds]->plugin->store_prepare_cb(mod->ly_mod, store_ds, mod_info->conn->cid,
                        sid, mod_diff, mod_data, mod->ds_handle[store_ds]->plg_data);
            }
            if (err_info) {
                lyd_free_siblings(mod_diff);
                lyd_free_siblings(mod_data);
                goto cleanup;
            }

            if (commit && (mod_info->ds == SR_DS_RUNNING)) {
                /* update the cache ID because data were modified, ignored if data_version callback is used instead */
                mod->shm_mod->run_cache_id++;

                if (mod_info->conn->opts & SR_CONN_CACHE_RUNNING) {
                    /* store the changed data in the cache */
                    if ((err_info = sr_run_cache_update_mod(session->conn, &sr_run_cache, mod->ly_mod, mod->shm_mod->run_cache_id,
                            mod_data))) {
                        /* not a fatal error, cache can be updated in a future operation */
                        sr_errinfo_free(&err_info);
                        lyd_free_siblings(mod_data);
                    }

                    /* mod data spent */
                    mod_data = NULL;
                    mod->state &= ~MOD_INFO_DATA;
                }
            }

            if (commit && (mod_info->ds == SR_DS_OPERATIONAL) && (mod_info->ds2 == SR_DS_OPERATIONAL)) {
                assert(session);
                if (shmmod_session_del) {
                    /* no stored oper data and session stopped, remove info from mod/ext SHM */
                    assert(!mod_data);
                    if ((err_info = sr_shmext_oper_push_del(mod_info->conn, mod->shm_mod, mod->ly_mod->name,
                            sid, SR_LOCK_WRITE))) {
                        goto cleanup;
                    }
                } else {
                    /* stored oper data, determine if session Ext SHM data needs a `change` or `create` from the
                     * session's cached state */
                    sr_modinfo_push_oper_mod_learn_changes(session, mod->ly_mod->name, !!mod_data, &create, &change);

                    /* change info in mod/ext SHM or create only if necessary */
                    if (change && (err_info = sr_shmext_oper_push_change_has_data(mod_info->conn, mod->shm_mod, sid, !!mod_data))) {
                        goto cleanup;
                    } else if (create && (err_info = sr_shmext_oper_push_update(mod_info->conn, mod->shm_mod,
                            mod->ly_mod->name, sid, 0, !!mod_data, SR_LOCK_WRITE))) {
                        goto cleanup;
                    }

                    /* cache the mod_data info into session */
                    if ((err_info = sr_modinfo_push_oper_mod_update_cache(session, mod->ly_mod->name, mod_data))) {
                        goto cleanup;
                    }
                    mod_data = NULL;
                }
            }

            /* connect them back */
            if (mod_diff) {
                lyd_insert_sibling(mod_info->ds_diff, mod_diff, &mod_info->ds_diff);
            }
            if (mod_data) {
                lyd_insert_sibling(mod_info->data, mod_data, &mod_info->data);
            }
        }
    }

    if (commit && shmmod_session_del && !mod_info->mod_count && session->oper_push_mod_count) {
        /* we are stopping a session, we had pushed some data in the past, but no current data, so mod_info->count is zero */
        for (i = 0; i < session->oper_push_mod_count; ++i) {
            mod_name = session->oper_push_mods[i].name;
            shm_mod = sr_shmmod_find_module(SR_CTX_MOD_SHM(sr_yang_ctx), mod_name);
            if (!shm_mod) {
                /* module was removed, sr_remove_module should have removed Ext SHM data for it as well */
                continue;
            }
            if ((err_info = sr_shmext_oper_push_del(mod_info->conn, shm_mod, mod_name, sid, SR_LOCK_WRITE))) {
                goto cleanup;
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

    lyd_free_siblings(mod_info->notify_diff);
    if ((mod_info->ds == SR_DS_OPERATIONAL) && (mod_info->ds2 == SR_DS_OPERATIONAL)) {
        /* only for oper DS the 2 diffs can differ */
        lyd_free_siblings(mod_info->ds_diff);
    }

    if (mod_info->data_cached) {
        /* CACHE READ UNLOCK */
        sr_rwunlock(&sr_run_cache.lock, SR_RUN_CACHE_LOCK_TIMEOUT, SR_LOCK_READ, mod_info->conn->cid, __func__);
    } else {
        lyd_free_siblings(mod_info->data);
    }

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        assert(!(mod->state & (MOD_INFO_RLOCK | MOD_INFO_RLOCK_UPGR | MOD_INFO_WLOCK | MOD_INFO_RLOCK2)));

        for (j = 0; j < mod->xpath_count; ++j) {
            if (mod->xpaths[j].dyn) {
                free((char *)mod->xpaths[j].xpath);
            }
        }
        free(mod->xpaths);
    }

    /* free the schema mount reference of this mod_info */
    sr_modinfo_smdata_free();

    free(mod_info->mods);
}

/**
 * @brief Parse schema mount data from a file.
 *
 * The parsed data is reference-counted and its life cycle is tied to mod_info.
 * The data can be made available by multiple mod_info structures, but it is freed only by the last one.
 *
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_modinfo_smdata_parse(void)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *schema_mount_data = NULL;

    /* SM DATA LOCK */
    if ((err_info = sr_mlock(&sr_schema_mount_cache.lock, SR_SM_CTX_LOCK_TIMEOUT, __func__, NULL, NULL))) {
        return err_info;
    }

    if (sr_schema_mount_cache.refcount) {
        /* already parsed */
        sr_schema_mount_cache.refcount++;
        goto cleanup;
    }

    /* parse schema mount data from shm */
    if ((err_info = sr_schema_mount_data_file_parse(&schema_mount_data))) {
        goto cleanup;
    }

    if (!schema_mount_data) {
        /* no schema mount data */
        goto cleanup;
    }

    sr_schema_mount_cache.data = schema_mount_data;
    sr_schema_mount_cache.refcount = 1;

cleanup:
    /* SM DATA UNLOCK */
    sr_munlock(&sr_schema_mount_cache.lock);
    return err_info;
}

/**
 * @brief Free schema mount data.
 *
 * Called whenever mod_info is being destroyed.
 */
static void
sr_modinfo_smdata_free(void)
{
    sr_error_info_t *err_info = NULL;

    /* SM DATA LOCK */
    if ((err_info = sr_mlock(&sr_schema_mount_cache.lock, SR_SM_CTX_LOCK_TIMEOUT, __func__, NULL, NULL))) {
        /* continue on error */
        sr_errinfo_free(&err_info);
    }

    if (sr_schema_mount_cache.refcount > 1) {
        /* just decrease the reference count */
        sr_schema_mount_cache.refcount--;
    } else if (sr_schema_mount_cache.refcount == 1) {
        /* last reference, free the data */
        assert(sr_schema_mount_cache.data);
        lyd_free_siblings(sr_schema_mount_cache.data);
        sr_schema_mount_cache.data = NULL;
        sr_schema_mount_cache.refcount = 0;
    }

    /* SM DATA UNLOCK */
    sr_munlock(&sr_schema_mount_cache.lock);
}
