/**
 * @file lyd_mods.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Sysrepo module data routines
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
#include "lyd_mods.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libyang/plugins_types.h>

#include "common.h"
#include "common_json.h"
#include "common_types.h"
#include "config.h"
#include "context_change.h"
#include "log.h"
#include "ly_wrap.h"
#include "plugins_datastore.h"
#include "plugins_notification.h"
#include "replay.h"
#include "shm_mod.h"

#include "../modules/ietf_datastores_yang.h"
#include "../modules/ietf_factory_default_yang.h"
#include "../modules/ietf_netconf_acm_yang.h"
#include "../modules/sysrepo_factory_default_yang.h"
#include "../modules/sysrepo_yang.h"

#if SR_YANGLIB_REVISION == 2019 - 01 - 04
# include "../modules/ietf_yang_library@2019_01_04_yang.h"
#elif SR_YANGLIB_REVISION == 2016 - 06 - 21
# include "../modules/ietf_yang_library@2016_06_21_yang.h"
#else
# error "Unknown yang-library revision!"
#endif

#include "../modules/ietf_netconf_notifications_yang.h"
#include "../modules/ietf_netconf_with_defaults_yang.h"
#include "../modules/ietf_netconf_yang.h"
#include "../modules/ietf_origin_yang.h"
#include "../modules/sysrepo_monitoring_yang.h"
#include "../modules/sysrepo_notifications_yang.h"
#include "../modules/sysrepo_plugind_yang.h"

/**
 * @brief Add module into sysrepo module data.
 *
 * @param[in] sr_mods SR internal module data.
 * @param[in] ly_mod Module to add.
 * @param[in] module_ds Module datastore plugins.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_add_module(struct lyd_node *sr_mods, const struct lys_module *ly_mod, const sr_module_ds_t module_ds)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mod, *sr_plugin;
    struct lysp_feature *f = NULL;
    uint32_t i;

    if ((err_info = sr_lyd_new_list(sr_mods, "module", ly_mod->name, &sr_mod))) {
        goto cleanup;
    }
    if (ly_mod->revision && (err_info = sr_lyd_new_term(sr_mod, NULL, "revision", ly_mod->revision))) {
        goto cleanup;
    }

    /* enable all the features */
    i = 0;
    while ((f = lysp_feature_next(f, ly_mod->parsed, &i))) {
        if (f->flags & LYS_FENABLED) {
            if ((err_info = sr_lyd_new_term(sr_mod, NULL, "enabled-feature", f->name))) {
                goto cleanup;
            }
        }
    }

    /* set datastore plugin names */
    for (i = 0; i < SR_MOD_DS_PLUGIN_COUNT; ++i) {
        if ((i == SR_DS_RUNNING) && !module_ds.plugin_name[i]) {
            /* disabled */
            continue;
        }
        assert(module_ds.plugin_name[i]);

        if ((err_info = sr_lyd_new_list(sr_mod, "plugin", sr_mod_ds2ident(i), &sr_plugin))) {
            goto cleanup;
        }
        if ((err_info = sr_lyd_new_term(sr_plugin, NULL, "name", module_ds.plugin_name[i]))) {
            goto cleanup;
        }
    }

cleanup:
    return err_info;
}

/**
 * @brief Add dependent module and all of its implemented imports into sysrepo module data (if not there already), recursively.
 * All new modules have their data files created and YANG modules stored as well.
 *
 * @param[in] sr_mods Internal sysrepo data.
 * @param[in] ly_mod Module with implemented imports to add.
 * @param[in] module_ds Array of datastoru plugin names to use.
 * @param[in] owner Owner of the module.
 * @param[in] group Group of the module.
 * @param[in] perm Permissions of the module.
 * @param[in,out] new_mods Array of all the newly installed modules, is added to.
 * @param[in,out] new_mod_count Count of @p new_mods.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_add_module_with_imps_r(struct lyd_node *sr_mods, const struct lys_module *ly_mod, const sr_module_ds_t module_ds,
        const char *owner, const char *group, mode_t perm, sr_int_install_mod_t **new_mods, uint32_t *new_mod_count)
{
    sr_error_info_t *err_info = NULL;
    const struct lysp_submodule *lysp_submod;
    sr_int_install_mod_t *new_mod;
    void *mem;
    char *xpath = NULL;
    int found = 0;
    LY_ARRAY_COUNT_TYPE i, j;

    if (ly_mod->implemented) {
        if (*new_mod_count) {
            i = *new_mod_count;
            do {
                --i;
                if ((*new_mods)[i].ly_mod == ly_mod) {
                    /* module found and was/will be installed in this batch */
                    goto cleanup;
                }
            } while (i);
        }

        if (asprintf(&xpath, "module[name='%s']", ly_mod->name) == -1) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }
        if (!lyd_find_path(sr_mods, xpath, 0, NULL)) {
            /* installed before but there may be new implemented modules in its imports anyway */
            found = 1;
        }

        if (!found) {
            /* install the module */
            if ((err_info = sr_lydmods_add_module(sr_mods, ly_mod, module_ds))) {
                goto cleanup;
            }

            /* add into new_mods */
            mem = realloc(*new_mods, (*new_mod_count + 1) * sizeof **new_mods);
            SR_CHECK_MEM_GOTO(!mem, err_info, cleanup);
            *new_mods = mem;
            new_mod = &(*new_mods)[*new_mod_count];
            memset(new_mod, 0, sizeof *new_mod);
            ++(*new_mod_count);

            new_mod->ly_mod = ly_mod;
            new_mod->module_ds = module_ds;
            new_mod->owner = owner;
            new_mod->group = group;
            new_mod->perm = perm;
        }
    }

    /* all newly implemented modules will be added also from imports and includes, recursively */
    LY_ARRAY_FOR(ly_mod->parsed->imports, i) {
        if ((err_info = sr_lydmods_add_module_with_imps_r(sr_mods, ly_mod->parsed->imports[i].module, module_ds, owner,
                group, perm, new_mods, new_mod_count))) {
            goto cleanup;
        }
    }

    LY_ARRAY_FOR(ly_mod->parsed->includes, i) {
        lysp_submod = ly_mod->parsed->includes[i].submodule;
        LY_ARRAY_FOR(lysp_submod->imports, j) {
            if ((err_info = sr_lydmods_add_module_with_imps_r(sr_mods, lysp_submod->imports[j].module, module_ds, owner,
                    group, perm, new_mods, new_mod_count))) {
                goto cleanup;
            }
        }
    }

cleanup:
    free(xpath);
    return err_info;
}

/**
 * @brief Add explicit module and all of its implemented imports into sysrepo module data (if not there already), recursively.
 * All new modules have their data files created and YANG modules stored as well.
 *
 * @param[in] sr_mods Internal sysrepo data.
 * @param[in] ly_mod Module to add.
 * @param[in] module_ds Array of datastoru plugin names to use.
 * @param[in] owner Owner of the module.
 * @param[in] group Group of the module.
 * @param[in] perm Permissions of the module.
 * @param[in,out] new_mods Array of all the newly installed modules, is added to.
 * @param[in,out] new_mod_count Count of @p new_mods.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_add_module_with_imps(struct lyd_node *sr_mods, const struct lys_module *ly_mod,
        const sr_module_ds_t module_ds, const char *owner, const char *group, mode_t perm,
        sr_int_install_mod_t **new_mods, uint32_t *new_mod_count)
{
    sr_error_info_t *err_info = NULL;
    const struct lysp_submodule *lysp_submod;
    LY_ARRAY_COUNT_TYPE i, j;

    assert(ly_mod->implemented);

    /* install the module */
    if ((err_info = sr_lydmods_add_module(sr_mods, ly_mod, module_ds))) {
        goto cleanup;
    }

    /* all newly implemented modules will be added also from imports and includes, recursively */
    LY_ARRAY_FOR(ly_mod->parsed->imports, i) {
        if ((err_info = sr_lydmods_add_module_with_imps_r(sr_mods, ly_mod->parsed->imports[i].module, module_ds, owner,
                group, perm, new_mods, new_mod_count))) {
            goto cleanup;
        }
    }

    LY_ARRAY_FOR(ly_mod->parsed->includes, i) {
        lysp_submod = ly_mod->parsed->includes[i].submodule;
        LY_ARRAY_FOR(lysp_submod->imports, j) {
            if ((err_info = sr_lydmods_add_module_with_imps_r(sr_mods, lysp_submod->imports[j].module, module_ds, owner,
                    group, perm, new_mods, new_mod_count))) {
                goto cleanup;
            }
        }
    }

cleanup:
    return err_info;
}

struct sr_lydmods_deps_dfs_arg {
    struct lyd_node *sr_mod;
    struct lyd_node *sr_deps;
    struct lysc_node *root_notif;
    sr_error_info_t *err_info;
};

static LY_ERR sr_lydmods_add_all_deps_dfs_cb(struct lysc_node *node, void *data, ly_bool *dfs_continue);

/**
 * @brief Add (collect) operation data dependencies into internal sysrepo data.
 *
 * @param[in] sr_mod Module of the data.
 * @param[in] op_root Root node of the operation data to inspect.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_add_op_deps(struct lyd_node *sr_mod, const struct lysc_node *op_root)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_op_deps, *ly_cur_deps;
    struct ly_set *set = NULL;
    char *data_path = NULL, *xpath = NULL;
    struct sr_lydmods_deps_dfs_arg dfs_arg;
    int is_rpc;

    assert(op_root->nodetype & (LYS_RPC | LYS_ACTION | LYS_NOTIF));

    if (op_root->nodetype & (LYS_RPC | LYS_ACTION)) {
        is_rpc = 1;
    } else {
        is_rpc = 0;
    }

    data_path = lysc_path(op_root, LYSC_PATH_DATA, NULL, 0);
    SR_CHECK_MEM_GOTO(!data_path, err_info, cleanup);
    if (asprintf(&xpath, is_rpc ? "rpc[path='%s']" : "notification[path='%s']", data_path) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }

    if ((err_info = sr_lyd_find_xpath(sr_mod, xpath, &set))) {
        goto cleanup;
    }
    if (set->count == 1) {
        /* already exists */
        goto cleanup;
    }
    assert(!set->count);

    /* RPC/notification with path */
    if ((err_info = sr_lyd_new_list(sr_mod, is_rpc ? "rpc" : "notification", data_path, &sr_op_deps))) {
        goto cleanup;
    }

    /* collect dependencies of nested data and put them into correct containers */
    switch (op_root->nodetype) {
    case LYS_NOTIF:
        if ((err_info = sr_lyd_new_inner(sr_op_deps, NULL, "deps", &ly_cur_deps))) {
            goto cleanup;
        }

        /* collect notif dependencies */
        dfs_arg.sr_mod = sr_mod;
        dfs_arg.sr_deps = ly_cur_deps;
        dfs_arg.err_info = NULL;
        dfs_arg.root_notif = (struct lysc_node *)op_root;
        if (lysc_tree_dfs_full(op_root, sr_lydmods_add_all_deps_dfs_cb, &dfs_arg)) {
            err_info = dfs_arg.err_info;
            goto cleanup;
        }
        break;
    case LYS_RPC:
    case LYS_ACTION:
        /* input */
        if ((err_info = sr_lyd_new_inner(sr_op_deps, NULL, "in", &ly_cur_deps))) {
            goto cleanup;
        }
        op_root = lysc_node_child(op_root);

        dfs_arg.sr_mod = sr_mod;
        dfs_arg.sr_deps = ly_cur_deps;
        dfs_arg.err_info = NULL;
        dfs_arg.root_notif = NULL;
        if (lysc_tree_dfs_full(op_root, sr_lydmods_add_all_deps_dfs_cb, &dfs_arg)) {
            err_info = dfs_arg.err_info;
            goto cleanup;
        }

        /* output */
        if ((err_info = sr_lyd_new_inner(sr_op_deps, NULL, "out", &ly_cur_deps))) {
            goto cleanup;
        }
        op_root = op_root->next;

        dfs_arg.sr_deps = ly_cur_deps;
        if (lysc_tree_dfs_full(op_root, sr_lydmods_add_all_deps_dfs_cb, &dfs_arg)) {
            err_info = dfs_arg.err_info;
            goto cleanup;
        }
        break;
    default:
        SR_ERRINFO_INT(&err_info);
        goto cleanup;
    }

cleanup:
    ly_set_free(set, NULL);
    free(data_path);
    free(xpath);
    return err_info;
}

/**
 * @brief Add a leafref dependency into internal sysrepo data.
 *
 * @param[in] target_mod Leafref target module.
 * @param[in] exp Leafref parsed path.
 * @param[in] prefixes Resolved prefixes in @p exp.
 * @param[in,out] sr_deps Internal sysrepo data dependencies to add to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_moddep_add_lref(const char *target_mod, const struct lyxp_expr *exp, struct lysc_prefix *prefixes,
        struct lyd_node *sr_deps)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_lref;
    char *path = NULL;

    /* create new dependency */
    if ((err_info = sr_lyd_new_list(sr_deps, "lref", NULL, &sr_lref))) {
        goto cleanup;
    }

    /* get the path in canonical (JSON) format */
    if ((err_info = sr_ly_canonize_xpath10_value(LYD_CTX(sr_deps), lyxp_get_expr(exp), LY_VALUE_SCHEMA_RESOLVED,
            prefixes, &path))) {
        goto cleanup;
    }

    if ((err_info = sr_lyd_new_term(sr_lref, NULL, "target-path", path))) {
        goto cleanup;
    }
    if ((err_info = sr_lyd_new_term(sr_lref, NULL, "target-module", target_mod))) {
        goto cleanup;
    }

cleanup:
    free(path);
    return err_info;
}

/**
 * @brief Add an instance-identifier dependency into internal sysrepo data.
 *
 * @param[in] node Instance-identifier schema node.
 * @param[in] default_val Instance-identifier default value in canonical (JSON) format, if any.
 * @param[in,out] sr_deps Internal sysrepo data dependencies to add to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_moddep_add_instid(const struct lysc_node *node, const char *default_val, struct lyd_node *sr_deps)
{
    sr_error_info_t *err_info = NULL;
    char *data_path = NULL;
    struct lyd_node *sr_instid;

    /* create path of the node */
    data_path = lysc_path(node, LYSC_PATH_DATA, NULL, 0);
    SR_CHECK_MEM_GOTO(!data_path, err_info, cleanup);

    /* create new dependency */
    if ((err_info = sr_lyd_new_list(sr_deps, "inst-id", NULL, &sr_instid))) {
        goto cleanup;
    }
    if ((err_info = sr_lyd_new_term(sr_instid, NULL, "source-path", data_path))) {
        goto cleanup;
    }
    if (default_val && (err_info = sr_lyd_new_term(sr_instid, NULL, "default-target-path", default_val))) {
        goto cleanup;
    }

cleanup:
    free(data_path);
    return err_info;
}

/**
 * @brief Add an xpath (when or must) dependency into internal sysrepo data.
 *
 * @param[in] target_mods XPath expression target modules.
 * @param[in] exp Parsed XPath.
 * @param[in] prefixes Resolved prefixes in @p exp.
 * @param[in,out] sr_deps Internal sysrepo data dependencies to add to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_moddep_add_xpath(const struct ly_set *target_mods, const struct lyxp_expr *exp, struct lysc_prefix *prefixes,
        struct lyd_node *sr_deps)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_xpath;
    char *path = NULL;
    const struct lys_module *ly_mod;
    uint32_t i;

    /* create new dependency */
    if ((err_info = sr_lyd_new_list(sr_deps, "xpath", NULL, &sr_xpath))) {
        goto cleanup;
    }

    /* get the path in canonical (JSON) format */
    if ((err_info = sr_ly_canonize_xpath10_value(LYD_CTX(sr_deps), lyxp_get_expr(exp), LY_VALUE_SCHEMA_RESOLVED,
            prefixes, &path))) {
        goto cleanup;
    }

    if ((err_info = sr_lyd_new_term(sr_xpath, NULL, "expression", path))) {
        goto cleanup;
    }

    for (i = 0; i < target_mods->count; ++i) {
        ly_mod = target_mods->objs[i];
        if ((err_info = sr_lyd_new_term(sr_xpath, NULL, "target-module", ly_mod->name))) {
            goto cleanup;
        }
    }

cleanup:
    free(path);
    return err_info;
}

/**
 * @brief Collect dependencies from an XPath expression atoms.
 *
 * @param[in] op_node First parent operational node or top-level node.
 * @param[in] exp Parsed XPath.
 * @param[in] prefixes Resolved prefixes in @p exp.
 * @param[in] atoms Set of atoms (schema nodes).
 * @param[in,out] sr_deps Internal sysrepo data dependencies to add to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_moddep_xpath_atoms(const struct lysc_node *op_node, const struct lyxp_expr *exp, struct lysc_prefix *prefixes,
        const struct ly_set *atoms, struct lyd_node *sr_deps)
{
    sr_error_info_t *err_info = NULL;
    struct lys_module *dep_mod;
    struct ly_set target_mods = {0};
    uint32_t i;

    /* find all top-level foreign nodes (augment nodes are not considered foreign now) */
    for (i = 0; i < atoms->count; ++i) {
        if ((dep_mod = sr_ly_atom_is_foreign(atoms->snodes[i], op_node))) {
            if (ly_set_add(&target_mods, dep_mod, 0, NULL)) {
                SR_ERRINFO_MEM(&err_info);
                goto cleanup;
            }
        }
    }

    /* add new dependency */
    if ((err_info = sr_lydmods_moddep_add_xpath(&target_mods, exp, prefixes, sr_deps))) {
        goto cleanup;
    }

cleanup:
    ly_set_erase(&target_mods, NULL);
    return err_info;
}

/**
 * @brief Collect dependencies from a type.
 *
 * @param[in] type Type to inspect.
 * @param[in] node Type node.
 * @param[in] op_node First parent operational node or top-level node.
 * @param[in,out] sr_deps Internal sysrepo data dependencies to add to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_moddep_type(const struct lysc_type *type, const struct lysc_node *node, const struct lysc_node *op_node,
        struct lyd_node *sr_deps)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod = NULL;
    const struct lysc_type_union *uni;
    const struct lysc_type_leafref *lref;
    struct ly_set *atoms = NULL;
    char *default_val = NULL;
    LY_ARRAY_COUNT_TYPE u;
    uint32_t i;

    switch (type->basetype) {
    case LY_TYPE_INST:
        if (!((struct lysc_type_instanceid *)type)->require_instance) {
            /* not needed for validation, ignore */
            break;
        }

        if ((node->nodetype == LYS_LEAF) && ((struct lysc_node_leaf *)node)->dflt.str) {
            /* get JSON format of the default value */
            if ((err_info = sr_ly_canonize_xpath10_value(node->module->ctx, ((struct lysc_node_leaf *)node)->dflt.str,
                    LY_VALUE_SCHEMA_RESOLVED, ((struct lysc_node_leaf *)node)->dflt.prefixes, &default_val))) {
                goto cleanup;
            }

            /* get target module of the default value */
            if (lys_find_path_atoms(node->module->ctx, NULL, default_val, 0, &atoms)) {
                SR_ERRINFO_MEM(&err_info);
                goto cleanup;
            }
            assert(atoms->count);
            ly_mod = sr_ly_atom_is_foreign(atoms->snodes[0], op_node);
        }

        if ((err_info = sr_lydmods_moddep_add_instid(node, ly_mod ? default_val : NULL, sr_deps))) {
            goto cleanup;
        }
        break;
    case LY_TYPE_LEAFREF:
        lref = (struct lysc_type_leafref *)type;
        if (!lref->require_instance) {
            /* not needed for validation, ignore */
            break;
        }

        if ((err_info = sr_lys_find_expr_atoms(node, node->module, lref->path, lref->prefixes, 0, &atoms))) {
            goto cleanup;
        }
        assert(atoms->count);

        for (i = 0; i < atoms->count; ++i) {
            ly_mod = sr_ly_atom_is_foreign(atoms->snodes[i], op_node);
            if (!ly_mod) {
                continue;
            }

            /* a foregin module is referenced */
            if ((err_info = sr_lydmods_moddep_add_lref(ly_mod->name, lref->path, lref->prefixes, sr_deps))) {
                goto cleanup;
            }

            /* only a single module can be referenced */
            break;
        }
        break;
    case LY_TYPE_UNION:
        uni = (struct lysc_type_union *)type;
        LY_ARRAY_FOR(uni->types, u) {
            if ((err_info = sr_lydmods_moddep_type(uni->types[u], node, op_node, sr_deps))) {
                goto cleanup;
            }
        }
        break;
    default:
        /* no dependency */
        break;
    }

cleanup:
    ly_set_free(atoms, NULL);
    free(default_val);
    return err_info;
}

/**
 * @brief Add (collect) (operation) data dependencies into internal sysrepo data tree
 * from a node. Collected recursively in a DFS callback.
 *
 * @param[in] node Node to inspect.
 * @param[in] data Callback arg struct sr_lydmods_deps_dfs_arg.
 * @return LY_SUCCESS on success.
 * @return LY_EOTHER on error, arg err_info is filled.
 */
static LY_ERR
sr_lydmods_add_all_deps_dfs_cb(struct lysc_node *node, void *data, ly_bool *dfs_continue)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *atoms;
    struct lysc_type *type = NULL;
    struct lysc_when **when = NULL;
    struct lysc_must *musts = NULL;
    const struct lysc_node *op_node;
    LY_ARRAY_COUNT_TYPE u;
    int atom_opts;
    struct sr_lydmods_deps_dfs_arg *arg = data;

    atom_opts = LYS_FIND_XP_SCHEMA;

    if (node->nodetype & (LYS_RPC | LYS_ACTION)) {
        /* operation, put the dependencies separately */
        if ((err_info = sr_lydmods_add_op_deps(arg->sr_mod, node))) {
            goto cleanup;
        }
        *dfs_continue = 1;
    } else if ((node->nodetype == LYS_NOTIF) && (node != arg->root_notif)) {
        /* operation, put the dependencies separately */
        if ((err_info = sr_lydmods_add_op_deps(arg->sr_mod, node))) {
            goto cleanup;
        }
        *dfs_continue = 1;
    } else {
        /* collect all the specific information */
        if (node->nodetype & (LYS_LEAF | LYS_LEAFLIST)) {
            type = ((struct lysc_node_leaf *)node)->type;
        }
        when = lysc_node_when(node);
        musts = lysc_node_musts(node);
        if (node->nodetype == LYS_OUTPUT) {
            atom_opts = LYS_FIND_XP_OUTPUT;
        }
    }

    /* find out if we are in an operation, otherwise simply find top-level node */
    op_node = node;
    while (!(op_node->nodetype & (LYS_RPC | LYS_ACTION | LYS_NOTIF)) && op_node->parent) {
        op_node = op_node->parent;
    }

    /* collect the dependencies */
    if (type) {
        if ((err_info = sr_lydmods_moddep_type(type, node, op_node, arg->sr_deps))) {
            goto cleanup;
        }
    }
    LY_ARRAY_FOR(when, u) {
        if ((err_info = sr_lys_find_expr_atoms(when[u]->context, node->module, when[u]->cond, when[u]->prefixes,
                atom_opts, &atoms))) {
            goto cleanup;
        }
        err_info = sr_lydmods_moddep_xpath_atoms(op_node, when[u]->cond, when[u]->prefixes, atoms, arg->sr_deps);
        ly_set_free(atoms, NULL);
        if (err_info) {
            goto cleanup;
        }
    }
    LY_ARRAY_FOR(musts, u) {
        if ((err_info = sr_lys_find_expr_atoms(node, node->module, musts[u].cond, musts[u].prefixes, atom_opts, &atoms))) {
            goto cleanup;
        }
        err_info = sr_lydmods_moddep_xpath_atoms(op_node, musts[u].cond, musts[u].prefixes, atoms, arg->sr_deps);
        ly_set_free(atoms, NULL);
        if (err_info) {
            goto cleanup;
        }
    }

cleanup:
    if (err_info) {
        arg->err_info = err_info;
        return LY_EOTHER;
    }
    return LY_SUCCESS;
}

/**
 * @brief Add inverse dependency node but only if there is not already similar one.
 *
 * @param[in] sr_mod Module with the inverse dependency.
 * @param[in] inv_dep_mod Name of the module that depends on @p sr_mod.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_add_inv_data_dep(struct lyd_node *sr_mod, const char *inv_dep_mod)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *node;

    /* does it exist already? */
    LY_LIST_FOR(lyd_child(sr_mod), node) {
        if (strcmp(node->schema->name, "inverse-deps")) {
            continue;
        }

        if (!strcmp(lyd_get_value(node), inv_dep_mod)) {
            /* exists already */
            return NULL;
        }
    }

    if ((err_info = sr_lyd_new_term(sr_mod, NULL, "inverse-deps", inv_dep_mod))) {
        return err_info;
    }

    return NULL;
}

/**
 * @brief Free all module dependency containers from SR internal module data.
 *
 * @param[in] sr_mods SR internal module data to modify.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_del_deps_all(struct lyd_node *sr_mods)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set = NULL;
    uint32_t i;

    /* find all the containers */
    if ((err_info = sr_lyd_find_xpath(sr_mods, "module/deps | module/inverse-deps | module/rpc | module/notification",
            &set))) {
        goto cleanup;
    }

    /* free all of them */
    for (i = 0; i < set->count; ++i) {
        lyd_free_tree(set->dnodes[i]);
    }

cleanup:
    ly_set_free(set, NULL);
    return err_info;
}

/**
 * @brief Rebuild all dependencies (with inverse) and RPCs/notifications with dependencies in SR internal module data.
 *
 * @param[in] ly_ctx Context with all the modules and in the same state as described in @p sr_mods.
 * @param[in,out] sr_mods SR internal module data to add to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_add_deps_all(const struct ly_ctx *ly_ctx, struct lyd_node *sr_mods)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    struct ly_set *set = NULL;
    struct lyd_node *sr_mod, *sr_mod2, *sr_deps;
    uint32_t i;
    char *xpath;
    struct sr_lydmods_deps_dfs_arg dfs_arg;

    LY_LIST_FOR(lyd_child(sr_mods), sr_mod) {
        if (strcmp(LYD_NAME(sr_mod), "module")) {
            continue;
        }

        /* there can be no dependencies yet (but inverse ones yes) */
        assert(!lyd_find_xpath(sr_mod, "deps | rpc | notification", &set));
        assert(!set->count || ((set->count == 1) && (set->dnodes[0]->flags & LYD_DEFAULT)));
        ly_set_free(set, NULL);
        set = NULL;

        /* find the module */
        assert(!strcmp(LYD_NAME(lyd_child(sr_mod)), "name"));
        ly_mod = ly_ctx_get_module_implemented(ly_ctx, lyd_get_value(lyd_child(sr_mod)));
        SR_CHECK_INT_GOTO(!ly_mod, err_info, cleanup);

        /* create new deps */
        if ((err_info = sr_lyd_new_inner(sr_mod, NULL, "deps", &sr_deps))) {
            goto cleanup;
        }

        /* add all module deps (data, RPC, notif) */
        dfs_arg.sr_mod = sr_mod;
        dfs_arg.sr_deps = sr_deps;
        dfs_arg.root_notif = NULL;
        dfs_arg.err_info = NULL;
        if (lysc_module_dfs_full(ly_mod, sr_lydmods_add_all_deps_dfs_cb, &dfs_arg)) {
            err_info = dfs_arg.err_info;
            goto cleanup;
        }

        /* add inverse data deps */
        if ((err_info = sr_lyd_find_xpath(sr_mod, "deps/*/target-module", &set))) {
            goto cleanup;
        }

        for (i = 0; i < set->count; ++i) {
            if (asprintf(&xpath, "module[name='%s']", lyd_get_value(set->dnodes[i])) == -1) {
                SR_ERRINFO_MEM(&err_info);
                goto cleanup;
            }

            /* find the dependent module */
            err_info = sr_lyd_find_path(lyd_parent(sr_mod), xpath, 0, &sr_mod2);
            free(xpath);
            if (err_info) {
                goto cleanup;
            }

            /* add inverse dependency */
            if ((err_info = sr_lydmods_add_inv_data_dep(sr_mod2, lyd_get_value(lyd_child(sr_mod))))) {
                goto cleanup;
            }
        }
        ly_set_free(set, NULL);
        set = NULL;
    }

cleanup:
    ly_set_free(set, NULL);
    return err_info;
}

/**
 * @brief Store (print) sysrepo module data.
 *
 * @param[in,out] sr_mods Data to store, are validated so could (in theory) be modified.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_print(struct lyd_node **sr_mods)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *sr_ly_mod;
    struct lyd_node *node;
    uint32_t hash;

    assert(sr_mods && *sr_mods && !strcmp((*sr_mods)->schema->module->name, "sysrepo"));

    /* get the module */
    sr_ly_mod = (*sr_mods)->schema->module;

    /* validate */
    if ((err_info = sr_lyd_validate_module(sr_mods, sr_ly_mod, 0, NULL))) {
        return err_info;
    }

    /* update content-id */
    if ((err_info = sr_lyd_find_path(*sr_mods, "/sysrepo:sysrepo-modules/content-id", 0, &node))) {
        return err_info;
    }
    hash = ly_ctx_get_modules_hash(sr_ly_mod->ctx);
    lyd_change_term_bin(node, &hash, sizeof hash);

    /* store the data using the internal JSON plugin */
    if ((err_info = srpds_json.store_prepare_cb(sr_ly_mod, SR_DS_STARTUP, 0, 0, NULL, *sr_mods, NULL))) {
        return err_info;
    }

    if ((err_info = srpds_json.store_commit_cb(sr_ly_mod, SR_DS_STARTUP, 0, 0, NULL, *sr_mods, NULL))) {
        return err_info;
    }

    return NULL;
}

/**
 * @brief Get module DS for an internal module.
 *
 * @param[in] name Mdoule name.
 * @return Module DS structure for the module.
 */
static sr_module_ds_t
sr_lydmods_int_mod_ds(const char *name)
{
    const char *int_mod_str = " " SR_INT_MOD_DISABLED_RUNNING " ";
    char *needle;
    int run_disabled = 0;

    if (!strcmp(int_mod_str, " * ")) {
        /* all internal module running disabled */
        run_disabled = 1;
    } else {
        if (asprintf(&needle, " %s ", name) == -1) {
            return sr_module_ds_default;
        }
        if (strstr(int_mod_str, needle)) {
            /* running disabled */
            run_disabled = 1;
        }
        free(needle);
    }

    return run_disabled ? sr_module_ds_disabled_run : sr_module_ds_default;
}

/**
 * @brief Create default sysrepo module data. All libyang internal implemented modules
 * are installed into sysrepo. Sysrepo internal modules ietf-netconf, ietf-netconf-with-defaults,
 * and ietf-netconf-notifications are also installed.
 *
 * @param[in] conn Connection to use for DS handles.
 * @param[in,out] ly_ctx Context for parsing @p sr_mods_p and is initialize according to the default created sr_mods.
 * @param[out] sr_mods_p Created default sysrepo module data.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_create(sr_conn_ctx_t *conn, struct ly_ctx *ly_ctx, struct lyd_node **sr_mods_p)
{
    sr_error_info_t *err_info = NULL;
    struct lys_module *ly_mod;
    struct lyd_node *sr_mods = NULL, *init_data = NULL;
    sr_int_install_mod_t *new_mods = NULL;
    uint32_t i, new_mod_count = 0;
    struct sr_data_update_s data_info = {0};
    const char *mod_origin;

#define SR_INSTALL_INT_MOD(ctx, yang_mod, dep, new_mods, new_mod_count) \
    if ((err_info = sr_lys_parse(ctx, yang_mod, NULL, LYS_IN_YANG, NULL, &ly_mod))) { \
        goto cleanup; \
    } \
    if ((err_info = sr_lydmods_add_module_with_imps_r(sr_mods, ly_mod, sr_lydmods_int_mod_ds(ly_mod->name), NULL, \
            strlen(SR_GROUP) ? SR_GROUP : NULL, sr_module_default_mode(ly_mod), &(new_mods), &(new_mod_count)))) { \
        goto cleanup; \
    } \
    SR_LOG_INF("Sysrepo internal%s module \"%s\" was installed.", dep ? " dependency" : "", ly_mod->name)

    ly_mod = ly_ctx_get_module_implemented(ly_ctx, "sysrepo");
    SR_CHECK_INT_GOTO(!ly_mod, err_info, cleanup);

    /* create empty container */
    if ((err_info = sr_lyd_new_inner(NULL, ly_mod, "sysrepo-modules", &sr_mods))) {
        goto cleanup;
    }

    /* add content-id */
    if ((err_info = sr_lyd_new_term(sr_mods, NULL, "content-id", "1"))) {
        goto cleanup;
    }

    /* for internal libyang and sysrepo modules create files and store in the persistent module data tree */
    i = 0;
    while ((ly_mod = ly_ctx_get_module_iter(ly_ctx, &i))) {
        /* no "sysrepo" and module must be implemented */
        if (!ly_mod->implemented || !strcmp(ly_mod->name, "sysrepo")) {
            continue;
        }

        if ((err_info = sr_lydmods_add_module_with_imps_r(sr_mods, ly_mod, sr_lydmods_int_mod_ds(ly_mod->name), NULL,
                strlen(SR_GROUP) ? SR_GROUP : NULL, sr_module_default_mode(ly_mod), &new_mods, &new_mod_count))) {
            goto cleanup;
        }

        mod_origin = (i < ly_ctx_internal_modules_count(ly_ctx)) ? "Libyang" : "Sysrepo";
        SR_LOG_INF("%s internal module \"%s\" was installed.", mod_origin, ly_mod->name);
    }

    /* install ietf-yang-library */
    SR_INSTALL_INT_MOD(ly_ctx, ietf_yang_library_yang, 0, new_mods, new_mod_count);

    /* install sysrepo-monitoring */
    SR_INSTALL_INT_MOD(ly_ctx, sysrepo_monitoring_yang, 0, new_mods, new_mod_count);

    /* install sysrepo-plugind */
    SR_INSTALL_INT_MOD(ly_ctx, sysrepo_plugind_yang, 0, new_mods, new_mod_count);

    /* install sysrepo-notifications */
    SR_INSTALL_INT_MOD(ly_ctx, sysrepo_notifications_yang, 0, new_mods, new_mod_count);

    /* install ietf-netconf (implemented dependency) and ietf-netconf-with-defaults */
    SR_INSTALL_INT_MOD(ly_ctx, ietf_netconf_yang, 1, new_mods, new_mod_count);
    SR_INSTALL_INT_MOD(ly_ctx, ietf_netconf_with_defaults_yang, 0, new_mods, new_mod_count);

    /* install ietf-netconf-notifications */
    SR_INSTALL_INT_MOD(ly_ctx, ietf_netconf_notifications_yang, 0, new_mods, new_mod_count);

    /* install ietf-origin */
    SR_INSTALL_INT_MOD(ly_ctx, ietf_origin_yang, 0, new_mods, new_mod_count);

    /* compile all */
    if ((err_info = sr_ly_ctx_compile(ly_ctx))) {
        goto cleanup;
    }

    if (strlen(SR_INT_MOD_DATA)) {
        /* parse and validate the initial data, if any */
        if ((err_info = sr_lyd_parse_data(ly_ctx, SR_INT_MOD_DATA, NULL, SR_INT_MOD_DATA_FORMAT, 0, LYD_VALIDATE_NO_STATE,
                &init_data))) {
            goto cleanup;
        }
    } else {
        /* use implicit data */
        if ((err_info = sr_lyd_new_implicit_all(&init_data, ly_ctx, LYD_IMPLICIT_NO_STATE))) {
            goto cleanup;
        }
    }
    if ((err_info = sr_lyd_dup(init_data, NULL, LYD_DUP_RECURSIVE, 1, &data_info.new.start))) {
        goto cleanup;
    }
    if ((err_info = sr_lyd_dup(init_data, NULL, LYD_DUP_RECURSIVE, 1, &data_info.new.run))) {
        goto cleanup;
    }
    data_info.new.fdflt = init_data;
    init_data = NULL;

    /* finish installing all the modules */
    if ((err_info = sr_lycc_add_modules(conn, new_mods, new_mod_count))) {
        goto cleanup;
    }

    /* store initial or implicit data */
    if ((err_info = sr_lycc_store_data_if_differ(conn, ly_ctx, sr_mods, &data_info))) {
        goto cleanup;
    }

    /* finish SR internal module data by adding dependencies */
    if ((err_info = sr_lydmods_add_deps_all(ly_ctx, sr_mods))) {
        goto cleanup;
    }

    /* store the created data */
    if ((err_info = sr_lydmods_print(&sr_mods))) {
        goto cleanup;
    }

cleanup:
    free(new_mods);
    lyd_free_tree(init_data);
    sr_lycc_update_data_clear(&data_info);
    if (err_info) {
        lyd_free_all(sr_mods);
    } else {
        *sr_mods_p = sr_mods;
    }
    return err_info;

#undef SR_INSTALL_INT_MOD
}

sr_error_info_t *
sr_lydmods_parse(const struct ly_ctx *ly_ctx, sr_conn_ctx_t *conn, int *initialized, struct lyd_node **sr_mods_p)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL;
    const struct lys_module *ly_mod;
    char *path = NULL;
    int created = 0;

    assert(ly_ctx && sr_mods_p);

    if (initialized) {
        *initialized = 0;
    }

    /* get SR module */
    ly_mod = ly_ctx_get_module_implemented(ly_ctx, "sysrepo");
    assert(ly_mod);

    /* check whether the file exists */
    if (srpjson_get_path(NULL, ly_mod->name, SR_DS_STARTUP, &path)) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    if (srpjson_file_exists(NULL, path)) {
        /* load the data using the internal JSON plugin */
        if ((err_info = srpds_json.load_cb(ly_mod, SR_DS_STARTUP, 0, 0, NULL, 0, NULL, &sr_mods))) {
            goto cleanup;
        }
        if (!sr_mods) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Empty \"sysrepo\" startup data file.");
            goto cleanup;
        }
    } else if (initialized) {
        /* install the "sysrepo" module */
        if ((err_info = srpds_json.install_cb(ly_mod, SR_DS_STARTUP, NULL, strlen(SR_GROUP) ? SR_GROUP : NULL,
                SR_INTMOD_MAIN_FILE_PERM, NULL))) {
            goto cleanup;
        }
        created = 1;
        if ((err_info = sr_store_module_yang_r(ly_mod))) {
            goto cleanup;
        }

        /* no data, create default */
        if ((err_info = sr_lydmods_create(conn, (struct ly_ctx *)ly_ctx, &sr_mods))) {
            goto cleanup;
        }
        *initialized = 1;
    } else {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Startup \"sysrepo\" data file does not exist.");
        goto cleanup;
    }

cleanup:
    if (err_info) {
        lyd_free_all(sr_mods);
        if (created) {
            srpds_json.uninstall_cb(ly_mod, SR_DS_STARTUP, NULL);
        }
    } else {
        *sr_mods_p = sr_mods;
    }
    free(path);
    return err_info;
}

sr_error_info_t *
sr_lydmods_change_add_modules(const struct ly_ctx *ly_ctx, sr_conn_ctx_t *conn, sr_int_install_mod_t **new_mods,
        uint32_t *new_mod_count, struct lyd_node **sr_mods)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, j, orig_mod_count = *new_mod_count;
    struct lyd_node *sr_mod;
    char *path = NULL;

    *sr_mods = NULL;

    /* parse current module information */
    if ((err_info = sr_lydmods_parse(ly_ctx, conn, NULL, sr_mods))) {
        goto cleanup;
    }

    /* add new modules with all implemented dependencies/enable module features to SR data, the dependencies are added
     * to new_mods as well */
    for (i = 0; i < orig_mod_count; ++i) {
        if ((*new_mods)[i].enable_features) {
            /* find this module */
            if (asprintf(&path, "module[name='%s']", (*new_mods)[i].ly_mod->name) == -1) {
                SR_ERRINFO_MEM(&err_info);
                goto cleanup;
            }
            if ((err_info = sr_lyd_find_path(*sr_mods, path, 0, &sr_mod))) {
                goto cleanup;
            }
            free(path);
            path = NULL;
            SR_CHECK_INT_GOTO(!sr_mod, err_info, cleanup);

            /* add all enabled features */
            for (j = 0; (*new_mods)[i].enable_features[j]; ++j) {
                if ((err_info = sr_lyd_new_term(sr_mod, NULL, "enabled-feature", (*new_mods)[i].enable_features[j]))) {
                    goto cleanup;
                }
                SR_LOG_INF("Module \"%s\" feature \"%s\" enabled.", (*new_mods)[i].ly_mod->name,
                        (*new_mods)[i].enable_features[j]);
            }
        } else {
            /* install the module */
            if ((err_info = sr_lydmods_add_module_with_imps(*sr_mods, (*new_mods)[i].ly_mod, (*new_mods)[i].module_ds,
                    (*new_mods)[i].owner, (*new_mods)[i].group, (*new_mods)[i].perm, new_mods, new_mod_count))) {
                goto cleanup;
            }
            SR_LOG_INF("Module \"%s\" was installed.", (*new_mods)[i].ly_mod->name);
        }
    }
    for ( ; i < *new_mod_count; ++i) {
        /* all dependencies already installed */
        SR_LOG_INF("Dependency module \"%s\" was installed.", (*new_mods)[i].ly_mod->name);
    }

    /* delete all dependencies */
    if ((err_info = sr_lydmods_del_deps_all(*sr_mods))) {
        goto cleanup;
    }

    /* add new dependencies for all the modules */
    if ((err_info = sr_lydmods_add_deps_all(ly_ctx, *sr_mods))) {
        goto cleanup;
    }

    /* store updated SR internal module data */
    if ((err_info = sr_lydmods_print(sr_mods))) {
        goto cleanup;
    }

cleanup:
    free(path);
    if (err_info) {
        lyd_free_all(*sr_mods);
        *sr_mods = NULL;
    }
    return err_info;
}

sr_error_info_t *
sr_lydmods_change_del_module(const struct ly_ctx *ly_ctx, const struct ly_ctx *new_ctx, const struct ly_set *mod_set,
        sr_conn_ctx_t *conn, struct lyd_node **sr_del_mods, struct lyd_node **sr_mods)
{
    sr_error_info_t *err_info = NULL;
    struct lys_module *ly_mod;
    struct lyd_node *sr_mod;
    char *path = NULL;
    uint32_t i;

    *sr_del_mods = NULL;
    *sr_mods = NULL;

    /* parse current module information */
    if ((err_info = sr_lydmods_parse(ly_ctx, conn, NULL, sr_mods))) {
        goto cleanup;
    }

    for (i = 0; i < mod_set->count; ++i) {
        ly_mod = mod_set->objs[i];

        /* find module in SR data */
        if (asprintf(&path, "module[name=\"%s\"]", ly_mod->name) == -1) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }
        SR_CHECK_INT_GOTO(lyd_find_path(*sr_mods, path, 0, &sr_mod), err_info, cleanup);
        free(path);
        path = NULL;

        /* relink it */
        if (!*sr_del_mods && (err_info = sr_lyd_dup(*sr_mods, NULL, 0, 0, sr_del_mods))) {
            goto cleanup;
        }
        if ((err_info = sr_lyd_insert_child(*sr_del_mods, sr_mod))) {
            goto cleanup;
        }

        SR_LOG_INF("Module \"%s\" removed.", ly_mod->name);
    }

    /* delete all dependencies */
    if ((err_info = sr_lydmods_del_deps_all(*sr_mods))) {
        goto cleanup;
    }

    /* add new dependencies for all the modules */
    if ((err_info = sr_lydmods_add_deps_all(new_ctx, *sr_mods))) {
        goto cleanup;
    }

    /* store updated SR internal module data */
    if ((err_info = sr_lydmods_print(sr_mods))) {
        goto cleanup;
    }

cleanup:
    free(path);
    if (err_info) {
        lyd_free_all(*sr_del_mods);
        *sr_del_mods = NULL;
        lyd_free_all(*sr_mods);
        *sr_mods = NULL;
    }
    return err_info;
}

sr_error_info_t *
sr_lydmods_change_upd_modules(const struct ly_ctx *ly_ctx, const struct ly_set *upd_mod_set, sr_conn_ctx_t *conn,
        struct lyd_node **sr_mods)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *upd_mod = NULL;
    struct lyd_node *sr_mod, *sr_rev;
    char *path = NULL;
    uint32_t i;

    *sr_mods = NULL;

    /* parse current module information */
    if ((err_info = sr_lydmods_parse(ly_ctx, conn, NULL, sr_mods))) {
        goto cleanup;
    }

    for (i = 0; i < upd_mod_set->count; ++i) {
        upd_mod = upd_mod_set->objs[i];

        /* find module in SR data */
        if (asprintf(&path, "module[name=\"%s\"]", upd_mod->name) == -1) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }
        SR_CHECK_INT_GOTO(lyd_find_path(*sr_mods, path, 0, &sr_mod), err_info, cleanup);
        free(path);
        path = NULL;

        /* remove revision, if any */
        lyd_find_path(sr_mod, "revision", 0, &sr_rev);
        lyd_free_tree(sr_rev);

        /* add new revision */
        assert(upd_mod->revision);
        if ((err_info = sr_lyd_new_term(sr_mod, NULL, "revision", upd_mod->revision))) {
            goto cleanup;
        }

        SR_LOG_INF("Module \"%s\" updated.", upd_mod->name);
    }

    /* delete all dependencies */
    if ((err_info = sr_lydmods_del_deps_all(*sr_mods))) {
        goto cleanup;
    }

    /* add new dependencies for all the modules */
    if ((err_info = sr_lydmods_add_deps_all(upd_mod->ctx, *sr_mods))) {
        goto cleanup;
    }

    /* store updated SR internal module data */
    if ((err_info = sr_lydmods_print(sr_mods))) {
        goto cleanup;
    }

cleanup:
    free(path);
    if (err_info) {
        lyd_free_all(*sr_mods);
        *sr_mods = NULL;
    }
    return err_info;
}

sr_error_info_t *
sr_lydmods_change_chng_feature(const struct ly_ctx *ly_ctx, const struct lys_module *old_mod,
        const struct ly_ctx *new_ctx, const struct ly_set *feat_set, int enable, sr_conn_ctx_t *conn,
        struct lyd_node **sr_mods)
{
    sr_error_info_t *err_info = NULL;
    const char *feat_name;
    struct lyd_node *sr_mod, *node;
    char *path = NULL;
    uint32_t i;

    *sr_mods = NULL;

    /* parse current module information */
    if ((err_info = sr_lydmods_parse(ly_ctx, conn, NULL, sr_mods))) {
        goto cleanup;
    }

    /* find this module */
    if (asprintf(&path, "module[name='%s']", old_mod->name) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    if ((err_info = sr_lyd_find_path(*sr_mods, path, 0, &sr_mod))) {
        goto cleanup;
    }
    SR_CHECK_INT_GOTO(!sr_mod, err_info, cleanup);

    for (i = 0; i < feat_set->count; ++i) {
        feat_name = feat_set->objs[i];

        if (enable) {
            /* add enabled feature */
            if ((err_info = sr_lyd_new_term(sr_mod, NULL, "enabled-feature", feat_name))) {
                goto cleanup;
            }

            SR_LOG_INF("Module \"%s\" feature \"%s\" enabled.", old_mod->name, feat_name);
        } else {
            /* find and free the enabled feature */
            free(path);
            if (asprintf(&path, "enabled-feature[.='%s']", feat_name) == -1) {
                SR_ERRINFO_MEM(&err_info);
                goto cleanup;
            }
            if ((err_info = sr_lyd_find_path(sr_mod, path, 0, &node))) {
                goto cleanup;
            }
            SR_CHECK_INT_GOTO(!node, err_info, cleanup);
            lyd_free_tree(node);

            SR_LOG_INF("Module \"%s\" feature \"%s\" disabled.", old_mod->name, feat_name);
        }
    }

    /* delete all dependencies */
    if ((err_info = sr_lydmods_del_deps_all(*sr_mods))) {
        goto cleanup;
    }

    /* add new dependencies for all the modules */
    if ((err_info = sr_lydmods_add_deps_all(new_ctx, *sr_mods))) {
        goto cleanup;
    }

    /* store updated SR internal module data */
    if ((err_info = sr_lydmods_print(sr_mods))) {
        goto cleanup;
    }

cleanup:
    free(path);
    if (err_info) {
        lyd_free_all(*sr_mods);
        *sr_mods = NULL;
    }
    return err_info;
}

/**
 * @brief Update replay support of a module.
 *
 * @param[in] ly_mod libyang module.
 * @param[in,out] sr_mod Module to update.
 * @param[in] enable Whether replay should be enabled or disabled.
 * @param[in,out] mod_set Set of changed modules, is added to.
 * @param[in] conn Connection to use for NTF handles.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_update_replay_support_module(const struct lys_module *ly_mod, struct lyd_node *sr_mod, int enable,
        struct ly_set *mod_set, sr_conn_ctx_t *conn)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_replay, *sr_plg_name;
    struct timespec ts;
    const struct sr_ntf_handle_s *ntf_handle;
    char *buf = NULL;

    if ((err_info = sr_lyd_find_path(sr_mod, "replay-support", 0, &sr_replay))) {
        return err_info;
    }

    if (!enable && sr_replay) {
        /* remove replay support */
        lyd_free_tree(sr_replay);

        /* changed, add into set */
        if (ly_set_add(mod_set, (void *)ly_mod, 1, NULL)) {
            SR_ERRINFO_MEM(&err_info);
            return err_info;
        }

        SR_LOG_INF("Module \"%s\" replay support disabled.", ly_mod->name);
    } else if (enable && !sr_replay) {
        /* find NTF plugin */
        if ((err_info = sr_lyd_find_path(sr_mod, "plugin[datastore='notification']/name", 0, &sr_plg_name))) {
            return err_info;
        }
        SR_CHECK_INT_RET(!sr_plg_name, err_info);
        if ((err_info = sr_ntf_handle_find(lyd_get_value(sr_plg_name), conn, &ntf_handle))) {
            return err_info;
        }

        /* use earliest stored notification timestamp or use current time */
        if ((err_info = ntf_handle->plugin->earliest_get_cb(ly_mod, &ts))) {
            return err_info;
        }
        if (SR_TS_IS_ZERO(ts)) {
            sr_realtime_get(&ts);
        }
        if ((err_info = sr_ly_time_ts2str(&ts, &buf))) {
            return err_info;
        }

        /* add replay support */
        err_info = sr_lyd_new_term(sr_mod, NULL, "replay-support", buf);
        free(buf);
        if (err_info) {
            return err_info;
        }

        /* changed, add into set */
        if ((err_info = sr_ly_set_add(mod_set, (void *)ly_mod))) {
            return err_info;
        }

        SR_LOG_INF("Module \"%s\" replay support enabled.", ly_mod->name);
    }

    return NULL;
}

sr_error_info_t *
sr_lydmods_change_chng_replay_support(const struct lys_module *ly_mod, int enable, struct ly_set *mod_set,
        sr_conn_ctx_t *conn, struct lyd_node **sr_mods)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mod;
    char *path = NULL;

    /* parse current module information */
    if ((err_info = sr_lydmods_parse(sr_yang_ctx.ly_ctx, conn, NULL, sr_mods))) {
        goto cleanup;
    }

    if (ly_mod) {
        /* print path */
        if (asprintf(&path, "module[name='%s']", ly_mod->name) == -1) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }

        /* we expect the module to exist */
        if ((err_info = sr_lyd_find_path(*sr_mods, path, 0, &sr_mod))) {
            goto cleanup;
        }
        assert(sr_mod);

        /* set replay support */
        if ((err_info = sr_lydmods_update_replay_support_module(ly_mod, sr_mod, enable, mod_set, conn))) {
            goto cleanup;
        }
    } else {
        LY_LIST_FOR(lyd_child(*sr_mods), sr_mod) {
            if (strcmp(LYD_NAME(sr_mod), "module")) {
                continue;
            }

            /* find module */
            ly_mod = ly_ctx_get_module_implemented(sr_yang_ctx.ly_ctx, lyd_get_value(lyd_child(sr_mod)));
            assert(ly_mod);

            /* set replay support */
            if ((err_info = sr_lydmods_update_replay_support_module(ly_mod, sr_mod, enable, mod_set, conn))) {
                goto cleanup;
            }
        }
    }

    /* store updated SR internal module data */
    if ((err_info = sr_lydmods_print(sr_mods))) {
        goto cleanup;
    }

cleanup:
    free(path);
    if (err_info) {
        lyd_free_all(*sr_mods);
        *sr_mods = NULL;
    }
    return err_info;
}
