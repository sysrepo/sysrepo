/**
 * @file lyd_mods.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Sysrepo module data routines
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

#include "common.h"
#include "compat.h"
#include "log.h"
#include "replay.h"
#include "shm.h"

#include "../modules/ietf_datastores_yang.h"
#include "../modules/sysrepo_yang.h"
#if SR_YANGLIB_REVISION == 2019 - 01 - 04
# include "../modules/ietf_yang_library@2019_01_04_yang.h"
#elif SR_YANGLIB_REVISION == 2016 - 06 - 21
# include "../modules/ietf_yang_library@2016_06_21_yang.h"
#else
# error "Unknown yang-library revision!"
#endif

#include "../modules/ietf_netconf_acm_yang.h"
#include "../modules/ietf_netconf_notifications_yang.h"
#include "../modules/ietf_netconf_with_defaults_yang.h"
#include "../modules/ietf_netconf_yang.h"
#include "../modules/ietf_origin_yang.h"
#include "../modules/sysrepo_monitoring_yang.h"
#include "../modules/sysrepo_plugind_yang.h"

sr_error_info_t *
sr_lydmods_lock(pthread_mutex_t *lock, const struct ly_ctx *ly_ctx, const char *func)
{
    struct sr_shmmod_recover_cb_s cb_data;

    cb_data.ly_mod = ly_ctx_get_module_implemented(ly_ctx, SR_YANG_MOD);
    cb_data.ds = SR_DS_STARTUP;

    /* LOCK */
    return sr_mlock(lock, SR_LYDMODS_LOCK_TIMEOUT, func, sr_shmmod_recover_cb, &cb_data);
}

sr_error_info_t *
sr_lydmods_parse(struct ly_ctx *ly_ctx, struct lyd_node **sr_mods_p)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL;
    char *path;

    assert(ly_ctx && sr_mods_p);

    /* get internal startup file path */
    if ((err_info = sr_path_startup_file(SR_YANG_MOD, &path))) {
        goto cleanup;
    }

    /* load sysrepo data even if the stored data used an older revision of the sysrepo module */
    if (lyd_parse_data_path(ly_ctx, path, LYD_LYB, LYD_PARSE_LYB_MOD_UPDATE | LYD_PARSE_STRICT | LYD_PARSE_ONLY,
            0, &sr_mods)) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    /* success */

cleanup:
    free(path);
    if (err_info) {
        lyd_free_all(sr_mods);
    } else {
        *sr_mods_p = sr_mods;
    }
    return err_info;
}

sr_error_info_t *
sr_lydmods_get_content_id(sr_main_shm_t *main_shm, struct ly_ctx *ly_ctx, uint32_t *cont_id)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL;

    /* LYDMODS LOCK */
    if ((err_info = sr_lydmods_lock(&main_shm->lydmods_lock, ly_ctx, __func__))) {
        return err_info;
    }

    /* parse sysrepo module data */
    err_info = sr_lydmods_parse(ly_ctx, &sr_mods);

    /* LYDMODS UNLOCK */
    sr_munlock(&main_shm->lydmods_lock);

    if (err_info) {
        goto cleanup;
    }

    /* get content-id */
    assert(!strcmp(LYD_NAME(lyd_child(sr_mods)), "content-id"));
    *cont_id = ((struct lyd_node_term *)lyd_child(sr_mods))->value.uint32;

cleanup:
    lyd_free_all(sr_mods);
    return err_info;
}

/**
 * @brief Check whether sysrepo module data file exists.
 *
 * @param[out] exists Whether the file exists.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_exists(int *exists)
{
    sr_error_info_t *err_info = NULL;
    char *path = NULL;

    /* get internal startup file path */
    if ((err_info = sr_path_startup_file(SR_YANG_MOD, &path))) {
        goto cleanup;
    }

    /* check the existence of the data file */
    if (access(path, F_OK) == -1) {
        if (errno != ENOENT) {
            SR_ERRINFO_SYSERRPATH(&err_info, "access", path);
            goto cleanup;
        }
        *exists = 0;
    } else {
        *exists = 1;
    }

cleanup:
    free(path);
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
    char *path;
    mode_t um;

    assert(sr_mods && *sr_mods && !strcmp((*sr_mods)->schema->module->name, SR_YANG_MOD));

    /* get the module */
    sr_ly_mod = (*sr_mods)->schema->module;

    /* validate */
    if (lyd_validate_module(sr_mods, sr_ly_mod, 0, NULL)) {
        sr_errinfo_new_ly(&err_info, sr_ly_mod->ctx);
        return err_info;
    }

    /* get path */
    if ((err_info = sr_path_startup_file(SR_YANG_MOD, &path))) {
        return err_info;
    }

    /* set umask so that the correct permissions are set in case this file does not exist */
    um = umask(SR_UMASK);

    /* store the data tree */
    if (lyd_print_path(path, *sr_mods, LYD_LYB, LYD_PRINT_WITHSIBLINGS)) {
        sr_errinfo_new_ly(&err_info, sr_ly_mod->ctx);
    }
    umask(um);
    free(path);

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

    SR_CHECK_INT_GOTO(lyd_find_xpath(sr_mod, xpath, &set), err_info, cleanup);
    if (set->count == 1) {
        /* already exists */
        goto cleanup;
    }
    assert(!set->count);

    /* RPC/notification with path */
    if (lyd_new_list(sr_mod, NULL, is_rpc ? "rpc" : "notification", 0, &sr_op_deps, data_path)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(sr_mod));
        goto cleanup;
    }

    /* collect dependencies of nested data and put them into correct containers */
    switch (op_root->nodetype) {
    case LYS_NOTIF:
        if (lyd_new_inner(sr_op_deps, NULL, "deps", 0, &ly_cur_deps)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(sr_op_deps));
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
        if (lyd_new_inner(sr_op_deps, NULL, "in", 0, &ly_cur_deps)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(sr_op_deps));
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
        if (lyd_new_inner(sr_op_deps, NULL, "out", 0, &ly_cur_deps)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(sr_op_deps));
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
 * @brief Add a dependency into internal sysrepo data.
 *
 * @param[in] sr_deps Internal sysrepo data dependencies to add to.
 * @param[in] dep_type Dependency type.
 * @param[in] mod_name Name of the module with the dependency.
 * @param[in] node Node causing the dependency.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_moddep_add(struct lyd_node *sr_deps, sr_dep_type_t dep_type, const char *mod_name, const struct lysc_node *node)
{
    const struct lysc_node *data_child;
    char *data_path = NULL, *expr = NULL;
    struct lyd_node *sr_instid;
    struct ly_set *set = NULL;
    sr_error_info_t *err_info = NULL;

    assert(((dep_type == SR_DEP_REF) && mod_name) || ((dep_type == SR_DEP_INSTID) && node));

    if (dep_type == SR_DEP_REF) {
        if (asprintf(&expr, "module[.='%s']", mod_name) == -1) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }
    } else {
        /* find the instance node(s) */
        switch (node->nodetype) {
        case LYS_LEAF:
        case LYS_LEAFLIST:
        case LYS_CONTAINER:
        case LYS_LIST:
        case LYS_ANYDATA:
        case LYS_ANYXML:
        case LYS_NOTIF:
            /* data-instantiable nodes, we are fine */
            break;
        case LYS_CHOICE:
        case LYS_CASE:
            /* not data-instantiable nodes, we need to find all such nodes */
            assert(dep_type != SR_DEP_INSTID);
            data_child = NULL;
            while ((data_child = lys_getnext(data_child, node, NULL, 0))) {
                if ((err_info = sr_lydmods_moddep_add(sr_deps, dep_type, mod_name, data_child))) {
                    goto cleanup;
                }
            }
            return NULL;
        default:
            SR_ERRINFO_INT(&err_info);
            goto cleanup;
        }

        /* create xpath of the node */
        data_path = lysc_path(node, LYSC_PATH_DATA, NULL, 0);
        if (!data_path || (asprintf(&expr, "inst-id[xpath='%s']", data_path) == -1)) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }
    }

    /* check that there is not a duplicity */
    if (lyd_find_xpath(sr_deps, expr, &set)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(sr_deps));
        goto cleanup;
    } else if (set->count > 1) {
        SR_ERRINFO_INT(&err_info);
        goto cleanup;
    } else if (set->count) {
        /* already exists */
        goto cleanup;
    }

    /* create new dependency */
    if (dep_type == SR_DEP_REF) {
        if (lyd_new_term(sr_deps, NULL, "module", mod_name, 0, NULL)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(sr_deps));
            goto cleanup;
        }
    } else {
        if (lyd_new_list(sr_deps, NULL, "inst-id", 0, &sr_instid, data_path)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(sr_deps));
            goto cleanup;
        }
        if (mod_name && lyd_new_term(sr_instid, NULL, "default-module", mod_name, 0, NULL)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(sr_deps));
            goto cleanup;
        }
    }

cleanup:
    ly_set_free(set, NULL);
    free(expr);
    free(data_path);
    return err_info;
}

/**
 * @brief Check whether an atom (node) is foreign with respect to the expression.
 *
 * @param[in] atom Node to check.
 * @param[in] top_node Top-level node for the expression.
 * @return Foreign dependency module, NULL if atom is not foreign.
 */
static struct lys_module *
sr_lydmods_moddep_expr_atom_is_foreign(const struct lysc_node *atom, const struct lysc_node *top_node)
{
    assert(atom && top_node && (!top_node->parent || (top_node->nodetype & (LYS_RPC | LYS_ACTION | LYS_NOTIF))));

    while (atom->parent && (atom != top_node)) {
        atom = atom->parent;
    }

    if (atom == top_node) {
        /* shared parent, local node */
        return NULL;
    }

    if (top_node->nodetype & (LYS_RPC | LYS_ACTION | LYS_NOTIF)) {
        /* outside operation, foreign node */
        return (struct lys_module *)atom->module;
    }

    if (atom->module != top_node->module) {
        /* foreing top-level node module (so cannot be augment), foreign node */
        return (struct lys_module *)atom->module;
    }

    /* same top-level modules, local node */
    return NULL;
}

/**
 * @brief Collect dependencies from an XPath expression atoms.
 *
 * @param[in] ctx_node Expression context node.
 * @param[in] atoms Set of atoms (schema nodes).
 * @param[out] dep_mods Array of dependent modules.
 * @param[out] dep_mod_count Dependent module count.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_moddep_atoms_get_dep_mods(const struct lysc_node *ctx_node, const struct ly_set *atoms,
        struct lys_module ***dep_mods, size_t *dep_mod_count)
{
    sr_error_info_t *err_info = NULL;
    const struct lysc_node *top_node;
    struct lys_module *dep_mod;
    size_t i, j;

    /* find out if we are in an operation, otherwise simply find top-level node */
    top_node = ctx_node;
    while (!(top_node->nodetype & (LYS_RPC | LYS_ACTION | LYS_NOTIF)) && top_node->parent) {
        top_node = top_node->parent;
    }

    /* find all top-level foreign nodes (augment nodes are not considered foreign now) */
    for (i = 0; i < atoms->count; ++i) {
        if ((dep_mod = sr_lydmods_moddep_expr_atom_is_foreign(atoms->snodes[i], top_node))) {
            /* check for duplicities */
            for (j = 0; j < *dep_mod_count; ++j) {
                if ((*dep_mods)[j] == dep_mod) {
                    break;
                }
            }

            /* add a new dependency module */
            if (j == *dep_mod_count) {
                *dep_mods = sr_realloc(*dep_mods, (*dep_mod_count + 1) * sizeof **dep_mods);
                if (!*dep_mods) {
                    *dep_mod_count = 0;
                    SR_ERRINFO_MEM(&err_info);
                    return err_info;
                }

                (*dep_mods)[*dep_mod_count] = dep_mod;
                ++(*dep_mod_count);
            }
        }
    }

    /* success */
    return NULL;
}

/**
 * @brief Collect dependencies from a type.
 *
 * @param[in] type Type to inspect.
 * @param[in] node Type node.
 * @param[in] sr_deps Internal sysrepo data dependencies to add to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_moddep_type(const struct lysc_type *type, const struct lysc_node *node, struct lyd_node *sr_deps)
{
    sr_error_info_t *err_info = NULL;
    const struct lysc_type_union *uni;
    const struct lysc_type_leafref *lref;
    struct ly_set *atoms;
    LY_ARRAY_COUNT_TYPE u;
    struct lys_module **dep_mods = NULL;
    size_t dep_mod_count = 0;

    switch (type->basetype) {
    case LY_TYPE_INST:
        if ((node->nodetype == LYS_LEAF) && ((struct lysc_node_leaf *)node)->dflt) {
            if (lys_find_lypath_atoms(((struct lysc_node_leaf *)node)->dflt->target, &atoms)) {
                SR_ERRINFO_MEM(&err_info);
                return err_info;
            }
            err_info = sr_lydmods_moddep_atoms_get_dep_mods(node, atoms, &dep_mods, &dep_mod_count);
            ly_set_free(atoms, NULL);
            if (err_info) {
                return err_info;
            }
            assert(dep_mod_count < 2);
        }

        err_info = sr_lydmods_moddep_add(sr_deps, SR_DEP_INSTID, (dep_mod_count ? dep_mods[0]->name : NULL), node);
        free(dep_mods);
        if (err_info) {
            return err_info;
        }
        break;
    case LY_TYPE_LEAFREF:
        lref = (struct lysc_type_leafref *)type;
        if (lys_find_expr_atoms(node, node->module, lref->path, lref->prefixes, 0, &atoms)) {
            sr_errinfo_new_ly(&err_info, node->module->ctx);
            return err_info;
        }
        err_info = sr_lydmods_moddep_atoms_get_dep_mods(node, atoms, &dep_mods, &dep_mod_count);
        ly_set_free(atoms, NULL);
        if (err_info) {
            return err_info;
        }
        assert(dep_mod_count < 2);

        if (dep_mod_count) {
            /* a foregin module is referenced */
            err_info = sr_lydmods_moddep_add(sr_deps, SR_DEP_REF, dep_mods[0]->name, NULL);
            free(dep_mods);
            if (err_info) {
                return err_info;
            }
        }
        break;
    case LY_TYPE_UNION:
        uni = (struct lysc_type_union *)type;
        LY_ARRAY_FOR(uni->types, u) {
            if ((err_info = sr_lydmods_moddep_type(uni->types[u], node, sr_deps))) {
                return err_info;
            }
        }
        break;
    default:
        /* no dependency */
        break;
    }

    return NULL;
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
    struct lys_module **dep_mods = NULL;
    size_t dep_mod_count = 0;
    struct ly_set *atoms;
    struct lysc_type *type = NULL;
    struct lysc_when **when = NULL;
    struct lysc_must *musts = NULL;
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

    /* collect the dependencies */
    if (type) {
        if ((err_info = sr_lydmods_moddep_type(type, node, arg->sr_deps))) {
            goto cleanup;
        }
    }
    LY_ARRAY_FOR(when, u) {
        if (lys_find_expr_atoms(when[u]->context, node->module, when[u]->cond, when[u]->prefixes, atom_opts, &atoms)) {
            sr_errinfo_new_ly(&err_info, node->module->ctx);
            goto cleanup;
        }
        err_info = sr_lydmods_moddep_atoms_get_dep_mods(node, atoms, &dep_mods, &dep_mod_count);
        ly_set_free(atoms, NULL);
        if (err_info) {
            goto cleanup;
        }
    }
    LY_ARRAY_FOR(musts, u) {
        if (lys_find_expr_atoms(node, node->module, musts[u].cond, musts[u].prefixes, atom_opts, &atoms)) {
            sr_errinfo_new_ly(&err_info, node->module->ctx);
            goto cleanup;
        }
        err_info = sr_lydmods_moddep_atoms_get_dep_mods(node, atoms, &dep_mods, &dep_mod_count);
        ly_set_free(atoms, NULL);
        if (err_info) {
            goto cleanup;
        }
    }

    /* add those collected from when and must */
    for (u = 0; u < dep_mod_count; ++u) {
        if ((err_info = sr_lydmods_moddep_add(arg->sr_deps, SR_DEP_REF, dep_mods[u]->name, NULL))) {
            goto cleanup;
        }
    }

cleanup:
    free(dep_mods);
    if (err_info) {
        arg->err_info = err_info;
        return LY_EOTHER;
    }
    return LY_SUCCESS;
}

/**
 * @brief Add module into sysrepo module data.
 *
 * @param[in] sr_mods Sysrepo module data.
 * @param[in] ly_mod Module to add.
 * @param[out] sr_mod_p Added module.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_add_module(struct lyd_node *sr_mods, const struct lys_module *ly_mod, struct lyd_node **sr_mod_p)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mod;
    struct lysp_feature *f = NULL;
    uint32_t i = 0;

    if (lyd_new_list(sr_mods, NULL, "module", 0, &sr_mod, ly_mod->name)) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        return err_info;
    }
    if (ly_mod->revision && lyd_new_term(sr_mod, NULL, "revision", ly_mod->revision, 0, NULL)) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        return err_info;
    }

    /* enable all the features */
    while ((f = lysp_feature_next(f, ly_mod->parsed, &i))) {
        if (f->flags & LYS_FENABLED) {
            if (lyd_new_term(sr_mod, NULL, "enabled-feature", f->name, 0, NULL)) {
                sr_errinfo_new_ly(&err_info, ly_mod->ctx);
                return err_info;
            }
        }
    }

    if (sr_mod_p) {
        *sr_mod_p = sr_mod;
    }
    return NULL;
}

/**
 * @brief Add module and all of its implemented imports into sysrepo module data (if not there already), recursively.
 * All new modules have their data files created and YANG modules stored as well.
 *
 * @param[in] sr_mods Internal sysrepo data.
 * @param[in] ly_mod Module with implemented imports to add.
 * @param[in] log_first If set to 0, nothing will be logged on success. Set to 2 to log installing module
 * and its dependencies.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_add_module_with_imps_r(struct lyd_node *sr_mods, const struct lys_module *ly_mod, int log_first)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mod;
    const struct lysp_submodule *lysp_submod;
    struct ly_set *set = NULL;
    char *xpath = NULL;
    LY_ARRAY_COUNT_TYPE i, j;

    if ((err_info = sr_store_module_files(ly_mod))) {
        goto cleanup;
    }

    if (ly_mod->implemented) {
        /* check the module was not already added */
        if (asprintf(&xpath, "module[name='%s']", ly_mod->name) == -1) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }
        if (lyd_find_xpath(sr_mods, xpath, &set)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(sr_mods));
            goto cleanup;
        } else if (!set->count) {
            /* install the module and create its startup data file */
            if ((err_info = sr_lydmods_add_module(sr_mods, ly_mod, &sr_mod))) {
                goto cleanup;
            }
            if ((err_info = sr_create_startup_file(ly_mod))) {
                goto cleanup;
            }
            if (log_first == 2) {
                SR_LOG_INF("Module \"%s\" was installed.", ly_mod->name);

                /* the rest of the modules will be dependencies */
                --log_first;
            } else if (log_first == 1) {
                SR_LOG_INF("Dependency module \"%s\" was installed.", ly_mod->name);
            }
        } /* else module has already been added */
    }

    /* all newly implemented modules will be added also from imports and includes, recursively */
    LY_ARRAY_FOR(ly_mod->parsed->imports, i) {
        if ((err_info = sr_lydmods_add_module_with_imps_r(sr_mods, ly_mod->parsed->imports[i].module, log_first))) {
            goto cleanup;
        }
    }

    LY_ARRAY_FOR(ly_mod->parsed->includes, i) {
        lysp_submod = ly_mod->parsed->includes[i].submodule;
        LY_ARRAY_FOR(lysp_submod->imports, j) {
            if ((err_info = sr_lydmods_add_module_with_imps_r(sr_mods, lysp_submod->imports[j].module, log_first))) {
                goto cleanup;
            }
        }
    }

cleanup:
    free(xpath);
    ly_set_free(set, NULL);
    return err_info;
}

/**
 * @brief libyang import callback to provide internal non-implemented dependencies.
 */
static LY_ERR
sr_ly_nacm_module_imp_clb(const char *mod_name, const char *mod_rev, const char *submod_name, const char *submod_rev,
        void *user_data, LYS_INFORMAT *format, const char **module_data, ly_module_imp_data_free_clb *free_module_data)
{
    (void)mod_rev;
    (void)submod_name;
    (void)submod_rev;
    (void)user_data;

    if (!strcmp(mod_name, "ietf-netconf-acm")) {
        *format = LYS_IN_YANG;
        *module_data = ietf_netconf_acm_yang;
        *free_module_data = NULL;
        return LY_SUCCESS;
    }

    return LY_ENOT;
}

/**
 * @brief Create default sysrepo module data. All libyang internal implemented modules
 * are installed into sysrepo. Sysrepo internal modules ietf-netconf, ietf-netconf-with-defaults,
 * and ietf-netconf-notifications are also installed.
 *
 * @param[in,out] ly_ctx Context to initialize according to the default created sr_mods.
 * @param[in] sr_mods_ctx Context to parse @p sr_mods_p in.
 * @param[out] sr_mods_p Created default sysrepo module data.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_create(struct ly_ctx *ly_ctx, const struct ly_ctx *sr_mods_ctx, struct lyd_node **sr_mods_p)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    struct lyd_node *sr_mods = NULL;
    uint32_t i;

#define SR_INSTALL_INT_MOD(ctx, yang_mod, dep) \
    if (lys_parse_mem(ctx, yang_mod, LYS_IN_YANG, &ly_mod)) { \
        sr_errinfo_new_ly(&err_info, ctx); \
        goto error; \
    } \
    if ((err_info = sr_lydmods_add_module_with_imps_r(sr_mods, ly_mod, 0))) { \
        goto error; \
    } \
    SR_LOG_INF("Sysrepo internal%s module \"%s\" was installed.", dep ? " dependency" : "", ly_mod->name)

    ly_mod = ly_ctx_get_module_implemented(sr_mods_ctx, SR_YANG_MOD);
    SR_CHECK_INT_RET(!ly_mod, err_info);

    /* create empty container */
    SR_CHECK_INT_RET(lyd_new_inner(NULL, ly_mod, "sysrepo-modules", 0, &sr_mods), err_info);

    /* add content-id */
    SR_CHECK_INT_RET(lyd_new_term(sr_mods, NULL, "content-id", "1", 0, NULL), err_info);

    /* for internal libyang modules create files and store in the persistent module data tree */
    i = 0;
    while ((i < ly_ctx_internal_modules_count(ly_ctx)) && (ly_mod = ly_ctx_get_module_iter(ly_ctx, &i))) {
        /* module must be implemented */
        if (ly_mod->implemented) {
            if ((err_info = sr_lydmods_add_module_with_imps_r(sr_mods, ly_mod, 0))) {
                goto error;
            }
            SR_LOG_INF("Libyang internal module \"%s\" was installed.", ly_mod->name);
        }
    }

    /* install ietf-datastores and ietf-yang-library */
    SR_INSTALL_INT_MOD(ly_ctx, ietf_datastores_yang, 1);
    SR_INSTALL_INT_MOD(ly_ctx, ietf_yang_library_yang, 0);

    /* install sysrepo-monitoring */
    SR_INSTALL_INT_MOD(ly_ctx, sysrepo_monitoring_yang, 0);

    /* install sysrepo-plugind */
    SR_INSTALL_INT_MOD(ly_ctx, sysrepo_plugind_yang, 0);

    /* make sure ietf-netconf-acm is found as an import */
    ly_ctx_set_module_imp_clb(ly_ctx, sr_ly_nacm_module_imp_clb, NULL);

    /* install ietf-netconf (implemented dependency) and ietf-netconf-with-defaults */
    SR_INSTALL_INT_MOD(ly_ctx, ietf_netconf_yang, 1);
    SR_INSTALL_INT_MOD(ly_ctx, ietf_netconf_with_defaults_yang, 0);

    ly_ctx_set_module_imp_clb(ly_ctx, NULL, NULL);

    /* install ietf-netconf-notifications */
    SR_INSTALL_INT_MOD(ly_ctx, ietf_netconf_notifications_yang, 0);

    /* install ietf-origin */
    SR_INSTALL_INT_MOD(ly_ctx, ietf_origin_yang, 0);

    *sr_mods_p = sr_mods;
    return NULL;

error:
    lyd_free_all(sr_mods);
    return err_info;

#undef SR_INSTALL_INT_MOD
}

/**
 * @brief Update feature set based on scheduled feature changes.
 *
 * @param[in] sr_mod Module from sysrepo module data to use.
 * @param[in,out] feat_set Current features to be enabled, is updated.
 * @param[out] change Whether any features were changed.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_sched_change_features(const struct lyd_node *sr_mod, struct ly_set **feat_set, int *change)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node_inner *inner;
    struct ly_set *set = NULL;
    const char *feat_name;
    uint32_t i, j;
    int enable;

    assert(sr_mod);

    /* find all changed features of the particular module */
    if (lyd_find_xpath(sr_mod, "changed-feature", &set)) {
        SR_ERRINFO_INT(&err_info);
        return err_info;
    } else if (!set->count) {
        /* no changed features */
        goto cleanup;
    }

    /* update the feature set */
    for (i = 0; i < set->count; ++i) {
        inner = set->objs[i];
        assert(!strcmp(inner->child->schema->name, "name"));
        feat_name = lyd_get_value(inner->child);
        assert(!strcmp(inner->child->next->schema->name, "change"));
        enable = !strcmp(lyd_get_value(inner->child->next), "enable") ? 1 : 0;

        if (enable) {
            if (!*feat_set && ly_set_new(feat_set)) {
                SR_ERRINFO_MEM(&err_info);
                goto cleanup;
            }

            /* add the feature into the set */
            if (ly_set_add(*feat_set, inner->child, 1, NULL)) {
                SR_ERRINFO_MEM(&err_info);
                goto cleanup;
            }
        } else {
            /* remove the disabled feature */
            for (j = 0; *feat_set && (j < (*feat_set)->count); ++j) {
                if (lyd_get_value((*feat_set)->dnodes[j]) == feat_name) {
                    break;
                }
            }
            if (!*feat_set || (j == (*feat_set)->count)) {
                SR_ERRINFO_INT(&err_info);
                goto cleanup;
            }
            ly_set_rm_index(*feat_set, j, NULL);
        }
    }

    /* success */
    if (change) {
        *change = 1;
    }

cleanup:
    ly_set_free(set, NULL);
    return err_info;
}

/**
 * @brief Generate an array of features terminated with NULL from set with data nodes with feature names as values.
 *
 * @param[in] feat_set Set with the data nodes.
 * @param[out] features Array of features.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_features_array(const struct ly_set *feat_set, const char ***features)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;

    if (!feat_set->count) {
        *features = NULL;
        return NULL;
    }

    *features = malloc((feat_set->count + 1) * sizeof **features);
    if (!*features) {
        SR_ERRINFO_MEM(&err_info);
        return err_info;
    }

    for (i = 0; i < feat_set->count; ++i) {
        (*features)[i] = lyd_get_value(feat_set->dnodes[i]);
    }
    (*features)[i] = NULL;

    return NULL;
}

/**
 * @brief Load a module into context (if not already there) based on its information from sysrepo module data.
 *
 * @param[in] sr_mod Module from sysrepo module data to load.
 * @param[in] ly_ctx Context to load the module into.
 * @param[in] sched_features Whether to load the module with schedule feature changes applied.
 * @param[out] ly_mod_p Optionally return the loaded module.
 * @param[out] change Whether there were any changed features.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_ctx_load_module(const struct lyd_node *sr_mod, struct ly_ctx *ly_ctx, int sched_features,
        const struct lys_module **ly_mod_p, int *change)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *node;
    const struct lys_module *ly_mod = NULL;
    struct ly_set *feat_set = NULL;
    const char *mod_name, *revision, **features = NULL;

    /* if ly_ctx is recompiled, sr_mod becomes invalid */
    assert(LYD_CTX(sr_mod) != ly_ctx);

    /* learn about the module */
    mod_name = NULL;
    revision = NULL;
    LY_LIST_FOR(lyd_child(sr_mod), node) {
        if (!strcmp(node->schema->name, "name")) {
            mod_name = lyd_get_value(node);
        } else if (!strcmp(node->schema->name, "revision")) {
            revision = lyd_get_value(node);
            break;
        }
    }
    assert(mod_name);

    /* collect all currently enabled features */
    if (lyd_find_xpath(sr_mod, "enabled-feature", &feat_set)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(sr_mod));
        goto cleanup;
    }

    if (sched_features) {
        /* change features according to the changes in lydmods data */
        if ((err_info = sr_lydmods_sched_change_features(sr_mod, &feat_set, change))) {
            goto cleanup;
        }
    }

    /* get feature array */
    if ((err_info = sr_lydmods_features_array(feat_set, &features))) {
        goto cleanup;
    }

    /* get/load the module (the module is not supposed to be loaded yet, but is in case of LY internal modules
     * and dependency modules) */
    ly_mod = ly_ctx_load_module(ly_ctx, mod_name, revision, features);
    if (!ly_mod) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    /* success */

cleanup:
    free(features);
    ly_set_free(feat_set, NULL);
    if (!err_info && ly_mod_p) {
        *ly_mod_p = ly_mod;
    }
    return err_info;
}

sr_error_info_t *
sr_lydmods_ctx_load_modules(const struct lyd_node *sr_mods, struct ly_ctx *ly_ctx, int removed, int updated,
        int sched_features, int *change)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mod, *node;

    LY_LIST_FOR(lyd_child(sr_mods), sr_mod) {
        if (strcmp(sr_mod->schema->name, "module")) {
            continue;
        }
        if (!removed || !updated) {
            LY_LIST_FOR(lyd_child(sr_mod), node) {
                /* check that the module was not removed or updated */
                if (!removed && !strcmp(node->schema->name, "removed")) {
                    break;
                } else if (!updated && !strcmp(node->schema->name, "updated-yang")) {
                    break;
                }
            }
            if (node) {
                if (change) {
                    *change = 1;
                }
                continue;
            }
        }

        /* load the module */
        if ((err_info = sr_lydmods_ctx_load_module(sr_mod, ly_ctx, sched_features, NULL, change))) {
            return err_info;
        }
    }

    return NULL;
}

/**
 * @brief Append startup and running data by implemented modules from context.
 *
 * @param[in] ctx Context containing modules.
 * @param[out] start_data Startup data tree.
 * @param[out] run_data Running data tree.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_append_startup_and_running_data(const struct ly_ctx *ctx, struct lyd_node **start_data, struct lyd_node **run_data)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    uint32_t idx = 0;
    int exists;
    char *path;

    while ((ly_mod = ly_ctx_get_module_iter(ctx, &idx))) {
        if (!ly_mod->implemented) {
            /* we need data of only implemented modules */
            continue;
        }

        /* append startup data */
        if ((err_info = sr_module_file_data_append(ly_mod, SR_DS_STARTUP, start_data))) {
            break;
        }

        /* check that running data file exists */
        if ((err_info = sr_path_ds_shm(ly_mod->name, SR_DS_RUNNING, &path))) {
            break;
        }
        exists = sr_file_exists(path);
        free(path);

        if (exists) {
            /* append running data */
            if ((err_info = sr_module_file_data_append(ly_mod, SR_DS_RUNNING, run_data))) {
                break;
            }
        }
    }

    return err_info;
}

/**
 * @brief Iterate over modules from @p old_ctx and find those that have the same name as in @p new_ctx.
 *
 * @param[in] old_ctx Iterated context.
 * @param[in] new_ctx Context to compare.
 * @param[out] intersection_set Set that will contain modules that are in both @p old_ctx and @p new_ctx.
 * @param[out] old_ctx_complement_set Set that will contain modules which were not found in @p new_ctx.
 */
static void
sr_get_same_modules_by_name(const struct ly_ctx *old_ctx, const struct ly_ctx *new_ctx,
        struct ly_set *intersection_set, struct ly_set *old_ctx_complement_set)
{
    const struct lys_module *old_ly_mod, *new_ly_mod;
    uint32_t idx = 0;

    assert(intersection_set && old_ctx_complement_set);

    while ((old_ly_mod = ly_ctx_get_module_iter(old_ctx, &idx))) {
        if (!old_ly_mod->implemented) {
            /* we need data of only implemented modules */
            continue;
        }

        new_ly_mod = ly_ctx_get_module_implemented(new_ctx, old_ly_mod->name);
        if (new_ly_mod) {
            /* remember this module from the new context */
            ly_set_add(intersection_set, (void *)new_ly_mod, 1, NULL);
        } else {
            /* module was removed, remember it as well */
            ly_set_add(old_ctx_complement_set, (void *)old_ly_mod, 1, NULL);
        }
    }
}

/**
 * @brief Update data parsed with old context to be parsed with a new context.
 *
 * @param[in] sr_mods Sysrepo module data.
 * @param[in] old_ctx Old context.
 * @param[in] old_start_data Startup data tree from @p old_ctx.
 * @param[in] old_run_data Running data tree from @p old_ctx.
 * @param[in] new_ctx New context.
 * @param[out] new_start_data Startup data tree from @p new_ctx.
 * @param[out] new_run_data Running data tree from @p new_ctx.
 * @param[out] mod_set Set of modules that are in either @p new_start_data or @p new_run_data.
 * @param[out] fail Whether any data failed to be parsed.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_update_data(const struct lyd_node *sr_mods,
        const struct ly_ctx *old_ctx, const struct lyd_node *old_start_data, const struct lyd_node *old_run_data,
        const struct ly_ctx *new_ctx, struct lyd_node **new_start_data, struct lyd_node **new_run_data,
        struct ly_set *mod_set, int *fail)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *mod_data;
    struct ly_set *startup_set = NULL;
    char *start_data_json = NULL, *run_data_json = NULL;
    uint32_t idx;

    /* print the data of all the modules into JSON */
    if (lyd_print_mem(&start_data_json, old_start_data, LYD_JSON, LYD_PRINT_SHRINK | LYD_PRINT_WITHSIBLINGS)) {
        sr_errinfo_new_ly(&err_info, old_ctx);
        return err_info;
    }
    if (lyd_print_mem(&run_data_json, old_run_data, LYD_JSON, LYD_PRINT_SHRINK | LYD_PRINT_WITHSIBLINGS)) {
        sr_errinfo_new_ly(&err_info, old_ctx);
        return err_info;
    }

    /* try to load it into the new updated context skipping any unknown nodes */
    if (lyd_parse_data_mem(new_ctx, start_data_json, LYD_JSON, LYD_PARSE_NO_STATE | LYD_PARSE_ONLY, 0, new_start_data)) {
        /* it failed, some of the scheduled changes are not compatible with the stored data, abort them all */
        sr_log_wrn_ly(new_ctx);
        *fail = 1;
        goto cleanup;
    }
    if (lyd_parse_data_mem(new_ctx, run_data_json, LYD_JSON, LYD_PARSE_NO_STATE | LYD_PARSE_ONLY, 0, new_run_data)) {
        sr_log_wrn_ly(new_ctx);
        *fail = 1;
        goto cleanup;
    }

    if (lyd_find_xpath(sr_mods, "installed-module/data", &startup_set)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(sr_mods));
        goto cleanup;
    }
    for (idx = 0; idx < startup_set->count; ++idx) {
        /* this was parsed before */
        lyd_parse_data_mem(new_ctx, lyd_get_value(startup_set->dnodes[idx]), LYD_JSON,
                LYD_PARSE_NO_STATE | LYD_PARSE_STRICT | LYD_PARSE_ONLY, 0, &mod_data);
        if (!mod_data) {
            continue;
        }

        /* remember this module */
        ly_set_add(mod_set, (void *)lyd_owner_module(mod_data), 1, NULL);

        /* link to the new startup/running data */
        if (!(*new_start_data)) {
            if (lyd_dup_siblings(mod_data, NULL, LYD_DUP_RECURSIVE | LYD_DUP_WITH_FLAGS, new_start_data)) {
                SR_ERRINFO_MEM(&(err_info));
                break;
            }
        } else if (lyd_merge_siblings(new_start_data, mod_data, 0)) {
            sr_errinfo_new_ly(&err_info, new_ctx);
            break;
        }
        if (!(*new_run_data)) {
            *new_run_data = mod_data;
        } else if (lyd_merge_siblings(new_run_data, mod_data, LYD_MERGE_DESTRUCT)) {
            sr_errinfo_new_ly(&err_info, new_ctx);
            break;
        }
    }

cleanup:
    ly_set_free(startup_set, NULL);
    free(start_data_json);
    free(run_data_json);
    return err_info;
}

/**
 * @brief Learn whether any module in a set augments/deviates a specific module.
 *
 * @param[in] old_base_mod Module that can be augmented/deviated.
 * @param[in] old_mod_set Set with modules possibly augmenting/deviating @p old_base_mod.
 * @return Whether any module in @p old_mod_set was augmenting/deviating @p old_base_mod.
 */
static int
sr_contains_dev_aug_module(const struct lys_module *old_base_mod, const struct ly_set *old_mod_set)
{
    const struct lys_module *old_mod;
    uint32_t i;
    LY_ARRAY_COUNT_TYPE u;

    for (i = 0; i < old_mod_set->count; ++i) {
        old_mod = old_mod_set->objs[i];

        /* deviates */
        LY_ARRAY_FOR(old_base_mod->deviated_by, u) {
            if (old_base_mod->deviated_by[u] == old_mod) {
                return 1;
            }
        }

        /* augments */
        LY_ARRAY_FOR(old_base_mod->augmented_by, u) {
            if (old_base_mod->augmented_by[u] == old_mod) {
                return 1;
            }
        }
    }

    return 0;
}

/**
 * @brief Print data if they differ, are completely new, or their LYB metadata differ (augment/deviation module was removed).
 * Is evaluated for each module data separately.
 *
 * @param[in] mod_set Set of investigated modules.
 * @param[in] del_mod_set Set of modules that are not in a @p new_ctx.
 * @param[in] old_ctx Context before scheduled changes.
 * @param[in,out] old_start_data Startup data tree from @p old_ctx.
 * @param[in,out] old_run_data Running data tree from @p old_ctx.
 * @param[in] new_ctx Context with all scheduled module changes.
 * @param[in,out] new_start_data Startup data tree from @p new_ctx.
 * @param[in,out] new_run_data Running data tree from @p new_ctx.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_print_data_if_differ(const struct ly_set *mod_set, const struct ly_set *del_mod_set,
        const struct ly_ctx *old_ctx, struct lyd_node **old_start_data, struct lyd_node **old_run_data,
        const struct ly_ctx *new_ctx, struct lyd_node **new_start_data, struct lyd_node **new_run_data)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *new_ly_mod, *old_ly_mod;
    struct lyd_node *new_mod_data = NULL, *old_mod_data = NULL;
    uint32_t idx;
    int store_data;
    LY_ERR lyrc;

    for (idx = 0; idx < mod_set->count; ++idx) {
        new_ly_mod = (struct lys_module *)mod_set->objs[idx];
        old_ly_mod = ly_ctx_get_module_implemented(old_ctx, new_ly_mod->name);

        if (!old_ly_mod) {
            /* module was added, we always want to store its data */
            store_data = 1;
        } else {
            /* check whether a removed module was not augmenting/deviating this module,
             * if it was, we must always write the data because their metadata changed */
            store_data = sr_contains_dev_aug_module(old_ly_mod, del_mod_set);
        }

        /* startup data */
        lyd_free_siblings(new_mod_data);
        lyd_free_siblings(old_mod_data);
        new_mod_data = sr_module_data_unlink(new_start_data, new_ly_mod);
        if (old_ly_mod) {
            old_mod_data = sr_module_data_unlink(old_start_data, old_ly_mod);
        } else {
            old_mod_data = NULL;
        }

        if (!store_data) {
            lyrc = lyd_compare_siblings(new_mod_data, old_mod_data, LYD_COMPARE_FULL_RECURSION | LYD_COMPARE_DEFAULTS);
            if (lyrc == LY_ENOT) {
                store_data = 1;
            } else if (lyrc) {
                sr_errinfo_new_ly(&err_info, new_ctx);
                break;
            }
        }
        if (store_data) {
            if ((err_info = sr_module_file_data_set(new_ly_mod->name, SR_DS_STARTUP, new_mod_data, O_CREAT, SR_FILE_PERM))) {
                break;
            }
        }

        /* running data */
        lyd_free_siblings(new_mod_data);
        lyd_free_siblings(old_mod_data);
        new_mod_data = sr_module_data_unlink(new_run_data, new_ly_mod);
        if (old_ly_mod) {
            old_mod_data = sr_module_data_unlink(old_run_data, old_ly_mod);
        } else {
            old_mod_data = NULL;
        }

        if (!store_data) {
            lyrc = lyd_compare_siblings(new_mod_data, old_mod_data, LYD_COMPARE_FULL_RECURSION | LYD_COMPARE_DEFAULTS);
            if (lyrc == LY_ENOT) {
                store_data = 1;
            } else if (lyrc) {
                sr_errinfo_new_ly(&err_info, new_ctx);
                break;
            }
        }
        if (store_data) {
            if ((err_info = sr_module_file_data_set(new_ly_mod->name, SR_DS_RUNNING, new_mod_data, O_CREAT, SR_FILE_PERM))) {
                break;
            }
        }
    }
    lyd_free_siblings(new_mod_data);
    lyd_free_siblings(old_mod_data);
    return err_info;
}

/**
 * @brief Check that persistent (startup) module data can be loaded into updated context.
 * On success print the new updated LYB data.
 *
 * @param[in] sr_mods Sysrepo module data.
 * @param[in] new_ctx Context with all scheduled module changes.
 * @param[out] fail Whether any data failed to be parsed.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_sched_update_data(const struct lyd_node *sr_mods, const struct ly_ctx *new_ctx, int *fail)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *old_start_data = NULL, *new_start_data = NULL, *old_run_data = NULL, *new_run_data = NULL;
    struct ly_ctx *old_ctx = NULL;
    struct ly_set *mod_set = NULL, *del_mod_set = NULL;

    SR_CHECK_MEM_GOTO(ly_set_new(&mod_set), err_info, cleanup);
    SR_CHECK_MEM_GOTO(ly_set_new(&del_mod_set), err_info, cleanup);

    /* first build context without any scheduled changes */
    if ((err_info = sr_ly_ctx_new(&old_ctx))) {
        goto cleanup;
    }
    if ((err_info = sr_lydmods_ctx_load_modules(sr_mods, old_ctx, 1, 1, 0, NULL))) {
        goto cleanup;
    }

    /* parse all the startup/running data using the old context (that must succeed) */
    if ((err_info = sr_append_startup_and_running_data(old_ctx, &old_start_data, &old_run_data))) {
        goto cleanup;
    }
    sr_get_same_modules_by_name(old_ctx, new_ctx, mod_set, del_mod_set);

    /* update all the data for the new context */
    if ((err_info = sr_update_data(sr_mods, old_ctx, old_start_data, old_run_data, new_ctx, &new_start_data,
            &new_run_data, mod_set, fail))) {
        goto cleanup;
    }

    /* fully validate complete startup and running datastore */
    if (lyd_validate_all(&new_start_data, new_ctx, LYD_VALIDATE_NO_STATE, NULL) ||
            lyd_validate_all(&new_run_data, new_ctx, LYD_VALIDATE_NO_STATE, NULL)) {
        sr_log_wrn_ly(new_ctx);
        *fail = 1;
        goto cleanup;
    }

    /* print all modules data with the updated module context if the new data is different from the old one */
    if ((err_info = sr_print_data_if_differ(mod_set, del_mod_set, old_ctx, &old_start_data, &old_run_data, new_ctx,
            &new_start_data, &new_run_data))) {
        goto cleanup;
    }

    /* success */

cleanup:
    ly_set_free(mod_set, NULL);
    ly_set_free(del_mod_set, NULL);
    lyd_free_siblings(old_start_data);
    lyd_free_siblings(new_start_data);
    lyd_free_siblings(old_run_data);
    lyd_free_siblings(new_run_data);
    ly_ctx_destroy(old_ctx);
    if (err_info) {
        sr_errinfo_new(&err_info, SR_ERR_OPERATION_FAILED, "Failed to update data for the new context.");
    }
    return err_info;
}

/**
 * @brief Finalize applying scheduled module removal. Meaning remove its data files
 * and module file in case it is not imported by other modules.
 *
 * @param[in] sr_mod Sysrepo module to remove. Will be freed.
 * @param[in] new_ctx Context with the new modules.
 * @param[in] update Whether this function is called from module update or module removal.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_sched_finalize_module_remove(struct lyd_node *sr_mod, const struct ly_ctx *new_ctx, int update)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    const char *mod_name, *mod_rev;
    struct lyd_node *child;
    uint32_t idx;
    LY_ARRAY_COUNT_TYPE u;

    child = lyd_child(sr_mod);
    assert(!strcmp(child->schema->name, "name"));
    mod_name = lyd_get_value(child);
    if (child->next && !strcmp(child->next->schema->name, "revision")) {
        mod_rev = lyd_get_value(child->next);
    } else {
        mod_rev = NULL;
    }

    /* remove data files */
    if (!update && (err_info = sr_remove_data_files(mod_name))) {
        return err_info;
    }

    /* check whether it is imported by other modules */
    idx = ly_ctx_internal_modules_count(new_ctx);
    while ((ly_mod = ly_ctx_get_module_iter(new_ctx, &idx))) {
        LY_ARRAY_FOR(ly_mod->parsed->imports, u) {
            if (!strcmp(ly_mod->parsed->imports[u].module->name, mod_name)) {
                break;
            }
        }
        if (ly_mod->parsed->imports && (u < LY_ARRAY_COUNT(ly_mod->parsed->imports))) {
            break;
        }
    }
    if (!ly_mod) {
        /* no module imports the removed one, remove the YANG as well */
        if ((err_info = sr_remove_module_file(mod_name, mod_rev))) {
            return err_info;
        }
    }

    if (!update) {
        SR_LOG_INF("Module \"%s\" was removed.", mod_name);
    }

    /* remove module list instance */
    lyd_free_tree(sr_mod);
    return NULL;
}

/**
 * @brief Finalize applying scheduled module update.
 *
 * @param[in] sr_mod Sysrepo module to update. Will be freed.
 * @param[in] new_ctx Context with the updated module loaded.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_sched_finalize_module_update(struct lyd_node *sr_mod, const struct ly_ctx *new_ctx)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    struct lyd_node *sr_mods;

    sr_mods = lyd_parent(sr_mod);

    /* find the updated module in the new context */
    assert(!strcmp(lyd_child(sr_mod)->schema->name, "name"));
    ly_mod = ly_ctx_get_module_implemented(new_ctx, SR_LY_CHILD_VALUE(sr_mod));
    assert(ly_mod);

    /* remove module */
    if ((err_info = sr_lydmods_sched_finalize_module_remove(sr_mod, new_ctx, 1))) {
        return err_info;
    }

    /* re-add it (only the data files are kept) */
    if ((err_info = sr_lydmods_add_module_with_imps_r(sr_mods, ly_mod, 0))) {
        return err_info;
    }

    SR_LOG_INF("Module \"%s\" was updated to revision %s.", ly_mod->name, ly_mod->revision);
    return NULL;
}

/**
 * @brief Finalize applying scheduled module feature changes.
 *
 * @param[in] sr_mod Sysrepo module with feature changes.
 * @param[in] new_ctx Context with new modules used for printing them.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_sched_finalize_module_change_features(struct lyd_node *sr_mod, const struct ly_ctx *new_ctx)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    const char *feat_name;
    struct lyd_node *next, *node;
    struct lyd_node_inner *inner;
    struct ly_set *set;
    int enable;
    char *xpath;
    LY_ERR lyrc;

    assert(!strcmp(lyd_child(sr_mod)->schema->name, "name"));
    ly_mod = ly_ctx_get_module_implemented(new_ctx, SR_LY_CHILD_VALUE(sr_mod));
    assert(ly_mod);

    LY_LIST_FOR_SAFE(lyd_child(sr_mod)->next, next, node) {
        if (!strcmp(node->schema->name, "changed-feature")) {
            /*
             * changed feature
             */
            inner = (struct lyd_node_inner *)node;
            assert(!strcmp(inner->child->schema->name, "name"));
            assert(!strcmp(inner->child->next->schema->name, "change"));

            feat_name = lyd_get_value(inner->child);
            enable = !strcmp(lyd_get_value(inner->child->next), "enable") ? 1 : 0;

            /* update internal sysrepo data tree */
            if (enable) {
                if (lyd_new_path(sr_mod, NULL, "enabled-feature", (void *)feat_name, 0, NULL)) {
                    sr_errinfo_new_ly(&err_info, LYD_CTX(sr_mod));
                    return err_info;
                }
            } else {
                if (asprintf(&xpath, "enabled-feature[.='%s']", feat_name) == -1) {
                    SR_ERRINFO_MEM(&err_info);
                    return err_info;
                }
                lyrc = lyd_find_xpath(sr_mod, xpath, &set);
                free(xpath);
                if (lyrc) {
                    sr_errinfo_new_ly(&err_info, LYD_CTX(sr_mod));
                    return err_info;
                }
                assert(set->count == 1);
                lyd_free_tree(set->dnodes[0]);
                ly_set_free(set, NULL);
            }

            SR_LOG_INF("Module \"%s\" feature \"%s\" was %s.", ly_mod->name, feat_name, enable ? "enabled" : "disabled");
            lyd_free_tree(node);
        }
    }

    return NULL;
}

/**
 * @brief Finalize applying scheduled module installation. That consists of updating
 * sysrepo module data tree and storing updated YANG module files.
 *
 * @param[in] sr_mod Sysrepo module to install. Will be freed.
 * @param[in] new_ctx Context with new modules used for printing them.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_sched_finalize_module_install(struct lyd_node *sr_mod, const struct ly_ctx *new_ctx)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    struct lyd_node *sr_mods, *node;
    LY_ARRAY_COUNT_TYPE u;

    LY_LIST_FOR(sr_mod->next, node) {
        if (strcmp(node->schema->name, "installed-module")) {
            continue;
        }

        assert(!strcmp(lyd_child(node)->schema->name, "name"));
        ly_mod = ly_ctx_get_module_implemented(new_ctx, SR_LY_CHILD_VALUE(node));
        assert(ly_mod);

        LY_ARRAY_FOR(ly_mod->parsed->imports, u) {
            if (ly_mod->parsed->imports[u].module->implemented &&
                    !strcmp(ly_mod->parsed->imports[u].module->name, SR_LY_CHILD_VALUE(sr_mod))) {
                /* we will install this module as a dependency of a module installed later */
                SR_LOG_INF("Module \"%s\" will be installed as \"%s\" module dependency.",
                        SR_LY_CHILD_VALUE(sr_mod), ly_mod->name);
                lyd_free_tree(sr_mod);
                return NULL;
            }
        }
    }

    sr_mods = lyd_parent(sr_mod);

    /*
     * installed module, store new YANG, install all of its implemented dependencies
     */
    assert(!strcmp(lyd_child(sr_mod)->schema->name, "name"));
    ly_mod = ly_ctx_get_module_implemented(new_ctx, SR_LY_CHILD_VALUE(sr_mod));
    assert(ly_mod);
    lyd_free_tree(sr_mod);

    if ((err_info = sr_lydmods_add_module_with_imps_r(sr_mods, ly_mod, 2))) {
        return err_info;
    }

    return NULL;
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

    SR_CHECK_LY_RET(lyd_new_term(sr_mod, NULL, "inverse-deps", inv_dep_mod, 0, NULL), LYD_CTX(sr_mod), err_info)

    return NULL;
}

/**
 * @brief Add all dependencies (with inverse) and RPCs/notifications with dependencies into internal sysrepo data tree.
 *
 * @param[in] sr_mod Module data node from sysrepo data tree.
 * @param[in] ly_mod Parsed libyang module.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_add_all(struct lyd_node *sr_mod, const struct lys_module *ly_mod)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set = NULL, *set2;
    struct lyd_node *ly_deps;
    uint32_t i;
    char *xpath;
    LY_ERR lyrc;
    struct sr_lydmods_deps_dfs_arg dfs_arg;

    /* there can be no dependencies yet (but inverse ones yes) */
    assert(!lyd_find_xpath(sr_mod, "deps | rpcs | notifications", &set));
    assert(!set->count || ((set->count == 1) && (set->dnodes[0]->flags & LYD_DEFAULT)));
    ly_set_free(set, NULL);
    set = NULL;

    /* create new deps */
    SR_CHECK_LY_GOTO(lyd_new_inner(sr_mod, NULL, "deps", 0, &ly_deps), ly_mod->ctx, err_info, cleanup);

    /* add all module deps (data, RPC, notif) */
    dfs_arg.sr_mod = sr_mod;
    dfs_arg.sr_deps = ly_deps;
    dfs_arg.root_notif = NULL;
    dfs_arg.err_info = NULL;
    if (lysc_module_dfs_full(ly_mod, sr_lydmods_add_all_deps_dfs_cb, &dfs_arg)) {
        err_info = dfs_arg.err_info;
        goto cleanup;
    }

    /* add inverse data deps */
    SR_CHECK_LY_GOTO(lyd_find_xpath(sr_mod, "deps/module", &set), ly_mod->ctx, err_info, cleanup);

    for (i = 0; i < set->count; ++i) {
        if (asprintf(&xpath, "module[name='%s']", lyd_get_value(set->dnodes[i])) == -1) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }

        /* find the dependent module */
        lyrc = lyd_find_xpath(lyd_parent(sr_mod), xpath, &set2);
        free(xpath);
        SR_CHECK_LY_GOTO(lyrc, ly_mod->ctx, err_info, cleanup);
        assert(set2->count == 1);

        /* add inverse dependency */
        err_info = sr_lydmods_add_inv_data_dep(set2->dnodes[0], lyd_get_value(lyd_child(sr_mod)));
        ly_set_free(set2, NULL);
        if (err_info) {
            goto cleanup;
        }
    }

    /* success */

cleanup:
    ly_set_free(set, NULL);
    return err_info;
}

static sr_error_info_t *
sr_lys_parse_mem(struct ly_ctx *ly_ctx, const char *path, const struct ly_set *feat_set,
        const struct lys_module **ly_mod, int *fail)
{
    sr_error_info_t *err_info = NULL;
    const char **features;
    struct ly_in *in;

    /* create the features array */
    if ((err_info = sr_lydmods_features_array(feat_set, &features))) {
        return err_info;
    }

    /* load the new module */
    ly_in_new_memory(path, &in);
    if (lys_parse(ly_ctx, in, LYS_IN_YANG, features, ly_mod)) {
        if (fail) {
            *fail = 1;
        } else {
            sr_errinfo_new_ly(&err_info, ly_ctx);
        }
    }

    /* cleanup */
    free(features);
    ly_in_free(in, 0);
    return err_info;
}

/**
 * @brief Check whether some removed module is not a dependency of a non-removed module.
 *
 * @param[in] sr_mods Sysrepo module data.
 * @param[in] new_ctx Context with all scheduled module changes applied.
 * @param[out] fail Whether any scheduled module removal failed.
 * @return err_info, NULL on error.
 */
static sr_error_info_t *
sr_lydmods_sched_check_removed_modules(const struct lyd_node *sr_mods, const struct ly_ctx *new_ctx, int *fail)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *node;
    struct ly_set *set = NULL;
    const char *mod_name, *revision;
    const struct lys_module *ly_mod;
    uint32_t i;

    assert(sr_mods);

    /* find all removed modules */
    if (lyd_find_xpath(sr_mods, "/" SR_YANG_MOD ":sysrepo-modules/module[removed]", &set)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(sr_mods));
        goto cleanup;
    } else if (!set->count) {
        /* nothing to do */
        goto cleanup;
    }

    /* check that the removed modules are not implemented in the new context */
    for (i = 0; i < set->count; ++i) {
        /* learn about the module */
        mod_name = NULL;
        revision = NULL;
        LY_LIST_FOR(lyd_child(set->dnodes[i]), node) {
            if (!strcmp(node->schema->name, "name")) {
                mod_name = lyd_get_value(node);
            } else if (!strcmp(node->schema->name, "revision")) {
                revision = lyd_get_value(node);
                break;
            }
        }
        assert(mod_name);

        ly_mod = ly_ctx_get_module(new_ctx, mod_name, revision);
        if (ly_mod && ly_mod->implemented) {
            /* this module cannot be removed */
            SR_LOG_WRN("Cannot remove module \"%s\" because some other installed module depends on it.", mod_name);

            /* we failed, do not apply any scheduled changes */
            *fail = 1;
            goto cleanup;
        }
    }

    /* success */

cleanup:
    ly_set_free(set, NULL);
    return err_info;
}

/**
 * @brief Load updated modules into context.
 *
 * @param[in] sr_mods Sysrepo module data.
 * @param[in] new_ctx Context to load updated modules into.
 * @param[out] change Whether there were any updated modules.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_sched_ctx_update_modules(const struct lyd_node *sr_mods, struct ly_ctx *new_ctx, int *change)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    struct ly_set *set = NULL, *feat_set = NULL;
    uint32_t i;

    assert(sr_mods);

    /* find updated modules and change internal module data tree */
    if (lyd_find_xpath(sr_mods, "/" SR_YANG_MOD ":sysrepo-modules/module/updated-yang", &set)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(sr_mods));
        goto cleanup;
    }
    for (i = 0; i < set->count; ++i) {
        /* collect all enabled features */
        if (lyd_find_xpath(lyd_parent(set->dnodes[i]), "enabled-feature", &feat_set)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(sr_mods));
            goto cleanup;
        }

        /* change features according to the changes in lydmods data */
        if ((err_info = sr_lydmods_sched_change_features(lyd_parent(set->dnodes[i]), &feat_set, change))) {
            goto cleanup;
        }

        /* load the updated module */
        if ((err_info = sr_lys_parse_mem(new_ctx, lyd_get_value(set->dnodes[i]), feat_set, &ly_mod, NULL))) {
            goto cleanup;
        }

        ly_set_free(feat_set, NULL);
        feat_set = NULL;
        *change = 1;
    }

    /* success */

cleanup:
    ly_set_free(set, NULL);
    ly_set_free(feat_set, NULL);
    return err_info;
}

/**
 * @brief Load new installed modules into context from sysrepo module data.
 *
 * @param[in] sr_mods Sysrepo module data.
 * @param[in] new_ctx Context to load the new modules into.
 * @param[out] change Whether any new modules were loaded.
 * @param[out] fail Whether any new dependant modules were not implemented.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_sched_ctx_install_modules(const struct lyd_node *sr_mods, struct ly_ctx *new_ctx, int *change, int *fail)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    struct ly_set *set = NULL, *feat_set = NULL;
    uint32_t i;

    assert(sr_mods);

    if (lyd_find_xpath(sr_mods, "/" SR_YANG_MOD ":sysrepo-modules/installed-module/module-yang", &set)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(sr_mods));
        goto cleanup;
    }
    for (i = 0; i < set->count; ++i) {
        /* collect all enabled features */
        if (lyd_find_xpath(lyd_parent(set->dnodes[i]), "enabled-feature", &feat_set)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(sr_mods));
            goto cleanup;
        }

        /* change features according to the changes in lydmods data */
        if ((err_info = sr_lydmods_sched_change_features(lyd_parent(set->dnodes[i]), &feat_set, change))) {
            goto cleanup;
        }

        /* parse the module */
        if ((err_info = sr_lys_parse_mem(new_ctx, lyd_get_value(set->dnodes[i]), feat_set, &ly_mod, fail))) {
            goto cleanup;
        }
        if (*fail) {
            sr_log_wrn_ly(new_ctx);
            SR_LOG_WRN("Installing module \"%s\" failed.", SR_LY_CHILD_VALUE(lyd_parent(set->dnodes[i])));
            goto cleanup;
        }

        ly_set_free(feat_set, NULL);
        feat_set = NULL;
        *change = 1;
    }

    /* success */

cleanup:
    ly_set_free(set, NULL);
    ly_set_free(feat_set, NULL);
    return err_info;
}

/**
 * @brief Apply all scheduled changes in sysrepo module data.
 * Note that @p sr_mods cannot be parsed with @p new_ctx because the context may be recompiled
 * and the links to schema broken.
 *
 * @param[in,out] sr_mods Sysrepo modules data tree.
 * @param[in,out] new_ctx Initalized context with no SR modules loaded. On return all SR modules are loaded
 * with all the changes (if any) applied.
 * @param[out] change Whether sysrepo module data were changed.
 * @param[out] fail Whether some changes in @p new_ctx are not valid. In that case this context
 * is not usable and needs to be created anew.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_sched_apply(struct lyd_node *sr_mods, struct ly_ctx *new_ctx, int *change, int *fail)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *next, *next2, *sr_mod, *node;
    const struct lys_module *ly_mod;
    uint32_t content_id;
    char buf[11];

    assert(sr_mods && new_ctx && change);
    assert(LYD_CTX(sr_mods) != new_ctx);

    SR_LOG_INF("Applying scheduled changes.");
    *change = 0;
    *fail = 0;

    /*
     * 1) create the new context, LY sysrepo data are not modified
     */

    /* load updated modules into new context */
    if ((err_info = sr_lydmods_sched_ctx_update_modules(sr_mods, new_ctx, change))) {
        goto cleanup;
    }

    /* load all remaining non-updated non-removed modules into new context */
    if ((err_info = sr_lydmods_ctx_load_modules(sr_mods, new_ctx, 0, 0, 1, change))) {
        goto cleanup;
    }

    /* install modules */
    if ((err_info = sr_lydmods_sched_ctx_install_modules(sr_mods, new_ctx, change, fail)) || *fail) {
        goto cleanup;
    }

    if (*change) {
        /* check that removed modules can really be removed */
        if ((err_info = sr_lydmods_sched_check_removed_modules(sr_mods, new_ctx, fail)) || *fail) {
            goto cleanup;
        }

        /* check that persistent module data can be loaded with updated modules */
        if ((err_info = sr_lydmods_sched_update_data(sr_mods, new_ctx, fail)) || *fail) {
            goto cleanup;
        }

        /*
         * 2) update LY sysrepo data, dependencies are created from scratch
         */
        LY_LIST_FOR_SAFE(lyd_child(sr_mods), next, sr_mod) {
            if (!strcmp(sr_mod->schema->name, "module")) {
                assert(!strcmp(lyd_child(sr_mod)->schema->name, "name"));
                LY_LIST_FOR_SAFE(lyd_child(sr_mod)->next, next2, node) {
                    if (!strcmp(node->schema->name, "removed")) {
                        if ((err_info = sr_lydmods_sched_finalize_module_remove(sr_mod, new_ctx, 0))) {
                            goto cleanup;
                        }
                        /* sr_mod was freed */
                        break;
                    } else if (!strcmp(node->schema->name, "updated-yang")) {
                        if ((err_info = sr_lydmods_sched_finalize_module_update(sr_mod, new_ctx))) {
                            goto cleanup;
                        }
                        /* sr_mod was freed */
                        break;
                    } else if (!strcmp(node->schema->name, "changed-feature")) {
                        if ((err_info = sr_lydmods_sched_finalize_module_change_features(sr_mod, new_ctx))) {
                            goto cleanup;
                        }
                        /* sr_mod children were freed, restart the iteration */
                        next2 = lyd_child(sr_mod)->next;
                    } else if (!strcmp(node->schema->name, "deps") ||
                            !strcmp(node->schema->name, "inverse-deps") ||
                            !strcmp(node->schema->name, "rpc") ||
                            !strcmp(node->schema->name, "notification")) {
                        /* remove all stored dependencies, RPCs, and notifications of all the modules */
                        lyd_free_tree(node);
                    }
                }
            } else if (!strcmp(sr_mod->schema->name, "installed-module")) {
                if ((err_info = sr_lydmods_sched_finalize_module_install(sr_mod, new_ctx))) {
                    goto cleanup;
                }
            } else {
                /* increase content-id */
                assert(!strcmp(sr_mod->schema->name, "content-id"));
                content_id = ((struct lyd_node_term *)sr_mod)->value.uint32 + 1;
                sprintf(buf, "%" PRIu32, content_id);
                if (lyd_change_term(sr_mod, buf)) {
                    SR_ERRINFO_INT(&err_info);
                    goto cleanup;
                }
            }
        }

        /* now add (rebuild) dependencies and RPCs, notifications of all the modules */
        LY_LIST_FOR(lyd_child(sr_mods), sr_mod) {
            if (strcmp(sr_mod->schema->name, "module")) {
                continue;
            }

            ly_mod = ly_ctx_get_module_implemented(new_ctx, lyd_get_value(lyd_child(sr_mod)));
            assert(ly_mod);
            if ((err_info = sr_lydmods_add_all(sr_mod, ly_mod))) {
                goto cleanup;
            }
        }
    }

    /* success */

cleanup:
    if (!err_info) {
        if (*fail) {
            SR_LOG_WRN("Failed to apply some changes, leaving all changes scheduled.");
            *change = 0;
        } else if (*change) {
            SR_LOG_INF("Scheduled changes applied.");
        } else {
            SR_LOG_INF("No scheduled changes.");
        }
    }
    return err_info;
}

sr_error_info_t *
sr_lydmods_conn_ctx_update(sr_main_shm_t *main_shm, struct ly_ctx **ly_ctx, int apply_sched, int err_on_sched_fail,
        int *changed)
{
    sr_error_info_t *err_info = NULL;
    int chng, exists, fail, ctx_updated = 0;
    uint32_t conn_count;
    struct lyd_node *sr_mods = NULL;
    struct ly_ctx *sr_mods_ctx = NULL;

    chng = 0;

    /* LYDMODS LOCK */
    if ((err_info = sr_lydmods_lock(&main_shm->lydmods_lock, *ly_ctx, __func__))) {
        return err_info;
    }

    /* create temporary context for sr_mods */
    if ((err_info = sr_shmmain_ly_ctx_init(&sr_mods_ctx))) {
        goto cleanup;
    }

    /* check whether any internal module data exist */
    if ((err_info = sr_lydmods_exists(&exists))) {
        goto cleanup;
    }
    if (!exists) {
        /* create new persistent module data file and fill a context accordingly */
        if ((err_info = sr_lydmods_create(*ly_ctx, sr_mods_ctx, &sr_mods))) {
            goto cleanup;
        }
        ctx_updated = 1;
        chng = 1;
    } else {
        /* parse sysrepo module data */
        if ((err_info = sr_lydmods_parse(sr_mods_ctx, &sr_mods))) {
            goto cleanup;
        }
        if (apply_sched) {
            /* apply scheduled changes if we can */
            if ((err_info = sr_conn_info(NULL, NULL, &conn_count, NULL, NULL))) {
                goto cleanup;
            }
            if (!conn_count) {
                if ((err_info = sr_lydmods_sched_apply(sr_mods, *ly_ctx, &chng, &fail))) {
                    goto cleanup;
                }
                if (fail) {
                    if (err_on_sched_fail) {
                        sr_errinfo_new(&err_info, SR_ERR_OPERATION_FAILED, "Applying scheduled changes failed.");
                        goto cleanup;
                    }

                    /* the context is not valid anymore, we have to create it from scratch in the connection */
                    ly_ctx_destroy(*ly_ctx);
                    if ((err_info = sr_shmmain_ly_ctx_init(ly_ctx))) {
                        goto cleanup;
                    }
                } else {
                    ctx_updated = 1;
                }
            } else {
                SR_LOG_INF("Scheduled changes not applied because of other existing connections.");
            }
        }
    }

    /* update the connection context modules */
    if (!ctx_updated) {
        if ((err_info = sr_lydmods_ctx_load_modules(sr_mods, *ly_ctx, 1, 1, 0, NULL))) {
            goto cleanup;
        }
    }

    if (chng) {
        /* store updated internal sysrepo data */
        if ((err_info = sr_lydmods_print(&sr_mods))) {
            goto cleanup;
        }
    }

    /* success */
    if (changed) {
        *changed = chng;
    }

cleanup:
    /* LYDMODS UNLOCK */
    sr_munlock(&main_shm->lydmods_lock);

    lyd_free_all(sr_mods);
    ly_ctx_destroy(sr_mods_ctx);
    return err_info;
}

sr_error_info_t *
sr_lydmods_deferred_add_module(sr_main_shm_t *main_shm, struct ly_ctx *ly_ctx, const struct lys_module *ly_mod,
        const char **features)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL, *inst_mod;
    struct ly_set *set = NULL;
    char *path = NULL, *yang_str = NULL;
    int i;

    /* LYDMODS LOCK */
    if ((err_info = sr_lydmods_lock(&main_shm->lydmods_lock, ly_ctx, __func__))) {
        return err_info;
    }

    /* parse current module information */
    if ((err_info = sr_lydmods_parse(ly_ctx, &sr_mods))) {
        goto cleanup;
    }

    /* check that the module is not already marked for installation */
    if (asprintf(&path, "installed-module[name=\"%s\"]", ly_mod->name) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    SR_CHECK_INT_GOTO(lyd_find_xpath(sr_mods, path, &set), err_info, cleanup);
    if (set->count == 1) {
        sr_errinfo_new(&err_info, SR_ERR_EXISTS, "Module \"%s\" already scheduled for installation.", ly_mod->name);
        goto cleanup;
    }

    /* store all info for installation */
    if (lyd_new_path(sr_mods, NULL, path, NULL, 0, &inst_mod)) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    if (ly_mod->revision && lyd_new_term(inst_mod, NULL, "revision", ly_mod->revision, 0, NULL)) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    for (i = 0; features && features[i]; ++i) {
        if (lyd_new_term(inst_mod, NULL, "enabled-feature", features[i], 0, NULL)) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            goto cleanup;
        }
    }

    /* print the module into memory */
    if (lys_print_mem(&yang_str, ly_mod, LYS_OUT_YANG, 0)) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        goto cleanup;
    }

    if (lyd_new_term(inst_mod, NULL, "module-yang", yang_str, 0, NULL)) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    /* store the updated persistent data tree */
    if ((err_info = sr_lydmods_print(&sr_mods))) {
        goto cleanup;
    }

    SR_LOG_INF("Module \"%s\" scheduled for installation.", ly_mod->name);

cleanup:
    /* LYDMODS UNLOCK */
    sr_munlock(&main_shm->lydmods_lock);

    free(path);
    free(yang_str);
    ly_set_free(set, NULL);
    lyd_free_all(sr_mods);
    return err_info;
}

sr_error_info_t *
sr_lydmods_unsched_add_module(sr_main_shm_t *main_shm, struct ly_ctx *ly_ctx, const char *module_name)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL;
    struct ly_set *set = NULL;
    char *path = NULL;

    /* LYDMODS LOCK */
    if ((err_info = sr_lydmods_lock(&main_shm->lydmods_lock, ly_ctx, __func__))) {
        return err_info;
    }

    /* parse current module information */
    if ((err_info = sr_lydmods_parse(ly_ctx, &sr_mods))) {
        goto cleanup;
    }

    /* check that the module is scheduled for installation */
    if (asprintf(&path, "installed-module[name=\"%s\"]", module_name) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    SR_CHECK_INT_GOTO(lyd_find_xpath(sr_mods, path, &set), err_info, cleanup);
    if (!set->count) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" not scheduled for installation.", module_name);
        goto cleanup;
    }

    /* unschedule installation */
    lyd_free_tree(set->dnodes[0]);

    /* store the updated persistent data tree */
    if ((err_info = sr_lydmods_print(&sr_mods))) {
        goto cleanup;
    }

    SR_LOG_INF("Module \"%s\" installation unscheduled.", module_name);

cleanup:
    /* LYDMODS UNLOCK */
    sr_munlock(&main_shm->lydmods_lock);

    free(path);
    ly_set_free(set, NULL);
    lyd_free_all(sr_mods);
    return err_info;
}

/**
 * @brief Load an installed module from sysrepo module data into a context with any other installed modules.
 *
 * @param[in] sr_mods Sysrepo modules data tree.
 * @param[in] ly_ctx Context to parse the module into.
 * @param[in] module_name Name of the module to find.
 * @param[out] ly_mod Parsed module.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_ctx_load_installed_module_all(const struct lyd_node *sr_mods, struct ly_ctx *ly_ctx, const char *module_name,
        const struct lys_module **ly_mod)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set = NULL;
    const struct lys_module *lmod;
    uint32_t i;

    *ly_mod = NULL;

    /* find all scheduled modules */
    SR_CHECK_INT_GOTO(lyd_find_xpath(sr_mods, "installed-module/module-yang", &set), err_info, cleanup);

    /* load all the modules, it must succeed */
    for (i = 0; i < set->count; ++i) {
        if (lys_parse_mem(ly_ctx, lyd_get_value(set->dnodes[i]), LYS_IN_YANG, &lmod)) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            SR_ERRINFO_INT(&err_info);
            goto cleanup;
        }

        /* just enable all features */
        if ((err_info = sr_lydmods_ctx_load_module(lyd_parent(set->dnodes[i]), ly_ctx, 1, NULL, NULL))) {
            goto cleanup;
        }

        if (!strcmp(lmod->name, module_name)) {
            /* the required module was found */
            *ly_mod = lmod;
        }
    }

    if (!*ly_mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" not scheduled for installation.", module_name);
        goto cleanup;
    }

    /* success */

cleanup:
    ly_set_free(set, NULL);
    return err_info;
}

sr_error_info_t *
sr_lydmods_deferred_add_module_data(sr_main_shm_t *main_shm, struct ly_ctx *ly_ctx, const char *module_name,
        const char *data, const char *data_path, LYD_FORMAT format)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set = NULL;
    struct lyd_node *node, *sr_mods = NULL, *mod_data = NULL;
    char *path = NULL, *data_json = NULL;
    const struct lys_module *ly_mod;
    struct ly_ctx *sr_mods_ctx = NULL;
    LY_ERR lyrc;

    assert((data && !data_path) || (!data && data_path));

    /* create temporary context for sr_mods */
    if ((err_info = sr_shmmain_ly_ctx_init(&sr_mods_ctx))) {
        return err_info;
    }

    /* LYDMODS LOCK */
    if ((err_info = sr_lydmods_lock(&main_shm->lydmods_lock, ly_ctx, __func__))) {
        return err_info;
    }

    /* parse sysrepo module data */
    if ((err_info = sr_lydmods_parse(sr_mods_ctx, &sr_mods))) {
        goto cleanup;
    }

    /* update load all the modules into context */
    if ((err_info = sr_lydmods_ctx_load_modules(sr_mods, ly_ctx, 1, 1, 0, NULL))) {
        goto cleanup;
    }

    /* load the module to be installed */
    if ((err_info = sr_lydmods_ctx_load_installed_module_all(sr_mods, ly_ctx, module_name, &ly_mod))) {
        goto cleanup;
    }

    /* parse module data */
    if (data_path) {
        lyrc = lyd_parse_data_path(ly_ctx, data_path, format, LYD_PARSE_ONLY | LYD_PARSE_STRICT, 0, &mod_data);
    } else {
        lyrc = lyd_parse_data_mem(ly_ctx, data, format, LYD_PARSE_ONLY | LYD_PARSE_STRICT, 0, &mod_data);
    }
    if (lyrc) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    /* check that there are only this module data */
    LY_LIST_FOR(mod_data, node) {
        if (!(node->flags & LYD_DEFAULT) && (lyd_owner_module(node) != ly_mod)) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Only data for the module \"%s\" can be set.", module_name);
            goto cleanup;
        }
    }

    /* find the module */
    if (asprintf(&path, "installed-module[name=\"%s\"]", module_name) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    SR_CHECK_INT_GOTO(lyd_find_xpath(sr_mods, path, &set), err_info, cleanup);
    if (!set->count) {
        sr_errinfo_new(&err_info, SR_ERR_EXISTS, "Module \"%s\" not scheduled for installation.", module_name);
        goto cleanup;
    }

    /* remove any previously set data */
    LY_LIST_FOR(lyd_child(set->dnodes[0]), node) {
        if (!strcmp(node->schema->name, "data")) {
            lyd_free_tree(node);
            break;
        }
    }

    /* print into buffer */
    if (lyd_print_mem(&data_json, mod_data, LYD_JSON, LYD_PRINT_WITHSIBLINGS)) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    /* add into module */
    if (lyd_new_term(set->dnodes[0], NULL, "data", data_json, 0, NULL)) {
        goto cleanup;
    }

    /* store updated sysrepo module data */
    if ((err_info = sr_lydmods_print(&sr_mods))) {
        goto cleanup;
    }

    /* success */

cleanup:
    /* LYDMODS UNLOCK */
    sr_munlock(&main_shm->lydmods_lock);

    free(path);
    free(data_json);
    ly_set_free(set, NULL);
    lyd_free_all(sr_mods);
    lyd_free_all(mod_data);
    ly_ctx_destroy(sr_mods_ctx);
    return err_info;
}

sr_error_info_t *
sr_lydmods_deferred_del_module(sr_main_shm_t *main_shm, struct ly_ctx *ly_ctx, const char *mod_name)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL;
    struct ly_set *set = NULL;
    char *path = NULL;

    /* LYDMODS LOCK */
    if ((err_info = sr_lydmods_lock(&main_shm->lydmods_lock, ly_ctx, __func__))) {
        return err_info;
    }

    /* parse current module information */
    if ((err_info = sr_lydmods_parse(ly_ctx, &sr_mods))) {
        goto cleanup;
    }

    /* check that the module is not already marked for deletion */
    if (asprintf(&path, "module[name=\"%s\"]/removed", mod_name) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    SR_CHECK_INT_GOTO(lyd_find_xpath(sr_mods, path, &set), err_info, cleanup);
    if (set->count == 1) {
        sr_errinfo_new(&err_info, SR_ERR_EXISTS, "Module \"%s\" already scheduled for deletion.", mod_name);
        goto cleanup;
    }

    /* mark for deletion */
    if (lyd_new_path(sr_mods, NULL, path, NULL, 0, NULL)) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    /* store the updated persistent data tree */
    if ((err_info = sr_lydmods_print(&sr_mods))) {
        goto cleanup;
    }

    SR_LOG_INF("Module \"%s\" scheduled for deletion.", mod_name);

cleanup:
    /* LYDMODS UNLOCK */
    sr_munlock(&main_shm->lydmods_lock);

    free(path);
    ly_set_free(set, NULL);
    lyd_free_all(sr_mods);
    return err_info;
}

/**
 * @brief Unchedule module (with any implemented dependencies) deletion from internal sysrepo data.
 *
 * @param[in] main_shm_add Main SHM mapping address.
 * @param[in] sr_mods Internal sysrepo data to modify.
 * @param[in] ly_mod Module whose removal to unschedule.
 * @param[in] first Whether this is the first module or just a dependency.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_unsched_del_module_r(struct lyd_node *sr_mods, const struct lys_module *ly_mod, int first)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set = NULL;
    char *path = NULL;
    uint32_t i;

    /* check whether the module is marked for deletion */
    if (asprintf(&path, "module[name=\"%s\"]/removed", ly_mod->name) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    SR_CHECK_INT_GOTO(lyd_find_xpath(sr_mods, path, &set), err_info, cleanup);
    if (!set->count) {
        if (first) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" not scheduled for deletion.", ly_mod->name);
            goto cleanup;
        }
    } else {
        assert(set->count == 1);
        lyd_free_tree(set->dnodes[0]);
        SR_LOG_INF("Module \"%s\" deletion unscheduled.", ly_mod->name);
    }
    first = 0;

    /* recursively check all imported implemented modules */
    LY_ARRAY_FOR(ly_mod->parsed->imports, i) {
        if (ly_mod->parsed->imports[i].module->implemented) {
            if ((err_info = sr_lydmods_unsched_del_module_r(sr_mods, ly_mod->parsed->imports[i].module, 0))) {
                goto cleanup;
            }
        }
    }

cleanup:
    free(path);
    ly_set_free(set, NULL);
    return err_info;
}

sr_error_info_t *
sr_lydmods_unsched_del_module_with_imps(sr_main_shm_t *main_shm, struct ly_ctx *ly_ctx, const struct lys_module *ly_mod)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL;

    /* LYDMODS LOCK */
    if ((err_info = sr_lydmods_lock(&main_shm->lydmods_lock, ly_ctx, __func__))) {
        return err_info;
    }

    /* parse current module information */
    if ((err_info = sr_lydmods_parse(ly_ctx, &sr_mods))) {
        goto cleanup;
    }

    /* try to unschedule deletion */
    if ((err_info = sr_lydmods_unsched_del_module_r(sr_mods, ly_mod, 1))) {
        goto cleanup;
    }

    /* store the updated persistent data tree */
    err_info = sr_lydmods_print(&sr_mods);

cleanup:
    /* LYDMODS UNLOCK */
    sr_munlock(&main_shm->lydmods_lock);

    lyd_free_all(sr_mods);
    return err_info;
}

sr_error_info_t *
sr_lydmods_deferred_upd_module(sr_main_shm_t *main_shm, struct ly_ctx *ly_ctx, const struct lys_module *ly_upd_mod)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL;
    struct ly_set *set = NULL;
    char *path = NULL, *yang_str = NULL;

    /* LYDMODS LOCK */
    if ((err_info = sr_lydmods_lock(&main_shm->lydmods_lock, ly_ctx, __func__))) {
        return err_info;
    }

    /* parse current module information */
    if ((err_info = sr_lydmods_parse(ly_ctx, &sr_mods))) {
        goto cleanup;
    }

    /* check that the module is not already marked for update */
    if (asprintf(&path, "module[name=\"%s\"]/updated-yang", ly_upd_mod->name) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    SR_CHECK_INT_GOTO(lyd_find_xpath(sr_mods, path, &set), err_info, cleanup);
    if (set->count == 1) {
        sr_errinfo_new(&err_info, SR_ERR_EXISTS, "Module \"%s\" already scheduled for an update.", ly_upd_mod->name);
        goto cleanup;
    }

    /* print the module into memory */
    if (lys_print_mem(&yang_str, ly_upd_mod, LYS_OUT_YANG, LYS_PRINT_SHRINK)) {
        sr_errinfo_new_ly(&err_info, ly_upd_mod->ctx);
        goto cleanup;
    }

    /* mark for update */
    if (lyd_new_path(sr_mods, NULL, path, yang_str, 0, NULL)) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    /* store the updated persistent data tree */
    if ((err_info = sr_lydmods_print(&sr_mods))) {
        goto cleanup;
    }

    SR_LOG_INF("Module \"%s\" scheduled for an update.", ly_upd_mod->name);

cleanup:
    /* LYDMODS UNLOCK */
    sr_munlock(&main_shm->lydmods_lock);

    free(path);
    free(yang_str);
    ly_set_free(set, NULL);
    lyd_free_all(sr_mods);
    return err_info;
}

sr_error_info_t *
sr_lydmods_unsched_upd_module(sr_main_shm_t *main_shm, struct ly_ctx *ly_ctx, const char *mod_name)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL;
    struct ly_set *set = NULL;
    char *path = NULL;

    /* LYDMODS LOCK */
    if ((err_info = sr_lydmods_lock(&main_shm->lydmods_lock, ly_ctx, __func__))) {
        return err_info;
    }

    /* parse current module information */
    if ((err_info = sr_lydmods_parse(ly_ctx, &sr_mods))) {
        goto cleanup;
    }

    /* check whether the module is marked for update */
    if (asprintf(&path, "module[name=\"%s\"]/updated-yang", mod_name) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    SR_CHECK_INT_GOTO(lyd_find_xpath(sr_mods, path, &set), err_info, cleanup);
    if (!set->count) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" not scheduled for an update.", mod_name);
        goto cleanup;
    }

    assert(set->count == 1);
    /* free the "updated-yang" node */
    lyd_free_tree(set->dnodes[0]);

    /* store the updated persistent data tree */
    if ((err_info = sr_lydmods_print(&sr_mods))) {
        goto cleanup;
    }

    SR_LOG_INF("Module \"%s\" update unscheduled.", mod_name);

cleanup:
    /* LYDMODS UNLOCK */
    sr_munlock(&main_shm->lydmods_lock);

    free(path);
    ly_set_free(set, NULL);
    lyd_free_all(sr_mods);
    return err_info;
}

sr_error_info_t *
sr_lydmods_deferred_change_feature(sr_main_shm_t *main_shm, struct ly_ctx *ly_ctx, const struct lys_module *ly_mod,
        const char *feat_name, int to_enable, int is_enabled)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL;
    struct ly_set *set = NULL;
    char *path = NULL;

    /* LYDMODS LOCK */
    if ((err_info = sr_lydmods_lock(&main_shm->lydmods_lock, ly_ctx, __func__))) {
        return err_info;
    }

    /* parse current module information */
    if ((err_info = sr_lydmods_parse(ly_ctx, &sr_mods))) {
        goto cleanup;
    }

    /* check that the feature is not already marked for change */
    if (asprintf(&path, "module[name=\"%s\"]/changed-feature[name=\"%s\"]/change",
            ly_mod->name, feat_name) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    SR_CHECK_INT_GOTO(lyd_find_xpath(sr_mods, path, &set), err_info, cleanup);
    if (set->count == 1) {
        if ((to_enable && !strcmp(lyd_get_value(set->dnodes[0]), "enable")) ||
                (!to_enable && !strcmp(lyd_get_value(set->dnodes[0]), "disable"))) {
            sr_errinfo_new(&err_info, SR_ERR_EXISTS, "Module \"%s\" feature \"%s\" already scheduled to be %s.",
                    ly_mod->name, feat_name, to_enable ? "enabled" : "disabled");
            goto cleanup;
        }

        /* unschedule the feature change */
        lyd_free_tree(lyd_parent(set->dnodes[0]));
        SR_LOG_INF("Module \"%s\" feature \"%s\" %s unscheduled.", ly_mod->name, feat_name,
                to_enable ? "disabling" : "enabling");
    } else {
        if ((to_enable && is_enabled) || (!to_enable && !is_enabled)) {
            sr_errinfo_new(&err_info, SR_ERR_EXISTS, "Module \"%s\" feature \"%s\" is already %s.",
                    ly_mod->name, feat_name, to_enable ? "enabled" : "disabled");
            goto cleanup;
        }

        /* schedule the feature change */
        if (lyd_new_path(sr_mods, NULL, path, to_enable ? "enable" : "disable", 0, NULL)) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            goto cleanup;
        }

        SR_LOG_INF("Module \"%s\" feature \"%s\" %s scheduled.", ly_mod->name, feat_name,
                to_enable ? "enabling" : "disabling");
    }

    /* store the updated persistent data tree */
    if ((err_info = sr_lydmods_print(&sr_mods))) {
        goto cleanup;
    }

cleanup:
    /* LYDMODS UNLOCK */
    sr_munlock(&main_shm->lydmods_lock);

    free(path);
    ly_set_free(set, NULL);
    lyd_free_all(sr_mods);
    return err_info;
}

/**
 * @brief Update replay support of a module.
 *
 * @param[in,out] sr_mod Module to update.
 * @param[in] replay_support Whether replay should be enabled or disabled.
 * @param[in] s_replay Schema node of replay support.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_update_replay_support_module(struct lyd_node *sr_mod, int replay_support, const struct lysc_node *s_replay)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_replay;
    char buf[21];
    time_t from_ts, to_ts;

    lyd_find_sibling_val(lyd_child(sr_mod), s_replay, NULL, 0, &sr_replay);
    if (!replay_support && sr_replay) {
        /* remove replay support */
        lyd_free_tree(sr_replay);
    } else if (replay_support && !sr_replay) {
        /* find earliest stored notification or use current time */
        if ((err_info = sr_replay_find_file(lyd_get_value(lyd_child(sr_mod)), 1, 0, &from_ts, &to_ts))) {
            return err_info;
        }
        if (!from_ts) {
            from_ts = time(NULL);
        }
        sprintf(buf, "%ld", (long int)from_ts);

        /* add replay support */
        SR_CHECK_LY_RET(lyd_new_term(sr_mod, NULL, "replay-support", buf, 0, NULL), LYD_CTX(sr_mod), err_info);
    }

    return NULL;
}

sr_error_info_t *
sr_lydmods_update_replay_support(sr_main_shm_t *main_shm, struct ly_ctx *ly_ctx, const char *mod_name, int replay_support)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL, *sr_mod;
    char *pred = NULL;
    const struct lysc_node *s_mod, *s_replay;

    /* find schema nodes */
    s_mod = lys_find_path(ly_ctx, NULL, "/sysrepo:sysrepo-modules/module", 0);
    assert(s_mod);
    s_replay = lys_find_path(NULL, s_mod, "replay-support", 0);
    assert(s_replay);

    /* LYDMODS LOCK */
    if ((err_info = sr_lydmods_lock(&main_shm->lydmods_lock, ly_ctx, __func__))) {
        return err_info;
    }

    /* parse current module information */
    if ((err_info = sr_lydmods_parse(ly_ctx, &sr_mods))) {
        goto cleanup;
    }

    if (mod_name) {
        if (asprintf(&pred, "[name=\"%s\"]", mod_name) == -1) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }

        /* we expect the module to exist */
        lyd_find_sibling_val(lyd_child(sr_mods), s_mod, pred, strlen(pred), &sr_mod);
        assert(sr_mod);

        /* set replay support */
        if ((err_info = sr_lydmods_update_replay_support_module(sr_mod, replay_support, s_replay))) {
            goto cleanup;
        }
    } else {
        LY_LIST_FOR(lyd_child(sr_mods), sr_mod) {
            if (sr_mod->schema != s_mod) {
                continue;
            }

            /* set replay support */
            if ((err_info = sr_lydmods_update_replay_support_module(sr_mod, replay_support, s_replay))) {
                goto cleanup;
            }
        }
    }

    /* store the updated persistent data tree */
    if ((err_info = sr_lydmods_print(&sr_mods))) {
        goto cleanup;
    }

    /* success */

cleanup:
    /* LYDMODS UNLOCK */
    sr_munlock(&main_shm->lydmods_lock);

    free(pred);
    lyd_free_all(sr_mods);
    return err_info;
}
