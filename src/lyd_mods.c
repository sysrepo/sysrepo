/**
 * @file lyd_mods.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Sysrepo module data routines
 *
 * @copyright
 * Copyright 2019 - 2021 CESNET, z.s.p.o.
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

#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define NEW_REVISION 2019-01-04
#define OLD_REVISION 2016-06-21

#include "../modules/ietf_datastores_yang.h"
#include "../modules/sysrepo_yang.h"
#if SR_YANGLIB_REVISION == NEW_REVISION
# include "../modules/ietf_yang_library@2019_01_04_yang.h"
#elif SR_YANGLIB_REVISION == OLD_REVISION
# include "../modules/ietf_yang_library@2016_06_21_yang.h"
#else
# error "Unknown yang-library revision!"
#endif

#include "../modules/ietf_netconf_notifications_yang.h"
#include "../modules/ietf_netconf_with_defaults_yang.h"
#include "../modules/ietf_netconf_yang.h"
#include "../modules/ietf_origin_yang.h"
#include "../modules/sysrepo_monitoring_yang.h"
#include "../modules/sysrepo_plugind_yang.h"

static sr_error_info_t *sr_lydmods_add_deps_r(struct lyd_node *sr_mod, struct lys_node *data_root, struct lyd_node *sr_deps);

sr_error_info_t *
sr_lydmods_lock(pthread_mutex_t *lock, const struct ly_ctx *ly_ctx, const char *func)
{
    struct sr_shmmod_recover_cb_s cb_data;

    cb_data.ly_mod = ly_ctx_get_module(ly_ctx, SR_YANG_MOD, NULL, 1);
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
    sr_mods = lyd_parse_path(ly_ctx, path, LYD_LYB, LYD_OPT_DATA | LYD_OPT_LYB_MOD_UPDATE | LYD_OPT_STRICT | LYD_OPT_TRUSTED);
    if (!sr_mods) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    /* success */

cleanup:
    free(path);
    if (err_info) {
        lyd_free_withsiblings(sr_mods);
    } else {
        *sr_mods_p = sr_mods;
    }
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
            SR_ERRINFO_SYSERRNO(&err_info, "access");
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

    assert(sr_mods && *sr_mods && !strcmp((*sr_mods)->schema->module->name, SR_YANG_MOD));

    /* get the module */
    sr_ly_mod = (*sr_mods)->schema->module;

    /* validate */
    if (lyd_validate_modules(sr_mods, &sr_ly_mod, 1, LYD_OPT_DATA)) {
        sr_errinfo_new_ly(&err_info, sr_ly_mod->ctx);
        return err_info;
    }

    /* store the data */
    if ((err_info = sr_module_file_data_set(SR_YANG_MOD, SR_DS_STARTUP, *sr_mods, O_CREAT, SR_INT_FILE_PERM))) {
        return err_info;
    }

    return NULL;
}

/**
 * @brief Add (collect) RPC/action data dependencies into internal sysrepo data.
 *
 * @param[in] sr_mod Module of the data.
 * @param[in] op_root Root node of the RPC/action data to inspect.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_add_rpc_deps(struct lyd_node *sr_mod, struct lys_node *op_root)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_rpc, *ly_cur_deps;
    struct lys_node *op_child;
    struct ly_set *set = NULL;
    char *data_path = NULL, *xpath = NULL;
    struct ly_ctx *ly_ctx = lys_node_module(op_root)->ctx;

    assert(op_root->nodetype & (LYS_RPC | LYS_ACTION));

    data_path = lys_data_path(op_root);
    SR_CHECK_MEM_GOTO(!data_path, err_info, cleanup);
    if (asprintf(&xpath, "rpc[path='%s']", data_path) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }

    set = lyd_find_path(sr_mod, xpath);
    SR_CHECK_INT_GOTO(!set, err_info, cleanup);
    if (set->number == 1) {
        /* already exists */
        goto cleanup;
    }
    assert(!set->number);

    sr_rpc = lyd_new(sr_mod, NULL, "rpc");
    if (!sr_rpc) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    /* RPC path */
    if (!lyd_new_leaf(sr_rpc, NULL, "path", data_path)) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    /* collect RPC/action dependencies of nested data and put them into correct containers */
    LY_TREE_FOR(op_root->child, op_child) {
        SR_CHECK_INT_GOTO(!(op_child->nodetype & (LYS_INPUT | LYS_OUTPUT)), err_info, cleanup);

        if (op_child->nodetype == LYS_INPUT) {
            ly_cur_deps = lyd_new(sr_rpc, NULL, "in");
        } else {
            ly_cur_deps = lyd_new(sr_rpc, NULL, "out");
        }
        if (!ly_cur_deps) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            goto cleanup;
        }

        if ((err_info = sr_lydmods_add_deps_r(sr_mod, op_child, ly_cur_deps))) {
            goto cleanup;
        }
    }


cleanup:
    ly_set_free(set);
    free(data_path);
    free(xpath);
    return err_info;
}

/**
 * @brief Add (collect) notification data dependencies into internal sysrepo data.
 *
 * @param[in] sr_mod Module of the data.
 * @param[in] op_root Root node of the notification data to inspect.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_add_notif_deps(struct lyd_node *sr_mod, struct lys_node *op_root)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_notif, *ly_cur_deps;
    struct ly_set *set = NULL;
    char *data_path = NULL, *xpath = NULL;
    struct ly_ctx *ly_ctx = lys_node_module(op_root)->ctx;

    assert(op_root->nodetype == LYS_NOTIF);

    data_path = lys_data_path(op_root);
    SR_CHECK_MEM_GOTO(!data_path, err_info, cleanup);
    if (asprintf(&xpath, "notification[path='%s']", data_path) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }

    set = lyd_find_path(sr_mod, xpath);
    SR_CHECK_INT_GOTO(!set, err_info, cleanup);
    if (set->number == 1) {
        /* already exists */
        goto cleanup;
    }
    assert(!set->number);

    sr_notif = lyd_new(sr_mod, NULL, "notification");
    if (!sr_notif) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    /* operation dep xpath */
    if (!lyd_new_leaf(sr_notif, NULL, "path", data_path)) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    /* collect dependencies of nested data and put them into correct containers */
    ly_cur_deps = lyd_new(sr_notif, NULL, "deps");
    if (!ly_cur_deps) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    if ((err_info = sr_lydmods_add_deps_r(sr_mod, op_root, ly_cur_deps))) {
        goto cleanup;
    }

cleanup:
    ly_set_free(set);
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
sr_lydmods_moddep_add(struct lyd_node *sr_deps, sr_dep_type_t dep_type, const char *mod_name, const struct lys_node *node)
{
    const struct lys_node *data_child;
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
        case LYS_INPUT:
        case LYS_OUTPUT:
        case LYS_USES:
        case LYS_AUGMENT:
            /* not data-instantiable nodes, we need to find all such nodes */
            assert(dep_type != SR_DEP_INSTID);
            data_child = NULL;
            while ((data_child = lys_getnext(data_child, node, NULL, LYS_GETNEXT_PARENTUSES | LYS_GETNEXT_NOSTATECHECK))) {
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
        data_path = lys_data_path(node);
        if (!data_path || (asprintf(&expr, "inst-id[path='%s']", data_path) == -1)) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }
    }

    /* check that there is not a duplicity */
    set = lyd_find_path(sr_deps, expr);
    if (!set || (set->number > 1)) {
        if (!set) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(sr_deps)->ctx);
        } else {
            SR_ERRINFO_INT(&err_info);
        }
        goto cleanup;
    }
    if (set->number) {
        /* already exists */
        goto cleanup;
    }

    /* create new dependency */
    if (dep_type == SR_DEP_REF) {
        if (!lyd_new_leaf(sr_deps, NULL, "module", mod_name)) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(sr_deps)->ctx);
            goto cleanup;
        }
    } else {
        sr_instid = lyd_new(sr_deps, NULL, "inst-id");
        if (!sr_instid) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(sr_deps)->ctx);
            goto cleanup;
        }
        if (!lyd_new_leaf(sr_instid, NULL, "path", data_path)) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(sr_deps)->ctx);
            goto cleanup;
        }
        if (mod_name && !lyd_new_leaf(sr_instid, NULL, "default-module", mod_name)) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(sr_deps)->ctx);
            goto cleanup;
        }
    }

cleanup:
    ly_set_free(set);
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
sr_lydmods_moddep_expr_atom_is_foreign(const struct lys_node *atom, const struct lys_node *top_node)
{
    assert(atom && top_node && (!lys_parent(top_node) || (top_node->nodetype & (LYS_RPC | LYS_ACTION | LYS_NOTIF))));

    while (lys_parent(atom) && (atom != top_node)) {
        atom = lys_parent(atom);
    }

    if (atom == top_node) {
        /* shared parent, local node */
        return NULL;
    }

    if (top_node->nodetype & (LYS_RPC | LYS_ACTION | LYS_NOTIF)) {
        /* outside operation, foreign node */
        return (struct lys_module *)lys_node_module(atom);
    }

    if (lys_node_module(atom) != lys_node_module(top_node)) {
        /* foreing top-level node module (so cannot be augment), foreign node */
        return (struct lys_module *)lys_node_module(atom);
    }

    /* same top-level modules, local node */
    return NULL;
}

/**
 * @brief Collect dependencies from an XPath expression.
 *
 * @param[in] ctx_node Expression context node.
 * @param[in] expr Expression.
 * @param[in] lyxp_opt libyang lyxp options.
 * @param[out] dep_mods Array of dependent modules.
 * @param[out] dep_mod_count Dependent module count.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_moddep_expr_get_dep_mods(const struct lys_node *ctx_node, const char *expr, int lyxp_opt,
        struct lys_module ***dep_mods, size_t *dep_mod_count)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set;
    const struct lys_node *top_node;
    struct lys_module *dep_mod;
    size_t i, j;

    /* find out if we are in an operation, otherwise simply find top-level node */
    top_node = ctx_node;
    while (!(top_node->nodetype & (LYS_ACTION | LYS_NOTIF)) && lys_parent(top_node)) {
        top_node = lys_parent(top_node);
    }

    /* get all atoms of the XPath condition */
    set = lys_xpath_atomize(ctx_node, LYXP_NODE_ELEM, expr, lyxp_opt);
    if (!set) {
        sr_errinfo_new_ly(&err_info, lys_node_module(ctx_node)->ctx);
        return err_info;
    }

    /* find all top-level foreign nodes (augment nodes are not considered foreign now) */
    for (i = 0; i < set->number; ++i) {
        if ((dep_mod = sr_lydmods_moddep_expr_atom_is_foreign(set->set.s[i], top_node))) {
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
                    goto cleanup;
                }

                (*dep_mods)[*dep_mod_count] = dep_mod;
                ++(*dep_mod_count);
            }
        }
    }

    /* success */

cleanup:
    ly_set_free(set);
    return err_info;
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
sr_lydmods_moddep_type(const struct lys_type *type, struct lys_node *node, struct lyd_node *sr_deps)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_type *t;
    struct lys_module **dep_mods = NULL;
    size_t dep_mod_count = 0;

    switch (type->base) {
    case LY_TYPE_INST:
        if ((node->nodetype == LYS_LEAF) && ((struct lys_node_leaf *)node)->dflt) {
            if ((err_info = sr_lydmods_moddep_expr_get_dep_mods(node, ((struct lys_node_leaf *)node)->dflt, 0, &dep_mods,
                    &dep_mod_count))) {
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
        assert(type->info.lref.path);
        if ((err_info = sr_lydmods_moddep_expr_get_dep_mods(node, type->info.lref.path, 0, &dep_mods, &dep_mod_count))) {
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
        t = NULL;
        while ((t = lys_getnext_union_type(t, type))) {
            if ((err_info = sr_lydmods_moddep_type(t, node, sr_deps))) {
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
 * @brief Add (collect) dependencies into internal sysrepo data tree starting with a subtree, recursively.
 *
 * @param[in] sr_mod Module of the data from sysrepo data tree.
 * @param[in] data_root Root node of the data to inspect.
 * @param[in] sr_deps Internal sysrepo dependencies to add to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_add_deps_r(struct lyd_node *sr_mod, struct lys_node *data_root, struct lyd_node *sr_deps)
{
    sr_error_info_t *err_info = NULL;
    struct lys_module **dep_mods;
    size_t dep_mod_count;
    struct lys_node *next, *elem;
    struct lys_type *type;
    struct lys_when *when;
    struct lys_restr *musts;
    uint8_t i, must_size;

    for (elem = next = data_root; elem; elem = next) {
        /* skip disabled nodes */
        if (lys_is_disabled(elem, 0)) {
            goto next_sibling;
        }

        type = NULL;
        when = NULL;
        must_size = 0;
        musts = NULL;
        dep_mods = NULL;
        dep_mod_count = 0;

        switch (elem->nodetype) {
        case LYS_LEAF:
            type = &((struct lys_node_leaf *)elem)->type;
            when = ((struct lys_node_leaf *)elem)->when;
            must_size = ((struct lys_node_leaf *)elem)->must_size;
            musts = ((struct lys_node_leaf *)elem)->must;
            break;
        case LYS_LEAFLIST:
            type = &((struct lys_node_leaflist *)elem)->type;
            when = ((struct lys_node_leaflist *)elem)->when;
            must_size = ((struct lys_node_leaflist *)elem)->must_size;
            musts = ((struct lys_node_leaflist *)elem)->must;
            break;
        case LYS_CONTAINER:
            when = ((struct lys_node_container *)elem)->when;
            must_size = ((struct lys_node_container *)elem)->must_size;
            musts = ((struct lys_node_container *)elem)->must;
            break;
        case LYS_CHOICE:
            when = ((struct lys_node_choice *)elem)->when;
            break;
        case LYS_LIST:
            when = ((struct lys_node_list *)elem)->when;
            must_size = ((struct lys_node_list *)elem)->must_size;
            musts = ((struct lys_node_list *)elem)->must;
            break;
        case LYS_ANYDATA:
        case LYS_ANYXML:
            when = ((struct lys_node_anydata *)elem)->when;
            must_size = ((struct lys_node_anydata *)elem)->must_size;
            musts = ((struct lys_node_anydata *)elem)->must;
            break;
        case LYS_CASE:
            when = ((struct lys_node_case *)elem)->when;
            break;
        case LYS_RPC:
        case LYS_ACTION:
            /* RPC/action, put the dependencies separately */
            if ((err_info = sr_lydmods_add_rpc_deps(sr_mod, elem))) {
                return err_info;
            }
            goto next_sibling;
        case LYS_INPUT:
        case LYS_OUTPUT:
            assert(elem == data_root);
            must_size = ((struct lys_node_inout *)elem)->must_size;
            musts = ((struct lys_node_inout *)elem)->must;
            break;
        case LYS_NOTIF:
            if (!strcmp(sr_deps->parent->schema->name, "notification")) {
                /* recursive call in this case */
                must_size = ((struct lys_node_notif *)elem)->must_size;
                musts = ((struct lys_node_notif *)elem)->must;
            } else {
                /* operation, put the dependencies separately */
                if ((err_info = sr_lydmods_add_notif_deps(sr_mod, elem))) {
                    return err_info;
                }
                goto next_sibling;
            }
            break;
        case LYS_USES:
            when = ((struct lys_node_uses *)elem)->when;
            break;
        case LYS_AUGMENT:
            when = ((struct lys_node_augment *)elem)->when;
            break;
        case LYS_GROUPING:
            /* skip groupings */
            goto next_sibling;
        default:
            SR_ERRINFO_INT(&err_info);
            return err_info;
        }

        /* collect the dependencies */
        if (type) {
            if ((err_info = sr_lydmods_moddep_type(type, elem, sr_deps))) {
                return err_info;
            }
        }
        if (when) {
            if ((err_info = sr_lydmods_moddep_expr_get_dep_mods(elem, when->cond, LYXP_WHEN, &dep_mods, &dep_mod_count))) {
                return err_info;
            }
        }
        for (i = 0; i < must_size; ++i) {
            if ((err_info = sr_lydmods_moddep_expr_get_dep_mods(elem, musts[i].expr, LYXP_MUST, &dep_mods, &dep_mod_count))) {
                free(dep_mods);
                return err_info;
            }
        }

        /* add those collected from when and must */
        for (i = 0; i < dep_mod_count; ++i) {
            if ((err_info = sr_lydmods_moddep_add(sr_deps, SR_DEP_REF, dep_mods[i]->name, NULL))) {
                free(dep_mods);
                return err_info;
            }
        }
        free(dep_mods);

        /* LY_TREE_DFS_END */
        if (elem->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYDATA)) {
            next = NULL;
        } else {
            next = elem->child;
        }
        if (!next) {
next_sibling:
            /* no children */
            if (elem == data_root) {
                /* we are done, (START) has no children */
                break;
            }
            /* try siblings */
            next = elem->next;
        }
        while (!next) {
            /* parent is already processed, go to its sibling */
            elem = lys_parent(elem);
            /* no siblings, go back through parents */
            if (lys_parent(elem) == lys_parent(data_root)) {
                /* we are done, no next element to process */
                break;
            }
            next = elem->next;
        }
    }

    return NULL;
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
    struct lys_feature *feat;
    uint32_t i;

    sr_mod = lyd_new(sr_mods, NULL, "module");
    if (!sr_mod) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        return err_info;
    }
    if (!lyd_new_leaf(sr_mod, NULL, "name", ly_mod->name)) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        return err_info;
    }
    if (ly_mod->rev_size && !lyd_new_leaf(sr_mod, NULL, "revision", ly_mod->rev[0].date)) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        return err_info;
    }

    /* enable all the features */
    feat = NULL;
    while ((feat = sr_lys_next_feature(feat, ly_mod, &i))) {
        if (feat->flags & LYS_FENABLED) {
            if (!lyd_new_leaf(sr_mod, NULL, "enabled-feature", feat->name)) {
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
    const struct lys_module *cur_mod;
    struct ly_set *set = NULL;
    char *xpath = NULL;
    uint8_t i, j;

    if ((err_info = sr_store_module_files(ly_mod))) {
        goto cleanup;
    }

    if (ly_mod->implemented) {
        /* check the module was not already added */
        if (asprintf(&xpath, "module[name='%s']", ly_mod->name) == -1) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }
        set = lyd_find_path(sr_mods, xpath);
        if (!set) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(sr_mods)->ctx);
            goto cleanup;
        } else if (!set->number) {
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
    j = 0;
    cur_mod = ly_mod;
    while (1) {
        for (i = 0; i < cur_mod->imp_size; ++i) {
            if ((err_info = sr_lydmods_add_module_with_imps_r(sr_mods, cur_mod->imp[i].module, log_first))) {
                goto cleanup;
            }
        }

        if (j == ly_mod->inc_size) {
            break;
        }

        /* next iter */
        cur_mod = (const struct lys_module *)ly_mod->inc[j].submodule;
        ++j;
    }

cleanup:
    free(xpath);
    ly_set_free(set);
    return err_info;
}

/**
 * @brief Create default sysrepo module data. All libyang internal implemented modules
 * are installed into sysrepo. Sysrepo internal modules ietf-netconf, ietf-netconf-with-defaults,
 * and ietf-netconf-notifications are also installed.
 *
 * @param[in] ly_ctx Context to use for creating the data.
 * @param[out] sr_mods_p Created default sysrepo module data.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_create(struct ly_ctx *ly_ctx, struct lyd_node **sr_mods_p)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    struct lyd_node *sr_mods = NULL;
    uint32_t i;

#define SR_INSTALL_INT_MOD(yang_mod, dep) \
    if (!(ly_mod = lys_parse_mem(ly_ctx, yang_mod, LYS_YANG))) { \
        sr_errinfo_new_ly(&err_info, ly_ctx); \
        goto error; \
    } \
    if ((err_info = sr_lydmods_add_module_with_imps_r(sr_mods, ly_mod, 0))) { \
        goto error; \
    } \
    SR_LOG_INF("Sysrepo internal%s module \"%s\" was installed.", dep ? " dependency" : "", ly_mod->name)

    ly_mod = ly_ctx_get_module(ly_ctx, SR_YANG_MOD, NULL, 1);
    SR_CHECK_INT_RET(!ly_mod, err_info);

    /* create empty container */
    sr_mods = lyd_new(NULL, ly_mod, "sysrepo-modules");
    SR_CHECK_INT_RET(!sr_mods, err_info);

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
    SR_INSTALL_INT_MOD(ietf_datastores_yang, 1);
    SR_INSTALL_INT_MOD(ietf_yang_library_yang, 0);

    /* install sysrepo-monitoring */
    SR_INSTALL_INT_MOD(sysrepo_monitoring_yang, 0);

    /* install sysrepo-plugind */
    SR_INSTALL_INT_MOD(sysrepo_plugind_yang, 0);

    /* install ietf-netconf (implemented dependency) and ietf-netconf-with-defaults */
    SR_INSTALL_INT_MOD(ietf_netconf_yang, 1);
    SR_INSTALL_INT_MOD(ietf_netconf_with_defaults_yang, 0);

    /* install ietf-netconf-notifications */
    SR_INSTALL_INT_MOD(ietf_netconf_notifications_yang, 0);

    /* install ietf-origin */
    SR_INSTALL_INT_MOD(ietf_origin_yang, 0);

    *sr_mods_p = sr_mods;
    return NULL;

error:
    lyd_free_withsiblings(sr_mods);
    return err_info;

#undef SR_INSTALL_INT_MOD
}

/**
 * @brief Load a module into context (if not already there) based on its information from sysrepo module data.
 *
 * @param[in] sr_mod Module from sysrepo mdoule data to load.
 * @param[in] ly_ctx Context to load the module into.
 * @param[out] ly_mod Optionally return the loaded module.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_ctx_load_module(const struct lyd_node *sr_mod, struct ly_ctx *ly_ctx, const struct lys_module **ly_mod_p)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *node;
    const struct lys_module *ly_mod;
    struct ly_set *feat_set = NULL;
    const char *mod_name, *revision;
    uint32_t i;

    /* learn about the module */
    mod_name = NULL;
    revision = NULL;
    LY_TREE_FOR(sr_mod->child, node) {
        if (!strcmp(node->schema->name, "name")) {
            mod_name = sr_ly_leaf_value_str(node);
        } else if (!strcmp(node->schema->name, "revision")) {
            revision = sr_ly_leaf_value_str(node);
            break;
        }
    }
    assert(mod_name);

    /* the module is not supposed to be loaded yet, but is in case of LY internal modules and dependency modules */
    ly_mod = ly_ctx_get_module(ly_ctx, mod_name, revision, 1);
    if (!ly_mod || !ly_mod->implemented) {
        /* load the module */
        ly_mod = ly_ctx_load_module(ly_ctx, mod_name, revision);
    }
    if (!ly_mod) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    /* collect all currently enabled features */
    feat_set = lyd_find_path(sr_mod, "enabled-feature");
    if (!feat_set) {
        sr_errinfo_new_ly(&err_info, lyd_node_module(sr_mod)->ctx);
        goto cleanup;
    }

    /* enable all the features */
    for (i = 0; i < feat_set->number; ++i) {
        if (lys_features_enable_force(ly_mod, sr_ly_leaf_value_str(feat_set->set.d[i]))) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            goto cleanup;
        }
    }

    /* success */

cleanup:
    ly_set_free(feat_set);
    if (!err_info && ly_mod_p) {
        *ly_mod_p = ly_mod;
    }
    return err_info;
}

/**
 * @brief Load modules from sysrepo module data into context.
 *
 * @param[in] sr_mods Sysrepo module data.
 * @param[in] ly_ctx Context to load into.
 * @param[in] removed Whether to load removed modules.
 * @param[in] updated Whether to load updated modules.
 * @param[out] change Whether there were any removed or updated modules, if @p removed or @p updated was set.
 * @return error_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_ctx_load_modules(const struct lyd_node *sr_mods, struct ly_ctx *ly_ctx, int removed, int updated, int *change)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mod, *node;

    LY_TREE_FOR(sr_mods->child, sr_mod) {
        if (!strcmp(sr_mod->schema->name, "installed-module")) {
            continue;
        }
        if (!removed || !updated) {
            LY_TREE_FOR(sr_mod->child, node) {
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
        if ((err_info = sr_lydmods_ctx_load_module(sr_mod, ly_ctx, NULL))) {
            return err_info;
        }
    }

    return NULL;
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
    struct lyd_node *old_start_data = NULL, *new_start_data = NULL, *old_run_data = NULL, *new_run_data = NULL, *mod_data;
    struct ly_ctx *old_ctx = NULL;
    struct ly_set *set = NULL, *startup_set = NULL;
    const struct lys_module *ly_mod;
    char *start_data_json = NULL, *run_data_json = NULL, *path;
    uint32_t idx;
    int exists;

    set = ly_set_new();
    SR_CHECK_MEM_GOTO(!set, err_info, cleanup);

    /* first build context without any scheduled changes */
    if ((err_info = sr_ly_ctx_new(&old_ctx))) {
        goto cleanup;
    }
    if ((err_info = sr_lydmods_ctx_load_modules(sr_mods, old_ctx, 1, 1, NULL))) {
        goto cleanup;
    }

    /* parse all the startup/running data using the old context (that must succeed) */
    idx = 0;
    while ((ly_mod = ly_ctx_get_module_iter(old_ctx, &idx))) {
        if (!ly_mod->implemented) {
            /* we need data of only implemented modules */
            continue;
        }

        /* append startup data */
        if ((err_info = sr_module_file_data_append(ly_mod, SR_DS_STARTUP, &old_start_data))) {
            goto cleanup;
        }

        /* check that running data file exists */
        if ((err_info = sr_path_ds_shm(ly_mod->name, SR_DS_RUNNING, &path))) {
            goto cleanup;
        }
        exists = sr_file_exists(path);
        free(path);

        if (exists) {
            /* append running data */
            if ((err_info = sr_module_file_data_append(ly_mod, SR_DS_RUNNING, &old_run_data))) {
                goto cleanup;
            }
        }

        /* remember this module from the new context */
        ly_mod = ly_ctx_get_module(new_ctx, ly_mod->name, NULL, 1);
        if (ly_mod) {
            assert(ly_mod->implemented);
            ly_set_add(set, (void *)ly_mod, LY_SET_OPT_USEASLIST);
        } /* else the module was removed */
    }

    /* print the data of all the modules into JSON */
    if (lyd_print_mem(&start_data_json, old_start_data, LYD_JSON, LYP_WITHSIBLINGS)) {
        sr_errinfo_new_ly(&err_info, old_ctx);
        goto cleanup;
    }
    if (lyd_print_mem(&run_data_json, old_run_data, LYD_JSON, LYP_WITHSIBLINGS)) {
        sr_errinfo_new_ly(&err_info, old_ctx);
        goto cleanup;
    }

    /* try to load it into the new updated context skipping any unknown nodes */
    ly_errno = 0;
    new_start_data = lyd_parse_mem((struct ly_ctx *)new_ctx, start_data_json, LYD_JSON,
            LYD_OPT_CONFIG | LYD_OPT_TRUSTED);
    if (!ly_errno) {
        new_run_data = lyd_parse_mem((struct ly_ctx *)new_ctx, run_data_json, LYD_JSON,
            LYD_OPT_CONFIG | LYD_OPT_TRUSTED);
    }
    if (ly_errno) {
        /* it failed, some of the scheduled changes are not compatible with the stored data, abort them all */
        sr_log_wrn_ly((struct ly_ctx *)new_ctx);
        *fail = 1;
        goto cleanup;
    }

    /* check that any startup data can be loaded and are valid */
    startup_set = lyd_find_path(sr_mods, "installed-module/data");
    if (!startup_set) {
        sr_errinfo_new_ly(&err_info, lyd_node_module(sr_mods)->ctx);
        goto cleanup;
    }
    for (idx = 0; idx < startup_set->number; ++idx) {
        ly_errno = 0;
        mod_data = lyd_parse_mem((struct ly_ctx *)new_ctx, sr_ly_leaf_value_str(startup_set->set.d[idx]), LYD_JSON,
                LYD_OPT_CONFIG | LYD_OPT_TRUSTED | LYD_OPT_STRICT);
        /* this was parsed before */
        assert(!ly_errno);
        if (!mod_data) {
            continue;
        }

        /* remember this module */
        ly_set_add(set, (void *)lyd_node_module(mod_data), LY_SET_OPT_USEASLIST);

        /* link to the new startup/running data */
        if (!new_start_data) {
            new_start_data = lyd_dup_withsiblings(mod_data, LYD_DUP_OPT_RECURSIVE | LYD_DUP_OPT_WITH_WHEN);
            SR_CHECK_MEM_GOTO(!new_start_data, err_info, cleanup);
        } else if (lyd_merge(new_start_data, mod_data, LYD_OPT_EXPLICIT)) {
            sr_errinfo_new_ly(&err_info, (struct ly_ctx *)new_ctx);
            goto cleanup;
        }
        if (!new_run_data) {
            new_run_data = mod_data;
        } else if (lyd_merge(new_run_data, mod_data, LYD_OPT_EXPLICIT | LYD_OPT_DESTRUCT)) {
            sr_errinfo_new_ly(&err_info, (struct ly_ctx *)new_ctx);
            goto cleanup;
        }
    }

    /* fully validate complete startup and running datastore */
    if (lyd_validate(&new_start_data, LYD_OPT_CONFIG, (void *)new_ctx) ||
            lyd_validate(&new_run_data, LYD_OPT_CONFIG, (void *)new_ctx)) {
        sr_log_wrn_ly((struct ly_ctx *)new_ctx);
        *fail = 1;
        goto cleanup;
    }

    /* print all modules data with the updated module context and free them, no longer needed */
    for (idx = 0; idx < set->number; ++idx) {
        ly_mod = (struct lys_module *)set->set.g[idx];

        /* startup data */
        mod_data = sr_module_data_unlink(&new_start_data, ly_mod);
        if ((err_info = sr_module_file_data_set(ly_mod->name, SR_DS_STARTUP, mod_data, O_CREAT, SR_FILE_PERM))) {
            lyd_free_withsiblings(mod_data);
            goto cleanup;
        }
        lyd_free_withsiblings(mod_data);

        /* running data */
        mod_data = sr_module_data_unlink(&new_run_data, ly_mod);
        if ((err_info = sr_module_file_data_set(ly_mod->name, SR_DS_RUNNING, mod_data, O_CREAT, SR_FILE_PERM))) {
            lyd_free_withsiblings(mod_data);
            goto cleanup;
        }
        lyd_free_withsiblings(mod_data);
    }

    /* success */

cleanup:
    ly_set_free(set);
    ly_set_free(startup_set);
    lyd_free_withsiblings(old_start_data);
    lyd_free_withsiblings(new_start_data);
    lyd_free_withsiblings(old_run_data);
    lyd_free_withsiblings(new_run_data);
    free(start_data_json);
    free(run_data_json);
    ly_ctx_destroy(old_ctx, NULL);
    if (err_info) {
        sr_errinfo_new(&err_info, SR_ERR_OPERATION_FAILED, NULL, "Failed to update data for the new context.");
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
    uint32_t idx;
    uint8_t i;

    assert(!strcmp(sr_mod->child->schema->name, "name"));
    mod_name = sr_ly_leaf_value_str(sr_mod->child);
    if (sr_mod->child->next && !strcmp(sr_mod->child->next->schema->name, "revision")) {
        mod_rev = sr_ly_leaf_value_str(sr_mod->child->next);
    } else {
        mod_rev = NULL;
    }

    /* remove data files */
    if (!update && (err_info = sr_remove_data_files(mod_name))) {
        return err_info;
    }

    /* check whether it is imported by other modules */
    idx = ly_ctx_internal_modules_count((struct ly_ctx *)new_ctx);
    while ((ly_mod = ly_ctx_get_module_iter(new_ctx, &idx))) {
        for (i = 0; i < ly_mod->imp_size; ++i) {
            if (!strcmp(ly_mod->imp[i].module->name, mod_name)) {
                break;
            }
        }
        if (i < ly_mod->imp_size) {
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
    lyd_free(sr_mod);
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

    sr_mods = sr_mod->parent;

    /* find the updated module in the new context */
    assert(!strcmp(sr_mod->child->schema->name, "name"));
    ly_mod = ly_ctx_get_module(new_ctx, sr_ly_leaf_value_str(sr_mod->child), NULL, 1);
    assert(ly_mod);

    /* remove module */
    if ((err_info = sr_lydmods_sched_finalize_module_remove(sr_mod, new_ctx, 1))) {
        return err_info;
    }

    /* re-add it (only the data files are kept) */
    if ((err_info = sr_lydmods_add_module_with_imps_r(sr_mods, ly_mod, 0))) {
        return err_info;
    }

    SR_LOG_INF("Module \"%s\" was updated to revision %s.", ly_mod->name, ly_mod->rev[0].date);
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
    struct ly_set *set;
    int enable;
    char *xpath;

    assert(!strcmp(sr_mod->child->schema->name, "name"));
    ly_mod = ly_ctx_get_module(new_ctx, sr_ly_leaf_value_str(sr_mod->child), NULL, 1);
    assert(ly_mod);

    LY_TREE_FOR_SAFE(sr_mod->child->next, next, node) {
        if (!strcmp(node->schema->name, "changed-feature")) {
            /*
             * changed feature
             */
            assert(!strcmp(node->child->schema->name, "name"));
            assert(!strcmp(node->child->next->schema->name, "change"));

            feat_name = sr_ly_leaf_value_str(node->child);
            enable = !strcmp(sr_ly_leaf_value_str(node->child->next), "enable") ? 1 : 0;
            lyd_free(node);

            /* update internal sysrepo data tree */
            if (enable) {
                node = lyd_new_path(sr_mod, NULL, "enabled-feature", (void *)feat_name, 0, 0);
                if (!node) {
                    sr_errinfo_new_ly(&err_info, lyd_node_module(sr_mod)->ctx);
                    return err_info;
                }
            } else {
                if (asprintf(&xpath, "enabled-feature[.='%s']", feat_name) == -1) {
                    SR_ERRINFO_MEM(&err_info);
                    return err_info;
                }
                set = lyd_find_path(sr_mod, xpath);
                free(xpath);
                if (!set) {
                    sr_errinfo_new_ly(&err_info, lyd_node_module(sr_mod)->ctx);
                    return err_info;
                }
                assert(set->number == 1);
                lyd_free(set->set.d[0]);
                ly_set_free(set);
            }

            SR_LOG_INF("Module \"%s\" feature \"%s\" was %s.", ly_mod->name, feat_name, enable ? "enabled" : "disabled");
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
    uint32_t i;

    LY_TREE_FOR(sr_mod->next, node) {
        if (strcmp(node->schema->name, "installed-module")) {
            continue;
        }

        assert(!strcmp(node->child->schema->name, "name"));
        ly_mod = ly_ctx_get_module(new_ctx, sr_ly_leaf_value_str(node->child), NULL, 1);
        assert(ly_mod);

        for (i = 0; i < ly_mod->imp_size; ++i) {
            if (ly_mod->imp[i].module->implemented && !strcmp(ly_mod->imp[i].module->name, sr_ly_leaf_value_str(sr_mod->child))) {
                /* we will install this module as a dependency of a module installed later */
                SR_LOG_INF("Module \"%s\" will be installed as \"%s\" module dependency.",
                        sr_ly_leaf_value_str(sr_mod->child), ly_mod->name);
                lyd_free(sr_mod);
                return NULL;
            }
        }
    }

    sr_mods = sr_mod->parent;

    /*
     * installed module, store new YANG, install all of its implemented dependencies
     */
    assert(!strcmp(sr_mod->child->schema->name, "name"));
    ly_mod = ly_ctx_get_module(new_ctx, sr_ly_leaf_value_str(sr_mod->child), NULL, 1);
    assert(ly_mod);
    lyd_free(sr_mod);

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
    LY_TREE_FOR(sr_mod->child, node) {
        if (strcmp(node->schema->name, "inverse-deps")) {
            continue;
        }

        if (!strcmp(sr_ly_leaf_value_str(node), inv_dep_mod)) {
            /* exists already */
            return NULL;
        }
    }

    node = lyd_new_leaf(sr_mod, NULL, "inverse-deps", inv_dep_mod);
    if (!node) {
        sr_errinfo_new_ly(&err_info, lyd_node_module(sr_mod)->ctx);
    }

    return err_info;
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
    struct lys_node *root;
    struct ly_set *set = NULL, *set2;
    struct lyd_node *ly_deps;
    uint16_t i;
    char *xpath;

#ifndef NDEBUG
    /* there can be no dependencies yet (but inverse ones yes) */
    set = lyd_find_path(sr_mod, "deps | rpcs | notifications");
    assert(set);
    assert(!set->number || ((set->number == 1) && set->set.d[0]->dflt));
    ly_set_free(set);
    set = NULL;
#endif

    /* create new deps */
    ly_deps = lyd_new(sr_mod, NULL, "deps");
    if (!ly_deps) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        goto cleanup;
    }

    /* add all the data */
    LY_TREE_FOR(ly_mod->data, root) {
        if ((err_info = sr_lydmods_add_deps_r(sr_mod, root, ly_deps))) {
            goto cleanup;
        }
    }

    /* add inverse data deps */
    set = lyd_find_path(sr_mod, "deps/module");
    if (!set) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        goto cleanup;
    }

    for (i = 0; i < set->number; ++i) {
        if (asprintf(&xpath, "module[name='%s']", sr_ly_leaf_value_str(set->set.d[i])) == -1) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }

        /* find the dependent module */
        set2 = lyd_find_path(sr_mod->parent, xpath);
        free(xpath);
        if (!set2) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }
        assert(set2->number == 1);

        /* add inverse dependency */
        err_info = sr_lydmods_add_inv_data_dep(set2->set.d[0], sr_ly_leaf_value_str(sr_mod->child));
        ly_set_free(set2);
        if (err_info) {
            goto cleanup;
        }
    }

    /* success */

cleanup:
    ly_set_free(set);
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
    set = lyd_find_path(sr_mods, "/" SR_YANG_MOD ":sysrepo-modules/module[removed]");
    if (!set) {
        sr_errinfo_new_ly(&err_info, lyd_node_module(sr_mods)->ctx);
        goto cleanup;
    } else if (!set->number) {
        /* nothing to do */
        goto cleanup;
    }

    /* check that the removed modules are not implemented in the new context */
    for (i = 0; i < set->number; ++i) {
        /* learn about the module */
        mod_name = NULL;
        revision = NULL;
        LY_TREE_FOR(set->set.d[i]->child, node) {
            if (!strcmp(node->schema->name, "name")) {
                mod_name = sr_ly_leaf_value_str(node);
            } else if (!strcmp(node->schema->name, "revision")) {
                revision = sr_ly_leaf_value_str(node);
                break;
            }
        }
        assert(mod_name);

        ly_mod = ly_ctx_get_module(new_ctx, mod_name, revision, 0);
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
    ly_set_free(set);
    return err_info;
}

/**
 * @brief Check dependencies from a type.
 *
 * @param[in] type Type to inspect.
 * @param[in] node Type node.
 * @param[out] dep_mods Array of dependent modules.
 * @param[out] dep_mod_count Dependent module count.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_moddep_check_type(const struct lys_type *type, const struct lys_node *node, struct lys_module ***dep_mods,
        size_t *dep_mod_count)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_type *t;

    switch (type->base) {
    case LY_TYPE_INST:
        if ((node->nodetype == LYS_LEAF) && ((struct lys_node_leaf *)node)->dflt) {
            if ((err_info = sr_lydmods_moddep_expr_get_dep_mods(node, ((struct lys_node_leaf *)node)->dflt, 0, dep_mods,
                    dep_mod_count))) {
                return err_info;
            }
        }
        break;
    case LY_TYPE_UNION:
        t = NULL;
        while ((t = lys_getnext_union_type(t, type))) {
            if ((err_info = sr_lydmods_moddep_check_type(t, node, dep_mods, dep_mod_count))) {
                return err_info;
            }
        }
        break;
    default:
        /* no dependency, leafref must be handled by libyang */
        break;
    }

    return NULL;
}

/**
 * @brief Check data dependencies of a module.
 *
 * @param[in] ly_mod Libyang module to check.
 * @param[in] sr_mods Sysrepo module data.
 * @param[out] fail Whether any dependant module was not implemented.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_check_data_deps(const struct lys_module *ly_mod, const struct lyd_node *sr_mods, int *fail)
{
    sr_error_info_t *err_info = NULL;
    struct lys_module **dep_mods = NULL;
    size_t dep_mod_count = 0;
    const struct lys_node *root, *next, *elem;
    struct lys_type *type;
    struct lys_when *when;
    struct lys_restr *musts;
    uint8_t i, must_size;
    char *xpath;
    struct ly_set *set;

    LY_TREE_FOR(ly_mod->data, root) {
        for (elem = next = root; elem; elem = next) {
            /* skip disabled nodes */
            if (lys_is_disabled(elem, 0)) {
                goto next_sibling;
            }

            type = NULL;
            when = NULL;
            must_size = 0;
            musts = NULL;

            switch (elem->nodetype) {
            case LYS_LEAF:
                type = &((struct lys_node_leaf *)elem)->type;
                when = ((struct lys_node_leaf *)elem)->when;
                must_size = ((struct lys_node_leaf *)elem)->must_size;
                musts = ((struct lys_node_leaf *)elem)->must;
                break;
            case LYS_LEAFLIST:
                type = &((struct lys_node_leaflist *)elem)->type;
                when = ((struct lys_node_leaflist *)elem)->when;
                must_size = ((struct lys_node_leaflist *)elem)->must_size;
                musts = ((struct lys_node_leaflist *)elem)->must;
                break;
            case LYS_CONTAINER:
                when = ((struct lys_node_container *)elem)->when;
                must_size = ((struct lys_node_container *)elem)->must_size;
                musts = ((struct lys_node_container *)elem)->must;
                break;
            case LYS_CHOICE:
                when = ((struct lys_node_choice *)elem)->when;
                break;
            case LYS_LIST:
                when = ((struct lys_node_list *)elem)->when;
                must_size = ((struct lys_node_list *)elem)->must_size;
                musts = ((struct lys_node_list *)elem)->must;
                break;
            case LYS_ANYDATA:
            case LYS_ANYXML:
                when = ((struct lys_node_anydata *)elem)->when;
                must_size = ((struct lys_node_anydata *)elem)->must_size;
                musts = ((struct lys_node_anydata *)elem)->must;
                break;
            case LYS_CASE:
                when = ((struct lys_node_case *)elem)->when;
                break;
            case LYS_RPC:
            case LYS_ACTION:
                /* nothing to do */
                break;
            case LYS_INPUT:
            case LYS_OUTPUT:
                must_size = ((struct lys_node_inout *)elem)->must_size;
                musts = ((struct lys_node_inout *)elem)->must;
                break;
            case LYS_NOTIF:
                must_size = ((struct lys_node_notif *)elem)->must_size;
                musts = ((struct lys_node_notif *)elem)->must;
                break;
            case LYS_USES:
                when = ((struct lys_node_uses *)elem)->when;
                break;
            case LYS_AUGMENT:
                when = ((struct lys_node_augment *)elem)->when;
                break;
            case LYS_GROUPING:
                /* skip groupings */
                goto next_sibling;
            default:
                SR_ERRINFO_INT(&err_info);
                goto cleanup;
            }

            /* collect the dependencies */
            if (type) {
                if ((err_info = sr_lydmods_moddep_check_type(type, elem, &dep_mods, &dep_mod_count))) {
                    goto cleanup;
                }
            }
            if (when) {
                if ((err_info = sr_lydmods_moddep_expr_get_dep_mods(elem, when->cond, LYXP_WHEN, &dep_mods, &dep_mod_count))) {
                    goto cleanup;
                }
            }
            for (i = 0; i < must_size; ++i) {
                if ((err_info = sr_lydmods_moddep_expr_get_dep_mods(elem, musts[i].expr, LYXP_MUST, &dep_mods, &dep_mod_count))) {
                    goto cleanup;
                }
            }

            /* LY_TREE_DFS_END */
            if (elem->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYDATA)) {
                next = NULL;
            } else {
                next = elem->child;
            }
            if (!next) {
    next_sibling:
                /* no children */
                if (elem == root) {
                    /* we are done, (START) has no children */
                    break;
                }
                /* try siblings */
                next = elem->next;
            }
            while (!next) {
                /* parent is already processed, go to its sibling */
                elem = lys_parent(elem);
                /* no siblings, go back through parents */
                if (lys_parent(elem) == lys_parent(root)) {
                    /* we are done, no next element to process */
                    break;
                }
                next = elem->next;
            }
        }
    }

    /* check all the dependency modules */
    for (i = 0; i < dep_mod_count; ++i) {
        if (!dep_mods[i]->implemented) {
            /* maybe it is scheduled to be installed? */
            if (asprintf(&xpath, "installed-module[name='%s']", dep_mods[i]->name) == -1) {
                SR_ERRINFO_MEM(&err_info);
                goto cleanup;
            }
            set = lyd_find_path(sr_mods, xpath);
            free(xpath);
            if (!set) {
                sr_errinfo_new_ly(&err_info, lyd_node_module(sr_mods)->ctx);
                goto cleanup;
            }
            assert(set->number < 2);

            if (!set->number) {
                SR_LOG_WRN("Module \"%s\" depends on module \"%s\", which is not implemented.", ly_mod->name, dep_mods[i]->name);
                *fail = 1;
            }
            ly_set_free(set);
        }
    }

cleanup:
    free(dep_mods);
    return err_info;
}

/**
 * @brief Update context module features based on sysrepo module data.
 *
 * @param[in] sr_mods Sysrepo module data.
 * @param[in] new_ctx Context with modules to update features.
 * @param[out] change Whether there were any feature changes.
 * @param[out] fail Whether any new dependant modules were not implemented.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_sched_ctx_change_features(const struct lyd_node *sr_mods, struct ly_ctx *new_ctx, int *change, int *fail)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mod;
    const struct lys_module *ly_mod, *imp_ly_mod;
    struct ly_set *set = NULL, *feat_set = NULL;
    const char *feat_name, **f_names = NULL;
    uint8_t *f_state_old = NULL, *f_state_new = NULL;
    uint32_t i, j;
    int enable;

    assert(sr_mods);

    LY_TREE_FOR(sr_mods->child, sr_mod) {
        /* find all changed features of the particular module */
        set = lyd_find_path(sr_mod, "changed-feature");
        if (!set) {
            SR_ERRINFO_INT(&err_info);
            return err_info;
        } else if (!set->number) {
            /* no changed features */
            ly_set_free(set);
            set = NULL;
            continue;
        }

        /* get the module */
        ly_mod = ly_ctx_get_module(new_ctx, sr_ly_leaf_value_str(sr_mod->child), NULL, 1);
        if (!ly_mod) {
            /* this can happen only if the module is also scheduled to be removed */
#ifndef NDEBUG
            struct lyd_node *node;
            LY_TREE_FOR(sr_mod->child, node) {
                if (!strcmp(node->schema->name, "removed")) {
                    break;
                }
            }
            assert(node);
#endif
            SR_LOG_WRN("Module \"%s\" is scheduled for both removal and feature changes, ignoring them.",
                    sr_ly_leaf_value_str(sr_mod->child));
            ly_set_free(set);
            set = NULL;
            continue;
        }

        /* update the features */
        for (i = 0; i < set->number; ++i) {
            assert(!strcmp(set->set.d[i]->child->schema->name, "name"));
            assert(!strcmp(set->set.d[i]->child->next->schema->name, "change"));
            feat_name = sr_ly_leaf_value_str(set->set.d[i]->child);
            enable = !strcmp(sr_ly_leaf_value_str(set->set.d[i]->child->next), "enable") ? 1 : 0;

            if (enable && lys_features_enable_force(ly_mod, feat_name)) {
                sr_errinfo_new_ly(&err_info, ly_mod->ctx);
                SR_ERRINFO_INT(&err_info);
                goto cleanup;
            } else if (!enable && lys_features_disable_force(ly_mod, feat_name)) {
                sr_errinfo_new_ly(&err_info, ly_mod->ctx);
                SR_ERRINFO_INT(&err_info);
                goto cleanup;
            }
        }
        ly_set_free(set);
        set = NULL;

        /* check that all the dependant modules are implemented */
        if ((err_info = sr_lydmods_check_data_deps(ly_mod, sr_mods, fail)) || *fail) {
            goto cleanup;
        }

        /* check that all module dependencies that import this module are implemented */
        i = 0;
        while ((imp_ly_mod = ly_ctx_get_module_iter(ly_mod->ctx, &i))) {
            if ((imp_ly_mod == ly_mod) || /*sr_is_internal_module(imp_ly_mod) ||*/ !imp_ly_mod->implemented) {
                continue;
            }

            for (j = 0; j < imp_ly_mod->imp_size; ++j) {
                if (imp_ly_mod->imp[j].module == ly_mod) {
                    break;
                }
            }
            if (j == imp_ly_mod->imp_size) {
                continue;
            }

            if ((err_info = sr_lydmods_check_data_deps(imp_ly_mod, sr_mods, fail)) || *fail) {
                goto cleanup;
            }
        }

        *change = 1;
    }

    /* success */

cleanup:
    free(f_names);
    free(f_state_old);
    free(f_state_new);
    ly_set_free(set);
    ly_set_free(feat_set);
    return err_info;
}

/**
 * @brief Load updated modules into context.
 *
 * @param[in] sr_mods Sysrepo module data.
 * @param[in] new_ctx Context to load updated modules into.
 * @param[out] change Whether there were any updated modules.
 * @param[out] fail Whether any new dependant modules were not implemented.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_sched_ctx_update_modules(const struct lyd_node *sr_mods, struct ly_ctx *new_ctx, int *change, int *fail)
{
    sr_error_info_t *err_info = NULL;
    struct ly_ctx *ly_ctx;
    const struct lys_module *ly_mod;
    struct ly_set *set = NULL, *feat_set = NULL;
    uint32_t i, j;

    assert(sr_mods);
    ly_ctx = lyd_node_module(sr_mods)->ctx;

    /* find updated modules and change internal module data tree */
    set = lyd_find_path(sr_mods, "/" SR_YANG_MOD ":sysrepo-modules/module/updated-yang");
    if (!set) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }
    for (i = 0; i < set->number; ++i) {
        /* load the updated module */
        ly_mod = lys_parse_mem(new_ctx, sr_ly_leaf_value_str(set->set.d[i]), LYS_YANG);
        if (!ly_mod) {
            sr_errinfo_new_ly(&err_info, new_ctx);
            goto cleanup;
        }

        /* collect all enabled features */
        feat_set = lyd_find_path(set->set.d[i]->parent, "enabled-feature");
        if (!feat_set) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            goto cleanup;
        }

        /* enable all the features */
        for (j = 0; j < feat_set->number; ++j) {
            if (lys_features_enable_force(ly_mod, sr_ly_leaf_value_str(feat_set->set.d[j]))) {
                sr_errinfo_new_ly(&err_info, new_ctx);
                goto cleanup;
            }
        }
        ly_set_free(feat_set);
        feat_set = NULL;

        /* check that all the dependant modules are implemented */
        if ((err_info = sr_lydmods_check_data_deps(ly_mod, sr_mods, fail)) || *fail) {
            goto cleanup;
        }

        *change = 1;
    }

    /* success */

cleanup:
    ly_set_free(set);
    ly_set_free(feat_set);
    return err_info;
}

/**
 * @brief Check data dependencies of a module and all its implemented imports, recursively.
 *
 * @param[in] ly_mod Libyang module to check.
 * @param[in] sr_mods Sysrepo module data.
 * @param[out] fail Whether any dependant module was not implemented.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lydmods_check_data_deps_r(const struct lys_module *ly_mod, const struct lyd_node *sr_mods, int *fail)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;

    /* check data deps of this module */
    if ((err_info = sr_lydmods_check_data_deps(ly_mod, sr_mods, fail)) || *fail) {
        return err_info;
    }

    /* check data deps of all the implemented dependencies, recursively */
    for (i = 0; i < ly_mod->imp_size; ++i) {
        if (ly_mod->imp[i].module->implemented) {
            if ((err_info = sr_lydmods_check_data_deps_r(ly_mod->imp[i].module, sr_mods, fail)) || *fail) {
                return err_info;
            }
        }
    }

    return NULL;
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
    struct ly_ctx *ly_ctx;
    const struct lys_module *ly_mod;
    struct ly_set *set = NULL, *feat_set = NULL;
    uint32_t i, j;

    assert(sr_mods);
    ly_ctx = lyd_node_module(sr_mods)->ctx;

    set = lyd_find_path(sr_mods, "/" SR_YANG_MOD ":sysrepo-modules/installed-module/module-yang");
    if (!set) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }
    for (i = 0; i < set->number; ++i) {
        /* load the new module, it can still fail on, for example, duplicate namespace */
        ly_mod = lys_parse_mem(new_ctx, sr_ly_leaf_value_str(set->set.d[i]), LYS_YANG);
        if (!ly_mod) {
            sr_log_wrn_ly(new_ctx);
            SR_LOG_WRN("Installing module \"%s\" failed.", sr_ly_leaf_value_str(set->set.d[i]->parent->child));
            *fail = 1;
            goto cleanup;
        }

        /* collect all enabled features */
        feat_set = lyd_find_path(set->set.d[i]->parent, "enabled-feature");
        if (!feat_set) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            goto cleanup;
        }

        /* enable all the features */
        for (j = 0; j < feat_set->number; ++j) {
            if (lys_features_enable_force(ly_mod, sr_ly_leaf_value_str(feat_set->set.d[j]))) {
                sr_errinfo_new_ly(&err_info, new_ctx);
                goto cleanup;
            }
        }

        /* check that all the dependant modules are implemented */
        if ((err_info = sr_lydmods_check_data_deps_r(ly_mod, sr_mods, fail)) || *fail) {
            goto cleanup;
        }

        ly_set_free(feat_set);
        feat_set = NULL;
        *change = 1;
    }

    /* success */

cleanup:
    ly_set_free(set);
    ly_set_free(feat_set);
    return err_info;
}

/**
 * @brief Apply all scheduled changes in sysrepo module data.
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

    assert(sr_mods && new_ctx && change);

    SR_LOG_INF("Applying scheduled changes.");
    *change = 0;
    *fail = 0;

    /*
     * 1) create the new context, LY sysrepo data are not modified
     */

    /* load updated modules into new context */
    if ((err_info = sr_lydmods_sched_ctx_update_modules(sr_mods, new_ctx, change, fail)) || *fail) {
        goto cleanup;
    }

    /* load all remaining non-updated non-removed modules into new context */
    if ((err_info = sr_lydmods_ctx_load_modules(sr_mods, new_ctx, 0, 0, change))) {
        goto cleanup;
    }

    /* change features */
    if ((err_info = sr_lydmods_sched_ctx_change_features(sr_mods, new_ctx, change, fail)) || *fail) {
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
        LY_TREE_FOR_SAFE(sr_mods->child, next, sr_mod) {
            if (!strcmp(sr_mod->schema->name, "module")) {
                assert(!strcmp(sr_mod->child->schema->name, "name"));
                LY_TREE_FOR_SAFE(sr_mod->child->next, next2, node) {
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
                        /* sr_mod children were freed, iteration cannot continue */
                        break;
                    } else if (!strcmp(node->schema->name, "deps")
                            || !strcmp(node->schema->name, "inverse-deps")
                            || !strcmp(node->schema->name, "rpc")
                            || !strcmp(node->schema->name, "notification")) {
                        /* remove all stored dependencies, RPCs, and notifications of all the modules */
                        lyd_free(node);
                    }
                }
            } else {
                assert(!strcmp(sr_mod->schema->name, "installed-module"));
                if ((err_info = sr_lydmods_sched_finalize_module_install(sr_mod, new_ctx))) {
                    goto cleanup;
                }
            }
        }

        /* now add (rebuild) dependencies and RPCs, notifications of all the modules */
        LY_TREE_FOR(sr_mods->child, sr_mod) {
            ly_mod = ly_ctx_get_module(new_ctx, sr_ly_leaf_value_str(sr_mod->child), NULL, 1);
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
        struct lyd_node **sr_mods, int *changed)
{
    sr_error_info_t *err_info = NULL;
    int chng, exists, fail, ctx_updated = 0;
    uint32_t conn_count;

    *sr_mods = NULL;
    chng = 0;

    /* LYDMODS LOCK */
    if ((err_info = sr_lydmods_lock(&main_shm->lydmods_lock, *ly_ctx, __func__))) {
        return err_info;
    }

    /* check whether any internal module data exist */
    if ((err_info = sr_lydmods_exists(&exists))) {
        goto cleanup;
    }
    if (!exists) {
        /* create new persistent module data file */
        if ((err_info = sr_lydmods_create(*ly_ctx, sr_mods))) {
            goto cleanup;
        }
        chng = 1;
    } else {
        /* parse sysrepo module data */
        if ((err_info = sr_lydmods_parse(*ly_ctx, sr_mods))) {
            goto cleanup;
        }
        if (apply_sched) {
            /* apply scheduled changes if we can */
            if ((err_info = sr_conn_info(NULL, NULL, &conn_count, NULL, NULL))) {
                goto cleanup;
            }
            if (!conn_count) {
                if ((err_info = sr_lydmods_sched_apply(*sr_mods, *ly_ctx, &chng, &fail))) {
                    goto cleanup;
                }
                if (fail) {
                    if (err_on_sched_fail) {
                        sr_errinfo_new(&err_info, SR_ERR_OPERATION_FAILED, NULL, "Applying scheduled changes failed.");
                        goto cleanup;
                    }

                    /* the context is not valid anymore, we have to create it from scratch in the connection
                     * but also update sr_mods, because it was parsed with the context */
                    lyd_free_withsiblings(*sr_mods);
                    ly_ctx_destroy(*ly_ctx, NULL);
                    if ((err_info = sr_shmmain_ly_ctx_init(ly_ctx))) {
                        goto cleanup;
                    }
                    if ((err_info = sr_lydmods_parse(*ly_ctx, sr_mods))) {
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
        if ((err_info = sr_lydmods_ctx_load_modules(*sr_mods, *ly_ctx, 1, 1, NULL))) {
            goto cleanup;
        }
    }

    if (chng) {
        /* store updated internal sysrepo data */
        if ((err_info = sr_lydmods_print(sr_mods))) {
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

    if (err_info) {
        lyd_free_withsiblings(*sr_mods);
        *sr_mods = NULL;
    }
    return err_info;
}

sr_error_info_t *
sr_lydmods_deferred_add_module(sr_main_shm_t *main_shm, struct ly_ctx *ly_ctx, const struct lys_module *ly_mod,
        const char **features, int feat_count)
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
    set = lyd_find_path(sr_mods, path);
    SR_CHECK_INT_GOTO(!set, err_info, cleanup);
    if (set->number == 1) {
        sr_errinfo_new(&err_info, SR_ERR_EXISTS, NULL, "Module \"%s\" already scheduled for installation.", ly_mod->name);
        goto cleanup;
    }

    /* store all info for installation */
    if (!(inst_mod = lyd_new_path(sr_mods, NULL, path, NULL, 0, 0))) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    if (ly_mod->rev_size && !lyd_new_leaf(inst_mod, NULL, "revision", ly_mod->rev[0].date)) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    for (i = 0; i < feat_count; ++i) {
        if (!lyd_new_leaf(inst_mod, NULL, "enabled-feature", features[i])) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            goto cleanup;
        }
    }

    /* print the module into memory */
    if (lys_print_mem(&yang_str, ly_mod, LYS_YANG, NULL, 0, 0)) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        goto cleanup;
    }

    if (!lyd_new_leaf(inst_mod, NULL, "module-yang", yang_str)) {
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
    ly_set_free(set);
    lyd_free_withsiblings(sr_mods);
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
    set = lyd_find_path(sr_mods, path);
    SR_CHECK_INT_GOTO(!set, err_info, cleanup);
    if (!set->number) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" not scheduled for installation.", module_name);
        goto cleanup;
    }

    /* unschedule installation */
    lyd_free(set->set.d[0]);

    /* store the updated persistent data tree */
    if ((err_info = sr_lydmods_print(&sr_mods))) {
        goto cleanup;
    }

    SR_LOG_INF("Module \"%s\" installation unscheduled.", module_name);

cleanup:
    /* LYDMODS UNLOCK */
    sr_munlock(&main_shm->lydmods_lock);

    free(path);
    ly_set_free(set);
    lyd_free_withsiblings(sr_mods);
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
    set = lyd_find_path(sr_mods, "installed-module/module-yang");
    SR_CHECK_INT_GOTO(!set, err_info, cleanup);

    /* load all the modules, it must succeed */
    for (i = 0; i < set->number; ++i) {
        lmod = lys_parse_mem(ly_ctx, sr_ly_leaf_value_str(set->set.d[i]), LYS_YANG);
        if (!lmod) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            SR_ERRINFO_INT(&err_info);
            goto cleanup;
        }

        /* just enable all features */
        if ((err_info = sr_lydmods_ctx_load_module(set->set.d[i]->parent, ly_ctx, NULL))) {
            goto cleanup;
        }

        if (!strcmp(lmod->name, module_name)) {
            /* the required mdule was found */
            *ly_mod = lmod;
        }
    }

    if (!*ly_mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" not scheduled for installation.", module_name);
        goto cleanup;
    }

    /* success */

cleanup:
    ly_set_free(set);
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

    assert((data && !data_path) || (!data && data_path));

    /* LYDMODS LOCK */
    if ((err_info = sr_lydmods_lock(&main_shm->lydmods_lock, ly_ctx, __func__))) {
        return err_info;
    }

    /* parse sysrepo module data */
    if ((err_info = sr_lydmods_parse(ly_ctx, &sr_mods))) {
        goto cleanup;
    }

    /* update load all the modules into context */
    if ((err_info = sr_lydmods_ctx_load_modules(sr_mods, ly_ctx, 1, 1, NULL))) {
        goto cleanup;
    }

    /* load the module to be installed */
    if ((err_info = sr_lydmods_ctx_load_installed_module_all(sr_mods, ly_ctx, module_name, &ly_mod))) {
        goto cleanup;
    }

    /* parse module data */
    ly_errno = 0;
    if (data_path) {
        mod_data = lyd_parse_path(ly_ctx, data_path, format, LYD_OPT_CONFIG | LYD_OPT_STRICT | LYD_OPT_TRUSTED);
    } else {
        mod_data = lyd_parse_mem(ly_ctx, data, format, LYD_OPT_CONFIG | LYD_OPT_STRICT | LYD_OPT_TRUSTED);
    }
    if (ly_errno) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    /* check that there are only this module data */
    LY_TREE_FOR(mod_data, node) {
        if (!node->dflt && (lyd_node_module(node) != ly_mod)) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, NULL, "Only data for the module \"%s\" can be set.", module_name);
            goto cleanup;
        }
    }

    /* find the module */
    if (asprintf(&path, "installed-module[name=\"%s\"]", module_name) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    set = lyd_find_path(sr_mods, path);
    SR_CHECK_INT_GOTO(!set, err_info, cleanup);
    if (!set->number) {
        sr_errinfo_new(&err_info, SR_ERR_EXISTS, NULL, "Module \"%s\" not scheduled for installation.", module_name);
        goto cleanup;
    }

    /* remove any previously set data */
    LY_TREE_FOR(set->set.d[0]->child, node) {
        if (!strcmp(node->schema->name, "data")) {
            lyd_free(node);
            break;
        }
    }

    /* print into buffer */
    if (lyd_print_mem(&data_json, mod_data, LYD_JSON, LYP_WITHSIBLINGS)) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    /* add into module */
    if (!lyd_new_leaf(set->set.d[0], NULL, "data", data_json)) {
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
    ly_set_free(set);
    lyd_free_withsiblings(sr_mods);
    lyd_free_withsiblings(mod_data);
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
    set = lyd_find_path(sr_mods, path);
    SR_CHECK_INT_GOTO(!set, err_info, cleanup);
    if (set->number == 1) {
        sr_errinfo_new(&err_info, SR_ERR_EXISTS, NULL, "Module \"%s\" already scheduled for deletion.", mod_name);
        goto cleanup;
    }

    /* mark for deletion */
    if (!lyd_new_path(sr_mods, NULL, path, NULL, 0, LYD_PATH_OPT_NOPARENT)) {
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
    ly_set_free(set);
    lyd_free_withsiblings(sr_mods);
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
    set = lyd_find_path(sr_mods, path);
    SR_CHECK_INT_GOTO(!set, err_info, cleanup);
    if (!set->number) {
        if (first) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" not scheduled for deletion.", ly_mod->name);
            goto cleanup;
        }
    } else {
        assert(set->number == 1);
        lyd_free(set->set.d[0]);
        SR_LOG_INF("Module \"%s\" deletion unscheduled.", ly_mod->name);
    }
    first = 0;

    /* recursively check all imported implemented modules */
    for (i = 0; i < ly_mod->imp_size; ++i) {
        if (ly_mod->imp[i].module->implemented) {
            if ((err_info = sr_lydmods_unsched_del_module_r(sr_mods, ly_mod->imp[i].module, 0))) {
                goto cleanup;
            }
        }
    }

cleanup:
    free(path);
    ly_set_free(set);
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

    lyd_free_withsiblings(sr_mods);
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
    set = lyd_find_path(sr_mods, path);
    SR_CHECK_INT_GOTO(!set, err_info, cleanup);
    if (set->number == 1) {
        sr_errinfo_new(&err_info, SR_ERR_EXISTS, NULL, "Module \"%s\" already scheduled for an update.", ly_upd_mod->name);
        goto cleanup;
    }

    /* print the module into memory */
    if (lys_print_mem(&yang_str, ly_upd_mod, LYS_YANG, NULL, 0, 0)) {
        sr_errinfo_new_ly(&err_info, ly_upd_mod->ctx);
        goto cleanup;
    }

    /* mark for update */
    if (!lyd_new_path(sr_mods, NULL, path, yang_str, 0, LYD_PATH_OPT_NOPARENT)) {
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
    ly_set_free(set);
    lyd_free_withsiblings(sr_mods);
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
    set = lyd_find_path(sr_mods, path);
    SR_CHECK_INT_GOTO(!set, err_info, cleanup);
    if (!set->number) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" not scheduled for an update.", mod_name);
        goto cleanup;
    }

    assert(set->number == 1);
    /* free the "updated-yang" node */
    lyd_free(set->set.d[0]);

    /* store the updated persistent data tree */
    if ((err_info = sr_lydmods_print(&sr_mods))) {
        goto cleanup;
    }

    SR_LOG_INF("Module \"%s\" update unscheduled.", mod_name);

cleanup:
    /* LYDMODS UNLOCK */
    sr_munlock(&main_shm->lydmods_lock);

    free(path);
    ly_set_free(set);
    lyd_free_withsiblings(sr_mods);
    return err_info;
}

sr_error_info_t *
sr_lydmods_deferred_change_feature(sr_main_shm_t *main_shm, struct ly_ctx *ly_ctx, const struct lys_module *ly_mod,
        const char *feat_name, int to_enable, int is_enabled)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL, *feat_change;
    struct lyd_node_leaf_list *leaf;
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
    set = lyd_find_path(sr_mods, path);
    SR_CHECK_INT_GOTO(!set, err_info, cleanup);
    if (set->number == 1) {
        leaf = (struct lyd_node_leaf_list *)set->set.d[0];

        if ((to_enable && !strcmp(leaf->value_str, "enable")) || (!to_enable && !strcmp(leaf->value_str, "disable"))) {
            sr_errinfo_new(&err_info, SR_ERR_EXISTS, NULL, "Module \"%s\" feature \"%s\" already scheduled to be %s.",
                    ly_mod->name, feat_name, to_enable ? "enabled" : "disabled");
            goto cleanup;
        }

        /* unschedule the feature change */
        lyd_free(set->set.d[0]->parent);
        SR_LOG_INF("Module \"%s\" feature \"%s\" %s unscheduled.", ly_mod->name, feat_name,
                to_enable ? "disabling" : "enabling");
    } else {
        if ((to_enable && is_enabled) || (!to_enable && !is_enabled)) {
            sr_errinfo_new(&err_info, SR_ERR_EXISTS, NULL, "Module \"%s\" feature \"%s\" is already %s.",
                    ly_mod->name, feat_name, to_enable ? "enabled" : "disabled");
            goto cleanup;
        }

        /* schedule the feature change */
        if (!(feat_change = lyd_new_path(sr_mods, NULL, path, to_enable ? "enable" : "disable", 0, 0))) {
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
    ly_set_free(set);
    lyd_free_withsiblings(sr_mods);
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
sr_lydmods_update_replay_support_module(struct lyd_node *sr_mod, int replay_support, const struct lys_node *s_replay)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_replay;
    char buf[21];
    time_t from_ts, to_ts;

    lyd_find_sibling_val(sr_mod->child, s_replay, NULL, &sr_replay);
    if (!replay_support && sr_replay) {
        /* remove replay support */
        lyd_free(sr_replay);
    } else if (replay_support && !sr_replay) {
        /* find earliest stored notification or use current time */
        if ((err_info = sr_replay_find_file(sr_ly_leaf_value_str(sr_mod->child), 1, 0, &from_ts, &to_ts))) {
            return err_info;
        }
        if (!from_ts) {
            from_ts = time(NULL);
        }
        sprintf(buf, "%ld", (long int)from_ts);

        /* add replay support */
        SR_CHECK_LY_RET(!lyd_new_leaf(sr_mod, NULL, "replay-support", buf), lyd_node_module(sr_mod)->ctx, err_info);
    }

    return NULL;
}

sr_error_info_t *
sr_lydmods_update_replay_support(sr_main_shm_t *main_shm, struct ly_ctx *ly_ctx, const char *mod_name, int replay_support)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL, *sr_mod;
    char *pred = NULL;
    const struct lys_node *s_mod, *s_replay;

    /* find schema nodes */
    s_mod = ly_ctx_get_node(ly_ctx, NULL, "/sysrepo:sysrepo-modules/module", 0);
    assert(s_mod);
    s_replay = ly_ctx_get_node(NULL, s_mod, "replay-support", 0);
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
        lyd_find_sibling_val(sr_mods->child, s_mod, pred, &sr_mod);
        assert(sr_mod);

        /* set replay support */
        if ((err_info = sr_lydmods_update_replay_support_module(sr_mod, replay_support, s_replay))) {
            goto cleanup;
        }
    } else {
        LY_TREE_FOR(sr_mods->child, sr_mod) {
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
    lyd_free_withsiblings(sr_mods);
    return err_info;
}
