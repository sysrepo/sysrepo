/**
 * @file ly_wrap.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libyang function wrappers
 *
 * @copyright
 * Copyright (c) 2024 Deutsche Telekom AG.
 * Copyright (c) 2024 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "compat.h"
#include "ly_wrap.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include <libyang/hash_table.h>
#include <libyang/libyang.h>
#include <libyang/plugins_types.h>

#include "common.h"
#include "log.h"
#include "sysrepo.h"

#define SR_CHECK_LY_GOTO(cond, ly_ctx, err_info, go) if (cond) { sr_errinfo_new_ly(&(err_info), ly_ctx, NULL); goto go; }
#define SR_CHECK_LY_RET(cond, ly_ctx, err_info) if (cond) { sr_errinfo_new_ly(&(err_info), ly_ctx, NULL); return err_info; }

/**
 * @brief Log the error(s) from a libyang context and add them into an error info structure.
 *
 * @param[in,out] err_info Existing error info.
 * @param[in] ly_ctx libyang context to use.
 * @param[in] data Optional data tree to look for another extension context that may have the error.
 * @param[in] err_code Error code to use.
 */
static void
sr_errinfo_new_ly(sr_error_info_t **err_info, const struct ly_ctx *ly_ctx, const struct lyd_node *data,
        sr_error_t err_code)
{
    const struct ly_err_item *e = NULL;
    const struct lyd_node *node;

    if (ly_ctx) {
        e = ly_err_first(ly_ctx);
    }
    if (!e && data) {
        if (ly_ctx != LYD_CTX(data)) {
            e = ly_err_first(LYD_CTX(data));
        } else {
            LYD_TREE_DFS_BEGIN(data, node) {
                if (node->flags & LYD_EXT) {
                    e = ly_err_first(LYD_CTX(node));
                    break;
                }
                LYD_TREE_DFS_END(data, node);
            }
        }
    }

    if (!e) {
        /* this function is called only when an error is expected, but it is still possible there
         * will be none in a context, try to use the last */
        sr_errinfo_new(err_info, err_code, "%s", ly_last_logmsg());
        return;
    }

    do {
        if (e->level == LY_LLWRN) {
            /* just print it */
            sr_log_msg(0, SR_LL_WRN, e->msg);
        } else {
            assert(e->level == LY_LLERR);
            /* store it and print it */
            if (e->data_path || e->schema_path) {
                sr_errinfo_new(err_info, err_code, "%s (path \"%s\")", e->msg, e->data_path ? e->data_path : e->schema_path);
            } else {
                sr_errinfo_new(err_info, err_code, "%s", e->msg);
            }
        }

        e = e->next;
    } while (e);

    if (ly_ctx) {
        ly_err_clean((struct ly_ctx *)ly_ctx, NULL);
    }
}

sr_error_info_t *
sr_ly_ctx_new(sr_conn_ctx_t *conn, struct ly_ctx **ly_ctx)
{
    sr_error_info_t *err_info = NULL;
    char *yang_dir;
    const char *factory_default_features[] = {"factory-default-datastore", NULL};
    uint16_t ctx_opts;
    uint32_t temp_lo = LY_LOSTORE;
    struct ly_in *in = NULL;
    LY_ERR lyrc;

    /* context options */
    ctx_opts = LY_CTX_NO_YANGLIBRARY | LY_CTX_DISABLE_SEARCHDIR_CWD | LY_CTX_REF_IMPLEMENTED |
            LY_CTX_EXPLICIT_COMPILE | LY_CTX_STATIC_PLUGINS_ONLY | LY_CTX_LYB_HASHES;
    if (conn && (conn->opts & SR_CONN_CTX_SET_PRIV_PARSED)) {
        ctx_opts |= LY_CTX_SET_PRIV_PARSED;
    }

    /* create new context */
    ly_temp_log_options(&temp_lo);
    if ((err_info = sr_path_yang_dir(&yang_dir))) {
        goto cleanup;
    }
    lyrc = ly_ctx_new(yang_dir, ctx_opts, ly_ctx);
    free(yang_dir);
    if (lyrc) {
        sr_errinfo_new(&err_info, SR_ERR_LY, "%s", ly_last_logmsg());
        sr_errinfo_new(&err_info, SR_ERR_INTERNAL, "Failed to create a new libyang context.");
        goto cleanup;
    }

    /* load just the internal datastores modules and the "sysrepo" module */
    if (lys_parse_mem(*ly_ctx, ietf_datastores_yang, LYS_IN_YANG, NULL)) {
        sr_errinfo_new_ly(&err_info, *ly_ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }
    if (lys_parse_mem(*ly_ctx, sysrepo_yang, LYS_IN_YANG, NULL)) {
        sr_errinfo_new_ly(&err_info, *ly_ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }
    if (lys_parse_mem(*ly_ctx, ietf_netconf_acm_yang, LYS_IN_YANG, NULL)) {
        sr_errinfo_new_ly(&err_info, *ly_ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

    if (ly_in_new_memory(ietf_factory_default_yang, &in)) {
        sr_errinfo_new_ly(&err_info, NULL, NULL, SR_ERR_LY);
        goto cleanup;
    }
    if (lys_parse(*ly_ctx, in, LYS_IN_YANG, factory_default_features, NULL)) {
        sr_errinfo_new_ly(&err_info, *ly_ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }
    if (lys_parse_mem(*ly_ctx, sysrepo_factory_default_yang, LYS_IN_YANG, NULL)) {
        sr_errinfo_new_ly(&err_info, *ly_ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

    /* compile the final context */
    if ((err_info = sr_ly_ctx_compile(*ly_ctx))) {
        goto cleanup;
    }

cleanup:
    if (err_info) {
        ly_ctx_destroy(*ly_ctx);
        *ly_ctx = NULL;
    }
    ly_temp_log_options(NULL);
    ly_in_free(in, 0);
    return err_info;
}

sr_error_info_t *
sr_lys_parse(struct ly_ctx *ctx, const char *data, const char *path, LYS_INFORMAT format, const char **features,
        struct lys_module **ly_mod)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;
    struct ly_in *in = NULL;

    ly_temp_log_options(&temp_lo);

    if (path) {
        if (ly_in_new_filepath(path, 0, &in)) {
            sr_errinfo_new(&err_info, SR_ERR_LY, "%s", ly_last_logmsg());
            goto cleanup;
        }
    } else {
        if (ly_in_new_memory(data, &in)) {
            sr_errinfo_new(&err_info, SR_ERR_LY, "%s", ly_last_logmsg());
            goto cleanup;
        }
    }

    if (lys_parse(ctx, in, format, features, ly_mod)) {
        sr_errinfo_new_ly(&err_info, ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_in_free(in, 0);
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lys_set_implemented(struct lys_module *mod, const char **features)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lys_set_implemented(mod, features)) {
        sr_errinfo_new_ly(&err_info, mod->ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lys_print(const char *path, const struct lys_module *mod, const struct lysp_submodule *submod)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;
    struct ly_out *out = NULL;
    LY_ERR lyrc;

    ly_temp_log_options(&temp_lo);

    ly_out_new_filepath(path, &out);

    if (submod) {
        lyrc = lys_print_submodule(out, submod, LYS_OUT_YANG, 0, 0);
    } else {
        lyrc = lys_print_module(out, mod, LYS_OUT_YANG, 0, 0);
    }
    if (lyrc) {
        sr_errinfo_new_ly(&err_info, submod ? submod->mod->ctx : mod->ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_out_free(out, NULL, 0);
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_ly_ctx_get_yanglib_data(const struct ly_ctx *ctx, struct lyd_node **data, uint32_t content_id)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (ly_ctx_get_yanglib_data(ctx, data, "0x%08x", content_id)) {
        sr_errinfo_new_ly(&err_info, ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_ly_ctx_load_module(struct ly_ctx *ctx, const char *name, const char *revision, const char **features,
        const struct lys_module **ly_mod)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;
    const struct lys_module *mod = NULL;

    ly_temp_log_options(&temp_lo);

    if (!(mod = ly_ctx_load_module(ctx, name, revision, features))) {
        sr_errinfo_new_ly(&err_info, ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    *ly_mod = mod;
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_ly_ctx_compile(struct ly_ctx *ctx)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (ly_ctx_compile(ctx)) {
        sr_errinfo_new_ly(&err_info, ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lys_find_path(const struct ly_ctx *ctx, const char *path, int *valid, const struct lysc_node **match)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;
    const struct lysc_node *m;

    ly_temp_log_options(&temp_lo);

    if (valid) {
        *valid = 1;
    }

    if (!(m = lys_find_path(ctx, NULL, path, 0))) {
        if (valid) {
            *valid = 0;
        } else {
            sr_errinfo_new_ly(&err_info, ctx, NULL, SR_ERR_LY);
        }
        goto cleanup;
    }

    if (match) {
        *match = m;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lys_find_xpath(const struct ly_ctx *ctx, const char *xpath, uint32_t options, int *valid, struct ly_set **set)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (valid) {
        *valid = 1;
    }

    if (lys_find_xpath(ctx, NULL, xpath, options, set) || !(*set)->count) {
        if (valid) {
            *valid = 0;
        } else {
            sr_errinfo_new_ly(&err_info, ctx, NULL, SR_ERR_LY);
        }
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lys_find_xpath_atoms(const struct ly_ctx *ctx, const char *xpath, uint32_t options, int *valid, struct ly_set **set)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;
    LY_ERR lyrc;

    ly_temp_log_options(&temp_lo);

    if (valid) {
        *valid = 1;
    }

    if ((lyrc = lys_find_xpath_atoms(ctx, NULL, xpath, options, set))) {
        if (valid) {
            *valid = 0;
        } else if (lyrc == LY_ENOTFOUND) {
            /* no error message */
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL);
            /* free any errors which were generated */
            ly_err_clean((struct ly_ctx *) ctx, NULL);
        } else {
            sr_errinfo_new_ly(&err_info, ctx, NULL, SR_ERR_LY);
        }
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lys_find_expr_atoms(const struct lysc_node *ctx_node, const struct lys_module *cur_mod, const struct lyxp_expr *exp,
        struct lysc_prefix *prefixes, uint32_t options, struct ly_set **set)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lys_find_expr_atoms(ctx_node, cur_mod, exp, prefixes, options, set)) {
        sr_errinfo_new_ly(&err_info, ctx_node->module->ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_parse_data(const struct ly_ctx *ctx, const char *data, const char *data_path, LYD_FORMAT format,
        uint32_t parse_options, uint32_t validation_options, struct lyd_node **tree)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;
    LY_ERR lyrc = LY_SUCCESS;

    ly_temp_log_options(&temp_lo);

    *tree = NULL;

    if (data_path) {
        lyrc = lyd_parse_data_path(ctx, data_path, format, parse_options, validation_options, tree);
    } else if (data) {
        lyrc = lyd_parse_data_mem(ctx, data, format, parse_options, validation_options, tree);
    }

    /* empty data are fine */
    if (lyrc && (lyrc != LY_EINVAL)) {
        sr_errinfo_new_ly(&err_info, ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

    /* discard any suppressed errors */
    ly_err_clean((struct ly_ctx *) ctx, NULL);

cleanup:
    if (err_info) {
        lyd_free_siblings(*tree);
        *tree = NULL;
    }
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_parse_op(const struct ly_ctx *ctx, const char *data, LYD_FORMAT format, enum lyd_type data_type,
        struct lyd_node **tree)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;
    struct ly_in *in = NULL;

    ly_temp_log_options(&temp_lo);

    if (ly_in_new_memory(data, &in)) {
        sr_errinfo_new(&err_info, SR_ERR_LY, "%s", ly_last_logmsg());
        goto cleanup;
    }

    if (lyd_parse_op(ctx, NULL, in, format, data_type, LYD_PARSE_STRICT, tree, NULL)) {
        sr_errinfo_new_ly(&err_info, ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_in_free(in, 0);
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_print_data(const struct lyd_node *data, LYD_FORMAT format, uint32_t print_options, int fd, char **str,
        uint32_t *len)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;
    struct ly_out *out = NULL;

    ly_temp_log_options(&temp_lo);

    if (fd == -1) {
        ly_out_new_memory(str, 0, &out);
    } else {
        ly_out_new_fd(fd, &out);
    }

    if (lyd_print_all(out, data, format, print_options)) {
        if (data) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(data), NULL, SR_ERR_LY);
        } else {
            SR_ERRINFO_INT(&err_info);
        }
        goto cleanup;
    }

    if (len) {
        *len = ly_out_printed(out);
    }

cleanup:
    ly_out_free(out, NULL, 0);
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_validate_all(struct lyd_node **data, const struct ly_ctx *ctx, uint32_t options)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_validate_all(data, ctx, options, NULL)) {
        sr_errinfo_new_ly(&err_info, ctx, NULL, SR_ERR_VALIDATION_FAILED);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_validate_module(struct lyd_node **data, const struct lys_module *mod, uint32_t options, struct lyd_node **diff)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_validate_module(data, mod, options, diff)) {
        sr_errinfo_new_ly(&err_info, mod->ctx, NULL, SR_ERR_VALIDATION_FAILED);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_validate_module_final(struct lyd_node *data, const struct lys_module *mod, uint32_t options)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;
    const struct ly_err_item *e;

    ly_temp_log_options(&temp_lo);

    /* clear any previous errors and warnings */
    ly_err_clean(mod->ctx, NULL);

    if (lyd_validate_module_final(data, mod, options)) {
        sr_errinfo_new_ly(&err_info, mod->ctx, data, SR_ERR_VALIDATION_FAILED);
        goto cleanup;
    }

    /* print any warnings (such as about obsolete data being instantiated) */
    for (e = ly_err_first(mod->ctx); e; e = e->next) {
        SR_LOG_WRN("%s", e->msg);
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_validate_op(struct lyd_node *op, const struct lyd_node *oper_data, enum lyd_type op_type)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;
    const struct ly_err_item *e;

    ly_temp_log_options(&temp_lo);

    /* clear any previous errors and warnings */
    ly_err_clean((struct ly_ctx *)LYD_CTX(op), NULL);

    if (lyd_validate_op(op, oper_data, op_type, NULL)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(op), op, SR_ERR_VALIDATION_FAILED);
        goto cleanup;
    }

    /* print any warnings (such as about obsolete data being instantiated) */
    for (e = ly_err_first(LYD_CTX(op)); e; e = e->next) {
        SR_LOG_WRN("%s", e->msg);
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_new_path(struct lyd_node *parent, const struct ly_ctx *ctx, const char *path, const char *value,
        uint32_t options, struct lyd_node **new_parent, struct lyd_node **new_node)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_new_path2(parent, ctx, path, value, value ? strlen(value) * 8 : 0, LYD_ANYDATA_STRING, options, new_parent,
            new_node)) {
        sr_errinfo_new_ly(&err_info, ctx ? ctx : LYD_CTX(parent), NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_new_term(struct lyd_node *parent, const struct lys_module *mod, const char *name, const char *value)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_new_term(parent, mod, name, value, 0, NULL)) {
        sr_errinfo_new_ly(&err_info, parent ? LYD_CTX(parent) : mod->ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_new_term2(struct lyd_node *parent, const struct lys_module *mod, const char *name, const char *value,
        struct lyd_node **node)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_new_term(parent, mod, name, value, 0, node)) {
        sr_errinfo_new_ly(&err_info, parent ? LYD_CTX(parent) : mod->ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_new_list(struct lyd_node *parent, const char *name, const char *key_value, struct lyd_node **node)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_new_list3(parent, NULL, name, key_value ? (const void **)&key_value : NULL, NULL, 0, node)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(parent), NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_new_inner(struct lyd_node *parent, const struct lys_module *mod, const char *name, struct lyd_node **node)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_new_inner(parent, mod, name, 0, node)) {
        sr_errinfo_new_ly(&err_info, parent ? LYD_CTX(parent) : mod->ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_new_any(struct lyd_node *parent, const char *name, void *value, LYD_ANYDATA_VALUETYPE value_type)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_new_any(parent, NULL, name, value, value_type, LYD_NEW_ANY_USE_VALUE, NULL)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(parent), NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_new_opaq(const struct ly_ctx *ctx, const char *name, const char *value, const char *prefix,
        const char *module_name, struct lyd_node **node)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_new_opaq(NULL, ctx, name, value, prefix, module_name, node)) {
        sr_errinfo_new_ly(&err_info, ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_new_meta(struct lyd_node *parent, const struct lys_module *mod, const char *name, const char *value)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_new_meta(NULL, parent, mod, name, value, 0, NULL)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(parent), NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_new_meta2(const struct ly_ctx *ctx, struct lyd_node *parent, const struct lyd_attr *attr, struct lyd_meta **meta)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;
    LY_ERR lyrc;

    ly_temp_log_options(&temp_lo);

    lyrc = lyd_new_meta2(ctx, parent, 0, attr, meta);
    if (lyrc && (lyrc != LY_ENOT)) {
        sr_errinfo_new_ly(&err_info, ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

    /* discard any suppressed errors */
    ly_err_clean((struct ly_ctx *) ctx, NULL);

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_dup_meta_single(const struct lyd_meta *meta, struct lyd_node *parent)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_dup_meta_single(meta, parent, NULL)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(parent), NULL, SR_ERR_LY);
        goto cleanup;
    }

    /* discard any suppressed errors */
    ly_err_clean((struct ly_ctx *)LYD_CTX(parent), NULL);

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_new_attr(struct lyd_node *parent, const char *mod_name, const char *name, const char *value)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_new_attr(parent, mod_name, name, value, NULL)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(parent), NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_new_attr2(struct lyd_node *parent, const char *mod_ns, const char *name, const char *value)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_new_attr2(parent, mod_ns, name, value, NULL)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(parent), NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_new_implicit_all(struct lyd_node **tree, const struct ly_ctx *ctx, uint32_t options)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_new_implicit_all(tree, ctx, options, NULL)) {
        sr_errinfo_new_ly(&err_info, *tree ? LYD_CTX(*tree) : ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_new_implicit_module(struct lyd_node **data, const struct lys_module *mod, uint32_t options, struct lyd_node **diff)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_new_implicit_module(data, mod, options, diff)) {
        sr_errinfo_new_ly(&err_info, mod->ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_new_implicit_tree(struct lyd_node *tree, uint32_t options)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_new_implicit_tree(tree, options, NULL)) {
        sr_errinfo_new_ly(&err_info, tree ? LYD_CTX(tree) : NULL, NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_dup(const struct lyd_node *node, struct lyd_node *parent, uint32_t options, int siblings, struct lyd_node **dup)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;
    LY_ERR lyrc;

    ly_temp_log_options(&temp_lo);

    if (siblings) {
        lyrc = lyd_dup_siblings(node, (struct lyd_node_inner *)parent, options, dup);
    } else {
        lyrc = lyd_dup_single(node, (struct lyd_node_inner *)parent, options, dup);
    }

    if (lyrc) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(node), NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_dup_siblings_to_ctx(const struct lyd_node *sibling, const struct ly_ctx *trg_ctx, uint32_t options,
        struct lyd_node **dup)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_dup_siblings_to_ctx(sibling, trg_ctx, NULL, options, dup)) {
        sr_errinfo_new_ly(&err_info, trg_ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

void
sr_lyd_free_tree_safe(struct lyd_node *tree, struct lyd_node **first)
{
    struct lyd_node *parent, *iter;

    if (!tree) {
        return;
    }

    /* update first pointer */
    if (first && (*first == tree)) {
        *first = (*first)->next;
    }

    /* free the subtree */
    parent = lyd_parent(tree);
    lyd_free_tree(tree);

    while (parent && (parent->schema->nodetype == LYS_CONTAINER) && !(parent->schema->flags & LYS_PRESENCE)) {
        /* set empty non-presence container dflt flag */
        LY_LIST_FOR(lyd_child(parent), iter) {
            if (!(iter->flags & LYD_DEFAULT)) {
                return;
            }
        }
        parent->flags |= LYD_DEFAULT;

        /* check all the parent containers */
        parent = lyd_parent(parent);
    }
}

sr_error_info_t *
sr_lyd_merge(struct lyd_node **target, const struct lyd_node *source, int siblings, uint32_t options)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;
    LY_ERR lyrc;

    ly_temp_log_options(&temp_lo);

    if (siblings) {
        lyrc = lyd_merge_siblings(target, source, options);
    } else {
        lyrc = lyd_merge_tree(target, source, options);
    }
    if (lyrc) {
        sr_errinfo_new_ly(&err_info, *target ? LYD_CTX(*target) : LYD_CTX(source), NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_merge_module(struct lyd_node **target, const struct lyd_node *source, const struct lys_module *mod,
        lyd_merge_cb merge_cb, void *cb_data, uint32_t options)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;
    const struct ly_ctx *ly_ctx;

    ly_temp_log_options(&temp_lo);

    if (mod) {
        ly_ctx = mod->ctx;
    } else if (source) {
        ly_ctx = LYD_CTX(source);
    } else {
        ly_ctx = LYD_CTX(*target);
    }

    if (lyd_merge_module(target, source, mod, merge_cb, cb_data, options)) {
        sr_errinfo_new_ly(&err_info, ly_ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_find_xpath(const struct lyd_node *tree, const char *xpath, struct ly_set **set)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    if (!tree) {
        /* return empty set */
        return sr_ly_set_new(set);
    }

    ly_temp_log_options(&temp_lo);

    if (lyd_find_xpath(tree, xpath, set)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(tree), NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_find_path(const struct lyd_node *tree, const char *path, int with_incomplete, struct lyd_node **match)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;
    LY_ERR lyrc;
    const struct ly_ctx *ctx = tree ? LYD_CTX(tree) : NULL;

    ly_temp_log_options(&temp_lo);

    lyrc = lyd_find_path(tree, path, 0, match);
    if (lyrc == LY_EINCOMPLETE) {
        if (!with_incomplete) {
            *match = NULL;
        }
    } else if (lyrc && (lyrc != LY_ENOTFOUND)) {
        sr_errinfo_new_ly(&err_info, ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

    /* discard any suppressed errors */
    if (ctx) {
        ly_err_clean((struct ly_ctx *) ctx, NULL);
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_find_sibling_first(const struct lyd_node *sibling, const struct lyd_node *target, struct lyd_node **match)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;
    LY_ERR lyrc;
    const struct ly_ctx *ctx = sibling ? LYD_CTX(sibling) : NULL;

    ly_temp_log_options(&temp_lo);

    lyrc = lyd_find_sibling_first(sibling, target, match);
    if (lyrc && (lyrc != LY_ENOTFOUND)) {
        sr_errinfo_new_ly(&err_info, ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

    /* discard any suppressed errors */
    if (ctx) {
        ly_err_clean((struct ly_ctx *) ctx, NULL);
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_find_sibling_val(const struct lyd_node *sibling, const struct lysc_node *schema, const char *value,
        struct lyd_node **match)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;
    LY_ERR lyrc;
    const struct ly_ctx *ctx = sibling ? LYD_CTX(sibling) : NULL;

    ly_temp_log_options(&temp_lo);

    lyrc = lyd_find_sibling_val(sibling, schema, value, value ? strlen(value) : 0, match);
    if (lyrc && (lyrc != LY_ENOTFOUND)) {
        sr_errinfo_new_ly(&err_info, ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

    /* discard any suppressed errors */
    if (ctx) {
        ly_err_clean((struct ly_ctx *) ctx, NULL);
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_find_sibling_opaq_next(const struct lyd_node *sibling, const char *name, struct lyd_node **match)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;
    LY_ERR lyrc;
    const struct ly_ctx *ctx = sibling ? LYD_CTX(sibling) : NULL;

    ly_temp_log_options(&temp_lo);

    lyrc = lyd_find_sibling_opaq_next(sibling, name, match);
    if (lyrc && (lyrc != LY_ENOTFOUND)) {
        sr_errinfo_new_ly(&err_info, ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

    /* discard any suppressed errors */
    if (ctx) {
        ly_err_clean((struct ly_ctx *) ctx, NULL);
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_insert_sibling(struct lyd_node *sibling, struct lyd_node *node, struct lyd_node **first)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    if (!node) {
        return NULL;
    }

    ly_temp_log_options(&temp_lo);

    if (lyd_insert_sibling(sibling, node, first)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(node), NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_insert_child(struct lyd_node *parent, struct lyd_node *child)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_insert_child(parent, child)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(parent), NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_insert_before(struct lyd_node *sibling, struct lyd_node *node)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_insert_before(sibling, node)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(node), NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_insert_after(struct lyd_node *sibling, struct lyd_node *node)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_insert_after(sibling, node)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(node), NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_change_term(struct lyd_node *node, const char *value, int ignore_fail)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;
    LY_ERR lyrc;
    const struct ly_ctx *ctx = node ? LYD_CTX(node) : NULL;

    ly_temp_log_options(&temp_lo);

    lyrc = lyd_change_term(node, value);
    if (lyrc && (!ignore_fail || ((lyrc != LY_EEXIST) && (lyrc != LY_ENOT)))) {
        sr_errinfo_new_ly(&err_info, ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

    /* discard any suppressed errors */
    if (ctx) {
        ly_err_clean((struct ly_ctx *) ctx, NULL);
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_any_value_str(const struct lyd_node *node, char **str)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_any_value_str(node, str)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(node), NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_any_copy_value(struct lyd_node *node, const union lyd_any_value *value,
        LYD_ANYDATA_VALUETYPE value_type)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_any_copy_value(node, value, value_type)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(node), NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_diff_siblings(const struct lyd_node *target, const struct lyd_node *source, uint32_t options,
        struct lyd_node **diff)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_diff_siblings(target, source, options, diff)) {
        sr_errinfo_new_ly(&err_info, target ? LYD_CTX(target) : LYD_CTX(source), source, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_diff_apply_module(struct lyd_node **data, const struct lyd_node *diff, const struct lys_module *mod,
        lyd_diff_cb diff_cb)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_diff_apply_module(data, diff, mod, diff_cb, NULL)) {
        sr_errinfo_new_ly(&err_info, mod->ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_diff_merge_module(struct lyd_node **target, const struct lyd_node *source, const struct lys_module *mod)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_diff_merge_module(target, source, mod, NULL, NULL, 0)) {
        sr_errinfo_new_ly(&err_info, mod->ctx, NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_diff_merge_all(struct lyd_node **target, const struct lyd_node *source)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_diff_merge_all(target, source, 0)) {
        sr_errinfo_new_ly(&err_info, *target ? LYD_CTX(*target) : LYD_CTX(source), NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_diff_merge_tree(struct lyd_node **target_first, struct lyd_node *target_parent, const struct lyd_node *source)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_diff_merge_tree(target_first, target_parent, source, NULL, NULL, 0)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(*target_first), NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_diff_reverse_all(const struct lyd_node *diff, struct lyd_node **rdiff)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyd_diff_reverse_all(diff, rdiff)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(diff), NULL, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_ly_set_new(struct ly_set **set)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (ly_set_new(set)) {
        sr_errinfo_new(&err_info, SR_ERR_LY, "%s", ly_last_logmsg());
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_ly_set_add(struct ly_set *set, void *item)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (ly_set_add(set, item, 1, NULL)) {
        sr_errinfo_new(&err_info, SR_ERR_LY, "%s", ly_last_logmsg());
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_ly_set_merge(struct ly_set *target, const struct ly_set *source)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (ly_set_merge(target, source, 0, NULL)) {
        sr_errinfo_new(&err_info, SR_ERR_LY, "%s", ly_last_logmsg());
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyht_insert(struct ly_ht *ht, void *val_p, uint32_t hash)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (lyht_insert(ht, val_p, hash, NULL)) {
        sr_errinfo_new(&err_info, SR_ERR_LY, "%s", ly_last_logmsg());
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_ly_print_xpath10_value(const struct lyd_value_xpath10 *xp_val, char **str)
{
    sr_error_info_t *err_info = NULL;
    struct ly_err_item *err;

    if (lyplg_type_print_xpath10_value(xp_val, LY_VALUE_JSON, NULL, str, &err)) {
        if (err) {
            sr_errinfo_new(&err_info, SR_ERR_LY, "%s", err->msg);
            ly_err_free(err);
        } else {
            sr_errinfo_new(&err_info, SR_ERR_LY, "Failed to print parent reference value.");
        }
        goto cleanup;
    }

cleanup:
    return err_info;
}

sr_error_info_t *
sr_ly_canonize_xpath10_value(const struct ly_ctx *ctx, const char *value, LY_VALUE_FORMAT format, void *prefix_data,
        char **str)
{
    sr_error_info_t *err_info = NULL;
    const struct lysc_node_leaf *leaf_xpath = NULL;
    struct lyd_value val = {0};
    struct ly_err_item *err = NULL;
    struct lyplg_type *type_plg;

    /* get leaf of xpath1.0 type */
    leaf_xpath = (struct lysc_node_leaf *)lys_find_path(ctx, NULL, "/sysrepo:sysrepo-modules/module/rpc/path", 0);
    assert(leaf_xpath);

    type_plg = lysc_get_type_plugin(leaf_xpath->type->plugin_ref);
    assert(!strcmp(type_plg->id, "ly2 xpath1.0"));

    /* get the path in canonical (JSON) format */
    if (type_plg->store(ctx, leaf_xpath->type, value, strlen(value) * 8, 0, format, prefix_data,
            LYD_HINT_DATA, NULL, &val, NULL, &err)) {
        if (err) {
            sr_errinfo_new(&err_info, SR_ERR_LY, "%s", err->msg);
        }
        SR_ERRINFO_INT(&err_info);
        memset(&val, 0, sizeof val);
        goto cleanup;
    }
    *str = strdup(lyd_value_get_canonical(ctx, &val));

cleanup:
    ly_err_free(err);
    type_plg->free(ctx, &val);
    return err_info;
}

sr_error_info_t *
sr_lyd_parse_opaq_error(const struct lyd_node *node)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    lyd_parse_opaq_error(node);
    sr_errinfo_new_ly(&err_info, LYD_CTX(node), NULL, SR_ERR_LY);

    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_ly_time_ts2str(const struct timespec *ts, char **str)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (ly_time_ts2str(ts, str)) {
        sr_errinfo_new(&err_info, SR_ERR_LY, "%s", ly_last_logmsg());
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_ly_ctx_compiled_print(const struct ly_ctx *ctx, void *mem, void **mem_end)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (ly_ctx_compiled_print(ctx, mem, mem_end)) {
        sr_errinfo_new(&err_info, SR_ERR_LY, "%s", ly_last_logmsg());
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_ly_ctx_new_printed(const void *mem, struct ly_ctx **ctx)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;

    ly_temp_log_options(&temp_lo);

    if (ly_ctx_new_printed(mem, ctx)) {
        sr_errinfo_new(&err_info, SR_ERR_LY, "%s", ly_last_logmsg());
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}

sr_error_info_t *
sr_lyplg_ext_schema_mount_create_shared_context(struct lysc_ext_instance *ext,
        const struct lyd_node *ext_data)
{
    sr_error_info_t *err_info = NULL;
    uint32_t temp_lo = LY_LOSTORE;
    LY_ERR r;

    ly_temp_log_options(&temp_lo);

    r = lyplg_ext_schema_mount_create_shared_context(ext, ext_data);
    if (r && (r != LY_ENOT)) {
        /* do not treat missing mount point data as an error */
        sr_errinfo_new(&err_info, SR_ERR_LY, "%s", ly_last_logmsg());
        goto cleanup;
    }

cleanup:
    ly_temp_log_options(NULL);
    return err_info;
}
