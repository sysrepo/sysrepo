/**
 * @file ly_wrap.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libyang function wrappers
 *
 * @copyright
 * Copyright (c) 2024 - 2026 Deutsche Telekom AG.
 * Copyright (c) 2024 - 2026 CESNET, z.s.p.o.
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
#include "context_change.h"
#include "log.h"
#include "sysrepo.h"

struct sr_ly_err {
    sr_log_level_t level;
    char *msg;
    char *path;
};

THREAD uint32_t ly_temp_lo = LY_LOLOG;  /**< temp LY log options to use */
THREAD uint32_t *prev_ly_temp_lo;   /**< previous temp LY log options, for nested calls */
THREAD ly_log_clb prev_ly_log_cb;   /**< previous LY log callback */

THREAD struct {
    struct sr_ly_err *errs;
    uint32_t err_count;
} ly_errs;                          /**< array of generated LY errors */

/**
 * @brief Transform LY log level to SR log level.
 *
 * @param[in] level LY log level.
 * @return SR log level.
 */
static sr_log_level_t
sr_log_level_ly2sr(LY_LOG_LEVEL level)
{
    switch (level) {
    case LY_LLERR:
        return SR_LL_ERR;
    case LY_LLWRN:
        return SR_LL_WRN;
    case LY_LLVRB:
        return SR_LL_VRB;
    case LY_LLDBG:
        return SR_LL_DBG;
    }

    return SR_LL_NONE;
}

/**
 * @brief Sysrepo logging callback for libyang.
 */
static void
sr_ly_log_clb(LY_LOG_LEVEL level, const char *msg, const char *data_path, const char *schema_path, uint64_t UNUSED(line))
{
    sr_error_info_t *err_info = NULL;
    struct sr_ly_err *err;
    void *mem;

    /* allocate a new error */
    mem = realloc(ly_errs.errs, (ly_errs.err_count + 1) * sizeof *ly_errs.errs);
    SR_CHECK_MEM_GOTO(!mem, err_info, cleanup);
    ly_errs.errs = mem;
    ++ly_errs.err_count;

    err = &ly_errs.errs[ly_errs.err_count - 1];
    memset(err, 0, sizeof *err);

    /* store level */
    err->level = sr_log_level_ly2sr(level);

    /* store message */
    err->msg = strdup(msg);
    SR_CHECK_MEM_GOTO(!err->msg, err_info, cleanup);

    /* store path */
    if (data_path) {
        err->path = strdup(data_path);
        SR_CHECK_MEM_GOTO(!err->path, err_info, cleanup);
    } else if (schema_path) {
        err->path = strdup(schema_path);
        SR_CHECK_MEM_GOTO(!err->path, err_info, cleanup);
    }

cleanup:
    sr_errinfo_free(&err_info);
}

/**
 * @brief Set up libyang logging for sysrepo.
 *
 * Stores all the generated messages in ::ly_errs.
 */
static void
sr_ly_log_setup(void)
{
    /* only log ... */
    prev_ly_temp_lo = ly_temp_log_options(&ly_temp_lo);

    /* (unless in a nested call when we could not be logging at all, for example) */
    if (prev_ly_temp_lo) {
        ly_temp_log_options(prev_ly_temp_lo);
        return;
    }

    /* ... using a callback */
    prev_ly_log_cb = ly_temp_log_clb(sr_ly_log_clb);
}

/**
 * @brief Clear any generated stored LY messages.
 */
static void
sr_ly_log_clear(void)
{
    struct sr_ly_err *err;
    uint32_t i;

    /* free all the messages */
    for (i = 0; i < ly_errs.err_count; ++i) {
        err = &ly_errs.errs[i];

        free(err->msg);
        free(err->path);
    }

    free(ly_errs.errs);
    ly_errs.errs = NULL;
    ly_errs.err_count = 0;
}

/**
 * @brief Revert back libyang logging set up for sysrepo.
 */
static void
sr_ly_log_revert(void)
{
    struct sr_ly_err *err;
    uint32_t i;

    /* revert log options */
    if (prev_ly_temp_lo) {
        prev_ly_temp_lo = NULL;
        return;
    }
    ly_temp_log_options(NULL);

    /* revert log callback */
    ly_temp_log_clb(prev_ly_log_cb);

    /* print any messages */
    for (i = 0; i < ly_errs.err_count; ++i) {
        err = &ly_errs.errs[i];
        assert(err->level != SR_LL_ERR);

        sr_log_msg(0, err->level, err->msg);
    }

    /* free all the messages */
    sr_ly_log_clear();
}

/**
 * @brief Log the error(s) generated and stored by a previous LY function call
 *
 * @param[in,out] err_info Existing error info.
 * @param[in] err_code Error code to use.
 */
static void
sr_errinfo_new_ly(sr_error_info_t **err_info, sr_error_t err_code)
{
    struct sr_ly_err *err;
    uint32_t i;

    for (i = 0; i < ly_errs.err_count; ++i) {
        err = &ly_errs.errs[i];

        if (err->level == SR_LL_ERR) {
            /* store and print */
            if (err->path) {
                sr_errinfo_new(err_info, err_code, "%s (path \"%s\")", err->msg, err->path);
            } else {
                sr_errinfo_new(err_info, err_code, "%s", err->msg);
            }
        } else {
            /* only print */
            sr_log_msg(0, err->level, err->msg);
        }
    }

    /* free the printed messages */
    sr_ly_log_clear();
}

sr_error_info_t *
sr_ly_ctx_new(struct ly_ctx **ly_ctx)
{
    sr_error_info_t *err_info = NULL;
    char *yang_dir = NULL;
    const char *factory_default_features[] = {"factory-default-datastore", NULL};
    uint16_t ctx_opts;
    struct ly_in *in = NULL;
    LY_ERR r;

    /* context options */
    ctx_opts = LY_CTX_NO_YANGLIBRARY | LY_CTX_DISABLE_SEARCHDIR_CWD | LY_CTX_REF_IMPLEMENTED |
            LY_CTX_EXPLICIT_COMPILE | LY_CTX_STATIC_PLUGINS_ONLY | LY_CTX_LYB_HASHES;

    /* add the configured options */
    if (ATOMIC_LOAD_RELAXED(sr_yang_ctx.sr_opts) & SR_CTX_SET_PRIV_PARSED) {
        ctx_opts |= LY_CTX_SET_PRIV_PARSED;
    }

    if (ATOMIC_LOAD_RELAXED(sr_yang_ctx.sr_opts) & SR_CTX_COMPILE_OBSOLETE) {
        ctx_opts |= LY_CTX_COMPILE_OBSOLETE;
    }

    sr_ly_log_setup();

    /* create a new context */
    if (ly_ctx_new(ly_yang_module_dir(), ctx_opts, ly_ctx)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        sr_errinfo_new(&err_info, SR_ERR_INTERNAL, "Failed to create a new libyang context.");
        goto cleanup;
    }

    /* set search path for the internal YANG modules */
    r = ly_ctx_set_searchdir(*ly_ctx, sr_yang_module_dir());
    if (r && (r != LY_EEXIST)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

    /* load just the internal datastores modules and the "sysrepo" module */
    if (!ly_ctx_load_module(*ly_ctx, "ietf-datastores", "2018-02-14", NULL)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }
    if (!ly_ctx_load_module(*ly_ctx, "sysrepo", "2025-04-04", NULL)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }
    if (!ly_ctx_load_module(*ly_ctx, "ietf-netconf-acm", "2018-02-14", NULL)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

    if (!ly_ctx_load_module(*ly_ctx, "ietf-factory-default", "2020-08-31", factory_default_features)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }
    if (!ly_ctx_load_module(*ly_ctx, "sysrepo-factory-default", "2025-03-18", NULL)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

    /* compile the final context */
    if ((err_info = sr_ly_ctx_compile(*ly_ctx))) {
        goto cleanup;
    }

    /* set the repo search path yang dir */
    if ((err_info = sr_path_yang_dir(&yang_dir))) {
        goto cleanup;
    }
    r = ly_ctx_set_searchdir(*ly_ctx, yang_dir);
    if (r && (r != LY_EEXIST)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

    /* set the ext callback */
    ly_ctx_set_ext_data_clb(*ly_ctx, sr_ly_ext_data_clb, NULL);

cleanup:
    if (err_info) {
        ly_ctx_destroy(*ly_ctx);
        *ly_ctx = NULL;
    }
    sr_ly_log_revert();
    free(yang_dir);
    ly_in_free(in, 0);
    return err_info;
}

void
sr_ly_ctx_destroy(struct ly_ctx *ly_ctx)
{
    sr_ly_log_setup();

    ly_ctx_destroy(ly_ctx);

    sr_ly_log_revert();
}

sr_error_info_t *
sr_lys_parse(struct ly_ctx *ctx, const char *data, const char *path, LYS_INFORMAT format, const char **features,
        struct lys_module **ly_mod)
{
    sr_error_info_t *err_info = NULL;
    struct ly_in *in = NULL;

    sr_ly_log_setup();

    if (path) {
        if (ly_in_new_filepath(path, 0, &in)) {
            sr_errinfo_new_ly(&err_info, SR_ERR_LY);
            goto cleanup;
        }
    } else {
        if (ly_in_new_memory(data, &in)) {
            sr_errinfo_new_ly(&err_info, SR_ERR_LY);
            goto cleanup;
        }
    }

    if (lys_parse(ctx, in, format, features, ly_mod)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_in_free(in, 0);
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lys_set_implemented(struct lys_module *mod, const char **features)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lys_set_implemented(mod, features)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lys_print(const char *path, const struct lys_module *mod, const struct lysp_submodule *submod)
{
    sr_error_info_t *err_info = NULL;
    struct ly_out *out = NULL;
    LY_ERR lyrc;

    sr_ly_log_setup();

    ly_out_new_filepath(path, &out);

    if (submod) {
        lyrc = lys_print_submodule(out, submod, LYS_OUT_YANG, 0, 0);
    } else {
        lyrc = lys_print_module(out, mod, LYS_OUT_YANG, 0, 0);
    }
    if (lyrc) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_out_free(out, NULL, 0);
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_ly_ctx_get_yanglib_data(const struct ly_ctx *ctx, struct lyd_node **data, uint32_t content_id)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (ly_ctx_get_yanglib_data(ctx, data, "0x%08x", content_id)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_ly_ctx_load_module(struct ly_ctx *ctx, const char *name, const char *revision, const char **features,
        const struct lys_module **ly_mod)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *mod = NULL;

    sr_ly_log_setup();

    if (!(mod = ly_ctx_load_module(ctx, name, revision, features))) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    *ly_mod = mod;
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_ly_ctx_compile(struct ly_ctx *ctx)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (ly_ctx_compile(ctx)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lys_find_path(const struct ly_ctx *ctx, const char *path, int *valid, const struct lysc_node **match)
{
    sr_error_info_t *err_info = NULL;
    const struct lysc_node *m;

    sr_ly_log_setup();

    if (valid) {
        *valid = 1;
    }

    if (!(m = lys_find_path(ctx, NULL, path, 0))) {
        if (valid) {
            *valid = 0;
            sr_ly_log_clear();
        } else {
            sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        }
        goto cleanup;
    }

    if (match) {
        *match = m;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lys_find_path_atoms(const struct ly_ctx *ctx, const struct lysc_node *ctx_node, const char *path, int *valid,
        struct ly_set **set)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (valid) {
        *valid = 1;
    }

    if (lys_find_path_atoms(ctx, ctx_node, path, 0, set)) {
        if (valid) {
            *valid = 0;
            sr_ly_log_clear();
        } else {
            sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        }
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lys_find_xpath(const struct ly_ctx *ctx, const char *xpath, uint32_t options, int *valid, struct ly_set **set)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (valid) {
        *valid = 1;
    }

    if (lys_find_xpath(ctx, NULL, xpath, options, set) || !(*set)->count) {
        if (valid) {
            *valid = 0;
            sr_ly_log_clear();
        } else {
            sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        }
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lys_find_xpath_atoms(const struct ly_ctx *ctx, const char *xpath, uint32_t options, int *valid, struct ly_set **set)
{
    sr_error_info_t *err_info = NULL;
    LY_ERR lyrc;
    uint32_t i;

    sr_ly_log_setup();

    if (valid) {
        *valid = 1;
    }

    if ((lyrc = lys_find_xpath_atoms(ctx, NULL, xpath, options, set))) {
        if (valid) {
            *valid = 0;
            sr_ly_log_clear();
        } else if (lyrc == LY_ENOTFOUND) {
            sr_errinfo_new_ly(&err_info, SR_ERR_NOT_FOUND);
        } else {
            sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        }
        goto cleanup;
    }

    if (options & LYS_FIND_NO_MATCH_ERROR) {
        /* some unions may have matched while others did not and generated errors, make them into warnings */
        for (i = 0; i < ly_errs.err_count; ++i) {
            if (ly_errs.errs[i].level == SR_LL_ERR) {
                ly_errs.errs[i].level = SR_LL_WRN;
            }
        }
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lys_find_expr_atoms(const struct lysc_node *ctx_node, const struct lys_module *cur_mod, const struct lyxp_expr *exp,
        struct lysc_prefix *prefixes, uint32_t options, struct ly_set **set)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lys_find_expr_atoms(ctx_node, cur_mod, exp, prefixes, options, set)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

    /* ignore any warnings, exp has already been parsed and checked so any relevant warnings must have already been
     * printed and these can even be false-positives */
    sr_ly_log_clear();

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_parse_data(const struct ly_ctx *ctx, const char *data, const char *data_path, LYD_FORMAT format,
        uint32_t parse_options, uint32_t validation_options, struct lyd_node **tree)
{
    sr_error_info_t *err_info = NULL;
    LY_ERR lyrc = LY_SUCCESS;

    sr_ly_log_setup();

    *tree = NULL;

    if (data_path) {
        lyrc = lyd_parse_data_path(ctx, data_path, format, parse_options, validation_options, tree);
    } else if (data) {
        lyrc = lyd_parse_data_mem(ctx, data, format, parse_options, validation_options, tree);
    }

    /* empty data are fine */
    if (lyrc) {
        if ((lyrc != LY_EINVAL) || strcmp(ly_last_logmsg(), "Empty input file.")) {
            sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        } else {
            sr_ly_log_clear();
        }
        goto cleanup;
    }

cleanup:
    if (err_info) {
        lyd_free_siblings(*tree);
        *tree = NULL;
    }
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_parse_op(const struct ly_ctx *ctx, const char *data, LYD_FORMAT format, enum lyd_type data_type,
        struct lyd_node **tree)
{
    sr_error_info_t *err_info = NULL;
    struct ly_in *in = NULL;

    sr_ly_log_setup();

    if (ly_in_new_memory(data, &in)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

    if (lyd_parse_op(ctx, NULL, in, format, data_type, LYD_PARSE_STRICT, tree, NULL)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    ly_in_free(in, 0);
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_print_data(const struct lyd_node *data, LYD_FORMAT format, uint32_t print_options, int fd, char **str,
        uint32_t *len)
{
    sr_error_info_t *err_info = NULL;
    struct ly_out *out = NULL;

    sr_ly_log_setup();

    if (fd == -1) {
        ly_out_new_memory(str, 0, &out);
    } else {
        ly_out_new_fd(fd, &out);
    }

    if (lyd_print_all(out, data, format, print_options)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

    if (len) {
        *len = ly_out_printed(out);
    }

cleanup:
    ly_out_free(out, NULL, 0);
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_validate_all(struct lyd_node **data, const struct ly_ctx *ctx, uint32_t options)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_validate_all(data, ctx, options, NULL)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_VALIDATION_FAILED);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_validate_module(struct lyd_node **data, const struct lys_module *mod, uint32_t options, struct lyd_node **diff)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_validate_module(data, mod, options, diff)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_VALIDATION_FAILED);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_validate_module_final(struct lyd_node *data, const struct lys_module *mod, uint32_t options)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_validate_module_final(data, mod, options)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_VALIDATION_FAILED);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_validate_op(struct lyd_node *op, const struct lyd_node *oper_data, enum lyd_type op_type)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_validate_op(op, oper_data, op_type, NULL)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_VALIDATION_FAILED);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_new_path(struct lyd_node *parent, const struct ly_ctx *ctx, const char *path, const char *value,
        uint32_t options, struct lyd_node **new_parent, struct lyd_node **new_node)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_new_path2(parent, ctx, path, value, value ? strlen(value) * 8 : 0, 0, options, new_parent,
            new_node)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_new_term(struct lyd_node *parent, const struct lys_module *mod, const char *name, const char *value)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_new_term(parent, mod, name, value, 0, NULL)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_new_term2(struct lyd_node *parent, const struct lys_module *mod, const char *name, const char *value,
        struct lyd_node **node)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_new_term(parent, mod, name, value, 0, node)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_new_list(struct lyd_node *parent, const char *name, const char *key_value, struct lyd_node **node)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_new_list3(parent, NULL, name, key_value ? (const void **)&key_value : NULL, NULL, 0, node)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_new_inner(struct lyd_node *parent, const struct lys_module *mod, const char *name, struct lyd_node **node)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_new_inner(parent, mod, name, 0, node)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_new_any(struct lyd_node *parent, const char *name, struct lyd_node *child, char *value)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_new_any(parent, NULL, name, child, value, 0, LYD_NEW_ANY_USE_VALUE, NULL)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_new_opaq(const struct ly_ctx *ctx, const char *name, const char *value, const char *prefix,
        const char *module_name, struct lyd_node **node)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_new_opaq(NULL, ctx, name, value, prefix, module_name, node)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_new_meta(struct lyd_node *parent, const struct lys_module *mod, const char *name, const char *value)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_new_meta(NULL, parent, mod, name, value, 0, NULL)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_new_meta2(const struct ly_ctx *ctx, struct lyd_node *parent, const struct lyd_attr *attr, struct lyd_meta **meta)
{
    sr_error_info_t *err_info = NULL;
    LY_ERR lyrc;

    sr_ly_log_setup();

    lyrc = lyd_new_meta2(ctx, parent, 0, attr, meta);
    if (lyrc && (lyrc != LY_ENOT)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_dup_meta_single(const struct lyd_meta *meta, struct lyd_node *parent)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_dup_meta_single(meta, parent, NULL)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_new_attr(struct lyd_node *parent, const char *mod_name, const char *name, const char *value)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_new_attr(parent, mod_name, name, value, NULL)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_new_attr2(struct lyd_node *parent, const char *mod_ns, const char *name, const char *value)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_new_attr2(parent, mod_ns, name, value, NULL)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_new_implicit_all(struct lyd_node **tree, const struct ly_ctx *ctx, uint32_t options)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_new_implicit_all(tree, ctx, options, NULL)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_new_implicit_module(struct lyd_node **data, const struct lys_module *mod, uint32_t options, struct lyd_node **diff)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_new_implicit_module(data, mod, options, diff)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_new_implicit_tree(struct lyd_node *tree, uint32_t options)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_new_implicit_tree(tree, options, NULL)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_dup(const struct lyd_node *node, struct lyd_node *parent, uint32_t options, int siblings, struct lyd_node **dup)
{
    sr_error_info_t *err_info = NULL;
    LY_ERR lyrc;

    sr_ly_log_setup();

    if (siblings) {
        lyrc = lyd_dup_siblings(node, parent, options, dup);
    } else {
        lyrc = lyd_dup_single(node, parent, options, dup);
    }

    if (lyrc) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_dup_single_to_ctx(const struct lyd_node *node, const struct ly_ctx *trg_ctx, uint32_t options, struct lyd_node **dup)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_dup_single_to_ctx(node, trg_ctx, NULL, options, dup)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
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
    LY_ERR lyrc;

    sr_ly_log_setup();

    if (siblings) {
        lyrc = lyd_merge_siblings(target, source, options);
    } else {
        lyrc = lyd_merge_tree(target, source, options);
    }
    if (lyrc) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_merge_module(struct lyd_node **target, const struct lyd_node *source, const struct lys_module *mod,
        lyd_merge_cb merge_cb, void *cb_data, uint32_t options)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_merge_module(target, source, mod, merge_cb, cb_data, options)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_find_xpath(const struct lyd_node *tree, const char *xpath, struct ly_set **set)
{
    sr_error_info_t *err_info = NULL;

    if (!tree) {
        /* return empty set */
        return sr_ly_set_new(set);
    }

    sr_ly_log_setup();

    if (lyd_find_xpath(tree, xpath, set)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_find_path(const struct lyd_node *tree, const char *path, int with_incomplete, struct lyd_node **match)
{
    sr_error_info_t *err_info = NULL;
    LY_ERR lyrc;

    sr_ly_log_setup();

    lyrc = lyd_find_path(tree, path, 0, match);
    if (lyrc == LY_EINCOMPLETE) {
        if (!with_incomplete) {
            *match = NULL;
        }
    } else if (lyrc && (lyrc != LY_ENOTFOUND)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_find_sibling_first(const struct lyd_node *sibling, const struct lyd_node *target, struct lyd_node **match)
{
    sr_error_info_t *err_info = NULL;
    LY_ERR lyrc;

    sr_ly_log_setup();

    lyrc = lyd_find_sibling_first(sibling, target, match);
    if (lyrc && (lyrc != LY_ENOTFOUND)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_find_sibling_val(const struct lyd_node *sibling, const struct lysc_node *schema, const char *value,
        struct lyd_node **match)
{
    sr_error_info_t *err_info = NULL;
    LY_ERR lyrc;

    sr_ly_log_setup();

    lyrc = lyd_find_sibling_val(sibling, schema, value, value ? strlen(value) : 0, match);
    if (lyrc && (lyrc != LY_ENOTFOUND)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_find_sibling_opaq_next(const struct lyd_node *sibling, const char *name, struct lyd_node **match)
{
    sr_error_info_t *err_info = NULL;
    LY_ERR lyrc;

    sr_ly_log_setup();

    lyrc = lyd_find_sibling_opaq_next(sibling, name, match);
    if (lyrc && (lyrc != LY_ENOTFOUND)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_insert_sibling(struct lyd_node *sibling, struct lyd_node *node, struct lyd_node **first)
{
    sr_error_info_t *err_info = NULL;

    if (!node) {
        return NULL;
    }

    sr_ly_log_setup();

    if (lyd_insert_sibling(sibling, node, first)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_insert_child(struct lyd_node *parent, struct lyd_node *child)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_insert_child(parent, child)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_insert_before(struct lyd_node *sibling, struct lyd_node *node)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_insert_before(sibling, node)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_insert_after(struct lyd_node *sibling, struct lyd_node *node)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_insert_after(sibling, node)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_change_term(struct lyd_node *node, const char *value, int ignore_fail)
{
    sr_error_info_t *err_info = NULL;
    LY_ERR lyrc;

    sr_ly_log_setup();

    lyrc = lyd_change_term(node, value);
    if (lyrc && (!ignore_fail || ((lyrc != LY_EEXIST) && (lyrc != LY_ENOT)))) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_any_value_str(const struct lyd_node *node, char **str)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_any_value_str(node, LYD_XML, str)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_any_copy_value(struct lyd_node *node, const struct lyd_node *child, const void *value, uint32_t hints)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_any_copy_value(node, child, value, hints)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_diff_siblings(const struct lyd_node *target, const struct lyd_node *source, uint32_t options,
        int *snode_not_found, struct lyd_node **diff)
{
    sr_error_info_t *err_info = NULL;
    LY_ERR lyrc;

    if (snode_not_found) {
        *snode_not_found = 0;
    }

    sr_ly_log_setup();

    lyrc = lyd_diff_siblings(target, source, options, diff);
    if ((lyrc == LY_ENOTFOUND) && snode_not_found) {
        /* ignore this error, just set the flag */
        sr_ly_log_clear();
        *snode_not_found = 1;
    } else if (lyrc) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_diff_apply_all(struct lyd_node **data, const struct lyd_node *diff)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_diff_apply_all(data, diff)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_diff_apply_module(struct lyd_node **data, const struct lyd_node *diff, const struct lys_module *mod,
        lyd_diff_cb diff_cb)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_diff_apply_module(data, diff, mod, diff_cb, NULL)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_diff_merge_module(struct lyd_node **target, const struct lyd_node *source, const struct lys_module *mod)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_diff_merge_module(target, source, mod, NULL, NULL, 0)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_diff_merge_all(struct lyd_node **target, const struct lyd_node *source)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_diff_merge_all(target, source, 0)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_diff_merge_tree(struct lyd_node **target_first, struct lyd_node *target_parent, const struct lyd_node *source)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_diff_merge_tree(target_first, target_parent, source, NULL, NULL, 0)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyd_diff_reverse_all(const struct lyd_node *diff, struct lyd_node **rdiff)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyd_diff_reverse_all(diff, rdiff)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_ly_set_new(struct ly_set **set)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (ly_set_new(set)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_ly_set_add(struct ly_set *set, void *item)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (ly_set_add(set, item, 1, NULL)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_ly_set_merge(struct ly_set *target, const struct ly_set *source)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (ly_set_merge(target, source, 0, NULL)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyht_insert(struct ly_ht *ht, void *val_p, uint32_t hash)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (lyht_insert(ht, val_p, hash, NULL)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
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

    sr_ly_log_setup();

    lyd_parse_opaq_error(node);
    sr_errinfo_new_ly(&err_info, SR_ERR_LY);

    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_ly_time_ts2str(const struct timespec *ts, char **str)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (ly_time_ts2str(ts, str)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_ly_ctx_compiled_print(const struct ly_ctx *ctx, void *mem, void **mem_end)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (ly_ctx_compiled_print(ctx, mem, mem_end)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_ly_ctx_new_printed(const void *mem, struct ly_ctx **ctx)
{
    sr_error_info_t *err_info = NULL;

    sr_ly_log_setup();

    if (ly_ctx_new_printed(mem, ctx)) {
        sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}

sr_error_info_t *
sr_lyplg_ext_schema_mount_create_shared_context(struct lysc_ext_instance *ext,
        const struct lyd_node *ext_data)
{
    sr_error_info_t *err_info = NULL;
    LY_ERR lyrc;

    sr_ly_log_setup();

    lyrc = lyplg_ext_schema_mount_create_shared_context(ext, ext_data);
    if (lyrc) {
        if (lyrc == LY_ENOT) {
            /* do not treat missing mount point data as an error */
            sr_ly_log_clear();
        } else {
            sr_errinfo_new_ly(&err_info, SR_ERR_LY);
        }
        goto cleanup;
    }

cleanup:
    sr_ly_log_revert();
    return err_info;
}
