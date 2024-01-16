/**
 * @file log.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief logging routines
 *
 * @copyright
 * Copyright (c) 2018 - 2024 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2024 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "compat.h"
#include "log.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <libyang/libyang.h>

#include "config.h"

sr_log_level_t sr_stderr_ll = SR_LL_NONE;   /**< stderr log level */
sr_log_level_t sr_syslog_ll = SR_LL_NONE;   /**< syslog log level */
int syslog_open;                            /**< Whether syslog was opened */
sr_log_cb sr_lcb;                           /**< Logging callback */

/**
 * @brief String error list.
 */
static const char * const sr_errlist[] = {
    "Operation succeeded",                      /* SR_ERR_OK */
    "Invalid argument",                         /* SR_ERR_INVAL_ARG */
    "libyang error",                            /* SR_ERR_LY */
    "System function call failed",              /* SR_ERR_SYS */
    "Out of memory",                            /* SR_ERR_NO_MEM */
    "Item not found",                           /* SR_ERR_NOT_FOUND */
    "Item already exists",                      /* SR_ERR_EXISTS */
    "Internal error",                           /* SR_ERR_INTERNAL */
    "Operation not supported",                  /* SR_ERR_UNSUPPORTED */
    "Validation failed",                        /* SR_ERR_VALIDATION_FAILED */
    "Operation failed",                         /* SR_ERR_OPERATION_FAILED */
    "Operation not authorized",                 /* SR_ERR_UNAUTHORIZED */
    "Requested resource already locked",        /* SR_ERR_LOCKED */
    "Timeout expired",                          /* SR_ERR_TIME_OUT */
    "User callback failed",                     /* SR_ERR_CALLBACK_FAILED */
    "User callback shelved",                    /* SR_ERR_CALLBACK_SHELVE */
};

struct sr_error_info_err2_s {
    sr_error_t err_code;
    char *message;
    char *error_format;
    void *error_data;
};

static struct sr_error_info_err2_s mem_err = {
    .err_code = SR_ERR_NO_MEMORY,
    .message = "Memory allocation failed.",
    .error_format = NULL,
    .error_data = NULL,
};

/**
 * @brief Internal static error structure after a memory allocation error.
 */
static sr_error_info_t sr_errinfo_mem = {
    .err = (void *)&mem_err,
    .err_count = 1
};

int
sr_api_ret(sr_session_ctx_t *session, sr_error_info_t *err_info)
{
    sr_error_t err_code = SR_ERR_OK;

    if (session) {
        /* free any previous errors */
        sr_errinfo_free(&session->err_info);
    }

    if (err_info) {
        err_code = err_info->err[err_info->err_count - 1].err_code;
        if (session) {
            /* store error info in the session */
            session->err_info = err_info;
        } else {
            /* no session, free error info */
            sr_errinfo_free(&err_info);
        }
    }

    return err_code;
}

void
sr_log_msg(int plugin, sr_log_level_t ll, const char *msg)
{
    int priority = 0;
    const char *severity = NULL;

    switch (ll) {
    case SR_LL_ERR:
        priority = LOG_ERR;
        severity = "ERR";
        break;
    case SR_LL_WRN:
        priority = LOG_WARNING;
        severity = "WRN";
        break;
    case SR_LL_INF:
        priority = LOG_INFO;
        severity = "INF";
        break;
    case SR_LL_DBG:
        priority = LOG_DEBUG;
        severity = "DBG";
        break;
    case SR_LL_NONE:
        assert(0);
        return;
    }

    /* stderr logging */
    if (ll <= sr_stderr_ll) {
        fprintf(stderr, "[%s] %s\n", severity, msg);
    }

    /* syslog logging */
    if (ll <= sr_syslog_ll) {
        syslog(priority | (plugin ? LOG_DAEMON : 0), "[%s] %s\n", severity, msg);
    }

    /* logging callback */
    if (sr_lcb) {
        sr_lcb(ll, msg);
    }
}

void
sr_errinfo_add(sr_error_info_t **err_info, sr_error_t err_code, const char *err_format, const void *err_data,
        const char *msg_format, va_list *vargs)
{
    void *mem;
    sr_error_info_err_t *e;

    assert(!err_data || err_format);

    if (!*err_info) {
        *err_info = calloc(1, sizeof **err_info);
        if (!*err_info) {
            *err_info = &sr_errinfo_mem;
            return;
        }
    }

    mem = realloc((*err_info)->err, ((*err_info)->err_count + 1) * sizeof *(*err_info)->err);
    if (!mem) {
        return;
    }
    (*err_info)->err = mem;
    e = &(*err_info)->err[(*err_info)->err_count];

    /* error code */
    e->err_code = err_code;

    /* error message */
    if (vargs) {
        if (vasprintf(&e->message, msg_format, *vargs) == -1) {
            return;
        }
    } else if (msg_format) {
        if (!(e->message = strdup(msg_format))) {
            return;
        }
    } else {
        e->message = NULL;
    }

    /* error format */
    if (err_format) {
        e->error_format = strdup(err_format);
        if (!e->error_format) {
            free(e->message);
            return;
        }
    } else {
        e->error_format = NULL;
    }

    /* error data */
    if (err_data) {
        e->error_data = malloc(sr_ev_data_size(err_data));
        if (!e->error_data) {
            free(e->message);
            free(e->error_format);
            return;
        }
        memcpy(e->error_data, err_data, sr_ev_data_size(err_data));
    } else {
        e->error_data = NULL;
    }

    ++(*err_info)->err_count;
}

void
sr_errinfo_new(sr_error_info_t **err_info, sr_error_t err_code, const char *msg_format, ...)
{
    va_list vargs;
    int idx;

    if ((err_code == SR_ERR_NO_MEMORY) && !msg_format) {
        /* there is no dynamic memory, use the static error structure */
        sr_errinfo_free(err_info);
        *err_info = &sr_errinfo_mem;
    } else if (!msg_format) {
        /* error without a message */
        sr_errinfo_add(err_info, err_code, NULL, NULL, NULL, NULL);
        return;
    } else {
        va_start(vargs, msg_format);
        sr_errinfo_add(err_info, err_code, NULL, NULL, msg_format, &vargs);
        va_end(vargs);
    }

    /* print it */
    idx = (*err_info)->err_count - 1;
    sr_log_msg(0, SR_LL_ERR, (*err_info)->err[idx].message);
}

void
sr_errinfo_new_data(sr_error_info_t **err_info, sr_error_t err_code, const char *err_format, const void *err_data,
        const char *msg_format, ...)
{
    va_list vargs;
    int idx;

    if ((err_code == SR_ERR_NO_MEMORY) && !err_format && !err_data && !msg_format) {
        /* there is no dynamic memory, use the static error structure */
        sr_errinfo_free(err_info);
        *err_info = &sr_errinfo_mem;
    } else {
        va_start(vargs, msg_format);
        sr_errinfo_add(err_info, err_code, err_format, err_data, msg_format, &vargs);
        va_end(vargs);
    }

    /* print it */
    idx = (*err_info)->err_count - 1;
    sr_log_msg(0, SR_LL_ERR, (*err_info)->err[idx].message);
}

void
sr_errinfo_new_ly(sr_error_info_t **err_info, const struct ly_ctx *ly_ctx, const struct lyd_node *data)
{
    struct ly_err_item *e = NULL;
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
        sr_errinfo_new(err_info, SR_ERR_LY, "%s", ly_last_errmsg());
        return;
    }

    do {
        if (e->level == LY_LLWRN) {
            /* just print it */
            sr_log_msg(0, SR_LL_WRN, e->msg);
        } else {
            assert(e->level == LY_LLERR);
            /* store it and print it */
            if (e->path) {
                sr_errinfo_new(err_info, SR_ERR_LY, "%s (%s)", e->msg, e->path);
            } else {
                sr_errinfo_new(err_info, SR_ERR_LY, "%s", e->msg);
            }
        }

        e = e->next;
    } while (e);

    if (ly_ctx) {
        ly_err_clean((struct ly_ctx *)ly_ctx, NULL);
    }
}

void
sr_errinfo_new_ly_first(sr_error_info_t **err_info, const struct ly_ctx *ly_ctx)
{
    struct ly_err_item *e;

    e = ly_err_first(ly_ctx);
    /* this function is called only when an error is expected */
    assert(e);

    if (e->level == LY_LLWRN) {
        /* just print it */
        sr_log_msg(0, SR_LL_WRN, e->msg);
    } else {
        assert(e->level == LY_LLERR);
        /* store it and print it */
        if (e->path) {
            sr_errinfo_new(err_info, SR_ERR_LY, "%s (%s)", e->msg, e->path);
        } else {
            sr_errinfo_new(err_info, SR_ERR_LY, "%s", e->msg);
        }
    }

    ly_err_clean((struct ly_ctx *)ly_ctx, NULL);
}

void
sr_log_wrn_ly(const struct ly_ctx *ly_ctx)
{
    struct ly_err_item *e;

    e = ly_err_first(ly_ctx);
    /* this function is called only when an error is expected */
    assert(e);

    do {
        /* print everything as warnings */
        sr_log_msg(0, SR_LL_WRN, e->msg);

        e = e->next;
    } while (e);

    ly_err_clean((struct ly_ctx *)ly_ctx, NULL);
}

void
sr_errinfo_free(sr_error_info_t **err_info)
{
    size_t i;

    if (err_info && *err_info) {
        /* NO_MEM is always a static error info structure */
        if (((*err_info)->err_count != 1) || ((*err_info)->err[0].err_code != SR_ERR_NO_MEMORY)) {
            for (i = 0; i < (*err_info)->err_count; ++i) {
                free((*err_info)->err[i].message);
                free((*err_info)->err[i].error_format);
                free((*err_info)->err[i].error_data);
            }
            free((*err_info)->err);
            free(*err_info);
        }
        *err_info = NULL;
    }
}

void
sr_errinfo_merge(sr_error_info_t **err_info, sr_error_info_t *err_info2)
{
    size_t i;

    if (!err_info2) {
        return;
    }

    if (!*err_info) {
        *err_info = err_info2;
        return;
    }

    for (i = 0; i < err_info2->err_count; ++i) {
        sr_errinfo_add(err_info, err_info2->err[i].err_code, err_info2->err[i].error_format,
                err_info2->err[i].error_data, err_info2->err[i].message, NULL);

        free(err_info2->err[i].message);
        free(err_info2->err[i].error_format);
        free(err_info2->err[i].error_data);
    }
    free(err_info2->err);
    free(err_info2);
}

void
sr_log(sr_log_level_t ll, const char *format, ...)
{
    va_list ap;
    char *msg;
    int msg_len = 0;

    va_start(ap, format);
    sr_vsprintf(&msg, &msg_len, 0, format, ap);
    va_end(ap);

    sr_log_msg(0, ll, msg);
    free(msg);
}

API void
srplg_log_errinfo(sr_error_info_t **err_info, const char *plg_name, const char *err_format_name, sr_error_t err_code,
        const char *format, ...)
{
    va_list vargs;
    char *msg;
    int idx;

    if (!plg_name) {
        return;
    }

    /* add plugin name first */
    if (asprintf(&msg, "%s: %s", plg_name, format) == -1) {
        *err_info = &sr_errinfo_mem;
    } else {
        /* add err_info */
        va_start(vargs, format);
        sr_errinfo_add(err_info, err_code, err_format_name, NULL, msg, &vargs);
        va_end(vargs);
    }

    /* print it */
    idx = (*err_info)->err_count - 1;
    sr_log_msg(1, SR_LL_ERR, (*err_info)->err[idx].message);
    free(msg);
}

API int
srplg_errinfo_push_error_data(sr_error_info_t *err_info, uint32_t size, const void *data)
{
    sr_error_info_t *einfo = NULL;

    SR_CHECK_ARG_APIRET(!err_info || !err_info->err_count || !err_info->err[err_info->err_count - 1].error_format ||
            !size || !data, NULL, einfo);

    einfo = sr_ev_data_push(&err_info->err[err_info->err_count - 1].error_data, size, data);
    return sr_api_ret(NULL, einfo);
}

API void
srplg_errinfo_free(sr_error_info_t **err_info)
{
    sr_errinfo_free(err_info);
}

API void
srplg_log(const char *plg_name, sr_log_level_t ll, const char *format, ...)
{
    va_list ap;
    char *msg;
    int msg_len = 0, off;

    if (!plg_name) {
        return;
    }

    /* store plugin name first */
    off = msg_len = asprintf(&msg, "%s: ", plg_name);
    ++msg_len;

    va_start(ap, format);
    sr_vsprintf(&msg, &msg_len, off, format, ap);
    va_end(ap);

    sr_log_msg(1, ll, msg);
    free(msg);
}

API const char *
sr_strerror(int err_code)
{
    if ((unsigned)err_code >= (sizeof(sr_errlist) / (sizeof *sr_errlist))) {
        return "Unknown error";
    } else {
        return sr_errlist[err_code];
    }
}

API void
sr_log_stderr(sr_log_level_t log_level)
{
    /* initializes libyang logging for our purposes */
    ly_log_options(LY_LOSTORE);

    sr_stderr_ll = log_level;
}

API sr_log_level_t
sr_log_get_stderr(void)
{
    return sr_stderr_ll;
}

API void
sr_log_syslog(const char *app_name, sr_log_level_t log_level)
{
    /* initializes libyang logging for our purposes */
    ly_log_options(LY_LOSTORE);

    sr_syslog_ll = log_level;

    if ((log_level > SR_LL_NONE) && !syslog_open) {
        openlog(app_name ? app_name : "sysrepo", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_USER);

        syslog_open = 1;
    } else if ((log_level == SR_LL_NONE) && syslog_open) {
        closelog();

        syslog_open = 0;
    }
}

API sr_log_level_t
sr_log_get_syslog(void)
{
    return sr_syslog_ll;
}

API void
sr_log_set_cb(sr_log_cb log_callback)
{
    /* initializes libyang logging for our purposes */
    ly_log_options(LY_LOSTORE);

    sr_lcb = log_callback;
}
