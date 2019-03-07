/**
 * @file log.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief logging routines
 *
 * @copyright
 * Copyright (c) 2019 CESNET, z.s.p.o.
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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <syslog.h>

sr_log_level_t stderr_ll = SR_LL_NONE;
sr_log_level_t syslog_ll = SR_LL_NONE;
int syslog_open;
sr_log_cb log_cb;

static const char *const sr_errlist[] = {
        "Operation succeeded",                  /* SR_ERR_OK */
        "Invalid argument",                     /* SR_ERR_INVAL_ARG */
        "libyang error",                        /* SR_ERR_LY */
        "System function call failed",          /* SR_ERR_SYS */
        "Out of memory",                        /* SR_ERR_NOMEM */
        "Item not found",                       /* SR_ERR_NOT_FOUND */
        "Item already exists",                  /* SR_ERR_EXISTS */
        "Internal error",                       /* SR_ERR_INTERNAL */
        "Initialization failed",                /* SR_ERR_INIT_FAILED */
        "The peer disconnected",                /* SR_ERR_DISCONNECT */
        "Malformed message",                    /* SR_ERR_MALFORMED_MSG */
        "Operation not supported",              /* SR_ERR_UNSUPPORTED */
        "Unknown schema model",                 /* SR_ERR_UNKNOWN_MODEL */
        "Unknown element",                      /* SR_ERR_BAD_ELEMENT */
        "Validation failed",                    /* SR_ERR_VALIDATION_FAILED */
        "Operation failed",                     /* SR_ERR_OPERATION_FAILED */
        "Operation not authorized",             /* SR_ERR_UNAUTHORIZED */
        "Invalid username",                     /* SR_ERR_INVAL_USER */
        "Requested resource already locked",    /* SR_ERR_LOCKED */
        "Timeout expired",                      /* SR_ERR_TIME_OUT */
        "User callback failed",                 /* SR_ERR_CALLBACK_FAILED */
};

struct sr_error_info_err_s {
    const char *message;
    const char *xpath;
};

static struct sr_error_info_err_s mem_err = {
    .message = "Memory allocation failed.",
    .xpath = NULL
};

static sr_error_info_t sr_errinfo_mem = {
    .err_code = SR_ERR_NOMEM,
    .err = (void *)&mem_err,
    .err_count = 1
};

sr_error_t
sr_api_ret(sr_session_ctx_t *session, sr_error_info_t *err_info)
{
    sr_error_t err_code = SR_ERR_OK;

    if (session) {
        /* free any previous errors */
        sr_errinfo_free(&session->err_info);
    }

    if (err_info) {
        err_code = err_info->err_code;
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
sr_log_msg(sr_log_level_t ll, const char *msg, const char *path)
{
    int facility;
    const char *severity;

    switch (ll) {
    case SR_LL_ERR:
        facility = LOG_ERR;
        severity = "ERR";
        break;
    case SR_LL_WRN:
        facility = LOG_WARNING;
        severity = "WRN";
        break;
    case SR_LL_INF:
        facility = LOG_INFO;
        severity = "INF";
        break;
    case SR_LL_DBG:
        facility = LOG_DEBUG;
        severity = "DBG";
        break;
    case SR_LL_NONE:
        assert(0);
        return;
    }

    /* stderr logging */
    if (ll <= stderr_ll) {
        if (path) {
            fprintf(stderr, "[%s]: %s (path: %s)\n", severity, msg, path);
        } else {
            fprintf(stderr, "[%s]: %s\n", severity, msg);
        }
    }

    /* syslog logging */
    if (ll < syslog_ll) {
        syslog(facility, "[%s] %s\n", severity, msg);
    }

    /* logging callback */
    if (log_cb) {
        log_cb(ll, msg);
    }
}

void
sr_errinfo_new(sr_error_info_t **err_info, sr_error_t err_code, const char *xpath, const char *format, ...)
{
    void *mem;
    va_list vargs;
    int ret, idx;

    /* special case, when we have no memory, we would try to allocate rror info in vain */
    if (err_code == SR_ERR_NOMEM) {
        /* check that both private and public structures are the same (could be compile-time) */
        assert(sizeof(struct sr_error_info_err_s) == sizeof *(*err_info)->err);
        assert(!xpath && !format);

        sr_errinfo_free(err_info);
        *err_info = &sr_errinfo_mem;
        goto print;
    }

    if (!*err_info) {
        *err_info = calloc(1, sizeof **err_info);
        if (!*err_info) {
            *err_info = &sr_errinfo_mem;
            return;
        }
    }

    (*err_info)->err_code = err_code;

    mem = realloc((*err_info)->err, ((*err_info)->err_count + 1) * sizeof *(*err_info)->err);
    if (!mem) {
        return;
    }
    (*err_info)->err = mem;

    va_start(vargs, format);
    ret = vasprintf(&(*err_info)->err[(*err_info)->err_count].message, format, vargs);
    va_end(vargs);
    if (ret == -1) {
        return;
    }

    if (xpath) {
        (*err_info)->err[(*err_info)->err_count].xpath = strdup(xpath);
        if (!(*err_info)->err[(*err_info)->err_count].xpath) {
            free((*err_info)->err[(*err_info)->err_count].message);
            return;
        }
    } else {
        (*err_info)->err[(*err_info)->err_count].xpath = NULL;
    }

    ++(*err_info)->err_count;

    /* print it */
print:
    idx = (*err_info)->err_count - 1;
    sr_log_msg(SR_LL_ERR, (*err_info)->err[idx].message, (*err_info)->err[idx].xpath);
}

void
sr_errinfo_new_ly(sr_error_info_t **err_info, struct ly_ctx *ly_ctx)
{
    struct ly_err_item *e;

    e = ly_err_first(ly_ctx);
    /* this function is called only when an error is expected */
    assert(e);

    do {
        if (e->level == LY_LLWRN) {
            /* just print it */
            sr_log_msg(SR_LL_WRN, e->msg, e->path);
        } else {
            assert(e->level == LY_LLERR);
            /* store it and print it */
            sr_errinfo_new(err_info, SR_ERR_LY, e->path, e->msg);
        }

        e = e->next;
    } while (e);

    ly_err_clean(ly_ctx, NULL);
}

void
sr_errinfo_new_ly_first(sr_error_info_t **err_info, struct ly_ctx *ly_ctx)
{
    struct ly_err_item *e;

    e = ly_err_first(ly_ctx);
    /* this function is called only when an error is expected */
    assert(e);

    if (e->level == LY_LLWRN) {
        /* just print it */
        sr_log_msg(SR_LL_WRN, e->msg, e->path);
    } else {
        assert(e->level == LY_LLERR);
        /* store it and print it */
        sr_errinfo_new(err_info, SR_ERR_LY, e->path, e->msg);
    }

    ly_err_clean(ly_ctx, NULL);
}

void
sr_log_wrn_ly(struct ly_ctx *ly_ctx)
{
    struct ly_err_item *e;

    e = ly_err_first(ly_ctx);
    /* this function is called only when an error is expected */
    assert(e);

    do {
        /* print everything as warnings */
        sr_log_msg(SR_LL_WRN, e->msg, e->path);

        e = e->next;
    } while (e);

    ly_err_clean(ly_ctx, NULL);
}

void
sr_errinfo_free(sr_error_info_t **err_info)
{
    size_t i;

    if (err_info && *err_info) {
        /* NOMEM is always a static error info structure */
        if ((*err_info)->err_code != SR_ERR_NOMEM) {
            for (i = 0; i < (*err_info)->err_count; ++i) {
                free((*err_info)->err[i].message);
                free((*err_info)->err[i].xpath);
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
        sr_errinfo_new(err_info, err_info2->err_code, err_info2->err[i].xpath, err_info2->err[i].message);

        free(err_info2->err[i].xpath);
        free(err_info2->err[i].message);
    }
    free(err_info2->err);
    free(err_info2);
}

void
sr_log(sr_log_level_t ll, const char *format, ...)
{
    va_list ap;
    char msg[2048];

    va_start(ap, format);
    if (vsnprintf(msg, 2048, format, ap) == -1) {
        va_end(ap);
        return;
    }
    va_end(ap);

    sr_log_msg(ll, msg, NULL);
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
    /* initializes libyang logging for our purpose */
    ly_log_options(LY_LOSTORE);

    stderr_ll = log_level;
}

API void
sr_log_syslog(sr_log_level_t log_level)
{
    /* initializes libyang logging for our purpose */
    ly_log_options(LY_LOSTORE);

    syslog_ll = log_level;

    if ((log_level > SR_LL_NONE) && !syslog_open) {
        openlog("sysrepo", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_DAEMON);

        syslog_open = 1;
    } else if ((log_level == SR_LL_NONE) && syslog_open) {
        closelog();

        syslog_open = 0;
    }
}

API void
sr_log_set_cb(sr_log_cb log_callback)
{
    log_cb = log_callback;
}
