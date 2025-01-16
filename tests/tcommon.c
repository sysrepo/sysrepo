/**
 * @file tcommon.c
 * @author Irfan
 * @brief common header file for all tests to facilitate uniform logging format
 *
 * @copyright
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#define _GNU_SOURCE

#include <assert.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#include "sysrepo.h"
#include "tests/tcommon.h"

static void
_test_log_msg(sr_log_level_t level, const char *message, const char *prefix)
{
    const char *severity = NULL;
    struct timespec ts;

    switch (level) {
    case SR_LL_ERR:
        severity = "ERR";
        break;
    case SR_LL_WRN:
        severity = "WRN";
        break;
    case SR_LL_INF:
        severity = "INF";
        break;
    case SR_LL_DBG:
        /*severity = "DBG";
        break;*/
        return;
    case SR_LL_NONE:
        assert(0);
        return;
    }

    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec %= 1000;
    ts.tv_nsec /= 1000;
    fprintf(stderr, "%03ld.%06ld [%ld][%lu][%s]%s: %s\n", ts.tv_sec, ts.tv_nsec,
            (long)getpid(), (unsigned long)pthread_self(), severity,
            prefix, message);
}

static void
_test_sr_log_cb(sr_log_level_t level, const char *message)
{
    _test_log_msg(level, message, "");
}

void
test_log_init(void)
{
    sr_log_set_cb(_test_sr_log_cb);
}

void
_test_log(sr_log_level_t ll, ...)
{
    va_list ap;
    char msg[1024] = "";
    char *fmt = NULL;

    va_start(ap, ll);
    fmt = va_arg(ap, char *);

    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    _test_log_msg(ll, msg, "[TestLog]");
}
