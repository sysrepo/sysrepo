/**
 * @file test_common.h
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

#ifndef SR_TEST_COMMON_H
#define SR_TEST_COMMON_H

#include <pthread.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include "sysrepo.h"
#include "tests/config.h"

/**
 * Only function that needs to be called from test code
 * Initializes callback and facilitates logging to stderr
 * with timestamps and thread-id
 */
static void test_log_init();

#define LOG_INF(...) _test_log(SR_LL_INF, __VA_ARGS__)
#define LOG_ERR(...) _test_log(SR_LL_ERR, __VA_ARGS__)
#define LOG_WRN(...) _test_log(SR_LL_WRN, __VA_ARGS__)

static void
_test_log_cb(sr_log_level_t level, const char *message);

static void _test_log(sr_log_level_t ll, ...);

static void test_log_init()
{
    sr_log_set_cb(_test_log_cb);
    LOG_INF("Initialized sysrepo logging for tests");
}

static void
_test_log_cb(sr_log_level_t level, const char *message)
{
    const char *severity;

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
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    ts.tv_sec %= 1000;
    ts.tv_nsec /= 1000;
    fprintf(stderr, "%03ld.%06ld [%ld][%lu][%s]: %s\n", ts.tv_sec, ts.tv_nsec,
                    (long)getpid(), (unsigned long)pthread_self(), severity, message);
}

static void
_test_log(sr_log_level_t ll, ...)
{
    va_list ap;
    char msg[1024];

    va_start(ap, ll);
    char *fmt = va_arg(ap, char *);

    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    _test_log_cb(ll, msg);
}

#endif

