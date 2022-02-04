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

#include <stdarg.h>
#include "tests/config.h"

/**
 * Only function that needs to be called from test code
 * Initializes callback and facilitates logging to stderr
 * with timestamps and thread-id
 */
void test_log_init();

/* Test Logging macros */
#define TLOG_ERR(...) _test_log(SR_LL_ERR, __VA_ARGS__)
#define TLOG_WRN(...) _test_log(SR_LL_WRN, __VA_ARGS__)
#define TLOG_INF(...) _test_log(SR_LL_INF, __VA_ARGS__)

void _test_log(sr_log_level_t ll, ...);

#endif
