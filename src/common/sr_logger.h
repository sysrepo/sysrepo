/**
 * @file sr_logger.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo logging API.
 *
 * @copyright
 * Copyright 2015 Cisco Systems, Inc.
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

#ifndef SR_LOGGER_H_
#define SR_LOGGER_H_

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>

/**
 * @defgroup logger Sysrepo Logger
 * @ingroup common
 * @{
 *
 * @brief Logger module allows logging of messages with various severities into
 * stderr, syslog, or into specified function callback.
 *
 * By default, no logging is enabled. You can selectively enable the logging
 * to stderr (::sr_log_stderr) or into syslog (::sr_log_syslog) with specified
 * verbosity level, or setup a callback that will be called for each log entry
 * that would be populated (or combine all three options).
 *
 * Please note that enabling logging into syslog will overwrite your syslog
 * connection settings (calls openlog), if you are connected to syslog already.
 *
 * Since syslog does not allow opening more connections to system logger per
 * application, this module is global for the application (call ::sr_logger_init
 * and ::sr_logger_cleanup only once in the lifetime of the application.
 *
 * Logs in syslog will be identified as application "sysrepo" in case that
 * provided app_name argument of ::sr_logger_init will be NULL, or as
 * "sysrepo-app_name" if some string will be provided (see ::sr_logger_init).
 * Logs of sysrepo daemon will be identified as "sysrepod".
 */

#define SR_LOGGING_ENABLED (1)  /**< Controls whether logging is enabled. */

/**
 * Controls whether function names should be printed.
 */
#ifdef NDEBUG
    #define SR_LOG_PRINT_FUNCTION_NAMES (0)
#else
    #define SR_LOG_PRINT_FUNCTION_NAMES (1)
#endif

extern volatile uint8_t sr_ll_stderr;       /**< Holds current level of stderr debugs. */
extern volatile uint8_t sr_ll_syslog;       /**< Holds current level of syslog debugs. */
extern volatile sr_log_cb sr_log_callback;  /**< Holds pointer to logging callback, if set. */

#define SR_LOG__LL_STR(LL) \
    ((SR_LL_DBG == LL) ? "DBG" : \
     (SR_LL_INF == LL) ? "INF" : \
     (SR_LL_WRN == LL) ? "WRN" : \
     "ERR")

#define SR_LOG__LL_FACILITY(LL) \
    ((SR_LL_DBG == LL) ? LOG_DEBUG : \
     (SR_LL_INF == LL) ? LOG_INFO : \
     (SR_LL_WRN == LL) ? LOG_WARNING : \
      LOG_ERR)

#if SR_LOG_PRINT_FUNCTION_NAMES
#define SR_LOG__SYSLOG(LL, MSG, ...) \
        syslog(SR_LOG__LL_FACILITY(LL), "[%s] (%s:%d) " MSG, SR_LOG__LL_STR(LL), __FUNCTION__, __LINE__, __VA_ARGS__);
#define SR_LOG__STDERR(LL, MSG, ...) \
        fprintf(stderr, "[%s] (%s:%d) " MSG "\n", SR_LOG__LL_STR(LL), __FUNCTION__, __LINE__, __VA_ARGS__);
#define SR_LOG__CALLBACK(LL, MSG, ...) \
        sr_log_to_cb(LL, "(%s:%d) " MSG, __FUNCTION__, __LINE__, __VA_ARGS__);
#else
#define SR_LOG__SYSLOG(LL, MSG, ...) \
        syslog(SR_LOG__LL_FACILITY(LL), "[%s] " MSG, SR_LOG__LL_STR(LL), __VA_ARGS__);
#define SR_LOG__STDERR(LL, MSG, ...) \
        fprintf(stderr, "[%s] " MSG "\n", SR_LOG__LL_STR(LL), __VA_ARGS__);
#define SR_LOG__CALLBACK(LL, MSG, ...) \
        sr_log_to_cb(LL, MSG, __VA_ARGS__);
#endif

#define SR_LOG__INTERNAL(LL, MSG, ...) \
    do { \
        if (sr_ll_stderr >= LL) \
            SR_LOG__STDERR(LL, MSG, __VA_ARGS__) \
        if (sr_ll_syslog >= LL) \
            SR_LOG__SYSLOG(LL, MSG, __VA_ARGS__) \
        if (NULL != sr_log_callback) \
            SR_LOG__CALLBACK(LL, MSG, __VA_ARGS__) \
    } while(0)

#if SR_LOGGING_ENABLED

/** Prints an error message (with format specifiers). */
#define SR_LOG_ERR(MSG, ...) SR_LOG__INTERNAL(SR_LL_ERR, MSG, __VA_ARGS__)
/** Prints an error message. */
#define SR_LOG_ERR_MSG(MSG) SR_LOG__INTERNAL(SR_LL_ERR, MSG "%s", "")

/** Prints a warning message (with format specifiers). */
#define SR_LOG_WRN(MSG, ...) SR_LOG__INTERNAL(SR_LL_WRN, MSG, __VA_ARGS__)
/** Prints a warning message. */
#define SR_LOG_WRN_MSG(MSG) SR_LOG__INTERNAL(SR_LL_WRN, MSG "%s", "")

/** Prints an informational message (with format specifiers). */
#define SR_LOG_INF(MSG, ...) SR_LOG__INTERNAL(SR_LL_INF, MSG, __VA_ARGS__)
/** Prints an informational message. */
#define SR_LOG_INF_MSG(MSG) SR_LOG__INTERNAL(SR_LL_INF, MSG "%s", "")

/** Prints a development debug message (with format specifiers). */
#define SR_LOG_DBG(MSG, ...) SR_LOG__INTERNAL(SR_LL_DBG, MSG, __VA_ARGS__)
/** Prints a development debug message. */
#define SR_LOG_DBG_MSG(MSG) SR_LOG__INTERNAL(SR_LL_DBG, MSG "%s", "")

#else
#define SR_LOG_ERR(...)
#define SR_LOG_ERR_MSG(...)
#define SR_LOG_WRN(...)
#define SR_LOG_WRN_MSG(...)
#define SR_LOG_INF(...)
#define SR_LOG_INF_MSG(...)
#define SR_LOG_DBG(...)
#define SR_LOG_DBG_MSG(...)
#endif

/**
 * @brief Initializes Sysrepo logging subsystem.
 *
 * @note Needs to be called only once per the application life-time.
 *
 * @param[in] app_name Name of the application using Sysrepo, used to identify
 * the logs in syslog. Prefix "sysrepo-" will be prepended to the application name.
 * Can be NULL, in that case, logs will be identified as "sysrepo". The string
 * will be duped and automatically released upon ::sr_logger_cleanup call.
 */
void sr_logger_init(const char *app_name);

/**
 * @brief Cleans up Sysrepo logging subsystem.
 *
 * @note Needs to be called only once per the application life-time.
 */
void sr_logger_cleanup();

/**
 * @brief Logs into callback pre-specified by ::sr_log_set_cb.
 * Used internally by logging macros.
 *
 * @param[in] level Log level.
 * @param[in] format Format message.
 */
void sr_log_to_cb(sr_log_level_t level, const char *format, ...);

/**@} logger */

#endif /* SR_LOGGER_H_ */
