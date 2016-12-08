/**
 * @file plugin_utils.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo helpers for plugin integrations.
 *
 * @copyright
 * Copyright 2016 Cisco Systems, Inc.
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

#ifndef SYSREPO_PLUGINS_H_
#define SYSREPO_PLUGINS_H_

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>

#include <sysrepo.h>

/**
 * @defgroup plugin_utils Plugin Utilities
 * @{
 *
 *  @brief Utilities that expand sysrepo API aimed for sysrepo plugins.
 *
 *  The provided features are: logging macros.
 */

/** Prints an error message (with format specifiers). */
#define SRP_LOG_ERR(MSG, ...) SRP_LOG__INTERNAL(SR_LL_ERR, MSG, __VA_ARGS__)
/** Prints an error message. */
#define SRP_LOG_ERR_MSG(MSG) SRP_LOG__INTERNAL(SR_LL_ERR, MSG "%s", "")

/** Prints a warning message (with format specifiers). */
#define SRP_LOG_WRN(MSG, ...) SRP_LOG__INTERNAL(SR_LL_WRN, MSG, __VA_ARGS__)
/** Prints a warning message. */
#define SRP_LOG_WRN_MSG(MSG) SRP_LOG__INTERNAL(SR_LL_WRN, MSG "%s", "")

/** Prints an informational message (with format specifiers). */
#define SRP_LOG_INF(MSG, ...) SRP_LOG__INTERNAL(SR_LL_INF, MSG, __VA_ARGS__)
/** Prints an informational message. */
#define SRP_LOG_INF_MSG(MSG) SRP_LOG__INTERNAL(SR_LL_INF, MSG "%s", "")

/** Prints a development debug message (with format specifiers). */
#define SRP_LOG_DBG(MSG, ...) SRP_LOG__INTERNAL(SR_LL_DBG, MSG, __VA_ARGS__)
/** Prints a development debug message. */
#define SRP_LOG_DBG_MSG(MSG) SRP_LOG__INTERNAL(SR_LL_DBG, MSG "%s", "")

/**@} plugin_utils */


////////////////////////////////////////////////////////////////////////////////
// Internal macros (not intended to be used directly)
////////////////////////////////////////////////////////////////////////////////

#ifdef NDEBUG
    #define SRP_LOG_PRINT_FUNCTION_NAMES (0)
#else
    #define SRP_LOG_PRINT_FUNCTION_NAMES (1)
#endif

extern volatile uint8_t sr_ll_stderr;       /**< Holds current level of stderr debugs. */
extern volatile uint8_t sr_ll_syslog;       /**< Holds current level of syslog debugs. */

#define SRP_LOG__LL_STR(LL) \
    ((SR_LL_DBG == LL) ? "DBG" : \
     (SR_LL_INF == LL) ? "INF" : \
     (SR_LL_WRN == LL) ? "WRN" : \
     "ERR")

#define SRP_LOG__LL_FACILITY(LL) \
    ((SR_LL_DBG == LL) ? LOG_DEBUG : \
     (SR_LL_INF == LL) ? LOG_INFO : \
     (SR_LL_WRN == LL) ? LOG_WARNING : \
      LOG_ERR)

#if SRP_LOG_PRINT_FUNCTION_NAMES
#define SRP_LOG__SYSLOG(LL, MSG, ...) \
        syslog(SRP_LOG__LL_FACILITY(LL), "[%s] (%s:%d) " MSG, SRP_LOG__LL_STR(LL), __func__, __LINE__, __VA_ARGS__);
#define SRP_LOG__STDERR(LL, MSG, ...) \
        fprintf(stderr, "[%s] (%s:%d) " MSG "\n", SRP_LOG__LL_STR(LL), __func__, __LINE__, __VA_ARGS__);
#else
#define SRP_LOG__SYSLOG(LL, MSG, ...) \
        syslog(SRP_LOG__LL_FACILITY(LL), "[%s] " MSG, SRP_LOG__LL_STR(LL), __VA_ARGS__);
#define SRP_LOG__STDERR(LL, MSG, ...) \
        fprintf(stderr, "[%s] " MSG "\n", SRP_LOG__LL_STR(LL), __VA_ARGS__);
#endif

#define SRP_LOG__INTERNAL(LL, MSG, ...) \
    do { \
        if (sr_ll_stderr >= LL) \
            SRP_LOG__STDERR(LL, MSG, __VA_ARGS__) \
        if (sr_ll_syslog >= LL) \
            SRP_LOG__SYSLOG(LL, MSG, __VA_ARGS__) \
    } while(0)

#endif /* SYSREPO_PLUGINS_H_ */
