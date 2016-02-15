/**
 * @file sr_logger.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo logging engine.
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>

#include "sr_common.h"
#include "sr_logger.h"

volatile uint8_t sr_ll_stderr = SR_LOG_STDERR_DEFAULT_LL;  /**< Global variable used to store log level of stderr messages. */
volatile uint8_t sr_ll_syslog = SR_LOG_SYSLOG_DEFAULT_LL;  /**< Global variable used to store log level of syslog messages. */

#define SR_DEFAULT_LOG_IDENTIFIER "sysrepo"  /**< Default identifier used in syslog messages. */
#define SR_DAEMON_LOG_IDENTIFIER "sysrepod"  /**< Sysrepo deamon identifier used in syslog messages. */

char *syslog_identifier = NULL; /**< Global variable used to store syslog identifier. */

void
sr_logger_init(const char *app_name)
{
#if SR_LOGGING_ENABLED
    char *identifier = NULL;
    size_t buff_size = 0;

    if ((NULL != app_name) && (0 != strcmp(SR_DEFAULT_LOG_IDENTIFIER, app_name)) &&
            (0 != strcmp(SR_DAEMON_LOG_IDENTIFIER, app_name))) {
        buff_size = snprintf(NULL, 0, "%s-%s", SR_DEFAULT_LOG_IDENTIFIER, app_name);
        syslog_identifier = malloc(buff_size + 1);
        if (NULL != syslog_identifier) {
            sprintf(syslog_identifier, "%s-%s", SR_DEFAULT_LOG_IDENTIFIER, app_name);
            identifier = syslog_identifier;
        }
    }
    if (NULL == identifier) {
        if ((NULL == app_name) || (0 != strcmp(SR_DAEMON_LOG_IDENTIFIER, app_name))) {
            identifier = SR_DEFAULT_LOG_IDENTIFIER;
        } else {
            identifier = SR_DAEMON_LOG_IDENTIFIER;
        }
    }

    openlog(identifier, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_DAEMON);
#endif
}

void
sr_logger_cleanup()
{
#if SR_LOGGING_ENABLED
    fflush(stderr);
    closelog();
    free(syslog_identifier);
#endif
}

void
sr_set_log_level(sr_log_level_t ll_stderr, sr_log_level_t ll_syslog)
{
    sr_ll_stderr = ll_stderr;
    sr_ll_syslog = ll_syslog;
}
