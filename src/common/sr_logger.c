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
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <pthread.h>

#include "sr_common.h"
#include "sr_logger.h"

#define SR_LOG_MSG_SIZE 2048  /**< Maximum size of one log entry. */

#define SR_DEFAULT_LOG_IDENTIFIER "sysrepo"  /**< Default identifier used in syslog messages. */
#define SR_DAEMON_LOG_IDENTIFIER "sysrepod"  /**< Sysrepo deamon identifier used in syslog messages. */

volatile uint8_t sr_ll_stderr = SR_LL_NONE;  /**< Global variable used to store log level of stderr messages. */
volatile uint8_t sr_ll_syslog = SR_LL_NONE;  /**< Global variable used to store log level of syslog messages. */
volatile sr_log_cb sr_log_callback = NULL;   /**< Global variable used to store logging callback, if set. */

static volatile bool sr_syslog_enabled = false;     /**< Global variable used to mark if the syslog initialization (openlog) has been done. */
static volatile char *sr_syslog_identifier = NULL;  /**< Global variable used to store syslog identifier. */

static pthread_once_t sr_logger_once = PTHREAD_ONCE_INIT;
static pthread_key_t sr_logger_key;

static void
sr_logger_createkey(void)
{
#if SR_LOGGING_ENABLED
    while (pthread_key_create(&sr_logger_key, free) == EAGAIN);
    pthread_setspecific(sr_logger_key, NULL);
#endif
}

void
sr_logger_init(const char *app_name)
{
#if SR_LOGGING_ENABLED
    size_t buff_size = 0;
    if (NULL != sr_syslog_identifier) {
        free((char*)sr_syslog_identifier);
        sr_syslog_identifier = NULL;
    }
    if ((NULL != app_name) && (0 != strcmp(SR_DEFAULT_LOG_IDENTIFIER, app_name)) &&
            (0 != strcmp(SR_DAEMON_LOG_IDENTIFIER, app_name))) {
        buff_size = snprintf(NULL, 0, "%s-%s", SR_DEFAULT_LOG_IDENTIFIER, app_name);
        sr_syslog_identifier = malloc(buff_size + 1);
        if (NULL != sr_syslog_identifier) {
            sprintf((char*)sr_syslog_identifier, "%s-%s", SR_DEFAULT_LOG_IDENTIFIER, app_name);
        }
    }
    if (NULL == sr_syslog_identifier) {
        if ((NULL == app_name) || (0 != strcmp(SR_DAEMON_LOG_IDENTIFIER, app_name))) {
            sr_syslog_identifier = strdup(SR_DEFAULT_LOG_IDENTIFIER);
        } else {
            sr_syslog_identifier = strdup(SR_DAEMON_LOG_IDENTIFIER);
        }
    }
#endif
}

void
sr_logger_cleanup()
{
#if SR_LOGGING_ENABLED
    fflush(stderr);
    if (sr_syslog_enabled) {
        closelog();
        sr_syslog_enabled = false;
    }
    free((char*)sr_syslog_identifier);
    sr_syslog_identifier = NULL;

    pthread_once(&sr_logger_once, sr_logger_createkey);
    char *msg_buff = pthread_getspecific(sr_logger_key);
    if (NULL != msg_buff) {
        free(msg_buff);
        pthread_setspecific(sr_logger_key, NULL);
    }
#endif
}

void
sr_log_set_level(sr_log_level_t ll_stderr, sr_log_level_t ll_syslog)
{
#if SR_LOGGING_ENABLED
    sr_ll_stderr = ll_stderr;
    sr_ll_syslog = ll_syslog;

    SR_LOG_DBG("Setting log level of stderr logs to %d, syslog logs to %d.", ll_stderr, ll_syslog);

    if ((SR_LL_NONE != ll_syslog) && !sr_syslog_enabled) {
        if (NULL == sr_syslog_identifier) {
            sr_logger_init(NULL);
        }
        openlog((char*)sr_syslog_identifier, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_DAEMON);
        sr_syslog_enabled = true;
        SR_LOG_DBG_MSG("Opening the connection to system logger (syslog).");
    }
#endif
}

void
sr_log_set_cb(sr_log_cb log_callback)
{
#if SR_LOGGING_ENABLED
    sr_log_callback = log_callback;
#endif
}

void
sr_log_to_cb(sr_log_level_t level, const char *format, ...)
{
#if SR_LOGGING_ENABLED
    char *msg_buff = NULL;
    va_list arg_list;

    if (NULL != sr_log_callback) {
        pthread_once(&sr_logger_once, sr_logger_createkey);
        msg_buff = pthread_getspecific(sr_logger_key);
        if (NULL == msg_buff) {
            msg_buff = calloc(SR_LOG_MSG_SIZE, sizeof(char*));
            pthread_setspecific(sr_logger_key, msg_buff);
        }
        if (NULL != msg_buff) {
            va_start(arg_list, format);
            vsnprintf(msg_buff, SR_LOG_MSG_SIZE - 1, format, arg_list);
            va_end(arg_list);
            msg_buff[SR_LOG_MSG_SIZE - 1] = '\0';
            sr_log_callback(level, msg_buff);
        }
    }
#endif
}
