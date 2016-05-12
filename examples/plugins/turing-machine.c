/**
 * @file turing-machine.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Example plugin for sysrepo datastore - turing machine.
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

#include <stdio.h>
#include <syslog.h>
#include "sysrepo.h"

/* logging macro for unformatted messages */
#define log_msg(MSG) \
    do { \
        fprintf(stderr, MSG "\n"); \
        syslog(LOG_INFO, MSG); \
    } while(0)

/* logging macro for formatted messages */
#define log_fmt(MSG, ...) \
    do { \
        fprintf(stderr, MSG "\n", __VA_ARGS__); \
        syslog(LOG_INFO, MSG, __VA_ARGS__); \
    } while(0)

static void
module_change_cb(sr_session_ctx_t *session, const char *module_name, void *private_ctx)
{
    log_msg("turing-machine configuration has changed");
}

int
sr_plugin_init(sr_session_ctx_t *session, void **private_ctx)
{
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;

    rc = sr_module_change_subscribe(session, "turing-machine", true, module_change_cb, NULL, &subscription);
    *private_ctx = subscription;

    log_msg("turing-machine plugin initialized");

    return rc;
}

void
sr_plugin_cleanup(sr_session_ctx_t *session, void *private_ctx)
{
    sr_unsubscribe(private_ctx);

    log_msg("turing-machine plugin cleanup finished");
}
