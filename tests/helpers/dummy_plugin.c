/**
 * @file dummy_plugin.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Source code of dummy sysrepo plugin used for unit tests.
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

int
sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
    printf("dummy plugin init");

    return SR_ERR_OK;
}

void
sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
    printf("dummy plugin cleanup");
}

int
sr_plugin_health_check_cb(sr_session_ctx_t *session, void *private_ctx)
{
    printf("dummy plugin health check");

    return SR_ERR_OK;
}
