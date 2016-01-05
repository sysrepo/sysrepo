/**
 * @file sr_client.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo client library (public API) implementation.
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

#include "sr_common.h"

/* Sysrepo context */
typedef struct sr_conn_ctx_s {
    char *path_to_conf;
} sr_conn_ctx_t;

/* session context */
typedef struct sr_session_ctx_s {
    uint32_t session_id;
} sr_session_ctx_t;

int
sr_connect(const bool allow_library_mode, sr_conn_ctx_t **conn_ctx)
{
    return 0;
}
