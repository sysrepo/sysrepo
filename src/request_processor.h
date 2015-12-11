/**
 * @file request_processor.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief API of Sysrepo's Request Processor.
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

#ifndef REQUEST_PROCESSOR_H_
#define REQUEST_PROCESSOR_H_

#include "sysrepo.pb-c.h"

/**
 * @brief Structure that holds the context of an instance of Request Processor.
 */
typedef struct rp_ctx_s rp_ctx_t;

/**
 * @brief Structure that holds Request Processor's per-session context.
 */
typedef struct rp_session_s rp_session_t;

int rp_init(rp_ctx_t **rp_ctx);

int rp_cleanup(rp_ctx_t *rp_ctx);

int rp_session_start(const rp_ctx_t *rp_ctx, const char *user_name, const void *cm_session_ctx, rp_session_t **rp_session_ctx);

int rp_session_stop(const rp_ctx_t *rp_ctx, rp_session_t *rp_session_ctx);

int rp_msg_process(const rp_ctx_t *rp_ctx, const rp_session_t *rp_session_ctx, Sr__Msg *msg);

#endif /* REQUEST_PROCESSOR_H_ */
