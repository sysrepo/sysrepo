/**
 * @file request_processor.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Implementation of Sysrepo's Request Processor.
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

#include "sr_common.h"
#include "connection_manager.h"

/**
 * @brief Structure that holds the context of an instance of Request Processor.
 */
typedef struct rp_ctx_s {
    cm_ctx_t *cm_ctx;
} rp_ctx_t;

/**
 * @brief Structure that holds Request Processor's per-session context.
 */
typedef struct rp_session_s {
    uint32_t session_id;
    const char *real_user;
    const char *effective_user;
    sr_datastore_t datastore;
} rp_session_t;

int
rp_init(cm_ctx_t *cm_ctx, rp_ctx_t **rp_ctx_p)
{
    rp_ctx_t *ctx = NULL;

    CHECK_NULL_ARG(rp_ctx_p);

    ctx = calloc(1, sizeof(*ctx));
    if (NULL == ctx) {
        SR_LOG_ERR_MSG("Cannot allocate memory for Request Processor context.");
        return SR_ERR_NOMEM;
    }

    ctx->cm_ctx = cm_ctx;
    *rp_ctx_p = ctx;

    return SR_ERR_OK;
}

void
rp_cleanup(rp_ctx_t *rp_ctx)
{
    if (NULL != rp_ctx) {
        free(rp_ctx);
    }
}

int
rp_session_start(const rp_ctx_t *rp_ctx, const char *real_user, const char *effective_user,
        const uint32_t session_id, const sr_datastore_t datastore, rp_session_t **session_p)
{
    rp_session_t *session = NULL;

    CHECK_NULL_ARG2(rp_ctx, session_p);

    session = calloc(1, sizeof(*session));
    if (NULL == session) {
        SR_LOG_ERR_MSG("Cannot allocate memory for RP session context.");
        return SR_ERR_NOMEM;
    }

    session->real_user = real_user;
    session->effective_user = effective_user;
    session->session_id = session_id;
    session->datastore = datastore;

    *session_p = session;

    return SR_ERR_OK;
}

int
rp_session_stop(const rp_ctx_t *rp_ctx, rp_session_t *session)
{
    CHECK_NULL_ARG2(rp_ctx, session);

    free(session);

    return SR_ERR_OK;
}

int
rp_msg_process(const rp_ctx_t *rp_ctx, const rp_session_t *session, Sr__Msg *msg)
{
    CHECK_NULL_ARG3(rp_ctx, session, msg);

    // TODO: dispatch the message

    // TODO: for now, just send "some" response
    Sr__Msg *resp = NULL;
    sr_pb_resp_alloc(SR__OPERATION__GET_ITEM, session->session_id, &resp);
    cm_msg_send(rp_ctx->cm_ctx, resp);

    sr__msg__free_unpacked(msg, NULL);

    return SR_ERR_OK;
}
