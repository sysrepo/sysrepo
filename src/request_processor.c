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

#include <inttypes.h>

#include "sr_common.h"
#include "connection_manager.h"

/**
 * @brief Structure that holds the context of an instance of Request Processor.
 */
typedef struct rp_ctx_s {
    cm_ctx_t *cm_ctx;  /**< Connection Manager context. */
} rp_ctx_t;

/**
 * @brief Structure that holds Request Processor's per-session context.
 */
typedef struct rp_session_s {
    uint32_t id;                 /**< Assigned session id. */
    const char *real_user;       /**< Real user name of the client. */
    const char *effective_user;  /**< Effective user name of the client (if different to real_user). */
    sr_datastore_t datastore;    /**< Datastore selected for this session. */
} rp_session_t;

/**
 * Processes a get_item request.
 */
static int
rp_get_item_req_process(const rp_ctx_t *rp_ctx, const rp_session_t *session, Sr__Msg *msg)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->get_item_req);

    // TODO: implementation - for now, just send an empty response
    Sr__Msg *resp = NULL;
    rc = sr_pb_resp_alloc(SR__OPERATION__GET_ITEM, session->id, &resp);
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    return rc;
}

/**
 * Processes a get_items request.
 */
static int
rp_get_items_req_process(const rp_ctx_t *rp_ctx, const rp_session_t *session, Sr__Msg *msg)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->get_items_req);

    // TODO: implementation - for now, just send an empty response
    Sr__Msg *resp = NULL;
    rc = sr_pb_resp_alloc(SR__OPERATION__GET_ITEMS, session->id, &resp);
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    return rc;
}

int
rp_init(cm_ctx_t *cm_ctx, rp_ctx_t **rp_ctx_p)
{
    rp_ctx_t *ctx = NULL;

    CHECK_NULL_ARG(rp_ctx_p);

    SR_LOG_DBG_MSG("Request Processor init started.");

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
    SR_LOG_DBG_MSG("Request Processor cleanup.");

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

    SR_LOG_DBG("RP session start, session id=%"PRIu32".", session_id);

    session = calloc(1, sizeof(*session));
    if (NULL == session) {
        SR_LOG_ERR_MSG("Cannot allocate memory for RP session context.");
        return SR_ERR_NOMEM;
    }

    session->real_user = real_user;
    session->effective_user = effective_user;
    session->id = session_id;
    session->datastore = datastore;

    *session_p = session;

    return SR_ERR_OK;
}

int
rp_session_stop(const rp_ctx_t *rp_ctx, rp_session_t *session)
{
    CHECK_NULL_ARG2(rp_ctx, session);

    SR_LOG_DBG("RP session stop, session id=%"PRIu32".", session->id);

    free(session);

    return SR_ERR_OK;
}

int
rp_msg_process(const rp_ctx_t *rp_ctx, const rp_session_t *session, Sr__Msg *msg)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_ARG3(rp_ctx, session, msg);

    if (SR__MSG__MSG_TYPE__REQUEST == msg->type) {
        /* request handling */
        switch (msg->request->operation) {
            case SR__OPERATION__GET_ITEM:
                rc = rp_get_item_req_process(rp_ctx, session, msg);
                break;
            case SR__OPERATION__GET_ITEMS:
                rc = rp_get_items_req_process(rp_ctx, session, msg);
                break;
            default:
                SR_LOG_ERR("Unsupported request received (session id=%"PRIu32", operation=%d).",
                        session->id, msg->request->operation);
                rc = SR_ERR_UNSUPPORTED;
                break;
        }
    } else {
        /* response handling */
        SR_LOG_ERR("Unsupported response received (session id=%"PRIu32", operation=%d).",
                session->id, msg->request->operation);
        rc = SR_ERR_UNSUPPORTED;
    }

    sr__msg__free_unpacked(msg, NULL);

    if (SR_ERR_OK != rc) {
        SR_LOG_WRN("Error by processing of the message: %s.", sr_strerror(rc));
    }
    return SR_ERR_OK; /* message processed, no matter what was the return code */
}
