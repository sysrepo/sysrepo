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
#include "data_manager.h"
#include "dm_location.h"
#include "rp_data_tree.h"

/**
 * @brief Structure that holds the context of an instance of Request Processor.
 */
typedef struct rp_ctx_s {
    cm_ctx_t *cm_ctx;  /**< Connection Manager context. */
    dm_ctx_t *dm_ctx;  /**< Data Manager Context */
} rp_ctx_t;

/**
 * @brief Structure that holds Request Processor's per-session context.
 */
typedef struct rp_session_s {
    uint32_t id;                         /**< Assigned session id. */
    const char *real_user;               /**< Real user name of the client. */
    const char *effective_user;          /**< Effective user name of the client (if different to real_user). */
    sr_datastore_t datastore;            /**< Datastore selected for this session. */
    dm_session_t *dm_session;            /**< Per session data manager context */
    rp_dt_get_items_ctx_t get_items_ctx; /**< Context for get_items_iter calls*/
} rp_session_t;

/**
 * Processes a list_schemas request.
 */
static int
rp_list_schemas_req_process(const rp_ctx_t *rp_ctx, const rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    sr_schema_t *schemas = NULL;
    size_t schema_cnt = 0;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->list_schemas_req);

    SR_LOG_DBG_MSG("Processing list_schemas request.");

    /* allocate the response */
    rc = sr_pb_resp_alloc(SR__OPERATION__LIST_SCHEMAS, session->id, &resp);
    if (SR_ERR_OK != rc){
        SR_LOG_ERR_MSG("Cannot allocate list_schemas response.");
        return SR_ERR_NOMEM;
    }

    /* retrieve schemas from DM */
    rc = dm_list_schemas(rp_ctx->dm_ctx, session->dm_session, &schemas, &schema_cnt);

    /* copy schemas to response */
    if (SR_ERR_OK == rc) {
        rc = sr_schemas_sr_to_gpb(schemas, schema_cnt, &resp->response->list_schemas_resp->schemas);
    }
    if (SR_ERR_OK == rc) {
        resp->response->list_schemas_resp->n_schemas = schema_cnt;
    }
    sr_free_schemas(schemas, schema_cnt);

    /* set response result code */
    resp->response->result = rc;

    /* send the response */
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    return rc;
}

/**
 * Processes a get_item request.
 */
static int
rp_get_item_req_process(const rp_ctx_t *rp_ctx, const rp_session_t *session, Sr__Msg *msg)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->get_item_req);

    SR_LOG_DBG_MSG("Processing get_item request.");

    Sr__Msg *resp = NULL;
    rc = sr_pb_resp_alloc(SR__OPERATION__GET_ITEM, session->id, &resp);
    if (SR_ERR_OK != rc){
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }

    sr_val_t *value = NULL;
    char *xpath = msg->request->get_item_req->path;

    //TODO select datatree corresponding to the datastore

    /* get value from data manager*/
    rc = rp_dt_get_value_wrapper(rp_ctx->dm_ctx, session->dm_session, xpath, &value);
    if (SR_ERR_OK != rc){
        SR_LOG_ERR("Get item failed for '%s', session id=%"PRIu32".", xpath, session->id);
    }

    /* copy value to gpb*/
    if (SR_ERR_OK == rc){
        rc = sr_dup_val_t_to_gpb(value, &resp->response->get_item_resp->value);
        if (SR_ERR_OK != rc){
            SR_LOG_ERR("Copying sr_val_t to gpb failed for xpath '%s'", xpath);
        }
    }

    /* set response code */
    resp->response->result = rc;

    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    sr_free_val(value);

    return rc;
}

/**
 * Processes a get_items request.
 */
static int
rp_get_items_req_process(const rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->get_items_req);

    SR_LOG_DBG_MSG("Processing get_items request.");

    Sr__Msg *resp = NULL;
    rc = sr_pb_resp_alloc(SR__OPERATION__GET_ITEMS, session->id, &resp);

    if (SR_ERR_OK != rc){
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }

    sr_val_t **values = NULL;
    size_t count = 0;
    char *xpath = msg->request->get_items_req->path;
    bool recursive = msg->request->get_items_req->recursive;
    size_t offset = msg->request->get_items_req->offset;
    size_t limit = msg->request->get_items_req->limit;

    //TODO select datatree corresponding to the datastore

    if (msg->request->get_items_req->has_recursive || msg->request->get_items_req->has_offset ||
            msg->request->get_items_req->has_limit){

        rc = rp_dt_get_values_wrapper_with_opts(rp_ctx->dm_ctx, session->dm_session, &session->get_items_ctx, xpath,
        recursive, offset, limit, &values, &count);
    }
    else {
        rc = rp_dt_get_values_wrapper(rp_ctx->dm_ctx, session->dm_session, xpath, &values, &count);
    }

    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Get items failed for '%s', session id=%"PRIu32".", xpath, session->id);
        goto cleanup;
    }
    SR_LOG_DBG("%zu items found for '%s', session id=%"PRIu32".", count, xpath, session->id);

    if (0 == count){
        SR_LOG_DBG("No items found for '%s', session id=%"PRIu32".", xpath, session->id);
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }


    resp->response->get_items_resp->values = calloc(count, sizeof(Sr__Value *));
    if (NULL == resp->response->get_items_resp->values){
        SR_LOG_ERR_MSG("Memory allocation failed");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    /* copy value to gpb*/
    if (SR_ERR_OK == rc) {
        for (size_t i = 0; i< count; i++){
            rc = sr_dup_val_t_to_gpb(values[i], &resp->response->get_items_resp->values[i]);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Copying sr_val_t to gpb failed for xpath '%s'", xpath);
                for (size_t j = 0; j<i; j++){
                    sr__value__free_unpacked(resp->response->get_items_resp->values[j], NULL);
                }
                free(resp->response->get_items_resp->values);
            }
        }
        resp->response->get_items_resp->n_values = count;
    }

cleanup:


    /* set response code */
    resp->response->result = rc;

    rc = cm_msg_send(rp_ctx->cm_ctx, resp);
    for (size_t i = 0; i< count; i++){
        sr_free_val(values[i]);
    }
    free(values);

    return rc;
}

int
rp_init(cm_ctx_t *cm_ctx, rp_ctx_t **rp_ctx_p)
{
    rp_ctx_t *ctx = NULL;

    CHECK_NULL_ARG(rp_ctx_p);

    SR_LOG_DBG_MSG("Request Processor init started.");

    int rc = SR_ERR_OK;
    ctx = calloc(1, sizeof(*ctx));
    if (NULL == ctx) {
        SR_LOG_ERR_MSG("Cannot allocate memory for Request Processor context.");
        return SR_ERR_NOMEM;
    }

    rc = dm_init(DM_SCHEMA_SEARCH_DIR, DM_DATA_SEARCH_DIR, &ctx->dm_ctx);
    if (SR_ERR_OK != rc){
        SR_LOG_ERR_MSG("Data manager init failed");
        free(ctx);
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
        dm_cleanup(rp_ctx->dm_ctx);
        free(rp_ctx);
    }
}

int
rp_session_start(const rp_ctx_t *rp_ctx, const char *real_user, const char *effective_user,
        const uint32_t session_id, const sr_datastore_t datastore, rp_session_t **session_p)
{
    rp_session_t *session = NULL;
    int rc = SR_ERR_OK;

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

    rc = dm_session_start(rp_ctx->dm_ctx, &session->dm_session);
    if (SR_ERR_OK  != rc){
        SR_LOG_ERR("Init of dm_session failed for session id=%"PRIu32".", session_id);
        free(session);
        return rc;
    }

    *session_p = session;

    return rc;
}

int
rp_session_stop(const rp_ctx_t *rp_ctx, rp_session_t *session)
{
    CHECK_NULL_ARG2(rp_ctx, session);

    SR_LOG_DBG("RP session stop, session id=%"PRIu32".", session->id);

    dm_session_stop(rp_ctx->dm_ctx, session->dm_session);

    rp_ns_clean(&session->get_items_ctx.stack);
    free(session->get_items_ctx.xpath);
    free(session);

    return SR_ERR_OK;
}

int
rp_msg_process(const rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG_NORET3(rc, rp_ctx, session, msg);

    if (SR_ERR_OK != rc) {
        if (NULL != msg) {
            sr__msg__free_unpacked(msg, NULL);
        }
        return rc;
    }

    if (SR__MSG__MSG_TYPE__REQUEST == msg->type) {
        /* request handling */
        switch (msg->request->operation) {
            case SR__OPERATION__LIST_SCHEMAS:
                rc = rp_list_schemas_req_process(rp_ctx, session, msg);
                break;
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
                session->id, msg->response->operation);
        rc = SR_ERR_UNSUPPORTED;
    }

    /* release the message */
    sr__msg__free_unpacked(msg, NULL);

    if (SR_ERR_OK != rc) {
        SR_LOG_WRN("Error by processing of the message: %s.", sr_strerror(rc));
    }
    return rc;
}
