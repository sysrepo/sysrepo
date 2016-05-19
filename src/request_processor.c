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

#include <time.h>
#include <inttypes.h>
#include <pthread.h>

#include "sr_common.h"
#include "access_control.h"
#include "connection_manager.h"
#include "notification_processor.h"
#include "data_manager.h"
#include "rp_internal.h"
#include "rp_dt_get.h"
#include "rp_dt_edit.h"

#define RP_INIT_REQ_QUEUE_SIZE 10    /**< Initial size of the request queue. */

/*
 * Attributes that can significantly affect performance of the threadpool.
 */
#define RP_REQ_PER_THREADS 2           /**< Number of requests that can be WAITING in queue per each thread before waking up another thread. */
#define RP_THREAD_SPIN_TIMEOUT 500000  /**< Time in nanoseconds (500000 equals to a half of a millisecond).
                                            Enables thread spinning if a thread needs to be woken up again in less than this timeout. */
#define RP_THREAD_SPIN_MIN 1000        /**< Minimum number of cycles that a thread will spin before going to sleep, if spin is enabled. */
#define RP_THREAD_SPIN_MAX 1000000     /**< Maximum number of cycles that a thread can spin before going to sleep. */

/**
 * @brief Request context (for storing requests inside of the request queue).
 */
typedef struct rp_request_s {
    rp_session_t *session;  /**< Request Processor's session. */
    Sr__Msg *msg;           /**< Message to be processed. */
} rp_request_t;

/**
 * @brief Copy errors saved in the Data Manager session into the GPB response.
 */
static int
rp_resp_fill_errors(Sr__Msg *msg, dm_session_t *dm_session)
{
    CHECK_NULL_ARG2(msg, dm_session);
    int rc = SR_ERR_OK;

    if (!dm_has_error(dm_session)) {
        return SR_ERR_OK;
    }

    msg->response->error = calloc(1, sizeof(Sr__Error));
    if (NULL == msg->response->error) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }
    sr__error__init(msg->response->error);
    rc = dm_copy_errors(dm_session, &msg->response->error->message, &msg->response->error->xpath);
    return rc;
}

/**
 * @brief Processes a list_schemas request.
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
    rc = sr_gpb_resp_alloc(SR__OPERATION__LIST_SCHEMAS, session->id, &resp);
    if (SR_ERR_OK != rc) {
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
 * @brief Processes a get_schema request.
 */
static int
rp_get_schema_req_process(const rp_ctx_t *rp_ctx, const rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->get_schema_req);

    SR_LOG_DBG_MSG("Processing get_schema request.");

    /* allocate the response */
    rc = sr_gpb_resp_alloc(SR__OPERATION__GET_SCHEMA, session->id, &resp);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate get_schema response.");
        return SR_ERR_NOMEM;
    }

    /* set response result code */
    resp->response->result = dm_get_schema(rp_ctx->dm_ctx,
            msg->request->get_schema_req->module_name,
            msg->request->get_schema_req->revision,
            msg->request->get_schema_req->submodule_name,
            msg->request->get_schema_req->yang_format,
            &resp->response->get_schema_resp->schema_content);

    /* send the response */
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    return rc;
}

/**
 * @brief Processes a module_install request.
 */
static int
rp_module_install_req_process(const rp_ctx_t *rp_ctx, const rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    int rc = SR_ERR_OK, oper_rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->module_install_req);

    SR_LOG_DBG_MSG("Processing module_install request.");

    rc = ac_check_module_permissions(session->ac_session, msg->request->module_install_req->module_name, AC_OPER_READ_WRITE);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Access control check failed for xpath '%s'", msg->request->module_install_req->module_name);
        return rc;
    }

    /* allocate the response */
    rc = sr_gpb_resp_alloc(SR__OPERATION__MODULE_INSTALL, session->id, &resp);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate module_install response.");
        return SR_ERR_NOMEM;
    }

    /* install the module in the DM */
    oper_rc = msg->request->module_install_req->installed ?
            dm_install_module(rp_ctx->dm_ctx,
            msg->request->module_install_req->module_name,
            msg->request->module_install_req->revision)
            :
            dm_uninstall_module(rp_ctx->dm_ctx,
            msg->request->module_install_req->module_name,
            msg->request->module_install_req->revision);

    /* set response code */
    resp->response->result = oper_rc;

    /* send the response */
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    /* notify subscribers */
    if (SR_ERR_OK == oper_rc) {
        rc = np_module_install_notify(rp_ctx->np_ctx, msg->request->module_install_req->module_name,
                msg->request->module_install_req->revision, msg->request->module_install_req->installed);
    }

    return rc;
}

/**
 * @brief Processes a feature_enable request.
 */
static int
rp_feature_enable_req_process(const rp_ctx_t *rp_ctx, const rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    int rc = SR_ERR_OK, oper_rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->feature_enable_req);

    SR_LOG_DBG_MSG("Processing feature_enable request.");

    /* allocate the response */
    rc = sr_gpb_resp_alloc(SR__OPERATION__FEATURE_ENABLE, session->id, &resp);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate feature_enable response.");
        return SR_ERR_NOMEM;
    }

    Sr__FeatureEnableReq *req = msg->request->feature_enable_req;

    /* enable the feature in the DM */
    oper_rc = dm_feature_enable(rp_ctx->dm_ctx, req->module_name, req->feature_name, req->enabled);

    /* enable the feature in persistent data */
    if (SR_ERR_OK == oper_rc) {
        oper_rc = pm_save_feature_state(rp_ctx->pm_ctx, session->user_credentials,
                req->module_name, req->feature_name, req->enabled);
        if (SR_ERR_OK != oper_rc) {
            /* rollback of the change in DM */
            dm_feature_enable(rp_ctx->dm_ctx, req->module_name, req->feature_name, !req->enabled);
        }
    }

    /* set response code */
    resp->response->result = oper_rc;

    /* send the response */
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    /* notify subscribers */
    if (SR_ERR_OK == oper_rc) {
        rc = np_feature_enable_notify(rp_ctx->np_ctx, msg->request->feature_enable_req->module_name,
                msg->request->feature_enable_req->feature_name, msg->request->feature_enable_req->enabled);
    }

    return rc;
}

/**
 * @brief Processes a get_item request.
 */
static int
rp_get_item_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->get_item_req);

    SR_LOG_DBG_MSG("Processing get_item request.");

    Sr__Msg *resp = NULL;
    rc = sr_gpb_resp_alloc(SR__OPERATION__GET_ITEM, session->id, &resp);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }

    sr_val_t *value = NULL;
    char *xpath = msg->request->get_item_req->xpath;

    /* get value from data manager */
    rc = rp_dt_get_value_wrapper(rp_ctx, session, xpath, &value);
    if (SR_ERR_OK != rc) {
        if (SR_ERR_NOT_FOUND != rc) {
            SR_LOG_ERR("Get item failed for '%s', session id=%"PRIu32".", xpath, session->id);
        }
    }

    /* copy value to gpb */
    if (SR_ERR_OK == rc) {
        rc = sr_dup_val_t_to_gpb(value, &resp->response->get_item_resp->value);
        if (SR_ERR_OK != rc){
            SR_LOG_ERR("Copying sr_val_t to gpb failed for xpath '%s'", xpath);
        }
    }

    /* set response code */
    resp->response->result = rc;

    rc = rp_resp_fill_errors(resp, session->dm_session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Copying errors to gpb failed");
    }

    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    sr_free_val(value);

    return rc;
}

/**
 * @brief Processes a get_items request.
 */
static int
rp_get_items_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    sr_val_t *values = NULL;
    size_t count = 0, limit = 0, offset = 0;
    char *xpath = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->get_items_req);

    SR_LOG_DBG_MSG("Processing get_items request.");

    Sr__Msg *resp = NULL;
    rc = sr_gpb_resp_alloc(SR__OPERATION__GET_ITEMS, session->id, &resp);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }

    xpath = msg->request->get_items_req->xpath;
    offset = msg->request->get_items_req->offset;
    limit = msg->request->get_items_req->limit;

    if (msg->request->get_items_req->has_offset || msg->request->get_items_req->has_limit) {
        rc = rp_dt_get_values_wrapper_with_opts(rp_ctx, session, &session->get_items_ctx, xpath,
                offset, limit, &values, &count);
    } else {
        rc = rp_dt_get_values_wrapper(rp_ctx, session, xpath, &values, &count);
    }

    if (SR_ERR_OK != rc) {
        if (SR_ERR_NOT_FOUND != rc) {
            SR_LOG_ERR("Get items failed for '%s', session id=%"PRIu32".", xpath, session->id);
        }
        goto cleanup;
    }
    SR_LOG_DBG("%zu items found for '%s', session id=%"PRIu32".", count, xpath, session->id);

    /* copy values to gpb */
    rc = sr_values_sr_to_gpb(values, count, &resp->response->get_items_resp->values, &resp->response->get_items_resp->n_values);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Copying values to GPB failed.");

cleanup:
    /* set response code */
    resp->response->result = rc;

    rc = rp_resp_fill_errors(resp, session->dm_session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Copying errors to gpb failed");
    }

    rc = cm_msg_send(rp_ctx->cm_ctx, resp);
    sr_free_values(values, count);

    return rc;
}

/**
 * @brief Processes a set_item request.
 */
static int
rp_set_item_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    char *xpath = NULL;
    sr_val_t *value = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->set_item_req);

    SR_LOG_DBG_MSG("Processing set_item request.");

    xpath = msg->request->set_item_req->xpath;

    /* allocate the response */
    rc = sr_gpb_resp_alloc(SR__OPERATION__SET_ITEM, session->id, &resp);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Allocation of set_item response failed.");
        free(value);
        return SR_ERR_NOMEM;
    }

    if (NULL != msg->request->set_item_req->value) {
        /* copy the value from gpb */
        value = calloc(1, sizeof(*value));
        rc = sr_copy_gpb_to_val_t(msg->request->set_item_req->value, value);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Copying gpb value to sr_val_t failed for xpath '%s'", xpath);
            free(value);
        }

        /* set the value in data manager */
        if (SR_ERR_OK == rc) {
            rc = rp_dt_set_item_wrapper(rp_ctx, session, xpath, value, msg->request->set_item_req->options);
        }
    }
    else{
        /* when creating list or presence container value can be NULL */
        rc = rp_dt_set_item_wrapper(rp_ctx, session, xpath, NULL, msg->request->set_item_req->options);
    }

    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Set item failed for '%s', session id=%"PRIu32".", xpath, session->id);
    }

    /* set response code */
    resp->response->result = rc;

    rc = rp_resp_fill_errors(resp, session->dm_session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Copying errors to gpb failed");
    }

    /* send the response */
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    return rc;
}

/**
 * @brief Processes a delete_item request.
 */
static int
rp_delete_item_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    char *xpath = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->delete_item_req);

    SR_LOG_DBG_MSG("Processing delete_item request.");

    xpath = msg->request->delete_item_req->xpath;

    /* allocate the response */
    rc = sr_gpb_resp_alloc(SR__OPERATION__DELETE_ITEM, session->id, &resp);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Allocation of delete_item response failed.");
        return SR_ERR_NOMEM;
    }

    /* delete the item in data manager */
    rc = rp_dt_delete_item_wrapper(rp_ctx, session, xpath, msg->request->delete_item_req->options);
    if (SR_ERR_OK != rc){
        SR_LOG_ERR("Delete item failed for '%s', session id=%"PRIu32".", xpath, session->id);
    }

    /* set response code */
    resp->response->result = rc;

    rc = rp_resp_fill_errors(resp, session->dm_session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Copying errors to gpb failed");
    }

    /* send the response */
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    return rc;
}

/**
 * @brief Processes a move_item request.
 */
static int
rp_move_item_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    char *xpath = NULL;
    char *relative_item = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->move_item_req);

    SR_LOG_DBG_MSG("Processing move_item request.");

    xpath = msg->request->move_item_req->xpath;
    relative_item = msg->request->move_item_req->relative_item;

    /* allocate the response */
    rc = sr_gpb_resp_alloc(SR__OPERATION__MOVE_ITEM, session->id, &resp);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Allocation of move_item response failed.");
        return SR_ERR_NOMEM;
    }

    rc = rp_dt_move_list_wrapper(rp_ctx, session, xpath,
            sr_move_direction_gpb_to_sr(msg->request->move_item_req->position), relative_item);

    /* set response code */
    resp->response->result = rc;

    rc = rp_resp_fill_errors(resp, session->dm_session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Copying errors to gpb failed");
    }

    /* send the response */
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    return rc;
}

/**
 * @brief Processes a validate request.
 */
static int
rp_validate_req_process(const rp_ctx_t *rp_ctx, const rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->validate_req);

    SR_LOG_DBG_MSG("Processing validate request.");

    /* allocate the response */
    rc = sr_gpb_resp_alloc(SR__OPERATION__VALIDATE, session->id, &resp);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Allocation of validate response failed.");
        return SR_ERR_NOMEM;
    }

    sr_error_info_t *errors = NULL;
    size_t err_cnt = 0;
    rc = dm_validate_session_data_trees(rp_ctx->dm_ctx, session->dm_session, &errors, &err_cnt);

    /* set response code */
    resp->response->result = rc;

    /* copy error information to GPB  (if any) */
    if (err_cnt > 0) {
        sr_gpb_fill_errors(errors, err_cnt, &resp->response->validate_resp->errors, &resp->response->validate_resp->n_errors);
        sr_free_errors(errors, err_cnt);
    }

    /* send the response */
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    return rc;
}

/**
 * @brief Processes a commit request.
 */
static int
rp_commit_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->commit_req);

    SR_LOG_DBG_MSG("Processing commit request.");

    /* allocate the response */
    rc = sr_gpb_resp_alloc(SR__OPERATION__COMMIT, session->id, &resp);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Allocation of commit response failed.");
        return SR_ERR_NOMEM;
    }

    sr_error_info_t *errors = NULL;
    size_t err_cnt = 0;
    rc = rp_dt_commit(rp_ctx, session, &errors, &err_cnt);

    /* set response code */
    resp->response->result = rc;

    /* copy error information to GPB  (if any) */
    if (err_cnt > 0) {
        sr_gpb_fill_errors(errors, err_cnt, &resp->response->commit_resp->errors, &resp->response->commit_resp->n_errors);
        sr_free_errors(errors, err_cnt);
    }

    /* send the response */
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    return rc;
}

/**
 * @brief Processes a discard_changes request.
 */
static int
rp_discard_changes_req_process(const rp_ctx_t *rp_ctx, const rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->discard_changes_req);

    SR_LOG_DBG_MSG("Processing discard_changes request.");

    /* allocate the response */
    rc = sr_gpb_resp_alloc(SR__OPERATION__DISCARD_CHANGES, session->id, &resp);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Allocation of discard_changes response failed.");
        return SR_ERR_NOMEM;
    }

    rc = dm_discard_changes(rp_ctx->dm_ctx, session->dm_session);

    /* set response code */
    resp->response->result = rc;

    rc = rp_resp_fill_errors(resp, session->dm_session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Copying errors to gpb failed");
    }

    /* send the response */
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    return rc;
}

/**
 * @brief Processes a discard_changes request.
 */
static int
rp_copy_config_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->copy_config_req);

    SR_LOG_DBG_MSG("Processing copy_config request.");

    /* allocate the response */
    rc = sr_gpb_resp_alloc(SR__OPERATION__COPY_CONFIG, session->id, &resp);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Allocation of copy_config response failed.");
        return SR_ERR_NOMEM;
    }

    rc = rp_dt_copy_config(rp_ctx, session, msg->request->copy_config_req->module_name,
                sr_datastore_gpb_to_sr(msg->request->copy_config_req->src_datastore),
                sr_datastore_gpb_to_sr(msg->request->copy_config_req->dst_datastore));

    /* set response code */
    resp->response->result = rc;

    rc = rp_resp_fill_errors(resp, session->dm_session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Copying errors to gpb failed");
    }

    /* send the response */
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    return rc;
}

/**
 * @brief Processes a session_data_refresh request.
 */
static int
rp_session_refresh_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->session_refresh_req);

    SR_LOG_DBG_MSG("Processing session_data_refresh request.");

    /* allocate the response */
    rc = sr_gpb_resp_alloc(SR__OPERATION__SESSION_REFRESH, session->id, &resp);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Allocation of session_data_refresh response failed.");
        return SR_ERR_NOMEM;
    }

    sr_error_info_t *errors = NULL;
    size_t err_cnt = 0;

    rc = rp_dt_refresh_session(rp_ctx, session, &errors, &err_cnt);

    /* set response code */
    resp->response->result = rc;

    /* copy error information to GPB  (if any) */
    if (NULL != errors) {
        sr_gpb_fill_errors(errors, err_cnt, &resp->response->session_refresh_resp->errors,
                &resp->response->session_refresh_resp->n_errors);
        sr_free_errors(errors, err_cnt);
    }

    /* send the response */
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    return rc;
}

static int
rp_switch_datastore_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->session_switch_ds_req);

    SR_LOG_DBG_MSG("Processing session_switch_ds request.");

    /* allocate the response */
    rc = sr_gpb_resp_alloc(SR__OPERATION__SESSION_SWITCH_DS, session->id, &resp);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Allocation of session_switch_ds response failed.");
        return SR_ERR_NOMEM;
    }

    rc = rp_dt_switch_datastore(rp_ctx, session, sr_datastore_gpb_to_sr(msg->request->session_switch_ds_req->datastore));

    /* set response code */
    resp->response->result = rc;

    rc = rp_resp_fill_errors(resp, session->dm_session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Copying errors to gpb failed");
    }

    /* send the response */
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    return rc;
}

/**
 * @brief Processes a lock request.
 */
static int
rp_lock_req_process(const rp_ctx_t *rp_ctx, const rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->lock_req);

    SR_LOG_DBG_MSG("Processing lock request.");

    /* allocate the response */
    rc = sr_gpb_resp_alloc(SR__OPERATION__LOCK, session->id, &resp);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Allocation of lock response failed.");
        return SR_ERR_NOMEM;
    }

    rc = rp_dt_lock(rp_ctx, session, msg->request->lock_req->module_name);

    /* set response code */
    resp->response->result = rc;

    rc = rp_resp_fill_errors(resp, session->dm_session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Copying errors to gpb failed");
    }

    /* send the response */
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    return rc;
}

/**
 * @brief Processes an unlock request.
 */
static int
rp_unlock_req_process(const rp_ctx_t *rp_ctx, const rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->unlock_req);

    SR_LOG_DBG_MSG("Processing unlock request.");

    /* allocate the response */
    rc = sr_gpb_resp_alloc(SR__OPERATION__UNLOCK, session->id, &resp);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Allocation of unlock response failed.");
        return SR_ERR_NOMEM;
    }

    if (NULL != msg->request->unlock_req->module_name) {
        /* module-level lock */
        rc = dm_unlock_module(rp_ctx->dm_ctx, session->dm_session, msg->request->unlock_req->module_name);
    } else {
        /* datastore-level lock */
        rc = dm_unlock_datastore(rp_ctx->dm_ctx, session->dm_session);
    }

    /* set response code */
    resp->response->result = rc;

    rc = rp_resp_fill_errors(resp, session->dm_session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Copying errors to gpb failed");
    }

    /* send the response */
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    return rc;
}

/**
 * @brief Processes a subscribe request.
 */
static int
rp_subscribe_req_process(const rp_ctx_t *rp_ctx, const rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    Sr__SubscribeReq *subscribe_req = NULL;
    np_subscr_options_t options = NP_SUBSCR_DEFAULT;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->subscribe_req);

    SR_LOG_DBG_MSG("Processing subscribe request.");

    /* allocate the response */
    rc = sr_gpb_resp_alloc(SR__OPERATION__SUBSCRIBE, session->id, &resp);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Allocation of subscribe response failed.");
        return SR_ERR_NOMEM;
    }
    subscribe_req = msg->request->subscribe_req;

    /* set subscribe options */
    if (subscribe_req->enable_running) {
        options |= NP_SUBSCR_ENABLE_RUNNING;
    }
    if (SR__NOTIFICATION_EVENT__RPC_EV == subscribe_req->event) {
        options |= NP_SUBSCR_EXCLUSIVE;
    }

    /* subscribe to the notification */
    rc = np_notification_subscribe(rp_ctx->np_ctx, session, subscribe_req->event,
            subscribe_req->destination, subscribe_req->subscription_id,
            subscribe_req->module_name, subscribe_req->xpath, options);

    /* set response code */
    resp->response->result = rc;

    rc = rp_resp_fill_errors(resp, session->dm_session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Copying errors to gpb failed");
    }

    /* send the response */
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    if (SR_ERR_OK == rc) {
        /* send initial HELLO notification to test the subscription */
        rc = np_hello_notify(rp_ctx->np_ctx, subscribe_req->module_name,
                subscribe_req->destination, subscribe_req->subscription_id);
    }

    return rc;
}

/**
 * @brief Processes an unsubscribe request.
 */
static int
rp_unsubscribe_req_process(const rp_ctx_t *rp_ctx, const rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->unsubscribe_req);

    SR_LOG_DBG_MSG("Processing unsubscribe request.");

    /* allocate the response */
    rc = sr_gpb_resp_alloc(SR__OPERATION__UNSUBSCRIBE, session->id, &resp);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Allocation of unsubscribe response failed.");
        return SR_ERR_NOMEM;
    }

    /* unsubscribe from the notifications */
    rc = np_notification_unsubscribe(rp_ctx->np_ctx, session, msg->request->unsubscribe_req->event,
            msg->request->unsubscribe_req->destination, msg->request->unsubscribe_req->subscription_id,
            msg->request->unsubscribe_req->module_name);

    /* set response code */
    resp->response->result = rc;

    rc = rp_resp_fill_errors(resp, session->dm_session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Copying errors to gpb failed");
    }

    /* send the response */
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    return rc;
}

/**
 * @brief Processes a RPC request.
 */
static int
rp_rpc_req_process(const rp_ctx_t *rp_ctx, const rp_session_t *session, Sr__Msg *msg)
{
    char *module_name = NULL;
    sr_val_t *input = NULL;
    size_t input_cnt = 0;
    np_subscription_t *subscriptions = NULL;
    size_t subscription_cnt = 0;
    Sr__Msg *req = NULL, *resp = NULL;
    int rc = SR_ERR_OK, rc_tmp = SR_ERR_OK;

    CHECK_NULL_ARG_NORET5(rc, rp_ctx, session, msg, msg->request, msg->request->rpc_req);
    if (SR_ERR_OK != rc) {
        /* release the message since it won't be released in dispatch */
        sr__msg__free_unpacked(msg, NULL);
        return rc;
    }

    SR_LOG_DBG_MSG("Processing RPC request.");

    /* validate RPC request */
    rc = sr_values_gpb_to_sr(msg->request->rpc_req->input,  msg->request->rpc_req->n_input, &input, &input_cnt);
    if (SR_ERR_OK == rc) {
        rc = dm_validate_rpc(rp_ctx->dm_ctx, session->dm_session, msg->request->rpc_req->xpath, &input, &input_cnt, true);
    }

    /* duplicate msg into req with the new input values */
    if (SR_ERR_OK == rc) {
        rc = sr_gpb_req_alloc(SR__OPERATION__RPC, session->id, &req);
    }
    if (SR_ERR_OK == rc) {
        req->request->rpc_req->xpath = strdup(msg->request->rpc_req->xpath);
        CHECK_NULL_NOMEM_ERROR(req->request->rpc_req->xpath, rc);
    }
    if (SR_ERR_OK == rc) {
        rc = sr_values_sr_to_gpb(input, input_cnt, &req->request->rpc_req->input, &req->request->rpc_req->n_input);
    }
    sr_free_values(input, input_cnt);
    sr__msg__free_unpacked(msg, NULL);
    msg = NULL;

    /* get module name */
    if (SR_ERR_OK == rc) {
        rc = sr_copy_first_ns(req->request->rpc_req->xpath, &module_name);
    }

    /* authorize (write permissions are required to deliver the RPC) */
    if (SR_ERR_OK == rc) {
        rc = ac_check_module_permissions(session->ac_session, module_name, AC_OPER_READ_WRITE);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Access control check failed for module name '%s'", module_name);
        }
    }

    /* get RPC subscription */
    if (SR_ERR_OK == rc) {
        rc = pm_get_subscriptions(rp_ctx->pm_ctx, module_name, SR__NOTIFICATION_EVENT__RPC_EV,
                &subscriptions, &subscription_cnt);
    }
    free(module_name);

    /* fill-in subscription details into the request */
    if (subscription_cnt > 0) {
        req->request->rpc_req->subscriber_address = (char*)subscriptions[0].dst_address; /* copied to GPB - do not free */
        req->request->rpc_req->subscription_id = subscriptions[0].dst_id;
        req->request->rpc_req->has_subscription_id = true;
        req->request->rpc_req->session_id = session->id;
        req->request->rpc_req->has_session_id = true;
        free(subscriptions);
    } else if (SR_ERR_OK == rc) {
        /* no subscription for this RPC */
        SR_LOG_ERR("No subscription found for RPC delivery (xpath = '%s').", req->request->rpc_req->xpath);
        rc = SR_ERR_NOT_FOUND;
    }

    if (SR_ERR_OK == rc) {
        /* forward the request to the subscriber */
        rc = cm_msg_send(rp_ctx->cm_ctx, req);
    } else {
        /* send the response with error */
        rc_tmp = sr_gpb_resp_alloc(SR__OPERATION__RPC, session->id, &resp);
        if (SR_ERR_OK == rc_tmp) {
            resp->response->result = rc;
            resp->response->rpc_resp->xpath = req->request->rpc_req->xpath;
            req->request->rpc_req->xpath = NULL;
            /* send the response */
            rc = cm_msg_send(rp_ctx->cm_ctx, resp);
        }
        /* release the request */
        sr__msg__free_unpacked(req, NULL);
    }

    return rc;
}

/**
 * @brief Processes a RPC response.
 */
static int
rp_rpc_resp_process(const rp_ctx_t *rp_ctx, const rp_session_t *session, Sr__Msg *msg)
{
    sr_val_t *output = NULL;
    size_t output_cnt = 0;
    Sr__Msg *resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG_NORET5(rc, rp_ctx, session, msg, msg->response, msg->response->rpc_resp);
    if (SR_ERR_OK != rc) {
        /* release the message since it won't be released in dispatch */
        sr__msg__free_unpacked(msg, NULL);
        return rc;
    }

    /* validate the RPC response */
    rc = sr_values_gpb_to_sr(msg->response->rpc_resp->output,  msg->response->rpc_resp->n_output, &output, &output_cnt);
    if (SR_ERR_OK == rc) {
        rc = dm_validate_rpc(rp_ctx->dm_ctx, session->dm_session, msg->response->rpc_resp->xpath, &output, &output_cnt, false);
    }

    /* duplicate msg into resp with the new output values */
    if (SR_ERR_OK == rc) {
        rc = sr_gpb_resp_alloc(SR__OPERATION__RPC, session->id, &resp);
    }
    if (SR_ERR_OK == rc) {
        resp->response->rpc_resp->xpath = strdup(msg->response->rpc_resp->xpath);
        CHECK_NULL_NOMEM_ERROR(resp->response->rpc_resp->xpath, rc);
    }
    if (SR_ERR_OK == rc) {
        rc = sr_values_sr_to_gpb(output, output_cnt, &resp->response->rpc_resp->output, &resp->response->rpc_resp->n_output);
    }
    sr_free_values(output, output_cnt);

    if (SR_ERR_OK == rc) {
        sr__msg__free_unpacked(msg, NULL);
        msg = NULL;
    } else {
        resp = msg;
    }

    /* set response code */
    resp->response->result = rc;

    /* copy DM errors, if any */
    rc = rp_resp_fill_errors(resp, session->dm_session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Copying errors to gpb failed.");
    }

    /* forward RPC response to the originator */
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    return rc;
}

/**
 * @brief Processes an unsubscribe-destination internal request.
 */
static int
rp_unsubscribe_destination_req_process(const rp_ctx_t *rp_ctx, const rp_session_t *session, Sr__Msg *msg)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(rp_ctx, msg, msg->internal_request, msg->internal_request->unsubscribe_dst_req);

    SR_LOG_DBG_MSG("Processing unsubscribe destination request.");

    rc = np_unsubscribe_destination(rp_ctx->np_ctx, msg->internal_request->unsubscribe_dst_req->destination);

    return rc;
}

/**
 * @brief Dispatches the received message.
 */
static int
rp_msg_dispatch(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(rp_ctx, msg);

    /* NULL session is only allowed for internal messages */
    if ((NULL == session) && (SR__MSG__MSG_TYPE__INTERNAL_REQUEST != msg->type)) {
        SR_LOG_ERR("Session argument of the message  to be processed is NULL (type=%d).", msg->type);
        sr__msg__free_unpacked(msg, NULL);
        return SR_ERR_INVAL_ARG;
    }

    /* whitelist only some operations for notification sessions */
    if ((NULL != session) && (session->options & SR__SESSION_FLAGS__SESS_NOTIFICATION)) {
        if ((SR__OPERATION__GET_ITEM != msg->request->operation) &&
                (SR__OPERATION__GET_ITEMS != msg->request->operation) &&
                (SR__OPERATION__UNSUBSCRIBE != msg->request->operation)) {
            SR_LOG_ERR("Unsupported operation for notification session (session id=%"PRIu32", operation=%d).",
                    session->id, msg->response->operation);
            sr__msg__free_unpacked(msg, NULL);
            return SR_ERR_UNSUPPORTED;
        }
    }

    if (SR__MSG__MSG_TYPE__REQUEST == msg->type) {
        /* request handling */

        dm_clear_session_errors(session->dm_session);
        /* acquire lock for operation accessing data */
        switch (msg->request->operation) {
            case SR__OPERATION__GET_ITEM:
            case SR__OPERATION__GET_ITEMS:
            case SR__OPERATION__SET_ITEM:
            case SR__OPERATION__DELETE_ITEM:
            case SR__OPERATION__MOVE_ITEM:
            case SR__OPERATION__SESSION_REFRESH:
                pthread_rwlock_rdlock(&rp_ctx->commit_lock);
                break;
            case SR__OPERATION__COMMIT:
                pthread_rwlock_wrlock(&rp_ctx->commit_lock);
                break;
            default:
                break;
        }

        switch (msg->request->operation) {
            case SR__OPERATION__SESSION_SWITCH_DS:
                rc = rp_switch_datastore_req_process(rp_ctx, session, msg);
                break;
            case SR__OPERATION__LIST_SCHEMAS:
                rc = rp_list_schemas_req_process(rp_ctx, session, msg);
                break;
            case SR__OPERATION__GET_SCHEMA:
                rc = rp_get_schema_req_process(rp_ctx, session, msg);
                break;
            case SR__OPERATION__MODULE_INSTALL:
                rc = rp_module_install_req_process(rp_ctx, session, msg);
                break;
            case SR__OPERATION__FEATURE_ENABLE:
                rc = rp_feature_enable_req_process(rp_ctx, session, msg);
                break;
            case SR__OPERATION__GET_ITEM:
                rc = rp_get_item_req_process(rp_ctx, session, msg);
                break;
            case SR__OPERATION__GET_ITEMS:
                rc = rp_get_items_req_process(rp_ctx, session, msg);
                break;
            case SR__OPERATION__SET_ITEM:
                rc = rp_set_item_req_process(rp_ctx, session, msg);
                break;
            case SR__OPERATION__DELETE_ITEM:
                rc = rp_delete_item_req_process(rp_ctx, session, msg);
                break;
            case SR__OPERATION__MOVE_ITEM:
                rc = rp_move_item_req_process(rp_ctx, session, msg);
                break;
            case SR__OPERATION__VALIDATE:
                rc = rp_validate_req_process(rp_ctx, session, msg);
                break;
            case SR__OPERATION__COMMIT:
                rc = rp_commit_req_process(rp_ctx, session, msg);
                break;
            case SR__OPERATION__DISCARD_CHANGES:
                rc = rp_discard_changes_req_process(rp_ctx, session, msg);
                break;
            case SR__OPERATION__COPY_CONFIG:
                rc = rp_copy_config_req_process(rp_ctx, session, msg);
                break;
            case SR__OPERATION__SESSION_REFRESH:
                rc = rp_session_refresh_req_process(rp_ctx, session, msg);
                break;
            case SR__OPERATION__LOCK:
                rc = rp_lock_req_process(rp_ctx, session, msg);
                break;
            case SR__OPERATION__UNLOCK:
                rc = rp_unlock_req_process(rp_ctx, session, msg);
                break;
            case SR__OPERATION__SUBSCRIBE:
                rc = rp_subscribe_req_process(rp_ctx, session, msg);
                break;
            case SR__OPERATION__UNSUBSCRIBE:
                rc = rp_unsubscribe_req_process(rp_ctx, session, msg);
                break;
            case SR__OPERATION__RPC:
                rc = rp_rpc_req_process(rp_ctx, session, msg);
                return rc; /* skip further processing and msg cleanup */
                break;
            default:
                SR_LOG_ERR("Unsupported request received (session id=%"PRIu32", operation=%d).",
                        session->id, msg->request->operation);
                rc = SR_ERR_UNSUPPORTED;
                break;
        }

        /* release lock*/
        switch (msg->request->operation) {
            case SR__OPERATION__GET_ITEM:
            case SR__OPERATION__GET_ITEMS:
            case SR__OPERATION__SET_ITEM:
            case SR__OPERATION__DELETE_ITEM:
            case SR__OPERATION__MOVE_ITEM:
            case SR__OPERATION__SESSION_REFRESH:
            case SR__OPERATION__COMMIT:
                pthread_rwlock_unlock(&rp_ctx->commit_lock);
                break;
            default:
                break;
        }
    } else if (SR__MSG__MSG_TYPE__INTERNAL_REQUEST == msg->type) {
        /* internal request handling */
        switch (msg->internal_request->operation) {
            case SR__OPERATION__UNSUBSCRIBE_DESTINATION:
                rc = rp_unsubscribe_destination_req_process(rp_ctx, session, msg);
                break;
            default:
                SR_LOG_ERR("Unsupported internal request received (operation=%d).", msg->request->operation);
                rc = SR_ERR_UNSUPPORTED;
                break;
        }
    } else if (SR__MSG__MSG_TYPE__RESPONSE == msg->type) {
        /* response handling */
        switch (msg->response->operation) {
            case SR__OPERATION__RPC:
                rc = rp_rpc_resp_process(rp_ctx, session, msg);
                return rc; /* skip further processing and msg cleanup */
                break;
            default:
                SR_LOG_ERR("Unsupported response received (session id=%"PRIu32", operation=%d).",
                        session->id, msg->response->operation);
                rc = SR_ERR_UNSUPPORTED;
                break;
        }
    } else {
        SR_LOG_ERR("Unsupported message received (session id=%"PRIu32", operation=%d).",
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

/**
 * @brief Cleans up the session (releases the data allocated by Request Processor).
 */
static int
rp_session_cleanup(const rp_ctx_t *rp_ctx, rp_session_t *session)
{
    CHECK_NULL_ARG2(rp_ctx, session);

    SR_LOG_DBG("RP session cleanup, session id=%"PRIu32".", session->id);

    dm_session_stop(rp_ctx->dm_ctx, session->dm_session);
    ac_session_cleanup(session->ac_session);

    ly_set_free(session->get_items_ctx.nodes);
    free(session->get_items_ctx.xpath);
    pthread_mutex_destroy(&session->msg_count_mutex);
    free(session);

    return SR_ERR_OK;
}

/**
 * @brief Executes the work of a worker thread.
 */
static void *
rp_worker_thread_execute(void *rp_ctx_p)
{
    if (NULL == rp_ctx_p) {
        return NULL;
    }
    rp_ctx_t *rp_ctx = (rp_ctx_t*)rp_ctx_p;
    rp_request_t req = { 0 };
    bool dequeued = false, dequeued_prev = false, exit = false;

    SR_LOG_DBG("Starting worker thread id=%lu.", (unsigned long)pthread_self());

    pthread_mutex_lock(&rp_ctx->request_queue_mutex);
    rp_ctx->active_threads++;
    pthread_mutex_unlock(&rp_ctx->request_queue_mutex);

    do {
        /* process requests while there are some */
        dequeued_prev = false;
        do {
            /* dequeue a request */
            pthread_mutex_lock(&rp_ctx->request_queue_mutex);
            dequeued = sr_cbuff_dequeue(rp_ctx->request_queue, &req);
            pthread_mutex_unlock(&rp_ctx->request_queue_mutex);

            if (dequeued) {
                /* process the request */
                if (NULL == req.msg) {
                    SR_LOG_DBG("Thread id=%lu received an empty request, exiting.", (unsigned long)pthread_self());
                    exit = true;
                } else {
                    rp_msg_dispatch(rp_ctx, req.session, req.msg);
                    if (NULL != req.session) {
                        /* update message count and release session if needed */
                        pthread_mutex_lock(&req.session->msg_count_mutex);
                        req.session->msg_count -= 1;
                        if (0 == req.session->msg_count && req.session->stop_requested) {
                            pthread_mutex_unlock(&req.session->msg_count_mutex);
                            rp_session_cleanup(rp_ctx, req.session);
                        } else {
                            pthread_mutex_unlock(&req.session->msg_count_mutex);
                        }
                    }
                }
                dequeued_prev = true;
            } else {
                /* no items in queue - spin for a while */
                if (dequeued_prev) {
                    /* only if the thread has actually processed something since the last wakeup */
                    size_t count = 0;
                    while ((0 == sr_cbuff_items_in_queue(rp_ctx->request_queue)) && (count < rp_ctx->thread_spin_limit)) {
                        count++;
                    }
                }
                pthread_mutex_lock(&rp_ctx->request_queue_mutex);
                if (0 != sr_cbuff_items_in_queue(rp_ctx->request_queue)) {
                    /* some items are in queue - process them */
                    pthread_mutex_unlock(&rp_ctx->request_queue_mutex);
                    dequeued = true;
                    continue;
                } else {
                    /* no items in queue - go to sleep */
                    rp_ctx->active_threads--;
                    pthread_mutex_unlock(&rp_ctx->request_queue_mutex);
                }
            }
        } while (dequeued && !exit);

        if (!exit) {
            /* wait until new request comes */
            SR_LOG_DBG("Thread id=%lu will wait.",  (unsigned long)pthread_self());

            /* wait for a signal */
            pthread_mutex_lock(&rp_ctx->request_queue_mutex);
            if (rp_ctx->stop_requested) {
                /* stop has been requested, do not wait anymore */
                pthread_mutex_unlock(&rp_ctx->request_queue_mutex);
                break;
            }
            pthread_cond_wait(&rp_ctx->request_queue_cv, &rp_ctx->request_queue_mutex);
            rp_ctx->active_threads++;

            SR_LOG_DBG("Thread id=%lu signaled.",  (unsigned long)pthread_self());
            pthread_mutex_unlock(&rp_ctx->request_queue_mutex);
        }
    } while (!exit);

    SR_LOG_DBG("Worker thread id=%lu is exiting.",  (unsigned long)pthread_self());

    return NULL;
}

int
rp_init(cm_ctx_t *cm_ctx, rp_ctx_t **rp_ctx_p)
{
    size_t i = 0, j = 0;
    rp_ctx_t *ctx = NULL;
    int ret = 0, rc = SR_ERR_OK;

    CHECK_NULL_ARG(rp_ctx_p);

    SR_LOG_DBG_MSG("Request Processor init started.");

    /* allocate the context */
    ctx = calloc(1, sizeof(*ctx));
    if (NULL == ctx) {
        SR_LOG_ERR_MSG("Cannot allocate memory for Request Processor context.");
        return SR_ERR_NOMEM;
    }
    ctx->cm_ctx = cm_ctx;

    /* initialize access control module */
    rc = ac_init(SR_DATA_SEARCH_DIR, &ctx->ac_ctx);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Access Control module initialization failed.");
        goto cleanup;
    }

    /* initialize request queue */
    rc = sr_cbuff_init(RP_INIT_REQ_QUEUE_SIZE, sizeof(rp_request_t), &ctx->request_queue);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("RP request queue initialization failed.");
        goto cleanup;
    }

    pthread_rwlockattr_t attr;
    pthread_rwlockattr_init(&attr);
#if defined(HAVE_PTHREAD_RWLOCKATTR_SETKIND_NP)
    pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
#endif
    ret = pthread_rwlock_init(&ctx->commit_lock, &attr);
    pthread_rwlockattr_destroy(&attr);
    CHECK_ZERO_MSG_GOTO(ret, rc, SR_ERR_INIT_FAILED, cleanup, "Commit rwlock initialization failed.");

    /* initialize Notification Processor */
    rc = np_init(ctx, &ctx->np_ctx);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Notification Processor initialization failed.");
        goto cleanup;
    }

    /* initialize Persistence Manager */
    rc = pm_init(ctx, SR_INTERNAL_SCHEMA_SEARCH_DIR, SR_DATA_SEARCH_DIR, &ctx->pm_ctx);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Persistence Manager initialization failed.");
        goto cleanup;
    }

    /* initialize Data Manager */
    rc = dm_init(ctx->ac_ctx, ctx->np_ctx, ctx->pm_ctx, SR_SCHEMA_SEARCH_DIR, SR_DATA_SEARCH_DIR, &ctx->dm_ctx);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Data Manager initialization failed.");
        goto cleanup;
    }

    /* run worker threads */
    pthread_mutex_init(&ctx->request_queue_mutex, NULL);
    pthread_cond_init(&ctx->request_queue_cv, NULL);

    for (i = 0; i < RP_THREAD_COUNT; i++) {
        rc = pthread_create(&ctx->thread_pool[i], NULL, rp_worker_thread_execute, ctx);
        if (0 != rc) {
            SR_LOG_ERR("Error by creating a new thread: %s", strerror(errno));
            for (j = 0; j < i; j++) {
                pthread_cancel(ctx->thread_pool[j]);
            }
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
    }

    *rp_ctx_p = ctx;
    return SR_ERR_OK;

cleanup:
    dm_cleanup(ctx->dm_ctx);
    np_cleanup(ctx->np_ctx);
    pm_cleanup(ctx->pm_ctx);
    ac_cleanup(ctx->ac_ctx);
    sr_cbuff_cleanup(ctx->request_queue);
    free(ctx);
    return rc;
}

void
rp_cleanup(rp_ctx_t *rp_ctx)
{
    size_t i = 0;
    rp_request_t req = { 0 };

    SR_LOG_DBG_MSG("Request Processor cleanup started, requesting cancel of each worker thread.");

    if (NULL != rp_ctx) {
        /* enqueue RP_THREAD_COUNT "empty" messages and send signal to all threads */
        pthread_mutex_lock(&rp_ctx->request_queue_mutex);
        rp_ctx->stop_requested = true;
        /* enqueue empty requests to request thread exits */
        for (i = 0; i < RP_THREAD_COUNT; i++) {
            sr_cbuff_enqueue(rp_ctx->request_queue, &req);
        }
        pthread_cond_broadcast(&rp_ctx->request_queue_cv);
        pthread_mutex_unlock(&rp_ctx->request_queue_mutex);

        /* wait for threads to exit */
        for (i = 0; i < RP_THREAD_COUNT; i++) {
            pthread_join(rp_ctx->thread_pool[i], NULL);
        }
        pthread_mutex_destroy(&rp_ctx->request_queue_mutex);
        pthread_cond_destroy(&rp_ctx->request_queue_cv);

        while (sr_cbuff_dequeue(rp_ctx->request_queue, &req)) {
            if (NULL != req.msg) {
                sr__msg__free_unpacked(req.msg, NULL);
            }
        }
        pthread_rwlock_destroy(&rp_ctx->commit_lock);
        dm_cleanup(rp_ctx->dm_ctx);
        np_cleanup(rp_ctx->np_ctx);
        pm_cleanup(rp_ctx->pm_ctx);
        ac_cleanup(rp_ctx->ac_ctx);
        sr_cbuff_cleanup(rp_ctx->request_queue);
        free(rp_ctx);
    }

    SR_LOG_DBG_MSG("Request Processor cleanup finished.");
}

int
rp_session_start(const rp_ctx_t *rp_ctx, const uint32_t session_id, const ac_ucred_t *user_credentials,
        const sr_datastore_t datastore, const uint32_t session_options, rp_session_t **session_p)
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

    pthread_mutex_init(&session->msg_count_mutex, NULL);
    session->user_credentials = user_credentials;
    session->id = session_id;
    session->datastore = datastore;
    session->options = session_options;

    rc = ac_session_init(rp_ctx->ac_ctx, user_credentials, &session->ac_session);
    if (SR_ERR_OK  != rc) {
        SR_LOG_ERR("Access Control session init failed for session id=%"PRIu32".", session_id);
        rp_session_cleanup(rp_ctx, session);
        return rc;
    }

    rc = dm_session_start(rp_ctx->dm_ctx, user_credentials, datastore, &session->dm_session);
    if (SR_ERR_OK  != rc) {
        SR_LOG_ERR("Init of dm_session failed for session id=%"PRIu32".", session_id);
        rp_session_cleanup(rp_ctx, session);
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

    /* sanity check - normally there should not be any unprocessed messages
     * within the session when calling rp_session_stop */
    pthread_mutex_lock(&session->msg_count_mutex);
    if (session->msg_count > 0) {
        /* cleanup will be called after last message has been processed so
         * that RP can survive this unexpected situation */
        SR_LOG_WRN("There are some (%"PRIu32") unprocessed messages for the session id=%"PRIu32" when"
                " session stop has been requested, this can lead to unspecified behavior - check RP caller code!!!",
                session->msg_count, session->id);
        session->stop_requested = true;
        pthread_mutex_unlock(&session->msg_count_mutex);
    } else {
        pthread_mutex_unlock(&session->msg_count_mutex);
        rp_session_cleanup(rp_ctx, session);
    }

    return SR_ERR_OK;
}

int
rp_msg_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    rp_request_t req = { 0 };
    struct timespec now = { 0 };
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG_NORET2(rc, rp_ctx, msg);

    if (SR_ERR_OK != rc) {
        if (NULL != msg) {
            sr__msg__free_unpacked(msg, NULL);
        }
        return rc;
    }

    if (NULL != session) {
        pthread_mutex_lock(&session->msg_count_mutex);
        session->msg_count += 1;
        pthread_mutex_unlock(&session->msg_count_mutex);
    }

    req.session = session;
    req.msg = msg;

    pthread_mutex_lock(&rp_ctx->request_queue_mutex);

    /* enqueue the request into buffer */
    rc = sr_cbuff_enqueue(rp_ctx->request_queue, &req);

    if (0 == rp_ctx->active_threads) {
        /* there is no active (non-sleeping) thread - if this is happening too
         * frequently, instruct the threads to spin before going to sleep */
        clock_gettime(CLOCK_MONOTONIC, &now);
        uint64_t diff = (1000000000L * (now.tv_sec - rp_ctx->last_thread_wakeup.tv_sec)) + now.tv_nsec - rp_ctx->last_thread_wakeup.tv_nsec;
        if (diff < RP_THREAD_SPIN_TIMEOUT) {
            /* a thread has been woken up in less than RP_THREAD_SPIN_TIMEOUT, increase the spin */
            if (0 == rp_ctx->thread_spin_limit) {
                /* no spin set yet, set to initial value */
                rp_ctx->thread_spin_limit = RP_THREAD_SPIN_MIN;
            } else if(rp_ctx->thread_spin_limit < RP_THREAD_SPIN_MAX) {
                /* double the spin limit */
                rp_ctx->thread_spin_limit *= 2;
            }
        } else {
            /* reset spin to 0 if wakaups are not too frequent */
            rp_ctx->thread_spin_limit = 0;
        }
        rp_ctx->last_thread_wakeup = now;
    }

    /* send signal if there is no active thread ready to process the request */
    if (0 == rp_ctx->active_threads ||
            (((sr_cbuff_items_in_queue(rp_ctx->request_queue) / rp_ctx->active_threads) > RP_REQ_PER_THREADS) &&
             rp_ctx->active_threads < RP_THREAD_COUNT)) {
        pthread_cond_signal(&rp_ctx->request_queue_cv);
    }

    pthread_mutex_unlock(&rp_ctx->request_queue_mutex);

    if (SR_ERR_OK != rc) {
        /* release the message by error */
        SR_LOG_ERR_MSG("Unable to process the message, skipping.");
        sr__msg__free_unpacked(msg, NULL);
    }

    return rc;
}
