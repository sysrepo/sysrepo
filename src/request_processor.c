/**
 * @file request_processor.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
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
#include <unistd.h>
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
#include "rp_dt_xpath.h"

#define RP_INIT_REQ_QUEUE_SIZE   10  /**< Initial size of the request queue. */

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
 * @brief Capability change type
 */
typedef enum rp_capability_change_type_e {
    SR_CAPABILITY_ADDED,
    SR_CAPABILITY_DELETED,
    SR_CAPABILITY_MODIFIED,
}rp_capability_change_type_t;

//! @cond doxygen_suppress
#define CAPABILITY_CHANGE_NOTIFICATION_XPATH "/ietf-netconf-notifications:netconf-capability-change"
#define CAPABILITY_ADDED_XPATH "/ietf-netconf-notifications:netconf-capability-change/added-capability"
#define CAPABILITY_DELETED_XPATH "/ietf-netconf-notifications:netconf-capability-change/deleted-capability"
#define CAPABILITY_MODIFIED_XPATH "/ietf-netconf-notifications:netconf-capability-change/modified-capability"
#define CAPABILITY_CHANGED_BY_SERVER "/ietf-netconf-notifications:netconf-capability-change/changed-by/server"

#define CONFIG_CHANGE_NOTIFICATION_XPATH "/ietf-netconf-notifications:netconf-config-change"
#define CONFIG_CHANGE_USERNAME_XPATH "/ietf-netconf-notifications:netconf-config-change/changed-by/username"
#define CONFIG_CHANGE_SESSION_ID_XPATH "/ietf-netconf-notifications:netconf-config-change/changed-by/session-id"
#define CONFIG_CHANGE_DATASTORE_XPATH "/ietf-netconf-notifications:netconf-config-change/datastore"
#define CONFIG_CHANGE_TARGET_XPATH "/ietf-netconf-notifications:netconf-config-change/edit[%d]/target"
#define CONFIG_CHANGE_OPERATION_XPATH "/ietf-netconf-notifications:netconf-config-change/edit[%d]/operation"
//! @endcond

/**
 * @brief Copy errors saved in the Data Manager session into the GPB response.
 */
static int
rp_resp_fill_errors(Sr__Msg *msg, dm_session_t *dm_session)
{
    CHECK_NULL_ARG2(msg, dm_session);
    sr_mem_ctx_t *sr_mem = (sr_mem_ctx_t *)msg->_sysrepo_mem_ctx;
    int rc = SR_ERR_OK;

    if (!dm_has_error(dm_session)) {
        return SR_ERR_OK;
    }

    msg->response->error = sr_calloc(sr_mem, 1, sizeof(Sr__Error));
    if (NULL == msg->response->error) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }
    sr__error__init(msg->response->error);
    rc = dm_copy_errors(dm_session, sr_mem, &msg->response->error->message, &msg->response->error->xpath);
    return rc;
}

/**
 * @brief Verifies that the requested commit context still exists. Copies data tree from commit context to the session if
 * needed.
 */
static int
rp_check_notif_session(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    int rc = SR_ERR_OK;
    dm_commit_context_t *c_ctx = NULL;
    char *module_name = NULL;
    const char *xpath = NULL;
    dm_commit_ctxs_t *dm_ctxs = NULL;
    uint32_t id = session->commit_id;

    rc = dm_get_commit_ctxs(rp_ctx->dm_ctx, &dm_ctxs);
    CHECK_RC_MSG_RETURN(rc, "Get commit ctx failed");
    pthread_rwlock_rdlock(&dm_ctxs->lock);

    rc = dm_get_commit_context(rp_ctx->dm_ctx, id, &c_ctx);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Get commit context failed");
    if (NULL == c_ctx) {
        SR_LOG_ERR("Commit context with id %d can not be found", id);
        dm_report_error(session->dm_session, "Commit data are not available anymore", NULL, SR_ERR_INTERNAL);
        goto cleanup;
    }

    if (SR__OPERATION__GET_ITEM == msg->request->operation) {
        xpath = msg->request->get_item_req->xpath;
    } else if (SR__OPERATION__GET_ITEMS == msg->request->operation) {
        xpath = msg->request->get_items_req->xpath;
    } else if (SR__OPERATION__GET_CHANGES == msg->request->operation) {
        xpath = msg->request->get_changes_req->xpath;
    } else if (SR__OPERATION__GET_SUBTREE == msg->request->operation) {
        xpath = msg->request->get_subtree_req->xpath;
    } else if (SR__OPERATION__GET_SUBTREES == msg->request->operation) {
        xpath = msg->request->get_subtrees_req->xpath;
    } else if (SR__OPERATION__GET_SUBTREE_CHUNK == msg->request->operation) {
        xpath = msg->request->get_subtree_chunk_req->xpath;
    } else {
        SR_LOG_WRN_MSG("Check notif session called for unknown operation");
    }

    rc = sr_copy_first_ns(xpath, &module_name);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Copy first ns failed for xpath %s", xpath);

    /* copy requested model from commit context */
    rc = dm_copy_if_not_loaded(rp_ctx->dm_ctx,  c_ctx->session, session->dm_session, module_name);

cleanup:
    free(module_name);
    pthread_rwlock_unlock(&dm_ctxs->lock);
    return rc;
}

/**
 * @brief Sets a timeout for processing of a operational data request.
 */
static int
rp_set_oper_request_timeout(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *request, uint32_t timeout)
{
    Sr__Msg *msg = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(rp_ctx, session, request);

    SR_LOG_DBG("Setting up a timeout for op. data request (%"PRIu32" seconds).", timeout);

    rc = sr_mem_new(0, &sr_mem);
    if (SR_ERR_OK == rc) {
        rc = sr_gpb_internal_req_alloc(sr_mem, SR__OPERATION__OPER_DATA_TIMEOUT, &msg);
    }
    if (SR_ERR_OK == rc) {
        msg->session_id = session->id;
        msg->internal_request->oper_data_timeout_req->request_id = request->request->_id;
        msg->internal_request->postpone_timeout = timeout;
        msg->internal_request->has_postpone_timeout = true;
        rc = cm_msg_send(rp_ctx->cm_ctx, msg);
    }

    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
        SR_LOG_ERR("Unable to setup a timeout for op. data request: %s.", sr_strerror(rc));
    }

    return rc;
}

static int
rp_create_capability_change_values(rp_ctx_t *rp_ctx, rp_session_t *session, const char *module_name, rp_capability_change_type_t change_type, sr_val_t **value, size_t *val_cnt)
{
    CHECK_NULL_ARG5(rp_ctx, session, module_name, value, val_cnt);
    int rc = SR_ERR_OK;
    sr_val_t *val = NULL;
    dm_schema_info_t *si = NULL;
    char *uri = NULL;

    rc = sr_new_values(2, &val);
    CHECK_RC_MSG_RETURN(rc, "Failed to allocate values");

    rc = sr_val_set_xpath(&val[0], CAPABILITY_CHANGED_BY_SERVER);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to set xpath");

    val[0].type = SR_LEAF_EMPTY_T;

    switch (change_type) {
    case SR_CAPABILITY_ADDED:
        rc = sr_val_set_xpath(&val[1], CAPABILITY_ADDED_XPATH);
        break;
    case SR_CAPABILITY_DELETED:
        rc = sr_val_set_xpath(&val[1], CAPABILITY_DELETED_XPATH);
        break;
    case SR_CAPABILITY_MODIFIED:
        rc = sr_val_set_xpath(&val[1], CAPABILITY_MODIFIED_XPATH);
        break;
    }
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create value for capability change notification");

    val[1].type = SR_STRING_T;

    rc = dm_get_module_and_lock(rp_ctx->dm_ctx, module_name, &si);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to lookup schema context for %s", module_name);

    rc = sr_create_uri_for_module(si->module, &uri);
    CHECK_RC_LOG_GOTO(rc, unlock, "Failed to create URI for module %s", si->module_name);

    rc = sr_mem_edit_string(val[0]._sr_mem, &val[1].data.string_val, uri);
    free(uri);

    SR_LOG_DBG("Generated notification %s %s", val[1].xpath, val[1].data.string_val);
unlock:
    pthread_rwlock_unlock(&si->model_lock);

cleanup:
    if (SR_ERR_OK != rc) {
        sr_free_values(val, 2);
    } else {
        *value = val;
        *val_cnt = 2;
    }

    return rc;
}

static int
rp_prepare_capability_change_notification(rp_ctx_t *rp_ctx, rp_session_t *session, const char *module_name, rp_capability_change_type_t change_type, Sr__Msg **msg)
{
    CHECK_NULL_ARG4(rp_ctx, session, module_name, msg);

    int rc = SR_ERR_OK;
    Sr__Msg *req = NULL;
    sr_val_t *values = NULL;
    size_t val_cnt = 0;

    rc = rp_create_capability_change_values(rp_ctx, session, module_name, change_type, &values, &val_cnt);
    CHECK_RC_MSG_RETURN(rc, "Failed to create value for capability change notification");

    rc = sr_gpb_req_alloc(values->_sr_mem, SR__OPERATION__EVENT_NOTIF, session->id, &req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to allocate message");

    req->session_id = session->id;
    req->request->event_notif_req->do_not_send_reply = true;
    req->request->event_notif_req->timestamp = time(NULL);

    rc = sr_mem_edit_string(values->_sr_mem, &req->request->event_notif_req->xpath, CAPABILITY_CHANGE_NOTIFICATION_XPATH);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to set xpath in the message");

    rc = sr_values_sr_to_gpb(values, val_cnt, &req->request->event_notif_req->values, &req->request->event_notif_req->n_values);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to transform values to gpb");

cleanup:
    sr_free_values(values, val_cnt);
    if (SR_ERR_OK != rc) {
        sr_msg_free(req);
    } else {
        *msg = req;
    }
    return rc;
}

static int
rp_send_netconf_change_notification(rp_ctx_t *rp_ctx, Sr__Msg *msg) {

    CHECK_NULL_ARG2(rp_ctx, msg);
    int rc = SR_ERR_OK;

    rc = rp_msg_process(rp_ctx, NULL, msg);
    return rc;
}

static int
rp_generate_capability_change_notification(rp_ctx_t *rp_ctx, rp_session_t *session, const char *module_name, rp_capability_change_type_t change_type)
{
    CHECK_NULL_ARG3(rp_ctx, session, module_name);

    int rc = SR_ERR_OK;
    Sr__Msg *msg = NULL;

    SR_LOG_DBG("Capability changes notification for module %s", module_name);

    rc = rp_prepare_capability_change_notification(rp_ctx, session, module_name, change_type, &msg);
    CHECK_RC_LOG_RETURN(rc, "Failed to prepare capability notification message for module %s", module_name);

    rc = rp_send_netconf_change_notification(rp_ctx, msg);
    return rc;
}

static size_t
rp_count_changes_in_difflists(sr_list_t *diff_lists)
{
    size_t diff_cnt = 0;
    if (NULL != diff_lists) {
        for (size_t i = 0; i < diff_lists->count; i++) {
            struct lyd_difflist *dl = (struct lyd_difflist *) diff_lists->data[i];
            size_t diff_index = 0;

            while (LYD_DIFF_END != dl->type[diff_index]) {
                diff_index++;
                if (LYD_DIFF_MOVEDAFTER2 != dl->type[diff_index]) {
                    diff_cnt++;
                }
            }
        }
    }

    return diff_cnt;
}

int
rp_generate_config_change_notification(rp_ctx_t *rp_ctx, rp_session_t *session, sr_list_t *diff_lists)
{
    CHECK_NULL_ARG3(rp_ctx, session, diff_lists);
    int rc = SR_ERR_OK;
    Sr__Msg *req = NULL;
    sr_val_t *values = NULL;
    size_t val_cnt = 3;

    size_t diff_count = rp_count_changes_in_difflists(diff_lists);
    SR_LOG_DBG("%zu instance of /ietf-netconf-notifications/netconf-config-change/edit list will be created", diff_count);
    if (0 == diff_count) {
        return SR_ERR_OK;
    }

    /* target + operation */
    val_cnt += diff_count * 2;

    values = calloc(val_cnt, sizeof(*values));
    CHECK_NULL_NOMEM_RETURN(values);

    rc = sr_val_set_xpath(&values[0], CONFIG_CHANGE_SESSION_ID_XPATH);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to set xpath");

    values[0].type = SR_UINT32_T;
    values[0].data.uint32_val = session->id;

    rc = sr_val_set_xpath(&values[1], CONFIG_CHANGE_USERNAME_XPATH);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to set xpath");

    const char *user_name = NULL != session->user_credentials->e_username ? session->user_credentials->e_username : session->user_credentials->r_username;
    rc = sr_val_set_str_data(&values[1], SR_STRING_T, user_name);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to set username value in config-changed notification");

    rc = sr_val_set_xpath(&values[2], CONFIG_CHANGE_DATASTORE_XPATH);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to set xpath");

    rc = sr_val_set_str_data(&values[2], SR_ENUM_T, SR_DS_STARTUP == session->datastore ? "startup" : "running");
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to set datstore value in config-changed notification");

    rc = sr_gpb_req_alloc(NULL, SR__OPERATION__EVENT_NOTIF, session->id, &req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to allocate message");

    req->session_id = session->id;
    req->request->event_notif_req->do_not_send_reply = true;
    req->request->event_notif_req->timestamp = time(NULL);

    rc = sr_mem_edit_string(NULL, &req->request->event_notif_req->xpath, CONFIG_CHANGE_NOTIFICATION_XPATH);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to set xpath in the message");

    /* index into values */
    size_t index = 3; /* start inserting on the third position */

    /* index for edit list */
    size_t list_cnt = 1;
    char *operation = NULL;

    for (size_t i = 0; i < diff_lists->count; i++) {
        struct lyd_difflist *dl = (struct lyd_difflist *) diff_lists->data[i];
        size_t diff_index = 0;

        while (LYD_DIFF_END != dl->type[diff_index]) {
            char *path = NULL;
            switch (dl->type[diff_index]) {
            case LYD_DIFF_CHANGED:
            case LYD_DIFF_MOVEDAFTER1:
                path = lyd_path(dl->first[diff_index]);
                operation = "merge";
                break;
            case LYD_DIFF_DELETED:
                path = lyd_path(dl->first[diff_index]);
                operation = "delete";
                break;
            case LYD_DIFF_CREATED:
                path = lyd_path(dl->second[diff_index]);
                operation = "create";
                break;
            case LYD_DIFF_MOVEDAFTER2:
            case LYD_DIFF_END:
                /* do nothing*/
                break;
            }

            if (NULL != path) {
                SR_LOG_DBG("CONFIG CHANGE: %s %s", operation, path);

                sr_val_build_xpath(&values[index], CONFIG_CHANGE_TARGET_XPATH, list_cnt);
                sr_val_set_str_data(&values[index], SR_INSTANCEID_T, path);

                sr_val_build_xpath(&values[index+1], CONFIG_CHANGE_OPERATION_XPATH, list_cnt);
                sr_val_set_str_data(&values[index+1], SR_ENUM_T, operation);
                index += 2;
                list_cnt++;
            }
            free(path);
            diff_index++;
        }
    }

    rc = sr_values_sr_to_gpb(values, val_cnt, &req->request->event_notif_req->values, &req->request->event_notif_req->n_values);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to transform values to gpb");

    rc = rp_send_netconf_change_notification(rp_ctx, req);
    req = NULL;
    SR_LOG_DBG("Config changed notification generated session %"PRIu32, session->id);
cleanup:
    sr_free_values(values, val_cnt);
    if (SR_ERR_OK != rc) {
        sr_msg_free(req);
    }

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
    int rc = SR_ERR_OK, rc_tmp = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->list_schemas_req);

    SR_LOG_DBG_MSG("Processing list_schemas request.");

    /* retrieve schemas from DM */
    rc = dm_list_schemas(rp_ctx->dm_ctx, session->dm_session, &schemas, &schema_cnt);

    /* allocate the response */
    rc_tmp = sr_gpb_resp_alloc(schemas ? schemas[0]._sr_mem : NULL, SR__OPERATION__LIST_SCHEMAS, session->id, &resp);
    if (SR_ERR_OK != rc_tmp) {
        sr_free_schemas(schemas, schema_cnt);
        SR_LOG_ERR_MSG("Cannot allocate list_schemas response.");
        return SR_ERR_NOMEM;
    }

    /* copy schemas to response */
    if (SR_ERR_OK == rc && schema_cnt > 0) {
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

    /**
     * Allocate the response.
     * @note: Cannot use memory context here as ::dm_get_schema calls lys_print_mem which
     * cannot be told to use our memory allocation primitives
     */
    rc = sr_gpb_resp_alloc(NULL, SR__OPERATION__GET_SCHEMA, session->id, &resp);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate get_schema response.");
        return SR_ERR_NOMEM;
    }

    /* set response result code */
    resp->response->result = dm_get_schema(rp_ctx->dm_ctx,
            msg->request->get_schema_req->module_name,
            msg->request->get_schema_req->revision,
            msg->request->get_schema_req->submodule_name,
            msg->request->get_schema_req->submodule_revision,
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
rp_module_install_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    md_module_key_t *module_key = NULL;
    sr_list_t *implicitly_installed = NULL, *implicitly_removed = NULL;
    int rc = SR_ERR_OK, oper_rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->module_install_req);

    SR_LOG_DBG_MSG("Processing module_install request.");

    /* allocate the response */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__MODULE_INSTALL, session->id, &resp);
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
        SR_LOG_ERR_MSG("Cannot allocate module_install response.");
        return SR_ERR_NOMEM;
    }

    const char *module_name = msg->request->module_install_req->module_name;
    /* check for write permission */
    oper_rc = ac_check_module_permissions(session->ac_session, module_name, AC_OPER_READ_WRITE);
    if (SR_ERR_OK != oper_rc) {
        SR_LOG_ERR("Access control check failed for xpath '%s'", module_name);
    }

    /* install the module in the DM */
    if (SR_ERR_OK == oper_rc) {
        if (msg->request->module_install_req->installed) {
            oper_rc = dm_install_module(rp_ctx->dm_ctx,
                        session->dm_session,
                        module_name,
                        msg->request->module_install_req->revision,
                        msg->request->module_install_req->file_name,
                        &implicitly_installed);
            if (SR_ERR_OK == oper_rc) {
                rp_generate_capability_change_notification(rp_ctx, session, module_name, SR_CAPABILITY_ADDED);
            }
        } else {
            Sr__Msg *notif = NULL;
            rp_prepare_capability_change_notification(rp_ctx, session, module_name, SR_CAPABILITY_DELETED, &notif);

            oper_rc = dm_uninstall_module(rp_ctx->dm_ctx,
                        module_name,
                        msg->request->module_install_req->revision,
                        &implicitly_removed);
            if (SR_ERR_OK == oper_rc) {
                rp_send_netconf_change_notification(rp_ctx, notif);
            } else {
                sr_msg_free(notif);
            }
        }
    }

    /* set response code */
    resp->response->result = oper_rc;

    /* send the response */
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    /* notify subscribers */
    if (SR_ERR_OK == oper_rc) {
        rc = np_module_install_notify(rp_ctx->np_ctx, msg->request->module_install_req->module_name,
                msg->request->module_install_req->revision,
                msg->request->module_install_req->installed ? SR_MS_IMPLEMENTED : SR_MS_UNINSTALLED);
        for (size_t i = 0; SR_ERR_OK == rc && NULL != implicitly_installed && i < implicitly_installed->count; ++i) {
            module_key = (md_module_key_t *)implicitly_installed->data[i];
            rc = np_module_install_notify(rp_ctx->np_ctx, module_key->name, module_key->revision_date,
                                          SR_MS_IMPORTED);
        }
        for (size_t i = 0; SR_ERR_OK == rc && NULL != implicitly_removed && i < implicitly_removed->count; ++i) {
            module_key = (md_module_key_t *)implicitly_removed->data[i];
            rc = np_module_install_notify(rp_ctx->np_ctx, module_key->name, module_key->revision_date,
                                          SR_MS_UNINSTALLED);
        }
    }

    /* cleanup */
    md_free_module_key_list(implicitly_installed);
    md_free_module_key_list(implicitly_removed);

    return rc;
}

/**
 * @brief Processes a feature_enable request.
 */
static int
rp_feature_enable_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    bool notify = true;
    int rc = SR_ERR_OK, oper_rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->feature_enable_req);

    SR_LOG_DBG_MSG("Processing feature_enable request.");

    /* allocate the response */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__FEATURE_ENABLE, session->id, &resp);
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
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
        if ((req->enabled && SR_ERR_DATA_EXISTS == oper_rc) || (!req->enabled && SR_ERR_DATA_MISSING == oper_rc)) {
            oper_rc = SR_ERR_OK;
            notify = false;
        }
        if (SR_ERR_OK != oper_rc) {
            /* rollback of the change in DM */
            dm_feature_enable(rp_ctx->dm_ctx, req->module_name, req->feature_name, !req->enabled);
        } else {
            rp_generate_capability_change_notification(rp_ctx, session, req->module_name, SR_CAPABILITY_MODIFIED);
        }
    }

    /* set response code */
    resp->response->result = oper_rc;

    /* send the response */
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    /* notify subscribers */
    if (SR_ERR_OK == oper_rc && notify) {
        rc = np_feature_enable_notify(rp_ctx->np_ctx, msg->request->feature_enable_req->module_name,
                msg->request->feature_enable_req->feature_name, msg->request->feature_enable_req->enabled);
    }

    return rc;
}

static void
rp_handle_get_call_state(rp_session_t *session)
{
    if (NULL != session) {
        if (RP_REQ_FINISHED == session->state) {
            session->state = RP_REQ_NEW;
        } else if (RP_REQ_TIMED_OUT == session->state) {
            SR_LOG_ERR("Time out waiting for operational data expired before all responses have been received, "
                    "session id = %u, req = %" PRIu64, session->id, session->req->request->_id);
            session->state = RP_REQ_DATA_LOADED;
            /* log an error and continue processing with the data we have */
        }
    }
}

/**
 * @brief Processes a get_item request.
 */
static int
rp_get_item_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg, bool *skip_msg_cleanup)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->get_item_req);

    SR_LOG_DBG("Processing get_item request (id=%" PRIu64 ").", msg->request->_id);

    Sr__Msg *resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;

    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__GET_ITEM, session->id, &resp);
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
        SR_LOG_ERR_MSG("Gpb response allocation failed");
        return rc;
    }

    sr_val_t *value = NULL;
    char *xpath = msg->request->get_item_req->xpath;

    if (session->options & SR__SESSION_FLAGS__SESS_NOTIFICATION) {
        rc = rp_check_notif_session(rp_ctx, session, msg);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Check notif session failed");
    }

    MUTEX_LOCK_TIMED_CHECK_GOTO(&session->cur_req_mutex, rc, cleanup);
    rp_handle_get_call_state(session);

    /* store current request to session */
    session->req = msg;

    /* get value from data manager */
    rc = rp_dt_get_value_wrapper(rp_ctx, session, sr_mem, xpath, &value);
    if (SR_ERR_OK != rc && SR_ERR_NOT_FOUND != rc) {
        SR_LOG_ERR("Get item failed for '%s', session id=%"PRIu32".", xpath, session->id);
    }

    if (RP_REQ_WAITING_FOR_DATA == session->state) {
        SR_LOG_DBG_MSG("Request paused, waiting for data");
        /* we are waiting for operational data do not free the request */
        *skip_msg_cleanup = true;
        /* setup timeout */
        rc = rp_set_oper_request_timeout(rp_ctx, session, msg, SR_OPER_DATA_PROVIDE_TIMEOUT);
        sr_free_val(value);
        sr_msg_free(resp);
        pthread_mutex_unlock(&session->cur_req_mutex);
        return rc;
    }

    pthread_mutex_unlock(&session->cur_req_mutex);

    /* copy value to gpb */
    if (SR_ERR_OK == rc) {
        rc = sr_dup_val_t_to_gpb(value, &resp->response->get_item_resp->value);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Copying sr_val_t to gpb failed for xpath '%s'", xpath);
        }
    }

cleanup:
    session->req = NULL;
    /* set response code */
    resp->response->result = rc;

    rc = rp_resp_fill_errors(resp, session->dm_session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Copying errors to gpb failed");
    }

    sr_free_val(value);
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    return rc;
}

/**
 * @brief Processes a get_items request.
 */
static int
rp_get_items_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg, bool *skip_msg_cleanup)
{
    sr_val_t *values = NULL;
    size_t count = 0, limit = 0, offset = 0;
    char *xpath = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->get_items_req);

    SR_LOG_DBG_MSG("Processing get_items request.");

    Sr__Msg *resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;

    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__GET_ITEMS, session->id, &resp);
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
        SR_LOG_ERR_MSG("Gpb response allocation failed");
        return rc;
    }

    if (session->options & SR__SESSION_FLAGS__SESS_NOTIFICATION) {
        rc = rp_check_notif_session(rp_ctx, session, msg);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Check notif session failed");
    }

    MUTEX_LOCK_TIMED_CHECK_GOTO(&session->cur_req_mutex, rc, cleanup);
    rp_handle_get_call_state(session);

    /* store current request to session */
    session->req = msg;

    xpath = msg->request->get_items_req->xpath;
    offset = msg->request->get_items_req->offset;
    limit = msg->request->get_items_req->limit;

    if (msg->request->get_items_req->has_offset || msg->request->get_items_req->has_limit) {
        rc = rp_dt_get_values_wrapper_with_opts(rp_ctx, session, &session->get_items_ctx, sr_mem, xpath,
                offset, limit, &values, &count);
    } else {
        rc = rp_dt_get_values_wrapper(rp_ctx, session, sr_mem, xpath, &values, &count);
    }

    if (SR_ERR_OK != rc) {
        if (SR_ERR_NOT_FOUND != rc) {
            SR_LOG_ERR("Get items failed for '%s', session id=%"PRIu32".", xpath, session->id);
        }
        pthread_mutex_unlock(&session->cur_req_mutex);
        goto cleanup;
    }

    if (RP_REQ_WAITING_FOR_DATA == session->state) {
        SR_LOG_DBG_MSG("Request paused, waiting for data");
        /* we are waiting for operational data do not free the request */
        *skip_msg_cleanup = true;
        /* setup timeout */
        rc = rp_set_oper_request_timeout(rp_ctx, session, msg, SR_OPER_DATA_PROVIDE_TIMEOUT);
        sr_free_values(values, count);
        sr_msg_free(resp);
        pthread_mutex_unlock(&session->cur_req_mutex);
        return rc;
    }

    SR_LOG_DBG("%zu items found for '%s', session id=%"PRIu32".", count, xpath, session->id);
    pthread_mutex_unlock(&session->cur_req_mutex);

    /* copy values to gpb */
    rc = sr_values_sr_to_gpb(values, count, &resp->response->get_items_resp->values, &resp->response->get_items_resp->n_values);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Copying values to GPB failed.");

cleanup:
    session->req = NULL;

    /* set response code */
    resp->response->result = rc;

    rc = rp_resp_fill_errors(resp, session->dm_session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Copying errors to gpb failed");
    }

    sr_free_values(values, count);
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    return rc;
}

/**
 * @brief Processes a get_subtree request.
 */
static int
rp_get_subtree_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg, bool *skip_msg_cleanup)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->get_subtree_req);

    SR_LOG_DBG_MSG("Processing get_subtree request.");

    Sr__Msg *resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;

    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__GET_SUBTREE, session->id, &resp);
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
        SR_LOG_ERR_MSG("Gpb response allocation failed");
        return rc;
    }

    sr_node_t *tree = NULL;
    char *xpath = msg->request->get_subtree_req->xpath;

    if (session->options & SR__SESSION_FLAGS__SESS_NOTIFICATION) {
        rc = rp_check_notif_session(rp_ctx, session, msg);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Check notif session failed");
    }

    MUTEX_LOCK_TIMED_CHECK_GOTO(&session->cur_req_mutex, rc, cleanup);
    rp_handle_get_call_state(session);

    /* store current request to session */
    session->req = msg;

    /* get subtree from data manager */
    rc = rp_dt_get_subtree_wrapper(rp_ctx, session, sr_mem, xpath, &tree);
    if (SR_ERR_OK != rc && SR_ERR_NOT_FOUND != rc) {
        SR_LOG_ERR("Get subtree failed for '%s', session id=%"PRIu32".", xpath, session->id);
    }

    if (RP_REQ_WAITING_FOR_DATA == session->state) {
        SR_LOG_DBG_MSG("Request paused, waiting for data");
        /* we are waiting for operational data do not free the request */
        *skip_msg_cleanup = true;
        /* setup timeout */
        rc = rp_set_oper_request_timeout(rp_ctx, session, msg, SR_OPER_DATA_PROVIDE_TIMEOUT);
        sr_free_tree(tree);
        sr_msg_free(resp);
        pthread_mutex_unlock(&session->cur_req_mutex);
        return rc;
    }

    pthread_mutex_unlock(&session->cur_req_mutex);

    /* copy value to gpb */
    if (SR_ERR_OK == rc) {
        rc = sr_dup_tree_to_gpb(tree, &resp->response->get_subtree_resp->tree);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Copying sr_node_t to gpb failed for xpath '%s'", xpath);
        }
    }

cleanup:
    session->req = NULL;
    /* set response code */
    resp->response->result = rc;

    rc = rp_resp_fill_errors(resp, session->dm_session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Copying errors to gpb failed");
    }

    sr_free_tree(tree);
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    return rc;
}

/**
 * @brief Processes a get_subtrees request.
 */
static int
rp_get_subtrees_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg, bool *skip_msg_cleanup)
{
    sr_node_t *trees = NULL;
    size_t count = 0;
    char *xpath = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->get_subtrees_req);

    SR_LOG_DBG_MSG("Processing get_subtrees request.");

    Sr__Msg *resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;

    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__GET_SUBTREES, session->id, &resp);
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
        SR_LOG_ERR_MSG("Gpb response allocation failed");
        return rc;
    }

    if (session->options & SR__SESSION_FLAGS__SESS_NOTIFICATION) {
        rc = rp_check_notif_session(rp_ctx, session, msg);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Check notif session failed");
    }

    MUTEX_LOCK_TIMED_CHECK_GOTO(&session->cur_req_mutex, rc, cleanup);
    rp_handle_get_call_state(session);

    /* store current request to session */
    session->req = msg;

    xpath = msg->request->get_subtrees_req->xpath;
    rc = rp_dt_get_subtrees_wrapper(rp_ctx, session, sr_mem, xpath, &trees, &count);

    if (SR_ERR_OK != rc) {
        if (SR_ERR_NOT_FOUND != rc) {
            SR_LOG_ERR("Get subtrees failed for '%s', session id=%"PRIu32".", xpath, session->id);
        }
        pthread_mutex_unlock(&session->cur_req_mutex);
        goto cleanup;
    }

    if (RP_REQ_WAITING_FOR_DATA == session->state) {
        SR_LOG_DBG_MSG("Request paused, waiting for data");
        /* we are waiting for operational data do not free the request */
        *skip_msg_cleanup = true;
        /* setup timeout */
        rc = rp_set_oper_request_timeout(rp_ctx, session, msg, SR_OPER_DATA_PROVIDE_TIMEOUT);
        sr_free_trees(trees, count);
        sr_msg_free(resp);
        pthread_mutex_unlock(&session->cur_req_mutex);
        return rc;
    }

    SR_LOG_DBG("%zu subtrees found for '%s', session id=%"PRIu32".", count, xpath, session->id);
    pthread_mutex_unlock(&session->cur_req_mutex);

    /* copy subtrees to gpb */
    rc = sr_trees_sr_to_gpb(trees, count, &resp->response->get_subtrees_resp->trees, &resp->response->get_subtrees_resp->n_trees);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Copying values to GPB failed.");

cleanup:
    session->req = NULL;

    /* set response code */
    resp->response->result = rc;

    rc = rp_resp_fill_errors(resp, session->dm_session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Copying errors to gpb failed");
    }

    sr_free_trees(trees, count);
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    return rc;
}

/**
 * @brief Processes a get_subtree_chunk request.
 */
static int
rp_get_subtree_chunk_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg, bool *skip_msg_cleanup)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->get_subtree_chunk_req);

    SR_LOG_DBG_MSG("Processing get_subtree_chunk request.");

    Sr__Msg *resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;

    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__GET_SUBTREE_CHUNK, session->id, &resp);
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
        SR_LOG_ERR_MSG("Gpb response allocation failed");
        return rc;
    }

    sr_node_t *chunks = NULL;
    size_t chunk_cnt = 0;
    char **chunk_ids = NULL;
    char *xpath = msg->request->get_subtree_chunk_req->xpath;
    bool single = msg->request->get_subtree_chunk_req->single;
    size_t slice_offset = msg->request->get_subtree_chunk_req->slice_offset;
    size_t slice_width = msg->request->get_subtree_chunk_req->slice_width;
    size_t child_limit = msg->request->get_subtree_chunk_req->child_limit;
    size_t depth_limit = msg->request->get_subtree_chunk_req->depth_limit;

    if (session->options & SR__SESSION_FLAGS__SESS_NOTIFICATION) {
        rc = rp_check_notif_session(rp_ctx, session, msg);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Check notif session failed");
    }

    MUTEX_LOCK_TIMED_CHECK_GOTO(&session->cur_req_mutex, rc, cleanup);
    rp_handle_get_call_state(session);

    /* store current request to session */
    session->req = msg;

    /* get subtree chunk(s) from data manager */
    if (single) {
        chunk_ids = sr_calloc(sr_mem, 1, sizeof(char *));
        if (NULL == chunk_ids) {
            SR_LOG_ERR("Unable to allocate memory in %s", __func__);
            rc = SR_ERR_NOMEM;
        } else {
            rc = rp_dt_get_subtree_wrapper_with_opts(rp_ctx, session, sr_mem, xpath, slice_offset, slice_width, child_limit,
                    depth_limit, &chunks, &chunk_ids[0]);
            if (SR_ERR_OK == rc) {
                chunk_cnt = 1;
            } else {
                if (NULL == sr_mem) {
                    free(chunk_ids);
                }
                chunk_ids = NULL;
            }
        }
    } else {
        rc = rp_dt_get_subtrees_wrapper_with_opts(rp_ctx, session, sr_mem, xpath, slice_offset, slice_width, child_limit,
                depth_limit, &chunks, &chunk_cnt, &chunk_ids);
    }
    if (SR_ERR_OK != rc && SR_ERR_NOT_FOUND != rc) {
        SR_LOG_ERR("Get subtree chunk failed for '%s', session id=%"PRIu32".", xpath, session->id);
    }

    if (RP_REQ_WAITING_FOR_DATA == session->state) {
        SR_LOG_DBG_MSG("Request paused, waiting for data");
        /* we are waiting for operational data do not free the request */
        *skip_msg_cleanup = true;
        /* setup timeout */
        rc = rp_set_oper_request_timeout(rp_ctx, session, msg, SR_OPER_DATA_PROVIDE_TIMEOUT);
        sr_free_trees(chunks, chunk_cnt);
        if (NULL == sr_mem && chunk_ids) {
            for (size_t i = 0; i < chunk_cnt; ++i) {
                free(chunk_ids[i]);
            }
            free(chunk_ids);
        }
        sr_msg_free(resp);
        pthread_mutex_unlock(&session->cur_req_mutex);
        return rc;
    }

    pthread_mutex_unlock(&session->cur_req_mutex);

    /* copy chunk(s) to gpb */
    if (SR_ERR_OK == rc) {
        rc = sr_trees_sr_to_gpb(chunks, chunk_cnt, &resp->response->get_subtree_chunk_resp->chunk,
                &resp->response->get_subtree_chunk_resp->n_chunk);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Copying subtree chunk(s) to gpb failed for xpath '%s'", xpath);
        }
    }
    resp->response->get_subtree_chunk_resp->n_xpath = chunk_cnt;
    resp->response->get_subtree_chunk_resp->xpath = chunk_ids;

cleanup:
    session->req = NULL;
    /* set response code */
    resp->response->result = rc;

    rc = rp_resp_fill_errors(resp, session->dm_session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Copying errors to gpb failed");
    }

    sr_free_trees(chunks, chunk_cnt);
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    return rc;
}

/**
 * @brief Processes a set_item request.
 */
static int
rp_set_item_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    char *xpath = NULL;
    sr_val_t *value = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->set_item_req);

    SR_LOG_DBG_MSG("Processing set_item request.");

    xpath = msg->request->set_item_req->xpath;

    /* allocate the response */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__SET_ITEM, session->id, &resp);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Allocation of set_item response failed.");
        sr_mem_free(sr_mem);
        return SR_ERR_NOMEM;
    }

    if (NULL != msg->request->set_item_req->value) {
        /* copy the value from gpb */
        rc = sr_dup_gpb_to_val_t((sr_mem_ctx_t *)msg->_sysrepo_mem_ctx, msg->request->set_item_req->value, &value);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Copying gpb value to sr_val_t failed for xpath '%s'", xpath);
        }

        /* set the value in data manager */
        if (SR_ERR_OK == rc) {
            rc = rp_dt_set_item_wrapper(rp_ctx, session, xpath, value, NULL, msg->request->set_item_req->options);
        }
    }
    else{
        /* when creating list or presence container value can be NULL */
        rc = rp_dt_set_item_wrapper(rp_ctx, session, xpath, NULL, NULL, msg->request->set_item_req->options);
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
 * @brief Processes a set_item_str request.
 */
static int
rp_set_item_str_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    char *xpath = NULL;
    char *value = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->set_item_str_req);

    SR_LOG_DBG_MSG("Processing set_item_str request.");

    xpath = msg->request->set_item_str_req->xpath;

    /* allocate the response */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__SET_ITEM_STR, session->id, &resp);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Allocation of set_item_str response failed.");
        sr_mem_free(sr_mem);
        return SR_ERR_NOMEM;
    }

    if (NULL != msg->request->set_item_str_req->value) {
        /* copy the value from gpb */
        value = strdup(msg->request->set_item_str_req->value);
        CHECK_NULL_NOMEM_GOTO(value, rc, cleanup);
    }

    /* set the value in data manager, when creating list or presence container value can be NULL */
    rc = rp_dt_set_item_wrapper(rp_ctx, session, xpath, NULL, value, msg->request->set_item_str_req->options);

    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Set item failed for '%s', session id=%"PRIu32".", xpath, session->id);
    }

cleanup:
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
    sr_mem_ctx_t *sr_mem = NULL;
    char *xpath = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->delete_item_req);

    SR_LOG_DBG_MSG("Processing delete_item request.");

    xpath = msg->request->delete_item_req->xpath;

    /* allocate the response */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__DELETE_ITEM, session->id, &resp);
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
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
    sr_mem_ctx_t *sr_mem = NULL;
    char *xpath = NULL;
    char *relative_item = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->move_item_req);

    SR_LOG_DBG_MSG("Processing move_item request.");

    xpath = msg->request->move_item_req->xpath;
    relative_item = msg->request->move_item_req->relative_item;

    /* allocate the response */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__MOVE_ITEM, session->id, &resp);
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
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
rp_validate_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->validate_req);

    SR_LOG_DBG_MSG("Processing validate request.");

    /* allocate the response */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__VALIDATE, session->id, &resp);
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
        SR_LOG_ERR_MSG("Allocation of validate response failed.");
        return SR_ERR_NOMEM;
    }

    rc = rp_dt_remove_loaded_state_data(rp_ctx, session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("An error occurred while removing state data: %s", sr_strerror(rc));
    }

    sr_error_info_t *errors = NULL;
    size_t err_cnt = 0;
    rc = dm_validate_session_data_trees(rp_ctx->dm_ctx, session->dm_session, &errors, &err_cnt);

    /* set response code */
    resp->response->result = rc;

    /* copy error information to GPB  (if any) */
    if (err_cnt > 0) {
        sr_gpb_fill_errors(errors, err_cnt, sr_mem, &resp->response->validate_resp->errors, &resp->response->validate_resp->n_errors);
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
rp_commit_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg, bool *skip_msg_cleanup)
{
    Sr__Msg *resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;
    dm_commit_context_t *c_ctx = NULL;
    sr_error_info_t *errors = NULL;
    size_t err_cnt = 0;
    bool locked = false;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->commit_req);

    SR_LOG_DBG_MSG("Processing commit request.");

    /* allocate the response */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__COMMIT, session->id, &resp);
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
        SR_LOG_ERR_MSG("Allocation of commit response failed.");
        return SR_ERR_NOMEM;
    }

    if (rp_ctx->block_further_commits) {
        rc = SR_ERR_OPERATION_FAILED;
    }
    CHECK_RC_MSG_GOTO(rc, cleanup, "Stop requested, commits are blocked.");

    MUTEX_LOCK_TIMED_CHECK_GOTO(&session->cur_req_mutex, rc, cleanup);
    locked = true;

    if (RP_REQ_RESUMED == session->state) {
        rc = dm_get_commit_context(rp_ctx->dm_ctx, session->commit_id, &c_ctx);
        CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to resume commit, commit ctx with id %"PRIu32" not found.", session->commit_id);
        pthread_mutex_lock(&c_ctx->mutex);
    } else {
        rc = rp_dt_remove_loaded_state_data(rp_ctx, session);
        if (SR_ERR_OK != rc ) {
            SR_LOG_ERR_MSG("An error occurred while removing state data");
        }
    }

    if (SR_ERR_OK == rc ) {
        session->req = msg;
        rc = rp_dt_commit(rp_ctx, session, &c_ctx, false, &errors, &err_cnt);
    }
    if (SR_ERR_OK == rc && RP_REQ_WAITING_FOR_VERIFIERS == session->state) {
        SR_LOG_DBG_MSG("Commit request paused, waiting for verifiers");
        /* we are waiting for verifiers data do not free the request */
        *skip_msg_cleanup = true;
        sr_msg_free(resp);
        pthread_mutex_unlock(&session->cur_req_mutex);
        return SR_ERR_OK;
    }

cleanup:
    session->state = RP_REQ_FINISHED;
    session->req = NULL;
    if (locked) {
        pthread_mutex_unlock(&session->cur_req_mutex);
    }
    /* set response code */
    resp->response->result = rc;

    /* copy error information to GPB  (if any) */
    if (err_cnt > 0) {
        sr_gpb_fill_errors(errors, err_cnt, sr_mem, &resp->response->commit_resp->errors, &resp->response->commit_resp->n_errors);
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
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->discard_changes_req);

    SR_LOG_DBG_MSG("Processing discard_changes request.");

    /* allocate the response */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__DISCARD_CHANGES, session->id, &resp);
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
        SR_LOG_ERR_MSG("Allocation of discard_changes response failed.");
        return SR_ERR_NOMEM;
    }

    rc = dm_discard_changes(rp_ctx->dm_ctx, session->dm_session, NULL);

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
 * @brief Processes a copy-config request.
 */
static int
rp_copy_config_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg, bool *skip_msg_cleanup)
{
    Sr__Msg *resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;
    sr_error_info_t *errors = NULL;
    size_t err_cnt = 0;
    bool locked = false;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->copy_config_req);

    SR_LOG_DBG_MSG("Processing copy_config request.");

    /* allocate the response */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__COPY_CONFIG, session->id, &resp);
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
        SR_LOG_ERR_MSG("Allocation of copy_config response failed.");
        return SR_ERR_NOMEM;
    }

    /* do this check only if this really will be a commit */
    if (SR__DATA_STORE__RUNNING == msg->request->copy_config_req->dst_datastore && rp_ctx->block_further_commits) {
        rc = SR_ERR_OPERATION_FAILED;
    }
    CHECK_RC_MSG_GOTO(rc, cleanup, "Stop requested, commits are blocked.");

    MUTEX_LOCK_TIMED_CHECK_GOTO(&session->cur_req_mutex, rc, cleanup);
    locked = true;

    session->req = msg;
    rc = rp_dt_copy_config(rp_ctx, session, msg->request->copy_config_req->module_name,
                sr_datastore_gpb_to_sr(msg->request->copy_config_req->src_datastore),
                sr_datastore_gpb_to_sr(msg->request->copy_config_req->dst_datastore), &errors, &err_cnt);

    if (SR_ERR_OK == rc && RP_REQ_WAITING_FOR_VERIFIERS == session->state) {
        SR_LOG_DBG_MSG("Copy_config request paused, waiting for verifiers");
        /* we are waiting for verifiers data do not free the request */
        *skip_msg_cleanup = true;
        sr_msg_free(resp);
        pthread_mutex_unlock(&session->cur_req_mutex);
        return SR_ERR_OK;
    }

cleanup:
    session->state = RP_REQ_FINISHED;
    session->req = NULL;
    if (locked) {
        pthread_mutex_unlock(&session->cur_req_mutex);
    }
    /* set response code */
    resp->response->result = rc;

    /* copy error information to GPB  (if any) */
    if (err_cnt > 0) {
        sr_gpb_fill_errors(errors, err_cnt, sr_mem, &resp->response->copy_config_resp->errors,
                &resp->response->copy_config_resp->n_errors);
        sr_free_errors(errors, err_cnt);
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
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->session_refresh_req);

    SR_LOG_DBG_MSG("Processing session_data_refresh request.");

    /* allocate the response */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__SESSION_REFRESH, session->id, &resp);
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
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
        sr_gpb_fill_errors(errors, err_cnt, sr_mem, &resp->response->session_refresh_resp->errors,
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
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->session_switch_ds_req);

    SR_LOG_DBG_MSG("Processing session_switch_ds request.");

    /* allocate the response */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__SESSION_SWITCH_DS, session->id, &resp);
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
        SR_LOG_ERR_MSG("Allocation of session_switch_ds response failed.");
        return SR_ERR_NOMEM;
    }

    rp_dt_switch_datastore(rp_ctx, session, sr_datastore_gpb_to_sr(msg->request->session_switch_ds_req->datastore));

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

static int
rp_session_set_opts(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->session_set_opts_req);

    SR_LOG_DBG_MSG("Procession session set opts request.");

    /* allocate the response */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__SESSION_SET_OPTS, session->id, &resp);
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
        SR_LOG_ERR_MSG("Allocation of session_set_opts response failed.");
        return SR_ERR_NOMEM;
    }

    /* white list options that can be set */
    session->options = msg->request->session_set_opts_req->options & SR_SESS_MUTABLE_OPTS;

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
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->lock_req);

    SR_LOG_DBG_MSG("Processing lock request.");

    /* allocate the response */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__LOCK, session->id, &resp);
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
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
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->unlock_req);

    SR_LOG_DBG_MSG("Processing unlock request.");

    /* allocate the response */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__UNLOCK, session->id, &resp);
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
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
    sr_mem_ctx_t *sr_mem = NULL;
    Sr__SubscribeReq *subscribe_req = NULL;
    np_subscr_options_t options = NP_SUBSCR_DEFAULT;
    const char *username = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->subscribe_req);

    SR_LOG_DBG_MSG("Processing subscribe request.");

    /* allocate the response */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__SUBSCRIBE, session->id, &resp);
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
        SR_LOG_ERR_MSG("Allocation of subscribe response failed.");
        return SR_ERR_NOMEM;
    }
    subscribe_req = msg->request->subscribe_req;
    if (SR__SUBSCRIPTION_TYPE__EVENT_NOTIF_SUBS == subscribe_req->type) {
        if (NULL != session->user_credentials->e_username) {
            username = session->user_credentials->e_username;
        } else {
            username = session->user_credentials->r_username;
        }
    }

    /* set subscribe options */
    if (subscribe_req->has_enable_running && subscribe_req->enable_running) {
        options |= NP_SUBSCR_ENABLE_RUNNING;
    }
    if (SR__SUBSCRIPTION_TYPE__RPC_SUBS == subscribe_req->type ||
        SR__SUBSCRIPTION_TYPE__ACTION_SUBS == subscribe_req->type) {
        options |= NP_SUBSCR_EXCLUSIVE;
    }
    if (subscribe_req->has_enable_event && subscribe_req->enable_event) {
        options |= NP_SUBSCR_EV_EVENT;
    }

    /* subscribe to the notification */
    rc = np_notification_subscribe(rp_ctx->np_ctx, session, subscribe_req->type,
            subscribe_req->destination, subscribe_req->subscription_id,
            subscribe_req->module_name, subscribe_req->xpath, username,
            (subscribe_req->has_notif_event ? subscribe_req->notif_event : SR__NOTIFICATION_EVENT__APPLY_EV),
            (subscribe_req->has_priority ? subscribe_req->priority : 0),
            sr_api_variant_gpb_to_sr(subscribe_req->api_variant),
            options);

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
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->unsubscribe_req);

    SR_LOG_DBG_MSG("Processing unsubscribe request.");

    /* allocate the response */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__UNSUBSCRIBE, session->id, &resp);
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
        SR_LOG_ERR_MSG("Allocation of unsubscribe response failed.");
        return SR_ERR_NOMEM;
    }

    /* unsubscribe from the notifications */
    rc = np_notification_unsubscribe(rp_ctx->np_ctx, session, msg->request->unsubscribe_req->type,
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
 * @brief Processes a check-enabled-running request.
 */
static int
rp_check_enabled_running_req_process(const rp_ctx_t *rp_ctx, const rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;
    bool enabled = false;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->check_enabled_running_req);

    SR_LOG_DBG_MSG("Processing check-enabled-running request.");

    /* allocate the response */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__CHECK_ENABLED_RUNNING, session->id, &resp);
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
        SR_LOG_ERR_MSG("Allocation of check-enabled-running response failed.");
        return SR_ERR_NOMEM;
    }

    /* query data manager */
    rc = dm_has_enabled_subtree(rp_ctx->dm_ctx, msg->request->check_enabled_running_req->module_name, NULL, &enabled);
    if (SR_ERR_OK == rc) {
        resp->response->check_enabled_running_resp->enabled = enabled;
    }

    /* set response code */
    resp->response->result = rc;

    /* copy DM errors, if any */
    rc = rp_resp_fill_errors(resp, session->dm_session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Copying errors to gpb failed");
    }

    /* send the response */
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);
    return rc;
}

/**
 * @brief Process get changes request.
 */
static int
rp_get_changes_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;
    dm_commit_ctxs_t *dm_ctxs = NULL;
    dm_commit_context_t *c_ctx = NULL;
    sr_list_t *changes = NULL;
    bool locked = false;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->get_changes_req);
    SR_LOG_DBG_MSG("Processing get changes request.");

    /* allocate the response */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__GET_CHANGES, session->id, &resp);
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
        SR_LOG_ERR_MSG("Allocation of get changes response failed.");
        return SR_ERR_NOMEM;
    }

    char *xpath = msg->request->get_changes_req->xpath;

    uint32_t id = session->commit_id;

    if (session->options & SR__SESSION_FLAGS__SESS_NOTIFICATION) {
        rc = rp_check_notif_session(rp_ctx, session, msg);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Check notif session failed");
    } else {
        rc = dm_report_error(session->dm_session, "Get changes call can be issued only on notification session", NULL, SR_ERR_UNSUPPORTED);
        goto cleanup;
    }

    rc = dm_get_commit_ctxs(rp_ctx->dm_ctx, &dm_ctxs);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Get commit ctx failed");
    pthread_rwlock_rdlock(&dm_ctxs->lock);
    locked = true;

    rc = dm_get_commit_context(rp_ctx->dm_ctx, id, &c_ctx);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Get commit context failed");
    if (NULL == c_ctx) {
        SR_LOG_ERR("Commit context with id %d can not be found", id);
        dm_report_error(session->dm_session, "Commit data are not available anymore", NULL, SR_ERR_INTERNAL);
        goto cleanup;
    }

    /* get changes */
    rc = rp_dt_get_changes(rp_ctx, session, c_ctx, xpath,
            msg->request->get_changes_req->offset,
            msg->request->get_changes_req->limit,
            &changes);

    if (SR_ERR_OK == rc) {
        /* copy values to gpb */
        rc = sr_changes_sr_to_gpb(changes, sr_mem, &resp->response->get_changes_resp->changes, &resp->response->get_changes_resp->n_changes);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Copying values to GPB failed.");
        }
    }

cleanup:
    if (locked) {
        pthread_rwlock_unlock(&dm_ctxs->lock);
    }

    /* set response code */
    resp->response->result = rc;

    rc = rp_resp_fill_errors(resp, session->dm_session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Copying errors to gpb failed");
    }

    /* send the response */
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    sr_list_cleanup(changes);
    return rc;
}

static int
rp_match_subscription_rpc(const rp_ctx_t *rp_ctx, np_subscription_t *subscription, const char *xpath, bool *matched)
{
    CHECK_NULL_ARG4(rp_ctx, subscription, xpath, matched);
    int rc = SR_ERR_OK;
    dm_schema_info_t *schema_info = NULL;
    struct lys_node *subs_node = NULL;
    struct lys_node *rpc_node = NULL;

    *matched = false;

    if (NULL != subscription->xpath) {
        rc = rp_dt_validate_node_xpath_lock(rp_ctx->dm_ctx, NULL, subscription->xpath, &schema_info, &subs_node);
        CHECK_RC_LOG_RETURN(rc, "Failed to validate xpath %s", subscription->xpath);

        rc = rp_dt_validate_node_xpath(rp_ctx->dm_ctx, NULL, xpath, NULL, &rpc_node);
        CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to validate xpath %s", xpath);

        SR_LOG_DBG("Matching subscription %s with xpath %s %s", subscription->xpath, xpath, (subs_node == rpc_node) ? "matched" : "not matched");
        *matched = subs_node == rpc_node;
    }

cleanup:
    if (NULL != schema_info) {
        pthread_rwlock_unlock(&schema_info->model_lock);
    }
    return rc;
}

/**
 * @brief Processes a Check-exec-permission request.
 */
static int
rp_check_exec_perm_req_process(const rp_ctx_t *rp_ctx, const rp_session_t *session, Sr__Msg *msg)
{
    Sr__Msg *resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    nacm_ctx_t *nacm_ctx = NULL;
    nacm_action_t nacm_action = NACM_ACTION_PERMIT;
    char *nacm_rule = NULL, *nacm_rule_info = NULL;
    int rc = SR_ERR_OK, oper_rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->check_exec_perm_req);

    SR_LOG_DBG_MSG("Processing check-exec-permission request.");
    Sr__CheckExecPermReq *req = msg->request->check_exec_perm_req;

    /* allocate the response */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__CHECK_EXEC_PERMISSION, session->id, &resp);
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
        SR_LOG_ERR_MSG("Cannot allocate check-exec-permission response.");
        return SR_ERR_NOMEM;
    }

    oper_rc = dm_get_nacm_ctx(rp_ctx->dm_ctx, &nacm_ctx);
    if (SR_ERR_OK == oper_rc && NULL != nacm_ctx && (session->options & SR_SESS_ENABLE_NACM)) {
        oper_rc = nacm_check_rpc(nacm_ctx, session->user_credentials, req->xpath,
                &nacm_action, &nacm_rule, &nacm_rule_info);
        if (SR_ERR_OK == oper_rc && NACM_ACTION_DENY == nacm_action) {
            nacm_report_exec_access_denied(session->user_credentials, session->dm_session,
                    req->xpath, nacm_rule, nacm_rule_info);
        }
        free(nacm_rule);
        free(nacm_rule_info);
    }
    if (SR_ERR_OK != oper_rc) {
        SR_LOG_WRN("Failed to verify if the user is allowed to execute operation: %s", req->xpath);
    }

    /* set response data */
    resp->response->result = oper_rc;
    resp->response->check_exec_perm_resp->permitted = (nacm_action == NACM_ACTION_PERMIT);

    /* send the response */
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    return rc;
}

/**
 * @brief Processes a RPC/Action request.
 */
static int
rp_rpc_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg, bool *skip_msg_cleanup)
{
    const char *xpath = NULL;
    char *module_name = NULL;
    sr_api_variant_t msg_api_variant = SR_API_VALUES;
    sr_val_t *input = NULL, *with_def = NULL;
    sr_node_t *input_tree = NULL, *with_def_tree = NULL;
    size_t input_cnt = 0, with_def_cnt = 0, with_def_tree_cnt = 0;
    sr_list_t *subscriptions_list = NULL;
    np_subscription_t *subscription = NULL;
    Sr__Msg *req = NULL, *resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    const char *op_name = NULL;
    bool action = false;
    nacm_ctx_t *nacm_ctx = NULL;
    nacm_action_t nacm_action = NACM_ACTION_PERMIT;
    char *nacm_rule = NULL, *nacm_rule_info = NULL;
    int rc = SR_ERR_OK, rc_tmp = SR_ERR_OK;

    CHECK_NULL_ARG_NORET5(rc, rp_ctx, session, msg, msg->request, msg->request->rpc_req);
    if (SR_ERR_OK != rc) {
        goto finalize;
    }

    xpath = msg->request->rpc_req->xpath;
    action = msg->request->rpc_req->action;
    op_name = (action ? "Action" : "RPC");
    SR_LOG_DBG("Processing %s request (%s).", op_name, xpath);

    /* reuse context from msg for req (or resp) */
    sr_mem = (sr_mem_ctx_t *)msg->_sysrepo_mem_ctx;

    /* parse input arguments */
    msg_api_variant = sr_api_variant_gpb_to_sr(msg->request->rpc_req->orig_api_variant);
    switch (msg_api_variant) {
        case SR_API_VALUES:
            rc = sr_values_gpb_to_sr(sr_mem, msg->request->rpc_req->input, msg->request->rpc_req->n_input,
                    &input, &input_cnt);
            break;
        case SR_API_TREES:
            rc = sr_trees_gpb_to_sr(sr_mem, msg->request->rpc_req->input_tree, msg->request->rpc_req->n_input_tree,
                    &input_tree, &input_cnt);
            break;
    }
    CHECK_RC_LOG_GOTO(rc, finalize, "Failed to parse %s (%s) input arguments from GPB message.",
                      op_name, msg->request->rpc_req->xpath);

    session->req = msg;

    MUTEX_LOCK_TIMED_CHECK_GOTO(&session->cur_req_mutex, rc, finalize);
    rp_handle_get_call_state(session);

    /* validate RPC/Action request */
    switch (msg_api_variant) {
        case SR_API_VALUES:
            if (action) {
                rc = dm_validate_action(rp_ctx, session, msg->request->rpc_req->xpath,
                                 input, input_cnt, true, sr_mem, &with_def, &with_def_cnt,
                                 &with_def_tree, &with_def_tree_cnt);

            } else {
                rc = dm_validate_rpc(rp_ctx, session, msg->request->rpc_req->xpath,
                                     input, input_cnt, true, sr_mem, &with_def, &with_def_cnt,
                                     &with_def_tree, &with_def_tree_cnt);
            }
            break;
        case SR_API_TREES:
            if (action) {
                rc = dm_validate_action_tree(rp_ctx, session, msg->request->rpc_req->xpath,
                                     input_tree, input_cnt, true, sr_mem, &with_def, &with_def_cnt,
                                     &with_def_tree, &with_def_tree_cnt);
            } else {
                rc = dm_validate_rpc_tree(rp_ctx, session, msg->request->rpc_req->xpath,
                                     input_tree, input_cnt, true, sr_mem, &with_def, &with_def_cnt,
                                     &with_def_tree, &with_def_tree_cnt);
            }
            break;
    }
    if (rc != SR_ERR_OK) {
        SR_LOG_ERR("Validation of an %s (%s) message failed.", op_name, msg->request->rpc_req->xpath);
    }

    if (RP_REQ_WAITING_FOR_DATA == session->state) {
        SR_LOG_DBG_MSG("Request paused, waiting for data");
        /* we are waiting for operational data do not free the request */
        *skip_msg_cleanup = true;
        /* setup timeout */
        rc = rp_set_oper_request_timeout(rp_ctx, session, msg, SR_OPER_DATA_PROVIDE_TIMEOUT);

        if (SR_API_VALUES == msg_api_variant) {
            sr_free_values(input, input_cnt);
        } else {
            sr_free_trees(input_tree, input_cnt);
        }
        sr_free_values(with_def, with_def_cnt);
        sr_free_trees(with_def_tree, with_def_tree_cnt);
        pthread_mutex_unlock(&session->cur_req_mutex);
        return rc;
    }

    pthread_mutex_unlock(&session->cur_req_mutex);

    if (rc != SR_ERR_OK) {
        goto finalize;
    }

    /* get module name */
    rc = sr_copy_first_ns(msg->request->rpc_req->xpath, &module_name);
    CHECK_RC_LOG_GOTO(rc, finalize, "Failed to obtain module name for %s request (%s).", op_name,
            msg->request->rpc_req->xpath);

    /* authorize (write permissions are required to deliver the RPC/Action) */
    rc = ac_check_module_permissions(session->ac_session, module_name, AC_OPER_READ_WRITE);
    CHECK_RC_LOG_GOTO(rc, finalize, "Access control check failed for module name '%s'", module_name);

    /* NACM access control */
    rc = dm_get_nacm_ctx(rp_ctx->dm_ctx, &nacm_ctx);
    CHECK_RC_MSG_GOTO(rc, finalize, "Failed to get NACM context");

    if (NULL != nacm_ctx && (session->options & SR_SESS_ENABLE_NACM)) {
        /* check if the user is authorized to execute the RPC */
        rc = nacm_check_rpc(nacm_ctx, session->user_credentials, xpath, &nacm_action, &nacm_rule, &nacm_rule_info);
        CHECK_RC_LOG_GOTO(rc, finalize, "Failed to verify if the user is allowed to execute RPC: %s", xpath);
        if (NACM_ACTION_DENY == nacm_action) {
            nacm_report_exec_access_denied(session->user_credentials, session->dm_session, xpath, nacm_rule,
                    nacm_rule_info);
            rc = SR_ERR_UNAUTHORIZED;
            goto finalize;
        }
    }

    /* fill-in subscription details into the request */
    bool subscription_match = false;
    /* get RPC/Action subscription */
    rc = pm_get_subscriptions(rp_ctx->pm_ctx, session->user_credentials, module_name,
            action ? SR__SUBSCRIPTION_TYPE__ACTION_SUBS : SR__SUBSCRIPTION_TYPE__RPC_SUBS, &subscriptions_list);
    CHECK_RC_LOG_GOTO(rc, finalize, "Failed to get subscriptions for %s request (%s).", op_name,
            msg->request->rpc_req->xpath);

    if (NULL != subscriptions_list) {
        for (size_t i = 0; i < subscriptions_list->count; i++) {
            subscription = subscriptions_list->data[i];

            rc = rp_match_subscription_rpc(rp_ctx, subscription, msg->request->rpc_req->xpath, &subscription_match);
            CHECK_RC_MSG_GOTO(rc, finalize, "Failed to match rpc xpath");

            if (!subscription_match) {
                continue;
            }

            /* duplicate msg into req with the new input values */
            rc = sr_gpb_req_alloc(sr_mem, action ? SR__OPERATION__ACTION : SR__OPERATION__RPC, session->id, &req);
            CHECK_RC_LOG_GOTO(rc, finalize, "Failed to duplicate %s request (%s).", op_name,
                    msg->request->rpc_req->xpath);
            req->request->rpc_req->action = action;
            /*  - xpath */
            if (sr_mem) {
                req->request->rpc_req->xpath = msg->request->rpc_req->xpath;
            } else {
                req->request->rpc_req->xpath = strdup(msg->request->rpc_req->xpath);
                CHECK_NULL_NOMEM_ERROR(req->request->rpc_req->xpath, rc);
                CHECK_RC_LOG_GOTO(rc, finalize, "Failed to duplicate %s request xpath (%s).", op_name,
                        msg->request->rpc_req->xpath);
            }
            /*  - api variant */
            req->request->rpc_req->orig_api_variant = msg->request->rpc_req->orig_api_variant;
            /*  - arguments */
            switch (subscription->api_variant) {
                case SR_API_VALUES:
                    rc = sr_values_sr_to_gpb(with_def, with_def_cnt, &req->request->rpc_req->input,
                                             &req->request->rpc_req->n_input);
                    break;
                case SR_API_TREES:
                    rc = sr_trees_sr_to_gpb(with_def_tree, with_def_tree_cnt, &req->request->rpc_req->input_tree,
                                            &req->request->rpc_req->n_input_tree);
                    break;
            }
            CHECK_RC_LOG_GOTO(rc, finalize, "Failed to duplicate %s request (%s) input arguments.", op_name,
                    msg->request->rpc_req->xpath);
            /* subscription details */
            sr_mem_edit_string(sr_mem, &req->request->rpc_req->subscriber_address, subscription->dst_address);
            CHECK_NULL_NOMEM_GOTO(req->request->rpc_req->subscriber_address, rc, finalize);
            req->request->rpc_req->subscription_id = subscription->dst_id;
            req->request->rpc_req->has_subscription_id = true;
            subscription_match = true;
            break;
        }
    }
    CHECK_RC_LOG_GOTO(rc, finalize, "Failed to process subscription data for %s request (%s).", op_name,
            msg->request->rpc_req->xpath);

    if (!subscription_match) {
        /* no subscription for this RPC/Action */
        SR_LOG_ERR("No subscription found for %s delivery (xpath = '%s').", op_name, msg->request->rpc_req->xpath);
        rc = SR_ERR_NOT_FOUND;
        goto finalize;
    }

finalize:
    /* free all the allocated data */
    np_subscriptions_list_cleanup(subscriptions_list);
    free(module_name);
    free(nacm_rule);
    free(nacm_rule_info);
    if (SR_API_VALUES == msg_api_variant) {
        sr_free_values(input, input_cnt);
    } else {
        sr_free_trees(input_tree, input_cnt);
    }
    sr_free_values(with_def, with_def_cnt);
    sr_free_trees(with_def_tree, with_def_tree_cnt);

    session->req = NULL;

    if (SR_ERR_OK == rc) {
        /* forward the request to the subscriber */
        rc = cm_msg_send(rp_ctx->cm_ctx, req);
    } else {
        /* release the request */
        if (NULL != req) {
            sr_msg_free(req);
        }
        /* send the response with error */
        rc_tmp = sr_gpb_resp_alloc(sr_mem, action ? SR__OPERATION__ACTION : SR__OPERATION__RPC,
                                   session->id, &resp);
        if (SR_ERR_OK != rc_tmp) {
            SR_LOG_ERR_MSG("Failed to allocate RPC response message");
        }
        if (SR_ERR_OK == rc_tmp) {
            rc_tmp = rp_resp_fill_errors(resp, session->dm_session);
            if (SR_ERR_OK != rc_tmp) {
                SR_LOG_WRN_MSG("Copying errors to gpb failed");
            }
            resp->response->result = rc;
            resp->response->rpc_resp->action = action;
            if (sr_mem) {
                resp->response->rpc_resp->xpath = msg->request->rpc_req->xpath;
            } else {
                resp->response->rpc_resp->xpath = strdup(msg->request->rpc_req->xpath);
            }
            /* send the response */
            rc = cm_msg_send(rp_ctx->cm_ctx, resp);
        }
    }

    return rc;
}

/**
 * @brief Checks if the received xpath was requested and find corresponding schema node
 */
static int
rp_data_provide_resp_validate(rp_ctx_t *rp_ctx, rp_session_t *session, const char *xpath, sr_val_t *values, size_t values_cnt, struct lys_node **sch_node)
{
    CHECK_NULL_ARG3(rp_ctx, session, sch_node);
    if (values_cnt > 0) {
        CHECK_NULL_ARG(values);
    }
    int rc = SR_ERR_OK;
    bool found = false;
    dm_schema_info_t *si = NULL;
    struct lys_node *value_sch_node = NULL;
    struct ly_set *set = NULL;

    rc = dm_get_module_and_lock(rp_ctx->dm_ctx, session->module_name, &si);
    CHECK_RC_MSG_RETURN(rc, "Get schema info failed");

    /* verify that provided xpath was requested */
    for (size_t i = 0; i < session->state_data_ctx.requested_xpaths->count; i++) {
        char *xp = (char *)session->state_data_ctx.requested_xpaths->data[i];
        if (0 == strcmp(xp, xpath)) {
            found = true;
            rc = sr_find_schema_node(si->module, NULL, xp, 0, &set);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Schema node not found for %s", xp);
                rc = SR_ERR_INVAL_ARG;
                goto unlock;
            }
            *sch_node = set->set.s[0];
            ly_set_free(set);
            free(xp);
            sr_list_rm_at(session->state_data_ctx.requested_xpaths, i);
            break;
        }
    }
    if (!found) {
        SR_LOG_ERR("Data provider sent data for unexpected xpath %s", xpath);
        rc = SR_ERR_INVAL_ARG;
        goto unlock;
    }

    /* test that all values are under requested xpath */
    for (size_t i = 0; i < values_cnt; i++) {
        rc = sr_find_schema_node(si->module, NULL, values[i].xpath, 0, &set);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Value with xpath %s received from provider doesn't correspond to any schema node",
                    values[i].xpath);
            rc = SR_ERR_INVAL_ARG;
            goto unlock;
        }
        value_sch_node = set->set.s[0];
        ly_set_free(set);

        if (!rp_dt_depth_under_subtree(*sch_node, value_sch_node, NULL)) {
            SR_LOG_ERR("Unexpected value with xpath %s received from provider", values[i].xpath);
            rc = SR_ERR_INVAL_ARG;
            goto unlock;
        }
    }

unlock:
    pthread_rwlock_unlock(&si->model_lock);
    return rc;
}

/**
 * @brief Generate requests for nested data
 */
static int
rp_data_provide_request_nested(rp_ctx_t *rp_ctx, rp_session_t *session, const char *xpath, struct lys_node *sch_node)
{
    int rc = SR_ERR_OK;
    struct lys_node *iter = NULL;
    size_t subs_index = 0;
    char **xpaths = NULL;
    size_t xp_count = 0;
    char *request_xp = NULL;

    /* prepare xpaths where nested data will be requested */
    if (LYS_LIST == sch_node->nodetype) {
        rc = rp_dt_create_instance_xps(session, sch_node, &xpaths, &xp_count);
        CHECK_RC_MSG_RETURN(rc, "Failed to create xpaths for instances of sch node");
    } else {
        xpaths = calloc(1, sizeof(*xpaths));
        CHECK_NULL_NOMEM_GOTO(xpaths, rc, cleanup);

        xpaths[0] = strdup(xpath);
        CHECK_NULL_NOMEM_GOTO(xpaths[0], rc, cleanup);
        xp_count = 1;
    }

    /* loop through the node children */
    while ((iter = (struct lys_node *)lys_getnext(iter, sch_node, NULL, 0))) {
        subs_index = session->state_data_ctx.subscription_nodes->count;
        if ((LYS_LIST | LYS_CONTAINER) & iter->nodetype) {
            /* find subscription where subsequent request will be addressed
             * this must exists since the a parent node has been already requested
             */
            if (!rp_dt_find_subscription_covering_subtree(session, iter, &subs_index)) {
                SR_LOG_ERR("Failed to find subscription for nested requests %s", xpath);
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
        } else if (session->state_data_ctx.overlapping_leaf_subscription && ((LYS_LEAF | LYS_LEAFLIST) & iter->nodetype)) {
            /* check if we have exact match for leaf or leaf-list node */
            rp_dt_find_exact_match_subscription_for_node(session, iter, &subs_index);
        }
        if (subs_index < session->state_data_ctx.subscription_nodes->count) {
            for (size_t i = 0; i < xp_count; i++) {
                size_t len = strlen(xpaths[i]) + strlen(iter->name) + 2 /* slash + zero byte */;

                if (lys_node_module(sch_node) != lys_node_module(iter)) {
                    len += strlen(lys_node_module(iter)->name) + 1;
                }

                request_xp = calloc(len, sizeof(*request_xp));
                CHECK_NULL_NOMEM_GOTO(request_xp, rc, cleanup);

                if (lys_node_module(sch_node) == lys_node_module(iter)) {
                    snprintf(request_xp, len, "%s/%s", xpaths[i], iter->name);
                } else {
                    snprintf(request_xp, len, "%s/%s:%s", xpaths[i], lys_node_module(iter)->name, iter->name);
                }

                rc = np_data_provider_request(rp_ctx->np_ctx, session->state_data_ctx.subscriptions->data[subs_index],
                        session, request_xp);
                SR_LOG_DBG("Sending request for nested state data: %s using subs index %zu", request_xp, subs_index);

                session->dp_req_waiting += 1;

                rc = sr_list_add(session->state_data_ctx.requested_xpaths, request_xp);
                CHECK_RC_MSG_GOTO(rc, cleanup, "List add failed");
                request_xp = NULL;
            }
        }
    }

cleanup:
    for (size_t i = 0; i < xp_count; i++) {
        free(xpaths[i]);
    }
    free(xpaths);
    free(request_xp);

    return rc;
}

/**
 * @brief Processes an operational data provider response.
 */
static int
rp_data_provide_resp_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    sr_val_t *values = NULL;
    size_t values_cnt = 0;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->response, msg->response->data_provide_resp);

    /* copy values from GPB to sysrepo */
    rc = sr_values_gpb_to_sr((sr_mem_ctx_t *)msg->_sysrepo_mem_ctx, msg->response->data_provide_resp->values,
            msg->response->data_provide_resp->n_values, &values, &values_cnt);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to transform gpb to sr_val_t");

    MUTEX_LOCK_TIMED_CHECK_GOTO(&session->cur_req_mutex, rc, cleanup);
    if (RP_REQ_WAITING_FOR_DATA != session->state || NULL == session->req
            ||  msg->response->data_provide_resp->request_id != session->req->request->_id ) {
        SR_LOG_ERR("State data arrived after timeout expiration or session id=%u is invalid "
                "(msg=%" PRIu64 ", session->req=%" PRIu64 ").",
                session->id, msg->response->data_provide_resp->request_id, session->req ? session->req->request->_id : 0);
        goto error;
    }

    char *xpath = msg->response->data_provide_resp->xpath;
    struct lys_node *sch_node = NULL;

    session->dp_req_waiting -= 1;
    SR_LOG_DBG("Data provide response received, waiting for %zu more data providers.", session->dp_req_waiting);

    rc = rp_data_provide_resp_validate(rp_ctx, session, xpath, values, values_cnt, &sch_node);
    CHECK_RC_MSG_GOTO(rc, finish, "Data validation failed.");

    for (size_t i = 0; i < values_cnt; i++) {
        SR_LOG_DBG("Received value from data provider for xpath '%s'.", values[i].xpath);
        rc = rp_dt_set_item(rp_ctx->dm_ctx, session->dm_session, values[i].xpath, SR_EDIT_DEFAULT, &values[i], NULL, true);
        if (SR_ERR_OK != rc) {
            //TODO: maybe validate if this path corresponds to the operational data
            SR_LOG_WRN("Failed to set operational data for xpath '%s'.", values[i].xpath);
        }
    }

    /* handle nested data */
    if ((LYS_CONTAINER | LYS_LIST) & sch_node->nodetype) {
        rc = rp_data_provide_request_nested(rp_ctx, session, xpath, sch_node);
        if (SR_ERR_OK != rc) {
            SR_LOG_WRN("Requesting nested data for xpath %s was not successful", xpath);
        }
    }

finish:
    if (0 == session->dp_req_waiting) {
        //TODO validate data
        rp_dt_free_state_data_ctx_content(&session->state_data_ctx);
        if (RP_REQ_WAITING_FOR_DATA == session->state) {
            SR_LOG_DBG("All data from data providers has been received session id = %u, "
                    "re-enqueue the request id = %" PRIu64, session->id, session->req->request->_id);
            session->state = RP_REQ_DATA_LOADED;
            rp_msg_process(rp_ctx, session, session->req);
            session->req = NULL;
        }
    }

error:
    pthread_mutex_unlock(&session->cur_req_mutex);

cleanup:
    sr_free_values(values, values_cnt);

    return rc;
}

/**
 * @brief Processes a RPC/Action response.
 */
static int
rp_rpc_resp_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    sr_api_variant_t msg_api_variant = SR_API_VALUES;
    sr_val_t *output = NULL, *with_def = NULL;
    sr_node_t *output_tree = NULL, *with_def_tree = NULL;
    size_t output_cnt = 0, with_def_cnt = 0, with_def_tree_cnt = 0;
    Sr__Msg *resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    bool action = false;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG_NORET5(rc, rp_ctx, session, msg, msg->response, msg->response->rpc_resp);
    if (SR_ERR_OK != rc) {
        /* release the message since it won't be released in dispatch */
        sr_msg_free(msg);
        return rc;
    }

    action = msg->response->rpc_resp->action;
    SR_LOG_DBG("Processing %s response (%s).", (action ? "Action" : "RPC"), msg->response->rpc_resp->xpath);

    /* reuse memory context from msg for resp */
    sr_mem = (sr_mem_ctx_t *)msg->_sysrepo_mem_ctx;

    /* validate the RPC/Action response */
    if (msg->response->rpc_resp->n_output) {
        rc = sr_values_gpb_to_sr(sr_mem, msg->response->rpc_resp->output,
                                 msg->response->rpc_resp->n_output, &output, &output_cnt);
    } else if (msg->response->rpc_resp->n_output_tree) {
        msg_api_variant = SR_API_TREES;
        rc = sr_trees_gpb_to_sr(sr_mem, msg->response->rpc_resp->output_tree,
                                 msg->response->rpc_resp->n_output_tree, &output_tree, &output_cnt);
    }
    if (SR_ERR_OK == rc) {
        if (SR_API_VALUES == msg_api_variant) {
            if (action) {
                rc = dm_validate_action(rp_ctx, session, msg->response->rpc_resp->xpath,
                        output, output_cnt, false, sr_mem, &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt);
            } else {
                rc = dm_validate_rpc(rp_ctx, session, msg->response->rpc_resp->xpath,
                        output, output_cnt, false, sr_mem, &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt);
            }
        } else {
            if (action) {
                rc = dm_validate_action_tree(rp_ctx, session, msg->response->rpc_resp->xpath,
                        output_tree, output_cnt, false, sr_mem, &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt);
            } else {
                rc = dm_validate_rpc_tree(rp_ctx, session, msg->response->rpc_resp->xpath,
                        output_tree, output_cnt, false, sr_mem, &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt);
            }
        }
    }

    /* duplicate msg into resp with the new output values */
    if (SR_ERR_OK == rc) {
        rc = sr_gpb_resp_alloc(sr_mem, action ? SR__OPERATION__ACTION : SR__OPERATION__RPC, session->id, &resp);
    }
    if (SR_ERR_OK == rc) {
        resp->response->rpc_resp->action = action;
        if (sr_mem) {
            resp->response->rpc_resp->xpath = msg->response->rpc_resp->xpath;
        } else {
            resp->response->rpc_resp->xpath = strdup(msg->response->rpc_resp->xpath);
            CHECK_NULL_NOMEM_ERROR(resp->response->rpc_resp->xpath, rc);
        }
        resp->response->rpc_resp->orig_api_variant = msg->response->rpc_resp->orig_api_variant;
        resp->response->result = msg->response->result;
        if (SR_ERR_OK != msg->response->result && NULL != msg->response->error) {
            rc = dm_report_error(session->dm_session,
                                 msg->response->error->message,
                                 msg->response->error->xpath,
                                 msg->response->result);
        }
    }
    if (SR_ERR_OK == rc) {
        if (SR_API_VALUES == sr_api_variant_gpb_to_sr(msg->response->rpc_resp->orig_api_variant)) {
            rc = sr_values_sr_to_gpb(with_def, with_def_cnt, &resp->response->rpc_resp->output,
                    &resp->response->rpc_resp->n_output);
        } else {
            rc = sr_trees_sr_to_gpb(with_def_tree, with_def_tree_cnt, &resp->response->rpc_resp->output_tree,
                    &resp->response->rpc_resp->n_output_tree);
        }
    }
    if (SR_API_VALUES == msg_api_variant) {
        sr_free_values(output, output_cnt);
    } else {
        sr_free_trees(output_tree, output_cnt);
    }
    sr_free_values(with_def, with_def_cnt);
    sr_free_trees(with_def_tree, with_def_tree_cnt);

    if ((SR_ERR_OK == rc) || (NULL != resp)) {
        sr_msg_free(msg);
        msg = NULL;
    } else {
        resp = msg;
    }

    /* overwrite response code only in case of internal error */
    if (SR_ERR_OK != rc) {
        resp->response->result = rc;
    }

    /* copy DM errors, if any */
    rc = rp_resp_fill_errors(resp, session->dm_session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Copying errors to gpb failed.");
    }

    /* forward RPC/Action response to the originator */
    rc = cm_msg_send(rp_ctx->cm_ctx, resp);

    return rc;
}

/**
 * @brief Processes an unsubscribe-destination internal request.
 */
static int
rp_unsubscribe_destination_req_process(const rp_ctx_t *rp_ctx, Sr__Msg *msg)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(rp_ctx, msg, msg->internal_request, msg->internal_request->unsubscribe_dst_req);

    SR_LOG_DBG_MSG("Processing unsubscribe destination request.");

    rc = np_unsubscribe_destination(rp_ctx->np_ctx, msg->internal_request->unsubscribe_dst_req->destination);

    return rc;
}

/**
 * @brief Processes a commit-timeout internal request.
 */
static int
rp_commit_timeout_req_process(const rp_ctx_t *rp_ctx, Sr__Msg *msg)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(rp_ctx, msg, msg->internal_request, msg->internal_request->commit_timeout_req);

    SR_LOG_DBG_MSG("Processing commit-timeout request.");

    rc = np_commit_notifications_complete(rp_ctx->np_ctx, msg->internal_request->commit_timeout_req->commit_id,
            msg->internal_request->commit_timeout_req->expired);

    return rc;
}

/**
 * @brief Processes an operational data timeout request.
 */
static int
rp_oper_data_timeout_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, msg, msg->internal_request, msg->internal_request->oper_data_timeout_req, session);

    SR_LOG_DBG_MSG("Processing oper-data-timeout request.");

    MUTEX_LOCK_TIMED_CHECK_RETURN(&session->cur_req_mutex);
    if (RP_REQ_WAITING_FOR_DATA == session->state &&
        session->req && session->req->request->_id == msg->internal_request->oper_data_timeout_req->request_id) {
        SR_LOG_DBG("Time out expired for operational data to be loaded. Request (id=%" PRIu64 ") processing continue, "
                "session id = %u", session->req->request->_id, session->id);
        rp_msg_process(rp_ctx, session, session->req);
        session->state = RP_REQ_TIMED_OUT;
    }
    pthread_mutex_unlock(&session->cur_req_mutex);

    return rc;
}

/**
 * @brief Processes an internal state data request.
 */
static int
rp_internal_state_data_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg * msg)
{
    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->internal_request, msg->internal_request->internal_state_data_req);
    nacm_ctx_t *nacm_ctx = NULL;
    sr_val_t nacm_stats = {0};
    int rc = SR_ERR_OK;
    const char *xpath = msg->internal_request->internal_state_data_req->xpath;
    uint64_t orig_req_id = msg->internal_request->internal_state_data_req->request_id;
    nacm_stats.type = SR_UINT32_T;

    SR_LOG_INF("Internal request for state data at xpath %s, orig-req id = %" PRIu64, xpath, orig_req_id);

    MUTEX_LOCK_TIMED_CHECK_GOTO(&session->cur_req_mutex, rc, cleanup);
    if (RP_REQ_WAITING_FOR_DATA != session->state || NULL == session->req || orig_req_id != session->req->request->_id) {
        SR_LOG_ERR("State data arrived after timeout expiration or session id=%u is invalid.", session->id);
        goto cleanup;
    }

    session->dp_req_waiting -= 1;
    SR_LOG_DBG("Data provide response received, waiting for %zu more data providers.", session->dp_req_waiting);

    if (sr_str_begins_with(xpath, "/ietf-netconf-acm:nacm/")) {
        rc = dm_get_nacm_ctx(rp_ctx->dm_ctx, &nacm_ctx);
        if (SR_ERR_OK != rc) {
            SR_LOG_WRN_MSG("Failed to get NACM context.");
        }
    }

    /**
     * Set internal state data - only one request come for each subtree, nested data has to be filled as well
     */
    if (0 == strcmp(xpath, "/ietf-netconf-acm:nacm/denied-operations")) {
        if (NULL != nacm_ctx) {
            (void)nacm_get_stats(nacm_ctx, &nacm_stats.data.uint32_val, NULL, NULL);
            rc = rp_dt_set_item(rp_ctx->dm_ctx, session->dm_session, xpath, SR_EDIT_DEFAULT, &nacm_stats, NULL, false);
            if (SR_ERR_OK != rc) {
                SR_LOG_WRN("Failed to set operational data for xpath '%s'.", xpath);
            }
        }
    } else if (0 == strcmp(xpath, "/ietf-netconf-acm:nacm/denied-data-writes")) {
        if (NULL != nacm_ctx) {
            (void)nacm_get_stats(nacm_ctx, NULL, NULL, &nacm_stats.data.uint32_val);
            rc = rp_dt_set_item(rp_ctx->dm_ctx, session->dm_session, xpath, SR_EDIT_DEFAULT, &nacm_stats, NULL, false);
            if (SR_ERR_OK != rc) {
                SR_LOG_WRN("Failed to set operational data for xpath '%s'.", xpath);
            }
        }
    } else if (0 == strcmp(xpath, "/ietf-netconf-acm:nacm/denied-notifications")) {
        if (NULL != nacm_ctx) {
            (void)nacm_get_stats(nacm_ctx, NULL, &nacm_stats.data.uint32_val, NULL);
            rc = rp_dt_set_item(rp_ctx->dm_ctx, session->dm_session, xpath, SR_EDIT_DEFAULT, &nacm_stats, NULL, false);
            if (SR_ERR_OK != rc) {
                SR_LOG_WRN("Failed to set operational data for xpath '%s'.", xpath);
            }
        }
    } else {
        SR_LOG_WRN("Request for not supported internal state data %s received ", xpath);
    }


cleanup:
    if (0 == session->dp_req_waiting) {
        rp_dt_free_state_data_ctx_content(&session->state_data_ctx);
        if (RP_REQ_WAITING_FOR_DATA == session->state) {
            SR_LOG_DBG("All data from data providers has been received session id = %u, "
                    "re-enqueue the request (id=%" PRIu64 ")", session->id,
                    session->req ? session->req->request->_id : 0);
            session->state = RP_REQ_DATA_LOADED;
            rp_msg_process(rp_ctx, session, session->req);
            session->req = NULL;
        }
    }
    pthread_mutex_unlock(&session->cur_req_mutex);
    return rc;
}

/**
 * @brief Processes a notification store cleanup internal request.
 */
static int
rp_notif_store_cleanup_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg * msg)
{
    CHECK_NULL_ARG(rp_ctx);

    SR_LOG_DBG_MSG("Processing notif-store-cleanup request.");

    np_notification_store_cleanup(rp_ctx->np_ctx, true);

    return SR_ERR_OK;

}

/**
 * @brief Processes a delayed-msg internal request.
 */
static int
rp_delayed_msg_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg * msg)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(rp_ctx, msg->internal_request, msg->internal_request->delayed_msg_req);

    SR_LOG_DBG_MSG("Processing delayed-msg request.");

    if (NULL != msg->internal_request->delayed_msg_req->message) {
        rc = cm_msg_send(rp_ctx->cm_ctx, msg->internal_request->delayed_msg_req->message);
        msg->internal_request->delayed_msg_req->message = NULL;
    }

    return rc;

}

/**
 * @brief Processes a nacm-reload internal request.
 */
static int
rp_nacm_reload_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg * msg)
{
    int rc = SR_ERR_OK;
    nacm_ctx_t *nacm_ctx = NULL;
    CHECK_NULL_ARG(rp_ctx);

    SR_LOG_DBG_MSG("Processing nacm-reload request.");

    /* get NACM context */
    rc = dm_get_nacm_ctx(rp_ctx->dm_ctx, &nacm_ctx);
    CHECK_RC_MSG_RETURN(rc, "Failed to get NACM context");

    if (NULL != nacm_ctx) {
        rc = nacm_reload(nacm_ctx, SR_DS_RUNNING);
        CHECK_RC_MSG_RETURN(rc, "Failed to reload NACM configuration");
    }

    return SR_ERR_OK;
}

/**
 * @brief Sends an event notification to specified notification subscriber.
 */
static int
rp_event_notif_send(const rp_ctx_t *rp_ctx, const rp_session_t *session, Sr__EventNotifReq__NotifType type,
        const char *xpath, time_t timestamp, sr_api_variant_t api_variant, const sr_val_t *sr_values, size_t sr_values_cnt,
        const sr_node_t *sr_trees, size_t sr_trees_cnt, const char *subscription_address, uint32_t subscription_id,
        time_t delivery_time)
{
    Sr__Msg *req = NULL, *internal_req = NULL;
    int rc = SR_ERR_OK;

    rc = sr_gpb_req_alloc(NULL, SR__OPERATION__EVENT_NOTIF, (NULL != session ? session->id : 0), &req);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to duplicate event notification request (%s).", xpath);

    /* set type, xpath & timestamp */
    req->request->event_notif_req->type = type;
    req->request->event_notif_req->xpath = strdup(xpath);
    CHECK_NULL_NOMEM_GOTO(req->request->event_notif_req->xpath, rc, cleanup);
    req->request->event_notif_req->timestamp = timestamp;

    /* set values / trees */
    switch (api_variant) {
        case SR_API_VALUES:
            rc = sr_values_sr_to_gpb(sr_values, sr_values_cnt, &req->request->event_notif_req->values,
                    &req->request->event_notif_req->n_values);
            break;
        case SR_API_TREES:
            rc = sr_trees_sr_to_gpb(sr_trees, sr_trees_cnt, &req->request->event_notif_req->trees,
                    &req->request->event_notif_req->n_trees);
            break;
    }
    CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to duplicate event notification (%s) input data.", xpath);

    /* set subscription info */
    req->request->event_notif_req->subscriber_address = strdup(subscription_address);
    CHECK_NULL_NOMEM_GOTO(req->request->event_notif_req->subscriber_address, rc, cleanup);

    req->request->event_notif_req->subscription_id = subscription_id;
    req->request->event_notif_req->has_subscription_id = true;

    if (0 == delivery_time) {
        /* send the notification immediately */
        rc = cm_msg_send(rp_ctx->cm_ctx, req);
        req = NULL;
    } else {
        /* send the notification later */
        rc = sr_gpb_internal_req_alloc(NULL, SR__OPERATION__DELAYED_MSG, &internal_req);
        if (SR_ERR_OK == rc) {
            internal_req->session_id = (NULL != session ? session->id : 0);
            internal_req->internal_request->delayed_msg_req->message = req;
            req = NULL;
            internal_req->internal_request->postpone_timeout = delivery_time - time(NULL);
            internal_req->internal_request->has_postpone_timeout = true;
            rc = cm_msg_send(rp_ctx->cm_ctx, internal_req);
        }
    }

cleanup:
    if (NULL != req) {
        sr_msg_free(req);
        req = NULL;
    }

    return rc;
}

/**
 * @brief Checks that a notification matches a subcription.
 * @return 0 if not, 1 if matches.
 */
static int
rp_event_notif_match_subscr(const char *ntf_xpath, const char *subscr_xpath)
{
    /* specific subscription for this notification */
    if (!strcmp(ntf_xpath, subscr_xpath)) {
        return 1;
    }

    /* whole module subscription */
    if (!strcmp(subscr_xpath + strlen(subscr_xpath) - 4, "*//.") && !strncmp(ntf_xpath, subscr_xpath, strlen(subscr_xpath) - 4)) {
        return 1;
    }

    return 0;
}

/**
 * @brief Processes an event notification request.
 */
static int
rp_event_notif_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg, bool *skip_msg_cleanup)
{
    dm_data_info_t *di = NULL;
    char *xpath = NULL;
    char *module_name = NULL;
    struct lyd_node *notif_data_tree = NULL;
    struct ly_ctx *notif_ctx = NULL;
    sr_api_variant_t msg_api_variant = SR_API_VALUES;
    sr_val_t *values = NULL, *with_def = NULL;
    sr_node_t *trees = NULL, *with_def_tree = NULL;
    size_t values_cnt = 0, tree_cnt = 0, with_def_cnt = 0, with_def_tree_cnt = 0;
    sr_list_t *subscriptions_list = NULL;
    np_subscription_t *subscription = NULL;
    bool sub_match = false, tmp_rp_session = false;
    Sr__Msg *resp = NULL;
    sr_mem_ctx_t *sr_mem_msg = NULL;
    nacm_ctx_t *nacm_ctx = NULL;
    nacm_action_t nacm_action = NACM_ACTION_PERMIT;
    char *nacm_rule = NULL, *nacm_rule_info = NULL;
    int rc = SR_ERR_OK, rc_tmp = SR_ERR_OK;

    CHECK_NULL_ARG_NORET4(rc, rp_ctx, msg, msg->request, msg->request->event_notif_req);
    if (SR_ERR_OK != rc) {
        goto finalize;
    }

    SR_LOG_DBG("Processing event notification request (%s).", msg->request->event_notif_req->xpath);

    if (session == NULL) {
        rc = rp_session_start(rp_ctx, 0, NULL, SR_DS_RUNNING, 0, 0, &session);
        CHECK_RC_MSG_GOTO(rc, finalize, "Failed to start temporary RP session.");
        tmp_rp_session = true;
    }

    /* parse input arguments */
    sr_mem_msg = (sr_mem_ctx_t *)msg->_sysrepo_mem_ctx;
    if (msg->request->event_notif_req->n_values) {
        rc = sr_values_gpb_to_sr(sr_mem_msg, msg->request->event_notif_req->values,
                msg->request->event_notif_req->n_values, &values, &values_cnt);
    } else if (msg->request->event_notif_req->n_trees) {
        msg_api_variant = SR_API_TREES;
        rc = sr_trees_gpb_to_sr(sr_mem_msg, msg->request->event_notif_req->trees,
                msg->request->event_notif_req->n_trees, &trees, &tree_cnt);
    }
    CHECK_RC_LOG_GOTO(rc, finalize, "Failed to parse event notification (%s) data trees from GPB message.",
                      msg->request->event_notif_req->xpath);

    session->req = msg;

    MUTEX_LOCK_TIMED_CHECK_GOTO(&session->cur_req_mutex, rc, finalize);
    rp_handle_get_call_state(session);

    /* validate event-notification request */
    if (SR_API_VALUES == msg_api_variant) {
        rc = dm_validate_event_notif(rp_ctx, session, msg->request->event_notif_req->xpath, values, values_cnt, NULL,
                &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt, &notif_data_tree, &notif_ctx);
    } else {
        rc = dm_validate_event_notif_tree(rp_ctx, session, msg->request->event_notif_req->xpath, trees, tree_cnt, NULL,
                &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt, &notif_data_tree, &notif_ctx);
    }

    if (rc != SR_ERR_OK) {
        SR_LOG_ERR("Validation of an event notification (%s) message failed.", msg->request->event_notif_req->xpath);
    }

    if (RP_REQ_WAITING_FOR_DATA == session->state) {
        SR_LOG_DBG_MSG("Request paused, waiting for data");
        /* we are waiting for operational data do not free the request */
        *skip_msg_cleanup = true;
        /* setup timeout */
        rc = rp_set_oper_request_timeout(rp_ctx, session, msg, SR_OPER_DATA_PROVIDE_TIMEOUT);

        /* free all the allocated data */
        if (SR_API_VALUES == msg_api_variant) {
            sr_free_values(values, values_cnt);
        } else {
            sr_free_trees(trees, tree_cnt);
        }
        sr_free_values(with_def, with_def_cnt);
        sr_free_trees(with_def_tree, with_def_tree_cnt);
        pthread_mutex_unlock(&session->cur_req_mutex);
        if (tmp_rp_session) {
            rp_session_stop(rp_ctx, session);
        }
        return rc;
    }

    pthread_mutex_unlock(&session->cur_req_mutex);

    if (rc != SR_ERR_OK) {
        goto finalize;
    }

    rc = sr_copy_first_ns(msg->request->event_notif_req->xpath, &module_name);
    CHECK_RC_MSG_RETURN(rc, "Error by extracting module name from xpath.");
    rc = dm_get_data_info(rp_ctx->dm_ctx, session->dm_session, module_name, &di);
    CHECK_RC_LOG_GOTO(rc, finalize, "Dm_get_dat_info failed for module %s", module_name);

    xpath = ly_path_data2schema(di->schema->ly_ctx, msg->request->event_notif_req->xpath);
    if (NULL == xpath) {
        SR_LOG_ERR_MSG("Failed to transform schema path to data path");
        rc = SR_ERR_INTERNAL;
        goto finalize;
    }

    if (!tmp_rp_session) {
        /* authorize (write permissions are required to deliver the event-notification) */
        rc = ac_check_module_permissions(session->ac_session, module_name, AC_OPER_READ_WRITE);
        CHECK_RC_LOG_GOTO(rc, finalize, "Access control check failed for module name '%s'", module_name);
    }

#ifdef ENABLE_NOTIF_STORE
#ifndef STORE_CONFIG_CHANGE_NOTIF
    if (0 != strcmp(xpath, "/ietf-netconf-notifications:netconf-config-change")) {
#endif /* STORE_CONFIG_CHANGE_NOTIF */
    if (!(msg->request->event_notif_req->options & SR__EVENT_NOTIF_REQ__NOTIF_FLAGS__EPHEMERAL)) {
        /* store the notification in the datastore */
        rc = np_store_event_notification(rp_ctx->np_ctx, session->user_credentials,
                xpath, msg->request->event_notif_req->timestamp, notif_data_tree);
        CHECK_RC_MSG_GOTO(rc, finalize, "Failed to save event notification");
    }
#ifndef STORE_CONFIG_CHANGE_NOTIF
    }
#endif /* STORE_CONFIG_CHANGE_NOTIF */
#endif /* ENABLE_NOTIF_STORE */

    /* get event-notification subscriptions */
    rc = pm_get_subscriptions(rp_ctx->pm_ctx, session->user_credentials, module_name,
            SR__SUBSCRIPTION_TYPE__EVENT_NOTIF_SUBS, &subscriptions_list);
    CHECK_RC_LOG_GOTO(rc, finalize, "Failed to get subscriptions for event notification request (%s).", xpath);

    /* get NACM context */
    rc = dm_get_nacm_ctx(rp_ctx->dm_ctx, &nacm_ctx);
    CHECK_RC_MSG_GOTO(rc, finalize, "Failed to get NACM context");

    /* broadcast the notification to all subscribed processes */
    if (NULL != subscriptions_list) {
        for (size_t i = 0; i < subscriptions_list->count; i++) {
            subscription = subscriptions_list->data[i];
            if ((NULL != subscription->xpath && rp_event_notif_match_subscr(xpath, subscription->xpath))
                    || (NULL == subscription->xpath && 0 == sr_cmp_first_ns(xpath, subscription->module_name))) {
                /* duplicate msg into req with values and subscription details
                 * @note we are not using memory context for the *req* message because with so many
                 * duplications it would be actually less efficient than normally.
                 */
                sub_match = true;

                /* NACM access control */
                if (NULL != nacm_ctx && subscription->enable_nacm) {
                    free(nacm_rule);
                    free(nacm_rule_info);
                    nacm_rule = NULL;
                    nacm_rule_info = NULL;
                    /* check if the user is authorized to receive the notification */
                    rc = nacm_check_event_notif(nacm_ctx, subscription->username, xpath, &nacm_action,
                            &nacm_rule, &nacm_rule_info);
                    if (SR_ERR_OK != rc || NACM_ACTION_DENY == nacm_action) {
                        nacm_report_delivery_blocked(subscription, xpath, rc, nacm_rule, nacm_rule_info);
                        continue;
                    }
                }

                rc = rp_event_notif_send(rp_ctx, session, msg->request->event_notif_req->type,
                        xpath, msg->request->event_notif_req->timestamp,
                        subscription->api_variant, with_def, with_def_cnt, with_def_tree, with_def_tree_cnt,
                        subscription->dst_address, subscription->dst_id, 0);
                CHECK_RC_LOG_GOTO(rc, finalize, "Error by sending the notification '%s' to the subscriber '%s'.",
                        subscription->xpath, subscription->dst_address);
            }
        }
    }

finalize:
    /* free all the allocated data */
    if (SR_API_VALUES == msg_api_variant) {
        sr_free_values(values, values_cnt);
    } else {
        sr_free_trees(trees, tree_cnt);
    }
    sr_free_values(with_def, with_def_cnt);
    sr_free_trees(with_def_tree, with_def_tree_cnt);
    free(module_name);
    free(nacm_rule);
    free(nacm_rule_info);
    np_subscriptions_list_cleanup(subscriptions_list);

    if (!sub_match && SR_ERR_OK == rc) {
        /* no subscription for this event notification */
        SR_LOG_DBG("No subscription found for event notification delivery (xpath = '%s').", xpath);
    }

    /* send the response with return code */
    if (!msg->request->event_notif_req->do_not_send_reply) {
        rc_tmp = sr_gpb_resp_alloc(sr_mem_msg, SR__OPERATION__EVENT_NOTIF, session->id, &resp);
        if (SR_ERR_OK == rc_tmp) {
            resp->response->result = rc;
            rc = cm_msg_send(rp_ctx->cm_ctx, resp);
        }
    } else {
        SR_LOG_DBG("Internally generated event notification %s response not sent", xpath);
    }

    free(xpath);
    session->req = NULL;
    if (tmp_rp_session) {
        rp_session_stop(rp_ctx, session);
    }

    if (NULL != notif_data_tree) {
        lyd_free_withsiblings(notif_data_tree);
    }
    if (NULL != notif_ctx) {
        ly_ctx_destroy(notif_ctx, NULL);
    }
    return rc;
}

/**
 * @brief Processes an event notification replay request.
 */
static int
rp_event_notif_replay_req_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    Sr__EventNotifReplayReq *replay_req = NULL;
    Sr__Msg *resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->request, msg->request->event_notif_replay_req);

    SR_LOG_DBG_MSG("Processing event notification replay request.");

    replay_req = msg->request->event_notif_replay_req;

    /* allocate the response */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_resp_alloc(sr_mem, SR__OPERATION__EVENT_NOTIF_REPLAY, session->id, &resp);
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
        SR_LOG_ERR_MSG("Allocation of the response failed.");
        return SR_ERR_NOMEM;
    }

#ifdef ENABLE_NOTIF_STORE
    sr_list_t *notif_list = NULL;

    /* get matching notifications from the notification store */
    rc = np_get_event_notifications(rp_ctx->np_ctx, session, replay_req->xpath, replay_req->start_time,
            replay_req->stop_time, sr_api_variant_gpb_to_sr(replay_req->api_variant), &notif_list);
    CHECK_RC_LOG_GOTO(rc, finalize, "Error by loading event notifications for xpath '%s'.", replay_req->xpath);

    /* send each notification to the subscriber */
    if (NULL != notif_list) {
        for (size_t i = 0; i < notif_list->count; i++) {
            np_ev_notification_t *notification = notif_list->data[i];

            /* send the notification */
            rc = rp_event_notif_send(rp_ctx, session, SR__EVENT_NOTIF_REQ__NOTIF_TYPE__REPLAY, notification->xpath,
                    notification->timestamp, sr_api_variant_gpb_to_sr(replay_req->api_variant),
                    notification->data.values, notification->data_cnt, notification->data.trees, notification->data_cnt,
                    replay_req->subscriber_address, replay_req->subscription_id, 0);
            CHECK_RC_LOG_GOTO(rc, finalize, "Error by sending the replay of notification '%s' to the subscriber '%s'.",
                    notification->xpath, replay_req->subscriber_address);
        }
    }

    /* send replay-complete notification */
    rc = rp_event_notif_send(rp_ctx, session, SR__EVENT_NOTIF_REQ__NOTIF_TYPE__REPLAY_COMPLETE,
            replay_req->xpath, time(NULL), sr_api_variant_gpb_to_sr(replay_req->api_variant),
            NULL, 0, NULL, 0, replay_req->subscriber_address, replay_req->subscription_id, 0);
    CHECK_RC_LOG_GOTO(rc, finalize, "Error by sending the replay-complete notification to the subscriber '%s'.",
            replay_req->subscriber_address);

finalize:
    if (NULL != notif_list) {
        for (size_t i = 0; i < notif_list->count; i++) {
            np_event_notification_cleanup(notif_list->data[i]);
        }
    }
    sr_list_cleanup(notif_list);
#endif

    /* schedule replay-stop notification */
    if ((0 != replay_req->stop_time) && (time(NULL) <= replay_req->stop_time)) {
        rc = rp_event_notif_send(rp_ctx, session, SR__EVENT_NOTIF_REQ__NOTIF_TYPE__REPLAY_STOP, replay_req->xpath,
                replay_req->stop_time, sr_api_variant_gpb_to_sr(replay_req->api_variant), NULL, 0, NULL, 0,
                replay_req->subscriber_address, replay_req->subscription_id, replay_req->stop_time);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Error by scheduling the replay-stop notification to the subscriber '%s'.",
                    replay_req->subscriber_address);
        }
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
 * @brief Processes an notification acknowledgment.
 */
static int
rp_notification_ack_process(rp_ctx_t *rp_ctx, Sr__Msg *msg)
{
    Sr__Notification *notif = NULL;
    Sr__NotificationEvent event = SR__NOTIFICATION_EVENT__APPLY_EV;
    char *subs_xpath = NULL, *err_msg = NULL, *err_xpath = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(rp_ctx, msg, msg->notification_ack, msg->notification_ack->notif);

    SR_LOG_DBG("Notification ACK received with result = %"PRIu32".", msg->notification_ack->result);

    notif =  msg->notification_ack->notif;

    if (SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS == msg->notification_ack->notif->type) {
        subs_xpath = notif->module_change_notif->module_name;
        event = notif->module_change_notif->event;
    } else if (SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS == msg->notification_ack->notif->type) {
        subs_xpath = notif->subtree_change_notif->xpath;
        event = notif->subtree_change_notif->event;
    }

    if (SR_ERR_OK != msg->notification_ack->result) {
        if (NULL != msg->notification_ack->error) {
            err_msg = msg->notification_ack->error->message;
            err_xpath = msg->notification_ack->error->xpath;
        }
        SR_LOG_ERR("'%s' subscriber returned and error by processing of %s event: %s.",
                subs_xpath, sr_notification_event_gpb_to_str(event), sr_strerror(msg->notification_ack->result));
    }

    rc = np_commit_notification_ack(rp_ctx->np_ctx, notif->commit_id, subs_xpath, sr_notification_event_gpb_to_sr(event),
            msg->notification_ack->result, msg->notification_ack->do_not_send_abort, err_msg, err_xpath);

    return rc;
}

/**
 * @brief Dispatches received request message.
 */
static int
rp_req_dispatch(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg, bool *skip_msg_cleanup)
{
    bool locked = false;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(rp_ctx, msg, msg->request, skip_msg_cleanup);

    *skip_msg_cleanup = false;

    if (NULL != session) {
        dm_clear_session_errors(session->dm_session);
    }

    if (NULL != session && 0 == msg->request->_id) {
        /* generate new request id */
        pthread_mutex_lock(&session->total_req_cnt_mutex);
        ++session->total_req_cnt;
        pthread_mutex_unlock(&session->total_req_cnt_mutex);
        pthread_mutex_lock(&rp_ctx->total_req_cnt_mutex);
        ++rp_ctx->total_req_cnt;
        msg->request->_id = rp_ctx->total_req_cnt;
        pthread_mutex_unlock(&rp_ctx->total_req_cnt_mutex);
    }

    /* acquire lock for operation accessing data */
    switch (msg->request->operation) {
        case SR__OPERATION__GET_ITEM:
        case SR__OPERATION__GET_ITEMS:
        case SR__OPERATION__GET_SUBTREE:
        case SR__OPERATION__GET_SUBTREES:
        case SR__OPERATION__GET_SUBTREE_CHUNK:
        case SR__OPERATION__SET_ITEM:
        case SR__OPERATION__SET_ITEM_STR:
        case SR__OPERATION__DELETE_ITEM:
        case SR__OPERATION__MOVE_ITEM:
        case SR__OPERATION__SESSION_REFRESH:
            pthread_rwlock_rdlock(&rp_ctx->commit_lock);
            locked = true;
            break;
        case SR__OPERATION__COMMIT:
        case SR__OPERATION__COPY_CONFIG:
            if (!rp_ctx->block_further_commits) {
                pthread_rwlock_wrlock(&rp_ctx->commit_lock);
                locked = true;
            }
            break;
        default:
            break;
    }

    switch (msg->request->operation) {
        case SR__OPERATION__SESSION_SWITCH_DS:
            rc = rp_switch_datastore_req_process(rp_ctx, session, msg);
            break;
        case SR__OPERATION__SESSION_SET_OPTS:
            rc = rp_session_set_opts(rp_ctx, session, msg);
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
            rc = rp_get_item_req_process(rp_ctx, session, msg, skip_msg_cleanup);
            break;
        case SR__OPERATION__GET_ITEMS:
            rc = rp_get_items_req_process(rp_ctx, session, msg, skip_msg_cleanup);
            break;
        case SR__OPERATION__GET_SUBTREE:
            rc = rp_get_subtree_req_process(rp_ctx, session, msg, skip_msg_cleanup);
            break;
        case SR__OPERATION__GET_SUBTREES:
            rc = rp_get_subtrees_req_process(rp_ctx, session, msg, skip_msg_cleanup);
            break;
        case SR__OPERATION__GET_SUBTREE_CHUNK:
            rc = rp_get_subtree_chunk_req_process(rp_ctx, session, msg, skip_msg_cleanup);
            break;
        case SR__OPERATION__SET_ITEM:
            rc = rp_set_item_req_process(rp_ctx, session, msg);
            break;
        case SR__OPERATION__SET_ITEM_STR:
            rc = rp_set_item_str_req_process(rp_ctx, session, msg);
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
            rc = rp_commit_req_process(rp_ctx, session, msg, skip_msg_cleanup);
            break;
        case SR__OPERATION__DISCARD_CHANGES:
            rc = rp_discard_changes_req_process(rp_ctx, session, msg);
            break;
        case SR__OPERATION__COPY_CONFIG:
            rc = rp_copy_config_req_process(rp_ctx, session, msg, skip_msg_cleanup);
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
        case SR__OPERATION__CHECK_ENABLED_RUNNING:
            rc = rp_check_enabled_running_req_process(rp_ctx, session, msg);
            break;
        case SR__OPERATION__GET_CHANGES:
            rc = rp_get_changes_req_process(rp_ctx, session, msg);
            break;
        case SR__OPERATION__CHECK_EXEC_PERMISSION:
            rc = rp_check_exec_perm_req_process(rp_ctx, session, msg);
            break;
        case SR__OPERATION__RPC:
        case SR__OPERATION__ACTION:
            rc = rp_rpc_req_process(rp_ctx, session, msg, skip_msg_cleanup);
            break;
        case SR__OPERATION__EVENT_NOTIF:
            rc = rp_event_notif_req_process(rp_ctx, session, msg, skip_msg_cleanup);
            break;
        case SR__OPERATION__EVENT_NOTIF_REPLAY:
            rc = rp_event_notif_replay_req_process(rp_ctx, session, msg);
            break;
        default:
            SR_LOG_ERR("Unsupported request received (session id=%"PRIu32", operation=%d).",
                    NULL != session ? session->id : 0, msg->request->operation);
            rc = SR_ERR_UNSUPPORTED;
            break;
    }

    /* release lock */
    if (locked) {
        pthread_rwlock_unlock(&rp_ctx->commit_lock);
    }

    return rc;
}

/**
 * @brief Dispatches received response message.
 */
static int
rp_resp_dispatch(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg, bool *skip_msg_cleanup)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(rp_ctx, session, msg, msg->response, skip_msg_cleanup);

    *skip_msg_cleanup = false;

    switch (msg->response->operation) {
        case SR__OPERATION__DATA_PROVIDE:
            rc = rp_data_provide_resp_process(rp_ctx, session, msg);
            break;
        case SR__OPERATION__RPC:
        case SR__OPERATION__ACTION:
            rc = rp_rpc_resp_process(rp_ctx, session, msg);
            *skip_msg_cleanup = true;
            break;
        default:
            SR_LOG_ERR("Unsupported response received (session id=%"PRIu32", operation=%d).",
                    session->id, msg->response->operation);
            rc = SR_ERR_UNSUPPORTED;
            break;
    }

    return rc;
}

/**
 * @brief Dispatches received internal request message.
 */
static int
rp_internal_req_dispatch(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(rp_ctx, msg, msg->internal_request);

    switch (msg->internal_request->operation) {
        case SR__OPERATION__UNSUBSCRIBE_DESTINATION:
            rc = rp_unsubscribe_destination_req_process(rp_ctx, msg);
            break;
        case SR__OPERATION__COMMIT_TIMEOUT:
            rc = rp_commit_timeout_req_process(rp_ctx, msg);
            break;
        case SR__OPERATION__OPER_DATA_TIMEOUT:
            rc = rp_oper_data_timeout_req_process(rp_ctx, session, msg);
            break;
        case SR__OPERATION__INTERNAL_STATE_DATA:
            rc = rp_internal_state_data_req_process(rp_ctx, session, msg);
            break;
        case SR__OPERATION__NOTIF_STORE_CLEANUP:
            rc = rp_notif_store_cleanup_req_process(rp_ctx, session, msg);
            break;
        case SR__OPERATION__DELAYED_MSG:
            rc = rp_delayed_msg_req_process(rp_ctx, session, msg);
            break;
        case SR__OPERATION__NACM_RELOAD:
            rc = rp_nacm_reload_req_process(rp_ctx, session, msg);
            break;
        default:
            SR_LOG_ERR("Unsupported internal request received (operation=%d).", msg->internal_request->operation);
            rc = SR_ERR_UNSUPPORTED;
            break;
    }

    return rc;
}

static bool
rp_session_can_be_null_for_msg (Sr__Msg *msg) {

    if (NULL != msg ) {
        if ((SR__MSG__MSG_TYPE__INTERNAL_REQUEST == msg->type) ||
           (SR__MSG__MSG_TYPE__NOTIFICATION_ACK == msg->type)) {
            return true;
        } else if ((SR__MSG__MSG_TYPE__REQUEST == msg->type) &&
                (SR__OPERATION__EVENT_NOTIF == msg->request->operation) &&
                ((0 == strcmp(CAPABILITY_CHANGE_NOTIFICATION_XPATH, msg->request->event_notif_req->xpath) ||
                 (0 == strcmp(CONFIG_CHANGE_NOTIFICATION_XPATH, msg->request->event_notif_req->xpath)))
                )) {
            return true;
        }
    }
    return false;
}

/**
 * @brief Dispatches the received message.
 */
static int
rp_msg_dispatch(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg)
{
    int rc = SR_ERR_OK;
    bool skip_msg_cleanup = false;

    CHECK_NULL_ARG2(rp_ctx, msg);

    /* NULL session is only allowed for internal messages */
    if ((NULL == session) && !rp_session_can_be_null_for_msg(msg)) {
        SR_LOG_ERR("Session argument of the message  to be processed is NULL (type=%d).", msg->type);
        sr_msg_free(msg);
        return SR_ERR_INVAL_ARG;
    }

    /* whitelist only some operations for notification sessions */
    if ((NULL != session) && (SR__MSG__MSG_TYPE__REQUEST == msg->type) && (session->options & SR__SESSION_FLAGS__SESS_NOTIFICATION)) {
        if ((SR__OPERATION__GET_ITEM != msg->request->operation) &&
                (SR__OPERATION__GET_ITEMS != msg->request->operation) &&
                (SR__OPERATION__SESSION_REFRESH != msg->request->operation) &&
                (SR__OPERATION__GET_CHANGES != msg->request->operation) &&
                (SR__OPERATION__UNSUBSCRIBE != msg->request->operation) &&
                (SR__OPERATION__GET_SUBTREE != msg->request->operation) &&
                (SR__OPERATION__GET_SUBTREES != msg->request->operation) &&
                (SR__OPERATION__GET_SUBTREE_CHUNK != msg->request->operation)) {
            SR_LOG_ERR("Unsupported operation for notification session (session id=%"PRIu32", operation=%d).",
                    session->id, msg->request->operation);
            sr_msg_free(msg);
            return SR_ERR_UNSUPPORTED;
        }
    }

    switch (msg->type) {
        case SR__MSG__MSG_TYPE__REQUEST:
            rc = rp_req_dispatch(rp_ctx, session, msg, &skip_msg_cleanup);
            break;
        case SR__MSG__MSG_TYPE__RESPONSE:
            rc = rp_resp_dispatch(rp_ctx, session, msg, &skip_msg_cleanup);
            break;
        case SR__MSG__MSG_TYPE__INTERNAL_REQUEST:
            rc = rp_internal_req_dispatch(rp_ctx, session, msg);
            break;
        case SR__MSG__MSG_TYPE__NOTIFICATION_ACK:
            rc = rp_notification_ack_process(rp_ctx, msg);
            break;
        default:
            SR_LOG_ERR("Unsupported message received (session id=%"PRIu32", operation=%d).",
                    session->id, msg->response->operation);
            rc = SR_ERR_UNSUPPORTED;
    }

    /* release the message */
    if (!skip_msg_cleanup) {
        sr_msg_free(msg);
    }

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
    pthread_mutex_destroy(&session->total_req_cnt_mutex);
    pthread_mutex_destroy(&session->cur_req_mutex);
    free(session->change_ctx.xpath);
    free(session->module_name);
    if (NULL != session->req) {
        sr_msg_free(session->req);
    }
    for (size_t i = 0; i < DM_DATASTORE_COUNT; i++) {
        while (session->loaded_state_data[i]->count > 0) {
            char *item = session->loaded_state_data[i]->data[session->loaded_state_data[i]->count-1];
            sr_list_rm(session->loaded_state_data[i], item);
            free(item);
        }
        sr_list_cleanup(session->loaded_state_data[i]);
    }
    free(session->loaded_state_data);
    rp_dt_free_state_data_ctx_content(&session->state_data_ctx);
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
                    pthread_mutex_lock(&rp_ctx->request_queue_mutex);
                    while ((0 == sr_cbuff_items_in_queue(rp_ctx->request_queue)) && (count < rp_ctx->thread_spin_limit)) {
                        count++;
                    }
                    pthread_mutex_unlock(&rp_ctx->request_queue_mutex);
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

static void
rp_cleanup_internal_state_data_records(rp_ctx_t *rp_ctx)
{
    if (NULL != rp_ctx) {
        sr_free_list_of_strings(rp_ctx->modules_incl_intern_op_data);

        if (NULL != rp_ctx->inter_op_data_xpath) {
            for (size_t i = 0; i < rp_ctx->inter_op_data_xpath->count; i++) {
                sr_free_list_of_strings((sr_list_t *) rp_ctx->inter_op_data_xpath->data[i]);
            }
            sr_list_cleanup(rp_ctx->inter_op_data_xpath);
        }
    }
}

static int
rp_enable_xps_for_internal_state_data(rp_ctx_t *rp_ctx)
{
    CHECK_NULL_ARG(rp_ctx);
    int rc = SR_ERR_OK;
    dm_schema_info_t *si = NULL;
    char *xp_to_be_enabled = NULL;

    for (size_t m = 0; m < rp_ctx->modules_incl_intern_op_data->count; m++) {
        sr_list_t *module_xps = (sr_list_t *) rp_ctx->inter_op_data_xpath->data[m];
        char *module_name = (char *) rp_ctx->modules_incl_intern_op_data->data[m];

        rc = dm_get_module_and_lock(rp_ctx->dm_ctx, module_name, &si);
        if (SR_ERR_OK != rc) {
            SR_LOG_WRN("Module %s needed for internal state data is not installed.", module_name);
            /* ignore this error */
            rc = SR_ERR_OK;
            continue;
        }

        for (size_t x = 0; x < module_xps->count; x++) {
            xp_to_be_enabled = (char *) module_xps->data[x];
            rc = rp_dt_enable_xpath(rp_ctx->dm_ctx, NULL, si, xp_to_be_enabled);
            if (SR_ERR_OK != rc) {
                pthread_rwlock_unlock(&si->model_lock);
            }
            CHECK_RC_LOG_RETURN(rc, "Failed to enable xpath %s", xp_to_be_enabled);
        }
        pthread_rwlock_unlock(&si->model_lock);

    }
    return rc;
}

static int
rp_setup_internal_state_data(rp_ctx_t *rp_ctx)
{
    CHECK_NULL_ARG(rp_ctx);
    nacm_ctx_t *nacm_ctx = NULL;
    sr_list_t *ietf_netconf_acm = NULL;
    int rc = SR_ERR_OK;

    rc = dm_get_nacm_ctx(rp_ctx->dm_ctx, &nacm_ctx);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to get NACM context.");

    rc = sr_list_init(&rp_ctx->modules_incl_intern_op_data);
    CHECK_RC_MSG_RETURN(rc, "List init failed");

    rc = sr_list_init(&rp_ctx->inter_op_data_xpath);
    CHECK_RC_MSG_GOTO(rc, cleanup, "List init failed");

    /* setup here modules and subtrees of state data that will be handled internally */
    if (NULL != nacm_ctx) {
        rc = sr_list_init(&ietf_netconf_acm);
        CHECK_RC_MSG_GOTO(rc, cleanup, "List init failed");

        rc = sr_list_add(ietf_netconf_acm, strdup("/ietf-netconf-acm:nacm/denied-operations"));
        CHECK_RC_MSG_GOTO(rc, cleanup, "List add failed");

        rc = sr_list_add(ietf_netconf_acm, strdup("/ietf-netconf-acm:nacm/denied-data-writes"));
        CHECK_RC_MSG_GOTO(rc, cleanup, "List add failed");

        rc = sr_list_add(ietf_netconf_acm, strdup("/ietf-netconf-acm:nacm/denied-notifications"));
        CHECK_RC_MSG_GOTO(rc, cleanup, "List add failed");

        rc = sr_list_add(rp_ctx->modules_incl_intern_op_data, strdup("ietf-netconf-acm"));
        CHECK_RC_MSG_GOTO(rc, cleanup, "List add failed");

        rc = sr_list_add(rp_ctx->inter_op_data_xpath, ietf_netconf_acm);
        CHECK_RC_MSG_GOTO(rc, cleanup, "List add failed");
        ietf_netconf_acm = NULL;
    }
    rc = rp_enable_xps_for_internal_state_data(rp_ctx);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to enable xpaths for internal state data");

cleanup:
    if (SR_ERR_OK != rc) {
        sr_free_list_of_strings(ietf_netconf_acm);
        rp_cleanup_internal_state_data_records(rp_ctx);
    }
    return rc;
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

#ifndef ENABLE_CONFIG_CHANGE_NOTIF
    ctx->do_not_generate_config_change = true;
#endif

    /* initialize Notification Processor */
    rc = np_init(ctx, SR_INTERNAL_SCHEMA_SEARCH_DIR, SR_DATA_SEARCH_DIR, &ctx->np_ctx);
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
    rc = dm_init(ctx->ac_ctx, ctx->np_ctx, ctx->pm_ctx, cm_ctx ? cm_get_connection_mode(cm_ctx) : CM_MODE_LOCAL,
                 SR_SCHEMA_SEARCH_DIR, SR_DATA_SEARCH_DIR, &ctx->dm_ctx);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Data Manager initialization failed.");
        goto cleanup;
    }

    rc = rp_setup_internal_state_data(ctx);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Set up of internal state data failed");

    pthread_mutex_init(&ctx->total_req_cnt_mutex, NULL);

    /* run worker threads */
    pthread_mutex_init(&ctx->request_queue_mutex, NULL);
    pthread_cond_init(&ctx->request_queue_cv, NULL);

    for (i = 0; i < RP_THREAD_COUNT; i++) {
        rc = pthread_create(&ctx->thread_pool[i], NULL, rp_worker_thread_execute, ctx);
        if (0 != rc) {
            SR_LOG_ERR("Error by creating a new thread: %s", sr_strerror_safe(errno));
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
        pthread_mutex_destroy(&rp_ctx->total_req_cnt_mutex);

        while (sr_cbuff_dequeue(rp_ctx->request_queue, &req)) {
            if (NULL != req.msg) {
                sr_msg_free(req.msg);
            }
        }
        pthread_rwlock_destroy(&rp_ctx->commit_lock);
        dm_cleanup(rp_ctx->dm_ctx);
        np_cleanup(rp_ctx->np_ctx);
        pm_cleanup(rp_ctx->pm_ctx);
        ac_cleanup(rp_ctx->ac_ctx);
        sr_cbuff_cleanup(rp_ctx->request_queue);
        rp_cleanup_internal_state_data_records(rp_ctx);
        free(rp_ctx);
    }

    SR_LOG_DBG_MSG("Request Processor cleanup finished.");
}

int
rp_session_start(const rp_ctx_t *rp_ctx, const uint32_t session_id, const ac_ucred_t *user_credentials,
        const sr_datastore_t datastore, const uint32_t session_options, const uint32_t commit_id, rp_session_t **session_p)
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
    pthread_mutex_init(&session->total_req_cnt_mutex, NULL);
    session->user_credentials = user_credentials;
    session->id = session_id;
    session->datastore = datastore;
    session->options = session_options;
    session->commit_id = commit_id;
    pthread_mutex_init(&session->cur_req_mutex, NULL);

    session->loaded_state_data = calloc(DM_DATASTORE_COUNT, sizeof(*session->loaded_state_data));
    CHECK_NULL_NOMEM_GOTO(session->loaded_state_data, rc, cleanup);
    for (size_t i = 0; i < DM_DATASTORE_COUNT; i++) {
        rc = sr_list_init(&session->loaded_state_data[i]);
        CHECK_RC_LOG_GOTO(rc, cleanup, "List of state xpath initialization failed for session id=%"PRIu32".", session_id);
    }

    if (session_id != 0) {
        /* not for internal sessions */
        rc = ac_session_init(rp_ctx->ac_ctx, user_credentials, &session->ac_session);
        CHECK_RC_LOG_GOTO(rc, cleanup, "Access Control session init failed for session id=%"PRIu32".", session_id);
    }

    rc = dm_session_start(rp_ctx->dm_ctx, user_credentials, datastore, &session->dm_session);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Init of dm_session failed for session id=%"PRIu32".", session_id);

    *session_p = session;

    return rc;

cleanup:
    rp_session_cleanup(rp_ctx, session);
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
            sr_msg_free(msg);
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
        sr_clock_get_time(CLOCK_MONOTONIC, &now);
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

    SR_LOG_DBG("Threads: active=%zu/%d, %zu requests in queue", rp_ctx->active_threads, RP_THREAD_COUNT,
            sr_cbuff_items_in_queue(rp_ctx->request_queue));

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
        if (NULL != session) {
            pthread_mutex_lock(&session->msg_count_mutex);
            session->msg_count -= 1;
            pthread_mutex_unlock(&session->msg_count_mutex);
        }
        sr_msg_free(msg);
    }

    return rc;
}

int
rp_all_notifications_received(rp_ctx_t *rp_ctx, uint32_t commit_id, bool finished, int result,
        sr_list_t *err_subs_xpaths, sr_list_t *errors)
{
    CHECK_NULL_ARG(rp_ctx);
    int rc = SR_ERR_OK;
    const char *op_str;
    dm_commit_context_t *c_ctx = NULL;
    dm_commit_ctxs_t *dm_ctxs = NULL;
    bool locked = false;

    rc = dm_get_commit_ctxs(rp_ctx->dm_ctx, &dm_ctxs);
    CHECK_RC_MSG_RETURN(rc, "Get commit ctx failed");
    pthread_rwlock_rdlock(&dm_ctxs->lock);
    locked = true;

    rc = dm_get_commit_context(rp_ctx->dm_ctx, commit_id, &c_ctx);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Commit ctx with id %"PRIu32" not found", commit_id);

    pthread_mutex_lock(&c_ctx->mutex);
    SR_LOG_DBG("Commit context in state %d", c_ctx->state);
    c_ctx->result = result;

    if (!finished && DM_COMMIT_WAIT_FOR_NOTIFICATIONS == c_ctx->state && NULL != c_ctx->init_session) {
        switch (c_ctx->init_session->req->request->operation) {
        case SR__OPERATION__COPY_CONFIG:
            op_str = "copy_config";
            break;
        case SR__OPERATION__COMMIT:
            op_str = "commit";
            break;
        default:
            SR_LOG_ERR_MSG("Invalid operation of a resumed commit request");
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
        SR_LOG_INF("Resuming %s with id %"PRIu32" continue with %s", op_str, commit_id, SR_ERR_OK == result ? "write" : "abort");
        c_ctx->state = SR_ERR_OK == result ? DM_COMMIT_WRITE : DM_COMMIT_NOTIFY_ABORT;
        c_ctx->err_subs_xpaths = err_subs_xpaths;

        MUTEX_LOCK_TIMED_CHECK_GOTO(&c_ctx->init_session->cur_req_mutex, rc, cleanup);
        c_ctx->init_session->state = RP_REQ_RESUMED;
        c_ctx->init_session->commit_id = commit_id;
        pthread_mutex_unlock(&c_ctx->init_session->cur_req_mutex);

        if (NULL != errors) {
            c_ctx->errors = calloc(errors->count, sizeof(*c_ctx->errors));
            c_ctx->err_cnt = 0;
            CHECK_NULL_NOMEM_GOTO(c_ctx->errors, rc, cleanup);
            for (size_t i = 0; i < errors->count; i++) {
                sr_error_info_t *err = errors->data[i];
                SR_LOG_ERR("Error from verifier: %s %s", err->message, err->xpath);
                c_ctx->errors[i].message = err->message;
                c_ctx->errors[i].xpath = err->xpath;
                free(err);
                c_ctx->err_cnt += 1;
            }
            sr_list_cleanup(errors);
        }
        /* reenqueue the request */
        rc = rp_msg_process(rp_ctx, c_ctx->init_session, c_ctx->init_session->req);
        c_ctx->init_session->req = NULL;
        pthread_mutex_unlock(&c_ctx->mutex);
        pthread_rwlock_unlock(&dm_ctxs->lock);
    } else if (finished && DM_COMMIT_FINISHED == c_ctx->state) {
        pthread_mutex_unlock(&c_ctx->mutex);
        pthread_rwlock_unlock(&dm_ctxs->lock);
        locked = false;
        /* apply or abort phase finished, release commit context */
        SR_LOG_INF("Commit id %"PRIu32" received all notifications", commit_id);
        rc = dm_commit_notifications_complete(rp_ctx->dm_ctx, commit_id);
        goto cleanup;
    } else {
        /* this might occurs when verify timeout expires and commit has already moved forward */
        SR_LOG_DBG("Commit id %"PRIu32" is in an unexpected state.", commit_id);
        pthread_mutex_unlock(&c_ctx->mutex);
        pthread_rwlock_unlock(&dm_ctxs->lock);
    }
    return rc;

cleanup:
    if (NULL != c_ctx && SR_ERR_OK != rc) {
        pthread_mutex_unlock(&c_ctx->mutex);
    }
    if (locked) {
        pthread_rwlock_unlock(&dm_ctxs->lock);
    }
    /* cleanup error lists */
    if (NULL != err_subs_xpaths) {
        for (size_t i = 0; i < err_subs_xpaths->count; i++) {
            free(err_subs_xpaths->data[i]);
        }
        sr_list_cleanup(err_subs_xpaths);
    }
    if (NULL != errors) {
        for (size_t i = 0; i < errors->count; i++) {
            sr_free_errors(errors->data[i], 1);
        }
        sr_list_cleanup(errors);
    }
    return rc;
}

int
rp_wait_for_commits_to_finish(rp_ctx_t *rp_ctx)
{
    CHECK_NULL_ARG(rp_ctx);
    dm_commit_ctxs_t *commit_ctxs = NULL;
    int rc = SR_ERR_OK;

    /* block commits in request processor */
    rp_ctx->block_further_commits = true;

    /* block commits in data manager */
    rc = dm_get_commit_ctxs(rp_ctx->dm_ctx, &commit_ctxs);
    CHECK_RC_MSG_RETURN(rc, "Failed to retrieve commit contexts");

    MUTEX_LOCK_TIMED_CHECK_RETURN(&commit_ctxs->empty_mutex);
    commit_ctxs->commits_blocked = true;
    pthread_mutex_unlock(&commit_ctxs->empty_mutex);

    /* wait until all commit context are freed or timeout expires */
    rc = dm_wait_for_commit_context_to_be_empty(rp_ctx->dm_ctx);
    return rc;
}
