/**
 * @file client_library.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Sysrepo client library (public + non-public API) implementation.
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
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>

#include "sr_common.h"
#include "connection_manager.h"

#include "client_library.h"
#include "cl_subscription_manager.h"
#include "cl_common.h"
#include "trees_internal.h"

/**
 * @brief Number of items being fetched in one message from Sysrepo Engine by
 * processing of sr_get_items_iter calls.
 */
#define CL_GET_ITEMS_FETCH_LIMIT 100

/**
 * @brief Maximum number of children nodes (of any parent node) being fetched in
 * one message from Sysrepo Engine by processing of sr_get_subtree(s)_*_chunk(s).
 */
#define CL_GET_SUBTREE_CHUNK_CHILD_LIMIT 20

/**
 * @brief Maximum number of *not-yet-loaded* levels of any subtree chunk sent by the operation
 * sr_get_subtree(s)_*_chunk(s).
 */
#define CL_GET_SUBTREE_CHUNK_DEPTH_LIMIT 2

/**
 * @brief Filesystem path prefix for generating temporary socket names used
 * for local unix-domain connections (library mode).
 */
#define CL_LCONN_PATH_PREFIX "/tmp/sysrepo-local"

/**
 * @brief Umbrella context of a logical subscription, that can contain multiple
 * 'real' subscriptions in Subscription Manager.
 */
typedef struct sr_subscription_ctx_s {
    cl_sm_subscription_ctx_t **sm_subscriptions;  /**< Array of pointers to Subscription Manager's subscriptions. */
    size_t sm_subscription_cnt;                   /**< Count of sm_subscriptions stored within this context. */
} sr_subscription_ctx_t;

/**
 * @brief Structure holding data for iterative access to items (::sr_get_items_iter).
 */
typedef struct sr_val_iter_s {
    char *xpath;                    /**< Xpath of the request. */
    size_t offset;                  /**< Offset where the next data should be read. */
    size_t limit;                   /**< How many items should be read. */
    sr_val_t **buff_values;         /**< Buffered values. */
    size_t index;                   /**< Index into buff_values pointing to the value to be returned by next call. */
    size_t count;                   /**< Number of elements currently buffered. */
} sr_val_iter_t;

/**
 * @brief Structure holding data for iterative access to changes (::sr_get_changes_iter).
 */
typedef struct sr_change_iter_s {
    char *xpath;                    /**< Xpath of the request. */
    size_t offset;                  /**< Offset where the next data should be read. */
    size_t limit;                   /**< How many items should be read. */
    sr_change_oper_t *operations;   /**< Type of the change */
    sr_val_t **new_values;          /**< Buffered new values. */
    sr_val_t **old_values;          /**< Buffered old values. */
    size_t index;                   /**< Index into buff_values pointing to the value to be returned by next call. */
    size_t count;                   /**< Number of elements currently buffered. */
} sr_change_iter_t;

static int connections_cnt = 0;               /**< Number of active connections to the Sysrepo Engine. */
static int subscriptions_cnt = 0;             /**< Number of active subscriptions. */
static cl_sm_ctx_t *cl_sm_ctx = NULL;         /**< Subscription Manager context. */
static int local_watcher_fd[2] = { -1, -1 };  /**< File descriptor pair of an application-local file descriptor watcher. */
static pthread_mutex_t global_lock = PTHREAD_MUTEX_INITIALIZER;  /**< Mutex for locking shared global variables. */

/**
 * @brief Initializes our own sysrepo engine (fallback option if sysrepo daemon is not running)
 */
static int
cl_engine_init_local(sr_conn_ctx_t *conn_ctx, const char *socket_path)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(conn_ctx, socket_path);

    /* initialize local Connection Manager */
    rc = cm_init(CM_MODE_LOCAL, socket_path, &conn_ctx->local_cm);
    CHECK_RC_MSG_RETURN(rc, "Unable to initialize local Connection Manager.");

    /* start the server */
    rc = cm_start(conn_ctx->local_cm);
    CHECK_RC_MSG_RETURN(rc, "Unable to start local Connection Manager.");

    return rc;
}

/**
 * @brief Creates get_items request with options and send it
 */
static int
cl_send_get_items_iter(sr_session_ctx_t *session, const char *xpath, size_t offset, size_t limit, Sr__Msg **msg_resp)
{
    Sr__Msg *msg_req = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(session, session->conn_ctx, xpath, msg_resp);

    /* prepare get_item message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__GET_ITEMS, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate get_items message.");

    /* fill in the path */
    sr_mem_edit_string(sr_mem, &msg_req->request->get_items_req->xpath, xpath);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->get_items_req->xpath, rc, cleanup);

    /* fill in other arguments */
    msg_req->request->get_items_req->limit = limit;
    msg_req->request->get_items_req->offset = offset;
    msg_req->request->get_items_req->has_limit = true;
    msg_req->request->get_items_req->has_offset = true;

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, msg_resp, NULL, SR__OPERATION__GET_ITEMS);

    sr_msg_free(msg_req);

    return rc;

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    return rc;
}

/**
 * @brief Creates get_changes request and sends it
 */
static int
cl_send_get_changes(sr_session_ctx_t *session, const char *xpath, size_t offset, size_t limit, Sr__Msg **msg_resp)
{
    Sr__Msg *msg_req = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(session, session->conn_ctx, xpath, msg_resp);

    /* prepare get_item message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__GET_CHANGES, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate get_items message.");

    /* fill in the path */
    sr_mem_edit_string(sr_mem, &msg_req->request->get_changes_req->xpath, xpath);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->get_changes_req->xpath, rc, cleanup);

    /* fill in other arguments */
    msg_req->request->get_changes_req->limit = limit;
    msg_req->request->get_changes_req->offset = offset;

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, msg_resp, NULL, SR__OPERATION__GET_CHANGES);

    sr_msg_free(msg_req);

    return rc;

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    return rc;
}

/**
 * @brief Closes and cleans up the subscription.
 */
static int
cl_subscription_close(sr_session_ctx_t *session, cl_sm_subscription_ctx_t *subscription)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(session);
    if (NULL != subscription) {
        /* prepare unsubscribe message */
        rc = sr_mem_new(0, &sr_mem);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
        rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__UNSUBSCRIBE, session->id, &msg_req);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate unsubscribe message.");

        msg_req->request->unsubscribe_req->type = subscription->type;

        sr_mem_edit_string(sr_mem, &msg_req->request->unsubscribe_req->destination, subscription->delivery_address);
        CHECK_NULL_NOMEM_GOTO(msg_req->request->unsubscribe_req->destination, rc, cleanup);
        msg_req->request->unsubscribe_req->subscription_id = subscription->id;

        if (NULL != subscription->module_name) {
           sr_mem_edit_string(sr_mem, &msg_req->request->unsubscribe_req->module_name, subscription->module_name);
           CHECK_NULL_NOMEM_GOTO(msg_req->request->unsubscribe_req->module_name, rc, cleanup);
        }

        /* send the request and receive the response */
        rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__UNSUBSCRIBE);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");
    }
cleanup:
    /* cleanup the SM subscription */
    cl_sm_subscription_cleanup(subscription);

    /* global resources cleanup */
    pthread_mutex_lock(&global_lock);
    subscriptions_cnt--;
    if (0 == subscriptions_cnt) {
        /* this is the last subscription - destroy subscription manager */
        cl_sm_cleanup(cl_sm_ctx, true);
        cl_sm_ctx = NULL;
    }
    if ((0 == subscriptions_cnt) && (0 == connections_cnt)) {
        /* destroy library-global resources */
        sr_logger_cleanup();
    }
    pthread_mutex_unlock(&global_lock);

    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return rc;
}

/**
 * @brief Initializes a new subscription.
 */
static int
cl_subscription_init(sr_session_ctx_t *session, Sr__SubscriptionType type, const char *module_name,
        sr_api_variant_t api_variant, void *private_ctx, sr_subscription_ctx_t **sr_subscription_p,
        cl_sm_subscription_ctx_t **sm_subscription_p, Sr__Msg **msg_req_p)
{
    Sr__Msg *msg_req = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    sr_subscription_ctx_t *sr_subscription = NULL;
    cl_sm_subscription_ctx_t **tmp = NULL, *sm_subscription = NULL;
    cl_sm_server_ctx_t *server_ctx = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(session, sr_subscription_p, sm_subscription_p, msg_req_p);

    /* check if this is the first subscription, if yes, initialize subscription manager */
    pthread_mutex_lock(&global_lock);
    if (0 == subscriptions_cnt) {
        /* this is the first subscription - initialize subscription manager */
        rc = cl_sm_init((-1 != local_watcher_fd[0]), local_watcher_fd, &cl_sm_ctx);
    }
    subscriptions_cnt++;
    if (SR_ERR_OK == rc) {
        rc = cl_sm_get_server_ctx(cl_sm_ctx, module_name, &server_ctx);
    }
    pthread_mutex_unlock(&global_lock);

    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot initialize Client Subscription Manager.");

    /* prepare subscribe message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__SUBSCRIBE, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate subscribe message.");

    /* initialize subscription ctx */
    rc = cl_sm_subscription_init(cl_sm_ctx, server_ctx, &sm_subscription);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by initialization of the subscription in the Subscription Manager.");

    sm_subscription->api_variant = api_variant;
    sm_subscription->type = type;
    sm_subscription->private_ctx = private_ctx;
    if (NULL != module_name) {
        sm_subscription->module_name = strdup(module_name);
        CHECK_NULL_NOMEM_GOTO(sm_subscription->module_name, rc, cleanup);
    }

    /* fill-in subscription details into GPB message */
    sr_mem_edit_string(sr_mem, &msg_req->request->subscribe_req->destination, sm_subscription->delivery_address);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->subscribe_req->destination, rc, cleanup);

    msg_req->request->subscribe_req->subscription_id = sm_subscription->id;
    msg_req->request->subscribe_req->type = type;
    msg_req->request->subscribe_req->api_variant = sr_api_variant_sr_to_gpb(api_variant);

    /* if not already allocated, allocate 'umbrella' subscription context */
    if (NULL == *sr_subscription_p) {
        sr_subscription = calloc(1, sizeof(*sr_subscription));
        CHECK_NULL_NOMEM_GOTO(sr_subscription, rc, cleanup);
    } else {
        sr_subscription = *sr_subscription_p;
    }

    /* realloc array of SM subscriptions */
    tmp = realloc(sr_subscription->sm_subscriptions, (sizeof(*tmp) * (sr_subscription->sm_subscription_cnt + 1)));
    CHECK_NULL_NOMEM_GOTO(tmp, rc, cleanup);
    /* save the new subscription in the array */
    sr_subscription->sm_subscriptions = tmp;
    sr_subscription->sm_subscriptions[sr_subscription->sm_subscription_cnt] = sm_subscription;
    sr_subscription->sm_subscription_cnt += 1;

    *sr_subscription_p = sr_subscription;
    *sm_subscription_p = sm_subscription;
    *msg_req_p = msg_req;

    return rc;

cleanup:
    if (NULL == *sr_subscription_p) {
        free(sr_subscription);
    }
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    cl_subscription_close(session, sm_subscription);
    return rc;
}

static void
cl_sr_subscription_remove_one(sr_subscription_ctx_t *sr_subscription)
{
    if (NULL != sr_subscription) {
        if (sr_subscription->sm_subscription_cnt > 1) {
            sr_subscription->sm_subscription_cnt -= 1;
        } else {
            free(sr_subscription->sm_subscriptions);
            free(sr_subscription);
        }
    }
}

int
sr_connect(const char *app_name, const sr_conn_options_t opts, sr_conn_ctx_t **conn_ctx_p)
{
    sr_conn_ctx_t *connection = NULL;
    int rc = SR_ERR_OK;
    char socket_path[PATH_MAX] = { 0, };

    CHECK_NULL_ARG2(app_name, conn_ctx_p);

    SR_LOG_DBG_MSG("Connecting to Sysrepo Engine.");

    /* create the connection */
    rc = cl_connection_create(&connection);
    CHECK_RC_MSG_RETURN(rc, "Unable to create new connection.");

    /* check if this is the first connection */
    pthread_mutex_lock(&global_lock);
    if (0 == connections_cnt) {
        /* this is the first connection - initialize logging */
        sr_logger_init(app_name);
    }
    connections_cnt++;
    pthread_mutex_unlock(&global_lock);

    /* attempt to connect to sysrepo daemon socket */
    rc = cl_socket_connect(connection, SR_DAEMON_SOCKET);
    if (SR_ERR_OK != rc) {
        if (opts & SR_CONN_DAEMON_REQUIRED) {
            SR_LOG_ERR_MSG("Sysrepo daemon not detected while library mode disallowed.");
            if ((opts & SR_CONN_DAEMON_START) && (0 == getuid())) {
                /* sysrepo daemon start requested and process is running under root privileges */
                int ret = system("sysrepod");
                if (0 == ret) {
                    SR_LOG_INF_MSG("Sysrepo daemon has been started.");
                } else {
                    SR_LOG_WRN("Unable to start sysrepo daemon, error code=%d.", ret);
                }
            }
            goto cleanup;
        } else {
            SR_LOG_WRN_MSG("Sysrepo daemon not detected. Connecting to local Sysrepo Engine.");

            /* connect in library mode */
            connection->library_mode = true;
            snprintf(socket_path, PATH_MAX, "%s-%d.sock", CL_LCONN_PATH_PREFIX, getpid());

            /* attempt to connect to our own sysrepo engine (local engine may already exist) */
            rc = cl_socket_connect(connection, socket_path);
            if (SR_ERR_OK != rc) {
                /* initialize our own sysrepo engine and attempt to connect again */
                SR_LOG_INF_MSG("Local Sysrepo Engine not running yet, initializing new one.");

                rc = cl_engine_init_local(connection, socket_path);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to start local sysrepo engine.");

                rc = cl_socket_connect(connection, socket_path);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to connect to the local sysrepo engine.");
            }
            SR_LOG_INF("Connected to local Sysrepo Engine at socket=%s", socket_path);
        }
    } else {
        SR_LOG_INF("Connected to daemon Sysrepo Engine at socket=%s", SR_DAEMON_SOCKET);
    }

    *conn_ctx_p = connection;
    return SR_ERR_OK;

cleanup:
    if ((NULL != connection) && (NULL != connection->local_cm)) {
        cm_cleanup(connection->local_cm);
    }
    cl_connection_cleanup(connection);
    return rc;
}

void
sr_disconnect(sr_conn_ctx_t *conn_ctx)
{
    if (NULL != conn_ctx) {
        if (NULL != conn_ctx->local_cm) {
            /* destroy our own sysrepo engine */
            cm_stop(conn_ctx->local_cm);
            cm_cleanup(conn_ctx->local_cm);
        }

        pthread_mutex_lock(&global_lock);
        connections_cnt--;
        if ((0 == subscriptions_cnt) && (0 == connections_cnt)) {
            /* destroy library-global resources */
            sr_logger_cleanup();
        }
        pthread_mutex_unlock(&global_lock);

        cl_connection_cleanup(conn_ctx);
    }
}

int
sr_session_start(sr_conn_ctx_t *conn_ctx, sr_datastore_t datastore,
        const sr_sess_options_t opts, sr_session_ctx_t **session_p)
{
    return sr_session_start_user(conn_ctx, NULL, datastore, opts, session_p);
}

int
sr_session_start_user(sr_conn_ctx_t *conn_ctx, const char *user_name, sr_datastore_t datastore,
        const sr_sess_options_t opts, sr_session_ctx_t **session_p)
{
    sr_session_ctx_t *session = NULL;
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(conn_ctx, session_p);

    /* create a new session */
    rc = cl_session_create(conn_ctx, &session);
    CHECK_RC_MSG_RETURN(rc, "Unable to create new session.");

    /* prepare session_start message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__SESSION_START, /* undefined session id */ 0, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    msg_req->request->session_start_req->options = opts;
    msg_req->request->session_start_req->datastore = sr_datastore_sr_to_gpb(datastore);

    /* set user name if provided */
    if (NULL != user_name) {
        sr_mem_edit_string(sr_mem, &msg_req->request->session_start_req->user_name, user_name);
        CHECK_NULL_NOMEM_GOTO(msg_req->request->session_start_req->user_name, rc, cleanup);
    }

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__SESSION_START);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    session->id = msg_resp->response->session_start_resp->session_id;
    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    *session_p = session;
    return SR_ERR_OK;

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    cl_session_cleanup(session);
    return rc;
}

int
sr_session_stop(sr_session_ctx_t *session)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, session->conn_ctx);

    cl_session_clear_errors(session);

    /* prepare session_stop message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__SESSION_STOP, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    msg_req->request->session_stop_req->session_id = session->id;

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__SESSION_STOP);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    cl_session_cleanup(session);

    return SR_ERR_OK; /* do not use cl_session_return - session has been freed one line above */

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);
}

int
sr_session_refresh(sr_session_ctx_t *session)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, session->conn_ctx);

    cl_session_clear_errors(session);

    /* prepare session_stop message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__SESSION_REFRESH, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__SESSION_REFRESH);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);
}

int
sr_session_switch_ds(sr_session_ctx_t* session, sr_datastore_t datastore)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(session);
    cl_session_clear_errors(session);

    /* prepare session_switch ds message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__SESSION_SWITCH_DS, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    msg_req->request->session_switch_ds_req->datastore = sr_datastore_sr_to_gpb(datastore);

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__SESSION_SWITCH_DS);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);
}

int
sr_session_set_options(sr_session_ctx_t *session, const sr_sess_options_t opts)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(session);
    cl_session_clear_errors(session);

    /* prepare session_set_opts message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__SESSION_SET_OPTS, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    msg_req->request->session_set_opts_req->options = opts;

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__SESSION_SET_OPTS);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);

}

int
sr_list_schemas(sr_session_ctx_t *session, sr_schema_t **schemas, size_t *schema_cnt)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(session, session->conn_ctx, schemas, schema_cnt);

    cl_session_clear_errors(session);

    /* prepare list_schemas message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__LIST_SCHEMAS, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__LIST_SCHEMAS);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    /* copy schemas from response to output argument */
    if (0 != msg_resp->response->list_schemas_resp->n_schemas) {
        rc = sr_schemas_gpb_to_sr((sr_mem_ctx_t *)msg_resp->_sysrepo_mem_ctx,
                                  (const Sr__Schema**)msg_resp->response->list_schemas_resp->schemas,
                                  msg_resp->response->list_schemas_resp->n_schemas, schemas);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to copy schemas from GPB.");
    }
    *schema_cnt = msg_resp->response->list_schemas_resp->n_schemas;

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);
}

int
sr_get_schema(sr_session_ctx_t *session, const char *module_name, const char *module_revision,
        const char *submodule_name, sr_schema_format_t format, char **schema_content)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(session, session->conn_ctx, module_name, schema_content);

    cl_session_clear_errors(session);

    /* prepare get_schema message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__GET_SCHEMA, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* set arguments */
    sr_mem_edit_string(sr_mem, &msg_req->request->get_schema_req->module_name, module_name);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->get_schema_req->module_name, rc, cleanup);
    if (NULL != submodule_name) {
        sr_mem_edit_string(sr_mem, &msg_req->request->get_schema_req->submodule_name, submodule_name);
        CHECK_NULL_NOMEM_GOTO(msg_req->request->get_schema_req->submodule_name, rc, cleanup);
    }
    if(NULL != module_revision) {
        sr_mem_edit_string(sr_mem, &msg_req->request->get_schema_req->revision, module_revision);
        CHECK_NULL_NOMEM_GOTO(msg_req->request->get_schema_req->revision, rc, cleanup);
    }
    msg_req->request->get_schema_req->yang_format = (format == SR_SCHEMA_YANG);

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__GET_SCHEMA);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    /* copy schema content */
    if (NULL != msg_resp->response->get_schema_resp->schema_content) {
        *schema_content = strdup(msg_resp->response->get_schema_resp->schema_content);
        CHECK_NULL_NOMEM_GOTO(*schema_content, rc, cleanup);
    }

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);
}

int
sr_get_item(sr_session_ctx_t *session, const char *xpath, sr_val_t **value)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(session, session->conn_ctx, xpath, value);

    cl_session_clear_errors(session);

    /* prepare get_item message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__GET_ITEM, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* fill in the path */
    sr_mem_edit_string(sr_mem, &msg_req->request->get_item_req->xpath, xpath);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->get_item_req->xpath, rc, cleanup);

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__GET_ITEM);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    /* duplicate the content of gpb to sr_val_t */
    rc = sr_dup_gpb_to_val_t((sr_mem_ctx_t *)msg_resp->_sysrepo_mem_ctx,
                             msg_resp->response->get_item_resp->value, value);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Value duplication failed.");

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);
}

int
sr_get_items(sr_session_ctx_t *session, const char *xpath, sr_val_t **values, size_t *value_cnt)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(session, session->conn_ctx, xpath, values, value_cnt);

    cl_session_clear_errors(session);

    /* prepare get_item message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__GET_ITEMS, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* fill in the path */
    sr_mem_edit_string(sr_mem, &msg_req->request->get_items_req->xpath, xpath);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->get_items_req->xpath, rc, cleanup);

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__GET_ITEMS);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    /* copy the content of gpb values to sr_val_t */
    rc = sr_values_gpb_to_sr((sr_mem_ctx_t *)msg_resp->_sysrepo_mem_ctx, msg_resp->response->get_items_resp->values,
                             msg_resp->response->get_items_resp->n_values, values, value_cnt);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by copying the values from GPB.");

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);
}

int
sr_get_items_iter(sr_session_ctx_t *session, const char *xpath, sr_val_iter_t **iter)
{
    Sr__Msg *msg_resp = NULL;
    sr_val_iter_t *it = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(session, session->conn_ctx, xpath, iter);

    cl_session_clear_errors(session);

    rc = cl_send_get_items_iter(session, xpath, 0, CL_GET_ITEMS_FETCH_LIMIT, &msg_resp);
    if (SR_ERR_NOT_FOUND == rc) {
        SR_LOG_DBG("No items found for xpath '%s'", xpath);
        /* SR_ERR_NOT_FOUND will be returned on get_item_next call */
        rc = SR_ERR_OK;
    } else {
        CHECK_RC_LOG_GOTO(rc, cleanup, "Sending get_items request failed '%s'", xpath);
    }

    it = calloc(1, sizeof(*it));
    CHECK_NULL_NOMEM_GOTO(it, rc, cleanup);

    it->index = 0;
    it->count = msg_resp->response->get_items_resp->n_values;
    it->offset = it->count;

    it->xpath = strdup(xpath);
    CHECK_NULL_NOMEM_GOTO(it->xpath, rc, cleanup);

    it->buff_values = calloc(it->count, sizeof(*it->buff_values));
    CHECK_NULL_NOMEM_GOTO(it->buff_values, rc, cleanup);

    /* copy the content of gpb to sr_val_t */
    for (size_t i = 0; i < it->count; i++) {
        rc = sr_dup_gpb_to_val_t((sr_mem_ctx_t *)msg_resp->_sysrepo_mem_ctx,
                                 msg_resp->response->get_items_resp->values[i], &it->buff_values[i]);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Copying from gpb to sr_val_t failed");
            sr_free_values_arr(it->buff_values, i);
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
    }

    *iter = it;

    sr_msg_free(msg_resp);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    if (NULL != it){
        free(it->xpath);
        free(it);
    }
    return cl_session_return(session, rc);
}

int
sr_get_item_next(sr_session_ctx_t *session, sr_val_iter_t *iter, sr_val_t **value)
{
    int rc = SR_ERR_OK;
    Sr__Msg *msg_resp = NULL;

    CHECK_NULL_ARG3(session, iter, value);

    cl_session_clear_errors(session);

    if (0 == iter->count) {
        /* No more data to be read */
        *value = NULL;
        return SR_ERR_NOT_FOUND;
    } else if (iter->index < iter->count) {
        /* There are buffered data */
        *value = iter->buff_values[iter->index++];
    } else {
        /* Fetch more items */
        rc = cl_send_get_items_iter(session, iter->xpath, iter->offset,
                CL_GET_ITEMS_FETCH_LIMIT, &msg_resp);
        if (SR_ERR_NOT_FOUND == rc) {
            SR_LOG_DBG("All items has been read for xpath '%s'", iter->xpath);
            goto cleanup;
        } else {
            CHECK_RC_LOG_GOTO(rc, cleanup, "Fetching more items failed '%s'", iter->xpath);
        }

        size_t received_cnt = msg_resp->response->get_items_resp->n_values;
        if (0 == received_cnt) {
            /* There is no more data to be read */
            *value = NULL;
            rc = SR_ERR_NOT_FOUND;
            goto cleanup;
        }
        if (iter->count < received_cnt) {
            /* realloc the array for buffered values pointers */
            sr_val_t **tmp = NULL;
            tmp = realloc(iter->buff_values, received_cnt * sizeof(*iter->buff_values));
            CHECK_NULL_NOMEM_GOTO(tmp, rc, cleanup);
            iter->buff_values = tmp;
        }
        iter->index = 0;
        iter->count = received_cnt;

        /* copy the content of gpb to sr_val_t*/
        for (size_t i = 0; i < iter->count; i++){
            rc = sr_dup_gpb_to_val_t((sr_mem_ctx_t *)msg_resp->_sysrepo_mem_ctx,
                    msg_resp->response->get_items_resp->values[i], &iter->buff_values[i]);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR_MSG("Copying from gpb to sr_val_t failed");
                sr_free_values_arr(iter->buff_values, i);
                iter->count = 0;
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
        }
        *value = iter->buff_values[iter->index++];
        iter->offset+=received_cnt;
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);
}

void
sr_free_val_iter(sr_val_iter_t *iter){
    if (NULL == iter){
        return;
    }
    free(iter->xpath);
    iter->xpath = NULL;
    if (NULL != iter->buff_values) {
        /* free items that has not been passed to user already*/
        sr_free_values_arr_range(iter->buff_values, iter->index, iter->count);
        iter->buff_values = NULL;
    }
    free(iter);
}

int
sr_get_subtree(sr_session_ctx_t *session, const char *xpath, sr_get_subtree_options_t opts,
        sr_node_t **subtree)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(session, session->conn_ctx, xpath, subtree);

    if (opts & SR_GET_SUBTREE_ITERATIVE) {
        return sr_get_subtree_first_chunk(session, xpath, subtree);
    }

    cl_session_clear_errors(session);

    /* prepare get_subtree message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__GET_SUBTREE, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* fill in the path */
    sr_mem_edit_string(sr_mem, &msg_req->request->get_subtree_req->xpath, xpath);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->get_subtree_req->xpath, rc, cleanup);

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__GET_SUBTREE);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    /* duplicate the content of gpb to sr_node_t */
    rc = sr_dup_gpb_to_tree((sr_mem_ctx_t *)msg_resp->_sysrepo_mem_ctx,
                             msg_resp->response->get_subtree_resp->tree, subtree);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Subtree duplication failed.");

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);
}

int
sr_get_subtrees(sr_session_ctx_t *session, const char *xpath, sr_get_subtree_options_t opts,
        sr_node_t **subtrees, size_t *subtree_cnt)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(session, session->conn_ctx, xpath, subtrees, subtree_cnt);

    if (opts & SR_GET_SUBTREE_ITERATIVE) {
        return sr_get_subtrees_first_chunks(session, xpath, subtrees, subtree_cnt);
    }

    cl_session_clear_errors(session);

    /* prepare get_subtrees message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__GET_SUBTREES, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* fill in the path */
    sr_mem_edit_string(sr_mem, &msg_req->request->get_subtrees_req->xpath, xpath);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->get_subtrees_req->xpath, rc, cleanup);

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__GET_SUBTREES);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    /* copy the content of gpb trees to sr_node_t */
    rc = sr_trees_gpb_to_sr((sr_mem_ctx_t *)msg_resp->_sysrepo_mem_ctx, msg_resp->response->get_subtrees_resp->trees,
                             msg_resp->response->get_subtrees_resp->n_trees, subtrees, subtree_cnt);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by copying subtrees from GPB.");

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);
}

/**
 * @brief Returns true if the passed node could be an internal one (based on the type), false otherwise.
 */
static bool
sr_is_internal_node(sr_node_t *node)
{
    switch (node->type) {
        case SR_CONTAINER_T:
        case SR_CONTAINER_PRESENCE_T:
        case SR_LIST_T:
            return true;
        default:
            return false;
    }
}

/**
 * @brief Add a tree iterator into a subtree chunk.
 */
static int
sr_add_tree_iterator(sr_node_t *root, sr_node_t *iterator, const char *xpath, bool bounded_slice, size_t depth_limit)
{
    int rc = SR_ERR_OK;
    bool process_children = true;
    sr_node_t *node = NULL, *prev = NULL;
    size_t depth = 0, child_cnt = 0;
    CHECK_NULL_ARG(root);

    if (NULL == iterator) {
        if (NULL == xpath) {
            return SR_ERR_INVAL_ARG;
        }
        rc = sr_new_node(root->_sr_mem, xpath, "sysrepo", &iterator);
        CHECK_RC_MSG_RETURN(rc, "Failed to create sysrepo tree iterator.");
        iterator->type = SR_TREE_ITERATOR_T;
        iterator->data.int32_val = 0; /* usage counter */
    }

    node = root;
    do {
        if (process_children) {
            while (node->first_child) {
                ++depth;
                node = node->first_child;
            }
        }
        if (sr_is_internal_node(node) && NULL == node->first_child && depth == depth_limit-1) {
            sr_node_insert_child(node, iterator);
            ++iterator->data.int32_val;
        }
        if (node != root) {
            if (node->next) {
                node = node->next;
                process_children = true;
            } else {
                child_cnt = 1;
                prev = node->prev;
                while (prev) {
                    ++child_cnt;
                    prev = prev->prev;
                }
                if ((1 < depth || (1 == depth && !bounded_slice))
                        && CL_GET_SUBTREE_CHUNK_CHILD_LIMIT == child_cnt) {
                    sr_node_insert_child(node->parent, iterator);
                    ++iterator->data.int32_val;
                }
                node = node->parent;
                --depth;
                process_children = false;
            }
        }
    } while (node != root);
    assert(0 == depth);

    if (0 == iterator->data.int32_val) {
        /* iterator is not really used */
        sr_free_node(iterator);
    }

    return rc;
}

int
sr_get_subtree_first_chunk(sr_session_ctx_t *session, const char *xpath, sr_node_t **chunk_p)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    sr_node_t *chunk = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(session, session->conn_ctx, xpath, chunk_p);

    cl_session_clear_errors(session);

    /* prepare get_subtree_chunk message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__GET_SUBTREE_CHUNK, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* fill in the operation arguments */
    sr_mem_edit_string(sr_mem, &msg_req->request->get_subtree_chunk_req->xpath, xpath);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->get_subtree_chunk_req->xpath, rc, cleanup);
    msg_req->request->get_subtree_chunk_req->single = true;
    msg_req->request->get_subtree_chunk_req->slice_offset = 0;
    msg_req->request->get_subtree_chunk_req->slice_width = CL_GET_SUBTREE_CHUNK_CHILD_LIMIT;
    msg_req->request->get_subtree_chunk_req->child_limit = CL_GET_SUBTREE_CHUNK_CHILD_LIMIT;
    msg_req->request->get_subtree_chunk_req->depth_limit = CL_GET_SUBTREE_CHUNK_DEPTH_LIMIT;

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__GET_SUBTREE_CHUNK);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    /* duplicate the content of gpb to sr_node_t */
    if (0 == msg_resp->response->get_subtree_chunk_resp->n_chunk) {
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }
    if (1 < msg_resp->response->get_subtree_chunk_resp->n_chunk) {
        SR_LOG_ERR_MSG("Sysrepo returned more subtree chunks than expected.");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }
    if (msg_resp->response->get_subtree_chunk_resp->n_xpath != msg_resp->response->get_subtree_chunk_resp->n_chunk) {
        SR_LOG_ERR_MSG("List of node-ids does not match the list of subtree chunks.");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }
    rc = sr_dup_gpb_to_tree((sr_mem_ctx_t *)msg_resp->_sysrepo_mem_ctx,
                             msg_resp->response->get_subtree_chunk_resp->chunk[0], &chunk);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Subtree chunk duplication failed.");

    rc = sr_add_tree_iterator(chunk, NULL, msg_resp->response->get_subtree_chunk_resp->xpath[0],
            false, CL_GET_SUBTREE_CHUNK_DEPTH_LIMIT);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to add tree iterator into a subtree chunk.");

    *chunk_p = chunk;

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    if (SR_ERR_OK != rc) {
        sr_free_tree(chunk);
    }
    return cl_session_return(session, rc);
}

int
sr_get_subtrees_first_chunks(sr_session_ctx_t *session, const char *xpath, sr_node_t **chunks_p,
        size_t *chunk_cnt_p)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    sr_node_t *chunks = NULL;
    size_t chunk_cnt = 0;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(session, session->conn_ctx, xpath, chunks_p, chunk_cnt_p);

    cl_session_clear_errors(session);

    /* prepare get_subtree_chunk message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__GET_SUBTREE_CHUNK, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* fill in the operation arguments */
    sr_mem_edit_string(sr_mem, &msg_req->request->get_subtree_chunk_req->xpath, xpath);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->get_subtree_chunk_req->xpath, rc, cleanup);
    msg_req->request->get_subtree_chunk_req->single = false;
    msg_req->request->get_subtree_chunk_req->slice_offset = 0;
    msg_req->request->get_subtree_chunk_req->slice_width = CL_GET_SUBTREE_CHUNK_CHILD_LIMIT;
    msg_req->request->get_subtree_chunk_req->child_limit = CL_GET_SUBTREE_CHUNK_CHILD_LIMIT;
    msg_req->request->get_subtree_chunk_req->depth_limit = CL_GET_SUBTREE_CHUNK_DEPTH_LIMIT;

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__GET_SUBTREE_CHUNK);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    /* duplicate the content of gpb to sr_node_t */
    if (0 == msg_resp->response->get_subtree_chunk_resp->n_chunk) {
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }
    if (msg_resp->response->get_subtree_chunk_resp->n_xpath != msg_resp->response->get_subtree_chunk_resp->n_chunk) {
        SR_LOG_ERR_MSG("List of node-ids does not match the list of subtree chunks.");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }
    rc = sr_trees_gpb_to_sr((sr_mem_ctx_t *)msg_resp->_sysrepo_mem_ctx, msg_resp->response->get_subtree_chunk_resp->chunk,
                             msg_resp->response->get_subtree_chunk_resp->n_chunk, &chunks, &chunk_cnt);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by copying subtree chunks from GPB.");

    for (size_t i = 0; i < chunk_cnt; ++i) {
        rc = sr_add_tree_iterator(chunks+i, NULL, msg_resp->response->get_subtree_chunk_resp->xpath[i],
                false, CL_GET_SUBTREE_CHUNK_DEPTH_LIMIT);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to add tree iterator into a subtree chunk.");
    }

    *chunks_p = chunks;
    *chunk_cnt_p = chunk_cnt;

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    if (SR_ERR_OK != rc) {
        sr_free_trees(chunks, chunk_cnt);
    }
    return cl_session_return(session, rc);
}

int
sr_get_subtree_next_chunk(sr_session_ctx_t *session, sr_node_t *parent)
{
#define BUFFER_LEN  12
    typedef char buffer_t[BUFFER_LEN];
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    sr_node_t *chunk = NULL;
    size_t slice_offset = 0, slice_width = 0, depth_limit = 0, i = 0, index = 0;
    const char *tree_id = NULL;
    char *xpath = NULL;
    buffer_t *indices = NULL;
    size_t xpath_len = 0, indices_len = 0;
    sr_node_t *node = NULL, *child = NULL, *iterator = NULL, *prev = NULL, *next = NULL, *node2 = NULL;
    char *cur = NULL;
    bool bounded_slice = false;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, parent);

    cl_session_clear_errors(session);

    node = parent->first_child;
    while (node && node->type != SR_TREE_ITERATOR_T) {
        child = node;
        node = node->next;
    }

    if (NULL == node) {
        /* no more children of this parent to be loaded */
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }
    iterator = node;

    /* get the JSON node-ID of the root node */
    tree_id = iterator->name;
    if (NULL == tree_id) {
        SR_LOG_ERR_MSG("Encountered tree iterator without xpath.");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* determine the parameters of the slice */
    if (NULL == child && NULL != parent->parent) {
        /* consider also siblings */
        /*  -> slice offset */
        node = parent;
        while (node->prev) {
            ++slice_offset;
            node = node->prev;
        }
        /*  -> slice width */
        node = parent;
        bounded_slice = true;
        while (CL_GET_SUBTREE_CHUNK_CHILD_LIMIT > slice_width && NULL != node) {
            if (SR_TREE_ITERATOR_T == node->type) {
                bounded_slice = false;
                slice_width = CL_GET_SUBTREE_CHUNK_CHILD_LIMIT;
                break;
            }
            if (node->first_child && SR_TREE_ITERATOR_T == node->first_child->type) {
                ++slice_width;
            } else {
                break;
            }
            node = node->next;
        }
        assert(slice_width);
    }
    if (1 < slice_width) {
        /* cover also siblings with this chunk */
        parent = parent->parent;
        depth_limit = CL_GET_SUBTREE_CHUNK_DEPTH_LIMIT + 2;
    } else {
        /* get offset of the first unloaded child */
        slice_offset = 0;
        node = child;
        while (node) {
            ++slice_offset;
            node = node->prev;
        }
        /* include as many nodes as allowed */
        bounded_slice = false;
        slice_width = CL_GET_SUBTREE_CHUNK_CHILD_LIMIT;
        depth_limit = CL_GET_SUBTREE_CHUNK_DEPTH_LIMIT + 1;
    }

    /* construct XPath for the parent node */
    /* -> number of indices */
    node = parent;
    while (NULL != node->parent) {
        ++indices_len;
        node = node->parent;
    }
    /* -> alloc indices */
    if (0 < indices_len) {
        indices = calloc(indices_len, sizeof(buffer_t));
        CHECK_NULL_NOMEM_GOTO(indices, rc, cleanup);
    }
    /* -> compute indices */
    i = indices_len;
    node = parent;
    while (NULL != node->parent) {
        --i;
        index = 1;
        prev = node->prev;
        while (prev) {
            if (0 == strcmp(node->name, prev->name) &&
                ((NULL != node->module_name && NULL != prev->module_name &&
                  0 == strcmp(node->module_name, prev->module_name)) ||
                 (NULL == node->module_name && NULL == prev->module_name))) {
                ++index;
            }
            prev = prev->prev;
        }
        snprintf(indices[i], BUFFER_LEN, "%lu", index);
        node = node->parent;
    }
    /* -> xpath length */
    xpath_len = strlen(tree_id);
    i = indices_len;
    node = parent;
    while (NULL != node->parent) {
        --i;
        xpath_len += strlen(node->name);
        xpath_len += strlen(indices[i]) + 2; /* "[" + index + "]" */
        if (NULL != node->module_name) {
            xpath_len += strlen(node->module_name) + 1 /* ":" */;
        }
        xpath_len += 1; /* "/" */
        node = node->parent;
    }
    /* -> alloc xpath */
    xpath = calloc(xpath_len + 1, 1);
    CHECK_NULL_NOMEM_GOTO(xpath, rc, cleanup);
    /* -> copy strings */
    strcpy(xpath, tree_id);
    i = indices_len;
    node = parent;
    cur = xpath + xpath_len;
    while (NULL != node->parent) {
        --i;
        --cur;
        *cur = ']';
        cur -= strlen(indices[i]);
        memcpy(cur, indices[i], strlen(indices[i]));
        --cur;
        *cur = '[';
        cur -= strlen(node->name);
        memcpy(cur, node->name, strlen(node->name));
        if (NULL != node->module_name) {
            --cur;
            *cur = ':';
            cur -= strlen(node->module_name);
            memcpy(cur, node->module_name, strlen(node->module_name));
        }
        --cur;
        *cur = '/';
        node = node->parent;
    }

    /* prepare get_subtree_chunk message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__GET_SUBTREE_CHUNK, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* fill in the operation arguments */
    sr_mem_edit_string(sr_mem, &msg_req->request->get_subtree_chunk_req->xpath, xpath);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->get_subtree_chunk_req->xpath, rc, cleanup);
    msg_req->request->get_subtree_chunk_req->single = true;
    msg_req->request->get_subtree_chunk_req->slice_offset = slice_offset;
    msg_req->request->get_subtree_chunk_req->slice_width = slice_width;
    msg_req->request->get_subtree_chunk_req->child_limit = CL_GET_SUBTREE_CHUNK_CHILD_LIMIT;
    msg_req->request->get_subtree_chunk_req->depth_limit = depth_limit;

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, parent->_sr_mem, SR__OPERATION__GET_SUBTREE_CHUNK);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    /* duplicate the content of gpb to sr_node_t */
    if (0 == msg_resp->response->get_subtree_chunk_resp->n_chunk) {
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }
    if (1 < msg_resp->response->get_subtree_chunk_resp->n_chunk) {
        SR_LOG_ERR_MSG("Sysrepo returned more subtree chunks than expected.");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }
    rc = sr_dup_gpb_to_tree((sr_mem_ctx_t *)msg_resp->_sysrepo_mem_ctx,
                             msg_resp->response->get_subtree_chunk_resp->chunk[0], &chunk);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Subtree chunk duplication failed.");

    rc = sr_add_tree_iterator(chunk, iterator, NULL, bounded_slice, depth_limit);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to add tree iterator into a subtree chunk.");

    /* attach the chunk to the tree */
    prev = NULL;
    node = parent->first_child;
    assert(node);
    node2 = chunk->first_child;
    while (slice_offset) {
        prev = node;
        node = node->next;
        assert(node);
        --slice_offset;
    }
    while (node && slice_width) {
        if (SR_TREE_ITERATOR_T == node->type) {
            /* remove iterator reference */
            assert(false == bounded_slice);
            --iterator->data.int32_val;
            /* append the remaining nodes from the chunk */
            if (NULL != node2) {
                parent->last_child = chunk->last_child;
            } else {
                parent->last_child = prev;
            }
            if (prev) {
                prev->next = node2;
                if (NULL != node2 && SR_TREE_ITERATOR_T != node2->type) {
                    node2->prev = prev;
                }
            } else {
                parent->first_child = node2;
            }
            while (node2 && SR_TREE_ITERATOR_T != node2->type) {
                node2->parent = parent;
                node2 = node2->next;
            }
            break; /**< nothing more to add */
        } else {
            if (NULL == node2) {
                /* no more child nodes left in the chunk */
                break;
            }
            /* some clarity checks */
            assert(SR_TREE_ITERATOR_T != node2->type);
            assert(node->first_child && SR_TREE_ITERATOR_T == node->first_child->type &&
                   node->first_child == node->last_child);
            /* move child nodes from node2 to node */
            node->first_child = node->last_child = NULL; /**< remove iterator reference */
            --iterator->data.int32_val;
            node->first_child = node2->first_child;
            node->last_child = node2->last_child;
            node2->first_child = node2->last_child = NULL;
            child = node->first_child;
            while (child && SR_TREE_ITERATOR_T != child->type) {
                child->parent = node;
                child = child->next;
            }
            /* remove the duplicate child node from the chunk */
            next = node2->next;
            if (NULL == node2->_sr_mem) {
                sr_free_tree(node2);
            }
            node2 = next;
        }
        prev = node;
        node = node->next;
        --slice_width;
    }
    if (NULL != node2) {
        /* something unrequested left in the chunk, deallocate it */
        assert(true == bounded_slice);
        do {
            next = node2->next;
            node2->next = node2->prev = node2->parent = NULL;
            if (NULL == node2->_sr_mem) {
                sr_free_tree(node2);
            }
            node2 = next;
        } while (NULL != node2);
    }

    /* remove the duplicate of the parent node from the chunk */
    chunk->first_child = chunk->last_child = NULL;
    sr_free_tree(chunk);
    chunk = NULL;

    /* remove the iterator if it is no longer used */
    if (0 == iterator->data.int32_val) {
        sr_free_node(iterator);
    }

cleanup:
    free(indices);
    free(xpath);
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    sr_free_tree(chunk);
    return cl_session_return(session, rc);
#undef BUFFER_LEN
}

int
sr_set_item(sr_session_ctx_t *session, const char *xpath, const sr_val_t *value, const sr_edit_options_t opts)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    sr_mem_snapshot_t snapshot = { 0, };
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(session, session->conn_ctx, xpath);

    cl_session_clear_errors(session);

    /* prepare get_item message */
    if (NULL != value) {
        sr_mem = value->_sr_mem;
        sr_mem_snapshot(sr_mem, &snapshot);
    } else {
        rc = sr_mem_new(0, &sr_mem);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    }
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__SET_ITEM, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* fill in the path and options */
    sr_mem_edit_string(sr_mem, &msg_req->request->set_item_req->xpath, xpath);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->set_item_req->xpath, rc, cleanup);

    msg_req->request->set_item_req->options = opts;

    /* duplicate the content of sr_val_t to gpb */
    if (NULL != value) {
        rc = sr_dup_val_t_to_gpb(value, &msg_req->request->set_item_req->value);
        CHECK_RC_MSG_GOTO(rc, cleanup, "value duplication failed.");
    }

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__SET_ITEM);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != sr_mem) {
        if (NULL != value) {
            sr_mem_restore(&snapshot);
        } else {
            if (NULL != msg_req) {
                sr_msg_free(msg_req);
            } else {
                sr_mem_free(sr_mem);
            }
        }
    } else {
        sr_msg_free(msg_req);
    }
    sr_msg_free(msg_resp);
    return cl_session_return(session, rc);
}

int
sr_delete_item(sr_session_ctx_t *session, const char *xpath, const sr_edit_options_t opts)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(session, session->conn_ctx, xpath);

    cl_session_clear_errors(session);

    /* prepare delete_item message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__DELETE_ITEM, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* fill in the path and options */
    sr_mem_edit_string(sr_mem, &msg_req->request->delete_item_req->xpath, xpath);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->delete_item_req->xpath, rc, cleanup);

    msg_req->request->delete_item_req->options = opts;

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__DELETE_ITEM);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);
}

int
sr_move_item(sr_session_ctx_t *session, const char *xpath, const sr_move_position_t position, const char *relative_item)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(session, session->conn_ctx, xpath);

    cl_session_clear_errors(session);

    /* prepare get_item message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__MOVE_ITEM, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* fill in the path and direction */
    sr_mem_edit_string(sr_mem, &msg_req->request->move_item_req->xpath, xpath);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->move_item_req->xpath, rc, cleanup);

    msg_req->request->move_item_req->position = sr_move_position_sr_to_gpb(position);

    if (NULL != relative_item) {
        sr_mem_edit_string(sr_mem, &msg_req->request->move_item_req->relative_item, relative_item);
        CHECK_NULL_NOMEM_GOTO(msg_req->request->move_item_req->relative_item, rc, cleanup);
    }

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__MOVE_ITEM);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);
}

int
sr_validate(sr_session_ctx_t *session)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    Sr__ValidateResp *validate_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, session->conn_ctx);

    cl_session_clear_errors(session);

    /* prepare validate message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__VALIDATE, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__VALIDATE);
    if ((SR_ERR_OK != rc) && (SR_ERR_VALIDATION_FAILED != rc)) {
        SR_LOG_ERR_MSG("Error by processing of validate request.");
        goto cleanup;
    }

    validate_resp = msg_resp->response->validate_resp;
    if (SR_ERR_VALIDATION_FAILED == rc) {
        SR_LOG_ERR("Validate operation failed with %zu error(s).", validate_resp->n_errors);

        /* store validation errors within the session */
        if (validate_resp->n_errors > 0) {
            cl_session_set_errors(session, validate_resp->errors, validate_resp->n_errors);
        }
    }

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    return cl_session_return(session, rc);

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);
}

int
sr_commit(sr_session_ctx_t *session)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    Sr__CommitResp *commit_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, session->conn_ctx);

    cl_session_clear_errors(session);

    /* prepare commit message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__COMMIT, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__COMMIT);
    if ((SR_ERR_OK != rc) && (SR_ERR_OPERATION_FAILED != rc)) {
        SR_LOG_ERR_MSG("Error by processing of commit request.");
        goto cleanup;
    }

    commit_resp = msg_resp->response->commit_resp;
    if (SR_ERR_OPERATION_FAILED == rc) {
        SR_LOG_ERR("Commit operation failed with %zu error(s).", commit_resp->n_errors);

        /* store commit errors within the session */
        if (commit_resp->n_errors > 0) {
            cl_session_set_errors(session, commit_resp->errors, commit_resp->n_errors);
        }
    }

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    return cl_session_return(session, rc);

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);
}

int
sr_discard_changes(sr_session_ctx_t *session)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, session->conn_ctx);

    cl_session_clear_errors(session);

    /* prepare discard_changes message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__DISCARD_CHANGES, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__DISCARD_CHANGES);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);
}

int
sr_copy_config(sr_session_ctx_t *session, const char *module_name,
        sr_datastore_t src_datastore, sr_datastore_t dst_datastore)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, session->conn_ctx);

    cl_session_clear_errors(session);

    /* prepare copy_config message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__COPY_CONFIG, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* set the message content */
    msg_req->request->copy_config_req->src_datastore = sr_datastore_sr_to_gpb(src_datastore);
    msg_req->request->copy_config_req->dst_datastore = sr_datastore_sr_to_gpb(dst_datastore);
    if (NULL != module_name) {
        sr_mem_edit_string(sr_mem, &msg_req->request->copy_config_req->module_name, module_name);
        CHECK_NULL_NOMEM_GOTO(msg_req->request->copy_config_req->module_name, rc, cleanup);
    }

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__COPY_CONFIG);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);
}

int
sr_lock_datastore(sr_session_ctx_t *session)
{
    return sr_lock_module(session, NULL);
}

int
sr_unlock_datastore(sr_session_ctx_t *session)
{
    return sr_unlock_module(session, NULL);
}

int
sr_lock_module(sr_session_ctx_t *session, const char *module_name)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, session->conn_ctx);

    cl_session_clear_errors(session);

    /* prepare lock message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__LOCK, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* fill-in module name (if provided) */
    if (NULL != module_name) {
        sr_mem_edit_string(sr_mem, &msg_req->request->lock_req->module_name, module_name);
        CHECK_NULL_NOMEM_GOTO(msg_req->request->lock_req->module_name, rc, cleanup);
    }

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__LOCK);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);
}

int
sr_unlock_module(sr_session_ctx_t *session, const char *module_name)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, session->conn_ctx);

    cl_session_clear_errors(session);

    /* prepare lock message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__UNLOCK, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* fill-in module name (if provided) */
    if (NULL != module_name) {
        sr_mem_edit_string(sr_mem, &msg_req->request->unlock_req->module_name, module_name);
        CHECK_NULL_NOMEM_GOTO(msg_req->request->unlock_req->module_name, rc, cleanup);
    }

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__UNLOCK);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);
}

int
sr_get_last_error(sr_session_ctx_t *session, const sr_error_info_t **error_info)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, error_info);

    pthread_mutex_lock(&session->lock);

    if (0 == session->error_cnt) {
        /* no detailed error information, let's create it from the last error code */
        pthread_mutex_unlock(&session->lock);
        rc = cl_session_set_error(session, sr_strerror(session->last_error), NULL);
        CHECK_RC_MSG_RETURN(rc, "Error by setting latest error information.");
        pthread_mutex_lock(&session->lock);
    }

    *error_info = session->error_info;
    pthread_mutex_unlock(&session->lock);

    return session->last_error;
}

int
sr_get_last_errors(sr_session_ctx_t *session, const sr_error_info_t **error_info, size_t *error_cnt)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(session, error_info, error_cnt);

    pthread_mutex_lock(&session->lock);

    if (0 == session->error_cnt) {
        /* no detailed error information, let's create it from the last error code */
        pthread_mutex_unlock(&session->lock);
        rc = cl_session_set_error(session, sr_strerror(session->last_error), NULL);
        CHECK_RC_MSG_RETURN(rc, "Error by setting latest error information.");
        pthread_mutex_lock(&session->lock);
    }

    *error_info = session->error_info;
    *error_cnt = session->error_cnt;
    pthread_mutex_unlock(&session->lock);

    return session->last_error;
}

int
sr_set_error(sr_session_ctx_t *session, const char *message, const char *xpath)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, message);

    cl_session_clear_errors(session);

    if (! session->notif_session) {
        SR_LOG_ERR_MSG("sr_set_error called on a non-notification session - ignoring.");
        rc = SR_ERR_INVAL_ARG;
    } else {
        rc = cl_session_set_error(session, message, xpath);
    }

    return cl_session_return(session, rc);
}

int
sr_module_install_subscribe(sr_session_ctx_t *session, sr_module_install_cb callback, void *private_ctx,
        sr_subscr_options_t opts, sr_subscription_ctx_t **subscription_p)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_subscription_ctx_t *sr_subscription = NULL;
    cl_sm_subscription_ctx_t *sm_subscription = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(session, callback, subscription_p);

    cl_session_clear_errors(session);

    /* Initialize the subscription */
    if (opts & SR_SUBSCR_CTX_REUSE) {
        sr_subscription = *subscription_p;
    }
    rc = cl_subscription_init(session, SR__SUBSCRIPTION_TYPE__MODULE_INSTALL_SUBS, NULL, SR_API_VALUES,
            private_ctx, &sr_subscription, &sm_subscription, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by initialization of the subscription in the client library.");

    sm_subscription->callback.module_install_cb = callback;

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__SUBSCRIBE);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    *subscription_p = sr_subscription;

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    cl_subscription_close(session, sm_subscription);
    cl_sr_subscription_remove_one(sr_subscription);
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);
}

int
sr_feature_enable_subscribe(sr_session_ctx_t *session, sr_feature_enable_cb callback, void *private_ctx,
        sr_subscr_options_t opts, sr_subscription_ctx_t **subscription_p)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_subscription_ctx_t *sr_subscription = NULL;
    cl_sm_subscription_ctx_t *sm_subscription = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(session, callback, subscription_p);

    cl_session_clear_errors(session);

    /* Initialize the subscription */
    if (opts & SR_SUBSCR_CTX_REUSE) {
        sr_subscription = *subscription_p;
    }
    rc = cl_subscription_init(session, SR__SUBSCRIPTION_TYPE__FEATURE_ENABLE_SUBS, NULL, SR_API_VALUES,
            private_ctx, &sr_subscription, &sm_subscription, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by initialization of the subscription in the client library.");

    sm_subscription->callback.feature_enable_cb = callback;

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__SUBSCRIBE);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    *subscription_p = sr_subscription;

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    cl_subscription_close(session, sm_subscription);
    cl_sr_subscription_remove_one(sr_subscription);
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);
}

int
sr_check_enabled_running(sr_session_ctx_t *session, const char *module_name, bool *res)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(session, module_name, res);

    cl_session_clear_errors(session);

    /* prepare request message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__CHECK_ENABLED_RUNNING, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* fill-in module name */
    sr_mem_edit_string(sr_mem, &msg_req->request->check_enabled_running_req->module_name, module_name);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->check_enabled_running_req->module_name, rc, cleanup);

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__CHECK_ENABLED_RUNNING);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    *res = msg_resp->response->check_enabled_running_resp->enabled;

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);
}

int
sr_module_change_subscribe(sr_session_ctx_t *session, const char *module_name, sr_module_change_cb callback,
        void *private_ctx, uint32_t priority, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription_p)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    sr_subscription_ctx_t *sr_subscription = NULL;
    cl_sm_subscription_ctx_t *sm_subscription = NULL;
    int rc = SR_ERR_OK;
    size_t sm_subscription_cnt = 0;

    CHECK_NULL_ARG4(session, module_name, callback, subscription_p);

    cl_session_clear_errors(session);

    /* Initialize the subscription */
    if (opts & SR_SUBSCR_CTX_REUSE) {
        sr_subscription = *subscription_p;
        if (sr_subscription) {
            sm_subscription_cnt = sr_subscription->sm_subscription_cnt;
        }
    }
    rc = cl_subscription_init(session, SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS, module_name, SR_API_VALUES,
            private_ctx, &sr_subscription, &sm_subscription, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by initialization of the subscription in the client library.");

    sm_subscription->callback.module_change_cb = callback;

    /* fill-in subscription details */
    sr_mem = (sr_mem_ctx_t *)msg_req->_sysrepo_mem_ctx;
    msg_req->request->subscribe_req->type = SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS;
    sr_mem_edit_string(sr_mem, &msg_req->request->subscribe_req->module_name, module_name);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->subscribe_req->module_name, rc, cleanup);

    msg_req->request->subscribe_req->has_notif_event = true;
    msg_req->request->subscribe_req->notif_event =
            (opts & SR_SUBSCR_APPLY_ONLY) ? SR__NOTIFICATION_EVENT__APPLY_EV : SR__NOTIFICATION_EVENT__VERIFY_EV;
    msg_req->request->subscribe_req->has_priority = true;
    msg_req->request->subscribe_req->priority = priority;
    msg_req->request->subscribe_req->has_enable_running = true;
    msg_req->request->subscribe_req->enable_running = !(opts & SR_SUBSCR_PASSIVE);

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__SUBSCRIBE);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    *subscription_p = sr_subscription;

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (sm_subscription) {
        cl_subscription_close(session, sm_subscription);
    }
    if (sr_subscription && sm_subscription_cnt < sr_subscription->sm_subscription_cnt) {
        cl_sr_subscription_remove_one(sr_subscription);
    }
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);
}

int
sr_subtree_change_subscribe(sr_session_ctx_t *session, const char *xpath, sr_subtree_change_cb callback,
        void *private_ctx, uint32_t priority, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription_p)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    sr_subscription_ctx_t *sr_subscription = NULL;
    cl_sm_subscription_ctx_t *sm_subscription = NULL;
    char *module_name = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(session, xpath, callback, subscription_p);

    cl_session_clear_errors(session);

    /* extract module name from xpath */
    rc = sr_copy_first_ns(xpath, &module_name);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by extracting module name from xpath.");

    /* Initialize the subscription */
    if (opts & SR_SUBSCR_CTX_REUSE) {
        sr_subscription = *subscription_p;
    }
    rc = cl_subscription_init(session, SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS, module_name, SR_API_VALUES,
            private_ctx, &sr_subscription, &sm_subscription, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by initialization of the subscription in the client library.");

    sm_subscription->callback.subtree_change_cb = callback;

    /* fill-in subscription details */
    sr_mem = (sr_mem_ctx_t *)msg_req->_sysrepo_mem_ctx;
    msg_req->request->subscribe_req->type = SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS;
    sr_mem_edit_string(sr_mem, &msg_req->request->subscribe_req->module_name, module_name);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->subscribe_req->module_name, rc, cleanup);
    sr_mem_edit_string(sr_mem, &msg_req->request->subscribe_req->xpath, xpath);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->subscribe_req->xpath, rc, cleanup);

    msg_req->request->subscribe_req->has_notif_event = true;
    msg_req->request->subscribe_req->notif_event =
            (opts & SR_SUBSCR_APPLY_ONLY) ? SR__NOTIFICATION_EVENT__APPLY_EV : SR__NOTIFICATION_EVENT__VERIFY_EV;
    msg_req->request->subscribe_req->has_priority = true;
    msg_req->request->subscribe_req->priority = priority;
    msg_req->request->subscribe_req->has_enable_running = true;
    msg_req->request->subscribe_req->enable_running = !(opts & SR_SUBSCR_PASSIVE);

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__SUBSCRIBE);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);
    free(module_name);

    *subscription_p = sr_subscription;

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    cl_subscription_close(session, sm_subscription);
    cl_sr_subscription_remove_one(sr_subscription);
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    free(module_name);
    return cl_session_return(session, rc);
}

int
sr_get_changes_iter(sr_session_ctx_t *session, const char *xpath, sr_change_iter_t **iter)
{
    Sr__Msg *msg_resp = NULL;
    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(session, session->conn_ctx, xpath, iter);

    cl_session_clear_errors(session);

    rc = cl_send_get_changes(session, xpath, 0, CL_GET_ITEMS_FETCH_LIMIT, &msg_resp);
    if (SR_ERR_NOT_FOUND == rc) {
        SR_LOG_DBG("No items found for xpath '%s'", xpath);
        /* SR_ERR_NOT_FOUND will be returned on get_change_next call */
        rc = SR_ERR_OK;
    } else {
        CHECK_RC_LOG_GOTO(rc, cleanup, "Sending get_changes request failed '%s'", xpath);
    }

    it = calloc(1, sizeof(*it));
    CHECK_NULL_NOMEM_GOTO(it, rc, cleanup);

    it->index = 0;
    it->count = msg_resp->response->get_changes_resp->n_changes;
    it->offset = it->count;

    it->xpath = strdup(xpath);
    CHECK_NULL_NOMEM_GOTO(it->xpath, rc, cleanup);

    it->operations = calloc(it->count, sizeof(*it->operations));
    CHECK_NULL_NOMEM_GOTO(it->operations, rc, cleanup);

    it->old_values = calloc(it->count, sizeof(*it->old_values));
    CHECK_NULL_NOMEM_GOTO(it->old_values, rc, cleanup);

    it->new_values = calloc(it->count, sizeof(*it->new_values));
    CHECK_NULL_NOMEM_GOTO(it->new_values, rc, cleanup);

    /* copy the content of gpb to sr_val_t */
    for (size_t i = 0; i < it->count; i++) {
        if (NULL != msg_resp->response->get_changes_resp->changes[i]->new_value) {
            rc = sr_dup_gpb_to_val_t((sr_mem_ctx_t *)msg_resp->_sysrepo_mem_ctx,
                                     msg_resp->response->get_changes_resp->changes[i]->new_value, &it->new_values[i]);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Copying from gpb to sr_val_t failed");
        }
        if (NULL != msg_resp->response->get_changes_resp->changes[i]->old_value) {
            rc = sr_dup_gpb_to_val_t((sr_mem_ctx_t *)msg_resp->_sysrepo_mem_ctx,
                                     msg_resp->response->get_changes_resp->changes[i]->old_value, &it->old_values[i]);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Copying from gpb to sr_val_t failed");
        }
        it->operations[i] = sr_change_op_gpb_to_sr(msg_resp->response->get_changes_resp->changes[i]->changeoperation);
    }

    *iter = it;

    sr_msg_free(msg_resp);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    if (NULL != it){
        sr_free_change_iter(it);
    }
    return cl_session_return(session, rc);
}

int
sr_get_change_next(sr_session_ctx_t *session, sr_change_iter_t *iter, sr_change_oper_t *operation,
        sr_val_t **old_value, sr_val_t **new_value)
{
    int rc = SR_ERR_OK;
    Sr__Msg *msg_resp = NULL;

    CHECK_NULL_ARG5(session, iter, operation, old_value, new_value);

    cl_session_clear_errors(session);

    if (0 == iter->count) {
        /* No more data to be read */
        *new_value = NULL;
        *old_value = NULL;
        return SR_ERR_NOT_FOUND;
    } else if (iter->index < iter->count) {
        /* There are buffered data */
        *operation = iter->operations[iter->index];
        *old_value = iter->old_values[iter->index];
        *new_value = iter->new_values[iter->index];
        iter->index++;
    } else {
        /* Fetch more items */
        rc = cl_send_get_changes(session, iter->xpath, iter->offset,
                CL_GET_ITEMS_FETCH_LIMIT, &msg_resp);
        if (SR_ERR_NOT_FOUND == rc) {
            SR_LOG_DBG("All items has been read for xpath '%s'", iter->xpath);
            goto cleanup;
        } else {
            CHECK_RC_LOG_GOTO(rc, cleanup, "Fetching more items failed '%s'", iter->xpath);
        }

        size_t received_cnt = msg_resp->response->get_changes_resp->n_changes;
        if (0 == received_cnt) {
            /* There is no more data to be read */
            *new_value = NULL;
            *old_value = NULL;
            rc = SR_ERR_NOT_FOUND;
            goto cleanup;
        }
        if (iter->count < received_cnt) {
            /* realloc the array for buffered values pointers */
            sr_val_t **tmp = NULL;
            tmp = realloc(iter->new_values, received_cnt * sizeof(*iter->new_values));
            CHECK_NULL_NOMEM_GOTO(tmp, rc, cleanup);
            iter->new_values = tmp;

            tmp = realloc(iter->old_values, received_cnt * sizeof(*iter->old_values));
            CHECK_NULL_NOMEM_GOTO(tmp, rc, cleanup);
            iter->old_values = tmp;

            sr_change_oper_t *oper_tmp = NULL;
            oper_tmp = realloc(iter->operations, received_cnt * sizeof(*iter->operations));
            CHECK_NULL_NOMEM_GOTO(oper_tmp, rc, cleanup);
            iter->operations = oper_tmp;

        }
        iter->index = 0;
        iter->count = received_cnt;

        /* copy the content of gpb to sr_val_t*/
        for (size_t i = 0; i < iter->count; i++) {
            if (NULL != msg_resp->response->get_changes_resp->changes[i]->new_value) {
                rc = sr_dup_gpb_to_val_t((sr_mem_ctx_t *)msg_resp->_sysrepo_mem_ctx,
                        msg_resp->response->get_changes_resp->changes[i]->new_value, &iter->new_values[i]);
            }
            if (SR_ERR_OK == rc && NULL != msg_resp->response->get_changes_resp->changes[i]->old_value) {
                rc = sr_dup_gpb_to_val_t((sr_mem_ctx_t *)msg_resp->_sysrepo_mem_ctx,
                        msg_resp->response->get_changes_resp->changes[i]->old_value, &iter->old_values[i]);
            }
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR_MSG("Copying from gpb to sr_val_t failed");
                sr_free_values_arr(iter->new_values, i);
                sr_free_values_arr(iter->old_values, i);
                iter->count = 0;
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            iter->operations[i] = sr_change_op_gpb_to_sr(msg_resp->response->get_changes_resp->changes[i]->changeoperation);
        }
        *operation = iter->operations[iter->index];
        *old_value = iter->old_values[iter->index];
        *new_value = iter->new_values[iter->index];
        iter->index++;
        iter->offset += received_cnt;
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_resp){
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);
}

void
sr_free_change_iter(sr_change_iter_t *iter)
{
    if (NULL != iter) {
        free(iter->xpath);
        for (size_t i = iter->index; i < iter->count; i++) {
            sr_free_val(iter->new_values[i]);
            sr_free_val(iter->old_values[i]);
        }
        free(iter->old_values);
        free(iter->new_values);
        free(iter->operations);
        free(iter);
    }
}

int
sr_unsubscribe(sr_session_ctx_t *session, sr_subscription_ctx_t *sr_subscription)
{
    sr_conn_ctx_t *tmp_connection = NULL;
    sr_session_ctx_t *tmp_session = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(sr_subscription);

    if (NULL == session) {
        /* create a temporary connection and session */
        rc = sr_connect("tmp-conn-unsubscribe", SR_CONN_DEFAULT, &tmp_connection);
        if (SR_ERR_OK == rc) {
            rc = sr_session_start(tmp_connection, SR_DS_STARTUP, SR_SESS_DEFAULT, &tmp_session);
        }
        CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to start new sysrepo session.");
    }

    /* close all subscriptions wrapped in the context */
    for (int i = (sr_subscription->sm_subscription_cnt - 1); i >= 0 ; i--) {
        if (SR_ERR_OK != cl_subscription_close((NULL != session ? session : tmp_session),
                                               sr_subscription->sm_subscriptions[i])) {
            SR_LOG_WRN("Unable to close the subscription id='%"PRIu32"'", sr_subscription->sm_subscriptions[i]->id);
        }
        cl_sr_subscription_remove_one(sr_subscription);
    }

cleanup:
    if (NULL != tmp_connection) {
        sr_disconnect(tmp_connection);
    }
    return rc;
}

int
sr_module_install(sr_session_ctx_t *session, const char *module_name, const char *revision, const char *file_name, bool installed)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(session, session->conn_ctx, module_name);

    cl_session_clear_errors(session);

    /* prepare module_install message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__MODULE_INSTALL, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* set arguments */
    sr_mem_edit_string(sr_mem, &msg_req->request->module_install_req->module_name, module_name);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->module_install_req->module_name, rc, cleanup);

    if (NULL != revision) {
        sr_mem_edit_string(sr_mem, &msg_req->request->module_install_req->revision, revision);
        CHECK_NULL_NOMEM_GOTO(msg_req->request->module_install_req->revision, rc, cleanup);
    }

    msg_req->request->module_install_req->installed = installed;

    if (installed && NULL == file_name) {
        SR_LOG_ERR_MSG("File name argument must not be NULL if installed is true");
        goto cleanup;
    }
    if (NULL != file_name) {
        sr_mem_edit_string(sr_mem, &msg_req->request->module_install_req->file_name, file_name);
        CHECK_NULL_NOMEM_GOTO(msg_req->request->module_install_req->file_name, rc, cleanup);
    }

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__MODULE_INSTALL);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);
}

int
sr_feature_enable(sr_session_ctx_t *session, const char *module_name, const char *feature_name, bool enabled)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(session, session->conn_ctx, module_name, feature_name);

    cl_session_clear_errors(session);

    /* prepare feature_enable message */
    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__FEATURE_ENABLE, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* set arguments */
    sr_mem_edit_string(sr_mem, &msg_req->request->feature_enable_req->module_name, module_name);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->feature_enable_req->module_name, rc, cleanup);

    sr_mem_edit_string(sr_mem, &msg_req->request->feature_enable_req->feature_name, feature_name);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->feature_enable_req->feature_name, rc, cleanup);

    msg_req->request->feature_enable_req->enabled = enabled;

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__FEATURE_ENABLE);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    } else {
        sr_mem_free(sr_mem);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    return cl_session_return(session, rc);
}

/**
 * @brief Subscribes for delivery of RPC specified by xpath.
 *
 * @param[in] sr_api_variant_t API variant.
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath XPath identifying the RPC.
 * @param[in] callback Callback to be called when the RPC is called.
 * @param[in] private_ctx Private context passed to the callback function, opaque to sysrepo.
 * @param[in] opts Options overriding default behavior of the subscription, it is supposed to be
 * a bitwise OR-ed value of any ::sr_subscr_flag_t flags.
 * @param[in,out] subscription Subscription context that is supposed to be released by ::sr_unsubscribe.
 * @note An existing context may be passed in case that SR_SUBSCR_CTX_REUSE option is specified.
 *
 * @return Error code (SR_ERR_OK on success).
 */
static int
cl_rpc_subscribe(sr_api_variant_t api_variant, sr_session_ctx_t *session, const char *xpath,
        cl_sm_callback_t callback, void *private_ctx, sr_subscr_options_t opts,
        sr_subscription_ctx_t **subscription_p)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    sr_subscription_ctx_t *sr_subscription = NULL;
    cl_sm_subscription_ctx_t *sm_subscription = NULL;
    char *module_name = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, subscription_p);

    cl_session_clear_errors(session);

    /* extract module name from xpath */
    rc = sr_copy_first_ns(xpath, &module_name);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by extracting module name from xpath.");

    /* Initialize the subscription */
    if (opts & SR_SUBSCR_CTX_REUSE) {
        sr_subscription = *subscription_p;
    }
    rc = cl_subscription_init(session, SR__SUBSCRIPTION_TYPE__RPC_SUBS, module_name, api_variant,
            private_ctx, &sr_subscription, &sm_subscription, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by initialization of the subscription in the client library.");

    sm_subscription->callback = callback;

    /* Fill-in GPB subscription information */
    sr_mem = (sr_mem_ctx_t *)msg_req->_sysrepo_mem_ctx;
    msg_req->request->subscribe_req->type = SR__SUBSCRIPTION_TYPE__RPC_SUBS;
    sr_mem_edit_string(sr_mem, &msg_req->request->subscribe_req->module_name, module_name);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->subscribe_req->module_name, rc, cleanup);
    sr_mem_edit_string(sr_mem, &msg_req->request->subscribe_req->xpath, xpath);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->subscribe_req->xpath, rc, cleanup);

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__SUBSCRIBE);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);
    free(module_name);

    *subscription_p = sr_subscription;

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != sm_subscription) {
        cl_subscription_close(session, sm_subscription);
        cl_sr_subscription_remove_one(sr_subscription);
    }
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    free(module_name);
    return cl_session_return(session, rc);
}

int
sr_rpc_subscribe(sr_session_ctx_t *session, const char *xpath, sr_rpc_cb callback,
        void *private_ctx, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription_p)
{
    cl_sm_callback_t callback_u;
    callback_u.rpc_cb = callback;
    return cl_rpc_subscribe(SR_API_VALUES, session, xpath, callback_u, private_ctx, opts, subscription_p);
}

int
sr_rpc_subscribe_tree(sr_session_ctx_t *session, const char *xpath, sr_rpc_tree_cb callback,
        void *private_ctx, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription_p)
{
    cl_sm_callback_t callback_u;
    callback_u.rpc_tree_cb = callback;
    return cl_rpc_subscribe(SR_API_TREES, session, xpath, callback_u, private_ctx, opts, subscription_p);
}

/**
 * @brief Sends a RPC/Action specified by xpath and waits for the result.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath XPath identifying the RPC/Action.
 * @param[in] input Array of input parameters (array of all nodes that hold some
 * data in RPC/Action input subtree - same as ::sr_get_items would return).
 * @param[in] input_cnt Number of input parameters.
 * @param[out] output Array of output parameters (all nodes that hold some data
 * in RPC/Action output subtree). Will be allocated by sysrepo and should be freed by
 * caller using ::sr_free_values.
 * @param[out] output_cnt Number of output parameters.
 *
 * @return Error code (SR_ERR_OK on success).
 */
static int
cl_rpc_send(sr_session_ctx_t *session, const char *xpath, bool action,
        const sr_val_t *input,  const size_t input_cnt, sr_val_t **output, size_t *output_cnt)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    sr_mem_snapshot_t snapshot = { 0, };
    const char *op_name = (action ? "Action" : "RPC");
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(session, session->conn_ctx, xpath);

    if (NULL != input) {
        sr_mem = input[0]._sr_mem;
        sr_mem_snapshot(sr_mem, &snapshot);
    }

    cl_session_clear_errors(session);

    /* prepare RPC/Action message */
    rc = sr_gpb_req_alloc(sr_mem, action ? SR__OPERATION__ACTION : SR__OPERATION__RPC, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* set arguments */
    msg_req->request->rpc_req->action = action;
    sr_mem_edit_string(sr_mem, &msg_req->request->rpc_req->xpath, xpath);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->rpc_req->xpath, rc, cleanup);
    msg_req->request->rpc_req->orig_api_variant = sr_api_variant_sr_to_gpb(SR_API_VALUES);

    /* set input arguments */
    rc = sr_values_sr_to_gpb(input, input_cnt, &msg_req->request->rpc_req->input, &msg_req->request->rpc_req->n_input);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Error by copying %s input arguments to GPB.", op_name);

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, action ? SR__OPERATION__ACTION : SR__OPERATION__RPC);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    if (NULL != output) {
        /* set output arguments */
        rc = sr_values_gpb_to_sr((sr_mem_ctx_t *)msg_resp->_sysrepo_mem_ctx, msg_resp->response->rpc_resp->output,
                msg_resp->response->rpc_resp->n_output, output, output_cnt);
        CHECK_RC_LOG_GOTO(rc, cleanup, "Error by copying %soutput arguments from GPB.", op_name);
    }

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    if (snapshot.sr_mem) {
        sr_mem_restore(&snapshot);
    }

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    if (snapshot.sr_mem) {
        sr_mem_restore(&snapshot);
    }
    return cl_session_return(session, rc);
}

/**
 * @brief Sends a RPC/Action specified by xpath and waits for the result. Input and output data
 * are represented as arrays of subtrees reflecting the scheme of RPC/Action arguments.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath XPath identifying the RPC/Action.
 * @param[in] input Array of input parameters (organized in trees).
 * @param[in] input_cnt Number of input parameters.
 * @param[out] output Array of output parameters (organized in trees).
 * Will be allocated by sysrepo and should be freed by caller using ::sr_free_trees.
 * @param[out] output_cnt Number of output parameters.
 *
 * @return Error code (SR_ERR_OK on success).
 */
static int
cl_rpc_send_tree(sr_session_ctx_t *session, const char *xpath, bool action,
        const sr_node_t *input,  const size_t input_cnt, sr_node_t **output, size_t *output_cnt)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    sr_mem_snapshot_t snapshot = { 0, };
    const char *op_name = (action ? "Action" : "RPC");
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(session, session->conn_ctx, xpath);

    if (NULL != input) {
        sr_mem = input[0]._sr_mem;
        sr_mem_snapshot(sr_mem, &snapshot);
    }

    cl_session_clear_errors(session);

    /* prepare RPC/Action message */
    rc = sr_gpb_req_alloc(sr_mem, action ? SR__OPERATION__ACTION : SR__OPERATION__RPC, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* set arguments */
    msg_req->request->rpc_req->action = action;
    sr_mem_edit_string(sr_mem, &msg_req->request->rpc_req->xpath, xpath);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->rpc_req->xpath, rc, cleanup);
    msg_req->request->rpc_req->orig_api_variant = sr_api_variant_sr_to_gpb(SR_API_TREES);

    /* set input arguments */
    rc = sr_trees_sr_to_gpb(input, input_cnt, &msg_req->request->rpc_req->input_tree, &msg_req->request->rpc_req->n_input_tree);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Error by copying %s input arguments to GPB.", op_name);

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, action ? SR__OPERATION__ACTION : SR__OPERATION__RPC);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    if (NULL != output) {
        /* set output arguments */
        rc = sr_trees_gpb_to_sr((sr_mem_ctx_t *)msg_resp->_sysrepo_mem_ctx, msg_resp->response->rpc_resp->output_tree,
                msg_resp->response->rpc_resp->n_output_tree, output, output_cnt);
        CHECK_RC_LOG_GOTO(rc, cleanup, "Error by copying %s output arguments from GPB.", op_name);
    }

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    if (snapshot.sr_mem) {
        sr_mem_restore(&snapshot);
    }

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    if (snapshot.sr_mem) {
        sr_mem_restore(&snapshot);
    }
    return cl_session_return(session, rc);
}

int
sr_rpc_send(sr_session_ctx_t *session, const char *xpath,
        const sr_val_t *input,  const size_t input_cnt, sr_val_t **output, size_t *output_cnt)
{
    return cl_rpc_send(session, xpath, false, input, input_cnt, output, output_cnt);
}

int
sr_rpc_send_tree(sr_session_ctx_t *session, const char *xpath,
        const sr_node_t *input,  const size_t input_cnt, sr_node_t **output, size_t *output_cnt)
{
    return cl_rpc_send_tree(session, xpath, false, input, input_cnt, output, output_cnt);
}

/**
 * @brief Subscribes for delivery of Action specified by xpath.
 *
 * @param[in] sr_api_variant_t API variant.
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath XPath identifying the Action.
 * @param[in] callback Callback to be called when the Action is called.
 * @param[in] private_ctx Private context passed to the callback function, opaque to sysrepo.
 * @param[in] opts Options overriding default behavior of the subscription, it is supposed to be
 * a bitwise OR-ed value of any ::sr_subscr_flag_t flags.
 * @param[in,out] subscription Subscription context that is supposed to be released by ::sr_unsubscribe.
 * @note An existing context may be passed in case that SR_SUBSCR_CTX_REUSE option is specified.
 *
 * @return Error code (SR_ERR_OK on success).
 */
static int
cl_action_subscribe(sr_api_variant_t api_variant, sr_session_ctx_t *session, const char *xpath,
        cl_sm_callback_t callback, void *private_ctx, sr_subscr_options_t opts,
        sr_subscription_ctx_t **subscription_p)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    sr_subscription_ctx_t *sr_subscription = NULL;
    cl_sm_subscription_ctx_t *sm_subscription = NULL;
    char *module_name = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, subscription_p);

    cl_session_clear_errors(session);

    /* extract module name from xpath */
    rc = sr_copy_first_ns(xpath, &module_name);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by extracting module name from xpath.");

    /* Initialize the subscription */
    if (opts & SR_SUBSCR_CTX_REUSE) {
        sr_subscription = *subscription_p;
    }
    rc = cl_subscription_init(session, SR__SUBSCRIPTION_TYPE__ACTION_SUBS, module_name, api_variant,
            private_ctx, &sr_subscription, &sm_subscription, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by initialization of the subscription in the client library.");

    sm_subscription->callback = callback;

    /* Fill-in GPB subscription information */
    sr_mem = (sr_mem_ctx_t *)msg_req->_sysrepo_mem_ctx;
    msg_req->request->subscribe_req->type = SR__SUBSCRIPTION_TYPE__ACTION_SUBS;
    sr_mem_edit_string(sr_mem, &msg_req->request->subscribe_req->module_name, module_name);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->subscribe_req->module_name, rc, cleanup);
    sr_mem_edit_string(sr_mem, &msg_req->request->subscribe_req->xpath, xpath);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->subscribe_req->xpath, rc, cleanup);

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__SUBSCRIBE);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);
    free(module_name);

    *subscription_p = sr_subscription;

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != sm_subscription) {
        cl_subscription_close(session, sm_subscription);
        cl_sr_subscription_remove_one(sr_subscription);
    }
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    free(module_name);
    return cl_session_return(session, rc);
}

int
sr_action_subscribe(sr_session_ctx_t *session, const char *xpath, sr_action_cb callback,
        void *private_ctx, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription_p)
{
    cl_sm_callback_t callback_u;
    callback_u.action_cb = callback;
    return cl_action_subscribe(SR_API_VALUES, session, xpath, callback_u, private_ctx, opts, subscription_p);
}

int
sr_action_subscribe_tree(sr_session_ctx_t *session, const char *xpath, sr_action_tree_cb callback,
        void *private_ctx, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription_p)
{
    cl_sm_callback_t callback_u;
    callback_u.action_tree_cb = callback;
    return cl_action_subscribe(SR_API_TREES, session, xpath, callback_u, private_ctx, opts, subscription_p);
}

int
sr_action_send(sr_session_ctx_t *session, const char *xpath,
        const sr_val_t *input,  const size_t input_cnt, sr_val_t **output, size_t *output_cnt)
{
    return cl_rpc_send(session, xpath, true, input, input_cnt, output, output_cnt);
}

int
sr_action_send_tree(sr_session_ctx_t *session, const char *xpath,
        const sr_node_t *input,  const size_t input_cnt, sr_node_t **output, size_t *output_cnt)
{
    return cl_rpc_send_tree(session, xpath, true, input, input_cnt, output, output_cnt);
}

int
sr_dp_get_items_subscribe(sr_session_ctx_t *session, const char *xpath, sr_dp_get_items_cb callback, void *private_ctx,
        sr_subscr_options_t opts, sr_subscription_ctx_t **subscription_p)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_subscription_ctx_t *sr_subscription = NULL;
    cl_sm_subscription_ctx_t *sm_subscription = NULL;
    char *module_name = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(session, callback, subscription_p);

    cl_session_clear_errors(session);

    /* extract module name from xpath */
    rc = sr_copy_first_ns(xpath, &module_name);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by extracting module name from xpath.");

    /* Initialize the subscription */
    if (opts & SR_SUBSCR_CTX_REUSE) {
        sr_subscription = *subscription_p;
    }
    rc = cl_subscription_init(session, SR__SUBSCRIPTION_TYPE__DP_GET_ITEMS_SUBS, module_name, SR_API_VALUES,
            private_ctx, &sr_subscription, &sm_subscription, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by initialization of the subscription in the client library.");

    sm_subscription->callback.dp_get_items_cb = callback;

    /* Fill-in GPB subscription information */
    sr_mem = (sr_mem_ctx_t *)msg_req->_sysrepo_mem_ctx;
    msg_req->request->subscribe_req->type = SR__SUBSCRIPTION_TYPE__DP_GET_ITEMS_SUBS;
    sr_mem_edit_string(sr_mem, &msg_req->request->subscribe_req->module_name, module_name);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->subscribe_req->module_name, rc, cleanup);
    sr_mem_edit_string(sr_mem, &msg_req->request->subscribe_req->xpath, xpath);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->subscribe_req->xpath, rc, cleanup);

    msg_req->request->subscribe_req->has_enable_running = true;
    msg_req->request->subscribe_req->enable_running = !(opts & SR_SUBSCR_PASSIVE);

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__SUBSCRIBE);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);
    free(module_name);

    *subscription_p = sr_subscription;

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != sm_subscription) {
        cl_subscription_close(session, sm_subscription);
        cl_sr_subscription_remove_one(sr_subscription);
    }
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    free(module_name);
    return cl_session_return(session, rc);
}

/**
 * @brief Subscribes for delivery of event notification specified by xpath.
 *
 * @param[in] sr_api_variant_t API variant.
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath XPath identifying the event notification.
 * @param[in] callback Callback to be called when the event notification is called.
 * @param[in] private_ctx Private context passed to the callback function, opaque to sysrepo.
 * @param[in] opts Options overriding default behavior of the subscription, it is supposed to be
 * a bitwise OR-ed value of any ::sr_subscr_flag_t flags.
 * @param[in,out] subscription Subscription context that is supposed to be released by ::sr_unsubscribe.
 * @note An existing context may be passed in case that SR_SUBSCR_CTX_REUSE option is specified.
 *
 * @return Error code (SR_ERR_OK on success).
 */
static int
cl_event_notif_subscribe(sr_api_variant_t api_variant, sr_session_ctx_t *session, const char *xpath,
        cl_sm_callback_t callback, void *private_ctx, sr_subscr_options_t opts,
        sr_subscription_ctx_t **subscription_p)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_subscription_ctx_t *sr_subscription = NULL;
    cl_sm_subscription_ctx_t *sm_subscription = NULL;
    char *module_name = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, subscription_p);

    cl_session_clear_errors(session);

    /* extract module name from xpath */
    rc = sr_copy_first_ns(xpath, &module_name);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by extracting module name from xpath.");

    /* Initialize the subscription */
    if (opts & SR_SUBSCR_CTX_REUSE) {
        sr_subscription = *subscription_p;
    }
    rc = cl_subscription_init(session, SR__SUBSCRIPTION_TYPE__EVENT_NOTIF_SUBS, module_name, api_variant,
            private_ctx, &sr_subscription, &sm_subscription, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by initialization of the subscription in the client library.");

    sm_subscription->callback = callback;

    /* Fill-in GPB subscription information */
    sr_mem = (sr_mem_ctx_t *)msg_req->_sysrepo_mem_ctx;
    msg_req->request->subscribe_req->type = SR__SUBSCRIPTION_TYPE__EVENT_NOTIF_SUBS;
    sr_mem_edit_string(sr_mem, &msg_req->request->subscribe_req->module_name, module_name);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->subscribe_req->module_name, rc, cleanup);
    sr_mem_edit_string(sr_mem, &msg_req->request->subscribe_req->xpath, xpath);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->subscribe_req->xpath, rc, cleanup);

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__SUBSCRIBE);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);
    free(module_name);

    *subscription_p = sr_subscription;

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != sm_subscription) {
        cl_subscription_close(session, sm_subscription);
        cl_sr_subscription_remove_one(sr_subscription);
    }
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    free(module_name);
    return cl_session_return(session, rc);
}

int
sr_event_notif_subscribe(sr_session_ctx_t *session, const char *xpath,
        sr_event_notif_cb callback, void *private_ctx, sr_subscr_options_t opts,
        sr_subscription_ctx_t **subscription_p)
{
    cl_sm_callback_t callback_u;
    callback_u.event_notif_cb = callback;
    return cl_event_notif_subscribe(SR_API_VALUES, session, xpath, callback_u, private_ctx, opts, subscription_p);
}

int
sr_event_notif_subscribe_tree(sr_session_ctx_t *session, const char *xpath,
        sr_event_notif_tree_cb callback, void *private_ctx, sr_subscr_options_t opts,
        sr_subscription_ctx_t **subscription_p)
{
    cl_sm_callback_t callback_u;
    callback_u.event_notif_tree_cb = callback;
    return cl_event_notif_subscribe(SR_API_TREES, session, xpath, callback_u, private_ctx, opts, subscription_p);
}

int
sr_event_notif_send(sr_session_ctx_t *session, const char *xpath,
        const sr_val_t *values,  const size_t values_cnt)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    sr_mem_snapshot_t snapshot = { 0, };
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(session, session->conn_ctx, xpath);

    if (NULL != values) {
        sr_mem = values[0]._sr_mem;
        sr_mem_snapshot(sr_mem, &snapshot);
    }

    cl_session_clear_errors(session);

    /* prepare event-notification message */
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__EVENT_NOTIF, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* set arguments */
    sr_mem_edit_string(sr_mem, &msg_req->request->event_notif_req->xpath, xpath);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->event_notif_req->xpath, rc, cleanup);

    /* set values */
    rc = sr_values_sr_to_gpb(values, values_cnt, &msg_req->request->event_notif_req->values,
                             &msg_req->request->event_notif_req->n_values);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by copying event notification values to GPB.");

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__EVENT_NOTIF);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    if (snapshot.sr_mem) {
        sr_mem_restore(&snapshot);
    }

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    if (snapshot.sr_mem) {
        sr_mem_restore(&snapshot);
    }
    return cl_session_return(session, rc);
}

int
sr_event_notif_send_tree(sr_session_ctx_t *session, const char *xpath,
        const sr_node_t *trees,  const size_t tree_cnt)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    sr_mem_snapshot_t snapshot = { 0, };
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(session, session->conn_ctx, xpath);

    if (NULL != trees) {
        sr_mem = trees[0]._sr_mem;
        sr_mem_snapshot(sr_mem, &snapshot);
    }

    cl_session_clear_errors(session);

    /* prepare event-notification message */
    rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__EVENT_NOTIF, session->id, &msg_req);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate GPB message.");

    /* set arguments */
    sr_mem_edit_string(sr_mem, &msg_req->request->event_notif_req->xpath, xpath);
    CHECK_NULL_NOMEM_GOTO(msg_req->request->event_notif_req->xpath, rc, cleanup);

    /* set trees */
    rc = sr_trees_sr_to_gpb(trees, tree_cnt, &msg_req->request->event_notif_req->trees,
                             &msg_req->request->event_notif_req->n_trees);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by copying event notification trees to GPB.");

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__EVENT_NOTIF);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by processing of the request.");

    sr_msg_free(msg_req);
    sr_msg_free(msg_resp);

    if (snapshot.sr_mem) {
        sr_mem_restore(&snapshot);
    }

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr_msg_free(msg_req);
    }
    if (NULL != msg_resp) {
        sr_msg_free(msg_resp);
    }
    if (snapshot.sr_mem) {
        sr_mem_restore(&snapshot);
    }
    return cl_session_return(session, rc);
}

int
sr_fd_watcher_init(int *fd_p)
{
    int pipefd[2] = { 0, };
    int ret = 0, rc = SR_ERR_OK;

    CHECK_NULL_ARG(fd_p);

    SR_LOG_DBG_MSG("Initializing application-local fd watcher.");

    ret = pipe(pipefd);
    CHECK_ZERO_LOG_RETURN(ret, SR_ERR_IO, "Unable to create a new pipe: %s", sr_strerror_safe(errno));

    /* set read end to nonblocking mode */
    rc = sr_fd_set_nonblock(pipefd[0]);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot set socket to nonblocking mode.");

    pthread_mutex_lock(&global_lock);
    local_watcher_fd[0] = pipefd[0];
    local_watcher_fd[1] = pipefd[1];
    pthread_mutex_unlock(&global_lock);

    *fd_p = pipefd[0]; /* return read end of the pipe */

    return SR_ERR_OK;

cleanup:
    sr_fd_watcher_cleanup();
    return rc;
}

void
sr_fd_watcher_cleanup()
{
    pthread_mutex_lock(&global_lock);
    for (size_t i = 0; i < 2; i++) {
        if (-1 != local_watcher_fd[i]) {
            close(local_watcher_fd[i]);
            local_watcher_fd[i] = -1;
        }
    }
    pthread_mutex_unlock(&global_lock);

    SR_LOG_DBG_MSG("Application-local fd watcher cleaned up.");
}

int
sr_fd_event_process(int fd, sr_fd_event_t event, sr_fd_change_t **fd_change_set, size_t *fd_change_set_cnt)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(fd_change_set, fd_change_set_cnt);

    *fd_change_set_cnt = 0;
    *fd_change_set = NULL;

    SR_LOG_DBG("New %s event on fd=%d.", (SR_FD_INPUT_READY == event ? "input" : "output"), fd);

    /* the lock is supposed to prevent from calling subscribe / unsubscribe / watcher_init / watcher_cleanup in the meantime */
    pthread_mutex_lock(&global_lock);

    rc = cl_sm_fd_event_process(cl_sm_ctx, fd, event, fd_change_set, fd_change_set_cnt);

    pthread_mutex_unlock(&global_lock);

    return rc;
}
