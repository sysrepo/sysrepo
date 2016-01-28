/**
 * @file client_library.c
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

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>

#include "sr_common.h"
#include "connection_manager.h"

/**
 * @brief Timeout (in seconds) for waiting for a response from server by each request.
 */
#define CL_REQUEST_TIMEOUT 2

/**
 * @brief Number of items being fetched in one message from Sysrepo Engine by
 * processing of sr_get_items_iter calls.
 */
#define CL_GET_ITEMS_FETCH_LIMIT 2

/**
 * @brief Filesystem path prefix for generating temporary socket names used
 * for local unix-domain connections (library mode).
 */
#define CL_LCONN_PATH_PREFIX "/tmp/sysrepo-local"

/**
 * Connection context used to identify a connection to sysrepo datastore.
 */
typedef struct sr_conn_ctx_s {
    int fd;                                  /**< File descriptor of the connection. */
    bool primary;                            /**< Primary connection. Handles all resources allocated only
                                                  once per process (first connection is always primary). */
    pthread_mutex_t lock;                    /**< Mutex of the connection to guarantee that requests on the
                                                  same connection are processed serially (one after another). */
    uint8_t *msg_buf;                        /**< Buffer used for sending / receiving messages. */
    size_t msg_buf_size;                     /**< Length of the message buffer. */
    struct sr_session_list_s *session_list;  /**< Linked-list of associated sessions. */
    bool library_mode;                       /**< Determine if we are connected to sysrepo daemon
                                                  or our own sysrepo engine (library mode). */
    cm_ctx_t *local_cm;                      /**< Local Connection Manager in case of library mode. */
} sr_conn_ctx_t;

/**
 * Session context used to identify a configuration session.
 */
typedef struct sr_session_ctx_s {
    sr_conn_ctx_t *conn_ctx;  /**< Associated connection context. */
    uint32_t id;              /**< Assigned session identifier. */
} sr_session_ctx_t;

/**
 * Linked-list of sessions.
 */
typedef struct sr_session_list_s {
    sr_session_ctx_t *session;       /**< Session context. */
    struct sr_session_list_s *next;  /**< Next element in the linked-list. */
} sr_session_list_t;

/**
 * Structure holding data for iterative access to items
 */
typedef struct sr_val_iter_s{
    char *path;                     /**< xpath of the request */
    bool recursive;                 /**< flag denoting whether child subtrees should be iterated */
    size_t offset;                  /**< offset where the next data should be read */
    size_t limit;                   /**< how many items should be read */
    sr_val_t **buff_values;         /**< buffered values */
    size_t index;                   /**< index into buff_values pointing to the value to be returned by next call */
    size_t count;                   /**< number of element currently buffered */
} sr_val_iter_t;

static sr_conn_ctx_t *primary_connection = NULL;  /**< Global variable holding pointer to the primary connection. */
pthread_mutex_t primary_lock = PTHREAD_MUTEX_INITIALIZER;  /**< Mutex for locking global variable primary_connection. */

/**
 * Connect the client to provided unix-domain socket.
 */
static int
cl_socket_connect(sr_conn_ctx_t *conn_ctx, const char *socket_path)
{
    struct sockaddr_un addr;
    struct timeval tv = { 0, };
    int fd = -1, rc = -1;

    CHECK_NULL_ARG2(socket_path, socket_path);

    SR_LOG_DBG("Connecting to socket=%s", socket_path);

    /* prepare a socket */
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (-1 == fd) {
        SR_LOG_ERR("Unable to create a new socket (socket=%s)", socket_path);
        return SR_ERR_INTERNAL;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);

    /* connect to server */
    rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (-1 == rc) {
        SR_LOG_DBG("Unable to connect to socket (socket=%s)", socket_path);
        close(fd);
        return SR_ERR_DISCONNECT;
    }

    /* set timeout for receive operation */
    tv.tv_sec = CL_REQUEST_TIMEOUT;
    tv.tv_usec = 0;
    rc = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
    if (-1 == rc) {
        SR_LOG_ERR("Unable to set timeout for socket operations (socket=%s)", socket_path);
        close(fd);
        return SR_ERR_DISCONNECT;
    }

    conn_ctx->fd = fd;
    return SR_ERR_OK;
}

/**
 * Initialize our own sysrepo engine (fallback option if sysrepo daemon is not running)
 */
static int
cl_engine_init_local(sr_conn_ctx_t *conn_ctx, const char *socket_path)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(conn_ctx, socket_path);

    /* initialize local Connection Manager */
    rc = cm_init(CM_MODE_LOCAL, socket_path, &conn_ctx->local_cm);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Unable to initialize local Connection Manager.");
        return rc;
    }

    /* start the server */
    rc = cm_start(conn_ctx->local_cm);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Unable to start local Connection Manager.");
        return rc;
    }

    return rc;
}

/**
 * @brief Adds a new session to the session list of the connection.
 */
static int
cl_conn_add_session(sr_conn_ctx_t *connection, sr_session_ctx_t *session)
{
    sr_session_list_t *session_item = NULL, *tmp = NULL;

    CHECK_NULL_ARG2(connection, session);

    session_item = calloc(1, sizeof(*session_item));
    if (NULL == session_item) {
        SR_LOG_ERR_MSG("Cannot allocate memory for new session list entry.");
        return SR_ERR_NOMEM;
    }
    session_item->session = session;

    pthread_mutex_lock(&connection->lock);

    /* append session entry at the end of list */
    if (NULL == connection->session_list) {
        connection->session_list = session_item;
    } else {
        tmp = connection->session_list;
        while (NULL != tmp->next) {
            tmp = tmp->next;
        }
        tmp->next = session_item;
    }

    pthread_mutex_unlock(&connection->lock);

    return SR_ERR_OK;
}

/**
 * @brief Removes a session from the session list of the connection.
 */
static int
cl_conn_remove_session(sr_conn_ctx_t *connection, sr_session_ctx_t *session)
{
    sr_session_list_t *tmp = NULL, *prev = NULL;

    CHECK_NULL_ARG2(connection, session);

    pthread_mutex_lock(&connection->lock);

    /* find matching session in linked list */
    tmp = connection->session_list;
    while ((NULL != tmp) && (tmp->session != session)) {
        prev = tmp;
        tmp = tmp->next;
    }

    /* remove the session from linked-list */
    if (NULL != tmp) {
        if (NULL != prev) {
            /* tmp is NOT the first item in list - skip it */
            prev->next = tmp->next;
        } else if (NULL != tmp->next) {
            /* tmp is the first, but not last item in list - skip it */
            connection->session_list = tmp->next;
        } else {
            /* tmp is the only item in the list */
            connection->session_list = NULL;
        }
        free(tmp);
    } else {
        SR_LOG_WRN("Session %p not found in session list of connection.", (void*)session);
    }

    pthread_mutex_unlock(&connection->lock);

    return SR_ERR_OK;
}

/**
 * Expand message buffer of a connection to fit given size, if needed.
 */
static int
cl_conn_msg_buf_expand(sr_conn_ctx_t *conn_ctx, size_t required_size)
{
    uint8_t *tmp = NULL;

    CHECK_NULL_ARG(conn_ctx);

    if (conn_ctx->msg_buf_size < required_size) {
        tmp = realloc(conn_ctx->msg_buf, required_size * sizeof(*tmp));
        if (NULL == tmp) {
            SR_LOG_ERR("Unable to expand message buffer of connection=%p.", (void*)conn_ctx);
            return SR_ERR_NOMEM;
        }
        conn_ctx->msg_buf = tmp;
        conn_ctx->msg_buf_size = required_size;
    }

    return SR_ERR_OK;
}

/**
 * Sends a message via provided connection.
 */
static int
cl_message_send(sr_conn_ctx_t *conn_ctx, Sr__Msg *msg)
{
    size_t msg_size = 0;
    int pos = 0, sent = 0;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(conn_ctx, msg);

    /* find out required message size */
    msg_size = sr__msg__get_packed_size(msg);
    if ((msg_size <= 0) || (msg_size > SR_MAX_MSG_SIZE)) {
        SR_LOG_ERR("Unable to send the message of size %zuB.", msg_size);
        return SR_ERR_INTERNAL;
    }

    /* expand the buffer if needed */
    rc = cl_conn_msg_buf_expand(conn_ctx, msg_size + SR_MSG_PREAM_SIZE);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot expand buffer for the message.");
        return rc;
    }

    /* write 4-byte length */
    sr_uint32_to_buff(msg_size, conn_ctx->msg_buf);

    /* pack the message */
    sr__msg__pack(msg, (conn_ctx->msg_buf + SR_MSG_PREAM_SIZE));

    /* send the message */
    do {
        sent = send(conn_ctx->fd, (conn_ctx->msg_buf + pos), (msg_size + SR_MSG_PREAM_SIZE - pos), 0);
        if (sent > 0) {
            pos += sent;
        } else {
            if (errno == EINTR) {
                continue;
            }
            SR_LOG_ERR("Error by sending of the message: %s.", strerror(errno));
            return SR_ERR_DISCONNECT;
        }
    } while ((pos < (msg_size + SR_MSG_PREAM_SIZE)) && (sent > 0));

    return SR_ERR_OK;
}

/*
 * Receive a message on provided connection (blocks until a message is received).
 */
static int
cl_message_recv(sr_conn_ctx_t *conn_ctx, Sr__Msg **msg)
{
    size_t len = 0, pos = 0;
    size_t msg_size = 0;
    int rc = 0;

    /* expand the buffer if needed */
    rc = cl_conn_msg_buf_expand(conn_ctx, SR_MSG_PREAM_SIZE);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot expand buffer for the message.");
        return rc;
    }

    /* read at least first 4 bytes with length of the message */
    while (pos < SR_MSG_PREAM_SIZE) {
        len = recv(conn_ctx->fd, conn_ctx->msg_buf, conn_ctx->msg_buf_size, 0);
        if (-1 == len) {
            if (errno == EINTR) {
                continue;
            }
            SR_LOG_ERR("Error by receiving of the message: %s.", strerror(errno));
            return SR_ERR_MALFORMED_MSG;
        }
        if (0 == len) {
            SR_LOG_ERR_MSG("Sysrepo server disconnected.");
            return SR_ERR_DISCONNECT;
        }
        pos += len;
    }
    msg_size = sr_buff_to_uint32(conn_ctx->msg_buf);

    /* check message size bounds */
    if ((msg_size <= 0) || (msg_size > SR_MAX_MSG_SIZE)) {
        SR_LOG_ERR("Invalid message size in the message preamble (%zu).", msg_size);
        return SR_ERR_MALFORMED_MSG;
    }

    /* expand the buffer if needed */
    rc = cl_conn_msg_buf_expand(conn_ctx, (msg_size + SR_MSG_PREAM_SIZE));
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot expand buffer for the message.");
        return rc;
    }

    /* read the rest of the message */
    while (pos < (msg_size + SR_MSG_PREAM_SIZE)) {
        len = recv(conn_ctx->fd, (conn_ctx->msg_buf + pos), (conn_ctx->msg_buf_size - pos), 0);
        if (-1 == len) {
            if (errno == EINTR) {
                continue;
            }
            SR_LOG_ERR("Error by receiving of the message: %s.", strerror(errno));
            return SR_ERR_MALFORMED_MSG;
        }
        if (0 == len) {
            SR_LOG_ERR_MSG("Sysrepo server disconnected.");
            return SR_ERR_DISCONNECT;
        }
        pos += len;
    }

    /* unpack the message */
    *msg = sr__msg__unpack(NULL, msg_size, (const uint8_t*)(conn_ctx->msg_buf + SR_MSG_PREAM_SIZE));
    if (NULL == *msg) {
        SR_LOG_ERR_MSG("Malformed message received.");
        return SR_ERR_MALFORMED_MSG;
    }

    return SR_ERR_OK;
}

/**
 * Process (send) the request over the connection and receive the response.
 */
static int
cl_request_process(sr_conn_ctx_t *conn_ctx, Sr__Msg *msg_req, Sr__Msg **msg_resp,
        const Sr__Operation expected_response_op)
{
    int rc = SR_ERR_OK;

    SR_LOG_DBG("Sending a request for operation=%d", expected_response_op);

    pthread_mutex_lock(&conn_ctx->lock);

    /* send the request */
    rc = cl_message_send(conn_ctx, msg_req);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Unable to send the message with request (conn=%p, operation=%d).",
                (void*)conn_ctx, msg_req->request->operation);
        pthread_mutex_unlock(&conn_ctx->lock);
        return rc;
    }

    SR_LOG_DBG("Request for operation=%d sent, waiting for response.", expected_response_op);

    /* receive the response */
    rc = cl_message_recv(conn_ctx, msg_resp);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Unable to receive the message with response (conn=%p, operation=%d).",
                (void*)conn_ctx, msg_req->request->operation);
        pthread_mutex_unlock(&conn_ctx->lock);
        return rc;
    }

    pthread_mutex_unlock(&conn_ctx->lock);

    SR_LOG_DBG("Response for operation=%d received, processing.", expected_response_op);

    /* validate the response */
    rc = sr_pb_msg_validate(*msg_resp, SR__MSG__MSG_TYPE__RESPONSE, expected_response_op);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Malformed message with response received (conn=%p, operation=%d).",
                (void*)conn_ctx, msg_req->request->operation);
        return rc;
    }

    /* check for errors */
    if (SR_ERR_OK != (*msg_resp)->response->result) {
        /* don't log not found err*/
        if (SR_ERR_NOT_FOUND != (*msg_resp)->response->result){
            SR_LOG_ERR("Error by processing of the request conn=%p, operation=%d): %s.",
                (void*)conn_ctx, msg_req->request->operation, (NULL != (*msg_resp)->response->error_msg) ?
                        (*msg_resp)->response->error_msg : sr_strerror((*msg_resp)->response->result));
        }
        return (*msg_resp)->response->result;
    }

    return SR_ERR_OK;
}

/**
 * Create get_items request with options and send it
 */
static int
cl_send_get_items_iter(sr_session_ctx_t *session, const char *path, bool recursive, size_t offset, size_t limit, Sr__Msg **msg_resp){
    Sr__Msg *msg_req = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(session, session->conn_ctx, path, msg_resp);

    /* prepare get_item message */
    rc = sr_pb_req_alloc(SR__OPERATION__GET_ITEMS, session->id, &msg_req);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate get_items message.");
        goto cleanup;
    }

    /* fill in the path */
    msg_req->request->get_items_req->path = strdup(path);
    if (NULL == msg_req->request->get_items_req->path) {
        SR_LOG_ERR_MSG("Cannot allocate get_items path.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }
    msg_req->request->get_items_req->limit = limit;
    msg_req->request->get_items_req->offset = offset;
    msg_req->request->get_items_req->recursive =recursive;
    msg_req->request->get_items_req->has_recursive = true;
    msg_req->request->get_items_req->has_limit = true;
    msg_req->request->get_items_req->has_offset = true;


    /* send the request and receive the response */
    rc = cl_request_process(session->conn_ctx, msg_req, msg_resp, SR__OPERATION__GET_ITEMS);
    if (SR_ERR_NOT_FOUND == rc){
        goto cleanup;
    }
    else if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Error by processing of get_items request.");
        goto cleanup;
    }

    sr__msg__free_unpacked(msg_req, NULL);

    return rc;

    cleanup:
    if (NULL != msg_req) {
        sr__msg__free_unpacked(msg_req, NULL);
    }
    return rc;
}

int
sr_connect(const char *app_name, const bool allow_library_mode, sr_conn_ctx_t **conn_ctx_p)
{
    sr_conn_ctx_t *ctx = NULL;
    int rc = SR_ERR_OK;
    char socket_path[PATH_MAX] = { 0, };

    CHECK_NULL_ARG2(app_name, conn_ctx_p);

    SR_LOG_DBG_MSG("Connecting to Sysrepo Engine.");

    /* initialize the context */
    ctx = calloc(1, sizeof(*ctx));
    if (NULL == ctx) {
        SR_LOG_ERR_MSG("Cannot allocate memory for connection context.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    /* init connection mutext */
    rc = pthread_mutex_init(&ctx->lock, NULL);
    if (0 != rc) {
        SR_LOG_ERR_MSG("Cannot initialize connection mutex.");
        rc = SR_ERR_INIT_FAILED;
        goto cleanup;
    }

    /* check if this is the primary connection */
    pthread_mutex_lock(&primary_lock);
    if (NULL == primary_connection) {
        /* this is the first connection - set as primary */
        primary_connection = ctx;
        ctx->primary = true;
        /* initialize logging */
        sr_logger_init(app_name);
    }
    pthread_mutex_unlock(&primary_lock);

    // TODO: milestone 2: attempt to connect to sysrepo daemon socket
    SR_LOG_WRN_MSG("Sysrepo daemon not detected. Connecting to local Sysrepo Engine.");

    /* connect in library mode */
    ctx->library_mode = true;
    snprintf(socket_path, PATH_MAX, "%s-%d", CL_LCONN_PATH_PREFIX, getpid());

    /* attempt to connect to our own sysrepo engine (local engine may already exist) */
    rc = cl_socket_connect(ctx, socket_path);
    if (SR_ERR_OK != rc) {
        /* initialize our own sysrepo engine and attempt to connect again */
        SR_LOG_INF_MSG("Local Sysrepo Engine not running yet, initializing new one.");

        rc = cl_engine_init_local(ctx, socket_path);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Unable to start local sysrepo engine.");
            goto cleanup;
        }
        rc = cl_socket_connect(ctx, socket_path);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Unable to connect to the local sysrepo engine.");
            goto cleanup;
        }
    }

    SR_LOG_INF("Connected to Sysrepo Engine at socket=%s", socket_path);

    *conn_ctx_p = ctx;
    return SR_ERR_OK;

cleanup:
    if ((NULL != ctx) && (NULL != ctx->local_cm)) {
        cm_cleanup(ctx->local_cm);
    }
    free(ctx);
    return rc;
}

void
sr_disconnect(sr_conn_ctx_t *conn_ctx)
{
    sr_session_list_t *session = NULL, *tmp = NULL;

    if (NULL != conn_ctx) {
        if (NULL != conn_ctx->local_cm) {
            /* destroy our own sysrepo engine */
            cm_stop(conn_ctx->local_cm);
            cm_cleanup(conn_ctx->local_cm);
        }

        if (conn_ctx->primary) {
            /* destroy global resources */
            sr_logger_cleanup();
        }

        /* destroy all sessions */
        session = conn_ctx->session_list;
        while (NULL != session) {
            tmp = session;
            session = session->next;
            free(tmp->session);
            free(tmp);
        }

        pthread_mutex_destroy(&conn_ctx->lock);
        free(conn_ctx->msg_buf);
        close(conn_ctx->fd);
        free(conn_ctx);
    }
}

int
sr_session_start(sr_conn_ctx_t *conn_ctx, const char *user_name, sr_datastore_t datastore, sr_session_ctx_t **session_p)
{
    sr_session_ctx_t *session = NULL;
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(conn_ctx, session_p);

    /* initialize session context */
    session = calloc(1, sizeof(*session));
    if (NULL == session) {
        SR_LOG_ERR_MSG("Cannot allocate memory for session context.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    /* prepare session_start message */
    rc = sr_pb_req_alloc(SR__OPERATION__SESSION_START, /* undefined session id */ 0, &msg_req);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate session_start message.");
        goto cleanup;
    }
    msg_req->request->session_start_req->datastore = sr_datastore_sr_to_gpb(datastore);

    /* set user name if provided */
    if (NULL != user_name) {
        msg_req->request->session_start_req->user_name = strdup(user_name);
        if (NULL == msg_req->request->session_start_req->user_name) {
            SR_LOG_ERR_MSG("Cannot duplicate user name for session_start message.");
            goto cleanup;
        }
    }

    /* send the request and receive the response */
    rc = cl_request_process(conn_ctx, msg_req, &msg_resp, SR__OPERATION__SESSION_START);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Error by processing of session_stop request.");
        goto cleanup;
    }

    session->id = msg_resp->response->session_start_resp->session_id;
    sr__msg__free_unpacked(msg_req, NULL);
    sr__msg__free_unpacked(msg_resp, NULL);

    /* store the session the in connection */
    rc = cl_conn_add_session(conn_ctx, session);
    if (SR_ERR_OK != rc) {
        SR_LOG_WRN_MSG("Error by adding the session to the connection session list.");
    }

    session->conn_ctx = conn_ctx;
    *session_p = session;

    return SR_ERR_OK;

cleanup:
    if (NULL != msg_req) {
        sr__msg__free_unpacked(msg_req, NULL);
    }
    if (NULL != msg_resp) {
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    free(session);
    return rc;
}

int
sr_session_stop(sr_session_ctx_t *session)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, session->conn_ctx);

    /* prepare session_stop message */
    rc = sr_pb_req_alloc(SR__OPERATION__SESSION_STOP, session->id, &msg_req);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate session_stop message.");
        goto cleanup;
    }
    msg_req->request->session_stop_req->session_id = session->id;

    /* send the request and receive the response */
    rc = cl_request_process(session->conn_ctx, msg_req, &msg_resp, SR__OPERATION__SESSION_STOP);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Error by processing of session_stop request.");
        goto cleanup;
    }

    /* remove the session from connection */
    rc = cl_conn_remove_session(session->conn_ctx, session);
    if (SR_ERR_OK != rc) {
        SR_LOG_WRN_MSG("Error by removing the session from the connection session list.");
    }

    sr__msg__free_unpacked(msg_req, NULL);
    sr__msg__free_unpacked(msg_resp, NULL);
    free(session);

    return SR_ERR_OK;

cleanup:
    if (NULL != msg_req) {
        sr__msg__free_unpacked(msg_req, NULL);
    }
    if (NULL != msg_resp) {
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    return rc;
}

int
sr_list_schemas(sr_session_ctx_t *session, sr_schema_t **schemas, size_t *schema_cnt)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(session, session->conn_ctx, schemas, schema_cnt);

    /* prepare list_schemas message */
    rc = sr_pb_req_alloc(SR__OPERATION__LIST_SCHEMAS, session->id, &msg_req);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate list_schemas message.");
        goto cleanup;
    }

    /* send the request and receive the response */
    rc = cl_request_process(session->conn_ctx, msg_req, &msg_resp, SR__OPERATION__LIST_SCHEMAS);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Error by processing of list_schemas request.");
        goto cleanup;
    }

    /* copy schemas from response to output argument */
    rc = sr_schemas_gpb_to_sr((const Sr__Schema**)msg_resp->response->list_schemas_resp->schemas,
            msg_resp->response->list_schemas_resp->n_schemas, schemas);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Unable to copy schemas from GPB.");
        goto cleanup;
    }
    *schema_cnt = msg_resp->response->list_schemas_resp->n_schemas;

    sr__msg__free_unpacked(msg_req, NULL);
    sr__msg__free_unpacked(msg_resp, NULL);

    return SR_ERR_OK;

cleanup:
    if (NULL != msg_req) {
        sr__msg__free_unpacked(msg_req, NULL);
    }
    if (NULL != msg_resp) {
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    return rc;
}

int
sr_get_item(sr_session_ctx_t *session, const char *path, sr_val_t **value)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(session, session->conn_ctx, path, value);

    /* prepare get_item message */
    rc = sr_pb_req_alloc(SR__OPERATION__GET_ITEM, session->id, &msg_req);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate get_item message.");
        goto cleanup;
    }

    /* fill in the path */
    msg_req->request->get_item_req->path = strdup(path);
    if (NULL == msg_req->request->get_item_req->path) {
        SR_LOG_ERR_MSG("Cannot allocate get_item path.");
        goto cleanup;
    }

    /* send the request and receive the response */
    rc = cl_request_process(session->conn_ctx, msg_req, &msg_resp, SR__OPERATION__GET_ITEM);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Error by processing of get_item request.");
        goto cleanup;
    }

    /* duplicate the content of gpb to sr_val_t */
    rc = sr_dup_gpb_to_val_t(msg_resp->response->get_item_resp->value, value);
    if (SR_ERR_OK != rc){
        SR_LOG_ERR_MSG("Copying from gpb to sr_val_t failed");
        goto cleanup;
    }

    sr__msg__free_unpacked(msg_req, NULL);
    sr__msg__free_unpacked(msg_resp, NULL);

    return SR_ERR_OK;

cleanup:
    if (NULL != msg_req) {
        sr__msg__free_unpacked(msg_req, NULL);
    }
    if (NULL != msg_resp) {
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    return rc;
}

int
sr_get_items(sr_session_ctx_t *session, const char *path, sr_val_t **values, size_t *value_cnt)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_val_t *vals = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(session, session->conn_ctx, path, values, value_cnt);

    /* prepare get_item message */
    rc = sr_pb_req_alloc(SR__OPERATION__GET_ITEMS, session->id, &msg_req);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate get_items message.");
        goto cleanup;
    }

    /* fill in the path */
    msg_req->request->get_items_req->path = strdup(path);
    if (NULL == msg_req->request->get_items_req->path) {
        SR_LOG_ERR_MSG("Cannot allocate get_items path.");
        goto cleanup;
    }

    /* send the request and receive the response */
    rc = cl_request_process(session->conn_ctx, msg_req, &msg_resp, SR__OPERATION__GET_ITEMS);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Error by processing of get_items request.");
        goto cleanup;
    }

    /* allocate the array of sr_val_t */
    size_t cnt = msg_resp->response->get_items_resp->n_values;
    vals = calloc(cnt, sizeof(*vals));
    if (NULL == vals){
        SR_LOG_ERR_MSG("Cannot allocate array of values.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    /* copy the content of gpb values to sr_val_t */
    for (size_t i = 0; i < cnt; i++) {
        rc = sr_copy_gpb_to_val_t(msg_resp->response->get_items_resp->values[i], &vals[i]);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Copying from gpb to sr_val_t failed");
            for (size_t j = 0; j < i; j++) {
                sr_free_val_content(&vals[i]);
            }
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
    }

    *values = vals;
    *value_cnt = cnt;

    sr__msg__free_unpacked(msg_req, NULL);
    sr__msg__free_unpacked(msg_resp, NULL);

    return SR_ERR_OK;

cleanup:
    free(vals);
    if (NULL != msg_req) {
        sr__msg__free_unpacked(msg_req, NULL);
    }
    if (NULL != msg_resp) {
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    return rc;
}


int
sr_get_items_iter(sr_session_ctx_t *session, const char *path, bool recursive, sr_val_iter_t **iter)
{
    Sr__Msg *msg_resp = NULL;
    sr_val_iter_t *it = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(session, session->conn_ctx, path, iter);
    rc = cl_send_get_items_iter(session, path, recursive, 0, CL_GET_ITEMS_FETCH_LIMIT, &msg_resp);
    if (SR_ERR_NOT_FOUND == rc){
        SR_LOG_DBG("No items found for xpath '%s'", path);
        goto cleanup;
    }
    else if (SR_ERR_OK != rc){
        SR_LOG_ERR("Sending get_items request failed '%s'", path);
        goto cleanup;
    }

    it = calloc(1, sizeof(*it));
    if (NULL == it){
        SR_LOG_ERR_MSG("Memory allocation failed");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    it->index = 0;
    it->count = msg_resp->response->get_items_resp->n_values;

    it->recursive = recursive;
    it->path = strdup(path);
    if (NULL == it->path){
        SR_LOG_ERR_MSG("Duplication of path failed");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    it->buff_values = calloc(it->count, sizeof(*it->buff_values));
    if (NULL == it->buff_values){
        SR_LOG_ERR_MSG("Memory allocation failed");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    /* copy the content of gpb to sr_val_t */
    for (size_t i = 0; i < it->count; i++){
        rc = sr_dup_gpb_to_val_t(msg_resp->response->get_items_resp->values[i], &it->buff_values[i]);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Copying from gpb to sr_val_t failed");
            sr_free_values_arr(it->buff_values, i);
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
    }

    *iter = it;

    sr__msg__free_unpacked(msg_resp, NULL);

    return SR_ERR_OK;

cleanup:
    if (NULL != msg_resp) {
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    if (NULL != it){
        if (NULL != it->path){
            free(it->path);
        }
        free(it);
    }
    return rc;
}

int
sr_get_item_next(sr_session_ctx_t *session, sr_val_iter_t *iter, sr_val_t **value)
{
    int rc = SR_ERR_OK;
    Sr__Msg *msg_resp = NULL;

    CHECK_NULL_ARG3(session, iter, value);

    if (0 == iter->count) {
        /* No more data to be read */
        *value = NULL;
        return SR_ERR_NOT_FOUND;
    }
    else if (iter->index < iter->count) {
        /* There are buffered data */
        *value = iter->buff_values[iter->index++];
        iter->offset++;
    }
    else {
        /* Fetch more items */
        rc = cl_send_get_items_iter(session, iter->path, iter->recursive, iter->offset,
                CL_GET_ITEMS_FETCH_LIMIT, &msg_resp);
        if (SR_ERR_NOT_FOUND == rc){
            SR_LOG_DBG("All items has been read for path '%s'", iter->path);
            goto cleanup;
        }
        else if (SR_ERR_OK != rc){
            SR_LOG_ERR("Fetching more items failed '%s'", iter->path);
            goto cleanup;
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
            if (NULL == tmp) {
                SR_LOG_ERR_MSG("Memory allocation failed");
                rc = SR_ERR_NOMEM;
                goto cleanup;
            }
            iter->buff_values = tmp;
        }

        iter->index = 0;
        iter->count = received_cnt;

        /* copy the content of gpb to sr_val_t*/
        for (size_t i = 0; i < iter->count; i++){
            rc = sr_dup_gpb_to_val_t(msg_resp->response->get_items_resp->values[i], &iter->buff_values[i]);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR_MSG("Copying from gpb to sr_val_t failed");
                sr_free_values_arr(iter->buff_values, i);
                iter->count = 0;
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
        }
        *value = iter->buff_values[iter->index++];
        iter->offset++;
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    return SR_ERR_OK;

cleanup:
    if (NULL != msg_resp){
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    return rc;
}

void
sr_free_val_iter(sr_val_iter_t *iter){
    if (NULL == iter){
        return;
    }
    free(iter->path);
    iter->path = NULL;
    if (NULL != iter->buff_values) {
        /* free items that has not been passed to user already*/
        sr_free_values_arr_range(iter->buff_values, iter->index, iter->count);
        iter->buff_values = NULL;
    }
    free(iter);
}

