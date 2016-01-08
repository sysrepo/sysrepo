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

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include "sr_common.h"
#include "connection_manager.h"

#define SR_LCONN_PATH_PREFIX "/tmp/sysrepo-local"  /**< Filesystem path prefix for local unix-domain connections (library mode). */

/**
 * Connection context used to identify a connection to sysrepo datastore.
 */
typedef struct sr_conn_ctx_s {
    int fd;                                  /**< File descriptor of the connection. */
    bool primary;                            /**< Primary connection. Handles all resources allocated only
                                                  once per process (first connection is always primary). */
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
    sr_session_ctx_t session;        /**< Session context. */
    struct sr_session_list_s *next;  /**< Next element in the linked-list. */
} sr_session_list_t;

static sr_conn_ctx_t *primary_connection = NULL;  /**< Global variable holding pointer to the primary connection. */

/**
 * Connect the client to provided unix-domain socket.
 */
static int
cl_socket_connect(sr_conn_ctx_t *conn_ctx, const char *socket_path)
{
    struct sockaddr_un addr;
    int fd = -1, rc = -1;

    CHECK_NULL_ARG2(socket_path, socket_path);

    SR_LOG_DBG("Connecting to socket=%s", socket_path);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (-1 == fd) {
        SR_LOG_ERR("Unable to create a new socket (socket=%s)", socket_path);
        return SR_ERR_INTERNAL;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);

    rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (-1 == rc) {
        SR_LOG_DBG("Unable to connect to socket (socket=%s)", socket_path);
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
 * Sends a message via provided connection.
 */
static int
cl_message_send(const sr_conn_ctx_t *conn_ctx, Sr__Msg *msg)
{
    size_t msg_size = 0;
    uint8_t *msg_buf = NULL; // TODO: preallocated dynamic message buffer per connection
    int rc = 0;

    CHECK_NULL_ARG2(conn_ctx, msg);

    /* allocate the buffer */
    msg_size = sr__msg__get_packed_size(msg);
    msg_buf = calloc(msg_size, sizeof(*msg_buf));
    if (NULL == msg_buf) {
        SR_LOG_ERR_MSG("Cannot allocate buffer for the message.");
        return SR_ERR_NOMEM;
    }

    /* pack the message */
    sr__msg__pack(msg, msg_buf);

    /* write 4-byte length */
    uint32_t length = htonl(msg_size);
    rc = send(conn_ctx->fd, &length, sizeof(length), 0);
    if (rc < 1) {
        SR_LOG_ERR("Error by sending of the message: %s.", strerror(errno));
        free(msg_buf);
        return SR_ERR_DISCONNECT;
    }

    /* write the message */
    rc = send(conn_ctx->fd, msg_buf, msg_size, 0);
    if (rc < 1) {
        SR_LOG_ERR("Error by sending of the message: %s.", strerror(errno));
        free(msg_buf);
        return SR_ERR_DISCONNECT;
    }

    free(msg_buf);
    return SR_ERR_OK;
}

#define CM_BUFF_LEN 1024  // TODO: preallocated dynamic message buffer per connection
/*
 * Receive a message on provided connection (blocks until a message is received).
 */
static int
cl_message_recv(const sr_conn_ctx_t *conn_ctx, Sr__Msg **msg)
{
    uint8_t *buf[CM_BUFF_LEN] = { 0, };
    size_t len = 0, pos = 0;

    /* read first 4 bytes with length of the message */
    while (pos < 4) {
        len = recv(conn_ctx->fd, buf + pos, CM_BUFF_LEN - pos, 0);
        if (-1 == len) {
            SR_LOG_ERR("Error by receiving of the message: %s.", strerror(errno));
            return SR_ERR_DISCONNECT;
        }
        if (0 == len) {
            SR_LOG_ERR_MSG("Sysrepo server disconnected.");
            return SR_ERR_DISCONNECT;
        }
        pos += len;
    }

    uint32_t msg_size_net = *((uint32_t*)buf);
    size_t msg_size = ntohl(msg_size_net);

    /* read the rest of the message */
    while (pos < msg_size + 4) {
        len = recv(conn_ctx->fd, buf + pos, CM_BUFF_LEN - pos, 0);
        if (-1 == len) {
            SR_LOG_ERR("Error by receiving of the message: %s.", strerror(errno));
            return SR_ERR_DISCONNECT;
        }
        if (0 == len) {
            SR_LOG_ERR_MSG("Sysrepo server disconnected.");
            return SR_ERR_DISCONNECT;
        }
        pos += len;
    }

    /* unpack the message */
    *msg = sr__msg__unpack(NULL, msg_size, (const uint8_t*)buf + 4);
    if (NULL == *msg) {
        SR_LOG_ERR_MSG("Malformed message received.");
        return SR_ERR_IO;
    }

    return SR_ERR_OK;
}

int
sr_connect(const char *app_name, const bool allow_library_mode, sr_conn_ctx_t **conn_ctx_p)
{
    sr_conn_ctx_t *ctx = NULL;
    int rc = SR_ERR_OK;
    char socket_path[PATH_MAX] = { 0, };

    CHECK_NULL_ARG2(app_name, conn_ctx_p);

    /* initialize the context */
    ctx = calloc(1, sizeof(*ctx));
    if (NULL == ctx) {
        SR_LOG_ERR_MSG("Cannot allocate memory for connection context.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    /* check if this is the primary connection */
    // TODO: lock
    if (NULL == primary_connection) {
        primary_connection = ctx;
        // unlock
        ctx->primary = true;

        /* initialize logging */
        sr_logger_init(app_name);
    }

    // TODO: attempt to connect to sysrepo daemon socket

    /* connect in library mode */
    ctx->library_mode = true;
    snprintf(socket_path, PATH_MAX, "%s-%d", SR_LCONN_PATH_PREFIX, getpid());

    /* attempt to connect to our own sysrepo engine (local engine may already exist) */
    rc = cl_socket_connect(ctx, socket_path);
    if (SR_ERR_OK != rc) {
        /* initialize our own sysrepo engine and attempt to connect again */
        SR_LOG_DBG_MSG("Local sysrepo engine not running yet, initializing new one.");

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

    *conn_ctx_p = ctx;
    return SR_ERR_OK;

cleanup:
    if (NULL != ctx->local_cm) {
        cm_cleanup(ctx->local_cm);
    }
    free(ctx);
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
        if (conn_ctx->primary) {
            /* destroy global resources */
            sr_logger_cleanup();
        }
        close(conn_ctx->fd);
        free(conn_ctx);
    }
}

int
sr_session_start(sr_conn_ctx_t *conn_ctx, const char *user_name, sr_datastore_t datastore, sr_session_ctx_t **session_p)
{
    sr_session_ctx_t *session = NULL;
    Sr__Msg *msg = NULL;
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
    rc = sr_pb_req_alloc(SR__OPERATION__SESSION_START, /* undefined session id */ 0, &msg);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate session_start message.");
        goto cleanup;
    }

    /* set user name if provided */
    if (NULL != user_name) {
        msg->request->session_start_req->user_name = strdup(user_name);
        if (NULL == msg->request->session_start_req->user_name) {
            SR_LOG_ERR_MSG("Cannot duplicate user name for session_start message.");
            goto cleanup;
        }
    }

    /* send the message */
    rc = cl_message_send(conn_ctx, msg);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Unable to send session_start message.");
        goto cleanup;
    }
    sr__msg__free_unpacked(msg, NULL);

    /* receive the response */
    rc = cl_message_recv(conn_ctx, &msg);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Unable to receive session_start response message.");
        goto cleanup;
    }

    /* validate the message */
    rc = sr_pb_msg_validate(msg, SR__MSG__MSG_TYPE__RESPONSE, SR__OPERATION__SESSION_START);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Malformed message received.");
        goto cleanup;
    }

    session->id = msg->response->session_start_resp->session_id;
    sr__msg__free_unpacked(msg, NULL);

    session->conn_ctx = conn_ctx;
    *session_p = session;

    return SR_ERR_OK;

cleanup:
    if (NULL != msg) {
        sr__msg__free_unpacked(msg, NULL);
    }
    free(session);
    return rc;
}

int sr_session_stop(sr_session_ctx_t *session)
{
    Sr__Msg *msg = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, session->conn_ctx);

    /* prepare session_stop message */
    rc = sr_pb_req_alloc(SR__OPERATION__SESSION_STOP, session->id, &msg);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate session_stop message.");
        goto cleanup;
    }
    msg->request->session_stop_req->session_id = session->id;

    /* send the message */
    rc = cl_message_send(session->conn_ctx, msg);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Unable to send session_stop message.");
        goto cleanup;
    }
    sr__msg__free_unpacked(msg, NULL);
    msg = NULL;

    /* receive the response */
    rc = cl_message_recv(session->conn_ctx, &msg);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Unable to receive session_stop response message.");
        goto cleanup;
    }

    /* validate the message */
    rc = sr_pb_msg_validate(msg, SR__MSG__MSG_TYPE__RESPONSE, SR__OPERATION__SESSION_STOP);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Malformed message received.");
        goto cleanup;
    }

    /* check for errors */
    if (SR_ERR_OK != msg->response->result) {
        SR_LOG_ERR("Error by processing session_stop request: %s.",
                (NULL != msg->response->error_msg) ? msg->response->error_msg : sr_strerror(msg->response->result));
        rc = msg->response->result;
        goto cleanup;
    }

    sr__msg__free_unpacked(msg, NULL);
    free(session);

    return SR_ERR_OK;

cleanup:
    if (NULL != msg) {
        sr__msg__free_unpacked(msg, NULL);
    }
    return rc;
}

char *
sr_strerror(int err_code)
{
    return NULL; // TODO
}
