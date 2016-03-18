/**
 * @file cl_common.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Common Client Library routines.
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

#include "cl_common.h"

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
static void
cl_conn_remove_session(sr_conn_ctx_t *connection, sr_session_ctx_t *session)
{
    sr_session_list_t *tmp = NULL, *prev = NULL;

    CHECK_NULL_ARG_VOID2(connection, session);

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
}

/**
 * @brief Expands message buffer of a connection to fit given size, if needed.
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
 * @brief Sends a message via provided connection.
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
 * @brief Receives a message on provided connection (blocks until a message is received).
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

int
cl_connection_create(sr_conn_ctx_t **conn_ctx_p)
{
    sr_conn_ctx_t *connection = NULL;
    int rc = 0;

    /* initialize the context */
    connection = calloc(1, sizeof(*connection));
    CHECK_NULL_NOMEM_RETURN(connection);

    /* init connection mutext */
    rc = pthread_mutex_init(&connection->lock, NULL);
    if (0 != rc) {
        SR_LOG_ERR_MSG("Cannot initialize connection mutex.");
        free(connection);
        return SR_ERR_INIT_FAILED;
    }

    connection->fd = -1;

    *conn_ctx_p = connection;
    return SR_ERR_OK;
}

void
cl_connection_cleanup(sr_conn_ctx_t *conn_ctx)
{
    sr_session_list_t *session = NULL, *tmp = NULL;

    if (NULL != conn_ctx) {
        /* destroy all sessions */
        session = conn_ctx->session_list;
        while (NULL != session) {
            tmp = session;
            session = session->next;
            cl_session_cleanup(tmp->session);
        }

        pthread_mutex_destroy(&conn_ctx->lock);
        free(conn_ctx->msg_buf);
        free((void*)conn_ctx->dst_address);
        if (-1 != conn_ctx->fd) {
            close(conn_ctx->fd);
        }
        free(conn_ctx);
    }
}

int
cl_session_create(sr_conn_ctx_t *conn_ctx, sr_session_ctx_t **session_p)
{
    sr_session_ctx_t *session = NULL;
    int rc = 0;

    /* initialize session context */
    session = calloc(1, sizeof(*session));
    CHECK_NULL_NOMEM_RETURN(session);

    /* initialize session mutext */
    rc = pthread_mutex_init(&session->lock, NULL);
    if (0 != rc) {
        SR_LOG_ERR_MSG("Cannot initialize session mutex.");
        free(session);
        return SR_ERR_INIT_FAILED;
    }

    session->conn_ctx = conn_ctx;

    /* store the session in the connection */
    rc = cl_conn_add_session(conn_ctx, session);
    if (SR_ERR_OK != rc) {
        SR_LOG_WRN_MSG("Error by adding the session to the connection session list.");
    }

    *session_p = session;
    return SR_ERR_OK;
}

void
cl_session_cleanup(sr_session_ctx_t *session)
{
    if (NULL != session) {
        /* remove the session from connection */
        cl_conn_remove_session(session->conn_ctx, session);

        sr_free_errors(session->error_info, session->error_info_size);
        pthread_mutex_destroy(&session->lock);
        free(session);
    }
}

int
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
        SR_LOG_ERR("Unable to create a new socket: %s", strerror(errno));
        return SR_ERR_INTERNAL;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);

    /* connect to server */
    rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (-1 == rc) {
        SR_LOG_DBG("Unable to connect to socket=%s: %s", socket_path, strerror(errno));
        close(fd);
        return SR_ERR_DISCONNECT;
    }

    /* set timeout for receive operation */
    tv.tv_sec = CL_REQUEST_TIMEOUT;
    tv.tv_usec = 0;
    rc = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
    if (-1 == rc) {
        SR_LOG_ERR("Unable to set timeout for socket operations on socket=%s: %s", socket_path, strerror(errno));
        close(fd);
        return SR_ERR_DISCONNECT;
    }

    conn_ctx->fd = fd;
    return SR_ERR_OK;
}

int
cl_request_process(sr_session_ctx_t *session, Sr__Msg *msg_req, Sr__Msg **msg_resp,
        const Sr__Operation expected_response_op)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(session, session->conn_ctx, msg_req, msg_resp);

    SR_LOG_DBG("Sending %s request.", sr_operation_name(expected_response_op));

    pthread_mutex_lock(&session->conn_ctx->lock);

    /* send the request */
    rc = cl_message_send(session->conn_ctx, msg_req);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Unable to send the message with request (session id=%"PRIu32", operation=%s).",
                session->id, sr_operation_name(msg_req->request->operation));
        pthread_mutex_unlock(&session->conn_ctx->lock);
        return rc;
    }

    SR_LOG_DBG("%s request sent, waiting for response.", sr_operation_name(expected_response_op));

    /* receive the response */
    rc = cl_message_recv(session->conn_ctx, msg_resp);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Unable to receive the message with response (session id=%"PRIu32", operation=%s).",
                session->id, sr_operation_name(msg_req->request->operation));
        pthread_mutex_unlock(&session->conn_ctx->lock);
        return rc;
    }

    pthread_mutex_unlock(&session->conn_ctx->lock);

    SR_LOG_DBG("%s response received, processing.", sr_operation_name(expected_response_op));

    /* validate the response */
    rc = sr_pb_msg_validate(*msg_resp, SR__MSG__MSG_TYPE__RESPONSE, expected_response_op);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Malformed message with response received (session id=%"PRIu32", operation=%s).",
                session->id, sr_operation_name(msg_req->request->operation));
        return rc;
    }

    /* check for errors */
    if (SR_ERR_OK != (*msg_resp)->response->result) {
        if (NULL != (*msg_resp)->response->error) {
            /* set detailed error information into session */
            rc = cl_session_set_error(session, (*msg_resp)->response->error->message, (*msg_resp)->response->error->path);
        }
        /* don't log expected errors */
        if (SR_ERR_NOT_FOUND != (*msg_resp)->response->result &&
                SR_ERR_VALIDATION_FAILED != (*msg_resp)->response->result &&
                SR_ERR_COMMIT_FAILED != (*msg_resp)->response->result) {
            SR_LOG_ERR("Error by processing of the request (session id=%"PRIu32", operation=%s): %s.",
                    session->id, sr_operation_name(msg_req->request->operation),
                (NULL != (*msg_resp)->response->error && NULL != (*msg_resp)->response->error->message) ?
                        (*msg_resp)->response->error->message : sr_strerror((*msg_resp)->response->result));
        }
        return (*msg_resp)->response->result;
    }

    return rc;
}

int
cl_session_set_error(sr_session_ctx_t *session, const char *error_message, const char *error_path)
{
    CHECK_NULL_ARG(session);

    pthread_mutex_lock(&session->lock);

    if (0 == session->error_info_size) {
        /* need to allocate the space for the error */
        session->error_info = calloc(1, sizeof(*session->error_info));
        if (NULL == session->error_info) {
            SR_LOG_ERR_MSG("Unable to allocate error information.");
            pthread_mutex_unlock(&session->lock);
            return SR_ERR_NOMEM;
        }
        session->error_info_size = 1;
    } else {
        /* space for the error already allocated, release old error data */
        if (NULL != session->error_info[0].message) {
            free((void*)session->error_info[0].message);
            session->error_info[0].message = NULL;
        }
        if (NULL != session->error_info[0].path) {
            free((void*)session->error_info[0].path);
            session->error_info[0].path = NULL;
        }
    }
    if (NULL != error_message) {
        session->error_info[0].message = strdup(error_message);
        if (NULL == session->error_info[0].message) {
            SR_LOG_ERR_MSG("Unable to allocate error message.");
            pthread_mutex_unlock(&session->lock);
            return SR_ERR_NOMEM;
        }
    }
    if (NULL != error_path) {
        session->error_info[0].path = strdup(error_path);
        if (NULL == session->error_info[0].path) {
            SR_LOG_ERR_MSG("Unable to allocate error xpath.");
            pthread_mutex_unlock(&session->lock);
            return SR_ERR_NOMEM;
        }
    }

    session->error_cnt = 1;
    pthread_mutex_unlock(&session->lock);

    return SR_ERR_OK;
}

int
cl_session_set_errors(sr_session_ctx_t *session, Sr__Error **errors, size_t error_cnt)
{
    sr_error_info_t *tmp_info = NULL;

    CHECK_NULL_ARG2(session, errors);

    pthread_mutex_lock(&session->lock);

    if (session->error_info_size < error_cnt) {
        tmp_info = realloc(session->error_info, (error_cnt * sizeof(*tmp_info)));
        if (NULL == tmp_info) {
            SR_LOG_ERR_MSG("Unable to allocate error information.");
            pthread_mutex_unlock(&session->lock);
            return SR_ERR_NOMEM;
        }
        session->error_info = tmp_info;
        session->error_info_size = error_cnt;
    }
    for (size_t i = 0; i < error_cnt; i++) {
        if (NULL != errors[i]->message) {
            session->error_info[i].message = strdup(errors[i]->message);
            if (NULL == session->error_info[i].message) {
                SR_LOG_WRN_MSG("Unable to allocate error message, will be left NULL.");
            }
        }
        if (NULL != errors[i]->path) {
            session->error_info[i].path = strdup(errors[i]->path);
            if (NULL == session->error_info[i].path) {
                SR_LOG_WRN_MSG("Unable to allocate error xpath, will be left NULL.");
            }
        }
    }

    session->error_cnt = error_cnt;
    pthread_mutex_unlock(&session->lock);

    return SR_ERR_OK;
}

int
cl_session_clear_errors(sr_session_ctx_t *session)
{
    CHECK_NULL_ARG(session);

    pthread_mutex_lock(&session->lock);
    session->error_cnt = 0;
    pthread_mutex_unlock(&session->lock);

    return SR_ERR_OK;
}

sr_error_t
cl_session_return(sr_session_ctx_t *session, sr_error_t error_code)
{
    CHECK_NULL_ARG(session);

    pthread_mutex_lock(&session->lock);
    session->last_error = error_code;
    pthread_mutex_unlock(&session->lock);

    return error_code;
}
