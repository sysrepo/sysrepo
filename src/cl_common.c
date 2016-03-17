/**
 * @file cl_common.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief TODO
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
        close(conn_ctx->fd);
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
