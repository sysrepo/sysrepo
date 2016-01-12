/**
 * @file connection_manager.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Implementation of Connection Manager - module that handles all connections to Sysrepo Engine.
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/select.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#include <pwd.h>

#include "sr_common.h"
#include "session_manager.h"
#include "request_processor.h"
#include "connection_manager.h"

#define CM_FD_INVALID -1  /**< Invalid value of file descriptor. */

#define CM_SELECT_TIMEOUT (10)      /**< Timeout used for select calls (in seconds). */
#define CM_SIG_STOP (SIGRTMIN + 8)  /**< Signal used to notify the thread with event loop about stop request (applicable for library mode). */

#define PIPE_READ 0   /**< Identifies read end of a pipe. */
#define PIPE_WRITE 1  /**< Identifies write end of a pipe. */

#define CM_IN_BUFF_MIN_SPACE 512  /**< Minimal empty space in the input buffer. */
#define CM_BUFF_ALLOC_CHUNK 1024  /**< Chunk size for buffer expansions. */

#define MSG_PREAM_SIZE sizeof(uint32_t)  /**< Size of message preamble. */

/**
 * @brief Global variable used to request stop of the event loop in all instances of CM,
 * it should be set ONLY by signal handler functions within the same thread as the loop.
 */
static volatile sig_atomic_t stop_requested = 0;

/**
 * @brief Connection Manager context.
 */
typedef struct cm_ctx_s {
    /** Mode in which Connection Manager will operate. */
    cm_connection_mode_t mode;

    /** Session Manager context. */
    sm_ctx_t *sm_ctx;
    /** Request Processor context. */
    rp_ctx_t *rp_ctx;

    /** Path where unix-domain server is binded to. */
    const char *server_socket_path;
    /** Socket descriptor used to listen & accept new unix-domain connections. */
    int listen_socket_fd;
    /** outgoing message queue (descriptors of a pipe, write is performed by ::cm_msg_send). */
    int out_msg_fds[2];

    /** Thread where event loop will be running in case of library mode. */
    pthread_t event_loop_thread;
    /** File descriptor set being watched for readable event by select. */
    fd_set select_read_fds;
    /** File descriptor set being watched for writable event by select. */
    fd_set select_write_fds;
    /** Maximum file descriptor being watched by select. */
    int select_fd_max;
} cm_ctx_t;

/**
 * @brief Sets the file descriptor to non-blocking I/O mode.
 */
static int
cm_fd_set_nonblock(int fd)
{
    int flags = 0, rc = 0;

    flags = fcntl(fd, F_GETFL, 0);
    if (-1 == flags) {
        SR_LOG_WRN("Socket fcntl error (skipped): %s", strerror(errno));
        flags = 0;
    }
    rc = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (-1 == rc) {
        SR_LOG_ERR("Socket fcntl error: %s", strerror(errno));
        return SR_ERR_INTERNAL;
    }

    return SR_ERR_OK;
}

/**
 * @brief Initializes unix-domain socket server.
 */
static int
cm_server_init(cm_ctx_t *cm_ctx, const char *socket_path)
{
    int fd = -1;
    int rc = SR_ERR_OK;
    struct sockaddr_un addr;

    CHECK_NULL_ARG2(cm_ctx, socket_path);

    SR_LOG_DBG("Initializing sysrepo server at socket=%s", socket_path);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (-1 == fd){
        SR_LOG_ERR("Socket create error: %s", strerror(errno));
        rc = SR_ERR_INIT_FAILED;
        goto cleanup;
    }

    rc = cm_fd_set_nonblock(fd);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot set socket to nonblocking mode.");
        rc = SR_ERR_INIT_FAILED;
        goto cleanup;
    }

    cm_ctx->server_socket_path = strdup(socket_path);
    if (NULL == cm_ctx->server_socket_path) {
        SR_LOG_ERR_MSG("Cannot allocate string for socket path.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }
    unlink(socket_path);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);

    rc = bind(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (-1 == rc) {
        SR_LOG_ERR("Socket bind error: %s", strerror(errno));
        rc = SR_ERR_INIT_FAILED;
        goto cleanup;
    }

    rc = listen(fd, SOMAXCONN);
    if (-1 == rc) {
        SR_LOG_ERR("Socket listen error: %s", strerror(errno));
        rc = SR_ERR_INIT_FAILED;
        goto cleanup;
    }

    cm_ctx->listen_socket_fd = fd;
    return SR_ERR_OK;

cleanup:
    if (-1 != fd) {
        close(fd);
    }
    unlink(socket_path);
    free((char*)cm_ctx->server_socket_path);
    return rc;
}

/**
 * @brief Cleans up unix-domain socket server.
 */
static void
cm_server_cleanup(cm_ctx_t *cm_ctx)
{
    if (NULL != cm_ctx) {
        if (-1 != cm_ctx->listen_socket_fd) {
            close(cm_ctx->listen_socket_fd);
        }
        if (NULL != cm_ctx->server_socket_path) {
            unlink(cm_ctx->server_socket_path);
            free((char*)cm_ctx->server_socket_path);
        }
    }
}

/**
 * @brief Initializes outgoing message queue.
 */
static int
cm_out_msg_queue_init(cm_ctx_t *cm_ctx)
{
    int rc = -1;

    CHECK_NULL_ARG(cm_ctx);

    /* create a pipe */
    rc = pipe(cm_ctx->out_msg_fds);
    if (-1 == rc) {
        SR_LOG_ERR("Pipe create error: %s", strerror(errno));
        return SR_ERR_INIT_FAILED;
    }

    /* set read end to nonblocking */
    rc = cm_fd_set_nonblock(cm_ctx->out_msg_fds[PIPE_READ]);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot set read end of the pipe to nonblocking mode.");
        close(cm_ctx->out_msg_fds[PIPE_READ]);
        close(cm_ctx->out_msg_fds[PIPE_WRITE]);
        return SR_ERR_INIT_FAILED;
    }

    return SR_ERR_OK;
}

/**
 * @brief Cleans up outgoing message queue.
 */
static void
cm_out_msg_queue_cleanup(cm_ctx_t *cm_ctx)
{
    if (NULL != cm_ctx) {
        close(cm_ctx->out_msg_fds[PIPE_READ]);
        close(cm_ctx->out_msg_fds[PIPE_WRITE]);
    }
}

/**
 * @brief Initializes data structures used by select. Adds unix-domain server
 * socket and read-end of the outgoing message queue to fd set monitored by select.
 */
static int
cm_select_init(cm_ctx_t *cm_ctx)
{
    CHECK_NULL_ARG(cm_ctx);

    if ((cm_ctx->listen_socket_fd >= FD_SETSIZE) || (cm_ctx->out_msg_fds[PIPE_READ] >= FD_SETSIZE)) {
        SR_LOG_ERR("FD_SETSIZE(%d) reached, cannot select on one of provided fds.", FD_SETSIZE);
        return SR_ERR_INTERNAL;
    }

    /* init both read and write fd sets */
    FD_ZERO(&cm_ctx->select_read_fds);
    FD_ZERO(&cm_ctx->select_write_fds);

    /* select on server listen socket */
    FD_SET(cm_ctx->listen_socket_fd, &cm_ctx->select_read_fds);
    cm_ctx->select_fd_max = cm_ctx->listen_socket_fd;

    /* select on read-end of outgoing msg queue pipe */
    FD_SET(cm_ctx->out_msg_fds[PIPE_READ], &cm_ctx->select_read_fds);
    if (cm_ctx->out_msg_fds[PIPE_READ] > cm_ctx->select_fd_max) {
        cm_ctx->select_fd_max = cm_ctx->out_msg_fds[PIPE_READ];
    }

    return SR_ERR_OK;
}

/**
 * @brief Cleans up the structures used by select. Closes all monitored
 * descriptors that left open.
 */
static void
cm_select_cleanup(cm_ctx_t *cm_ctx)
{
    int i = 0;

    if (NULL != cm_ctx) {
        for (i = 0; i < cm_ctx->select_fd_max; i++) {
            if (FD_ISSET(i, &cm_ctx->select_read_fds) || FD_ISSET(i, &cm_ctx->select_write_fds)) {
                close(i);
                FD_CLR(i, &cm_ctx->select_read_fds);
                FD_CLR(i, &cm_ctx->select_write_fds);
            }
        }
    }
}

/**
 * @brief Accepts new connections to the server and starts monitoring the new
 * client file descriptors.
 */
static int
cm_server_accept(cm_ctx_t *cm_ctx)
{
    int clnt_fd = -1;
    sm_connection_t *connection = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(cm_ctx);

    do {
        clnt_fd = accept(cm_ctx->listen_socket_fd, NULL, NULL);
        if (clnt_fd > 0) {
            /* accepted the new connection */
            SR_LOG_DBG("New client connection on fd %d", clnt_fd);
            if (clnt_fd >= FD_SETSIZE) {
                /* cannot accept connections with fd above FD_SETSIZE */
                SR_LOG_ERR("FD_SETSIZE(%d) reached, cannot accept connection with fd=%d.", FD_SETSIZE, clnt_fd);
                close(clnt_fd);
                continue;
            }
            /* set to nonblocking mode */
            rc = cm_fd_set_nonblock(clnt_fd);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Cannot set fd=%d to nonblocking mode.", clnt_fd);
                close(clnt_fd);
                continue;
            }
            /* start connection in session manager */
            rc = sm_connection_start(cm_ctx->sm_ctx, CM_AF_UNIX_CLIENT, clnt_fd, &connection);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Cannot start connection in Session manager (fd=%d).", clnt_fd);
                close(clnt_fd);
                continue;
            }
            /* check uid in case of local (library) mode */
            if (CM_MODE_LOCAL == cm_ctx->mode) {
                if (connection->uid != geteuid()) {
                    SR_LOG_ERR("Peer's uid=%d does not match with local uid=%d "
                            "(required by local mode).", connection->uid, geteuid());
                    sm_connection_stop(cm_ctx->sm_ctx, connection);
                    close(clnt_fd);
                    continue;
                }
            }
            /* add to select fd set */
            FD_SET(clnt_fd, &cm_ctx->select_read_fds);
            if (clnt_fd > cm_ctx->select_fd_max) {
                cm_ctx->select_fd_max = clnt_fd;
            }
        } else {
            if ((EWOULDBLOCK == errno) || (EAGAIN == errno)) {
                /* no more connections to accept */
                break;
            } else {
                /* error by accept - only log the error and skip it */
                SR_LOG_ERR("Unexpected error by accepting new connection: %s", strerror(errno));
                continue;
            }
        }
    } while (clnt_fd > 0); /* accept returns -1 when there are no more connections to accept */

    return SR_ERR_OK;
}

/**
 * @brief Dispatches a readable event on read-end of outgoing message queue.
 */
static int
cm_out_msg_queue_dispatch(const cm_ctx_t *cm_ctx)
{
    CHECK_NULL_ARG(cm_ctx);

    SR_LOG_DBG_MSG("out msg queue dispatch");

    // TODO process the message

    return SR_ERR_OK;
}

/**
 * @brief Close the connection inside of Connection Manager and Request Processor.
 */
static int
cm_conn_close(cm_ctx_t *cm_ctx, sm_connection_t *conn)
{
    sm_session_list_t *sess = NULL;
    int rc = SR_ERR_OK;

    SR_LOG_INF("Closing the connection %p.", (void*)conn);

    /* close all sessions assigned to this connection */
    while (NULL != conn->session_list) {
        sess = conn->session_list;

        /* stop the session in Request Processor */
        rp_session_stop(cm_ctx->rp_ctx, sess->session->rp_session);

        /* drop the session in Session manager */
        sm_session_drop(cm_ctx->sm_ctx, sess->session); /* also removes from conn->session_list */
    }

    sm_connection_stop(cm_ctx->sm_ctx, conn);

    return rc;
}

/**
 * @brief Close the file descriptor and stop monitoring it.
 */
static int
cm_fd_close(cm_ctx_t *cm_ctx, int fd)
{
    CHECK_NULL_ARG(cm_ctx);

    /* close the file descriptor */
    close(fd);

    /* remove from set of monitored fds */
    FD_CLR(fd, &cm_ctx->select_read_fds);
    FD_CLR(fd, &cm_ctx->select_write_fds);

    return SR_ERR_OK;
}

/**
 * @brief Expand the size of the buffer of given connection.
 */
static int
cm_conn_buffer_expand(const sm_connection_t *conn, sm_buffer_t *buff, size_t requested_space)
{
    uint8_t *tmp = NULL;

    CHECK_NULL_ARG2(conn, buff);

    if ((buff->size - buff->pos) < requested_space) {
        if (requested_space < CM_BUFF_ALLOC_CHUNK) {
            requested_space = CM_BUFF_ALLOC_CHUNK;
        }
        tmp = realloc(buff->data, buff->size + requested_space);
        if (NULL != tmp) {
            buff->data = tmp;
            buff->size += requested_space;
            SR_LOG_DBG("%s buffer for fd=%d expanded to %zu bytes.",
                    (&conn->in_buff == buff ? "Input" : "Output"), conn->fd, buff->size);
        } else {
            SR_LOG_ERR("Cannot expand %s buffer for fd=%d - not enough memory.",
                    (&conn->in_buff == buff ? "input" : "output"), conn->fd);
            return SR_ERR_NOMEM;
        }
    }

    return SR_ERR_OK;
}

/**
 * @brief Flush contents of the output buffer of the given connection.
 */
static int
cm_conn_out_buff_flush(cm_ctx_t *cm_ctx, sm_connection_t *connection)
{
    sm_buffer_t *buff = NULL;
    int written = 0;
    size_t buff_size = 0, buff_pos = 0;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(cm_ctx, connection);

    buff = &connection->out_buff;
    buff_size = buff->pos;
    buff_pos = 0;

    do {
        /* try to send all data */
        written = send(connection->fd, (buff->data + buff_pos), (buff_size - buff_pos), 0);
        if (written > 0) {
            buff_pos += written;
        } else {
            if ((EWOULDBLOCK == errno) || (EAGAIN == errno)) {
                /* no more data can be sent now */
                SR_LOG_DBG("fd %d would block", connection->fd);
                /* monitor fd for writable event */
                FD_SET(connection->fd, &cm_ctx->select_write_fds);
                if (connection->fd > cm_ctx->select_fd_max) {
                    cm_ctx->select_fd_max = connection->fd;
                }
            } else {
                /* error by writing - close the connection due to an error */
                SR_LOG_ERR("Error by writing data to fd %d: %s.", connection->fd, strerror(errno));
                connection->close_requested = true;
                break;
            }
        }
    } while ((buff_pos < buff_size) && (written > 0));

    if ((0 != buff_pos) && (buff_size - buff_pos) > 0) {
        /* move unsent data to the front of the buffer */
        memmove(buff->data, (buff->data + buff_pos), (buff_size - buff_pos));
        buff->pos = buff_size - buff_pos;
    } else {
        /* no more data left in the buffer */
        buff->pos = 0;
    }

    return rc;
}

/**
 * @brief Send message to the recipient identified by session context.
 */
static int
cm_msg_send_session(cm_ctx_t *cm_ctx, sm_session_t *session, Sr__Msg *msg)
{
    sm_buffer_t *buff = NULL;
    size_t msg_size = 0;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(cm_ctx, session, session->connection, msg);

    buff = &session->connection->out_buff;
    msg_size = sr__msg__get_packed_size(msg);

    rc = cm_conn_buffer_expand(session->connection, buff, MSG_PREAM_SIZE + msg_size);

    if (SR_ERR_OK == rc) {
        /* write the pramble */
        *((uint32_t*)(buff->data + buff->pos)) = htonl(msg_size);
        buff->pos += MSG_PREAM_SIZE;

        /* write the message */
        sr__msg__pack(msg, (buff->data + buff->pos));
        buff->pos += msg_size;

        /* flush the buffer */
        rc = cm_conn_out_buff_flush(cm_ctx, session->connection);
    }

    return rc;
}

/**
 * @brief Processes a session start request.
 */
static int
cm_session_start_req_process(cm_ctx_t *cm_ctx, sm_connection_t *conn, Sr__Msg *msg_in)
{
    sm_session_t *session = NULL;
    struct passwd *pws = NULL;
    Sr__Msg *msg = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(cm_ctx, conn, msg_in);

    /* validate the message */
    rc = sr_pb_msg_validate(msg_in, SR__MSG__MSG_TYPE__REQUEST, SR__OPERATION__SESSION_START);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Malformed message received.");
        return SR_ERR_INVAL_ARG;
    }

    SR_LOG_DBG("Processing session_start request (conn=%p).", (void*)conn);

    /* retrieve real user name */
    pws = getpwuid(conn->uid);

    /* create the session in SM */
    rc = sm_session_create(cm_ctx->sm_ctx, conn, pws->pw_name,
            msg_in->request->session_start_req->user_name, &session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Unable to create the session in Session Manager (conn=%p).", (void*)conn);
        return rc;
    }

    /* prepare the response */
    rc = sr_pb_resp_alloc(SR__OPERATION__SESSION_START, session->id, &msg);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Cannot allocate the response for session_start request (conn=%p).", (void*)conn);
        if (NULL != session) {
            sm_session_drop(cm_ctx->sm_ctx, session);
        }
        return SR_ERR_NOMEM;
    }

    /* start session in Request Processor */
    rc = rp_session_start(cm_ctx->rp_ctx, session->real_user, session->effective_user, session->id,
            /* TODO datastore */SR_DS_CANDIDATE, &session->rp_session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Cannot start Request Processor session (conn=%p).", (void*)conn);
    }

    if (SR_ERR_OK == rc) {
        /* set the id to response */
        msg->response->session_start_resp->session_id = session->id;
    } else {
        /* set the error code to response */
        msg->response->result = rc;
    }

    /* send the response */
    rc = cm_msg_send_session(cm_ctx, session, msg);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Unable to send session_start response (conn=%p).", (void*)conn);
    }

    /* release the message */
    sr__msg__free_unpacked(msg, NULL);

    return rc;
}

/**
 * @brief Processes a session stop request.
 */
static int
cm_session_stop_req_process(cm_ctx_t *cm_ctx, sm_session_t *session, Sr__Msg *msg_in)
{
    Sr__Msg *msg_out = NULL;
    int rc = SR_ERR_OK, rc_tmp = SR_ERR_OK;

    CHECK_NULL_ARG3(cm_ctx, session, msg_in);

    SR_LOG_DBG("Processing session_stop request (session id=%"PRIu32").", session->id);

    /* prepare the response */
    rc = sr_pb_resp_alloc(SR__OPERATION__SESSION_STOP, msg_in->session_id, &msg_out);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Cannot allocate the response for session_stop request (session id=%"PRIu32").", session->id);
        return SR_ERR_NOMEM;
    }

    /* validate the message */
    rc = sr_pb_msg_validate(msg_in, SR__MSG__MSG_TYPE__REQUEST, SR__OPERATION__SESSION_STOP);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Malformed message received.");
        rc = SR_ERR_INVAL_ARG;
    }

    if (SR_ERR_OK == rc) {
        /* validate provided session id */
        if (session->id != msg_in->request->session_stop_req->session_id) {
            SR_LOG_ERR("Stopping of other sessions is not allowed (sess id=%"PRIu32", requested id=%"PRIu32").",
                    session->id, msg_in->request->session_stop_req->session_id);
            msg_out->response->error_msg = strdup("Stopping of other sessions is not allowed");
            rc = SR_ERR_UNSUPPORTED;
        }
    }

    /* stop session in Request Processor */
    if (SR_ERR_OK == rc) {
        rc = rp_session_stop(cm_ctx->rp_ctx, session->rp_session);
    }

    if (SR_ERR_OK == rc) {
        /* set the id to response */
        msg_out->response->session_stop_resp->session_id = session->id;
    } else {
        /* set the error code to response */
        msg_out->response->result = rc;
    }

    /* send the response */
    rc_tmp = cm_msg_send_session(cm_ctx, session, msg_out);
    if (SR_ERR_OK != rc_tmp) {
        SR_LOG_WRN("Unable to send session_stop response via session id=%"PRIu32".", session->id);
    }

    /* release the message */
    sr__msg__free_unpacked(msg_out, NULL);

    /* drop session in SM - must be called AFTER sending */
    if (SR_ERR_OK == rc) {
        rc = sm_session_drop(cm_ctx->sm_ctx, session);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Unable to drop the session in Session Manager (session id=%"PRIu32").", session->id);
        }
    }

    return rc;
}

static int
cm_conn_msg_process(cm_ctx_t *cm_ctx, sm_connection_t *conn, uint8_t *msg_data, size_t msg_size)
{
    Sr__Msg *msg = NULL;
    bool release_msg = false;
    sm_session_t *session = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(cm_ctx, conn, msg_data);

    /* unpack the message */
    msg = sr__msg__unpack(NULL, msg_size, msg_data);
    if (NULL == msg) {
        SR_LOG_ERR("Unable to unpack the message (conn=%p).", (void*)conn);
        return SR_ERR_INTERNAL;
    }

    /* NULL check according to message type */
    if (((SR__MSG__MSG_TYPE__REQUEST == msg->type) && (NULL == msg->request)) ||
            ((SR__MSG__MSG_TYPE__RESPONSE == msg->type) && (NULL == msg->response))) {
        SR_LOG_ERR("Message with malformed type received (conn=%p).", (void*)conn);
        sr__msg__free_unpacked(msg, NULL);
        return SR_ERR_INVAL_ARG;
    }

    /* find matching session (except for session_start request) */
    if ((SR__MSG__MSG_TYPE__REQUEST != msg->type) || (SR__OPERATION__SESSION_START != msg->request->operation)) {
        rc = sm_session_find_id(cm_ctx->sm_ctx, msg->session_id, &session);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Unable to find session context for session id=%"PRIu32" (conn=%p).",
                    msg->session_id, (void*)conn);
            sr__msg__free_unpacked(msg, NULL);
            return SR_ERR_INVAL_ARG;
        }
    }

    if (SR__MSG__MSG_TYPE__REQUEST == msg->type) {
        /* request handling */
        switch (msg->request->operation) {
            case SR__OPERATION__SESSION_START:
                rc = cm_session_start_req_process(cm_ctx, conn, msg);
                release_msg = true;
                break;
            case SR__OPERATION__SESSION_STOP:
                rc = cm_session_stop_req_process(cm_ctx, session, msg);
                release_msg = true;
                break;
            default:
                /* forward the message to Request Processor */

                // TODO: make sure that there is always only one outstanding RP request per session at the time

                rc = rp_msg_process(cm_ctx->rp_ctx, session->rp_session, msg);
                break;
        }
    } else {
        /* response handling */
        /* forward the message to Request Processor */
        rc = rp_msg_process(cm_ctx->rp_ctx, session->rp_session, msg);
    }

    if (release_msg) {
        sr__msg__free_unpacked(msg, NULL);
    }

    return rc;
}

/**
 * Process the content of input buffer of a connection.
 */
static int
cm_conn_in_buff_process(cm_ctx_t *cm_ctx, sm_connection_t *conn)
{
    sm_buffer_t *buff = NULL;
    size_t buff_pos = 0, buff_size = 0;
    uint32_t msg_size = 0;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(cm_ctx, conn);

    buff = &conn->in_buff;
    buff_size = buff->pos;
    buff_pos = 0;

    if (buff_size <= MSG_PREAM_SIZE) {
        return SR_ERR_OK; /* nothing to process so far */
    }

    while ((buff_size - buff_pos) > MSG_PREAM_SIZE) {
        msg_size = ntohl( *((uint32_t*)(buff->data + buff_pos)) );
        if ((buff_size - buff_pos) >= msg_size) {
            /* the message is completely retrieved, parse it */
            SR_LOG_DBG("New message of size %d bytes received.", msg_size);
            rc = cm_conn_msg_process(cm_ctx, conn,
                    (buff->data + buff_pos + MSG_PREAM_SIZE), msg_size);
            buff_pos += MSG_PREAM_SIZE + msg_size;
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR_MSG("Error by processing of the message.");
                break;
            }
        } else {
            /* the message is not completely retrieved, end processing */
            SR_LOG_DBG("Partial message of size %d, received %zu.", msg_size,
                    (buff_size - MSG_PREAM_SIZE - buff_pos));
            break;
        }
    }

    if ((0 != buff_pos) && (buff_size - buff_pos) > 0) {
        /* move unprocessed data to the front of the buffer */
        memmove(buff->data, (buff->data + buff_pos), (buff_size - buff_pos));
        buff->pos = buff_size - buff_pos;
    } else {
        /* no more unprocessed data left in the buffer */
        buff->pos = 0;
    }

    return rc;
}

/**
 * @brief Dispatches a readable event on the file descriptor of a normal connection.
 */
static int
cm_conn_read(cm_ctx_t *cm_ctx, int fd)
{
    sm_connection_t *conn = NULL;
    int bytes = 0;
    sm_buffer_t *buff = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(cm_ctx);

    SR_LOG_DBG("fd %d readable", fd);

    /* find matching SM connection */
    rc = sm_connection_find_fd(cm_ctx->sm_ctx, fd, &conn);
    if ((SR_ERR_OK != rc) || (NULL == conn)) {
        SR_LOG_ERR("No SM connection assigned to fd=%d.", fd);
        return SR_ERR_OK;
    }
    buff = &conn->in_buff;

    do {
        /* expand input buffer if needed */
        rc = cm_conn_buffer_expand(conn, buff, CM_IN_BUFF_MIN_SPACE);
        if (SR_ERR_OK != rc) {
            conn->close_requested = true;
            break;
        }
        /* receive data */
        bytes = recv(fd, (buff->data + buff->pos), (buff->size - buff->pos), 0);
        if (bytes > 0) {
            /* recieved "bytes" bytes of data */
            SR_LOG_DBG("%d bytes of data recieved on fd %d : %s", bytes, fd, buff->data);
            buff->pos += bytes;
        } else if (0 == bytes) {
            /* connection closed by the other side */
            SR_LOG_DBG("Peer on fd %d disconnected.", fd);
            conn->close_requested = true;
            break;
        } else {
            if ((EWOULDBLOCK == errno) || (EAGAIN == errno)) {
                /* no more data to be read */
                SR_LOG_DBG("fd %d would block", fd);
                break;
            } else {
                /* error by reading - close the connection due to an error */
                SR_LOG_ERR("Error by reading data on fd %d: %s.", fd, strerror(errno));
                conn->close_requested = true;
                break;
            }
        }
    } while (bytes > 0); /* recv returns -1 when there is no more data to be read */

    /* process the content of input buffer */
    if (SR_ERR_OK == rc) {
        rc = cm_conn_in_buff_process(cm_ctx, conn);
        if (SR_ERR_OK != rc) {
            SR_LOG_WRN("Error by processing of the input buffer of fd=%d, closing the connection.", fd);
            conn->close_requested = true;
            rc = SR_ERR_OK; /* connection will be closed, we can continue */
        }
    }

    /* close the connection if requested */
    if (conn->close_requested) {
        cm_conn_close(cm_ctx, conn);
        cm_fd_close(cm_ctx, fd);
    }

    return rc;
}

/**
 * @brief Dispatches a writable event on the file descriptor of a normal connection.
 */
static int
cm_conn_write(cm_ctx_t *cm_ctx, int fd)
{
    sm_connection_t *conn = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(cm_ctx);

    SR_LOG_DBG("fd %d writeable", fd);

    /* find matching SM connection */
    rc = sm_connection_find_fd(cm_ctx->sm_ctx, fd, &conn);
    if ((SR_ERR_OK != rc) || (NULL == conn)) {
        SR_LOG_ERR("No SM connection assigned to fd=%d.", fd);
        return SR_ERR_OK;
    }

    /* flush the output buffer */
    rc = cm_conn_out_buff_flush(cm_ctx, conn);

    /* close the connection if requested */
    if (conn->close_requested) {
        cm_conn_close(cm_ctx, conn);
        cm_fd_close(cm_ctx, fd);
    }

    return SR_ERR_OK;
}

/**
 * @brief Event loop of Connection Manager. Monitors all connections for events
 * and calls proper dispatch handler for each event. This function call blocks
 * until an error occured or until a stop request comes via stop_requested variable.
 */
static int
cm_event_loop(cm_ctx_t *cm_ctx)
{
    int events_cnt = 0, events_processed = 0, i = 0;
    int fd_max = -1;
    fd_set read_fds, write_fds;
    struct timespec timeout = { 0, };
    sigset_t sig_mask;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(cm_ctx);

    SR_LOG_DBG_MSG("Starting CM event loop.");

    timeout.tv_sec  = CM_SELECT_TIMEOUT;
    timeout.tv_nsec = 0;

    /* prepare sig_mask used to unblock signals when execution is blocked in pselect */
    sigemptyset(&sig_mask);
    sigprocmask(SIG_SETMASK, NULL, &sig_mask); /* get current mask */
    if (CM_MODE_DAEMON == cm_ctx->mode) {
        /* unblock deamon signals inside of pselect */
        sigdelset(&sig_mask, SIGINT);
        sigdelset(&sig_mask, SIGTERM);
    } else {
        /* unblock library signals inside of pselect */
        sigdelset(&sig_mask, CM_SIG_STOP);
    }

    do {
        /* copy select master sets over working sets */
        memcpy(&read_fds, &cm_ctx->select_read_fds, sizeof(cm_ctx->select_read_fds));
        memcpy(&write_fds, &cm_ctx->select_write_fds, sizeof(cm_ctx->select_write_fds));
        fd_max = cm_ctx->select_fd_max;

        /* block until an event occurs */
        events_cnt = pselect(fd_max + 1, &read_fds, &write_fds, NULL, &timeout, &sig_mask);

        SR_LOG_DBG("select unblocked, events_cnt=%d.", events_cnt);

        if (-1 == events_cnt) {
            /* error */
            if (EINTR == errno) {
                SR_LOG_DBG("Event loop interrupted by a signal, "
                        "stop_requested=%d.", stop_requested);
            } else {
                SR_LOG_ERR("Unexpected error by select: %s.", strerror(errno));
                break;
            }
        } else if (0 == events_cnt) {
            /* timeout */
            SR_LOG_DBG_MSG("select timeout expired.");
        } else {
            /* event on some of the pollfds */
            events_processed = 0;

            for (i = 0 ; i <= fd_max; i++) {
                if (FD_ISSET(i, &read_fds)) {
                    /* data ready to be read */
                    events_processed += 1;
                    if (i == cm_ctx->listen_socket_fd) {
                        /* new connection */
                        rc = cm_server_accept(cm_ctx);
                    } else if (i == cm_ctx->out_msg_fds[PIPE_READ]) {
                        /* new msg in the outgoing queue */
                        rc = cm_out_msg_queue_dispatch(cm_ctx);
                    } else {
                        /* new data from some connection */
                        rc = cm_conn_read(cm_ctx, i);
                    }
                }
                if (FD_ISSET(i, &write_fds)) {
                    /* ready to write to some connection */
                    events_processed += 1;
                    rc = cm_conn_write(cm_ctx, i);
                }
                /* if all pollfds with events are processed, stop the iteration */
                if (events_processed == events_cnt) {
                    break;
                }
            }
        }
    } while ((SR_ERR_OK == rc) && (0 == stop_requested));

    SR_LOG_DBG_MSG("CM event loop finished.");

    return rc;
}

/**
 * @brief Signal handler for CM_SIG_STOP signal (applicable only for library mode).
 */
static void
cm_sig_stop_handle(int sig)
{
    stop_requested = 1;
}

/**
 * @brief Starts the event loop in a new thread (applicable only for library mode).
 */
static void *
cm_event_loop_threaded(void *cm_ctx_p)
{
    cm_ctx_t *cm_ctx = (cm_ctx_t*)cm_ctx_p;
    struct sigaction signal_action;
    int rc = SR_ERR_OK;

    /* install CM_SIG_STOP signal handler used to break the event loop from parent thread */
    memset(&signal_action, 0, sizeof(signal_action));
    signal_action.sa_handler = &cm_sig_stop_handle;
    sigaction(CM_SIG_STOP, &signal_action, NULL);

    /* start the event loop */
    rc = cm_event_loop(cm_ctx);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Error by processing in the event loop occured.");
    }

    return NULL;
}

int
cm_init(const cm_connection_mode_t mode, const char *socket_path, cm_ctx_t **cm_ctx_p)
{
    cm_ctx_t *ctx = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(socket_path, cm_ctx_p);

    SR_LOG_DBG_MSG("Connection Manager init started.");

    ctx = calloc(1, sizeof(*ctx));
    if (NULL == ctx) {
        SR_LOG_ERR_MSG("Cannot allocate memory for Connection Manager.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }
    ctx->mode = mode;

    rc = sm_init(&ctx->sm_ctx);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot initialize Session Manager.");
        goto cleanup;
    }

    rc = cm_server_init(ctx, socket_path);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot initialize server socket.");
        goto cleanup;
    }

    rc = cm_out_msg_queue_init(ctx);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot initialize output message queue.");
        goto cleanup;
    }

    rc = cm_select_init(ctx);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot initialize poll structure.");
        goto cleanup;
    }

    rc = rp_init(ctx, &ctx->rp_ctx);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot initialize Request Processor.");
        goto cleanup;
    }

    SR_LOG_DBG_MSG("Connection Manager initialized successfully.");

    *cm_ctx_p = ctx;
    return SR_ERR_OK;

cleanup:
    cm_cleanup(ctx);
    return rc;
}

void
cm_cleanup(cm_ctx_t *cm_ctx)
{
    if (NULL != cm_ctx) {
        rp_cleanup(cm_ctx->rp_ctx);
        cm_select_cleanup(cm_ctx);
        cm_server_cleanup(cm_ctx);
        cm_out_msg_queue_cleanup(cm_ctx);
        sm_cleanup(cm_ctx->sm_ctx);
        free(cm_ctx);
    }
}

int
cm_start(cm_ctx_t *cm_ctx)
{
    int rc = SR_ERR_OK;
    sigset_t mask;

    CHECK_NULL_ARG(cm_ctx);

    stop_requested = 0;

    if (CM_MODE_DAEMON == cm_ctx->mode) {
        /* block daemon signals (will be unblocked in the event loop) */
        sigemptyset(&mask);
        sigaddset(&mask, SIGINT);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGPIPE); /* also block SIGPIPE */
        pthread_sigmask(SIG_BLOCK, &mask, NULL);

        /* run the event loop in this thread */
        rc = cm_event_loop(cm_ctx);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Error by processing in the event loop occured.");
            pthread_sigmask(SIG_UNBLOCK, &mask, NULL);
        }
    } else {
        /* block CM_SIG_STOP signal (will be unblocked in the event loop) */
        sigemptyset(&mask);
        sigaddset(&mask, CM_SIG_STOP);
        sigaddset(&mask, SIGPIPE); /* also block SIGPIPE */
        pthread_sigmask(SIG_BLOCK, &mask, NULL);

        /* run the event loop in a new thread */
        rc = pthread_create(&cm_ctx->event_loop_thread, NULL,
                cm_event_loop_threaded, cm_ctx);
        if (0 != rc) {
            SR_LOG_ERR("Error by creating a new thread: %s", strerror(errno));
            pthread_sigmask(SIG_UNBLOCK, &mask, NULL);
        }
    }

    return rc;
}

int
cm_stop(cm_ctx_t *cm_ctx)
{
    CHECK_NULL_ARG(cm_ctx);

    if (CM_MODE_DAEMON == cm_ctx->mode) {
        /* main thread (with event loop) interrupted by signal, just mark request to stop */
        stop_requested = 1;
    } else {
        SR_LOG_DBG_MSG("Sending stop signal to the event loop thread.");
        /* send a signal to the thread with event loop */
        pthread_kill(cm_ctx->event_loop_thread, CM_SIG_STOP);
        /* block until cleanup is finished */
        pthread_join(cm_ctx->event_loop_thread, NULL);
    }

    return SR_ERR_OK;
}

int
cm_msg_send(cm_ctx_t *cm_ctx, Sr__Msg *msg)
{
    sm_session_t *session = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG_NORET2(rc, cm_ctx, msg);

    if (SR_ERR_OK != rc) {
        if (NULL != msg) {
            sr__msg__free_unpacked(msg, NULL);
        }
        return rc;
    }

    rc = sm_session_find_id(cm_ctx->sm_ctx, msg->session_id, &session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Unable to find the session matching with id specified in the message "
                "(id=%"PRIu32").", msg->session_id);
        return rc;
    }

    rc = cm_msg_send_session(cm_ctx, session, msg);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Unable to send the message over session (id=%"PRIu32").", msg->session_id);
        return rc;
    }

    /* release the message */
    sr__msg__free_unpacked(msg, NULL);

    return SR_ERR_OK;
}
