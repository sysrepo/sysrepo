/**
 * @file connection_manager.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Implementation of Connection Manager - module that handles all connection to Sysrepo Engine.
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
#include <stdint.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/poll.h>

#include "sr_common.h"
#include "session_manager.h"
#include "connection_manager.h"

#define CM_FD_INVALID -1  /**< Invalid file descriptor. */
#define CM_POLL_MAX_FD_CNT 200 /**< Maximum number of file descriptors that CM is able to handle. */
#define CM_POLL_TIMEOUT (1 * 1000) /**< Timeout used for poll calls (in milliseconds) */

/**
 * @brief Modes of Connection Manager.
 */
typedef enum {
    CM_MODE_SERVER,  /**< Server mode - any client is able to connect to it. */
    CM_MODE_LOCAL,   /**< Local mode - only one, local client connection is possible */
} cm_connection_mode_t;

/**
 * @brief Connection Manager context.
 */
typedef struct cm_ctx_s {
    cm_connection_mode_t mode;
    sm_ctx_t *session_manager;       /**< Session Manager context. */
    int listen_socket_fd;            /**< Socket descriptor used to listen & accept new connections. */
    const char *server_socket_path;  /**< Path used for unix-domain socket communication. */
    int out_msg_fds[2];              /**< "queue" of messagess to be sent (descriptors of a pipe). */
    struct pollfd poll_fds[CM_POLL_MAX_FD_CNT];     /**< Poll file descriptors. TODO: make this dynamic. */
    int poll_fd_cnt;                 /**< Number of file descriptors being polled. */
} cm_ctx_t;

/**
 * @brief TODO
 *
 * @param cm_ctx
 * @param socket_path
 * @return
 */
static int
cm_server_init(cm_ctx_t *cm_ctx, const char *socket_path)
{
    int fd = CM_FD_INVALID;
    int rc = SR_ERR_OK;
    struct sockaddr_un addr;
    int on = 1;

    CHECK_NULL_ARG2(cm_ctx, socket_path);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (-1 == fd){
        SR_LOG_ERR("Socket create error: %s", strerror(errno));
        rc = SR_ERR_INIT_FAILED;
        goto cleanup;
    }

    rc = ioctl(fd, FIONBIO, (char *)&on);
    if (-1 == rc) {
        SR_LOG_ERR("Socket ioctl error: %s", strerror(errno));
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
    if (CM_FD_INVALID != fd) {
        close(fd);
    }
    unlink(socket_path);
    free((char*)cm_ctx->server_socket_path);
    return rc;
}

/**
 * @brief TODO
 * @param cm_ctx
 */
static void
cm_server_cleanup(cm_ctx_t *cm_ctx)
{
    if (NULL != cm_ctx) {
        if (CM_FD_INVALID != cm_ctx->listen_socket_fd) {
            close(cm_ctx->listen_socket_fd);
        }
        if (NULL != cm_ctx->server_socket_path) {
            unlink(cm_ctx->server_socket_path);
            free((char*)cm_ctx->server_socket_path);
        }
    }
}

/**
 * @brief TODO
 * @param cm_ctx
 * @return
 */
static int
cm_out_msg_queue_init(cm_ctx_t *cm_ctx)
{
    int rc = -1;

    CHECK_NULL_ARG(cm_ctx);

    rc = pipe(cm_ctx->out_msg_fds);
    if (-1 == rc) {
        SR_LOG_ERR("Pipe create error: %s", strerror(errno));
        return SR_ERR_INIT_FAILED;
    }

    return SR_ERR_OK;
}

/**
 * TODO
 * @param cm_ctx
 */
static void
cm_out_msg_queue_cleanup(cm_ctx_t *cm_ctx)
{
    if (NULL != cm_ctx) {
        close(cm_ctx->out_msg_fds[0]);
        close(cm_ctx->out_msg_fds[1]);
    }
}

static int
cm_poll_init(cm_ctx_t *cm_ctx)
{
    CHECK_NULL_ARG(cm_ctx);

    /* initialize the array */
    memset(cm_ctx->poll_fds, 0 , sizeof(cm_ctx->poll_fds));

    /* poll on server listen socket */
    cm_ctx->poll_fds[0].fd = cm_ctx->listen_socket_fd;
    cm_ctx->poll_fds[0].events = POLLIN;

    /* poll on msg queue pipe */
    cm_ctx->poll_fds[1].fd = cm_ctx->out_msg_fds[0];
    cm_ctx->poll_fds[1].events = POLLIN;

    cm_ctx->poll_fd_cnt = 2;
    return SR_ERR_OK;
}

/**
 * @brief Accept new connections to the server and start polling on new
 * client file descriptors.
 */
static int
cm_server_accept(cm_ctx_t *cm_ctx)
{
    int clnt_fd = -1;

    do {
        clnt_fd = accept(cm_ctx->listen_socket_fd, NULL, NULL);
        if (clnt_fd > 0) {
            /* add the new connection to polled fds */
            SR_LOG_DBG("New client connection on fd %d", clnt_fd);
            if (cm_ctx->poll_fd_cnt >= CM_POLL_MAX_FD_CNT) {
                SR_LOG_ERR_MSG("Maximum number of file descriptors reached, "
                        "cannot accept any more connections.");
                return SR_ERR_INTERNAL;
            }
            cm_ctx->poll_fds[cm_ctx->poll_fd_cnt].fd = clnt_fd;
            cm_ctx->poll_fds[cm_ctx->poll_fd_cnt].events = POLLIN;
            cm_ctx->poll_fd_cnt += 1;
        } else {
            if (EWOULDBLOCK == errno || EAGAIN == errno) {
                /* no more connections to accept */
                break;
            } else {
                /* error by accept - only log the error and skip it */
                SR_LOG_ERR("Error by accepting a new connection: %s", strerror(errno));
                continue;
            }
        }
    } while (-1 != clnt_fd); /* accept returns -1 when there are no more connections to accept */

    return SR_ERR_OK;
}

static int
cm_out_msg_queue_dispatch(const cm_ctx_t *cm_ctx)
{
    SR_LOG_DBG_MSG("out msg queue dispatch");

    return SR_ERR_OK;
}

static int
cm_conn_read(const cm_ctx_t *cm_ctx, const int fd)
{
    SR_LOG_DBG("fd %d readable", fd);

    return SR_ERR_OK;
}

static int
cm_conn_write(const cm_ctx_t *cm_ctx, const int fd)
{
    SR_LOG_DBG("fd %d writeable", fd);

    /* check for server_socket_fd and out_msg_fds[0] */

    return SR_ERR_OK;
}

static int
cm_poll_loop(cm_ctx_t *cm_ctx)
{
    int events_cnt = 0, curr_fd_cnt = 0, events_processed = 0, i = 0;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(cm_ctx);

    do {
        events_cnt = poll(cm_ctx->poll_fds, cm_ctx->poll_fd_cnt, CM_POLL_TIMEOUT);
        if (-1 == events_cnt) {
            /* error */
        } else if (0 == events_cnt) {
            /* timeout */
        } else {
            /* event on some of the fds */
            curr_fd_cnt = cm_ctx->poll_fd_cnt;
            events_processed = 0;

            for (i = 0 ; i < curr_fd_cnt; i++) {
                if (0 == cm_ctx->poll_fds[i].revents) {
                    /* no events on this fd */
                    continue;
                } else {
                    events_processed += 1;
                }
                if (cm_ctx->poll_fds[i].revents & POLLIN) {
                    /* data ready to be read */
                    if (cm_ctx->poll_fds[i].fd == cm_ctx->listen_socket_fd) {
                        /* new connection */
                        rc = cm_server_accept(cm_ctx);
                    } else if (cm_ctx->poll_fds[i].fd == cm_ctx->out_msg_fds[0]) {
                        /* new msg in the outgoing queue */
                        rc = cm_out_msg_queue_dispatch(cm_ctx);
                    } else {
                        /* new data from some connection */
                        rc = cm_conn_read(cm_ctx, cm_ctx->poll_fds[i].fd);
                    }
                }
                if (cm_ctx->poll_fds[i].revents & POLLOUT) {
                    /* ready to write to some connection */
                    rc = cm_conn_write(cm_ctx, cm_ctx->poll_fds[i].fd);
                }
                if (events_processed == events_cnt) {
                    /* all fds with events processed */
                    break;
                }
            }

            /* TODO: if any of the connection has closed, we need to sqeeze the array */
        }
    } while (1);

    return rc;
}

int
cm_start(const char *socket_path, cm_ctx_t **cm_ctx_p)
{
    cm_ctx_t *ctx = NULL;
    int rc = SR_ERR_OK;

    ctx = calloc(1, sizeof(*ctx));
    if (NULL == ctx) {
        SR_LOG_ERR_MSG("Cannot allocate memory for Connection Manager.");
        rc = SR_ERR_NOMEM;
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

    rc = cm_poll_init(ctx);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot initialize poll structure.");
        goto cleanup;
    }

    rc = cm_poll_loop(ctx);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Error by processing in the event loop occured.");
        goto cleanup;
    }

    *cm_ctx_p = ctx;
    return SR_ERR_OK;

cleanup:
    cm_server_cleanup(ctx);
    cm_out_msg_queue_cleanup(ctx);
    return rc;
}
