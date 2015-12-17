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
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <pthread.h>
#include <signal.h>

#include "sr_common.h"
#include "session_manager.h"
#include "connection_manager.h"

#define CM_FD_INVALID -1  /**< Invalid file descriptor. */
#define CM_POLL_MAX_FD_CNT 200 /**< Maximum number of file descriptors that CM is able to handle. */
#define CM_POLL_TIMEOUT (10 * 1000) /**< Timeout used for poll calls (in milliseconds) */

#define CM_SIG_STOP (SIGRTMIN + 8)  /**< signal used to notify the thread with event loop about stop request */

/**
 * Global variable used to request stop of the event loop in all instances of CM,
 * it should be set ONLY by signal handler functions within the same thread as the loop.
 */
static volatile sig_atomic_t stop_requested = 0;

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

    pthread_t event_loop_thread;
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
    memset(cm_ctx->poll_fds, 0, sizeof(cm_ctx->poll_fds));

    /* poll on server listen socket */
    cm_ctx->poll_fds[0].fd = cm_ctx->listen_socket_fd;
    cm_ctx->poll_fds[0].events = POLLIN;

    /* poll on msg queue pipe */
    cm_ctx->poll_fds[1].fd = cm_ctx->out_msg_fds[0];
    cm_ctx->poll_fds[1].events = POLLIN;

    cm_ctx->poll_fd_cnt = 2;

    return SR_ERR_OK;
}

static void
cm_poll_cleanup(cm_ctx_t *cm_ctx)
{
    int i = 0;
    if (NULL != cm_ctx) {
        for (i = 0; i < cm_ctx->poll_fd_cnt; i++) {
            if (CM_FD_INVALID != cm_ctx->poll_fds[i].fd) {
                close(cm_ctx->poll_fds[i].fd);
                cm_ctx->poll_fds[i].fd = CM_FD_INVALID;
            }
        }
    }
}

/**
 * @brief Accept new connections to the server and start polling on new
 * client file descriptors.
 */
static int
cm_server_accept(cm_ctx_t *cm_ctx)
{
    int clnt_fd = CM_FD_INVALID;

    CHECK_NULL_ARG(cm_ctx);

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
    } while (clnt_fd > 0); /* accept returns -1 when there are no more connections to accept */

    return SR_ERR_OK;
}

static int
cm_out_msg_queue_dispatch(const cm_ctx_t *cm_ctx)
{
    CHECK_NULL_ARG(cm_ctx);

    SR_LOG_DBG_MSG("out msg queue dispatch");

    return SR_ERR_OK;
}

static int
cm_conn_read(const cm_ctx_t *cm_ctx, int *fd)
{
    int bytes = 0;
    bool close_connection = false;
    char buffer[80]; // TODO temporary

    CHECK_NULL_ARG2(cm_ctx, fd);

    SR_LOG_DBG("fd %d readable", *fd);

    do {
        bytes = recv(*fd, buffer, sizeof(buffer), 0);
        if (bytes > 0) {
            /* recieved "bytes" bytes of data */
            SR_LOG_DBG("%d bytes of data recieved on fd %d.", bytes, *fd);
        } else if (0 == bytes) {
            /* connection closed by the other side */
            SR_LOG_DBG("Peer on fd %d disconnected.", *fd);
            close_connection = true;
        } else {
            if (EWOULDBLOCK == errno || EAGAIN == errno) {
                /* no more data to be read */
                break;
            } else {
                /* error by reading - close the connection due to an error */
                SR_LOG_ERR("Error by reading data on fd %d: %s.", *fd, strerror(errno));
                close_connection = true;
            }
        }
    } while (bytes > 0); /* recv returns -1 when there is no more data to be read */

    if (close_connection) {
        close(*fd);
        *fd = CM_FD_INVALID;
    }

    return SR_ERR_OK;
}

static int
cm_conn_write(const cm_ctx_t *cm_ctx, int *fd)
{
    CHECK_NULL_ARG2(cm_ctx, fd);

    SR_LOG_DBG("fd %d writeable", *fd);

    /* check for server_socket_fd and out_msg_fds[0] */

    return SR_ERR_OK;
}

static int
cm_poll_fds_compress(cm_ctx_t *cm_ctx)
{
    int i = 0, j = 0;
    struct pollfd *fds = NULL;
    int fd_cnt = 0;

    CHECK_NULL_ARG(cm_ctx);

    SR_LOG_DBG_MSG("Poll FDs compress invoked.");

    fds = cm_ctx->poll_fds;
    fd_cnt = cm_ctx->poll_fd_cnt;

    for (i = 0; i < fd_cnt; i++) {
        if (CM_FD_INVALID == fds[i].fd) {
            for (j = i; j < (fd_cnt - 1); j++) {
                fds[j].fd = fds[j+1].fd;
            }
            i--;
            fd_cnt--;
        }
    }

    cm_ctx->poll_fd_cnt = fd_cnt;
    return SR_ERR_OK;
}

static int
cm_event_loop(cm_ctx_t *cm_ctx)
{
    int events_cnt = 0, events_processed = 0, i = 0;
    bool compress_needed = false;
    struct pollfd *fds = NULL;
    int fd_cnt = 0;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(cm_ctx);

    SR_LOG_DBG_MSG("Starting CM event loop.");

    fds = cm_ctx->poll_fds;

    do {
        fd_cnt = cm_ctx->poll_fd_cnt;
        events_cnt = poll(fds, fd_cnt, CM_POLL_TIMEOUT);

        SR_LOG_DBG("poll unblocked, events_cnt=%d.", events_cnt);

        if (-1 == events_cnt) {
            /* error */
            if (EINTR == errno) {
                SR_LOG_DBG("Event loop interrupted by a signal, "
                        "stop_requested=%d.", stop_requested);
            } else {
                SR_LOG_ERR("Unexpected error by poll: %s.", strerror(errno));
                break;
            }
        } else if (0 == events_cnt) {
            /* timeout */
            SR_LOG_DBG_MSG("poll timeout expired.");
        } else {
            /* event on some of the fds */
            events_processed = 0;
            compress_needed = false;

            for (i = 0 ; i < fd_cnt; i++) {
                if (0 == fds[i].revents) {
                    /* no events on this fd */
                    continue;
                } else {
                    events_processed += 1;
                }
                if (fds[i].revents & POLLIN) {
                    /* data ready to be read */
                    if (fds[i].fd == cm_ctx->listen_socket_fd) {
                        /* new connection */
                        rc = cm_server_accept(cm_ctx);
                    } else if (fds[i].fd == cm_ctx->out_msg_fds[0]) {
                        /* new msg in the outgoing queue */
                        rc = cm_out_msg_queue_dispatch(cm_ctx);
                    } else {
                        /* new data from some connection */
                        rc = cm_conn_read(cm_ctx, &fds[i].fd);
                    }
                }
                if (fds[i].revents & POLLOUT) {
                    /* ready to write to some connection */
                    rc = cm_conn_write(cm_ctx, &cm_ctx->poll_fds[i].fd);
                }
                /* if the peer disconnected in read / write handler, mark it */
                if (CM_FD_INVALID == fds[i].fd) {
                    compress_needed = true;
                }
                /* if all fds with events are processed, stop the iteration */
                if (events_processed == events_cnt) {
                    break;
                }
            }

            /* if some of the connections has closed, we need to compress the fds array */
            if (compress_needed) {
                rc = cm_poll_fds_compress(cm_ctx);
            }
        }
    } while ((SR_ERR_OK == rc) && (0 == stop_requested));

    SR_LOG_DBG_MSG("CM event loop finished.");

    return rc;
}

static void
cm_sig_stop_handle(int sig)
{
    SR_LOG_DBG_MSG("signal is here");
    stop_requested = 1;
}

static void *
cm_event_loop_threaded(void *cm_ctx_p)
{
    cm_ctx_t *cm_ctx = (cm_ctx_t*)cm_ctx_p;
    int rc = SR_ERR_OK;

    struct sigaction act;
    memset (&act, '\0', sizeof(act));
    act.sa_handler = &cm_sig_stop_handle;
    sigaction(CM_SIG_STOP, &act, NULL);

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
    cm_poll_cleanup(cm_ctx);
    cm_server_cleanup(cm_ctx);
    cm_out_msg_queue_cleanup(cm_ctx);
    free(cm_ctx);
}

int
cm_start(cm_ctx_t *cm_ctx)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(cm_ctx);

    stop_requested = 0;

    if (CM_MODE_DAEMON == cm_ctx->mode) {
        /* run the event loop in this thread */
        rc = cm_event_loop(cm_ctx);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Error by processing in the event loop occured.");
        }
//    } else {
//        sigset_t mask, orig_mask;
//        sigemptyset(&mask);
//        sigaddset(&mask, CM_SIG_STOP);
//        sigprocmask(SIG_BLOCK, &mask, &orig_mask);

        /* run the event loop in a new thread */
        rc = pthread_create(&cm_ctx->event_loop_thread, NULL,
                cm_event_loop_threaded, cm_ctx);
        if (0 != rc) {
            SR_LOG_ERR("Error by creating a new thread: %s", strerror(errno));
        }

//        sigprocmask(SIG_SETMASK, &orig_mask, NULL);
    }

    return rc;
}

int
cm_stop(cm_ctx_t *cm_ctx)
{
    CHECK_NULL_ARG(cm_ctx);

    SR_LOG_DBG_MSG("CM stop requested.");

    if (CM_MODE_DAEMON == cm_ctx->mode) {
        /* main thread (with event loop) interrupted by signal, just mark request to stop */
        stop_requested = 1;
    } else {
        /* send a signal to the thread with event loop */
        pthread_kill(cm_ctx->event_loop_thread, CM_SIG_STOP);
        /* block until cleanup is finished */
        pthread_join(cm_ctx->event_loop_thread, NULL);
    }

    return SR_ERR_OK;
}
