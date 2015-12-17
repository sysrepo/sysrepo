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
#include <fcntl.h>
#include <sys/poll.h>
#include <sys/select.h>
#include <pthread.h>
#include <signal.h>

#include "sr_common.h"
#include "session_manager.h"
#include "connection_manager.h"

#define CM_SELECT_TIMEOUT (10) /**< Timeout used for poll calls (in seconds) */

#define CM_SIG_STOP (SIGRTMIN + 8)  /**< signal used to notify the thread with event loop about stop request */

#define PIPE_READ 0
#define PIPE_WRITE 1

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

    pthread_t event_loop_thread;

    fd_set select_read_fds;
    fd_set select_write_fds;
    int select_fd_max;
} cm_ctx_t;

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
 * @brief TODO
 *
 * @param cm_ctx
 * @param socket_path
 * @return
 */
static int
cm_server_init(cm_ctx_t *cm_ctx, const char *socket_path)
{
    int fd = -1;
    int rc = SR_ERR_OK;
    struct sockaddr_un addr;

    CHECK_NULL_ARG2(cm_ctx, socket_path);

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
 * @brief TODO
 * @param cm_ctx
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
 * @brief TODO
 * @param cm_ctx
 * @return
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
 * TODO
 * @param cm_ctx
 */
static void
cm_out_msg_queue_cleanup(cm_ctx_t *cm_ctx)
{
    if (NULL != cm_ctx) {
        close(cm_ctx->out_msg_fds[PIPE_READ]);
        close(cm_ctx->out_msg_fds[PIPE_WRITE]);
    }
}

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

    /* select on msg queue pipe */
    FD_SET(cm_ctx->out_msg_fds[PIPE_READ], &cm_ctx->select_read_fds);
    if (cm_ctx->out_msg_fds[PIPE_READ] > cm_ctx->select_fd_max) {
        cm_ctx->select_fd_max = cm_ctx->out_msg_fds[PIPE_READ];
    }

    return SR_ERR_OK;
}

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
 * @brief Accept new connections to the server and start polling on new
 * client file descriptors.
 */
static int
cm_server_accept(cm_ctx_t *cm_ctx)
{
    int clnt_fd = -1;
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
                continue; /* let's try next one */
            }
            rc = cm_fd_set_nonblock(clnt_fd);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Cannot set fd=%d to nonblocking mode.", clnt_fd);
                close(clnt_fd);
                continue; /* let's try next one */
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

static int
cm_out_msg_queue_dispatch(const cm_ctx_t *cm_ctx)
{
    CHECK_NULL_ARG(cm_ctx);

    SR_LOG_DBG_MSG("out msg queue dispatch");

    return SR_ERR_OK;
}

static int
cm_conn_read(cm_ctx_t *cm_ctx, int fd)
{
    int bytes = 0;
    bool close_connection = false;
    char buffer[80]; // TODO temporary

    CHECK_NULL_ARG(cm_ctx);

    SR_LOG_DBG("fd %d readable", fd);

    do {
        bytes = recv(fd, buffer, sizeof(buffer), 0);
        if (bytes > 0) {
            /* recieved "bytes" bytes of data */
            SR_LOG_DBG("%d bytes of data recieved on fd %d : %s", bytes, fd, buffer);
        } else if (0 == bytes) {
            /* connection closed by the other side */
            SR_LOG_DBG("Peer on fd %d disconnected.", fd);
            close_connection = true;
        } else {
            if ((EWOULDBLOCK == errno) || (EAGAIN == errno)) {
                /* no more data to be read */
                SR_LOG_DBG("fd %d would block", fd);
                break;
            } else {
                /* error by reading - close the connection due to an error */
                SR_LOG_ERR("Error by reading data on fd %d: %s.", fd, strerror(errno));
                close_connection = true;
                break;
            }
        }
    } while (bytes > 0); /* recv returns -1 when there is no more data to be read */

    if (close_connection) {
        close(fd);
        FD_CLR(fd, &cm_ctx->select_read_fds);
        FD_CLR(fd, &cm_ctx->select_write_fds);
    }

    return SR_ERR_OK;
}

static int
cm_conn_write(const cm_ctx_t *cm_ctx, int fd)
{
    CHECK_NULL_ARG(cm_ctx);

    SR_LOG_DBG("fd %d writeable", fd);

    /* check for server_socket_fd and out_msg_fds[PIPE_READ] */

    return SR_ERR_OK;
}

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

static void
cm_sig_stop_handle(int sig)
{
    stop_requested = 1;
}

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
    cm_select_cleanup(cm_ctx);
    cm_server_cleanup(cm_ctx);
    cm_out_msg_queue_cleanup(cm_ctx);
    free(cm_ctx);
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
