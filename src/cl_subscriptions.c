/**
 * @file cl_subscriptions.c
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <ev.h>

#include "sr_common.h"

#define CL_SUBSCRIPTIONS_PATH_PREFIX "/tmp/sysrepo-subscriptions"

typedef struct cl_sm_ctx_s {
    char *socket_path;
    int listen_socket_fd;

    pthread_t event_loop_thread;

    /** Event loop context. */
    struct ev_loop *event_loop;
    /** Watcher for events on server unix-domain socket. */
    ev_io server_watcher;
    /** Watcher for stop request events. */
    ev_async stop_watcher;
} cl_sm_ctx_t;

static int
cl_sm_server_init(cl_sm_ctx_t *sm_ctx)
{
    int path_len = 0, fd = -1;
    int rc = SR_ERR_OK;
    struct sockaddr_un addr;

    /* generate socket path */
    path_len = snprintf(NULL, 0, "%s-%d.sock", CL_SUBSCRIPTIONS_PATH_PREFIX, getpid());
    sm_ctx->socket_path = calloc(path_len, sizeof(*sm_ctx->socket_path));
    if (NULL == sm_ctx->socket_path) {
        SR_LOG_ERR_MSG("Unable to allocate socket path string.");
        return SR_ERR_NOMEM;
    }
    snprintf(sm_ctx->socket_path, path_len, "%s-%d.sock", CL_SUBSCRIPTIONS_PATH_PREFIX, getpid());
    unlink(sm_ctx->socket_path);

    SR_LOG_DBG("Initializing sysrepo subscription server at socket=%s", sm_ctx->socket_path);

    /* create listening socket */
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (-1 == fd){
        SR_LOG_ERR("Socket create error: %s", strerror(errno));
        rc = SR_ERR_INIT_FAILED;
        goto cleanup;
    }

    /* set socket to nonblocking mode */
    rc = sr_fd_set_nonblock(fd);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot set socket to nonblocking mode.");
        rc = SR_ERR_INIT_FAILED;
        goto cleanup;
    }

    /* bind and listen */
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sm_ctx->socket_path, sizeof(addr.sun_path)-1);

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

    sm_ctx->listen_socket_fd = fd;
    return SR_ERR_OK;

cleanup:
    if (-1 != fd) {
        close(fd);
    }
    if (NULL != sm_ctx->socket_path) {
        unlink(sm_ctx->socket_path);
        free(sm_ctx->socket_path);
        sm_ctx->socket_path = NULL;
    }
    return rc;
}

static void
cl_sm_server_cleanup(cl_sm_ctx_t *sm_ctx)
{
    CHECK_NULL_ARG_VOID(sm_ctx);

    if (-1 != sm_ctx->listen_socket_fd) {
        close(sm_ctx->listen_socket_fd);
        sm_ctx->listen_socket_fd = -1;
    }
    if (NULL != sm_ctx->socket_path) {
        unlink(sm_ctx->socket_path);
        free(sm_ctx->socket_path);
        sm_ctx->socket_path = NULL;
    }
}

static int
cl_sm_fd_read_data(cl_sm_ctx_t *sm_ctx)
{
    CHECK_NULL_ARG(sm_ctx);

    // TODO: read data

    return SR_ERR_OK;
}

static void
cl_sm_fd_read_cb(struct ev_loop *loop, ev_io *w, int revents)
{
    cl_sm_ctx_t *sm_ctx = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG_VOID2(w, w->data);
    sm_ctx = (cl_sm_ctx_t*)w->data;

    SR_LOG_DBG("fd %d readable", w->fd);

    rc = cl_sm_fd_read_data(sm_ctx);

    if (SR_ERR_OK != rc) {
        ev_io_stop(sm_ctx->event_loop, w);
    }
}

static int
cl_sm_fd_watcher_init(cl_sm_ctx_t *sm_ctx, int fd)
{
    CHECK_NULL_ARG(sm_ctx);

    ev_io fd_read_watcher = { 0, };

    ev_io_init(&fd_read_watcher, cl_sm_fd_read_cb, fd, EV_READ);
    fd_read_watcher.data = (void*)sm_ctx;
    ev_io_start(sm_ctx->event_loop, &fd_read_watcher);

    return SR_ERR_OK;
}

static void
cl_sm_server_watcher_cb(struct ev_loop *loop, ev_io *w, int revents)
{
    cl_sm_ctx_t *sm_ctx = NULL;
    int clnt_fd = -1;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG_VOID2(w, w->data);
    sm_ctx = (cl_sm_ctx_t*)w->data;

    do {
        clnt_fd = accept(sm_ctx->listen_socket_fd, NULL, NULL);
        if (-1 != clnt_fd) {
            /* accepted the new connection */
            SR_LOG_DBG("New connection on fd %d", clnt_fd);

            /* set to nonblocking mode */
            rc = sr_fd_set_nonblock(clnt_fd);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Cannot set fd=%d to nonblocking mode.", clnt_fd);
                close(clnt_fd);
                continue;
            }
            /* start watching this fd */
            rc = cl_sm_fd_watcher_init(sm_ctx, clnt_fd);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Cannot initialize watcher for fd=%d.", clnt_fd);
                close(clnt_fd);
                continue;
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
    } while (-1 != clnt_fd); /* accept returns -1 when there are no more connections to accept */
}

static void
cl_sm_stop_cb(struct ev_loop *loop, ev_async *w, int revents)
{
    cl_sm_ctx_t *sm_ctx = NULL;

    CHECK_NULL_ARG_VOID3(loop, w, w->data);
    sm_ctx = (cl_sm_ctx_t*)w->data;

    SR_LOG_DBG_MSG("Event loop stop requested.");

    ev_break(sm_ctx->event_loop, EVBREAK_ALL);
}

static void *
cl_sm_event_loop_threaded(void *sm_ctx_p)
{
    if (NULL == sm_ctx_p) {
        return NULL;
    }

    cl_sm_ctx_t *sm_ctx = (cl_sm_ctx_t*)sm_ctx_p;

    ev_run(sm_ctx->event_loop, 0);

    return NULL;
}

int
cl_sm_init(cl_sm_ctx_t **sm_ctx_p)
{
    cl_sm_ctx_t *ctx = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(sm_ctx_p);

    /* allocate the context */
    ctx = calloc(1, sizeof(*ctx));
    if (NULL == ctx) {
        SR_LOG_ERR_MSG("Could not allocate Subscription Manger context");
        return SR_ERR_NOMEM;
    }

    /* initialize unix-domain server */
    rc = cl_sm_server_init(ctx);
    if (SR_ERR_OK != rc) {
        return rc;
    }

    /* initialize event loop */
    /* According to our measurements, EPOLL backend is significantly slower for
     * fewer file descriptors, so we are disabling it for now. */
    ctx->event_loop = ev_loop_new((EVBACKEND_ALL ^ EVBACKEND_EPOLL) | EVFLAG_NOENV);

    /* initialize event watcher for unix-domain server socket */
    ev_io_init(&ctx->server_watcher, cl_sm_server_watcher_cb, ctx->listen_socket_fd, EV_READ);
    ctx->server_watcher.data = (void*)ctx;
    ev_io_start(ctx->event_loop, &ctx->server_watcher);

    /* initialize event watcher for async stop requests */
    ev_async_init(&ctx->stop_watcher, cl_sm_stop_cb);
    ctx->stop_watcher.data = (void*)ctx;
    ev_async_start(ctx->event_loop, &ctx->stop_watcher);

    rc = pthread_create(&ctx->event_loop_thread, NULL, cl_sm_event_loop_threaded, ctx);
    if (0 != rc) {
        SR_LOG_ERR("Error by creating a new thread: %s", strerror(errno));
        rc = SR_ERR_INTERNAL;
    }

    *sm_ctx_p = ctx;
    return rc;
}

void
cl_sm_cleanup(cl_sm_ctx_t *sm_ctx)
{
    CHECK_NULL_ARG_VOID(sm_ctx);

    ev_async_send(sm_ctx->event_loop, &sm_ctx->stop_watcher);
    pthread_join(sm_ctx->event_loop_thread, NULL);

    ev_loop_destroy(sm_ctx->event_loop);
    cl_sm_server_cleanup(sm_ctx);

    free(sm_ctx);
}
