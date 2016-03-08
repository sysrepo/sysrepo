/**
 * @file cl_subscriptions.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Client Library's Subscription Manager implementation.
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

#define CL_SM_IN_BUFF_MIN_SPACE 512  /**< Minimal empty space in the input buffer. */
#define CL_SM_BUFF_ALLOC_CHUNK 1024  /**< Chunk size for buffer expansions. */

/**
 * @brief Filesystem path prefix for generating temporary socket names used for
 * unix-domain connections between remote sysrepo engines and subscription manager.
 */
#define CL_SUBSCRIPTIONS_PATH_PREFIX "/tmp/sysrepo-subscriptions"

/**
 * @brief Subscription manager context.
 */
typedef struct cl_sm_ctx_s {
    /** Path where unix-domain server for notifications is binded to. */
    char *socket_path;
    /** Socket descriptor used to listen & accept new unix-domain connections. */
    int listen_socket_fd;
    /** Binary tree used for fast connection context lookup by file descriptor. */
    sr_btree_t *fd_btree;
    
    /* Thread where Subscription Manger's event loop runs. */
    pthread_t event_loop_thread;
    /** Event loop context. */
    struct ev_loop *event_loop;
    /** Watcher for events on server unix-domain socket. */
    ev_io server_watcher;
    /** Watcher for stop request events. */
    ev_async stop_watcher;
} cl_sm_ctx_t;

/**
 * @brief Buffer of raw data received from / to be sent to the other side.
 */
typedef struct cl_sm_buffer_s {
    uint8_t *data;  /**< Data of the buffer. */
    size_t size;    /**< Current size of the buffer. */
    size_t start;   /**< Position where the useful data start. */
    size_t pos;     /**< Current position in the buffer. */
} cl_sm_buffer_t;

/**
 * @brief Context of a connection to Subscription Manger's unix-domain server.
 */
typedef struct cl_sm_conn_ctx_s {
    cl_sm_ctx_t *sm_ctx;      /**< Pointer to Subscription Manger context. */
    int fd;                   /**< File descriptor of the connection. */
    cl_sm_buffer_t in_buff;   /**< Input buffer. If not empty, there is some received data to be processed. */
    cl_sm_buffer_t out_buff;  /**< Output buffer. If not empty, there is some data to be sent when receiver is ready. */
    ev_io read_watcher;       /**< Watcher for readable events on connection's socket. */
    ev_io write_watcher;      /**< Watcher for writable events on connection's socket. */
    bool close_requested;     /**< TRUE if connection close has been requested. */
} cl_sm_conn_ctx_t;

/**
 * @brief Compares two connections by file descriptors
 * (used by lookups in fd binary tree).
 */
static int
cl_sm_connection_cmp_fd(const void *a, const void *b)
{
    assert(a);
    assert(b);
    cl_sm_conn_ctx_t *conn_a = (cl_sm_conn_ctx_t*)a;
    cl_sm_conn_ctx_t *conn_b = (cl_sm_conn_ctx_t*)b;

    if (conn_a->fd == conn_b->fd) {
        return 0;
    } else if (conn_a->fd < conn_b->fd) {
        return -1;
    } else {
        return 1;
    }
}

/**
 * @brief Cleans up a connection entry. Releases all resources held in connection
 * context by Subscription Manager (via provided callback).
 * @note Called automatically when a node from fd binary tree is removed
 * (which is also when the tree itself is being destroyed).
 */
static void
cl_sm_connection_cleanup(void *connection_p)
{
    cl_sm_conn_ctx_t *conn = NULL;

    if (NULL != connection_p) {
        conn = (cl_sm_conn_ctx_t *)connection_p;
        free(conn->in_buff.data);
        free(conn->out_buff.data);
        free(conn);
    }
}

/**
 * @brief Adds a new connection context into Subscription Manager.
 */
static int
cl_sm_connection_add(cl_sm_ctx_t *sm_ctx, int fd, cl_sm_conn_ctx_t **conn_p)
{
    cl_sm_conn_ctx_t *conn = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(sm_ctx);

    conn = calloc(1, sizeof(*conn));
    if (NULL == conn) {
        SR_LOG_ERR_MSG("Unable to allocate subscription connection context.");
        return SR_ERR_NOMEM;
    }
    conn->sm_ctx = sm_ctx;
    conn->fd = fd;

    rc = sr_btree_insert(sm_ctx->fd_btree, conn);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot insert new entry into fd binary tree (duplicate fd?).");
        free(conn);
        return SR_ERR_INTERNAL;
    }

    *conn_p = conn;
    return rc;
}

/**
 * @brief Removes the connection context from Subscription Manager.
 */
static int
cl_sm_connection_remove(cl_sm_ctx_t *sm_ctx, cl_sm_conn_ctx_t *conn)
{

    CHECK_NULL_ARG2(sm_ctx, conn);

    if (NULL != conn->read_watcher.data) {
        /* if read watcher was set, stop it */
        ev_io_stop(conn->sm_ctx->event_loop, &conn->read_watcher);
    }

    sr_btree_delete(sm_ctx->fd_btree, conn); /* sm_connection_cleanup auto-invoked */

    return SR_ERR_OK;
}

/**
 * @brief Initializes unix-domain socket server for notification connections.
 */
static int
cl_sm_server_init(cl_sm_ctx_t *sm_ctx)
{
    int path_len = 0, fd = -1;
    int rc = SR_ERR_OK;
    struct sockaddr_un addr;

    /* generate socket path */
    path_len = snprintf(NULL, 0, "%s-%d.sock", CL_SUBSCRIPTIONS_PATH_PREFIX, getpid());
    sm_ctx->socket_path = calloc(path_len + 1, sizeof(*sm_ctx->socket_path));
    if (NULL == sm_ctx->socket_path) {
        SR_LOG_ERR_MSG("Unable to allocate socket path string.");
        return SR_ERR_NOMEM;
    }
    snprintf(sm_ctx->socket_path, path_len + 1, "%s-%d.sock", CL_SUBSCRIPTIONS_PATH_PREFIX, getpid());
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

/**
 * @brief Destroys the unix-domain socket server for notification connections.
 */
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

/**
 * @brief Expands the size of the buffer of given connection.
 */
static int
cl_sm_conn_buffer_expand(const cl_sm_conn_ctx_t *conn, cl_sm_buffer_t *buff, size_t requested_space)
{
    uint8_t *tmp = NULL;

    CHECK_NULL_ARG2(conn, buff);

    if ((buff->size - buff->pos) < requested_space) {
        if (requested_space < CL_SM_BUFF_ALLOC_CHUNK) {
            requested_space = CL_SM_BUFF_ALLOC_CHUNK;
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
 * @brief Processes a message received on the connection.
 */
static int
cl_sm_conn_msg_process(cl_sm_ctx_t *sm_ctx, cl_sm_conn_ctx_t *conn, uint8_t *msg_data, size_t msg_size)
{
    Sr__Msg *msg = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(sm_ctx, conn, msg_data);

    /* unpack the message */
    msg = sr__msg__unpack(NULL, msg_size, msg_data);
    if (NULL == msg) {
        SR_LOG_ERR("Unable to unpack the message (conn=%p).", (void*)conn);
        return SR_ERR_INTERNAL;
    }

    /* NULL check according to message type */
    if (((SR__MSG__MSG_TYPE__REQUEST == msg->type) && (NULL == msg->request)) ||
            ((SR__MSG__MSG_TYPE__RESPONSE == msg->type) && (NULL == msg->response))) {
        SR_LOG_ERR("Message with NULL payload received (conn=%p).", (void*)conn);
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    SR_LOG_INF("NOTIFICATION: %d", msg->notification->subscription_id);
    // TODO: find matching subscription, process the notification / request

    sr__msg__free_unpacked(msg, NULL);

    return rc;

cleanup:
    sr__msg__free_unpacked(msg, NULL);
    return rc;
}

/**
 * @brief Processes the content of input buffer of a connection.
 */
static int
cl_sm_conn_in_buff_process(cl_sm_ctx_t *sm_ctx, cl_sm_conn_ctx_t *conn)
{
    cl_sm_buffer_t *buff = NULL;
    size_t buff_pos = 0, buff_size = 0;
    size_t msg_size = 0;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(sm_ctx, conn);

    buff = &conn->in_buff;
    buff_size = buff->pos;
    buff_pos = 0;

    if (buff_size <= SR_MSG_PREAM_SIZE) {
        return SR_ERR_OK; /* nothing to process so far */
    }

    while ((buff_size - buff_pos) > SR_MSG_PREAM_SIZE) {
        msg_size = sr_buff_to_uint32(buff->data + buff_pos);
        if ((msg_size <= 0) || (msg_size > SR_MAX_MSG_SIZE)) {
            /* invalid message size */
            SR_LOG_ERR("Invalid message size in the message preamble (%zu).", msg_size);
            return SR_ERR_MALFORMED_MSG;
        } else if ((buff_size - buff_pos) >= msg_size) {
            /* the message is completely retrieved, parse it */
            SR_LOG_DBG("New message of size %zu bytes received.", msg_size);
            rc = cl_sm_conn_msg_process(sm_ctx, conn,
                    (buff->data + buff_pos + SR_MSG_PREAM_SIZE), msg_size);
            buff_pos += SR_MSG_PREAM_SIZE + msg_size;
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR_MSG("Error by processing of the message.");
                break;
            }
        } else {
            /* the message is not completely retrieved, end processing */
            SR_LOG_DBG("Partial message of size %zu, received %zu.", msg_size,
                    (buff_size - SR_MSG_PREAM_SIZE - buff_pos));
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
 * @brief Reads data from a notification connection file descriptor and processes them.
 */
static int
cl_sm_fd_read_data(cl_sm_ctx_t *sm_ctx, int fd)
{
    cl_sm_conn_ctx_t tmp_conn = { 0, };
    cl_sm_conn_ctx_t *conn = NULL;
    cl_sm_buffer_t *buff = NULL;
    int bytes = 0;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(sm_ctx);

    /* find matching connection context */
    tmp_conn.fd = fd;
    conn = sr_btree_search(sm_ctx->fd_btree, &tmp_conn);
    if (NULL == conn) {
        SR_LOG_ERR("Invalid file descriptor fd=%d, matching subscription connection not found.", fd);
        return SR_ERR_INVAL_ARG;
    }

    SR_LOG_DBG("fd %d readable", conn->fd);

    buff = &conn->in_buff;
    do {
        /* expand input buffer if needed */
        rc = cl_sm_conn_buffer_expand(conn, buff, CL_SM_IN_BUFF_MIN_SPACE);
        if (SR_ERR_OK != rc) {
            conn->close_requested = true;
            break;
        }
        /* receive data */
        bytes = recv(conn->fd, (buff->data + buff->pos), (buff->size - buff->pos), 0);
        if (bytes > 0) {
            /* Received "bytes" bytes of data */
            SR_LOG_DBG("%d bytes of data received on fd %d", bytes, conn->fd);
            buff->pos += bytes;
        } else if (0 == bytes) {
            /* connection closed by the other side */
            SR_LOG_DBG("Peer on fd %d disconnected.", conn->fd);
            conn->close_requested = true;
            break;
        } else {
            if ((EWOULDBLOCK == errno) || (EAGAIN == errno)) {
                /* no more data to be read */
                SR_LOG_DBG("fd %d would block", conn->fd);
                break;
            } else {
                /* error by reading - close the connection due to an error */
                SR_LOG_ERR("Error by reading data on fd %d: %s.", conn->fd, strerror(errno));
                conn->close_requested = true;
                break;
            }
        }
    } while (bytes > 0); /* recv returns -1 when there is no more data to be read */

    /* process the content of input buffer */
    if (SR_ERR_OK == rc) {
        rc = cl_sm_conn_in_buff_process(sm_ctx, conn);
        if (SR_ERR_OK != rc) {
            SR_LOG_WRN("Error by processing of the input buffer of fd=%d, closing the connection.", conn->fd);
            conn->close_requested = true;
        }
    }

    /* close the connection if requested */
    if (conn->close_requested) {
        SR_LOG_DBG("Closing notification connection on fd=%d.", fd);
        cl_sm_connection_remove(sm_ctx, conn);
        close(fd);
        rc = SR_ERR_DISCONNECT;
    }

    return rc;
}

/**
 * @brief Callback called by the event loop watcher when the file descriptor of
 * a connection is readable (some data has arrived).
 */
static void
cl_sm_fd_read_cb(struct ev_loop *loop, ev_io *w, int revents)
{
    cl_sm_ctx_t *sm_ctx = NULL;

    CHECK_NULL_ARG_VOID2(w, w->data);
    sm_ctx = (cl_sm_ctx_t*)w->data;

    cl_sm_fd_read_data(sm_ctx, w->fd);
}

/**
 * @brief Callback called by the event loop watcher when a new connection is detected
 * on the server socket. Accepts new connections to the server and starts
 * monitoring the new client file descriptors.
 */
static void
cl_sm_server_watcher_cb(struct ev_loop *loop, ev_io *w, int revents)
{
    cl_sm_ctx_t *sm_ctx = NULL;
    cl_sm_conn_ctx_t *conn = NULL;
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
            /* track as new connection */
            rc = cl_sm_connection_add(sm_ctx, clnt_fd, &conn);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Cannot initialize watcher for fd=%d.", clnt_fd);
                close(clnt_fd);
                continue;
            }
            /* start watching this fd */
            ev_io_init(&conn->read_watcher, cl_sm_fd_read_cb, clnt_fd, EV_READ);
            conn->read_watcher.data = (void*)sm_ctx;
            ev_io_start(sm_ctx->event_loop, &conn->read_watcher);
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

/**
 * @brief Callback called by the event loop watcher when an async request to stop the loop is received.
 */
static void
cl_sm_stop_cb(struct ev_loop *loop, ev_async *w, int revents)
{
    cl_sm_ctx_t *sm_ctx = NULL;

    CHECK_NULL_ARG_VOID3(loop, w, w->data);
    sm_ctx = (cl_sm_ctx_t*)w->data;

    SR_LOG_DBG_MSG("Client subscription event loop stop requested.");

    ev_break(sm_ctx->event_loop, EVBREAK_ALL);
}

/**
 * @brief Runs the event loop in a new thread.
 */
static void *
cl_sm_event_loop_threaded(void *sm_ctx_p)
{
    if (NULL == sm_ctx_p) {
        return NULL;
    }

    cl_sm_ctx_t *sm_ctx = (cl_sm_ctx_t*)sm_ctx_p;

    SR_LOG_DBG_MSG("Starting client subscription event loop.");

    ev_run(sm_ctx->event_loop, 0);

    SR_LOG_DBG_MSG("Client subscription event loop finished.");

    return NULL;
}

int
cl_sm_init(cl_sm_ctx_t **sm_ctx_p)
{
    cl_sm_ctx_t *ctx = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(sm_ctx_p);

    SR_LOG_DBG_MSG("Client Subscription Manager init started.");

    /* allocate the context */
    ctx = calloc(1, sizeof(*ctx));
    if (NULL == ctx) {
        SR_LOG_ERR_MSG("Could not allocate Client Subscription Manger context");
        return SR_ERR_NOMEM;
    }

    /* create binary tree for fast connection lookup by fd,
     * with automatic cleanup when the session is removed from tree */
    rc = sr_btree_init(cl_sm_connection_cmp_fd, cl_sm_connection_cleanup, &ctx->fd_btree);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate binary tree for FDd.");
        goto cleanup;
    }

    /* initialize unix-domain server */
    rc = cl_sm_server_init(ctx);
    if (SR_ERR_OK != rc) {
        goto cleanup;
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
        goto cleanup;
    }

    SR_LOG_DBG_MSG("Client Subscription Manager initialized successfully.");

    *sm_ctx_p = ctx;
    return rc;

cleanup:
    if (NULL != ctx) {
        if (NULL != ctx->event_loop) {
            ev_loop_destroy(ctx->event_loop);
        }
        cl_sm_server_cleanup(ctx);
        sr_btree_cleanup(ctx->fd_btree);
        free(ctx);
    }
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

    sr_btree_cleanup(sm_ctx->fd_btree);

    free(sm_ctx);

    SR_LOG_INF_MSG("Client Subscription Manager successfully destroyed.");
}

int
cl_sm_subscribe(cl_sm_ctx_t *sm_ctx, char **destination, uint32_t *subscription_id)
{
    CHECK_NULL_ARG3(sm_ctx, destination, subscription_id);

    *destination = sm_ctx->socket_path;
    *subscription_id = 12345; // TODO assign real subscription id

    return SR_ERR_OK;
}

