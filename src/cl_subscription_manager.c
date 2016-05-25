/**
 * @file cl_subscription_manager.c
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

#include "cl_subscription_manager.h"
#include "sr_common.h"
#include "cl_common.h"

#define CL_SM_IN_BUFF_MIN_SPACE 512  /**< Minimal empty space in the input buffer. */
#define CL_SM_BUFF_ALLOC_CHUNK 1024  /**< Chunk size for buffer expansions. */

#define CL_SM_SUBSCRIPTION_ID_INVALID 0         /**< Invalid value of subscription id. */
#define CL_SM_SUBSCRIPTION_ID_MAX_ATTEMPTS 100  /**< Maximum number of attempts to generate unused random subscription id. */

/**
 * @brief Filesystem path prefix for generating temporary socket names used for
 * unix-domain connections between remote sysrepo engines and subscription manager.
 */
#define CL_SUBSCRIPTIONS_PATH_PREFIX "/tmp/sysrepo-subscriptions"

/**
 * @brief Client Subscription Manager context.
 */
typedef struct cl_sm_ctx_s {
    /** Path where subscriber unix-domain server is binded to. */
    char *socket_path;
    /** Socket descriptor used to listen & accept new unix-domain connections. */
    int listen_socket_fd;
    /** Binary tree used for fast subscriber connection lookup by file descriptor. */
    sr_btree_t *fd_btree;
    
    /** Binary tree of data connections to sysrepo, organized by destination socket address. */
    sr_btree_t *data_connection_btree;

    /** Binary tree used for fast subscription lookup by id. */
    sr_btree_t *subscriptions_btree;
    /** Lock for the subscriptions binary tree. */
    pthread_mutex_t subscriptions_lock;

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
 * @brief Context of a subscriber connection to Subscription Manger's unix-domain server.
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
 * @brief Compares two subscriptions by their id
 * (used by lookups in the binary tree).
 */
static int
cl_sm_subscription_cmp_id(const void *a, const void *b)
{
    assert(a);
    assert(b);
    cl_sm_subscription_ctx_t *subs_a = (cl_sm_subscription_ctx_t*)a;
    cl_sm_subscription_ctx_t *subs_b = (cl_sm_subscription_ctx_t*)b;

    if (subs_a->id == subs_b->id) {
        return 0;
    } else if (subs_a->id < subs_b->id) {
        return -1;
    } else {
        return 1;
    }
}

/**
 * @brief Cleans up a subscription entry.
 * Releases all resources held Subscription Manager.
 * @note Called automatically when a node from the binary tree is removed
 * (which is also when the tree itself is being destroyed).
 */
static void
cl_sm_subscription_cleanup_internal(void *subscription_p)
{
    cl_sm_subscription_ctx_t *subscription = NULL;

    if (NULL != subscription_p) {
        subscription = (cl_sm_subscription_ctx_t *)subscription_p;
        free((void*)subscription->module_name);
        free(subscription);
    }
}

/**
 * @brief Compares two data connections by associated destination addresses
 * (used by lookups in data connection binary tree).
 */
static int
cl_sm_data_connection_cmp_dst(const void *a, const void *b)
{
    assert(a);
    assert(b);
    sr_conn_ctx_t *conn_a = (sr_conn_ctx_t*)a;
    sr_conn_ctx_t *conn_b = (sr_conn_ctx_t*)b;

    int res = 0;

    assert(conn_a->dst_address);
    assert(conn_b->dst_address);

    res = strcmp(conn_a->dst_address, conn_b->dst_address);
    if (res == 0) {
        return 0;
    } else if (res < 0) {
        return -1;
    } else {
        return 1;
    }
}

/**
 * @brief Cleans up a data connection entry.
 * @note Called automatically when a node from the binary tree is removed
 * (which is also when the tree itself is being destroyed).
 */
static void
cl_sm_data_connection_cleanup(void *connection)
{
    cl_connection_cleanup(connection);
}

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
 * context by Subscription Manager.
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
    CHECK_NULL_NOMEM_RETURN(conn);

    conn->sm_ctx = sm_ctx;
    conn->fd = fd;

    rc = sr_btree_insert(sm_ctx->fd_btree, conn);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot insert new entry into fd binary tree (duplicate fd?).");

    *conn_p = conn;
    return rc;

cleanup:
    free(conn);
    return rc;
}

/**
 * @brief Removes the connection context from Subscription Manager.
 */
static int
cl_sm_conn_close(cl_sm_ctx_t *sm_ctx, cl_sm_conn_ctx_t *conn)
{

    CHECK_NULL_ARG2(sm_ctx, conn);

    SR_LOG_DBG("Closing subscriber connection on fd=%d.", conn->fd);

    if (NULL != conn->read_watcher.data) {
        ev_io_stop(conn->sm_ctx->event_loop, &conn->read_watcher);
    }
    if (NULL != conn->write_watcher.data) {
        ev_io_stop(conn->sm_ctx->event_loop, &conn->write_watcher);
    }

    close(conn->fd);

    sr_btree_delete(sm_ctx->fd_btree, conn); /* sm_connection_cleanup auto-invoked */

    return SR_ERR_OK;
}

/**
 * @brief Initializes unix-domain socket server for subscriber connections.
 */
static int
cl_sm_server_init(cl_sm_ctx_t *sm_ctx)
{
    int path_len = 0, fd = -1, fd_tmp = -1, ret = 0;
    int rc = SR_ERR_OK;
    struct sockaddr_un addr;
    mode_t old_umask = 0;

    /* generate socket path */
    path_len = snprintf(NULL, 0, "%s.%d.XXXXXX.sock", CL_SUBSCRIPTIONS_PATH_PREFIX, getpid());
    sm_ctx->socket_path = calloc(path_len + 1, sizeof(*sm_ctx->socket_path));
    CHECK_NULL_NOMEM_RETURN(sm_ctx->socket_path);

    snprintf(sm_ctx->socket_path, path_len + 1, "%s.%d.XXXXXX.sock", CL_SUBSCRIPTIONS_PATH_PREFIX, getpid());
    unlink(sm_ctx->socket_path);
    fd_tmp = mkstemps(sm_ctx->socket_path, 5);
    if (-1 != fd_tmp) {
        close(fd_tmp);
        unlink(sm_ctx->socket_path);
    }

    SR_LOG_DBG("Initializing sysrepo subscription server at socket=%s", sm_ctx->socket_path);

    /* create listening socket */
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (-1 == fd) {
        SR_LOG_ERR("Socket create error: %s", strerror(errno));
        rc = SR_ERR_INIT_FAILED;
        goto cleanup;
    }

    /* set socket to nonblocking mode */
    rc = sr_fd_set_nonblock(fd);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot set socket to nonblocking mode.");

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sm_ctx->socket_path, sizeof(addr.sun_path)-1);

    /* create the unix-domain socket writable to anyone */
    old_umask = umask(0);
    ret = bind(fd, (struct sockaddr*)&addr, sizeof(addr));
    umask(old_umask);
    CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_INIT_FAILED, cleanup, "Socket bind error: %s", strerror(errno));

    ret = listen(fd, SOMAXCONN);
    CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_INIT_FAILED, cleanup, "Socket listen error: %s", strerror(errno));

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
 * @brief Destroys the unix-domain socket server for subscriber connections.
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
        CHECK_NULL_NOMEM_RETURN(tmp);

        buff->data = tmp;
        buff->size += requested_space;
        SR_LOG_DBG("%s buffer for fd=%d expanded to %zu bytes.",
                (&conn->in_buff == buff ? "Input" : "Output"), conn->fd, buff->size);
    }

    return SR_ERR_OK;
}

/**
 * @brief Flush contents of the output buffer of the given connection.
 */
static int
cl_sm_conn_out_buff_flush(cl_sm_ctx_t *sm_ctx, cl_sm_conn_ctx_t *conn)
{
    cl_sm_buffer_t *buff = NULL;
    int written = 0;
    size_t buff_size = 0, buff_pos = 0;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(sm_ctx, conn);

    buff = &conn->out_buff;
    buff_size = buff->pos;
    buff_pos = conn->out_buff.start;

    SR_LOG_DBG("Sending %zu bytes of data.", (buff_size - buff_pos));

    do {
        /* try to send all data */
        written = send(conn->fd, (buff->data + buff_pos), (buff_size - buff_pos), 0);
        if (written > 0) {
            SR_LOG_DBG("%d bytes of data sent.", written);
            buff_pos += written;
        } else {
            if ((EWOULDBLOCK == errno) || (EAGAIN == errno)) {
                /* no more data can be sent now */
                SR_LOG_DBG("fd %d would block", conn->fd);
                /* mark the position where the unsent data start */
                conn->out_buff.start = buff_pos;
                /* monitor fd for writable event */
                ev_io_start(sm_ctx->event_loop, &conn->write_watcher);
                break;
            } else {
                /* error by writing - close the connection due to an error */
                SR_LOG_ERR("Error by writing data to fd %d: %s.", conn->fd, strerror(errno));
                conn->close_requested = true;
                break;
            }
        }
    } while ((buff_pos < buff_size) && (written > 0));

    if (buff_size == buff_pos) {
        /* no more data left in the buffer */
        buff->pos = 0;
        conn->out_buff.start = 0;
    }

    return rc;
}

/**
 * @brief Sends a message to the recipient identified by session context.
 */
static int
cl_sm_msg_send_connection(cl_sm_ctx_t *sm_ctx, cl_sm_conn_ctx_t *conn, Sr__Msg *msg)
{
    cl_sm_buffer_t *buff = NULL;
    size_t msg_size = 0;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(sm_ctx, conn, msg);

    buff = &conn->out_buff;

    /* find out required message size */
    msg_size = sr__msg__get_packed_size(msg);
    if ((msg_size <= 0) || (msg_size > SR_MAX_MSG_SIZE)) {
        SR_LOG_ERR("Unable to send the message of size %zuB.", msg_size);
        return SR_ERR_INTERNAL;
    }

    /* expand the buffer if needed */
    rc = cl_sm_conn_buffer_expand(conn, buff, SR_MSG_PREAM_SIZE + msg_size);

    if (SR_ERR_OK == rc) {
        /* write the pramble */
        sr_uint32_to_buff(msg_size, (buff->data + buff->pos));
        buff->pos += SR_MSG_PREAM_SIZE;

        /* write the message */
        sr__msg__pack(msg, (buff->data + buff->pos));
        buff->pos += msg_size;

        /* flush the buffer */
        rc = cl_sm_conn_out_buff_flush(sm_ctx, conn);
        if ((conn->close_requested) || (SR_ERR_OK != rc)) {
            cl_sm_conn_close(sm_ctx, conn);
        }
    }

    return rc;
}

/**
 * @brief Get (prepare) configuration session that can be used from notification callback.
 */
static int
cl_sm_get_data_session(cl_sm_ctx_t *sm_ctx, cl_sm_subscription_ctx_t *subscription,
        const char *source_address, uint32_t source_pid, sr_session_ctx_t **config_session_p)
{
    sr_conn_ctx_t *connection = NULL;
    sr_conn_ctx_t connection_lookup = { 0, };
    sr_session_ctx_t *session = NULL;
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(sm_ctx, subscription, source_address, config_session_p);

    if ((NULL != subscription->data_session) &&
            (NULL != subscription->data_session->conn_ctx) && (NULL != subscription->data_session->conn_ctx->dst_address) &&
            (0 == strcmp(subscription->data_session->conn_ctx->dst_address, source_address)) &&
            (subscription->data_session->conn_ctx->dst_pid == source_pid)) {
        /* use already existing session stored within the subscription */
        *config_session_p = subscription->data_session;
        return SR_ERR_OK;
    }

    /* find a connection matching with provided address */
    connection_lookup.dst_address = source_address;
    connection = sr_btree_search(sm_ctx->data_connection_btree, &connection_lookup);

    if (NULL != connection && connection->dst_pid != source_pid) {
        /* new PID on the destination address - reconnect */
        SR_LOG_DBG("New PID on the destination address '%s' - reconnect.", source_address);
        sr_btree_delete(sm_ctx->data_connection_btree, connection);
        connection = NULL;
    }

    if (NULL == connection) {
        /* connection not found, create a new one */
        SR_LOG_DBG("Connecting to the notification originator at '%s'.", source_address);
        rc = cl_connection_create(&connection);
        if (SR_ERR_OK == rc) {
            connection->dst_address = strdup(source_address);
            CHECK_NULL_NOMEM_ERROR(connection->dst_address, rc);
            connection->dst_pid = source_pid;
        }
        if (SR_ERR_OK == rc) {
            rc = cl_socket_connect(connection, connection->dst_address);
        }
        if (SR_ERR_OK == rc) {
            rc = sr_btree_insert(sm_ctx->data_connection_btree, connection);
        }
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Unable to connect to the notification originator at '%s'.", source_address);
            cl_connection_cleanup(connection);
            return rc;
        }
    }

    /* try to retrieve the session from the connection */
    if (NULL != connection->session_list) {
        session = connection->session_list->session;
    }
    if (NULL == session) {
        /* session not found, create a new one */
        SR_LOG_DBG("Creating a new data session at '%s'.", source_address);
        rc = cl_session_create(connection, &session);

        /* prepare session_start message */
        rc = sr_gpb_req_alloc(SR__OPERATION__SESSION_START, /* undefined session id */ 0, &msg_req);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Cannot allocate session_start message.");
            cl_session_cleanup(session);
            return rc;
        }
        msg_req->request->session_start_req->options = SR__SESSION_FLAGS__SESS_NOTIFICATION;
        msg_req->request->session_start_req->datastore = SR__DATA_STORE__RUNNING;

        /* send the request and receive the response */
        rc = cl_request_process(session, msg_req, &msg_resp, SR__OPERATION__SESSION_START);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Error by processing of session_start request.");
            sr__msg__free_unpacked(msg_req, NULL);
            cl_session_cleanup(session);
            return rc;
        }

        session->id = msg_resp->response->session_start_resp->session_id;
        sr__msg__free_unpacked(msg_req, NULL);
        sr__msg__free_unpacked(msg_resp, NULL);
    }

    subscription->data_session = session;
    *config_session_p = session;
    return rc;
}

/**
 * @brief Processes an incoming notification message.
 */
static int
cl_sm_notif_process(cl_sm_ctx_t *sm_ctx, Sr__Msg *msg)
{
    cl_sm_subscription_ctx_t *subscription = NULL;
    cl_sm_subscription_ctx_t subscription_lookup = { 0, };
    sr_session_ctx_t *data_session = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(sm_ctx, msg, msg->notification);

    SR_LOG_DBG("Received a notification for subscription id=%"PRIu32" (source address='%s').",
            msg->notification->subscription_id, msg->notification->source_address);

    pthread_mutex_lock(&sm_ctx->subscriptions_lock);

    /* find the subscription according to id */
    subscription_lookup.id = msg->notification->subscription_id;
    subscription = sr_btree_search(sm_ctx->subscriptions_btree, &subscription_lookup);
    if (NULL == subscription) {
        pthread_mutex_unlock(&sm_ctx->subscriptions_lock);
        SR_LOG_ERR("No matching subscription for subscription id=%"PRIu32".", msg->notification->subscription_id);
        return SR_ERR_INVAL_ARG;
    }

    /* validate the message according to the subscription type */
    rc = sr_gpb_msg_validate_notif(msg, subscription->event_type);
    if (SR_ERR_OK != rc) {
        pthread_mutex_unlock(&sm_ctx->subscriptions_lock);
        SR_LOG_ERR("Received notification message is not valid for subscription id=%"PRIu32".", subscription->id);
        return SR_ERR_INVAL_ARG;
    }

    /* get data session that can be used from notification callback */
    if (SR__NOTIFICATION_EVENT__MODULE_CHANGE_EV == msg->notification->event) {
        rc = cl_sm_get_data_session(sm_ctx, subscription, msg->notification->source_address,
                msg->notification->source_pid, &data_session);
        if (SR_ERR_OK != rc) {
            pthread_mutex_unlock(&sm_ctx->subscriptions_lock);
            return SR_ERR_INVAL_ARG;
        }
        rc = sr_session_refresh(data_session);
        if (SR_ERR_OK != rc) {
            pthread_mutex_unlock(&sm_ctx->subscriptions_lock);
            return rc;
        }
    }

    switch (msg->notification->event) {
        case SR__NOTIFICATION_EVENT__MODULE_INSTALL_EV:
            SR_LOG_DBG("Calling module-install callback for subscription id=%"PRIu32".", subscription->id);
            subscription->callback.module_install_cb(
                    msg->notification->module_install_notif->module_name,
                    msg->notification->module_install_notif->revision,
                    msg->notification->module_install_notif->installed,
                    subscription->private_ctx);
            break;
        case SR__NOTIFICATION_EVENT__FEATURE_ENABLE_EV:
            SR_LOG_DBG("Calling feature-enable callback for subscription id=%"PRIu32".", subscription->id);
            subscription->callback.feature_enable_cb(
                    msg->notification->feature_enable_notif->module_name,
                    msg->notification->feature_enable_notif->feature_name,
                    msg->notification->feature_enable_notif->enabled,
                    subscription->private_ctx);
            break;
        case SR__NOTIFICATION_EVENT__MODULE_CHANGE_EV:
            SR_LOG_DBG("Calling module-change callback for subscription id=%"PRIu32".", subscription->id);
            subscription->callback.module_change_cb(
                    data_session,
                    msg->notification->module_change_notif->module_name,
                    subscription->private_ctx);
            break;
        case SR__NOTIFICATION_EVENT__HELLO_EV:
            SR_LOG_DBG("HELLO notification received on subscription id=%"PRIu32".", subscription->id);
            break;
        default:
            SR_LOG_ERR("Unknown notification event received on subscription id=%"PRIu32".", subscription->id);
            rc = SR_ERR_INVAL_ARG;
    }

    pthread_mutex_unlock(&sm_ctx->subscriptions_lock);

    return rc;
}

/**
 * @brief Processes an incoming RPC message.
 */
static int
cl_sm_rpc_process(cl_sm_ctx_t *sm_ctx, cl_sm_conn_ctx_t *conn, Sr__Msg *msg)
{
    cl_sm_subscription_ctx_t *subscription = NULL;
    cl_sm_subscription_ctx_t subscription_lookup = { 0, };
    Sr__Msg *resp = NULL;
    sr_val_t *input = NULL, *output = NULL;
    size_t input_cnt = 0, output_cnt = 0;
    int rc = SR_ERR_OK, rpc_rc = SR_ERR_OK;

    CHECK_NULL_ARG4(sm_ctx, msg, msg->request, msg->request->rpc_req);

    SR_LOG_DBG("Received a RPC request for subscription id=%"PRIu32".", msg->request->rpc_req->subscription_id);

    /* copy input values from GPB */
    rc = sr_values_gpb_to_sr(msg->request->rpc_req->input, msg->request->rpc_req->n_input, &input, &input_cnt);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by copying RPC input arguments from GPB.");

    pthread_mutex_lock(&sm_ctx->subscriptions_lock);

    /* find the subscription according to id */
    subscription_lookup.id = msg->request->rpc_req->subscription_id;
    subscription = sr_btree_search(sm_ctx->subscriptions_btree, &subscription_lookup);
    if (NULL == subscription) {
        pthread_mutex_unlock(&sm_ctx->subscriptions_lock);
        SR_LOG_ERR("No matching subscription for subscription id=%"PRIu32".", msg->request->rpc_req->subscription_id);
        goto cleanup;
    }

    SR_LOG_DBG("Calling RPC callback for subscription id=%"PRIu32".", subscription->id);

    rpc_rc = subscription->callback.rpc_cb(
            msg->request->rpc_req->xpath,
            input, input_cnt,
            &output, &output_cnt,
            subscription->private_ctx);

    pthread_mutex_unlock(&sm_ctx->subscriptions_lock);

    /* allocate the response and send it */
    rc = sr_gpb_resp_alloc(SR__OPERATION__RPC, msg->session_id, &resp);
    CHECK_RC_MSG_RETURN(rc, "Allocation of RPC response failed.");

    resp->response->result = rpc_rc;
    resp->response->rpc_resp->xpath = strdup(msg->request->rpc_req->xpath);
    CHECK_NULL_NOMEM_GOTO(resp->response->rpc_resp->xpath, rc, cleanup);

    /* copy output values to GPB */
    if (SR_ERR_OK == rpc_rc) {
        rc = sr_values_sr_to_gpb(output, output_cnt, &resp->response->rpc_resp->output, &resp->response->rpc_resp->n_output);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Error by copying RPC output arguments to GPB.");
    }

    /* send the response */
    rc = cl_sm_msg_send_connection(sm_ctx, conn, resp);

cleanup:
    sr_free_values(input, input_cnt);
    sr_free_values(output, output_cnt);
    if (NULL != resp) {
        sr__msg__free_unpacked(resp, NULL);
    }
    return rc;
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

    /* check the message */
    if (SR__MSG__MSG_TYPE__NOTIFICATION == msg->type) {
        /* notification */
        rc = cl_sm_notif_process(sm_ctx, msg);
    } else if ((SR__MSG__MSG_TYPE__REQUEST == msg->type) && (SR__OPERATION__RPC == msg->request->operation)) {
        /* RPC request */
        rc = cl_sm_rpc_process(sm_ctx, conn, msg);
    } else {
        SR_LOG_ERR("Invalid or unexpected message received (conn=%p).", (void*)conn);
        rc = SR_ERR_INVAL_ARG;
    }

    /* release the message */
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
 * @brief Reads data from a subscriber connection file descriptor and processes them.
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
        SR_LOG_ERR("Invalid file descriptor fd=%d, matching subscriber connection not found.", fd);
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
        cl_sm_conn_close(sm_ctx, conn);
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
 * @brief Callback called by the event loop watcher when the file descriptor of
 * a connection is writable (without blocking).
 */
static void
cl_sm_conn_write_cb(struct ev_loop *loop, ev_io *w, int revents)
{
    cl_sm_conn_ctx_t *conn = NULL;
    cl_sm_ctx_t *sm_ctx = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG_VOID2(w, w->data);
    conn = (cl_sm_conn_ctx_t*)w->data;

    CHECK_NULL_ARG_VOID2(conn, conn->sm_ctx);
    sm_ctx = conn->sm_ctx;

    SR_LOG_DBG("fd %d writeable", conn->fd);

    ev_io_stop(sm_ctx->event_loop, &conn->write_watcher);

    /* flush the output buffer */
    rc = cl_sm_conn_out_buff_flush(sm_ctx, conn);

    /* close the connection if requested */
    if ((conn->close_requested) || (SR_ERR_OK != rc)) {
        cl_sm_conn_close(sm_ctx, conn);
    }
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

            ev_io_init(&conn->write_watcher, cl_sm_conn_write_cb, conn->fd, EV_WRITE);
            conn->write_watcher.data = (void*)conn;
            /* do not start write watcher - will be started when needed */
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
    int ret = 0, rc = SR_ERR_OK;

    CHECK_NULL_ARG(sm_ctx_p);

    SR_LOG_DBG_MSG("Client Subscription Manager init started.");

    /* allocate the context */
    ctx = calloc(1, sizeof(*ctx));
    CHECK_NULL_NOMEM_RETURN(ctx);

    /* create binary tree for fast connection lookup by fd,
     * with automatic cleanup when the session is removed from tree */
    rc = sr_btree_init(cl_sm_connection_cmp_fd, cl_sm_connection_cleanup, &ctx->fd_btree);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate binary tree for FDd.");

    /* create binary tree for fast subscription lookup by id */
    rc = sr_btree_init(cl_sm_subscription_cmp_id, cl_sm_subscription_cleanup_internal, &ctx->subscriptions_btree);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate binary tree for subscription IDs.");

    /* create binary tree for fast data connection lookup by destination (socket) string */
    rc = sr_btree_init(cl_sm_data_connection_cmp_dst, cl_sm_data_connection_cleanup, &ctx->data_connection_btree);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate binary tree for data connections.");

    /* initialize the mutex for subscriptions */
    ret = pthread_mutex_init(&ctx->subscriptions_lock, NULL);
    CHECK_ZERO_MSG_GOTO(ret, rc, SR_ERR_INIT_FAILED, cleanup, "Cannot initialize subscriptions btree mutex.");

    /* initialize unix-domain server */
    rc = cl_sm_server_init(ctx);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot initialize subscription unix-domain server.");

    srand(time(NULL));

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

    ret = pthread_create(&ctx->event_loop_thread, NULL, cl_sm_event_loop_threaded, ctx);
    CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_INIT_FAILED, cleanup, "Error by creating a new thread: %s", strerror(errno));

    SR_LOG_DBG_MSG("Client Subscription Manager initialized successfully.");

    *sm_ctx_p = ctx;
    return rc;

cleanup:
    if (NULL != ctx) {
        if (NULL != ctx->event_loop) {
            ev_loop_destroy(ctx->event_loop);
        }
        cl_sm_server_cleanup(ctx);
        pthread_mutex_destroy(&ctx->subscriptions_lock);
        sr_btree_cleanup(ctx->data_connection_btree);
        sr_btree_cleanup(ctx->subscriptions_btree);
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

    pthread_mutex_destroy(&sm_ctx->subscriptions_lock);
    sr_btree_cleanup(sm_ctx->data_connection_btree);
    sr_btree_cleanup(sm_ctx->subscriptions_btree);
    sr_btree_cleanup(sm_ctx->fd_btree);

    free(sm_ctx);

    SR_LOG_INF_MSG("Client Subscription Manager successfully destroyed.");
}

int
cl_sm_subscription_init(cl_sm_ctx_t *sm_ctx, cl_sm_subscription_ctx_t **subscription_p)
{
    cl_sm_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(sm_ctx, subscription_p);

    subscription = calloc(1, sizeof(*subscription));
    CHECK_NULL_NOMEM_RETURN(subscription);

    subscription->sm_ctx = sm_ctx;

    pthread_mutex_lock(&sm_ctx->subscriptions_lock);

    /* generate unused random subscription id */
    size_t attempts = 0;
    do {
        subscription->id = rand();
        if (NULL != sr_btree_search(sm_ctx->subscriptions_btree, subscription)) {
            subscription->id = CL_SM_SUBSCRIPTION_ID_INVALID;
        }
        if (++attempts > CL_SM_SUBSCRIPTION_ID_MAX_ATTEMPTS) {
            SR_LOG_ERR_MSG("Unable to generate an unique subscription id.");
            rc = SR_ERR_INTERNAL;
            pthread_mutex_unlock(&sm_ctx->subscriptions_lock);
            goto cleanup;
        }
    } while (CL_SM_SUBSCRIPTION_ID_INVALID == subscription->id);

    /* insert the subscription into the binary tree */
    rc = sr_btree_insert(sm_ctx->subscriptions_btree, subscription);

    pthread_mutex_unlock(&sm_ctx->subscriptions_lock);

    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot insert new entry into subscription binary tree (duplicate id?).");

    subscription->delivery_address = sm_ctx->socket_path;
    *subscription_p = subscription;
    return SR_ERR_OK;

cleanup:
    cl_sm_subscription_cleanup_internal(subscription);
    return rc;
}

void
cl_sm_subscription_cleanup(cl_sm_subscription_ctx_t *subscription)
{
    cl_sm_ctx_t *sm_ctx = NULL;

    CHECK_NULL_ARG_VOID2(subscription, subscription->sm_ctx);

    sm_ctx = subscription->sm_ctx;

    pthread_mutex_lock(&sm_ctx->subscriptions_lock);

    /* cl_sm_subscription_cleanup_internal will be auto-invoked */
    sr_btree_delete(sm_ctx->subscriptions_btree, subscription);

    pthread_mutex_unlock(&sm_ctx->subscriptions_lock);
}
