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
 * @brief Subscription Manager's unix-domain server context.
 */
typedef struct cl_sm_server_ctx_s {
    cl_sm_ctx_t *sm_ctx;      /**< Client Subscription Manager context associated with this server context. */
    char *module_name;        /**< Name of the YANG module for which this server context is being used. */
    char *socket_path;        /**< Path of the unix-domain server socket used for this server. */
    int listen_socket_fd;     /**< Socket descriptor used to listen & accept new unix-domain connections. */
    ev_io server_watcher;     /**< Watcher for events on the unix-domain socket. */
    bool watcher_started;     /**< TRUE if the watcher has been already started, FALSE otherwise. */
} cl_sm_server_ctx_t;

/**
 * @brief Client Subscription Manager context.
 */
typedef struct cl_sm_ctx_s {
    /** Linked-list of server contexts used in the Subscription Manager. */
    sr_llist_t *server_ctx_list;
    /** Lock for the server contexts linked-list. */
    pthread_mutex_t server_ctx_lock;

    /** Binary tree used for fast subscriber connection lookup by file descriptor. */
    sr_btree_t *fd_btree;

    /** Binary tree of data connections to sysrepo, organized by destination socket address. */
    sr_btree_t *data_connection_btree;

    /** Binary tree used for fast subscription lookup by id. */
    sr_btree_t *subscriptions_btree;
    /** Lock for the subscriptions binary tree. */
    pthread_mutex_t subscriptions_lock;

    /** Determines whether application-local file descriptor watcher is in place or not. */
    bool local_fd_watcher;
    /** File descriptor changes that need to be applied in application-local file descriptor watcher. */
    sr_fd_change_t *fd_changeset;
    /** Count of file descriptor changes in fd_changeset array. */
    size_t fd_changeset_cnt;
    /** Lock for the server contexts linked-list. */
    pthread_mutex_t fd_changeset_lock;
    /** Pipe used to notify application-local file descriptor watcher about required change in monitored FDs. */
    int fd_changeset_notify_pipe[2];

    /* Thread where Subscription Manger's event loop runs. */
    pthread_t event_loop_thread;
    /** Event loop context. */
    struct ev_loop *event_loop;
    /** Watcher for stop request events. */
    ev_async stop_watcher;
    /** Watcher for changes in server context list. */
    ev_async server_ctx_watcher;
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
 * @brief Adds a new file descriptor into the set of file descriptors whose monitoring state should be changed.
 */
static int
cl_sm_fd_changeset_add(cl_sm_ctx_t *sm_ctx, int fd, int events, sr_fd_action_t action)
{
    sr_fd_change_t *watcher_arr = NULL;

    CHECK_NULL_ARG(sm_ctx);

    /* allocate space for new change */
    watcher_arr = realloc(sm_ctx->fd_changeset, (sm_ctx->fd_changeset_cnt + 1) * sizeof(*watcher_arr));
    CHECK_NULL_NOMEM_RETURN(watcher_arr);

    pthread_mutex_lock(&sm_ctx->fd_changeset_lock);

    sm_ctx->fd_changeset = watcher_arr;
    sm_ctx->fd_changeset[sm_ctx->fd_changeset_cnt].fd = fd;
    sm_ctx->fd_changeset[sm_ctx->fd_changeset_cnt].events = events;
    sm_ctx->fd_changeset[sm_ctx->fd_changeset_cnt].action = action;

    sm_ctx->fd_changeset_cnt += 1;

    pthread_mutex_unlock(&sm_ctx->fd_changeset_lock);

    /* signal the changeset notify fd */
    return 1 == write(sm_ctx->fd_changeset_notify_pipe[1], "x", 1) ? SR_ERR_OK : SR_ERR_INTERNAL;
}

/**
 * @brief Retrieves current file descriptor chnageset from the SM context and clears it inside of the context.
 */
static int
cl_sm_get_fd_change_set(cl_sm_ctx_t *sm_ctx, sr_fd_change_t **fd_change_set, size_t *fd_change_set_cnt)
{
    CHECK_NULL_ARG3(sm_ctx, fd_change_set, fd_change_set_cnt);

    pthread_mutex_lock(&sm_ctx->fd_changeset_lock);

    *fd_change_set = sm_ctx->fd_changeset;
    *fd_change_set_cnt = sm_ctx->fd_changeset_cnt;
    sm_ctx->fd_changeset = NULL;
    sm_ctx->fd_changeset_cnt = 0;

    pthread_mutex_unlock(&sm_ctx->fd_changeset_lock);

    return SR_ERR_OK;
}


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

        SR_LOG_DBG("Closing subscriber connection on fd=%d.", conn->fd);

        /* stop monitoring client file descriptor */
        if (conn->sm_ctx->local_fd_watcher) {
            cl_sm_fd_changeset_add(conn->sm_ctx, conn->fd, (SR_FD_INPUT_READY | SR_FD_OUTPUT_READY), SR_FD_STOP_WATCHING);
        } else {
            if (NULL != conn->read_watcher.data) {
                ev_io_stop(conn->sm_ctx->event_loop, &conn->read_watcher);
            }
            if (NULL != conn->write_watcher.data) {
                ev_io_stop(conn->sm_ctx->event_loop, &conn->write_watcher);
            }
        }

        /* close the file descriptor */
        close(conn->fd);

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

    sr_btree_delete(sm_ctx->fd_btree, conn); /* sm_connection_cleanup auto-invoked */

    return SR_ERR_OK;
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
                if (sm_ctx->local_fd_watcher) {
                    rc = cl_sm_fd_changeset_add(sm_ctx, conn->fd, SR_FD_OUTPUT_READY, SR_FD_START_WATCHING);
                } else {
                    ev_io_start(sm_ctx->event_loop, &conn->write_watcher);
                }
                break;
            } else {
                /* error by writing - close the connection due to an error */
                SR_LOG_ERR("Error by writing data to fd %d: %s.", conn->fd, sr_strerror_safe(errno));
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
 * @brief Get (prepare) configuration session that can be used from notification callback.
 */
static int
cl_sm_get_data_session(cl_sm_ctx_t *sm_ctx, cl_sm_subscription_ctx_t *subscription,
        const char *source_address, uint32_t source_pid, uint32_t commit_id,
        sr_session_ctx_t **config_session_p)
{
    sr_conn_ctx_t *connection = NULL;
    sr_conn_ctx_t connection_lookup = { 0, };
    sr_session_ctx_t *session = NULL;
    sr_session_list_t *tmp = NULL;
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(sm_ctx, subscription, source_address, config_session_p);

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

    /* try to find the session matching with the commit ID in connection */
    if (NULL != connection->session_list) {
        tmp = connection->session_list;
        while (NULL != tmp) {
            if ((NULL != tmp->session) && (tmp->session->commit_id == commit_id)) {
                session = tmp->session;
                break;
            }
            tmp = tmp->next;
        }
    }
    /* if the matching session is not already open, open a new session */
    if (NULL == session) {
        /* session not found, create a new one */
        SR_LOG_DBG("Creating a new data session at '%s'.", source_address);
        rc = cl_session_create(connection, &session);

        /* prepare session_start message */
        rc = sr_mem_new(0, &sr_mem);
        if (SR_ERR_OK == rc) {
            rc = sr_gpb_req_alloc(sr_mem, SR__OPERATION__SESSION_START, /* undefined session id */ 0, &msg_req);
        }
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Cannot allocate session_start message.");
            cl_session_cleanup(session);
            return rc;
        }
        msg_req->request->session_start_req->options = SR__SESSION_FLAGS__SESS_NOTIFICATION;
        if (0 != commit_id) {
            msg_req->request->session_start_req->commit_id = commit_id;
            msg_req->request->session_start_req->has_commit_id = true;
        }
        msg_req->request->session_start_req->datastore = SR__DATA_STORE__RUNNING;

        /* send the request and receive the response */
        rc = cl_request_process(session, msg_req, &msg_resp, NULL, SR__OPERATION__SESSION_START);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Error by processing of session_start request.");
            sr_msg_free(msg_req);
            cl_session_cleanup(session);
            return rc;
        }

        session->id = msg_resp->response->session_start_resp->session_id;
        session->notif_session = true;
        session->commit_id = commit_id;

        sr_msg_free(msg_req);
        sr_msg_free(msg_resp);
    }

    subscription->data_session = session;
    *config_session_p = session;
    return rc;
}

static int
cl_sm_close_data_session(cl_sm_ctx_t *sm_ctx, cl_sm_subscription_ctx_t *subscription,
        const char *source_address, uint32_t commit_id)
{
    sr_conn_ctx_t *connection = NULL;
    sr_conn_ctx_t connection_lookup = { 0, };
    sr_session_ctx_t *session = NULL;
    sr_session_list_t *tmp = NULL;

    CHECK_NULL_ARG3(sm_ctx, subscription, source_address);

    /* find a connection matching with provided address */
    connection_lookup.dst_address = source_address;
    connection = sr_btree_search(sm_ctx->data_connection_btree, &connection_lookup);

    if (NULL == connection || NULL == connection->session_list) {
        /* no connection / sessions for this source address */
        return SR_ERR_OK;
    }

    /* try to find the session matching with the commit ID in connection */
    tmp = connection->session_list;
    while (NULL != tmp) {
        if ((NULL != tmp->session) && (tmp->session->commit_id == commit_id)) {
            session = tmp->session;
            break;
        }
        tmp = tmp->next;
    }

    if (NULL != session) {
        /* stop the session including sending of a session-stop request */
        sr_session_stop(session);
    }

    return SR_ERR_OK;
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
            /* do not close the connection right here - since send is always a consequence of receive,
             * it will be closed in receive code path */
            conn->close_requested = true;
            rc = SR_ERR_DISCONNECT;
        }
    }

    return rc;
}

/**
 * @brief Processes an incoming notification message.
 */
static int
cl_sm_notif_process(cl_sm_ctx_t *sm_ctx, cl_sm_conn_ctx_t *conn, Sr__Msg *msg)
{
    cl_sm_subscription_ctx_t *subscription = NULL;
    cl_sm_subscription_ctx_t subscription_lookup = { 0, };
    sr_session_ctx_t *data_session = NULL;
    Sr__Msg *ack_msg = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK, rc_tmp = SR_ERR_OK;

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
    rc = sr_gpb_msg_validate_notif(msg, subscription->type);
    if (SR_ERR_OK != rc) {
        pthread_mutex_unlock(&sm_ctx->subscriptions_lock);
        SR_LOG_ERR("Received notification message is not valid for subscription id=%"PRIu32".", msg->notification->subscription_id);
        return SR_ERR_INVAL_ARG;
    }

    /* get data session that can be used from notification callback */
    if ((SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS == msg->notification->type) ||
            (SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS == msg->notification->type)) {
        rc = cl_sm_get_data_session(sm_ctx, subscription, msg->notification->source_address,
                msg->notification->source_pid,
                (msg->notification->has_commit_id ? msg->notification->commit_id : 0),
                &data_session);
        if (SR_ERR_OK != rc) {
            pthread_mutex_unlock(&sm_ctx->subscriptions_lock);
            return rc;
        }
        cl_session_clear_errors(data_session);
    }

    switch (msg->notification->type) {
        case SR__SUBSCRIPTION_TYPE__MODULE_INSTALL_SUBS:
            SR_LOG_DBG("Calling module-install callback for subscription id=%"PRIu32".", subscription->id);
            subscription->callback.module_install_cb(
                    msg->notification->module_install_notif->module_name,
                    msg->notification->module_install_notif->revision,
                    msg->notification->module_install_notif->installed,
                    subscription->private_ctx);
            break;
        case SR__SUBSCRIPTION_TYPE__FEATURE_ENABLE_SUBS:
            SR_LOG_DBG("Calling feature-enable callback for subscription id=%"PRIu32".", subscription->id);
            subscription->callback.feature_enable_cb(
                    msg->notification->feature_enable_notif->module_name,
                    msg->notification->feature_enable_notif->feature_name,
                    msg->notification->feature_enable_notif->enabled,
                    subscription->private_ctx);
            break;
        case SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS:
            SR_LOG_DBG("Calling module-change callback for subscription id=%"PRIu32".", subscription->id);
            rc = subscription->callback.module_change_cb(
                    data_session,
                    msg->notification->module_change_notif->module_name,
                    sr_notification_event_gpb_to_sr(msg->notification->module_change_notif->event),
                    subscription->private_ctx);
            break;
        case SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS:
            SR_LOG_DBG("Calling subtree-change callback for subscription id=%"PRIu32".", subscription->id);
            rc = subscription->callback.subtree_change_cb(
                    data_session,
                    msg->notification->subtree_change_notif->xpath,
                    sr_notification_event_gpb_to_sr(msg->notification->subtree_change_notif->event),
                    subscription->private_ctx);
            break;
        case SR__SUBSCRIPTION_TYPE__HELLO_SUBS:
            SR_LOG_DBG("HELLO notification received on subscription id=%"PRIu32".", subscription->id);
            break;
        case SR__SUBSCRIPTION_TYPE__COMMIT_END_SUBS:
            SR_LOG_DBG("COMMIT-END notification received on subscription id=%"PRIu32".", subscription->id);
            /* close the session for this commit */
            if (msg->notification->has_commit_id) {
                rc = cl_sm_close_data_session(sm_ctx, subscription, msg->notification->source_address,
                        msg->notification->commit_id);
            }
            break;
        default:
            SR_LOG_ERR("Unknown notification event received on subscription id=%"PRIu32".", subscription->id);
            rc = SR_ERR_INVAL_ARG;
    }

    /* send notification ACK */
    if ((SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS == msg->notification->type) ||
            (SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS == msg->notification->type)) {
        rc_tmp = sr_mem_new(0, &sr_mem);
        if (SR_ERR_OK == rc_tmp) {
            rc_tmp = sr_gpb_notif_ack_alloc(sr_mem, msg, &ack_msg);
        }
        if (SR_ERR_OK == rc_tmp) {
            ack_msg->notification_ack->result = rc;
            if (SR_ERR_OK != rc && data_session->error_cnt > 0) {
                /* error info was provided */
                rc = sr_gpb_fill_error(data_session->error_info->message, data_session->error_info->xpath, sr_mem,
                        &ack_msg->notification_ack->error);
                if (SR_ERR_OK != rc) {
                    SR_LOG_WRN_MSG("Unable to fill errors into notification ACK message.");
                }
            }
        }
        if (SR_ERR_OK == rc_tmp) {
            rc_tmp = cl_sm_msg_send_connection(sm_ctx, conn, ack_msg);
            ack_msg->notification_ack->notif = NULL;
            sr_msg_free(ack_msg);
        }
        if (SR_ERR_OK != rc_tmp) {
            SR_LOG_ERR("Unable to send notification ACK: %s", sr_strerror(rc_tmp));
            rc = rc_tmp;
        } else {
            rc = SR_ERR_OK;
        }
    }

    pthread_mutex_unlock(&sm_ctx->subscriptions_lock);

    return rc;
}

/**
 * @brief Processes an incoming data-provide request message.
 */
static int
cl_sm_dp_request_process(cl_sm_ctx_t *sm_ctx, cl_sm_conn_ctx_t *conn, Sr__Msg *msg)
{
    cl_sm_subscription_ctx_t *subscription = NULL;
    cl_sm_subscription_ctx_t subscription_lookup = { 0, };
    Sr__Msg *resp = NULL;
    sr_mem_ctx_t *sr_mem_resp = NULL;
    sr_val_t *values = NULL;
    size_t values_cnt = 0;
    int rc = SR_ERR_OK, cb_rc = SR_ERR_OK;

    CHECK_NULL_ARG4(sm_ctx, msg, msg->request, msg->request->data_provide_req);

    SR_LOG_DBG("Received a data-provide request for subscription id=%"PRIu32".", msg->request->data_provide_req->subscription_id);

    pthread_mutex_lock(&sm_ctx->subscriptions_lock);

    /* find the subscription according to id */
    subscription_lookup.id = msg->request->data_provide_req->subscription_id;
    subscription = sr_btree_search(sm_ctx->subscriptions_btree, &subscription_lookup);
    if (NULL == subscription) {
        pthread_mutex_unlock(&sm_ctx->subscriptions_lock);
        SR_LOG_ERR("No matching subscription for subscription id=%"PRIu32".", msg->request->data_provide_req->subscription_id);
        goto cleanup;
    }

    SR_LOG_DBG("Calling dp_get_items_cb callback for subscription id=%"PRIu32".", subscription->id);

    cb_rc = subscription->callback.dp_get_items_cb(
            msg->request->data_provide_req->xpath,
            &values, &values_cnt,
            subscription->private_ctx);

    pthread_mutex_unlock(&sm_ctx->subscriptions_lock);

    /* allocate the response and send it */
    if (NULL != values) {
        sr_mem_resp = values[0]._sr_mem;
    }
    rc = sr_gpb_resp_alloc(sr_mem_resp, SR__OPERATION__DATA_PROVIDE, msg->session_id, &resp);
    CHECK_RC_MSG_RETURN(rc, "Allocation of data-provide response failed.");

    resp->response->result = cb_rc;
    resp->response->data_provide_resp->request_id = msg->request->data_provide_req->request_id;
    sr_mem_edit_string(sr_mem_resp, &resp->response->data_provide_resp->xpath, msg->request->data_provide_req->xpath);
    CHECK_NULL_NOMEM_GOTO(resp->response->data_provide_resp->xpath, rc, cleanup);

    /* copy output values to GPB */
    if (SR_ERR_OK == cb_rc) {
        rc = sr_values_sr_to_gpb(values, values_cnt, &resp->response->data_provide_resp->values,
                &resp->response->data_provide_resp->n_values);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Error by copying output values to GPB.");
    }

    /* send the response */
    rc = cl_sm_msg_send_connection(sm_ctx, conn, resp);

cleanup:
    sr_free_values(values, values_cnt);
    sr_msg_free(resp);
    return rc;
}

/**
 * @brief Processes an incoming RPC/Action message.
 */
static int
cl_sm_rpc_process(cl_sm_ctx_t *sm_ctx, cl_sm_conn_ctx_t *conn, Sr__Msg *msg)
{
    cl_sm_subscription_ctx_t *subscription = NULL;
    cl_sm_subscription_ctx_t subscription_lookup = { 0, };
    Sr__Msg *resp = NULL;
    sr_val_t *input = NULL, *output = NULL;
    sr_node_t *input_tree = NULL, *output_tree = NULL;
    sr_mem_ctx_t *sr_mem_resp = NULL;
    size_t input_cnt = 0, output_cnt = 0;
    const char *op_name = NULL;
    bool action = false;
    sr_rpc_cb cb = NULL;
    sr_rpc_tree_cb cb_tree = NULL;
    int rc = SR_ERR_OK, op_rc = SR_ERR_OK;

    CHECK_NULL_ARG4(sm_ctx, msg, msg->request, msg->request->rpc_req);

    action = msg->request->rpc_req->action;
    op_name = action ? "Action" : "RPC";
    SR_LOG_DBG("Received %s request for subscription id=%"PRIu32".", op_name, msg->request->rpc_req->subscription_id);

    /* copy input values from GPB */
    if (msg->request->rpc_req->n_input) {
        rc = sr_values_gpb_to_sr((sr_mem_ctx_t *)msg->_sysrepo_mem_ctx, msg->request->rpc_req->input,
                                 msg->request->rpc_req->n_input, &input, &input_cnt);
    } else if (msg->request->rpc_req->n_input_tree) {
        rc = sr_trees_gpb_to_sr((sr_mem_ctx_t *)msg->_sysrepo_mem_ctx, msg->request->rpc_req->input_tree,
                                msg->request->rpc_req->n_input_tree, &input_tree, &input_cnt);
    }
    CHECK_RC_LOG_GOTO(rc, cleanup, "Error by copying %s input arguments from GPB.", op_name);

    pthread_mutex_lock(&sm_ctx->subscriptions_lock);

    /* find the subscription according to id */
    subscription_lookup.id = msg->request->rpc_req->subscription_id;
    subscription = sr_btree_search(sm_ctx->subscriptions_btree, &subscription_lookup);
    if (NULL == subscription) {
        pthread_mutex_unlock(&sm_ctx->subscriptions_lock);
        SR_LOG_ERR("No matching subscription for subscription id=%"PRIu32".", msg->request->rpc_req->subscription_id);
        goto cleanup;
    }

    SR_LOG_DBG("Calling %s callback for subscription id=%"PRIu32".", op_name, subscription->id);

    if (SR_API_VALUES == subscription->api_variant) {
        cb = (action ? subscription->callback.action_cb : subscription->callback.rpc_cb);
        op_rc = cb(msg->request->rpc_req->xpath,
                   input, input_cnt,
                   &output, &output_cnt,
                   subscription->private_ctx);
    } else {
        cb_tree = (action ? subscription->callback.action_tree_cb : subscription->callback.rpc_tree_cb);
        op_rc = cb_tree(msg->request->rpc_req->xpath,
                        input_tree, input_cnt,
                        &output_tree, &output_cnt,
                        subscription->private_ctx);
    }

    pthread_mutex_unlock(&sm_ctx->subscriptions_lock);

    /* allocate the response and send it */
    if (NULL != output) {
        sr_mem_resp = output[0]._sr_mem;
    } else if (NULL != output_tree) {
        sr_mem_resp = output_tree[0]._sr_mem;
    }
    rc = sr_gpb_resp_alloc(sr_mem_resp, action ? SR__OPERATION__ACTION : SR__OPERATION__RPC, msg->session_id, &resp);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Allocation of %s response failed.", op_name);

    resp->response->result = op_rc;
    resp->response->rpc_resp->action = action;
    sr_mem_edit_string(sr_mem_resp, &resp->response->rpc_resp->xpath, msg->request->rpc_req->xpath);
    resp->response->rpc_resp->orig_api_variant = msg->request->rpc_req->orig_api_variant;
    CHECK_NULL_NOMEM_GOTO(resp->response->rpc_resp->xpath, rc, cleanup);

    /* copy output values to GPB */
    if (SR_ERR_OK == op_rc) {
        if (NULL != output) {
            rc = sr_values_sr_to_gpb(output, output_cnt, &resp->response->rpc_resp->output,
                    &resp->response->rpc_resp->n_output);
        } else if (NULL != output_tree) {
            rc = sr_trees_sr_to_gpb(output_tree, output_cnt, &resp->response->rpc_resp->output_tree,
                    &resp->response->rpc_resp->n_output_tree);
        }
        CHECK_RC_LOG_GOTO(rc, cleanup, "Error by copying %s output arguments to GPB.", op_name);
    }

    /* send the response */
    rc = cl_sm_msg_send_connection(sm_ctx, conn, resp);

cleanup:
    sr_free_values(input, input_cnt);
    sr_free_values(output, output_cnt);
    sr_free_trees(input_tree, input_cnt);
    sr_free_trees(output_tree, output_cnt);
    sr_msg_free(resp);
    return rc;
}

/**
 * @brief Processes an incoming event notification.
 */
static int
cl_sm_event_notif_process(cl_sm_ctx_t *sm_ctx, cl_sm_conn_ctx_t *conn, Sr__Msg *msg)
{
    cl_sm_subscription_ctx_t *subscription = NULL;
    cl_sm_subscription_ctx_t subscription_lookup = { 0, };
    sr_val_t *values = NULL;
    sr_node_t *trees = NULL;
    size_t values_cnt = 0;
    size_t tree_cnt = 0;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(sm_ctx, msg, msg->request, msg->request->event_notif_req);

    SR_LOG_DBG("Received an event notification for subscription id=%"PRIu32".",
            msg->request->event_notif_req->subscription_id);

    /* copy input data from GPB */
    if (msg->request->event_notif_req->n_values) {
        rc = sr_values_gpb_to_sr((sr_mem_ctx_t *)msg->_sysrepo_mem_ctx, msg->request->event_notif_req->values,
                msg->request->event_notif_req->n_values, &values, &values_cnt);
    } else if (msg->request->event_notif_req->n_trees) {
        rc = sr_trees_gpb_to_sr((sr_mem_ctx_t *)msg->_sysrepo_mem_ctx, msg->request->event_notif_req->trees,
                msg->request->event_notif_req->n_trees, &trees, &tree_cnt);
    }
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by copying event notification input data from GPB.");

    pthread_mutex_lock(&sm_ctx->subscriptions_lock);

    /* find the subscription according to id */
    subscription_lookup.id = msg->request->event_notif_req->subscription_id;
    subscription = sr_btree_search(sm_ctx->subscriptions_btree, &subscription_lookup);
    if (NULL == subscription) {
        pthread_mutex_unlock(&sm_ctx->subscriptions_lock);
        SR_LOG_ERR("No matching subscription for subscription id=%"PRIu32".",
                msg->request->event_notif_req->subscription_id);
        goto cleanup;
    }

    SR_LOG_DBG("Calling event notification callback for subscription id=%"PRIu32".", subscription->id);

    if (SR_API_VALUES == subscription->api_variant) {
        subscription->callback.event_notif_cb(msg->request->event_notif_req->xpath, values, values_cnt,
                subscription->private_ctx);
    } else {
        subscription->callback.event_notif_tree_cb(msg->request->event_notif_req->xpath, trees, tree_cnt,
                subscription->private_ctx);
    }

    pthread_mutex_unlock(&sm_ctx->subscriptions_lock);

cleanup:
    sr_free_values(values, values_cnt);
    sr_free_trees(trees, tree_cnt);
    return rc;
}

/**
 * @brief Processes a message received on the connection.
 */
static int
cl_sm_conn_msg_process(cl_sm_ctx_t *sm_ctx, cl_sm_conn_ctx_t *conn, uint8_t *msg_data, size_t msg_size)
{
    Sr__Msg *msg = NULL;
    sr_mem_ctx_t *sr_mem = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(sm_ctx, conn, msg_data);

    /* unpack the message */
    rc = sr_mem_new(msg_size, &sr_mem);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Failed to create a new Sysrepo memory context (conn=%p).", (void*)conn);
        return SR_ERR_INTERNAL;
    }
    ProtobufCAllocator allocator = sr_get_protobuf_allocator(sr_mem);
    msg = sr__msg__unpack(&allocator, msg_size, msg_data);
    if (NULL == msg) {
        sr_mem_free(sr_mem);
        SR_LOG_ERR("Unable to unpack the message (conn=%p).", (void*)conn);
        return SR_ERR_INTERNAL;
    }

    /* associate message with context */
    if (NULL != sr_mem) {
        msg->_sysrepo_mem_ctx = (uint64_t)sr_mem;
        ++sr_mem->obj_count;
    }

    /* check the message */
    if (SR__MSG__MSG_TYPE__NOTIFICATION == msg->type) {
        /* notification */
        rc = cl_sm_notif_process(sm_ctx, conn, msg);
    } else if ((SR__MSG__MSG_TYPE__REQUEST == msg->type) && (SR__OPERATION__DATA_PROVIDE == msg->request->operation)) {
        /* data-provide request */
        rc = cl_sm_dp_request_process(sm_ctx, conn, msg);
    } else if ((SR__MSG__MSG_TYPE__REQUEST == msg->type) &&
                (SR__OPERATION__RPC == msg->request->operation || SR__OPERATION__ACTION == msg->request->operation)) {
        /* RPC/Action request */
        rc = cl_sm_rpc_process(sm_ctx, conn, msg);
    } else if ((SR__MSG__MSG_TYPE__REQUEST == msg->type) && (SR__OPERATION__EVENT_NOTIF == msg->request->operation)) {
        /* event notification */
        rc = cl_sm_event_notif_process(sm_ctx, conn, msg);
    } else {
        SR_LOG_ERR("Invalid or unexpected message received (conn=%p).", (void*)conn);
        rc = SR_ERR_INVAL_ARG;
    }

    /* release the message */
    sr_msg_free(msg);

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
                return rc;
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
                SR_LOG_ERR("Error by reading data on fd %d: %s.", conn->fd, sr_strerror_safe(errno));
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
 * @brief Writes data in output buffer into specified connection.
 */
static int
cl_sm_write_conn(cl_sm_ctx_t *sm_ctx, cl_sm_conn_ctx_t *conn)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(sm_ctx, conn);

    /* stop monitoring the FD for writable event */
    if (sm_ctx->local_fd_watcher) {
        cl_sm_fd_changeset_add(sm_ctx, conn->fd, SR_FD_OUTPUT_READY, SR_FD_STOP_WATCHING);
    } else {
        ev_io_stop(sm_ctx->event_loop, &conn->write_watcher);
    }

    /* flush the output buffer */
    rc = cl_sm_conn_out_buff_flush(sm_ctx, conn);

    /* close the connection if requested */
    if ((conn->close_requested) || (SR_ERR_OK != rc)) {
        cl_sm_conn_close(sm_ctx, conn);
    }

    return rc;
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

    CHECK_NULL_ARG_VOID2(w, w->data);
    conn = (cl_sm_conn_ctx_t*)w->data;

    CHECK_NULL_ARG_VOID2(conn, conn->sm_ctx);
    sm_ctx = conn->sm_ctx;

    SR_LOG_DBG("fd %d writeable", conn->fd);

    cl_sm_write_conn(sm_ctx, conn);
}

/**
 * @brief Accepts new connections on specified unix-domain server socket.
 */
static int
cl_sm_accept_server_connections(cl_sm_ctx_t *sm_ctx, cl_sm_server_ctx_t *server_ctx)
{
    cl_sm_conn_ctx_t *conn = NULL;
    int clnt_fd = -1;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(sm_ctx, server_ctx);

    do {
        clnt_fd = accept(server_ctx->listen_socket_fd, NULL, NULL);
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
            /* start watching new client FD */
            if (sm_ctx->local_fd_watcher) {
                cl_sm_fd_changeset_add(sm_ctx, clnt_fd, SR_FD_INPUT_READY, SR_FD_START_WATCHING);
            } else {
                ev_io_init(&conn->read_watcher, cl_sm_fd_read_cb, clnt_fd, EV_READ);
                conn->read_watcher.data = (void*)sm_ctx;
                ev_io_start(sm_ctx->event_loop, &conn->read_watcher);

                ev_io_init(&conn->write_watcher, cl_sm_conn_write_cb, conn->fd, EV_WRITE);
                conn->write_watcher.data = (void*)conn;
                /* do not start write watcher - will be started when needed */
            }
        } else {
            if ((EWOULDBLOCK == errno) || (EAGAIN == errno)) {
                /* no more connections to accept */
                break;
            } else {
                /* error by accept - only log the error and skip it */
                SR_LOG_ERR("Unexpected error by accepting new connection: %s", sr_strerror_safe(errno));
                continue;
            }
        }
    } while (-1 != clnt_fd); /* accept returns -1 when there are no more connections to accept */

    return rc;
}

/**
 * @brief Callback called by the event loop watcher when a new connection is detected
 * on the server socket. Accepts new connections to the server and starts
 * monitoring the new client file descriptors.
 */
static void
cl_sm_server_watcher_cb(struct ev_loop *loop, ev_io *w, int revents)
{
    cl_sm_server_ctx_t *server_ctx = NULL;
    cl_sm_ctx_t *sm_ctx = NULL;

    CHECK_NULL_ARG_VOID2(w, w->data);
    server_ctx = (cl_sm_server_ctx_t*)w->data;
    sm_ctx = server_ctx->sm_ctx;

    cl_sm_accept_server_connections(sm_ctx, server_ctx);
}

/**
 * @brief Destroys the unix-domain socket server for subscriber connections.
 */
static void
cl_sm_server_cleanup(cl_sm_ctx_t *sm_ctx, cl_sm_server_ctx_t *server_ctx)
{
    if (NULL != server_ctx) {
        /* stop monitoring the server socket */
        if (sm_ctx->local_fd_watcher) {
            cl_sm_fd_changeset_add(sm_ctx, server_ctx->listen_socket_fd, (SR_FD_INPUT_READY | SR_FD_OUTPUT_READY),
                    SR_FD_STOP_WATCHING);
        } else {
            if (NULL != server_ctx->server_watcher.data) {
                ev_io_stop(sm_ctx->event_loop, &server_ctx->server_watcher);
            }
        }
        if (-1 != server_ctx->listen_socket_fd) {
            close(server_ctx->listen_socket_fd);
        }
        if (NULL != server_ctx->socket_path) {
            unlink(server_ctx->socket_path);
            free(server_ctx->socket_path);
        }
        free(server_ctx->module_name);
        free(server_ctx);
    }
}

/**
 * @brief Cleans up all server context within the Subscription Manager.
 */
static void
cl_sm_servers_cleanup(cl_sm_ctx_t *sm_ctx)
{
    sr_llist_node_t *node = NULL;

    if (NULL != sm_ctx ) {
        pthread_mutex_lock(&sm_ctx->server_ctx_lock);

        if (NULL != sm_ctx->server_ctx_list) {
            node = sm_ctx->server_ctx_list->first;
            while (NULL != node) {
                cl_sm_server_cleanup(sm_ctx, node->data);
                node = node->next;
            }
        }

        pthread_mutex_unlock(&sm_ctx->server_ctx_lock);
    }
}

/**
 * @brief Gets a filename that can be used for binding a new unix-domain server.
 * Creates needed directories in SR_CLIENT_SOCKET_DIR if missing.
 */
static int
cl_sm_get_server_socket_filename(cl_sm_ctx_t *sm_ctx, const char *module_name, char **socket_path)
{
    char path[PATH_MAX] = { 0, };
    char pid_str[20] = { 0, };
    int fd = -1;
    mode_t old_umask = 0;
    int ret = 0, rc = SR_ERR_OK;

    CHECK_NULL_ARG3(sm_ctx, module_name, socket_path);

    /* create the parent directory if does not exist */
    strncat(path, SR_SUBSCRIPTIONS_SOCKET_DIR, PATH_MAX - 1);
    strncat(path, "/", PATH_MAX - strlen(path) - 1);
    if (-1 == access(path, F_OK)) {
        old_umask = umask(0);
        ret = mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO);
        umask(old_umask);
        CHECK_ZERO_LOG_RETURN(ret, SR_ERR_INTERNAL, "Unable to create the directory '%s': %s", path, sr_strerror_safe(errno));
    }

    /* create the module directory if it does not exist */
    strncat(path, module_name, PATH_MAX - strlen(path) - 1);
    strncat(path, "/", PATH_MAX - strlen(path) - 1);
    if (-1 == access(path, F_OK)) {
        old_umask = umask(0);
        ret = mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO);
        umask(old_umask);
        CHECK_ZERO_LOG_RETURN(ret, SR_ERR_INTERNAL, "Unable to create the directory '%s': %s", path, sr_strerror_safe(errno));
        rc = sr_set_socket_dir_permissions(path, SR_DATA_SEARCH_DIR, module_name, false);
        if (SR_ERR_OK != rc) {
            rmdir(path);
            SR_LOG_WRN("Attempt to subscribe to unknown '%s' module probably", module_name);
        }
        CHECK_RC_LOG_RETURN(rc, "Unable to set socket directory permissions for '%s'.", path);
    }

    /* append PID */
    snprintf(pid_str, 20, "%d", getpid());
    strncat(path, pid_str, PATH_MAX - strlen(path) - 1);

    /* append temporary file name part */
    strncat(path, ".XXXXXX.sock", PATH_MAX - strlen(path) - 1);
    fd = mkstemps(path, 5);
    if (-1 != fd) {
        close(fd);
        unlink(path);
    }

    *socket_path = strdup(path);
    CHECK_NULL_NOMEM_RETURN(*socket_path);

    return rc;
}

/**
 * @brief Initializes unix-domain socket server for subscriber connections.
 */
static int
cl_sm_server_init(cl_sm_ctx_t *sm_ctx, const char *module_name, cl_sm_server_ctx_t **server_ctx_p)
{
    int ret = 0;
    struct sockaddr_un addr;
    mode_t old_umask = 0;
    cl_sm_server_ctx_t *server_ctx = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(sm_ctx, module_name, server_ctx_p);

    /* allocate the context */
    server_ctx = calloc(1, sizeof(*server_ctx));
    CHECK_NULL_NOMEM_RETURN(server_ctx);

    server_ctx->sm_ctx = sm_ctx;
    server_ctx->module_name = strdup(module_name);
    CHECK_NULL_NOMEM_GOTO(server_ctx->module_name, rc, cleanup);

    /* add the context into server list */
    rc = sr_llist_add_new(sm_ctx->server_ctx_list, server_ctx);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot add new server context into context list.");

    /* generate socket path */
    rc = cl_sm_get_server_socket_filename(sm_ctx, module_name, &server_ctx->socket_path);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot generate server socket path.");

    SR_LOG_DBG("Initializing sysrepo subscription server at socket=%s", server_ctx->socket_path);

    /* create listening socket */
    server_ctx->listen_socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (-1 == server_ctx->listen_socket_fd) {
        SR_LOG_ERR("Socket create error: %s", sr_strerror_safe(errno));
        rc = SR_ERR_INIT_FAILED;
        goto cleanup;
    }

    /* set socket to nonblocking mode */
    rc = sr_fd_set_nonblock(server_ctx->listen_socket_fd);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot set socket to nonblocking mode.");

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, server_ctx->socket_path, sizeof(addr.sun_path)-1);

    /* bind the unix-domain socket writable to anyone
     * (permission are guarded by the directory where the socket is placed) */
    old_umask = umask(0);
    ret = bind(server_ctx->listen_socket_fd, (struct sockaddr*)&addr, sizeof(addr));
    umask(old_umask);
    CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_INIT_FAILED, cleanup, "Socket bind error: %s", sr_strerror_safe(errno));

    /* start listening on the socket */
    ret = listen(server_ctx->listen_socket_fd, SOMAXCONN);
    CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_INIT_FAILED, cleanup, "Socket listen error: %s", sr_strerror_safe(errno));

    /* start monitoring the server socket for new connections */
    if (sm_ctx->local_fd_watcher) {
        /* add the server socket FD into FD change set */
        rc = cl_sm_fd_changeset_add(sm_ctx, server_ctx->listen_socket_fd, SR_FD_INPUT_READY, SR_FD_START_WATCHING);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot add the server socket FD into FD change set.");
    } else {
        /* send a signal to the thread with event loop to re-scan for new server contexts */
        ev_async_send(sm_ctx->event_loop, &sm_ctx->server_ctx_watcher);
    }

    *server_ctx_p = server_ctx;
    return SR_ERR_OK;

cleanup:
    cl_sm_server_cleanup(sm_ctx, server_ctx);
    if (server_ctx == (cl_sm_server_ctx_t *) sm_ctx->server_ctx_list->last->data) {
        sr_llist_rm(sm_ctx->server_ctx_list, sm_ctx->server_ctx_list->last);
    }
    return rc;
}

/**
 * @brief Finds server context matching with provided server socket file descriptor.
 */
static cl_sm_server_ctx_t *
cl_sm_fd_find_server_ctx(cl_sm_ctx_t *sm_ctx, int fd)
{
    sr_llist_node_t *node = NULL;

    if (NULL != sm_ctx) {
        pthread_mutex_lock(&sm_ctx->server_ctx_lock);

        if (NULL != sm_ctx->server_ctx_list) {
            node = sm_ctx->server_ctx_list->first;
            while (NULL != node) {
                if (fd == ((cl_sm_server_ctx_t*)(node->data))->listen_socket_fd) {
                    pthread_mutex_unlock(&sm_ctx->server_ctx_lock);
                    return node->data;
                }
                node = node->next;
            }
        }

        pthread_mutex_unlock(&sm_ctx->server_ctx_lock);
    }
    return NULL;
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
 * @brief Callback called by the event loop watcher when an async request to rescan server contexts is received.
 */
static void
cl_sm_server_ctx_change_cb(struct ev_loop *loop, ev_async *w, int revents)
{
    cl_sm_ctx_t *sm_ctx = NULL;
    sr_llist_node_t *node = NULL;
    cl_sm_server_ctx_t *server_ctx = NULL;

    CHECK_NULL_ARG_VOID3(loop, w, w->data);
    sm_ctx = (cl_sm_ctx_t*)w->data;

    SR_LOG_DBG_MSG("Server context changed.");

    pthread_mutex_lock(&sm_ctx->server_ctx_lock);

    if (NULL != sm_ctx && NULL != sm_ctx->server_ctx_list) {
        node = sm_ctx->server_ctx_list->first;
        while (NULL != node) {
            server_ctx = (cl_sm_server_ctx_t*)node->data;
            /* if not already initialized */
            if (!server_ctx->watcher_started) {
                /* initialize event watcher for unix-domain server socket */
                ev_io_init(&server_ctx->server_watcher, cl_sm_server_watcher_cb, server_ctx->listen_socket_fd, EV_READ);
                server_ctx->server_watcher.data = (void*)server_ctx;
                ev_io_start(sm_ctx->event_loop, &server_ctx->server_watcher);
                server_ctx->watcher_started = true;
            }
            node = node->next;
        }
    }

    pthread_mutex_unlock(&sm_ctx->server_ctx_lock);
}

/**
 * @brief Runs the event loop in a new thread.
 */
static void *
cl_sm_event_loop_threaded(void *sm_ctx_p)
{
    cl_sm_ctx_t *sm_ctx = NULL;

    if (NULL != sm_ctx_p) {
        sm_ctx = (cl_sm_ctx_t*)sm_ctx_p;

        SR_LOG_DBG_MSG("Starting client subscription event loop.");

        ev_run(sm_ctx->event_loop, 0);

        SR_LOG_DBG_MSG("Client subscription event loop finished.");
    }

    return NULL;
}

int
cl_sm_init(bool local_fd_watcher, int notify_pipe[2], cl_sm_ctx_t **sm_ctx_p)
{
    cl_sm_ctx_t *ctx = NULL;
    int ret = 0, rc = SR_ERR_OK;

    CHECK_NULL_ARG(sm_ctx_p);

    SR_LOG_DBG_MSG("Client Subscription Manager init started.");

    /* allocate the context */
    ctx = calloc(1, sizeof(*ctx));
    CHECK_NULL_NOMEM_RETURN(ctx);

    ctx->local_fd_watcher = local_fd_watcher;
    ctx->fd_changeset_notify_pipe[0] = notify_pipe[0];
    ctx->fd_changeset_notify_pipe[1] = notify_pipe[1];

    /* initialize linked-list for server contexts */
    rc = sr_llist_init(&ctx->server_ctx_list);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot initialize linked-list for server contexts.");

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

    /* initialize the mutexes */
    ret = pthread_mutex_init(&ctx->server_ctx_lock, NULL);
    CHECK_ZERO_MSG_GOTO(ret, rc, SR_ERR_INIT_FAILED, cleanup, "Cannot initialize subscriptions server contexts mutex.");
    ret = pthread_mutex_init(&ctx->fd_changeset_lock, NULL);
    CHECK_ZERO_MSG_GOTO(ret, rc, SR_ERR_INIT_FAILED, cleanup, "Cannot initialize fd changeset mutex.");
    ret = pthread_mutex_init(&ctx->subscriptions_lock, NULL);
    CHECK_ZERO_MSG_GOTO(ret, rc, SR_ERR_INIT_FAILED, cleanup, "Cannot initialize subscriptions mutex.");

    srand(time(NULL));

    if (local_fd_watcher) {
        /* use application-local file descriptor watcher */
        SR_LOG_DBG_MSG("Application-local file descriptor watcher will be used for monitoring of subscriptions.");
    } else {
        /* initialize event loop */
        /* According to our measurements, EPOLL backend is significantly slower for
         * fewer file descriptors, so we are disabling it for now. */
        ctx->event_loop = ev_loop_new((EVBACKEND_ALL ^ EVBACKEND_EPOLL) | EVFLAG_NOENV);

        /* initialize event watcher for async stop requests */
        ev_async_init(&ctx->stop_watcher, cl_sm_stop_cb);
        ctx->stop_watcher.data = (void*)ctx;
        ev_async_start(ctx->event_loop, &ctx->stop_watcher);

        /* initialize event watcher for changes in server context */
        ev_async_init(&ctx->server_ctx_watcher, cl_sm_server_ctx_change_cb);
        ctx->server_ctx_watcher.data = (void*)ctx;
        ev_async_start(ctx->event_loop, &ctx->server_ctx_watcher);

        /* start the event loop in a new thread */
        ret = pthread_create(&ctx->event_loop_thread, NULL, cl_sm_event_loop_threaded, ctx);
        CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_INIT_FAILED, cleanup, "Error by creating a new thread: %s", sr_strerror_safe(errno));

        SR_LOG_DBG_MSG("An event loop in the background thread successfully started.");
    }

    SR_LOG_DBG_MSG("Client Subscription Manager initialized successfully.");

    *sm_ctx_p = ctx;
    return rc;

cleanup:
    cl_sm_cleanup(ctx, false);
    return rc;
}

void
cl_sm_cleanup(cl_sm_ctx_t *sm_ctx, bool join)
{
    if (NULL != sm_ctx) {
        if (!sm_ctx->local_fd_watcher) {
            if (join) {
                ev_async_send(sm_ctx->event_loop, &sm_ctx->stop_watcher);
                pthread_join(sm_ctx->event_loop_thread, NULL);
            }
        }
        cl_sm_servers_cleanup(sm_ctx);

        sr_btree_cleanup(sm_ctx->data_connection_btree);
        sr_btree_cleanup(sm_ctx->subscriptions_btree);
        sr_btree_cleanup(sm_ctx->fd_btree);
        sr_llist_cleanup(sm_ctx->server_ctx_list);

        pthread_mutex_destroy(&sm_ctx->server_ctx_lock);
        pthread_mutex_destroy(&sm_ctx->fd_changeset_lock);
        pthread_mutex_destroy(&sm_ctx->subscriptions_lock);

        if (sm_ctx->local_fd_watcher) {
            if (sm_ctx->fd_changeset_cnt > 0) {
                free(sm_ctx->fd_changeset);
                sm_ctx->fd_changeset = NULL;
                sm_ctx->fd_changeset_cnt = 0;
            }
        } else {
            if (NULL != sm_ctx->event_loop) {
                ev_loop_destroy(sm_ctx->event_loop);
            }
        }

        free(sm_ctx);

        SR_LOG_INF_MSG("Client Subscription Manager successfully destroyed.");
    }
}

int
cl_sm_get_server_ctx(cl_sm_ctx_t *sm_ctx, const char *module_name, cl_sm_server_ctx_t **server_ctx_p)
{
    sr_llist_node_t *node = NULL;
    cl_sm_server_ctx_t *server_ctx = NULL;
    bool matched = false;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(sm_ctx, server_ctx_p);

    if (NULL == module_name) {
        /* use internal "fake" module name */
        module_name = SR_GLOBAL_SUBSCRIPTIONS_SUBDIR;
    }

    pthread_mutex_lock(&sm_ctx->server_ctx_lock);

    /* find if a server context already exists for this module */
    node = sm_ctx->server_ctx_list->first;
    while (NULL != node) {
        server_ctx = (cl_sm_server_ctx_t*)node->data;
        if ((NULL != server_ctx->module_name) && (0 == strcmp(server_ctx->module_name, module_name))) {
            matched = true;
            break;
        }
        node = node->next;
    }

    if (!matched) {
        /* start a new server */
        server_ctx = NULL;
        rc = cl_sm_server_init(sm_ctx, module_name, &server_ctx);
    }

    pthread_mutex_unlock(&sm_ctx->server_ctx_lock);
    *server_ctx_p = server_ctx;
    return rc;
}

int
cl_sm_subscription_init(cl_sm_ctx_t *sm_ctx, cl_sm_server_ctx_t *server_ctx, cl_sm_subscription_ctx_t **subscription_p)
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

    subscription->delivery_address = server_ctx->socket_path;
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

int
cl_sm_fd_event_process(cl_sm_ctx_t *sm_ctx, int fd, sr_fd_event_t event,
        sr_fd_change_t **fd_change_set, size_t *fd_change_set_cnt)
{
    char buf[256] = { 0, };
    cl_sm_server_ctx_t *server_ctx = NULL;
    cl_sm_conn_ctx_t tmp_conn = { 0, };
    cl_sm_conn_ctx_t *conn = NULL;
    int ret = 0, rc = SR_ERR_OK;

    CHECK_NULL_ARG3(sm_ctx, fd_change_set, fd_change_set_cnt);

    if (fd == sm_ctx->fd_changeset_notify_pipe[0]) {
        /* set of file descriptors used for watching needs to be modified */
        rc = cl_sm_get_fd_change_set(sm_ctx, fd_change_set, fd_change_set_cnt);
        SR_LOG_DBG("Change in the FD set for watching: %zu changes.", *fd_change_set_cnt);
        ret = read(fd, buf, sizeof(buf)); /* we do not care about the data, just read it */
        if (-1 == ret) {
            SR_LOG_WRN("Error by reading from fd notify pipe: %s", sr_strerror_safe(errno));
        }
    } else {
        if (SR_FD_INPUT_READY == event) {
            /* the file descriptor is readable */
            server_ctx = cl_sm_fd_find_server_ctx(sm_ctx, fd);
            if (NULL != server_ctx) {
                /* this is a server socket fd - accept */
                rc = cl_sm_accept_server_connections(sm_ctx, server_ctx);
            } else {
                /* this is a client socket connection - read a message from specified fd */
                rc = cl_sm_fd_read_data(sm_ctx, fd);
                if (SR_ERR_DISCONNECT == rc) {
                    SR_LOG_DBG("Client of fd %d disconnected, ignoring this fd.", fd);
                    rc = SR_ERR_OK;
                }
            }
        } else {
            /* the file descriptor is writeable */
            tmp_conn.fd = fd;
            conn = sr_btree_search(sm_ctx->fd_btree, &tmp_conn);
            rc = cl_sm_write_conn(sm_ctx, conn);
        }
    }

    return rc;
}
