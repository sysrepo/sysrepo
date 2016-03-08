/**
 * @file client_library.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo client library (public API) implementation.
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

#include "sr_common.h"
#include "connection_manager.h"

/**
 * @brief Timeout (in seconds) for waiting for a response from server by each request.
 */
#define CL_REQUEST_TIMEOUT 2

/**
 * @brief Number of items being fetched in one message from Sysrepo Engine by
 * processing of sr_get_items_iter calls.
 */
#define CL_GET_ITEMS_FETCH_LIMIT 2

/**
 * @brief Filesystem path prefix for generating temporary socket names used
 * for local unix-domain connections (library mode).
 */
#define CL_LCONN_PATH_PREFIX "/tmp/sysrepo-local"

/**
 * Connection context used to identify a connection to sysrepo datastore.
 */
typedef struct sr_conn_ctx_s {
    int fd;                                  /**< File descriptor of the connection. */
    bool primary;                            /**< Primary connection. Handles all resources allocated only
                                                  once per process (first connection is always primary). */
    pthread_mutex_t lock;                    /**< Mutex of the connection to guarantee that requests on the
                                                  same connection are processed serially (one after another). */
    uint8_t *msg_buf;                        /**< Buffer used for sending / receiving messages. */
    size_t msg_buf_size;                     /**< Length of the message buffer. */
    struct sr_session_list_s *session_list;  /**< Linked-list of associated sessions. */
    bool library_mode;                       /**< Determine if we are connected to sysrepo daemon
                                                  or our own sysrepo engine (library mode). */
    cm_ctx_t *local_cm;                      /**< Local Connection Manager in case of library mode. */
} sr_conn_ctx_t;

/**
 * Session context used to identify a configuration session.
 */
typedef struct sr_session_ctx_s {
    sr_conn_ctx_t *conn_ctx;      /**< Associated connection context. */
    uint32_t id;                  /**< Assigned session identifier. */
    pthread_mutex_t lock;         /**< Mutex for the session context content. */
    sr_error_t last_error;        /**< Latest error code returned from an API call. */
    sr_error_info_t *error_info;  /**< Array of detailed error information from last API call. */
    size_t error_info_size;       /**< Current size of the error_info array. */
    size_t error_cnt;             /**< Number of errors that occurred within last API call. */
} sr_session_ctx_t;

/**
 * Linked-list of sessions.
 */
typedef struct sr_session_list_s {
    sr_session_ctx_t *session;       /**< Session context. */
    struct sr_session_list_s *next;  /**< Next element in the linked-list. */
} sr_session_list_t;

/**
 * Structure holding data for iterative access to items
 */
typedef struct sr_val_iter_s{
    char *path;                     /**< xpath of the request */
    bool recursive;                 /**< flag denoting whether child subtrees should be iterated */
    size_t offset;                  /**< offset where the next data should be read */
    size_t limit;                   /**< how many items should be read */
    sr_val_t **buff_values;         /**< buffered values */
    size_t index;                   /**< index into buff_values pointing to the value to be returned by next call */
    size_t count;                   /**< number of element currently buffered */
} sr_val_iter_t;

static sr_conn_ctx_t *primary_connection = NULL;                  /**< Global variable holding pointer to the primary connection. */
static pthread_mutex_t primary_lock = PTHREAD_MUTEX_INITIALIZER;  /**< Mutex for locking global variable primary_connection. */

/**
 * @brief Returns provided error code and saves it in the session context.
 * Should be called as an exit point from any publicly available API function
 * taking the session as an argument.
 */
static sr_error_t
cl_session_return(sr_session_ctx_t *session, sr_error_t error_code)
{
    CHECK_NULL_ARG(session);

    pthread_mutex_lock(&session->lock);
    session->last_error = error_code;
    pthread_mutex_unlock(&session->lock);

    return error_code;
}

/**
 * @brief Set detailed error information into session context.
 */
static int
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

/**
 * @brief Set detailed error information from GPB error array into session context.
 */
static int
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

/**
 * @brief Clear number of errors stored within the session context.
 */
int
cl_session_clear_errors(sr_session_ctx_t *session)
{
    CHECK_NULL_ARG(session);

    pthread_mutex_lock(&session->lock);
    session->error_cnt = 0;
    pthread_mutex_unlock(&session->lock);

    return SR_ERR_OK;
}

/**
 * @brief Connects the client to provided unix-domain socket.
 */
static int
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
        SR_LOG_ERR("Unable to create a new socket (socket=%s)", socket_path);
        return SR_ERR_INTERNAL;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);

    /* connect to server */
    rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (-1 == rc) {
        SR_LOG_DBG("Unable to connect to socket (socket=%s)", socket_path);
        close(fd);
        return SR_ERR_DISCONNECT;
    }

    /* set timeout for receive operation */
    tv.tv_sec = CL_REQUEST_TIMEOUT;
    tv.tv_usec = 0;
    rc = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
    if (-1 == rc) {
        SR_LOG_ERR("Unable to set timeout for socket operations (socket=%s)", socket_path);
        close(fd);
        return SR_ERR_DISCONNECT;
    }

    conn_ctx->fd = fd;
    return SR_ERR_OK;
}

/**
 * @brief Initializes our own sysrepo engine (fallback option if sysrepo daemon is not running)
 */
static int
cl_engine_init_local(sr_conn_ctx_t *conn_ctx, const char *socket_path)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(conn_ctx, socket_path);

    /* initialize local Connection Manager */
    rc = cm_init(CM_MODE_LOCAL, socket_path, &conn_ctx->local_cm);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Unable to initialize local Connection Manager.");
        return rc;
    }

    /* start the server */
    rc = cm_start(conn_ctx->local_cm);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Unable to start local Connection Manager.");
        return rc;
    }

    return rc;
}

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
static int
cl_conn_remove_session(sr_conn_ctx_t *connection, sr_session_ctx_t *session)
{
    sr_session_list_t *tmp = NULL, *prev = NULL;

    CHECK_NULL_ARG2(connection, session);

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

    return SR_ERR_OK;
}

/**
 * @brief Cleans up a client library -local session.
 */
static void
cl_session_cleanup(sr_session_ctx_t *session)
{
    if (NULL != session) {
        sr_free_errors(session->error_info, session->error_info_size);
        pthread_mutex_destroy(&session->lock);
        free(session);
    }
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

/**
 *@brief  Processes (sends) the request over the connection and receive the response.
 */
static int
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

/**
 * @brief Creates get_items request with options and send it
 */
static int
cl_send_get_items_iter(sr_session_ctx_t *session, const char *path, bool recursive, size_t offset, size_t limit, Sr__Msg **msg_resp){
    Sr__Msg *msg_req = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(session, session->conn_ctx, path, msg_resp);

    /* prepare get_item message */
    rc = sr_pb_req_alloc(SR__OPERATION__GET_ITEMS, session->id, &msg_req);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate get_items message.");
        goto cleanup;
    }

    /* fill in the path */
    msg_req->request->get_items_req->path = strdup(path);
    if (NULL == msg_req->request->get_items_req->path) {
        SR_LOG_ERR_MSG("Cannot allocate get_items path.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }
    msg_req->request->get_items_req->limit = limit;
    msg_req->request->get_items_req->offset = offset;
    msg_req->request->get_items_req->recursive =recursive;
    msg_req->request->get_items_req->has_recursive = true;
    msg_req->request->get_items_req->has_limit = true;
    msg_req->request->get_items_req->has_offset = true;


    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, msg_resp, SR__OPERATION__GET_ITEMS);
    if (SR_ERR_NOT_FOUND == rc){
        goto cleanup;
    }
    else if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Error by processing of get_items request.");
        goto cleanup;
    }

    sr__msg__free_unpacked(msg_req, NULL);

    return rc;

    cleanup:
    if (NULL != msg_req) {
        sr__msg__free_unpacked(msg_req, NULL);
    }
    return rc;
}

int
sr_connect(const char *app_name, const sr_conn_options_t opts, sr_conn_ctx_t **conn_ctx_p)
{
    sr_conn_ctx_t *ctx = NULL;
    int rc = SR_ERR_OK;
    char socket_path[PATH_MAX] = { 0, };

    CHECK_NULL_ARG2(app_name, conn_ctx_p);

    SR_LOG_DBG_MSG("Connecting to Sysrepo Engine.");

    /* initialize the context */
    ctx = calloc(1, sizeof(*ctx));
    if (NULL == ctx) {
        SR_LOG_ERR_MSG("Cannot allocate memory for connection context.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    /* init connection mutext */
    rc = pthread_mutex_init(&ctx->lock, NULL);
    if (0 != rc) {
        SR_LOG_ERR_MSG("Cannot initialize connection mutex.");
        rc = SR_ERR_INIT_FAILED;
        goto cleanup;
    }

    /* check if this is the primary connection */
    pthread_mutex_lock(&primary_lock);
    if (NULL == primary_connection) {
        /* this is the first connection - set as primary */
        primary_connection = ctx;
        ctx->primary = true;
        /* initialize logging */
        sr_logger_init(app_name);
    }
    pthread_mutex_unlock(&primary_lock);

    /* attempt to connect to sysrepo daemon socket */
    rc = cl_socket_connect(ctx, SR_DAEMON_SOCKET);
    if (SR_ERR_OK != rc) {
        if (opts & SR_CONN_DAEMON_REQUIRED) {
            SR_LOG_ERR_MSG("Sysrepo daemon not detected while library mode disallowed.");
            if ((opts & SR_CONN_DAEMON_START) && (0 == getuid())) {
                /* sysrepo daemon start requested and process is running under root privileges */
                int ret = system("sysrepod");
                if (0 == ret) {
                    SR_LOG_INF_MSG("Sysrepo daemon has been started.");
                } else {
                    SR_LOG_WRN("Unable to start sysrepo daemon, error code=%d.", ret);
                }
            }
            goto cleanup;
        } else {
            SR_LOG_WRN_MSG("Sysrepo daemon not detected. Connecting to local Sysrepo Engine.");

            /* connect in library mode */
            ctx->library_mode = true;
            snprintf(socket_path, PATH_MAX, "%s-%d.sock", CL_LCONN_PATH_PREFIX, getpid());

            /* attempt to connect to our own sysrepo engine (local engine may already exist) */
            rc = cl_socket_connect(ctx, socket_path);
            if (SR_ERR_OK != rc) {
                /* initialize our own sysrepo engine and attempt to connect again */
                SR_LOG_INF_MSG("Local Sysrepo Engine not running yet, initializing new one.");

                rc = cl_engine_init_local(ctx, socket_path);
                if (SR_ERR_OK != rc) {
                    SR_LOG_ERR_MSG("Unable to start local sysrepo engine.");
                    goto cleanup;
                }
                rc = cl_socket_connect(ctx, socket_path);
                if (SR_ERR_OK != rc) {
                    SR_LOG_ERR_MSG("Unable to connect to the local sysrepo engine.");
                    goto cleanup;
                }
            }
            SR_LOG_INF("Connected to local Sysrepo Engine at socket=%s", socket_path);
        }
    } else {
        SR_LOG_INF("Connected to daemon Sysrepo Engine at socket=%s", SR_DAEMON_SOCKET);
    }

    *conn_ctx_p = ctx;
    return SR_ERR_OK;

cleanup:
    if ((NULL != ctx) && (NULL != ctx->local_cm)) {
        cm_cleanup(ctx->local_cm);
    }
    if (NULL != ctx) {
        pthread_mutex_destroy(&ctx->lock);
    }
    free(ctx);
    return rc;
}

void
sr_disconnect(sr_conn_ctx_t *conn_ctx)
{
    sr_session_list_t *session = NULL, *tmp = NULL;

    if (NULL != conn_ctx) {
        if (NULL != conn_ctx->local_cm) {
            /* destroy our own sysrepo engine */
            cm_stop(conn_ctx->local_cm);
            cm_cleanup(conn_ctx->local_cm);
        }

        if (conn_ctx->primary) {
            /* destroy global resources */
            pthread_mutex_lock(&primary_lock);
            sr_logger_cleanup();
            primary_connection = NULL;
            pthread_mutex_unlock(&primary_lock);
        }

        /* destroy all sessions */
        session = conn_ctx->session_list;
        while (NULL != session) {
            tmp = session;
            session = session->next;
            cl_session_cleanup(tmp->session);
            free(tmp);
        }

        pthread_mutex_destroy(&conn_ctx->lock);
        free(conn_ctx->msg_buf);
        close(conn_ctx->fd);
        free(conn_ctx);
    }
}

int
sr_session_start(sr_conn_ctx_t *conn_ctx, sr_datastore_t datastore, sr_session_ctx_t **session_p)
{
    return sr_session_start_user(conn_ctx, NULL, datastore, session_p);
}

int
sr_session_start_user(sr_conn_ctx_t *conn_ctx, const char *user_name, sr_datastore_t datastore, sr_session_ctx_t **session_p)
{
    sr_session_ctx_t *session = NULL;
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(conn_ctx, session_p);

    /* initialize session context */
    session = calloc(1, sizeof(*session));
    if (NULL == session) {
        SR_LOG_ERR_MSG("Cannot allocate memory for session context.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }
    session->conn_ctx = conn_ctx;

    /* initialize session mutext */
    rc = pthread_mutex_init(&session->lock, NULL);
    if (0 != rc) {
        SR_LOG_ERR_MSG("Cannot initialize session mutex.");
        rc = SR_ERR_INIT_FAILED;
        goto cleanup;
    }

    /* prepare session_start message */
    rc = sr_pb_req_alloc(SR__OPERATION__SESSION_START, /* undefined session id */ 0, &msg_req);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate session_start message.");
        goto cleanup;
    }
    msg_req->request->session_start_req->datastore = sr_datastore_sr_to_gpb(datastore);

    /* set user name if provided */
    if (NULL != user_name) {
        msg_req->request->session_start_req->user_name = strdup(user_name);
        if (NULL == msg_req->request->session_start_req->user_name) {
            SR_LOG_ERR_MSG("Cannot duplicate user name for session_start message.");
            rc = SR_ERR_NOMEM;
            goto cleanup;
        }
    }

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, SR__OPERATION__SESSION_START);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Error by processing of session_stop request.");
        goto cleanup;
    }

    session->id = msg_resp->response->session_start_resp->session_id;
    sr__msg__free_unpacked(msg_req, NULL);
    sr__msg__free_unpacked(msg_resp, NULL);

    /* store the session the in connection */
    rc = cl_conn_add_session(conn_ctx, session);
    if (SR_ERR_OK != rc) {
        SR_LOG_WRN_MSG("Error by adding the session to the connection session list.");
    }

    *session_p = session;
    return SR_ERR_OK;

cleanup:
    if (NULL != msg_req) {
        sr__msg__free_unpacked(msg_req, NULL);
    }
    if (NULL != msg_resp) {
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    if (NULL != session) {
        pthread_mutex_destroy(&session->lock);
    }
    free(session);
    return rc;
}

int
sr_session_stop(sr_session_ctx_t *session)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, session->conn_ctx);

    cl_session_clear_errors(session);

    /* prepare session_stop message */
    rc = sr_pb_req_alloc(SR__OPERATION__SESSION_STOP, session->id, &msg_req);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate session_stop message.");
        goto cleanup;
    }
    msg_req->request->session_stop_req->session_id = session->id;

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, SR__OPERATION__SESSION_STOP);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Error by processing of session_stop request.");
        goto cleanup;
    }

    /* remove the session from connection */
    rc = cl_conn_remove_session(session->conn_ctx, session);
    if (SR_ERR_OK != rc) {
        SR_LOG_WRN_MSG("Error by removing the session from the connection session list.");
    }

    sr__msg__free_unpacked(msg_req, NULL);
    sr__msg__free_unpacked(msg_resp, NULL);

    cl_session_cleanup(session);

    return SR_ERR_OK; /* do not use cl_session_return - session has been freed one line above */

cleanup:
    if (NULL != msg_req) {
        sr__msg__free_unpacked(msg_req, NULL);
    }
    if (NULL != msg_resp) {
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    return cl_session_return(session, rc);
}

int
sr_session_refresh(sr_session_ctx_t *session)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, session->conn_ctx);

    cl_session_clear_errors(session);

    /* prepare session_stop message */
    rc = sr_pb_req_alloc(SR__OPERATION__SESSION_REFRESH, session->id, &msg_req);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate session_data_refresh message.");
        goto cleanup;
    }

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, SR__OPERATION__SESSION_REFRESH);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Error by processing of session_data_refresh request.");
        goto cleanup;
    }

    sr__msg__free_unpacked(msg_req, NULL);
    sr__msg__free_unpacked(msg_resp, NULL);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr__msg__free_unpacked(msg_req, NULL);
    }
    if (NULL != msg_resp) {
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    return cl_session_return(session, rc);
}

int
sr_list_schemas(sr_session_ctx_t *session, sr_schema_t **schemas, size_t *schema_cnt)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(session, session->conn_ctx, schemas, schema_cnt);

    cl_session_clear_errors(session);

    /* prepare list_schemas message */
    rc = sr_pb_req_alloc(SR__OPERATION__LIST_SCHEMAS, session->id, &msg_req);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate list_schemas message.");
        goto cleanup;
    }

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, SR__OPERATION__LIST_SCHEMAS);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Error by processing of list_schemas request.");
        goto cleanup;
    }

    /* copy schemas from response to output argument */
    rc = sr_schemas_gpb_to_sr((const Sr__Schema**)msg_resp->response->list_schemas_resp->schemas,
            msg_resp->response->list_schemas_resp->n_schemas, schemas);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Unable to copy schemas from GPB.");
        goto cleanup;
    }
    *schema_cnt = msg_resp->response->list_schemas_resp->n_schemas;

    sr__msg__free_unpacked(msg_req, NULL);
    sr__msg__free_unpacked(msg_resp, NULL);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr__msg__free_unpacked(msg_req, NULL);
    }
    if (NULL != msg_resp) {
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    return cl_session_return(session, rc);
}

int
sr_get_schema(sr_session_ctx_t *session, const char *module_name, const char *module_revision,
        const char *submodule_name, sr_schema_format_t format, char **schema_content)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(session, session->conn_ctx, module_name, schema_content);

    cl_session_clear_errors(session);

    /* prepare get_schema message */
    rc = sr_pb_req_alloc(SR__OPERATION__GET_SCHEMA, session->id, &msg_req);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate get_schema message.");
        goto cleanup;
    }

    /* set arguments */
    msg_req->request->get_schema_req->module_name = strdup(module_name);
    if (NULL == msg_req->request->get_schema_req->module_name) {
        SR_LOG_ERR_MSG("Cannot duplicate module name.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }
    if (NULL != submodule_name) {
        msg_req->request->get_schema_req->submodule_name = strdup(submodule_name);
        if (NULL == msg_req->request->get_schema_req->submodule_name) {
            SR_LOG_ERR_MSG("Cannot duplicate submodule name.");
            rc = SR_ERR_NOMEM;
            goto cleanup;
        }
    }
    if(NULL != module_revision) {
        msg_req->request->get_schema_req->revision = strdup(module_revision);
        if (NULL == msg_req->request->get_schema_req->revision) {
            SR_LOG_ERR_MSG("Cannot duplicate schema revision.");
            rc = SR_ERR_NOMEM;
            goto cleanup;
        }
    }
    msg_req->request->get_schema_req->yang_format = (format == SR_SCHEMA_YANG);

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, SR__OPERATION__GET_SCHEMA);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Error by processing of get_schema request.");
        goto cleanup;
    }

    /* move pointers to schema content, so we don't need to duplicate the memory */
    if (NULL != msg_resp->response->get_schema_resp->schema_content) {
        *schema_content = msg_resp->response->get_schema_resp->schema_content;
        msg_resp->response->get_schema_resp->schema_content = NULL;
    }

    sr__msg__free_unpacked(msg_req, NULL);
    sr__msg__free_unpacked(msg_resp, NULL);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr__msg__free_unpacked(msg_req, NULL);
    }
    if (NULL != msg_resp) {
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    return cl_session_return(session, rc);
}

int
sr_feature_enable(sr_session_ctx_t *session, const char *module_name, const char *feature_name, bool enable)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(session, session->conn_ctx, module_name, feature_name);

    cl_session_clear_errors(session);

    /* prepare feature_enable message */
    rc = sr_pb_req_alloc(SR__OPERATION__FEATURE_ENABLE, session->id, &msg_req);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate feature_enable message.");
        goto cleanup;
    }

    /* set arguments */
    msg_req->request->feature_enable_req->module_name = strdup(module_name);
    if (NULL == msg_req->request->feature_enable_req->module_name) {
        SR_LOG_ERR_MSG("Cannot duplicate module name.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }
    msg_req->request->feature_enable_req->feature_name = strdup(feature_name);
    if (NULL == msg_req->request->feature_enable_req->feature_name) {
        SR_LOG_ERR_MSG("Cannot feature name.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }
    msg_req->request->feature_enable_req->enable = enable;

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, SR__OPERATION__FEATURE_ENABLE);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Error by processing of feature_enable request.");
        goto cleanup;
    }

    sr__msg__free_unpacked(msg_req, NULL);
    sr__msg__free_unpacked(msg_resp, NULL);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr__msg__free_unpacked(msg_req, NULL);
    }
    if (NULL != msg_resp) {
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    return cl_session_return(session, rc);
}

int
sr_get_item(sr_session_ctx_t *session, const char *path, sr_val_t **value)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(session, session->conn_ctx, path, value);

    cl_session_clear_errors(session);

    /* prepare get_item message */
    rc = sr_pb_req_alloc(SR__OPERATION__GET_ITEM, session->id, &msg_req);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate get_item message.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    /* fill in the path */
    msg_req->request->get_item_req->path = strdup(path);
    if (NULL == msg_req->request->get_item_req->path) {
        SR_LOG_ERR_MSG("Cannot allocate get_item path.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, SR__OPERATION__GET_ITEM);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Error by processing of get_item request.");
        goto cleanup;
    }

    /* duplicate the content of gpb to sr_val_t */
    rc = sr_dup_gpb_to_val_t(msg_resp->response->get_item_resp->value, value);
    if (SR_ERR_OK != rc){
        SR_LOG_ERR_MSG("Copying from gpb to sr_val_t failed");
        goto cleanup;
    }

    sr__msg__free_unpacked(msg_req, NULL);
    sr__msg__free_unpacked(msg_resp, NULL);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr__msg__free_unpacked(msg_req, NULL);
    }
    if (NULL != msg_resp) {
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    return cl_session_return(session, rc);
}

int
sr_get_items(sr_session_ctx_t *session, const char *path, sr_val_t **values, size_t *value_cnt)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    sr_val_t *vals = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(session, session->conn_ctx, path, values, value_cnt);

    cl_session_clear_errors(session);

    /* prepare get_item message */
    rc = sr_pb_req_alloc(SR__OPERATION__GET_ITEMS, session->id, &msg_req);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate get_items message.");
        goto cleanup;
    }

    /* fill in the path */
    msg_req->request->get_items_req->path = strdup(path);
    if (NULL == msg_req->request->get_items_req->path) {
        SR_LOG_ERR_MSG("Cannot allocate get_items path.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, SR__OPERATION__GET_ITEMS);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Error by processing of get_items request.");
        goto cleanup;
    }

    /* allocate the array of sr_val_t */
    size_t cnt = msg_resp->response->get_items_resp->n_values;
    vals = calloc(cnt, sizeof(*vals));
    if (NULL == vals){
        SR_LOG_ERR_MSG("Cannot allocate array of values.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    /* copy the content of gpb values to sr_val_t */
    for (size_t i = 0; i < cnt; i++) {
        rc = sr_copy_gpb_to_val_t(msg_resp->response->get_items_resp->values[i], &vals[i]);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Copying from gpb to sr_val_t failed");
            for (size_t j = 0; j < i; j++) {
                sr_free_val_content(&vals[i]);
            }
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
    }

    *values = vals;
    *value_cnt = cnt;

    sr__msg__free_unpacked(msg_req, NULL);
    sr__msg__free_unpacked(msg_resp, NULL);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    free(vals);
    if (NULL != msg_req) {
        sr__msg__free_unpacked(msg_req, NULL);
    }
    if (NULL != msg_resp) {
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    return cl_session_return(session, rc);
}


int
sr_get_items_iter(sr_session_ctx_t *session, const char *path, bool recursive, sr_val_iter_t **iter)
{
    Sr__Msg *msg_resp = NULL;
    sr_val_iter_t *it = NULL;
    int rc = SR_ERR_OK;

    cl_session_clear_errors(session);

    CHECK_NULL_ARG4(session, session->conn_ctx, path, iter);
    rc = cl_send_get_items_iter(session, path, recursive, 0, CL_GET_ITEMS_FETCH_LIMIT, &msg_resp);
    if (SR_ERR_NOT_FOUND == rc){
        SR_LOG_DBG("No items found for xpath '%s'", path);
        /* SR_ERR_NOT_FOUND will be returned on get_item_next call */
        rc = SR_ERR_OK;
    }
    else if (SR_ERR_OK != rc){
        SR_LOG_ERR("Sending get_items request failed '%s'", path);
        goto cleanup;
    }

    it = calloc(1, sizeof(*it));
    if (NULL == it){
        SR_LOG_ERR_MSG("Memory allocation failed");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    it->index = 0;
    it->count = msg_resp->response->get_items_resp->n_values;

    it->recursive = recursive;
    it->path = strdup(path);
    if (NULL == it->path){
        SR_LOG_ERR_MSG("Duplication of path failed");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    it->buff_values = calloc(it->count, sizeof(*it->buff_values));
    if (NULL == it->buff_values){
        SR_LOG_ERR_MSG("Memory allocation failed");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    /* copy the content of gpb to sr_val_t */
    for (size_t i = 0; i < it->count; i++){
        rc = sr_dup_gpb_to_val_t(msg_resp->response->get_items_resp->values[i], &it->buff_values[i]);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Copying from gpb to sr_val_t failed");
            sr_free_values_arr(it->buff_values, i);
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
    }

    *iter = it;

    sr__msg__free_unpacked(msg_resp, NULL);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_resp) {
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    if (NULL != it){
        if (NULL != it->path){
            free(it->path);
        }
        free(it);
    }
    return cl_session_return(session, rc);
}

int
sr_get_item_next(sr_session_ctx_t *session, sr_val_iter_t *iter, sr_val_t **value)
{
    int rc = SR_ERR_OK;
    Sr__Msg *msg_resp = NULL;

    CHECK_NULL_ARG3(session, iter, value);

    cl_session_clear_errors(session);

    if (0 == iter->count) {
        /* No more data to be read */
        *value = NULL;
        return SR_ERR_NOT_FOUND;
    } else if (iter->index < iter->count) {
        /* There are buffered data */
        *value = iter->buff_values[iter->index++];
        iter->offset++;
    } else {
        /* Fetch more items */
        rc = cl_send_get_items_iter(session, iter->path, iter->recursive, iter->offset,
                CL_GET_ITEMS_FETCH_LIMIT, &msg_resp);
        if (SR_ERR_NOT_FOUND == rc){
            SR_LOG_DBG("All items has been read for path '%s'", iter->path);
            goto cleanup;
        } else if (SR_ERR_OK != rc){
            SR_LOG_ERR("Fetching more items failed '%s'", iter->path);
            goto cleanup;
        }

        size_t received_cnt = msg_resp->response->get_items_resp->n_values;
        if (0 == received_cnt) {
            /* There is no more data to be read */
            *value = NULL;
            rc = SR_ERR_NOT_FOUND;
            goto cleanup;
        }

        if (iter->count < received_cnt) {
            /* realloc the array for buffered values pointers */
            sr_val_t **tmp = NULL;
            tmp = realloc(iter->buff_values, received_cnt * sizeof(*iter->buff_values));
            if (NULL == tmp) {
                SR_LOG_ERR_MSG("Memory allocation failed");
                rc = SR_ERR_NOMEM;
                goto cleanup;
            }
            iter->buff_values = tmp;
        }

        iter->index = 0;
        iter->count = received_cnt;

        /* copy the content of gpb to sr_val_t*/
        for (size_t i = 0; i < iter->count; i++){
            rc = sr_dup_gpb_to_val_t(msg_resp->response->get_items_resp->values[i], &iter->buff_values[i]);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR_MSG("Copying from gpb to sr_val_t failed");
                sr_free_values_arr(iter->buff_values, i);
                iter->count = 0;
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
        }
        *value = iter->buff_values[iter->index++];
        iter->offset++;
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_resp){
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    return cl_session_return(session, rc);
}

void
sr_free_val_iter(sr_val_iter_t *iter){
    if (NULL == iter){
        return;
    }
    free(iter->path);
    iter->path = NULL;
    if (NULL != iter->buff_values) {
        /* free items that has not been passed to user already*/
        sr_free_values_arr_range(iter->buff_values, iter->index, iter->count);
        iter->buff_values = NULL;
    }
    free(iter);
}

int
sr_set_item(sr_session_ctx_t *session, const char *path, const sr_val_t *value, const sr_edit_options_t opts)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(session, session->conn_ctx, path);

    cl_session_clear_errors(session);

    /* prepare get_item message */
    rc = sr_pb_req_alloc(SR__OPERATION__SET_ITEM, session->id, &msg_req);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate set_item message.");
        goto cleanup;
    }

    /* fill in the path and options */
    msg_req->request->set_item_req->path = strdup(path);
    if (NULL == msg_req->request->set_item_req->path) {
        SR_LOG_ERR_MSG("Cannot allocate set_item path.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }
    msg_req->request->set_item_req->options = opts;

    /* duplicate the content of sr_val_t to gpb */
    if (NULL != value) {
        rc = sr_dup_val_t_to_gpb(value, &msg_req->request->set_item_req->value);
        if (SR_ERR_OK != rc){
            SR_LOG_ERR_MSG("Copying from sr_val_t to gpb failed.");
            goto cleanup;
        }
    }

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, SR__OPERATION__SET_ITEM);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Error by processing of set_item request.");
        goto cleanup;
    }

    sr__msg__free_unpacked(msg_req, NULL);
    sr__msg__free_unpacked(msg_resp, NULL);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr__msg__free_unpacked(msg_req, NULL);
    }
    if (NULL != msg_resp) {
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    return cl_session_return(session, rc);
}

int
sr_delete_item(sr_session_ctx_t *session, const char *path, const sr_edit_options_t opts)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(session, session->conn_ctx, path);

    cl_session_clear_errors(session);

    /* prepare get_item message */
    rc = sr_pb_req_alloc(SR__OPERATION__DELETE_ITEM, session->id, &msg_req);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate delete_item message.");
        goto cleanup;
    }

    /* fill in the path and options */
    msg_req->request->delete_item_req->path = strdup(path);
    if (NULL == msg_req->request->delete_item_req->path) {
        SR_LOG_ERR_MSG("Cannot allocate delete_item path.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }
    msg_req->request->delete_item_req->options = opts;

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, SR__OPERATION__DELETE_ITEM);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Error by processing of delete_item request.");
        goto cleanup;
    }

    sr__msg__free_unpacked(msg_req, NULL);
    sr__msg__free_unpacked(msg_resp, NULL);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr__msg__free_unpacked(msg_req, NULL);
    }
    if (NULL != msg_resp) {
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    return cl_session_return(session, rc);
}

int
sr_move_item(sr_session_ctx_t *session, const char *path, const sr_move_direction_t direction)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(session, session->conn_ctx, path);

    cl_session_clear_errors(session);

    /* prepare get_item message */
    rc = sr_pb_req_alloc(SR__OPERATION__MOVE_ITEM, session->id, &msg_req);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate move_item message.");
        goto cleanup;
    }

    /* fill in the path and direction */
    msg_req->request->move_item_req->path = strdup(path);
    if (NULL == msg_req->request->move_item_req->path) {
        SR_LOG_ERR_MSG("Cannot allocate move_item path.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }
    msg_req->request->move_item_req->direction = sr_move_direction_sr_to_gpb(direction);

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, SR__OPERATION__MOVE_ITEM);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Error by processing of move_item request.");
        goto cleanup;
    }

    sr__msg__free_unpacked(msg_req, NULL);
    sr__msg__free_unpacked(msg_resp, NULL);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr__msg__free_unpacked(msg_req, NULL);
    }
    if (NULL != msg_resp) {
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    return cl_session_return(session, rc);
}

int
sr_validate(sr_session_ctx_t *session)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    Sr__ValidateResp *validate_resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, session->conn_ctx);

    cl_session_clear_errors(session);

    /* prepare validate message */
    rc = sr_pb_req_alloc(SR__OPERATION__VALIDATE, session->id, &msg_req);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate validate message.");
        goto cleanup;
    }

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, SR__OPERATION__VALIDATE);
    if ((SR_ERR_OK != rc) && (SR_ERR_VALIDATION_FAILED != rc)) {
        SR_LOG_ERR_MSG("Error by processing of validate request.");
        goto cleanup;
    }

    validate_resp = msg_resp->response->validate_resp;
    if (SR_ERR_VALIDATION_FAILED == rc) {
        SR_LOG_ERR("Validate operation failed with %zu error(s).", validate_resp->n_errors);

        /* store validation errors within the session */
        if (validate_resp->n_errors > 0) {
            cl_session_set_errors(session, validate_resp->errors, validate_resp->n_errors);
        }
    }

    sr__msg__free_unpacked(msg_req, NULL);
    sr__msg__free_unpacked(msg_resp, NULL);

    return cl_session_return(session, rc);

cleanup:
    if (NULL != msg_req) {
        sr__msg__free_unpacked(msg_req, NULL);
    }
    if (NULL != msg_resp) {
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    return cl_session_return(session, rc);
}

int
sr_commit(sr_session_ctx_t *session)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    Sr__CommitResp *commit_resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, session->conn_ctx);

    cl_session_clear_errors(session);

    /* prepare commit message */
    rc = sr_pb_req_alloc(SR__OPERATION__COMMIT, session->id, &msg_req);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate validate message.");
        goto cleanup;
    }

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, SR__OPERATION__COMMIT);
    if ((SR_ERR_OK != rc) && (SR_ERR_COMMIT_FAILED != rc)) {
        SR_LOG_ERR_MSG("Error by processing of commit request.");
        goto cleanup;
    }

    commit_resp = msg_resp->response->commit_resp;
    if (SR_ERR_COMMIT_FAILED == rc) {
        SR_LOG_ERR("Commit operation failed with %zu error(s).", commit_resp->n_errors);

        /* store commit errors within the session */
        if (commit_resp->n_errors > 0) {
            cl_session_set_errors(session, commit_resp->errors, commit_resp->n_errors);
        }
    }

    sr__msg__free_unpacked(msg_req, NULL);
    sr__msg__free_unpacked(msg_resp, NULL);

    return cl_session_return(session, rc);

cleanup:
    if (NULL != msg_req) {
        sr__msg__free_unpacked(msg_req, NULL);
    }
    if (NULL != msg_resp) {
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    return cl_session_return(session, rc);
}

int
sr_discard_changes(sr_session_ctx_t *session)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, session->conn_ctx);

    cl_session_clear_errors(session);

    /* prepare discard_changes message */
    rc = sr_pb_req_alloc(SR__OPERATION__DISCARD_CHANGES, session->id, &msg_req);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate discard_changes message.");
        goto cleanup;
    }

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, SR__OPERATION__DISCARD_CHANGES);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Error by processing of discard_changes request.");
        goto cleanup;
    }

    sr__msg__free_unpacked(msg_req, NULL);
    sr__msg__free_unpacked(msg_resp, NULL);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr__msg__free_unpacked(msg_req, NULL);
    }
    if (NULL != msg_resp) {
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    return cl_session_return(session, rc);
}

int
sr_lock_datastore(sr_session_ctx_t *session)
{
    return sr_lock_module(session, NULL);
}

int
sr_unlock_datastore(sr_session_ctx_t *session)
{
    return sr_unlock_module(session, NULL);
}

int
sr_lock_module(sr_session_ctx_t *session, const char *module_name)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, session->conn_ctx);

    cl_session_clear_errors(session);

    /* prepare lock message */
    rc = sr_pb_req_alloc(SR__OPERATION__LOCK, session->id, &msg_req);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate lock message.");
        goto cleanup;
    }

    /* fill-in model name (if provided) */
    if (NULL != module_name) {
        msg_req->request->lock_req->module_name = strdup(module_name);
        if (NULL == msg_req->request->lock_req->module_name) {
            SR_LOG_ERR_MSG("Could not duplicate module name.");
            rc = SR_ERR_NOMEM;
            goto cleanup;
        }
    }

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, SR__OPERATION__LOCK);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Error by processing of lock request.");
        goto cleanup;
    }

    sr__msg__free_unpacked(msg_req, NULL);
    sr__msg__free_unpacked(msg_resp, NULL);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr__msg__free_unpacked(msg_req, NULL);
    }
    if (NULL != msg_resp) {
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    return cl_session_return(session, rc);
}

int
sr_unlock_module(sr_session_ctx_t *session, const char *module_name)
{
    Sr__Msg *msg_req = NULL, *msg_resp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, session->conn_ctx);

    cl_session_clear_errors(session);

    /* prepare lock message */
    rc = sr_pb_req_alloc(SR__OPERATION__UNLOCK, session->id, &msg_req);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate unlock message.");
        goto cleanup;
    }

    /* fill-in model name (if provided) */
    if (NULL != module_name) {
        msg_req->request->unlock_req->module_name = strdup(module_name);
        if (NULL == msg_req->request->unlock_req->module_name) {
            SR_LOG_ERR_MSG("Could not duplicate module name.");
            rc = SR_ERR_NOMEM;
            goto cleanup;
        }
    }

    /* send the request and receive the response */
    rc = cl_request_process(session, msg_req, &msg_resp, SR__OPERATION__UNLOCK);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Error by processing of unlock request.");
        goto cleanup;
    }

    sr__msg__free_unpacked(msg_req, NULL);
    sr__msg__free_unpacked(msg_resp, NULL);

    return cl_session_return(session, SR_ERR_OK);

cleanup:
    if (NULL != msg_req) {
        sr__msg__free_unpacked(msg_req, NULL);
    }
    if (NULL != msg_resp) {
        sr__msg__free_unpacked(msg_resp, NULL);
    }
    return cl_session_return(session, rc);
}

int
sr_get_last_error(sr_session_ctx_t *session, const sr_error_info_t **error_info)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, error_info);

    pthread_mutex_lock(&session->lock);

    if (0 == session->error_cnt) {
        /* no detailed error information, let's create it from the last error code */
        pthread_mutex_unlock(&session->lock);
        rc = cl_session_set_error(session, sr_strerror(session->last_error), NULL);
        if (SR_ERR_OK != rc) {
            return rc;
        }
    }

    *error_info = session->error_info;
    pthread_mutex_unlock(&session->lock);

    return session->last_error;
}

int
sr_get_last_errors(sr_session_ctx_t *session, const sr_error_info_t **error_info, size_t *error_cnt)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(session, error_info, error_cnt);

    pthread_mutex_lock(&session->lock);

    if (0 == session->error_cnt) {
        /* no detailed error information, let's create it from the last error code */
        pthread_mutex_unlock(&session->lock);
        rc = cl_session_set_error(session, sr_strerror(session->last_error), NULL);
        if (SR_ERR_OK != rc) {
            return rc;
        }
    }

    *error_info = session->error_info;
    *error_cnt = session->error_cnt;
    pthread_mutex_unlock(&session->lock);

    return session->last_error;
}
