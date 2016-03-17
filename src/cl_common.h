/**
 * @file cl_common.h
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

#ifndef CL_COMMON_H_
#define CL_COMMON_H_

#include <pthread.h>
#include "sr_common.h"

typedef struct cm_ctx_s cm_ctx_t;

/**
 * @brief Timeout (in seconds) for waiting for a response from server by each request.
 */
#define CL_REQUEST_TIMEOUT 2

/**
 * @brief Connection context used to identify a connection to sysrepo datastore.
 */
typedef struct sr_conn_ctx_s {
    int fd;                                  /**< File descriptor of the connection. */
    const char *dst_address;                 /**< Destination socket address. */
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
 * @brief Session context used to identify a configuration session.
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
 * @brief Linked-list of sessions.
 */
typedef struct sr_session_list_s {
    sr_session_ctx_t *session;       /**< Session context. */
    struct sr_session_list_s *next;  /**< Next element in the linked-list. */
} sr_session_list_t;

/**
 * @brief TODO
 */
int cl_connection_create(sr_conn_ctx_t **conn_ctx);

/**
 * @brief
 */
void cl_connection_cleanup(sr_conn_ctx_t *conn_ctx);

/**
 * @brief
 */
int cl_session_create(sr_conn_ctx_t *conn_ctx, sr_session_ctx_t **session);

/**
 * @brief Cleans up a client library -local session.
 */
void cl_session_cleanup(sr_session_ctx_t *session);

/**
 * @brief Connects the client to provided unix-domain socket.
 */
int cl_socket_connect(sr_conn_ctx_t *conn_ctx, const char *socket_path);

#endif /* CL_COMMON_H_ */
