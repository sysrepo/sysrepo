/**
 * @file session_manager.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief API of Sysrepo Engine's Session Manager.
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

#ifndef SESSION_MANAGER_H_
#define SESSION_MANAGER_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#include "access_control.h"

typedef struct cm_session_ctx_s cm_session_ctx_t;        /**< Forward-declaration of Connection Manager's session context. */
typedef struct cm_connection_ctx_s cm_connection_ctx_t;  /**< Forward-declaration of Connection Manager's connection context. */

/**
 * @defgroup sm Session Manager
 * @{
 *
 * @brief Session manager tracks information about all active sysrepo sessions
 * (see ::sm_session_t), and connections (see ::sm_connection_t).
 *
 * Sessions and connections are tied together, one connection can be used
 * to serve multiple sessions.
 *
 * SM allows fast session lookup by provided session_id (::sm_session_t#id
 * - see ::sm_session_find_id) and connection lookup by associated file descriptor
 * (::sm_connection_t#fd - see ::sm_connection_find_fd).
 */

/**
 * @brief Opaque Session Manager context used to identify particular instance of
 * Session Manager.
 */
typedef struct sm_ctx_s sm_ctx_t;

/**
 * @brief Callback called by session / connection cleanup used to cleanup CM-related data.
 */
typedef void (*sm_cleanup_cb)(void *ctx);

/**
 * @brief Session context structure, represents one particular session.
 */
typedef struct sm_session_s {
    uint32_t id;                         /**< Auto-generated unique session ID (do not modify it). */
    struct sm_connection_s *connection;  /**< Connection associated with this session. */

    sm_ctx_t *sm_ctx;                    /**< Associated Session Manager context. */
    cm_session_ctx_t *cm_data;           /**< Connection Manager-related data. */

    ac_ucred_t credentials;              /**< Credentials of the peer. */
} sm_session_t;

/**
 * @brief Linked-list of sessions.
 */
typedef struct sm_session_list_s {
    sm_session_t *session;           /**< Session context. */
    struct sm_session_list_s *next;  /**< Pointer to the next session context. */
} sm_session_list_t;

/**
 * @brief Connection type.
 */
typedef enum {
    CM_AF_UNIX_CLIENT,  /**< The other side is an unix-domain socket client. */
    CM_AF_UNIX_SERVER,  /**< The other side is an unix-domain socket server. */
} sm_connection_type_t;

/**
 * @brief Connection context structure, represents one particular connection.
 * Multiple sessions can be assigned to the same connection.
 */
typedef struct sm_connection_s {
    sm_connection_type_t type;        /**< Type of the connection. */
    sm_session_list_t *session_list;  /**< List of sessions associated to the connection. */

    int fd;                           /**< File descriptor of the connection. */
    uid_t uid;                        /**< Peer's effective user ID. */
    gid_t gid;                        /**< Peer's effective group ID. */
    bool close_requested;             /**< Connection close requested. */

    sm_ctx_t *sm_ctx;                 /**< Associated Session Manager context. */
    cm_connection_ctx_t *cm_data;     /**< Connection Manager-related data. */
} sm_connection_t;

/**
 * @brief Initializes Session Manager.
 *
 * @param[in] session_cleanup_cb Callback called by session cleanup (used to free CM-related data).
 * @param[in] connection_cleanup_cb Callback called by connection cleanup (used to free CM-related data).
 * @param[out] sm_ctx Allocated Session Manager context that can be used in subsequent SM requests.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sm_init(sm_cleanup_cb session_cleanup_cb, sm_cleanup_cb connection_cleanup_cb, sm_ctx_t **sm_ctx);

/**
 * @brief Cleans up Session Manager.
 *
 * All outstanding sessions will be automatically dropped and all memory held by
 * this Session Manager instance will be freed.
 *
 * @param[in] sm_ctx Session Manager context.
 *
 * @return Error code (SR_ERR_OK on success).
 */
void sm_cleanup(sm_ctx_t *sm_ctx);

/**
 * @brief Starts a new connection identified by provided file descriptor.
 *
 * Lookup for the connection identified by given session ID is possible with
 * ::sm_connection_find_fd.
 *
 * @param[in] sm_ctx Session Manager context.
 * @param[in] type Type of the connection.
 * @param[in] fd File descriptor of the connection.
 * @param[out] connection Allocated and initialized connection context.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sm_connection_start(const sm_ctx_t *sm_ctx, const sm_connection_type_t type,
        const int fd, sm_connection_t **connection);

/**
 * @brief Stops the connection.
 *
 * All connection-related memory held by Session Manager will be freed.
 *
 * @note Sessions assigned to the connection won't be automatically dropped,
 * they will be only unassigned from the connection (their pointers to the
 * connection will become NULL) and explicit ::sm_session_drop is needed.
 *
 * @param[in] sm_ctx Session Manager context.
 * @param[in] connection Connection context.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sm_connection_stop(const sm_ctx_t *sm_ctx,  sm_connection_t *connection);

/**
 * @brief Creates new session and ties it with provided connection.
 *
 * A new unique session ID will be assigned and set to the allocated session
 * context (::sm_session_t#id). Lookup for the session identified by given session
 * ID is possible with ::sm_session_find_id.
 *
 * @param[in] sm_ctx Session Manager context.
 * @param[in] connection Connection where the session belongs.
 * @param[in] effective_user Effective user name of the other side.
 * @param[out] session Allocated and initialized session context.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sm_session_create(const sm_ctx_t *sm_ctx, sm_connection_t *connection,
        const char *effective_user, sm_session_t **session);

/**
 * @brief Drops the session.
 *
 * All session-related memory held by Session Manager will be freed, session ID
 * won't be valid anymore.
 *
 * @note Dropping of the last session of a connection won't cause automatic
 * connection cleanup, explicit ::sm_connection_stop is needed if no new
 * sessions are expected on the connection.
 *
 * @param[in] sm_ctx Session Manager context.
 * @param[in] session Session context.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sm_session_drop(const sm_ctx_t *sm_ctx, sm_session_t *session);

/**
 * @brief Finds session context associated to provided session ID.
 *
 * @param[in] sm_ctx Session Manager context.
 * @param[in] session_id ID of the session.
 * @param[out] session Session context matching with provided session_id.
 *
 * @return Error code (SR_ERR_OK on success, SR_ERR_NOT_FOUND if session
 * matching to session_id cannot be found).
 */
int sm_session_find_id(const sm_ctx_t *sm_ctx, uint32_t session_id, sm_session_t **session);

/**
 * @brief Finds connection context associated to provided file descriptor.
 *
 * @param[in] sm_ctx Session Manager context.
 * @param[in] fd File descriptor of the connection.
 * @param[out] connection Connection context matching with provided file descriptor.
 *
 * @return Error code (SR_ERR_OK on success, SR_ERR_NOT_FOUND if the connection
 * matching to fd cannot be found).
 */
int sm_connection_find_fd(const sm_ctx_t *sm_ctx, const int fd, sm_connection_t **connection);

/**
 * @brief Returns session context at given index (position) in a list (starting
 * from index 0, in increments of 1).
 *
 * It can be used to iterate over all sessions in the session manager, by
 * incrementing the index starting from 0 until SR_ERR_NOT_FOUND is returned.
 *
 * @param[in] sm_ctx Session Manager context.
 * @param[in] index Index of the session in the list, starting from 0.
 * @param[out] session Session context stored at provided index in the list.
 *
 * @return Error code (SR_ERR_OK on success, SR_ERR_NOT_FOUND if the session
 * on provided index does not exist).
 */
int sm_session_get_index(const sm_ctx_t *sm_ctx, uint32_t index, sm_session_t **session);

/**@} sm */

#endif /* SESSION_MANAGER_H_ */
