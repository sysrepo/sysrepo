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

typedef struct sm_ctx_s sm_ctx_t; /* Opaque session manager context. */

/**
 * Defines various types of sessions.
 */
typedef enum {
    SM_AF_UNIX_CLIENT_LOCAL,   /**< The other side is a local (intra-process) client. */
    SM_AF_UNIX_CLIENT_REMOTE,  /**< The other side is a remote (inter-process) client. */
    SM_AF_UNIX_SERVER,         /**< The other side is a remote server. */
} sm_session_type_t;

/**
 * Defines valid states of sessions.
 */
typedef enum {
    SM_SESS_NOT_CONNECTED,  /**< Session is not connected, but ready for usage later. */
    SM_SESS_CONNECTED,      /**< Session is connected, but still waiting for session_start. */
    SM_SESS_ACTIVE,         /**< Session is active, ready for transmission. */
} sm_session_state_t;

/**
 * Session Context structure.
 */
typedef struct sm_session_s {
    sm_session_type_t type;      /**< Type of the session. */
    sm_session_state_t state;    /**< Current state of the session. */
    uint32_t id;                 /**< Auto-generated unique session ID (do not modify it). */

    int fd;                      /**< File-descriptor used to communicate with the other hand, if applicable. Use sm_session_assign_fd to assign it. */
    const char *real_user;       /**< Real username of the other side. */
    const char *effective_user;  /**< Effective username of the other side (if different to real_user). */

    /**
     * Buffers used for send/receive data to/from the other side.
     */
    struct {
        char *in_buff;           /**< Input buffer. If not empty, there is some message to be processed (or part of it). */
        size_t in_buff_size;     /**< Current size of the input buffer. */
        size_t in_buff_pos;      /**< Current possition in the input buffer (new data is appended starting from this position). */

        char *out_buff;          /**< Output buffer. If not empty, there is some data to be sent when reciever is ready. */
        size_t out_buff_size;    /**< Current size of the output buffer. */
        size_t out_buff_pos;     /**< Current possition in the output buffer (new data is appended starting from this position). */
    } msg_buffers;

    void *rp_data;                /**< Request Processor session data, opaque to Session Manager. */
} sm_session_t;

/**
 * @brief Initializes Session Manager.
 *
 * @param[out] sm_ctx Allocated Session Manager context that can be used in subsequent SM requests.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sm_init(sm_ctx_t **sm_ctx);

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
 * @brief Creates new Session manager instance.
 *
 * A new unique session ID will be assigned and set to the allocated session
 * context. Lookup for a session by given session ID is possible (@see).
 *
 * @param[in] sm_ctx Session Manager context.
 * @param[in] type Type of the session.
 * @param[out] session Allocated session context.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sm_session_create(const sm_ctx_t *sm_ctx, sm_session_type_t type, sm_session_t **session);

/**
 * @brief Assigns a file descriptor to given session.
 *
 * File descriptor will be stored in the avl tree, to allow fast lookup for
 * session by provided descriptor (@see sm_session_find_fd).
 *
 * @param[in] sm_ctx Session Manager context.
 * @param[in] session Session context.
 * @param[in] fd File Descriptor.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sm_session_assign_fd(const sm_ctx_t *sm_ctx, sm_session_t *session, int fd);

/**
 * @brief Assigns usernames to given session.
 *
 * Usernames will be duped on the heap, so caller can release provided arguments
 * after return from this function. Usernames will be automatically freed when
 * session is dropped.
 *
 * @param[in] sm_ctx Session Manager context.
 * @param[in] session Session context.
 * @param[in] real_user Real username of the peer on the other side.
 * @param[in] effective_user Effective username of the peer on the other side
 * (NULL if it is the same as the real one).
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sm_session_assign_user(const sm_ctx_t *sm_ctx, sm_session_t *session, const char *real_user, const char *effective_user);

/**
 * @brief Drops a session.
 *
 * All session-related memory held by Session Manager will be freed, session ID
 * won't be valid anymore.
 *
 * @param[in] sm_ctx Session Manager context.
 * @param[in] session Session context.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sm_session_drop(const sm_ctx_t *sm_ctx, sm_session_t *session);

/**
 * @brief Finds session context related to provided session ID.
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
 * @brief Finds session context related to provided file descriptor.
 *
 * @param[in] sm_ctx Session Manager context.
 * @param[in] fd File Descriptor of the session.
 * @param[out] session Session context matching with provided file descriptor.
 *
 * @return Error code (SR_ERR_OK on success, SR_ERR_NOT_FOUND if session
 * matching to fd cannot be found).
 */
int sm_session_find_fd(const sm_ctx_t *sm_ctx, int fd, sm_session_t **session);

#endif /* SESSION_MANAGER_H_ */
