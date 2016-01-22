/**
 * @file connection_manager.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief API of Connection Manager - module that handles all connections to Sysrepo Engine.
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

#ifndef SRC_CONNECTION_MANAGER_H_
#define SRC_CONNECTION_MANAGER_H_

/**
 * @defgroup cm Connection Manager
 * @{
 *
 * @brief Provides the communication between applications using sysrepo
 * (via @ref cl) and Sysrepo Engine. Acts as sysrepo connection server.
 *
 * It provides the event loop (started with ::cm_start), which handles all
 * connections and does message retrieval/delivery between @ref cl and
 * @ref rp. Messages are in the format of encoded (binary) Google
 * Protocol Buffer messages, which are always prepended with 4-byte preamble
 * containing message size.
 *
 * Connection Manager can work in two modes: daemon mode, or local mode.
 * The main distinction between the two is that the event loop is executed in
 * the main thread in daemon mode (making the main thread blocked until stop
 * is requested by ::cm_stop), whereas in local (library( mode the event loop
 * runs in a new dedicated thread (to not block caller thread).
 */

#include "sysrepo.pb-c.h"
#include "session_manager.h"

/**
 * @brief Connection Manager context used to identify particular instance of
 * Connection Manager.
 */
typedef struct cm_ctx_s cm_ctx_t;

/**
 * @brief Modes in which Connection Manager can operate.
 */
typedef enum {
    CM_MODE_DAEMON,  /**< Daemon mode - clients from other processes are able to connect to it. */
    CM_MODE_LOCAL,   /**< Local mode - only local (intra-process) client connections are possible. */
} cm_connection_mode_t;

/**
 * @brief Initializes Connection Manager.
 *
 * Initializes server for accepting new connections and prepares all internal
 * structures, but still not starts the server (use ::cm_start to start it).
 *
 * @param[in] mode Mode in which Connection Manager will operate.
 * @param[in] socket_path Path of the unix-domain socket for accepting new connections.
 * @param[out] cm_ctx Connection Manager context which can be used in
 * subsequent CM API calls.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int cm_init(const cm_connection_mode_t mode, const char *socket_path, cm_ctx_t **cm_ctx);

/**
 * @brief Cleans up Connection Manager.
 *
 * All outstanding connections will be automatically closed and all memory held
 * by this Connection Manager instance will be freed.
 * This call does not stop the event loop of connection manager. Prior to calling
 * this function, it must be stopped via ::cm_stop.
 *
 * @param[in] cm_ctx Connection Manager context.
 *
 * @return Error code (SR_ERR_OK on success).
 */
void cm_cleanup(cm_ctx_t *cm_ctx);

/**
 * @brief Starts the event loop of Connection Manager.
 *
 * After calling, Connection Manager is able to start accepting incoming
 * connections and processing messages.
 *
 * If Connection manager runs in daemon mode (see ::cm_init), this function will
 * block the calling thread in the event loop until stop is requested or until
 * an error occurred. In library mode it returns immediately.
 *
 * @param[in] cm_ctx Connection Manager context.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int cm_start(cm_ctx_t *cm_ctx);

/**
 * @brief Sends a request to stop the Connection Manager.
 *
 * Used to request "nice" cleanup from signal handlers (if CM is running in
 * daemon mode), or from parent thread (if CM is running in library mode).
 *
 * Event loop will end and a) ::cm_start will return in case of daemon mode,
 * b) event loop thread will be destroyed in case of library mode.
 *
 * Due to the characteristics of signals which are used to accomplish this
 * request, this would stop all instances of Connection Manager if they were
 * multiple of them. Therefore having multiple instances of CM within one
 * application may not be a good design consideration.
 *
 * @param[in] cm_ctx Connection Manager context.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int cm_stop(cm_ctx_t *cm_ctx);

/**
 * @brief Sends the message to the proper recipient according to the
 * session id filled in in the message.
 *
 * @note This function is thread safe, can be called from any thread.
 *
 * @param[in] cm_ctx Connection Manager context.
 * @param[in] msg Message to be send. @note Message will be freed automatically
 * after sending, also in case of error.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int cm_msg_send(cm_ctx_t *cm_ctx, Sr__Msg *msg);

/**@} cm */

#endif /* SRC_CONNECTION_MANAGER_H_ */
