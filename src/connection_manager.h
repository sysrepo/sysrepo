/**
 * @file connection_manager.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief API of Connection Manager - module that handles all connection to Sysrepo Engine.
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

#include "sysrepo.pb-c.h"
#include "session_manager.h"

/**
 * @defgroup cm Connection Manager
 * @{
 *
 * @brief Connection Manager is responsible for communication between Sysrepo
 * daemon (or core engine in library mode) and sysrepo access library
 * (tha application which is accessing data in sysrepo).
 *
 * It handles all connections and does message retreival/delivery from/to
 * client library.
 *
 * It can work in two modes: server (daemon), or local (library) mode. See
 * ::cm_start_server and ::cm_start_local for more information.
 */

/**
 * @brief Connection Manager context used to identify particular instance of
 * Connection Manager.
 */
typedef struct cm_ctx_s cm_ctx_t;

/**
 * @brief Modes of Connection Manager.
 */
typedef enum {
    CM_MODE_DAEMON,  /**< Daemon mode - clients from any process are able to connect to it. */
    CM_MODE_LOCAL,   /**< Local mode - only local (intra-process) client connections are possible. */
} cm_connection_mode_t;

/**
 *
 */
int cm_init(const cm_connection_mode_t mode, const char *socket_path, cm_ctx_t **cm_ctx);

/**
 *
 */
void cm_cleanup(cm_ctx_t *cm_ctx);

/**
 * @brief Initializes Connection Manager in server (daemon) mode.
 *
 * After initialization, clients (other applications) are able to connect
 * to the server (as of now, by connecting to server's unix-domain socket).
 *
 * This function will block the thread in the event loop until stop is requested
 * or until an error occured.
 *
 * @param[in] mode Mode in which the Connection Mnager will operate (daemon/local).
 * @param[in] socket_path Path to the unix-domain socket where server should bind to.
 * @param[out] cm_ctx Connectaion manager context which can be used in subsequent
 * CM API calls.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int cm_start(cm_ctx_t *cm_ctx);

/**
 * @brief "Nice" request to stop the Connection Manager instance.
 *
 * Used to request for cleanup from signal handlers (if CM is running in daemon
 * mode), or from parent thread (if CM is running in library mode).
 *
 * All open connections will be closed and all memory held by Connection Manager
 * and chained modules of sysrepo will be released.
 * In case of library mode, the thread where CM was running will be destroyed too.
 *
 * @param[in] cm_ctx Connection Manager context.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int cm_stop(cm_ctx_t *cm_ctx);

/**
 * @brief Sends the message to the proper reciepient according to provided session.
 *
 * This function is thread safe, can be called from any thread.
 *
 * @param[in] cm_ctx Connection Manager context.
 * @param[in] cm_session_ctx Session context used to identifiy the receiver.
 * @param[in] msg Messge to be send.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int cm_msg_send(const cm_ctx_t *cm_ctx, void *cm_session_ctx, Sr__Msg *msg);

/**@} cm */

#endif /* SRC_CONNECTION_MANAGER_H_ */
