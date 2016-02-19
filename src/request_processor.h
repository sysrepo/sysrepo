/**
 * @file request_processor.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief API of Sysrepo's Request Processor.
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

#ifndef REQUEST_PROCESSOR_H_
#define REQUEST_PROCESSOR_H_

#include "access_control.h"
#include "connection_manager.h"
#include "sysrepo.pb-c.h"

typedef struct cm_ctx_s cm_ctx_t; /**< forward declaration of Connection Manager context */

/**
 * @defgroup rp Request Processor
 * @{
 *
 * @brief Request Processor processes individual requests that came from clients
 * in the format of Google Protocol Buffer messages.
 *
 * Messages are passed to Request Processor by Connection Manager (using
 * ::rp_msg_process function). When Request Processor needs to send the message
 * back to the client, it uses Connection Manager's ::cm_msg_send function.
 *
 * Communication between Request Processor and Connection Manager is
 * session-based, Connection Manager uses ::rp_session_start and ::rp_session_stop
 * function calls to notify Request Processor on session start / stop events.
 */

/**
 * @brief Structure that holds the context of an instance of Request Processor.
 */
typedef struct rp_ctx_s rp_ctx_t;

/**
 * @brief Structure that holds Request Processor's per-session context.
 */
typedef struct rp_session_s rp_session_t;

/**
 * @brief Initializes a Request Processor instance.
 *
 * @param[in] cm_ctx Connection Manager context.
 * @param[out] rp_ctx Request Processor context.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int rp_init(cm_ctx_t *cm_ctx, rp_ctx_t **rp_ctx);

/**
 * @brief Cleans up a Request Processor instance.
 *
 * All memory held by this Request Processor instance will be freed. @note
 * Sessions will not be automatically destroyed, so calling ::rp_session_stop for
 * each RP session is needed before calling this function to prevent memory leaks.
 *
 * @param[in] rp_ctx Request Processor context.
 *
 * @return Error code (SR_ERR_OK on success).
 */
void rp_cleanup(rp_ctx_t *rp_ctx);

/**
 * Starts a new Request Processor session.
 *
 * @note Only pointers to provided user names are stored inside of RP session
 * context, so it is needed to NOT free them until ::rp_session_stop is called.
 *
 * @param[in] rp_ctx Request Processor context.
 * @param[in] session_id Unique session identifier assigned by Session Manager.
 * @param[in] user_credentials Credentials of the user who this session belongs to.
 * @param[in] datastore Datastore selected for this configuration session.
 * @param[out] session Session context used for subsequent RP calls.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int rp_session_start(const rp_ctx_t *rp_ctx, const uint32_t session_id,
        const ac_ucred_t *user_credentials, const sr_datastore_t datastore, rp_session_t **session);

/**
 * Stops a Request Processor session.
 *
 * All session-related memory held by Request Processor will be freed.
 *
 * @param[in] rp_ctx Request Processor context.
 * @param[in] session Request Processor session context.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int rp_session_stop(const rp_ctx_t *rp_ctx, rp_session_t *session);

/**
 * @brief Pass the message for processing in Request Processor.
 *
 * @param[in] rp_ctx Request Processor context.
 * @param[in] session Request Processor session context related to the message.
 * @param[in] msg GPB Message to be passed. @note Message will be freed
 * automatically after calling, also in case of error.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int rp_msg_process(rp_ctx_t *rp_ctx, rp_session_t *session, Sr__Msg *msg);

/**@} rp */

#endif /* REQUEST_PROCESSOR_H_ */
