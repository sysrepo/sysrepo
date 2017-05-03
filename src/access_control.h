/**
 * @file access_control.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo Access Control module API.
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

#ifndef ACCESS_CONTROL_H_
#define ACCESS_CONTROL_H_

/**
 * @defgroup ac Access Control Module
 * @{
 *
 * @brief Provides authorization of requested datastore operations and an option
 * to temporarily switch the identity of the process according to the provided
 * user credentials.
 *
 * For authorization purposes, ACM temporarily switches filesystem UID and GID
 * on Linux, or effective UID and GID on non-Linux platforms.
 */

#include "sr_common.h"

/**
 * @brief Operation to be authorized.
 */
typedef enum ac_operation_e {
    AC_OPER_READ,        /**< Read-only operation. */
    AC_OPER_READ_WRITE,  /**< Read-write operation. */
} ac_operation_t;

/**
 * @brief Credentials of a sysrepo user.
 */
typedef struct ac_ucred_s {
    const char *r_username;  /**< Real user name of the user (auto-detected). */
    uid_t r_uid;             /**< Real user ID. */
    gid_t r_gid;             /**< Real group ID. */
    const char *e_username;  /**< Effective user name of the user (passed in as an optional argument). */
    uid_t e_uid;             /**< Effective user ID. */
    gid_t e_gid;             /**< Effective group ID. */
} ac_ucred_t;

/**
 * @brief Access Control module context.
 */
typedef struct ac_ctx_s ac_ctx_t;

/**
 * @brief Access Control session context.
 */
typedef struct ac_session_s ac_session_t;

/**
 * @brief Initializes Access Control module.
 *
 * @param[in] data_search_dir Directory with data files of individual YANG modules.
 * @param[out] ac_ctx Access Control module context that can be used in subsequent API calls.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int ac_init(const char *data_search_dir, ac_ctx_t **ac_ctx);

/**
 * @brief Cleans up Access Control module.
 *
 * Memory held by this Access Control module instance will be freed. Note that
 * sessions are not automatically freed, all sessions need to be cleaned up with
 * ::ac_session_cleanup call.
 *
 * @param[in] ac_ctx Access Control module context acquired by ::ac_init call.
 */
void ac_cleanup(ac_ctx_t *ac_ctx);

/**
 * @brief Starts a new session in Access Control module.
 *
 * @param[in] ac_ctx Access Control module context acquired by ::ac_init call.
 * @param[in] user_credentials Credentials of the user who started the session.
 * @param[out] session Access Control module session context that can be used in
 * subsequent API calls.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int ac_session_init(ac_ctx_t *ac_ctx, const ac_ucred_t *user_credentials, ac_session_t **session);

/**
 * @brief Cleans up Access Control module session.
 *
 * Memory held by this Access Control module session will be freed.
 *
 * @param[in] session Access Control module session context acquired by ::ac_session_init.
 */
void ac_session_cleanup(ac_session_t *session);

/**
 * @brief Check if the user of given session has the permission to perform
 * specified operation on the specified module.
 *
 * @param[in] session Access Control module session context acquired by ::ac_session_init.
 * @param[in] module_name Name of the module.
 * @param[in] operation Operation requested on the specified node.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int ac_check_module_permissions(ac_session_t *session, const char *module_name, const ac_operation_t operation);

/**
 * @brief Check if the user of given session has the permission to perform
 * specified operation on the node specified by xpath.
 *
 * @param[in] session Access Control module session context acquired by ::ac_session_init.
 * @param[in] node_xpath XPath to the node in question.
 * @param[in] operation Operation requested on the specified node.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int ac_check_node_permissions(ac_session_t *session, const char *node_xpath, const ac_operation_t operation);

/**
 * @brief Check if the user of given session has the permission to perform
 * specified operation on the specified file.
 *
 * @param[in] session Access Control module session context acquired by ::ac_session_init.
 * @param[in] file_name Path to the file that needs to be accessed.
 * @param[in] operation Operation requested on the specified file.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int ac_check_file_permissions(ac_session_t *session, const char *file_name, const ac_operation_t operation);

/**
 * @brief Switches the filesystem / effective uid and gid according to provided
 * user credentials, so that this thread / process will act as the specified user,
 * until ::ac_unset_user_identity is called.
 *
 * This call should be issued before accessing any data files for reading or
 * writing to prevent privilege escalation and TOCTOU races.
 *
 * @note On non-Linux platforms, this call will block any subsequent
 * ::ac_set_user_identity calls from other threads, until ::ac_unset_user_identity
 * is called. Therefore it is very important to always call ::ac_unset_user_identity
 * and to call it as soon as possible.
 *
 * @param[in] ac_ctx Access Control module context acquired by ::ac_init call.
 * @param[in] user_credentials Credentials of a sysrepo user.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int ac_set_user_identity(ac_ctx_t *ac_ctx, const ac_ucred_t *user_credentials);

/**
 * @brief Unsets user identity previously set by ::ac_set_user_identity back
 * to the process identity saved at the time of ::ac_init.
 *
 * @param[in] ac_ctx Access Control module context acquired by ::ac_init call.
 * @param[in] user_credentials Credentials of a sysrepo user.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int ac_unset_user_identity(ac_ctx_t *ac_ctx, const ac_ucred_t *user_credentials);

/**@} ac */

#endif /* ACCESS_CONTROL_H_ */
