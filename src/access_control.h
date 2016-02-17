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

#include "xpath_processor.h"

typedef enum ac_operation_e {
    AC_OPER_READ,
    AC_OPER_READ_WRITE,
} ac_operation_t;

typedef struct ac_ucred_s {
    const char *r_username;              /**< Real user name of the user. */
    uid_t r_uid;
    gid_t r_gid;
    const char *e_username;              /**< Effective user name of the user. */
    uid_t e_uid;
    gid_t e_gid;
} ac_ucred_t;

typedef struct ac_ctx_s ac_ctx_t;

typedef struct ac_session_s ac_session_t;

int ac_init(ac_ctx_t **ac_ctx);

void ac_cleanup(ac_ctx_t *ac_ctx);

int ac_session_init(ac_ctx_t *ac_ctx, const ac_ucred_t *user_credentials, ac_session_t **session);

void ac_session_cleanup(ac_session_t *session);

int ac_check_node_permissions(ac_session_t *session, const xp_loc_id_t *node_xpath, const ac_operation_t operation);

int ac_check_file_permissions(ac_session_t *session, const char *file_name, const ac_operation_t operation);

int ac_set_user_identity(ac_ctx_t *ac_ctx, const ac_ucred_t *user_credentials);

int ac_unset_user_identity(ac_ctx_t *ac_ctx);

#endif /* ACCESS_CONTROL_H_ */
