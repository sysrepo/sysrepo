/**
 * @file access_control.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo Access Control module.
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

typedef enum ac_operation_e {
    AC_OPER_READ,
    AC_OPER_WRITE,
} ac_operation_t;

typedef struct ac_ucred_s {
    const char *r_username;              /**< Real user name of the user. */
    uid_t r_uid;
    gid_t r_gid;
    const char *e_username;              /**< Effective user name of the user. */
    uid_t e_uid;
    gid_t e_gid;
} ac_ucred_t;

typedef struct rp_session_s rp_session_t;

int ac_check_module_permissions(rp_session_t rp_session, const char *module_name, ac_operation_t operation);

int ac_set_user_identity(rp_session_t rp_session);

int ac_unset_user_identity(rp_session_t rp_session);

#endif /* ACCESS_CONTROL_H_ */
