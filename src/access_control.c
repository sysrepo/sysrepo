/**
 * @file access_control.c
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

#include "sr_common.h"
#include "request_processor.h"
#include "access_control.h"

#define HAVE_SETFSUID // TODO tmp

int
ac_check_module_permissions(rp_session_t rp_session, const char *module_name, ac_operation_t operation)
{
#ifdef HAVE_SETFSUID

#else

#endif
    return SR_ERR_OK;
}

int
ac_set_user_identity(rp_session_t rp_session)
{
    return SR_ERR_OK;
}

int
ac_unset_user_identity(rp_session_t rp_session)
{
    return SR_ERR_OK;
}
