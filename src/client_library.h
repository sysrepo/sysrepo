/**
 * @file client_library.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo Client Library non-public API.
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

#ifndef CLIENT_LIBRARY_H_
#define CLIENT_LIBRARY_H_

/**
 *
 */
int sr_module_install(sr_session_ctx_t *session, const char *module_name, const char *revision, bool installed);

/**
 *
 */
int sr_feature_enable(sr_session_ctx_t *session, const char *module_name, const char *feature_name, bool enabled);

#endif /* CLIENT_LIBRARY_H_ */
