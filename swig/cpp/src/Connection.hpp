/**
 * @file Connection.h
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @brief Sysrepo Connection class header.
 *
 * @copyright
 * Copyright 2016 Deutsche Telekom AG.
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

#ifndef CONNECTION_H
#define CONNECTION_H

#include <iostream>

#include "Sysrepo.hpp"
#include "Internal.hpp"

extern "C" {
#include "sysrepo.h"
}

namespace sysrepo {

/**
 * @defgroup classes C++/Python
 * @{
 */

/**
 * @brief Class for wrapping sr_conn_ctx_t.
 * @class Connection
 */
class Connection
{
public:
    /** Wrapper for [sr_connect](@ref sr_connect) */
    Connection(const char *app_name, const sr_conn_options_t opts = CONN_DEFAULT);
    ~Connection();

    friend class Session;

private:
    sr_conn_ctx_t *_conn;
    sr_conn_options_t _opts;
};

/**@} */
}

#endif
