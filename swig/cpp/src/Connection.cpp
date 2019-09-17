/**
 * @file Connection.cpp
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Sysrepo Connection class implementation.
 *
 * @copyright
 * Copyright 2016 - 2019 Deutsche Telekom AG.
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

#include <iostream>
#include <stdexcept>

#include <libyang/Libyang.hpp>

#include "Sysrepo.hpp"
#include "Connection.hpp"

extern "C" {
#include "sysrepo.h"
}

namespace sysrepo {

Connection::Connection(const sr_conn_options_t opts)
{
    int ret;
    _conn = 0;
    _opts = opts;

    /* connect to sysrepo */
    ret = sr_connect(_opts, &_conn);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
        return;
    }
}

Connection::~Connection()
{
    if (nullptr != _conn) {
        sr_disconnect(_conn);
    }
}

libyang::S_Context Connection::get_context()
{
    return std::make_shared<libyang::Context>(const_cast<struct ly_ctx *>(sr_get_context(_conn)), nullptr);
}

}
