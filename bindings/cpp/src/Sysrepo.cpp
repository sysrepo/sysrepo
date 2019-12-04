/**
 * @file Sysrepo.cpp
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Sysrepo Sysrepo class implementation.
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
#include <stdlib.h>

#include "Sysrepo.hpp"
#include "Struct.hpp"

#include "sysrepo.h"

namespace sysrepo {

const char *get_repo_path()
{
    return sr_get_repo_path();
}

uint32_t connection_count()
{
    uint32_t count;
    int ret;

    ret = sr_connection_count(&count);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }

    return count;
}

sysrepo_exception::sysrepo_exception(const sr_error_t error_code)
    : std::runtime_error(sr_strerror(error_code))
    , m_error_code(error_code)
{
}

sysrepo_exception::~sysrepo_exception() {}

sr_error_t sysrepo_exception::error_code() const
{
    return m_error_code;
}

void throw_exception(int error) {
    throw sysrepo_exception((const sr_error_t) error);
}

// for consistent swig integration
Logs::Logs() {}
Logs::~Logs() {}

void Logs::set_stderr(sr_log_level_t log_level)
{
    sr_log_stderr(log_level);
}

void Logs::set_syslog(const char *app_name, sr_log_level_t log_level)
{
    sr_log_syslog(app_name, log_level);
}

}
