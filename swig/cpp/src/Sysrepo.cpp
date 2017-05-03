/**
 * @file Sysrepo.cpp
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @brief Sysrepo Sysrepo class implementation.
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

#include <iostream>
#include <stdlib.h>

#include "Struct.h"
#include "Sysrepo.h"

extern "C" {
#include "sysrepo.h"
}

using namespace std;

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
    switch(error) {
    case(SR_ERR_INVAL_ARG):
        throw sysrepo_exception(SR_ERR_INVAL_ARG);
    case(SR_ERR_NOMEM):
        throw sysrepo_exception(SR_ERR_NOMEM);
    case(SR_ERR_NOT_FOUND):
        throw sysrepo_exception(SR_ERR_NOT_FOUND);
    case(SR_ERR_INTERNAL):
        throw sysrepo_exception(SR_ERR_INTERNAL);
    case(SR_ERR_INIT_FAILED):
        throw sysrepo_exception(SR_ERR_INIT_FAILED);
    case(SR_ERR_IO):
        throw sysrepo_exception(SR_ERR_IO);
    case(SR_ERR_DISCONNECT):
        throw sysrepo_exception(SR_ERR_DISCONNECT);
    case(SR_ERR_MALFORMED_MSG):
        throw sysrepo_exception(SR_ERR_MALFORMED_MSG);
    case(SR_ERR_UNSUPPORTED):
        throw sysrepo_exception(SR_ERR_UNSUPPORTED);
    case(SR_ERR_UNKNOWN_MODEL):
        throw sysrepo_exception(SR_ERR_UNKNOWN_MODEL);
    case(SR_ERR_BAD_ELEMENT):
        throw sysrepo_exception(SR_ERR_BAD_ELEMENT);
    case(SR_ERR_VALIDATION_FAILED):
        throw sysrepo_exception(SR_ERR_VALIDATION_FAILED);
    case(SR_ERR_DATA_EXISTS):
        throw sysrepo_exception(SR_ERR_DATA_EXISTS);
    case(SR_ERR_DATA_MISSING):
        throw sysrepo_exception(SR_ERR_DATA_MISSING);
    case(SR_ERR_UNAUTHORIZED):
        throw sysrepo_exception(SR_ERR_UNAUTHORIZED);
    case(SR_ERR_LOCKED):
        throw sysrepo_exception(SR_ERR_LOCKED);
    case(SR_ERR_TIME_OUT):
        throw sysrepo_exception(SR_ERR_TIME_OUT);
    }
}

// for consistent swig integration
Logs::Logs() {}
Logs::~Logs() {}

void Logs::set_stderr(sr_log_level_t log_level)
{
    sr_log_stderr(log_level);
}

void Logs::set_syslog(sr_log_level_t log_level)
{
    sr_log_stderr(log_level);
}
