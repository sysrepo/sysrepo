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
#include <stdexcept>
#include <stdlib.h>

#include "Struct.h"
#include "Sysrepo.h"

extern "C" {
#include "sysrepo.h"
}

using namespace std;

void Throw_Exception::throw_exception(int error)
{
    switch(error) {
    case(SR_ERR_INVAL_ARG):
        throw runtime_error(sr_strerror(SR_ERR_INVAL_ARG));
    case(SR_ERR_NOMEM):
        throw runtime_error(sr_strerror(SR_ERR_NOMEM));
    case(SR_ERR_NOT_FOUND):
        throw runtime_error(sr_strerror(SR_ERR_NOT_FOUND));
    case(SR_ERR_INTERNAL):
        throw runtime_error(sr_strerror(SR_ERR_INTERNAL));
    case(SR_ERR_INIT_FAILED):
        throw runtime_error(sr_strerror(SR_ERR_INIT_FAILED));
    case(SR_ERR_IO):
        throw runtime_error(sr_strerror(SR_ERR_IO));
    case(SR_ERR_DISCONNECT):
        throw runtime_error(sr_strerror(SR_ERR_DISCONNECT));
    case(SR_ERR_MALFORMED_MSG):
        throw runtime_error(sr_strerror(SR_ERR_MALFORMED_MSG));
    case(SR_ERR_UNSUPPORTED):
        throw runtime_error(sr_strerror(SR_ERR_UNSUPPORTED));
    case(SR_ERR_UNKNOWN_MODEL):
        throw runtime_error(sr_strerror(SR_ERR_UNKNOWN_MODEL));
    case(SR_ERR_BAD_ELEMENT):
        throw runtime_error(sr_strerror(SR_ERR_BAD_ELEMENT));
    case(SR_ERR_VALIDATION_FAILED):
        throw runtime_error(sr_strerror(SR_ERR_VALIDATION_FAILED));
    case(SR_ERR_DATA_EXISTS):
        throw runtime_error(sr_strerror(SR_ERR_DATA_EXISTS));
    case(SR_ERR_DATA_MISSING):
        throw runtime_error(sr_strerror(SR_ERR_DATA_MISSING));
    case(SR_ERR_UNAUTHORIZED):
        throw runtime_error(sr_strerror(SR_ERR_UNAUTHORIZED));
    case(SR_ERR_LOCKED):
        throw runtime_error(sr_strerror(SR_ERR_LOCKED));
    case(SR_ERR_TIME_OUT):
        throw runtime_error(sr_strerror(SR_ERR_TIME_OUT));
    }
}

Logs::Logs()
{
    // for consistent swig integration
    return;
}

void Logs::set_stderr(sr_log_level_t log_level)
{
    sr_log_stderr(log_level);
}

void Logs::set_syslog(sr_log_level_t log_level)
{
    sr_log_stderr(log_level);
}

Schema_Content::Schema_Content(char *con)
{
    _con = con;
}

char *Schema_Content::get()
{
    return _con;
}

Schema_Content::~Schema_Content()
{
    free(_con);
}

Schemas::Schemas(sr_schema_t *sch, size_t cnt)
{
    _sch = sch;
    _cnt = cnt;
    _pos = 0;
}

Schemas::~Schemas()
{
    if (_sch && _cnt > 0)
        sr_free_schemas(_sch, _cnt);
    return;
}

bool Schemas::Next()
{
    if (_pos + 1 < _cnt) {
        ++_pos;
        return true;
    }

    return false;
}

bool Schemas::Prev()
{
    if (_pos - 1 > 0) {
        --_pos;
        return true;
    }

    return false;
}
