/**
 * @file Struct.cpp
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @brief Sysrepo class header implementation for C struts.
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
#include <memory>

#include "Struct.h"

extern "C" {
#include "sysrepo.h"
}

using namespace std;

Error::Error(const sr_error_info_t *info)
{
    _info = info;
}

Error::~Error()
{
    return;
}

Errors::Errors(const sr_error_info_t *info, size_t cnt)
{
    _info = info;
    _cnt = cnt;
}

Errors::~Errors()
{
    return;
}

shared_ptr<Error> Errors::error(size_t n)
{
    if (n < 0 && n >= _cnt)
        return NULL;

    shared_ptr<Error> error(new Error(&_info[n]));
    return error;
}
