/**
 * @file Struct.h
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @brief Sysrepo class header for C struts.
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

#ifndef STRUCT_H
#define STRUCT_H

#include <iostream>
#include <memory>

extern "C" {
#include "sysrepo.h"
}

using namespace std;

// class for sysrepo C struct sr_error_info_t
class Error
{
public:
    Error(const sr_error_info_t *info);
    ~Error();
    const char *message() {return _info->message;};
    const char *xpath() {return _info->xpath;};

private:
    const sr_error_info_t *_info;
};

// class for list of sysrepo C structs sr_error_info_t
class Errors
{
public:
    Errors(const sr_error_info_t *info, size_t cnt);
    ~Errors();
    shared_ptr<Error> error(size_t n);
    size_t error_cnt() {return _cnt;};

private:
    size_t _cnt;
    const sr_error_info_t *_info;
};

#endif
