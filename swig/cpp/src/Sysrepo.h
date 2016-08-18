/**
 * @file Sysrepo.h
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @brief Sysrepo Sysrepo class header.
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

#ifndef SYSREPO_H
#define SYSREPO_H

#include <iostream>

extern "C" {
#include "sysrepo.h"
}

typedef enum conn_flag_e {
    CONN_DEFAULT = 0,
    CONN_DAEMON_REQUIRED = 1,
    CONN_DAEMON_START = 2,
} conn_flag_t;

typedef enum session_flag_e {
    SESS_DEFAULT = 0,
    SESS_CONFIG_ONLY = 1,
} session_flag_t;

typedef enum edit_flag_e {
    EDIT_DEFAULT = 0,
    EDIT_NON_RECURSIVE = 1,
    EDIT_STRICT = 2,
} edit_flag_t;

typedef enum subscr_flag_e {
    SUBSCR_DEFAULT = 0,
    SUBSCR_CTX_REUSE = 1,
    SUBSCR_PASSIVE = 2,
    SUBSCR_VERIFIER = 4,
} subscr_flag_t;

typedef enum datastore_e {
    DS_STARTUP = 0,
    DS_RUNNING = 1,
    DS_CANDIDATE = 2,
} datastore_t;

class Throw_Exception
{

protected:
    void throw_exception(int error);
};

class Logs
{
public:
    Logs();
    void set_stderr(sr_log_level_t log_level);
    void set_syslog(sr_log_level_t log_level);
};

class Errors
{
public:
    Errors();
    size_t cnt;
    const sr_error_info_t *info;
};

class Schema
{

public:
    size_t cnt;
    sr_schema_t *sch;
    char *content;
};

#endif
