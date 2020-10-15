/**
 * @file Sysrepo.hpp
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @author Mcihal Vasko <mvasko@cesnet.cz>
 * @brief Sysrepo Sysrepo class header.
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

#ifndef SYSREPO_H
#define SYSREPO_H

#include <iostream>
#include <memory>
#include <stdexcept>

#include "Internal.hpp"

#include "sysrepo.h"

namespace sysrepo {

/**
 * @defgroup classes C++/Python
 * @{
 */

class Iter_Change;
class Session;
class Subscribe;
class Connection;
class Operation;
class Errors;
class Data;
class Val;
class Vals_Holder;
class Vals;
class Xpath_Ctx;
class Logs;
class Change;
class Tree_Change;
class Deleter;

using S_Iter_Change      = std::shared_ptr<Iter_Change>;
using S_Session          = std::shared_ptr<Session>;
using S_Subscribe        = std::shared_ptr<Subscribe>;
using S_Connection       = std::shared_ptr<Connection>;
using S_Operation        = std::shared_ptr<Operation>;
using S_Errors           = std::shared_ptr<Errors>;
using S_Data             = std::shared_ptr<Data>;
using S_Val              = std::shared_ptr<Val>;
using S_Vals_Holder      = std::shared_ptr<Vals_Holder>;
using S_Vals             = std::shared_ptr<Vals>;
using S_Xpath_Ctx        = std::shared_ptr<Xpath_Ctx>;
using S_Logs             = std::shared_ptr<Logs>;
using S_Change           = std::shared_ptr<Change>;
using S_Tree_Change      = std::shared_ptr<Tree_Change>;
using S_Deleter          = std::shared_ptr<Deleter>;

/* this is a workaround for python not recognizing
 * enum's in function default values */
static const int DS_RUNNING = SR_DS_RUNNING;
static const int EDIT_DEFAULT = SR_EDIT_DEFAULT;
static const int CONN_DEFAULT = SR_CONN_DEFAULT;
static const int SUBSCR_DEFAULT = SR_SUBSCR_DEFAULT;
static const int OPER_DEFAULT = SR_OPER_DEFAULT;

#ifdef SWIG
// https://github.com/swig/swig/issues/1158
void throw_exception (int error);
#else
void throw_exception [[noreturn]] (int error);
#endif

/** Wrapper for [sr_get_repo_path](@ref sr_get_repo_path) */
const char *get_repo_path();
/** Wrapper for [sr_connection_count](@ref sr_connection_count) */
uint32_t connection_count();

/**
 * @brief Class for wrapping sr_error_t.
 * @class sysrepo_exception
 */
class sysrepo_exception : public std::runtime_error
{
public:
    explicit sysrepo_exception(const sr_error_t error_code);
    virtual ~sysrepo_exception() override;
    sr_error_t error_code() const;
private:
    sr_error_t m_error_code;
};

/**
 * @brief Class for wrapping ref sr_log_level_t.
 * @class Logs
 */
class Logs
{
public:
    Logs();
    ~Logs();
    /** Wrapper for [sr_log_stderr](@ref sr_log_stderr) */
    void set_stderr(sr_log_level_t log_level);
    /** Wrapper for [sr_log_syslog](@ref sr_log_syslog) */
    void set_syslog(const char *app_name, sr_log_level_t log_level);
};

/** @} */
}
#endif
