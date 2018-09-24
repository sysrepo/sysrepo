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
#include <memory>
#include <stdexcept>

#include "Internal.hpp"

extern "C" {
#include "sysrepo.h"
}

namespace sysrepo {

/**
 * @defgroup classes C++/Python
 * @{
 */

class Iter_Value;
class Iter_Change;
class Session;
class Subscribe;
class Connection;
class Operation;
class Schema_Content;
class Error;
class Errors;
class Data;
class Schema_Revision;
class Schema_Submodule;
class Yang_Schema;
class Yang_Schemas;
class Fd_Change;
class Fd_Changes;
class Val;
class Vals_Holder;
class Vals;
class Tree;
class Trees;
class Trees_Holder;
class Xpath_Ctx;
class Logs;
class Change;
class Counter;
class Callback;
class Deleter;

#ifdef SWIGLUA
using S_Iter_Value       = Iter_Value*;
using S_Iter_Change      = Iter_Change*;
using S_Session          = Session*;
using S_Subscribe        = Subscribe*;
using S_Connection       = Connection*;
using S_Operation        = Operation*;
using S_Schema_Content   = Schema_Content*;
using S_Error            = Error*;
using S_Errors           = Errors*;
using S_Data             = Data*;
using S_Schema_Revision  = Schema_Revision*;
using S_Schema_Submodule = Schema_Submodule*;
using S_Yang_Schema      = Yang_Schema*;
using S_Yang_Schemas     = Yang_Schemas*;
using S_Fd_Change        = Fd_Change*;
using S_Fd_Changes       = Fd_Changes*;
using S_Val              = Val*;
using S_Vals_Holder      = Vals_Holder*;
using S_Vals             = Vals*;
using S_Tree             = Tree*;
using S_Trees            = Trees*;
using S_Trees_Holder     = Trees_Holder*;
using S_Xpath_Ctx        = Xpath_Ctx*;
using S_Logs             = Logs*;
using S_Change           = Change*;
using S_Counter          = Counter*;
using S_Callback         = Callback*;
#else
using S_Iter_Value       = std::shared_ptr<Iter_Value>;
using S_Iter_Change      = std::shared_ptr<Iter_Change>;
using S_Session          = std::shared_ptr<Session>;
using S_Subscribe        = std::shared_ptr<Subscribe>;
using S_Connection       = std::shared_ptr<Connection>;
using S_Operation        = std::shared_ptr<Operation>;
using S_Schema_Content   = std::shared_ptr<Schema_Content>;
using S_Error            = std::shared_ptr<Error>;
using S_Errors           = std::shared_ptr<Errors>;
using S_Data             = std::shared_ptr<Data>;
using S_Schema_Revision  = std::shared_ptr<Schema_Revision>;
using S_Schema_Submodule = std::shared_ptr<Schema_Submodule>;
using S_Yang_Schema      = std::shared_ptr<Yang_Schema>;
using S_Yang_Schemas     = std::shared_ptr<Yang_Schemas>;
using S_Fd_Change        = std::shared_ptr<Fd_Change>;
using S_Fd_Changes       = std::shared_ptr<Fd_Changes>;
using S_Val              = std::shared_ptr<Val>;
using S_Vals_Holder      = std::shared_ptr<Vals_Holder>;
using S_Vals             = std::shared_ptr<Vals>;
using S_Tree             = std::shared_ptr<Tree>;
using S_Trees            = std::shared_ptr<Trees>;
using S_Trees_Holder     = std::shared_ptr<Trees_Holder>;
using S_Xpath_Ctx        = std::shared_ptr<Xpath_Ctx>;
using S_Logs             = std::shared_ptr<Logs>;
using S_Change           = std::shared_ptr<Change>;
using S_Counter          = std::shared_ptr<Counter>;
using S_Callback         = std::shared_ptr<Callback>;
using S_Deleter          = std::shared_ptr<Deleter>;
#endif

/* this is a workaround for python not recognizing
 * enum's in function default values */
static const int SESS_DEFAULT = SR_SESS_DEFAULT;
static const int DS_RUNNING = SR_DS_RUNNING;
static const int EDIT_DEFAULT = SR_EDIT_DEFAULT;
static const int CONN_DEFAULT = SR_CONN_DEFAULT;
static const int GET_SUBTREE_DEFAULT = SR_GET_SUBTREE_DEFAULT;
static const int SUBSCR_DEFAULT = SR_SUBSCR_DEFAULT;

#ifdef SWIG
// https://github.com/swig/swig/issues/1158
void throw_exception (int error);
#else
void throw_exception [[noreturn]] (int error);
#endif

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
    void set_syslog(sr_log_level_t log_level);
};

/**@} */
}
#endif
