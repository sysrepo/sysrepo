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

#ifdef SWIGLUA
    #define S_Iter_Value       Iter_Value*
    #define S_Iter_Change      Iter_Change*
    #define S_Session          Session*
    #define S_Subscribe        Subscribe*
    #define S_Connection       Connection*
    #define S_Operation        Operation*
    #define S_Schema_Content   Schema_Content*
    #define S_Error            Error*
    #define S_Errors           Errors*
    #define S_Data             Data*
    #define S_Schema_Revision  Schema_Revision*
    #define S_Schema_Submodule Schema_Submodule*
    #define S_Yang_Schema      Yang_Schema*
    #define S_Yang_Schemas     Yang_Schemas*
    #define S_Fd_Change        Fd_Change*
    #define S_Fd_Changes       Fd_Changes*
    #define S_Val              Val*
    #define S_Vals_Holder      Vals_Holder*
    #define S_Vals             Vals*
    #define S_Tree             Tree*
    #define S_Trees            Trees*
    #define S_Trees_Holder     Trees_Holder*
    #define S_Xpath_Ctx        Xpath_Ctx*
    #define S_Logs             Logs*
    #define S_Change           Change*
    #define S_Counter          std::shared_ptr<Counter>
    #define S_Callback         Callback*
#else
    #define S_Iter_Value       std::shared_ptr<Iter_Value>
    #define S_Iter_Change      std::shared_ptr<Iter_Change>
    #define S_Session          std::shared_ptr<Session>
    #define S_Subscribe        std::shared_ptr<Subscribe>
    #define S_Connection       std::shared_ptr<Connection>
    #define S_Operation        std::shared_ptr<Operation>
    #define S_Schema_Content   std::shared_ptr<Schema_Content>
    #define S_Error            std::shared_ptr<Error>
    #define S_Errors           std::shared_ptr<Errors>
    #define S_Data             std::shared_ptr<Data>
    #define S_Schema_Revision  std::shared_ptr<Schema_Revision>
    #define S_Schema_Submodule std::shared_ptr<Schema_Submodule>
    #define S_Yang_Schema      std::shared_ptr<Yang_Schema>
    #define S_Yang_Schemas     std::shared_ptr<Yang_Schemas>
    #define S_Fd_Change        std::shared_ptr<Fd_Change>
    #define S_Fd_Changes       std::shared_ptr<Fd_Changes>
    #define S_Val              std::shared_ptr<Val>
    #define S_Vals_Holder      std::shared_ptr<Vals_Holder>
    #define S_Vals             std::shared_ptr<Vals>
    #define S_Tree             std::shared_ptr<Tree>
    #define S_Trees            std::shared_ptr<Trees>
    #define S_Trees_Holder     std::shared_ptr<Trees_Holder>
    #define S_Xpath_Ctx        std::shared_ptr<Xpath_Ctx>
    #define S_Logs             std::shared_ptr<Logs>
    #define S_Change           std::shared_ptr<Change>
    #define S_Counter          std::shared_ptr<Counter>
    #define S_Callback         std::shared_ptr<Callback>
#endif

#define SESS_DEFAULT 0
#define DS_RUNNING 1
#define EDIT_DEFAULT 0
#define CONN_DEFAULT 0
#define GET_SUBTREE_DEFAULT 0
#define SUBSCR_DEFAULT 0

#include <iostream>
#include <stdexcept>

#include "Internal.h"

extern "C" {
#include "sysrepo.h"
}

#ifdef SWIG
// https://github.com/swig/swig/issues/1158
void throw_exception (int error);
#else
void throw_exception [[noreturn]] (int error);
#endif

class sysrepo_exception : public std::runtime_error
{
public:
    explicit sysrepo_exception(const sr_error_t error_code);
    virtual ~sysrepo_exception() override;
    sr_error_t error_code() const;
private:
    sr_error_t m_error_code;
};

class Logs
{
public:
    Logs();
    ~Logs();
    void set_stderr(sr_log_level_t log_level);
    void set_syslog(sr_log_level_t log_level);
};

#endif
