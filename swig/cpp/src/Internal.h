/**
 * @file Internal.h
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @brief Sysrepo class header for internal C++ classes.
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

#ifndef INTERNAL_H
#define INTERNAL_H

#define S_Iter_Value       std::shared_ptr<Iter_Value>
#define S_Iter_Change      std::shared_ptr<Iter_Change>
#define S_Session          std::shared_ptr<Session>
#define S_Subscribe        std::shared_ptr<Subscribe>
#define S_Connection       std::shared_ptr<Connection>
#define S_Operation        std::shared_ptr<Operation>
#define S_Schema_Content   std::shared_ptr<Schema_Content>
#define S_Schemas          std::shared_ptr<Schemas>
#define S_Throw_Exception  std::shared_ptr<Throw_Exception>

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
#define S_Val_Holder       std::shared_ptr<Val_Holder>
#define S_Vals             std::shared_ptr<Vals>
#define S_Tree             std::shared_ptr<Tree>
#define S_Trees            std::shared_ptr<Trees>
#define S_Xpath_Ctx        std::shared_ptr<Xpath_Ctx>
#define S_Logs             std::shared_ptr<Logs>
#define S_Change           std::shared_ptr<Change>
#define S_Counter          std::shared_ptr<Counter>
#define S_wrap_cb        std::shared_ptr<wrap_cb>

extern "C" {
#include "sysrepo.h"
#include "sysrepo/trees.h"
}

using namespace std;

typedef enum free_type_e {
    VAL,
    VALS,
    VALS_POINTER,
    TREE,
    TREES,
    TREES_POINTER,
} free_type_t;

class Counter
{
public:
    Counter(sr_val_t *val);
    Counter(sr_val_t *vals, size_t cnt);
    Counter(sr_val_t **vals, size_t *cnt);
    Counter(sr_node_t *tree);
    Counter(sr_node_t *trees, size_t cnt);
    Counter(sr_node_t **trees, size_t *cnt);
    ~Counter();

private:
    sr_val_t *_val;
    sr_val_t *_vals;
    size_t _cnt;
    sr_val_t **p_vals;
    size_t *p_cnt;

    sr_node_t *_tree;
    sr_node_t *_trees;
    sr_node_t **p_trees;
    free_type_t _t;
};

#endif
