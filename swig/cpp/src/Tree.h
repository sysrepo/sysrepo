/**
 * @file Trees.h
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @brief Sysrepo class header for C header trees.h.
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

#ifndef TREE_H
#define TREE_H

#include "Sysrepo.h"
#include "Struct.h"

extern "C" {
#include "sysrepo.h"
#include "sysrepo/trees.h"
}

class Tree
{
public:
    Tree();
    Tree(const char *root_name, const char *root_module_name);
    Tree(sr_node_t *tree, S_Deleter deleter);
    S_Tree dup();
    S_Tree node();
    char *name() {return _node->name;};
    sr_type_t type() {return _node->type;};
    bool dflt() {return _node->dflt;};
    S_Data data() {S_Data data(new Data(_node->data, _node->type, _deleter)); return data;};
    char *module_name() {return _node->module_name;};
    S_Tree parent();
    S_Tree next();
    S_Tree prev();
    S_Tree first_child();
    S_Tree last_child();
    std::string to_string(int depth_limit);
    std::string value_to_string();
    void set_name(const char *name);
    void set_module(const char *module_name);
    void set_str_data(sr_type_t type, const char *string_val);
    void add_child(const char *child_name, const char *child_module_name, S_Tree child);
    void set(const char *val, sr_type_t type = SR_STRING_T);
    void set(bool bool_val, sr_type_t type = SR_BOOL_T);
    void set(double decimal64_val);
    void set(int8_t int8_val, sr_type_t type);
    void set(int16_t int16_val, sr_type_t type);
    void set(int32_t int32_val, sr_type_t type);
    void set(int64_t int64_val, sr_type_t type);
    void set(uint8_t uint8_val, sr_type_t type);
    void set(uint16_t uint16_val, sr_type_t type);
    void set(uint32_t uint32_val, sr_type_t type);
    void set(uint64_t uint64_val, sr_type_t type);
    ~Tree();

    friend class Session;
    friend class Subscribe;

private:
    sr_node_t *_node;
    S_Deleter _deleter;
};

class Trees
{
public:
    Trees();
    Trees(size_t n);
    Trees(sr_node_t **trees, size_t *cnt, S_Deleter deleter = nullptr);
    Trees(const sr_node_t *trees, const size_t n, S_Deleter deleter = nullptr);
    S_Tree tree(size_t n);
    S_Trees dup();
    size_t tree_cnt() {return _cnt;};
    ~Trees();

    friend class Session;
    friend class Subscribe;

private:
    size_t _cnt;
    sr_node_t *_trees;
    S_Deleter _deleter;
};

// class for wrapping Vals classes
class Trees_Holder
{
public:
    Trees_Holder(sr_node_t **trees, size_t *cnt);
    S_Trees allocate(size_t n);
    ~Trees_Holder();

private:
    size_t *p_cnt;
    sr_node_t **p_trees;
    bool _allocate;
};

#endif
