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

#include "Sysrepo.hpp"
#include "Struct.hpp"

extern "C" {
#include "sysrepo.h"
#include "sysrepo/trees.h"
}

namespace sysrepo {

/**
 * @defgroup classes C++/Python
 * @{
 */

/**
 * @brief Class for wrapping sr_node_t.
 * @class Tree
 */
class Tree
{
public:
    /** Constructor for an empty [sr_node_t](@ref sr_node_t).*/
    Tree();
    /** Wrapper for [sr_new_tree](@ref sr_new_tree).*/
    Tree(const char *root_name, const char *root_module_name);
    /** Wrapper for [sr_node_t](@ref sr_node_t).*/
    Tree(sr_node_t *tree, S_Deleter deleter);
    /** Wrapper for [sr_dup_tree](@ref sr_dup_tree).*/
    S_Tree dup();
    /** Get the node value.*/
    S_Tree node();
    /** Getter for name.*/
    char *name() {return _node->name;};
    /** Getter for type.*/
    sr_type_t type() {return _node->type;};
    /** Getter for dflt.*/
    bool dflt() {return _node->dflt;};
    /** Getter for data.*/
    S_Data data() {S_Data data(new Data(_node->data, _node->type, _deleter)); return data;};
    /** Getter for module_name.*/
    char *module_name() {return _node->module_name;};
    /** Getter for parent.*/
    S_Tree parent();
    /** Getter for next.*/
    S_Tree next();
    /** Getter for prev.*/
    S_Tree prev();
    /** Getter for first_child.*/
    S_Tree first_child();
    /** Getter for last_child.*/
    S_Tree last_child();
    /** Wrapper for [sr_print_tree_mem](@ref sr_print_tree_mem).*/
    std::string to_string(int depth_limit);
    /** Wrapper for [sr_print_val_mem](@ref sr_print_val_mem).*/
    std::string value_to_string();
    /** Wrapper for [sr_node_set_name](@ref sr_node_set_name).*/
    void set_name(const char *name);
    /** Wrapper for [sr_node_set_module](@ref sr_node_set_module).*/
    void set_module(const char *module_name);
    /** Wrapper for [sr_node_set_str_data](@ref sr_node_set_str_data).*/
    void set_str_data(sr_type_t type, const char *string_val);
    /** Wrapper for [sr_node_add_child](@ref sr_node_add_child).*/
    void add_child(const char *child_name, const char *child_module_name, S_Tree child);
    /** Setter for string value, type can be SR_STRING_T, SR_BINARY_T, SR_BITS_T, SR_ENUM_T,
     * SR_IDENTITYREF_T and SR_INSTANCEID_T.*/
    void set(const char *val, sr_type_t type = SR_STRING_T);
    /** Setter for bool value.*/
    void set(bool bool_val, sr_type_t type = SR_BOOL_T);
    /** Setter for decimal64 value.*/
    void set(double decimal64_val);
    /** Setter for int8 value, C++ only.*/
    void set(int8_t int8_val);
    /** Setter for int16 value, C++ only.*/
    void set(int16_t int16_val);
    /** Setter for int32 value, C++ only.*/
    void set(int32_t int32_val);
    /** Setter for int64 value, type can be SR_INT8_T, SR_INT16_T, SR_INT32_T,
     * SR_INT64_T, SR_UINT8_T, SR_UINT16_T, SR_UINT32_T, and SR_UINT64_T */
    void set(int64_t int64_val, sr_type_t type = SR_INT64_T);
    /** Setter for uint8 value, C++ only.*/
    void set(uint8_t uint8_val);
    /** Setter for uint16 value, C++ only.*/
    void set(uint16_t uint16_val);
    /** Setter for uint32 value, C++ only.*/
    void set(uint32_t uint32_val);
    /** Setter for uint64 value, C++ only.*/
    void set(uint64_t uint64_val);
    ~Tree();

    friend class Session;
    friend class Subscribe;

private:
    sr_node_t *_node;
    S_Deleter _deleter;
};

/**
 * @brief Class for wrapping sr_node_t array.
 * @class Trees
 */
class Trees
{
public:
    /** Constructor for an empty [sr_node_t](@ref sr_node_t) array.*/
    Trees();
    /** Wrapper for [sr_node_t](@ref sr_node_t) array, create n-array.*/
    Trees(size_t n);
    /** Wrapper for [sr_node_t](@ref sr_node_t) array, internal use only.*/
    Trees(sr_node_t **trees, size_t *cnt, S_Deleter deleter = nullptr);
    /** Wrapper for [sr_node_t](@ref sr_node_t) array, internal use only.*/
    Trees(const sr_node_t *trees, const size_t n, S_Deleter deleter = nullptr);
    /** Getter for [sr_node_t](@ref sr_node_t), get the n-th element in array.*/
    S_Tree tree(size_t n);
    /** Wrapper for [sr_dup_trees](@ref sr_dup_trees) */
    S_Trees dup();
    /** Getter for array size */
    size_t tree_cnt() {return _cnt;};
    ~Trees();

    friend class Session;
    friend class Subscribe;

private:
    size_t _cnt;
    sr_node_t *_trees;
    S_Deleter _deleter;
};

/**
 * @brief Class for wrapping sr_node_t in callbacks.
 * @class Trees_Holder
 */
class Trees_Holder
{
public:
    /** Wrapper for [sr_node_t](@ref sr_node_t) array, used only in callbacks.*/
    Trees_Holder(sr_node_t **trees, size_t *cnt);
    /** Create [sr_node_t](@ref sr_node_t) array of n size.*/
    S_Trees allocate(size_t n);
    ~Trees_Holder();

private:
    size_t *p_cnt;
    sr_node_t **p_trees;
    bool _allocate;
};

/**@} */
}
#endif
