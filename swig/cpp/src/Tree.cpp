/**
 * @file Trees.cpp
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @brief Sysrepo class header implementation for C header trees.h
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

#include "Sysrepo.hpp"
#include "Struct.hpp"
#include "Tree.hpp"

#include <string.h>

extern "C" {
#include "sysrepo.h"
#include "sysrepo/trees.h"
#include "sysrepo/values.h"
}

namespace sysrepo {

Tree::Tree() {
    _node = nullptr;
    _deleter = S_Deleter(new Deleter(_node));
}
Tree::Tree(const char *root_name, const char *root_module_name) {
    sr_node_t *node;
    int ret = sr_new_tree(root_name, root_module_name, &node);
    if (ret != SR_ERR_OK)
        throw_exception(ret);

    _deleter = S_Deleter(new Deleter(node));
    _node = node;
}
Tree::Tree(sr_node_t *tree, S_Deleter deleter) {
    _node = tree;
    _deleter = deleter;
}
Tree::~Tree() {}
S_Tree Tree::dup() {
    if (!_node)
        throw std::logic_error("Tree::dup: called on null Tree");

    sr_node_t *tree_dup = nullptr;
    int ret = sr_dup_tree(_node, &tree_dup);
    if (ret != SR_ERR_OK) throw_exception(ret);

    S_Deleter deleter(new Deleter(tree_dup));
    S_Tree dup(new Tree(tree_dup, deleter));
    return dup;
}
S_Tree Tree::node() {
    if (!_node)
        throw std::logic_error("Tree::node: called on null Tree");

    S_Tree node(new Tree(_node, _deleter));
    return node;
}
S_Tree Tree::parent() {
    if (!_node)
        throw std::logic_error("Tree::parent: called on null Tree");
    if (!_node->parent)
        return nullptr;

    S_Tree node(new Tree(_node->parent, _deleter));
    return node;
}
S_Tree Tree::next() {
    if (!_node)
        throw std::logic_error("Tree::next: called on null Tree");
    if (!_node->next)
        return nullptr;

    S_Tree node(new Tree(_node->next, _deleter));
    return node;
}
S_Tree Tree::prev() {
    if (!_node)
        throw std::logic_error("Tree::prev: called on null Tree");
    if (!_node->prev)
        return nullptr;

    S_Tree node(new Tree(_node->prev, _deleter));
    return node;
}
S_Tree Tree::first_child() {
    if (!_node)
        throw std::logic_error("Tree::first_child: called on null Tree");
    if (!_node->first_child)
        return nullptr;

    S_Tree node(new Tree(_node->first_child, _deleter));
    return node;
}
S_Tree Tree::last_child() {
    if (!_node)
        throw std::logic_error("Tree::last_child: called on null Tree");
    if (!_node->last_child)
        return nullptr;

    S_Tree node(new Tree(_node->last_child, _deleter));
    return node;
}
std::string Tree::to_string(int depth_limit) {
    char *mem = nullptr;

    int ret = sr_print_tree_mem(&mem, _node, depth_limit);
    if (SR_ERR_OK == ret) {
        if (!mem) {
            return std::string();
        }
        std::string string_val = mem;
        free(mem);
        return string_val;
    }
    if (SR_ERR_NOT_FOUND == ret) {
        return std::string();
    }
    throw_exception(ret);
}
std::string Tree::value_to_string() {
    char *mem = nullptr;

    if (_node == nullptr) throw_exception(SR_ERR_DATA_MISSING);

    sr_val_t *val = (sr_val_t *) _node;

    int ret = sr_print_val_mem(&mem, val);
    if (SR_ERR_OK == ret) {
        if (!mem) {
            return std::string();
        }
        std::string string_val = mem;
        free(mem);
        return string_val;
    }
    if (SR_ERR_NOT_FOUND == ret) {
        return nullptr;
    }
    throw_exception(ret);
}
void Tree::set_name(const char *name) {
    if (_node == nullptr) throw_exception(SR_ERR_DATA_MISSING);
    int ret = sr_node_set_name(_node, name);
    if (ret != SR_ERR_OK) throw_exception(ret);
}
void Tree::set_module(const char *module_name) {
    if (_node == nullptr) throw_exception(SR_ERR_DATA_MISSING);
    int ret = sr_node_set_module(_node, module_name);
    if (ret != SR_ERR_OK) throw_exception(ret);
}
void Tree::set_str_data(sr_type_t type, const char *string_val) {
    if (_node == nullptr) throw_exception(SR_ERR_DATA_MISSING);
    int ret = sr_node_set_str_data(_node, type, string_val);
    if (ret != SR_ERR_OK) throw_exception(ret);
}
void Tree::add_child(const char *child_name, const char *child_module_name, S_Tree child) {
    if (_node == nullptr) throw_exception(SR_ERR_DATA_MISSING);
    int ret = sr_node_add_child(_node, child_name, child_module_name, &child->_node);
    if (ret != SR_ERR_OK) throw_exception(ret);
}
void Tree::set(const char *value, sr_type_t type) {
    int ret = SR_ERR_OK;

    _node->type = type;

    if (type == SR_BINARY_T || type == SR_BITS_T || type == SR_ENUM_T || type == SR_IDENTITYREF_T || \
        type == SR_INSTANCEID_T || type == SR_STRING_T) {
        ret = sr_node_set_str_data(_node, type, value);
        if (ret != SR_ERR_OK)
            throw_exception(ret);
    } else if (value != nullptr && ( type != SR_LIST_T && type != SR_CONTAINER_T && type != SR_CONTAINER_PRESENCE_T &&\
        type != SR_UNKNOWN_T && type != SR_LEAF_EMPTY_T)) {
        throw_exception(SR_ERR_INVAL_ARG);
    }
}
void Tree::set(bool bool_val, sr_type_t type) {
    if (type == SR_BOOL_T) {
        _node->data.bool_val = bool_val;
    } else {
        throw_exception(SR_ERR_INVAL_ARG);
    }

    _node->type = type;
}
void Tree::set(double decimal64_val) {
    _node->data.decimal64_val = decimal64_val;
    _node->type = SR_DECIMAL64_T;
}
void Tree::set(int8_t int8_val) {
    _node->data.int8_val = int8_val;
    _node->type = SR_INT8_T;
}
void Tree::set(int16_t int16_val) {
    _node->data.int16_val = int16_val;
    _node->type = SR_INT16_T;
}
void Tree::set(int32_t int32_val) {
    _node->data.int32_val = int32_val;
    _node->type = SR_INT32_T;
}
void Tree::set(int64_t int64_val, sr_type_t type) {
    if (type == SR_UINT64_T) {
        _node->data.uint64_val = (uint64_t) int64_val;
    } else if (type == SR_UINT32_T) {
        _node->data.uint32_val = (uint32_t) int64_val;
    } else if (type == SR_UINT16_T) {
        _node->data.uint16_val = (uint16_t) int64_val;
    } else if (type == SR_UINT8_T) {
        _node->data.uint8_val = (uint8_t) int64_val;
    } else if (type == SR_INT64_T) {
        _node->data.int64_val = (int64_t) int64_val;
    } else if (type == SR_INT32_T) {
        _node->data.int32_val = (int32_t) int64_val;
    } else if (type == SR_INT16_T) {
        _node->data.int16_val = (int16_t) int64_val;
    } else if (type == SR_INT8_T) {
        _node->data.int8_val = (int8_t) int64_val;
    } else {
        throw_exception(SR_ERR_INVAL_ARG);
    }

    _node->type = type;
}
void Tree::set(uint8_t uint8_val) {
    _node->data.uint8_val = uint8_val;
    _node->type = SR_UINT8_T;
}
void Tree::set(uint16_t uint16_val) {
    _node->data.uint16_val = uint16_val;
    _node->type = SR_UINT16_T;
}
void Tree::set(uint32_t uint32_val) {
    _node->data.uint32_val = uint32_val;
    _node->type = SR_UINT32_T;
}
void Tree::set(uint64_t uint64_val) {
    _node->data.uint64_val = uint64_val;
    _node->type = SR_UINT64_T;
}

Trees::Trees(size_t cnt): Trees() {
    if (cnt) {
        int ret = sr_new_trees(cnt, &_trees);
        if (ret != SR_ERR_OK)
            throw_exception(ret);

        _cnt = cnt;
        _deleter = S_Deleter(new Deleter(_trees, _cnt));
    }
}
Trees::Trees(): _cnt(0), _trees(nullptr)
{
}
Trees::Trees(sr_node_t **trees, size_t *cnt, S_Deleter deleter) {
    _trees = *trees;
    _cnt = *cnt;
    _deleter = deleter;
}
Trees::Trees(const sr_node_t *trees, const size_t n, S_Deleter deleter) {
    _trees = (sr_node_t *) trees;
    _cnt = (size_t) n;

    _deleter = deleter;
}
Trees::~Trees() {}
S_Tree Trees::tree(size_t n) {
    if (n >= _cnt)
        throw std::out_of_range("Trees::tree: index out of range");
    if (!_trees)
        throw std::logic_error("Trees::tree: called on null Trees");


    S_Tree tree(new Tree(&_trees[n], _deleter));
    return tree;
}
S_Trees Trees::dup() {
    if (_cnt == 0)
        throw std::out_of_range("Trees::tree: no elements to copy");
    if (!_trees)
        throw std::logic_error("Trees::tree: called on null Trees");

    sr_node_t *tree_dup = nullptr;
    int ret = sr_dup_trees(_trees, _cnt, &tree_dup);
    if (ret != SR_ERR_OK) throw_exception(ret);

    S_Trees dup(new Trees(tree_dup, _cnt));
    return dup;
}

// Trees_Holder
Trees_Holder::Trees_Holder(sr_node_t **trees, size_t *cnt) {
    p_trees = trees;
    p_cnt = cnt;
    _allocate = true;
}
S_Trees Trees_Holder::allocate(size_t n) {
    if (_allocate == false)
        throw_exception(SR_ERR_DATA_EXISTS);
    _allocate = false;

    if (n == 0)
        return nullptr;

    *p_cnt = n;
    int ret = sr_new_trees(n, p_trees);
    if (ret != SR_ERR_OK)
        throw_exception(ret);
    S_Trees trees(new Trees(p_trees, p_cnt, nullptr));
    return trees;
}
Trees_Holder::~Trees_Holder() {}

}
