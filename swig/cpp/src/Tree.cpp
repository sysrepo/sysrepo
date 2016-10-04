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

#include "Sysrepo.h"
#include "Struct.h"
#include "Tree.h"

#include <string.h>

using namespace std;

extern "C" {
#include "sysrepo.h"
#include "sysrepo/trees.h"
}

Tree::Tree(const char *root_name, const char *root_module_name) {
    sr_node_t *node;
    int ret = sr_new_tree(root_name, root_module_name, &node);
    if (ret != SR_ERR_OK)
        throw_exception(ret);

    S_Counter counter(new Counter(node));
    _counter = counter;
    _node = node;
}
Tree::Tree(sr_node_t *tree, S_Counter counter) {
    _node = tree;
    _counter = counter;
}
Tree::~Tree() {return;}
S_Tree Tree::dup() {
    sr_node_t *tree_dup = NULL;
    if (_node == NULL) return NULL;

    int ret = sr_dup_tree(_node, &tree_dup);
    if (ret != SR_ERR_OK) throw_exception(ret);

    S_Counter counter(new Counter(tree_dup));
    S_Tree dup(new Tree(tree_dup, counter));
    return dup;
}
S_Tree Tree::node() {
    if (_node == NULL) return NULL;

    S_Tree node(new Tree(_node, _counter));
    return node;
}
S_Tree Tree::parent() {
    if (_node->parent == NULL)
        return NULL;

    S_Tree node(new Tree(_node->parent, _counter));
    return node;
}
S_Tree Tree::next() {
    if (_node->next == NULL)
        return NULL;

    S_Tree node(new Tree(_node->next, _counter));
    return node;
}
S_Tree Tree::prev() {
    if (_node->prev == NULL)
        return NULL;

    S_Tree node(new Tree(_node->prev, _counter));
    return node;
}
S_Tree Tree::first_child() {
    if (_node->first_child == NULL)
        return NULL;

    S_Tree node(new Tree(_node->first_child, _counter));
    return node;
}
S_Tree Tree::last_child() {
    if (_node->last_child == NULL)
        return NULL;

    S_Tree node(new Tree(_node->last_child, _counter));
    return node;
}
void Tree::set_name(const char *name) {
    if (_node == NULL) throw_exception(SR_ERR_DATA_MISSING);
    int ret = sr_node_set_name(_node, name);
    if (ret != SR_ERR_OK) throw_exception(ret);
}
void Tree::set_module(const char *module_name) {
    if (_node == NULL) throw_exception(SR_ERR_DATA_MISSING);
    _node->module_name = strdup((char *) module_name);
    int ret = sr_node_set_module(_node, module_name);
    if (ret != SR_ERR_OK) throw_exception(ret);
}
void Tree::set_string(const char *string_val) {
    if (_node == NULL) throw_exception(SR_ERR_DATA_MISSING);
    int ret = sr_node_set_string(_node, string_val);
    if (ret != SR_ERR_OK) throw_exception(ret);
}
void Tree::add_child(const char *child_name, const char *child_module_name, S_Tree child) {
    if (_node == NULL) throw_exception(SR_ERR_DATA_MISSING);
    int ret = sr_node_add_child(_node, child_name, child_module_name, child->get());
    if (ret != SR_ERR_OK) throw_exception(ret);
}
void Tree::set(const char *value, sr_type_t type) {
    if (type == SR_BINARY_T) {
	    _node->data.binary_val = strdup((char *) value);
    } else if (type == SR_BITS_T) {
	    _node->data.bits_val = strdup((char *) value);
    } else if (type == SR_ENUM_T) {
	    _node->data.enum_val = strdup((char *) value);
    } else if (type == SR_IDENTITYREF_T) {
	    _node->data.identityref_val = strdup((char *) value);
    } else if (type == SR_INSTANCEID_T) {
	    _node->data.instanceid_val = strdup((char *) value);
    } else if (type == SR_STRING_T) {
	    _node->data.string_val = strdup((char *) value);
    } else {
        throw_exception(SR_ERR_INVAL_ARG);
    }

    _node->type = type;
}
void Tree::set(bool bool_val, sr_type_t type) {
    if (type == SR_BOOL_T) {
	    _node->data.bool_val = bool_val;
    } else {
        throw_exception(SR_ERR_INVAL_ARG);
    }

    _node->type = type;
}
void Tree::set(double decimal64_val, sr_type_t type) {
    if (type == SR_DECIMAL64_T) {
	    _node->data.decimal64_val = decimal64_val;
    } else {
        throw_exception(SR_ERR_INVAL_ARG);
    }

    _node->type = type;
}
void Tree::set(int8_t int8_val, sr_type_t type) {
    if (type == SR_INT8_T) {
	    _node->data.int8_val = int8_val;
    } else {
        throw_exception(SR_ERR_INVAL_ARG);
    }

    _node->type = type;
}
void Tree::set(int16_t int16_val, sr_type_t type) {
    if (type == SR_INT16_T) {
	    _node->data.int16_val = int16_val;
    } else {
        throw_exception(SR_ERR_INVAL_ARG);
    }

    _node->type = type;
}
void Tree::set(int32_t int32_val, sr_type_t type) {
    if (type == SR_INT32_T) {
	    _node->data.int32_val = int32_val;
    } else {
        throw_exception(SR_ERR_INVAL_ARG);
    }

    _node->type = type;
}
void Tree::set(int64_t int64_val, sr_type_t type) {
    if (type == SR_DECIMAL64_T) {
	    _node->data.uint64_val = (double) int64_val;
    } else if (type == SR_UINT64_T) {
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
void Tree::set(uint8_t uint8_val, sr_type_t type) {
    if (type == SR_UINT8_T) {
	    _node->data.uint8_val = uint8_val;
    } else {
        throw_exception(SR_ERR_INVAL_ARG);
    }

    _node->type = type;
}
void Tree::set(uint16_t uint16_val, sr_type_t type) {
    if (type == SR_UINT16_T) {
	    _node->data.uint16_val = uint16_val;
    } else {
        throw_exception(SR_ERR_INVAL_ARG);
    }

    _node->type = type;
}
void Tree::set(uint32_t uint32_val, sr_type_t type) {
    if (type == SR_UINT32_T) {
	    _node->data.uint32_val = uint32_val;
    } else {
        throw_exception(SR_ERR_INVAL_ARG);
    }

    _node->type = type;
}
void Tree::set(uint64_t uint64_val, sr_type_t type) {
    if (type == SR_UINT64_T) {
	    _node->data.uint64_val = uint64_val;
    } else {
        throw_exception(SR_ERR_INVAL_ARG);
    }

    _node->type = type;
}
void Tree::set(sr_type_t type) {
    if (type != SR_LIST_T && type != SR_CONTAINER_T && type != SR_CONTAINER_PRESENCE_T &&\
        type != SR_UNKNOWN_T && type != SR_LEAF_EMPTY_T) {
        throw_exception(SR_ERR_INVAL_ARG);
    }

    _node->type = type;
}

Trees::Trees() {
    _trees = NULL;
    _cnt = 0;
    S_Counter counter(new Counter(_trees, _cnt));
    _counter = counter;
}
Trees::Trees(size_t cnt) {
    int ret = sr_new_trees(cnt, &_trees);
    if (ret != SR_ERR_OK)
        throw_exception(ret);

    _cnt = cnt;
    S_Counter counter(new Counter(_trees, _cnt));
    _counter = counter;
}
Trees::Trees(sr_node_t **trees, size_t *cnt, S_Counter counter) {
    _trees = *trees;
    _cnt = *cnt;
    _counter = counter;
}
Trees::Trees(const sr_node_t *trees, const size_t n, S_Counter counter) {
    _trees = (sr_node_t *) trees;
    _cnt = (size_t) n;

    _counter = counter;
}
Trees::~Trees() {return;}
S_Tree Trees::tree(size_t n) {
    if (_trees == NULL || n >= _cnt) return NULL;

    S_Tree tree(new Tree(&_trees[n], _counter));
    return tree;
}
S_Trees Trees::dup() {
    sr_node_t *tree_dup = NULL;
    if (_trees == NULL || _cnt == 0) return NULL;

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
        return NULL;

    *p_cnt = n;
    int ret = sr_new_trees(n, p_trees);
    if (ret != SR_ERR_OK)
        throw_exception(ret);
    S_Trees trees(new Trees(p_trees, p_cnt, NULL));
    return trees;
}
Trees_Holder::~Trees_Holder() {return;}
