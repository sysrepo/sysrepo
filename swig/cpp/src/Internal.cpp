/**
 * @file Internal.cpp
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @brief Sysrepo class header implementation for internal C++ classes
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

#include "Internal.h"
#include <iostream>

extern "C" {
#include "sysrepo.h"
#include "sysrepo/trees.h"
}

using namespace std;

void Counter::init_all() {
    _val = NULL;
    _vals = NULL;
    _cnt = 0;
    p_vals = NULL;
    p_cnt = NULL;

    _tree = NULL;
    _trees = NULL;
    p_trees = NULL;
}
Counter::Counter(sr_val_t *val) {
    Counter::init_all();
    _val = val;
    _t = VAL;
}
Counter::Counter(sr_val_t *vals, size_t cnt) {
    Counter::init_all();
    _vals = vals;
    _cnt = cnt;
    _t = VALS;
}
Counter::Counter(sr_val_t **vals, size_t *cnt) {
    Counter::init_all();
    p_vals = vals;
    p_cnt = cnt;
    _t = VALS_POINTER;
}
Counter::Counter(sr_node_t *tree) {
    Counter::init_all();
    _tree = tree;
    _t = TREE;
}
Counter::Counter(sr_node_t *trees, size_t cnt) {
    Counter::init_all();
    _trees = trees;
    _cnt = cnt;
    _t = TREES;
}
Counter::Counter(sr_node_t **trees, size_t *cnt) {
    Counter::init_all();
    p_trees = trees;
    p_cnt = cnt;
    _t = TREES_POINTER;
}
Counter::~Counter() {
    switch(_t) {
    case VAL:
        if (_val) sr_free_val(_val);
	_val = NULL;
    break;
    case VALS:
        if (_vals) sr_free_values(_vals, _cnt);
	_vals = NULL;
    break;
    case VALS_POINTER:
        if (*p_vals) sr_free_values(*p_vals, *p_cnt);
	*p_vals = NULL;
    break;
    case TREE:
        if (_tree) sr_free_tree(_tree);
	_tree = NULL;
    break;
    case TREES:
        if (_trees) sr_free_trees(_trees, _cnt);
	_trees = NULL;
    break;
    case TREES_POINTER:
        if (*p_trees) sr_free_trees(*p_trees, *p_cnt);
	*p_trees = NULL;
    break;
    }
    return;
}
