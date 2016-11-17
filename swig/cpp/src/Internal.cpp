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

void Deleter::init_all() {
    _val = NULL;
    _cnt = 0;
    p_vals = NULL;
    p_cnt = NULL;

    _tree = NULL;
    p_trees = NULL;
}
Deleter::Deleter(sr_val_t *val) {
    Deleter::init_all();
    _val = val;
    _t = VAL;
}
Deleter::Deleter(sr_val_t *vals, size_t cnt) {
    Deleter::init_all();
    _val = vals;
    _cnt = cnt;
    _t = VALS;
}
Deleter::Deleter(sr_val_t **vals, size_t *cnt) {
    Deleter::init_all();
    p_vals = vals;
    p_cnt = cnt;
    _t = VALS_POINTER;
}
Deleter::Deleter(sr_node_t *tree) {
    Deleter::init_all();
    _tree = tree;
    _t = TREE;
}
Deleter::Deleter(sr_node_t *trees, size_t cnt) {
    Deleter::init_all();
    _tree = trees;
    _cnt = cnt;
    _t = TREES;
}
Deleter::Deleter(sr_node_t **trees, size_t *cnt) {
    Deleter::init_all();
    p_trees = trees;
    p_cnt = cnt;
    _t = TREES_POINTER;
}
Deleter::Deleter(sr_schema_t *sch, size_t cnt) {
    Deleter::init_all();
    _sch = sch;
    _cnt = cnt;
    _t = SCHEMAS;
}
Deleter::~Deleter() {
    switch(_t) {
    case VAL:
        if (_val) sr_free_val(_val);
	_val = NULL;
    break;
    case VALS:
        if (_val) sr_free_values(_val, _cnt);
	_val = NULL;
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
        if (_tree) sr_free_trees(_tree, _cnt);
	_tree = NULL;
    break;
    case TREES_POINTER:
        if (*p_trees) sr_free_trees(*p_trees, *p_cnt);
	*p_trees = NULL;
    case SCHEMAS:
        if (_sch) sr_free_schemas(_sch, _cnt);
	_sch = NULL;
    break;
    }
    return;
}
