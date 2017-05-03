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
#include "Sysrepo.h"
#include <iostream>

extern "C" {
#include "sysrepo.h"
#include "sysrepo/trees.h"
}

using namespace std;

Deleter::Deleter(sr_val_t *val) {
    v._val = val;
    _t = VAL;
}
Deleter::Deleter(sr_val_t *vals, size_t cnt) {
    v._val = vals;
    c._cnt = cnt;
    _t = VALS;
}
Deleter::Deleter(sr_val_t **vals, size_t *cnt) {
    v.p_vals = vals;
    c.p_cnt = cnt;
    _t = VALS_POINTER;
}
Deleter::Deleter(sr_node_t *tree) {
    v._tree = tree;
    _t = TREE;
}
Deleter::Deleter(sr_node_t *trees, size_t cnt) {
    v._tree = trees;
    c._cnt = cnt;
    _t = TREES;
}
Deleter::Deleter(sr_node_t **trees, size_t *cnt) {
    v.p_trees = trees;
    c.p_cnt = cnt;
    _t = TREES_POINTER;
}
Deleter::Deleter(sr_schema_t *sch, size_t cnt) {
    v._sch = sch;
    c._cnt = cnt;
    _t = SCHEMAS;
}
Deleter::Deleter(sr_session_ctx_t *sess) {
    v._sess = sess;
    _t = SESSION;
}
Deleter::~Deleter() {
    switch(_t) {
    case VAL:
        if (v._val) sr_free_val(v._val);
	v._val = NULL;
    break;
    case VALS:
        if (v._val) sr_free_values(v._val, c._cnt);
	v._val = NULL;
    break;
    case VALS_POINTER:
        if (*v.p_vals) sr_free_values(*v.p_vals, *c.p_cnt);
	*v.p_vals = NULL;
    break;
    case TREE:
        if (v._tree) sr_free_tree(v._tree);
	v._tree = NULL;
    break;
    case TREES:
        if (v._tree) sr_free_trees(v._tree, c._cnt);
	v._tree = NULL;
    break;
    case TREES_POINTER:
        if (*v.p_trees) sr_free_trees(*v.p_trees, *c.p_cnt);
	*v.p_trees = NULL;
    break;
    case SCHEMAS:
        if (v._sch) sr_free_schemas(v._sch, c._cnt);
	v._sch = NULL;
    break;
    case SESSION:
        if (!v._sess) break;
        int ret = sr_session_stop(v._sess);
        if (ret != SR_ERR_OK) {
            //this exception can't be catched
            //throw_exception(ret);
        }
	v._sess = NULL;
    break;
    }
    return;
}
