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

#include <iostream>
#include <memory>

extern "C" {
#include "sysrepo.h"
#include "sysrepo/trees.h"
}

namespace sysrepo {

enum class Free_Type {
    VAL,
    VALS,
    VALS_POINTER,
    TREE,
    TREES,
    TREES_POINTER,
    SCHEMAS,
    SESSION,
};

typedef union value_e {
    sr_val_t *_val;
    sr_val_t **p_vals;
    sr_node_t *_tree;
    sr_node_t **p_trees;
    sr_schema_t *_sch;
    sr_session_ctx_t *_sess;
} value_t;

typedef union count_e {
    size_t _cnt;
    size_t *p_cnt;
} count_t;

class Deleter
{
public:
    Deleter(sr_val_t *val);
    Deleter(sr_val_t *vals, size_t cnt);
    Deleter(sr_val_t **vals, size_t *cnt);
    Deleter(sr_node_t *tree);
    Deleter(sr_node_t *trees, size_t cnt);
    Deleter(sr_node_t **trees, size_t *cnt);
    Deleter(sr_schema_t *sch, size_t cnt);
    Deleter(sr_session_ctx_t *sess);
    ~Deleter();

    void update_vals_with_count(sr_val_t *val, size_t cnt);

private:
    count_t c;
    value_t v;
    Free_Type _t;
};

}
#endif
