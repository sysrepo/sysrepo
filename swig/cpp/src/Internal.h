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

extern "C" {
#include "sysrepo.h"
#include "sysrepo/trees.h"
}

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
    void init_all();
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
