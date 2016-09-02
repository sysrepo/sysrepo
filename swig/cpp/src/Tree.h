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

using namespace std;

class Tree:public Throw_Exception
{
public:
    Tree(const char *root_name, const char *root_module_name);
    Tree(sr_node_t *tree);
    shared_ptr<Tree> dup();
    shared_ptr<Node> node();
    sr_node_t *tree() {return _tree;};
    ~Tree();

private:
    sr_node_t *_tree;
};

class Trees:public Throw_Exception
{
public:
    Trees();
    Trees(size_t n);
    Trees(sr_node_t **trees, size_t *cnt, size_t n);
    Trees(const sr_node_t *trees, const size_t n);
    shared_ptr<Tree> tree(size_t n);
    shared_ptr<Trees> dup();
    size_t tree_cnt() {return _cnt;};
    size_t *p_trees_cnt() {return &_cnt;};
    sr_node_t **p_trees() {return &_trees;};
    sr_node_t *trees() {return _trees;};
    ~Trees();

private:
    sr_node_t **p_tree;
    sr_node_t *_trees;
    size_t _cnt;
};

#endif
