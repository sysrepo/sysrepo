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

    _tree = node;
}
Tree::Tree(sr_node_t *tree) {_tree = tree;}
Tree::~Tree() {
    if (_tree != NULL)
        sr_free_tree(_tree);
}
shared_ptr<Tree> Tree::dup() {
    sr_node_t *tree_dup = NULL;
    if (_tree == NULL) return NULL;

    int ret = sr_dup_tree(_tree, &tree_dup);
    if (ret != SR_ERR_OK) throw_exception(ret);

    shared_ptr<Tree> dup(new Tree(tree_dup));
    return dup;
}
shared_ptr<Node> Tree::node() {
    if (_tree == NULL) return NULL;

    shared_ptr<Node> node(new Node(_tree));
    return node;
}

Trees::Trees() {_trees = NULL; _cnt = 0; p_tree = NULL;}
Trees::Trees(size_t n) {
    sr_node_t *trees = NULL;

    int ret = sr_new_trees(n, &trees);
    if (ret != SR_ERR_OK)
        throw_exception(ret);

    p_tree = NULL;
    _trees = trees;
    _cnt = n;
}
Trees::Trees(sr_node_t **trees, size_t *cnt, size_t n) {
    int ret = sr_new_trees(n, trees);
    if (ret != SR_ERR_OK)
        throw_exception(ret);

    _trees = *trees;
    p_tree = trees;
    _cnt = n;
    *cnt = n;
}
Trees::Trees(const sr_node_t *trees, const size_t n) {
    _trees = (sr_node_t *) trees;
    _cnt = (size_t) n;
    p_tree = NULL;
}
Trees::~Trees() {
    if (_trees != NULL && p_tree == NULL)
        sr_free_trees(_trees, _cnt);
}
shared_ptr<Tree> Trees::tree(size_t n) {
    if (_trees == NULL || n >= _cnt) return NULL;

    shared_ptr<Tree> tree(new Tree(&_trees[n]));
    return tree;
}
shared_ptr<Trees> Trees::dup() {
    sr_node_t *tree_dup = NULL;
    if (_trees == NULL || _cnt == 0) return NULL;

    int ret = sr_dup_trees(_trees, _cnt, &tree_dup);
    if (ret != SR_ERR_OK) throw_exception(ret);

    shared_ptr<Trees> dup(new Trees(tree_dup, _cnt));
    return dup;
}
