/**
 * @file trees_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Unit tests targeting functions from "sysrepo/trees.h".
 *
 * @copyright
 * Copyright 2015 Cisco Systems, Inc.
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

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <setjmp.h>
#include <cmocka.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "sr_common.h"
#include "system_helper.h"

/**
 * @brief Retrieve child of a parent node by an index.
 */
static sr_node_t *
get_child_by_index(sr_node_t *parent, int index)
{
    assert_non_null(parent->first_child);
    sr_node_t *child = parent->first_child;

    while (index) {
        child = child->next;
        assert_non_null(child);
        --index;
    }
    return child;
}

static void
sr_new_tree_test(void **state)
{
    int rc = 0;
    sr_node_t *tree = NULL;

    rc = sr_new_tree(NULL, NULL, &tree);
    assert_int_equal(SR_ERR_OK, rc);
#ifdef USE_SR_MEM_MGMT
    assert_non_null(tree->_sr_mem);
    assert_int_equal(1, tree->_sr_mem->obj_count);
    assert_true(0 < tree->_sr_mem->used_total);
#else
    assert_null(tree->_sr_mem);
#endif
    assert_null(tree->name);
    assert_false(tree->dflt);
    assert_null(tree->module_name);
    assert_int_equal(SR_UNKNOWN_T, tree->type);
    assert_int_equal(0, tree->data.uint64_val);
    assert_null(tree->parent);
    assert_null(tree->first_child);
    assert_null(tree->last_child);
    assert_null(tree->prev);
    assert_null(tree->next);
    sr_free_tree(tree);

    rc = sr_new_tree("leaf", NULL, &tree);
    assert_int_equal(SR_ERR_OK, rc);
#ifdef USE_SR_MEM_MGMT
    assert_non_null(tree->_sr_mem);
    assert_int_equal(1, tree->_sr_mem->obj_count);
    assert_true(0 < tree->_sr_mem->used_total);
#else
    assert_null(tree->_sr_mem);
#endif
    assert_string_equal("leaf", tree->name);
    assert_false(tree->dflt);
    assert_null(tree->module_name);
    assert_int_equal(SR_UNKNOWN_T, tree->type);
    assert_int_equal(0, tree->data.uint64_val);
    assert_null(tree->parent);
    assert_null(tree->first_child);
    assert_null(tree->last_child);
    assert_null(tree->prev);
    assert_null(tree->next);
    sr_free_tree(tree);

    rc = sr_new_tree("leaf", "example-module", &tree);
    assert_int_equal(SR_ERR_OK, rc);
#ifdef USE_SR_MEM_MGMT
    assert_non_null(tree->_sr_mem);
    assert_int_equal(1, tree->_sr_mem->obj_count);
    assert_true(0 < tree->_sr_mem->used_total);
#else
    assert_null(tree->_sr_mem);
#endif
    assert_string_equal("leaf", tree->name);
    assert_false(tree->dflt);
    assert_string_equal("example-module", tree->module_name);
    assert_int_equal(SR_UNKNOWN_T, tree->type);
    assert_int_equal(0, tree->data.uint64_val);
    assert_null(tree->parent);
    assert_null(tree->first_child);
    assert_null(tree->last_child);
    assert_null(tree->prev);
    assert_null(tree->next);
    sr_free_tree(tree);
}

static void
sr_new_trees_test(void **state)
{
    int rc = 0;
    sr_node_t *trees = NULL;

    rc = sr_new_trees(10, &trees);
    assert_int_equal(SR_ERR_OK, rc);
#ifdef USE_SR_MEM_MGMT
    assert_non_null(trees->_sr_mem);
    assert_int_equal(1, trees->_sr_mem->obj_count);
    assert_true(0 < trees->_sr_mem->used_total);
#else
    assert_null(trees->_sr_mem);
#endif

    for (int i = 0; i < 10; ++i) {
#ifdef USE_SR_MEM_MGMT
        if (0 < i) {
            assert_ptr_equal(trees[i-1]._sr_mem, trees[i]._sr_mem);
        }
#endif
        assert_null(trees[i].name);
        assert_false(trees[i].dflt);
        assert_null(trees[i].module_name);
        assert_int_equal(SR_UNKNOWN_T, trees[i].type);
        assert_int_equal(0, trees[i].data.uint64_val);
        assert_null(trees[i].parent);
        assert_null(trees[i].first_child);
        assert_null(trees[i].last_child);
        assert_null(trees[i].prev);
        assert_null(trees[i].next);
    }

    sr_free_trees(trees, 10);
}

static void
sr_node_set_name_test(void **state)
{
    int rc = 0;
    sr_node_t *tree = NULL, *trees = NULL;
    char name[10] = { 0, };
   
    /* single tree */
    rc = sr_new_tree(NULL, NULL, &tree);
    assert_int_equal(SR_ERR_OK, rc);
    assert_null(tree->name);
    rc = sr_node_set_name(tree, "container");
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("container", tree->name);
    rc = sr_node_set_name(tree, "leaf");
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("leaf", tree->name);
    sr_free_tree(tree);

    /* trees */
    rc = sr_new_trees(10, &trees);
    assert_int_equal(SR_ERR_OK, rc);
    for (int i = 0; i < 10; ++i) {
        assert_null(trees[i].name);
        snprintf(name, 10, "node-%d", i);
        rc = sr_node_set_name(trees + i, name);
        assert_int_equal(SR_ERR_OK, rc);
    }
    for (int i = 0; i < 10; ++i) {
        snprintf(name, 10, "node-%d", i);
        assert_string_equal(name, trees[i].name);
    }
    sr_free_trees(trees, 10);
}

static void
sr_node_set_module_test(void **state)
{
    int rc = 0;
    sr_node_t *tree = NULL, *trees = NULL;
   
    /* single tree */
    rc = sr_new_tree(NULL, NULL, &tree);
    assert_int_equal(SR_ERR_OK, rc);
    assert_null(tree->module_name);
    rc = sr_node_set_module(tree, "example-module");
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("example-module", tree->module_name);
    rc = sr_node_set_module(tree, "test-module");
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("test-module", tree->module_name);
    sr_free_tree(tree);

    /* trees */
    rc = sr_new_trees(10, &trees);
    assert_int_equal(SR_ERR_OK, rc);
    for (int i = 0; i < 10; ++i) {
        assert_null(trees[i].module_name);
        rc = sr_node_set_module(trees + i, "example-module");
        assert_int_equal(SR_ERR_OK, rc);
    }
    for (int i = 0; i < 10; ++i) {
        if (0 < i) {
            assert_ptr_not_equal(trees[i-1].module_name, trees[i].module_name);
        }
        assert_string_equal("example-module", trees[i].module_name);
    }
    sr_free_trees(trees, 10);
}

static void
sr_node_set_string_test(void **state)
{
    int rc = 0;
    sr_node_t *tree = NULL;

    rc = sr_new_tree("leaf", "trst-module", &tree);
    assert_int_equal(SR_ERR_OK, rc);
    assert_null(tree->data.string_val);

    rc = sr_node_set_string(tree, "string value");
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    tree->type = SR_STRING_T;
    rc = sr_node_set_string(tree, "string value");
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("string value", tree->data.string_val);

    tree->type = SR_BINARY_T;
    rc = sr_node_set_string(tree, "binary value");
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("binary value", tree->data.binary_val);

    tree->type = SR_ENUM_T;
    rc = sr_node_set_string(tree, "enum value");
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("enum value", tree->data.enum_val);

    tree->type = SR_BITS_T;
    rc = sr_node_set_string(tree, "bits");
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("bits", tree->data.bits_val);

    tree->type = SR_IDENTITYREF_T;
    rc = sr_node_set_string(tree, "identityref value");
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("identityref value", tree->data.identityref_val);

    tree->type = SR_INSTANCEID_T;
    rc = sr_node_set_string(tree, "instance ID");
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("instance ID", tree->data.instanceid_val);

    sr_free_tree(tree);
}

static sr_node_t *
create_example_module_trees(size_t *tree_cnt)
{
    int rc = 0;
    sr_node_t *trees = NULL, *node = NULL, *leaf = NULL;
    char value[10] = { 0, };

    rc = sr_new_trees(6, &trees);
    assert_int_equal(SR_ERR_OK, rc);

    /* /example_module:container */
    rc = sr_node_set_name(trees, "container");
    assert_int_equal(SR_ERR_OK, rc);
    rc = sr_node_set_module(trees, "example-module");
    assert_int_equal(SR_ERR_OK, rc);
    trees[0].type = SR_CONTAINER_T;

    for (int i = 0; i < 10; ++i) {
        /* /example_module:container/list[key1="key1-i"][key2="key2-i"] */
        rc = sr_node_add_child(trees, "list", NULL, &node);
        assert_int_equal(SR_ERR_OK, rc);
        node->type = SR_LIST_T;
        assert_ptr_equal(trees, node->parent);
        if (0 < i) {
            assert_ptr_equal(get_child_by_index(trees, i-1), node->prev);
            assert_ptr_equal(node->prev->next, node);
        } else {
            assert_null(node->prev);
        }
        assert_null(node->next);
        assert_null(node->first_child);
        assert_null(node->last_child);
        assert_ptr_equal(get_child_by_index(trees, i), node);

        /* /example_module:container/list[key1="key1-i"][key2="key2-i"]/key1 */
        rc = sr_node_add_child(node, "key1", NULL, &leaf);
        assert_int_equal(SR_ERR_OK, rc);
        leaf->type = SR_STRING_T;
        snprintf(value, 10, "key1-%d", i);
        rc = sr_node_set_string(leaf, value);
        assert_int_equal(SR_ERR_OK, rc);
        assert_ptr_equal(node, leaf->parent);
        assert_null(leaf->prev);
        assert_null(leaf->next);
        assert_null(leaf->first_child);
        assert_null(leaf->last_child);
        assert_ptr_equal(get_child_by_index(node, 0), leaf);

        /* /example_module:container/list[key1="key1-i"][key2="key2-i"]/key2 */
        rc = sr_node_add_child(node, "key2", NULL, &leaf);
        assert_int_equal(SR_ERR_OK, rc);
        leaf->type = SR_STRING_T;
        snprintf(value, 10, "key2-%d", i);
        rc = sr_node_set_string(leaf, value);
        assert_int_equal(SR_ERR_OK, rc);
        assert_ptr_equal(node, leaf->parent);
        assert_ptr_equal(get_child_by_index(node, 0), leaf->prev);
        assert_ptr_equal(leaf->prev->next, leaf);
        assert_null(leaf->next);
        assert_null(leaf->first_child);
        assert_null(leaf->last_child);
        assert_ptr_equal(get_child_by_index(node, 1), leaf);

        /* /example_module:container/list[key1="key1-i"][key2="key2-i"]/leaf (="leaf-i") */
        rc = sr_node_add_child(node, "leaf", NULL, &leaf);
        assert_int_equal(SR_ERR_OK, rc);
        leaf->type = SR_STRING_T;
        snprintf(value, 10, "leaf-%d", i);
        rc = sr_node_set_string(leaf, value);
        assert_int_equal(SR_ERR_OK, rc);
        assert_ptr_equal(node, leaf->parent);
        assert_ptr_equal(get_child_by_index(node, 1), leaf->prev);
        assert_ptr_equal(leaf->prev->next, leaf);
        assert_null(leaf->next);
        assert_null(leaf->first_child);
        assert_null(leaf->last_child);
        assert_ptr_equal(get_child_by_index(node, 2), leaf);
    }

    for (int i = 0; i < 5; ++i) {
        /* /example_module:number[.=i] */
        rc = sr_node_set_name(trees + i + 1, "number");
        assert_int_equal(SR_ERR_OK, rc);
        rc = sr_node_set_module(trees + i + 1, "example-module");
        assert_int_equal(SR_ERR_OK, rc);
        trees[i+1].type = SR_UINT16_T;
        trees[i+1].data.uint16_val = i;
    }

    assert_non_null(tree_cnt);
    *tree_cnt = 6;
    return trees;
}

static void
sr_node_add_child_test(void **state)
{
    int rc = SR_ERR_OK;
    sr_node_t *trees = NULL;
    size_t tree_cnt = 0;

    trees = create_example_module_trees(&tree_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_trees(trees, tree_cnt);
}

static void
sr_dup_tree_test(void **state)
{
    int rc = SR_ERR_OK;
    sr_node_t *trees = NULL, *tree_dup = NULL, *node = NULL, *leaf = NULL;
    size_t tree_cnt = 0;
    char value[10] = { 0, };

    trees = create_example_module_trees(&tree_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    /* duplicate the container */
    rc = sr_dup_tree(&trees[0], &tree_dup);
    assert_int_equal(SR_ERR_OK, rc);

    /* /example_module:container */
    assert_non_null(tree_dup);
#ifdef USE_SR_MEM_MGMT
    assert_non_null(tree_dup->_sr_mem);
    assert_ptr_not_equal(trees->_sr_mem, tree_dup->_sr_mem);
    assert_int_equal(1, tree_dup->_sr_mem->obj_count);
    assert_true(0 < tree_dup->_sr_mem->used_total);
#else
    assert_null(tree_dup->_sr_mem);
#endif
    assert_string_equal("container", tree_dup->name);
    assert_false(tree_dup->dflt);
    assert_string_equal("example-module", tree_dup->module_name);
    assert_int_equal(SR_CONTAINER_T, tree_dup->type);
    assert_null(tree_dup->parent);
    assert_non_null(tree_dup->first_child);
    assert_non_null(tree_dup->last_child);
    assert_null(tree_dup->prev);
    assert_null(tree_dup->next);
    for (int i = 0; i < 10; ++i) {
        /* /example_module:container/list[key1="key1-i"][key2="key2-i"] */
        node = get_child_by_index(tree_dup, i);
        assert_string_equal("list", node->name);
        assert_false(node->dflt);
        assert_null(node->module_name);
        assert_int_equal(SR_LIST_T, node->type);
        assert_ptr_equal(tree_dup, node->parent);
        assert_non_null(node->first_child);
        assert_non_null(node->last_child);
        if (0 < i) {
            assert_ptr_equal(get_child_by_index(tree_dup, i-1), node->prev);
            assert_ptr_equal(node->prev->next, node);
        } else {
            assert_null(node->prev);
        }
        if (9 > i) {
            assert_ptr_equal(get_child_by_index(tree_dup, i+1), node->next);
            assert_ptr_equal(node->next->prev, node);
        } else {
            assert_null(node->next);
        }

        /* /example_module:container/list[key1="key1-i"][key2="key2-i"]/key1 */
        leaf = get_child_by_index(node, 0);
        assert_string_equal("key1", leaf->name);
        assert_false(leaf->dflt);
        assert_null(leaf->module_name);
        assert_int_equal(SR_STRING_T, leaf->type);
        snprintf(value, 10, "key1-%d", i);
        assert_string_equal(value, leaf->data.string_val);
        assert_ptr_equal(node, leaf->parent);
        assert_null(leaf->first_child);
        assert_null(leaf->last_child);
        assert_null(leaf->prev);
        assert_ptr_equal(get_child_by_index(node, 1), leaf->next);
        assert_ptr_equal(leaf->next->prev, leaf);

        /* /example_module:container/list[key1="key1-i"][key2="key2-i"]/key2 */
        leaf = get_child_by_index(node, 1);
        assert_string_equal("key2", leaf->name);
        assert_false(leaf->dflt);
        assert_null(leaf->module_name);
        assert_int_equal(SR_STRING_T, leaf->type);
        snprintf(value, 10, "key2-%d", i);
        assert_string_equal(value, leaf->data.string_val);
        assert_ptr_equal(node, leaf->parent);
        assert_null(leaf->first_child);
        assert_null(leaf->last_child);
        assert_ptr_equal(get_child_by_index(node, 0), leaf->prev);
        assert_ptr_equal(leaf->prev->next, leaf);
        assert_ptr_equal(get_child_by_index(node, 2), leaf->next);
        assert_ptr_equal(leaf->next->prev, leaf);

        /* /example_module:container/list[key1="key1-i"][key2="key2-i"]/leaf */
        leaf = get_child_by_index(node, 2);
        assert_string_equal("leaf", leaf->name);
        assert_false(leaf->dflt);
        assert_null(leaf->module_name);
        assert_int_equal(SR_STRING_T, leaf->type);
        snprintf(value, 10, "leaf-%d", i);
        assert_string_equal(value, leaf->data.string_val);
        assert_ptr_equal(node, leaf->parent);
        assert_null(leaf->first_child);
        assert_null(leaf->last_child);
        assert_ptr_equal(get_child_by_index(node, 1), leaf->prev);
        assert_ptr_equal(leaf->prev->next, leaf);
        assert_null(leaf->next);
    }
    sr_free_tree(tree_dup);

    /* duplicate the second leaf-list */
    rc = sr_dup_tree(&trees[2], &tree_dup);
    assert_int_equal(SR_ERR_OK, rc);

    /* /example_module:number[.=0] */
    assert_non_null(tree_dup);
#ifdef USE_SR_MEM_MGMT
    assert_non_null(tree_dup->_sr_mem);
    assert_ptr_not_equal(trees->_sr_mem, tree_dup->_sr_mem);
    assert_int_equal(1, tree_dup->_sr_mem->obj_count);
    assert_true(0 < tree_dup->_sr_mem->used_total);
#else
    assert_null(tree_dup->_sr_mem);
#endif
    assert_string_equal("number", tree_dup->name);
    assert_false(tree_dup->dflt);
    assert_string_equal("example-module", tree_dup->module_name);
    assert_int_equal(SR_UINT16_T, tree_dup->type);
    assert_int_equal(1, tree_dup->data.uint16_val);
    assert_null(tree_dup->parent);
    assert_null(tree_dup->first_child);
    assert_null(tree_dup->last_child);
    assert_null(tree_dup->prev);
    assert_null(tree_dup->next);

    sr_free_tree(tree_dup);
    sr_free_trees(trees, tree_cnt);
}

static void
sr_dup_trees_test(void **state)
{
    int rc = SR_ERR_OK;
    sr_node_t *trees = NULL, *trees_dup = NULL, *node = NULL, *leaf = NULL;
    size_t tree_cnt = 0;
    char value[10] = { 0, };

    trees = create_example_module_trees(&tree_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    /* duplicate the array of trees */
    rc = sr_dup_trees(trees, tree_cnt, &trees_dup);
    assert_int_equal(SR_ERR_OK, rc);

    /* /example_module:container */
    assert_non_null(trees_dup);
#ifdef USE_SR_MEM_MGMT
    assert_non_null(trees_dup->_sr_mem);
    assert_ptr_not_equal(trees->_sr_mem, trees_dup->_sr_mem);
    assert_int_equal(1, trees_dup->_sr_mem->obj_count);
    assert_true(0 < trees_dup->_sr_mem->used_total);
#else
    assert_null(trees_dup->_sr_mem);
#endif
    assert_string_equal("container", trees_dup->name);
    assert_false(trees_dup->dflt);
    assert_string_equal("example-module", trees_dup->module_name);
    assert_int_equal(SR_CONTAINER_T, trees_dup->type);
    assert_null(trees_dup->parent);
    assert_non_null(trees_dup->first_child);
    assert_non_null(trees_dup->last_child);
    assert_null(trees_dup->prev);
    assert_null(trees_dup->next);
    for (int i = 0; i < 10; ++i) {
        /* /example_module:container/list[key1="key1-i"][key2="key2-i"] */
        node = get_child_by_index(trees_dup, i);
        assert_string_equal("list", node->name);
        assert_false(node->dflt);
        assert_null(node->module_name);
        assert_int_equal(SR_LIST_T, node->type);
        assert_ptr_equal(trees_dup, node->parent);
        assert_non_null(node->first_child);
        assert_non_null(node->last_child);
        if (0 < i) {
            assert_ptr_equal(get_child_by_index(trees_dup, i-1), node->prev);
            assert_ptr_equal(node->prev->next, node);
        } else {
            assert_null(node->prev);
        }
        if (9 > i) {
            assert_ptr_equal(get_child_by_index(trees_dup, i+1), node->next);
            assert_ptr_equal(node->next->prev, node);
        } else {
            assert_null(node->next);
        }

        /* /example_module:container/list[key1="key1-i"][key2="key2-i"]/key1 */
        leaf = get_child_by_index(node, 0);
        assert_string_equal("key1", leaf->name);
        assert_false(leaf->dflt);
        assert_null(leaf->module_name);
        assert_int_equal(SR_STRING_T, leaf->type);
        snprintf(value, 10, "key1-%d", i);
        assert_string_equal(value, leaf->data.string_val);
        assert_ptr_equal(node, leaf->parent);
        assert_null(leaf->first_child);
        assert_null(leaf->last_child);
        assert_null(leaf->prev);
        assert_ptr_equal(get_child_by_index(node, 1), leaf->next);
        assert_ptr_equal(leaf->next->prev, leaf);

        /* /example_module:container/list[key1="key1-i"][key2="key2-i"]/key2 */
        leaf = get_child_by_index(node, 1);
        assert_string_equal("key2", leaf->name);
        assert_false(leaf->dflt);
        assert_null(leaf->module_name);
        assert_int_equal(SR_STRING_T, leaf->type);
        snprintf(value, 10, "key2-%d", i);
        assert_string_equal(value, leaf->data.string_val);
        assert_ptr_equal(node, leaf->parent);
        assert_null(leaf->first_child);
        assert_null(leaf->last_child);
        assert_ptr_equal(get_child_by_index(node, 0), leaf->prev);
        assert_ptr_equal(leaf->prev->next, leaf);
        assert_ptr_equal(get_child_by_index(node, 2), leaf->next);
        assert_ptr_equal(leaf->next->prev, leaf);

        /* /example_module:container/list[key1="key1-i"][key2="key2-i"]/leaf */
        leaf = get_child_by_index(node, 2);
        assert_string_equal("leaf", leaf->name);
        assert_false(leaf->dflt);
        assert_null(leaf->module_name);
        assert_int_equal(SR_STRING_T, leaf->type);
        snprintf(value, 10, "leaf-%d", i);
        assert_string_equal(value, leaf->data.string_val);
        assert_ptr_equal(node, leaf->parent);
        assert_null(leaf->first_child);
        assert_null(leaf->last_child);
        assert_ptr_equal(get_child_by_index(node, 1), leaf->prev);
        assert_ptr_equal(leaf->prev->next, leaf);
        assert_null(leaf->next);
    }

    for (int i = 1; i < tree_cnt; ++i) { 
        /* /example_module:number[.=0] */
        leaf = trees_dup + i;
        assert_non_null(leaf);
#ifdef USE_SR_MEM_MGMT
        assert_non_null(leaf->_sr_mem);
        assert_ptr_not_equal(trees->_sr_mem, leaf->_sr_mem);
        assert_ptr_equal(trees_dup[i-1]._sr_mem, leaf->_sr_mem);
        assert_int_equal(1, leaf->_sr_mem->obj_count);
        assert_true(0 < leaf->_sr_mem->used_total);
#else
        assert_null(leaf->_sr_mem);
#endif
        assert_string_equal("number", leaf->name);
        assert_false(leaf->dflt);
        assert_string_equal("example-module", leaf->module_name);
        assert_int_equal(SR_UINT16_T, leaf->type);
        assert_int_equal(i-1, leaf->data.uint16_val);
        assert_null(leaf->parent);
        assert_null(leaf->first_child);
        assert_null(leaf->last_child);
        assert_null(leaf->prev);
        assert_null(leaf->next);
    }

    sr_free_trees(trees_dup, tree_cnt);
    sr_free_trees(trees, tree_cnt);
}

static void
sr_test_all_printers(sr_node_t *tree, int depth_level, const char *expected)
{
    int rc = SR_ERR_OK;
    char *mem = NULL;
    char filepath1[] = "/tmp/sr_tree_test1.XXXXXX", filepath2[] = "/tmp/sr_tree_test2.XXXXXX";
    int fd = 0;
    FILE *stream = NULL;
    mode_t orig_umask = umask(S_IRWXO|S_IRWXG);

    /* memory */
    rc = sr_print_tree_mem(&mem, tree, depth_level);
    assert_int_equal(SR_ERR_OK, rc);
    if (NULL == expected) {
        assert_null(mem);
    } else {
        assert_non_null(mem);
        assert_string_equal(expected, mem);
    }
    free(mem);

    /* fd */
    fd = mkstemp(filepath1);
    assert_true(0 < fd);
    rc = sr_print_tree_fd(fd, tree, depth_level);
    assert_int_equal(SR_ERR_OK, rc);
    close(fd);
    test_file_content(filepath1, expected ? expected : "", false);
    unlink(filepath1);

    /* stream */
    fd = mkstemp(filepath2);
    assert_true(0 < fd);
    stream = fdopen(fd, "w");
    assert_non_null(stream);
    rc = sr_print_tree_stream(stream, tree, depth_level);
    assert_int_equal(SR_ERR_OK, rc);
    fclose(stream);
    test_file_content(filepath2, expected ? expected : "", false);
    unlink(filepath2);
    umask(orig_umask);
}

static void
sr_print_tree_test(void **state)
{
    sr_node_t *tree = NULL, *node = NULL;

    /* empty tree */
    sr_test_all_printers(tree, INT_MAX, NULL);

    /* one leaf tree */
    assert_int_equal(SR_ERR_OK, sr_new_tree("root", "test-module", &tree));
    tree->type = SR_UINT32_T;
    tree->data.uint32_val = 123;
    sr_test_all_printers(tree, INT_MAX, "test-module:root = 123\n");

    /* 2 levels */
    tree->type = SR_CONTAINER_T;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(tree, "root-child1", NULL, &node));
    node->type = SR_BOOL_T;
    node->data.bool_val = true;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(tree, "root-child2", NULL, &node));
    node->type = SR_STRING_T;
    assert_int_equal(SR_ERR_OK, sr_node_set_string(node, "string value"));
    assert_int_equal(SR_ERR_OK, sr_node_add_child(tree, "root-child3", NULL, &node));
    node->type = SR_LIST_T;

#define TREE_WITH_TWO_LEVELS \
    "test-module:root (container)\n"\
    " |\n"\
    " -- root-child1 = true\n"\
    " |\n"\
    " -- root-child2 = string value\n"\
    " |\n"\
    " -- root-child3 (list instance)\n"

    sr_test_all_printers(tree, INT_MAX, TREE_WITH_TWO_LEVELS);

    /* 3 levels */
    node = tree->first_child;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(node, "a", "another-module", &node));
    node->type = SR_UINT8_T;
    node->data.uint8_val = 56;
    node = node->parent;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(node, "b", "another-module", &node));
    node->type = SR_UINT16_T;
    node->data.uint16_val = 1234;
    node = node->parent;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(node, "c", "another-module", &node));
    node->type = SR_UINT32_T;
    node->data.uint32_val = 10000;
    node = node->parent->next;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(node, "leaf", NULL, &node));
    node->type = SR_LEAF_EMPTY_T;
    node = node->parent->next;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(node, "list1", NULL, &node));
    node->type = SR_LIST_T;
    node = node->parent;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(node, "list2", NULL, &node));
    node->type = SR_LIST_T;
    node = node->parent;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(node, "list3", NULL, &node));
    node->type = SR_LIST_T;

#define TREE_WITH_THREE_LEVELS \
    "test-module:root (container)\n"\
    " |\n"\
    " -- root-child1 = true\n"\
    " |   |\n"\
    " |   -- another-module:a = 56\n"\
    " |   |\n"\
    " |   -- another-module:b = 1234\n"\
    " |   |\n"\
    " |   -- another-module:c = 10000\n"\
    " |\n"\
    " -- root-child2 = string value\n"\
    " |   |\n"\
    " |   -- leaf (empty leaf)\n"\
    " |\n"\
    " -- root-child3 (list instance)\n"\
    "     |\n"\
    "     -- list1 (list instance)\n"\
    "     |\n"\
    "     -- list2 (list instance)\n"\
    "     |\n"\
    "     -- list3 (list instance)\n"

    sr_test_all_printers(tree, INT_MAX, TREE_WITH_THREE_LEVELS);

    /* 4 levels */
    node = tree->first_child->first_child;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(node, "a1", NULL, &node));
    node->type = SR_STRING_T;
    assert_int_equal(SR_ERR_OK, sr_node_set_string(node, "abc"));
    node = node->parent;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(node, "a2", NULL, &node));
    node->type = SR_STRING_T;
    assert_int_equal(SR_ERR_OK, sr_node_set_string(node, "def"));
    node = node->parent->next->next;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(node, "c1", NULL, &node));
    node->type = SR_BOOL_T;
    node->data.bool_val = true;
    node = node->parent;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(node, "c2", NULL, &node));
    node->type = SR_BOOL_T;
    node->data.bool_val = true;
    node = node->parent;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(node, "c3", NULL, &node));
    node->type = SR_BOOL_T;
    node->data.bool_val = false;
    node = tree->last_child->first_child;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(node, "key", NULL, &node));
    node->type = SR_UINT16_T;
    node->data.uint16_val = 11;
    node = node->parent->next;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(node, "key", NULL, &node));
    node->type = SR_UINT16_T;
    node->data.uint16_val = 12;
    node = node->parent->next;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(node, "key", NULL, &node));
    node->type = SR_UINT16_T;
    node->data.uint16_val = 13;

#define TREE_WITH_FOUR_LEVELS \
    "test-module:root (container)\n"\
    " |\n"\
    " -- root-child1 = true\n"\
    " |   |\n"\
    " |   -- another-module:a = 56\n"\
    " |   |   |\n"\
    " |   |   -- a1 = abc\n"\
    " |   |   |\n"\
    " |   |   -- a2 = def\n"\
    " |   |\n"\
    " |   -- another-module:b = 1234\n"\
    " |   |\n"\
    " |   -- another-module:c = 10000\n"\
    " |       |\n"\
    " |       -- c1 = true\n"\
    " |       |\n"\
    " |       -- c2 = true\n"\
    " |       |\n"\
    " |       -- c3 = false\n"\
    " |\n"\
    " -- root-child2 = string value\n"\
    " |   |\n"\
    " |   -- leaf (empty leaf)\n"\
    " |\n"\
    " -- root-child3 (list instance)\n"\
    "     |\n"\
    "     -- list1 (list instance)\n"\
    "     |   |\n"\
    "     |   -- key = 11\n"\
    "     |\n"\
    "     -- list2 (list instance)\n"\
    "     |   |\n"\
    "     |   -- key = 12\n"\
    "     |\n"\
    "     -- list3 (list instance)\n"\
    "         |\n"\
    "         -- key = 13\n"

    sr_test_all_printers(tree, INT_MAX, TREE_WITH_FOUR_LEVELS);

    /* depth limit = 0 */
    sr_test_all_printers(tree, 0, NULL);

    /* depth limit = 1 */
#define DEPTH_LIMIT_ONE \
    "test-module:root (container)\n"\
    " |\n"\
    " ...\n"

    sr_test_all_printers(tree, 1, DEPTH_LIMIT_ONE);

    /* depth limit = 2 */
#define DEPTH_LIMIT_TWO \
    "test-module:root (container)\n"\
    " |\n"\
    " -- root-child1 = true\n"\
    " |   |\n"\
    " |   ...\n"\
    " |\n"\
    " -- root-child2 = string value\n"\
    " |   |\n"\
    " |   ...\n"\
    " |\n"\
    " -- root-child3 (list instance)\n"\
    "     |\n"\
    "     ...\n"

    sr_test_all_printers(tree, 2, DEPTH_LIMIT_TWO);

    /* depth limit = 3 */
#define DEPTH_LIMIT_THREE \
    "test-module:root (container)\n"\
    " |\n"\
    " -- root-child1 = true\n"\
    " |   |\n"\
    " |   -- another-module:a = 56\n"\
    " |   |   |\n"\
    " |   |   ...\n"\
    " |   |\n"\
    " |   -- another-module:b = 1234\n"\
    " |   |\n"\
    " |   -- another-module:c = 10000\n"\
    " |       |\n"\
    " |       ...\n"\
    " |\n"\
    " -- root-child2 = string value\n"\
    " |   |\n"\
    " |   -- leaf (empty leaf)\n"\
    " |\n"\
    " -- root-child3 (list instance)\n"\
    "     |\n"\
    "     -- list1 (list instance)\n"\
    "     |   |\n"\
    "     |   ...\n"\
    "     |\n"\
    "     -- list2 (list instance)\n"\
    "     |   |\n"\
    "     |   ...\n"\
    "     |\n"\
    "     -- list3 (list instance)\n"\
    "         |\n"\
    "         ...\n"

    sr_test_all_printers(tree, 3, DEPTH_LIMIT_THREE);

    /* subtree */
#define SUBTREE \
    "root-child1 = true\n"\
    " |\n"\
    " -- another-module:a = 56\n"\
    " |   |\n"\
    " |   -- a1 = abc\n"\
    " |   |\n"\
    " |   -- a2 = def\n"\
    " |\n"\
    " -- another-module:b = 1234\n"\
    " |\n"\
    " -- another-module:c = 10000\n"\
    "     |\n"\
    "     -- c1 = true\n"\
    "     |\n"\
    "     -- c2 = true\n"\
    "     |\n"\
    "     -- c3 = false\n"\

    sr_test_all_printers(tree->first_child, INT_MAX, SUBTREE);

    /* with tree iterator */
    node = tree->first_child->first_child;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(node, "iter", NULL, &node));
    node->type = SR_TREE_ITERATOR_T;
    node->prev = node->next = node->parent = NULL;

#define TREE_WITH_ITERATOR \
    "test-module:root (container)\n"\
    " |\n"\
    " -- root-child1 = true\n"\
    " |   |\n"\
    " |   -- another-module:a = 56\n"\
    " |   |   |\n"\
    " |   |   -- a1 = abc\n"\
    " |   |   |\n"\
    " |   |   -- a2 = def\n"\
    " |   |   |\n"\
    " |   |   ...\n"\
    " |   |\n"\
    " |   -- another-module:b = 1234\n"\
    " |   |\n"\
    " |   -- another-module:c = 10000\n"\
    " |       |\n"\
    " |       -- c1 = true\n"\
    " |       |\n"\
    " |       -- c2 = true\n"\
    " |       |\n"\
    " |       -- c3 = false\n"\
    " |\n"\
    " -- root-child2 = string value\n"\
    " |   |\n"\
    " |   -- leaf (empty leaf)\n"\
    " |\n"\
    " -- root-child3 (list instance)\n"\
    "     |\n"\
    "     -- list1 (list instance)\n"\
    "     |   |\n"\
    "     |   -- key = 11\n"\
    "     |\n"\
    "     -- list2 (list instance)\n"\
    "     |   |\n"\
    "     |   -- key = 12\n"\
    "     |\n"\
    "     -- list3 (list instance)\n"\
    "         |\n"\
    "         -- key = 13\n"

    sr_test_all_printers(tree, INT_MAX, TREE_WITH_ITERATOR);

    sr_free_tree(tree);
}

int
main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(sr_new_tree_test),
        cmocka_unit_test(sr_new_trees_test),
        cmocka_unit_test(sr_node_set_name_test),
        cmocka_unit_test(sr_node_set_module_test),
        cmocka_unit_test(sr_node_set_string_test),
        cmocka_unit_test(sr_node_add_child_test),
        cmocka_unit_test(sr_dup_tree_test),
        cmocka_unit_test(sr_dup_trees_test),
        cmocka_unit_test(sr_print_tree_test)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
