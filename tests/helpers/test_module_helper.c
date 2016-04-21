/**
 * @file test_module_helper.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief
 *
 * @copyright
 * Copyright 2016 Cisco Systems, Inc.
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

#include "test_module_helper.h"
#include "sr_common.h"
#include "test_data.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

void
createDataTreeTestModule()
{
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node = NULL;
    struct lyd_node *n = NULL;
    struct lyd_node *r = NULL;

    ctx = ly_ctx_new(TEST_SCHEMA_SEARCH_DIR);
    assert_non_null(ctx);

    const struct lys_module *module = ly_ctx_load_module(ctx, "test-module", NULL);
    assert_non_null(module);

    r = lyd_new(NULL, module, "main");
    assert_non_null(r);
    node = lyd_new_leaf(r, module, "enum", XP_TEST_MODULE_ENUM_VALUE);
    assert_non_null(node);
    node = lyd_new_leaf(r, module, "raw", XP_TEST_MODULE_RAW_VALUE);
    assert_non_null(node);

    /*Strict = 1, Recursive = 1, Loggin = 0*/
    node = lyd_new_leaf(r, module, "options", XP_TEST_MODULE_BITS_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "dec64", XP_TEST_MODULE_DEC64_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "i8", XP_TEST_MODULE_INT8_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "i16", XP_TEST_MODULE_INT16_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "i32", XP_TEST_MODULE_INT32_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "i64", XP_TEST_MODULE_INT64_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "ui8", XP_TEST_MODULE_UINT8_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "ui16", XP_TEST_MODULE_UINT16_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "ui32", XP_TEST_MODULE_UINT32_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "ui64", XP_TEST_MODULE_INT64_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "empty", XP_TEST_MODULE_EMPTY_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "boolean", XP_TEST_MODULE_BOOL_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "string", XP_TEST_MODULE_STRING_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "id_ref", XP_TEST_MODULE_IDREF_VALUE);
    assert_non_null(node);

    /* leaf -list*/
    n = lyd_new_leaf(r, module, "numbers", "1");
    assert_non_null(n);

    n = lyd_new_leaf(r, module, "numbers", "2");
    assert_non_null(n);

    n = lyd_new_leaf(r, module, "numbers", "42");
    assert_non_null(n);

    /* list k1*/
    node = lyd_new(NULL, module, "list");
    assert_non_null(node);
    assert_int_equal(0,lyd_insert_after(r, node));

    n = lyd_new_leaf(node, module, "key", "k1");
    assert_non_null(n);

    n = lyd_new_leaf(node, module, "id_ref", "id_1");
    assert_non_null(n);

    n = lyd_new_leaf(node, module, "union", "42");
    assert_non_null(n);

    /* presence container*/
    n = lyd_new(node, module, "wireless");
    assert_non_null(n);

    /* list k2*/
    node = lyd_new(NULL, module, "list");
    assert_non_null(node);
    assert_int_equal(0, lyd_insert_after(r, node));

    n = lyd_new_leaf(node, module, "key", "k2");
    assert_non_null(n);

    n = lyd_new_leaf(node, module, "id_ref", "id_2");
    assert_non_null(n);

    n = lyd_new_leaf(node, module, "union", "infinity");
    assert_non_null(n);

    assert_int_equal(0, lyd_validate(&r, LYD_OPT_STRICT | LYD_OPT_CONFIG));
    assert_int_equal(SR_ERR_OK, sr_save_data_tree_file(TEST_MODULE_DATA_FILE_NAME, r));

    lyd_free_withsiblings(r);

    ly_ctx_destroy(ctx, NULL);

}

void
createDataTreeExampleModule()
{
    struct ly_ctx *ctx = NULL;
    struct lyd_node *root = NULL;

    ctx = ly_ctx_new(TEST_SCHEMA_SEARCH_DIR);
    assert_non_null(ctx);

    const struct lys_module *module = ly_ctx_load_module(ctx, "example-module", NULL);
    assert_non_null(module);

#define XPATH "/example-module:container/list[key1='key1'][key2='key2']/leaf"

    root = lyd_new_path(NULL, ctx, XPATH, "Leaf value", 0);
    assert_int_equal(0, lyd_validate(&root, LYD_OPT_STRICT | LYD_OPT_CONFIG));
    assert_int_equal(SR_ERR_OK, sr_save_data_tree_file(EXAMPLE_MODULE_DATA_FILE_NAME, root));

    lyd_free_withsiblings(root);
    ly_ctx_destroy(ctx, NULL);
}

void
createDataTreeLargeExampleModule(int list_count)
{
    struct ly_ctx *ctx = NULL;
    struct lyd_node *root = NULL, *node = NULL;

    ctx = ly_ctx_new(TEST_SCHEMA_SEARCH_DIR);
    assert_non_null(ctx);

    const struct lys_module *module = ly_ctx_load_module(ctx, "example-module", NULL);
    assert_non_null(module);

#define MAX_XP_LEN 100
    const char *template = "/example-module:container/list[key1='k1%d'][key2='k2%d']/leaf";
    char xpath[MAX_XP_LEN] = {0,};


    for (int i = 0; i < list_count; i++){
        snprintf(xpath, MAX_XP_LEN, template, i, i);
        node = lyd_new_path(root, ctx, xpath, "Leaf value", 0);
        if (NULL == root) {
            root = node;
        }
    }
    lyd_new_path(root, ctx, "/example-module:container/list[key1='key1'][key2='key2']/leaf", "Leaf value", 0);

    assert_int_equal(0, lyd_validate(&root, LYD_OPT_STRICT | LYD_OPT_CONFIG));
    assert_int_equal(SR_ERR_OK, sr_save_data_tree_file(EXAMPLE_MODULE_DATA_FILE_NAME, root));

    lyd_free_withsiblings(root);
    ly_ctx_destroy(ctx, NULL);
}
