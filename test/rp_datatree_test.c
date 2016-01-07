/**
 * @file rp_datatree_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief 
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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdlib.h>
#include <stdio.h>
#include "data_manager.h"
#include "test_data.h"
#include "sr_common.h"
#include "rp_data_tree.h"
#include "xpath_processor.h"

int setup(void **state){
   int rc = 0;
   dm_ctx_t *ctx;
   rc = dm_init(TEST_DATA_DIR, &ctx);
   assert_int_equal(SR_ERR_OK,rc);
   *state = ctx;
   return rc;
}

int teardown(void **state){
    dm_ctx_t *ctx = *state;
    int rc = dm_cleanup(ctx);
    assert_int_equal(SR_ERR_OK,rc);
    return rc;
}

void get_values_test(void **state){
    int rc = 0;
    dm_ctx_t *ctx = *state;
    dm_session_t *ses_ctx = NULL;
    struct lyd_node *data_tree = NULL;
    dm_session_start(ctx, &ses_ctx);
    rc = dm_get_datatree(ctx, ses_ctx, "example-module", &data_tree);
    assert_int_equal(SR_ERR_OK, rc);


    sr_val_t **values;
    size_t count;

#define XP "/example-module:container/list[key1='key1'][key2='key2']"
    rc = rp_dt_get_values_xpath(ctx, data_tree, XP, &values, &count);
    for (size_t i = 0; i<count; i++){
        puts(values[i]->path);
        sr_free_val_t(values[i]);
    }
    free(values);
    assert_int_equal(SR_ERR_OK, rc);

    dm_session_stop(ctx, ses_ctx);
}

void get_value_test(void **state){
    int rc = 0;
    dm_ctx_t *ctx = *state;
    dm_session_t *ses_ctx = NULL;
    struct lyd_node *data_tree = NULL;
    dm_session_start(ctx, &ses_ctx);

    /* Load from file */
    rc = dm_get_datatree(ctx, ses_ctx, "example-module", &data_tree);
    assert_int_equal(SR_ERR_OK, rc);
    sr_val_t *value = NULL;

    /*leaf*/
    xp_loc_id_t *l;
#define XPATH_FOR_VALUE "/example-module:container/list[key1='key1'][key2='key2']/leaf"
    assert_int_equal(SR_ERR_OK, xp_char_to_loc_id(XPATH_FOR_VALUE, &l));
    assert_int_equal(SR_ERR_OK, rp_dt_get_value(ctx, data_tree, l, &value));

    assert_int_equal(SR_STRING_T, value->type);
    assert_string_equal("Leaf value", value->data.string_val);
    assert_string_equal(XPATH_FOR_VALUE, value->path);

    sr_free_val_t(value);
    xp_free_loc_id(l);

    /*list*/
#define XPATH_FOR_LIST "/example-module:container/list[key1='key1'][key2='key2']"
    assert_int_equal(SR_ERR_OK, rp_dt_get_value_xpath(ctx, data_tree, XPATH_FOR_LIST, &value));
    assert_int_equal(SR_LIST_T, value->type);
    assert_string_equal(XPATH_FOR_LIST, value->path);
    sr_free_val_t(value);

    /*container*/
#define XPATH_FOR_CONTAINER "/example-module:container"
    assert_int_equal(SR_ERR_OK, rp_dt_get_value_xpath(ctx, data_tree, "/example-module:container", &value));
    assert_int_equal(SR_CONTAINER_T, value->type);
    assert_string_equal(XPATH_FOR_CONTAINER, value->path);
    sr_free_val_t(value);

    dm_session_stop(ctx, ses_ctx);
}

void get_node_test_found(void **state)
{
    int rc = 0;
    dm_ctx_t *ctx = *state;
    dm_session_t *ses_ctx = NULL;
    struct lyd_node *data_tree = NULL;
    struct lyd_node *node = NULL;
    dm_session_start(ctx, &ses_ctx);

    /* Load from file */
    rc = dm_get_datatree(ctx, ses_ctx ,"example-module", &data_tree);
    assert_int_equal(SR_ERR_OK, rc);

#define XPATH "/example-module:container/list[key1='key1'][key2='key2']/leaf"
    rc = rp_dt_get_node_xpath(ctx, data_tree, XPATH, &node);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(node);
    assert_string_equal("leaf", node->schema->name);

/* if key names are specified the order does not matter*/
#define XPATH2 "/example-module:container/list[key2='key2'][key1='key1']/leaf"
    rc = rp_dt_get_node_xpath(ctx, data_tree, XPATH2, &node);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(node);
    assert_string_equal("leaf", node->schema->name);

#define XPATH_CONT "/example-module:container"
    rc = rp_dt_get_node_xpath(ctx, data_tree, XPATH_CONT, &node);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(node);
    assert_string_equal("container", node->schema->name);

#define XPATH_LIST "/example-module:container/list[key1='key1'][key2='key2']"
    rc = rp_dt_get_node_xpath(ctx, data_tree, XPATH_LIST, &node);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(node);
    assert_string_equal("list", node->schema->name);

#define XPATH_LIST_WITHOUT_KEY "/example-module:container/list"
    /* key values must be specified for get_node*/
    rc = rp_dt_get_node_xpath(ctx, data_tree, XPATH_LIST_WITHOUT_KEY, &node);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    dm_session_stop(ctx, ses_ctx);

}

void get_node_test_not_found(void **state)
{
    int rc = 0;
    dm_ctx_t *ctx = *state;
    dm_session_t *ses_ctx = NULL;
    struct lyd_node *data_tree = NULL;
    struct lyd_node *node = NULL;
    dm_session_start(ctx, &ses_ctx);

    /* Load from file */
    rc = dm_get_datatree(ctx, ses_ctx, "example-module", &data_tree);
    assert_int_equal(SR_ERR_OK, rc);

    /* non existing nodes*/
#define XPATH_UNKNOWN1 "/example-module:abc"
    rc = rp_dt_get_node_xpath(ctx, data_tree, XPATH_UNKNOWN1, &node);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
#define XPATH_UNKNOWN2 "/example-module:container/a"
    rc = rp_dt_get_node_xpath(ctx, data_tree, XPATH_UNKNOWN2, &node);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
#define XPATH_UNKNOWN3 "/example-module:container/list[key1='key1'][key2='key2']/abc"
    rc = rp_dt_get_node_xpath(ctx, data_tree, XPATH_UNKNOWN3, &node);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* non matching key values*/
#define XPATH_NF "/example-module:container/list[key1='k1'][key2='k2']/leaf"
    rc = rp_dt_get_node_xpath(ctx, data_tree, XPATH_NF, &node);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* missing key*/
#define XPATH_INV "/example-module:container/list[key1='key1']/leaf"
    rc = rp_dt_get_node_xpath(ctx, data_tree, XPATH_INV, &node);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    dm_session_stop(ctx, ses_ctx);

}

int main(){

    const struct CMUnitTest tests[] = {
            cmocka_unit_test(get_node_test_found),
            cmocka_unit_test(get_node_test_not_found),
            cmocka_unit_test(get_value_test),
            cmocka_unit_test(get_values_test),
    };
    return cmocka_run_group_tests(tests, setup, teardown);
}


