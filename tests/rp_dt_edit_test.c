/**
 * @file rp_dt_edit_test.c
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

#define LEAF_VALUE "leafV"

int setup(void **state){
   int rc = 0;
   dm_ctx_t *ctx;
   rc = dm_init(TEST_SCHEMA_SEARCH_DIR, TEST_DATA_SEARCH_DIR, &ctx);
   assert_int_equal(SR_ERR_OK,rc);
   *state = ctx;
   return rc;
}

int teardown(void **state){
    dm_ctx_t *ctx = *state;
    dm_cleanup(ctx);
    return 0;
}

void delete_item_leaf_test(void **state){
    int rc = 0;
    dm_ctx_t *ctx = *state;
    dm_session_t *session = NULL;
    sr_val_t *val = NULL;

    /* delete leaf*/
    dm_session_start(ctx, &session);

    rc = rp_dt_get_value_wrapper(ctx, session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);

    rc = rp_dt_delete_item(ctx, session, SR_DS_CANDIDATE, "/example-module:container/list[key1='key1'][key2='key2']/leaf", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_value_wrapper(ctx, session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    dm_session_stop(ctx, session);

    /* delete non existing leaf*/
    dm_session_start(ctx, &session);
    rc = rp_dt_get_value_wrapper(ctx, session, "/example-module:container/list[key1='abc'][key2='abc']/leaf", &val);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    rc = rp_dt_delete_item(ctx, session, SR_DS_CANDIDATE, "/example-module:container/list[key1='abc'][key2='abc']/leaf", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    /* deleting non existing leaf with strict should fail*/
    rc = rp_dt_delete_item(ctx, session, SR_DS_CANDIDATE, "/example-module:container/list[key1='abc'][key2='abc']/leaf", SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* delete key leaf is not allowed */
    rc = rp_dt_delete_item(ctx, session, SR_DS_CANDIDATE, "/example-module:container/list[key1='key1'][key2='key2']/key1", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    dm_session_stop(ctx, session);
}

void delete_item_container_test(void **state){
    int rc = 0;
    dm_ctx_t *ctx = *state;
    dm_session_t *session = NULL;
    sr_val_t *val = NULL;

    /* delete container*/
    dm_session_start(ctx, &session);

    rc = rp_dt_get_value_wrapper(ctx, session, "/example-module:container", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);

    rc = rp_dt_delete_item(ctx, session, SR_DS_CANDIDATE, "/example-module:container", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_value_wrapper(ctx, session, "/example-module:container", &val);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

#define CONTAINER_XP "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4"
    rc = rp_dt_get_value_wrapper(ctx, session, CONTAINER_XP, &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);

    rc = rp_dt_delete_item(ctx, session, SR_DS_CANDIDATE, CONTAINER_XP, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_value_wrapper(ctx, session, CONTAINER_XP, &val);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* delete non existing container*/
    rc = rp_dt_delete_item(ctx, session, SR_DS_CANDIDATE, CONTAINER_XP , SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_delete_item(ctx, session, SR_DS_CANDIDATE, CONTAINER_XP , SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    dm_session_stop(ctx, session);

    dm_session_start(ctx, &session);
    rc = rp_dt_get_value_wrapper(ctx, session, CONTAINER_XP, &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);

    rc = rp_dt_delete_item(ctx, session, SR_DS_CANDIDATE, CONTAINER_XP , SR_EDIT_NON_RECURSIVE);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    dm_session_stop(ctx, session);
}


void delete_item_list_test(void **state){
    int rc = 0;
    dm_ctx_t *ctx = *state;
    dm_session_t *session = NULL;
    sr_val_t *val = NULL;

    /* delete list*/
    dm_session_start(ctx, &session);

#define LIST_INST1_XP "/ietf-interfaces:interfaces/interface[name='eth0']"
#define LIST_INST2_XP "/ietf-interfaces:interfaces/interface[name='eth1']"
#define LIST_INST3_XP "/ietf-interfaces:interfaces/interface[name='gigaeth0']"

    /* there three list instances*/
    rc = rp_dt_get_value_wrapper(ctx, session, LIST_INST1_XP, &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);

    rc = rp_dt_get_value_wrapper(ctx, session, LIST_INST2_XP, &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);

    rc = rp_dt_get_value_wrapper(ctx, session, LIST_INST3_XP, &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);

    /* delete on list instance*/
    rc = rp_dt_delete_item(ctx, session, SR_DS_CANDIDATE, LIST_INST1_XP, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_value_wrapper(ctx, session, LIST_INST1_XP, &val);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* two remaining stays in place */
    rc = rp_dt_get_value_wrapper(ctx, session, LIST_INST2_XP, &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);

    rc = rp_dt_get_value_wrapper(ctx, session, LIST_INST3_XP, &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);

    /* try to delete non existing list*/
    rc = rp_dt_delete_item(ctx, session, SR_DS_CANDIDATE, LIST_INST1_XP, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_delete_item(ctx, session, SR_DS_CANDIDATE, LIST_INST1_XP, SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    dm_session_stop(ctx, session);


    dm_session_start(ctx, &session);
    rc = rp_dt_get_value_wrapper(ctx, session, LIST_INST1_XP, &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);

    /* list deletion with non recursive fails*/
    rc = rp_dt_delete_item(ctx, session, SR_DS_CANDIDATE, LIST_INST1_XP , SR_EDIT_NON_RECURSIVE);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);
    dm_session_stop(ctx, session);
}

void delete_item_alllist_test(void **state){
    int rc = 0;
    dm_ctx_t *ctx = *state;
    dm_session_t *session = NULL;

    /* delete list*/
    dm_session_start(ctx, &session);

#define LIST_XP "/ietf-interfaces:interfaces/interface"

    sr_val_t **values = NULL;
    size_t count = 0;

    /* there are three list instances*/
    rc = rp_dt_get_values_wrapper(ctx, session, LIST_XP, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_values_arr(values, count);

    /* delete with non recursive should fail*/
    rc = rp_dt_delete_item(ctx, session, SR_DS_CANDIDATE, LIST_XP, SR_EDIT_NON_RECURSIVE);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* items should remain in place*/
    rc = rp_dt_get_values_wrapper(ctx, session, LIST_XP, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_values_arr(values, count);

    /* delete all list instances*/
    rc = rp_dt_delete_item(ctx, session, SR_DS_CANDIDATE, LIST_XP, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    /* items should be deleted*/
    rc = rp_dt_get_values_wrapper(ctx, session, LIST_XP, &values, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* delete non existing */
    rc = rp_dt_delete_item(ctx, session, SR_DS_CANDIDATE, LIST_XP, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    /* delete non existing with strict should fail*/
    rc = rp_dt_delete_item(ctx, session, SR_DS_CANDIDATE, LIST_XP, SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    dm_session_stop(ctx, session);
}

void delete_item_leaflist_test(void **state){
    int rc = 0;
    dm_ctx_t *ctx = *state;
    dm_session_t *session = NULL;

    /* delete list*/
    dm_session_start(ctx, &session);

#define LEAF_LIST_XP "/test-module:main/numbers"

    sr_val_t **values = NULL;
    size_t count = 0;
    /* three leaf list items*/
    rc = rp_dt_get_values_wrapper(ctx, session, LEAF_LIST_XP, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_values_arr(values, count);

    /* delete all list instances*/
    rc = rp_dt_delete_item(ctx, session, SR_DS_CANDIDATE, LEAF_LIST_XP, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_values_wrapper(ctx, session, LEAF_LIST_XP, &values, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    dm_session_stop(ctx, session);
}

void set_item_leaf_test(void **state){
    int rc = 0;
    dm_ctx_t *ctx = *state;
    dm_session_t *session = NULL;

    dm_session_start(ctx, &session);

    /* replace existing leaf*/
    sr_val_t *val = NULL;
    rc = rp_dt_get_value_wrapper(ctx, session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);

    /* modify the value*/
    free(val->data.string_val);
    val->data.string_val = strdup("abcdef");
    assert_non_null(val->data.string_val);

    rc = rp_dt_set_item(ctx, session, SR_DS_CANDIDATE, val->xpath, SR_EDIT_STRICT, val);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    rc = rp_dt_set_item(ctx, session, SR_DS_CANDIDATE, val->xpath, SR_EDIT_DEFAULT, val);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_val(val);
    val = NULL;

    rc = rp_dt_get_value_wrapper(ctx, session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_string_equal("abcdef", val->data.string_val);

    /*reuse sr_val_t insert new value under the existing container*/
    free(val->xpath);
    val->xpath = strdup("/example-module:container/list[key1='new_key1'][key2='new_key2']/leaf");
    assert_non_null(val->xpath);

    /* setting key leaf is not allowed*/
    rc = rp_dt_set_item(ctx, session, SR_DS_CANDIDATE, "/example-module:container/list[key1='new_key1'][key2='new_key2']/key1", SR_EDIT_DEFAULT, val);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    rc = rp_dt_set_item(ctx, session, SR_DS_CANDIDATE, "/example-module:container/list[key1='new_key1'][key2='new_key2']/key2", SR_EDIT_DEFAULT, val);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* creating with non recursive with missing parent not*/
    rc = rp_dt_set_item(ctx, session, SR_DS_CANDIDATE, val->xpath, SR_EDIT_NON_RECURSIVE, val);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    rc = rp_dt_set_item(ctx, session, SR_DS_CANDIDATE, val->xpath, SR_EDIT_DEFAULT, val);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_val(val);
    val = NULL;

    rc = rp_dt_get_value_wrapper(ctx, session, "/example-module:container/list[key1='new_key1'][key2='new_key2']/leaf", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_string_equal("abcdef", val->data.string_val);

    sr_free_val(val);

    dm_session_stop(ctx, session);
}

void set_item_leaflist_test(void **state){
    int rc = 0;
    dm_ctx_t *ctx = *state;
    dm_session_t *session = NULL;

    dm_session_start(ctx, &session);

    sr_val_t **values = NULL;
    size_t count = 0;
    /* three leaf list items*/
    rc = rp_dt_get_values_wrapper(ctx, session, LEAF_LIST_XP, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);
    sr_free_values_arr(values, count);

    /* append new item*/
    sr_val_t *val = NULL;
    val = calloc(1, sizeof(*val));
    assert_non_null(val);

    val->xpath = strdup("/test-module:main/numbers");
    assert_non_null(val->xpath);
    val->type = SR_UINT8_T;
    val->data.uint8_val = 99;

    rc = rp_dt_set_item(ctx, session, SR_DS_CANDIDATE, val->xpath, SR_EDIT_DEFAULT, val);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_val(val);

    rc = rp_dt_get_values_wrapper(ctx, session, LEAF_LIST_XP, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(4, count);

    assert_int_equal(SR_UINT8_T, values[3]->type);
    assert_int_equal(99, values[3]->data.uint8_val);
    sr_free_values_arr(values, count);

    dm_session_stop(ctx, session);
}

void set_item_list_test(void **state){
    int rc = 0;
    dm_ctx_t *ctx = *state;
    dm_session_t *session = NULL;

    dm_session_start(ctx, &session);

    sr_val_t **values = NULL;
    size_t count = 0;

    /* one existing list instance */
    rc = rp_dt_get_values_wrapper(ctx, session, "/example-module:container/list", &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, count);
    sr_free_values_arr(values, count);

    rc = rp_dt_set_item(ctx, session, SR_DS_CANDIDATE, "/example-module:container/list[key1='new_key1'][key2='new_key2']", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_values_wrapper(ctx, session, "/example-module:container/list", &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, count);
    sr_free_values_arr(values, count);

    /* set existing list */
    rc = rp_dt_set_item(ctx, session, SR_DS_CANDIDATE, "/example-module:container/list[key1='new_key1'][key2='new_key2']", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_set_item(ctx, session, SR_DS_CANDIDATE, "/example-module:container/list[key1='new_key1'][key2='new_key2']", SR_EDIT_STRICT, NULL);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    dm_session_stop(ctx, session);
}

int main(){

    sr_logger_set_level(SR_LL_DBG, SR_LL_NONE);

    const struct CMUnitTest tests[] = {
            cmocka_unit_test(delete_item_leaf_test),
            cmocka_unit_test(delete_item_container_test),
            cmocka_unit_test(delete_item_list_test),
            cmocka_unit_test(delete_item_alllist_test),
            cmocka_unit_test(delete_item_leaflist_test),
            cmocka_unit_test(set_item_leaf_test),
            cmocka_unit_test(set_item_leaflist_test),
            cmocka_unit_test(set_item_list_test)
    };
    return cmocka_run_group_tests(tests, setup, teardown);
}


