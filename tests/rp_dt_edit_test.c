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
#include "test_module_helper.h"

#define LEAF_VALUE "leafV"

int setup(void **state){
   createDataTreeTestModule();
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
    val = NULL;

    sr_val_t **values = NULL;
    size_t cnt = 0;
    rc = rp_dt_get_values_wrapper(ctx, session, "/example-module:container", &values, &cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, cnt);
    sr_free_values_arr(values, cnt);

    /* list deletion with non recursive fails*/
    rc = rp_dt_delete_item(ctx, session, SR_DS_CANDIDATE, LIST_INST1_XP , SR_EDIT_NON_RECURSIVE);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    rc = rp_dt_delete_item(ctx, session, SR_DS_CANDIDATE, "/example-module:container/list[key1='key1'][key2='key2']" , SR_EDIT_NON_RECURSIVE);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* delete the leaf, so the list contains only keys*/
    rc = rp_dt_delete_item(ctx, session, SR_DS_CANDIDATE, "/example-module:container/list[key1='key1'][key2='key2']/leaf" , SR_EDIT_NON_RECURSIVE);
    assert_int_equal(SR_ERR_OK, rc);

    /* if the list contains only keys it can be deleted even with non recursive flag*/
    rc = rp_dt_delete_item(ctx, session, SR_DS_CANDIDATE, "/example-module:container/list[key1='key1'][key2='key2']" , SR_EDIT_NON_RECURSIVE);
    assert_int_equal(SR_ERR_OK, rc);

    /* delete the only list instance in the container the container should be also deleted */
    rc = rp_dt_get_value_wrapper(ctx, session, "/example-module:container", &val);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

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

    dm_session_start(ctx, &session);


    /* create item from root */
    rc = rp_dt_get_value_wrapper(ctx, session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);

    /* create item with explicitly specified namespace*/
    rc = rp_dt_set_item(ctx, session, SR_DS_STARTUP, "/example-module:container/example-module:list[key1='key11'][key2='key22']/example-module:leaf", SR_EDIT_DEFAULT, val);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_delete_item(ctx, session, SR_DS_CANDIDATE, "/example-module:container", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    sr_val_t *del = NULL;

    rc = rp_dt_get_value_wrapper(ctx, session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &del);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    assert_null(del);

    rc = rp_dt_set_item(ctx, session, SR_DS_CANDIDATE, val->xpath, SR_EDIT_DEFAULT, val);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_val(val);


    rc = rp_dt_get_value_wrapper(ctx, session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);

    /* create augment node */
    sr_val_t v;
    v.xpath = NULL;
    v.type = SR_STRING_T;
    v.data.string_val = strdup("abc");
    assert_non_null(v.data.string_val);

    rc = rp_dt_set_item(ctx, session, SR_DS_STARTUP, "/small-module:item/info-module:info", SR_EDIT_DEFAULT, &v);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_value_wrapper(ctx, session, "/small-module:item/info-module:info", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);

    assert_int_equal(v.type, val->type);
    assert_string_equal(v.data.string_val, val->data.string_val);

    sr_free_val(val);
    sr_free_val_content(&v);


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

void set_item_container_test(void **state){
    int rc = 0;
    dm_ctx_t *ctx = *state;
    dm_session_t *session = NULL;

    dm_session_start(ctx, &session);

    sr_val_t *value = NULL;
    rc = rp_dt_get_value_wrapper(ctx, session, "/test-module:list[key='key']/wireless", &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    rc = rp_dt_set_item(ctx, session, SR_DS_CANDIDATE, "/test-module:list[key='key']/wireless", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_value_wrapper(ctx, session, "/test-module:list[key='key']/wireless", &value);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(value);
    assert_int_equal(SR_CONTAINER_PRESENCE_T, value->type);

    sr_free_val(value);

    /* set existing does nothing*/
    rc = rp_dt_set_item(ctx, session, SR_DS_CANDIDATE, "/test-module:list[key='key']/wireless", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    /* set existing fails with strict opt*/
    rc = rp_dt_set_item(ctx, session, SR_DS_CANDIDATE, "/test-module:list[key='key']/wireless", SR_EDIT_STRICT, NULL);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    dm_session_stop(ctx, session);
}

void
set_item_negative_test(void **state)
{
    int rc = 0;
    dm_ctx_t *ctx = *state;
    dm_session_t *session = NULL;

    dm_session_start(ctx, &session);


    rc = rp_dt_delete_item(ctx, session, SR_DS_RUNNING, "/test-module:main", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    /* set non-presence container */
    rc = rp_dt_set_item(ctx, session, SR_DS_RUNNING, "/test-module:main", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);


    /* set list without keys*/
    rc = rp_dt_set_item(ctx, session, SR_DS_RUNNING, "/test-module:list", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    rc = rp_dt_set_item(ctx, session, SR_DS_STARTUP, "^usfd&", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* updating key value is not allowed */
    rc = rp_dt_set_item(ctx, session, SR_DS_STARTUP, "/example-module:container/list[key1='key1'][key2='key2']/key1", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* set item called with NULL value */
    rc = rp_dt_set_item(ctx, session, SR_DS_STARTUP, "/example-module:container/list[key1='key1'][key2='key2']/leaf", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    dm_session_stop(ctx, session);
}

void delete_get_set_get(dm_ctx_t *ctx, dm_session_t *session, const char* xpath, const sr_val_t *value, sr_val_t **new_set)
{
    int rc = SR_ERR_OK;

    rc = rp_dt_delete_item(ctx, session, SR_DS_STARTUP, xpath, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    /* verify that item has been deleted*/
    rc = rp_dt_get_value_wrapper(ctx, session, xpath, new_set);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    assert_null(*new_set);

    /* set it */
    rc = rp_dt_set_item(ctx, session, SR_DS_STARTUP, xpath, SR_EDIT_DEFAULT, value);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_value_wrapper(ctx, session, xpath, new_set);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(*new_set);
    assert_int_equal(value->type, (*new_set)->type);

}

void edit_test_module_test(void **state){
    int rc = 0;
    dm_ctx_t *ctx = *state;
    dm_session_t *session = NULL;
    sr_val_t *value = NULL;
    sr_val_t *new_set = NULL;
    dm_session_start(ctx, &session);

#define FREE_VARS(A, B) do{sr_free_val(A); sr_free_val(B); A = NULL; B = NULL;}while(0)

    /* binary leaf*/
    rc = rp_dt_get_value_wrapper(ctx, session, XP_TEST_MODULE_RAW, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_BINARY_T, value->type);
    assert_string_equal(XP_TEST_MODULE_RAW_VALUE, value->data.binary_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_RAW, value, &new_set);

    assert_string_equal(value->data.binary_val, new_set->data.binary_val);
    FREE_VARS(value, new_set);

    /*bits leaf*/

    rc = rp_dt_get_value_wrapper(ctx, session, XP_TEST_MODULE_BITS, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_BITS_T, value->type);
    assert_string_equal(XP_TEST_MODULE_BITS_VALUE, value->data.bits_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_BITS, value, &new_set);
    assert_string_equal(value->data.bits_val, new_set->data.bits_val);
    FREE_VARS(value, new_set);

    /* bool leaf */
    rc = rp_dt_get_value_wrapper(ctx, session, XP_TEST_MODULE_BOOL, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_BOOL_T, value->type);
    assert_int_equal(XP_TEST_MODULE_BOOL_VALUE_T, value->data.bool_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_BOOL, value, &new_set);
    assert_int_equal(value->data.bool_val, new_set->data.bool_val);
    FREE_VARS(value, new_set);

    /* decimal 64 leaf*/
    rc = rp_dt_get_value_wrapper(ctx, session, XP_TEST_MODULE_DEC64, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_DECIMAL64_T, value->type);
    assert_int_equal(XP_TEST_MODULE_DEC64_VALUE_T, value->data.decimal64_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_DEC64, value, &new_set);

    assert_int_equal(value->data.decimal64_val, new_set->data.decimal64_val);

    FREE_VARS(value, new_set);

    /* enum leaf*/
    rc = rp_dt_get_value_wrapper(ctx, session, XP_TEST_MODULE_ENUM, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_ENUM_T, value->type);
    assert_string_equal(XP_TEST_MODULE_ENUM_VALUE, value->data.enum_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_ENUM, value, &new_set);

    assert_string_equal(value->data.enum_val, new_set->data.enum_val);

    FREE_VARS(value, new_set);

    /* empty */
    rc = rp_dt_get_value_wrapper(ctx, session, XP_TEST_MODULE_EMPTY, &value);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(SR_LEAF_EMPTY_T, value->type);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_EMPTY, value, &new_set);

    FREE_VARS(value, new_set);

    /* identity ref*/
    rc = rp_dt_get_value_wrapper(ctx, session, XP_TEST_MODULE_IDREF, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_IDENTITYREF_T, value->type);
    assert_string_equal(XP_TEST_MODULE_IDREF_VALUE, value->data.identityref_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_IDREF, value, &new_set);
    assert_string_equal(value->data.identityref_val, new_set->data.identityref_val);
    FREE_VARS(value, new_set);

    /* int8*/
    rc = rp_dt_get_value_wrapper(ctx, session, XP_TEST_MODULE_INT8, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_INT8_T, value->type);
    assert_int_equal(XP_TEST_MODULE_INT8_VALUE_T, value->data.int8_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_INT8, value, &new_set);
    assert_int_equal(value->data.int8_val, new_set->data.int8_val);
    FREE_VARS(value, new_set);

    /* int16*/
    rc = rp_dt_get_value_wrapper(ctx, session, XP_TEST_MODULE_INT16, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_INT16_T, value->type);
    assert_int_equal(XP_TEST_MODULE_INT16_VALUE_T, value->data.int16_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_INT16, value, &new_set);
    assert_int_equal(value->data.int16_val, new_set->data.int16_val);
    FREE_VARS(value, new_set);

    /* int32*/
    rc = rp_dt_get_value_wrapper(ctx, session, XP_TEST_MODULE_INT32, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_INT32_T, value->type);
    assert_int_equal(XP_TEST_MODULE_INT32_VALUE_T, value->data.int32_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_INT32, value, &new_set);
    assert_int_equal(value->data.int32_val, new_set->data.int32_val);
    FREE_VARS(value, new_set);

    /* int64*/
    rc = rp_dt_get_value_wrapper(ctx, session, XP_TEST_MODULE_INT64, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_INT64_T, value->type);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T, value->data.int64_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_INT64, value, &new_set);
    assert_int_equal(value->data.int64_val, new_set->data.int64_val);
    FREE_VARS(value, new_set);

    /* string ref*/
    rc = rp_dt_get_value_wrapper(ctx, session, XP_TEST_MODULE_STRING, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_STRING_T, value->type);
    assert_string_equal(XP_TEST_MODULE_STRING_VALUE, value->data.string_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_STRING, value, &new_set);
    assert_string_equal(value->data.string_val, new_set->data.string_val);
    FREE_VARS(value, new_set);

    /* uint8*/
    rc = rp_dt_get_value_wrapper(ctx, session, XP_TEST_MODULE_UINT8, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_UINT8_T, value->type);
    assert_int_equal(XP_TEST_MODULE_UINT8_VALUE_T, value->data.uint8_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_UINT8, value, &new_set);
    assert_int_equal(value->data.uint8_val, new_set->data.uint8_val);
    FREE_VARS(value, new_set);

    /* uint16*/
    rc = rp_dt_get_value_wrapper(ctx, session, XP_TEST_MODULE_UINT16, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_UINT16_T, value->type);
    assert_int_equal(XP_TEST_MODULE_UINT16_VALUE_T, value->data.uint16_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_UINT16, value, &new_set);
    assert_int_equal(value->data.uint16_val, new_set->data.uint16_val);
    FREE_VARS(value, new_set);

    /* uint32*/
    rc = rp_dt_get_value_wrapper(ctx, session, XP_TEST_MODULE_UINT32, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_UINT32_T, value->type);
    assert_int_equal(XP_TEST_MODULE_UINT32_VALUE_T, value->data.uint32_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_UINT32, value, &new_set);
    assert_int_equal(value->data.uint32_val, new_set->data.uint32_val);
    FREE_VARS(value, new_set);

    /* uint64*/
    rc = rp_dt_get_value_wrapper(ctx, session, XP_TEST_MODULE_UINT64, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_UINT64_T, value->type);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T, value->data.uint64_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_UINT64, value, &new_set);
    assert_int_equal(value->data.uint64_val, new_set->data.uint64_val);
    FREE_VARS(value, new_set);

    dm_session_stop(ctx, session);
}

void delete_negative_test(void **state){
    int rc = 0;
    dm_ctx_t *ctx = *state;
    dm_session_t *session = NULL;

    dm_session_start(ctx, &session);

    /* invalid xpath*/
    rc =rp_dt_delete_item(ctx, session, SR_DS_STARTUP, "^usfd&", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    rc =rp_dt_delete_item(ctx, session, SR_DS_STARTUP, "/example-module:unknown", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_BAD_ELEMENT, rc);

    dm_session_stop(ctx, session);
}

void
edit_validate_test(void **state)
{
    int rc = 0;
    dm_ctx_t *ctx = *state;
    dm_session_t *session = NULL;
    char **errors = NULL;
    size_t e_cnt = 0;


    /* must when */
    dm_session_start(ctx, &session);

    sr_val_t iftype;
    iftype.xpath = NULL;
    iftype.type = SR_ENUM_T;
    iftype.data.enum_val = strdup ("ethernet");

    rc = rp_dt_set_item(ctx, session, SR_DS_STARTUP, "/test-module:interface/ifType", SR_EDIT_DEFAULT, &iftype);
    assert_int_equal(SR_ERR_OK, rc);

    sr_free_val_content(&iftype);

    rc = dm_validate_session_data_trees(ctx, session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);

    sr_val_t mtu;
    mtu.xpath = NULL;
    mtu.type = SR_UINT32_T;
    mtu.data.uint32_val = 1024;

    rc = rp_dt_set_item(ctx, session, SR_DS_STARTUP, "/test-module:interface/ifMTU", SR_EDIT_DEFAULT, &mtu);
    assert_int_equal(SR_ERR_OK, rc);

    rc = dm_validate_session_data_trees(ctx, session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);

    mtu.data.uint32_val = 1500;
    rc = rp_dt_set_item(ctx, session, SR_DS_STARTUP, "/test-module:interface/ifMTU", SR_EDIT_DEFAULT, &mtu);
    assert_int_equal(SR_ERR_OK, rc);

    rc = dm_validate_session_data_trees(ctx, session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    dm_session_stop(ctx, session);

    /* regexp */
    dm_session_start(ctx, &session);

    sr_val_t hexnumber;
    hexnumber.xpath = NULL;
    hexnumber.type = SR_STRING_T;
    hexnumber.data.string_val = strdup("92FF");
    assert_non_null(hexnumber.data.string_val);

    rc = rp_dt_set_item(ctx, session, SR_DS_STARTUP, "/test-module:hexnumber", SR_EDIT_DEFAULT, &hexnumber);
    assert_int_equal(SR_ERR_OK, rc);

    rc = dm_validate_session_data_trees(ctx, session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    free(hexnumber.data.string_val);
    hexnumber.data.string_val = strdup("AAZZ");

    /* Regular expression mismatch causes SR_ERR_INVAL_ARG */
    rc = rp_dt_set_item(ctx, session, SR_DS_STARTUP, "/test-module:hexnumber", SR_EDIT_DEFAULT, &hexnumber);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    sr_free_val_content(&hexnumber);

    dm_session_stop(ctx, session);

    /* mandatory leaf */
    dm_session_start(ctx, &session);

    sr_val_t name;
    name.xpath = NULL;
    name.type = SR_STRING_T;
    name.data.string_val = strdup("Name");
    assert_non_null(name.data.string_val);

    rc = rp_dt_set_item(ctx, session, SR_DS_STARTUP, "/test-module:location/name", SR_EDIT_DEFAULT, &name);
    assert_int_equal(SR_ERR_OK, rc);

    rc = dm_validate_session_data_trees(ctx, session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);

    sr_val_t lonigitude;
    lonigitude.xpath = NULL;
    lonigitude.type = SR_STRING_T;
    lonigitude.data.string_val = strdup("Longitude 49.45");
    assert_non_null(lonigitude.data.string_val);

    rc = rp_dt_set_item(ctx, session, SR_DS_STARTUP, "/test-module:location/longitude", SR_EDIT_DEFAULT, &lonigitude);
    assert_int_equal(SR_ERR_OK, rc);

    rc = dm_validate_session_data_trees(ctx, session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);

    sr_val_t latitude;
    latitude.xpath = NULL;
    latitude.type = SR_STRING_T;
    latitude.data.string_val = strdup("Latitude 56.46");
    assert_non_null(latitude.data.string_val);

    rc = rp_dt_set_item(ctx, session, SR_DS_STARTUP, "/test-module:location/latitude", SR_EDIT_DEFAULT, &latitude);
    assert_int_equal(SR_ERR_OK, rc);

    rc = dm_validate_session_data_trees(ctx, session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    sr_free_val_content(&name);
    sr_free_val_content(&lonigitude);
    sr_free_val_content(&latitude);

    dm_session_stop(ctx, session);

    /* choice */
    dm_session_start(ctx, &session);
    sr_val_t interval;
    interval.xpath = NULL;
    interval.type = SR_UINT16_T;
    interval.data.uint16_val = 9;

    rc = rp_dt_set_item(ctx, session, SR_DS_STARTUP, "/test-module:transfer/interval", SR_EDIT_DEFAULT, &interval);
    assert_int_equal(SR_ERR_OK, rc);

    errors = NULL;
    e_cnt = 0;

    rc = dm_validate_session_data_trees(ctx, session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    sr_val_t daily;
    daily.xpath = NULL;
    daily.type = SR_LEAF_EMPTY_T;

    rc = rp_dt_set_item(ctx, session, SR_DS_STARTUP, "/test-module:transfer/daily", SR_EDIT_DEFAULT, &daily);
    assert_int_equal(SR_ERR_OK, rc);

    errors = NULL;
    e_cnt = 0;

    rc = dm_validate_session_data_trees(ctx, session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);

    for (size_t i = 0; i < e_cnt; i++) {
        free(errors[i]);
    }
    free(errors);

    dm_session_stop(ctx, session);

    /* leaf-list unique values */
    dm_session_start(ctx, &session);
    sr_val_t val;
    val.xpath = NULL;
    val.type = SR_UINT8_T;
    val.data.uint8_val = 9;

    rc = rp_dt_set_item(ctx, session, SR_DS_STARTUP, "/test-module:main/numbers", SR_EDIT_DEFAULT, &val);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_set_item(ctx, session, SR_DS_STARTUP, "/test-module:main/numbers", SR_EDIT_DEFAULT, &val);
    assert_int_equal(SR_ERR_OK, rc);

    errors = NULL;
    e_cnt = 0;
    rc = dm_validate_session_data_trees(ctx, session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);

    for (size_t i = 0; i < e_cnt; i++) {
        free(errors[i]);
    }
    free(errors);

    dm_session_stop(ctx, session);
}

void
edit_discard_changes_test(void **state)
{
    int rc = 0;
    dm_ctx_t *ctx = *state;
    dm_session_t *sessionA = NULL, *sessionB = NULL;
    sr_val_t *valueA = NULL, *valueB = NULL;


    dm_session_start(ctx, &sessionA);
    dm_session_start(ctx, &sessionB);

    /* read value in session A*/
    rc = rp_dt_get_value_wrapper(ctx, sessionA, XP_TEST_MODULE_INT64, &valueA);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueA);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T, valueA->data.int64_val);

    /* read value in session B*/
    rc = rp_dt_get_value_wrapper(ctx, sessionB, XP_TEST_MODULE_INT64, &valueB);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueB);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T, valueB->data.int64_val);
    sr_free_val(valueB);

    /* update value in session A*/
    valueA->data.int64_val = XP_TEST_MODULE_INT64_VALUE_T + 42;
    rc = rp_dt_set_item(ctx, sessionA, SR_DS_STARTUP, XP_TEST_MODULE_INT64, SR_EDIT_DEFAULT, valueA);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_val(valueA);

    /* check update in session A*/
    rc = rp_dt_get_value_wrapper(ctx, sessionA, XP_TEST_MODULE_INT64, &valueA);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueA);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T + 42, valueA->data.int64_val);
    sr_free_val(valueA);

    /* update in sessionA should not affect value in session B*/
    rc = rp_dt_get_value_wrapper(ctx, sessionB, XP_TEST_MODULE_INT64, &valueB);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueB);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T, valueB->data.int64_val);
    sr_free_val(valueB);

    rc = dm_discard_changes(ctx, sessionA);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_value_wrapper(ctx, sessionA, XP_TEST_MODULE_INT64, &valueA);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueA);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T, valueA->data.int64_val);
    sr_free_val(valueA);

    dm_session_stop(ctx, sessionA);
    dm_session_stop(ctx, sessionB);

}

void
edit_commit_test(void **state)
{
    int rc = 0;
    dm_ctx_t *ctx = *state;
    dm_session_t *sessionA = NULL, *sessionB = NULL;
    sr_val_t *valueA = NULL, *valueB = NULL;


    dm_session_start(ctx, &sessionA);
    dm_session_start(ctx, &sessionB);

    /* read value in session A*/
    rc = rp_dt_get_value_wrapper(ctx, sessionA, XP_TEST_MODULE_INT64, &valueA);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueA);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T, valueA->data.int64_val);

    /* read value in session B*/
    rc = rp_dt_get_value_wrapper(ctx, sessionB, XP_TEST_MODULE_INT64, &valueB);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueB);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T, valueB->data.int64_val);
    sr_free_val(valueB);

    /* update value in session A*/
    valueA->data.int64_val = XP_TEST_MODULE_INT64_VALUE_T + 99;
    rc = rp_dt_set_item(ctx, sessionA, SR_DS_STARTUP, XP_TEST_MODULE_INT64, SR_EDIT_DEFAULT, valueA);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_val(valueA);

    /* check update in session A*/
    rc = rp_dt_get_value_wrapper(ctx, sessionA, XP_TEST_MODULE_INT64, &valueA);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueA);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T + 99, valueA->data.int64_val);
    sr_free_val(valueA);

    /* update in sessionA should not affect value in session B*/
    rc = rp_dt_get_value_wrapper(ctx, sessionB, XP_TEST_MODULE_INT64, &valueB);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueB);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T, valueB->data.int64_val);
    sr_free_val(valueB);

    char **errors = NULL;
    size_t e_cnt = 0;

    rc = dm_commit(ctx, sessionA, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_value_wrapper(ctx, sessionA, XP_TEST_MODULE_INT64, &valueA);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueA);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T + 99, valueA->data.int64_val);
    sr_free_val(valueA);

    /* since the session be has not been modified it should be update after commit */
    rc = rp_dt_get_value_wrapper(ctx, sessionB, XP_TEST_MODULE_INT64, &valueB);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueB);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T + 99, valueB->data.int64_val);
    sr_free_val(valueB);

    dm_session_stop(ctx, sessionA);
    dm_session_stop(ctx, sessionB);

     /* check that update is permanent in new session*/
    dm_session_start(ctx, &sessionA);
    rc = rp_dt_get_value_wrapper(ctx, sessionA, XP_TEST_MODULE_INT64, &valueA);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueA);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T + 99, valueA->data.int64_val);

    valueA->data.int64_val = XP_TEST_MODULE_INT64_VALUE_T;

    rc = rp_dt_set_item(ctx, sessionA, SR_DS_STARTUP, XP_TEST_MODULE_INT64, SR_EDIT_DEFAULT, valueA);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_val(valueA);

    rc = dm_commit(ctx, sessionA, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    dm_session_stop(ctx, sessionA);
}

int main(){

    sr_logger_set_level(SR_LL_DBG, SR_LL_NONE);

    const struct CMUnitTest tests[] = {
            cmocka_unit_test(delete_item_leaf_test),
            cmocka_unit_test(delete_item_container_test),
            cmocka_unit_test(delete_item_list_test),
            cmocka_unit_test(delete_item_alllist_test),
            cmocka_unit_test(delete_item_leaflist_test),
            cmocka_unit_test(delete_negative_test),
            cmocka_unit_test(set_item_leaf_test),
            cmocka_unit_test(set_item_leaflist_test),
            cmocka_unit_test(set_item_list_test),
            cmocka_unit_test(set_item_container_test),
            cmocka_unit_test(set_item_negative_test),
            cmocka_unit_test(edit_test_module_test),
            cmocka_unit_test(edit_validate_test),
            cmocka_unit_test(edit_discard_changes_test),
            cmocka_unit_test(edit_commit_test),
    };
    return cmocka_run_group_tests(tests, setup, teardown);
}
