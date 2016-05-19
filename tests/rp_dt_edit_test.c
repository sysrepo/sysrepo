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
#include <unistd.h>
#include "data_manager.h"
#include "test_data.h"
#include "sr_common.h"
#include "rp_dt_get.h"
#include "rp_dt_edit.h"
#include "test_module_helper.h"
#include "rp_dt_context_helper.h"
#include "rp_internal.h"

#define LEAF_VALUE "leafV"

/* Must be updated with data_manager.c*/
typedef struct dm_session_s {
    sr_datastore_t datastore;           /**< datastore to which the session is tied */
    const ac_ucred_t *user_credentials; /**< credentials of the user who this session belongs to */
    sr_btree_t **session_modules;       /**< array of binary trees holding session copies of data models for each datastore */
    dm_sess_op_t **operations;          /**< array of list of operations performed in this session */
    size_t *oper_count;                 /**< array of number of performed operation */
    size_t *oper_size;                  /**< array of number of allocated operations */
    char *error_msg;                    /**< description of the last error */
    char *error_xpath;                  /**< xpath of the last error if applicable */
    struct ly_set *locked_files;        /**< set of filename that are locked by this session */
    bool holds_ds_lock;                 /**< flags if the session holds ds lock*/
} dm_session_t;

int setup(void **state){
    createDataTreeExampleModule();
    createDataTreeTestModule();
    test_rp_ctx_create((rp_ctx_t**)state);
    return 0;
}

int teardown(void **state){
    rp_ctx_t *ctx = *state;
    test_rp_ctx_cleanup(ctx);
    return 0;
}

void delete_item_leaf_test(void **state){
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;
    sr_val_t *val = NULL;

    /* delete leaf*/
    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);

    rc = rp_dt_get_value_wrapper(ctx, session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_value_wrapper(ctx, session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    test_rp_session_cleanup(ctx, session);

    /* delete non existing leaf*/
    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);
    rc = rp_dt_get_value_wrapper(ctx, session, "/example-module:container/list[key1='abc'][key2='abc']/leaf", &val);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/example-module:container/list[key1='abc'][key2='abc']/leaf", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    /* deleting non existing leaf with strict should fail*/
    rc = rp_dt_delete_item_wrapper(ctx, session, "/example-module:container/list[key1='abc'][key2='abc']/leaf", SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_DATA_MISSING, rc);

    /* delete key leaf is not allowed */
    rc = rp_dt_delete_item_wrapper(ctx, session, "/example-module:container/list[key1='key1'][key2='key2']/key1", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    test_rp_session_cleanup(ctx, session);
}

void delete_item_container_test(void **state){
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;
    sr_val_t *val = NULL;

    /* delete container*/
    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);

    rc = rp_dt_get_value_wrapper(ctx, session, "/example-module:container", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/example-module:container", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_value_wrapper(ctx, session, "/example-module:container", &val);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

#define CONTAINER_XP "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4"
    rc = rp_dt_get_value_wrapper(ctx, session, CONTAINER_XP, &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);

    rc = rp_dt_delete_item_wrapper(ctx, session, CONTAINER_XP, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_value_wrapper(ctx, session, CONTAINER_XP, &val);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* delete non existing container*/
    rc = rp_dt_delete_item_wrapper(ctx, session, CONTAINER_XP , SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_delete_item_wrapper(ctx, session, CONTAINER_XP , SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_DATA_MISSING, rc);

    test_rp_session_cleanup(ctx, session);

    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);
    rc = rp_dt_get_value_wrapper(ctx, session, CONTAINER_XP, &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);

    rc = rp_dt_delete_item_wrapper(ctx, session, CONTAINER_XP , SR_EDIT_NON_RECURSIVE);
    assert_int_equal(SR_ERR_DATA_EXISTS, rc);

    test_rp_session_cleanup(ctx, session);
}


void delete_item_list_test(void **state){
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;
    sr_val_t *val = NULL;

    /* delete list*/
    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);

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
    rc = rp_dt_delete_item_wrapper(ctx, session, LIST_INST1_XP, SR_EDIT_DEFAULT);
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
    rc = rp_dt_delete_item_wrapper(ctx, session, LIST_INST1_XP, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_delete_item_wrapper(ctx, session, LIST_INST1_XP, SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_DATA_MISSING, rc);

    test_rp_session_cleanup(ctx, session);


    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);
    rc = rp_dt_get_value_wrapper(ctx, session, LIST_INST1_XP, &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);
    val = NULL;

    sr_val_t *values = NULL;
    size_t cnt = 0;
    rc = rp_dt_get_values_wrapper(ctx, session, "/example-module:container", &values, &cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, cnt);
    sr_free_values(values, cnt);

    /* list deletion with non recursive fails*/
    rc = rp_dt_delete_item_wrapper(ctx, session, LIST_INST1_XP , SR_EDIT_NON_RECURSIVE);
    assert_int_equal(SR_ERR_DATA_EXISTS, rc);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/example-module:container/list[key1='key1'][key2='key2']" , SR_EDIT_NON_RECURSIVE);
    assert_int_equal(SR_ERR_DATA_EXISTS, rc);

    /* delete the leaf, so the list contains only keys*/
    rc = rp_dt_delete_item_wrapper(ctx, session, "/example-module:container/list[key1='key1'][key2='key2']/leaf" , SR_EDIT_NON_RECURSIVE);
    assert_int_equal(SR_ERR_OK, rc);

    /* if the list contains only keys it can be deleted even with non recursive flag*/
    rc = rp_dt_delete_item_wrapper(ctx, session, "/example-module:container/list[key1='key1'][key2='key2']" , SR_EDIT_NON_RECURSIVE);
    assert_int_equal(SR_ERR_OK, rc);

    /* delete the only list instance in the container the container should be also deleted */
    rc = rp_dt_get_value_wrapper(ctx, session, "/example-module:container", &val);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    test_rp_session_cleanup(ctx, session);
}

void delete_whole_module_test(void **state)
{
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;

    /* delete whole module */
    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);

    /* module xpath must not be called with non recursive*/
    rc = rp_dt_delete_item_wrapper(ctx, session, "/example-module:*", SR_EDIT_NON_RECURSIVE);
    assert_int_equal(SR_ERR_DATA_EXISTS, rc);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/example-module:*", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    /* data tree is already empty can not be called with strict*/
    rc = rp_dt_delete_item_wrapper(ctx, session, "/example-module:*", SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_DATA_MISSING, rc);

    sr_val_t *values = NULL;
    size_t cnt = 0;
    rc = rp_dt_get_values_wrapper(ctx, session, "/example-module:*", &values, &cnt);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    assert_int_equal(0, cnt);

    test_rp_session_cleanup(ctx, session);

    createDataTreeExampleModule();
}

void delete_item_alllist_test(void **state){
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;

    /* delete list*/
    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);

#define LIST_XP "/ietf-interfaces:interfaces/interface"

    sr_val_t *values = NULL;
    size_t count = 0;

    /* there are three list instances*/
    rc = rp_dt_get_values_wrapper(ctx, session, LIST_XP, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_values(values, count);

    /* delete with non recursive should fail*/
    rc = rp_dt_delete_item_wrapper(ctx, session, LIST_XP, SR_EDIT_NON_RECURSIVE);
    assert_int_equal(SR_ERR_DATA_EXISTS, rc);

    /* items should remain in place*/
    rc = rp_dt_get_values_wrapper(ctx, session, LIST_XP, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_values(values, count);

    /* delete all list instances*/
    rc = rp_dt_delete_item_wrapper(ctx, session, LIST_XP, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    /* items should be deleted*/
    rc = rp_dt_get_values_wrapper(ctx, session, LIST_XP, &values, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* delete non existing */
    rc = rp_dt_delete_item_wrapper(ctx, session, LIST_XP, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    /* delete non existing with strict should fail*/
    rc = rp_dt_delete_item_wrapper(ctx, session, LIST_XP, SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_DATA_MISSING, rc);

    test_rp_session_cleanup(ctx, session);
}

void delete_item_leaflist_test(void **state){
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;

    /* delete list*/
    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);

#define LEAF_LIST_XP "/test-module:main/numbers"

    sr_val_t *values = NULL;
    size_t count = 0;
    /* three leaf list items*/
    rc = rp_dt_get_values_wrapper(ctx, session, LEAF_LIST_XP, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_values(values, count);

    /* delete all list instances*/
    rc = rp_dt_delete_item_wrapper(ctx, session, LEAF_LIST_XP, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_values_wrapper(ctx, session, LEAF_LIST_XP, &values, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    test_rp_session_cleanup(ctx, session);
}

void set_item_leaf_test(void **state){
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;

    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);

    /* replace existing leaf*/
    sr_val_t *val = NULL;
    rc = rp_dt_get_value_wrapper(ctx, session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);

    /* modify the value*/
    free(val->data.string_val);
    val->data.string_val = strdup("abcdef");
    assert_non_null(val->data.string_val);

    /* existing leaf */
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, val->xpath, SR_EDIT_STRICT, val);
    assert_int_equal(SR_ERR_DATA_EXISTS, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, val->xpath, SR_EDIT_DEFAULT, val);
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
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/example-module:container/list[key1='new_key1'][key2='new_key2']/key1", SR_EDIT_DEFAULT, val);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/example-module:container/list[key1='new_key1'][key2='new_key2']/key2", SR_EDIT_DEFAULT, val);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* creating with non recursive with missing parent not*/

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, val->xpath, SR_EDIT_NON_RECURSIVE, val);
    assert_int_equal(SR_ERR_DATA_MISSING, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, val->xpath, SR_EDIT_DEFAULT, val);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_val(val);
    val = NULL;

    rc = rp_dt_get_value_wrapper(ctx, session, "/example-module:container/list[key1='new_key1'][key2='new_key2']/leaf", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_string_equal("abcdef", val->data.string_val);

    sr_free_val(val);

    test_rp_session_cleanup(ctx, session);

    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);


    /* create item from root */
    rc = rp_dt_get_value_wrapper(ctx, session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);

    /* create item with explicitly specified namespace*/
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/example-module:container/example-module:list[key1='key11'][key2='key22']/example-module:leaf", SR_EDIT_DEFAULT, val);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/example-module:container", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    sr_val_t *del = NULL;

    rc = rp_dt_get_value_wrapper(ctx, session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &del);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    assert_null(del);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, val->xpath, SR_EDIT_DEFAULT, val);
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

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/small-module:item/info-module:info", SR_EDIT_DEFAULT, &v);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_value_wrapper(ctx, session, "/small-module:item/info-module:info", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);

    assert_int_equal(v.type, val->type);
    assert_string_equal(v.data.string_val, val->data.string_val);

    sr_free_val(val);
    sr_free_val_content(&v);

    test_rp_session_cleanup(ctx, session);
}

void set_item_leaflist_test(void **state){
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;

    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);

    sr_val_t *values = NULL;
    size_t count = 0;
    /* three leaf list items*/
    rc = rp_dt_get_values_wrapper(ctx, session, LEAF_LIST_XP, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);
    sr_free_values(values, count);

    /* append new item*/
    sr_val_t *val = NULL;
    val = calloc(1, sizeof(*val));
    assert_non_null(val);

    val->xpath = strdup("/test-module:main/numbers");
    assert_non_null(val->xpath);
    val->type = SR_UINT8_T;
    val->data.uint8_val = 99;

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, val->xpath, SR_EDIT_DEFAULT, val);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_val(val);

    rc = rp_dt_get_values_wrapper(ctx, session, LEAF_LIST_XP, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(4, count);

    assert_int_equal(SR_UINT8_T, values[3].type);
    assert_int_equal(99, values[3].data.uint8_val);
    sr_free_values(values, count);

    test_rp_session_cleanup(ctx, session);
}

void set_item_list_test(void **state){
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;

    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);

    sr_val_t *values = NULL;
    size_t count = 0;

    /* one existing list instance */
    rc = rp_dt_get_values_wrapper(ctx, session, "/example-module:container/list", &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, count);
    sr_free_values(values, count);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/example-module:container/list[key1='new_key1'][key2='new_key2']", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_values_wrapper(ctx, session, "/example-module:container/list", &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, count);
    sr_free_values(values, count);

    /* set existing list */
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/example-module:container/list[key1='new_key1'][key2='new_key2']", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/example-module:container/list[key1='new_key1'][key2='new_key2']", SR_EDIT_STRICT, NULL);
    assert_int_equal(SR_ERR_DATA_EXISTS, rc);

    test_rp_session_cleanup(ctx, session);
}

void set_item_container_test(void **state){
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;

    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);

    sr_val_t *value = NULL;
    rc = rp_dt_get_value_wrapper(ctx, session, "/test-module:list[key='key']/wireless", &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:list[key='key']/wireless", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_value_wrapper(ctx, session, "/test-module:list[key='key']/wireless", &value);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(value);
    assert_int_equal(SR_CONTAINER_PRESENCE_T, value->type);

    sr_free_val(value);

    /* set existing does nothing*/
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:list[key='key']/wireless", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    /* set existing fails with strict opt*/
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:list[key='key']/wireless", SR_EDIT_STRICT, NULL);
    assert_int_equal(SR_ERR_DATA_EXISTS, rc);

    test_rp_session_cleanup(ctx, session);
}

void
set_item_negative_test(void **state)
{
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;

    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);

    /* set module xpath */
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/test-module:main", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    /* set non-presence container */
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:main", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

#if 0
    /* set list without keys*/
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:list", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);
#endif
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "^usfd&", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* updating key value is not allowed */
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/example-module:container/list[key1='key1'][key2='key2']/key1", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* set item called with NULL value */
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    test_rp_session_cleanup(ctx, session);

    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/example-module:*", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/example-module:container/list[key1='key1'][key2='key2']", SR_EDIT_NON_RECURSIVE, NULL);
    assert_int_equal(SR_ERR_DATA_MISSING, rc);

    test_rp_session_cleanup(ctx, session);
}

void delete_get_set_get(rp_ctx_t *ctx, rp_session_t *session, const char* xpath, sr_val_t *value, sr_val_t **new_set)
{
    int rc = SR_ERR_OK;

    rc = rp_dt_delete_item_wrapper(ctx, session, xpath, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    /* verify that item has been deleted*/
    rc = rp_dt_get_value_wrapper(ctx, session, xpath, new_set);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    assert_null(*new_set);

    /* set it */
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, xpath, SR_EDIT_DEFAULT, value);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_value_wrapper(ctx, session, xpath, new_set);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(*new_set);
    assert_int_equal(value->type, (*new_set)->type);

}

void edit_test_module_test(void **state){
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;
    sr_val_t *value = NULL;
    sr_val_t *new_set = NULL;

    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);

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

    test_rp_session_cleanup(ctx, session);
}

void delete_negative_test(void **state){
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;

    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);

    /* invalid xpath*/
    rc = rp_dt_delete_item_wrapper(ctx, session, "^usfd&", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/example-module:unknown", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_BAD_ELEMENT, rc);

    test_rp_session_cleanup(ctx, session);
}

void
edit_validate_test(void **state)
{
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;
    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;


    /* must when */
    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);

    sr_val_t iftype;
    iftype.xpath = NULL;
    iftype.type = SR_ENUM_T;
    iftype.data.enum_val = strdup ("ethernet");

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:interface/ifType", SR_EDIT_DEFAULT, &iftype);
    assert_int_equal(SR_ERR_OK, rc);

    sr_free_val_content(&iftype);
    rc = dm_validate_session_data_trees(ctx->dm_ctx, session->dm_session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);
    assert_int_equal(1, e_cnt);
    assert_string_equal("An ethernet MTU must be 1500", errors[0].message);
    //assert_string_equal("/test-module:interface", errors[0].path);

    sr_free_errors(errors, e_cnt);

    sr_val_t mtu;
    mtu.xpath = NULL;
    mtu.type = SR_UINT32_T;
    mtu.data.uint32_val = 1024;

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:interface/ifMTU", SR_EDIT_DEFAULT, &mtu);
    assert_int_equal(SR_ERR_OK, rc);

    errors = NULL;
    e_cnt = 0;

    rc = dm_validate_session_data_trees(ctx->dm_ctx, session->dm_session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);
    sr_free_errors(errors, e_cnt);

    mtu.data.uint32_val = 1500;
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:interface/ifMTU", SR_EDIT_DEFAULT, &mtu);
    assert_int_equal(SR_ERR_OK, rc);

    errors = NULL;
    e_cnt = 0;

    rc = dm_validate_session_data_trees(ctx->dm_ctx, session->dm_session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_errors(errors, e_cnt);

    test_rp_session_cleanup(ctx, session);

    /* regexp */
    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);

    sr_val_t hexnumber;
    hexnumber.xpath = NULL;
    hexnumber.type = SR_STRING_T;
    hexnumber.data.string_val = strdup("92FF");
    assert_non_null(hexnumber.data.string_val);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:hexnumber", SR_EDIT_DEFAULT, &hexnumber);
    assert_int_equal(SR_ERR_OK, rc);

    errors = NULL;
    e_cnt = 0;

    rc = dm_validate_session_data_trees(ctx->dm_ctx, session->dm_session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_errors(errors, e_cnt);

    free(hexnumber.data.string_val);
    hexnumber.data.string_val = strdup("AAZZ");

    /* Regular expression mismatch causes SR_ERR_INVAL_ARG */
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:hexnumber", SR_EDIT_DEFAULT, &hexnumber);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    sr_free_val_content(&hexnumber);

    test_rp_session_cleanup(ctx, session);

    /* mandatory leaf */
    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);

    sr_val_t name;
    name.xpath = NULL;
    name.type = SR_STRING_T;
    name.data.string_val = strdup("Name");
    assert_non_null(name.data.string_val);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:location/name", SR_EDIT_DEFAULT, &name);
    assert_int_equal(SR_ERR_OK, rc);

    errors = NULL;
    e_cnt = 0;

    rc = dm_validate_session_data_trees(ctx->dm_ctx, session->dm_session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);
    sr_free_errors(errors, e_cnt);

    sr_val_t lonigitude;
    lonigitude.xpath = NULL;
    lonigitude.type = SR_STRING_T;
    lonigitude.data.string_val = strdup("Longitude 49.45");
    assert_non_null(lonigitude.data.string_val);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:location/longitude", SR_EDIT_DEFAULT, &lonigitude);
    assert_int_equal(SR_ERR_OK, rc);

    errors = NULL;
    e_cnt = 0;

    rc = dm_validate_session_data_trees(ctx->dm_ctx, session->dm_session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);
    assert_int_equal(1, e_cnt);
    assert_string_equal("Missing required element \"latitude\" in \"location\".", errors[0].message);
    assert_string_equal("/test-module:location", errors[0].xpath);
    sr_free_errors(errors, e_cnt);

    sr_val_t latitude;
    latitude.xpath = NULL;
    latitude.type = SR_STRING_T;
    latitude.data.string_val = strdup("Latitude 56.46");
    assert_non_null(latitude.data.string_val);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:location/latitude", SR_EDIT_DEFAULT, &latitude);
    assert_int_equal(SR_ERR_OK, rc);

    errors = NULL;
    e_cnt = 0;

    rc = dm_validate_session_data_trees(ctx->dm_ctx, session->dm_session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_errors(errors, e_cnt);

    sr_free_val_content(&name);
    sr_free_val_content(&lonigitude);
    sr_free_val_content(&latitude);

    test_rp_session_cleanup(ctx, session);

    /* choice */
    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);
    sr_val_t interval;
    interval.xpath = NULL;
    interval.type = SR_UINT16_T;
    interval.data.uint16_val = 9;

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:transfer/interval", SR_EDIT_DEFAULT, &interval);
    assert_int_equal(SR_ERR_OK, rc);

    errors = NULL;
    e_cnt = 0;

    rc = dm_validate_session_data_trees(ctx->dm_ctx, session->dm_session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_errors(errors, e_cnt);

    sr_val_t daily;
    daily.xpath = NULL;
    daily.type = SR_LEAF_EMPTY_T;

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:transfer/daily", SR_EDIT_DEFAULT, &daily);
    assert_int_equal(SR_ERR_OK, rc);

    errors = NULL;
    e_cnt = 0;

    /* Validation should pass because libyang automatically overwrites nodes from different choice alternative */
    rc = dm_validate_session_data_trees(ctx->dm_ctx, session->dm_session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_errors(errors, e_cnt);

    test_rp_session_cleanup(ctx, session);

    /* leaf-list unique values */
    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);
    sr_val_t val;
    val.xpath = NULL;
    val.type = SR_UINT8_T;
    val.data.uint8_val = 9;

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:main/numbers", SR_EDIT_DEFAULT, &val);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:main/numbers", SR_EDIT_DEFAULT, &val);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:main/numbers", SR_EDIT_STRICT, &val);
    assert_int_equal(SR_ERR_DATA_EXISTS, rc);

    errors = NULL;
    e_cnt = 0;

    /* validation pass because lyd_new path doesn't add duplicate leaf-list */
    rc = dm_validate_session_data_trees(ctx->dm_ctx, session->dm_session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    test_rp_session_cleanup(ctx, session);

    /* multiple errors */
#if 0
    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);
    val.xpath = NULL;
    val.type = SR_UINT8_T;
    val.data.uint8_val = 9;

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:main/numbers", SR_EDIT_DEFAULT, &val);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:main/numbers", SR_EDIT_DEFAULT, &val);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/example-module:number", SR_EDIT_DEFAULT, &val);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/example-module:number", SR_EDIT_DEFAULT, &val);
    assert_int_equal(SR_ERR_OK, rc);

    errors = NULL;
    e_cnt = 0;

    rc = dm_validate_session_data_trees(ctx->dm_ctx, session->dm_session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);
    assert_int_equal(2, e_cnt);
    assert_string_equal("Instances of \"number\" list are not unique.", errors[0].message);
    //assert_string_equal("/example-module:number", errors[0].path);

    assert_string_equal("Instances of \"numbers\" list are not unique.", errors[1].message);
    //assert_string_equal("/test-module:main/numbers", errors[1].path);
    sr_free_errors(errors, e_cnt);

    test_rp_session_cleanup(ctx, session);
#endif
}

void
edit_discard_changes_test(void **state)
{
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *sessionA = NULL, *sessionB = NULL;
    sr_val_t *valueA = NULL, *valueB = NULL;

    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &sessionA);
    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &sessionB);

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
    rc = rp_dt_set_item(ctx->dm_ctx, sessionA->dm_session, XP_TEST_MODULE_INT64, SR_EDIT_DEFAULT, valueA);
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

    rc = dm_discard_changes(ctx->dm_ctx, sessionA->dm_session);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_value_wrapper(ctx, sessionA, XP_TEST_MODULE_INT64, &valueA);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueA);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T, valueA->data.int64_val);
    sr_free_val(valueA);

    test_rp_session_cleanup(ctx, sessionA);
    test_rp_session_cleanup(ctx, sessionB);

}

void
empty_commit_test(void **state)
{
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;
    dm_data_info_t *info = NULL;
    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);

    /* no session copy made*/
    sr_error_info_t *errors = NULL;
    size_t err_cnt = 0;
    rc = rp_dt_commit(ctx, session, &errors, &err_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_errors(errors, err_cnt);

    /* not modified session copy */
    rc = dm_get_data_info(ctx->dm_ctx, session->dm_session, "test-module", &info);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_commit(ctx, session, &errors, &err_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_errors(errors, err_cnt);

    rc = dm_get_data_info(ctx->dm_ctx, session->dm_session, "test-module", &info);
    assert_int_equal(SR_ERR_OK, rc);
    info->modified = true;

    rc = rp_dt_commit(ctx, session, &errors, &err_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_errors(errors, err_cnt);

    test_rp_session_cleanup(ctx, session);
}


void
edit_commit_test(void **state)
{
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *sessionA = NULL, *sessionB = NULL;
    sr_val_t *valueA = NULL, *valueB = NULL;

    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &sessionA);
    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &sessionB);

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
    rc = rp_dt_set_item_wrapper(ctx, sessionA, XP_TEST_MODULE_INT64, valueA, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

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


    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;

    rc = rp_dt_commit(ctx, sessionA, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_errors(errors, e_cnt);

    rc = rp_dt_get_value_wrapper(ctx, sessionA, XP_TEST_MODULE_INT64, &valueA);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueA);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T + 99, valueA->data.int64_val);
    sr_free_val(valueA);

    /* refresh the session B to see changes made by commit */
    rc = rp_dt_refresh_session(ctx, sessionB, &errors, &e_cnt);
    assert_int_equal(rc, SR_ERR_OK);

    rc = rp_dt_get_value_wrapper(ctx, sessionB, XP_TEST_MODULE_INT64, &valueB);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueB);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T + 99, valueB->data.int64_val);
    sr_free_val(valueB);

    test_rp_session_cleanup(ctx, sessionA);
    test_rp_session_cleanup(ctx, sessionB);

     /* check that update is permanent in new session*/
    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &sessionA);
    rc = rp_dt_get_value_wrapper(ctx, sessionA, XP_TEST_MODULE_INT64, &valueA);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueA);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T + 99, valueA->data.int64_val);

    valueA->data.int64_val = XP_TEST_MODULE_INT64_VALUE_T;

    rc = rp_dt_set_item_wrapper(ctx, sessionA, XP_TEST_MODULE_INT64, valueA, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_commit(ctx, sessionA, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_errors(errors, e_cnt);

    test_rp_session_cleanup(ctx, sessionA);
}

void
edit_commit2_test(void **state)
{
    /* replay of operations fails */
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL, *sessionB = NULL;

    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);
    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &sessionB);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/test-module:main", SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_delete_item_wrapper(ctx, sessionB, "/test-module:main", SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_OK, rc);

    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;
    rc = rp_dt_commit(ctx, session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    /*this commit should failed because main container is already deleted */
    rc = rp_dt_commit(ctx, sessionB, &errors, &e_cnt);
    assert_int_equal(SR_ERR_DATA_MISSING, rc);
    sr_free_errors(errors, e_cnt);

    test_rp_session_cleanup(ctx, session);
    test_rp_session_cleanup(ctx, sessionB);
}

void
edit_commit3_test(void **state)
{
    /* validation after replay fails*/
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL, *sessionB = NULL;

    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);
    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &sessionB);

    sr_val_t *v1 = NULL;
    sr_val_t *v2 = NULL;

    v1 = calloc(1, sizeof(*v1));
    assert_non_null(v1);
    v1->type = SR_UINT8_T;
    v1->data.uint8_val = 42;

    v2 = calloc(1, sizeof(*v2));
    assert_non_null(v2);
    v2->type = SR_UINT8_T;
    v2->data.uint8_val = 42;

    rc = rp_dt_set_item_wrapper(ctx, session, "/test-module:main/numbers", v1, SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_set_item_wrapper(ctx, sessionB, "/test-module:main/numbers", v2, SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_OK, rc);

    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;

    rc = rp_dt_commit(ctx, session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    /* the leaf-list value was committed during the first commit */
    rc = rp_dt_commit(ctx, sessionB, &errors, &e_cnt);
    assert_int_equal(SR_ERR_DATA_EXISTS, rc);
    sr_free_errors(errors, e_cnt);

    test_rp_session_cleanup(ctx, session);
    test_rp_session_cleanup(ctx, sessionB);
}

void
edit_commit4_test(void **state)
{
    unlink(TEST_MODULE_DATA_FILE_NAME);
    /* empty data file */
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;

    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);

    sr_val_t *v = NULL;
    v = calloc(1, sizeof(*v));
    assert_non_null(v);

    v->type = SR_ENUM_T;
    v->data.enum_val = strdup("yes");
    assert_non_null(v->data.enum_val);

    rc = rp_dt_set_item_wrapper(ctx, session, "/test-module:main/enum", v, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;
    rc = rp_dt_commit(ctx, session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    test_rp_session_cleanup(ctx, session);

    createDataTreeTestModule();
}

void
edit_move_test(void **state)
{
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;
    sr_val_t *values = NULL;
    size_t cnt = 0;

    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);

    /* module xpath */
    rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:", SR_MOVE_LAST, NULL);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* existing item not list */
    rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:main", SR_MOVE_BEFORE, "/test-module:list[key='asdf']");
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* system ordered list non existing instance */
    rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:list[key='asdf']", SR_MOVE_FIRST, NULL);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* system ordered list existing instance */
    rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:list[key='k1']", SR_MOVE_LAST, NULL);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* only the one instance of list */
    rc = rp_dt_get_values_wrapper(ctx, session, "/test-module:user", &values, &cnt);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:user[name='nameA']", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:user[name='nameA']", SR_MOVE_FIRST, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:user[name='nameA']", SR_MOVE_LAST, NULL);
    assert_int_equal(SR_ERR_OK, rc);


    /* multiple instances */

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:user[name='nameB']", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:user[name='nameC']", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_values_wrapper(ctx, session, "/test-module:user", &values, &cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, cnt);

    assert_string_equal("/test-module:user[name='nameA']", values[0].xpath);
    assert_string_equal("/test-module:user[name='nameB']", values[1].xpath);
    assert_string_equal("/test-module:user[name='nameC']", values[2].xpath);

    sr_free_values(values, cnt);

    rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:user[name='nameA']", SR_MOVE_AFTER, "/test-module:user[name='nameB']");
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:user[name='nameC']", SR_MOVE_BEFORE, "/test-module:user[name='nameA']");
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_values_wrapper(ctx, session, "/test-module:user", &values, &cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, cnt);

    assert_string_equal("/test-module:user[name='nameB']", values[0].xpath);
    assert_string_equal("/test-module:user[name='nameC']", values[1].xpath);
    assert_string_equal("/test-module:user[name='nameA']", values[2].xpath);

    sr_free_values(values, cnt);

    test_rp_session_cleanup(ctx, session);
}

void
edit_move2_test(void **state)
{
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;
    sr_val_t *values = NULL;
    size_t cnt = 0;

    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);

    /* empty the data tree*/
    rc = rp_dt_delete_item_wrapper(ctx, session, "/test-module:main", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/test-module:list", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_values_wrapper(ctx, session, "/test-module:user", &values, &cnt);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* only one list instance in data tree */
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:user[name='nameA']", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:user[name='nameA']", SR_MOVE_FIRST, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:user[name='nameA']", SR_MOVE_LAST, NULL);
    assert_int_equal(SR_ERR_OK, rc);


    /* multiple instances */

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:user[name='nameB']", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:user[name='nameC']", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_values_wrapper(ctx, session, "/test-module:user", &values, &cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, cnt);

    assert_string_equal("/test-module:user[name='nameA']", values[0].xpath);
    assert_string_equal("/test-module:user[name='nameB']", values[1].xpath);
    assert_string_equal("/test-module:user[name='nameC']", values[2].xpath);

    sr_free_values(values, cnt);

    /* at the top, this move does nothing*/
    rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:user[name='nameB']", SR_MOVE_FIRST, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:user[name='nameA']", SR_MOVE_LAST, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:user[name='nameC']", SR_MOVE_BEFORE, "/test-module:user[name='nameA']");
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_values_wrapper(ctx, session, "/test-module:user", &values, &cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, cnt);

    assert_string_equal("/test-module:user[name='nameB']", values[0].xpath);
    assert_string_equal("/test-module:user[name='nameC']", values[1].xpath);
    assert_string_equal("/test-module:user[name='nameA']", values[2].xpath);

    sr_free_values(values, cnt);

    rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:user[name='nameB']", SR_MOVE_AFTER, "/test-module:user[name='nameB']" );
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:user[name='nameC']", SR_MOVE_FIRST, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:user[name='nameA']", SR_MOVE_FIRST, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_values_wrapper(ctx, session, "/test-module:user", &values, &cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, cnt);

    assert_string_equal("/test-module:user[name='nameA']", values[0].xpath);
    assert_string_equal("/test-module:user[name='nameC']", values[1].xpath);
    assert_string_equal("/test-module:user[name='nameB']", values[2].xpath);

    sr_free_values(values, cnt);

    test_rp_session_cleanup(ctx, session);
}

void
edit_move3_test(void **state)
{
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;
    sr_val_t *values = NULL;
    size_t cnt = 0;

    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);

    /* empty the data tree*/
    rc = rp_dt_delete_item_wrapper(ctx, session, "/test-module:main", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/test-module:list", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_values_wrapper(ctx, session, "/test-module:user", &values, &cnt);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    rc = rp_dt_get_values_wrapper(ctx, session, "/test-module:ordered-numbers", &values, &cnt);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* add some ordered leaf-list entries */
    sr_val_t *v = NULL;
    v = calloc(1, sizeof(*v));
    assert_non_null(v);
    v->type = SR_UINT8_T;
    v->xpath = strdup("/test-module:ordered-numbers");
    v->data.uint8_val = 1;

    rc = rp_dt_set_item_wrapper(ctx, session, v->xpath, v, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    v = calloc(1, sizeof(*v));
    assert_non_null(v);
    v->type = SR_UINT8_T;
    v->xpath = strdup("/test-module:ordered-numbers");
    v->data.uint8_val = 2;
    rc = rp_dt_set_item_wrapper(ctx, session, v->xpath, v, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    v = calloc(1, sizeof(*v));
    assert_non_null(v);
    v->type = SR_UINT8_T;
    v->xpath = strdup("/test-module:ordered-numbers");
    v->data.uint8_val = 9;
    rc = rp_dt_set_item_wrapper(ctx, session, v->xpath, v, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_values_wrapper(ctx, session, "/test-module:ordered-numbers", &values, &cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, cnt);

    assert_int_equal(1, values[0].data.uint8_val);
    assert_int_equal(2, values[1].data.uint8_val);
    assert_int_equal(9, values[2].data.uint8_val);

    sr_free_values(values, cnt);

    rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:ordered-numbers[.='9']", SR_MOVE_FIRST, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_values_wrapper(ctx, session, "/test-module:ordered-numbers", &values, &cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, cnt);

    assert_int_equal(9, values[0].data.uint8_val);
    assert_int_equal(1, values[1].data.uint8_val);
    assert_int_equal(2, values[2].data.uint8_val);

    sr_free_values(values, cnt);

    /* move with different node */
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:user[name='nameA']", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:ordered-numbers[.='9']", SR_MOVE_AFTER, "/test-module:user[name='nameA']");
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* relative item invalid node */
    rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:ordered-numbers[.='9']", SR_MOVE_AFTER, "/test-module:main");
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    test_rp_session_cleanup(ctx, session);
}

void
operation_logging_test(void **state)
{
   int rc = 0;
   rp_ctx_t *ctx = *state;
   rp_session_t *session = NULL;

   test_rp_sesssion_create(ctx, SR_DS_STARTUP, &session);

   assert_int_equal(0, session->dm_session->oper_count[session->datastore]);

   /* set */

   /* type mismatch unsuccessful not logged*/
   sr_val_t *value = NULL;
   value = calloc(1, sizeof(*value));
   assert_non_null(value);
   value->data.string_val = strdup("abc");
   value->type = SR_STRING_T;
   rc = rp_dt_set_item_wrapper(ctx, session, "/test-module:main/i8", value, SR_EDIT_DEFAULT);
   assert_int_equal(SR_ERR_INVAL_ARG, rc);
   assert_int_equal(0, session->dm_session->oper_count[session->datastore]);


   rc = rp_dt_set_item_wrapper(ctx, session, "/test-module:user[name='nameC']", NULL, SR_EDIT_DEFAULT);
   assert_int_equal(SR_ERR_OK, rc);
   assert_int_equal(1, session->dm_session->oper_count[session->datastore]);
   assert_int_equal(DM_SET_OP, session->dm_session->operations[session->datastore][session->dm_session->oper_count[session->datastore]-1].op);

   rc = rp_dt_set_item_wrapper(ctx, session, "/test-module:user[name='nameX']", NULL, SR_EDIT_DEFAULT);
   assert_int_equal(SR_ERR_OK, rc);
   assert_int_equal(2, session->dm_session->oper_count[session->datastore]);

   /* move */
   rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:user[name='nameX']", SR_MOVE_LAST, NULL);
   assert_int_equal(SR_ERR_OK, rc);
   assert_int_equal(3, session->dm_session->oper_count[session->datastore]);
   assert_int_equal(DM_MOVE_OP, session->dm_session->operations[session->datastore][session->dm_session->oper_count[session->datastore]-1].op);

   rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:!^", SR_MOVE_BEFORE, "/test-module:user[name='nameC']");
   assert_int_equal(SR_ERR_BAD_ELEMENT, rc);
   assert_int_equal(3, session->dm_session->oper_count[session->datastore]);

   /* delete */
   rc = rp_dt_delete_item_wrapper(ctx, session, "/test-module:user[name='nameC']", SR_EDIT_DEFAULT);
   assert_int_equal(SR_ERR_OK, rc);
   assert_int_equal(4, session->dm_session->oper_count[session->datastore]);
   assert_int_equal(DM_DELETE_OP, session->dm_session->operations[session->datastore][session->dm_session->oper_count[session->datastore]-1].op);

   /* unsuccessful operation should not be logged */
   rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:user[name='nameC']", SR_MOVE_AFTER, "/test-module:user[name='nameC']");
   assert_int_equal(SR_ERR_INVAL_ARG, rc);
   assert_int_equal(4, session->dm_session->oper_count[session->datastore]);

   test_rp_session_cleanup(ctx, session);
}

void
lock_commit_test(void **state)
{
   int rc = 0;
   rp_ctx_t *ctx = *state;
   rp_session_t *sessionA = NULL, *sessionB = NULL;

   test_rp_sesssion_create(ctx, SR_DS_STARTUP, &sessionA);
   test_rp_sesssion_create(ctx, SR_DS_STARTUP, &sessionB);

   /* lock example module in A*/
   rc = dm_lock_module(ctx->dm_ctx, sessionA->dm_session, "test-module");
   assert_int_equal(SR_ERR_OK, rc);

   /* do some changes in A */
   rc = rp_dt_set_item_wrapper(ctx, sessionA, "/example-module:container/list[key1='key1'][key2='key2']", NULL, SR_EDIT_DEFAULT);
   assert_int_equal(SR_ERR_OK, rc);

   rc = rp_dt_delete_item_wrapper(ctx, sessionA, "/test-module:list", SR_EDIT_DEFAULT);
   assert_int_equal(SR_ERR_OK, rc);

   /* lock something in B */
   rc = dm_lock_module(ctx->dm_ctx, sessionB->dm_session, "example-module");
   assert_int_equal(SR_ERR_OK, rc);

   /* commit A should fail */
   size_t e_cnt = 0;
   sr_error_info_t *errors = NULL;
   rc = rp_dt_commit(ctx, sessionA, &errors, &e_cnt);
   assert_int_equal(SR_ERR_LOCKED, rc);

   /* unlock B */
   rc = dm_unlock_module(ctx->dm_ctx, sessionB->dm_session, "example-module");
   assert_int_equal(SR_ERR_OK, rc);

   /* commit A should succeed */
   rc = rp_dt_commit(ctx, sessionA, &errors, &e_cnt);
   assert_int_equal(SR_ERR_OK, rc);

   /* should be still locked even after commit */
   rc = dm_lock_module(ctx->dm_ctx, sessionB->dm_session, "test-module");
   assert_int_equal(SR_ERR_LOCKED, rc);

   test_rp_session_cleanup(ctx, sessionA);
   test_rp_session_cleanup(ctx, sessionB);
}


void
empty_string_leaf_test(void **state)
{
   int rc = 0;
   rp_ctx_t *ctx = *state;
   rp_session_t *sessionA = NULL, *sessionB = NULL;

   test_rp_sesssion_create(ctx, SR_DS_STARTUP, &sessionA);
   test_rp_sesssion_create(ctx, SR_DS_STARTUP, &sessionB);

   sr_val_t *v = NULL;
   v = calloc(1, sizeof(*v));
   assert_non_null(v);
   v->type = SR_STRING_T;

   rc = rp_dt_set_item_wrapper(ctx, sessionA, "/test-module:main/string", v, SR_EDIT_DEFAULT);
   assert_int_equal(SR_ERR_OK, rc);

   size_t e_cnt = 0;
   sr_error_info_t *errors = NULL;
   rc = rp_dt_commit(ctx, sessionA, &errors, &e_cnt);
   assert_int_equal(SR_ERR_OK, rc);

   sr_val_t *retrieved = NULL;
   rc = rp_dt_get_value_wrapper(ctx, sessionB, "/test-module:main/string", &retrieved);
   assert_int_equal(SR_ERR_OK, rc);

   sr_free_val(retrieved);

   test_rp_session_cleanup(ctx, sessionA);
   test_rp_session_cleanup(ctx, sessionB);
}

static void
candidate_edit_test(void **state)
{
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *sessionA = NULL, *sessionB = NULL;
    sr_val_t *value = NULL;

    test_rp_sesssion_create(ctx, SR_DS_CANDIDATE, &sessionA);
    test_rp_sesssion_create(ctx, SR_DS_CANDIDATE, &sessionB);

    sr_val_t iftype = {0};
    iftype.xpath = NULL;
    iftype.type = SR_ENUM_T;
    iftype.data.enum_val = strdup ("ethernet");

    rc = rp_dt_set_item(ctx->dm_ctx, sessionA->dm_session, "/test-module:interface/ifType", SR_EDIT_DEFAULT, &iftype);
    assert_int_equal(SR_ERR_OK, rc);

    sr_free_val_content(&iftype);

    /* modified module in cadidate is validated before copy */
    rc = dm_copy_module(ctx->dm_ctx, sessionA->dm_session, "test-module", SR_DS_CANDIDATE, SR_DS_STARTUP);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);

    rc = dm_discard_changes(ctx->dm_ctx, sessionA->dm_session);
    assert_int_equal(SR_ERR_OK, rc);

    /* refresh candidate session */
    sr_val_t *v = NULL;
    v = calloc(1, sizeof(*v));
    assert_non_null(v);

    v->xpath = strdup("/test-module:main/i8");
    v->type = SR_INT8_T;
    v->data.int8_val = 42;

    rc = rp_dt_get_value_wrapper(ctx, sessionA, "/test-module:main/i8", &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    rc = rp_dt_set_item_wrapper(ctx, sessionA, v->xpath, v, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;

    rc = rp_dt_refresh_session(ctx, sessionA, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_value_wrapper(ctx, sessionA, "/test-module:main/i8", &value);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(SR_INT8_T, value->type);
    assert_int_equal(v->data.int8_val, value->data.int8_val);
    sr_free_val(value);

    /* test locking on candidate ds */
    rc = dm_lock_module(ctx->dm_ctx, sessionA->dm_session, "test-module");
    assert_int_equal(SR_ERR_OK, rc);

    rc = dm_lock_module(ctx->dm_ctx, sessionB->dm_session, "test-module");
    assert_int_equal(SR_ERR_LOCKED, rc);

    test_rp_session_cleanup(ctx, sessionA);
    test_rp_session_cleanup(ctx, sessionB);
}

static void
copy_to_running_test(void **state)
{
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *sessionA = NULL, *sessionB = NULL;

    test_rp_sesssion_create(ctx, SR_DS_CANDIDATE, &sessionA);
    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &sessionB);

    /* only enabled modules are copied, no module is enabled => no operation*/
    rc = rp_dt_copy_config(ctx, sessionB, NULL, SR_DS_STARTUP, SR_DS_RUNNING);
    assert_int_equal(SR_ERR_OK, rc);

    /* explictly select a module which is not enabled copy fails*/
    rc = rp_dt_copy_config(ctx, sessionB, "test-module", SR_DS_STARTUP, SR_DS_RUNNING);
    assert_int_equal(SR_ERR_OPERATION_FAILED, rc);

    /* only enabled modules are copied, no module is enabled => no operation*/
    rc = rp_dt_copy_config(ctx, sessionA, NULL, SR_DS_CANDIDATE, SR_DS_RUNNING);
    assert_int_equal(SR_ERR_OK, rc);

    /* empty data tree loaded from running (source of candidate) can be copied to running */
    rc = rp_dt_copy_config(ctx, sessionA, "test-module", SR_DS_CANDIDATE, SR_DS_RUNNING);
    assert_int_equal(SR_ERR_OK, rc);

    /* copy startup to candidate */
    rc = rp_dt_copy_config(ctx, sessionA, "test-module", SR_DS_STARTUP, SR_DS_CANDIDATE);
    assert_int_equal(SR_ERR_OK, rc);

    /* copy of not enabled module to running should fail */
    rc = rp_dt_copy_config(ctx, sessionA, "test-module", SR_DS_CANDIDATE, SR_DS_RUNNING);
    assert_int_equal(SR_ERR_OPERATION_FAILED, rc);

    test_rp_session_cleanup(ctx, sessionA);
    test_rp_session_cleanup(ctx, sessionB);
}

static void
candidate_commit_lock_test(void **state)
{
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *sessionA = NULL, *sessionB = NULL, *sessionC = NULL;
    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;
    sr_val_t *value = NULL;

    test_rp_sesssion_create(ctx, SR_DS_CANDIDATE, &sessionA);
    test_rp_sesssion_create(ctx, SR_DS_RUNNING, &sessionB);
    test_rp_sesssion_create(ctx, SR_DS_CANDIDATE, &sessionC);

    rc = dm_enable_module_running(ctx->dm_ctx, sessionA->dm_session, "test-module", NULL);
    assert_int_equal(SR_ERR_OK, rc);

    /* lock test module in running*/
    rc = dm_lock_module(ctx->dm_ctx, sessionB->dm_session, "test-module");
    assert_int_equal(SR_ERR_OK, rc);

    sr_val_t *v = NULL;
    v = calloc(1, sizeof(*v));
    assert_non_null(v);

    v->xpath = strdup("/test-module:main/i8");
    v->type = SR_INT8_T;
    v->data.int8_val = 42;

    rc = rp_dt_set_item_wrapper(ctx, sessionA, v->xpath, v, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    /* commit failed running locked */
    rc = rp_dt_commit(ctx, sessionA, &errors, &e_cnt);
    assert_int_equal(SR_ERR_LOCKED, rc);
    sr_free_errors(errors, e_cnt);

    rc = dm_lock_module(ctx->dm_ctx, sessionC->dm_session, "test-module");
    assert_int_equal(SR_ERR_OK, rc);

    /* commit failed running & candidate locked */
    rc = rp_dt_commit(ctx, sessionA, &errors, &e_cnt);
    assert_int_equal(SR_ERR_LOCKED, rc);
    sr_free_errors(errors, e_cnt);

    rc = dm_unlock_module(ctx->dm_ctx, sessionB->dm_session, "test-module");
    assert_int_equal(SR_ERR_OK, rc);

    /* commit failed candidate locked */
    rc = rp_dt_commit(ctx, sessionA, &errors, &e_cnt);
    assert_int_equal(SR_ERR_LOCKED, rc);
    sr_free_errors(errors, e_cnt);

    rc = dm_unlock_module(ctx->dm_ctx, sessionC->dm_session, "test-module");
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_commit(ctx, sessionA, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_value_wrapper(ctx, sessionA, "/test-module:main/i8", &value);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(SR_INT8_T, value->type);
    assert_int_equal(42, value->data.int8_val);

    sr_free_val(value);

    test_rp_session_cleanup(ctx, sessionA);
    test_rp_session_cleanup(ctx, sessionB);
    test_rp_session_cleanup(ctx, sessionC);
}

int main(){

    sr_log_stderr(SR_LL_DBG);

    const struct CMUnitTest tests[] = {
            cmocka_unit_test(delete_item_leaf_test),
            cmocka_unit_test(delete_item_container_test),
            cmocka_unit_test(delete_item_list_test),
            cmocka_unit_test(delete_item_alllist_test),
            cmocka_unit_test(delete_item_leaflist_test),
            cmocka_unit_test(delete_whole_module_test),
            cmocka_unit_test(delete_negative_test),
            cmocka_unit_test(set_item_leaf_test),
            cmocka_unit_test(set_item_leaflist_test),
            cmocka_unit_test(set_item_list_test),
            cmocka_unit_test(set_item_container_test),
            cmocka_unit_test(set_item_negative_test),
            cmocka_unit_test(edit_test_module_test),
            cmocka_unit_test(edit_validate_test),
            cmocka_unit_test(edit_discard_changes_test),
            cmocka_unit_test(empty_commit_test),
            cmocka_unit_test(edit_commit_test),
            cmocka_unit_test(edit_move_test),
            cmocka_unit_test(edit_move2_test),
            cmocka_unit_test(edit_move3_test),
            cmocka_unit_test(edit_commit2_test),
            cmocka_unit_test(edit_commit3_test),
            cmocka_unit_test(edit_commit4_test),
            cmocka_unit_test(operation_logging_test),
            cmocka_unit_test(lock_commit_test),
            cmocka_unit_test(empty_string_leaf_test),
            cmocka_unit_test(candidate_edit_test),
            cmocka_unit_test(copy_to_running_test),
            cmocka_unit_test(candidate_commit_lock_test),
    };
    return cmocka_run_group_tests(tests, setup, teardown);
}
