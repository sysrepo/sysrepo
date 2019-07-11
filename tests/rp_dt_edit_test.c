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
#include "rp_dt_xpath.h"
#include "test_module_helper.h"
#include "nacm_module_helper.h"
#include "rp_dt_context_helper.h"
#include "rp_internal.h"
#include "system_helper.h"

#define LEAF_VALUE "leafV"

/* Must be updated with data_manager.c*/
typedef struct dm_session_s {
    dm_ctx_t *dm_ctx;                   /**< dm_ctx where the session belongs to */
    sr_datastore_t datastore;           /**< datastore to which the session is tied */
    const ac_ucred_t *user_credentials; /**< credentials of the user who this session belongs to */
    sr_btree_t **session_modules;       /**< array of binary trees holding session copies of data models for each datastore */
    dm_sess_op_t **operations;          /**< array of list of operations performed in this session */
    size_t *oper_count;                 /**< array of number of performed operation */
    size_t *oper_size;                  /**< array of number of allocated operations */
    char *error_msg;                    /**< description of the last error */
    char *error_xpath;                  /**< xpath of the last error if applicable */
    sr_list_t *locked_files;            /**< set of filename that are locked by this session */
    bool holds_ds_lock;                 /**< flags if the session holds ds lock*/
} dm_session_t;

int
createData(void **state)
{
    createDataTreeExampleModule();
    createDataTreeTestModule();
    createDataTreeIETFinterfacesModule();
    return 0;
}

int setup(void **state){
    createData(state);
    test_rp_ctx_create(CM_MODE_LOCAL, (rp_ctx_t**)state);
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
    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    rc = rp_dt_get_value_wrapper(ctx, session, NULL, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    test_rp_session_cleanup(ctx, session);

    /* delete non existing leaf*/
    test_rp_session_create(ctx, SR_DS_STARTUP, &session);
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, "/example-module:container/list[key1='abc'][key2='abc']/leaf", &val);
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
    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    rc = rp_dt_get_value_wrapper(ctx, session, NULL, "/example-module:container", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/example-module:container", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, "/example-module:container", &val);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

#define CONTAINER_XP "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4"
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, CONTAINER_XP, &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);

    rc = rp_dt_delete_item_wrapper(ctx, session, CONTAINER_XP, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, CONTAINER_XP, &val);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* delete non existing container*/
    rc = rp_dt_delete_item_wrapper(ctx, session, CONTAINER_XP , SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_delete_item_wrapper(ctx, session, CONTAINER_XP , SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_DATA_MISSING, rc);

    test_rp_session_cleanup(ctx, session);

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, CONTAINER_XP, &val);
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
    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

#define LIST_INST1_XP "/ietf-interfaces:interfaces/interface[name='eth0']"
#define LIST_INST2_XP "/ietf-interfaces:interfaces/interface[name='eth1']"
#define LIST_INST3_XP "/ietf-interfaces:interfaces/interface[name='gigaeth0']"

    /* there three list instances*/
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, LIST_INST1_XP, &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, LIST_INST2_XP, &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, LIST_INST3_XP, &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);

    /* delete on list instance*/
    session->state = RP_REQ_NEW;
    rc = rp_dt_delete_item_wrapper(ctx, session, LIST_INST1_XP, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, LIST_INST1_XP, &val);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* two remaining stays in place */
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, LIST_INST2_XP, &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, LIST_INST3_XP, &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);

    /* try to delete non existing list*/
    rc = rp_dt_delete_item_wrapper(ctx, session, LIST_INST1_XP, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_delete_item_wrapper(ctx, session, LIST_INST1_XP, SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_DATA_MISSING, rc);

    test_rp_session_cleanup(ctx, session);


    test_rp_session_create(ctx, SR_DS_STARTUP, &session);
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, LIST_INST1_XP, &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);
    val = NULL;

    sr_val_t *values = NULL;
    size_t cnt = 0;
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_values_wrapper(ctx, session, NULL, "/example-module:container", &values, &cnt);
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
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, "/example-module:container", &val);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    test_rp_session_cleanup(ctx, session);
}

void delete_whole_module_test(void **state)
{
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;

    /* delete whole module */
    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

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
    rc = rp_dt_get_values_wrapper(ctx, session, NULL, "/example-module:*", &values, &cnt);
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
    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

#define LIST_XP "/ietf-interfaces:interfaces/interface"

    sr_val_t *values = NULL;
    size_t count = 0;

    /* there are three list instances*/
    rc = rp_dt_get_values_wrapper(ctx, session, NULL, LIST_XP, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_values(values, count);

    /* delete with non recursive should fail*/
    rc = rp_dt_delete_item_wrapper(ctx, session, LIST_XP, SR_EDIT_NON_RECURSIVE);
    assert_int_equal(SR_ERR_DATA_EXISTS, rc);

    /* items should remain in place*/
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_values_wrapper(ctx, session, NULL, LIST_XP, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_values(values, count);

    /* delete all list instances*/
    rc = rp_dt_delete_item_wrapper(ctx, session, LIST_XP, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    /* items should be deleted*/
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_values_wrapper(ctx, session, NULL, LIST_XP, &values, &count);
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
    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

#define LEAF_LIST_XP "/test-module:main/numbers"

    sr_val_t *values = NULL;
    size_t count = 0;
    /* three leaf list items*/
    rc = rp_dt_get_values_wrapper(ctx, session, NULL, LEAF_LIST_XP, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);
    sr_free_values(values, count);

    /* delete one leaf-list instance */
    rc = rp_dt_delete_item_wrapper(ctx, session, LEAF_LIST_XP "[.=42]", SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_OK, rc);

    session->state = RP_REQ_NEW;

    rc = rp_dt_get_values_wrapper(ctx, session, NULL, LEAF_LIST_XP, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, count);
    sr_free_values(values, count);

    /* delete all remaining leaf-list instances*/
    rc = rp_dt_delete_item_wrapper(ctx, session, LEAF_LIST_XP, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_values_wrapper(ctx, session, NULL, LEAF_LIST_XP, &values, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    test_rp_session_cleanup(ctx, session);
}

void delete_item_leafref_test(void **state) {
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;
    sr_val_t *values = NULL;
    size_t count = 0;

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    /* delete list item with leafrefs */
#define ITEM_WITH_LEAFREFS_XP "/test-module:university/classes/class[title='CCNA']/student[name='nameC']"
#define REFERENCED_ITEM_XP "/test-module:university/students/student[name='nameC']"

    rc = rp_dt_delete_item_wrapper(ctx, session, ITEM_WITH_LEAFREFS_XP, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_values_wrapper(ctx, session, NULL, ITEM_WITH_LEAFREFS_XP, &values, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    /* do not delete referenced item though */
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_values_wrapper(ctx, session, NULL, REFERENCED_ITEM_XP, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_values(values, count);
    values = NULL;

    /* delete one leafref only */
#define LEAFREF_XP "/test-module:university/classes/class[title='CCNA']/student[name='nameB']/age"
#define REFERENCED_LEAFREF_XP "/test-module:university/students/student[name='nameB']/age"

    rc = rp_dt_delete_item_wrapper(ctx, session, LEAFREF_XP, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_values_wrapper(ctx, session, NULL, LEAFREF_XP, &values, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    /* do not delete referenced item though */
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_values_wrapper(ctx, session, NULL, REFERENCED_LEAFREF_XP, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_values(values, count);
    values = NULL;

    test_rp_session_cleanup(ctx, session);

}

void set_item_leaf_test(void **state){
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    /* replace existing leaf*/
    sr_val_t *val = NULL;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);

    /* modify the value*/
    free(val->data.string_val);
    val->data.string_val = strdup("abcdef");
    assert_non_null(val->data.string_val);

    /* existing leaf */
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, val->xpath, SR_EDIT_STRICT, val, NULL, false);
    assert_int_equal(SR_ERR_DATA_EXISTS, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, val->xpath, SR_EDIT_DEFAULT, val, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_val(val);
    val = NULL;

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_string_equal("abcdef", val->data.string_val);

    /*reuse sr_val_t insert new value under the existing container*/
    free(val->xpath);
    val->xpath = strdup("/example-module:container/list[key1='new_key1'][key2='new_key2']/leaf");
    assert_non_null(val->xpath);

    /* setting key leaf is not allowed*/
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/example-module:container/list[key1='new_key1'][key2='new_key2']/key1", SR_EDIT_DEFAULT, val, NULL, false);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/example-module:container/list[key1='new_key1'][key2='new_key2']/key2", SR_EDIT_DEFAULT, val, NULL, false);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* creating with non recursive with missing parent not*/

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, val->xpath, SR_EDIT_NON_RECURSIVE, val, NULL, false);
    assert_int_equal(SR_ERR_DATA_MISSING, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, val->xpath, SR_EDIT_DEFAULT, val, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_val(val);
    val = NULL;

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, "/example-module:container/list[key1='new_key1'][key2='new_key2']/leaf", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_string_equal("abcdef", val->data.string_val);

    sr_free_val(val);

    test_rp_session_cleanup(ctx, session);

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);


    /* create item from root */
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);

    /* create item with explicitly specified namespace*/
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/example-module:container/example-module:list[key1='key11'][key2='key22']/example-module:leaf", SR_EDIT_DEFAULT, val, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/example-module:container", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    sr_val_t *del = NULL;

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &del);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    assert_null(del);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, val->xpath, SR_EDIT_DEFAULT, val, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_val(val);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    sr_free_val(val);

    /* create augment node */
    sr_val_t v;
    v._sr_mem = NULL;
    v.xpath = NULL;
    v.type = SR_STRING_T;
    v.data.string_val = strdup("abc");
    assert_non_null(v.data.string_val);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/small-module:item/info-module:info", SR_EDIT_DEFAULT, &v, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, "/small-module:item/info-module:info", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);

    assert_int_equal(v.type, val->type);
    assert_string_equal(v.data.string_val, val->data.string_val);

    sr_free_val(val);
    sr_free_val_content(&v);

    /* try to create leaf with incorrect type (uint32 instead of expected string) */
    v.xpath = NULL;
    v.type = SR_UINT32_T;
    v.data.uint32_val = 42;

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:main/string", SR_EDIT_DEFAULT, &v, NULL, false);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    test_rp_session_cleanup(ctx, session);
}

void set_item_leaflist_test(void **state){
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    sr_val_t *values = NULL;
    size_t count = 0;
    /* three leaf list items*/
    rc = rp_dt_get_values_wrapper(ctx, session, NULL, LEAF_LIST_XP, &values, &count);
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

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, val->xpath, SR_EDIT_DEFAULT, val, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_val(val);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_values_wrapper(ctx, session, NULL, LEAF_LIST_XP, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(4, count);

    assert_int_equal(SR_UINT8_T, values[3].type);
    assert_int_equal(99, values[3].data.uint8_val);
    sr_free_values(values, count);

    /* create leaf-list with predicate value can be NULL*/
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:main/numbers[.='33']", SR_EDIT_STRICT, NULL, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_values_wrapper(ctx, session, NULL, LEAF_LIST_XP, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(5, count);

    assert_int_equal(SR_UINT8_T, values[4].type);
    assert_int_equal(33, values[4].data.uint8_val);
    sr_free_values(values, count);

    val = calloc(1, sizeof(*val));
    assert_non_null(val);

    val->xpath = strdup("/test-module:main/numbers");
    assert_non_null(val->xpath);
    val->type = SR_UINT8_T;
    val->data.uint8_val = 66;

    /* if there is a leaf-list predicate, value is ignored */
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:main/numbers[.='55']", SR_EDIT_STRICT, val, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_val(val);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_values_wrapper(ctx, session, NULL, LEAF_LIST_XP, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(6, count);

    assert_int_equal(SR_UINT8_T, values[5].type);
    assert_int_equal(55, values[5].data.uint8_val);
    sr_free_values(values, count);

    /* either predicate or value must be specified */
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:main/numbers", SR_EDIT_STRICT, NULL, NULL, false);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    test_rp_session_cleanup(ctx, session);
}

void set_item_list_test(void **state){
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    sr_val_t *values = NULL;
    size_t count = 0;

    /* one existing list instance */
    rc = rp_dt_get_values_wrapper(ctx, session, NULL, "/example-module:container/list", &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, count);
    sr_free_values(values, count);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/example-module:container/list[key1='new_key1'][key2='new_key2']", SR_EDIT_DEFAULT, NULL, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_values_wrapper(ctx, session, NULL, "/example-module:container/list", &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, count);
    sr_free_values(values, count);

    /* set existing list */
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/example-module:container/list[key1='new_key1'][key2='new_key2']", SR_EDIT_DEFAULT, NULL, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/example-module:container/list[key1='new_key1'][key2='new_key2']", SR_EDIT_STRICT, NULL, NULL, false);
    assert_int_equal(SR_ERR_DATA_EXISTS, rc);

    test_rp_session_cleanup(ctx, session);
}

void set_item_container_test(void **state){
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    sr_val_t *value = NULL;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, "/test-module:list[key='key']/wireless", &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:list[key='key']/wireless", SR_EDIT_DEFAULT, NULL, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, "/test-module:list[key='key']/wireless", &value);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(value);
    assert_int_equal(SR_CONTAINER_PRESENCE_T, value->type);

    sr_free_val(value);

    /* set existing does nothing*/
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:list[key='key']/wireless", SR_EDIT_DEFAULT, NULL, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    /* set existing fails with strict opt*/
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:list[key='key']/wireless", SR_EDIT_STRICT, NULL, NULL, false);
    assert_int_equal(SR_ERR_DATA_EXISTS, rc);

    test_rp_session_cleanup(ctx, session);
}

void set_item_leafref_test(void **state) {
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    /* set list item with leafref as the key */
#undef ITEM_WITH_LEAFREFS_XP
#define ITEM_WITH_LEAFREFS_XP "/test-module:university/classes/class[title='CCNA']/student[name='nameA']"
    sr_val_t *value = NULL;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, ITEM_WITH_LEAFREFS_XP, &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, ITEM_WITH_LEAFREFS_XP, SR_EDIT_DEFAULT, NULL, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, ITEM_WITH_LEAFREFS_XP "/name", &value);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(value);
    assert_int_equal(SR_STRING_T, value->type);
    assert_string_equal("nameA", value->data.string_val);

    sr_free_val(value);

    /* set existing does nothing*/
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, ITEM_WITH_LEAFREFS_XP, SR_EDIT_DEFAULT, NULL, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    /* set existing fails with strict opt*/
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, ITEM_WITH_LEAFREFS_XP, SR_EDIT_STRICT, NULL, NULL, false);
    assert_int_equal(SR_ERR_DATA_EXISTS, rc);

    /* set leafref */
    value = calloc(1, sizeof(*value));
    assert_non_null(value);
    value->type = SR_UINT8_T;
    value->data.uint8_val = 18;

#undef LEAFREF_XP
#define LEAFREF_XP "/test-module:university/classes/class[title='CCNA']/student[name='nameC']/age"

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, LEAFREF_XP, &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, LEAFREF_XP, SR_EDIT_DEFAULT, value, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    sr_free_val(value);
    value = NULL;

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, LEAFREF_XP, &value);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(value);
    assert_int_equal(SR_UINT8_T, value->type);
    assert_int_equal(18, value->data.uint8_val);
    sr_free_val(value);

    test_rp_session_cleanup(ctx, session);
}

void
set_item_negative_test(void **state)
{
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    /* set module xpath */
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:", SR_EDIT_DEFAULT, NULL, NULL, false);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/test-module:main", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    /* set non-presence container */
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:main", SR_EDIT_DEFAULT, NULL, NULL, false);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

#if 0
    /* set list without keys*/
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:list", SR_EDIT_DEFAULT, NULL);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);
#endif
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "^usfd&", SR_EDIT_DEFAULT, NULL, NULL, false);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* updating key value is not allowed */
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/example-module:container/list[key1='key1'][key2='key2']/key1", SR_EDIT_DEFAULT, NULL, NULL, false);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* set item called with NULL value */
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", SR_EDIT_DEFAULT, NULL, NULL, false);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    test_rp_session_cleanup(ctx, session);

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/example-module:*", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/example-module:container/list[key1='key1'][key2='key2']", SR_EDIT_NON_RECURSIVE, NULL, NULL, false);
    assert_int_equal(SR_ERR_DATA_MISSING, rc);

    test_rp_session_cleanup(ctx, session);
}

void delete_get_set_get(rp_ctx_t *ctx, rp_session_t *session, const char* xpath, sr_val_t *value, sr_val_t **new_set)
{
    int rc = SR_ERR_OK;

    rc = rp_dt_delete_item_wrapper(ctx, session, xpath, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    /* verify that item has been deleted*/
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, xpath, new_set);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    assert_null(*new_set);

    /* set it */
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, xpath, SR_EDIT_DEFAULT, value, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, xpath, new_set);
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

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

#define FREE_VARS(A, B) do{sr_free_val(A); sr_free_val(B); A = NULL; B = NULL;}while(0)

    /* binary leaf*/
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, XP_TEST_MODULE_RAW, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_BINARY_T, value->type);
    assert_string_equal(XP_TEST_MODULE_RAW_VALUE, value->data.binary_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_RAW, value, &new_set);

    assert_string_equal(value->data.binary_val, new_set->data.binary_val);
    FREE_VARS(value, new_set);

    /*bits leaf*/

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, XP_TEST_MODULE_BITS, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_BITS_T, value->type);
    assert_string_equal(XP_TEST_MODULE_BITS_VALUE, value->data.bits_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_BITS, value, &new_set);
    assert_string_equal(value->data.bits_val, new_set->data.bits_val);
    FREE_VARS(value, new_set);

    /* bool leaf */
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, XP_TEST_MODULE_BOOL, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_BOOL_T, value->type);
    assert_int_equal(XP_TEST_MODULE_BOOL_VALUE_T, value->data.bool_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_BOOL, value, &new_set);
    assert_int_equal(value->data.bool_val, new_set->data.bool_val);
    FREE_VARS(value, new_set);

    /* decimal 64 leaf*/
#define ABS(x) ((x) < 0 ? (-(x)) : (x))
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, XP_TEST_MODULE_DEC64, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_DECIMAL64_T, value->type);
    assert_true(ABS(XP_TEST_MODULE_DEC64_VALUE_T - value->data.decimal64_val) < 0.001);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_DEC64, value, &new_set);

    assert_int_equal(value->data.decimal64_val, new_set->data.decimal64_val);

    FREE_VARS(value, new_set);

    /* decimal 64 defined inside union */
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, XP_TEST_MODULE_DEC64_IN_UNION, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_DECIMAL64_T, value->type);
    assert_true(ABS(value->data.decimal64_val - XP_TEST_MODULE_DEC64_IN_UNION_VALUE_T) < 0.001);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_DEC64_IN_UNION, value, &new_set);

    assert_int_equal(value->data.decimal64_val, new_set->data.decimal64_val);

    FREE_VARS(value, new_set);

    /* enum leaf*/
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, XP_TEST_MODULE_ENUM, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_ENUM_T, value->type);
    assert_string_equal(XP_TEST_MODULE_ENUM_VALUE, value->data.enum_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_ENUM, value, &new_set);

    assert_string_equal(value->data.enum_val, new_set->data.enum_val);

    FREE_VARS(value, new_set);

    /* empty */
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, XP_TEST_MODULE_EMPTY, &value);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(SR_LEAF_EMPTY_T, value->type);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_EMPTY, value, &new_set);

    FREE_VARS(value, new_set);

    /* identity ref*/
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, XP_TEST_MODULE_IDREF, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_IDENTITYREF_T, value->type);
    assert_string_equal(XP_TEST_MODULE_IDREF_VALUE, value->data.identityref_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_IDREF, value, &new_set);
    assert_string_equal(value->data.identityref_val, new_set->data.identityref_val);
    FREE_VARS(value, new_set);

    /* int8*/
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, XP_TEST_MODULE_INT8, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_INT8_T, value->type);
    assert_int_equal(XP_TEST_MODULE_INT8_VALUE_T, value->data.int8_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_INT8, value, &new_set);
    assert_int_equal(value->data.int8_val, new_set->data.int8_val);
    FREE_VARS(value, new_set);

    /* int16*/
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, XP_TEST_MODULE_INT16, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_INT16_T, value->type);
    assert_int_equal(XP_TEST_MODULE_INT16_VALUE_T, value->data.int16_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_INT16, value, &new_set);
    assert_int_equal(value->data.int16_val, new_set->data.int16_val);
    FREE_VARS(value, new_set);

    /* int32*/
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, XP_TEST_MODULE_INT32, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_INT32_T, value->type);
    assert_int_equal(XP_TEST_MODULE_INT32_VALUE_T, value->data.int32_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_INT32, value, &new_set);
    assert_int_equal(value->data.int32_val, new_set->data.int32_val);
    FREE_VARS(value, new_set);

    /* int64*/
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, XP_TEST_MODULE_INT64, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_INT64_T, value->type);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T, value->data.int64_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_INT64, value, &new_set);
    assert_int_equal(value->data.int64_val, new_set->data.int64_val);
    FREE_VARS(value, new_set);

    /* string ref*/
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, XP_TEST_MODULE_STRING, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_STRING_T, value->type);
    assert_string_equal(XP_TEST_MODULE_STRING_VALUE, value->data.string_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_STRING, value, &new_set);
    assert_string_equal(value->data.string_val, new_set->data.string_val);
    FREE_VARS(value, new_set);

    /* uint8*/
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, XP_TEST_MODULE_UINT8, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_UINT8_T, value->type);
    assert_int_equal(XP_TEST_MODULE_UINT8_VALUE_T, value->data.uint8_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_UINT8, value, &new_set);
    assert_int_equal(value->data.uint8_val, new_set->data.uint8_val);
    FREE_VARS(value, new_set);

    /* uint16*/
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, XP_TEST_MODULE_UINT16, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_UINT16_T, value->type);
    assert_int_equal(XP_TEST_MODULE_UINT16_VALUE_T, value->data.uint16_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_UINT16, value, &new_set);
    assert_int_equal(value->data.uint16_val, new_set->data.uint16_val);
    FREE_VARS(value, new_set);

    /* uint32*/
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, XP_TEST_MODULE_UINT32, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_UINT32_T, value->type);
    assert_int_equal(XP_TEST_MODULE_UINT32_VALUE_T, value->data.uint32_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_UINT32, value, &new_set);
    assert_int_equal(value->data.uint32_val, new_set->data.uint32_val);
    FREE_VARS(value, new_set);

    /* uint64*/
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, XP_TEST_MODULE_UINT64, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_UINT64_T, value->type);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T, value->data.uint64_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_UINT64, value, &new_set);
    assert_int_equal(value->data.uint64_val, new_set->data.uint64_val);
    FREE_VARS(value, new_set);

    /* leafref */
#undef LEAFREF_XP
#define LEAFREF_XP "/test-module:university/classes/class[title='CCNA']/student[name='nameB']/age"
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, LEAFREF_XP, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_UINT8_T, value->type);
    assert_int_equal(17, value->data.uint8_val);

    delete_get_set_get(ctx, session, LEAFREF_XP, value, &new_set);
    assert_int_equal(value->data.uint8_val, new_set->data.uint8_val);
    FREE_VARS(value, new_set);

    /* anyxml ref*/
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, XP_TEST_MODULE_ANYXML, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_ANYXML_T, value->type);
    assert_non_null(strstr(value->data.anyxml_val, XP_TEST_MODULE_ANYXML_VALUE));

    delete_get_set_get(ctx, session, XP_TEST_MODULE_ANYXML, value, &new_set);
    assert_string_equal(value->data.anyxml_val, new_set->data.anyxml_val);
    FREE_VARS(value, new_set);

    /* anydata ref*/
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, XP_TEST_MODULE_ANYDATA, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_ANYDATA_T, value->type);
    assert_non_null(strstr(value->data.anydata_val, XP_TEST_MODULE_ANYDATA_VALUE));

    delete_get_set_get(ctx, session, XP_TEST_MODULE_ANYDATA, value, &new_set);
    assert_string_equal(value->data.anydata_val, new_set->data.anydata_val);
    FREE_VARS(value, new_set);

    /* instance identifier */
    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, XP_TEST_MODULE_INSTANCE_ID, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_INSTANCEID_T, value->type);
    assert_string_equal(XP_TEST_MODULE_INSTANCE_ID_VALUE, value->data.instanceid_val);

    delete_get_set_get(ctx, session, XP_TEST_MODULE_INSTANCE_ID, value, &new_set);
    assert_string_equal(value->data.instanceid_val, new_set->data.instanceid_val);
    FREE_VARS(value, new_set);
    test_rp_session_cleanup(ctx, session);
}

void edit_instance_id_test(void **state) {
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;
    sr_val_t *value = NULL;
    sr_val_t *new_val = NULL;
    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;
    dm_commit_context_t *c_ctx = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);
    /* leaf */
    value = calloc(1, sizeof(*value));
    assert_non_null(value);
    value->type = SR_INSTANCEID_T;
    value->data.instanceid_val = strdup("/test-module:main/test-module:string");
    assert_non_null(value->data.instanceid_val);

    rc = rp_dt_set_item_wrapper(ctx, session, "/test-module:main/instance_id", value, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_commit(ctx, session, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_refresh_session(ctx, session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, "/test-module:main/instance_id", &new_val);
    assert_int_equal(SR_ERR_OK, rc);

    assert_string_equal("/test-module:main/string", new_val->data.instanceid_val);
    sr_free_val(new_val);

    /* container */
    value = calloc(1, sizeof(*value));
    assert_non_null(value);
    value->type = SR_INSTANCEID_T;
    value->data.instanceid_val = strdup("/test-module:main");
    assert_non_null(value->data.instanceid_val);

    rc = rp_dt_set_item_wrapper(ctx, session, "/test-module:main/instance_id", value, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_commit(ctx, session, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_refresh_session(ctx, session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, "/test-module:main/instance_id", &new_val);
    assert_int_equal(SR_ERR_OK, rc);

    assert_string_equal("/test-module:main", new_val->data.instanceid_val);
    sr_free_val(new_val);

    /* list */
    value = calloc(1, sizeof(*value));
    assert_non_null(value);
    value->type = SR_INSTANCEID_T;
    value->data.instanceid_val = strdup("/test-module:list[test-module:key='k1']");
    assert_non_null(value->data.instanceid_val);

    rc = rp_dt_set_item_wrapper(ctx, session, "/test-module:main/instance_id", value, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_commit(ctx, session, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_refresh_session(ctx, session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, "/test-module:main/instance_id", &new_val);
    assert_int_equal(SR_ERR_OK, rc);

    assert_string_equal("/test-module:list[key='k1']", new_val->data.instanceid_val);
    sr_free_val(new_val);

    /* leaf-list */
    value = calloc(1, sizeof(*value));
    assert_non_null(value);
    value->type = SR_INSTANCEID_T;
    value->data.instanceid_val = strdup("/test-module:main/numbers[.='42']");
    assert_non_null(value->data.instanceid_val);

    rc = rp_dt_set_item_wrapper(ctx, session, "/test-module:main/instance_id", value, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_commit(ctx, session, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_refresh_session(ctx, session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, session, NULL, "/test-module:main/instance_id", &new_val);
    assert_int_equal(SR_ERR_OK, rc);

    assert_string_equal("/test-module:main/numbers[.='42']", new_val->data.instanceid_val);
    sr_free_val(new_val);

    //TODO: node outside of the module

    test_rp_session_cleanup(ctx, session);
}

void delete_negative_test(void **state){
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    /* invalid xpath*/
    rc = rp_dt_delete_item_wrapper(ctx, session, "^usfd&", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/example-module:unknown", SR_EDIT_DEFAULT);
    /* validation of the xpath produces only warning */
    assert_int_equal(SR_ERR_OK, rc);

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
    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    sr_val_t iftype;
    iftype._sr_mem = NULL;
    iftype.xpath = NULL;
    iftype.type = SR_ENUM_T;
    iftype.data.enum_val = strdup ("ethernet");

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:interface/ifType", SR_EDIT_DEFAULT, &iftype, NULL, false);
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

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:interface/ifMTU", SR_EDIT_DEFAULT, &mtu, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    errors = NULL;
    e_cnt = 0;

    rc = dm_validate_session_data_trees(ctx->dm_ctx, session->dm_session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);
    sr_free_errors(errors, e_cnt);

    mtu.data.uint32_val = 1500;
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:interface/ifMTU", SR_EDIT_DEFAULT, &mtu, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    errors = NULL;
    e_cnt = 0;

    rc = dm_validate_session_data_trees(ctx->dm_ctx, session->dm_session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_errors(errors, e_cnt);

    test_rp_session_cleanup(ctx, session);

    /* regexp */
    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    sr_val_t hexnumber;
    hexnumber._sr_mem = NULL;
    hexnumber.xpath = NULL;
    hexnumber.type = SR_STRING_T;
    hexnumber.data.string_val = strdup("92FF");
    assert_non_null(hexnumber.data.string_val);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:hexnumber", SR_EDIT_DEFAULT, &hexnumber, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    errors = NULL;
    e_cnt = 0;

    rc = dm_validate_session_data_trees(ctx->dm_ctx, session->dm_session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_errors(errors, e_cnt);

    free(hexnumber.data.string_val);
    hexnumber.data.string_val = strdup("AAZZ");

    /* Regular expression mismatch causes SR_ERR_INVAL_ARG */
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:hexnumber", SR_EDIT_DEFAULT, &hexnumber, NULL, false);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    sr_free_val_content(&hexnumber);

    test_rp_session_cleanup(ctx, session);

    /* mandatory leaf */
    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    sr_val_t name;
    name._sr_mem = NULL;
    name.xpath = NULL;
    name.type = SR_STRING_T;
    name.data.string_val = strdup("Name");
    assert_non_null(name.data.string_val);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:location/name", SR_EDIT_DEFAULT, &name, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    errors = NULL;
    e_cnt = 0;

    rc = dm_validate_session_data_trees(ctx->dm_ctx, session->dm_session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);
    sr_free_errors(errors, e_cnt);

    sr_val_t lonigitude;
    lonigitude._sr_mem = NULL;
    lonigitude.xpath = NULL;
    lonigitude.type = SR_STRING_T;
    lonigitude.data.string_val = strdup("Longitude 49.45");
    assert_non_null(lonigitude.data.string_val);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:location/longitude", SR_EDIT_DEFAULT, &lonigitude, NULL, false);
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
    latitude._sr_mem = NULL;
    latitude.xpath = NULL;
    latitude.type = SR_STRING_T;
    latitude.data.string_val = strdup("Latitude 56.46");
    assert_non_null(latitude.data.string_val);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:location/latitude", SR_EDIT_DEFAULT, &latitude, NULL, false);
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
    test_rp_session_create(ctx, SR_DS_STARTUP, &session);
    sr_val_t interval;
    interval.xpath = NULL;
    interval.type = SR_UINT16_T;
    interval.data.uint16_val = 9;

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:transfer/interval", SR_EDIT_DEFAULT, &interval, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    errors = NULL;
    e_cnt = 0;

    rc = dm_validate_session_data_trees(ctx->dm_ctx, session->dm_session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_errors(errors, e_cnt);

    sr_val_t daily;
    daily.xpath = NULL;
    daily.type = SR_LEAF_EMPTY_T;

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:transfer/daily", SR_EDIT_DEFAULT, &daily, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    errors = NULL;
    e_cnt = 0;

    /* Validation should pass because libyang automatically overwrites nodes from different choice alternative */
    rc = dm_validate_session_data_trees(ctx->dm_ctx, session->dm_session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_errors(errors, e_cnt);

    test_rp_session_cleanup(ctx, session);

    /* leaf-list unique values */
    test_rp_session_create(ctx, SR_DS_STARTUP, &session);
    sr_val_t val;
    val._sr_mem = NULL;
    val.xpath = NULL;
    val.type = SR_UINT8_T;
    val.data.uint8_val = 9;

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:main/numbers", SR_EDIT_DEFAULT, &val, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:main/numbers", SR_EDIT_DEFAULT, &val, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:main/numbers", SR_EDIT_STRICT, &val, NULL, false);
    assert_int_equal(SR_ERR_DATA_EXISTS, rc);

    errors = NULL;
    e_cnt = 0;

    /* validation pass because lyd_new path doesn't add duplicate leaf-list */
    rc = dm_validate_session_data_trees(ctx->dm_ctx, session->dm_session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    test_rp_session_cleanup(ctx, session);

    /* leafref */
    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

#undef LEAFREF_XP
#define LEAFREF_XP "/test-module:university/classes/class[title='CCNA']/student[name='nameC']/age"

    sr_val_t age;
    age.type = SR_UINT8_T;
    age.data.uint8_val = 17; /* invalid reference */

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, LEAFREF_XP, SR_EDIT_DEFAULT, &age, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    errors = NULL;
    e_cnt = 0;

    rc = dm_validate_session_data_trees(ctx->dm_ctx, session->dm_session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);
    assert_int_equal(1, e_cnt);
    assert_string_equal("Leafref \"../../../../students/student[name = current()/../name]/age\" of value \"17\" "
                        "points to a non-existing leaf.", errors[0].message);
    assert_string_equal(LEAFREF_XP, errors[0].xpath);
    sr_free_errors(errors, e_cnt);

    age.data.uint8_val = 18; /* valid reference */

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, LEAFREF_XP, SR_EDIT_DEFAULT, &age, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    rc = dm_validate_session_data_trees(ctx->dm_ctx, session->dm_session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    test_rp_session_cleanup(ctx, session);

    /* leafref chain */
    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    sr_val_t link;
    link.type = SR_STRING_T;
    link.data.string_val = "final-leaf";

#define LEAFREF_CHAIN         "/test-module:leafref-chain/"
#define LEAFREF_CHAIN_LINK_A  LEAFREF_CHAIN "A"
#define LEAFREF_CHAIN_LINK_B  LEAFREF_CHAIN "B"

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, LEAFREF_CHAIN_LINK_A, SR_EDIT_DEFAULT, &link, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    errors = NULL;
    e_cnt = 0;

    /* missing link "B" */
    rc = dm_validate_session_data_trees(ctx->dm_ctx, session->dm_session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);
    assert_int_equal(1, e_cnt);
    assert_string_equal("Leafref \"../B\" of value \"final-leaf\" points to a non-existing leaf.", errors[0].message);
    assert_string_equal(LEAFREF_CHAIN_LINK_A, errors[0].xpath);
    sr_free_errors(errors, e_cnt);

    /* add missing link */
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, LEAFREF_CHAIN_LINK_B, SR_EDIT_DEFAULT, &link, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    rc = dm_validate_session_data_trees(ctx->dm_ctx, session->dm_session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    test_rp_session_cleanup(ctx, session);

    /* multiple errors */
#if 0
    test_rp_session_create(ctx, SR_DS_STARTUP, &session);
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

    rc = dm_validate_session_data_trees(ctx->dm_ctx, session->dm_session, NULL, &errors, &e_cnt);
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

    test_rp_session_create(ctx, SR_DS_STARTUP, &sessionA);
    test_rp_session_create(ctx, SR_DS_STARTUP, &sessionB);

    /* read value in session A*/
    rc = rp_dt_get_value_wrapper(ctx, sessionA, NULL, XP_TEST_MODULE_INT64, &valueA);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueA);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T, valueA->data.int64_val);

    /* read value in session B*/
    rc = rp_dt_get_value_wrapper(ctx, sessionB, NULL, XP_TEST_MODULE_INT64, &valueB);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueB);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T, valueB->data.int64_val);
    sr_free_val(valueB);

    /* update value in session A*/
    valueA->data.int64_val = XP_TEST_MODULE_INT64_VALUE_T + 42;
    rc = rp_dt_set_item(ctx->dm_ctx, sessionA->dm_session, XP_TEST_MODULE_INT64, SR_EDIT_DEFAULT, valueA, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_val(valueA);

    /* check update in session A*/
    sessionA->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, sessionA, NULL, XP_TEST_MODULE_INT64, &valueA);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueA);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T + 42, valueA->data.int64_val);
    sr_free_val(valueA);

    /* update in sessionA should not affect value in session B*/
    sessionB->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, sessionB, NULL, XP_TEST_MODULE_INT64, &valueB);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueB);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T, valueB->data.int64_val);
    sr_free_val(valueB);

    rc = dm_discard_changes(ctx->dm_ctx, sessionA->dm_session, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    sessionA->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, sessionA, NULL, XP_TEST_MODULE_INT64, &valueA);
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
    dm_commit_context_t *c_ctx = NULL;
    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    /* no session copy made*/
    sr_error_info_t *errors = NULL;
    size_t err_cnt = 0;
    rc = rp_dt_commit(ctx, session, &c_ctx, false, &errors, &err_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_errors(errors, err_cnt);

    /* not modified session copy */
    rc = dm_get_data_info(ctx->dm_ctx, session->dm_session, "test-module", &info);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_commit(ctx, session, &c_ctx, false, &errors, &err_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_errors(errors, err_cnt);

    rc = dm_get_data_info(ctx->dm_ctx, session->dm_session, "test-module", &info);
    assert_int_equal(SR_ERR_OK, rc);
    info->modified = true;

    rc = rp_dt_commit(ctx, session, &c_ctx, false, &errors, &err_cnt);
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
    dm_commit_context_t *c_ctx = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &sessionA);
    test_rp_session_create(ctx, SR_DS_STARTUP, &sessionB);

    /* read value in session A*/
    rc = rp_dt_get_value_wrapper(ctx, sessionA, NULL, XP_TEST_MODULE_INT64, &valueA);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueA);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T, valueA->data.int64_val);

    /* read value in session B*/
    rc = rp_dt_get_value_wrapper(ctx, sessionB, NULL, XP_TEST_MODULE_INT64, &valueB);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueB);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T, valueB->data.int64_val);
    sr_free_val(valueB);

    /* update value in session A*/
    valueA->data.int64_val = XP_TEST_MODULE_INT64_VALUE_T + 99;
    rc = rp_dt_set_item_wrapper(ctx, sessionA, XP_TEST_MODULE_INT64, valueA, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    /* check update in session A*/
    sessionA->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, sessionA, NULL, XP_TEST_MODULE_INT64, &valueA);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueA);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T + 99, valueA->data.int64_val);
    sr_free_val(valueA);

    /* update in sessionA should not affect value in session B*/
    sessionB->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, sessionB, NULL, XP_TEST_MODULE_INT64, &valueB);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueB);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T, valueB->data.int64_val);
    sr_free_val(valueB);


    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;

    rc = rp_dt_commit(ctx, sessionA, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_errors(errors, e_cnt);

    sessionA->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, sessionA, NULL, XP_TEST_MODULE_INT64, &valueA);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueA);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T + 99, valueA->data.int64_val);
    sr_free_val(valueA);

    /* refresh the session B to see changes made by commit */
    rc = rp_dt_refresh_session(ctx, sessionB, &errors, &e_cnt);
    assert_int_equal(rc, SR_ERR_OK);

    sessionB->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, sessionB, NULL, XP_TEST_MODULE_INT64, &valueB);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueB);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T + 99, valueB->data.int64_val);
    sr_free_val(valueB);

    test_rp_session_cleanup(ctx, sessionA);
    test_rp_session_cleanup(ctx, sessionB);

     /* check that update is permanent in new session*/
    test_rp_session_create(ctx, SR_DS_STARTUP, &sessionA);
    rc = rp_dt_get_value_wrapper(ctx, sessionA, NULL, XP_TEST_MODULE_INT64, &valueA);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valueA);
    assert_int_equal(XP_TEST_MODULE_INT64_VALUE_T + 99, valueA->data.int64_val);

    valueA->data.int64_val = XP_TEST_MODULE_INT64_VALUE_T;

    rc = rp_dt_set_item_wrapper(ctx, sessionA, XP_TEST_MODULE_INT64, valueA, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_commit(ctx, sessionA, &c_ctx, false, &errors, &e_cnt);
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
    dm_commit_context_t *c_ctx = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);
    test_rp_session_create(ctx, SR_DS_STARTUP, &sessionB);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/test-module:main", SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_delete_item_wrapper(ctx, sessionB, "/test-module:main", SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_OK, rc);

    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;
    rc = rp_dt_commit(ctx, session, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    /*this commit should failed because main container is already deleted */
    rc = rp_dt_commit(ctx, sessionB, &c_ctx, false, &errors, &e_cnt);
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
    dm_commit_context_t *c_ctx = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);
    test_rp_session_create(ctx, SR_DS_STARTUP, &sessionB);

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

    rc = rp_dt_set_item_wrapper(ctx, session, "/test-module:main/numbers", v1, NULL, SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_set_item_wrapper(ctx, sessionB, "/test-module:main/numbers", v2, NULL, SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_OK, rc);

    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;

    rc = rp_dt_commit(ctx, session, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    /* the leaf-list value was committed during the first commit */
    rc = rp_dt_commit(ctx, sessionB, &c_ctx, false, &errors, &e_cnt);
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
    dm_commit_context_t *c_ctx = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    sr_val_t *v = NULL;
    v = calloc(1, sizeof(*v));
    assert_non_null(v);

    v->type = SR_ENUM_T;
    v->data.enum_val = strdup("yes");
    assert_non_null(v->data.enum_val);

    rc = rp_dt_set_item_wrapper(ctx, session, "/test-module:main/enum", v, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;
    rc = rp_dt_commit(ctx, session, &c_ctx, false, &errors, &e_cnt);
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

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

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
    rc = rp_dt_get_values_wrapper(ctx, session, NULL, "/test-module:user", &values, &cnt);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:user[name='nameA']", SR_EDIT_DEFAULT, NULL, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:user[name='nameA']", SR_MOVE_FIRST, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:user[name='nameA']", SR_MOVE_LAST, NULL);
    assert_int_equal(SR_ERR_OK, rc);


    /* multiple instances */

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:user[name='nameB']", SR_EDIT_DEFAULT, NULL, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:user[name='nameC']", SR_EDIT_DEFAULT, NULL, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_values_wrapper(ctx, session, NULL, "/test-module:user", &values, &cnt);
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

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_values_wrapper(ctx, session, NULL, "/test-module:user", &values, &cnt);
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

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    /* empty the data tree*/
    rc = rp_dt_delete_item_wrapper(ctx, session, "/test-module:main", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/test-module:list", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/test-module:kernel-modules", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_values_wrapper(ctx, session, NULL, "/test-module:user", &values, &cnt);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* only one list instance in data tree */
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:user[name='nameA']", SR_EDIT_DEFAULT, NULL, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:user[name='nameA']", SR_MOVE_FIRST, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:user[name='nameA']", SR_MOVE_LAST, NULL);
    assert_int_equal(SR_ERR_OK, rc);


    /* multiple instances */

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:user[name='nameB']", SR_EDIT_DEFAULT, NULL, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:user[name='nameC']", SR_EDIT_DEFAULT, NULL, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_values_wrapper(ctx, session, NULL, "/test-module:user", &values, &cnt);
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

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_values_wrapper(ctx, session, NULL, "/test-module:user", &values, &cnt);
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

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_values_wrapper(ctx, session, NULL, "/test-module:user", &values, &cnt);
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

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    /* empty the data tree*/
    rc = rp_dt_delete_item_wrapper(ctx, session, "/test-module:main", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/test-module:list", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/test-module:kernel-modules", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_values_wrapper(ctx, session, NULL, "/test-module:user", &values, &cnt);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* add some ordered leaf-list entries */
    sr_val_t *v = NULL;
    v = calloc(1, sizeof(*v));
    assert_non_null(v);
    v->type = SR_UINT8_T;
    v->xpath = strdup("/test-module:ordered-numbers");
    v->data.uint8_val = 1;

    rc = rp_dt_set_item_wrapper(ctx, session, v->xpath, v, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    v = calloc(1, sizeof(*v));
    assert_non_null(v);
    v->type = SR_UINT8_T;
    v->xpath = strdup("/test-module:ordered-numbers");
    v->data.uint8_val = 2;
    rc = rp_dt_set_item_wrapper(ctx, session, v->xpath, v, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    v = calloc(1, sizeof(*v));
    assert_non_null(v);
    v->type = SR_UINT8_T;
    v->xpath = strdup("/test-module:ordered-numbers");
    v->data.uint8_val = 9;
    rc = rp_dt_set_item_wrapper(ctx, session, v->xpath, v, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_values_wrapper(ctx, session, NULL, "/test-module:ordered-numbers", &values, &cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(7, cnt);

    assert_int_equal(0, values[0].data.uint8_val);
    assert_int_equal(57, values[1].data.uint8_val);
    assert_int_equal(12, values[2].data.uint8_val);
    assert_int_equal(45, values[3].data.uint8_val);
    assert_int_equal(1, values[4].data.uint8_val);
    assert_int_equal(2, values[5].data.uint8_val);
    assert_int_equal(9, values[6].data.uint8_val);

    sr_free_values(values, cnt);

    rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:ordered-numbers[.='9']", SR_MOVE_FIRST, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    session->state = RP_REQ_NEW;
    rc = rp_dt_get_values_wrapper(ctx, session, NULL, "/test-module:ordered-numbers", &values, &cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(7, cnt);

    assert_int_equal(9, values[0].data.uint8_val);
    assert_int_equal(0, values[1].data.uint8_val);
    assert_int_equal(57, values[2].data.uint8_val);
    assert_int_equal(12, values[3].data.uint8_val);
    assert_int_equal(45, values[4].data.uint8_val);
    assert_int_equal(1, values[5].data.uint8_val);
    assert_int_equal(2, values[6].data.uint8_val);

    sr_free_values(values, cnt);

    /* move with different node */
    rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:user[name='nameA']", SR_EDIT_DEFAULT, NULL, NULL, false);
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

   test_rp_session_create(ctx, SR_DS_STARTUP, &session);

   assert_int_equal(0, session->dm_session->oper_count[session->datastore]);

   /* set */

   /* type mismatch unsuccessful not logged*/
   sr_val_t *value = NULL;
   value = calloc(1, sizeof(*value));
   assert_non_null(value);
   value->data.string_val = strdup("abc");
   value->type = SR_STRING_T;
   rc = rp_dt_set_item_wrapper(ctx, session, "/test-module:main/i8", value, NULL, SR_EDIT_DEFAULT);
   assert_int_equal(SR_ERR_INVAL_ARG, rc);
   assert_int_equal(0, session->dm_session->oper_count[session->datastore]);


   rc = rp_dt_set_item_wrapper(ctx, session, "/test-module:user[name='nameC']", NULL, NULL, SR_EDIT_DEFAULT);
   assert_int_equal(SR_ERR_OK, rc);
   assert_int_equal(1, session->dm_session->oper_count[session->datastore]);
   assert_int_equal(DM_SET_OP, session->dm_session->operations[session->datastore][session->dm_session->oper_count[session->datastore]-1].op);

   rc = rp_dt_set_item_wrapper(ctx, session, "/test-module:user[name='nameX']", NULL, NULL, SR_EDIT_DEFAULT);
   assert_int_equal(SR_ERR_OK, rc);
   assert_int_equal(2, session->dm_session->oper_count[session->datastore]);

   /* move */
   rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:user[name='nameX']", SR_MOVE_LAST, NULL);
   assert_int_equal(SR_ERR_OK, rc);
   assert_int_equal(3, session->dm_session->oper_count[session->datastore]);
   assert_int_equal(DM_MOVE_OP, session->dm_session->operations[session->datastore][session->dm_session->oper_count[session->datastore]-1].op);

   rc = rp_dt_move_list_wrapper(ctx, session, "/test-module:!^", SR_MOVE_BEFORE, "/test-module:user[name='nameC']");
   assert_int_equal(SR_ERR_INVAL_ARG, rc);
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
   dm_commit_context_t *c_ctx = NULL;

   test_rp_session_create(ctx, SR_DS_STARTUP, &sessionA);
   test_rp_session_create(ctx, SR_DS_STARTUP, &sessionB);

   /* lock example module in A*/
   rc = dm_lock_module(ctx->dm_ctx, sessionA->dm_session, "test-module");
   assert_int_equal(SR_ERR_OK, rc);

   /* do some changes in A */
   rc = rp_dt_set_item_wrapper(ctx, sessionA, "/example-module:container/list[key1='key1'][key2='key2']", NULL, NULL, SR_EDIT_DEFAULT);
   assert_int_equal(SR_ERR_OK, rc);

   rc = rp_dt_delete_item_wrapper(ctx, sessionA, "/test-module:list", SR_EDIT_DEFAULT);
   assert_int_equal(SR_ERR_OK, rc);

   /* lock something in B */
   rc = dm_lock_module(ctx->dm_ctx, sessionB->dm_session, "example-module");
   assert_int_equal(SR_ERR_OK, rc);

   /* commit A should fail */
   size_t e_cnt = 0;
   sr_error_info_t *errors = NULL;
   rc = rp_dt_commit(ctx, sessionA, &c_ctx, false, &errors, &e_cnt);
   assert_int_equal(SR_ERR_LOCKED, rc);

   /* unlock B */
   rc = dm_unlock_module(ctx->dm_ctx, sessionB->dm_session, "example-module");
   assert_int_equal(SR_ERR_OK, rc);

   /* commit A should succeed */
   rc = rp_dt_commit(ctx, sessionA, &c_ctx, false, &errors, &e_cnt);
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
   dm_commit_context_t *c_ctx = NULL;

   test_rp_session_create(ctx, SR_DS_STARTUP, &sessionA);
   test_rp_session_create(ctx, SR_DS_STARTUP, &sessionB);

   sr_val_t *v = NULL;
   v = calloc(1, sizeof(*v));
   assert_non_null(v);
   v->type = SR_STRING_T;

   rc = rp_dt_set_item_wrapper(ctx, sessionA, "/test-module:main/string", v, NULL, SR_EDIT_DEFAULT);
   assert_int_equal(SR_ERR_OK, rc);

   size_t e_cnt = 0;
   sr_error_info_t *errors = NULL;
   rc = rp_dt_commit(ctx, sessionA, &c_ctx, false, &errors, &e_cnt);
   assert_int_equal(SR_ERR_OK, rc);

   sr_val_t *retrieved = NULL;
   rc = rp_dt_get_value_wrapper(ctx, sessionB, NULL, "/test-module:main/string", &retrieved);
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
    rp_session_t *sessionA = NULL;
    sr_val_t *value = NULL;
    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;

    test_rp_session_create(ctx, SR_DS_CANDIDATE, &sessionA);

    sr_val_t iftype = {0};
    iftype.xpath = NULL;
    iftype.type = SR_ENUM_T;
    iftype.data.enum_val = strdup ("ethernet");

    rc = rp_dt_set_item(ctx->dm_ctx, sessionA->dm_session, "/test-module:interface/ifType", SR_EDIT_DEFAULT, &iftype, NULL, false);
    assert_int_equal(SR_ERR_OK, rc);

    sr_free_val_content(&iftype);

    /* modified module in cadidate is validated before copy */
    rc = dm_validate_session_data_trees(ctx->dm_ctx, sessionA->dm_session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);
    sr_free_errors(errors, e_cnt);
    errors = NULL;
    e_cnt = 0;

    rc = dm_discard_changes(ctx->dm_ctx, sessionA->dm_session, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    sr_val_t *v = NULL;
    v = calloc(1, sizeof(*v));
    assert_non_null(v);

    v->xpath = strdup("/test-module:main/i8");
    v->type = SR_INT8_T;
    v->data.int8_val = 42;

    rc = rp_dt_get_value_wrapper(ctx, sessionA, NULL, "/test-module:main/i8", &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    rc = rp_dt_set_item_wrapper(ctx, sessionA, v->xpath, v, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    /* refresh candidate session */
    rc = rp_dt_refresh_session(ctx, sessionA, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    sessionA->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, sessionA, NULL, "/test-module:main/i8", &value);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(SR_INT8_T, value->type);
    assert_int_equal(v->data.int8_val, value->data.int8_val);
    sr_free_val(value);

    test_rp_session_cleanup(ctx, sessionA);
}

static void
copy_to_running_test(void **state)
{
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *sessionA = NULL, *sessionB = NULL;
    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;

    test_rp_session_create(ctx, SR_DS_CANDIDATE, &sessionA);
    test_rp_session_create(ctx, SR_DS_STARTUP, &sessionB);

    /* only enabled modules are copied, no module is enabled => no operation */
    rc = rp_dt_copy_config(ctx, sessionB, NULL, SR_DS_STARTUP, SR_DS_RUNNING, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    /* explictly select a module which is not enabled copy fails*/
    rc = rp_dt_copy_config(ctx, sessionB, "test-module", SR_DS_STARTUP, SR_DS_RUNNING, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OPERATION_FAILED, rc);
    sr_free_errors(errors, e_cnt);
    errors = NULL;
    e_cnt = 0;

    /* only enabled modules are copied, no module is enabled => no operation */
    rc = rp_dt_copy_config(ctx, sessionA, NULL, SR_DS_CANDIDATE, SR_DS_RUNNING, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    /* copy of not enabled module to running should fail */
    rc = rp_dt_copy_config(ctx, sessionA, "test-module", SR_DS_CANDIDATE, SR_DS_RUNNING, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OPERATION_FAILED, rc);
    sr_free_errors(errors, e_cnt);

    test_rp_session_cleanup(ctx, sessionA);
    test_rp_session_cleanup(ctx, sessionB);
}

static void
add_delete_list_row_with_nacm_test(void **state)
{
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *sessionA = NULL;
    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;
    test_nacm_cfg_t *nacm_config = NULL;

    new_nacm_config(&nacm_config);
    enable_nacm_config(nacm_config, true);
    add_nacm_user(nacm_config, "user1", "group1");
    add_nacm_rule_list(nacm_config, "acl1", "group1", NULL);
    add_nacm_rule(nacm_config, "acl1", "allow-segfault", "commit-nacm", NACM_RULE_DATA, "/commit-nacm:test-list[test-key='test-key']", "*", "permit", NULL);
    assert_non_null(ly_ctx_load_module(nacm_config->ly_ctx, "commit-nacm", NULL));
    save_nacm_config(nacm_config);

    test_rp_session_create_with_options(ctx, SR_DS_RUNNING, SR_SESS_ENABLE_NACM, &sessionA);

    rc = dm_enable_module_running(ctx->dm_ctx, sessionA->dm_session, "commit-nacm", NULL);

    assert_int_equal(SR_ERR_OK, rc);

    sr_val_t *value = NULL;
    value = calloc(1, sizeof(*value));
    assert_non_null(value);
    value->xpath = strdup("/commit-nacm:test-list[test-key='test-key']");
    value->type = SR_LIST_T;
    assert_non_null(value->xpath);

    // Create row
    rc = rp_dt_set_item_wrapper(ctx, sessionA, value->xpath, value, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);
    value = NULL;

    // Commit
    dm_commit_context_t *c_ctx = NULL;
    rc = rp_dt_commit(ctx, sessionA, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    // Delete row
    rc = rp_dt_delete_item_wrapper(ctx, sessionA, "/commit-nacm:test-list[test-key='test-key']", SR_EDIT_DEFAULT);
    rc = rp_dt_commit(ctx, sessionA, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    test_rp_session_cleanup(ctx, sessionA);
    delete_nacm_config(nacm_config);
}

static void
candidate_copy_config_lock_test(void **state)
{
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *sessionA = NULL, *sessionB = NULL;
    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;
    sr_val_t *value = NULL;
    dm_commit_context_t *c_ctx = NULL;

    test_rp_session_create(ctx, SR_DS_CANDIDATE, &sessionA);
    test_rp_session_create(ctx, SR_DS_RUNNING, &sessionB);

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

    rc = rp_dt_set_item_wrapper(ctx, sessionA, v->xpath, v, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    /* copy-config failed running locked */
    rc = rp_dt_commit(ctx, sessionA, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    rc = rp_dt_copy_config(ctx, sessionA, NULL, SR_DS_CANDIDATE, SR_DS_RUNNING, &errors, &e_cnt);
    assert_int_equal(SR_ERR_LOCKED, rc);
    sr_free_errors(errors, e_cnt);

    rc = dm_unlock_module(ctx->dm_ctx, sessionB->dm_session, "test-module");
    assert_int_equal(SR_ERR_OK, rc);

    /* already committed... */
    rc = rp_dt_commit(ctx, sessionA, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    rc = rp_dt_copy_config(ctx, sessionA, NULL, SR_DS_CANDIDATE, SR_DS_RUNNING, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_get_value_wrapper(ctx, sessionA, NULL, "/test-module:main/i8", &value);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(SR_INT8_T, value->type);
    assert_int_equal(42, value->data.int8_val);

    sr_free_val(value);

    test_rp_session_cleanup(ctx, sessionA);
    test_rp_session_cleanup(ctx, sessionB);
}


static void
edit_union_type(void **state)
{
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *sessionA = NULL;
    sr_val_t *val = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &sessionA);

    /* union - uint8 */
    rc = rp_dt_get_value_wrapper(ctx, sessionA, NULL, "/test-module:list[key='k1']/union", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_int_equal(SR_UINT8_T, val->type);
    assert_int_equal(42, val->data.uint8_val);
    assert_false(val->dflt);

    rc = rp_dt_delete_item_wrapper(ctx, sessionA, "/test-module:list[key='k1']/union", SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_set_item_wrapper(ctx, sessionA, val->xpath, val, NULL, SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_OK, rc);

    /* value is freed inside set operation*/
    val = NULL;

    /* union string*/
    sessionA->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, sessionA, NULL, "/test-module:list[key='k2']/union", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_int_equal(SR_ENUM_T, val->type);
    assert_string_equal("infinity", val->data.string_val);
    assert_false(val->dflt);

    rc = rp_dt_delete_item_wrapper(ctx, sessionA, "/test-module:list[key='k2']/union", SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_set_item_wrapper(ctx, sessionA, val->xpath, val, NULL, SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_OK, rc);

    /* value is freed inside set operation*/
    val = NULL;

    /* check that correctly set */
    sessionA->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, sessionA, NULL, "/test-module:list[key='k2']/union", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_int_equal(SR_ENUM_T, val->type);
    assert_string_equal("infinity", val->data.string_val);
    assert_false(val->dflt);
    sr_free_val(val);


    sessionA->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, sessionA, NULL, "/test-module:list[key='k1']/union", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_int_equal(SR_UINT8_T, val->type);
    assert_int_equal(42, val->data.uint8_val);
    assert_false(val->dflt);
    sr_free_val(val);

    test_rp_session_cleanup(ctx, sessionA);

}

static void
validaton_of_multiple_models(void **state)
{
    /* multiple models are validate the validation of the first fails and succeed for others
     * test verifies that an error is returned and it is not hidden by success of following models*/
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *sessionA = NULL;
    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;

    test_rp_session_create(ctx, SR_DS_STARTUP, &sessionA);

    rc = rp_dt_delete_item_wrapper(ctx, sessionA, "/ietf-interfaces:interfaces/interface[name='withoutType']", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    /* missing mandatory leaf*/
    rc = rp_dt_set_item_wrapper(ctx, sessionA, "/ietf-interfaces:interfaces/interface[name='withoutType']", NULL, NULL, SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_OK, rc);

    /* validation succeed for test-module*/
    rc = rp_dt_delete_item_wrapper(ctx, sessionA, "/test-module:main/i8", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = dm_validate_session_data_trees(ctx->dm_ctx, sessionA->dm_session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);

    sr_free_errors(errors, e_cnt);

    test_rp_session_cleanup(ctx, sessionA);

}

void set_and_get_item_id_ref(void **state){
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;
    dm_commit_context_t *c_ctx = NULL;
    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;
    sr_val_t *val = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/id-ref-base:main/id-ref-aug:augmented/id-ref", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    val = calloc(1, sizeof(*val));
    assert_non_null(val);
    val->type = SR_IDENTITYREF_T;
    val->data.identityref_val = strdup("id-def-extended:external-derived-id");
    assert_non_null(val->data.identityref_val);
    rc = rp_dt_set_item_wrapper(ctx, session, "/id-ref-base:main/id-ref-aug:augmented/id-ref", val, NULL, SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_commit(ctx, session, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(e_cnt, 0);
    assert_ptr_equal(errors, NULL);

    rc = rp_dt_get_value_wrapper(ctx, session, NULL, "/id-ref-base:main/id-ref-aug:augmented/id-ref-aug:id-ref", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_int_equal(SR_IDENTITYREF_T, val->type);
    assert_string_equal("id-def-extended:external-derived-id", val->data.identityref_val);
    sr_free_val(val);

    test_rp_session_cleanup(ctx, session);
}

void set_item_leafref_augment(void ** state) {
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;
    dm_commit_context_t *c_ctx = NULL;
    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;
    sr_val_t *val = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/augm_leafref_m1:augleafrefcontainer/augm_leafref_m1:name", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/augm_leafref_m2:item/augm_leafref_m1:augleaf", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    val = calloc(1, sizeof(*val));
    assert_non_null(val);
    val->type = SR_STRING_T;
    val->data.string_val = strdup("leafrefval");
    assert_non_null(val->data.string_val);
    rc = rp_dt_set_item_wrapper(ctx, session, "/augm_leafref_m1:augleafrefcontainer/augm_leafref_m1:name", val, NULL, SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_commit(ctx, session, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(e_cnt, 0);
    assert_ptr_equal(errors, NULL);

    val = calloc(1, sizeof(*val));
    assert_non_null(val);
    val->type = SR_STRING_T;
    val->data.string_val = strdup("leafrefval");
    assert_non_null(val->data.string_val);
    rc = rp_dt_set_item_wrapper(ctx, session, "/augm_leafref_m2:item/augm_leafref_m1:augleaf", val, NULL, SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_commit(ctx, session, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(e_cnt, 0);
    assert_ptr_equal(errors, NULL);

    test_rp_session_cleanup(ctx, session);
}

void ident_ref_in_installed_module(void ** state) {
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;
    dm_commit_context_t *c_ctx = NULL;
    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;
    sr_val_t *val = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/id-ref-main:main/id-ref-main:ident-ref", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    val = calloc(1, sizeof(*val));
    assert_non_null(val);
    val->type = SR_IDENTITYREF_T;
    val->data.identityref_val = strdup("id-ref-installed:id-ref-extended");
    assert_non_null(val->data.identityref_val);
    rc = rp_dt_set_item_wrapper(ctx, session, "/id-ref-main:main/id-ref-main:ident-ref", val, NULL, SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_commit(ctx, session, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(e_cnt, 0);
    assert_ptr_equal(errors, NULL);

    test_rp_session_cleanup(ctx, session);
}

void extended_ident_ref_in_installed_module(void ** state) {
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;
    dm_commit_context_t *c_ctx = NULL;
    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;
    sr_val_t *val = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    rc = rp_dt_delete_item_wrapper(ctx, session, "/id-ref-main:main/id-ref-main:ident-list", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    val = calloc(1, sizeof(*val));
    assert_non_null(val);
    val->type = SR_LIST_T;
    rc = rp_dt_set_item_wrapper(ctx, session, "/id-ref-main:main/id-ref-main:ident-list[ref1='id-ref-installed:id-ref-main-extended']", val, NULL, SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_commit(ctx, session, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(e_cnt, 0);
    assert_ptr_equal(errors, NULL);

    test_rp_session_cleanup(ctx, session);
}

int main(){

    sr_log_stderr(SR_LL_DBG);

    const struct CMUnitTest tests[] = {
            cmocka_unit_test(delete_item_leaf_test),
            cmocka_unit_test(delete_item_container_test),
            cmocka_unit_test(delete_item_list_test),
            cmocka_unit_test(delete_item_alllist_test),
            cmocka_unit_test(delete_item_leaflist_test),
            cmocka_unit_test(delete_item_leafref_test),
            cmocka_unit_test(delete_whole_module_test),
            cmocka_unit_test(delete_negative_test),
            cmocka_unit_test(set_item_leaf_test),
            cmocka_unit_test(set_item_leaflist_test),
            cmocka_unit_test(set_item_list_test),
            cmocka_unit_test(set_item_container_test),
            cmocka_unit_test(set_item_leafref_test),
            cmocka_unit_test(set_item_negative_test),
            cmocka_unit_test(edit_test_module_test),
            cmocka_unit_test(edit_instance_id_test),
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
            cmocka_unit_test(candidate_copy_config_lock_test),
            cmocka_unit_test(add_delete_list_row_with_nacm_test),
            cmocka_unit_test_setup(edit_union_type, createData),
            cmocka_unit_test_setup(validaton_of_multiple_models, createData),
            cmocka_unit_test(set_and_get_item_id_ref),
            cmocka_unit_test(set_item_leafref_augment),
            cmocka_unit_test(ident_ref_in_installed_module),
            cmocka_unit_test(extended_ident_ref_in_installed_module),
    };

    return cmocka_run_group_tests(tests, setup, teardown);
}
