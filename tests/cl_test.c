/**
 * @file cl_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Client Library unit tests.
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <pthread.h>

#include "sr_constants.h"
#include "sysrepo.h"
#include "client_library.h"

#include "sr_common.h"
#include "test_module_helper.h"

static int
logging_setup(void **state)
{
    sr_log_stderr(SR_LL_DBG);
    return 0;
}

static int
sysrepo_setup(void **state)
{
    createDataTreeTestModule();
    createDataTreeExampleModule();
    sr_conn_ctx_t *conn = NULL;
    int rc = SR_ERR_OK;

    logging_setup(state);

    /* connect to sysrepo */
    rc = sr_connect("cl_test", SR_CONN_DEFAULT, &conn);
    assert_int_equal(rc, SR_ERR_OK);

    *state = (void*)conn;
    return 0;
}

static int
sysrepo_teardown(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    /* disconnect from sysrepo */
    sr_disconnect(conn);

    return 0;
}

static void
cl_connection_test(void **state)
{
    sr_conn_ctx_t *conn1 = NULL, *conn2 = NULL;
    sr_session_ctx_t *sess1 = NULL, *sess2 = NULL, *sess_other1 = NULL, *sess_other2 = NULL;
    int rc = 0;

    /* connect to sysrepo - conn 1 */
    rc = sr_connect("cl_test", SR_CONN_DEFAULT, &conn1);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(conn1);

    /* connect to sysrepo - conn 2 */
    rc = sr_connect("cl_test", SR_CONN_DEFAULT, &conn2);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(conn2);

    /* start a new session in conn 1 */
    rc = sr_session_start(conn1, SR_DS_RUNNING, SR_SESS_DEFAULT, &sess1);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(sess1);

    /* start few new sessions in conn 2 */
    rc = sr_session_start(conn2, SR_DS_STARTUP, SR_SESS_DEFAULT, &sess_other1);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(sess_other1);
    rc = sr_session_start(conn2, SR_DS_STARTUP, SR_SESS_DEFAULT, &sess_other2);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(sess_other2);
    rc = sr_session_start(conn2, SR_DS_STARTUP, SR_SESS_DEFAULT, &sess2);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(sess2);
    rc = sr_session_start(conn2, SR_DS_STARTUP, SR_SESS_DEFAULT, &sess2);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(sess2);

    /* try session_data_refresh */
    rc = sr_session_refresh(sess1);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop the session 1 */
    rc = sr_session_stop(sess1);
    assert_int_equal(rc, SR_ERR_OK);

    /* not all sessions in conn2 stopped explicitly - should be released automatically by disconnect */
    rc = sr_session_stop(sess_other2);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_stop(sess_other1);
    assert_int_equal(rc, SR_ERR_OK);

    /* disconnect from sysrepo - conn 2 */
    sr_disconnect(conn2);

    /* disconnect from sysrepo - conn 1 */
    sr_disconnect(conn1);
}

static void
cl_list_schemas_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_schema_t *schemas = NULL;
    size_t schema_cnt = 0, i = 0, j = 0;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* list schemas request */
    rc = sr_list_schemas(session, &schemas, &schema_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_not_equal(schema_cnt, 0);
    assert_non_null(schemas);

    /* check and print the schemas */
    for (i = 0; i < schema_cnt; i++) {
        printf("\n\nSchema #%zu:\n%s\n%s\n%s\n", i,
                schemas[i].module_name,
                schemas[i].ns,
                schemas[i].prefix);
            printf("%s\n\t%s\n\t%s\n\n",
                    schemas[i].revision.revision,
                    schemas[i].revision.file_path_yang,
                    schemas[i].revision.file_path_yin);

        for (size_t s = 0; s < schemas[i].submodule_count; s++) {
            printf("\t%s\n", schemas[i].submodules[s].submodule_name);
               printf("\t%s\n\t\t%s\n\t\t%s\n\n",
                       schemas[i].submodules[s].revision.revision,
                       schemas[i].submodules[s].revision.file_path_yang,
                       schemas[i].submodules[s].revision.file_path_yin);

        }
        /* print enabled features */
        for (j = 0; j < schemas[i].enabled_feature_cnt; j++) {
            printf("\tEnabled feature: %s\n", schemas[i].enabled_features[j]);
        }
    }
    sr_free_schemas(schemas, schema_cnt);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_get_schema_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    char *schema_content = NULL;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* get schema for specified module, latest revision */
    rc = sr_get_schema(session, "module-b", NULL, NULL, SR_SCHEMA_YANG, &schema_content);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(schema_content);
    printf("%s\n", schema_content);
    free(schema_content);
    schema_content = NULL;

    /* get schema for specified module, latest revision */
    rc = sr_get_schema(session, "module-a", NULL, NULL, SR_SCHEMA_YANG, &schema_content);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(schema_content);
    printf("%s\n", schema_content);
    free(schema_content);
    schema_content = NULL;

    /* get schema for specified module, latest revision YIN format*/
    rc = sr_get_schema(session, "module-a", NULL, NULL, SR_SCHEMA_YIN, &schema_content);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(schema_content);
    printf("%s\n", schema_content);
    free(schema_content);
    schema_content = NULL;

    /* get schema for specified module and revision */
    rc = sr_get_schema(session, "module-a", "2016-02-02", NULL, SR_SCHEMA_YANG, &schema_content);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(schema_content);
    printf("%s\n", schema_content);
    free(schema_content);
    schema_content = NULL;

    /* get schema for specified submodule, latest revision */
    rc = sr_get_schema(session, "module-a",  NULL, "sub-a-one", SR_SCHEMA_YANG, &schema_content);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(schema_content);
    printf("%s\n", schema_content);
    free(schema_content);
    schema_content = NULL;


    /* get schema for specified submodule and revision */
    rc = sr_get_schema(session, "module-a", "2016-02-02", "sub-a-one", SR_SCHEMA_YANG, &schema_content);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(schema_content);
    printf("%.100s\n", schema_content);
    free(schema_content);
    schema_content = NULL;

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_get_item_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_val_t *value = NULL;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform a get-item request */

    /* illegal xpath */
    rc = sr_get_item(session, "^&((", &value);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);
    assert_null(value);

    /* unknown model */
    rc = sr_get_item(session, "/unknown-model:abc", &value);
    assert_int_equal(SR_ERR_UNKNOWN_MODEL, rc);
    assert_null(value);

    /* not existing data tree*/
    rc = sr_get_item(session, "/small-module:item", &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    assert_null(value);

    /* bad element in existing module returns SR_ERR_NOT_FOUND instead of SR_ERR_BAD_ELEMENT*/
    rc = sr_get_item(session, "/example-module:unknown/next", &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    assert_null(value);
#if 0
    /* xpath validation produces only warning on get-like calls */
    const sr_error_info_t *err = NULL;
    sr_get_last_error(session, &err);
    assert_non_null(err->xpath);
    assert_string_equal("/example-module:unknown/next", err->xpath);
#endif
    /* existing leaf */
    rc = sr_get_item(session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &value);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(value);
    assert_int_equal(SR_STRING_T, value->type);
    assert_string_equal("Leaf value", value->data.string_val);
    assert_string_equal("/example-module:container/list[key1='key1'][key2='key2']/leaf", value->xpath);
    sr_free_val(value);

    /* container */
    rc = sr_get_item(session, "/example-module:container", &value);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(value);
    assert_int_equal(SR_CONTAINER_T, value->type);
    assert_string_equal("/example-module:container", value->xpath);
    sr_free_val(value);

    /* list */
    rc = sr_get_item(session, "/example-module:container/list[key1='key1'][key2='key2']", &value);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(value);
    assert_int_equal(SR_LIST_T, value->type);
    assert_string_equal("/example-module:container/list[key1='key1'][key2='key2']", value->xpath);
    sr_free_val(value);

    /* leafref (transparent for user) */
    rc = sr_get_item(session, "/test-module:university/classes/class[title='CCNA']/student[name='nameB']/age", &value);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(value);
    assert_int_equal(SR_UINT8_T, value->type);
    assert_string_equal("/test-module:university/classes/class[title='CCNA']/student[name='nameB']/age", value->xpath);
    assert_int_equal(17, value->data.uint8_val);
    sr_free_val(value);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_get_items_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    createDataTreeIETFinterfacesModule();
    sr_session_ctx_t *session = NULL;
    sr_val_t *values = NULL;
    size_t values_cnt = 0;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(session);

    /* perform a get-items request */

    /* illegal xpath */
    rc = sr_get_items(session, "^&((",  &values, &values_cnt);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* unknown model */
    rc = sr_get_items(session, "/unknown-model:abc",  &values, &values_cnt);
    assert_int_equal(SR_ERR_UNKNOWN_MODEL, rc);

    /* not existing data tree*/
    rc = sr_get_items(session, "/small-module:item",  &values, &values_cnt);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* bad element in existing module produces SR_ERR_NOT_FOUND instead of SR_ERR_BAD_ELEMENT */
    rc = sr_get_items(session, "/example-module:unknown", &values, &values_cnt);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* container */
    rc = sr_get_items(session, "/ietf-interfaces:interfaces/*", &values, &values_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(3, values_cnt);
    sr_free_values(values, values_cnt);

    /* list without keys */
    rc = sr_get_items(session, "/ietf-interfaces:interfaces/interface", &values, &values_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(3, values_cnt);
    sr_free_values(values, values_cnt);

    /* list with keys */
    rc = sr_get_items(session, "/ietf-interfaces:interfaces/interface[name='eth0']/*", &values, &values_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(5, values_cnt);
    sr_free_values(values, values_cnt);

    /* leaf-list*/
    rc = sr_get_items(session, "/test-module:main/numbers", &values, &values_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(3, values_cnt);
    sr_free_values(values, values_cnt);

    /* leafrefs */
    rc = sr_get_items(session, "/test-module:university/classes/class[title='CCNA']/student[name='nameB']/*", &values, &values_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(2, values_cnt);
    sr_free_values(values, values_cnt);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_get_items_iter_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_val_t *value = NULL;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(session);

    /* perform a get-items_iter request */
    sr_val_iter_t *it = NULL;

    /* illegal xpath */
    rc = sr_get_items_iter(session, "^&((", &it);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);
    assert_null(it);

    /* non existing item*/
    rc = sr_get_items_iter(session, "/small-module:item", &it);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(it);

    rc = sr_get_item_next(session, it, &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    assert_null(value);
    sr_free_val_iter(it);
    it = NULL;

    /* container */
    rc = sr_get_items_iter(session, "/example-module:container/*", &it);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(it);
    for (int i = 0; i < 6; i++) {
        rc = sr_get_item_next(session, it, &value);
        if (SR_ERR_NOT_FOUND == rc ){
            break;
        }
        assert_int_equal(SR_ERR_OK, rc);
        puts(value->xpath);
        sr_free_val(value);
    }
    sr_free_val_iter(it);

    /* list */
    rc = sr_get_items_iter(session, "/test-module:list[key='k1']/*", &it);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(it);
    while(SR_ERR_OK == sr_get_item_next(session, it, &value)) {
        puts(value->xpath);
        sr_free_val(value);
    }
    sr_free_val_iter(it);

    rc = sr_get_items_iter(session, "/test-module:list", &it);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(it);
    while(SR_ERR_OK == sr_get_item_next(session, it, &value)) {
        puts(value->xpath);
        sr_free_val(value);
    }
    sr_free_val_iter(it);

    /* leaf-list*/
    rc = sr_get_items_iter(session, "/test-module:main/numbers", &it);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(it);
    while(SR_ERR_OK == sr_get_item_next(session, it, &value)) {
        assert_string_equal("/test-module:main/numbers", value->xpath);
        sr_free_val(value);
    }
    sr_free_val_iter(it);

    /* all supported data types*/
    rc = sr_get_items_iter(session, "/test-module:main//*", &it);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(it);
    while(SR_ERR_OK == sr_get_item_next(session, it, &value)) {
        puts(value->xpath);
        if (0 == strcmp("/test-module:main/numbers", value->xpath)){
            assert_int_equal(SR_UINT8_T, value->type);
        }
        else if (0 == strcmp(XP_TEST_MODULE_EMPTY,value->xpath)){
            assert_int_equal(SR_LEAF_EMPTY_T, value->type);
        }
        else if (0 == strcmp(XP_TEST_MODULE_UINT64, value->xpath)){
            assert_int_equal(SR_UINT64_T, value->type);
            assert_int_equal(XP_TEST_MODULE_UINT64_VALUE_T, value->data.uint64_val);
        }
        else if (0 == strcmp(XP_TEST_MODULE_UINT32, value->xpath)){
            assert_int_equal(SR_UINT32_T, value->type);
        }
        else if (0 == strcmp(XP_TEST_MODULE_UINT16, value->xpath)){
            assert_int_equal(SR_UINT16_T, value->type);
        }
        else if (0 == strcmp(XP_TEST_MODULE_UINT8, value->xpath)){
            assert_int_equal(SR_UINT8_T, value->type);
        }
        else if (0 == strcmp(XP_TEST_MODULE_INT64, value->xpath)){
            assert_int_equal(SR_INT64_T, value->type);
        }
        else if (0 == strcmp(XP_TEST_MODULE_INT32, value->xpath)){
            assert_int_equal(SR_INT32_T, value->type);
        }
        else if (0 == strcmp(XP_TEST_MODULE_INT16, value->xpath)){
            assert_int_equal(SR_INT16_T, value->type);
        }
        else if (0 == strcmp(XP_TEST_MODULE_INT8, value->xpath)){
            assert_int_equal(SR_INT8_T, value->type);
        }
        else if (0 == strcmp(XP_TEST_MODULE_DEC64, value->xpath)){
            assert_int_equal(SR_DECIMAL64_T, value->type);
            assert_int_equal(XP_TEST_MODULE_DEC64_VALUE_T, value->data.decimal64_val);
        }
        else if (0 == strcmp(XP_TEST_MODULE_BITS, value->xpath)){
            assert_int_equal(SR_BITS_T, value->type);
        }
        else if (0 == strcmp(XP_TEST_MODULE_RAW, value->xpath)){
            assert_int_equal(SR_BINARY_T, value->type);
        }
        else if (0 == strcmp(XP_TEST_MODULE_ENUM, value->xpath)){
            assert_int_equal(SR_ENUM_T, value->type);
        }
        else if (0 == strcmp(XP_TEST_MODULE_BOOL, value->xpath)){
            assert_int_equal(SR_BOOL_T, value->type);
        }
        else if (0 == strcmp(XP_TEST_MODULE_IDREF, value->xpath)){
            assert_int_equal(SR_IDENTITYREF_T, value->type);
        }
        else if (0 == strcmp(XP_TEST_MODULE_STRING, value->xpath)){
            assert_int_equal(SR_STRING_T, value->type);
        }
        else{
            /* unknown node*/
            assert_true(false);
        }
        sr_free_val(value);
    }
    sr_free_val_iter(it);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_set_item_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_val_t value = { 0 };
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform a set-item request */
    value.type = SR_STRING_T;
    value.data.string_val = "abcdefghijkl";
    rc = sr_set_item(session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_delete_item_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform a delete-item request */
    rc = sr_delete_item(session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_move_item_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    int rc = 0;
    sr_val_t *values = NULL;
    size_t cnt = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform a move-item request, not user ordered list */
    rc = sr_move_item(session, "/test-module:list[key='k1']", SR_MOVE_FIRST, NULL);
    assert_int_equal(rc, SR_ERR_INVAL_ARG);

    /* perform a move-item request, unknown element */
    rc = sr_move_item(session, "/test-module:unknown", SR_MOVE_FIRST, NULL);
    assert_int_equal(rc, SR_ERR_BAD_ELEMENT);

    rc = sr_set_item(session, "/test-module:user[name='nameA']", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_set_item(session, "/test-module:user[name='nameB']", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_set_item(session, "/test-module:user[name='nameC']", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_get_items(session, "/test-module:user", &values, &cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, cnt);

    assert_string_equal("/test-module:user[name='nameA']", values[0].xpath);
    assert_string_equal("/test-module:user[name='nameB']", values[1].xpath);
    assert_string_equal("/test-module:user[name='nameC']", values[2].xpath);
    sr_free_values(values, cnt);

    rc = sr_move_item(session, "/test-module:user[name='nameA']", SR_MOVE_LAST, NULL);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_move_item(session, "/test-module:user[name='nameC']", SR_MOVE_BEFORE, "/test-module:user[name='nameA']");
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_get_items(session, "/test-module:user", &values, &cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, cnt);

    assert_string_equal("/test-module:user[name='nameB']", values[0].xpath);
    assert_string_equal("/test-module:user[name='nameC']", values[1].xpath);
    assert_string_equal("/test-module:user[name='nameA']", values[2].xpath);
    sr_free_values(values, cnt);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_validate_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;
    sr_val_t value = { 0 };
    const sr_error_info_t *errors = NULL;
    size_t error_cnt = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* set some data in the container, but don't set mandatory leaves */
    value.type = SR_STRING_T;
    value.data.string_val = "Europe/Banska Bystrica";
    rc = sr_set_item(session, "/test-module:location/name", &value, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    /* perform a validate request - expect an error */
    rc = sr_validate(session);
    assert_int_equal(rc, SR_ERR_VALIDATION_FAILED);

    /* print out all errors (if any) */
    rc = sr_get_last_errors(session, &errors, &error_cnt);
    if (error_cnt > 0) {
        for (size_t i = 0; i < error_cnt; i++) {
            printf("Error[%zu]: %s: %s\n", i, errors[i].xpath, errors[i].message);
        }
    }

    /* set mandatory leaf 1 */
    value.type = SR_STRING_T;
    value.data.string_val = "48°46'N";
    rc = sr_set_item(session, "/test-module:location/latitude", &value, SR_EDIT_DEFAULT);

    /* set mandatory leaf 2 */
    value.type = SR_STRING_T;
    value.data.string_val = "19°14'E";
    rc = sr_set_item(session, "/test-module:location/longitude", &value, SR_EDIT_DEFAULT);

    /* perform a validate request again - expect success */
    rc = sr_validate(session);
    assert_int_equal(rc, SR_ERR_OK);

    /* leafref: non-existing leaf and then fix it */
    value.type = SR_UINT8_T;
    value.data.uint8_val = 18;
    rc = sr_set_item(session, "/test-module:university/classes/class[title='CCNA']/student[name='nameB']/age", &value, SR_EDIT_DEFAULT);

    rc = sr_validate(session);
    assert_int_equal(rc, SR_ERR_VALIDATION_FAILED);

    /* print out all errors (if any) */
    rc = sr_get_last_errors(session, &errors, &error_cnt);
    if (error_cnt > 0) {
        for (size_t i = 0; i < error_cnt; i++) {
            printf("Error[%zu]: %s: %s\n", i, errors[i].xpath, errors[i].message);
        }
    }

    /* fix leafref */
    value.data.uint8_val = 17;
    rc = sr_set_item(session, "/test-module:university/classes/class[title='CCNA']/student[name='nameB']/age", &value, SR_EDIT_DEFAULT);

    rc = sr_validate(session);
    assert_int_equal(rc, SR_ERR_OK);

    /* leafref chain */
    value.type = SR_STRING_T;
    value.data.string_val = "final-leaf";
    rc = sr_set_item(session, "/test-module:leafref-chain/A", &value, SR_EDIT_DEFAULT);

    rc = sr_validate(session);
    assert_int_equal(rc, SR_ERR_VALIDATION_FAILED); /* missing "B" as the second link in the chain */

    /* add missing link, but with an invalid value */
    value.data.string_val = "second-leaf";
    rc = sr_set_item(session, "/test-module:leafref-chain/B", &value, SR_EDIT_DEFAULT);
    rc = sr_validate(session);
    assert_int_equal(rc, SR_ERR_VALIDATION_FAILED);

    /* print out all errors (if any) */
    rc = sr_get_last_errors(session, &errors, &error_cnt);
    if (error_cnt > 0) {
        for (size_t i = 0; i < error_cnt; i++) {
            printf("Error[%zu]: %s: %s\n", i, errors[i].xpath, errors[i].message);
        }
    }

    /* fix the value of "B" */
    value.data.string_val = "final-leaf";
    rc = sr_set_item(session, "/test-module:leafref-chain/B", &value, SR_EDIT_DEFAULT);

    rc = sr_validate(session);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_commit_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;
    sr_val_t value = { 0 };
    const sr_error_info_t *errors = NULL;
    size_t error_cnt = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* set some data in the container, but don't set mandatory leaves */
    value.type = SR_STRING_T;
    value.data.string_val = "Europe/Banska Bystrica";
    rc = sr_set_item(session, "/test-module:location/name", &value, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    /* perform a commit request - expect an error */
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_VALIDATION_FAILED);

    /* print out all errors (if any) */
    rc = sr_get_last_errors(session, &errors, &error_cnt);
    if (error_cnt > 0) {
        for (size_t i = 0; i < error_cnt; i++) {
            printf("Error[%zu]: %s: %s\n", i, errors[i].xpath, errors[i].message);
        }
    }

    /* set mandatory leaf 1 */
    value.type = SR_STRING_T;
    value.data.string_val = "48°46'N";
    rc = sr_set_item(session, "/test-module:location/latitude", &value, SR_EDIT_DEFAULT);

    /* set mandatory leaf 2 */
    value.type = SR_STRING_T;
    value.data.string_val = "19°14'E";
    rc = sr_set_item(session, "/test-module:location/longitude", &value, SR_EDIT_DEFAULT);

    /* perform a commit request again - expect success */
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    /* cleanup - delete added data */
    rc = sr_delete_item(session, "/test-module:location", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    /* leafref: non-existing leaf and then fix it */
    value.type = SR_UINT8_T;
    value.data.uint8_val = 18;
    rc = sr_set_item(session, "/test-module:university/classes/class[title='CCNA']/student[name='nameB']/age", &value, SR_EDIT_DEFAULT);

    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_VALIDATION_FAILED);

    /* print out all errors (if any) */
    rc = sr_get_last_errors(session, &errors, &error_cnt);
    if (error_cnt > 0) {
        for (size_t i = 0; i < error_cnt; i++) {
            printf("Error[%zu]: %s: %s\n", i, errors[i].xpath, errors[i].message);
        }
    }

    /* fix leafref */
    value.data.uint8_val = 17;
    rc = sr_set_item(session, "/test-module:university/classes/class[title='CCNA']/student[name='nameB']/age", &value, SR_EDIT_DEFAULT);

    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    /* leafref chain */
    value.type = SR_STRING_T;
    value.data.string_val = "final-leaf";
    rc = sr_set_item(session, "/test-module:leafref-chain/A", &value, SR_EDIT_DEFAULT);

    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_VALIDATION_FAILED); /* missing "B" as the second link in the chain */

    /* add missing link, but with an invalid value */
    value.data.string_val = "second-leaf";
    rc = sr_set_item(session, "/test-module:leafref-chain/B", &value, SR_EDIT_DEFAULT);
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_VALIDATION_FAILED);

    /* print out all errors (if any) */
    rc = sr_get_last_errors(session, &errors, &error_cnt);
    if (error_cnt > 0) {
        for (size_t i = 0; i < error_cnt; i++) {
            printf("Error[%zu]: %s: %s\n", i, errors[i].xpath, errors[i].message);
        }
    }

    /* fix the value of "B" */
    value.data.string_val = "final-leaf";
    rc = sr_set_item(session, "/test-module:leafref-chain/B", &value, SR_EDIT_DEFAULT);

    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_discard_changes_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    sr_val_t *values = NULL;
    size_t cnt = 0;

    rc = sr_get_items(session, "/example-module:container/list", &values, &cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(1, cnt);
    sr_free_values(values, cnt);

    rc = sr_set_item(session, "/example-module:container/list[key1='a'][key2='b']", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_get_items(session, "/example-module:container/list", &values, &cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(2, cnt);
    sr_free_values(values, cnt);

    /* perform a discard-changes request */
    rc = sr_discard_changes(session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_get_items(session, "/example-module:container/list", &values, &cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(1, cnt);
    sr_free_values(values, cnt);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_locking_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *sessionA = NULL, *sessionB = NULL;
    int rc = 0;

    /* start 2 sessions */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &sessionA);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &sessionB);
    assert_int_equal(rc, SR_ERR_OK);

    /* lock datastore in session A */
    rc = sr_lock_datastore(sessionA);
    assert_int_equal(rc, SR_ERR_OK);

    /* try locking in session B and expect error */
    rc = sr_lock_module(sessionB, "example-module");
    assert_int_equal(rc, SR_ERR_LOCKED);

    rc = sr_lock_datastore(sessionB);
    assert_int_equal(rc, SR_ERR_LOCKED);

    /* unlock the datastore */
    rc = sr_unlock_datastore(sessionA);
    assert_int_equal(rc, SR_ERR_OK);

    /* lock a module in session A */
    rc = sr_lock_module(sessionA, "example-module");
    assert_int_equal(rc, SR_ERR_OK);

    /* try locking module and whole ds in session B and expect error */
    rc = sr_lock_module(sessionB, "example-module");
    assert_int_equal(rc, SR_ERR_LOCKED);

    rc = sr_lock_datastore(sessionB);
    assert_int_equal(rc, SR_ERR_LOCKED);

    /* unlock the module */
    rc = sr_unlock_module(sessionA, "example-module");
    assert_int_equal(rc, SR_ERR_OK);

    /* try to lock unknown module */
    rc = sr_lock_module(sessionB, "unknown-module");
    assert_int_equal(rc, SR_ERR_UNKNOWN_MODEL);

    /* modified module can not be locked*/
    rc = sr_delete_item(sessionB, "/test-module:main", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_lock_module(sessionB, "test-module");
    assert_int_equal(rc, SR_ERR_OPERATION_FAILED);

    rc = sr_lock_datastore(sessionB);
    assert_int_equal(rc, SR_ERR_OPERATION_FAILED);

    const sr_error_info_t *error = NULL;
    sr_get_last_error(sessionB, &error);

    assert_string_equal("test-module", error->xpath);
    assert_string_equal("Module has been modified, it can not be locked. Discard or commit changes", error->message);

    /* stop the sessions */
    rc = sr_session_stop(sessionA);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_stop(sessionB);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_refresh_session(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *sessionA = NULL, *sessionB = NULL;
    sr_val_t valA = {0,};
    sr_val_t *valB = NULL;
    const sr_error_info_t *error_info = NULL;
    size_t error_cnt = 0;
    int rc = 0;

    /* start two session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &sessionA);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &sessionB);
    assert_int_equal(rc, SR_ERR_OK);

    /* Perform 4 operation in session A */

    /*op 1*/
    valA.type = SR_UINT8_T;
    valA.data.uint8_val = 26;
    valA.xpath = NULL;

    rc = sr_set_item(sessionA, XP_TEST_MODULE_UINT8, &valA, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_val_content(&valA);

    /*op 2*/
    rc = sr_set_item(sessionA, "/test-module:list[key='abc']", NULL, SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_OK, rc);

    /*op 3*/
    rc = sr_set_item(sessionA, "/test-module:list[key='def']", NULL, SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_OK, rc);


    /*op 4*/
    valA.type = SR_UINT64_T;
    valA.data.uint64_val = 999;
    valA.xpath = NULL;

    rc = sr_set_item(sessionA, XP_TEST_MODULE_UINT64, &valA, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_val_content(&valA);

    /* Perform two operation that conflicts with 2nd 3rd open in A */

    rc = sr_set_item(sessionB, "/test-module:list[key='abc']", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_set_item(sessionB, "/test-module:list[key='def']", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    /* commit session B */
    rc = sr_commit(sessionB);
    assert_int_equal(SR_ERR_OK, rc);

    /* Session refresh of A should end with error but op 1 and 4 stay in place */
    rc = sr_session_refresh(sessionA);
    assert_int_equal(SR_ERR_INTERNAL, rc);

    sr_get_last_errors(sessionA, &error_info, &error_cnt);
    for (size_t i=0; i<error_cnt; i++) {
        printf("%s:\n\t%s\n", error_info[i].message, error_info[i].xpath);
    }

    /* commit session A*/
    rc = sr_commit(sessionA);
    assert_int_equal(SR_ERR_OK, rc);

    /* check that op 1 and 4 stayed in place */
    rc = sr_session_refresh(sessionB);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_get_item(sessionB, XP_TEST_MODULE_UINT8, &valB);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valB);
    assert_int_equal(26, valB->data.uint8_val);
    sr_free_val(valB);

    rc = sr_get_item(sessionB, XP_TEST_MODULE_UINT64, &valB);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(valB);
    assert_int_equal(999, valB->data.uint64_val);
    sr_free_val(valB);

    rc = sr_session_stop(sessionA);
    rc = sr_session_stop(sessionB);

}

static void
cl_refresh_session2(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *sessionA = NULL, *sessionB = NULL, *sessionC = NULL;
    const sr_error_info_t *error_info = NULL;
    size_t error_cnt = 0;
    int rc = 0;

    /* start two session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &sessionA);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &sessionB);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &sessionC);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_set_item(sessionA, "/test-module:ordered-numbers[.='1']", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item(sessionA, "/test-module:ordered-numbers[.='2']", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item(sessionA, "/test-module:ordered-numbers[.='3']", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_commit(sessionA);
    assert_int_equal(SR_ERR_OK, rc);


    /* delete whole module configuration in sessionA */
    rc = sr_delete_item(sessionA, "/test-module:*", SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_OK, rc);

    /* delete whole module configuration in sessionB */
    rc = sr_delete_item(sessionB, "/test-module:*", SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_OK, rc);

    /* delete whole module configuration in sessionB */
    rc = sr_move_item(sessionC, "/test-module:ordered-numbers[.='1']", SR_MOVE_AFTER, "/test-module:ordered-numbers[.='2']");
    assert_int_equal(SR_ERR_OK, rc);

    /* commit session A */
    rc = sr_commit(sessionA);
    assert_int_equal(SR_ERR_OK, rc);

    /* Session refresh of B should fail, can not delete non existing configuration */
    rc = sr_session_refresh(sessionB);
    assert_int_equal(SR_ERR_INTERNAL, rc);

    sr_get_last_errors(sessionB, &error_info, &error_cnt);
    for (size_t i=0; i<error_cnt; i++) {
        printf("%s:\n\t%s\n", error_info[i].message, error_info[i].xpath);
    }

    /* Session refresh of C should fail, can not move deleted list */
    rc = sr_session_refresh(sessionC);
    assert_int_equal(SR_ERR_INTERNAL, rc);

    sr_get_last_errors(sessionC, &error_info, &error_cnt);
    for (size_t i=0; i<error_cnt; i++) {
        printf("%s:\n\t%s\n", error_info[i].message, error_info[i].xpath);
    }

    rc = sr_session_stop(sessionA);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_session_stop(sessionB);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_session_stop(sessionC);
    assert_int_equal(SR_ERR_OK, rc);
}

static void
cl_get_error_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    const sr_error_info_t *error_info = NULL;
#if 0
    size_t error_cnt = 0;
    sr_val_t *value = NULL;
#endif
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* retrieve last error information - no error */
    rc = sr_get_last_error(session, &error_info);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(error_info);
    assert_non_null(error_info->message);
#if 0
    /* xpath validation produces only warnings on get like calls */
    /* attempt to get item on bad element in existing module */
    rc = sr_get_item(session, "/example-module:container/unknown", &value);
    assert_int_equal(SR_ERR_BAD_ELEMENT, rc);
    assert_null(value);

    /* retrieve last error information */
    rc = sr_get_last_error(session, &error_info);
    assert_int_equal(SR_ERR_BAD_ELEMENT, rc);
    assert_non_null(error_info);
    assert_non_null(error_info->message);

    /* retrieve last error information */
    rc = sr_get_last_errors(session, &error_info, &error_cnt);
    assert_int_equal(SR_ERR_BAD_ELEMENT, rc);
    assert_non_null(error_info);
    assert_int_equal(error_cnt, 1);
    assert_non_null(error_info[0].message);
#endif
    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
test_module_install_cb(const char *module_name, const char *revision, bool installed, void *private_ctx)
{
    int *callback_called = (int*)private_ctx;
    *callback_called += 1;
    printf("Module '%s' revision '%s' has been %s.\n", module_name, revision, installed ? "installed" : "uninstalled");
}

static void
test_feature_enable_cb(const char *module_name, const char *feature_name, bool enabled, void *private_ctx)
{
    int *callback_called = (int*)private_ctx;
    *callback_called += 1;
    printf("Feature '%s' has been %s in module '%s'.\n", feature_name, enabled ? "enabled" : "disabled", module_name);
}

static int
test_module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    sr_val_t *value = NULL;
    int rc = SR_ERR_OK;

    int *callback_called = (int*)private_ctx;
    printf("Some data within the module '%s' has changed.\n", module_name);

    rc = sr_get_item(session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &value);
    if (SR_ERR_OK == rc) {
        printf("New value for '%s' = '%s'\n", value->xpath, value->data.string_val);
        sr_free_val(value);
        *callback_called += 1;
    } else {
        printf("While retrieving '%s' error with code (%d) occured\n", "/example-module:container/list[key1='key1'][key2='key2']/leaf", rc);
    }

    return SR_ERR_OK;
}

static int
test_subtree_change_cb(sr_session_ctx_t *session, const char *xpath, sr_notif_event_t event, void *private_ctx)
{
    sr_val_t *value = NULL;
    int rc = SR_ERR_OK;

    int *callback_called = (int*)private_ctx;
    printf("Some data within the subtree '%s' has changed.\n", xpath);

    rc = sr_get_item(session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &value);
    if (SR_ERR_OK == rc) {
        printf("New value for '%s' = '%s'\n", value->xpath, value->data.string_val);
        sr_free_val(value);
        *callback_called += 1;
    } else {
        printf("While retrieving '%s' error with code (%d) occured\n", "/example-module:container/list[key1='key1'][key2='key2']/leaf", rc);
    }

    return SR_ERR_OK;
}

static void
cl_notification_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int callback_called = 0;
    sr_val_t value = { 0, };
    int rc = SR_ERR_OK;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe to some notifications */
    rc = sr_module_install_subscribe(session, test_module_install_cb, &callback_called, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_feature_enable_subscribe(session, test_feature_enable_cb, &callback_called, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "example-module", test_module_change_cb, &callback_called,
            0, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_subtree_change_subscribe(session, "/example-module:container/list", test_subtree_change_cb, &callback_called,
            0, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    char file_name[512] = {0};
    snprintf(file_name, 512, "%s%s.yang", SR_SCHEMA_SEARCH_DIR, "example-module");
    /* do some changes */
    rc = sr_module_install(session, "example-module", NULL, file_name, true);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_feature_enable(session, "ietf-interfaces", "pre-provisioning", true);
    assert_int_equal(rc, SR_ERR_OK);

    /* validate changes in modules and features using list-schemas */
    size_t schema_cnt = 0;
    sr_schema_t *schemas = NULL;
    rc = sr_list_schemas(session, &schemas, &schema_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    for (size_t s = 0; s < schema_cnt; s++) {
        if (0 == strcmp("ietf-interfaces", schemas[s].module_name)){
            assert_true(schemas[s].enabled_feature_cnt > 0);
            assert_string_equal("pre-provisioning", schemas[s].enabled_features[0]);
        } else {
            assert_int_equal(0, schemas[s].enabled_feature_cnt);
        }
    }
    sr_free_schemas(schemas, schema_cnt);

    rc = sr_feature_enable(session, "ietf-interfaces", "pre-provisioning", false);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform a set-item request */
    value.type = SR_STRING_T;
    value.data.string_val = "notification_test";
    rc = sr_set_item(session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    /* commit */
    rc = sr_commit(session);

    /* wait for all callbacks or timeout after 10 seconds */
    for (size_t i = 0; i < 1000; i++) {
        if (callback_called >= 5) break;
        usleep(10000); /* 10 ms */
    }
    assert_true(callback_called >= 5);

    /* some negative tests */
    rc = sr_feature_enable(session, "unknown-module", "unknown", true);
    assert_int_equal(rc, SR_ERR_UNKNOWN_MODEL);

    rc = sr_feature_enable(session, "example-module", "unknown", true);
    assert_int_equal(rc, SR_ERR_INVAL_ARG);

    snprintf(file_name, 512, "%s%s%s.yang", SR_SCHEMA_SEARCH_DIR, "example-module", "@2016-05-03");
    rc = sr_module_install(session, "example-module", "2016-05-03", file_name, false);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

    snprintf(file_name, 512, "%s%s.yang", SR_SCHEMA_SEARCH_DIR, "example-module");
    rc = sr_module_install(session, "example-module", NULL, file_name, false);
    assert_int_equal(rc, SR_ERR_OK);

    /* after module uninstallation all subsequent operation return UNKOWN_MODEL */
    rc = sr_lock_module(session, "example-module");
    assert_int_equal(rc, SR_ERR_UNKNOWN_MODEL);
    
    /* install module back */
    snprintf(file_name, 512, "%s%s.yang", SR_SCHEMA_SEARCH_DIR, "example-module");
    rc = sr_module_install(session, "example-module", NULL, file_name, true);
    assert_int_equal(rc, SR_ERR_OK);
    
    rc = sr_unsubscribe(session, subscription);
    assert_int_equal(rc, SR_ERR_OK);
    
    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_copy_config_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session_startup = NULL, *session_running = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int callback_called = 0;
    sr_val_t value = { 0, }, *val = NULL;
    int rc = SR_ERR_OK;

    /* start sessions */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session_startup);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session_running);
    assert_int_equal(rc, SR_ERR_OK);

    /* copy to/from candidate */
    rc = sr_copy_config(session_startup, NULL, SR_DS_STARTUP, SR_DS_CANDIDATE);
    assert_int_equal(rc, SR_ERR_OK);

    /* copy-config all enabled models, currently none */
    rc = sr_copy_config(session_startup, NULL, SR_DS_RUNNING, SR_DS_STARTUP);
    assert_int_equal(rc, SR_ERR_OK);

    /* enable running DS for example-module */
    rc = sr_module_change_subscribe(session_startup, "example-module", test_module_change_cb,
            &callback_called, 0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* edit config in running */
    value.type = SR_STRING_T;
    value.data.string_val = "copy_config_test";
    rc = sr_set_item(session_running, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* commit */
    rc = sr_commit(session_running);

    /* copy-config */
    rc = sr_copy_config(session_startup, "example-module", SR_DS_RUNNING, SR_DS_STARTUP);
    assert_int_equal(rc, SR_ERR_OK);

    /* get-config from startup */
    rc = sr_get_item(session_startup, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(rc, SR_ERR_OK);
    assert_string_equal(val->data.string_val, "copy_config_test");
    sr_free_val(val);

    /* edit config in running 2 */
    value.type = SR_STRING_T;
    value.data.string_val = "copy_config_modified";
    rc = sr_set_item(session_running, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* commit */
    rc = sr_commit(session_running);

    /* copy-config all enabled models */
    rc = sr_copy_config(session_startup, NULL, SR_DS_RUNNING, SR_DS_STARTUP);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_refresh(session_startup);
    assert_int_equal(rc, SR_ERR_OK);

    /* get-config from startup */
    rc = sr_get_item(session_startup, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(rc, SR_ERR_OK);
    assert_string_equal(val->data.string_val, value.data.string_val);
    sr_free_val(val);

    /* stop the sessions */
    rc = sr_session_stop(session_startup);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_stop(session_running);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_copy_config_test2(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session_candidate = NULL, *session_running = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int callback_called = 0;
    sr_val_t value = { 0, }, *val = NULL;
    int rc = SR_ERR_OK;

    /* start sessions */
    rc = sr_session_start(conn, SR_DS_CANDIDATE, SR_SESS_DEFAULT, &session_candidate);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session_running);
    assert_int_equal(rc, SR_ERR_OK);

    /* enable example-module */
    rc = sr_module_change_subscribe(session_running, "example-module", test_module_change_cb,
            &callback_called, 0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* edit config candidate */
    value.type = SR_STRING_T;
    value.data.string_val = "copy_config_test";
    rc = sr_set_item(session_candidate, "/example-module:container/list[key1='abc'][key2='def']/leaf", &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* copy-config */
    rc = sr_copy_config(session_candidate, NULL, SR_DS_CANDIDATE, SR_DS_RUNNING);
    assert_int_equal(rc, SR_ERR_OK);

    /* check that value from candidate has been copied */
    rc = sr_get_item(session_running, "/example-module:container/list[key1='abc'][key2='def']/leaf", &val);
    assert_int_equal(rc, SR_ERR_OK);
    assert_string_equal(val->data.string_val, "copy_config_test");
    sr_free_val(val);

    /* overwrite change in candidate - copy all enabled modules from startup to running */
    rc = sr_copy_config(session_candidate, NULL, SR_DS_STARTUP, SR_DS_RUNNING);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_refresh(session_running);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_get_item(session_running, "/example-module:container/list[key1='abc'][key2='def']/leaf", &val);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

    /* stop the sessions */
    rc = sr_session_stop(session_candidate);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_stop(session_running);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);
}

static int
test_rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt,
        sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    int *callback_called = (int*)private_ctx;
    *callback_called += 1;

    printf("'Executing' RPC: %s\n", xpath);
    for (size_t i = 0; i < input_cnt; i++) {
        printf("    input parameter[%zu]: %s = %s\n", i, input[i].xpath, input[i].data.string_val);
    }

    /* check input */
    assert_int_equal(2, input_cnt);
    assert_string_equal("/test-module:activate-software-image/image-name", input[0].xpath);
    assert_false(input[0].dflt);
    assert_int_equal(SR_STRING_T, input[0].type);
    assert_string_equal("acmefw-2.3", input[0].data.string_val);
    assert_string_equal("/test-module:activate-software-image/location", input[1].xpath);
    assert_true(input[1].dflt);
    assert_int_equal(SR_STRING_T, input[1].type);
    assert_string_equal("/", input[1].data.string_val);

    *output = calloc(2, sizeof(**output));
    (*output)[0].xpath = strdup("/test-module:activate-software-image/status");
    (*output)[0].type = SR_STRING_T;
    (*output)[0].data.string_val = strdup("The image acmefw-2.3 is being installed.");
    (*output)[1].xpath = strdup("/test-module:activate-software-image/version");
    (*output)[1].type = SR_STRING_T;
    (*output)[1].data.string_val = strdup("2.3");

    *output_cnt = 2;

    return SR_ERR_OK;
}

static void
cl_rpc_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int callback_called = 0;
    int rc = SR_ERR_OK;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe for RPC */
    rc = sr_rpc_subscribe(session, "/test-module:activate-software-image", test_rpc_cb, &callback_called,
            SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    sr_val_t input = { 0, };
    sr_val_t *output = NULL;
    size_t output_cnt = 0;
    input.xpath = "/test-module:activate-software-image/image-name";
    input.type = SR_STRING_T;
    input.data.string_val = "acmefw-2.3";

    /* send a RPC */
    rc = sr_rpc_send(session, "/test-module:activate-software-image", &input, 1, &output, &output_cnt);
    assert_int_equal(rc, SR_ERR_OK);

    for (size_t i = 0; i < output_cnt; i++) {
        printf("RPC output parameter[%zu]: %s = %s\n", i, output[i].xpath, output[i].data.string_val);
    }

    /* check output */
    assert_int_equal(3, output_cnt);
    assert_string_equal("/test-module:activate-software-image/status", output[0].xpath);
    assert_false(output[0].dflt);
    assert_int_equal(SR_STRING_T, output[0].type);
    assert_string_equal("The image acmefw-2.3 is being installed.", output[0].data.string_val);
    assert_string_equal("/test-module:activate-software-image/version", output[1].xpath);
    assert_false(output[1].dflt);
    assert_int_equal(SR_STRING_T, output[1].type);
    assert_string_equal("2.3", output[1].data.string_val);
    assert_string_equal("/test-module:activate-software-image/location", output[2].xpath);
    assert_true(output[2].dflt);
    assert_int_equal(SR_STRING_T, output[2].type);
    assert_string_equal("/", output[2].data.string_val);

    sr_free_values(output, output_cnt);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);

    /* unsubscribe */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);
}

static int
test_rpc_tree_cb(const char *xpath, const sr_node_t *input, const size_t input_cnt,
        sr_node_t **output, size_t *output_cnt, void *private_ctx)
{
    const sr_node_t *sr_in_node = NULL;
    sr_node_t *sr_out_node = NULL;
    int *callback_called = (int*)private_ctx;
    *callback_called += 1;

    printf("'Executing' RPC: %s\n", xpath);
    for (size_t i = 0; i < input_cnt; i++) {
        printf("    input parameter[%zu]: %s = %s\n", i, input[i].name, input[i].data.string_val);
    }

    /* check input */
    assert_int_equal(2, input_cnt);
    /*   /test-module:activate-software-image/input/image-name */
    sr_in_node = input;
    assert_string_equal("image-name", sr_in_node->name);
    assert_string_equal("test-module", sr_in_node->module_name);
    assert_false(sr_in_node->dflt);
    assert_int_equal(SR_STRING_T, sr_in_node->type);
    assert_string_equal("acmefw-2.3", sr_in_node->data.string_val);
    assert_int_equal(0, sr_in_node->children_cnt);
    assert_null(sr_in_node->children);
    /*   /test-module:activate-software-image/input/location */
    sr_in_node = input + 1;
    assert_string_equal("location", sr_in_node->name);
    assert_string_equal("test-module", sr_in_node->module_name);
    assert_true(sr_in_node->dflt);
    assert_int_equal(SR_STRING_T, sr_in_node->type);
    assert_string_equal("/", sr_in_node->data.string_val);
    assert_int_equal(0, sr_in_node->children_cnt);
    assert_null(sr_in_node->children);

    /* prepare output */
    *output_cnt = 3;
    *output = calloc(*output_cnt, sizeof(**output));
    (*output)[0].name = strdup("status");
    (*output)[0].type = SR_STRING_T;
    (*output)[0].data.string_val = strdup("The image acmefw-2.3 is being installed.");
    (*output)[1].name = strdup("version");
    (*output)[1].type = SR_STRING_T;
    (*output)[1].data.string_val = strdup("2.3");
    (*output)[2].name = strdup("init-log");
    (*output)[2].type = SR_CONTAINER_T;
    (*output)[2].children_cnt = 2;
    (*output)[2].children = calloc(2, sizeof(sr_node_t));
    /* log-msg[1] */
    sr_out_node = (*output)[2].children;
    sr_out_node->name = strdup("log-msg");
    sr_out_node->type = SR_LIST_T;
    sr_out_node->children_cnt = 3;
    sr_out_node->children = calloc(sr_out_node->children_cnt, sizeof(sr_node_t));
    sr_out_node->children[0].name = strdup("msg");
    sr_out_node->children[0].type = SR_STRING_T;
    sr_out_node->children[0].data.string_val = strdup("Successfully loaded software image.");
    sr_out_node->children[1].name = strdup("time");
    sr_out_node->children[1].type = SR_UINT32_T;
    sr_out_node->children[1].data.uint32_val = 1469625110;
    sr_out_node->children[2].name = strdup("msg-type");
    sr_out_node->children[2].type = SR_ENUM_T;
    sr_out_node->children[2].data.enum_val = strdup("debug");
    /* log-msg[2] */
    sr_out_node = (*output)[2].children + 1;
    sr_out_node->name = strdup("log-msg");
    sr_out_node->type = SR_LIST_T;
    sr_out_node->children_cnt = 3;
    sr_out_node->children = calloc(sr_out_node->children_cnt, sizeof(sr_node_t));
    sr_out_node->children[0].name = strdup("msg");
    sr_out_node->children[0].type = SR_STRING_T;
    sr_out_node->children[0].data.string_val = strdup("Some soft limit exceeded...");
    sr_out_node->children[1].name = strdup("time");
    sr_out_node->children[1].type = SR_UINT32_T;
    sr_out_node->children[1].data.uint32_val = 1469625150;
    sr_out_node->children[2].name = strdup("msg-type");
    sr_out_node->children[2].type = SR_ENUM_T;
    sr_out_node->children[2].data.enum_val = strdup("warning");

    return SR_ERR_OK;
}

static void
cl_rpc_tree_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int callback_called = 0;
    int rc = SR_ERR_OK;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe for RPC */
    rc = sr_rpc_subscribe_tree(session, "/test-module:activate-software-image", test_rpc_tree_cb, &callback_called,
            SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    sr_node_t input = { 0, };
    sr_node_t *output = NULL;
    size_t output_cnt = 0;
    input.name = "image-name";
    input.type = SR_STRING_T;
    input.data.string_val = "acmefw-2.3";

    /* send a RPC */
    rc = sr_rpc_send_tree(session, "/test-module:activate-software-image", &input, 1, &output, &output_cnt);
    assert_int_equal(rc, SR_ERR_OK);

    assert_int_equal(output_cnt, 4);
    for (size_t i = 0; i < output_cnt; i++) {
        printf("RPC output parameter[%zu]: %s = %s\n", i, output[i].name, output[i].data.string_val);
    }

    /* check output */
    sr_node_t *sr_node = output;
    /*   /test-module:activate-software-image/output/status */
    assert_string_equal("status", sr_node->name);
    assert_string_equal("test-module", sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_STRING_T, sr_node->type);
    assert_string_equal("The image acmefw-2.3 is being installed.", sr_node->data.string_val);
    assert_int_equal(0, sr_node->children_cnt);
    assert_null(sr_node->children);
    /*   /test-module:activate-software-image/output/version */
    sr_node = output + 1;
    assert_string_equal("version", sr_node->name);
    assert_string_equal("test-module", sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_STRING_T, sr_node->type);
    assert_string_equal("2.3", sr_node->data.string_val);
    assert_int_equal(0, sr_node->children_cnt);
    assert_null(sr_node->children);
    /*   /test-module:activate-software-image/output/location */
    sr_node = output + 2;
    assert_string_equal("location", sr_node->name);
    assert_string_equal("test-module", sr_node->module_name);
    assert_true(sr_node->dflt);
    assert_int_equal(SR_STRING_T, sr_node->type);
    assert_string_equal("/", sr_node->data.string_val);
    assert_int_equal(0, sr_node->children_cnt);
    assert_null(sr_node->children);
    /*   /test-module:activate-software-image/output/init-log */
    sr_node = output + 3;
    assert_string_equal("init-log", sr_node->name);
    assert_string_equal("test-module", sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_CONTAINER_T, sr_node->type);
    assert_int_equal(2, sr_node->children_cnt);
    assert_non_null(sr_node->children);
    /*   /test-module:activate-software-image/output/init-log/log-msg[1] */
    sr_node = sr_node->children;
    assert_string_equal("log-msg", sr_node->name);
    assert_null( sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_LIST_T, sr_node->type);
    assert_int_equal(3, sr_node->children_cnt);
    assert_non_null(sr_node->children);
    /*   /test-module:activate-software-image/output/init-log/log-msg[1]/msg */
    assert_string_equal("msg", sr_node->children[0].name);
    assert_null(sr_node->children[0].module_name);
    assert_false(sr_node->children[0].dflt);
    assert_int_equal(SR_STRING_T, sr_node->children[0].type);
    assert_string_equal("Successfully loaded software image.", sr_node->children[0].data.string_val);
    assert_int_equal(0, sr_node->children[0].children_cnt);
    assert_null(sr_node->children[0].children);
    /*   /test-module:activate-software-image/output/init-log/log-msg[1]/time */
    assert_string_equal("time", sr_node->children[1].name);
    assert_null(sr_node->children[1].module_name);
    assert_false(sr_node->children[1].dflt);
    assert_int_equal(SR_UINT32_T, sr_node->children[1].type);
    assert_int_equal(1469625110, sr_node->children[1].data.uint32_val);
    assert_int_equal(0, sr_node->children[1].children_cnt);
    assert_null(sr_node->children[1].children);
    /*   /test-module:activate-software-image/output/init-log/log-msg[1]/msg-type */
    assert_string_equal("msg-type", sr_node->children[2].name);
    assert_null(sr_node->children[2].module_name);
    assert_false(sr_node->children[2].dflt);
    assert_int_equal(SR_ENUM_T, sr_node->children[2].type);
    assert_string_equal("debug", sr_node->children[2].data.string_val);
    assert_int_equal(0, sr_node->children[1].children_cnt);
    assert_null(sr_node->children[2].children);
    /*   /test-module:activate-software-image/output/init-log/log-msg[2] */
    sr_node = output[3].children + 1;
    assert_string_equal("log-msg", sr_node->name);
    assert_null( sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_LIST_T, sr_node->type);
    assert_int_equal(3, sr_node->children_cnt);
    assert_non_null(sr_node->children);
    /*   /test-module:activate-software-image/output/init-log/log-msg[1]/msg */
    assert_string_equal("msg", sr_node->children[0].name);
    assert_null(sr_node->children[0].module_name);
    assert_false(sr_node->children[0].dflt);
    assert_int_equal(SR_STRING_T, sr_node->children[0].type);
    assert_string_equal("Some soft limit exceeded...", sr_node->children[0].data.string_val);
    assert_int_equal(0, sr_node->children[0].children_cnt);
    assert_null(sr_node->children[0].children);
    /*   /test-module:activate-software-image/output/init-log/log-msg[1]/time */
    assert_string_equal("time", sr_node->children[1].name);
    assert_null(sr_node->children[1].module_name);
    assert_false(sr_node->children[1].dflt);
    assert_int_equal(SR_UINT32_T, sr_node->children[1].type);
    assert_int_equal(1469625150, sr_node->children[1].data.uint32_val);
    assert_int_equal(0, sr_node->children[1].children_cnt);
    assert_null(sr_node->children[1].children);
    /*   /test-module:activate-software-image/output/init-log/log-msg[1]/msg-type */
    assert_string_equal("msg-type", sr_node->children[2].name);
    assert_null(sr_node->children[2].module_name);
    assert_false(sr_node->children[2].dflt);
    assert_int_equal(SR_ENUM_T, sr_node->children[2].type);
    assert_string_equal("warning", sr_node->children[2].data.string_val);
    assert_int_equal(0, sr_node->children[1].children_cnt);
    assert_null(sr_node->children[2].children);

    sr_free_trees(output, output_cnt);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);

    /* unsubscribe */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
candidate_ds_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session_startup = NULL, *session_running = NULL, *session_candidate = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int callback_called = 0;
    sr_val_t value = { 0, }, *val = NULL;
    int rc = SR_ERR_OK;

    /* start sessions */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session_startup);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_start(conn, SR_DS_CANDIDATE, SR_SESS_DEFAULT, &session_candidate);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session_running);
    assert_int_equal(rc, SR_ERR_OK);

    /* get-config from candidate, should be empty no module enabled */
    rc = sr_get_item(session_candidate, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);
    sr_free_val(val);

    value.type = SR_STRING_T;
    value.data.string_val = "abcd";
    value.xpath = "/example-module:container/list[key1='key1'][key2='key2']/leaf";

    /* set item into candidate work even for not enabled leaf */
    rc = sr_set_item(session_candidate, value.xpath, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_get_item(session_candidate, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(value.type, val->type);
    assert_string_equal(value.data.string_val, val->data.string_val);
    sr_free_val(val);

    rc = sr_copy_config(session_candidate, "example-module", SR_DS_CANDIDATE, SR_DS_STARTUP);
    assert_int_equal(rc, SR_ERR_OK);

    /* get-config from startup, candidate should be copied to the startup */
    rc = sr_get_item(session_startup, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(value.type, val->type);
    assert_string_equal(value.data.string_val, val->data.string_val);
    sr_free_val(val);

    /* commit should fail because non enabled nodes are modified */
    rc = sr_commit(session_candidate);
    assert_int_equal(SR_ERR_OPERATION_FAILED, rc);

    rc = sr_copy_config(session_candidate, "example-module", SR_DS_CANDIDATE, SR_DS_RUNNING);
    assert_int_equal(SR_ERR_OPERATION_FAILED, rc);

    /* enable running DS for example-module */
    rc = sr_module_change_subscribe(session_startup, "example-module", test_module_change_cb,
            &callback_called, 0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* commit should pass */
    rc = sr_commit(session_candidate);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_get_item(session_running, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(value.type, val->type);
    assert_string_equal(value.data.string_val, val->data.string_val);
    sr_free_val(val);

    /* copy config should work as well*/
    value.data.string_val = "xyz";
    rc = sr_set_item(session_candidate, value.xpath, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_copy_config(session_candidate, "example-module", SR_DS_CANDIDATE, SR_DS_RUNNING);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_session_refresh(session_running);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_get_item(session_running, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(value.type, val->type);
    assert_string_equal(value.data.string_val, val->data.string_val);
    sr_free_val(val);

    /* stop the sessions */
    rc = sr_session_stop(session_startup);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_stop(session_candidate);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_stop(session_running);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_switch_ds(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_val_t value = { 0, }, *val = NULL;
    int rc = SR_ERR_OK;

    /* start session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* value can be found in startup */
    rc = sr_get_item(session, "/test-module:main/i8", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(SR_INT8_T, val->type);
    sr_free_val(val);
    val = NULL;

    value.type = SR_INT8_T;
    value.xpath = "/test-module:main/i8";
    value.data.int8_val = 1;

    /* modify value in startup */
    rc = sr_set_item(session, value.xpath, &value, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_session_switch_ds(session, SR_DS_RUNNING);
    assert_int_equal(SR_ERR_OK, rc);

    /* value is not enabled in running */
    rc = sr_get_item(session, "/test-module:main/i8", &val);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* switch back to startup*/
    rc = sr_session_switch_ds(session, SR_DS_STARTUP);
    assert_int_equal(SR_ERR_OK, rc);

    /* changes made in session are in place */
    rc = sr_get_item(session, "/test-module:main/i8", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(SR_INT8_T, val->type);
    assert_int_equal(1, val->data.uint8_val);
    sr_free_val(val);
    val = NULL;

    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);

}

static int
module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    int *callback_called = (int*)private_ctx;
    *callback_called += 1;
    return SR_ERR_OK;
}

static void
cl_candidate_refresh(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int cb_called = 0;

    sr_val_t *val = NULL;
    const char *xpath = NULL;
    int rc = SR_ERR_OK;
    xpath = "/example-module:container/list[key1='key1'][key2='key2']/leaf";

    /* start session */
    rc = sr_session_start(conn, SR_DS_CANDIDATE, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "example-module", module_change_cb, &cb_called,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* check the list presence in candidate */
    rc = sr_get_item(session, xpath, &val);
    assert_int_equal(rc, SR_ERR_OK);
    sr_free_val(val);

    /* switch to running */
    rc = sr_session_switch_ds(session, SR_DS_RUNNING);
    assert_int_equal(rc, SR_ERR_OK);

    /* remove the list instance */
    rc = sr_delete_item(session, xpath, SR_EDIT_DEFAULT);

    /* save changes to running */
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    /* check the change in running */
    rc = sr_get_item(session, xpath, &val);
    assert_int_not_equal(rc, SR_ERR_OK);

    /* switch to candidate */
    rc = sr_session_switch_ds(session, SR_DS_CANDIDATE);
    assert_int_equal(rc, SR_ERR_OK);

    /* check the change in candidate - the change is not yet reflected */
    rc = sr_get_item(session, xpath, &val);
    assert_int_equal(rc, SR_ERR_OK);
    sr_free_val(val);

    /* check the change after session refresh */
    rc = sr_session_refresh(session);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_get_item(session, xpath, &val);
    assert_int_not_equal(rc, SR_ERR_OK);

    rc = sr_unsubscribe(session, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);

}

#define MAX_CHANGE 10
typedef struct changes_s{
    size_t cnt;
    sr_val_t *new_values[MAX_CHANGE];
    sr_val_t *old_values[MAX_CHANGE];
    sr_change_oper_t oper[MAX_CHANGE];
}changes_t;

static int
list_changes_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t ev, void *private_ctx)
{
    changes_t *ch = (changes_t *) private_ctx;
    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;
    rc = sr_get_changes_iter(session, "/example-module:container", &it);
    puts("Iteration over changes started");
    if (SR_ERR_OK != rc) {
        puts("sr get changes iter failed");
        goto cleanup;
    }
    ch->cnt = 0;
    while (ch->cnt < MAX_CHANGE) {
        rc = sr_get_change_next(session, it,
                &ch->oper[ch->cnt],
                &ch->old_values[ch->cnt],
                &ch->new_values[ch->cnt]);
        if (SR_ERR_OK != rc) {
            break;
        }
        ch->cnt++;
    }

cleanup:
    sr_free_change_iter(it);
    return SR_ERR_OK;
}

static void
cl_get_changes_iter_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    changes_t changes = {0};
    sr_change_iter_t *iter = NULL;

    sr_val_t *val = NULL;
    const char *xpath = NULL;
    int rc = SR_ERR_OK;
    xpath = "/example-module:container/list[key1='key1'][key2='key2']/leaf";

    /* start session */
    rc = sr_session_start(conn, SR_DS_CANDIDATE, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* get changes can not be called only on notification session */
    rc = sr_get_changes_iter(session, "/example-module:container", &iter);
    assert_int_equal(rc, SR_ERR_UNSUPPORTED);

    rc = sr_module_change_subscribe(session, "example-module", list_changes_cb, &changes,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* check the list presence in candidate */
    rc = sr_get_item(session, xpath, &val);
    assert_int_equal(rc, SR_ERR_OK);
    sr_free_val(val);

    /* remove the list instance */
    rc = sr_delete_item(session, xpath, SR_EDIT_DEFAULT);

    /* save changes to running */
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    usleep(100000);

    assert_int_equal(changes.cnt, 1);
    for (size_t i = 0; i < changes.cnt; i++) {
        sr_free_val(changes.new_values[i]);
        sr_free_val(changes.old_values[i]);
    }


    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static int
empty_subtree_change_cb(sr_session_ctx_t *session, const char *xpath, sr_notif_event_t event, void *private_ctx)
{
    return SR_ERR_OK;
}

static void
cl_enable_empty_startup(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_subscription_ctx_t *subs = NULL;
    sr_session_ctx_t *sessionA = NULL;
    sr_val_t *values = NULL;
    size_t cnt = 0;

    int rc = SR_ERR_OK;

    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &sessionA);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_subtree_change_subscribe(sessionA, "/example-module:container", empty_subtree_change_cb, NULL, 0, SR_SUBSCR_DEFAULT, &subs);
    assert_int_equal(SR_ERR_OK, rc);

    /* check that value are present in running */
    rc = sr_get_items(sessionA, "/example-module:container/*", &values, &cnt);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(1, cnt);

    sr_free_values(values, cnt);

    /* delete values from startup */
    rc = sr_session_switch_ds(sessionA, SR_DS_STARTUP);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_delete_item(sessionA, "/example-module:*", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_commit(sessionA);
    assert_int_equal(SR_ERR_OK, rc);

    sr_session_stop(sessionA);

    /* enable again, verify that there are no data as well*/
    values = NULL;
    cnt = 0;

    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &sessionA);
    assert_int_equal(SR_ERR_OK, rc);


    /* data should be copied to running in case of the flags does not contain SR_SUBSCR_PASSIVE */
    rc = sr_subtree_change_subscribe(sessionA, "/example-module:container", empty_subtree_change_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &subs);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_get_items(sessionA, "/example-module:container/*", &values, &cnt);
    assert_int_equal(SR_ERR_OK, 0);
    assert_int_equal(0, cnt);

    sr_unsubscribe(sessionA, subs);
    sr_session_stop(sessionA);
}

static int
dp_get_items_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    printf("operational data for '%s' requested.\n", xpath);

    // TODO: return some real operational data
    *values = calloc(2, sizeof(**values));
    (*values)[0].xpath = strdup("/state-module:bus/gps_located");
    (*values)[0].type = SR_BOOL_T;
    (*values)[0].data.bool_val = false;
    (*values)[1].xpath = strdup("/state-module:bus/distance_travelled");
    (*values)[1].type = SR_UINT32_T;
    (*values)[1].data.uint32_val = 42;

    *values_cnt = 2;

    return SR_ERR_OK;
}

static void
cl_dp_get_items_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL, *config_only_session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;
    sr_val_t *value = NULL;

    /* start session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe as a data provider */
    rc = sr_dp_get_items_subscribe(session, "/state-module:bus", dp_get_items_cb, NULL,
            SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_get_item(session, "/state-module:bus/distance_travelled", &value);
    assert_int_equal(rc, SR_ERR_OK);

    assert_int_equal(SR_UINT32_T, value->type);
    assert_int_equal(42, value->data.uint32_val);
    sr_free_val(value);

    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_CONFIG_ONLY, &config_only_session);
    assert_int_equal(rc, SR_ERR_OK);

    /* no state data in config only session */
    rc = sr_get_item(config_only_session, "/state-module:bus/distance_travelled", &value);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

    /* data are also removed when switched to CONFIG_ONLY */
    rc = sr_session_set_options(session, SR_SESS_CONFIG_ONLY);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_get_item(session, "/state-module:bus/distance_travelled", &value);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

    /* unsubscribe */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_stop(config_only_session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_session_set_opts(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    int rc;

    rc = sr_session_start(conn, SR_DS_CANDIDATE, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_set_options(session, SR_SESS_CONFIG_ONLY);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

#define CL_TEST_EN_NUM_SESSIONS  5

typedef struct cl_test_en_cb_status_s {
    int link_discovered;
    int link_removed;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} cl_test_en_cb_status_t;

typedef struct cl_test_en_session_s {
    sr_session_ctx_t *session;
    sr_subscription_ctx_t *subscription_ld;
    sr_subscription_ctx_t *subscription_lr;
    sr_subscription_ctx_t *subscription_lo;
} cl_test_en_session_t;

static void
test_event_notif_link_discovery_cb(const char *xpath, const sr_val_t *values, const size_t values_cnt,
        void *private_ctx)
{
    cl_test_en_cb_status_t *cb_status = (cl_test_en_cb_status_t*)private_ctx;

    assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
    assert_int_equal(values_cnt, 7);

    assert_string_equal("/test-module:link-discovered", xpath);

    assert_string_equal("/test-module:link-discovered/source", values[0].xpath);
    assert_int_equal(SR_CONTAINER_T, values[0].type);
    assert_string_equal("/test-module:link-discovered/source/address", values[1].xpath);
    assert_int_equal(SR_STRING_T, values[1].type);
    assert_string_equal("10.10.1.5", values[1].data.string_val);
    assert_string_equal("/test-module:link-discovered/source/interface", values[2].xpath);
    assert_int_equal(SR_STRING_T, values[2].type);
    assert_string_equal("eth1", values[2].data.string_val);
    assert_string_equal("/test-module:link-discovered/destination", values[3].xpath);
    assert_int_equal(SR_CONTAINER_T, values[3].type);
    assert_string_equal("/test-module:link-discovered/destination/address", values[4].xpath);
    assert_int_equal(SR_STRING_T, values[4].type);
    assert_string_equal("10.10.1.8", values[4].data.string_val);
    assert_string_equal("/test-module:link-discovered/destination/interface", values[5].xpath);
    assert_int_equal(SR_STRING_T, values[5].type);
    assert_string_equal("eth0", values[5].data.string_val);
    assert_string_equal("/test-module:link-discovered/MTU", values[6].xpath);  /**< default */
    assert_int_equal(SR_UINT16_T, values[6].type);
    assert_int_equal(1500, values[6].data.uint16_val);

    cb_status->link_discovered += 1;
    if (cb_status->link_discovered == CL_TEST_EN_NUM_SESSIONS) {
        assert_int_equal(0, pthread_cond_signal(&cb_status->cond));
    }
    assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
}

static void
test_event_notif_link_removed_cb(const char *xpath, const sr_val_t *values, const size_t values_cnt,
        void *private_ctx)
{
    cl_test_en_cb_status_t *cb_status = (cl_test_en_cb_status_t*)private_ctx;

    assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
    assert_int_equal(values_cnt, 7);

    assert_string_equal("/test-module:link-removed", xpath);

    assert_string_equal("/test-module:link-removed/source", values[0].xpath);
    assert_int_equal(SR_CONTAINER_T, values[0].type);
    assert_string_equal("/test-module:link-removed/source/address", values[1].xpath);
    assert_int_equal(SR_STRING_T, values[1].type);
    assert_string_equal("10.10.2.4", values[1].data.string_val);
    assert_string_equal("/test-module:link-removed/source/interface", values[2].xpath);
    assert_int_equal(SR_STRING_T, values[2].type);
    assert_string_equal("eth0", values[2].data.string_val);
    assert_string_equal("/test-module:link-removed/destination", values[3].xpath);
    assert_int_equal(SR_CONTAINER_T, values[3].type);
    assert_string_equal("/test-module:link-removed/destination/address", values[4].xpath);
    assert_int_equal(SR_STRING_T, values[4].type);
    assert_string_equal("10.10.2.5", values[4].data.string_val);
    assert_string_equal("/test-module:link-removed/destination/interface", values[5].xpath);
    assert_int_equal(SR_STRING_T, values[5].type);
    assert_string_equal("eth2", values[5].data.string_val);
    assert_string_equal("/test-module:link-removed/MTU", values[6].xpath); /**< default */
    assert_int_equal(SR_UINT16_T, values[6].type);
    assert_int_equal(1500, values[6].data.uint16_val);

    cb_status->link_removed += 1;
    if (cb_status->link_removed == CL_TEST_EN_NUM_SESSIONS) {
        assert_int_equal(0, pthread_cond_signal(&cb_status->cond));
    }
    assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
}

static void
test_event_notif_link_overutilized_cb(const char *xpath, const sr_val_t *values, const size_t values_cnt,
        void *private_ctx)
{
    assert_true(0 && "This callback should not get called");
}

static void
cl_event_notif_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    cl_test_en_session_t sub_session[CL_TEST_EN_NUM_SESSIONS];
    sr_session_ctx_t *notif_session = NULL;
    cl_test_en_cb_status_t cb_status;
    sr_val_t values[4];
    size_t i;
    int rc = SR_ERR_OK;

    memset(&values, '\0', sizeof(values));
    cb_status.link_discovered = 0;
    cb_status.link_removed = 0;
    assert_int_equal(0, pthread_mutex_init(&cb_status.mutex, NULL));
    assert_int_equal(0, pthread_cond_init(&cb_status.cond, NULL));
    assert_int_equal(0, pthread_mutex_lock(&cb_status.mutex));

    /* start sessions */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &notif_session);
    assert_int_equal(rc, SR_ERR_OK);
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &sub_session[i].session);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* subscribe for link discovery in every session */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_event_notif_subscribe(sub_session[i].session, "/test-module:link-discovered", test_event_notif_link_discovery_cb,
                &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_ld);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* subscribe for link removal in every session */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_event_notif_subscribe(sub_session[i].session, "/test-module:link-removed", test_event_notif_link_removed_cb,
                &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_lr);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* subscribe for nonexistent notification in every session */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_event_notif_subscribe(sub_session[i].session, "/test-module:link-overutilized", test_event_notif_link_overutilized_cb,
                    &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_lo);
        assert_int_equal(rc, SR_ERR_OK); /**< not verified at this stage */
    }

    /* send event notification - link discovery */
    values[0].xpath = "/test-module:link-discovered/source/address";
    values[0].type = SR_STRING_T;
    values[0].data.string_val = "10.10.1.5";
    values[1].xpath = "/test-module:link-discovered/source/interface";
    values[1].type = SR_STRING_T;
    values[1].data.string_val = "eth1";
    values[2].xpath = "/test-module:link-discovered/destination/address";
    values[2].type = SR_STRING_T;
    values[2].data.string_val = "10.10.1.8";
    values[3].xpath = "/test-module:link-discovered/destination/interface";
    values[3].type = SR_STRING_T;
    values[3].data.string_val = "eth0";

    rc = sr_event_notif_send(notif_session, "/test-module:link-discovered", values, 4);
    assert_int_equal(rc, SR_ERR_OK);

    /* send event notification - link removal */
    values[0].xpath = "/test-module:link-removed/source/address";
    values[0].type = SR_STRING_T;
    values[0].data.string_val = "10.10.2.4";
    values[1].xpath = "/test-module:link-removed/source/interface";
    values[1].type = SR_STRING_T;
    values[1].data.string_val = "eth0";
    values[2].xpath = "/test-module:link-removed/destination/address";
    values[2].type = SR_STRING_T;
    values[2].data.string_val = "10.10.2.5";
    values[3].xpath = "/test-module:link-removed/destination/interface";
    values[3].type = SR_STRING_T;
    values[3].data.string_val = "eth2";

    rc = sr_event_notif_send(notif_session, "/test-module:link-removed", values, 4);
    assert_int_equal(rc, SR_ERR_OK);

    /* send event notification - link overutilized (not defined in yang) */
    values[0].xpath = "/test-module:link-overutilized/source/address";
    values[0].type = SR_STRING_T;
    values[0].data.string_val = "10.10.1.5";
    values[1].xpath = "/test-module:link-overutilized/source/interface";
    values[1].type = SR_STRING_T;
    values[1].data.string_val = "eth1";
    values[2].xpath = "/test-module:link-overutilized/destination/address";
    values[2].type = SR_STRING_T;
    values[2].data.string_val = "10.10.1.8";
    values[3].xpath = "/test-module:link-overutilized/destination/interface";
    values[3].type = SR_STRING_T;
    values[3].data.string_val = "eth0";

    rc = sr_event_notif_send(notif_session, "/test-module:link-overutilized", values, 4);
    assert_int_equal(rc, SR_ERR_BAD_ELEMENT);

    /* wait at most 5 seconds for all callbacks to get called */
    struct timespec ts;
    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += 5;
    while (ETIMEDOUT != pthread_cond_timedwait(&cb_status.cond, &cb_status.mutex, &ts)
            && (cb_status.link_removed < CL_TEST_EN_NUM_SESSIONS || cb_status.link_discovered < CL_TEST_EN_NUM_SESSIONS));
    assert_int_equal(CL_TEST_EN_NUM_SESSIONS, cb_status.link_discovered);
    assert_int_equal(CL_TEST_EN_NUM_SESSIONS, cb_status.link_removed);
    assert_int_equal(0, pthread_mutex_unlock(&cb_status.mutex));

    /* unsubscribe */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_ld);
        assert_int_equal(rc, SR_ERR_OK);
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_lr);
        assert_int_equal(rc, SR_ERR_OK);
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_lo);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* stop sessions */
    rc = sr_session_stop(notif_session);
    assert_int_equal(rc, SR_ERR_OK);
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_session_stop(sub_session[i].session);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* cleanup */
    assert_int_equal(0, pthread_mutex_destroy(&cb_status.mutex));
    assert_int_equal(0, pthread_cond_destroy(&cb_status.cond));
}

int
main()
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(cl_connection_test, logging_setup, NULL),
            cmocka_unit_test_setup_teardown(cl_list_schemas_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_get_schema_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_get_item_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_get_items_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_get_items_iter_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_set_item_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_delete_item_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_move_item_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_validate_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_commit_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_discard_changes_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_locking_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_get_error_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_refresh_session, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_refresh_session2, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_notification_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_copy_config_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_copy_config_test2, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_rpc_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_rpc_tree_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(candidate_ds_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_switch_ds, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_candidate_refresh, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_get_changes_iter_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_enable_empty_startup, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_dp_get_items_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_session_set_opts, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_event_notif_test, sysrepo_setup, sysrepo_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
