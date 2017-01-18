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
#include <signal.h>
#include <fcntl.h>

#include "sr_constants.h"
#include "sysrepo.h"
#include "client_library.h"

#include "sr_common.h"
#include "test_module_helper.h"
#include "system_helper.h"

#define COND_WAIT_SEC 5

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
    createDataTreeReferencedModule(17);
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

static int
empty_module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    return SR_ERR_OK;
}

/**
 * @brief Check size of a linked-list.
 */
static size_t
sr_node_t_get_children_cnt(const sr_node_t *node)
{
    size_t size = 0;
    const sr_node_t *child = node->first_child;

    while (child) {
        ++size;
        child = child->next;
    }
    return size;
}

/**
 * @brief Get node child at a given index.
 */
static sr_node_t *
sr_node_t_get_child(const sr_node_t *node, size_t index)
{
    size_t i = 0;
    sr_node_t *child = (sr_node_t *)node->first_child;

    while (child) {
        if (index == i) {
            return child;
        }
        ++i;
        child = child->next;
    }
    assert_true(false && "index out of range");
    return NULL;
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
cl_multiconnect_test(void **state)
{
    sr_conn_ctx_t *conn1 = NULL, *conn2 = NULL;
    sr_session_ctx_t *sess1 = NULL, *sess2 = NULL;
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

    /* start a new session in conn 2 */
    rc = sr_session_start(conn2, SR_DS_STARTUP, SR_SESS_DEFAULT, &sess2);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(sess2);

    /* try session_data_refresh in both sessions */
    rc = sr_session_refresh(sess1);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_refresh(sess2);
    assert_int_equal(rc, SR_ERR_OK);

    /* disconnect from sysrepo - conn 1 */
    sr_disconnect(conn1);

    /* try session_data_refresh via conn2 - should still work */
    rc = sr_session_refresh(sess2);
    assert_int_equal(rc, SR_ERR_OK);

    /* disconnect from sysrepo - conn 2 */
    sr_disconnect(conn2);
}

static void
cl_disconnect_test(void **state)
{
    /* used to retrieve fd from conn_ctx */
    typedef struct test_sr_conn_ctx_s {
        int fd;
    } test_sr_conn_ctx_t;

    sr_conn_ctx_t *conn = NULL;
    sr_session_ctx_t *sess = NULL;
    int pipefd[2] = { -1, -1 };
    int fd_to_close = -1;
    int rc = 0;

    signal(SIGPIPE, SIG_IGN); /* ignore sigpipe */

    /* connect to sysrepo */
    rc = sr_connect("cl_test", SR_CONN_DEFAULT, &conn);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(conn);

    /* start a new session in the connection */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &sess);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(sess);

    /* check the session - should be OK */
    rc = sr_session_check(sess);
    assert_int_equal(rc, SR_ERR_OK);

    /* close the socket to the server and replace it with pipe */
    fd_to_close = ((test_sr_conn_ctx_t*)conn)->fd;
    printf("fd %d will be closed\n", fd_to_close);
    close(fd_to_close);
    pipe(pipefd);
    if (fd_to_close == pipefd[0]) {
        close(pipefd[1]);
    } else {
        assert_int_equal(fd_to_close, pipefd[0]);
        close(pipefd[0]);
    }

    /* try session_data_refresh - should fail with SR_ERR_DISCONNECT */
    rc = sr_session_refresh(sess);
    assert_int_equal(rc, SR_ERR_DISCONNECT);

    /* check the session - should be DISCONNECTED */
    rc = sr_session_check(sess);
    assert_int_equal(rc, SR_ERR_DISCONNECT);

    /* reconnect */
    sr_disconnect(conn);
    rc = sr_connect("cl_test", SR_CONN_DEFAULT, &conn);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(conn);

    /* start a new session in the new connection */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &sess);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(sess);

    /* try session_data_refresh */
    rc = sr_session_refresh(sess);
    assert_int_equal(rc, SR_ERR_OK);

    /* disconnect from sysrepo */
    sr_disconnect(conn);
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

    /* empty data tree */
    rc = sr_get_item(session, "/small-module:item/name", &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

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
cl_get_subtree_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_node_t *tree = NULL, *subtree = NULL;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform a get-subtree request */

    /* illegal xpath */
    rc = sr_get_subtree(session, "^&((", 0, &tree);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);
    assert_null(tree);

    /* unknown model */
    rc = sr_get_subtree(session, "/unknown-model:abc", 0, &tree);
    assert_int_equal(SR_ERR_UNKNOWN_MODEL, rc);
    assert_null(tree);

    /* empty data tree */
    rc = sr_get_subtree(session, "/small-module:item/name", 0, &tree);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* bad element in existing module returns SR_ERR_NOT_FOUND instead of SR_ERR_BAD_ELEMENT*/
    rc = sr_get_subtree(session, "/example-module:unknown/next", 0, &tree);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    assert_null(tree);

    /* existing leaf */
    rc = sr_get_subtree(session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", 0, &tree);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(tree);
    assert_string_equal("leaf", tree->name);
    assert_string_equal("example-module", tree->module_name);
    assert_int_equal(SR_STRING_T, tree->type);
    assert_string_equal("Leaf value", tree->data.string_val);
    assert_null(tree->first_child);
    sr_free_tree(tree);

    /* container */
    rc = sr_get_subtree(session, "/example-module:container", 0, &tree);
    assert_int_equal(rc, SR_ERR_OK);
    // container
    assert_non_null(tree);
    assert_string_equal("container", tree->name);
    assert_string_equal("example-module", tree->module_name);
    assert_int_equal(SR_CONTAINER_T, tree->type);
    assert_false(tree->dflt);
    assert_null(tree->next);
    assert_null(tree->prev);
    // list
    subtree = tree->first_child;
    assert_non_null(subtree);
    assert_string_equal("list", subtree->name);
    assert_null(subtree->module_name);
    assert_int_equal(SR_LIST_T, subtree->type);
    assert_false(subtree->dflt);
    assert_null(subtree->next);
    // key1
    subtree = subtree->first_child;
    assert_non_null(subtree);
    assert_string_equal("key1", subtree->name);
    assert_null(subtree->module_name);
    assert_int_equal(SR_STRING_T, subtree->type);
    assert_string_equal("key1", subtree->data.string_val);
    assert_false(subtree->dflt);
    assert_null(subtree->first_child);
    // key2
    subtree = subtree->next;
    assert_non_null(subtree);
    assert_string_equal("key2", subtree->name);
    assert_null(subtree->module_name);
    assert_int_equal(SR_STRING_T, subtree->type);
    assert_string_equal("key2", subtree->data.string_val);
    assert_false(subtree->dflt);
    assert_null(subtree->first_child);
    // leaf
    subtree = subtree->next;
    assert_non_null(subtree);
    assert_string_equal("leaf", subtree->name);
    assert_null(subtree->module_name);
    assert_int_equal(SR_STRING_T, subtree->type);
    assert_string_equal("Leaf value", subtree->data.string_val);
    assert_false(subtree->dflt);
    assert_null(subtree->first_child);
    assert_null(subtree->next);
    sr_free_tree(tree);

    /* list */
    rc = sr_get_subtree(session, "/example-module:container/list[key1='key1'][key2='key2']", 0, &tree);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(tree);
    // list
    assert_string_equal("list", tree->name);
    assert_string_equal("example-module", tree->module_name);
    assert_int_equal(SR_LIST_T, tree->type);
    assert_false(tree->dflt);
    assert_null(tree->next);
    assert_null(tree->prev);
    assert_null(tree->parent);
    // key1
    subtree = tree->first_child;
    assert_non_null(subtree);
    assert_string_equal("key1", subtree->name);
    assert_null(subtree->module_name);
    assert_int_equal(SR_STRING_T, subtree->type);
    assert_string_equal("key1", subtree->data.string_val);
    assert_false(subtree->dflt);
    assert_null(subtree->first_child);
    // key2
    subtree = subtree->next;
    assert_non_null(subtree);
    assert_string_equal("key2", subtree->name);
    assert_null(subtree->module_name);
    assert_int_equal(SR_STRING_T, subtree->type);
    assert_string_equal("key2", subtree->data.string_val);
    assert_false(subtree->dflt);
    assert_null(subtree->first_child);
    // leaf
    subtree = subtree->next;
    assert_non_null(subtree);
    assert_string_equal("leaf", subtree->name);
    assert_null(subtree->module_name);
    assert_int_equal(SR_STRING_T, subtree->type);
    assert_string_equal("Leaf value", subtree->data.string_val);
    assert_false(subtree->dflt);
    assert_null(subtree->first_child);
    assert_null(subtree->next);
    sr_free_tree(tree);

    /* leafref (transparent for user) */
    rc = sr_get_subtree(session, "/test-module:university/classes/class[title='CCNA']/student[name='nameB']/age", 0, &tree);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(tree);
    assert_string_equal("age", tree->name);
    assert_string_equal("test-module", tree->module_name);
    assert_int_equal(SR_UINT8_T, tree->type);
    assert_int_equal(17, tree->data.uint8_val);
    sr_free_tree(tree);

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

    /* empty data tree */
    rc = sr_get_items(session, "/small-module:item/name", &values, &values_cnt);
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
cl_get_subtrees_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    createDataTreeIETFinterfacesModule();
    sr_session_ctx_t *session = NULL;
    sr_node_t *trees = NULL;
    size_t tree_cnt = 0;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(session);

    /* perform a get-subtrees request */

    /* illegal xpath */
    rc = sr_get_subtrees(session, "^&((",  0, &trees, &tree_cnt);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* unknown model */
    rc = sr_get_subtrees(session, "/unknown-model:abc", 0, &trees, &tree_cnt);
    assert_int_equal(SR_ERR_UNKNOWN_MODEL, rc);

    /* empty data tree */
    rc = sr_get_subtrees(session, "/small-module:item/name", 0, &trees, &tree_cnt);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* bad element in existing module produces SR_ERR_NOT_FOUND instead of SR_ERR_BAD_ELEMENT */
    rc = sr_get_subtrees(session, "/example-module:unknown", 0, &trees, &tree_cnt);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* container */
    rc = sr_get_subtrees(session, "/ietf-interfaces:interfaces/*", 0, &trees, &tree_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(3, tree_cnt);
    sr_free_trees(trees, tree_cnt);

    /* list without keys */
    rc = sr_get_subtrees(session, "/ietf-interfaces:interfaces/interface", 0, &trees, &tree_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(3, tree_cnt);
    sr_free_trees(trees, tree_cnt);

    /* list with keys */
    rc = sr_get_subtrees(session, "/ietf-interfaces:interfaces/interface[name='eth0']/*", 0, &trees, &tree_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(5, tree_cnt);
    sr_free_trees(trees, tree_cnt);

    /* leaf-list*/
    rc = sr_get_subtrees(session, "/test-module:main/numbers", 0, &trees, &tree_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(3, tree_cnt);
    sr_free_trees(trees, tree_cnt);

    /* leafrefs */
    rc = sr_get_subtrees(session, "/test-module:university/classes/class[title='CCNA']/student[name='nameB']/*", 0, &trees, &tree_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(2, tree_cnt);
    sr_free_trees(trees, tree_cnt);

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

    /* empty data tree */
    rc = sr_get_items_iter(session, "/small-module:item/name", &it);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(it);

    rc = sr_get_item_next(session, it, &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
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
        else if (0 == strcmp(XP_TEST_MODULE_ANYXML, value->xpath)){
            assert_int_equal(SR_ANYXML_T, value->type);
        }
        else if (0 == strcmp(XP_TEST_MODULE_ANYDATA, value->xpath)){
            assert_int_equal(SR_ANYDATA_T, value->type);
        }
        else if (0 == strcmp(XP_TEST_MODULE_INSTANCE_ID, value->xpath)){
            assert_int_equal(SR_INSTANCEID_T, value->type);
            assert_string_equal(XP_TEST_MODULE_INSTANCE_ID_VALUE, value->data.instanceid_val);
        }
        else {
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

/**
 * @brief Traverses through at most visited_limit nodes of a given tree and counts visited iterators.
 */
static int
cl_tree_traversal(sr_session_ctx_t *session, sr_node_t *tree, size_t visited_limit, size_t *visited_iter)
{
    sr_node_t *node = NULL, *child = NULL, *next = NULL;
    size_t nodes_cnt = 0;
    bool backtrack = false;

    CHECK_NULL_ARG3(session, tree, visited_iter);
    *visited_iter = 0;

    node = tree;
    do { /**< traverse in DFS pre-order */
        if (false == backtrack) {
            ++nodes_cnt;
            if (visited_limit <= nodes_cnt) {
                break;
            }
            if (node->first_child && SR_TREE_ITERATOR_T == node->first_child->type) {
                *visited_iter += 1;
            }
            child = sr_node_get_child(session, node);
            if (NULL == child) {
                backtrack = true;
            } else {
                node = child;
            }
        } else {
            if (node->next && SR_TREE_ITERATOR_T == node->next->type) {
                *visited_iter += 1;
            }
            next = sr_node_get_next_sibling(session, node);
            if (next) {
                node = next;
                backtrack = false;
            } else {
                node = sr_node_get_parent(session, node);
                assert(node);
                backtrack = true;
            }
        }
    } while (node != tree);

    return SR_ERR_OK;
}

static void
cl_iterative_tree_traversal(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_node_t *tree = NULL, *tree_dup = NULL;
    size_t visited_iter = 0;
    int rc = 0;

    createDataTreeLargeIETFinterfacesModule(25);

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform an iterative get-subtree request */
    rc = sr_get_subtree(session, "/ietf-interfaces:interfaces", SR_GET_SUBTREE_ITERATIVE, &tree);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(tree);

    /* go the the 3rd level (one more chunk will get fetched) */
    rc = cl_tree_traversal(session, tree, 3, &visited_iter);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(visited_iter, 1);

    /* duplicate the partly loaded tree */
    rc = sr_dup_tree(tree, &tree_dup);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(tree_dup);
    sr_free_tree(tree);
    tree = tree_dup;

    /* go the the 3rd level again (all needed chunks are already fetched) */
    rc = cl_tree_traversal(session, tree, 3, &visited_iter);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(visited_iter, 0);

    /* traverse through one interface (one more chunk will get fetched) */
    rc = cl_tree_traversal(session, tree, 12, &visited_iter);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(visited_iter, 1);

    /* traverse up to the addr list instance of the second interface (this was retrieved by the second chunk) */
    rc = cl_tree_traversal(session, tree, 16, &visited_iter);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(visited_iter, 0);

    /* traverse through the first and second interface (one more chunk will get fetched) */
    rc = cl_tree_traversal(session, tree, 23, &visited_iter);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(visited_iter, 1);

    /* duplicate the partly loaded tree */
    rc = sr_dup_tree(tree, &tree_dup);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(tree_dup);
    sr_free_tree(tree);
    tree = tree_dup;

    /**
     * traverse through the entire tree
     *  - need to get the content of addr for interfaces 3-20
     *  - need to get the top 2 levels of last 5 interfaces
     *  - need to get the content of ipv4 for interfaces 21-25
     */
    rc = cl_tree_traversal(session, tree, SIZE_MAX, &visited_iter);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(visited_iter, 18+1+5);

    sr_free_tree(tree);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_iterative_trees_traversal(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_node_t *trees = NULL, *trees_dup = NULL;
    size_t tree_cnt = 0, visited_iter = 0, i = 0;
    int rc = 0;

    createDataTreeLargeIETFinterfacesModule(50);

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform an iterative get-subtrees request */
    rc = sr_get_subtrees(session, "/ietf-interfaces:interfaces/*", SR_GET_SUBTREE_ITERATIVE, &trees, &tree_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(trees);
    assert_int_equal(50, tree_cnt);

    /* go the the 2rd level on each tree (all needed data are fetched) */
    for (i = 0; i < 50; ++i) {
        rc = cl_tree_traversal(session, trees+i, 3, &visited_iter); /* interface, name, ipv4 */
        assert_int_equal(SR_ERR_OK, rc);
        assert_int_equal(visited_iter, 0);
    }

    /* go the the 3rd level in the first half of the trees (they will get fully fetched) */
    for (i = 0; i < 25; ++i) {
        rc = cl_tree_traversal(session, trees+i, 4, &visited_iter); /* interface, name, ipv4, addr */
        assert_int_equal(SR_ERR_OK, rc);
        assert_int_equal(visited_iter, 1);
    }

    /* duplicate the partly loaded trees */
    rc = sr_dup_trees(trees, tree_cnt, &trees_dup);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(trees_dup);
    sr_free_trees(trees, tree_cnt);
    trees = trees_dup;

    /* completely traverse through the first half of the trees (all data already loaded) */
    for (i = 0; i < 25; ++i) {
        rc = cl_tree_traversal(session, trees+i, SIZE_MAX, &visited_iter);
        assert_int_equal(SR_ERR_OK, rc);
        assert_int_equal(visited_iter, 0);
    }

    /**
     * traverse through the entire forest
     *  - need to get one chunk (3rd and 4rd level) for the second half of the trees
     */
    for (i = 0; i < 50; ++i) {
        rc = cl_tree_traversal(session, trees+i, SIZE_MAX, &visited_iter);
        assert_int_equal(SR_ERR_OK, rc);
        assert_int_equal(visited_iter, i < 25 ? 0 : 1);
    }

    sr_free_trees(trees, tree_cnt);

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

    value.type = SR_STRING_T;
    value.data.string_val = "disabled";

    rc = sr_set_item(session, "/test-module:tpdfs/unival", &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    value.type = SR_UINT8_T;
    value.data.uint8_val = 42;

    rc = sr_set_item(session, "/test-module:tpdfs/unival", &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    value.type = SR_UINT8_T;
    value.data.uint8_val = 42;

    rc = sr_set_item(session, "/test-module:tpdfs/intval", &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    value.type = SR_STRING_T;
    value.data.string_val = "k1";

    rc = sr_set_item(session, "/test-module:tpdfs/leafrefval", &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    value.type = SR_DECIMAL64_T;
    value.data.decimal64_val = 42.42;

    rc = sr_set_item(session, "/test-module:tpdfs/undecided", &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    value.type = SR_BOOL_T;
    value.data.bool_val = false;

    rc = sr_set_item(session, "/test-module:tpdfs/undecided", &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    value.type = SR_ENUM_T;
    value.data.enum_val = "a";

    rc = sr_set_item(session, "/test-module:tpdfs/undecided", &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    value.type = SR_INSTANCEID_T;
    value.data.instanceid_val = "/test-module:main";

    rc = sr_set_item(session, "/test-module:main/instance_id", &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_set_item_str_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_val_t *v = NULL;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform a set-item request */
    rc = sr_set_item_str(session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", "abcdef", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_get_item(session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &v);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(v);
    assert_int_equal(SR_STRING_T, v->type);
    assert_string_equal("abcdef", v->data.string_val);
    sr_free_val(v);

    /* with union first matched type is use */
    rc = sr_set_item_str(session, "/test-module:tpdfs/unival", "42", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_get_item(session, "/test-module:tpdfs/unival", &v);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(v);
    assert_int_equal(SR_UINT8_T, v->type);
    assert_int_equal(42, v->data.uint8_val);
    sr_free_val(v);

    rc = sr_set_item_str(session, "/test-module:main/dec64", "-42.56", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_set_item_str(session, "/test-module:user[name='abc']", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_set_item_str(session, "/test-module:user[name='unknown']/full-name", "Unknown user", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* commit */
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    /* incorrect value */
    rc = sr_set_item_str(session, "/test-module:main/i8", "abcd", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_INVAL_ARG);

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

    /* leafref: non-existing leaf */
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
    assert_int_equal(SR_ERR_OK, rc);

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
    assert_int_equal(SR_ERR_OK, rc);

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
    assert_int_equal(SR_ERR_OK, rc);

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
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_validate(session);
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
    assert_int_equal(rc, SR_ERR_OK);

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
cl_ds_locking_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *sessionA = NULL, *sessionB = NULL;
    int rc = 0;

    /* start 2 sessions */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &sessionA);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &sessionB);
    assert_int_equal(rc, SR_ERR_OK);

    /* lock startup */
    rc = sr_lock_datastore(sessionA);
    assert_int_equal(rc, SR_ERR_OK);

    /* lock running */
    rc = sr_lock_datastore(sessionB);
    assert_int_equal(rc, SR_ERR_OK);

    /* switch and lock candidate*/
    rc = sr_unlock_datastore(sessionA);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_switch_ds(sessionA, SR_DS_CANDIDATE);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_lock_datastore(sessionA);
    assert_int_equal(rc, SR_ERR_OK);

    /* try to lock candidate from different session*/
    rc = sr_session_switch_ds(sessionB, SR_DS_CANDIDATE);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_lock_datastore(sessionB);
    assert_int_equal(rc, SR_ERR_LOCKED);

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
test_module_install_cb(const char *module_name, const char *revision, sr_module_state_t state, void *private_ctx)
{
    int *callback_called = (int*)private_ctx;
    *callback_called += 1;
    printf("Module '%s' revision '%s' has been %s.\n", module_name, revision, sr_module_state_sr_to_str(state));
}

typedef struct cl_module_state_s {
    char *module_name;
    char *revision;
    sr_module_state_t state;
} cl_module_state_t;

static void
test_module_install_state_cb(const char *module_name, const char *revision, sr_module_state_t state, void *private_ctx)
{
    sr_list_t *list = (sr_list_t *)private_ctx;

    cl_module_state_t *module_state = calloc(1, sizeof *module_state);
    assert_non_null(module_state);
    module_state->module_name = module_name ? strdup(module_name) : NULL;
    module_state->revision = revision ? strdup(revision) : NULL;
    module_state->state = state;

    assert_int_equal(SR_ERR_OK, sr_list_add(list, module_state));
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

    skip_if_daemon_running(); /* module uninstall & install requires restart of the Sysrepo Engine */

    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    volatile int callback_called = 0;
    sr_val_t value = { 0, };
    sr_list_t *module_states = NULL;
    int rc = SR_ERR_OK;
    cl_module_state_t *module_state = NULL;
    char example_module_path[PATH_MAX] = {0}, test_module_path[PATH_MAX] = {0};
    char cross_module_path[PATH_MAX] = {0}, referenced_data_path[PATH_MAX] = {0};

    snprintf(example_module_path, PATH_MAX, "%s%s.yang", SR_SCHEMA_SEARCH_DIR, "example-module");
    snprintf(test_module_path, PATH_MAX, "%s%s.yang", SR_SCHEMA_SEARCH_DIR, "test-module");
    snprintf(cross_module_path, PATH_MAX, "%s%s.yang", SR_SCHEMA_SEARCH_DIR, "cross-module");
    snprintf(referenced_data_path, PATH_MAX, "%s%s.yang", SR_SCHEMA_SEARCH_DIR, "referenced-data");

    assert_int_equal(SR_ERR_OK, sr_list_init(&module_states));

    /* start a session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe to some notifications */
    rc = sr_module_install_subscribe(session, test_module_install_cb, (void*)&callback_called, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_install_subscribe(session, test_module_install_state_cb, module_states, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_feature_enable_subscribe(session, test_feature_enable_cb, (void*)&callback_called, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "example-module", test_module_change_cb, (void*)&callback_called,
            0, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_subtree_change_subscribe(session, "/example-module:container/list", test_subtree_change_cb, (void*)&callback_called,
            0, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* do some changes */
    rc = sr_module_install(session, "example-module", NULL, example_module_path, false);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_install(session, "example-module", NULL, example_module_path, true);
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
        if (callback_called >= 8) break;
        usleep(10000); /* 10 ms */
    }
    assert_true(callback_called == 8);
    callback_called = 0;

    /* some negative tests */
    rc = sr_feature_enable(session, "unknown-module", "unknown", true);
    assert_int_equal(rc, SR_ERR_UNKNOWN_MODEL);

    rc = sr_feature_enable(session, "example-module", "unknown", true);
    assert_int_equal(rc, SR_ERR_INVAL_ARG);

    rc = sr_module_install(session, "example-module", "2016-05-03", example_module_path, false);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

    rc = sr_module_install(session, "example-module", NULL, example_module_path, false);
    assert_int_equal(rc, SR_ERR_OK);

    /* after module uninstallation all subsequent operation return UNKOWN_MODEL */
    rc = sr_lock_module(session, "example-module");
    assert_int_equal(rc, SR_ERR_UNKNOWN_MODEL);

    /* install module back */
    rc = sr_module_install(session, "example-module", NULL, example_module_path, true);
    assert_int_equal(rc, SR_ERR_OK);

    /* uninstall test-module, cross-module && referenced-data */
    rc = sr_module_install(session, "test-module", NULL, test_module_path, false);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_module_install(session, "cross-module", NULL, cross_module_path, false);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_module_install(session, "referenced-data", NULL, referenced_data_path, false);
    assert_int_equal(rc, SR_ERR_OK);

    /* install test-module; referenced-data will get only imported */
    rc = sr_module_install(session, "test-module", NULL, test_module_path, true);
    assert_int_equal(rc, SR_ERR_OK);

    /* install cross-module; referenced-data is already imported */
    rc = sr_module_install(session, "cross-module", NULL, cross_module_path, true);
    assert_int_equal(rc, SR_ERR_OK);

    /* uninstall test-module; referenced-data should remain imported */
    rc = sr_module_install(session, "test-module", NULL, test_module_path, false);
    assert_int_equal(rc, SR_ERR_OK);

    /* uninstall cross-module; referenced-data should be automatically uninstalled */
    rc = sr_module_install(session, "cross-module", NULL, cross_module_path, false);
    assert_int_equal(rc, SR_ERR_OK);

    /* wait for all remaining callbacks or timeout after 10 seconds */
    for (size_t i = 0; i < 1000; i++) {
        if (callback_called >= 11 && module_states->count >= 13) break;
        usleep(10000); /* 10 ms */
    }
    assert_int_equal(11, callback_called);
    assert_int_equal(13, module_states->count);

    /* check callback parameters */
    for (int i = 0; i < 13; ++i) {
        module_state = (cl_module_state_t *)module_states->data[i];
        switch (i) {
            case 0:
                assert_string_equal("example-module", module_state->module_name);
                assert_null(module_state->revision);
                assert_int_equal(SR_MS_UNINSTALLED, module_state->state);
                break;
            case 1:
                assert_string_equal("example-module", module_state->module_name);
                assert_null(module_state->revision);
                assert_int_equal(SR_MS_IMPLEMENTED, module_state->state);
                break;
            case 2:
                assert_string_equal("example-module", module_state->module_name);
                assert_null(module_state->revision);
                assert_int_equal(SR_MS_UNINSTALLED, module_state->state);
                break;
            case 3:
                assert_string_equal("example-module", module_state->module_name);
                assert_null(module_state->revision);
                assert_int_equal(SR_MS_IMPLEMENTED, module_state->state);
                break;
            case 4:
                assert_string_equal("test-module", module_state->module_name);
                assert_null(module_state->revision);
                assert_int_equal(SR_MS_UNINSTALLED, module_state->state);
                break;
            case 5:
                assert_string_equal("cross-module", module_state->module_name);
                assert_null(module_state->revision);
                assert_int_equal(SR_MS_UNINSTALLED, module_state->state);
                break;
            case 6:
                assert_string_equal("referenced-data", module_state->module_name);
                assert_null(module_state->revision);
                assert_int_equal(SR_MS_UNINSTALLED, module_state->state);
                break;
            case 7:
                assert_string_equal("test-module", module_state->module_name);
                assert_null(module_state->revision);
                assert_int_equal(SR_MS_IMPLEMENTED, module_state->state);
                break;
            case 8:
                assert_string_equal("referenced-data", module_state->module_name);
                assert_null(module_state->revision);
                assert_int_equal(SR_MS_IMPORTED, module_state->state);
                break;
            case 9:
                assert_string_equal("cross-module", module_state->module_name);
                assert_null(module_state->revision);
                assert_int_equal(SR_MS_IMPLEMENTED, module_state->state);
                break;
            case 10:
                assert_string_equal("test-module", module_state->module_name);
                assert_null(module_state->revision);
                assert_int_equal(SR_MS_UNINSTALLED, module_state->state);
                break;
            case 11:
                assert_string_equal("cross-module", module_state->module_name);
                assert_null(module_state->revision);
                assert_int_equal(SR_MS_UNINSTALLED, module_state->state);
                break;
            case 12:
                assert_string_equal("referenced-data", module_state->module_name);
                assert_null(module_state->revision);
                assert_int_equal(SR_MS_UNINSTALLED, module_state->state);
                break;
            default:
                assert_true(false);
                break;

        }
        free(module_state->module_name);
        free(module_state->revision);
        free(module_state);
    }
    sr_list_cleanup(module_states);

    /* unsubscribe */
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
            &callback_called, 0, SR_SUBSCR_DEFAULT | SR_SUBSCR_APPLY_ONLY, &subscription);
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
            &callback_called, 0, SR_SUBSCR_DEFAULT | SR_SUBSCR_APPLY_ONLY, &subscription);
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

    *output_cnt = 6;
    *output = calloc(*output_cnt, sizeof(**output));
    (*output)[0].xpath = strdup("/test-module:activate-software-image/status");
    (*output)[0].type = SR_STRING_T;
    (*output)[0].data.string_val = strdup("The image acmefw-2.3 is being installed.");
    (*output)[1].xpath = strdup("/test-module:activate-software-image/version");
    (*output)[1].type = SR_STRING_T;
    (*output)[1].data.string_val = strdup("2.3");
    (*output)[2].xpath = strdup("/test-module:activate-software-image/init-log/"
                                "log-msg[msg='Successfully loaded software image.'][time='1469625110']/msg-type");
    (*output)[2].type = SR_ENUM_T;
    (*output)[2].data.enum_val = strdup("debug");

    /* explictly create list - not necessary - list will be automatically created when any of its inner node is created */
    (*output)[3].xpath = strdup("/test-module:activate-software-image/init-log/"
                                "log-msg[msg='Successfully loaded software image.'][time='1469625110']");
    (*output)[3].type = SR_LIST_T;
    /* explictly create list key - redundant only for test purposes*/
    (*output)[4].xpath = strdup("/test-module:activate-software-image/init-log/"
                                "log-msg[msg='Successfully loaded software image.'][time='1469625110']/msg");
    (*output)[4].type = SR_STRING_T;
    (*output)[4].data.string_val = strdup("Successfully loaded software image.");


    (*output)[5].xpath = strdup("/test-module:activate-software-image/init-log/"
                                "log-msg[msg='Some soft limit exceeded...'][time='1469625150']/msg-type");
    (*output)[5].type = SR_ENUM_T;
    (*output)[5].data.enum_val = strdup("warning");

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
    assert_int_equal(1, callback_called);

    /* check output */
    assert_int_equal(12, output_cnt);
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

    assert_string_equal("/test-module:activate-software-image/init-log", output[3].xpath);
    assert_false(output[3].dflt);
    assert_int_equal(SR_CONTAINER_T, output[3].type);
    assert_string_equal("/test-module:activate-software-image/init-log/"
                        "log-msg[msg='Successfully loaded software image.'][time='1469625110']", output[4].xpath);
    assert_false(output[4].dflt);
    assert_int_equal(SR_LIST_T, output[4].type);
    assert_string_equal("/test-module:activate-software-image/init-log/"
                        "log-msg[msg='Successfully loaded software image.'][time='1469625110']/msg", output[5].xpath);
    assert_false(output[5].dflt);
    assert_int_equal(SR_STRING_T, output[5].type);
    assert_string_equal("Successfully loaded software image.", output[5].data.string_val);
    assert_string_equal("/test-module:activate-software-image/init-log/"
                        "log-msg[msg='Successfully loaded software image.'][time='1469625110']/time", output[6].xpath);
    assert_false(output[6].dflt);
    assert_int_equal(SR_UINT32_T, output[6].type);
    assert_int_equal(1469625110, output[6].data.uint32_val);
    assert_string_equal("/test-module:activate-software-image/init-log/"
                        "log-msg[msg='Successfully loaded software image.'][time='1469625110']/msg-type", output[7].xpath);
    assert_false(output[7].dflt);
    assert_int_equal(SR_ENUM_T, output[7].type);
    assert_string_equal("debug", output[7].data.enum_val);
    assert_string_equal("/test-module:activate-software-image/init-log/"
                        "log-msg[msg='Some soft limit exceeded...'][time='1469625150']", output[8].xpath);
    assert_false(output[8].dflt);
    assert_int_equal(SR_LIST_T, output[8].type);
    assert_string_equal("/test-module:activate-software-image/init-log/"
                        "log-msg[msg='Some soft limit exceeded...'][time='1469625150']/msg", output[9].xpath);
    assert_false(output[9].dflt);
    assert_int_equal(SR_STRING_T, output[9].type);
    assert_string_equal("Some soft limit exceeded...", output[9].data.string_val);
    assert_string_equal("/test-module:activate-software-image/init-log/"
                        "log-msg[msg='Some soft limit exceeded...'][time='1469625150']/time", output[10].xpath);
    assert_false(output[10].dflt);
    assert_int_equal(SR_UINT32_T, output[10].type);
    assert_int_equal(1469625150, output[10].data.uint32_val);
    assert_string_equal("/test-module:activate-software-image/init-log/"
                        "log-msg[msg='Some soft limit exceeded...'][time='1469625150']/msg-type", output[11].xpath);
    assert_false(output[11].dflt);
    assert_int_equal(SR_ENUM_T, output[11].type);
    assert_string_equal("warning", output[11].data.enum_val);

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
    sr_node_t *sr_out_node = NULL, *child = NULL;
    int *callback_called = (int*)private_ctx;
    *callback_called += 1;

    /* check input */
    assert_int_equal(2, input_cnt);
    /*   /test-module:activate-software-image/input/image-name */
    sr_in_node = input;
    assert_string_equal("image-name", sr_in_node->name);
    assert_string_equal("test-module", sr_in_node->module_name);
    assert_false(sr_in_node->dflt);
    assert_int_equal(SR_STRING_T, sr_in_node->type);
    assert_string_equal("acmefw-2.3", sr_in_node->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_in_node));
    /*   /test-module:activate-software-image/input/location */
    sr_in_node = input + 1;
    assert_string_equal("location", sr_in_node->name);
    assert_string_equal("test-module", sr_in_node->module_name);
    assert_true(sr_in_node->dflt);
    assert_int_equal(SR_STRING_T, sr_in_node->type);
    assert_string_equal("/", sr_in_node->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_in_node));

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
    /* log-msg[1] */
    assert_int_equal(0, sr_node_add_child((*output) + 2, "log-msg", NULL, &sr_out_node));
    sr_out_node->type = SR_LIST_T;
    assert_int_equal(0, sr_node_add_child(sr_out_node, "msg", NULL, &child));
    child->type = SR_STRING_T;
    child->data.string_val = strdup("Successfully loaded software image.");
    assert_int_equal(0, sr_node_add_child(sr_out_node, "time", NULL, &child));
    child->type = SR_UINT32_T;
    child->data.uint32_val = 1469625110;
    assert_int_equal(0, sr_node_add_child(sr_out_node, "msg-type", NULL, &child));
    child->type = SR_ENUM_T;
    child->data.enum_val = strdup("debug");
    /* log-msg[2] */
    assert_int_equal(0, sr_node_add_child((*output) + 2, "log-msg", NULL, &sr_out_node));
    sr_out_node->type = SR_LIST_T;
    assert_int_equal(0, sr_node_add_child(sr_out_node, "msg", NULL, &child));
    child->type = SR_STRING_T;
    child->data.string_val = strdup("Some soft limit exceeded...");
    assert_int_equal(0, sr_node_add_child(sr_out_node, "time", NULL, &child));
    child->type = SR_UINT32_T;
    child->data.uint32_val = 1469625150;
    assert_int_equal(0, sr_node_add_child(sr_out_node, "msg-type", NULL, &child));
    child->type = SR_ENUM_T;
    child->data.enum_val = strdup("warning");

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
    assert_int_equal(1 , callback_called);

    /* check output */
    sr_node_t *sr_node = output, *child = NULL;
    /*   /test-module:activate-software-image/output/status */
    assert_string_equal("status", sr_node->name);
    assert_string_equal("test-module", sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_STRING_T, sr_node->type);
    assert_string_equal("The image acmefw-2.3 is being installed.", sr_node->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_node));
    /*   /test-module:activate-software-image/output/version */
    sr_node = output + 1;
    assert_string_equal("version", sr_node->name);
    assert_string_equal("test-module", sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_STRING_T, sr_node->type);
    assert_string_equal("2.3", sr_node->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_node));
    /*   /test-module:activate-software-image/output/location */
    sr_node = output + 2;
    assert_string_equal("location", sr_node->name);
    assert_string_equal("test-module", sr_node->module_name);
    assert_true(sr_node->dflt);
    assert_int_equal(SR_STRING_T, sr_node->type);
    assert_string_equal("/", sr_node->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_node));
    /*   /test-module:activate-software-image/output/init-log */
    sr_node = output + 3;
    assert_string_equal("init-log", sr_node->name);
    assert_string_equal("test-module", sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_CONTAINER_T, sr_node->type);
    assert_int_equal(2, sr_node_t_get_children_cnt(sr_node));
    /*   /test-module:activate-software-image/output/init-log/log-msg[1] */
    sr_node = sr_node_t_get_child(sr_node, 0);
    assert_string_equal("log-msg", sr_node->name);
    assert_null( sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_LIST_T, sr_node->type);
    assert_int_equal(3, sr_node_t_get_children_cnt(sr_node));
    /*   /test-module:activate-software-image/output/init-log/log-msg[1]/msg */
    child = sr_node_t_get_child(sr_node, 0);
    assert_string_equal("msg", child->name);
    assert_null(child->module_name);
    assert_false(child->dflt);
    assert_int_equal(SR_STRING_T, child->type);
    assert_string_equal("Successfully loaded software image.", child->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(child));
    /*   /test-module:activate-software-image/output/init-log/log-msg[1]/time */
    child = sr_node_t_get_child(sr_node, 1);
    assert_string_equal("time", child->name);
    assert_null(child->module_name);
    assert_false(child->dflt);
    assert_int_equal(SR_UINT32_T, child->type);
    assert_int_equal(1469625110, child->data.uint32_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(child));
    /*   /test-module:activate-software-image/output/init-log/log-msg[1]/msg-type */
    child = sr_node_t_get_child(sr_node, 2);
    assert_string_equal("msg-type", child->name);
    assert_null(child->module_name);
    assert_false(child->dflt);
    assert_int_equal(SR_ENUM_T, child->type);
    assert_string_equal("debug", child->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(child));
    /*   /test-module:activate-software-image/output/init-log/log-msg[2] */
    sr_node = sr_node_t_get_child(output + 3, 1);
    assert_string_equal("log-msg", sr_node->name);
    assert_null( sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_LIST_T, sr_node->type);
    assert_int_equal(3, sr_node_t_get_children_cnt(sr_node));
    /*   /test-module:activate-software-image/output/init-log/log-msg[1]/msg */
    child = sr_node_t_get_child(sr_node, 0);
    assert_string_equal("msg", child->name);
    assert_null(child->module_name);
    assert_false(child->dflt);
    assert_int_equal(SR_STRING_T, child->type);
    assert_string_equal("Some soft limit exceeded...", child->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(child));
    /*   /test-module:activate-software-image/output/init-log/log-msg[1]/time */
    child = sr_node_t_get_child(sr_node, 1);
    assert_string_equal("time", child->name);
    assert_null(child->module_name);
    assert_false(child->dflt);
    assert_int_equal(SR_UINT32_T, child->type);
    assert_int_equal(1469625150, child->data.uint32_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(child));
    /*   /test-module:activate-software-image/output/init-log/log-msg[1]/msg-type */
    child = sr_node_t_get_child(sr_node, 2);
    assert_string_equal("msg-type", child->name);
    assert_null(child->module_name);
    assert_false(child->dflt);
    assert_int_equal(SR_ENUM_T, child->type);
    assert_string_equal("warning", child->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(child));

    sr_free_trees(output, output_cnt);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);

    /* unsubscribe */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_rpc_combo_test(void **state)
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

    /* subscribe for RPC with the tree variant of RPC callback */
    rc = sr_rpc_subscribe_tree(session, "/test-module:activate-software-image", test_rpc_tree_cb, &callback_called,
            SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* while subscription uses the *tree* interface, we will send and received RPC arguments as *values* */
    sr_val_t input = { 0, };
    sr_val_t *output = NULL;
    size_t output_cnt = 0;
    input.xpath = "/test-module:activate-software-image/image-name";
    input.type = SR_STRING_T;
    input.data.string_val = "acmefw-2.3";

    /* send a RPC */
    rc = sr_rpc_send(session, "/test-module:activate-software-image", &input, 1, &output, &output_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(1, callback_called);

    /* check output */
    assert_int_equal(12, output_cnt);
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

    assert_string_equal("/test-module:activate-software-image/init-log", output[3].xpath);
    assert_false(output[3].dflt);
    assert_int_equal(SR_CONTAINER_T, output[3].type);
    assert_string_equal("/test-module:activate-software-image/init-log/"
                        "log-msg[msg='Successfully loaded software image.'][time='1469625110']", output[4].xpath);
    assert_false(output[4].dflt);
    assert_int_equal(SR_LIST_T, output[4].type);
    assert_string_equal("/test-module:activate-software-image/init-log/"
                        "log-msg[msg='Successfully loaded software image.'][time='1469625110']/msg", output[5].xpath);
    assert_false(output[5].dflt);
    assert_int_equal(SR_STRING_T, output[5].type);
    assert_string_equal("Successfully loaded software image.", output[5].data.string_val);
    assert_string_equal("/test-module:activate-software-image/init-log/"
                        "log-msg[msg='Successfully loaded software image.'][time='1469625110']/time", output[6].xpath);
    assert_false(output[6].dflt);
    assert_int_equal(SR_UINT32_T, output[6].type);
    assert_int_equal(1469625110, output[6].data.uint32_val);
    assert_string_equal("/test-module:activate-software-image/init-log/"
                        "log-msg[msg='Successfully loaded software image.'][time='1469625110']/msg-type", output[7].xpath);
    assert_false(output[7].dflt);
    assert_int_equal(SR_ENUM_T, output[7].type);
    assert_string_equal("debug", output[7].data.enum_val);
    assert_string_equal("/test-module:activate-software-image/init-log/"
                        "log-msg[msg='Some soft limit exceeded...'][time='1469625150']", output[8].xpath);
    assert_false(output[8].dflt);
    assert_int_equal(SR_LIST_T, output[8].type);
    assert_string_equal("/test-module:activate-software-image/init-log/"
                        "log-msg[msg='Some soft limit exceeded...'][time='1469625150']/msg", output[9].xpath);
    assert_false(output[9].dflt);
    assert_int_equal(SR_STRING_T, output[9].type);
    assert_string_equal("Some soft limit exceeded...", output[9].data.string_val);
    assert_string_equal("/test-module:activate-software-image/init-log/"
                        "log-msg[msg='Some soft limit exceeded...'][time='1469625150']/time", output[10].xpath);
    assert_false(output[10].dflt);
    assert_int_equal(SR_UINT32_T, output[10].type);
    assert_int_equal(1469625150, output[10].data.uint32_val);
    assert_string_equal("/test-module:activate-software-image/init-log/"
                        "log-msg[msg='Some soft limit exceeded...'][time='1469625150']/msg-type", output[11].xpath);
    assert_false(output[11].dflt);
    assert_int_equal(SR_ENUM_T, output[11].type);
    assert_string_equal("warning", output[11].data.enum_val);

    sr_free_values(output, output_cnt);

    /* unsubscribe */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* now subscribe for RPC with the variant of RPC callback that expects *values* */
    rc = sr_rpc_subscribe(session, "/test-module:activate-software-image", test_rpc_cb, &callback_called,
            SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* while subscription uses the *values* interface, we will send and received RPC arguments as *trees* */
    sr_node_t input_tree = { 0, };
    sr_node_t *output_tree = NULL;
    output_cnt = 0;
    input_tree.name = "image-name";
    input_tree.type = SR_STRING_T;
    input_tree.data.string_val = "acmefw-2.3";

    /* send a RPC */
    callback_called = 0;
    rc = sr_rpc_send_tree(session, "/test-module:activate-software-image", &input_tree, 1, &output_tree, &output_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(1 , callback_called);

    /* check output */
    sr_node_t *sr_node = output_tree, *child = NULL;
    /*   /test-module:activate-software-image/output/status */
    assert_string_equal("status", sr_node->name);
    assert_string_equal("test-module", sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_STRING_T, sr_node->type);
    assert_string_equal("The image acmefw-2.3 is being installed.", sr_node->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_node));
    /*   /test-module:activate-software-image/output/version */
    sr_node = output_tree + 1;
    assert_string_equal("version", sr_node->name);
    assert_string_equal("test-module", sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_STRING_T, sr_node->type);
    assert_string_equal("2.3", sr_node->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_node));
    /*   /test-module:activate-software-image/output/location */
    sr_node = output_tree + 2;
    assert_string_equal("location", sr_node->name);
    assert_string_equal("test-module", sr_node->module_name);
    assert_true(sr_node->dflt);
    assert_int_equal(SR_STRING_T, sr_node->type);
    assert_string_equal("/", sr_node->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_node));
    /*   /test-module:activate-software-image/output/init-log */
    sr_node = output_tree + 3;
    assert_string_equal("init-log", sr_node->name);
    assert_string_equal("test-module", sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_CONTAINER_T, sr_node->type);
    assert_int_equal(2, sr_node_t_get_children_cnt(sr_node));
    /*   /test-module:activate-software-image/output/init-log/log-msg[1] */
    sr_node = sr_node_t_get_child(sr_node, 0);
    assert_string_equal("log-msg", sr_node->name);
    assert_null( sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_LIST_T, sr_node->type);
    assert_int_equal(3, sr_node_t_get_children_cnt(sr_node));
    /*   /test-module:activate-software-image/output/init-log/log-msg[1]/msg */
    child = sr_node_t_get_child(sr_node, 0);
    assert_string_equal("msg", child->name);
    assert_null(child->module_name);
    assert_false(child->dflt);
    assert_int_equal(SR_STRING_T, child->type);
    assert_string_equal("Successfully loaded software image.", child->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(child));
    /*   /test-module:activate-software-image/output/init-log/log-msg[1]/time */
    child = sr_node_t_get_child(sr_node, 1);
    assert_string_equal("time", child->name);
    assert_null(child->module_name);
    assert_false(child->dflt);
    assert_int_equal(SR_UINT32_T, child->type);
    assert_int_equal(1469625110, child->data.uint32_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(child));
    /*   /test-module:activate-software-image/output/init-log/log-msg[1]/msg-type */
    child = sr_node_t_get_child(sr_node, 2);
    assert_string_equal("msg-type", child->name);
    assert_null(child->module_name);
    assert_false(child->dflt);
    assert_int_equal(SR_ENUM_T, child->type);
    assert_string_equal("debug", child->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(child));
    /*   /test-module:activate-software-image/output/init-log/log-msg[2] */
    sr_node = sr_node_t_get_child(output_tree + 3, 1);
    assert_string_equal("log-msg", sr_node->name);
    assert_null( sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_LIST_T, sr_node->type);
    assert_int_equal(3, sr_node_t_get_children_cnt(sr_node));
    /*   /test-module:activate-software-image/output/init-log/log-msg[1]/msg */
    child = sr_node_t_get_child(sr_node, 0);
    assert_string_equal("msg", child->name);
    assert_null(child->module_name);
    assert_false(child->dflt);
    assert_int_equal(SR_STRING_T, child->type);
    assert_string_equal("Some soft limit exceeded...", child->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(child));
    /*   /test-module:activate-software-image/output/init-log/log-msg[1]/time */
    child = sr_node_t_get_child(sr_node, 1);
    assert_string_equal("time", child->name);
    assert_null(child->module_name);
    assert_false(child->dflt);
    assert_int_equal(SR_UINT32_T, child->type);
    assert_int_equal(1469625150, child->data.uint32_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(child));
    /*   /test-module:activate-software-image/output/init-log/log-msg[1]/msg-type */
    child = sr_node_t_get_child(sr_node, 2);
    assert_string_equal("msg-type", child->name);
    assert_null(child->module_name);
    assert_false(child->dflt);
    assert_int_equal(SR_ENUM_T, child->type);
    assert_string_equal("warning", child->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(child));

    sr_free_trees(output_tree, output_cnt);

    /* unsubscribe */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static int
test_failing_rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt,
        sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    int *callback_called = (int*)private_ctx;
    *callback_called += 1;

    return 12;
}

static void
cl_failed_rpc_test(void **state)
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
    rc = sr_rpc_subscribe(session, "/test-module:activate-software-image", test_failing_rpc_cb, &callback_called,
            SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    sr_val_t input = { 0, };
    sr_val_t *output = NULL;
    size_t output_cnt = 0;
    input.xpath = "/test-module:activate-software-image/image-name";
    input.type = SR_STRING_T;
    input.data.string_val = "acmefw-2.3";

    /* send a RPC; callback will return error */
    rc = sr_rpc_send(session, "/test-module:activate-software-image", &input, 1, &output, &output_cnt);
    assert_int_equal(1, callback_called);
    assert_int_equal(rc, 12);

    /* unsubscribe */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);

}

static int
test_invalid_rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt,
        sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    int *callback_called = (int*)private_ctx;
    *callback_called += 1;

    *output_cnt = 2;
    *output = calloc(*output_cnt, sizeof(**output));
    (*output)[0].xpath = strdup("/test-module:activate-software-image/status");
    (*output)[0].type = SR_STRING_T;
    (*output)[0].data.string_val = strdup("invalid status");
    (*output)[1].xpath = strdup("/test-module:activate-software-image/version");
    (*output)[1].type = SR_STRING_T;
    (*output)[1].data.string_val = strdup("2.3");

    return SR_ERR_OK;
}

static void
cl_invalid_rpc_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int callback_called = 0;
    const sr_error_info_t *error = NULL;
    int rc = SR_ERR_OK;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe for RPC */
    callback_called = 0;
    rc = sr_rpc_subscribe(session, "/test-module:activate-software-image", test_invalid_rpc_cb, &callback_called,
            SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    sr_val_t input = { 0, };
    sr_val_t *output = NULL;
    size_t output_cnt = 0;
    input.xpath = "/test-module:activate-software-image/location";
    input.type = SR_STRING_T;
    input.data.string_val = "invalid location";

    /* send a RPC; request validation will fail */
    rc = sr_rpc_send(session, "/test-module:activate-software-image", &input, 1, &output, &output_cnt);
    assert_int_equal(0, callback_called);
    assert_int_equal(rc, SR_ERR_VALIDATION_FAILED);
    sr_get_last_error(session, &error);
    assert_non_null(error);
    assert_string_equal("/test-module:activate-software-image/location", error->xpath);
    assert_string_equal("Must condition \". != 'invalid location'\" not satisfied.", error->message);

    input.data.string_val = "valid location";

    /* send a RPC; response validation will fail */
    rc = sr_rpc_send(session, "/test-module:activate-software-image", &input, 1, &output, &output_cnt);
    assert_int_equal(1, callback_called);
    assert_int_equal(rc, SR_ERR_VALIDATION_FAILED);
    sr_get_last_error(session, &error);
    assert_non_null(error);
    assert_string_equal("/test-module:activate-software-image/status", error->xpath);
    assert_string_equal("Must condition \". != 'invalid status'\" not satisfied.", error->message);

    /* unsubscribe */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static int
test_action_cb1(const char *xpath, const sr_val_t *input, const size_t input_cnt,
        sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    int *callback_called = (int*)private_ctx;
    *callback_called += 1;

    /* check input */
    assert_string_equal("/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load", xpath);
    assert_int_equal(input_cnt, 3);
    assert_string_equal("/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load/params", input[0].xpath);
    assert_int_equal(SR_STRING_T, input[0].type);
    assert_string_equal("", input[0].data.string_val);
    assert_false(input[0].dflt);
    assert_string_equal("/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load/force", input[1].xpath);
    assert_int_equal(SR_BOOL_T, input[1].type);
    assert_true(input[1].data.bool_val);
    assert_false(input[1].dflt);
    assert_string_equal("/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load/dry-run", input[2].xpath);
    assert_int_equal(SR_BOOL_T, input[2].type);
    assert_false(input[2].data.bool_val);
    assert_true(input[2].dflt);

    /* prepare output */
    *output = calloc(1, sizeof(**output));
    (*output)[0].xpath = strdup("/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load/return-code");
    (*output)[0].type = SR_UINT8_T;
    (*output)[0].data.uint8_val = 0;
    *output_cnt = 1;

    return SR_ERR_OK;
}

static int
test_action_cb2(const char *xpath, const sr_val_t *input, const size_t input_cnt,
        sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    int *callback_called = (int*)private_ctx;
    *callback_called += 1;

    /* check input */
    assert_string_equal("/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/get-dependencies", xpath);
    assert_int_equal(input_cnt, 0);

    /* prepare output */
    *output = calloc(3, sizeof(**output));
    (*output)[0].xpath = strdup("/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/get-dependencies/dependency");
    (*output)[0].type = SR_STRING_T;
    (*output)[0].data.string_val = strdup("drm");
    (*output)[1].xpath = strdup("/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/get-dependencies/dependency");
    (*output)[1].type = SR_STRING_T;
    (*output)[1].data.string_val = strdup("drm_kms_helper");
    (*output)[2].xpath = strdup("/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/get-dependencies/dependency");
    (*output)[2].type = SR_STRING_T;
    (*output)[2].data.string_val = strdup("ttm");

    *output_cnt = 3;

    return SR_ERR_OK;
}

static int
test_action_tree_cb1(const char *xpath, const sr_node_t *input, const size_t input_cnt,
        sr_node_t **output, size_t *output_cnt, void *private_ctx)
{
    const sr_node_t *sr_in_node = NULL;
    int *callback_called = (int*)private_ctx;
    *callback_called += 1;

    /* check input */
    assert_string_equal("/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load", xpath);
    assert_int_equal(input_cnt, 3);
    /*   /test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load/params */
    sr_in_node = input;
    assert_string_equal("params", sr_in_node->name);
    assert_string_equal("test-module", sr_in_node->module_name);
    assert_false(sr_in_node->dflt);
    assert_int_equal(SR_STRING_T, sr_in_node->type);
    assert_string_equal("", sr_in_node->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_in_node));
    /*   /test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load/force */
    sr_in_node = input + 1;
    assert_string_equal("force", sr_in_node->name);
    assert_string_equal("test-module", sr_in_node->module_name);
    assert_false(sr_in_node->dflt);
    assert_int_equal(SR_BOOL_T, sr_in_node->type);
    assert_true(sr_in_node->data.bool_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_in_node));
    /*   /test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load/dry-run */
    sr_in_node = input + 2;
    assert_string_equal("dry-run", sr_in_node->name);
    assert_string_equal("test-module", sr_in_node->module_name);
    assert_true(sr_in_node->dflt);
    assert_int_equal(SR_BOOL_T, sr_in_node->type);
    assert_false(sr_in_node->data.bool_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_in_node));

    /* prepare output */
    assert_int_equal(SR_ERR_OK, sr_new_tree("return-code", "test-module", output));
    (*output)[0].type = SR_UINT8_T;
    (*output)[0].data.uint8_val = 0;
    *output_cnt = 1;

    return SR_ERR_OK;
}

static int
test_action_tree_cb2(const char *xpath, const sr_node_t *input, const size_t input_cnt,
        sr_node_t **output, size_t *output_cnt, void *private_ctx)
{
    int *callback_called = (int*)private_ctx;
    *callback_called += 1;

    /* check input */
    assert_string_equal("/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/get-dependencies", xpath);
    assert_int_equal(input_cnt, 0);

    /* prepare output */
    assert_int_equal(SR_ERR_OK, sr_new_trees(3, output));
    *output_cnt = 3;
    assert_int_equal(SR_ERR_OK, sr_node_set_name((*output), "dependency"));
    assert_int_equal(SR_ERR_OK, sr_node_set_module((*output), "test-module"));
    assert_int_equal(SR_ERR_OK, sr_node_set_str_data((*output), SR_STRING_T, "drm"));
    assert_int_equal(SR_ERR_OK, sr_node_set_name((*output) + 1, "dependency"));
    assert_int_equal(SR_ERR_OK, sr_node_set_module((*output) + 1, "test-module"));
    assert_int_equal(SR_ERR_OK, sr_node_set_str_data((*output) + 1, SR_STRING_T, "drm_kms_helper"));
    assert_int_equal(SR_ERR_OK, sr_node_set_name((*output) + 2, "dependency"));
    assert_int_equal(SR_ERR_OK, sr_node_set_module((*output) + 2, "test-module"));
    assert_int_equal(SR_ERR_OK, sr_node_set_str_data((*output) + 2, SR_STRING_T, "ttm"));

    return SR_ERR_OK;
}

static void
cl_action_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int cb1_called = 0, cb2_called = 0;
    int rc = SR_ERR_OK;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "test-module", empty_module_change_cb, NULL, 0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe for actions */
    rc = sr_action_subscribe(session, "/test-module:kernel-modules/kernel-module/load",
            test_action_cb1, &cb1_called, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_action_subscribe(session, "/test-module:kernel-modules/kernel-module/get-dependencies",
            test_action_cb2, &cb2_called, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    sr_val_t input[2];
    memset(&input, '\0', sizeof(input));
    input[0].xpath = "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load/params";
    input[0].type = SR_STRING_T;
    input[0].data.string_val = "";
    input[1].xpath = "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load/force";
    input[1].type = SR_BOOL_T;
    input[1].data.bool_val = true;
    sr_val_t *output = NULL;
    size_t output_cnt = 0;

    /* send an Action (load a kernel module) */
    rc = sr_action_send(session, "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load",
            input, 2, &output, &output_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(1, cb1_called);
    assert_int_equal(0, cb2_called);

    assert_int_equal(output_cnt, 1);
    assert_string_equal("/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load/return-code", output[0].xpath);
    assert_int_equal(SR_UINT8_T, output[0].type);
    assert_int_equal(0, output[0].data.uint8_val);
    sr_free_values(output, output_cnt);
    output_cnt = 0;
    output = NULL;

    /* send an Action (get dependencies of a kernel module) */
    rc = sr_action_send(session, "/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/get-dependencies",
            NULL, 0, &output, &output_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(1, cb1_called);
    assert_int_equal(1, cb2_called);

    char *expected_values [] = {"ttm", "drm_kms_helper", "drm"};
    size_t expected_cnt = sizeof(expected_values) / sizeof(*expected_values);
    assert_int_equal(output_cnt, expected_cnt);

    for (size_t i = 0; i < expected_cnt; i++) {
        assert_string_equal("/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/get-dependencies/dependency", output[i].xpath);
        assert_int_equal(SR_STRING_T, output[i].type);
    }

    for (size_t j = 0; j < expected_cnt; j++) {
        bool found = false;

        for (size_t i = 0; i < expected_cnt; i++) {
            if (0 == strcmp(expected_values[j], output[i].data.string_val)) {
                found = true;
                break;
            }
        }
        if (!found) {
            assert_string_equal(expected_values[j], "");
        }
    }

    sr_free_values(output, output_cnt);
    output_cnt = 0;
    output = NULL;

    /* send Action non-existing in the data tree */
    rc = sr_action_send(session, "/test-module:kernel-modules/kernel-module[name='non-existing-module']/get-dependencies",
            NULL, 0, &output, &output_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);

    /* unsubscribe */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_action_tree_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int cb1_called = 0, cb2_called = 0;
    int rc = SR_ERR_OK;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "test-module", empty_module_change_cb, NULL, 0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe for actions */
    rc = sr_action_subscribe_tree(session, "/test-module:kernel-modules/kernel-module/load",
            test_action_tree_cb1, &cb1_called, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_action_subscribe_tree(session, "/test-module:kernel-modules/kernel-module/get-dependencies",
            test_action_tree_cb2, &cb2_called, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* prepare input for action_tree_cb1 */
    sr_node_t *input;
    assert_int_equal(SR_ERR_OK, sr_new_trees(2, &input));
    /*  -> params */
    assert_int_equal(SR_ERR_OK, sr_node_set_name(input, "params"));
    assert_int_equal(SR_ERR_OK, sr_node_set_module(input, "test-module"));
    assert_int_equal(SR_ERR_OK, sr_node_set_str_data(input, SR_STRING_T, ""));
    /*  -> force */
    assert_int_equal(SR_ERR_OK, sr_node_set_name(input+1, "force"));
    assert_int_equal(SR_ERR_OK, sr_node_set_module(input+1, "test-module"));
    input[1].type = SR_BOOL_T;
    input[1].data.bool_val = true;

    sr_node_t *output = NULL;
    size_t output_cnt = 0;

    /* send an Action (load a kernel module) */
    rc = sr_action_send_tree(session, "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load",
            input, 2, &output, &output_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(1, cb1_called);
    assert_int_equal(0, cb2_called);

    assert_int_equal(output_cnt, 1);
    assert_string_equal("return-code", output[0].name);
    assert_string_equal("test-module", output[0].module_name);
    assert_false(output[0].dflt);
    assert_int_equal(SR_UINT8_T, output[0].type);
    assert_int_equal(0, output[0].data.uint8_val);

    sr_free_trees(input, 2);
    sr_free_trees(output, output_cnt);
    output_cnt = 0;
    output = NULL;

    /* send an Action (get dependencies of a kernel module) */
    rc = sr_action_send_tree(session, "/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/get-dependencies",
            NULL, 0, &output, &output_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(1, cb1_called);
    assert_int_equal(1, cb2_called);

    char *expected_values [] = {"ttm", "drm_kms_helper", "drm"};
    size_t expected_cnt = sizeof(expected_values) / sizeof(*expected_values);
    assert_int_equal(output_cnt, expected_cnt);

    for (size_t i = 0; i < expected_cnt; i++) {
        assert_string_equal("dependency", output[i].name);
        assert_string_equal("test-module", output[i].module_name);
        assert_false(output[i].dflt);
        assert_int_equal(SR_STRING_T, output[i].type);
    }

    for (size_t j = 0; j < expected_cnt; j++) {
        bool found = false;

        for (size_t i = 0; i < expected_cnt; i++) {
            if (0 == strcmp(expected_values[j], output[i].data.string_val)) {
                found = true;
                break;
            }
        }
        if (!found) {
            assert_string_equal(expected_values[j], "");
        }
    }

    sr_free_trees(output, output_cnt);
    output_cnt = 0;
    output = NULL;

    /* send Action non-existing in the data tree */
    rc = sr_action_send_tree(session, "/test-module:kernel-modules/kernel-module[name='non-existing-module']/get-dependencies",
            NULL, 0, &output, &output_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);

    /* unsubscribe */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_action_combo_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int cb1_called = 0, cb2_called = 0;
    int rc = SR_ERR_OK;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "test-module", empty_module_change_cb, NULL, 0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe for actions with the tree variants of Action callbacks*/
    rc = sr_action_subscribe_tree(session, "/test-module:kernel-modules/kernel-module/load",
            test_action_tree_cb1, &cb1_called, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_action_subscribe_tree(session, "/test-module:kernel-modules/kernel-module/get-dependencies",
            test_action_tree_cb2, &cb2_called, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* while subscription uses the *tree* interface, we will send and received Action arguments as *values* */
    sr_val_t input[2];
    memset(&input, '\0', sizeof(input));
    input[0].xpath = "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load/params";
    input[0].type = SR_STRING_T;
    input[0].data.string_val = "";
    input[1].xpath = "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load/force";
    input[1].type = SR_BOOL_T;
    input[1].data.bool_val = true;
    sr_val_t *output = NULL;
    size_t output_cnt = 0;

    /* send an Action (load a kernel module) */
    rc = sr_action_send(session, "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load",
            input, 2, &output, &output_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(1, cb1_called);
    assert_int_equal(0, cb2_called);

    assert_int_equal(output_cnt, 1);
    assert_string_equal("/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load/return-code", output[0].xpath);
    assert_int_equal(SR_UINT8_T, output[0].type);
    assert_int_equal(0, output[0].data.uint8_val);
    sr_free_values(output, output_cnt);
    output_cnt = 0;
    output = NULL;

    /* send an Action (get dependencies of a kernel module) */
    rc = sr_action_send(session, "/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/get-dependencies",
            NULL, 0, &output, &output_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(1, cb1_called);
    assert_int_equal(1, cb2_called);

    char *expected_values [] = {"ttm", "drm_kms_helper", "drm"};
    size_t expected_cnt = sizeof(expected_values) / sizeof(*expected_values);
    assert_int_equal(output_cnt, expected_cnt);

    for (size_t i = 0; i < expected_cnt; i++) {
        assert_string_equal("/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/get-dependencies/dependency", output[i].xpath);
        assert_int_equal(SR_STRING_T, output[i].type);
    }

    for (size_t j = 0; j < expected_cnt; j++) {
        bool found = false;

        for (size_t i = 0; i < expected_cnt; i++) {
            if (0 == strcmp(expected_values[j], output[i].data.string_val)) {
                found = true;
                break;
            }
        }
        if (!found) {
            assert_string_equal(expected_values[j], "");
        }
    }

    sr_free_values(output, output_cnt);
    output_cnt = 0;
    output = NULL;

    /* unsubscribe */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    cb1_called = 0;
    cb2_called = 0;

    /* now subscribe for Actions with the variants of Action callbacks that expect *values* */
    rc = sr_action_subscribe(session, "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load",
            test_action_cb1, &cb1_called, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_action_subscribe(session, "/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/get-dependencies",
            test_action_cb2, &cb2_called, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* while subscriptions use the *values* interface, we will send and received Action arguments as *trees* */
    sr_node_t *input_tree;
    assert_int_equal(SR_ERR_OK, sr_new_trees(2, &input_tree));
    /*  -> params */
    assert_int_equal(SR_ERR_OK, sr_node_set_name(input_tree, "params"));
    assert_int_equal(SR_ERR_OK, sr_node_set_module(input_tree, "test-module"));
    assert_int_equal(SR_ERR_OK, sr_node_set_str_data(input_tree, SR_STRING_T, ""));
    /*  -> force */
    assert_int_equal(SR_ERR_OK, sr_node_set_name(input_tree+1, "force"));
    assert_int_equal(SR_ERR_OK, sr_node_set_module(input_tree+1, "test-module"));
    input_tree[1].type = SR_BOOL_T;
    input_tree[1].data.bool_val = true;

    sr_node_t *output_tree = NULL;

    /* send an Action (load a kernel module) */
    rc = sr_action_send_tree(session, "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load",
            input_tree, 2, &output_tree, &output_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(1, cb1_called);
    assert_int_equal(0, cb2_called);

    assert_int_equal(output_cnt, 1);
    assert_string_equal("return-code", output_tree[0].name);
    assert_string_equal("test-module", output_tree[0].module_name);
    assert_false(output_tree[0].dflt);
    assert_int_equal(SR_UINT8_T, output_tree[0].type);
    assert_int_equal(0, output_tree[0].data.uint8_val);

    sr_free_trees(input_tree, 2);
    sr_free_trees(output_tree, output_cnt);
    output_cnt = 0;
    output_tree = NULL;

    /* send an Action (get dependencies of a kernel module) */
    rc = sr_action_send_tree(session, "/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/get-dependencies",
            NULL, 0, &output_tree, &output_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(1, cb1_called);
    assert_int_equal(1, cb2_called);

    assert_int_equal(output_cnt, expected_cnt);

    for (size_t i = 0; i < expected_cnt; i++) {
        assert_string_equal("dependency", output_tree[i].name);
        assert_string_equal("test-module", output_tree[i].module_name);
        assert_false(output_tree[i].dflt);
        assert_int_equal(SR_STRING_T, output_tree[i].type);
    }

    for (size_t j = 0; j < expected_cnt; j++) {
        bool found = false;

        for (size_t i = 0; i < expected_cnt; i++) {
            if (0 == strcmp(expected_values[j], output_tree[i].data.string_val)) {
                found = true;
                break;
            }
        }
        if (!found) {
            assert_string_equal(expected_values[j], "");
        }
    }

    sr_free_trees(output_tree, output_cnt);
    output_cnt = 0;
    output_tree = NULL;

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
            &callback_called, 0, SR_SUBSCR_DEFAULT | SR_SUBSCR_APPLY_ONLY, &subscription);
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
            0, SR_SUBSCR_DEFAULT | SR_SUBSCR_APPLY_ONLY, &subscription);
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

#define MAX_CHANGE 150
typedef struct changes_s{
    pthread_mutex_t mutex;
    pthread_cond_t cv;
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

    pthread_mutex_lock(&ch->mutex);
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
    pthread_cond_signal(&ch->cv);
    pthread_mutex_unlock(&ch->mutex);
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
    changes_t changes = {.mutex = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER};
    sr_change_iter_t *iter = NULL;
    struct timespec ts;

    sr_val_t *val = NULL;
    const char *xpath = NULL;
    int rc = SR_ERR_OK;
    xpath = "/example-module:container/list[key1='key1'][key2='key2']/leaf";

    /* start session */
    rc = sr_session_start(conn, SR_DS_CANDIDATE, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* get changes can be called only on notification session */
    rc = sr_get_changes_iter(session, "/example-module:container", &iter);
    assert_int_equal(rc, SR_ERR_UNSUPPORTED);

    /* subscribe for changes */
    rc = sr_module_change_subscribe(session, "example-module", list_changes_cb, &changes,
            0, SR_SUBSCR_DEFAULT | SR_SUBSCR_APPLY_ONLY, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* check the list presence in candidate */
    rc = sr_get_item(session, xpath, &val);
    assert_int_equal(rc, SR_ERR_OK);
    sr_free_val(val);

    /* remove the list instance */
    rc = sr_delete_item(session, xpath, SR_EDIT_DEFAULT);

    pthread_mutex_lock(&changes.mutex);
    /* save changes to running */
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    pthread_cond_timedwait(&changes.cv, &changes.mutex, &ts);

    assert_int_equal(changes.cnt, 1);
    for (size_t i = 0; i < changes.cnt; i++) {
        assert_int_equal(changes.oper[i], SR_OP_DELETED);
        sr_free_val(changes.new_values[i]);
        sr_free_val(changes.old_values[i]);
    }

    pthread_mutex_unlock(&changes.mutex);
    pthread_mutex_destroy(&changes.mutex);
    pthread_cond_destroy(&changes.cv);

    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_get_changes_iter_multi_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    changes_t changes = {.mutex = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER };
    sr_val_t val = { 0, };
    char xpath[PATH_MAX] = { 0, };
    int rc = SR_ERR_OK;
    struct timespec ts;

    /* start session */
    rc = sr_session_start(conn, SR_DS_CANDIDATE, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe for changes */
    rc = sr_module_change_subscribe(session, "example-module", list_changes_cb, &changes,
            0, SR_SUBSCR_DEFAULT | SR_SUBSCR_APPLY_ONLY, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    val.type = SR_STRING_T;
    val.data.string_val = "test-value";

    /* genarate a lot of changes */
    for (size_t i = 0; i < 30; i++) {
        snprintf(xpath, PATH_MAX - 1, "/example-module:container/list[key1='test_%zu'][key2='test_%zu']/leaf", i, i);
        rc = sr_set_item(session, xpath, &val, SR_EDIT_DEFAULT);
        assert_int_equal(rc, SR_ERR_OK);
    }

    pthread_mutex_lock(&changes.mutex);
    /* save changes to running */
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    pthread_cond_timedwait(&changes.cv, &changes.mutex, &ts);

    assert_int_equal(changes.cnt, 120);
    for (size_t i = 0; i < changes.cnt; i++) {
        assert_int_equal(changes.oper[i], SR_OP_CREATED);
        sr_free_val(changes.new_values[i]);
        sr_free_val(changes.old_values[i]);
    }

    /* delete changes + create new ones */
    for (size_t i = 0; i < 30; i++) {
        snprintf(xpath, PATH_MAX - 1, "/example-module:container/list[key1='test_%zu'][key2='test_%zu']/leaf", i, i);
        rc = sr_delete_item(session, xpath, SR_EDIT_DEFAULT);
        assert_int_equal(rc, SR_ERR_OK);

        snprintf(xpath, PATH_MAX - 1, "/example-module:container/list[key1='test2_%zu'][key2='test2_%zu']/leaf", i, i);
        rc = sr_set_item(session, xpath, &val, SR_EDIT_DEFAULT);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* save changes to running */
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    pthread_cond_timedwait(&changes.cv, &changes.mutex, &ts);

    assert_int_equal(changes.cnt, 150);
    for (size_t i = 0; i < changes.cnt; i++) {
        assert_true(SR_OP_DELETED == changes.oper[i] || SR_OP_CREATED == changes.oper[i]);
        sr_free_val(changes.new_values[i]);
        sr_free_val(changes.old_values[i]);
    }

    /* delete all changes */
    for (size_t i = 0; i < 30; i++) {
        snprintf(xpath, PATH_MAX - 1, "/example-module:container/list[key1='test2_%zu'][key2='test2_%zu']/leaf", i, i);
        rc = sr_delete_item(session, xpath, SR_EDIT_DEFAULT);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* save changes to running */
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    pthread_cond_timedwait(&changes.cv, &changes.mutex, &ts);

    assert_int_equal(changes.cnt, 30);
    for (size_t i = 0; i < changes.cnt; i++) {
        assert_int_equal(changes.oper[i], SR_OP_DELETED);
        sr_free_val(changes.new_values[i]);
        sr_free_val(changes.old_values[i]);
    }

    pthread_mutex_unlock(&changes.mutex);
    pthread_mutex_destroy(&changes.mutex);
    pthread_cond_destroy(&changes.cv);

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

    *values = calloc(1, sizeof(**values));
    if (0 == strcmp(xpath, "/state-module:bus/gps_located")) {
        (*values)[0].xpath = strdup("/state-module:bus/gps_located");
        (*values)[0].type = SR_BOOL_T;
        (*values)[0].data.bool_val = false;
    } else {
        (*values)[0].xpath = strdup("/state-module:bus/distance_travelled");
        (*values)[0].type = SR_UINT32_T;
        (*values)[0].data.uint32_val = 42;
    }
    *values_cnt = 1;

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
    int status_change;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} cl_test_en_cb_status_t;

typedef struct cl_test_en_session_s {
    sr_session_ctx_t *session;
    sr_subscription_ctx_t *subscription_ld;
    sr_subscription_ctx_t *subscription_lr;
    sr_subscription_ctx_t *subscription_lo;
    sr_subscription_ctx_t *subscription_st;
} cl_test_en_session_t;

static void
test_event_notif_link_discovery_cb(const sr_ev_notif_type_t notif_type, const char *xpath,
        const sr_val_t *values, const size_t values_cnt, time_t timestamp, void *private_ctx)
{
    cl_test_en_cb_status_t *cb_status = (cl_test_en_cb_status_t*)private_ctx;

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

    assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
    cb_status->link_discovered += 1;
    if (cb_status->link_discovered == CL_TEST_EN_NUM_SESSIONS) {
        assert_int_equal(0, pthread_cond_signal(&cb_status->cond));
    }
    assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
}

static void
test_event_notif_link_removed_cb(const sr_ev_notif_type_t notif_type, const char *xpath, const sr_val_t *values,
        const size_t values_cnt, time_t timestamp, void *private_ctx)
{
    cl_test_en_cb_status_t *cb_status = (cl_test_en_cb_status_t*)private_ctx;

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

    assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
    cb_status->link_removed += 1;
    if (cb_status->link_removed == CL_TEST_EN_NUM_SESSIONS) {
        assert_int_equal(0, pthread_cond_signal(&cb_status->cond));
    }
    assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
}

static void
test_event_notif_link_overutilized_cb(const sr_ev_notif_type_t notif_type, const char *xpath,
        const sr_val_t *values, const size_t values_cnt, time_t timestamp, void *private_ctx)
{
    assert_true(0 && "This callback should not get called");
}

static void
test_event_notif_status_change_cb(const sr_ev_notif_type_t notif_type, const char *xpath,
        const sr_val_t *values, const size_t values_cnt, time_t timestamp, void *private_ctx)
{
    cl_test_en_cb_status_t *cb_status = (cl_test_en_cb_status_t*)private_ctx;

    assert_string_equal("/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change", xpath);

    assert_int_equal(values_cnt, 2);
    assert_string_equal("/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change/loaded", values[0].xpath);
    assert_int_equal(SR_BOOL_T, values[0].type);
    assert_true(values[0].data.bool_val);
    assert_string_equal("/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change/time-of-change", values[1].xpath);
    assert_int_equal(SR_UINT32_T, values[1].type);
    assert_int_equal(18, values[1].data.uint32_val);

    assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
    cb_status->status_change += 1;
    if (cb_status->status_change >= CL_TEST_EN_NUM_SESSIONS) {
        assert_int_equal(0, pthread_cond_signal(&cb_status->cond));
    }
    assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
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
    cb_status.status_change = 0;
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

    /* subscribe for status-change in every session */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_event_notif_subscribe(sub_session[i].session, "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change",
                test_event_notif_status_change_cb, &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_st);
        assert_int_equal(rc, SR_ERR_OK);
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

    rc = sr_event_notif_send(notif_session, "/test-module:link-discovered", values, 4, SR_EV_NOTIF_DEFAULT);
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

    rc = sr_event_notif_send(notif_session, "/test-module:link-removed", values, 4, SR_EV_NOTIF_DEFAULT);
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

    rc = sr_event_notif_send(notif_session, "/test-module:link-overutilized", values, 4, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_VALIDATION_FAILED);

    /* send event notification - status-change */
    values[0].xpath = "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change/loaded";
    values[0].type = SR_BOOL_T;
    values[0].data.bool_val = true;
    values[1].xpath = "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change/time-of-change";
    values[1].type = SR_UINT32_T;
    values[1].data.uint32_val = 18;

    rc = sr_event_notif_send(notif_session, "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change",
            values, 2, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* wait at most 5 seconds for all callbacks to get called */
    struct timespec ts;
    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += 5;
    while (ETIMEDOUT != pthread_cond_timedwait(&cb_status.cond, &cb_status.mutex, &ts)
            && (cb_status.link_removed < CL_TEST_EN_NUM_SESSIONS || cb_status.link_discovered < CL_TEST_EN_NUM_SESSIONS ||
                cb_status.status_change < CL_TEST_EN_NUM_SESSIONS));
    assert_int_equal(CL_TEST_EN_NUM_SESSIONS, cb_status.link_discovered);
    assert_int_equal(CL_TEST_EN_NUM_SESSIONS, cb_status.link_removed);
    assert_int_equal(CL_TEST_EN_NUM_SESSIONS, cb_status.status_change);
    assert_int_equal(0, pthread_mutex_unlock(&cb_status.mutex));

    /* unsubscribe */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_ld);
        assert_int_equal(rc, SR_ERR_OK);
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_lr);
        assert_int_equal(rc, SR_ERR_OK);
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_lo);
        assert_int_equal(rc, SR_ERR_OK);
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_st);
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

static void
test_event_notif_link_discovery_tree_cb(const sr_ev_notif_type_t notif_type, const char *xpath,
        const sr_node_t *trees, const size_t tree_cnt, time_t timestamp, void *private_ctx)
{
    const sr_node_t *tree = NULL;
    cl_test_en_cb_status_t *cb_status = (cl_test_en_cb_status_t*)private_ctx;

    assert_string_equal("/test-module:link-discovered", xpath);
    assert_int_equal(tree_cnt, 3);
    /*  /test-module:link-discovered/source */
    tree = trees;
    assert_string_equal("source", tree->name);
    assert_string_equal("test-module", tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_CONTAINER_T, tree->type);
    assert_int_equal(2, sr_node_t_get_children_cnt(tree));
    /*  /test-module:link-discovered/source/address */
    tree = sr_node_t_get_child(trees, 0);
    assert_string_equal("address", tree->name);
    assert_null(tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_STRING_T, tree->type);
    assert_string_equal("10.10.1.5", tree->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(tree));
    /*  /test-module:link-discovered/source/interface */
    tree = sr_node_t_get_child(trees, 1);
    assert_string_equal("interface", tree->name);
    assert_null(tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_STRING_T, tree->type);
    assert_string_equal("eth1", tree->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(tree));
    /*  /test-module:link-discovered/destination */
    tree = trees + 1;
    assert_string_equal("destination", tree->name);
    assert_string_equal("test-module", tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_CONTAINER_T, tree->type);
    assert_int_equal(2, sr_node_t_get_children_cnt(tree));
    /*  /test-module:link-discovered/destination/address */
    tree = sr_node_t_get_child(trees + 1, 0);
    assert_string_equal("address", tree->name);
    assert_null(tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_STRING_T, tree->type);
    assert_string_equal("10.10.1.8", tree->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(tree));
    /*  /test-module:link-discovered/destination/interface */
    tree = sr_node_t_get_child(trees + 1, 1);
    assert_string_equal("interface", tree->name);
    assert_null(tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_STRING_T, tree->type);
    assert_string_equal("eth0", tree->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(tree));
    /*  /test-module:link-discovered/MTU */
    tree = trees + 2;
    assert_string_equal("MTU", tree->name);
    assert_string_equal("test-module", tree->module_name);
    assert_true(tree->dflt);  /**< default */
    assert_int_equal(SR_UINT16_T, tree->type);
    assert_int_equal(1500, tree->data.uint16_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(tree));

    assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
    cb_status->link_discovered += 1;
    if (cb_status->link_discovered == CL_TEST_EN_NUM_SESSIONS) {
        assert_int_equal(0, pthread_cond_signal(&cb_status->cond));
    }
    assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
}

static void
test_event_notif_link_removed_tree_cb(const sr_ev_notif_type_t notif_type, const char *xpath,
        const sr_node_t *trees, const size_t tree_cnt, time_t timestamp, void *private_ctx)
{
    const sr_node_t *tree = NULL;
    cl_test_en_cb_status_t *cb_status = (cl_test_en_cb_status_t*)private_ctx;

    assert_string_equal("/test-module:link-removed", xpath);
    assert_int_equal(tree_cnt, 3);
    /*  /test-module:link-discovered/source */
    tree = trees;
    assert_string_equal("source", tree->name);
    assert_string_equal("test-module", tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_CONTAINER_T, tree->type);
    assert_int_equal(2, sr_node_t_get_children_cnt(tree));
    /*  /test-module:link-discovered/source/address */
    tree = sr_node_t_get_child(trees, 0);
    assert_string_equal("address", tree->name);
    assert_null(tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_STRING_T, tree->type);
    assert_string_equal("10.10.2.4", tree->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(tree));
    /*  /test-module:link-discovered/source/interface */
    tree = sr_node_t_get_child(trees, 1);
    assert_string_equal("interface", tree->name);
    assert_null(tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_STRING_T, tree->type);
    assert_string_equal("eth0", tree->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(tree));
    /*  /test-module:link-discovered/destination */
    tree = trees + 1;
    assert_string_equal("destination", tree->name);
    assert_string_equal("test-module", tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_CONTAINER_T, tree->type);
    assert_int_equal(2, sr_node_t_get_children_cnt(tree));
    /*  /test-module:link-discovered/destination/address */
    tree = sr_node_t_get_child(trees + 1, 0);
    assert_string_equal("address", tree->name);
    assert_null(tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_STRING_T, tree->type);
    assert_string_equal("10.10.2.5", tree->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(tree));
    /*  /test-module:link-discovered/destination/interface */
    tree = sr_node_t_get_child(trees + 1, 1);
    assert_string_equal("interface", tree->name);
    assert_null(tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_STRING_T, tree->type);
    assert_string_equal("eth2", tree->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(tree));
    /*  /test-module:link-discovered/MTU */
    tree = trees + 2;
    assert_string_equal("MTU", tree->name);
    assert_string_equal("test-module", tree->module_name);
    assert_true(tree->dflt);  /**< default */
    assert_int_equal(SR_UINT16_T, tree->type);
    assert_int_equal(1500, tree->data.uint16_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(tree));

    assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
    cb_status->link_removed += 1;
    if (cb_status->link_removed == CL_TEST_EN_NUM_SESSIONS) {
        assert_int_equal(0, pthread_cond_signal(&cb_status->cond));
    }
    assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
}

static void
test_event_notif_link_overutilized_tree_cb(const sr_ev_notif_type_t notif_type, const char *xpath,
        const sr_node_t *trees, const size_t tree_cnt, time_t timestamp, void *private_ctx)
{
    assert_true(0 && "This callback should not get called");
}

static void
test_event_notif_status_change_tree_cb(const sr_ev_notif_type_t notif_type, const char *xpath,
        const sr_node_t *trees, const size_t tree_cnt, time_t timestamp, void *private_ctx)
{
    const sr_node_t *tree = NULL;
    cl_test_en_cb_status_t *cb_status = (cl_test_en_cb_status_t*)private_ctx;

    assert_string_equal("/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change", xpath);
    assert_int_equal(tree_cnt, 2);
    /*  /test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change/loaded */
    tree = trees;
    assert_string_equal("loaded", tree->name);
    assert_string_equal("test-module", tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_BOOL_T, tree->type);
    assert_true(tree->data.bool_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(tree));
    /*  /test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change/time-of-change */
    tree = trees + 1;
    assert_string_equal("time-of-change", tree->name);
    assert_string_equal("test-module", tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_UINT32_T, tree->type);
    assert_int_equal(18, tree->data.uint32_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(tree));

    assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
    cb_status->status_change += 1;
    if (cb_status->status_change >= CL_TEST_EN_NUM_SESSIONS) {
        assert_int_equal(0, pthread_cond_signal(&cb_status->cond));
    }
    assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
}

static void
cl_event_notif_tree_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    cl_test_en_session_t sub_session[CL_TEST_EN_NUM_SESSIONS];
    sr_session_ctx_t *notif_session = NULL;
    cl_test_en_cb_status_t cb_status;
    sr_node_t *trees = NULL;
    sr_node_t *tree = NULL;
    size_t tree_cnt = 0;
    size_t i;
    int rc = SR_ERR_OK;

    cb_status.link_discovered = 0;
    cb_status.link_removed = 0;
    cb_status.status_change = 0;
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
        rc = sr_event_notif_subscribe_tree(sub_session[i].session, "/test-module:link-discovered",
                test_event_notif_link_discovery_tree_cb,
                &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_ld);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* subscribe for link removal in every session */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_event_notif_subscribe_tree(sub_session[i].session, "/test-module:link-removed",
                test_event_notif_link_removed_tree_cb,
                &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_lr);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* subscribe for nonexistent notification in every session */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_event_notif_subscribe_tree(sub_session[i].session, "/test-module:link-overutilized",
                test_event_notif_link_overutilized_tree_cb,
                &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_lo);
        assert_int_equal(rc, SR_ERR_OK); /**< not verified at this stage */
    }

    /* subscribe for status change in every session */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_event_notif_subscribe_tree(sub_session[i].session, "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change",
                test_event_notif_status_change_tree_cb,
                &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_st);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* send event notification - link discovery */
    tree_cnt = 2;
    trees = calloc(tree_cnt, sizeof(*trees));
    /* - source */
    tree = trees;
    tree->name = strdup("source");
    tree->type = SR_CONTAINER_T;
    assert_int_equal(0, sr_node_add_child(trees, "address", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("10.10.1.5");
    assert_int_equal(0, sr_node_add_child(trees, "interface", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("eth1");
    /* - destination */
    tree = trees + 1;
    tree->name = strdup("destination");
    tree->type = SR_CONTAINER_T;
    assert_int_equal(0, sr_node_add_child(trees + 1, "address", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("10.10.1.8");
    assert_int_equal(0, sr_node_add_child(trees + 1, "interface", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("eth0");

    rc = sr_event_notif_send_tree(notif_session, "/test-module:link-discovered", trees, tree_cnt, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    sr_free_trees(trees, tree_cnt);

    /* send event notification - link removal */
    tree_cnt = 2;
    trees = calloc(tree_cnt, sizeof(*trees));
    /* - source */
    tree = trees;
    tree->name = strdup("source");
    tree->type = SR_CONTAINER_T;
    assert_int_equal(0, sr_node_add_child(trees, "address", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("10.10.2.4");
    assert_int_equal(0, sr_node_add_child(trees, "interface", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("eth0");
    /* - destination */
    tree = trees + 1;
    tree->name = strdup("destination");
    tree->type = SR_CONTAINER_T;
    assert_int_equal(0, sr_node_add_child(trees + 1, "address", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("10.10.2.5");
    assert_int_equal(0, sr_node_add_child(trees + 1, "interface", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("eth2");

    rc = sr_event_notif_send_tree(notif_session, "/test-module:link-removed", trees, tree_cnt, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    sr_free_trees(trees, tree_cnt);

    /* send event notification - link overutilized (not defined in yang) */
    tree_cnt = 2;
    trees = calloc(tree_cnt, sizeof(*trees));
    /* - source */
    tree = trees;
    tree->name = strdup("source");
    tree->type = SR_CONTAINER_T;
    assert_int_equal(0, sr_node_add_child(trees, "address", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("10.10.1.5");
    assert_int_equal(0, sr_node_add_child(trees, "interface", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("eth1");
    /* - destination */
    tree = trees + 1;
    tree->name = strdup("destination");
    tree->type = SR_CONTAINER_T;
    assert_int_equal(0, sr_node_add_child(trees + 1, "address", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("10.10.1.8");
    assert_int_equal(0, sr_node_add_child(trees + 1, "interface", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("eth0");

    rc = sr_event_notif_send_tree(notif_session, "/test-module:link-overutilized", trees, tree_cnt, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_VALIDATION_FAILED);
    sr_free_trees(trees, tree_cnt);

    /* send event notification - status change */
    tree_cnt = 2;
    trees = calloc(tree_cnt, sizeof(*trees));
    /* - loaded */
    tree = trees;
    tree->name = strdup("loaded");
    tree->type = SR_BOOL_T;
    tree->data.bool_val = true;
    /* - time-of-change */
    tree = trees + 1;
    tree->name = strdup("time-of-change");
    tree->type = SR_UINT32_T;
    tree->data.uint32_val = 18;

    rc = sr_event_notif_send_tree(notif_session, "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change",
            trees, tree_cnt, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    sr_free_trees(trees, tree_cnt);

    /* wait at most 5 seconds for all callbacks to get called */
    struct timespec ts;
    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += 5;
    while (ETIMEDOUT != pthread_cond_timedwait(&cb_status.cond, &cb_status.mutex, &ts)
            && (cb_status.link_removed < CL_TEST_EN_NUM_SESSIONS || cb_status.link_discovered < CL_TEST_EN_NUM_SESSIONS ||
                cb_status.status_change < CL_TEST_EN_NUM_SESSIONS));
    assert_int_equal(CL_TEST_EN_NUM_SESSIONS, cb_status.link_discovered);
    assert_int_equal(CL_TEST_EN_NUM_SESSIONS, cb_status.link_removed);
    assert_int_equal(CL_TEST_EN_NUM_SESSIONS, cb_status.status_change);
    assert_int_equal(0, pthread_mutex_unlock(&cb_status.mutex));

    /* unsubscribe */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_ld);
        assert_int_equal(rc, SR_ERR_OK);
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_lr);
        assert_int_equal(rc, SR_ERR_OK);
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_lo);
        assert_int_equal(rc, SR_ERR_OK);
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_st);
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


static void
cl_event_notif_combo_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    cl_test_en_session_t sub_session[CL_TEST_EN_NUM_SESSIONS];
    sr_session_ctx_t *notif_session = NULL;
    cl_test_en_cb_status_t cb_status;
    sr_node_t *trees = NULL;
    sr_node_t *tree = NULL;
    sr_val_t values[4];
    size_t tree_cnt = 0;
    size_t i;
    int rc = SR_ERR_OK;

    memset(&values, '\0', sizeof(values));
    cb_status.link_discovered = 0;
    cb_status.link_removed = 0;
    cb_status.status_change = 0;
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

    /* subscribe for link discovery in every session (mix of values and nodes) */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        if (0 == i % 2) {
            rc = sr_event_notif_subscribe(sub_session[i].session, "/test-module:link-discovered",
                    test_event_notif_link_discovery_cb,
                    &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_ld);
        } else {
            rc = sr_event_notif_subscribe_tree(sub_session[i].session, "/test-module:link-discovered",
                    test_event_notif_link_discovery_tree_cb,
                    &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_ld);
        }
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* subscribe for link removal in every session (mix of values and nodes) */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        if (0 == i % 2) {
            rc = sr_event_notif_subscribe(sub_session[i].session, "/test-module:link-removed",
                    test_event_notif_link_removed_cb,
                    &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_lr);
        } else {
            rc = sr_event_notif_subscribe_tree(sub_session[i].session, "/test-module:link-removed",
                    test_event_notif_link_removed_tree_cb,
                    &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_lr);
        }
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* subscribe for nonexistent notification in every session (mix of values and nodes) */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        if (0 == i % 2) {
            rc = sr_event_notif_subscribe(sub_session[i].session, "/test-module:link-overutilized",
                    test_event_notif_link_overutilized_cb,
                    &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_lo);
        } else {
            rc = sr_event_notif_subscribe_tree(sub_session[i].session, "/test-module:link-overutilized",
                    test_event_notif_link_overutilized_tree_cb,
                    &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_lo);
        }
        assert_int_equal(rc, SR_ERR_OK); /**< not verified at this stage */
    }

    /* subscribe for status-change in every session (mix of values and nodes) */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        if (0 == i % 2) {
            rc = sr_event_notif_subscribe(sub_session[i].session,
                    "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change",
                    test_event_notif_status_change_cb,
                    &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_st);
        } else {
            rc = sr_event_notif_subscribe_tree(sub_session[i].session,
                    "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change",
                    test_event_notif_status_change_tree_cb,
                    &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_st);
        }
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* send event notification (using nodes) - link discovery */
    tree_cnt = 2;
    trees = calloc(tree_cnt, sizeof(*trees));
    /* - source */
    tree = trees;
    tree->name = strdup("source");
    tree->type = SR_CONTAINER_T;
    assert_int_equal(0, sr_node_add_child(trees, "address", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("10.10.1.5");
    assert_int_equal(0, sr_node_add_child(trees, "interface", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("eth1");
    /* - destination */
    tree = trees + 1;
    tree->name = strdup("destination");
    tree->type = SR_CONTAINER_T;
    assert_int_equal(0, sr_node_add_child(trees + 1, "address", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("10.10.1.8");
    assert_int_equal(0, sr_node_add_child(trees + 1, "interface", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("eth0");

    rc = sr_event_notif_send_tree(notif_session, "/test-module:link-discovered", trees, tree_cnt, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    sr_free_trees(trees, tree_cnt);

    /* send event notification (using values) - link removal */
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

    rc = sr_event_notif_send(notif_session, "/test-module:link-removed", values, 4, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* send event notification - link overutilized (not defined in yang) */
    tree_cnt = 2;
    trees = calloc(tree_cnt, sizeof(*trees));
    /* - source */
    tree = trees;
    tree->name = strdup("source");
    tree->type = SR_CONTAINER_T;
    assert_int_equal(0, sr_node_add_child(trees, "address", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("10.10.1.5");
    assert_int_equal(0, sr_node_add_child(trees, "interface", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("eth1");
    /* - destination */
    tree = trees + 1;
    tree->name = strdup("destination");
    tree->type = SR_CONTAINER_T;
    assert_int_equal(0, sr_node_add_child(trees + 1, "address", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("10.10.1.8");
    assert_int_equal(0, sr_node_add_child(trees + 1, "interface", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("eth0");

    rc = sr_event_notif_send_tree(notif_session, "/test-module:link-overutilized", trees, tree_cnt, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_VALIDATION_FAILED);
    sr_free_trees(trees, tree_cnt);

    /* send event notification (using nodes) - status-change */
    tree_cnt = 2;
    trees = calloc(tree_cnt, sizeof(*trees));
    /* - loaded */
    tree = trees;
    tree->name = strdup("loaded");
    tree->type = SR_BOOL_T;
    tree->data.bool_val = true;
    /* - time-of-change */
    tree = trees + 1;
    tree->name = strdup("time-of-change");
    tree->type = SR_UINT32_T;
    tree->data.uint32_val = 18;

    rc = sr_event_notif_send_tree(notif_session, "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change",
            trees, tree_cnt, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    sr_free_trees(trees, tree_cnt);

    /* send event notification (using values) - status-change */
    values[0].xpath = "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change/loaded";
    values[0].type = SR_BOOL_T;
    values[0].data.bool_val = true;
    values[1].xpath = "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change/time-of-change";
    values[1].type = SR_UINT32_T;
    values[1].data.uint32_val = 18;

    rc = sr_event_notif_send(notif_session, "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change",
            values, 2, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* wait at most 5 seconds for all callbacks to get called */
    struct timespec ts;
    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += 5;
    while (ETIMEDOUT != pthread_cond_timedwait(&cb_status.cond, &cb_status.mutex, &ts)
            && (cb_status.link_removed < CL_TEST_EN_NUM_SESSIONS || cb_status.link_discovered < CL_TEST_EN_NUM_SESSIONS ||
                cb_status.status_change < 2*CL_TEST_EN_NUM_SESSIONS));
    assert_int_equal(CL_TEST_EN_NUM_SESSIONS, cb_status.link_discovered);
    assert_int_equal(CL_TEST_EN_NUM_SESSIONS, cb_status.link_removed);
    assert_int_equal(2*CL_TEST_EN_NUM_SESSIONS, cb_status.status_change);
    assert_int_equal(0, pthread_mutex_unlock(&cb_status.mutex));

    /* unsubscribe */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_ld);
        assert_int_equal(rc, SR_ERR_OK);
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_lr);
        assert_int_equal(rc, SR_ERR_OK);
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_lo);
        assert_int_equal(rc, SR_ERR_OK);
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_st);
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

#ifdef ENABLE_NOTIF_STORE
static void
test_event_notif_link_discovery_replay_cb(const sr_ev_notif_type_t notif_type, const char *xpath,
        const sr_val_t *values, const size_t values_cnt, time_t timestamp, void *private_ctx)
{
    cl_test_en_cb_status_t *cb_status = (cl_test_en_cb_status_t*)private_ctx;

    assert_string_equal("/test-module:link-discovered", xpath);

    assert_false(SR_EV_NOTIF_T_REALTIME == notif_type);

    if (SR_EV_NOTIF_T_REPLAY == notif_type) {
        assert_int_equal(values_cnt, 7);
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

        assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
        cb_status->link_discovered += 1;
        assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
    }

    if (SR_EV_NOTIF_T_REPLAY_COMPLETE == notif_type) {
        assert_int_equal(values_cnt, 0);
        assert_null(values);

        assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
        cb_status->link_discovered += 1;
        assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
    }

    if (SR_EV_NOTIF_T_REPLAY_STOP == notif_type) {
        assert_int_equal(values_cnt, 0);
        assert_null(values);

        assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
        cb_status->link_discovered += 1;
        assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
    }

    assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
    if (cb_status->link_discovered == 3) {
        assert_int_equal(0, pthread_cond_signal(&cb_status->cond));
    }
    assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
}
#endif

#ifdef ENABLE_NOTIF_STORE
static void
test_event_notif_link_removed_replay_cb(const sr_ev_notif_type_t notif_type, const char *xpath, const sr_val_t *values,
        const size_t values_cnt, time_t timestamp, void *private_ctx)
{
    cl_test_en_cb_status_t *cb_status = (cl_test_en_cb_status_t*)private_ctx;

    assert_false(SR_EV_NOTIF_T_REALTIME == notif_type);

    if (SR_EV_NOTIF_T_REPLAY == notif_type) {
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

        assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
        cb_status->link_removed += 1;
        assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
    }

    if (SR_EV_NOTIF_T_REPLAY_COMPLETE == notif_type) {
        assert_int_equal(values_cnt, 0);
        assert_null(values);

        assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
        cb_status->link_removed += 1;
        assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
    }

    if (SR_EV_NOTIF_T_REPLAY_STOP == notif_type) {
        assert_int_equal(values_cnt, 0);
        assert_null(values);

        assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
        cb_status->link_removed += 1;
        assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
    }

    assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
    if (cb_status->link_removed == 3) {
        assert_int_equal(0, pthread_cond_signal(&cb_status->cond));
    }
    assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
}
#endif

static void
cl_event_notif_replay_test(void **state)
{
#ifndef ENABLE_NOTIF_STORE
    skip();
#else
    sr_conn_ctx_t *conn = *state;
    sr_subscription_ctx_t *subscription = NULL;
    assert_non_null(conn);
    cl_test_en_cb_status_t cb_status;
    sr_val_t values[4];
    int rc = SR_ERR_OK;

    time_t start_time = time(NULL);

    sr_session_ctx_t *session = NULL;

    memset(&values, '\0', sizeof(values));
    cb_status.link_discovered = 0;
    cb_status.link_removed = 0;
    cb_status.status_change = 0;
    assert_int_equal(0, pthread_mutex_init(&cb_status.mutex, NULL));
    assert_int_equal(0, pthread_cond_init(&cb_status.cond, NULL));
    assert_int_equal(0, pthread_mutex_lock(&cb_status.mutex));

    /* start session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe for link discovery */
    rc = sr_event_notif_subscribe(session, "/test-module:link-discovered", test_event_notif_link_discovery_replay_cb,
            &cb_status, SR_SUBSCR_NOTIF_REPLAY_FIRST, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe for link removal */
    rc = sr_event_notif_subscribe(session, "/test-module:link-removed", test_event_notif_link_removed_replay_cb,
            &cb_status, SR_SUBSCR_NOTIF_REPLAY_FIRST | SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

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

    rc = sr_event_notif_send(session, "/test-module:link-discovered", values, 4, SR_EV_NOTIF_DEFAULT);
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

    rc = sr_event_notif_send(session, "/test-module:link-removed", values, 4, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* replay the notifications */
    rc = sr_event_notif_replay(session, subscription, start_time, time(NULL) + 1);
    assert_int_equal(rc, SR_ERR_OK);

    /* wait at most 5 seconds for all callbacks to get called */
    struct timespec ts;
    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += 5;
    while (ETIMEDOUT != pthread_cond_timedwait(&cb_status.cond, &cb_status.mutex, &ts)
            && (cb_status.link_removed < 3 || cb_status.link_discovered < 3));
    assert_true(cb_status.link_discovered >= 3);
    assert_true(cb_status.link_removed >= 3);
    assert_int_equal(0, pthread_mutex_unlock(&cb_status.mutex));

    /* unsubscribe */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);

    /* cleanup */
    assert_int_equal(0, pthread_mutex_destroy(&cb_status.mutex));
    assert_int_equal(0, pthread_cond_destroy(&cb_status.cond));
#endif
}

static void
cl_cross_module_dependency(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;

    int rc = SR_ERR_OK;
    sr_val_t *value = NULL;
    sr_val_t val = {0};

    /* start session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* clean prev data */
    rc = sr_delete_item(session, "/referenced-data:*", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_delete_item(session, "/cross-module:*", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_commit(session);
    assert_int_equal(SR_ERR_OK, rc);

    val.type = SR_STRING_T;
    val.data.string_val = "abcd";

    /* create leafref */
    rc = sr_set_item(session, "/cross-module:reference", &val, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_get_item(session, "/cross-module:reference", &value);
    assert_int_equal(rc, SR_ERR_OK);

    assert_non_null(value);
    assert_int_equal(SR_STRING_T, value->type);
    assert_string_equal(val.data.string_val, value->data.string_val);
    sr_free_val(value);

    /* referenced node does not exists yet*/
    rc = sr_validate(session);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);

    /* create referenced node*/
    rc = sr_set_item(session, "/referenced-data:list-b[name='abcd']", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_validate(session);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_commit(session);
    assert_int_equal(SR_ERR_OK, rc);

    val.type = SR_UINT32_T;
    val.data.uint32_val = 100;
    rc = sr_set_item(session, "/referenced-data:list-b[name='abcd']/value", &val, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_set_item(session, "/cross-module:links/value_in_list", &val, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_validate(session);
    assert_int_equal(SR_ERR_OK, rc);

    val.type = SR_UINT8_T;
    val.data.uint8_val = 10;

    rc = sr_set_item(session, "/cross-module:links/number", &val, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    val.type = SR_UINT8_T;
    val.data.uint8_val = 42;

    rc = sr_set_item(session, "/referenced-data:magic_number", &val, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* must statement not satisfied */
    rc = sr_validate(session);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);

    rc = sr_set_item(session, "/cross-module:links/number", &val, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_validate(session);
    assert_int_equal(SR_ERR_OK, rc);

    sr_session_stop(session);
}

static void
cl_data_in_submodule(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subs = NULL;

    int rc = SR_ERR_OK;
    sr_val_t *value = NULL;
    sr_val_t val = {0};

    /* start session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* clean prev data */
    val.type = SR_STRING_T;
    val.data.string_val = "abc";

    rc = sr_set_item(session, "/module-a:sub-two-leaf", &val, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_commit(session);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_session_switch_ds(session, SR_DS_RUNNING);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_module_change_subscribe(session, "module-a", empty_module_change_cb, NULL, 0, SR_SUBSCR_DEFAULT, &subs);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_get_item(session, "/module-a:sub-two-leaf", &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_non_null(value);
    assert_int_equal(SR_STRING_T, value->type);
    assert_string_equal("/module-a:sub-two-leaf", value->xpath);
    sr_free_val(value);

    sr_unsubscribe(session, subs);
    sr_session_stop(session);
}

static void
cl_get_schema_with_subscription(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subs = NULL;

    int rc = SR_ERR_OK;

    /* start session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_subtree_change_subscribe(session, "/ietf-interfaces:interfaces/interface", empty_module_change_cb, NULL, 0, SR_SUBSCR_DEFAULT, &subs);
    assert_int_equal(SR_ERR_OK, rc);

    char *content = NULL;
    rc = sr_get_schema(session, "ietf-ip", NULL, NULL, SR_SCHEMA_YANG, &content);
    assert_int_equal(rc, SR_ERR_OK);

    assert_non_null(content);
    free(content);

    sr_unsubscribe(session, subs);
    sr_session_stop(session);
}

static void
cl_session_get_id_test (void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;

    assert_int_equal(0, sr_session_get_id(session));

    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_not_equal(0, sr_session_get_id(session));

    sr_session_stop(session);
}

static void
cl_apos_xpath_test (void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;

    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(SR_ERR_OK, rc);

    char *xp = "/example-module:container/list[key1=\"abc'def\"][key2=\"xy'z\"]";

    /* list */
    rc = sr_set_item(session, xp, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_commit(session);
    assert_int_equal(SR_ERR_OK, rc);

    sr_val_t *v = NULL;

    rc = sr_get_item(session, xp, &v);
    assert_int_equal(SR_ERR_OK, rc);

    assert_string_equal(xp, v->xpath);

    sr_free_val(v);

    rc = sr_delete_item(session, xp, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_get_item(session, xp, &v);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* leaf-list */
    char *ll_xpath = "/example-module:array[.=\"val'apos\"]";
    rc = sr_set_item(session, ll_xpath, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_commit(session);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_get_item(session, ll_xpath, &v);
    assert_int_equal(SR_ERR_OK, rc);

    assert_string_equal("/example-module:array", v->xpath);

    sr_free_val(v);

    rc = sr_delete_item(session, ll_xpath, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_get_item(session, ll_xpath, &v);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    sr_session_stop(session);
}

int
main()
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(cl_connection_test, logging_setup, NULL),
            cmocka_unit_test_setup_teardown(cl_multiconnect_test, logging_setup, NULL),
            cmocka_unit_test_setup_teardown(cl_disconnect_test, logging_setup, NULL),
            cmocka_unit_test_setup_teardown(cl_list_schemas_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_get_schema_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_get_item_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_get_items_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_get_items_iter_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_get_subtree_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_get_subtrees_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_iterative_tree_traversal, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_iterative_trees_traversal, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_set_item_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_delete_item_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_move_item_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_validate_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_commit_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_discard_changes_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_locking_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_ds_locking_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_get_error_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_refresh_session, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_refresh_session2, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_notification_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_copy_config_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_copy_config_test2, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_rpc_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_rpc_tree_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_rpc_combo_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_failed_rpc_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_invalid_rpc_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_action_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_action_tree_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_action_combo_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(candidate_ds_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_switch_ds, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_candidate_refresh, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_get_changes_iter_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_get_changes_iter_multi_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_enable_empty_startup, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_dp_get_items_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_session_set_opts, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_event_notif_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_event_notif_tree_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_event_notif_combo_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_event_notif_replay_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_cross_module_dependency, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_data_in_submodule, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_get_schema_with_subscription, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_set_item_str_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_session_get_id_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_apos_xpath_test, sysrepo_setup, sysrepo_teardown),
    };

    watchdog_start(300);
    int ret = cmocka_run_group_tests(tests, NULL, NULL);
    watchdog_stop();
    return ret;
}
