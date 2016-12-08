/**
 * @file concurr_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo Concurrency tests.
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
#include <setjmp.h>
#include <cmocka.h>
#include <pthread.h>

#include "sysrepo.h"
#include "sr_common.h"

#include "test_module_helper.h"

#define TEST_THREAD_COUNT 10

static int
sysrepo_setup(void **state)
{
    createDataTreeExampleModule();
    sr_conn_ctx_t *conn = NULL;
    int rc = SR_ERR_OK;

    /* abort if test fails (needed for tests with multiple threads) */
    putenv("CMOCKA_TEST_ABORT=1");

    sr_logger_init(NULL);
    /* turn off all logging */
    sr_log_stderr(SR_LL_NONE);
    sr_log_syslog(SR_LL_NONE);

    /* connect to sysrepo */
    rc = sr_connect("concurr_test", SR_CONN_DEFAULT, &conn);
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

    sr_logger_cleanup();

    return 0;
}

static void
test_execute_in_session(sr_session_ctx_t *session)
{
    int rc = 0;
    sr_val_t *value = NULL;
    sr_node_t *tree = NULL;

    /* perform get-item requests */
    for (size_t i = 0; i<500; i++) {
        /* existing leaf */
        rc = sr_get_item(session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &value);
        assert_int_equal(rc, SR_ERR_OK);
        assert_non_null(value);
        assert_int_equal(SR_STRING_T, value->type);
        sr_free_val(value);
        rc = sr_get_subtree(session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", 0, &tree);
        assert_int_equal(rc, SR_ERR_OK);
        assert_non_null(tree);
        assert_int_equal(SR_STRING_T, tree->type);
        sr_free_tree(tree);
    }
}

static void *
test_thread_execute_in_sess(void *sr_session_ctx_p)
{
    sr_session_ctx_t *session = (sr_session_ctx_t*)sr_session_ctx_p;

    test_execute_in_session(session);

    return NULL;
}

static void *
test_thread_execute_in_conn(void *sr_conn_ctx_p)
{
    sr_conn_ctx_t *conn = (sr_conn_ctx_t*)sr_conn_ctx_p;

    sr_session_ctx_t *session = NULL;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    test_execute_in_session(session);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);

    return NULL;
}

static void *
test_thread_execute_separated(void *ctx)
{
    sr_conn_ctx_t *conn = NULL;
    sr_session_ctx_t *session = NULL;
    int rc = 0;

    /* connect to sysrepo */
    rc = sr_connect("concurr_test", SR_CONN_DEFAULT, &conn);
    assert_int_equal(rc, SR_ERR_OK);

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    test_execute_in_session(session);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);

    /* disconnect from sysrepo */
    sr_disconnect(conn);

    return NULL;
}

/**
 * Test concurrent requests within one session.
 */
static void
concurr_requests_test(void **state)
{
    pthread_t threads[TEST_THREAD_COUNT];
    size_t i = 0;
    sr_session_ctx_t *session = NULL;
    int rc = 0;
    sr_conn_ctx_t *conn = *state;

    assert_non_null(state);

    /* start a session */
   rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
   assert_int_equal(rc, SR_ERR_OK);

    for (i = 0; i < TEST_THREAD_COUNT; i++) {
        pthread_create(&threads[i], NULL, test_thread_execute_in_sess, session);
    }
    for (i = 0; i < TEST_THREAD_COUNT; i++) {
        pthread_join(threads[i], NULL);
    }

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

/**
 * Test concurrent sessions within one connection.
 */
static void
concurr_sessions_test(void **state)
{
    pthread_t threads[TEST_THREAD_COUNT];
    size_t i = 0;
    sr_conn_ctx_t *conn = *state;

    assert_non_null(state);

    for (i = 0; i < TEST_THREAD_COUNT; i++) {
        pthread_create(&threads[i], NULL, test_thread_execute_in_conn, conn);
    }
    for (i = 0; i < TEST_THREAD_COUNT; i++) {
        pthread_join(threads[i], NULL);
    }
}

/**
 * Test concurrent connections.
 */
static void
concurr_connections_test(void **state)
{
    pthread_t threads[TEST_THREAD_COUNT];
    size_t i = 0;
    sr_conn_ctx_t *conn = *state;

    assert_non_null(state);

    for (i = 0; i < TEST_THREAD_COUNT; i++) {
        pthread_create(&threads[i], NULL, test_thread_execute_separated, conn);
    }
    for (i = 0; i < TEST_THREAD_COUNT; i++) {
        pthread_join(threads[i], NULL);
    }
}

int
main()
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(concurr_requests_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(concurr_sessions_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(concurr_connections_test, sysrepo_setup, sysrepo_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
