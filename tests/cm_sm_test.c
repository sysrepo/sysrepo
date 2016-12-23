/**
 * @file cm_sm_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Connection Manager's Session Manager unit tests.
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
#include <unistd.h>
#include <sys/socket.h>
#include <setjmp.h>
#include <cmocka.h>

#include "sr_common.h"
#include "cm_session_manager.h"
#include "system_helper.h"

static int
setup(void **state) {
    sm_ctx_t *ctx = NULL;

    sr_logger_init("sm_test");
    sr_log_stderr(SR_LL_DBG);

    sm_init(NULL, NULL, &ctx);
    *state = ctx;

    return 0;
}

static int
teardown(void **state) {
    sm_ctx_t *ctx = *state;

    sm_cleanup(ctx);
    sr_logger_cleanup();

    return 0;
}

/**
 * Creates, initializes and drops one session.
 */
static void
session_create_drop(void **state) {
#ifdef __linux__
    sm_ctx_t *ctx = *state;
    sm_connection_t *conn = NULL;
    sm_session_t *sess = NULL;
    int sockets[2] = { 0, };
    int rc = SR_ERR_OK;

    /* create some sockets */
    socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);

    /* start a connection */
    rc = sm_connection_start(ctx, CM_AF_UNIX_CLIENT, sockets[0], &conn);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(conn);

    /* create one session */
    rc = sm_session_create(ctx, conn, NULL, &sess);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(sess);

    /* drop session */
    rc = sm_session_drop(ctx, sess);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop a connection */
    rc = sm_connection_stop(ctx, conn);
    assert_int_equal(rc, SR_ERR_OK);
#endif
}

/**
 * Creates 100 sessions, searches for one by session id, drops it.
 * Outstanding 99 sessions should be removed automatically in teardown.
 */
static void
session_find_id(void **state) {
#ifdef __linux__
    sm_ctx_t *ctx = *state;
    sm_connection_t *conn = NULL;
    sm_session_t *sess = NULL;
    int sockets[2] = { 0, };
    int rc = SR_ERR_OK;

    /* create some sockets */
    socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);

    /* start a connection */
    rc = sm_connection_start(ctx, CM_AF_UNIX_CLIENT, sockets[0], &conn);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(conn);

    /* create 100 sessions */
    size_t i = 0;
    for (i = 0; i < 100; i ++) {
        rc = sm_session_create(ctx, conn, NULL, &sess);
        assert_int_equal(rc, SR_ERR_OK);
        assert_non_null(sess);
    }

    /* save session id of last session */
    uint32_t id = sess->id;
    sess = NULL;

    /* find session by id */
    rc = sm_session_find_id(ctx, id, &sess);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(sess);

    /* drop session */
    rc = sm_session_drop(ctx, sess);
    assert_int_equal(rc, SR_ERR_OK);

    /* find session by id again - should return not found */
    sess = NULL;
    rc = sm_session_find_id(ctx, id, &sess);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);
    assert_null(sess);

    /* stop the connection */
    rc = sm_connection_stop(ctx, conn);
    assert_int_equal(rc, SR_ERR_OK);
#endif
}

/**
 * Creates 100 sessions, searches for one by fd, drops it.
 * Outstanding 99 sessions should be removed automatically in teardown.
 */
static void
session_find_fd(void **state) {
#ifdef __linux__
    sm_ctx_t *ctx = *state;
    sm_connection_t *conn = NULL;
    sm_session_t *sess = NULL;
    sm_session_list_t *curr = NULL;
    int sockets[2] = { 0, };
    int rc = SR_ERR_OK, cnt = 0;

    /* create 100 sessions in 10 connections */
    int i = 0;
    for (i = 0; i < 100; i ++) {
        if (0 == i % 10) {
            conn = NULL;
            socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
            rc = sm_connection_start(ctx, CM_AF_UNIX_CLIENT, sockets[0], &conn);
            assert_int_equal(rc, SR_ERR_OK);
            assert_non_null(conn);
        }
        rc = sm_session_create(ctx, conn, NULL, &sess);
        assert_int_equal(rc, SR_ERR_OK);
        assert_non_null(sess);
    }

    /* find connection by fd */
    conn = NULL;
    rc = sm_connection_find_fd(ctx, sockets[0], &conn);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(conn);

    curr = conn->session_list;
    cnt = 0;
    sm_session_t *s0 = 0, *s5 = 0, *s9 = 0;
    while (NULL != curr) {
        if (0 == cnt) s0 = curr->session;
        if (5 == cnt) s5 = curr->session;
        if (9 == cnt) s9 = curr->session;
        curr = curr->next;
        cnt++;
    }
    assert_int_equal(cnt, 10);

    /* drop first, middle and last session from list */
    rc = sm_session_drop(ctx, s0);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sm_session_drop(ctx, s5);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sm_session_drop(ctx, s9);
    assert_int_equal(rc, SR_ERR_OK);

    /* find connection by fd again */
    conn = NULL;
    rc = sm_connection_find_fd(ctx, sockets[0], &conn);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(conn);

    curr = conn->session_list;
    cnt = 0;
    while (NULL != curr) {
        /* check for already removed sessions */
        assert_ptr_not_equal(curr->session, s0);
        assert_ptr_not_equal(curr->session, s5);
        assert_ptr_not_equal(curr->session, s9);
        curr = curr->next;
        cnt++;
    }
    assert_int_equal(cnt, 7);
#endif
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(session_create_drop, setup, teardown),
            cmocka_unit_test_setup_teardown(session_find_id, setup, teardown),
            cmocka_unit_test_setup_teardown(session_find_fd, setup, teardown),
    };

    watchdog_start(300);
    int ret = cmocka_run_group_tests(tests, NULL, NULL);
    watchdog_stop();
    return ret;
}

