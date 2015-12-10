/**
 * @file session_manager.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Session Manager unit tests.
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
#include <setjmp.h>
#include <cmocka.h>

#include "sr_common.h"
#include "session_manager.h"

static int
setup(void **state) {
    sm_ctx_t *ctx = NULL;

    sr_logger_init(NULL);
    sr_logger_set_level(SR_LL_ERR, SR_LL_ERR); /* print only errors. */

    sm_init(&ctx);
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
    sm_ctx_t *ctx = *state;
    sm_session_t *sess = NULL;
    int rc = SR_ERR_OK;

    /* create one session */
    rc = sm_session_create(ctx, SM_AF_UNIX_CLIENT_REMOTE, &sess);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(sess);

    rc = sm_session_assign_fd(ctx, sess, 10);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sm_session_assign_user(ctx, sess, "root", "alice");
    assert_int_equal(rc, SR_ERR_OK);

    /* drop session */
    rc = sm_session_drop(ctx, sess);
    assert_int_equal(rc, SR_ERR_OK);
}

/**
 * Creates 100 sessions, searches for one by session id, drops it.
 * Outstanding 99 sessions should be removed automatically in teardown.
 */
static void
session_find_id(void **state) {
    sm_ctx_t *ctx = *state;
    sm_session_t *sess = NULL;
    int rc = SR_ERR_OK;

    /* create 100 sessions */
    size_t i = 0;
    for (i = 0; i < 100; i ++) {
        rc = sm_session_create(ctx, SM_AF_UNIX_CLIENT_REMOTE, &sess);
        assert_int_equal(rc, SR_ERR_OK);
        assert_non_null(sess);
        rc = sm_session_assign_user(ctx, sess, "root", "alice");
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* save session id of last session */
    assert_non_null(sess);
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
}

/**
 * Creates 100 sessions, searches for one by fd, drops it.
 * Outstanding 99 sessions should be removed automatically in teardown.
 */
static void
session_find_fd(void **state) {
    sm_ctx_t *ctx = *state;
    sm_session_t *sess = NULL;
    int rc = SR_ERR_OK;

    /* create 100 sessions */
    int i = 0;
    for (i = 0; i < 100; i ++) {
        rc = sm_session_create(ctx, SM_AF_UNIX_CLIENT_REMOTE, &sess);
        assert_int_equal(rc, SR_ERR_OK);
        assert_non_null(sess);
        rc = sm_session_assign_user(ctx, sess, "root", "alice");
        assert_int_equal(rc, SR_ERR_OK);
        rc = sm_session_assign_fd(ctx, sess, i);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* find session by fd */
    rc = sm_session_find_fd(ctx, 50, &sess);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(sess);

    /* drop session */
    rc = sm_session_drop(ctx, sess);
    assert_int_equal(rc, SR_ERR_OK);

    /* find session by fd again - should return not found */
    sess = NULL;
    rc = sm_session_find_fd(ctx, 50, &sess);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);
    assert_null(sess);
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(session_create_drop, setup, teardown),
            cmocka_unit_test_setup_teardown(session_find_id, setup, teardown),
            cmocka_unit_test_setup_teardown(session_find_fd, setup, teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

