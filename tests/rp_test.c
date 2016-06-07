/**
 * @file rp_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Request Processor unit tests.
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
#include "access_control.h"
#include "request_processor.h"

static int
rp_setup(void **state)
{
    rp_ctx_t *rp_ctx = NULL;
    int rc = 0;

    sr_logger_init("rp_test");
    sr_log_stderr(SR_LL_DBG);

    rc = rp_init(NULL, &rp_ctx);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(rp_ctx);

    *state = rp_ctx;
    return 0;
}

static int
rp_teardown(void **state)
{
    rp_ctx_t *rp_ctx = *state;
    assert_non_null(rp_ctx);

    rp_cleanup(rp_ctx);
    sr_logger_cleanup();

    return 0;
}

/*
 * Test creating 100 RP sessions.
 */
static void
rp_session_test(void **state)
{
    int rc = 0, i = 0;
    rp_session_t *session = NULL;

    ac_ucred_t credentials = { 0 };
    credentials.e_uid = getuid();
    credentials.e_gid = getgid();

    rp_ctx_t *rp_ctx = *state;
    assert_non_null(rp_ctx);

    for (i = 0; i < 100; i++) {
        /* create a session */
        rc = rp_session_start(rp_ctx, 123456, &credentials, SR_DS_STARTUP, SR_SESS_DEFAULT, 0, &session);
        assert_int_equal(rc, SR_ERR_OK);
        assert_non_null(session);

        /* stop the session */
        rc = rp_session_stop(rp_ctx, session);
        assert_int_equal(rc, SR_ERR_OK);
    }
}

/**
 * Test RP processing of an invalid messages.
 */
static void
rp_msg_neg_test(void **state)
{
    int rc = 0;
    rp_session_t *session = NULL;
    Sr__Msg *msg = NULL;

    rp_ctx_t *rp_ctx = *state;
    assert_non_null(rp_ctx);

    ac_ucred_t credentials = { 0 };
    credentials.e_uid = getuid();
    credentials.e_gid = getgid();

    /* generate some request */
    rc = sr_gpb_req_alloc(SR__OPERATION__GET_ITEM, 123456, &msg);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(msg);

    /* process the message with NULL session */
    rc = rp_msg_process(rp_ctx, NULL, msg);
    assert_int_equal(rc, SR_ERR_OK);

    /* create a session */
    rc = rp_session_start(rp_ctx, 123456, &credentials, SR_DS_STARTUP, SR_SESS_DEFAULT, 0, &session);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(session);

    /* RP does not implement session start request */
    rc = sr_gpb_req_alloc(SR__OPERATION__SESSION_START, 123456, &msg);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(msg);

    /* process the message */
    rc = rp_msg_process(rp_ctx, session, msg);
    assert_int_equal(rc, SR_ERR_OK);

    /* RP does not implement session start response */
    rc = sr_gpb_resp_alloc(SR__OPERATION__SESSION_START, 123456, &msg);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(msg);

    /* process the message */
    rc = rp_msg_process(rp_ctx, session, msg);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop the session */
    rc = rp_session_stop(rp_ctx, session);
    assert_int_equal(rc, SR_ERR_OK);
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(rp_session_test, rp_setup, rp_teardown),
            cmocka_unit_test_setup_teardown(rp_msg_neg_test, rp_setup, rp_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
