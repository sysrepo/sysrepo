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

int
setup(void **state) {
    sm_ctx_t *ctx = NULL;

    sm_init(&ctx);
    *state = ctx;

    return 0;
}

int
teardown(void **state) {
    sm_ctx_t *ctx = *state;

    sm_cleanup(ctx);

    return 0;
}

void
session_create_auto_cleanup(void **state) {
    sm_ctx_t *ctx = *state;
    sm_session_t *sess = NULL;
    int rc = SR_ERR_OK;

    rc = sm_session_create(ctx, SM_AF_UNIX_CLIENT_REMOTE, &sess);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sm_session_assign_fd(ctx, sess, 10);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sm_session_assign_user(ctx, sess, "root", "alice");
    assert_int_equal(rc, SR_ERR_OK);
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(session_create_auto_cleanup, setup, teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

