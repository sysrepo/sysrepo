/**
 * @file ac_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Access Control module unit tests.
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
#include <sys/socket.h>
#include <setjmp.h>
#include <cmocka.h>

#include "sr_common.h"
#include "access_control.h"

static int
logging_setup(void **state)
{
    sr_set_log_level(SR_LL_DBG, SR_LL_ERR); /* print debugs to stderr */
    sr_logger_init("ac_test");

    return 0;
}

static void
ac_test1(void **state)
{
    ac_ctx_t *ctx = NULL;
    ac_session_t *session = NULL;
    int rc = SR_ERR_OK;

    ac_ucred_t credentials = { 0 };
    credentials.r_username = getenv("USER");
    credentials.r_uid = getuid();
    credentials.r_gid = getgid();
//    credentials.e_username = "rasto";
//    credentials.e_uid = 1000;
//    credentials.e_gid = 1000;

    rc = ac_init(&ctx);
    assert_int_equal(rc, SR_ERR_OK);

    rc = ac_session_init(ctx, &credentials, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = ac_check_file_permissions(ctx, &credentials, "/etc/passwd", AC_OPER_READ);
    assert_int_equal(rc, SR_ERR_OK);

    ac_session_cleanup(session);
    ac_cleanup(ctx);
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(ac_test1, logging_setup, NULL),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
