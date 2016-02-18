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
#include "test_module_helper.h"

static int
logging_setup(void **state)
{
    sr_set_log_level(SR_LL_DBG, SR_LL_ERR); /* print debugs to stderr */
    sr_logger_init("ac_test");

    return 0;
}

static int
logging_cleanup(void **state)
{
    sr_logger_cleanup();

    return 0;
}

static void
ac_test_unpriviledged(void **state)
{
    ac_ctx_t *ctx = NULL;
    ac_session_t *session = NULL;
    xp_loc_id_t *loc_id = NULL;
    int rc = SR_ERR_OK;

    if (0 == getuid()) {
        /* run the test only for unprivileged user */
        return;
    }

    /* set real user to current user */
    ac_ucred_t credentials = { 0 };
    credentials.r_username = getenv("USER");
    credentials.r_uid = getuid();
    credentials.r_gid = getgid();

    /* init */
    rc = ac_init(&ctx);
    assert_int_equal(rc, SR_ERR_OK);
    rc = ac_session_init(ctx, &credentials, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* node permission checks */
    rc = xp_char_to_loc_id(XP_TEST_MODULE_STRING, &loc_id);
    assert_int_equal(rc, SR_ERR_OK);

    rc = ac_check_node_permissions(session, loc_id, AC_OPER_READ);
    assert_int_equal(rc, SR_ERR_OK);

    rc = ac_check_node_permissions(session, loc_id, AC_OPER_READ_WRITE);
    assert_int_equal(rc, SR_ERR_OK);

    rc = ac_check_node_permissions(session, loc_id, AC_OPER_READ);
    assert_int_equal(rc, SR_ERR_OK);

    rc = ac_check_node_permissions(session, loc_id, AC_OPER_READ_WRITE);
    assert_int_equal(rc, SR_ERR_OK);

    xp_free_loc_id(loc_id);

    /* file permission checks */
    rc = ac_check_file_permissions(session, "/etc/passwd", AC_OPER_READ);
    assert_int_equal(rc, SR_ERR_OK);

    rc = ac_check_file_permissions(session, "/etc/passwd", AC_OPER_READ_WRITE);
    assert_int_equal(rc, SR_ERR_UNAUTHORIZED);

    /* cleanup */
    ac_session_cleanup(session);
    ac_cleanup(ctx);
}

static void
ac_test_priviledged(void **state)
{
    ac_ctx_t *ctx = NULL;
    ac_session_t *session = NULL;
    xp_loc_id_t *loc_id = NULL;
    int rc = SR_ERR_OK;

    if (0 != getuid()) {
        /* run the test only for privileged user */
        return;
    }

    /* set real user to current user */
    ac_ucred_t credentials1 = { 0 };
    credentials1.r_username = getenv("USER");
    credentials1.r_uid = getuid();
    credentials1.r_gid = getgid();

    /* set real user to current user */
    ac_ucred_t credentials2 = { 0 };
    credentials2.r_username = getenv("USER");
    credentials2.r_uid = getuid();
    credentials2.r_gid = getgid();
    credentials2.e_username = getenv("SUDO_USER");
    credentials2.e_uid = getenv("SUDO_UID");
    credentials2.e_gid = getenv("SUDO_GID");

    /* init */
    rc = ac_init(&ctx);
    assert_int_equal(rc, SR_ERR_OK);
    rc = ac_session_init(ctx, &credentials1, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* node permission checks */
    rc = xp_char_to_loc_id(XP_TEST_MODULE_STRING, &loc_id);
    assert_int_equal(rc, SR_ERR_OK);

    rc = ac_check_node_permissions(session, loc_id, AC_OPER_READ);
    assert_int_equal(rc, SR_ERR_OK);

    rc = ac_check_node_permissions(session, loc_id, AC_OPER_READ_WRITE);
    assert_int_equal(rc, SR_ERR_OK);

    rc = ac_check_node_permissions(session, loc_id, AC_OPER_READ);
    assert_int_equal(rc, SR_ERR_OK);

    rc = ac_check_node_permissions(session, loc_id, AC_OPER_READ_WRITE);
    assert_int_equal(rc, SR_ERR_OK);

    xp_free_loc_id(loc_id);

    /* file permission checks */
    rc = ac_check_file_permissions(session, "/etc/passwd", AC_OPER_READ);
    assert_int_equal(rc, SR_ERR_OK);

    rc = ac_check_file_permissions(session, "/etc/passwd", AC_OPER_READ_WRITE);
    assert_int_equal(rc, SR_ERR_OK);

    /* cleanup */
    ac_session_cleanup(session);
    ac_cleanup(ctx);
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(ac_test_unpriviledged, logging_setup, logging_cleanup),
            cmocka_unit_test_setup_teardown(ac_test_priviledged, logging_setup, logging_cleanup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
