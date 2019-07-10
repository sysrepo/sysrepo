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
#include <fcntl.h>

#include "sr_common.h"
#include "access_control.h"
#include "test_module_helper.h"
#include "test_data.h"
#include "system_helper.h"

/**
 * @brief Test setup routine.
 */
static int
ac_test_setup(void **state)
{
    sr_logger_init("ac_test");
    sr_log_stderr(SR_LL_DBG);

    unlink(TEST_MODULE_DATA_FILE_NAME);
    umask(S_IWGRP | S_IRGRP | S_IWOTH | S_IROTH);
    createDataTreeTestModule();

    return 0;
}

/**
 * @brief Test teardown routine.
 */
static int
ac_test_teardown(void **state)
{
    sr_logger_cleanup();

    unlink(TEST_MODULE_DATA_FILE_NAME);

    return 0;
}

/**
 * @brief Test authorization features when running as an unprivileged process.
 */
static void
ac_test_unpriviledged(void **state)
{
    ac_ctx_t *ctx = NULL;
    ac_session_t *session = NULL;
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
    rc = ac_init(TEST_DATA_SEARCH_DIR, &ctx);
    assert_int_equal(rc, SR_ERR_OK);
    rc = ac_session_init(ctx, &credentials, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* node permission checks */

    /* attempt 1 */
    rc = ac_check_node_permissions(session, XP_TEST_MODULE_STRING, AC_OPER_READ);
    assert_int_equal(rc, SR_ERR_OK);
    rc = ac_check_node_permissions(session, XP_TEST_MODULE_STRING, AC_OPER_READ_WRITE);
    assert_int_equal(rc, SR_ERR_OK);

    /* attempt 2 */
    rc = ac_check_node_permissions(session, XP_TEST_MODULE_STRING, AC_OPER_READ);
    assert_int_equal(rc, SR_ERR_OK);
    rc = ac_check_node_permissions(session, XP_TEST_MODULE_STRING, AC_OPER_READ_WRITE);
    assert_int_equal(rc, SR_ERR_OK);


    /* file permission checks */
    rc = ac_check_file_permissions(session, "/etc/passwd", AC_OPER_READ);
    assert_int_equal(rc, SR_ERR_OK);

    rc = ac_check_file_permissions(session, "/etc/passwd", AC_OPER_READ_WRITE);
    assert_int_equal(rc, SR_ERR_UNAUTHORIZED);

    /* cleanup */
    ac_session_cleanup(session);
    ac_cleanup(ctx);
}

/**
 * @brief Test authorization features when running as a privileged process.
 */
static void
ac_test_priviledged(void **state)
{
    ac_ctx_t *ctx = NULL;
    ac_session_t *session1 = NULL, *session2 = NULL, *session3 = NULL;
    int rc = SR_ERR_OK;

    if (0 != getuid()) {
        /* run the test only for privileged user */
        return;
    }
    bool proc_sudo = (NULL != getenv("SUDO_USER")); /* running under sudo */

    /* set real user to current user */
    ac_ucred_t credentials1 = { 0 };
    credentials1.r_username = getenv("USER");
    credentials1.r_uid = getuid();
    credentials1.r_gid = getgid();

    /* set effective user to sudo parent user (if possible) */
    ac_ucred_t credentials2 = { 0 };
    credentials2.r_username = getenv("USER");
    credentials2.r_uid = getuid();
    credentials2.r_gid = getgid();
    if (proc_sudo) {
        credentials2.e_username = getenv("SUDO_USER");
        credentials2.e_uid = atoi(getenv("SUDO_UID"));
        credentials2.e_gid = atoi(getenv("SUDO_GID"));
    }

    /* set real user to sudo parent user (if possible) */
    ac_ucred_t credentials3 = { 0 };
    if (proc_sudo) {
        credentials3.r_username = getenv("SUDO_USER");
        credentials3.r_uid = atoi(getenv("SUDO_UID"));
        credentials3.r_gid = atoi(getenv("SUDO_GID"));
    } else {
        credentials3.r_username = getenv("USER");
        credentials3.r_uid = getuid();
        credentials3.r_gid = getgid();
    }

    /* init */
    rc = ac_init(TEST_DATA_SEARCH_DIR, &ctx);
    assert_int_equal(rc, SR_ERR_OK);
    rc = ac_session_init(ctx, &credentials1, &session1);
    assert_int_equal(rc, SR_ERR_OK);
    rc = ac_session_init(ctx, &credentials2, &session2);
    assert_int_equal(rc, SR_ERR_OK);
    rc = ac_session_init(ctx, &credentials3, &session3);
    assert_int_equal(rc, SR_ERR_OK);

    /* node permission checks */

    /* credentials 1 */
    rc = ac_check_node_permissions(session1, XP_TEST_MODULE_STRING, AC_OPER_READ);
    assert_int_equal(rc, SR_ERR_OK);
    rc = ac_check_node_permissions(session1, XP_TEST_MODULE_STRING, AC_OPER_READ_WRITE);
    assert_int_equal(rc, SR_ERR_OK);

    /* credentials 2 */
    rc = ac_check_node_permissions(session2, XP_TEST_MODULE_STRING, AC_OPER_READ);
    assert_int_equal(rc, (proc_sudo ? SR_ERR_UNAUTHORIZED : SR_ERR_OK));
    rc = ac_check_node_permissions(session2, XP_TEST_MODULE_STRING, AC_OPER_READ_WRITE);
    assert_int_equal(rc, (proc_sudo ? SR_ERR_UNAUTHORIZED : SR_ERR_OK));

    /* credentials 3 */
    rc = ac_check_node_permissions(session3, XP_TEST_MODULE_STRING, AC_OPER_READ);
    assert_int_equal(rc, (proc_sudo ? SR_ERR_UNAUTHORIZED : SR_ERR_OK));
    rc = ac_check_node_permissions(session3, XP_TEST_MODULE_STRING, AC_OPER_READ);
    assert_int_equal(rc, (proc_sudo ? SR_ERR_UNAUTHORIZED : SR_ERR_OK));

    rc = ac_check_node_permissions(session3, XP_TEST_MODULE_STRING, AC_OPER_READ_WRITE);
    assert_int_equal(rc, (proc_sudo ? SR_ERR_UNAUTHORIZED : SR_ERR_OK));
    rc = ac_check_node_permissions(session3, XP_TEST_MODULE_STRING, AC_OPER_READ_WRITE);
    assert_int_equal(rc, (proc_sudo ? SR_ERR_UNAUTHORIZED : SR_ERR_OK));


    /* file permission checks */

    /* credentials 1 */
    rc = ac_check_file_permissions(session1, "/etc/passwd", AC_OPER_READ);
    assert_int_equal(rc, SR_ERR_OK);
    rc = ac_check_file_permissions(session1, "/etc/passwd", AC_OPER_READ_WRITE);
    assert_int_equal(rc, SR_ERR_OK);

    /* credentials 2 */
    rc = ac_check_file_permissions(session2, "/etc/passwd", AC_OPER_READ);
    assert_int_equal(rc, SR_ERR_OK);
    rc = ac_check_file_permissions(session2, "/etc/passwd", AC_OPER_READ_WRITE);
    assert_int_equal(rc, (proc_sudo ? SR_ERR_UNAUTHORIZED : SR_ERR_OK));

    /* cleanup */
    ac_session_cleanup(session1);
    ac_session_cleanup(session2);
    ac_session_cleanup(session3);
    ac_cleanup(ctx);
}

/**
 * @brief Test identity switching. Can be executed from both privileged an unprivileged processes.
 */
static void
ac_test_identity_switch(void **state)
{
    ac_ctx_t *ctx = NULL;
    int fd = -1;
    int rc = SR_ERR_OK;

    bool proc_priviledged = (getuid() == 0); /* running as privileged user */
    bool proc_sudo = (NULL != getenv("SUDO_USER")); /* running under sudo */

    /* init */
    rc = ac_init(TEST_DATA_SEARCH_DIR, &ctx);
    assert_int_equal(rc, SR_ERR_OK);

    /* set effective user to sudo parent user (if possible) */
    ac_ucred_t credentials1 = { 0 };
    credentials1.r_username = getenv("USER");
    credentials1.r_uid = getuid();
    credentials1.r_gid = getgid();
    if (proc_sudo) {
        credentials1.e_username = getenv("SUDO_USER");
        credentials1.e_uid = atoi(getenv("SUDO_UID"));
        credentials1.e_gid = atoi(getenv("SUDO_GID"));
    }

    /* make sure we can access passwd as expected */
    fd = open("/etc/passwd", O_RDWR);
    if (proc_priviledged) {
        assert_int_not_equal(fd, -1);
    } else {
        assert_int_equal(fd, -1);
    }
    close(fd);

    /* switch identity */
    rc = ac_set_user_identity(ctx, &credentials1);
    assert_int_equal(rc, SR_ERR_OK);

    /* check access */
    fd = open("/etc/passwd", O_RDWR);
    if (!proc_priviledged || proc_sudo) {
        /* not privileged, or identity switched (in case of sudo) - expect error */
        assert_int_equal(fd, -1);
    } else {
        /* privileged but ot sudo - expect success */
        assert_int_not_equal(fd, -1);
    }

    /* switch identity back */
    rc = ac_unset_user_identity(ctx, &credentials1);
    assert_int_equal(rc, SR_ERR_OK);

    /* make sure we can access passwd as before switching */
    fd = open("/etc/passwd", O_RDWR);
    if (proc_priviledged) {
        assert_int_not_equal(fd, -1);
    } else {
        assert_int_equal(fd, -1);
    }
    close(fd);

    if (proc_sudo) {
        /* try this only if running under sudo */

        /* set real user to sudo parent user */
        ac_ucred_t credentials2 = { 0 };
        credentials2.r_username = getenv("SUDO_USER");
        credentials2.r_uid = atoi(getenv("SUDO_UID"));
        credentials2.r_gid = atoi(getenv("SUDO_GID"));

        /* switch identity to credentials2 */
        rc = ac_set_user_identity(ctx, &credentials2);
        assert_int_equal(rc, SR_ERR_OK);

        /* check access - expect error */
        fd = open("/etc/passwd", O_RDWR);
        assert_int_equal(fd, -1);

        /* switch identity back */
        rc = ac_unset_user_identity(ctx, &credentials2);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* cleanup */
    ac_cleanup(ctx);
}

/**
 * @brief Negative authorization tests. Can be executed from both privileged an unprivileged processes.
 */
static void
ac_test_negative(void **state)
{
    ac_ctx_t *ctx = NULL;
    ac_session_t *session = NULL;
    int rc = SR_ERR_OK;

    /* set real user to current user */
    ac_ucred_t credentials = { 0 };
    credentials.r_username = getenv("USER");
    credentials.r_uid = getuid();
    credentials.r_gid = getgid();

    /* init */
    rc = ac_init(TEST_DATA_SEARCH_DIR, &ctx);
    assert_int_equal(rc, SR_ERR_OK);
    rc = ac_session_init(ctx, &credentials, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* non-existing module */
    rc = ac_check_node_permissions(session, "/non-existing-module:main/string", AC_OPER_READ);
    assert_int_equal(rc, SR_ERR_OK);

    /* try only namespace */
    rc = ac_check_node_permissions(session, "/another-non-existing-module:", AC_OPER_READ);
    assert_int_equal(rc, SR_ERR_OK);

    if (0 != getuid()) {
        /* negative tests only for unprivileged users */

        /* set uid of different user to real user credentials - UNAUTHORIZED */
        credentials.r_uid = 0;
        rc = ac_check_node_permissions(session, XP_TEST_MODULE_STRING, AC_OPER_READ);
        assert_int_equal(rc, SR_ERR_UNSUPPORTED);

        credentials.r_uid = getuid(); /* reset to original value */

        /* set some uid of different user to effective user credentials - UNAUTHORIZED */
        credentials.e_username = "nobody";
        rc = ac_check_node_permissions(session, XP_TEST_MODULE_STRING, AC_OPER_READ);
        assert_int_equal(rc, SR_ERR_UNSUPPORTED);

    }

    /* cleanup */
    ac_session_cleanup(session);
    ac_cleanup(ctx);
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(ac_test_unpriviledged, ac_test_setup, ac_test_teardown),
            cmocka_unit_test_setup_teardown(ac_test_priviledged, ac_test_setup, ac_test_teardown),
            cmocka_unit_test_setup_teardown(ac_test_identity_switch, ac_test_setup, ac_test_teardown),
            cmocka_unit_test_setup_teardown(ac_test_negative, ac_test_setup, ac_test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
