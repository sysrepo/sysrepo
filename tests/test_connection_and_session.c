/**
 * @file test_connection_and_session.c
 * @author Fred Gan <ganshaolong@vip.qq.com>
 * @brief test for sysrepo API, connection and session
 *
 * @copyright
 * Copyright 2018 Deutsche Telekom AG.
 * Copyright 2018 - 2019 CESNET, z.s.p.o.
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
#define _GNU_SOURCE

#include <unistd.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <pwd.h>
#include <errno.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "tests/config.h"
#include "sysrepo.h"

struct state {
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
};

static int
setup(void **state)
{
    struct state *st;
    uint32_t conn_count;

    st = calloc(1, sizeof *st);
    *state = st;

    sr_connection_count(&conn_count);
    assert_int_equal(conn_count, 0);

    if (sr_connect(0, &(st->conn)) != SR_ERR_OK) {
        return 1;
    }

    if (sr_install_module(st->conn, TESTS_DIR "/files/test.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        return 1;
    }

    sr_disconnect(st->conn);

    if (sr_connect(0, &(st->conn)) != SR_ERR_OK) {
        return 1;
    }

    if (sr_session_start(st->conn, SR_DS_RUNNING, &st->sess) != SR_ERR_OK) {
        return 1;
    }

    return 0;
}

static int
teardown(void **state)
{
    struct state *st = (struct state *)*state;

    sr_remove_module(st->conn, "test");

    sr_disconnect(st->conn);
    free(st);
    return 0;
}

/* set the error information with sr_set_error */
static int
diff_check_cb_1(sr_session_ctx_t *session, const struct lyd_node *diff)
{
    struct passwd *pwd;
    const char *user;

    if (!session || !diff) {
        sr_set_error(session, NULL, "Invalid arguments.");
        return SR_ERR_INVAL_ARG;
    }

    user = sr_session_get_user(session);
    pwd  = getpwuid(getuid());
    if (strncmp(user, pwd->pw_name, strlen(pwd->pw_name))) {
        sr_set_error(session, NULL, "User \"%s\" is not authorized.", user);
        return SR_ERR_UNAUTHORIZED;
    }

    return SR_ERR_OK;
}

/* sr_set_error is not been used */
static int
diff_check_cb_2(sr_session_ctx_t *session, const struct lyd_node *diff)
{
    struct passwd *pwd;
    const char *user;

    if (!session || !diff) {
        return SR_ERR_INVAL_ARG;
    }
    user = sr_session_get_user(session);
    pwd  = getpwuid(getuid());
    if (strncmp(user, pwd->pw_name, strlen(pwd->pw_name))) {
        return SR_ERR_UNAUTHORIZED;
    }

    return SR_ERR_OK;
}

static void
test_set_diff_check_callback(void **state)
{
    struct state *st = (struct state *)*state;
    struct passwd *pwd;
    const char *user = NULL;
    int ret;

    /* connection NULL */
    sr_conn_ctx_t *conn = NULL;
    sr_set_diff_check_callback(conn, diff_check_cb_1);

    sr_set_diff_check_callback(st->conn, diff_check_cb_1);
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "1", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* get a different user */
    pwd = getpwuid(getuid());
    while(1) {
        errno = 0;
        struct passwd *entry = getpwent();
        if (!entry) {
            if (errno) {
                fprintf(stderr, "Error reading password database (%s).\n", strerror(errno));
            }
            break;
        }
        if (strncmp(entry->pw_name, pwd->pw_name, strlen(pwd->pw_name))) { 
            user = entry->pw_name;
            break;
        }
    }
    endpwent();

    /* change user */
    assert_non_null(user);
    ret = sr_session_set_user(st->sess, user);
    /* not a root */
    if (geteuid()) {
        assert_int_equal(ret, SR_ERR_UNAUTHORIZED);
    } else {
        assert_int_equal(ret, SR_ERR_OK);
    }

    /* callback diff_check_cb_1 with sr_set_error */
    sr_set_diff_check_callback(st->conn, diff_check_cb_1);
    ret = sr_set_item_str(st->sess, "/test:l1[k='one']/v", "1", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    /* not a root */
    if (geteuid()) {
        assert_int_equal(ret, SR_ERR_OK);
    } else {
        assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);
    }

    /* callback diff_check_cb_2 without sr_set_error */
    sr_set_diff_check_callback(st->conn, diff_check_cb_2);
    ret = sr_set_item_str(st->sess, "/test:l1[k='two']/v", "2", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    /* not a root */
    if (geteuid()) {
        assert_int_equal(ret, SR_ERR_OK);
    } else {
        assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);
    }
}

/* MAIN */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_set_diff_check_callback, setup, teardown),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    sr_log_stderr(SR_LL_INF);

    return cmocka_run_group_tests(tests, NULL, NULL);
}
