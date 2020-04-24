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
    if (sr_install_module(st->conn, TESTS_DIR "/files/ops-ref.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_DIR "/files/ops.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
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
    sr_remove_module(st->conn, "ops");
    sr_remove_module(st->conn, "ops-ref");

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

static void
test_connect(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;

    /* param error, connection NULL */
    ret = sr_connect(0, NULL);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);

    st = calloc(1, sizeof *st);
    ret = sr_connect(0, &(st->conn));
    assert_int_equal(ret, SR_ERR_OK);

    sr_disconnect(st->conn);
    free(st);
}

static int
rpc_sub_cb(sr_session_ctx_t *session, const char *op_path, const sr_val_t *input, const size_t input_cnt,
sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
    (void)session;
    (void)op_path;
    (void)input;
    (void)input_cnt;
    (void)event;
    (void)request_id;
    (void)output;
    (void)output_cnt;
    (void)private_data;

    return SR_ERR_OK;
}

static void
test_disconnect(void **state)
{
    struct state *st = (struct state *)*state;
    sr_session_ctx_t *sess1 = NULL;
    sr_session_ctx_t *sess2 = NULL;
    sr_subscription_ctx_t *subscr = NULL;
    int ret;

    /* connection NULL */
    sr_conn_ctx_t *conn = NULL;
    ret = sr_disconnect(conn);
    assert_int_equal(ret, SR_ERR_OK);

    /* start session #1 */
    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess1);
    assert_int_equal(ret, SR_ERR_OK);

    /* start session #2 */
    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess2);
    assert_int_equal(ret, SR_ERR_OK);

    /* session #1 subscribe rpc1 */
    ret = sr_rpc_subscribe(sess1, "/ops:rpc1", rpc_sub_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* session #2 subscribe rpc2 */
    ret = sr_rpc_subscribe(sess2, "/ops:rpc2", rpc_sub_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* unsubscribes subscr */
    ret = sr_unsubscribe(subscr);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_get_context(void **state)
{
    struct state *st = (struct state *)*state;
    const struct ly_ctx *ly_ctx;

    /* connection NULL */
    ly_ctx = sr_get_context(NULL);
    assert_null(ly_ctx);

    ly_ctx = sr_get_context(st->conn);
    assert_non_null(ly_ctx);
}

static void
test_session_notif_buffer(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;

    ret = sr_session_notif_buffer(st->sess);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_session_switch_and_get_ds(void **state)
{
    struct state *st = (struct state *)*state;
    sr_datastore_t ds;
    int ret;

    /* param error,session NULL */
    sr_session_ctx_t *sess = NULL;
    ret = sr_session_switch_ds(sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);

    /* get datastore, session NULL */
    ds = sr_session_get_ds(sess);
    assert_int_equal(ds, 0);

    /* switch to candidate datastore */
    ret = sr_session_switch_ds(st->sess, SR_DS_CANDIDATE);
    assert_int_equal(ret, SR_ERR_OK);

    /* get datastore */
    ds = sr_session_get_ds(st->sess);
    assert_int_equal(ds, SR_DS_CANDIDATE);
}

static void
test_session_get_id(void **state)
{
    struct state *st = (struct state *)*state;
    uint32_t sid;

    /* session NULL*/
    sr_session_ctx_t*sess=NULL;
    sid = sr_session_get_id(sess);
    assert_int_equal(sid, 0);

    sid = sr_session_get_id(st->sess);
}

static void
test_session_set_and_get_nc_id(void **state)
{
    struct state *st = (struct state *)*state;
    uint32_t nc_sid;

    /* session NULL */
    sr_session_ctx_t *sess = NULL;
    sr_session_set_nc_id(sess, 64);
    nc_sid = sr_session_get_nc_id(sess);
    assert_int_equal(nc_sid, 0);

    sr_session_set_nc_id(st->sess, 64);
    nc_sid = sr_session_get_nc_id(st->sess);
    assert_int_equal(nc_sid, 64);
}

static void
test_session_set_and_get_user(void **state)
{
    struct state *st =  (struct state *)*state;
    struct passwd *pwd;
    const char *user;
    int ret;

    pwd = getpwuid(getuid());

    /* params error,session NULL or user NULL */
    sr_session_ctx_t *sess = NULL;
    ret = sr_session_set_user(sess, pwd->pw_name);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    ret = sr_session_set_user(st->sess, NULL);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);

    user = sr_session_get_user(sess);
    assert_null(user);

    /* invalid user */
    ret = sr_session_set_user(st->sess, "no user");
    /* not a root*/
    if (geteuid()) {
        assert_int_equal(ret, SR_ERR_UNAUTHORIZED);
    } else {
        assert_int_equal(ret, SR_ERR_NOT_FOUND);
    }

    ret = sr_session_set_user(st->sess, pwd->pw_name);
    /* not a root*/
    if (geteuid()) {
        assert_int_equal(ret, SR_ERR_UNAUTHORIZED);
    } else {
        assert_int_equal(ret, SR_ERR_OK);
    }

    user = sr_session_get_user(st->sess);
    /* not a root*/
   if (geteuid()) {
       assert_null(user);
    } else {
        assert_string_equal(user, pwd->pw_name);
    }
}

static void
test_session_get_connection(void **state)
{
    struct state *st = (struct state *)*state;
    sr_conn_ctx_t *conn = NULL;

    /* sesssion NULL */
    sr_session_ctx_t *sess = NULL;
    conn = sr_session_get_connection(sess);
    assert_null(conn);

    conn = sr_session_get_connection(st->sess);
    assert_non_null(conn);
}

/* MAIN */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_set_diff_check_callback, setup, teardown),
        cmocka_unit_test(test_connect),
        cmocka_unit_test_setup_teardown(test_disconnect, setup, teardown),
        cmocka_unit_test_setup_teardown(test_get_context, setup, teardown),
        cmocka_unit_test_setup_teardown(test_session_notif_buffer, setup, teardown),
        cmocka_unit_test_setup_teardown(test_session_switch_and_get_ds, setup, teardown),
        cmocka_unit_test_setup_teardown(test_session_get_id, setup, teardown),
        cmocka_unit_test_setup_teardown(test_session_set_and_get_nc_id, setup, teardown),
        cmocka_unit_test_setup_teardown(test_session_set_and_get_user, setup, teardown),
        cmocka_unit_test_setup_teardown(test_session_get_connection, setup, teardown),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    sr_log_stderr(SR_LL_INF);

    return cmocka_run_group_tests(tests, NULL, NULL);
}
