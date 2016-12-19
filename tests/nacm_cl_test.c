/**
 * @file nacm_cl_test.c
 * @author Milan Lenco <milan.lenco@pantheon.tech>
 * @brief NETCONF Access Control unit tests that involves both sysrepo and client library.
 *
 * @copyright
 * Copyright 2016 Pantheon Technologies, s.r.o.
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
#include <setjmp.h>
#include <cmocka.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>

#include "sysrepo.h"
#include "sr_common.h"
#include "test_data.h"
#include "test_module_helper.h"
#include "nacm_module_helper.h"

bool daemon_run_before_test = false; /**< Indices if the daemon was running before executing the test. */

static void
daemon_kill()
{
    FILE *pidfile = NULL;
    int pid = 0, ret = 0;

    /* read PID of the daemon from sysrepo PID file */
    pidfile = fopen(SR_DAEMON_PID_FILE, "r");
    assert_non_null(pidfile);
    ret = fscanf(pidfile, "%d", &pid);
    assert_int_equal(ret, 1);

    /* send SIGTERM to the daemon process */
    ret = kill(pid, SIGTERM);
    assert_int_not_equal(ret, -1);
}

static void
start_sysrepo_daemon(sr_conn_ctx_t **conn_p)
{
    int ret = 0;
    sr_conn_ctx_t *conn = NULL;
    struct timespec ts = { 0 };
    int rc = SR_ERR_OK;

    if (0 != getuid()) {
        /* run tests only for privileged user */
        return;
    }

    /* connect to sysrepo, force daemon connection */
    rc = sr_connect("nacm_cl_test", SR_CONN_DAEMON_REQUIRED, &conn);
    sr_disconnect(conn);
    assert_true(SR_ERR_OK == rc || SR_ERR_DISCONNECT == rc);

    /* kill the daemon if it was running */
    if (SR_ERR_OK == rc) {
        daemon_run_before_test = true;
        daemon_kill();
        /* wait for the daemon to terminate */
        ts.tv_sec = 0;
        ts.tv_nsec = 100000000L; /* 100 milliseconds */
        nanosleep(&ts, NULL);
    } else {
        daemon_run_before_test = false;
    }

    /* create initial datastore content */
    createDataTreeTestModule();

    /* start sysrepo in the daemon mode */
    ret = system("../src/sysrepod");
    assert_int_equal(ret, 0);
    sr_log_stderr(SR_LL_DBG);
    rc = sr_connect("nacm_cl_test", SR_CONN_DAEMON_REQUIRED, &conn);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(conn_p);
    *conn_p = conn;
}

static int
sysrepo_setup_with_empty_nacm_cfg(void **state)
{
    sr_conn_ctx_t *conn = NULL;
    test_nacm_cfg_t *nacm_config = NULL;

    /* create empty NACM startup config */
    new_nacm_config(&nacm_config);
    save_nacm_config(nacm_config);
    delete_nacm_config(nacm_config);

    start_sysrepo_daemon(&conn);

    *state = (void*)conn;
    return 0;
}

static int
sysrepo_setup(void **state)
{
    sr_conn_ctx_t *conn = NULL;
    test_nacm_cfg_t *nacm_config = NULL;

    /* create NACM startup config */
    new_nacm_config(&nacm_config);
    /* TODO */
    save_nacm_config(nacm_config);
    delete_nacm_config(nacm_config);

    start_sysrepo_daemon(&conn);

    *state = (void*)conn;
    return 0;
}

static int
sysrepo_teardown(void **state)
{
    sr_conn_ctx_t *conn = *state;

    if (0 != getuid()) {
        /* run tests only for privileged user */
        return 0;
    } else {
        assert_non_null(conn);
    }

    /* disconnect from sysrepo */
    sr_disconnect(conn);

    /* kill the daemon if it was not running before test */
    if (!daemon_run_before_test) {
        daemon_kill();
    }

    return 0;
}

static int
dummy_rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt,
        sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    int *callback_called = (int*)private_ctx;
    *callback_called += 1;
    return SR_ERR_OK;
}

static void
nacm_cl_test_rpc_acl_with_empty_nacm_cfg(void **state)
{
    int callback_called = 0;
    int rc = SR_ERR_OK;
    sr_conn_ctx_t *conn = *state;
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_val_t *output = NULL;
    size_t output_cnt = 0;

    if (0 != getuid()) {
        /* run tests only for privileged user */
        skip();
    } else {
        assert_non_null(conn);
    }

    /* start a session */
    rc = sr_session_start_user(conn, "sysrepo-user1", SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    sr_val_t *value = NULL;
    rc = sr_get_item(session, "/test-module:university/classes/class[title='CCNA']/student[name='nameB']/age", &value);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(value);
    sr_free_val(value);

    /* subscribe for RPC */
    rc = sr_rpc_subscribe(session, "/test-module:activate-software-image", dummy_rpc_cb, &callback_called,
            SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* send a RPC */
    rc = sr_rpc_send(session, "/test-module:activate-software-image", NULL, 0, &output, &output_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(1, callback_called);
    sr_free_values(output, output_cnt);

    /* unsubscribe */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
nacm_cl_test_rpc_acl(void **state)
{
    int callback_called = 0;
    int rc = SR_ERR_OK;
    sr_conn_ctx_t *conn = *state;
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_val_t *output = NULL;
    size_t output_cnt = 0;

    if (0 != getuid()) {
        /* run tests only for privileged user */
        skip();
    } else {
        assert_non_null(conn);
    }

    /* start a session */
    rc = sr_session_start_user(conn, "sysrepo-user1", SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe for RPC */
    rc = sr_rpc_subscribe(session, "/test-module:activate-software-image", dummy_rpc_cb, &callback_called,
            SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* send a RPC */
    rc = sr_rpc_send(session, "/test-module:activate-software-image", NULL, 0, &output, &output_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(1, callback_called);
    sr_free_values(output, output_cnt);

    /* unsubscribe */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(nacm_cl_test_rpc_acl_with_empty_nacm_cfg, sysrepo_setup_with_empty_nacm_cfg, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(nacm_cl_test_rpc_acl, sysrepo_setup, sysrepo_teardown),
//            cmocka_unit_test(nacm_cl_test_rpc_acl_with_denied_exec_by_default),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
