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

bool satisfied_requirements = true; /**< Indices if the test can be actually run with the current system configuration */
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

    if (!satisfied_requirements) {
        return;
    }

#ifndef DEBUG_MODE
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
    ret = system("../src/sysrepod -l 4");
    assert_int_equal(ret, 0);
#endif
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

static void
common_nacm_config(test_nacm_cfg_t *nacm_config)
{
    /* TODO */
}

static int
sysrepo_setup_with_denied_exec_by_dflt(void **state)
{
    sr_conn_ctx_t *conn = NULL;
    test_nacm_cfg_t *nacm_config = NULL;

    /* NACM startup config */
    new_nacm_config(&nacm_config);
    set_nacm_exec_dflt(nacm_config, "deny");
    common_nacm_config(nacm_config);
    save_nacm_config(nacm_config);
    delete_nacm_config(nacm_config);

    start_sysrepo_daemon(&conn);

    *state = (void*)conn;
    return 0;
}

static int
sysrepo_setup_with_ext_groups(void **state)
{
    sr_conn_ctx_t *conn = NULL;
    test_nacm_cfg_t *nacm_config = NULL;

    /* NACM startup config */
    new_nacm_config(&nacm_config);
    enable_nacm_ext_groups(nacm_config, true);
    common_nacm_config(nacm_config);
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
    common_nacm_config(nacm_config);
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

    if (!satisfied_requirements) {
        return 0;
    }

    /* disconnect from sysrepo */
    assert_non_null(conn);
    sr_disconnect(conn);

#ifndef DEBUG_MODE
    /* kill the daemon if it was not running before test */
    if (!daemon_run_before_test) {
        daemon_kill();
    }
#endif
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
    bool permitted = true;

    if (!satisfied_requirements) {
        skip();
    }

    /* start a session */
    assert_non_null(conn);
    rc = sr_session_start_user(conn, "sysrepo-user1", SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe for RPC */
    rc = sr_rpc_subscribe(session, "/test-module:activate-software-image", dummy_rpc_cb, &callback_called,
            SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* check permission to execute the RPC */
    rc = sr_check_exec_permission(session, "/test-module:activate-software-image", &permitted);
    assert_int_equal(rc, SR_ERR_OK);
    assert_true(permitted);

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
    bool permitted = true;

    if (!satisfied_requirements) {
        skip();
    }

    /* start a session */
    assert_non_null(conn);
    rc = sr_session_start_user(conn, "sysrepo-user1", SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe for RPC */
    rc = sr_rpc_subscribe(session, "/test-module:activate-software-image", dummy_rpc_cb, &callback_called,
            SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* check permission to execute the RPC */
    rc = sr_check_exec_permission(session, "/test-module:activate-software-image", &permitted);
    assert_int_equal(rc, SR_ERR_OK);
    assert_true(permitted);

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
nacm_cl_test_rpc_acl_with_denied_exec_by_dflt(void **state)
{
    int callback_called = 0;
    int rc = SR_ERR_OK;
    sr_conn_ctx_t *conn = *state;
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_val_t *output = NULL;
    size_t output_cnt = 0;
    bool permitted = true;
    const sr_error_info_t *error_info = NULL;

    if (!satisfied_requirements) {
        skip();
    }

    /* start a session */
    assert_non_null(conn);
    rc = sr_session_start_user(conn, "sysrepo-user1", SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe for RPC */
    rc = sr_rpc_subscribe(session, "/test-module:activate-software-image", dummy_rpc_cb, &callback_called,
            SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* check permission to execute the RPC */
    rc = sr_check_exec_permission(session, "/test-module:activate-software-image", &permitted);
    assert_int_equal(rc, SR_ERR_OK);
    assert_false(permitted);

    /* send a RPC */
#undef RPC_XPATH
#define RPC_XPATH "/test-module:activate-software-image"
    rc = sr_rpc_send(session, RPC_XPATH, NULL, 0, &output, &output_cnt);
    assert_int_equal(rc, SR_ERR_UNAUTHORIZED);
    assert_int_equal(0, callback_called);
    rc = sr_get_last_error(session, &error_info);
    assert_int_equal(rc, SR_ERR_UNAUTHORIZED);
    assert_string_equal(RPC_XPATH, error_info->xpath);
    assert_string_equal("Execution of the operation '" RPC_XPATH "' was blocked by NACM.", error_info->message);

    /* unsubscribe */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
nacm_cl_test_rpc_acl_with_ext_groups(void **state)
{
    int callback_called = 0;
    int rc = SR_ERR_OK;
    sr_conn_ctx_t *conn = *state;
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_val_t *output = NULL;
    size_t output_cnt = 0;
    bool permitted = true;

    if (!satisfied_requirements) {
        skip();
    }

    /* start a session */
    assert_non_null(conn);
    rc = sr_session_start_user(conn, "sysrepo-user1", SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe for RPC */
    rc = sr_rpc_subscribe(session, "/test-module:activate-software-image", dummy_rpc_cb, &callback_called,
            SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* check permission to execute the RPC */
    rc = sr_check_exec_permission(session, "/test-module:activate-software-image", &permitted);
    assert_int_equal(rc, SR_ERR_OK);
    assert_true(permitted);

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
            cmocka_unit_test_setup_teardown(nacm_cl_test_rpc_acl_with_denied_exec_by_dflt, sysrepo_setup_with_denied_exec_by_dflt, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(nacm_cl_test_rpc_acl_with_ext_groups, sysrepo_setup_with_ext_groups, sysrepo_teardown),
    };

    if (0 != getuid()) {
        satisfied_requirements = false;
    }
    if (SR_ERR_OK != sr_get_user_id("sysrepo-user1", NULL, NULL) ||
        SR_ERR_OK != sr_get_user_id("sysrepo-user2", NULL, NULL) ||
        SR_ERR_OK != sr_get_user_id("sysrepo-user3", NULL, NULL)) {
        satisfied_requirements = false;
    }
    if (SR_ERR_OK != sr_get_group_id("sysrepo-users", NULL)) {
        satisfied_requirements = false;
    }

    /* not checking if users are members of the group and access rights of the data files */

    if (!satisfied_requirements) {
        printf("nacm_cl_test will be skipped due to unsatisfied system requirements.\n");
        printf("In order to fully run all unit tests from nacm_cl_test, make sure that:\n");
        printf("    - the executable nacm_cl_test is run with the root privileges\n");
        printf("    - users 'sysrepo-user1', 'sysrepo-user2', 'sysrepo-user3' exists in the system\n");
        printf("      and all are members of the group 'sysrepo-users'\n");
        printf("    - all data files in the testing repository are owned by the group 'sysrepo-users'\n");
        printf("      (user ownership can remain unchanged) \n");
        printf("    - all data files in the testing repository can be read and edited by the members\n");
        printf("      of the group but not by others (g+rw,o-rw)\n");
        printf("(see deploy/travis/install-test-users.sh for a set of commands to execute)\n");
    }

    return cmocka_run_group_tests(tests, NULL, NULL);
}
