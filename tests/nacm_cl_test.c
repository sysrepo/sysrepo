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

#define NUM_OF_USERS  3
//#define DEBUG_MODE

#define CHECK_UNAUTHORIZED_ERROR(EVENT, SESSION, XPATH, RULE, RULE_INFO) \
    do { \
        rc = sr_get_last_error(sessions[SESSION], &error_info); \
        assert_int_equal(rc, SR_ERR_UNAUTHORIZED); \
        assert_string_equal(XPATH, error_info->xpath); \
        if (strlen(RULE) && strlen(RULE_INFO)) { \
            assert_string_equal(EVENT " '" XPATH "' was blocked by the NACM rule '" RULE "' (" RULE_INFO ").", \
                                error_info->message); \
        } else if (strlen(RULE)) { \
            assert_string_equal(EVENT " '" XPATH "' was blocked by the NACM rule '" RULE "'.", \
                                error_info->message); \
        } else { \
            assert_string_equal(EVENT " '" XPATH "' was blocked by NACM.", error_info->message); \
        } \
    } while (0)

#define RPC_DENIED(SESSION, XPATH, INPUT, INPUT_CNT, RULE, RULE_INFO) \
    do { \
        rc = sr_check_exec_permission(sessions[SESSION], XPATH, &permitted); \
        assert_int_equal(rc, SR_ERR_OK); \
        assert_false(permitted); \
        callback_called = 0; \
        rc = sr_rpc_send(sessions[SESSION], XPATH, INPUT, INPUT_CNT, &output, &output_cnt); \
        assert_int_equal(rc, SR_ERR_UNAUTHORIZED); \
        assert_int_equal(0, callback_called); \
        CHECK_UNAUTHORIZED_ERROR("Execution of the operation", SESSION, XPATH, RULE, RULE_INFO); \
    } while (0)

#define RPC_DENIED_TREE(SESSION, XPATH, INPUT, INPUT_CNT, RULE, RULE_INFO) \
    do { \
        rc = sr_check_exec_permission(sessions[SESSION], XPATH, &permitted); \
        assert_int_equal(rc, SR_ERR_OK); \
        assert_false(permitted); \
        callback_called = 0; \
        rc = sr_rpc_send_tree(sessions[SESSION], XPATH, INPUT, INPUT_CNT, &output_tree, &output_cnt); \
        assert_int_equal(rc, SR_ERR_UNAUTHORIZED); \
        assert_int_equal(0, callback_called); \
        CHECK_UNAUTHORIZED_ERROR("Execution of the operation", SESSION, XPATH, RULE, RULE_INFO); \
    } while (0)

#define RPC_PERMITED(SESSION, XPATH, INPUT, INPUT_CNT, EXP_OUTPUT_CNT) \
    do { \
        rc = sr_check_exec_permission(sessions[SESSION], XPATH, &permitted); \
        assert_int_equal(rc, SR_ERR_OK); \
        assert_true(permitted); \
        callback_called = 0; \
        rc = sr_rpc_send(sessions[SESSION], XPATH, INPUT, INPUT_CNT, &output, &output_cnt); \
        if (-1 == EXP_OUTPUT_CNT) { \
            assert_int_equal(rc, SR_ERR_VALIDATION_FAILED); \
        } else { \
            assert_int_equal(rc, SR_ERR_OK); \
            assert_int_equal(EXP_OUTPUT_CNT, output_cnt); \
            sr_free_values(output, output_cnt); \
        } \
        assert_int_equal(1, callback_called); \
    } while (0)

#define RPC_PERMITED_TREE(SESSION, XPATH, INPUT, INPUT_CNT, EXP_OUTPUT_CNT) \
    do { \
        rc = sr_check_exec_permission(sessions[SESSION], XPATH, &permitted); \
        assert_int_equal(rc, SR_ERR_OK); \
        assert_true(permitted); \
        callback_called = 0; \
        rc = sr_rpc_send_tree(sessions[SESSION], XPATH, INPUT, INPUT_CNT, &output_tree, &output_cnt); \
        if (-1 == EXP_OUTPUT_CNT) { \
            assert_int_equal(rc, SR_ERR_VALIDATION_FAILED); \
        } else { \
            assert_int_equal(rc, SR_ERR_OK); \
            assert_int_equal(EXP_OUTPUT_CNT, output_cnt); \
            sr_free_trees(output_tree, output_cnt); \
        } \
        assert_int_equal(1, callback_called); \
    } while (0)

#define ACTION_DENIED(SESSION, XPATH, INPUT, INPUT_CNT, RULE, RULE_INFO) \
    do { \
        rc = sr_check_exec_permission(sessions[SESSION], XPATH, &permitted); \
        assert_int_equal(rc, SR_ERR_OK); \
        assert_false(permitted); \
        callback_called = 0; \
        rc = sr_action_send(sessions[SESSION], XPATH, INPUT, INPUT_CNT, &output, &output_cnt); \
        assert_int_equal(rc, SR_ERR_UNAUTHORIZED); \
        assert_int_equal(0, callback_called); \
        CHECK_UNAUTHORIZED_ERROR("Execution of the operation", SESSION, XPATH, RULE, RULE_INFO); \
    } while (0)

#define ACTION_DENIED_TREE(SESSION, XPATH, INPUT, INPUT_CNT, RULE, RULE_INFO) \
    do { \
        rc = sr_check_exec_permission(sessions[SESSION], XPATH, &permitted); \
        assert_int_equal(rc, SR_ERR_OK); \
        assert_false(permitted); \
        callback_called = 0; \
        rc = sr_action_send_tree(sessions[SESSION], XPATH, INPUT, INPUT_CNT, &output_tree, &output_cnt); \
        assert_int_equal(rc, SR_ERR_UNAUTHORIZED); \
        assert_int_equal(0, callback_called); \
        CHECK_UNAUTHORIZED_ERROR("Execution of the operation", SESSION, XPATH, RULE, RULE_INFO); \
    } while (0)

#define ACTION_PERMITED(SESSION, XPATH, INPUT, INPUT_CNT, EXP_OUTPUT_CNT) \
    do { \
        rc = sr_check_exec_permission(sessions[SESSION], XPATH, &permitted); \
        assert_int_equal(rc, SR_ERR_OK); \
        assert_true(permitted); \
        callback_called = 0; \
        rc = sr_action_send(sessions[SESSION], XPATH, INPUT, INPUT_CNT, &output, &output_cnt); \
        if (-1 == EXP_OUTPUT_CNT) { \
            assert_int_equal(rc, SR_ERR_VALIDATION_FAILED); \
        } else { \
            assert_int_equal(rc, SR_ERR_OK); \
            assert_int_equal(EXP_OUTPUT_CNT, output_cnt); \
            sr_free_values(output, output_cnt); \
        } \
        assert_int_equal(1, callback_called); \
    } while (0)

#define ACTION_PERMITED_TREE(SESSION, XPATH, INPUT, INPUT_CNT, EXP_OUTPUT_CNT) \
    do { \
        rc = sr_check_exec_permission(sessions[SESSION], XPATH, &permitted); \
        assert_int_equal(rc, SR_ERR_OK); \
        assert_true(permitted); \
        callback_called = 0; \
        rc = sr_action_send_tree(sessions[SESSION], XPATH, INPUT, INPUT_CNT, &output_tree, &output_cnt); \
        if (-1 == EXP_OUTPUT_CNT) { \
            assert_int_equal(rc, SR_ERR_VALIDATION_FAILED); \
        } else { \
            assert_int_equal(rc, SR_ERR_OK); \
            assert_int_equal(EXP_OUTPUT_CNT, output_cnt); \
            sr_free_trees(output_tree, output_cnt); \
        } \
        assert_int_equal(1, callback_called); \
    } while (0)

typedef sr_session_ctx_t *user_sessions_t[NUM_OF_USERS];

bool satisfied_requirements = true; /**< Indices if the test can be actually run with the current system configuration */
bool daemon_run_before_test = false; /**< Indices if the daemon was running before executing the test. */


/* TODO: Report the issue with failed validation when action reply is empty. Then reflect the fix. */

#ifndef DEBUG_MODE
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
    SR_LOG_DBG("Sending SIGTERM signal to PID=%d.", pid);
    ret = kill(pid, SIGTERM);
    assert_int_not_equal(ret, -1);
}
#endif

static void
start_sysrepo_daemon(sr_conn_ctx_t **conn_p)
{
#ifndef DEBUG_MODE
    int ret = 0;
    struct timespec ts = { 0 };
#endif
    sr_conn_ctx_t *conn = NULL;
    int rc = SR_ERR_OK;

    if (!satisfied_requirements) {
        return;
    }

    sr_log_stderr(SR_LL_DBG);

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
        ts.tv_nsec = 500000000L; /* 500 milliseconds */
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
    /* groups & users */
    add_nacm_user(nacm_config, "sysrepo-user1", "group1");
    add_nacm_user(nacm_config, "sysrepo-user2", "group2");
    add_nacm_user(nacm_config, NULL, "group3");
    add_nacm_user(nacm_config, "sysrepo-user3", "group1");
    add_nacm_user(nacm_config, "sysrepo-user3", "group2");
    add_nacm_user(nacm_config, "sysrepo-user3", "group4");
    /* access lists */
    add_nacm_rule_list(nacm_config, "acl1", "group1", "group4", "group5", NULL);
    add_nacm_rule_list(nacm_config, "acl2", "group2", "group3", NULL);
    add_nacm_rule_list(nacm_config, "acl3", "group4", "sysrepo-users", NULL);
    /*  -> acl1: */
    add_nacm_rule(nacm_config, "acl1", "deny-activate-software-image", "test-module", NACM_RULE_RPC,
            "activate-software-image", "exec", "deny", "Not allowed to run activate-software-image");
    add_nacm_rule(nacm_config, "acl1", "rule-with-no-effect", "ietf-netconf", NACM_RULE_RPC,
            "close-session", "*", "deny", "close-session NETCONF operation cannot be effectively denied");
    /*  -> acl2: */
    add_nacm_rule(nacm_config, "acl2", "permit-kill-session", "ietf-netconf", NACM_RULE_RPC,
            "kill-session", "exec", "permit", "Permit execution of the kill-session NETCONF operation.");
    add_nacm_rule(nacm_config, "acl2", "deny-initialize", "*", NACM_RULE_RPC,
            "initialize", "*", "deny", "Not allowed to touch RPC 'initialize' in any module.");
    /*  -> acl3: */
    add_nacm_rule(nacm_config, "acl3", "permit-unload", "test-module", NACM_RULE_RPC,
            "unload", "exec", "permit", "Permit action unload");
    add_nacm_rule(nacm_config, "acl3", "deny-test-module", "test-module", NACM_RULE_NOTSET,
            NULL, "*", "deny", "Deny everything not explicitly permitted in test-module.");
}

static int
sysrepo_setup_with_denied_exec_by_dflt(void **state)
{
    sr_conn_ctx_t *conn = NULL;
    test_nacm_cfg_t *nacm_config = NULL;

    /* NACM startup config */
    new_nacm_config(&nacm_config);
    set_nacm_exec_dflt(nacm_config, "deny");
    enable_nacm_ext_groups(nacm_config, false);
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
    enable_nacm_ext_groups(nacm_config, false);
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
start_user_sessions(sr_conn_ctx_t *conn, sr_session_ctx_t **handler_session, user_sessions_t *sessions)
{
    int rc = SR_ERR_OK;
    assert_non_null(conn);
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, handler_session);
    assert_int_equal(rc, SR_ERR_OK);
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        char *username = NULL;
        assert_int_equal(SR_ERR_OK, sr_asprintf(&username, "sysrepo-user%d", i+1));
        rc = sr_session_start_user(conn, username, SR_DS_STARTUP, SR_SESS_DEFAULT, (*sessions)+i);
        assert_int_equal(rc, SR_ERR_OK);
        free(username);
    }
}

static void
subscribe_dummy_callback(sr_session_ctx_t *handler_session, void *private_ctx, sr_subscription_ctx_t **subscription)
{
    int rc = SR_ERR_OK;

    /* subscribe for RPCs with dummy callback */
    rc = sr_rpc_subscribe(handler_session, "/test-module:activate-software-image", dummy_rpc_cb, private_ctx,
            SR_SUBSCR_DEFAULT, subscription);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_rpc_subscribe(handler_session, "/ietf-netconf:close-session", dummy_rpc_cb, private_ctx,
            SR_SUBSCR_CTX_REUSE, subscription);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_rpc_subscribe(handler_session, "/ietf-netconf:kill-session", dummy_rpc_cb, private_ctx,
            SR_SUBSCR_CTX_REUSE, subscription);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_rpc_subscribe(handler_session, "/turing-machine:initialize", dummy_rpc_cb, private_ctx,
            SR_SUBSCR_CTX_REUSE, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe for Actions with dummy callback */
    rc = sr_action_subscribe(handler_session, "/test-module:kernel-modules/kernel-module/unload",
            dummy_rpc_cb, private_ctx, SR_SUBSCR_CTX_REUSE, subscription);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_action_subscribe(handler_session, "/test-module:kernel-modules/kernel-module/load",
            dummy_rpc_cb, private_ctx, SR_SUBSCR_CTX_REUSE, subscription);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
nacm_cl_test_rpc_acl_with_empty_nacm_cfg(void **state)
{
    int callback_called = 0;
    int rc = SR_ERR_OK;
    sr_conn_ctx_t *conn = *state;
    sr_session_ctx_t *handler_session = NULL;
    user_sessions_t sessions = {NULL};
    sr_subscription_ctx_t *subscription = NULL;
    sr_val_t *output = NULL;
    sr_node_t *output_tree = NULL;
    size_t output_cnt = 0;
    bool permitted = true;
    sr_val_t *input = NULL;
    sr_node_t *input_tree = NULL;
    const sr_error_info_t *error_info = NULL;

    if (!satisfied_requirements) {
        skip();
    }

    /* prepare for RPC and Action executions */
    start_user_sessions(conn, &handler_session, &sessions);
    subscribe_dummy_callback(handler_session, &callback_called, &subscription);

    /* test RPC "activate-software-image" */
#undef RPC_XPATH
#define RPC_XPATH "/test-module:activate-software-image"
    /*  -> sysrepo-user1 */
    RPC_PERMITED(0, RPC_XPATH, NULL, 0, 2);
    RPC_PERMITED_TREE(0, RPC_XPATH, NULL, 0, 2);
    /*  -> sysrepo-user2 */
    RPC_PERMITED(1, RPC_XPATH, NULL, 0, 2);
    RPC_PERMITED_TREE(1, RPC_XPATH, NULL, 0, 2);
    /*  -> sysrepo-user3 */
    RPC_PERMITED(2, RPC_XPATH, NULL, 0, 2);
    RPC_PERMITED_TREE(2, RPC_XPATH, NULL, 0, 2);

    /* test NETCONF operation "close-session" */
#undef RPC_XPATH
#define RPC_XPATH "/ietf-netconf:close-session"
    /*  -> sysrepo-user1 */
    RPC_PERMITED(0, RPC_XPATH, NULL, 0, 0);
    RPC_PERMITED_TREE(0, RPC_XPATH, NULL, 0, 0);
    /*  -> sysrepo-user2 */
    RPC_PERMITED(1, RPC_XPATH, NULL, 0, 0);
    RPC_PERMITED_TREE(1, RPC_XPATH, NULL, 0, 0);
    /*  -> sysrepo-user3 */
    RPC_PERMITED(2, RPC_XPATH, NULL, 0, 0);
    RPC_PERMITED_TREE(2, RPC_XPATH, NULL, 0, 0);

    /* test NETCONF operation "kill-session" */
#undef RPC_XPATH
#define RPC_XPATH "/ietf-netconf:kill-session"
    assert_int_equal(SR_ERR_OK, sr_new_val(RPC_XPATH "/session-id", &input));
    input->type = SR_UINT32_T;
    input->data.uint32_val = 12;
    assert_int_equal(SR_ERR_OK, sr_new_tree("session-id", "ietf-netconf", &input_tree));
    input_tree->type = SR_UINT32_T;
    input_tree->data.uint32_val = 12;
    /*  -> sysrepo-user1 */
    RPC_DENIED(0, RPC_XPATH, input, 1, "", "");
    RPC_DENIED_TREE(0, RPC_XPATH, input_tree, 1, "", "");
    /*  -> sysrepo-user2 */
    RPC_DENIED(1, RPC_XPATH, input, 1, "", "");
    RPC_DENIED_TREE(1, RPC_XPATH, input_tree, 1, "", "");
    /*  -> sysrepo-user3 */
    RPC_DENIED(1, RPC_XPATH, input, 1, "", "");
    RPC_DENIED_TREE(1, RPC_XPATH, input_tree, 1, "", "");
    sr_free_val(input);
    sr_free_tree(input_tree);

    /* test RPC "initialize" from turing-machine */
#undef RPC_XPATH
#define RPC_XPATH "/turing-machine:initialize"
    /*  -> sysrepo-user1 */
    RPC_PERMITED(0, RPC_XPATH, NULL, 0, 0);
    RPC_PERMITED_TREE(0, RPC_XPATH, NULL, 0, 0);
    /*  -> sysrepo-user2 */
    RPC_PERMITED(1, RPC_XPATH, NULL, 0, 0);
    RPC_PERMITED_TREE(1, RPC_XPATH, NULL, 0, 0);
    /*  -> sysrepo-user3 */
    RPC_PERMITED(2, RPC_XPATH, NULL, 0, 0);
    RPC_PERMITED_TREE(2, RPC_XPATH, NULL, 0, 0);

    /* test Action "unload" from test-model */
#undef ACTION_XPATH
#define ACTION_XPATH "/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/unload"
    /*  -> sysrepo-user1 */
    ACTION_PERMITED(0, ACTION_XPATH, NULL, 0, -1);
    ACTION_PERMITED_TREE(0, ACTION_XPATH, NULL, 0, -1);
    /*  -> sysrepo-user2 */
    ACTION_PERMITED(1, ACTION_XPATH, NULL, 0, -1);
    ACTION_PERMITED_TREE(1, ACTION_XPATH, NULL, 0, -1);
    /*  -> sysrepo-user3 */
    ACTION_PERMITED(2, ACTION_XPATH, NULL, 0, -1);
    ACTION_PERMITED_TREE(2, ACTION_XPATH, NULL, 0, -1);

    /* test Action "load" from test-model */
#undef ACTION_XPATH
#define ACTION_XPATH "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load"
    assert_int_equal(SR_ERR_OK, sr_new_val(ACTION_XPATH "/params", &input));
    input->type = SR_STRING_T;
    sr_val_set_str_data(input, SR_STRING_T, "--force");
    assert_int_equal(SR_ERR_OK, sr_new_tree("params", "test-module", &input_tree));
    input_tree->type = SR_STRING_T;
    sr_node_set_str_data(input_tree, SR_STRING_T, "--force");
    /*  -> sysrepo-user1 */
    ACTION_PERMITED(0, ACTION_XPATH, input, 1, -1);
    ACTION_PERMITED_TREE(0, ACTION_XPATH, input_tree, 1, -1);
    /*  -> sysrepo-user2 */
    ACTION_PERMITED(1, ACTION_XPATH, input, 1, -1);
    ACTION_PERMITED_TREE(1, ACTION_XPATH, input_tree, 1, -1);
    /*  -> sysrepo-user3 */
    ACTION_PERMITED(2, ACTION_XPATH, input, 1, -1);
    ACTION_PERMITED_TREE(2, ACTION_XPATH, input_tree, 1, -1);
    sr_free_val(input);
    sr_free_tree(input_tree);

    /* unsubscribe */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop sessions */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        rc = sr_session_stop(sessions[i]);
        assert_int_equal(rc, SR_ERR_OK);
    }
    rc = sr_session_stop(handler_session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
nacm_cl_test_rpc_acl(void **state)
{
    int callback_called = 0;
    int rc = SR_ERR_OK;
    sr_conn_ctx_t *conn = *state;
    sr_session_ctx_t *handler_session = NULL;
    user_sessions_t sessions = {NULL};
    sr_subscription_ctx_t *subscription = NULL;
    sr_val_t *output = NULL;
    sr_node_t *output_tree = NULL;
    size_t output_cnt = 0;
    bool permitted = true;
    sr_val_t *input = NULL;
    sr_node_t *input_tree = NULL;
    const sr_error_info_t *error_info = NULL;

    if (!satisfied_requirements) {
        skip();
    }

    /* prepare for RPC and Action executions */
    start_user_sessions(conn, &handler_session, &sessions);
    subscribe_dummy_callback(handler_session, &callback_called, &subscription);

    /* test RPC "activate-software-image" */
#undef RPC_XPATH
#define RPC_XPATH "/test-module:activate-software-image"
    /*  -> sysrepo-user1 */
    RPC_DENIED(0, RPC_XPATH, NULL, 0, "deny-activate-software-image", "Not allowed to run activate-software-image");
    RPC_DENIED_TREE(0, RPC_XPATH, NULL, 0, "deny-activate-software-image", "Not allowed to run activate-software-image");
    /*  -> sysrepo-user2 */
    RPC_PERMITED(1, RPC_XPATH, NULL, 0, 2);
    RPC_PERMITED_TREE(1, RPC_XPATH, NULL, 0, 2);
    /*  -> sysrepo-user3 */
    RPC_DENIED(2, RPC_XPATH, NULL, 0, "deny-activate-software-image", "Not allowed to run activate-software-image");
    RPC_DENIED_TREE(2, RPC_XPATH, NULL, 0, "deny-activate-software-image", "Not allowed to run activate-software-image");

    /* test NETCONF operation "close-session" */
#undef RPC_XPATH
#define RPC_XPATH "/ietf-netconf:close-session"
    /*  -> sysrepo-user1 */
    RPC_PERMITED(0, RPC_XPATH, NULL, 0, 0);
    RPC_PERMITED_TREE(0, RPC_XPATH, NULL, 0, 0);
    /*  -> sysrepo-user2 */
    RPC_PERMITED(1, RPC_XPATH, NULL, 0, 0);
    RPC_PERMITED_TREE(1, RPC_XPATH, NULL, 0, 0);
    /*  -> sysrepo-user3 */
    RPC_PERMITED(2, RPC_XPATH, NULL, 0, 0);
    RPC_PERMITED_TREE(2, RPC_XPATH, NULL, 0, 0);

    /* test NETCONF operation "kill-session" */
#undef RPC_XPATH
#define RPC_XPATH "/ietf-netconf:kill-session"
    assert_int_equal(SR_ERR_OK, sr_new_val(RPC_XPATH "/session-id", &input));
    input->type = SR_UINT32_T;
    input->data.uint32_val = 12;
    assert_int_equal(SR_ERR_OK, sr_new_tree("session-id", "ietf-netconf", &input_tree));
    input_tree->type = SR_UINT32_T;
    input_tree->data.uint32_val = 12;
    /*  -> sysrepo-user1 */
    RPC_DENIED(0, RPC_XPATH, input, 1, "", "");
    RPC_DENIED_TREE(0, RPC_XPATH, input_tree, 1, "", "");
    /*  -> sysrepo-user2 */
    RPC_PERMITED(1, RPC_XPATH, input, 1, 0);
    RPC_PERMITED_TREE(1, RPC_XPATH, input_tree, 1, 0);
    /*  -> sysrepo-user3 */
    RPC_PERMITED(2, RPC_XPATH, input, 1, 0);
    RPC_PERMITED_TREE(2, RPC_XPATH, input_tree, 1, 0);
    sr_free_val(input);
    sr_free_tree(input_tree);

    /* test RPC "initialize" from turing-machine */
#undef RPC_XPATH
#define RPC_XPATH "/turing-machine:initialize"
    /*  -> sysrepo-user1 */
    RPC_PERMITED(0, RPC_XPATH, NULL, 0, 0);
    RPC_PERMITED_TREE(0, RPC_XPATH, NULL, 0, 0);
    /*  -> sysrepo-user2 */
    RPC_DENIED(1, RPC_XPATH, NULL, 0, "deny-initialize", "Not allowed to touch RPC 'initialize' in any module.");
    RPC_DENIED_TREE(1, RPC_XPATH, NULL, 0, "deny-initialize", "Not allowed to touch RPC 'initialize' in any module.");
    /*  -> sysrepo-user3 */
    RPC_DENIED(2, RPC_XPATH, NULL, 0, "deny-initialize", "Not allowed to touch RPC 'initialize' in any module.");
    RPC_DENIED_TREE(2, RPC_XPATH, NULL, 0, "deny-initialize", "Not allowed to touch RPC 'initialize' in any module.");

    /* test Action "unload" from test-model */
#undef ACTION_XPATH
#define ACTION_XPATH "/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/unload"
    /*  -> sysrepo-user1 */
    ACTION_PERMITED(0, ACTION_XPATH, NULL, 0, -1);
    ACTION_PERMITED_TREE(0, ACTION_XPATH, NULL, 0, -1);
    /*  -> sysrepo-user2 */
    ACTION_PERMITED(1, ACTION_XPATH, NULL, 0, -1);
    ACTION_PERMITED_TREE(1, ACTION_XPATH, NULL, 0, -1);
    /*  -> sysrepo-user3 */
    ACTION_PERMITED(2, ACTION_XPATH, NULL, 0, -1);
    ACTION_PERMITED_TREE(2, ACTION_XPATH, NULL, 0, -1);

    /* test Action "load" from test-model */
#undef ACTION_XPATH
#define ACTION_XPATH "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load"
    assert_int_equal(SR_ERR_OK, sr_new_val(ACTION_XPATH "/params", &input));
    input->type = SR_STRING_T;
    sr_val_set_str_data(input, SR_STRING_T, "--force");
    assert_int_equal(SR_ERR_OK, sr_new_tree("params", "test-module", &input_tree));
    input_tree->type = SR_STRING_T;
    sr_node_set_str_data(input_tree, SR_STRING_T, "--force");
    /*  -> sysrepo-user1 */
    ACTION_PERMITED(0, ACTION_XPATH, input, 1, -1);
    ACTION_PERMITED_TREE(0, ACTION_XPATH, input_tree, 1, -1);
    /*  -> sysrepo-user2 */
    ACTION_PERMITED(1, ACTION_XPATH, input, 1, -1);
    ACTION_PERMITED_TREE(1, ACTION_XPATH, input_tree, 1, -1);
    /*  -> sysrepo-user3 */
    ACTION_DENIED(2, ACTION_XPATH, input, 1, "deny-test-module", "Deny everything not explicitly permitted in test-module.");
    ACTION_DENIED_TREE(2, ACTION_XPATH, input_tree, 1, "deny-test-module", "Deny everything not explicitly permitted in test-module." );
    sr_free_val(input);
    sr_free_tree(input_tree);

    /* unsubscribe */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop sessions */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        rc = sr_session_stop(sessions[i]);
        assert_int_equal(rc, SR_ERR_OK);
    }
    rc = sr_session_stop(handler_session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
nacm_cl_test_rpc_acl_with_denied_exec_by_dflt(void **state)
{
    int callback_called = 0;
    int rc = SR_ERR_OK;
    sr_conn_ctx_t *conn = *state;
    sr_session_ctx_t *handler_session = NULL;
    user_sessions_t sessions = {NULL};
    sr_subscription_ctx_t *subscription = NULL;
    sr_val_t *output = NULL;
    sr_node_t *output_tree = NULL;
    size_t output_cnt = 0;
    bool permitted = true;
    sr_val_t *input = NULL;
    sr_node_t *input_tree = NULL;
    const sr_error_info_t *error_info = NULL;

    if (!satisfied_requirements) {
        skip();
    }

    /* prepare for RPC and Action executions */
    start_user_sessions(conn, &handler_session, &sessions);
    subscribe_dummy_callback(handler_session, &callback_called, &subscription);

    /* test RPC "activate-software-image" */
#undef RPC_XPATH
#define RPC_XPATH "/test-module:activate-software-image"
    /*  -> sysrepo-user1 */
    RPC_DENIED(0, RPC_XPATH, NULL, 0, "deny-activate-software-image", "Not allowed to run activate-software-image");
    RPC_DENIED_TREE(0, RPC_XPATH, NULL, 0, "deny-activate-software-image", "Not allowed to run activate-software-image");
    /*  -> sysrepo-user2 */
    RPC_DENIED(1, RPC_XPATH, NULL, 0, "", "");
    RPC_DENIED_TREE(1, RPC_XPATH, NULL, 0, "", "");
    /*  -> sysrepo-user3 */
    RPC_DENIED(2, RPC_XPATH, NULL, 0, "deny-activate-software-image", "Not allowed to run activate-software-image");
    RPC_DENIED_TREE(2, RPC_XPATH, NULL, 0, "deny-activate-software-image", "Not allowed to run activate-software-image");

    /* test NETCONF operation "close-session" */
#undef RPC_XPATH
#define RPC_XPATH "/ietf-netconf:close-session"
    /*  -> sysrepo-user1 */
    RPC_PERMITED(0, RPC_XPATH, NULL, 0, 0);
    RPC_PERMITED_TREE(0, RPC_XPATH, NULL, 0, 0);
    /*  -> sysrepo-user2 */
    RPC_PERMITED(1, RPC_XPATH, NULL, 0, 0);
    RPC_PERMITED_TREE(1, RPC_XPATH, NULL, 0, 0);
    /*  -> sysrepo-user3 */
    RPC_PERMITED(2, RPC_XPATH, NULL, 0, 0);
    RPC_PERMITED_TREE(2, RPC_XPATH, NULL, 0, 0);

    /* test NETCONF operation "kill-session" */
#undef RPC_XPATH
#define RPC_XPATH "/ietf-netconf:kill-session"
    assert_int_equal(SR_ERR_OK, sr_new_val(RPC_XPATH "/session-id", &input));
    input->type = SR_UINT32_T;
    input->data.uint32_val = 12;
    assert_int_equal(SR_ERR_OK, sr_new_tree("session-id", "ietf-netconf", &input_tree));
    input_tree->type = SR_UINT32_T;
    input_tree->data.uint32_val = 12;
    /*  -> sysrepo-user1 */
    RPC_DENIED(0, RPC_XPATH, input, 1, "", "");
    RPC_DENIED_TREE(0, RPC_XPATH, input_tree, 1, "", "");
    /*  -> sysrepo-user2 */
    RPC_PERMITED(1, RPC_XPATH, input, 1, 0);
    RPC_PERMITED_TREE(1, RPC_XPATH, input_tree, 1, 0);
    /*  -> sysrepo-user3 */
    RPC_PERMITED(2, RPC_XPATH, input, 1, 0);
    RPC_PERMITED_TREE(2, RPC_XPATH, input_tree, 1, 0);
    sr_free_val(input);
    sr_free_tree(input_tree);

    /* test RPC "initialize" from turing-machine */
#undef RPC_XPATH
#define RPC_XPATH "/turing-machine:initialize"
    /*  -> sysrepo-user1 */
    RPC_DENIED(0, RPC_XPATH, NULL, 0, "", "");
    RPC_DENIED_TREE(0, RPC_XPATH, NULL, 0, "", "");
    /*  -> sysrepo-user2 */
    RPC_DENIED(1, RPC_XPATH, NULL, 0, "deny-initialize", "Not allowed to touch RPC 'initialize' in any module.");
    RPC_DENIED_TREE(1, RPC_XPATH, NULL, 0, "deny-initialize", "Not allowed to touch RPC 'initialize' in any module.");
    /*  -> sysrepo-user3 */
    RPC_DENIED(2, RPC_XPATH, NULL, 0, "deny-initialize", "Not allowed to touch RPC 'initialize' in any module.");
    RPC_DENIED_TREE(2, RPC_XPATH, NULL, 0, "deny-initialize", "Not allowed to touch RPC 'initialize' in any module.");

    /* test Action "unload" from test-model */
#undef ACTION_XPATH
#define ACTION_XPATH "/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/unload"
    /*  -> sysrepo-user1 */
    ACTION_DENIED(0, ACTION_XPATH, NULL, 0, "", "");
    ACTION_DENIED_TREE(0, ACTION_XPATH, NULL, 0, "", "");
    /*  -> sysrepo-user2 */
    ACTION_DENIED(1, ACTION_XPATH, NULL, 0, "", "");
    ACTION_DENIED_TREE(1, ACTION_XPATH, NULL, 0, "", "");
    /*  -> sysrepo-user3 */
    ACTION_PERMITED(2, ACTION_XPATH, NULL, 0, -1);
    ACTION_PERMITED_TREE(2, ACTION_XPATH, NULL, 0, -1);

    /* test Action "load" from test-model */
#undef ACTION_XPATH
#define ACTION_XPATH "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load"
    assert_int_equal(SR_ERR_OK, sr_new_val(ACTION_XPATH "/params", &input));
    input->type = SR_STRING_T;
    sr_val_set_str_data(input, SR_STRING_T, "--force");
    assert_int_equal(SR_ERR_OK, sr_new_tree("params", "test-module", &input_tree));
    input_tree->type = SR_STRING_T;
    sr_node_set_str_data(input_tree, SR_STRING_T, "--force");
    /*  -> sysrepo-user1 */
    ACTION_DENIED(0, ACTION_XPATH, input, 1, "", "");
    ACTION_DENIED_TREE(0, ACTION_XPATH, input_tree, 1, "", "");
    /*  -> sysrepo-user2 */
    ACTION_DENIED(1, ACTION_XPATH, input, 1, "", "");
    ACTION_DENIED_TREE(1, ACTION_XPATH, input_tree, 1, "", "");
    /*  -> sysrepo-user3 */
    ACTION_DENIED(2, ACTION_XPATH, input, 1, "deny-test-module", "Deny everything not explicitly permitted in test-module.");
    ACTION_DENIED_TREE(2, ACTION_XPATH, input_tree, 1, "deny-test-module", "Deny everything not explicitly permitted in test-module." );
    sr_free_val(input);
    sr_free_tree(input_tree);

    /* unsubscribe */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop sessions */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        rc = sr_session_stop(sessions[i]);
        assert_int_equal(rc, SR_ERR_OK);
    }
    rc = sr_session_stop(handler_session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
nacm_cl_test_rpc_acl_with_ext_groups(void **state)
{
    int callback_called = 0;
    int rc = SR_ERR_OK;
    sr_conn_ctx_t *conn = *state;
    sr_session_ctx_t *handler_session = NULL;
    user_sessions_t sessions = {NULL};
    sr_subscription_ctx_t *subscription = NULL;
    sr_val_t *output = NULL;
    sr_node_t *output_tree = NULL;
    size_t output_cnt = 0;
    bool permitted = true;
    sr_val_t *input = NULL;
    sr_node_t *input_tree = NULL;
    const sr_error_info_t *error_info = NULL;

    if (!satisfied_requirements) {
        skip();
    }

    /* prepare for RPC and Action executions */
    start_user_sessions(conn, &handler_session, &sessions);
    subscribe_dummy_callback(handler_session, &callback_called, &subscription);

    /* test RPC "activate-software-image" */
#undef RPC_XPATH
#define RPC_XPATH "/test-module:activate-software-image"
    /*  -> sysrepo-user1 */
    RPC_DENIED(0, RPC_XPATH, NULL, 0, "deny-activate-software-image", "Not allowed to run activate-software-image");
    RPC_DENIED_TREE(0, RPC_XPATH, NULL, 0, "deny-activate-software-image", "Not allowed to run activate-software-image");
    /*  -> sysrepo-user2 */
    RPC_DENIED(1, RPC_XPATH, NULL, 0, "deny-test-module", "Deny everything not explicitly permitted in test-module.");
    RPC_DENIED_TREE(1, RPC_XPATH, NULL, 0, "deny-test-module", "Deny everything not explicitly permitted in test-module.");
    /*  -> sysrepo-user3 */
    RPC_DENIED(2, RPC_XPATH, NULL, 0, "deny-activate-software-image", "Not allowed to run activate-software-image");
    RPC_DENIED_TREE(2, RPC_XPATH, NULL, 0, "deny-activate-software-image", "Not allowed to run activate-software-image");

    /* test NETCONF operation "close-session" */
#undef RPC_XPATH
#define RPC_XPATH "/ietf-netconf:close-session"
    /*  -> sysrepo-user1 */
    RPC_PERMITED(0, RPC_XPATH, NULL, 0, 0);
    RPC_PERMITED_TREE(0, RPC_XPATH, NULL, 0, 0);
    /*  -> sysrepo-user2 */
    RPC_PERMITED(1, RPC_XPATH, NULL, 0, 0);
    RPC_PERMITED_TREE(1, RPC_XPATH, NULL, 0, 0);
    /*  -> sysrepo-user3 */
    RPC_PERMITED(2, RPC_XPATH, NULL, 0, 0);
    RPC_PERMITED_TREE(2, RPC_XPATH, NULL, 0, 0);

    /* test NETCONF operation "kill-session" */
#undef RPC_XPATH
#define RPC_XPATH "/ietf-netconf:kill-session"
    assert_int_equal(SR_ERR_OK, sr_new_val(RPC_XPATH "/session-id", &input));
    input->type = SR_UINT32_T;
    input->data.uint32_val = 12;
    assert_int_equal(SR_ERR_OK, sr_new_tree("session-id", "ietf-netconf", &input_tree));
    input_tree->type = SR_UINT32_T;
    input_tree->data.uint32_val = 12;
    /*  -> sysrepo-user1 */
    RPC_DENIED(0, RPC_XPATH, input, 1, "", "");
    RPC_DENIED_TREE(0, RPC_XPATH, input_tree, 1, "", "");
    /*  -> sysrepo-user2 */
    RPC_PERMITED(1, RPC_XPATH, input, 1, 0);
    RPC_PERMITED_TREE(1, RPC_XPATH, input_tree, 1, 0);
    /*  -> sysrepo-user3 */
    RPC_PERMITED(2, RPC_XPATH, input, 1, 0);
    RPC_PERMITED_TREE(2, RPC_XPATH, input_tree, 1, 0);
    sr_free_val(input);
    sr_free_tree(input_tree);

    /* test RPC "initialize" from turing-machine */
#undef RPC_XPATH
#define RPC_XPATH "/turing-machine:initialize"
    /*  -> sysrepo-user1 */
    RPC_PERMITED(0, RPC_XPATH, NULL, 0, 0);
    RPC_PERMITED_TREE(0, RPC_XPATH, NULL, 0, 0);
    /*  -> sysrepo-user2 */
    RPC_DENIED(1, RPC_XPATH, NULL, 0, "deny-initialize", "Not allowed to touch RPC 'initialize' in any module.");
    RPC_DENIED_TREE(1, RPC_XPATH, NULL, 0, "deny-initialize", "Not allowed to touch RPC 'initialize' in any module.");
    /*  -> sysrepo-user3 */
    RPC_DENIED(2, RPC_XPATH, NULL, 0, "deny-initialize", "Not allowed to touch RPC 'initialize' in any module.");
    RPC_DENIED_TREE(2, RPC_XPATH, NULL, 0, "deny-initialize", "Not allowed to touch RPC 'initialize' in any module.");

    /* test Action "unload" from test-model */
#undef ACTION_XPATH
#define ACTION_XPATH "/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/unload"
    /*  -> sysrepo-user1 */
    ACTION_PERMITED(0, ACTION_XPATH, NULL, 0, -1);
    ACTION_PERMITED_TREE(0, ACTION_XPATH, NULL, 0, -1);
    /*  -> sysrepo-user2 */
    ACTION_PERMITED(1, ACTION_XPATH, NULL, 0, -1);
    ACTION_PERMITED_TREE(1, ACTION_XPATH, NULL, 0, -1);
    /*  -> sysrepo-user3 */
    ACTION_PERMITED(2, ACTION_XPATH, NULL, 0, -1);
    ACTION_PERMITED_TREE(2, ACTION_XPATH, NULL, 0, -1);

    /* test Action "load" from test-model */
#undef ACTION_XPATH
#define ACTION_XPATH "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load"
    assert_int_equal(SR_ERR_OK, sr_new_val(ACTION_XPATH "/params", &input));
    input->type = SR_STRING_T;
    sr_val_set_str_data(input, SR_STRING_T, "--force");
    assert_int_equal(SR_ERR_OK, sr_new_tree("params", "test-module", &input_tree));
    input_tree->type = SR_STRING_T;
    sr_node_set_str_data(input_tree, SR_STRING_T, "--force");
    /*  -> sysrepo-user1 */
    ACTION_DENIED(0, ACTION_XPATH, input, 1, "deny-test-module", "Deny everything not explicitly permitted in test-module.");
    ACTION_DENIED_TREE(0, ACTION_XPATH, input_tree, 1, "deny-test-module", "Deny everything not explicitly permitted in test-module." );
    /*  -> sysrepo-user2 */
    ACTION_DENIED(1, ACTION_XPATH, input, 1, "deny-test-module", "Deny everything not explicitly permitted in test-module.");
    ACTION_DENIED_TREE(1, ACTION_XPATH, input_tree, 1, "deny-test-module", "Deny everything not explicitly permitted in test-module." );
    /*  -> sysrepo-user3 */
    ACTION_DENIED(2, ACTION_XPATH, input, 1, "deny-test-module", "Deny everything not explicitly permitted in test-module.");
    ACTION_DENIED_TREE(2, ACTION_XPATH, input_tree, 1, "deny-test-module", "Deny everything not explicitly permitted in test-module." );
    sr_free_val(input);
    sr_free_tree(input_tree);

    /* unsubscribe */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop sessions */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        rc = sr_session_stop(sessions[i]);
        assert_int_equal(rc, SR_ERR_OK);
    }
    rc = sr_session_stop(handler_session);
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
