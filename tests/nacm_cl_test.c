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

#include "test_data.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

#include "sysrepo.h"
#include "sr_common.h"
#include "test_module_helper.h"
#include "nacm_module_helper.h"
#include "system_helper.h"

#define NUM_OF_USERS  3
#define MAX_ATTEMPTS_TO_KILL_DAEMON  5
#define MAX_ATTEMPTS_TO_GET_LOG_MSG  10

//#define DEBUG_MODE /* Note: in debug mode we are not able to read logs from sysrepo daemon! */

#define CHECK_EXEC_UNAUTHORIZED_ERROR(SESSION, XPATH, RULE, RULE_INFO) \
    do { \
        rc = sr_get_last_error(sessions[SESSION], &error_info); \
        assert_int_equal(rc, SR_ERR_UNAUTHORIZED); \
        assert_string_equal(XPATH, error_info->xpath); \
        if (strlen(RULE) && strlen(RULE_INFO)) { \
            assert_string_equal("Execution of the operation '" XPATH "' was blocked by the NACM rule '" RULE "' (" RULE_INFO ").", \
                                error_info->message); \
        } else if (strlen(RULE)) { \
            assert_string_equal("Execution of the operation '" XPATH "' was blocked by the NACM rule '" RULE "'.", \
                                error_info->message); \
        } else { \
            assert_string_equal("Execution of the operation '" XPATH "' was blocked by NACM.", error_info->message); \
        } \
    } while (0)

#define CHECK_NOTIF_UNAUTHORIZED_LOG(XPATH, RULE, RULE_INFO) \
    do { \
        if (strlen(RULE) && strlen(RULE_INFO)) { \
            assert_true(has_log_message("\\[DBG\\] .* Delivery of the notification '" XPATH "' for subscription '[^']+' @ [0-9]+ " \
                                        "was blocked by the NACM rule '" RULE "' (" RULE_INFO").\n")); \
        } else if (strlen(RULE)) { \
            assert_true(has_log_message("\\[DBG\\] .* Delivery of the notification '" XPATH "' for subscription '[^']+' @ [0-9]+ " \
                                        "was blocked by the NACM rule '" RULE "'.\n")); \
        } else { \
            assert_true(has_log_message("\\[DBG\\] .* Delivery of the notification '" XPATH "' for subscription '[^']+' @ [0-9]+ " \
                                        "was blocked by NACM.\n")); \
        }\
    } while (0)

#define RPC_DENIED(SESSION, XPATH, INPUT, INPUT_CNT, RULE, RULE_INFO) \
    do { \
        rc = sr_check_exec_permission(sessions[SESSION], XPATH, &permitted); \
        assert_int_equal(rc, SR_ERR_OK); \
        assert_false(permitted); \
        reset_cb_call_count(); \
        rc = sr_rpc_send(sessions[SESSION], XPATH, INPUT, INPUT_CNT, &output, &output_cnt); \
        assert_int_equal(rc, SR_ERR_UNAUTHORIZED); \
        assert_int_equal(0, get_cb_call_count()); \
        CHECK_EXEC_UNAUTHORIZED_ERROR(SESSION, XPATH, RULE, RULE_INFO); \
    } while (0)

#define RPC_DENIED_TREE(SESSION, XPATH, INPUT, INPUT_CNT, RULE, RULE_INFO) \
    do { \
        rc = sr_check_exec_permission(sessions[SESSION], XPATH, &permitted); \
        assert_int_equal(rc, SR_ERR_OK); \
        assert_false(permitted); \
        reset_cb_call_count(); \
        rc = sr_rpc_send_tree(sessions[SESSION], XPATH, INPUT, INPUT_CNT, &output_tree, &output_cnt); \
        assert_int_equal(rc, SR_ERR_UNAUTHORIZED); \
        assert_int_equal(0, get_cb_call_count()); \
        CHECK_EXEC_UNAUTHORIZED_ERROR(SESSION, XPATH, RULE, RULE_INFO); \
    } while (0)

#define RPC_PERMITED(SESSION, XPATH, INPUT, INPUT_CNT, EXP_OUTPUT_CNT) \
    do { \
        rc = sr_check_exec_permission(sessions[SESSION], XPATH, &permitted); \
        assert_int_equal(rc, SR_ERR_OK); \
        assert_true(permitted); \
        reset_cb_call_count(); \
        rc = sr_rpc_send(sessions[SESSION], XPATH, INPUT, INPUT_CNT, &output, &output_cnt); \
        if (-1 == EXP_OUTPUT_CNT) { \
            assert_int_equal(rc, SR_ERR_VALIDATION_FAILED); \
        } else { \
            assert_int_equal(rc, SR_ERR_OK); \
            assert_int_equal(EXP_OUTPUT_CNT, output_cnt); \
            sr_free_values(output, output_cnt); \
        } \
        assert_int_equal(1, get_cb_call_count()); \
    } while (0)

#define RPC_PERMITED_TREE(SESSION, XPATH, INPUT, INPUT_CNT, EXP_OUTPUT_CNT) \
    do { \
        rc = sr_check_exec_permission(sessions[SESSION], XPATH, &permitted); \
        assert_int_equal(rc, SR_ERR_OK); \
        assert_true(permitted); \
        reset_cb_call_count(); \
        rc = sr_rpc_send_tree(sessions[SESSION], XPATH, INPUT, INPUT_CNT, &output_tree, &output_cnt); \
        if (-1 == EXP_OUTPUT_CNT) { \
            assert_int_equal(rc, SR_ERR_VALIDATION_FAILED); \
        } else { \
            assert_int_equal(rc, SR_ERR_OK); \
            assert_int_equal(EXP_OUTPUT_CNT, output_cnt); \
            sr_free_trees(output_tree, output_cnt); \
        } \
        assert_int_equal(1, get_cb_call_count()); \
    } while (0)

#define ACTION_DENIED(SESSION, XPATH, INPUT, INPUT_CNT, RULE, RULE_INFO) \
    do { \
        rc = sr_check_exec_permission(sessions[SESSION], XPATH, &permitted); \
        assert_int_equal(rc, SR_ERR_OK); \
        assert_false(permitted); \
        reset_cb_call_count(); \
        rc = sr_action_send(sessions[SESSION], XPATH, INPUT, INPUT_CNT, &output, &output_cnt); \
        assert_int_equal(rc, SR_ERR_UNAUTHORIZED); \
        assert_int_equal(0, get_cb_call_count()); \
        CHECK_EXEC_UNAUTHORIZED_ERROR(SESSION, XPATH, RULE, RULE_INFO); \
    } while (0)

#define ACTION_DENIED_TREE(SESSION, XPATH, INPUT, INPUT_CNT, RULE, RULE_INFO) \
    do { \
        rc = sr_check_exec_permission(sessions[SESSION], XPATH, &permitted); \
        assert_int_equal(rc, SR_ERR_OK); \
        assert_false(permitted); \
        reset_cb_call_count(); \
        rc = sr_action_send_tree(sessions[SESSION], XPATH, INPUT, INPUT_CNT, &output_tree, &output_cnt); \
        assert_int_equal(rc, SR_ERR_UNAUTHORIZED); \
        assert_int_equal(0, get_cb_call_count()); \
        CHECK_EXEC_UNAUTHORIZED_ERROR(SESSION, XPATH, RULE, RULE_INFO); \
    } while (0)

#define ACTION_PERMITED(SESSION, XPATH, INPUT, INPUT_CNT, EXP_OUTPUT_CNT) \
    do { \
        rc = sr_check_exec_permission(sessions[SESSION], XPATH, &permitted); \
        assert_int_equal(rc, SR_ERR_OK); \
        assert_true(permitted); \
        reset_cb_call_count(); \
        rc = sr_action_send(sessions[SESSION], XPATH, INPUT, INPUT_CNT, &output, &output_cnt); \
        if (-1 == EXP_OUTPUT_CNT) { \
            assert_int_equal(rc, SR_ERR_VALIDATION_FAILED); \
        } else { \
            assert_int_equal(rc, SR_ERR_OK); \
            assert_int_equal(EXP_OUTPUT_CNT, output_cnt); \
            sr_free_values(output, output_cnt); \
        } \
        assert_int_equal(1, get_cb_call_count()); \
    } while (0)

#define ACTION_PERMITED_TREE(SESSION, XPATH, INPUT, INPUT_CNT, EXP_OUTPUT_CNT) \
    do { \
        rc = sr_check_exec_permission(sessions[SESSION], XPATH, &permitted); \
        assert_int_equal(rc, SR_ERR_OK); \
        assert_true(permitted); \
        reset_cb_call_count(); \
        rc = sr_action_send_tree(sessions[SESSION], XPATH, INPUT, INPUT_CNT, &output_tree, &output_cnt); \
        if (-1 == EXP_OUTPUT_CNT) { \
            assert_int_equal(rc, SR_ERR_VALIDATION_FAILED); \
        } else { \
            assert_int_equal(rc, SR_ERR_OK); \
            assert_int_equal(EXP_OUTPUT_CNT, output_cnt); \
            sr_free_trees(output_tree, output_cnt); \
        } \
        assert_int_equal(1, get_cb_call_count()); \
    } while (0)

#define EVENT_NOTIF_PERMITED(XPATH, VALUES, VALUE_CNT) \
    do { \
        reset_cb_call_count(); \
        rc = sr_event_notif_send(handler_session, XPATH, VALUES, VALUE_CNT); \
        wait_ms(100); \
        assert_int_equal(rc, SR_ERR_OK); \
        assert_int_equal(1, get_cb_call_count()); \
        assert_false(has_log_message("\\[DBG\\] .* Delivery of the notification '" XPATH "' for subscription '[^']+' @ [0-9]+ " \
                                     "was blocked by .*NACM.*")); \
        clear_log_history(); \
    } while (0)

#define EVENT_NOTIF_DENIED(XPATH, VALUES, VALUE_CNT, RULE, RULE_INFO) \
    do { \
        reset_cb_call_count(); \
        rc = sr_event_notif_send(handler_session, XPATH, VALUES, VALUE_CNT); \
        wait_ms(100); \
        assert_int_equal(rc, SR_ERR_OK); \
        assert_int_equal(0, get_cb_call_count()); \
        CHECK_NOTIF_UNAUTHORIZED_LOG(XPATH, RULE, RULE_INFO); \
        clear_log_history(); \
    } while (0)

#define EVENT_NOTIF_PERMITED_TREE(XPATH, TREES, TREE_CNT) \
    do { \
        reset_cb_call_count(); \
        rc = sr_event_notif_send_tree(handler_session, XPATH, TREES, TREE_CNT); \
        wait_ms(100); \
        assert_int_equal(rc, SR_ERR_OK); \
        assert_int_equal(1, get_cb_call_count()); \
        assert_false(has_log_message("\\[DBG\\] .* Delivery of the notification '" XPATH "' for subscription '[^']+' @ [0-9]+ " \
                                     "was blocked by .*NACM.*")); \
        clear_log_history(); \
    } while (0)

#define EVENT_NOTIF_DENIED_TREE(XPATH, TREES, TREE_CNT, RULE, RULE_INFO) \
    do { \
        reset_cb_call_count(); \
        rc = sr_event_notif_send_tree(handler_session, XPATH, TREES, TREE_CNT); \
        wait_ms(100); \
        assert_int_equal(rc, SR_ERR_OK); \
        assert_int_equal(0, get_cb_call_count()); \
        CHECK_NOTIF_UNAUTHORIZED_LOG(XPATH, RULE, RULE_INFO); \
        clear_log_history(); \
    } while (0)

typedef sr_session_ctx_t *user_sessions_t[NUM_OF_USERS];

/**
+ * @brief Recent log history.
+ */
typedef struct log_history_s {
    pthread_mutex_t lock;
    sr_list_t *logs; /**< items are of type (char *) */
    bool running;
} log_history_t;

static bool satisfied_requirements = true;  /**< Indices if the test can be actually run with the current system configuration */
static bool daemon_run_before_test = false; /**< Indices if the daemon was running before executing the test. */
static pid_t daemon_pid = -1; /* PID of the sysrepo daemon (child of this process) */
static int daemon_stderr = -1;    /* read-end of the daemon's stderr */
static log_history_t log_history = { .lock = PTHREAD_MUTEX_INITIALIZER, .logs = NULL, .running = false }; /* recent log history */
static pthread_t stderr_reader = {0}; /* log-reader thread's control structure */
static int cb_call_count; /* how many times a callback was called */
pthread_mutex_t cb_call_count_lock = PTHREAD_MUTEX_INITIALIZER; /* protecting cb_call_count */

/* TODO: Report the issue with failed validation when action reply is empty. Then reflect the fix. */


static void
wait_ms(long int ms)
{
    struct timespec ts = { 0 };
    ts.tv_nsec = ms * 1000000L;
    nanosleep(&ts, NULL);
}

static void
inc_cb_call_count()
{
    pthread_mutex_lock(&cb_call_count_lock);
    ++cb_call_count;
    pthread_mutex_unlock(&cb_call_count_lock);
}

static int
get_cb_call_count()
{
    int count = 0;
    pthread_mutex_lock(&cb_call_count_lock);
    count = cb_call_count;
    pthread_mutex_unlock(&cb_call_count_lock);
    return count;
}

static void
reset_cb_call_count()
{
    pthread_mutex_lock(&cb_call_count_lock);
    cb_call_count = 0;
    pthread_mutex_unlock(&cb_call_count_lock);
}

#ifndef DEBUG_MODE
static void
daemon_kill(bool last_attempt)
{
    FILE *pidfile = NULL;
    int pid = 0, ret = 0;

    /* read PID of the daemon from sysrepo PID file */
    pidfile = fopen(SR_DAEMON_PID_FILE, "r");
    assert_non_null(pidfile);
    ret = fscanf(pidfile, "%d", &pid);
    assert_int_equal(ret, 1);

    /* send SIGTERM/SIGKILL to the daemon process */
    SR_LOG_DBG("Sending %s signal to PID=%d.", (last_attempt ? "SIGKILL" : "SIGTERM"), pid);
    ret = kill(pid, last_attempt ? SIGKILL : SIGTERM);
    assert_int_not_equal(ret, -1);
}
#endif

static void *
daemon_log_reader(void *arg)
{
    (void)arg;
    char *line = NULL, *msg = NULL;
    size_t len = 0;
    bool running = false;

    do {
        pthread_mutex_lock(&log_history.lock);
        running = log_history.running;
        pthread_mutex_unlock(&log_history.lock);
        if (!running) {
            wait_ms(5);
        }
    } while (!running);
    assert_true(daemon_stderr >= 0);

    while (running) {
        pthread_mutex_lock(&log_history.lock);
        while (readline(daemon_stderr, &line, &len)) {
            msg = strdup(line);
            assert_non_null(msg);
//            SR_LOG_DBG("Appending message: %s", msg);
            assert_int_equal(SR_ERR_OK, sr_list_add(log_history.logs, msg));
        }
        running = log_history.running;
        pthread_mutex_unlock(&log_history.lock);
        if (running) {
            wait_ms(5);
        }
    }

    free(line);
    return NULL;
}

static void
start_sysrepo_daemon(sr_conn_ctx_t **conn_p)
{
#ifndef DEBUG_MODE
    int attempt = 1;
    int flags = 0;
#endif
    sr_conn_ctx_t *conn = NULL;
    int rc = SR_ERR_OK;

    if (!satisfied_requirements) {
        return;
    }

    sr_log_stderr(SR_LL_DBG);

#ifndef DEBUG_MODE
    while (attempt <= MAX_ATTEMPTS_TO_KILL_DAEMON) {
        /* connect to sysrepo, force daemon connection */
        rc = sr_connect("nacm_cl_test", SR_CONN_DAEMON_REQUIRED, &conn);
        sr_disconnect(conn);
        conn = NULL;
        assert_true(SR_ERR_OK == rc || SR_ERR_DISCONNECT == rc);

        /* kill the daemon if it was running */
        if (SR_ERR_OK == rc) {
            if (1 == attempt) {
                daemon_run_before_test = true;
            }
            daemon_kill(attempt == MAX_ATTEMPTS_TO_KILL_DAEMON);
            /* wait for the daemon to terminate */
            wait_ms(500);
        } else {
            if (1 == attempt) {
                daemon_run_before_test = false;
            }
            break;
        }
        ++attempt;
    }

    /* create initial datastore content */
    createDataTreeTestModule();

    /* start sysrepo in the daemon debug mode as a child process */
    pthread_create(&stderr_reader, NULL, daemon_log_reader, NULL);
    daemon_pid = sr_popen("../src/sysrepod -l4 -d", NULL, NULL, &daemon_stderr);
    assert_int_not_equal(-1, daemon_pid);
    assert_true(daemon_stderr >= 0);

    /* start log reader */
    flags = fcntl(daemon_stderr, F_GETFL, 0);
    fcntl(daemon_stderr, F_SETFL, flags | O_NONBLOCK);
    pthread_mutex_lock(&log_history.lock);
    log_history.running = true;
    pthread_mutex_unlock(&log_history.lock);

    /* wait for the daemon to start */
    wait_ms(500);
#endif
    rc = sr_connect("nacm_cl_test", SR_CONN_DAEMON_REQUIRED, &conn);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(conn_p);
    *conn_p = conn;
}

static void
clear_log_history()
{
    pthread_mutex_lock(&log_history.lock);
    for (size_t i = 0; i < log_history.logs->count; ++i) {
        free(log_history.logs->data[i]);
    }
    log_history.logs->count = 0;
    pthread_mutex_unlock(&log_history.lock);
}

static bool
has_log_message(const char *msg_re)
{
    bool has = false;
    int attempt = 1;
    size_t log_count = 0;

#ifdef HAVE_REGEX_H
    while (!has && attempt < MAX_ATTEMPTS_TO_GET_LOG_MSG) {
        pthread_mutex_lock(&log_history.lock);
        for (size_t i = log_count; !has && (i < log_history.logs->count); ++i) {
            char *message = (char *)log_history.logs->data[i];
            regex_t re;
            /* Compile regular expression */
            assert_int_equal(0, regcomp(&re, msg_re, REG_NOSUB | REG_EXTENDED));
            if (0 == regexec(&re, message, 0, NULL, 0)) {
                has = true;
            }

            printf("REGEX TEST BEGIN -------------\n");
            printf("Regex: %s\n", msg_re);
            printf("Message: %s\n", message);
            printf("Matches: %s\n", has ? "YES" : "NO");
            printf("REGEX TEST END -------------\n");

            regfree(&re);
        }
        log_count = log_history.logs->count;
        pthread_mutex_unlock(&log_history.lock);
        ++attempt;
        if (!has) {
            /* log reader may need more time to sync */
            wait_ms(10);
        }
    }
#else
    has = true; /**< let the test pass */
#endif

    return has;
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
    add_nacm_rule(nacm_config, "acl1", "deny-link-discovered", "test-module", NACM_RULE_NOTIF,
            "link-discovered", "read", "deny", "Not allowed to receive the link-discovered notification");
    add_nacm_rule(nacm_config, "acl1", "rule-with-no-effect2", "nc-notifications", NACM_RULE_NOTIF,
            "replayComplete", "*", "deny", "NETCONF replayComplete notification cannot be effectively denied");
    /*  -> acl2: */
    add_nacm_rule(nacm_config, "acl2", "permit-kill-session", "ietf-netconf", NACM_RULE_RPC,
            "kill-session", "exec", "permit", "Permit execution of the kill-session NETCONF operation.");
    add_nacm_rule(nacm_config, "acl2", "deny-initialize", "*", NACM_RULE_RPC,
            "initialize", "*", "deny", "Not allowed to touch RPC 'initialize' in any module.");
    add_nacm_rule(nacm_config, "acl2", "deny-halted", "*", NACM_RULE_NOTIF,
            "halted", "*", "deny", "Not allowed to receive 'halted' notification from any module.");
    /*  -> acl3: */
    add_nacm_rule(nacm_config, "acl3", "permit-unload", "test-module", NACM_RULE_RPC,
            "unload", "exec", "permit", "Permit action unload");
    add_nacm_rule(nacm_config, "acl3", "permit-status-change", "test-module", NACM_RULE_NOTIF,
            "status-change", "*", "permit", "Permit notification 'status-change'.");
    add_nacm_rule(nacm_config, "acl3", "deny-netconf-capability-change", "ietf-netconf-notifications", NACM_RULE_NOTIF,
            "netconf-capability-change", "read", "deny", "Not allowed to receive the NETCONF capability change notification");
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
sysrepo_setup_with_denied_read_by_dflt(void **state)
{
    sr_conn_ctx_t *conn = NULL;
    test_nacm_cfg_t *nacm_config = NULL;

    /* NACM startup config */
    new_nacm_config(&nacm_config);
    set_nacm_read_dflt(nacm_config, "deny");
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
    int ret = 0, status = 0;
    sr_conn_ctx_t *conn = *state;

    if (!satisfied_requirements) {
        return 0;
    }

    /* disconnect from sysrepo */
    assert_non_null(conn);
    sr_disconnect(conn);

#ifndef DEBUG_MODE
    /* kill the daemon run as the child process */
    daemon_kill(false);

    /* stop stderr reader */
    pthread_mutex_lock(&log_history.lock);
    log_history.running = false;
    pthread_mutex_unlock(&log_history.lock);
    pthread_join(stderr_reader, NULL);
    clear_log_history();

    /* wait for daemon to stop */
    assert_int_not_equal(-1, daemon_pid);
    assert_int_equal(daemon_pid, waitpid(daemon_pid, &status, 0));
    assert_true(daemon_stderr >= 0);
    close(daemon_stderr);
    daemon_stderr = -1;
    daemon_pid = -1;

    /* restart daemon if it was running before the test */
    if (daemon_run_before_test) {
        ret = system("../src/sysrepod -l4");
        assert_int_equal(ret, 0);
    }
#endif
    return 0;
}

static int
dummy_rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt,
        sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    inc_cb_call_count();
    SR_LOG_DBG("Running dummy callback for RPC: %s", xpath);
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
subscribe_dummy_rpc_callback(sr_session_ctx_t *handler_session, void *private_ctx, sr_subscription_ctx_t **subscription)
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
dummy_event_notif_cb(const sr_ev_notif_type_t notif_type, const char *xpath, const sr_val_t *values,
        const size_t value_cnt, time_t timestamp, void *private_ctx)
{
    inc_cb_call_count();
    SR_LOG_DBG("Running dummy callback for Event notification: %s", xpath);
}

static void
subscribe_dummy_event_notif_callback(sr_session_ctx_t *user_session, void *private_ctx, sr_subscription_ctx_t **subscription)
{
    int rc = SR_ERR_OK;

    /* subscribe for Event notifications with dummy callback */
    rc = sr_event_notif_subscribe(user_session, "/test-module:link-discovered",
            dummy_event_notif_cb, private_ctx, SR_SUBSCR_DEFAULT, subscription);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_event_notif_subscribe(user_session, "/test-module:link-removed",
            dummy_event_notif_cb, private_ctx, SR_SUBSCR_CTX_REUSE, subscription);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_event_notif_subscribe(user_session, "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change",
            dummy_event_notif_cb, private_ctx, SR_SUBSCR_CTX_REUSE, subscription);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_event_notif_subscribe(user_session, "/turing-machine:halted",
            dummy_event_notif_cb, private_ctx, SR_SUBSCR_CTX_REUSE, subscription);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_event_notif_subscribe(user_session, "/ietf-netconf-notifications:netconf-capability-change",
            dummy_event_notif_cb, private_ctx, SR_SUBSCR_CTX_REUSE, subscription);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_event_notif_subscribe(user_session, "/nc-notifications:replayComplete",
            dummy_event_notif_cb, private_ctx, SR_SUBSCR_CTX_REUSE, subscription);
    assert_int_equal(rc, SR_ERR_OK);

}

static void
nacm_cl_test_rpc_acl_with_empty_nacm_cfg(void **state)
{
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
    subscribe_dummy_rpc_callback(handler_session, NULL, &subscription);

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
    subscribe_dummy_rpc_callback(handler_session, NULL, &subscription);

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
    subscribe_dummy_rpc_callback(handler_session, NULL, &subscription);

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
    subscribe_dummy_rpc_callback(handler_session, NULL, &subscription);

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

static void
nacm_cl_test_event_notif_acl_with_empty_nacm_cfg(void **state)
{
    int rc = SR_ERR_OK;
    sr_conn_ctx_t *conn = *state;
    sr_session_ctx_t *handler_session = NULL;
    user_sessions_t sessions = {NULL};
    sr_subscription_ctx_t *subscription = NULL;
    sr_val_t *values = NULL;
    sr_node_t *trees = NULL, *node = NULL;

    if (!satisfied_requirements) {
        skip();
    }

    /* start all sessions */
    start_user_sessions(conn, &handler_session, &sessions);

    /***** subscribe for notifications with sysrepo-user1 *****/
    subscribe_dummy_event_notif_callback(sessions[0], NULL, &subscription);

    /* test Event notification "link-discovered" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-discovered"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* test Event notification "link-removed" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-removed"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* test Event notification "status-change" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* test Event notification "halted" from turing-machine */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/turing-machine:halted"
    assert_int_equal(SR_ERR_OK, sr_new_val(EVENT_NOTIF_XPATH "/state", &values));
    values[0].type = SR_UINT16_T;
    values[0].data.uint16_val = 13;
    assert_int_equal(SR_ERR_OK, sr_new_tree("state", "turing-machine", &trees));
    trees[0].type = SR_UINT16_T;
    trees[0].data.uint16_val = 13;
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, values, 1);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, trees, 1);
    sr_free_val(values);
    sr_free_tree(trees);

    /* test Event notification "netconf-capability-change" from ietf-netconf-notifications */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/ietf-netconf-notifications:netconf-capability-change"
    assert_int_equal(SR_ERR_OK, sr_new_val(EVENT_NOTIF_XPATH "/changed-by/server", &values));
    values[0].type = SR_LEAF_EMPTY_T;
    assert_int_equal(SR_ERR_OK, sr_new_tree("changed-by", "turing-machine", &trees));
    trees[0].type = SR_CONTAINER_T;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(&trees[0], "server", NULL, &node));
    node->type = SR_LEAF_EMPTY_T;
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, values, 1);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, trees, 1);
    sr_free_val(values);
    sr_free_tree(trees);

    /* test Event notification "replayComplete" from nc-notifications */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/nc-notifications:replayComplete"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* unsubscribe sysrepo-user1 */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /***** subscribe for notifications with sysrepo-user2 *****/
    subscribe_dummy_event_notif_callback(sessions[0], NULL, &subscription);

    /* test Event notification "link-discovered" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-discovered"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* test Event notification "link-removed" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-removed"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* test Event notification "status-change" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* test Event notification "halted" from turing-machine */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/turing-machine:halted"
    assert_int_equal(SR_ERR_OK, sr_new_val(EVENT_NOTIF_XPATH "/state", &values));
    values[0].type = SR_UINT16_T;
    values[0].data.uint16_val = 13;
    assert_int_equal(SR_ERR_OK, sr_new_tree("state", "turing-machine", &trees));
    trees[0].type = SR_UINT16_T;
    trees[0].data.uint16_val = 13;
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, values, 1);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, trees, 1);
    sr_free_val(values);
    sr_free_tree(trees);

    /* test Event notification "netconf-capability-change" from ietf-netconf-notifications */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/ietf-netconf-notifications:netconf-capability-change"
    assert_int_equal(SR_ERR_OK, sr_new_val(EVENT_NOTIF_XPATH "/changed-by/server", &values));
    values[0].type = SR_LEAF_EMPTY_T;
    assert_int_equal(SR_ERR_OK, sr_new_tree("changed-by", "turing-machine", &trees));
    trees[0].type = SR_CONTAINER_T;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(&trees[0], "server", NULL, &node));
    node->type = SR_LEAF_EMPTY_T;
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, values, 1);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, trees, 1);
    sr_free_val(values);
    sr_free_tree(trees);

    /* test Event notification "replayComplete" from nc-notifications */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/nc-notifications:replayComplete"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* unsubscribe sysrepo-user2 */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /***** subscribe for notifications with sysrepo-user3 *****/
    subscribe_dummy_event_notif_callback(sessions[0], NULL, &subscription);

    /* test Event notification "link-discovered" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-discovered"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* test Event notification "link-removed" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-removed"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* test Event notification "status-change" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* test Event notification "halted" from turing-machine */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/turing-machine:halted"
    assert_int_equal(SR_ERR_OK, sr_new_val(EVENT_NOTIF_XPATH "/state", &values));
    values[0].type = SR_UINT16_T;
    values[0].data.uint16_val = 13;
    assert_int_equal(SR_ERR_OK, sr_new_tree("state", "turing-machine", &trees));
    trees[0].type = SR_UINT16_T;
    trees[0].data.uint16_val = 13;
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, values, 1);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, trees, 1);
    sr_free_val(values);
    sr_free_tree(trees);

    /* test Event notification "netconf-capability-change" from ietf-netconf-notifications */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/ietf-netconf-notifications:netconf-capability-change"
    assert_int_equal(SR_ERR_OK, sr_new_val(EVENT_NOTIF_XPATH "/changed-by/server", &values));
    values[0].type = SR_LEAF_EMPTY_T;
    assert_int_equal(SR_ERR_OK, sr_new_tree("changed-by", "turing-machine", &trees));
    trees[0].type = SR_CONTAINER_T;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(&trees[0], "server", NULL, &node));
    node->type = SR_LEAF_EMPTY_T;
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, values, 1);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, trees, 1);
    sr_free_val(values);
    sr_free_tree(trees);

    /* test Event notification "replayComplete" from nc-notifications */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/nc-notifications:replayComplete"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* unsubscribe sysrepo-user3 */
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
nacm_cl_test_event_notif_acl(void **state)
{
    int rc = SR_ERR_OK;
    sr_conn_ctx_t *conn = *state;
    sr_session_ctx_t *handler_session = NULL;
    user_sessions_t sessions = {NULL};
    sr_subscription_ctx_t *subscription = NULL;
    sr_val_t *values = NULL;
    sr_node_t *trees = NULL, *node = NULL;

    if (!satisfied_requirements) {
        skip();
    }

    /* start all sessions */
    start_user_sessions(conn, &handler_session, &sessions);

    /***** subscribe for notifications with sysrepo-user1 *****/
    subscribe_dummy_event_notif_callback(sessions[0], NULL, &subscription);

    /* test Event notification "link-discovered" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-discovered"
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "deny-link-discovered", "Not allowed to receive the link-discovered notification");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "deny-link-discovered", "Not allowed to receive the link-discovered notification");

    /* test Event notification "link-removed" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-removed"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* test Event notification "status-change" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* test Event notification "halted" from turing-machine */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/turing-machine:halted"
    assert_int_equal(SR_ERR_OK, sr_new_val(EVENT_NOTIF_XPATH "/state", &values));
    values[0].type = SR_UINT16_T;
    values[0].data.uint16_val = 13;
    assert_int_equal(SR_ERR_OK, sr_new_tree("state", "turing-machine", &trees));
    trees[0].type = SR_UINT16_T;
    trees[0].data.uint16_val = 13;
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, values, 1);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, trees, 1);
    sr_free_val(values);
    sr_free_tree(trees);

    /* test Event notification "netconf-capability-change" from ietf-netconf-notifications */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/ietf-netconf-notifications:netconf-capability-change"
    assert_int_equal(SR_ERR_OK, sr_new_val(EVENT_NOTIF_XPATH "/changed-by/server", &values));
    values[0].type = SR_LEAF_EMPTY_T;
    assert_int_equal(SR_ERR_OK, sr_new_tree("changed-by", "turing-machine", &trees));
    trees[0].type = SR_CONTAINER_T;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(&trees[0], "server", NULL, &node));
    node->type = SR_LEAF_EMPTY_T;
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);
    sr_free_val(values);
    sr_free_tree(trees);

    /* test Event notification "replayComplete" from nc-notifications */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/nc-notifications:replayComplete"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* unsubscribe sysrepo-user1 */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /***** subscribe for notifications with sysrepo-user2 *****/
    subscribe_dummy_event_notif_callback(sessions[0], NULL, &subscription);

    /* test Event notification "link-discovered" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-discovered"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* test Event notification "link-removed" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-removed"
    /*  -> sysrepo-user2 */
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* test Event notification "status-change" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change"

    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* test Event notification "halted" from turing-machine */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/turing-machine:halted"
    assert_int_equal(SR_ERR_OK, sr_new_val(EVENT_NOTIF_XPATH "/state", &values));
    values[0].type = SR_UINT16_T;
    values[0].data.uint16_val = 13;
    assert_int_equal(SR_ERR_OK, sr_new_tree("state", "turing-machine", &trees));
    trees[0].type = SR_UINT16_T;
    trees[0].data.uint16_val = 13;
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, values, 1, "deny-halted", "Not allowed to receive 'halted' notification from any module.");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, trees, 1, "deny-halted", "Not allowed to receive 'halted' notification from any module.");
    sr_free_val(values);
    sr_free_tree(trees);

    /* test Event notification "netconf-capability-change" from ietf-netconf-notifications */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/ietf-netconf-notifications:netconf-capability-change"
    assert_int_equal(SR_ERR_OK, sr_new_val(EVENT_NOTIF_XPATH "/changed-by/server", &values));
    values[0].type = SR_LEAF_EMPTY_T;
    assert_int_equal(SR_ERR_OK, sr_new_tree("changed-by", "turing-machine", &trees));
    trees[0].type = SR_CONTAINER_T;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(&trees[0], "server", NULL, &node));
    node->type = SR_LEAF_EMPTY_T;
    /*  -> sysrepo-user2 */
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);
    sr_free_val(values);
    sr_free_tree(trees);

    /* test Event notification "replayComplete" from nc-notifications */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/nc-notifications:replayComplete"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* unsubscribe sysrepo-user2 */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /***** subscribe for notifications with sysrepo-user3 *****/
    subscribe_dummy_event_notif_callback(sessions[0], NULL, &subscription);

    /* test Event notification "link-discovered" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-discovered"
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "deny-link-discovered", "Not allowed to receive the link-discovered notification");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "deny-link-discovered", "Not allowed to receive the link-discovered notification");

    /* test Event notification "link-removed" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-removed"
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "deny-test-module", "Deny everything not explicitly permitted in test-module.");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "deny-test-module", "Deny everything not explicitly permitted in test-module.");

    /* test Event notification "status-change" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* test Event notification "halted" from turing-machine */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/turing-machine:halted"
    assert_int_equal(SR_ERR_OK, sr_new_val(EVENT_NOTIF_XPATH "/state", &values));
    values[0].type = SR_UINT16_T;
    values[0].data.uint16_val = 13;
    assert_int_equal(SR_ERR_OK, sr_new_tree("state", "turing-machine", &trees));
    trees[0].type = SR_UINT16_T;
    trees[0].data.uint16_val = 13;
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, values, 1, "deny-halted", "Not allowed to receive 'halted' notification from any module.");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, trees, 1, "deny-halted", "Not allowed to receive 'halted' notification from any module.");
    sr_free_val(values);
    sr_free_tree(trees);

    /* test Event notification "netconf-capability-change" from ietf-netconf-notifications */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/ietf-netconf-notifications:netconf-capability-change"
    assert_int_equal(SR_ERR_OK, sr_new_val(EVENT_NOTIF_XPATH "/changed-by/server", &values));
    values[0].type = SR_LEAF_EMPTY_T;
    assert_int_equal(SR_ERR_OK, sr_new_tree("changed-by", "turing-machine", &trees));
    trees[0].type = SR_CONTAINER_T;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(&trees[0], "server", NULL, &node));
    node->type = SR_LEAF_EMPTY_T;
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "deny-netconf-capability-change", "Not allowed to receive the NETCONF capability change notification");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "deny-netconf-capability-change", "Not allowed to receive the NETCONF capability change notification");
    sr_free_val(values);
    sr_free_tree(trees);

    /* test Event notification "replayComplete" from nc-notifications */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/nc-notifications:replayComplete"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* unsubscribe sysrepo-user3 */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

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
nacm_cl_test_event_notif_acl_with_denied_read_by_dflt(void **state)
{
    int rc = SR_ERR_OK;
    sr_conn_ctx_t *conn = *state;
    sr_session_ctx_t *handler_session = NULL;
    user_sessions_t sessions = {NULL};
    sr_subscription_ctx_t *subscription = NULL;
    sr_val_t *values = NULL;
    sr_node_t *trees = NULL, *node = NULL;

    if (!satisfied_requirements) {
        skip();
    }

    /* start all sessions */
    start_user_sessions(conn, &handler_session, &sessions);

    /***** subscribe for notifications with sysrepo-user1 *****/
    subscribe_dummy_event_notif_callback(sessions[0], NULL, &subscription);

    /* test Event notification "link-discovered" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-discovered"
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "deny-link-discovered", "Not allowed to receive the link-discovered notification");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "deny-link-discovered", "Not allowed to receive the link-discovered notification");

    /* test Event notification "link-removed" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-removed"
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "", "");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "", "");

    /* test Event notification "status-change" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change"
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "", "");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "", "");

    /* test Event notification "halted" from turing-machine */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/turing-machine:halted"
    assert_int_equal(SR_ERR_OK, sr_new_val(EVENT_NOTIF_XPATH "/state", &values));
    values[0].type = SR_UINT16_T;
    values[0].data.uint16_val = 13;
    assert_int_equal(SR_ERR_OK, sr_new_tree("state", "turing-machine", &trees));
    trees[0].type = SR_UINT16_T;
    trees[0].data.uint16_val = 13;
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, values, 1, "", "");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, trees, 1, "", "");
    sr_free_val(values);
    sr_free_tree(trees);

    /* test Event notification "netconf-capability-change" from ietf-netconf-notifications */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/ietf-netconf-notifications:netconf-capability-change"
    assert_int_equal(SR_ERR_OK, sr_new_val(EVENT_NOTIF_XPATH "/changed-by/server", &values));
    values[0].type = SR_LEAF_EMPTY_T;
    assert_int_equal(SR_ERR_OK, sr_new_tree("changed-by", "turing-machine", &trees));
    trees[0].type = SR_CONTAINER_T;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(&trees[0], "server", NULL, &node));
    node->type = SR_LEAF_EMPTY_T;
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "", "");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "", "");
    sr_free_val(values);
    sr_free_tree(trees);

    /* test Event notification "replayComplete" from nc-notifications */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/nc-notifications:replayComplete"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* unsubscribe sysrepo-user1 */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /***** subscribe for notifications with sysrepo-user2 *****/
    subscribe_dummy_event_notif_callback(sessions[0], NULL, &subscription);

    /* test Event notification "link-discovered" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-discovered"
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "", "");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "", "");

    /* test Event notification "link-removed" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-removed"
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "", "");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "", "");

    /* test Event notification "status-change" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change"
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "", "");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "", "");

    /* test Event notification "halted" from turing-machine */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/turing-machine:halted"
    assert_int_equal(SR_ERR_OK, sr_new_val(EVENT_NOTIF_XPATH "/state", &values));
    values[0].type = SR_UINT16_T;
    values[0].data.uint16_val = 13;
    assert_int_equal(SR_ERR_OK, sr_new_tree("state", "turing-machine", &trees));
    trees[0].type = SR_UINT16_T;
    trees[0].data.uint16_val = 13;
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, values, 1, "deny-halted", "Not allowed to receive 'halted' notification from any module.");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, trees, 1, "deny-halted", "Not allowed to receive 'halted' notification from any module.");
    sr_free_val(values);
    sr_free_tree(trees);

    /* test Event notification "netconf-capability-change" from ietf-netconf-notifications */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/ietf-netconf-notifications:netconf-capability-change"
    assert_int_equal(SR_ERR_OK, sr_new_val(EVENT_NOTIF_XPATH "/changed-by/server", &values));
    values[0].type = SR_LEAF_EMPTY_T;
    assert_int_equal(SR_ERR_OK, sr_new_tree("changed-by", "turing-machine", &trees));
    trees[0].type = SR_CONTAINER_T;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(&trees[0], "server", NULL, &node));
    node->type = SR_LEAF_EMPTY_T;
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "", "");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "", "");
    sr_free_val(values);
    sr_free_tree(trees);

    /* test Event notification "replayComplete" from nc-notifications */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/nc-notifications:replayComplete"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* unsubscribe sysrepo-user2 */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /***** subscribe for notifications with sysrepo-user3 *****/
    subscribe_dummy_event_notif_callback(sessions[0], NULL, &subscription);

    /* test Event notification "link-discovered" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-discovered"
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "deny-link-discovered", "Not allowed to receive the link-discovered notification");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "deny-link-discovered", "Not allowed to receive the link-discovered notification");

    /* test Event notification "link-removed" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-removed"
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "deny-test-module", "Deny everything not explicitly permitted in test-module.");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "deny-test-module", "Deny everything not explicitly permitted in test-module.");

    /* test Event notification "status-change" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* test Event notification "halted" from turing-machine */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/turing-machine:halted"
    assert_int_equal(SR_ERR_OK, sr_new_val(EVENT_NOTIF_XPATH "/state", &values));
    values[0].type = SR_UINT16_T;
    values[0].data.uint16_val = 13;
    assert_int_equal(SR_ERR_OK, sr_new_tree("state", "turing-machine", &trees));
    trees[0].type = SR_UINT16_T;
    trees[0].data.uint16_val = 13;
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, values, 1, "deny-halted", "Not allowed to receive 'halted' notification from any module.");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, trees, 1, "deny-halted", "Not allowed to receive 'halted' notification from any module.");
    sr_free_val(values);
    sr_free_tree(trees);

    /* test Event notification "netconf-capability-change" from ietf-netconf-notifications */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/ietf-netconf-notifications:netconf-capability-change"
    assert_int_equal(SR_ERR_OK, sr_new_val(EVENT_NOTIF_XPATH "/changed-by/server", &values));
    values[0].type = SR_LEAF_EMPTY_T;
    assert_int_equal(SR_ERR_OK, sr_new_tree("changed-by", "turing-machine", &trees));
    trees[0].type = SR_CONTAINER_T;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(&trees[0], "server", NULL, &node));
    node->type = SR_LEAF_EMPTY_T;
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "deny-netconf-capability-change", "Not allowed to receive the NETCONF capability change notification");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "deny-netconf-capability-change", "Not allowed to receive the NETCONF capability change notification");
    sr_free_val(values);
    sr_free_tree(trees);

    /* test Event notification "replayComplete" from nc-notifications */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/nc-notifications:replayComplete"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* unsubscribe sysrepo-user3 */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

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
nacm_cl_test_event_notif_acl_with_ext_groups(void **state)
{
    int rc = SR_ERR_OK;
    sr_conn_ctx_t *conn = *state;
    sr_session_ctx_t *handler_session = NULL;
    user_sessions_t sessions = {NULL};
    sr_subscription_ctx_t *subscription = NULL;
    sr_val_t *values = NULL;
    sr_node_t *trees = NULL, *node = NULL;

    if (!satisfied_requirements) {
        skip();
    }

    /* start all sessions */
    start_user_sessions(conn, &handler_session, &sessions);

    /***** subscribe for notifications with sysrepo-user1 *****/
    subscribe_dummy_event_notif_callback(sessions[0], NULL, &subscription);

    /* test Event notification "link-discovered" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-discovered"
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "deny-link-discovered", "Not allowed to receive the link-discovered notification");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "deny-link-discovered", "Not allowed to receive the link-discovered notification");

    /* test Event notification "link-removed" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-removed"
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "deny-test-module", "Deny everything not explicitly permitted in test-module.");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "deny-test-module", "Deny everything not explicitly permitted in test-module.");

    /* test Event notification "status-change" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* test Event notification "halted" from turing-machine */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/turing-machine:halted"
    assert_int_equal(SR_ERR_OK, sr_new_val(EVENT_NOTIF_XPATH "/state", &values));
    values[0].type = SR_UINT16_T;
    values[0].data.uint16_val = 13;
    assert_int_equal(SR_ERR_OK, sr_new_tree("state", "turing-machine", &trees));
    trees[0].type = SR_UINT16_T;
    trees[0].data.uint16_val = 13;
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, values, 1);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, trees, 1);
    sr_free_val(values);
    sr_free_tree(trees);

    /* test Event notification "netconf-capability-change" from ietf-netconf-notifications */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/ietf-netconf-notifications:netconf-capability-change"
    assert_int_equal(SR_ERR_OK, sr_new_val(EVENT_NOTIF_XPATH "/changed-by/server", &values));
    values[0].type = SR_LEAF_EMPTY_T;
    assert_int_equal(SR_ERR_OK, sr_new_tree("changed-by", "turing-machine", &trees));
    trees[0].type = SR_CONTAINER_T;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(&trees[0], "server", NULL, &node));
    node->type = SR_LEAF_EMPTY_T;
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "deny-netconf-capability-change", "Not allowed to receive the NETCONF capability change notification");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "deny-netconf-capability-change", "Not allowed to receive the NETCONF capability change notification");
    sr_free_val(values);
    sr_free_tree(trees);

    /* test Event notification "replayComplete" from nc-notifications */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/nc-notifications:replayComplete"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* unsubscribe sysrepo-user1 */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /***** subscribe for notifications with sysrepo-user2 *****/
    subscribe_dummy_event_notif_callback(sessions[0], NULL, &subscription);

    /* test Event notification "link-discovered" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-discovered"
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "deny-test-module", "Deny everything not explicitly permitted in test-module.");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "deny-test-module", "Deny everything not explicitly permitted in test-module.");

    /* test Event notification "link-removed" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-removed"
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "deny-test-module", "Deny everything not explicitly permitted in test-module.");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "deny-test-module", "Deny everything not explicitly permitted in test-module.");

    /* test Event notification "status-change" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* test Event notification "halted" from turing-machine */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/turing-machine:halted"
    assert_int_equal(SR_ERR_OK, sr_new_val(EVENT_NOTIF_XPATH "/state", &values));
    values[0].type = SR_UINT16_T;
    values[0].data.uint16_val = 13;
    assert_int_equal(SR_ERR_OK, sr_new_tree("state", "turing-machine", &trees));
    trees[0].type = SR_UINT16_T;
    trees[0].data.uint16_val = 13;
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, values, 1, "deny-halted", "Not allowed to receive 'halted' notification from any module.");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, trees, 1, "deny-halted", "Not allowed to receive 'halted' notification from any module.");
    sr_free_val(values);
    sr_free_tree(trees);

    /* test Event notification "netconf-capability-change" from ietf-netconf-notifications */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/ietf-netconf-notifications:netconf-capability-change"
    assert_int_equal(SR_ERR_OK, sr_new_val(EVENT_NOTIF_XPATH "/changed-by/server", &values));
    values[0].type = SR_LEAF_EMPTY_T;
    assert_int_equal(SR_ERR_OK, sr_new_tree("changed-by", "turing-machine", &trees));
    trees[0].type = SR_CONTAINER_T;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(&trees[0], "server", NULL, &node));
    node->type = SR_LEAF_EMPTY_T;
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "deny-netconf-capability-change", "Not allowed to receive the NETCONF capability change notification");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "deny-netconf-capability-change", "Not allowed to receive the NETCONF capability change notification");
    sr_free_val(values);
    sr_free_tree(trees);

    /* test Event notification "replayComplete" from nc-notifications */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/nc-notifications:replayComplete"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* unsubscribe sysrepo-user2 */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /***** subscribe for notifications with sysrepo-user3 *****/
    subscribe_dummy_event_notif_callback(sessions[0], NULL, &subscription);

    /* test Event notification "link-discovered" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-discovered"
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "deny-link-discovered", "Not allowed to receive the link-discovered notification");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "deny-link-discovered", "Not allowed to receive the link-discovered notification");

    /* test Event notification "link-removed" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-removed"
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "deny-test-module", "Deny everything not explicitly permitted in test-module.");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "deny-test-module", "Deny everything not explicitly permitted in test-module.");

    /* test Event notification "status-change" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* test Event notification "halted" from turing-machine */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/turing-machine:halted"
    assert_int_equal(SR_ERR_OK, sr_new_val(EVENT_NOTIF_XPATH "/state", &values));
    values[0].type = SR_UINT16_T;
    values[0].data.uint16_val = 13;
    assert_int_equal(SR_ERR_OK, sr_new_tree("state", "turing-machine", &trees));
    trees[0].type = SR_UINT16_T;
    trees[0].data.uint16_val = 13;
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, values, 1, "deny-halted", "Not allowed to receive 'halted' notification from any module.");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, trees, 1, "deny-halted", "Not allowed to receive 'halted' notification from any module.");
    sr_free_val(values);
    sr_free_tree(trees);

    /* test Event notification "netconf-capability-change" from ietf-netconf-notifications */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/ietf-netconf-notifications:netconf-capability-change"
    assert_int_equal(SR_ERR_OK, sr_new_val(EVENT_NOTIF_XPATH "/changed-by/server", &values));
    values[0].type = SR_LEAF_EMPTY_T;
    assert_int_equal(SR_ERR_OK, sr_new_tree("changed-by", "turing-machine", &trees));
    trees[0].type = SR_CONTAINER_T;
    assert_int_equal(SR_ERR_OK, sr_node_add_child(&trees[0], "server", NULL, &node));
    node->type = SR_LEAF_EMPTY_T;
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "deny-netconf-capability-change", "Not allowed to receive the NETCONF capability change notification");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "deny-netconf-capability-change", "Not allowed to receive the NETCONF capability change notification");
    sr_free_val(values);
    sr_free_tree(trees);

    /* test Event notification "replayComplete" from nc-notifications */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/nc-notifications:replayComplete"
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);

    /* unsubscribe sysrepo-user3 */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

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
#if 0
            cmocka_unit_test_setup_teardown(nacm_cl_test_rpc_acl_with_empty_nacm_cfg, sysrepo_setup_with_empty_nacm_cfg, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(nacm_cl_test_rpc_acl, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(nacm_cl_test_rpc_acl_with_denied_exec_by_dflt, sysrepo_setup_with_denied_exec_by_dflt, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(nacm_cl_test_rpc_acl_with_ext_groups, sysrepo_setup_with_ext_groups, sysrepo_teardown),
#endif
            cmocka_unit_test_setup_teardown(nacm_cl_test_event_notif_acl_with_empty_nacm_cfg, sysrepo_setup_with_empty_nacm_cfg, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(nacm_cl_test_event_notif_acl, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(nacm_cl_test_event_notif_acl_with_denied_read_by_dflt, sysrepo_setup_with_denied_read_by_dflt, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(nacm_cl_test_event_notif_acl_with_ext_groups, sysrepo_setup_with_ext_groups, sysrepo_teardown),
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
    } else {
        assert_int_equal(SR_ERR_OK, sr_list_init(&log_history.logs));
    }

    watchdog_start(30000);
    int ret = cmocka_run_group_tests(tests, NULL, NULL);
    watchdog_stop();
    sr_list_cleanup(log_history.logs);
    return ret;
}
