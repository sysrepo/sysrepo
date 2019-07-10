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

#define NUM_OF_USERS  4

#define MAX_ATTEMPTS         10
#define DELAY_DURATION       10
#define DAEMON_WAIT_DURATION 500
#define NACM_RELOAD_DELAY    300

//#define DEBUG_MODE /* Note: in debug mode we are not able to read logs from sysrepo daemon! */

#define CHECK_EXEC_UNAUTHORIZED_ERROR(SESSION, XPATH, RULE, RULE_INFO) \
    do { \
        rc = sr_get_last_error(sessions[SESSION], &error_info); \
        assert_int_equal(rc, SR_ERR_UNAUTHORIZED); \
        assert_string_equal(XPATH, error_info->xpath); \
        if (strlen(RULE) && strlen(RULE_INFO)) { \
            assert_int_equal(SR_ERR_OK, \
                             sr_asprintf(&error_msg, "Access to execute the operation '%s' was blocked by the NACM rule '%s' "\
                                "(%s) for user 'sysrepo-user%d'.", XPATH, RULE, RULE_INFO, SESSION+1)); \
        } else if (strlen(RULE)) { \
            assert_int_equal(SR_ERR_OK, \
                             sr_asprintf(&error_msg, "Access to execute the operation '%s' was blocked by the NACM rule '%s' "\
                                "for user 'sysrepo-user%d'.", XPATH, RULE, SESSION+1)); \
        } else { \
            assert_int_equal(SR_ERR_OK, \
                             sr_asprintf(&error_msg, "Access to execute the operation '%s' was blocked by NACM "\
                                "for user 'sysrepo-user%d'.", XPATH, SESSION+1)); \
        } \
        assert_string_equal(error_msg, error_info->message); \
        free(error_msg); error_msg = NULL; \
    } while (0)

#define CHECK_NOTIF_UNAUTHORIZED_LOG(XPATH, RULE, RULE_INFO) \
    do { \
        escaped_xpath = escape(XPATH); \
        if (strlen(RULE) && strlen(RULE_INFO)) { \
            assert_int_equal(SR_ERR_OK, \
                             sr_asprintf(&regex, "\\[DBG\\] .* Delivery of the notification '%s' for subscription '[^']+' @ [0-9]+ " \
                                                 "was blocked by the NACM rule '%s' \\(%s\\).", escaped_xpath, RULE, RULE_INFO)); \
        } else if (strlen(RULE)) { \
            assert_int_equal(SR_ERR_OK, \
                             sr_asprintf(&regex, "\\[DBG\\] .* Delivery of the notification '%s' for subscription '[^']+' @ [0-9]+ " \
                                                 "was blocked by the NACM rule '%s'.", escaped_xpath, RULE)); \
        } else { \
            assert_int_equal(SR_ERR_OK, \
                             sr_asprintf(&regex, "\\[DBG\\] .* Delivery of the notification '%s' for subscription '[^']+' @ [0-9]+ " \
                                                 "was blocked by NACM.", escaped_xpath)); \
        }\
        verify_existence_of_log_msg(regex, true); \
        free(regex); regex = NULL; \
        free(escaped_xpath); escaped_xpath = NULL; \
    } while (0)

#define CHECK_WRITE_UNAUTHORIZED_ERROR(SESSION, ERR_CNT, ERR_IDX, XPATH, ACCESS_TYPE, RULE, RULE_INFO) \
    do { \
        rc = sr_get_last_errors(sessions[SESSION], &error_info, &error_cnt); \
        assert_int_equal(rc, SR_ERR_UNAUTHORIZED); \
        assert_int_equal(ERR_CNT, error_cnt); \
        assert_non_null(error_info[ERR_IDX].xpath); \
        assert_string_equal(XPATH, error_info[ERR_IDX].xpath); \
        if (strlen(RULE) && strlen(RULE_INFO)) { \
            assert_int_equal(SR_ERR_OK, \
                             sr_asprintf(&error_msg, "User 'sysrepo-user%d' was blocked from %s the node '%s' by the NACM rule '%s' (%s).", \
                                         SESSION+1, write_access_type_to_str(ACCESS_TYPE), XPATH, RULE, RULE_INFO)); \
        } else if (strlen(RULE)) { \
            assert_int_equal(SR_ERR_OK, \
                             sr_asprintf(&error_msg, "User 'sysrepo-user%d' was blocked from %s the node '%s' by the NACM rule '%s'.", \
                                         SESSION+1, write_access_type_to_str(ACCESS_TYPE), XPATH, RULE)); \
        } else { \
            assert_int_equal(SR_ERR_OK, \
                             sr_asprintf(&error_msg, "User 'sysrepo-user%d' was blocked from %s the node '%s' by NACM.", \
                                         SESSION+1, write_access_type_to_str(ACCESS_TYPE), XPATH)); \
        } \
        assert_non_null(error_info[ERR_IDX].message); \
        assert_string_equal(error_msg, error_info[ERR_IDX].message); \
        free(error_msg); error_msg = NULL; \
    } while (0)

#define RPC_DENIED(SESSION, XPATH, INPUT, INPUT_CNT, RULE, RULE_INFO) \
    do { \
        rc = sr_check_exec_permission(sessions[SESSION], XPATH, &permitted); \
        assert_int_equal(rc, SR_ERR_OK); \
        assert_false(permitted); \
        ++nacm_stats.denied_operations; \
        verify_nacm_stats(); \
        reset_cb_call_count(); \
        rc = sr_rpc_send(sessions[SESSION], XPATH, INPUT, INPUT_CNT, &output, &output_cnt); \
        assert_int_equal(rc, SR_ERR_UNAUTHORIZED); \
        verify_cb_call_count(false, 0); \
        ++nacm_stats.denied_operations; \
        verify_nacm_stats(); \
        CHECK_EXEC_UNAUTHORIZED_ERROR(SESSION, XPATH, RULE, RULE_INFO); \
    } while (0)

#define RPC_DENIED_TREE(SESSION, XPATH, INPUT, INPUT_CNT, RULE, RULE_INFO) \
    do { \
        rc = sr_check_exec_permission(sessions[SESSION], XPATH, &permitted); \
        assert_int_equal(rc, SR_ERR_OK); \
        assert_false(permitted); \
        ++nacm_stats.denied_operations; \
        verify_nacm_stats(); \
        reset_cb_call_count(); \
        rc = sr_rpc_send_tree(sessions[SESSION], XPATH, INPUT, INPUT_CNT, &output_tree, &output_cnt); \
        assert_int_equal(rc, SR_ERR_UNAUTHORIZED); \
        verify_cb_call_count(false, 0); \
        ++nacm_stats.denied_operations; \
        verify_nacm_stats(); \
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
        verify_cb_call_count(false, 1); \
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
        verify_cb_call_count(false, 1); \
    } while (0)

#define ACTION_DENIED(SESSION, XPATH, INPUT, INPUT_CNT, RULE, RULE_INFO) \
    do { \
        rc = sr_check_exec_permission(sessions[SESSION], XPATH, &permitted); \
        assert_int_equal(rc, SR_ERR_OK); \
        assert_false(permitted); \
        ++nacm_stats.denied_operations; \
        verify_nacm_stats(); \
        reset_cb_call_count(); \
        rc = sr_action_send(sessions[SESSION], XPATH, INPUT, INPUT_CNT, &output, &output_cnt); \
        assert_int_equal(rc, SR_ERR_UNAUTHORIZED); \
        verify_cb_call_count(false, 0); \
        ++nacm_stats.denied_operations; \
        verify_nacm_stats(); \
        CHECK_EXEC_UNAUTHORIZED_ERROR(SESSION, XPATH, RULE, RULE_INFO); \
    } while (0)

#define ACTION_DENIED_TREE(SESSION, XPATH, INPUT, INPUT_CNT, RULE, RULE_INFO) \
    do { \
        rc = sr_check_exec_permission(sessions[SESSION], XPATH, &permitted); \
        assert_int_equal(rc, SR_ERR_OK); \
        assert_false(permitted); \
        ++nacm_stats.denied_operations; \
        verify_nacm_stats(); \
        reset_cb_call_count(); \
        rc = sr_action_send_tree(sessions[SESSION], XPATH, INPUT, INPUT_CNT, &output_tree, &output_cnt); \
        assert_int_equal(rc, SR_ERR_UNAUTHORIZED); \
        verify_cb_call_count(false, 0); \
        ++nacm_stats.denied_operations; \
        verify_nacm_stats(); \
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
        verify_cb_call_count(false, 1); \
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
        verify_cb_call_count(false, 1); \
    } while (0)

#define EVENT_NOTIF_PERMITED(XPATH, VALUES, VALUE_CNT) \
    do { \
        reset_cb_call_count(); \
        rc = sr_event_notif_send(handler_session, XPATH, VALUES, VALUE_CNT, SR_EV_NOTIF_DEFAULT); \
        assert_int_equal(rc, SR_ERR_OK); \
        verify_cb_call_count(true, 1); \
        escaped_xpath = escape(XPATH); \
        assert_int_equal(SR_ERR_OK, \
                         sr_asprintf(&regex, "\\[DBG\\] .* Delivery of the notification '%s' for subscription '[^']+' @ [0-9]+ " \
                                             "was blocked by .*NACM.*", escaped_xpath)); \
        verify_existence_of_log_msg(regex, false); \
        free(escaped_xpath); escaped_xpath = NULL; \
        free(regex); regex = NULL; \
        clear_log_history(); \
    } while (0)

#define EVENT_NOTIF_PERMITED_TREE(XPATH, TREES, TREE_CNT) \
    do { \
        reset_cb_call_count(); \
        rc = sr_event_notif_send_tree(handler_session, XPATH, TREES, TREE_CNT, SR_EV_NOTIF_DEFAULT); \
        assert_int_equal(rc, SR_ERR_OK); \
        verify_cb_call_count(true, 1); \
        escaped_xpath = escape(XPATH); \
        assert_int_equal(SR_ERR_OK, \
                         sr_asprintf(&regex, "\\[DBG\\] .* Delivery of the notification '%s' for subscription '[^']+' @ [0-9]+ " \
                                             "was blocked by .*NACM.*", escaped_xpath)); \
        verify_existence_of_log_msg(regex, false); \
        free(escaped_xpath); escaped_xpath = NULL; \
        free(regex); regex = NULL; \
        clear_log_history(); \
    } while (0)

#define EVENT_NOTIF_DENIED(XPATH, VALUES, VALUE_CNT, RULE, RULE_INFO) \
    do { \
        reset_cb_call_count(); \
        rc = sr_event_notif_send(handler_session, XPATH, VALUES, VALUE_CNT, SR_EV_NOTIF_DEFAULT); \
        assert_int_equal(rc, SR_ERR_OK); \
        verify_cb_call_count(true, 0); \
        CHECK_NOTIF_UNAUTHORIZED_LOG(XPATH, RULE, RULE_INFO); \
        clear_log_history(); \
        ++nacm_stats.denied_notifications; \
        verify_nacm_stats(); \
    } while (0)

#define EVENT_NOTIF_DENIED_TREE(XPATH, TREES, TREE_CNT, RULE, RULE_INFO) \
    do { \
        reset_cb_call_count(); \
        rc = sr_event_notif_send_tree(handler_session, XPATH, TREES, TREE_CNT, SR_EV_NOTIF_DEFAULT); \
        assert_int_equal(rc, SR_ERR_OK); \
        verify_cb_call_count(true, 0); \
        CHECK_NOTIF_UNAUTHORIZED_LOG(XPATH, RULE, RULE_INFO); \
        clear_log_history(); \
        ++nacm_stats.denied_notifications; \
        verify_nacm_stats(); \
    } while (0)

#define COMMIT_PERMITTED(SESSION) \
    do { \
        rc = sr_commit(sessions[SESSION]); \
        assert_int_equal(rc, SR_ERR_OK); \
        revert_changes(); \
    } while(0);

#define COMMIT_DENIED(SESSION, NODE_XPATH, ACCESS_TYPE, RULE, RULE_INFO) \
    do { \
        rc = sr_commit(sessions[SESSION]); \
        assert_int_equal(rc, SR_ERR_UNAUTHORIZED); \
        CHECK_WRITE_UNAUTHORIZED_ERROR(SESSION, 1, 0, NODE_XPATH, ACCESS_TYPE, RULE, RULE_INFO); \
        rc = sr_discard_changes(sessions[SESSION]); \
        assert_int_equal(SR_ERR_OK, rc); \
        ++nacm_stats.denied_data_writes; \
        verify_nacm_stats(); \
    } while(0);

#define COMMIT_DENIED2(SESSION, NODE1_XPATH, ACCESS1_TYPE, RULE1, RULE1_INFO,\
                       NODE2_XPATH, ACCESS2_TYPE, RULE2, RULE2_INFO) \
    do { \
        rc = sr_commit(sessions[SESSION]); \
        assert_int_equal(rc, SR_ERR_UNAUTHORIZED); \
        CHECK_WRITE_UNAUTHORIZED_ERROR(SESSION, 2, 0, NODE1_XPATH, ACCESS1_TYPE, RULE1, RULE1_INFO); \
        CHECK_WRITE_UNAUTHORIZED_ERROR(SESSION, 2, 1, NODE2_XPATH, ACCESS2_TYPE, RULE2, RULE2_INFO); \
        rc = sr_discard_changes(sessions[SESSION]); \
        assert_int_equal(SR_ERR_OK, rc); \
        ++nacm_stats.denied_data_writes; \
        verify_nacm_stats(); \
    } while(0);

#define COMMIT_DENIED3(SESSION, NODE1_XPATH, ACCESS1_TYPE, RULE1, RULE1_INFO,\
                       NODE2_XPATH, ACCESS2_TYPE, RULE2, RULE2_INFO, \
                       NODE3_XPATH, ACCESS3_TYPE, RULE3, RULE3_INFO) \
    do { \
        rc = sr_commit(sessions[SESSION]); \
        assert_int_equal(rc, SR_ERR_UNAUTHORIZED); \
        CHECK_WRITE_UNAUTHORIZED_ERROR(SESSION, 3, 0, NODE1_XPATH, ACCESS1_TYPE, RULE1, RULE1_INFO); \
        CHECK_WRITE_UNAUTHORIZED_ERROR(SESSION, 3, 1, NODE2_XPATH, ACCESS2_TYPE, RULE2, RULE2_INFO); \
        CHECK_WRITE_UNAUTHORIZED_ERROR(SESSION, 3, 2, NODE3_XPATH, ACCESS3_TYPE, RULE3, RULE3_INFO); \
        rc = sr_discard_changes(sessions[SESSION]); \
        assert_int_equal(SR_ERR_OK, rc); \
        ++nacm_stats.denied_data_writes; \
        verify_nacm_stats(); \
    } while(0);

#define COMMIT_DENIED_N(SESSION, ERR_CNT) \
    do { \
        rc = sr_commit(sessions[SESSION]); \
        assert_int_equal(rc, SR_ERR_UNAUTHORIZED); \
        rc = sr_get_last_errors(sessions[SESSION], &error_info, &error_cnt); \
        assert_int_equal(rc, SR_ERR_UNAUTHORIZED); \
        assert_int_equal(ERR_CNT, error_cnt); \
        rc = sr_discard_changes(sessions[SESSION]); \
        assert_int_equal(SR_ERR_OK, rc); \
        ++nacm_stats.denied_data_writes; \
        verify_nacm_stats(); \
    } while(0);

typedef sr_session_ctx_t *user_sessions_t[NUM_OF_USERS];

/**
  * @brief Recent log history.
  */
typedef struct log_history_s {
    pthread_mutex_t lock;
    sr_list_t *logs; /**< items are of type (char *) */
    bool running;
} log_history_t;

/**
 * @brief NACM statistics.
 */
typedef struct nacm_stats_s {
    uint32_t denied_operations;
    uint32_t denied_data_writes;
    uint32_t denied_notifications;
    sr_session_ctx_t *session; /**< Session used to get the current NACM statistics of the daemon. */
} nacm_stats_t;

static bool satisfied_requirements = true;  /**< Indices if the test can be actually run with the current system configuration */
static bool daemon_run_before_test = false; /**< Indices if the daemon was running before executing the test. */
static pid_t daemon_pid = -1; /* PID of the sysrepo daemon (child of this process) */
static int daemon_stderr = -1;    /* read-end of the daemon's stderr */
static log_history_t log_history = { .lock = PTHREAD_MUTEX_INITIALIZER, .logs = NULL, .running = false }; /* recent log history */
static pthread_t stderr_reader = {0}; /* log-reader thread's control structure */
static int cb_call_count; /* how many times a callback was called */
pthread_mutex_t cb_call_count_lock = PTHREAD_MUTEX_INITIALIZER; /* protecting cb_call_count */
static nacm_stats_t nacm_stats = {0};


const char *
write_access_type_to_str(nacm_access_flag_t access_type)
{
    switch (access_type) {
        case NACM_ACCESS_CREATE:
            return "creating";
        case NACM_ACCESS_UPDATE:
            return "changing the value of";
        case NACM_ACCESS_DELETE:
            return "deleting";
        default:
            return "<not write-like access type>";
    }
}

static void
wait_ms(long int ms)
{
    struct timespec ts = { 0 };
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

static void
inc_cb_call_count()
{
    pthread_mutex_lock(&cb_call_count_lock);
    ++cb_call_count;
    pthread_mutex_unlock(&cb_call_count_lock);
}

static void
verify_cb_call_count(bool async_cb, int exp_count)
{
    int count = 0, attempt = 0;

    if (async_cb && 0 == exp_count) {
        wait_ms(4*DELAY_DURATION);
        /* if the callback hasn't been called within this delay, then we assume that it will never be. */
    }

    do {
        pthread_mutex_lock(&cb_call_count_lock);
        count = cb_call_count;
        pthread_mutex_unlock(&cb_call_count_lock);
        ++attempt;
        if (async_cb && count < exp_count) {
            wait_ms(DELAY_DURATION);
        }
    } while (async_cb && count < exp_count && attempt < MAX_ATTEMPTS);

    assert_int_equal_bt(exp_count, count);
}

static void
reset_cb_call_count()
{
    pthread_mutex_lock(&cb_call_count_lock);
    cb_call_count = 0;
    pthread_mutex_unlock(&cb_call_count_lock);
}

static void
verify_nacm_stats()
{
    int rc = SR_ERR_OK;
    sr_val_t *value = NULL;

    /* check the number of denied RPCs */
    rc = sr_get_item(nacm_stats.session, "/ietf-netconf-acm:nacm/denied-operations", &value);
    assert_int_equal_bt(SR_ERR_OK, rc);
    assert_non_null_bt(value);
    assert_int_equal_bt(SR_UINT32_T, value->type);
    assert_int_equal_bt(nacm_stats.denied_operations, value->data.uint32_val);
    sr_free_val(value);
    value = NULL;

    /* check the number of denied Event notifications */
    rc = sr_get_item(nacm_stats.session, "/ietf-netconf-acm:nacm/denied-notifications", &value);
    assert_int_equal_bt(SR_ERR_OK, rc);
    assert_non_null_bt(value);
    assert_int_equal_bt(SR_UINT32_T, value->type);
    assert_int_equal_bt(nacm_stats.denied_notifications, value->data.uint32_val);
    sr_free_val(value);
    value = NULL;

    /* check the number of denied operations with write effect */
    rc = sr_get_item(nacm_stats.session, "/ietf-netconf-acm:nacm/denied-data-writes", &value);
    assert_int_equal_bt(SR_ERR_OK, rc);
    assert_non_null_bt(value);
    assert_int_equal_bt(SR_UINT32_T, value->type);
    assert_int_equal_bt(nacm_stats.denied_data_writes, value->data.uint32_val);
    sr_free_val(value);
    value = NULL;

}

#ifndef DEBUG_MODE
static void
daemon_kill(bool last_attempt)
{
    int pidfile = 0;
    char *line = NULL;
    size_t len = 0;
    int pid = -1, ret = 0;

    /* read PID of the daemon from sysrepo PID file */
    pidfile = open(SR_DAEMON_PID_FILE, O_RDONLY);
    assert_int_not_equal_bt(-1, pidfile);
    if (readline(pidfile, &line, &len)) {
        pid = atoi(line);
    }
    free(line);
    assert_int_equal_bt(0, close(pidfile));

    if (-1 != pid) {
        /* send SIGTERM/SIGKILL to the daemon process */
        SR_LOG_DBG("Sending %s signal to PID=%d.", (last_attempt ? "SIGKILL" : "SIGTERM"), pid);
        ret = kill(pid, last_attempt ? SIGKILL : SIGTERM);
        assert_int_not_equal_bt(-1, ret);

        /* wait for real termination */
        while (-1 != access(SR_DAEMON_PID_FILE, F_OK)) {
            usleep(100);
        }
    }
}
#endif

static void *
daemon_log_reader(void *arg)
{
    (void)arg;
    char *line = NULL, *msg = NULL;
    size_t buflen = 0, len;
    bool running = false;

    do {
        pthread_mutex_lock(&log_history.lock);
        running = log_history.running;
        pthread_mutex_unlock(&log_history.lock);
        if (!running) {
            wait_ms(DELAY_DURATION);
        }
    } while (!running);
    assert_true_bt(daemon_stderr >= 0);

    while (running) {
        pthread_mutex_lock(&log_history.lock);
        while ((len = readline(daemon_stderr, &line, &buflen))) {
            msg = strdup(line);
            assert_non_null_bt(msg);
            if (msg[len - 1] == '\n') {
                msg[len - 1] = '\0';
            }
            SR_LOG_DBG("DAEMON: %s", msg);
            assert_int_equal_bt(SR_ERR_OK, sr_list_add(log_history.logs, msg));
        }
        running = log_history.running;
        pthread_mutex_unlock(&log_history.lock);
        if (running) {
            wait_ms(DELAY_DURATION);
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
    while (attempt <= MAX_ATTEMPTS) {
        /* connect to sysrepo, force daemon connection */
        rc = sr_connect("nacm_cl_test", SR_CONN_DAEMON_REQUIRED, &conn);
        sr_disconnect(conn);
        conn = NULL;
        assert_true_bt(SR_ERR_OK == rc || SR_ERR_DISCONNECT == rc);

        /* kill the daemon if it was running */
        if (SR_ERR_OK == rc) {
            if (1 == attempt) {
                daemon_run_before_test = true;
            }
            daemon_kill(attempt == MAX_ATTEMPTS);
            /* wait for the daemon to terminate */
            wait_ms(DAEMON_WAIT_DURATION);
        } else {
            if (1 == attempt) {
                daemon_run_before_test = false;
            }
            break;
        }
        ++attempt;
    }

    /* initial datastore content */
    createDataTreeTestModule();
    createDataTreeExampleModule();
    createDataTreeIETFinterfacesModule();

    /* initial NACM statistics */
    memset(&nacm_stats, 0, sizeof nacm_stats);

    /* start sysrepo in the daemon debug mode as a child process */
    pthread_create(&stderr_reader, NULL, daemon_log_reader, NULL);
    daemon_pid = sr_popen("../src/sysrepod -l4 -d", NULL, NULL, &daemon_stderr);
    SR_LOG_INF("Started Sysrepo daemon with PID=%d", daemon_pid);
    assert_int_not_equal_bt(-1, daemon_pid);
    assert_true_bt(daemon_stderr >= 0);

    /* start log reader */
    flags = fcntl(daemon_stderr, F_GETFL, 0);
    fcntl(daemon_stderr, F_SETFL, flags | O_NONBLOCK);
    pthread_mutex_lock(&log_history.lock);
    log_history.running = true;
    pthread_mutex_unlock(&log_history.lock);

    /* wait for the daemon to start */
    wait_ms(DAEMON_WAIT_DURATION);
#endif
    rc = sr_connect("nacm_cl_test", SR_CONN_DAEMON_REQUIRED, &conn);
    assert_int_equal_bt(rc, SR_ERR_OK);
    assert_non_null_bt(conn_p);
    *conn_p = conn;

    /* start a session that will be used to obtain the NACM statistics */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_ENABLE_NACM, &nacm_stats.session);
    assert_int_equal_bt(rc, SR_ERR_OK);
}

static void
revert_changes()
{
    createDataTreeTestModule();
    createDataTreeExampleModule();
    createDataTreeIETFinterfacesModule();
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

static char *
escape(const char *regex)
{
    assert_non_null_bt((void *)regex);
    static char *special_chars = ".^$*+?()[{\\|^-]";
    char *escaped = NULL;
    size_t new_size = strlen(regex);
    int pos = 0;

    for (size_t i = 0; i < strlen(regex); ++i) {
        if (strchr(special_chars, regex[i])) {
            new_size++;
        }
    }

    escaped = calloc(new_size+1, sizeof *escaped);
    assert_non_null_bt(escaped);

    for (size_t i = 0; i < strlen(regex); ++i) {
        if (strchr(special_chars, regex[i])) {
            escaped[pos] = '\\';
            ++pos;
        }
        escaped[pos++] = regex[i];
    }

    escaped[pos] = '\0';
    return escaped;
}

static void
verify_existence_of_log_msg(const char *msg_re, bool should_exist)
{
#ifdef HAVE_REGEX_H
    bool exists = false;
    int attempt = 0;
    size_t already_checked = 0;

    if (!should_exist) {
        wait_ms(4*DELAY_DURATION);
        /* if the message hasn't been logged in within this delay, then we assume that it will never be. */
    }

    do {
        pthread_mutex_lock(&log_history.lock);
        for (; !exists && (already_checked < log_history.logs->count); ++already_checked) {
            char *message = (char *)log_history.logs->data[already_checked];
            regex_t re;
            /* Compile regular expression */
            assert_int_equal_bt(0, regcomp(&re, msg_re, REG_NOSUB | REG_EXTENDED));
            if (0 == regexec(&re, message, 0, NULL, 0)) {
                exists = true;
            }
#if 0
            printf("REGEX TEST BEGIN -------------\n");
            printf("Regex: %s\n", msg_re);
            printf("Message: %s\n", message);
            printf("Matches: %s\n", exists ? "YES" : "NO");
            printf("REGEX TEST END -------------\n");
#endif
            regfree(&re);
        }
        pthread_mutex_unlock(&log_history.lock);
        ++attempt;
        if (should_exist && !exists) {
            /* log reader may need more time to sync */
            wait_ms(DELAY_DURATION);
        }
    } while (should_exist && !exists && attempt < MAX_ATTEMPTS);

    assert_true_bt(should_exist == exists);
#endif
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
    /*    -> RPC: */
    add_nacm_rule(nacm_config, "acl1", "deny-activate-software-image", "test-module", NACM_RULE_RPC,
            "activate-software-image", "exec", "deny", "Not allowed to run activate-software-image");
    add_nacm_rule(nacm_config, "acl1", "rule-with-no-effect", "ietf-netconf", NACM_RULE_RPC,
            "close-session", "*", "deny", "close-session NETCONF operation cannot be effectively denied");
    /*    -> notification: */
    add_nacm_rule(nacm_config, "acl1", "deny-link-discovered", "test-module", NACM_RULE_NOTIF,
            "link-discovered", "read", "deny", "Not allowed to receive the link-discovered notification");
    /*    -> data, test-module: */
    add_nacm_rule(nacm_config, "acl1", "allow-to-modify-i8", "test-module", NACM_RULE_DATA,
            "/test-module:main/i8", "update", "permit", "Allow to modify 8-bit signed integer in the main container");
    assert_non_null(ly_ctx_load_module(nacm_config->ly_ctx, "test-module", NULL));
    add_nacm_rule(nacm_config, "acl1", "permit-low-numbers", "test-module", NACM_RULE_DATA,
            "/test-module:main/numbers[.<10]", "create delete", "permit", "Allow to create/delete low numbers.");
    add_nacm_rule(nacm_config, "acl1", "deny-high-numbers", "test-module", NACM_RULE_DATA,
            "/test-module:main/numbers[.>10]", "create delete", "deny", "Do not allow to create/delete low numbers.");
    add_nacm_rule(nacm_config, "acl1", "allow-reordering", "test-module", NACM_RULE_DATA,
            "/test-module:ordered-numbers", "update", "permit", "Allow to re-order numbers.");
    add_nacm_rule(nacm_config, "acl1", "allow-presence-container-with-content", "test-module", NACM_RULE_DATA,
            "/test-module:presence-container", "*", "permit", "Allow to read/edit presence container from test-module.");
    /*    -> data, example-module: */
    add_nacm_rule(nacm_config, "acl1", "deny-specific-list-item", "example-module", NACM_RULE_DATA,
            "/example-module:container/list[key1='new-item-key1'][key2='new-item-key2']", "create", "deny",
            "Not allowed to create this specific list item.");
    assert_non_null(ly_ctx_load_module(nacm_config->ly_ctx, "example-module", NULL));
    add_nacm_rule(nacm_config, "acl1", "permit-specific-list-item", "example-module", NACM_RULE_DATA,
            "/example-module:container/list[key1='new-item2-key1'][key2='new-item2-key2']", "create", "permit",
            "Allowed to create this specific list item.");
    /*    -> data, ietf-interfaces: */
    add_nacm_rule(nacm_config, "acl1", "deny-interface-status-change", "ietf-interfaces", NACM_RULE_DATA,
            "/ietf-interfaces:interfaces/interface/enabled", "update", "deny", "Not allowed to change status of interface");
    assert_non_null(ly_ctx_load_module(nacm_config->ly_ctx, "ietf-interfaces", NULL));
    add_nacm_rule(nacm_config, "acl1", "allow-new-interfaces", "ietf-interfaces", NACM_RULE_DATA,
            "/ietf-interfaces:interfaces/interface", "create", "permit", "Allowed to create new interface");
    /*  -> acl2: */
    /*    -> RPC: */
    add_nacm_rule(nacm_config, "acl2", "permit-kill-session", "ietf-netconf", NACM_RULE_RPC,
            "kill-session", "exec", "permit", "Permit execution of the kill-session NETCONF operation.");
    add_nacm_rule(nacm_config, "acl2", "deny-initialize", "*", NACM_RULE_RPC,
            "initialize", "*", "deny", "Not allowed to touch RPC 'initialize' in any module.");
    /*    -> notification: */
    add_nacm_rule(nacm_config, "acl2", "deny-halted", "*", NACM_RULE_NOTIF,
            "halted", "*", "deny", "Not allowed to receive 'halted' notification from any module.");
    /*    -> data, test-module: */
    add_nacm_rule(nacm_config, "acl2", "disallow-to-modify-i8", "test-module", NACM_RULE_DATA,
            "/test-module:main/i8", "update", "deny", "Disallow modification of 8-bit signed integer in the main container");
    add_nacm_rule(nacm_config, "acl2", "permit-high-numbers", "test-module", NACM_RULE_DATA,
            "/test-module:main/numbers[.>10]", "create delete", "permit", "Allow to create/delete high numbers.");
    add_nacm_rule(nacm_config, "acl2", "deny-low-numbers", "test-module", NACM_RULE_DATA,
            "/test-module:main/numbers[.<10]", "create delete", "deny", "Do not allow to create/delete low numbers.");
    add_nacm_rule(nacm_config, "acl2", "deny-everything-but-reordering", "test-module", NACM_RULE_DATA,
            "/test-module:ordered-numbers", "create delete read", "deny", "Disallow any operation with ordered-numbers but re-ordering (update).");
    add_nacm_rule(nacm_config, "acl2", "deny-grandchild1-leaf", "test-module", NACM_RULE_DATA,
            "/test-module:presence-container/child1/grandchild1/grandchild1-leaf", "create update delete", "deny",
            "Do not allow to edit grandchild1-leaf.");
    add_nacm_rule(nacm_config, "acl2", "deny-child2", "test-module", NACM_RULE_DATA,
            "/test-module:presence-container/child2", "create", "deny", "Do not allow to create child2.");
    /*    -> data, example-module: */
    add_nacm_rule(nacm_config, "acl2", "allow-list-item-key1", "example-module", NACM_RULE_DATA,
            "/example-module:container/list/key1", "*", "permit",
            "Allowed to edit key1 from list item.");
    add_nacm_rule(nacm_config, "acl2", "allow-list-item-key2", "example-module", NACM_RULE_DATA,
            "/example-module:container/list/key2", "*", "permit",
            "Allowed to edit key2 from list item.");
    add_nacm_rule(nacm_config, "acl2", "allow-list-item-leaf", "example-module", NACM_RULE_DATA,
            "/example-module:container/list/leaf", "create", "permit",
            "Allowed to create (not delete) leaf from list item.");
    add_nacm_rule(nacm_config, "acl2", "disallow-to-delete-list-item-leaf", "example-module", NACM_RULE_DATA,
            "/example-module:container/list/leaf", "delete", "deny",
            "Do not allowed to delete leaf from list item.");
    /*    -> data, ietf-interfaces: */
    add_nacm_rule(nacm_config, "acl2", "deny-removing-interfaces", "ietf-interfaces", NACM_RULE_DATA,
            "/ietf-interfaces:interfaces/interface", "delete", "deny", "Not allowed to remove existing interface");
    add_nacm_rule(nacm_config, "acl2", "allow-enabling-interfaces", "ietf-interfaces", NACM_RULE_DATA,
            "/ietf-interfaces:interfaces/interface/enabled", "update", "permit", "Allow to enable interface");
    /*  -> acl3: */
    /*    -> RPC: */
    add_nacm_rule(nacm_config, "acl3", "permit-unload", "test-module", NACM_RULE_RPC,
            "unload", "exec", "permit", "Permit action unload");
    /*    -> notification: */
    add_nacm_rule(nacm_config, "acl3", "permit-status-change", "test-module", NACM_RULE_NOTIF,
            "status-change", "*", "permit", "Permit notification 'status-change'.");
    add_nacm_rule(nacm_config, "acl3", "deny-netconf-capability-change", "ietf-netconf-notifications", NACM_RULE_NOTIF,
            "netconf-capability-change", "read", "deny", "Not allowed to receive the NETCONF capability change notification");
    /*    -> data, test-module: */
    add_nacm_rule(nacm_config, "acl3", "permit-all-numbers", "test-module", NACM_RULE_DATA,
            "/test-module:main/numbers", "create delete", "permit", "Allow to create/delete all numbers.");
    add_nacm_rule(nacm_config, "acl3", "allow-presence-container", "test-module", NACM_RULE_DATA,
            "/test-module:presence-container", "*", "permit", "Allow to edit presence container from test-module.");
    /*    -> data, example-module: */
    add_nacm_rule(nacm_config, "acl3", "allow-list-items", "example-module", NACM_RULE_DATA,
            "/example-module:container/list", "create delete", "permit", "Allowed to create/delete list items.");
    /*    -> data, ietf-interfaces: */
    add_nacm_rule(nacm_config, "acl3", "allow-new-interfaces", "ietf-interfaces", NACM_RULE_DATA,
            "/ietf-interfaces:interfaces/interface", "create", "permit", "Allowed to create new interface");
    /*    -> any, test-module: */
    add_nacm_rule(nacm_config, "acl3", "deny-test-module", "test-module", NACM_RULE_NOTSET,
            NULL, "*", "deny", "Deny everything not explicitly permitted in test-module.");
}

static void
copy_config_nacm_config(test_nacm_cfg_t *nacm_config)
{
    /* groups & users */
    add_nacm_user(nacm_config, "sysrepo-user1", "group1");
    /* access lists */
    add_nacm_rule_list(nacm_config, "acl1", "group1", NULL);
    /*  -> acl1: */
    add_nacm_rule(nacm_config, "acl1", "deny-boolean", "test-module", NACM_RULE_DATA,
            XP_TEST_MODULE_BOOL, "read", "deny", "Forbid reading the 'boolean' leaf.");
    add_nacm_rule(nacm_config, "acl1", "deny-high-numbers", "test-module", NACM_RULE_DATA,
            "/test-module:main/numbers[.>10]", "read", "deny", "Forbid reading 'numbers' higher than 10.");
    assert_non_null(ly_ctx_load_module(nacm_config->ly_ctx, "test-module", NULL));
    add_nacm_rule(nacm_config, "acl1", "deny-read-interface-status", "*", NACM_RULE_DATA,
            "/ietf-interfaces:interfaces/interface/enabled", "read", "deny", "Forbid reading interface 'status'.");
    assert_non_null(ly_ctx_load_module(nacm_config->ly_ctx, "ietf-interfaces", NULL));
    add_nacm_rule(nacm_config, "acl1", "deny-read-acm", "ietf-netconf-acm", NACM_RULE_DATA,
            "/ietf-netconf-acm:*//.", "read", "deny", "Forbid reading NACM configuration.");
}

static int
sysrepo_setup_for_copy_config(void **state)
{
    sr_conn_ctx_t *conn = NULL;
    test_nacm_cfg_t *nacm_config = NULL;

    /* NACM startup config */
    new_nacm_config(&nacm_config);
    set_nacm_write_dflt(nacm_config, "permit");
    copy_config_nacm_config(nacm_config);
    save_nacm_config(nacm_config);
    delete_nacm_config(nacm_config);

    start_sysrepo_daemon(&conn);

    *state = (void*)conn;
    return 0;
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
sysrepo_setup_with_permitted_write_by_dflt(void **state)
{
    sr_conn_ctx_t *conn = NULL;
    test_nacm_cfg_t *nacm_config = NULL;

    /* initial datastore content */
    createDataTreeTestModule();
    createDataTreeExampleModule();
    createDataTreeIETFinterfacesModule();

    /* NACM startup config */
    new_nacm_config(&nacm_config);
    set_nacm_write_dflt(nacm_config, "permit");
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
#ifndef DEBUG_MODE
    int ret = 0, status = 0;
#endif
    int rc = SR_ERR_OK;
    sr_conn_ctx_t *conn = *state;
#ifndef DEBUG_MODE
    test_nacm_cfg_t *nacm_config = NULL;

    /* leave non-intrusive NACM startup config */
    new_nacm_config(&nacm_config);
    set_nacm_write_dflt(nacm_config, "permit");
    save_nacm_config(nacm_config);
    delete_nacm_config(nacm_config);
#endif

    if (!satisfied_requirements) {
        return 0;
    }

    /* stop the session used to get the NACM statistics */
    rc = sr_session_stop(nacm_stats.session);
    assert_int_equal(rc, SR_ERR_OK);

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
    assert_non_null_bt(conn);
    if (NULL != handler_session) {
        rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, handler_session);
        assert_int_equal_bt(rc, SR_ERR_OK);
    }
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        char *username = NULL;
        assert_int_equal_bt(SR_ERR_OK, sr_asprintf(&username, "sysrepo-user%d", i+1));
        rc = sr_session_start_user(conn, username, SR_DS_STARTUP,
                i == NUM_OF_USERS-1 ? SR_SESS_DEFAULT : SR_SESS_ENABLE_NACM, (*sessions)+i);
        assert_int_equal_bt(rc, SR_ERR_OK);
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
    assert_int_equal_bt(rc, SR_ERR_OK);
    rc = sr_rpc_subscribe(handler_session, "/turing-machine:initialize", dummy_rpc_cb, private_ctx,
            SR_SUBSCR_CTX_REUSE, subscription);
    assert_int_equal_bt(rc, SR_ERR_OK);

    /* subscribe for Actions with dummy callback */
    rc = sr_action_subscribe(handler_session, "/test-module:kernel-modules/kernel-module/unload",
            dummy_rpc_cb, private_ctx, SR_SUBSCR_CTX_REUSE, subscription);
    assert_int_equal_bt(rc, SR_ERR_OK);
    rc = sr_action_subscribe(handler_session, "/test-module:kernel-modules/kernel-module/load",
            dummy_rpc_cb, private_ctx, SR_SUBSCR_CTX_REUSE, subscription);
    assert_int_equal_bt(rc, SR_ERR_OK);
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
    assert_int_equal_bt(rc, SR_ERR_OK);
    rc = sr_event_notif_subscribe(user_session, "/test-module:link-removed",
            dummy_event_notif_cb, private_ctx, SR_SUBSCR_CTX_REUSE, subscription);
    assert_int_equal_bt(rc, SR_ERR_OK);
    rc = sr_event_notif_subscribe(user_session, "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change",
            dummy_event_notif_cb, private_ctx, SR_SUBSCR_CTX_REUSE, subscription);
    assert_int_equal_bt(rc, SR_ERR_OK);
    rc = sr_event_notif_subscribe(user_session, "/turing-machine:halted",
            dummy_event_notif_cb, private_ctx, SR_SUBSCR_CTX_REUSE, subscription);
    assert_int_equal_bt(rc, SR_ERR_OK);
    rc = sr_event_notif_subscribe(user_session, "/ietf-netconf-notifications:netconf-capability-change",
            dummy_event_notif_cb, private_ctx, SR_SUBSCR_CTX_REUSE, subscription);
    assert_int_equal_bt(rc, SR_ERR_OK);

}

static void
nacm_cl_test_rpc_nacm_with_empty_nacm_cfg(void **state)
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
    /*  -> sysrepo-user4 */
    RPC_PERMITED(3, RPC_XPATH, NULL, 0, 2);
    RPC_PERMITED_TREE(3, RPC_XPATH, NULL, 0, 2);

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
    /*  -> sysrepo-user4 */
    RPC_PERMITED(3, RPC_XPATH, NULL, 0, 0);
    RPC_PERMITED_TREE(3, RPC_XPATH, NULL, 0, 0);

    /* test Action "unload" from test-model */
#undef ACTION_XPATH
#define ACTION_XPATH "/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/unload"
    /*  -> sysrepo-user1 */
    ACTION_PERMITED(0, ACTION_XPATH, NULL, 0, 0);
    ACTION_PERMITED_TREE(0, ACTION_XPATH, NULL, 0, 0);
    /*  -> sysrepo-user2 */
    ACTION_PERMITED(1, ACTION_XPATH, NULL, 0, 0);
    ACTION_PERMITED_TREE(1, ACTION_XPATH, NULL, 0, 0);
    /*  -> sysrepo-user3 */
    ACTION_PERMITED(2, ACTION_XPATH, NULL, 0, 0);
    ACTION_PERMITED_TREE(2, ACTION_XPATH, NULL, 0, 0);
    /*  -> sysrepo-user4 */
    ACTION_PERMITED(3, ACTION_XPATH, NULL, 0, 0);
    ACTION_PERMITED_TREE(3, ACTION_XPATH, NULL, 0, 0);

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
    ACTION_PERMITED(0, ACTION_XPATH, input, 1, 0);
    ACTION_PERMITED_TREE(0, ACTION_XPATH, input_tree, 1, 0);
    /*  -> sysrepo-user2 */
    ACTION_PERMITED(1, ACTION_XPATH, input, 1, 0);
    ACTION_PERMITED_TREE(1, ACTION_XPATH, input_tree, 1, 0);
    /*  -> sysrepo-user3 */
    ACTION_PERMITED(2, ACTION_XPATH, input, 1, 0);
    ACTION_PERMITED_TREE(2, ACTION_XPATH, input_tree, 1, 0);
    /*  -> sysrepo-user4 */
    ACTION_PERMITED(3, ACTION_XPATH, input, 1, 0);
    ACTION_PERMITED_TREE(3, ACTION_XPATH, input_tree, 1, 0);
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
nacm_cl_test_rpc_nacm(void **state)
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
    char *error_msg = NULL;

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
    /*  -> sysrepo-user4 */
    RPC_PERMITED(3, RPC_XPATH, NULL, 0, 2);
    RPC_PERMITED_TREE(3, RPC_XPATH, NULL, 0, 2);

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
    /*  -> sysrepo-user4 */
    RPC_PERMITED(3, RPC_XPATH, NULL, 0, 0);
    RPC_PERMITED_TREE(3, RPC_XPATH, NULL, 0, 0);

    /* test Action "unload" from test-model */
#undef ACTION_XPATH
#define ACTION_XPATH "/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/unload"
    /*  -> sysrepo-user1 */
    ACTION_PERMITED(0, ACTION_XPATH, NULL, 0, 0);
    ACTION_PERMITED_TREE(0, ACTION_XPATH, NULL, 0, 0);
    /*  -> sysrepo-user2 */
    ACTION_PERMITED(1, ACTION_XPATH, NULL, 0, 0);
    ACTION_PERMITED_TREE(1, ACTION_XPATH, NULL, 0, 0);
    /*  -> sysrepo-user3 */
    ACTION_PERMITED(2, ACTION_XPATH, NULL, 0, 0);
    ACTION_PERMITED_TREE(2, ACTION_XPATH, NULL, 0, 0);
    /*  -> sysrepo-user4 */
    ACTION_PERMITED(3, ACTION_XPATH, NULL, 0, 0);
    ACTION_PERMITED_TREE(3, ACTION_XPATH, NULL, 0, 0);

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
    ACTION_PERMITED(0, ACTION_XPATH, input, 1, 0);
    ACTION_PERMITED_TREE(0, ACTION_XPATH, input_tree, 1, 0);
    /*  -> sysrepo-user2 */
    ACTION_PERMITED(1, ACTION_XPATH, input, 1, 0);
    ACTION_PERMITED_TREE(1, ACTION_XPATH, input_tree, 1, 0);
    /*  -> sysrepo-user3 */
    ACTION_DENIED(2, ACTION_XPATH, input, 1, "deny-test-module", "Deny everything not explicitly permitted in test-module.");
    ACTION_DENIED_TREE(2, ACTION_XPATH, input_tree, 1, "deny-test-module", "Deny everything not explicitly permitted in test-module." );
    /*  -> sysrepo-user4 */
    ACTION_PERMITED(3, ACTION_XPATH, input, 1, 0);
    ACTION_PERMITED_TREE(3, ACTION_XPATH, input_tree, 1, 0);
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
nacm_cl_test_rpc_nacm_with_denied_exec_by_dflt(void **state)
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
    char *error_msg = NULL;

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
    /*  -> sysrepo-user4 */
    RPC_PERMITED(3, RPC_XPATH, NULL, 0, 2);
    RPC_PERMITED_TREE(3, RPC_XPATH, NULL, 0, 2);

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
    /*  -> sysrepo-user4 */
    RPC_PERMITED(3, RPC_XPATH, NULL, 0, 0);
    RPC_PERMITED_TREE(3, RPC_XPATH, NULL, 0, 0);

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
    ACTION_PERMITED(2, ACTION_XPATH, NULL, 0, 0);
    ACTION_PERMITED_TREE(2, ACTION_XPATH, NULL, 0, 0);
    /*  -> sysrepo-user4 */
    ACTION_PERMITED(3, ACTION_XPATH, NULL, 0, 0);
    ACTION_PERMITED_TREE(3, ACTION_XPATH, NULL, 0, 0);

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
    /*  -> sysrepo-user4 */
    ACTION_PERMITED(3, ACTION_XPATH, input, 1, 0);
    ACTION_PERMITED_TREE(3, ACTION_XPATH, input_tree, 1, 0);
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
nacm_cl_test_rpc_nacm_with_ext_groups(void **state)
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
    char *error_msg = NULL;

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
    /*  -> sysrepo-user4 */
    RPC_PERMITED(3, RPC_XPATH, NULL, 0, 2);
    RPC_PERMITED_TREE(3, RPC_XPATH, NULL, 0, 2);

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
    /*  -> sysrepo-user4 */
    RPC_PERMITED(3, RPC_XPATH, NULL, 0, 0);
    RPC_PERMITED_TREE(3, RPC_XPATH, NULL, 0, 0);

    /* test Action "unload" from test-model */
#undef ACTION_XPATH
#define ACTION_XPATH "/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/unload"
    /*  -> sysrepo-user1 */
    ACTION_PERMITED(0, ACTION_XPATH, NULL, 0, 0);
    ACTION_PERMITED_TREE(0, ACTION_XPATH, NULL, 0, 0);
    /*  -> sysrepo-user2 */
    ACTION_PERMITED(1, ACTION_XPATH, NULL, 0, 0);
    ACTION_PERMITED_TREE(1, ACTION_XPATH, NULL, 0, 0);
    /*  -> sysrepo-user3 */
    ACTION_PERMITED(2, ACTION_XPATH, NULL, 0, 0);
    ACTION_PERMITED_TREE(2, ACTION_XPATH, NULL, 0, 0);
    /*  -> sysrepo-user4 */
    ACTION_PERMITED(3, ACTION_XPATH, NULL, 0, 0);
    ACTION_PERMITED_TREE(3, ACTION_XPATH, NULL, 0, 0);

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
    /*  -> sysrepo-user4 */
    ACTION_PERMITED(3, ACTION_XPATH, input, 1, 0);
    ACTION_PERMITED_TREE(3, ACTION_XPATH, input_tree, 1, 0);
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
nacm_cl_test_event_notif_nacm_with_empty_nacm_cfg(void **state)
{
    int rc = SR_ERR_OK;
    sr_conn_ctx_t *conn = *state;
    sr_session_ctx_t *handler_session = NULL;
    user_sessions_t sessions = {NULL};
    sr_subscription_ctx_t *subscription = NULL;
    sr_val_t *values = NULL;
    sr_node_t *trees = NULL, *node = NULL;
    char *escaped_xpath = NULL, *regex = NULL;

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

    /* unsubscribe sysrepo-user1 */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /***** subscribe for notifications with sysrepo-user2 *****/
    subscribe_dummy_event_notif_callback(sessions[1], NULL, &subscription);

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


    /* unsubscribe sysrepo-user2 */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /***** subscribe for notifications with sysrepo-user3 *****/
    subscribe_dummy_event_notif_callback(sessions[2], NULL, &subscription);

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

    /* unsubscribe sysrepo-user3 */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /***** subscribe for notifications with sysrepo-user4 *****/
    subscribe_dummy_event_notif_callback(sessions[3], NULL, &subscription);

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

    /* unsubscribe sysrepo-user4 */
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
nacm_cl_test_event_notif_nacm(void **state)
{
    int rc = SR_ERR_OK;
    sr_conn_ctx_t *conn = *state;
    sr_session_ctx_t *handler_session = NULL;
    user_sessions_t sessions = {NULL};
    sr_subscription_ctx_t *subscription = NULL;
    sr_val_t *values = NULL;
    sr_node_t *trees = NULL, *node = NULL;
    char *escaped_xpath = NULL, *regex = NULL;

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
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, values, 1);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, trees, 1);
    sr_free_val(values);
    sr_free_tree(trees);

    /* unsubscribe sysrepo-user1 */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /***** subscribe for notifications with sysrepo-user2 *****/
    subscribe_dummy_event_notif_callback(sessions[1], NULL, &subscription);

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
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, values, 1);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, trees, 1);
    sr_free_val(values);
    sr_free_tree(trees);

    /* unsubscribe sysrepo-user2 */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /***** subscribe for notifications with sysrepo-user3 *****/
    subscribe_dummy_event_notif_callback(sessions[2], NULL, &subscription);

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
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, values, 1, "deny-netconf-capability-change", "Not allowed to receive the NETCONF capability change notification");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, trees, 1, "deny-netconf-capability-change", "Not allowed to receive the NETCONF capability change notification");
    sr_free_val(values);
    sr_free_tree(trees);

    /* unsubscribe sysrepo-user3 */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /***** subscribe for notifications with sysrepo-user4 *****/
    subscribe_dummy_event_notif_callback(sessions[3], NULL, &subscription);

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

    /* unsubscribe sysrepo-user4 */
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
nacm_cl_test_event_notif_nacm_with_denied_read_by_dflt(void **state)
{
    int rc = SR_ERR_OK;
    sr_conn_ctx_t *conn = *state;
    sr_session_ctx_t *handler_session = NULL;
    user_sessions_t sessions = {NULL};
    sr_subscription_ctx_t *subscription = NULL;
    sr_val_t *values = NULL;
    sr_node_t *trees = NULL, *node = NULL;
    char *escaped_xpath = NULL, *regex = NULL;

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
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, values, 1, "", "");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, trees, 1, "", "");
    sr_free_val(values);
    sr_free_tree(trees);

    /* unsubscribe sysrepo-user1 */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /***** subscribe for notifications with sysrepo-user2 *****/
    subscribe_dummy_event_notif_callback(sessions[1], NULL, &subscription);

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
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, values, 1, "", "");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, trees, 1, "", "");
    sr_free_val(values);
    sr_free_tree(trees);

    /* unsubscribe sysrepo-user2 */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /***** subscribe for notifications with sysrepo-user3 *****/
    subscribe_dummy_event_notif_callback(sessions[2], NULL, &subscription);

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
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, values, 1, "deny-netconf-capability-change", "Not allowed to receive the NETCONF capability change notification");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, trees, 1, "deny-netconf-capability-change", "Not allowed to receive the NETCONF capability change notification");
    sr_free_val(values);
    sr_free_tree(trees);

    /* unsubscribe sysrepo-user3 */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /***** subscribe for notifications with sysrepo-user4 *****/
    subscribe_dummy_event_notif_callback(sessions[3], NULL, &subscription);

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

    /* unsubscribe sysrepo-user4 */
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
nacm_cl_test_event_notif_nacm_with_ext_groups(void **state)
{
    int rc = SR_ERR_OK;
    sr_conn_ctx_t *conn = *state;
    sr_session_ctx_t *handler_session = NULL;
    user_sessions_t sessions = {NULL};
    sr_subscription_ctx_t *subscription = NULL;
    sr_val_t *values = NULL;
    sr_node_t *trees = NULL, *node = NULL;
    char *escaped_xpath = NULL, *regex = NULL;

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
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, values, 1, "deny-netconf-capability-change", "Not allowed to receive the NETCONF capability change notification");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, trees, 1, "deny-netconf-capability-change", "Not allowed to receive the NETCONF capability change notification");
    sr_free_val(values);
    sr_free_tree(trees);

    /* unsubscribe sysrepo-user1 */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /***** subscribe for notifications with sysrepo-user2 *****/
    subscribe_dummy_event_notif_callback(sessions[1], NULL, &subscription);

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
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, values, 1, "deny-netconf-capability-change", "Not allowed to receive the NETCONF capability change notification");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, trees, 1, "deny-netconf-capability-change", "Not allowed to receive the NETCONF capability change notification");
    sr_free_val(values);
    sr_free_tree(trees);

    /* unsubscribe sysrepo-user2 */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /***** subscribe for notifications with sysrepo-user3 *****/
    subscribe_dummy_event_notif_callback(sessions[2], NULL, &subscription);

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
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, values, 1, "deny-netconf-capability-change", "Not allowed to receive the NETCONF capability change notification");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, trees, 1, "deny-netconf-capability-change", "Not allowed to receive the NETCONF capability change notification");
    sr_free_val(values);
    sr_free_tree(trees);

    /* unsubscribe sysrepo-user3 */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /***** subscribe for notifications with sysrepo-user4 *****/
    subscribe_dummy_event_notif_callback(sessions[3], NULL, &subscription);

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

    /* unsubscribe sysrepo-user4 */
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
nacm_cl_test_commit_nacm_with_empty_nacm_cfg(void **state)
{
    int rc = SR_ERR_OK;
    sr_conn_ctx_t *conn = *state;
    user_sessions_t sessions = {NULL};
    sr_val_t value = { 0 };
    const sr_error_info_t *error_info = NULL;
    size_t error_cnt = 0;
    char *error_msg = NULL;

    if (!satisfied_requirements) {
        skip();
    }

    /* start a session for each user */
    start_user_sessions(conn, NULL, &sessions);

    /* test "empty" commit */
    /*  -> sysrepo-user1 */
    COMMIT_PERMITTED(0);
    /*  -> sysrepo-user2 */
    COMMIT_PERMITTED(1);
    /*  -> sysrepo-user3 */
    COMMIT_PERMITTED(2);
    /*  -> sysrepo-user4 */
    COMMIT_PERMITTED(3);

    /* try to set single integer value */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:main/i8"
    /*  -> sysrepo-user1 */
    value.type = SR_INT8_T;
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T + 1;
    rc = sr_set_item(sessions[0], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(0, NODE_XPATH, NACM_ACCESS_UPDATE, "", "");
    /*  -> sysrepo-user2 */
    rc = sr_set_item(sessions[1], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(1, NODE_XPATH, NACM_ACCESS_UPDATE, "", "");
    /*  -> sysrepo-user3 */
    rc = sr_set_item(sessions[2], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(2, NODE_XPATH, NACM_ACCESS_UPDATE, "", "");
    /*  -> sysrepo-user4 */
    rc = sr_set_item(sessions[3], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* change value of a leaf, but then set the original value back => no effect */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:main/i8"
    /*  -> sysrepo-user1 */
    value.type = SR_INT8_T;
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T + 1;
    rc = sr_set_item(sessions[0], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T;
    rc = sr_set_item(sessions[0], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(0);
    /*  -> sysrepo-user2 */
    value.type = SR_INT8_T;
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T + 1;
    rc = sr_set_item(sessions[1], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T;
    rc = sr_set_item(sessions[1], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(1);
    /*  -> sysrepo-user3 */
    value.type = SR_INT8_T;
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T + 1;
    rc = sr_set_item(sessions[2], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T;
    rc = sr_set_item(sessions[2], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(2);
    /*  -> sysrepo-user4 */
    value.type = SR_INT8_T;
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T + 1;
    rc = sr_set_item(sessions[3], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T;
    rc = sr_set_item(sessions[3], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to create a new leaf-list */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:main/numbers[.='88']"
    /*  -> sysrepo-user1 */
    value.type = SR_UINT8_T;
    value.data.uint8_val = 88;
    rc = sr_set_item(sessions[0], NODE_XPATH, &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(0, NODE_XPATH, NACM_ACCESS_CREATE, "", "");
    /*  -> sysrepo-user2 */
    rc = sr_set_item(sessions[1], NODE_XPATH, &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(1, NODE_XPATH, NACM_ACCESS_CREATE, "", "");
    /*  -> sysrepo-user3 */
    rc = sr_set_item(sessions[2], NODE_XPATH, &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(2, NODE_XPATH, NACM_ACCESS_CREATE, "", "");
    /*  -> sysrepo-user4 */
    rc = sr_set_item(sessions[3], NODE_XPATH, &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to delete an existing leaf-list */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:main/numbers[.='2']"
    /*  -> sysrepo-user1 */
    rc = sr_delete_item(sessions[0], NODE_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(0, NODE_XPATH, NACM_ACCESS_DELETE, "", "");
    /*  -> sysrepo-user2 */
    rc = sr_delete_item(sessions[1], NODE_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(1, NODE_XPATH, NACM_ACCESS_DELETE, "", "");
    /*  -> sysrepo-user3 */
    rc = sr_delete_item(sessions[2], NODE_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(2, NODE_XPATH, NACM_ACCESS_DELETE, "", "");
    /*  -> sysrepo-user4 */
    rc = sr_delete_item(sessions[3], NODE_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to move an existing leaf-list to the first position */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:ordered-numbers[.='57']"
    /*  -> sysrepo-user1 */
    rc = sr_move_item(sessions[0], NODE_XPATH, SR_MOVE_LAST, NULL);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(0, NODE_XPATH, NACM_ACCESS_UPDATE, "", "");
    /*  -> sysrepo-user2 */
    rc = sr_move_item(sessions[1], NODE_XPATH, SR_MOVE_LAST, NULL);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(1, NODE_XPATH, NACM_ACCESS_UPDATE, "", "");
    /*  -> sysrepo-user3 */
    rc = sr_move_item(sessions[2], NODE_XPATH, SR_MOVE_LAST, NULL);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(2, NODE_XPATH, NACM_ACCESS_UPDATE, "", "");
    /*  -> sysrepo-user4 */
    rc = sr_move_item(sessions[3], NODE_XPATH, SR_MOVE_LAST, NULL);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to create a new leaf together with its parent and some implicitly created nodes */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:presence-container"
    /*  -> sysrepo-user1 */
    value.type = SR_INT8_T;
    value.data.int8_val = 99;
    rc = sr_set_item(sessions[0], NODE_XPATH "/topleaf1", &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(0, NODE_XPATH, NACM_ACCESS_CREATE, "", "");
    /*  -> sysrepo-user2 */
    rc = sr_set_item(sessions[1], NODE_XPATH "/topleaf1", &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(1, NODE_XPATH, NACM_ACCESS_CREATE, "", "");
    /*  -> sysrepo-user3 */
    rc = sr_set_item(sessions[2], NODE_XPATH "/topleaf1", &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(2, NODE_XPATH, NACM_ACCESS_CREATE, "", "");
    /*  -> sysrepo-user4 */
    rc = sr_set_item(sessions[3], NODE_XPATH "/topleaf1", &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to edit NACM configuration */
#undef NODE_XPATH
#define NODE_XPATH "/ietf-netconf-acm:nacm/write-default"
#undef NODE2_XPATH
#define NODE2_XPATH "/ietf-netconf-acm:nacm/groups/group[name='new-group']"
    /*  -> sysrepo-user1 */
    rc = sr_set_item_str(sessions[0], NODE_XPATH, "permit", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[0], NODE2_XPATH "/user-name", "Me", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED2(0, NODE_XPATH, NACM_ACCESS_UPDATE, "", "", NODE2_XPATH, NACM_ACCESS_CREATE, "", "");
    /*  -> sysrepo-user2 */
    rc = sr_set_item_str(sessions[1], NODE_XPATH, "permit", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[1], NODE2_XPATH "/user-name", "Me", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED2(1, NODE_XPATH, NACM_ACCESS_UPDATE, "", "", NODE2_XPATH, NACM_ACCESS_CREATE, "", "");
    /*  -> sysrepo-user3 */
    rc = sr_set_item_str(sessions[2], NODE_XPATH, "permit", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[2], NODE2_XPATH "/user-name", "Me", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED2(2, NODE_XPATH, NACM_ACCESS_UPDATE, "", "", NODE2_XPATH, NACM_ACCESS_CREATE, "", "");
    /*  -> sysrepo-user4 */
    rc = sr_set_item_str(sessions[3], NODE_XPATH, "permit", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[3], NODE2_XPATH "/user-name", "Me", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to edit container in the example-module */
#undef NODE_XPATH
#define NODE_XPATH "/example-module:container/list[key1='new-item-key1'][key2='new-item-key2']"
#undef NODE2_XPATH
#define NODE2_XPATH "/example-module:container/list[key1='new-item2-key1'][key2='new-item2-key2']"
#undef NODE3_XPATH
#define NODE3_XPATH "/example-module:container/list[key1='key1'][key2='key2']"
    /*  -> sysrepo-user1 */
    rc = sr_set_item_str(sessions[0], NODE_XPATH "/leaf", "new-item-leaf", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[0], NODE2_XPATH "/leaf", "new-item-leaf2", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[0], NODE3_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED3(0, NODE3_XPATH, NACM_ACCESS_DELETE, "", "",
                      NODE_XPATH, NACM_ACCESS_CREATE, "", "",
                      NODE2_XPATH, NACM_ACCESS_CREATE, "", "");
    /*  -> sysrepo-user2 */
    rc = sr_set_item_str(sessions[1], NODE_XPATH "/leaf", "new-item-leaf", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[1], NODE2_XPATH "/leaf", "new-item-leaf2", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[1], NODE3_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED3(1, NODE3_XPATH, NACM_ACCESS_DELETE, "", "",
                      NODE_XPATH, NACM_ACCESS_CREATE, "", "",
                      NODE2_XPATH, NACM_ACCESS_CREATE, "", "");
    /*  -> sysrepo-user3 */
    rc = sr_set_item_str(sessions[2], NODE_XPATH "/leaf", "new-item-leaf", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[2], NODE2_XPATH "/leaf", "new-item-leaf2", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[2], NODE3_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED3(2, NODE3_XPATH, NACM_ACCESS_DELETE, "", "",
                      NODE_XPATH, NACM_ACCESS_CREATE, "", "",
                      NODE2_XPATH, NACM_ACCESS_CREATE, "", "");
    /*  -> sysrepo-user4 */
    rc = sr_set_item_str(sessions[3], NODE_XPATH "/leaf", "new-item-leaf", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[3], NODE2_XPATH "/leaf", "new-item-leaf2", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[3], NODE3_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to edit ietf-interfaces */
#undef NODE_XPATH
#define NODE_XPATH  "/ietf-interfaces:interfaces/interface[name='eth0']"
#undef NODE2_XPATH
#define NODE2_XPATH "/ietf-interfaces:interfaces/interface[name='eth2']"
#undef NODE3_XPATH
#define NODE3_XPATH "/ietf-interfaces:interfaces/interface[name='gigaeth0']/enabled"
    /*  -> sysrepo-user1 */
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[0], NODE_XPATH, SR_EDIT_STRICT);
    rc = sr_set_item_str(sessions[0], NODE2_XPATH "/type", "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    value.type = SR_BOOL_T;
    value.data.bool_val = true;
    rc = sr_set_item(sessions[0], NODE3_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED3(0, NODE3_XPATH, NACM_ACCESS_UPDATE, "", "",
                      NODE_XPATH, NACM_ACCESS_DELETE, "", "",
                      NODE2_XPATH, NACM_ACCESS_CREATE, "", "");
    /*  -> sysrepo-user2 */
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[1], NODE_XPATH, SR_EDIT_STRICT);
    rc = sr_set_item_str(sessions[1], NODE2_XPATH "/type", "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item(sessions[1], NODE3_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED3(1, NODE3_XPATH, NACM_ACCESS_UPDATE, "", "",
                      NODE_XPATH, NACM_ACCESS_DELETE, "", "",
                      NODE2_XPATH, NACM_ACCESS_CREATE, "", "");
    /*  -> sysrepo-user3 */
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[2], NODE_XPATH, SR_EDIT_STRICT);
    rc = sr_set_item_str(sessions[2], NODE2_XPATH "/type", "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item(sessions[2], NODE3_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED3(2, NODE3_XPATH, NACM_ACCESS_UPDATE, "", "",
                      NODE_XPATH, NACM_ACCESS_DELETE, "", "",
                      NODE2_XPATH, NACM_ACCESS_CREATE, "", "");
    /*  -> sysrepo-user4 */
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[3], NODE_XPATH, SR_EDIT_STRICT);
    rc = sr_set_item_str(sessions[3], NODE2_XPATH "/type", "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item(sessions[3], NODE3_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* stop sessions */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        rc = sr_session_stop(sessions[i]);
        assert_int_equal(rc, SR_ERR_OK);
    }
}

static void
nacm_cl_test_commit_nacm(void **state)
{
    int rc = SR_ERR_OK;
    sr_conn_ctx_t *conn = *state;
    user_sessions_t sessions = {NULL};
    sr_val_t value = { 0 };
    const sr_error_info_t *error_info = NULL;
    size_t error_cnt = 0;
    char *error_msg = NULL;

    if (!satisfied_requirements) {
        skip();
    }

    /* start a session for each user */
    start_user_sessions(conn, NULL, &sessions);

    /* test "empty" commit */
    /*  -> sysrepo-user1 */
    COMMIT_PERMITTED(0);
    /*  -> sysrepo-user2 */
    COMMIT_PERMITTED(1);
    /*  -> sysrepo-user3 */
    COMMIT_PERMITTED(2);
    /*  -> sysrepo-user4 */
    COMMIT_PERMITTED(3);

    /* try to set single integer value */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:main/i8"
    /*  -> sysrepo-user1 */
    value.type = SR_INT8_T;
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T + 1;
    rc = sr_set_item(sessions[0], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(0);
    /*  -> sysrepo-user2 */
    rc = sr_set_item(sessions[1], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(1, NODE_XPATH, NACM_ACCESS_UPDATE, "disallow-to-modify-i8",
            "Disallow modification of 8-bit signed integer in the main container");
    /*  -> sysrepo-user3 */
    rc = sr_set_item(sessions[2], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(2);
    /*  -> sysrepo-user4 */
    rc = sr_set_item(sessions[3], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* change value of a leaf, but then set the original value back => no effect */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:main/i8"
    /*  -> sysrepo-user1 */
    value.type = SR_INT8_T;
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T + 1;
    rc = sr_set_item(sessions[0], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T;
    rc = sr_set_item(sessions[0], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(0);
    /*  -> sysrepo-user2 */
    value.type = SR_INT8_T;
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T + 1;
    rc = sr_set_item(sessions[1], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T;
    rc = sr_set_item(sessions[1], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(1);
    /*  -> sysrepo-user3 */
    value.type = SR_INT8_T;
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T + 1;
    rc = sr_set_item(sessions[2], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T;
    rc = sr_set_item(sessions[2], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(2);
    /*  -> sysrepo-user4 */
    value.type = SR_INT8_T;
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T + 1;
    rc = sr_set_item(sessions[3], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T;
    rc = sr_set_item(sessions[3], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to create a new leaf-list */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:main/numbers[.='88']"
    /*  -> sysrepo-user1 */
    value.type = SR_UINT8_T;
    value.data.uint8_val = 88;
    rc = sr_set_item(sessions[0], NODE_XPATH, &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(0, NODE_XPATH, NACM_ACCESS_CREATE, "deny-high-numbers", "Do not allow to create/delete low numbers.");
    /*  -> sysrepo-user2 */
    rc = sr_set_item(sessions[1], NODE_XPATH, &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(1);
    /*  -> sysrepo-user3 */
    rc = sr_set_item(sessions[2], NODE_XPATH, &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(2, NODE_XPATH, NACM_ACCESS_CREATE, "deny-high-numbers", "Do not allow to create/delete low numbers.");
    /*  -> sysrepo-user4 */
    rc = sr_set_item(sessions[3], NODE_XPATH, &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to delete an existing leaf-list */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:main/numbers[.='2']"
    /*  -> sysrepo-user1 */
    rc = sr_delete_item(sessions[0], NODE_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(0);
    /*  -> sysrepo-user2 */
    rc = sr_delete_item(sessions[1], NODE_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(1, NODE_XPATH, NACM_ACCESS_DELETE, "deny-low-numbers", "Do not allow to create/delete low numbers.");
    /*  -> sysrepo-user3 */
    rc = sr_delete_item(sessions[2], NODE_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(2);
    /*  -> sysrepo-user4 */
    rc = sr_delete_item(sessions[3], NODE_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to move an existing leaf-list to the first position */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:ordered-numbers[.='57']"
    /*  -> sysrepo-user1 */
    rc = sr_move_item(sessions[0], NODE_XPATH, SR_MOVE_LAST, NULL);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(0);
    /*  -> sysrepo-user2 */
    rc = sr_move_item(sessions[1], NODE_XPATH, SR_MOVE_LAST, NULL);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(1, NODE_XPATH, NACM_ACCESS_UPDATE, "", "");
    /*  -> sysrepo-user3 */
    rc = sr_move_item(sessions[2], NODE_XPATH, SR_MOVE_LAST, NULL);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(2);
    /*  -> sysrepo-user4 */
    rc = sr_move_item(sessions[3], NODE_XPATH, SR_MOVE_LAST, NULL);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to create a new leaf together with its parent and some implicitly created nodes */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:presence-container"
    /*  -> sysrepo-user1 */
    value.type = SR_INT8_T;
    value.data.int8_val = 99;
    rc = sr_set_item(sessions[0], NODE_XPATH "/topleaf1", &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(0);
    /*  -> sysrepo-user2 */
    rc = sr_set_item(sessions[1], NODE_XPATH "/topleaf1", &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(1, NODE_XPATH, NACM_ACCESS_CREATE, "", "");
    /*  -> sysrepo-user3 */
    rc = sr_set_item(sessions[2], NODE_XPATH "/topleaf1", &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(2);
    /*  -> sysrepo-user4 */
    rc = sr_set_item(sessions[3], NODE_XPATH "/topleaf1", &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to edit NACM configuration */
#undef NODE_XPATH
#define NODE_XPATH "/ietf-netconf-acm:nacm/write-default"
#undef NODE2_XPATH
#define NODE2_XPATH "/ietf-netconf-acm:nacm/groups/group[name='new-group']"
    /*  -> sysrepo-user1 */
    rc = sr_set_item_str(sessions[0], NODE_XPATH, "permit", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[0], NODE2_XPATH "/user-name", "Me", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED_N(0, 2);
    /*  -> sysrepo-user2 */
    rc = sr_set_item_str(sessions[1], NODE_XPATH, "permit", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[1], NODE2_XPATH "/user-name", "Me", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED_N(1, 2);
    /*  -> sysrepo-user3 */
    rc = sr_set_item_str(sessions[2], NODE_XPATH, "permit", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[2], NODE2_XPATH "/user-name", "Me", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED_N(2, 2);
    /*  -> sysrepo-user4 */
    rc = sr_set_item_str(sessions[3], NODE_XPATH, "permit", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[3], NODE2_XPATH "/user-name", "Me", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to edit container in the example-module */
#undef NODE_XPATH
#define NODE_XPATH "/example-module:container/list[key1='new-item-key1'][key2='new-item-key2']"
#undef NODE2_XPATH
#define NODE2_XPATH "/example-module:container/list[key1='new-item2-key1'][key2='new-item2-key2']"
#undef NODE3_XPATH
#define NODE3_XPATH "/example-module:container/list[key1='key1'][key2='key2']"
    /*  -> sysrepo-user1 */
    rc = sr_set_item_str(sessions[0], NODE_XPATH "/leaf", "new-item-leaf", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[0], NODE2_XPATH "/leaf", "new-item-leaf2", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[0], NODE3_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED2(0, NODE3_XPATH, NACM_ACCESS_DELETE, "", "",
                      NODE_XPATH, NACM_ACCESS_CREATE, "deny-specific-list-item", "Not allowed to create this specific list item.");
    /*  -> sysrepo-user2 */
    rc = sr_set_item_str(sessions[1], NODE_XPATH "/leaf", "new-item-leaf", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[1], NODE2_XPATH "/leaf", "new-item-leaf2", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[1], NODE3_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED3(1, NODE3_XPATH, NACM_ACCESS_DELETE, "", "",
                      NODE_XPATH, NACM_ACCESS_CREATE, "", "",
                      NODE2_XPATH, NACM_ACCESS_CREATE, "", "");
    /*  -> sysrepo-user3 */
    rc = sr_set_item_str(sessions[2], NODE_XPATH "/leaf", "new-item-leaf", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[2], NODE2_XPATH "/leaf", "new-item-leaf2", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[2], NODE3_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED2(2, NODE3_XPATH "/leaf", NACM_ACCESS_DELETE, "disallow-to-delete-list-item-leaf", "Do not allowed to delete leaf from list item.",
                      NODE_XPATH, NACM_ACCESS_CREATE, "deny-specific-list-item", "Not allowed to create this specific list item.");
    /*  -> sysrepo-user4 */
    rc = sr_set_item_str(sessions[3], NODE_XPATH "/leaf", "new-item-leaf", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[3], NODE2_XPATH "/leaf", "new-item-leaf2", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[3], NODE3_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to edit ietf-interfaces */
#undef NODE_XPATH
#define NODE_XPATH  "/ietf-interfaces:interfaces/interface[name='eth0']"
#undef NODE2_XPATH
#define NODE2_XPATH "/ietf-interfaces:interfaces/interface[name='eth2']"
#undef NODE3_XPATH
#define NODE3_XPATH "/ietf-interfaces:interfaces/interface[name='gigaeth0']/enabled"
    /*  -> sysrepo-user1 */
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[0], NODE_XPATH, SR_EDIT_STRICT);
    rc = sr_set_item_str(sessions[0], NODE2_XPATH "/type", "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    value.type = SR_BOOL_T;
    value.data.bool_val = true;
    rc = sr_set_item(sessions[0], NODE3_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED2(0, NODE3_XPATH, NACM_ACCESS_UPDATE, "deny-interface-status-change", "Not allowed to change status of interface",
                      NODE_XPATH, NACM_ACCESS_DELETE, "", "");
    /*  -> sysrepo-user2 */
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[1], NODE_XPATH, SR_EDIT_STRICT);
    rc = sr_set_item_str(sessions[1], NODE2_XPATH "/type", "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item(sessions[1], NODE3_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED2(1, NODE_XPATH, NACM_ACCESS_DELETE, "deny-removing-interfaces", "Not allowed to remove existing interface",
                      NODE2_XPATH, NACM_ACCESS_CREATE, "", "");
    /*  -> sysrepo-user3 */
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[2], NODE_XPATH, SR_EDIT_STRICT);
    rc = sr_set_item_str(sessions[2], NODE2_XPATH "/type", "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item(sessions[2], NODE3_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED2(2, NODE3_XPATH, NACM_ACCESS_UPDATE, "deny-interface-status-change", "Not allowed to change status of interface",
                      NODE_XPATH, NACM_ACCESS_DELETE, "deny-removing-interfaces", "Not allowed to remove existing interface");
    /*  -> sysrepo-user4 */
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[3], NODE_XPATH, SR_EDIT_STRICT);
    rc = sr_set_item_str(sessions[3], NODE2_XPATH "/type", "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item(sessions[3], NODE3_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* stop sessions */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        rc = sr_session_stop(sessions[i]);
        assert_int_equal(rc, SR_ERR_OK);
    }
}

static void
nacm_cl_test_commit_nacm_with_permitted_write_by_dflt(void **state)
{
    int rc = SR_ERR_OK;
    sr_conn_ctx_t *conn = *state;
    user_sessions_t sessions = {NULL};
    sr_val_t value = { 0 };
    const sr_error_info_t *error_info = NULL;
    size_t error_cnt = 0;
    char *error_msg = NULL;

    if (!satisfied_requirements) {
        skip();
    }

    /* start a session for each user */
    start_user_sessions(conn, NULL, &sessions);

    /* test "empty" commit */
    /*  -> sysrepo-user1 */
    COMMIT_PERMITTED(0);
    /*  -> sysrepo-user2 */
    COMMIT_PERMITTED(1);
    /*  -> sysrepo-user3 */
    COMMIT_PERMITTED(2);
    /*  -> sysrepo-user4 */
    COMMIT_PERMITTED(3);

    /* try to set single integer value */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:main/i8"
    /*  -> sysrepo-user1 */
    value.type = SR_INT8_T;
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T + 1;
    rc = sr_set_item(sessions[0], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(0);
    /*  -> sysrepo-user2 */
    rc = sr_set_item(sessions[1], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(1, NODE_XPATH, NACM_ACCESS_UPDATE, "disallow-to-modify-i8",
            "Disallow modification of 8-bit signed integer in the main container");
    /*  -> sysrepo-user3 */
    rc = sr_set_item(sessions[2], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(2);
    /*  -> sysrepo-user4 */
    rc = sr_set_item(sessions[3], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* change value of a leaf, but then set the original value back => no effect */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:main/i8"
    /*  -> sysrepo-user1 */
    value.type = SR_INT8_T;
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T + 1;
    rc = sr_set_item(sessions[0], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T;
    rc = sr_set_item(sessions[0], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(0);
    /*  -> sysrepo-user2 */
    value.type = SR_INT8_T;
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T + 1;
    rc = sr_set_item(sessions[1], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T;
    rc = sr_set_item(sessions[1], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(1);
    /*  -> sysrepo-user3 */
    value.type = SR_INT8_T;
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T + 1;
    rc = sr_set_item(sessions[2], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T;
    rc = sr_set_item(sessions[2], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(2);
    /*  -> sysrepo-user4 */
    value.type = SR_INT8_T;
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T + 1;
    rc = sr_set_item(sessions[3], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T;
    rc = sr_set_item(sessions[3], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to create a new leaf-list */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:main/numbers[.='88']"
    /*  -> sysrepo-user1 */
    value.type = SR_UINT8_T;
    value.data.uint8_val = 88;
    rc = sr_set_item(sessions[0], NODE_XPATH, &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(0, NODE_XPATH, NACM_ACCESS_CREATE, "deny-high-numbers", "Do not allow to create/delete low numbers.");
    /*  -> sysrepo-user2 */
    rc = sr_set_item(sessions[1], NODE_XPATH, &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(1);
    /*  -> sysrepo-user3 */
    rc = sr_set_item(sessions[2], NODE_XPATH, &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(2, NODE_XPATH, NACM_ACCESS_CREATE, "deny-high-numbers", "Do not allow to create/delete low numbers.");
    /*  -> sysrepo-user4 */
    rc = sr_set_item(sessions[3], NODE_XPATH, &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to delete an existing leaf-list */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:main/numbers[.='2']"
    /*  -> sysrepo-user1 */
    rc = sr_delete_item(sessions[0], NODE_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(0);
    /*  -> sysrepo-user2 */
    rc = sr_delete_item(sessions[1], NODE_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(1, NODE_XPATH, NACM_ACCESS_DELETE, "deny-low-numbers", "Do not allow to create/delete low numbers.");
    /*  -> sysrepo-user3 */
    rc = sr_delete_item(sessions[2], NODE_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(2);
    /*  -> sysrepo-user4 */
    rc = sr_delete_item(sessions[3], NODE_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to move an existing leaf-list to the first position */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:ordered-numbers[.='57']"
    /*  -> sysrepo-user1 */
    rc = sr_move_item(sessions[0], NODE_XPATH, SR_MOVE_LAST, NULL);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(0);
    /*  -> sysrepo-user2 */
    rc = sr_move_item(sessions[1], NODE_XPATH, SR_MOVE_LAST, NULL);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(1);
    /*  -> sysrepo-user3 */
    rc = sr_move_item(sessions[2], NODE_XPATH, SR_MOVE_LAST, NULL);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(2);
    /*  -> sysrepo-user4 */
    rc = sr_move_item(sessions[3], NODE_XPATH, SR_MOVE_LAST, NULL);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to create a new leaf together with its parent and some implicitly created nodes */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:presence-container"
    /*  -> sysrepo-user1 */
    value.type = SR_INT8_T;
    value.data.int8_val = 99;
    rc = sr_set_item(sessions[0], NODE_XPATH "/topleaf1", &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(0);
    /*  -> sysrepo-user2 */
    rc = sr_set_item(sessions[1], NODE_XPATH "/topleaf1", &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED2(1, NODE_XPATH "/child1/grandchild1/grandchild1-leaf", NACM_ACCESS_CREATE, "deny-grandchild1-leaf", "Do not allow to edit grandchild1-leaf.",
                      NODE_XPATH "/child2", NACM_ACCESS_CREATE, "deny-child2", "Do not allow to create child2.");
    /*  -> sysrepo-user3 */
    rc = sr_set_item(sessions[2], NODE_XPATH "/topleaf1", &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(2);
    /*  -> sysrepo-user4 */
    rc = sr_set_item(sessions[3], NODE_XPATH "/topleaf1", &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to edit NACM configuration */
#undef NODE_XPATH
#define NODE_XPATH "/ietf-netconf-acm:nacm/write-default"
#undef NODE2_XPATH
#define NODE2_XPATH "/ietf-netconf-acm:nacm/groups/group[name='new-group']"
    /*  -> sysrepo-user1 */
    rc = sr_set_item_str(sessions[0], NODE_XPATH, "permit", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[0], NODE2_XPATH "/user-name", "Me", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(0, NODE2_XPATH, NACM_ACCESS_CREATE, "", "");
    /*  -> sysrepo-user2 */
    rc = sr_set_item_str(sessions[1], NODE_XPATH, "permit", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[1], NODE2_XPATH "/user-name", "Me", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(1, NODE2_XPATH, NACM_ACCESS_CREATE, "", "");
    /*  -> sysrepo-user3 */
    rc = sr_set_item_str(sessions[2], NODE_XPATH, "permit", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[2], NODE2_XPATH "/user-name", "Me", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED_N(2, 1);
    /*  -> sysrepo-user4 */
    rc = sr_set_item_str(sessions[3], NODE_XPATH, "permit", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[3], NODE2_XPATH "/user-name", "Me", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to edit container in the example-module */
#undef NODE_XPATH
#define NODE_XPATH "/example-module:container/list[key1='new-item-key1'][key2='new-item-key2']"
#undef NODE2_XPATH
#define NODE2_XPATH "/example-module:container/list[key1='new-item2-key1'][key2='new-item2-key2']"
#undef NODE3_XPATH
#define NODE3_XPATH "/example-module:container/list[key1='key1'][key2='key2']"
    /*  -> sysrepo-user1 */
    rc = sr_set_item_str(sessions[0], NODE_XPATH "/leaf", "new-item-leaf", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[0], NODE2_XPATH "/leaf", "new-item-leaf2", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[0], NODE3_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(0, NODE_XPATH, NACM_ACCESS_CREATE, "deny-specific-list-item", "Not allowed to create this specific list item.");
    /*  -> sysrepo-user2 */
    rc = sr_set_item_str(sessions[1], NODE_XPATH "/leaf", "new-item-leaf", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[1], NODE2_XPATH "/leaf", "new-item-leaf2", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[1], NODE3_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(1, NODE3_XPATH "/leaf", NACM_ACCESS_DELETE, "disallow-to-delete-list-item-leaf", "Do not allowed to delete leaf from list item.");
    /*  -> sysrepo-user3 */
    rc = sr_set_item_str(sessions[2], NODE_XPATH "/leaf", "new-item-leaf", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[2], NODE2_XPATH "/leaf", "new-item-leaf2", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[2], NODE3_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED2(2, NODE3_XPATH "/leaf", NACM_ACCESS_DELETE, "disallow-to-delete-list-item-leaf", "Do not allowed to delete leaf from list item.",
                      NODE_XPATH, NACM_ACCESS_CREATE, "deny-specific-list-item", "Not allowed to create this specific list item.");
    /*  -> sysrepo-user4 */
    rc = sr_set_item_str(sessions[3], NODE_XPATH "/leaf", "new-item-leaf", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[3], NODE2_XPATH "/leaf", "new-item-leaf2", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[3], NODE3_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to edit ietf-interfaces */
#undef NODE_XPATH
#define NODE_XPATH  "/ietf-interfaces:interfaces/interface[name='eth0']"
#undef NODE2_XPATH
#define NODE2_XPATH "/ietf-interfaces:interfaces/interface[name='eth2']"
#undef NODE3_XPATH
#define NODE3_XPATH "/ietf-interfaces:interfaces/interface[name='gigaeth0']/enabled"
    /*  -> sysrepo-user1 */
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[0], NODE_XPATH, SR_EDIT_STRICT);
    rc = sr_set_item_str(sessions[0], NODE2_XPATH "/type", "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    value.type = SR_BOOL_T;
    value.data.bool_val = true;
    rc = sr_set_item(sessions[0], NODE3_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(0, NODE3_XPATH, NACM_ACCESS_UPDATE, "deny-interface-status-change", "Not allowed to change status of interface");
    /*  -> sysrepo-user2 */
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[1], NODE_XPATH, SR_EDIT_STRICT);
    rc = sr_set_item_str(sessions[1], NODE2_XPATH "/type", "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item(sessions[1], NODE3_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(1, NODE_XPATH, NACM_ACCESS_DELETE, "deny-removing-interfaces", "Not allowed to remove existing interface");
    /*  -> sysrepo-user3 */
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[2], NODE_XPATH, SR_EDIT_STRICT);
    rc = sr_set_item_str(sessions[2], NODE2_XPATH "/type", "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item(sessions[2], NODE3_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED2(2, NODE3_XPATH, NACM_ACCESS_UPDATE, "deny-interface-status-change", "Not allowed to change status of interface",
                      NODE_XPATH, NACM_ACCESS_DELETE, "deny-removing-interfaces", "Not allowed to remove existing interface");
    /*  -> sysrepo-user4 */
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[3], NODE_XPATH, SR_EDIT_STRICT);
    rc = sr_set_item_str(sessions[3], NODE2_XPATH "/type", "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item(sessions[3], NODE3_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* stop sessions */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        rc = sr_session_stop(sessions[i]);
        assert_int_equal(rc, SR_ERR_OK);
    }
}

static void
nacm_cl_test_commit_nacm_with_ext_groups(void **state)
{
    int rc = SR_ERR_OK;
    sr_conn_ctx_t *conn = *state;
    user_sessions_t sessions = {NULL};
    sr_val_t value = { 0 };
    const sr_error_info_t *error_info = NULL;
    size_t error_cnt = 0;
    char *error_msg = NULL;

    if (!satisfied_requirements) {
        skip();
    }

    /* start a session for each user */
    start_user_sessions(conn, NULL, &sessions);

    /* test "empty" commit */
    /*  -> sysrepo-user1 */
    COMMIT_PERMITTED(0);
    /*  -> sysrepo-user2 */
    COMMIT_PERMITTED(1);
    /*  -> sysrepo-user3 */
    COMMIT_PERMITTED(2);
    /*  -> sysrepo-user4 */
    COMMIT_PERMITTED(3);

    /* try to set single integer value */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:main/i8"
    /*  -> sysrepo-user1 */
    value.type = SR_INT8_T;
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T + 1;
    rc = sr_set_item(sessions[0], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(0);
    /*  -> sysrepo-user2 */
    rc = sr_set_item(sessions[1], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(1, NODE_XPATH, NACM_ACCESS_UPDATE, "disallow-to-modify-i8",
            "Disallow modification of 8-bit signed integer in the main container");
    /*  -> sysrepo-user3 */
    rc = sr_set_item(sessions[2], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(2);
    /*  -> sysrepo-user4 */
    rc = sr_set_item(sessions[3], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* change value of a leaf, but then set the original value back => no effect */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:main/i8"
    /*  -> sysrepo-user1 */
    value.type = SR_INT8_T;
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T + 1;
    rc = sr_set_item(sessions[0], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T;
    rc = sr_set_item(sessions[0], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(0);
    /*  -> sysrepo-user2 */
    value.type = SR_INT8_T;
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T + 1;
    rc = sr_set_item(sessions[1], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T;
    rc = sr_set_item(sessions[1], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(1);
    /*  -> sysrepo-user3 */
    value.type = SR_INT8_T;
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T + 1;
    rc = sr_set_item(sessions[2], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T;
    rc = sr_set_item(sessions[2], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(2);
    /*  -> sysrepo-user4 */
    value.type = SR_INT8_T;
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T + 1;
    rc = sr_set_item(sessions[3], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T;
    rc = sr_set_item(sessions[3], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to create a new leaf-list */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:main/numbers[.='88']"
    /*  -> sysrepo-user1 */
    value.type = SR_UINT8_T;
    value.data.uint8_val = 88;
    rc = sr_set_item(sessions[0], NODE_XPATH, &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(0, NODE_XPATH, NACM_ACCESS_CREATE, "deny-high-numbers", "Do not allow to create/delete low numbers.");
    /*  -> sysrepo-user2 */
    rc = sr_set_item(sessions[1], NODE_XPATH, &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(1);
    /*  -> sysrepo-user3 */
    rc = sr_set_item(sessions[2], NODE_XPATH, &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(2, NODE_XPATH, NACM_ACCESS_CREATE, "deny-high-numbers", "Do not allow to create/delete low numbers.");
    /*  -> sysrepo-user4 */
    rc = sr_set_item(sessions[3], NODE_XPATH, &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to delete an existing leaf-list */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:main/numbers[.='2']"
    /*  -> sysrepo-user1 */
    rc = sr_delete_item(sessions[0], NODE_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(0);
    /*  -> sysrepo-user2 */
    rc = sr_delete_item(sessions[1], NODE_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(1, NODE_XPATH, NACM_ACCESS_DELETE, "deny-low-numbers", "Do not allow to create/delete low numbers.");
    /*  -> sysrepo-user3 */
    rc = sr_delete_item(sessions[2], NODE_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(2);
    /*  -> sysrepo-user4 */
    rc = sr_delete_item(sessions[3], NODE_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to move an existing leaf-list to the first position */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:ordered-numbers[.='57']"
    /*  -> sysrepo-user1 */
    rc = sr_move_item(sessions[0], NODE_XPATH, SR_MOVE_LAST, NULL);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(0);
    /*  -> sysrepo-user2 */
    rc = sr_move_item(sessions[1], NODE_XPATH, SR_MOVE_LAST, NULL);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(1, NODE_XPATH, NACM_ACCESS_UPDATE, "deny-test-module", "Deny everything not explicitly permitted in test-module.");
    /*  -> sysrepo-user3 */
    rc = sr_move_item(sessions[2], NODE_XPATH, SR_MOVE_LAST, NULL);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(2);
    /*  -> sysrepo-user4 */
    rc = sr_move_item(sessions[3], NODE_XPATH, SR_MOVE_LAST, NULL);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to create a new leaf together with its parent and some implicitly created nodes */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:presence-container"
    /*  -> sysrepo-user1 */
    value.type = SR_INT8_T;
    value.data.int8_val = 99;
    rc = sr_set_item(sessions[0], NODE_XPATH "/topleaf1", &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(0);
    /*  -> sysrepo-user2 */
    rc = sr_set_item(sessions[1], NODE_XPATH "/topleaf1", &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED2(1, NODE_XPATH "/child1/grandchild1/grandchild1-leaf", NACM_ACCESS_CREATE, "deny-grandchild1-leaf", "Do not allow to edit grandchild1-leaf.",
                      NODE_XPATH "/child2", NACM_ACCESS_CREATE, "deny-child2", "Do not allow to create child2.");
    /*  -> sysrepo-user3 */
    rc = sr_set_item(sessions[2], NODE_XPATH "/topleaf1", &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(2);
    /*  -> sysrepo-user4 */
    rc = sr_set_item(sessions[3], NODE_XPATH "/topleaf1", &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to edit NACM configuration */
#undef NODE_XPATH
#define NODE_XPATH "/ietf-netconf-acm:nacm/write-default"
#undef NODE2_XPATH
#define NODE2_XPATH "/ietf-netconf-acm:nacm/groups/group[name='new-group']"
    /*  -> sysrepo-user1 */
    rc = sr_set_item_str(sessions[0], NODE_XPATH, "permit", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[0], NODE2_XPATH "/user-name", "Me", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED_N(0, 2);
    /*  -> sysrepo-user2 */
    rc = sr_set_item_str(sessions[1], NODE_XPATH, "permit", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[1], NODE2_XPATH "/user-name", "Me", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED_N(1, 2);
    /*  -> sysrepo-user3 */
    rc = sr_set_item_str(sessions[2], NODE_XPATH, "permit", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[2], NODE2_XPATH "/user-name", "Me", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED_N(2, 2);
    /*  -> sysrepo-user4 */
    rc = sr_set_item_str(sessions[3], NODE_XPATH, "permit", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[3], NODE2_XPATH "/user-name", "Me", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to edit container in the example-module */
#undef NODE_XPATH
#define NODE_XPATH "/example-module:container/list[key1='new-item-key1'][key2='new-item-key2']"
#undef NODE2_XPATH
#define NODE2_XPATH "/example-module:container/list[key1='new-item2-key1'][key2='new-item2-key2']"
#undef NODE3_XPATH
#define NODE3_XPATH "/example-module:container/list[key1='key1'][key2='key2']"
    /*  -> sysrepo-user1 */
    rc = sr_set_item_str(sessions[0], NODE_XPATH "/leaf", "new-item-leaf", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[0], NODE2_XPATH "/leaf", "new-item-leaf2", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[0], NODE3_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(0, NODE_XPATH, NACM_ACCESS_CREATE, "deny-specific-list-item", "Not allowed to create this specific list item.");
    /*  -> sysrepo-user2 */
    rc = sr_set_item_str(sessions[1], NODE_XPATH "/leaf", "new-item-leaf", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[1], NODE2_XPATH "/leaf", "new-item-leaf2", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[1], NODE3_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(1, NODE3_XPATH "/leaf", NACM_ACCESS_DELETE, "disallow-to-delete-list-item-leaf", "Do not allowed to delete leaf from list item.");
    /*  -> sysrepo-user3 */
    rc = sr_set_item_str(sessions[2], NODE_XPATH "/leaf", "new-item-leaf", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[2], NODE2_XPATH "/leaf", "new-item-leaf2", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[2], NODE3_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED2(2, NODE3_XPATH "/leaf", NACM_ACCESS_DELETE, "disallow-to-delete-list-item-leaf", "Do not allowed to delete leaf from list item.",
                      NODE_XPATH, NACM_ACCESS_CREATE, "deny-specific-list-item", "Not allowed to create this specific list item.");
    /*  -> sysrepo-user4 */
    rc = sr_set_item_str(sessions[3], NODE_XPATH "/leaf", "new-item-leaf", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(sessions[3], NODE2_XPATH "/leaf", "new-item-leaf2", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[3], NODE3_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* try to edit ietf-interfaces */
#undef NODE_XPATH
#define NODE_XPATH  "/ietf-interfaces:interfaces/interface[name='eth0']"
#undef NODE2_XPATH
#define NODE2_XPATH "/ietf-interfaces:interfaces/interface[name='eth2']"
#undef NODE3_XPATH
#define NODE3_XPATH "/ietf-interfaces:interfaces/interface[name='gigaeth0']/enabled"
    /*  -> sysrepo-user1 */
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[0], NODE_XPATH, SR_EDIT_STRICT);
    rc = sr_set_item_str(sessions[0], NODE2_XPATH "/type", "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    value.type = SR_BOOL_T;
    value.data.bool_val = true;
    rc = sr_set_item(sessions[0], NODE3_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED2(0, NODE3_XPATH, NACM_ACCESS_UPDATE, "deny-interface-status-change", "Not allowed to change status of interface",
                      NODE_XPATH, NACM_ACCESS_DELETE, "", "");
    /*  -> sysrepo-user2 */
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[1], NODE_XPATH, SR_EDIT_STRICT);
    rc = sr_set_item_str(sessions[1], NODE2_XPATH "/type", "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item(sessions[1], NODE3_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(1, NODE_XPATH, NACM_ACCESS_DELETE, "deny-removing-interfaces", "Not allowed to remove existing interface");
    /*  -> sysrepo-user3 */
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[2], NODE_XPATH, SR_EDIT_STRICT);
    rc = sr_set_item_str(sessions[2], NODE2_XPATH "/type", "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item(sessions[2], NODE3_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED2(2, NODE3_XPATH, NACM_ACCESS_UPDATE, "deny-interface-status-change", "Not allowed to change status of interface",
                      NODE_XPATH, NACM_ACCESS_DELETE, "deny-removing-interfaces", "Not allowed to remove existing interface");
    /*  -> sysrepo-user4 */
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_delete_item(sessions[3], NODE_XPATH, SR_EDIT_STRICT);
    rc = sr_set_item_str(sessions[3], NODE2_XPATH "/type", "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item(sessions[3], NODE3_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* stop sessions */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        rc = sr_session_stop(sessions[i]);
        assert_int_equal(rc, SR_ERR_OK);
    }
}

static int
module_change_empty_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    return SR_ERR_OK;
}

static void
nacm_cl_test_copy_config(void **state, sr_datastore_t src_ds, sr_datastore_t dst_ds)
{
    int rc = 0;
    sr_conn_ctx_t *conn = *state;
    user_sessions_t sessions = {NULL};
    sr_session_ctx_t *handler_session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_val_t *val = NULL;

    if (!satisfied_requirements) {
        skip();
    }

    /* start a session for each user */
    start_user_sessions(conn, &handler_session, &sessions);

    /* enable running datastore */
    rc = sr_module_change_subscribe(handler_session, "test-module", module_change_empty_cb, NULL,
            0, SR_SUBSCR_APPLY_ONLY, &subscription);
    assert_int_equal(SR_ERR_OK, rc);
    rc = sr_module_change_subscribe(handler_session, "ietf-interfaces", module_change_empty_cb, NULL,
            0, SR_SUBSCR_APPLY_ONLY | SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(SR_ERR_OK, rc);

    /* copy-config to src_ds */
    rc = sr_copy_config(sessions[0], NULL, dst_ds, src_ds);
    assert_int_equal(SR_ERR_OK, rc);

    /* change the same values in src_ds with user1 */
    rc = sr_session_switch_ds(sessions[0], src_ds);
    assert_int_equal(SR_ERR_OK, rc);

    val = calloc(1, sizeof *val);
    assert_ptr_not_equal(val, NULL);
    val->type = SR_BOOL_T;
    val->data.bool_val = 0;
    rc = sr_set_item(sessions[0], XP_TEST_MODULE_BOOL, val, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    val->type = SR_UINT8_T;
    val->data.uint8_val = 20;
    rc = sr_set_item(sessions[0], "/test-module:main/numbers", val, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    val->type = SR_BOOL_T;
    val->data.bool_val = 0;
    rc = sr_set_item(sessions[0], "/ietf-interfaces:interfaces/interface[name='eth1']/enabled", val, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    val->type = SR_BOOL_T;
    val->data.bool_val = 1;
    rc = sr_set_item(sessions[0], "/ietf-interfaces:interfaces/interface[name='gigaeth0']/enabled", val, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_val(val);
    val = NULL;

    rc = sr_commit(sessions[0]);
    assert_int_equal(SR_ERR_OK, rc);

    /* copy-config back */
    rc = sr_copy_config(sessions[0], NULL, dst_ds, src_ds);
    assert_int_equal(SR_ERR_OK, rc);

    /* refresh handler_session session dst_ds */
    rc = sr_session_switch_ds(handler_session, dst_ds);
    assert_int_equal(SR_ERR_OK, rc);
    rc = sr_session_refresh(handler_session);
    assert_int_equal(SR_ERR_OK, rc);

    /* check the result, that no data was actually changed */
    rc = sr_get_item(handler_session, XP_TEST_MODULE_BOOL, &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_ptr_not_equal(val, NULL);
    assert_int_equal(val->data.bool_val, 1);
    sr_free_val(val);
    val = NULL;

    rc = sr_get_item(handler_session, "/test-module:main/numbers[.='20']", &val);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    assert_ptr_equal(val, NULL);

    rc = sr_get_item(handler_session, "/ietf-interfaces:interfaces/interface[name='eth1']/enabled", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_ptr_not_equal(val, NULL);
    assert_int_equal(val->data.bool_val, 1);
    sr_free_val(val);
    val = NULL;

    rc = sr_get_item(handler_session, "/ietf-interfaces:interfaces/interface[name='gigaeth0']/enabled", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_ptr_not_equal(val, NULL);
    assert_int_equal(val->data.bool_val, 0);
    sr_free_val(val);
    val = NULL;

    /* stop sessions */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        rc = sr_session_stop(sessions[i]);
        assert_int_equal(rc, SR_ERR_OK);
    }
    rc = sr_unsubscribe(handler_session, subscription);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_stop(handler_session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
nacm_cl_test_copy_config_cand_to_run(void **state)
{
    nacm_cl_test_copy_config(state, SR_DS_CANDIDATE, SR_DS_RUNNING);
}

static void
nacm_cl_test_copy_config_cand_to_start(void **state)
{
    nacm_cl_test_copy_config(state, SR_DS_CANDIDATE, SR_DS_STARTUP);
}

static void
nacm_cl_test_copy_config_run_to_start(void **state)
{
    nacm_cl_test_copy_config(state, SR_DS_RUNNING, SR_DS_STARTUP);
}

static void
nacm_cl_test_reload_nacm(void **state)
{
    int rc = SR_ERR_OK;
    sr_conn_ctx_t *conn = *state;
    user_sessions_t sessions = {NULL};
    sr_val_t value = { 0 };
    sr_val_t *output = NULL;
    sr_node_t *output_tree = NULL;
    size_t output_cnt = 0;
    bool permitted = true;
    const sr_error_info_t *error_info = NULL;
    size_t error_cnt = 0;
    char *error_msg = NULL;
    sr_session_ctx_t *nacm_edit_session = NULL, *handler_session = NULL;
    sr_subscription_ctx_t *rpc_subscription = NULL, *en_subscription = NULL;
    char *escaped_xpath = NULL, *regex = NULL;

    if (!satisfied_requirements) {
        skip();
    }

    /* start a session for each user + handler session */
    start_user_sessions(conn, &handler_session, &sessions);
    /* start session that will be used to modify *running* NACM configuration */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &nacm_edit_session);
    assert_int_equal(rc, SR_ERR_OK);

    /***** test NACM reloading with the Commit operation *****/

    /* try to set single integer value */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:main/i8"
    /*  -> sysrepo-user1 */
    value.type = SR_INT8_T;
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T + 1;
    rc = sr_set_item(sessions[0], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(0);
    /*  -> sysrepo-user2 */
    rc = sr_set_item(sessions[1], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(1, NODE_XPATH, NACM_ACCESS_UPDATE, "disallow-to-modify-i8",
            "Disallow modification of 8-bit signed integer in the main container");
    /*  -> sysrepo-user3 */
    rc = sr_set_item(sessions[2], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(2);
    /*  -> sysrepo-user4 */
    rc = sr_set_item(sessions[3], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /* Edit NACM configuration */
#undef NODE_XPATH
#define NODE_XPATH "/ietf-netconf-acm:nacm/rule-list[name='acl1']/rule[name='allow-to-modify-i8']"
#undef NODE2_XPATH
#define NODE2_XPATH "/ietf-netconf-acm:nacm/rule-list[name='acl2']/rule[name='allow-to-modify-i8']"
    /*  -> delete permission from ACL1 */
    rc = sr_delete_item(nacm_edit_session, NODE_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    /*  -> add permission to ACL2 and make it the first match */
    rc = sr_set_item_str(nacm_edit_session, NODE2_XPATH "/action", "permit", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(nacm_edit_session, NODE2_XPATH "/path", "/test-module:main/i8", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_move_item(nacm_edit_session, NODE2_XPATH, SR_MOVE_FIRST, NULL);
    assert_int_equal(rc, SR_ERR_OK);
    /*  -> apply changes to NACM configuration */
    rc = sr_commit(nacm_edit_session);
    assert_int_equal(rc, SR_ERR_OK);
    wait_ms(NACM_RELOAD_DELAY);

    /* try to set the single integer value again */
#undef NODE_XPATH
#define NODE_XPATH "/test-module:main/i8"
    /*  -> sysrepo-user1 */
    value.type = SR_INT8_T;
    value.data.int8_val = XP_TEST_MODULE_INT8_VALUE_T + 2;
    rc = sr_set_item(sessions[0], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_DENIED(0, NODE_XPATH, NACM_ACCESS_UPDATE, "", "");
    /*  -> sysrepo-user2 */
    rc = sr_set_item(sessions[1], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(1);
    /*  -> sysrepo-user3 */
    rc = sr_set_item(sessions[2], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(2);
    /*  -> sysrepo-user4 */
    rc = sr_set_item(sessions[3], NODE_XPATH, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    COMMIT_PERMITTED(3);

    /***** test NACM reloading with RPCs *****/
    subscribe_dummy_rpc_callback(handler_session, NULL, &rpc_subscription);

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
    /*  -> sysrepo-user4 */
    RPC_PERMITED(3, RPC_XPATH, NULL, 0, 0);
    RPC_PERMITED_TREE(3, RPC_XPATH, NULL, 0, 0);

    /* Edit NACM configuration */
#undef NODE_XPATH
#define NODE_XPATH "/ietf-netconf-acm:nacm/rule-list[name='acl1']/rule[name='deny-initialize']"
#undef NODE2_XPATH
#define NODE2_XPATH "/ietf-netconf-acm:nacm/rule-list[name='acl2']/rule[name='deny-initialize']"
    /*  -> deny RPC "initialize" from turing machine in ACL1 */
    rc = sr_set_item_str(nacm_edit_session, NODE_XPATH "/module-name", "turing-machine", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(nacm_edit_session, NODE_XPATH "/rpc-name", "initialize", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(nacm_edit_session, NODE_XPATH "/access-operations", "exec", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(nacm_edit_session, NODE_XPATH "/action", "deny", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(nacm_edit_session, NODE_XPATH "/comment", "NACM rule added at the run-time.", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    /*  -> in ACL2, limit restriction to execute "initialize" to module ietf-interfaces only */
    rc = sr_set_item_str(nacm_edit_session, NODE2_XPATH "/module-name", "ietf-interfaces", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    /*  -> apply changes to NACM configuration */
    rc = sr_commit(nacm_edit_session);
    assert_int_equal(rc, SR_ERR_OK);
    wait_ms(NACM_RELOAD_DELAY);

    /* test RPC "initialize" from turing-machine, again */
#undef RPC_XPATH
#define RPC_XPATH "/turing-machine:initialize"
    /*  -> sysrepo-user1 */
    RPC_DENIED(0, RPC_XPATH, NULL, 0, "deny-initialize", "NACM rule added at the run-time.");
    RPC_DENIED_TREE(0, RPC_XPATH, NULL, 0, "deny-initialize", "NACM rule added at the run-time.");
    /*  -> sysrepo-user2 */
    RPC_PERMITED(1, RPC_XPATH, NULL, 0, 0);
    RPC_PERMITED_TREE(1, RPC_XPATH, NULL, 0, 0);
    /*  -> sysrepo-user3 */
    RPC_DENIED(0, RPC_XPATH, NULL, 0, "deny-initialize", "NACM rule added at the run-time.");
    RPC_DENIED_TREE(0, RPC_XPATH, NULL, 0, "deny-initialize", "NACM rule added at the run-time.");
    /*  -> sysrepo-user4 */
    RPC_PERMITED(3, RPC_XPATH, NULL, 0, 0);
    RPC_PERMITED_TREE(3, RPC_XPATH, NULL, 0, 0);

    /* unsubscribe RPCs */
    rc = sr_unsubscribe(NULL, rpc_subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /***** test NACM reloading with Event notifications *****/

    /* test Event notification "link-discovered" */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-discovered"
    /*  -> sysrepo-user1 */
    subscribe_dummy_event_notif_callback(sessions[0], NULL, &en_subscription);
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "deny-link-discovered", "Not allowed to receive the link-discovered notification");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "deny-link-discovered", "Not allowed to receive the link-discovered notification");
    rc = sr_unsubscribe(NULL, en_subscription);
    assert_int_equal(rc, SR_ERR_OK);
    /*  -> sysrepo-user2 */
    subscribe_dummy_event_notif_callback(sessions[1], NULL, &en_subscription);
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);
    rc = sr_unsubscribe(NULL, en_subscription);
    assert_int_equal(rc, SR_ERR_OK);
    /*  -> sysrepo-user3 */
    subscribe_dummy_event_notif_callback(sessions[2], NULL, &en_subscription);
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "deny-link-discovered", "Not allowed to receive the link-discovered notification");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "deny-link-discovered", "Not allowed to receive the link-discovered notification");
    rc = sr_unsubscribe(NULL, en_subscription);
    assert_int_equal(rc, SR_ERR_OK);
    /*  -> sysrepo-user4 */
    subscribe_dummy_event_notif_callback(sessions[3], NULL, &en_subscription);
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);
    rc = sr_unsubscribe(NULL, en_subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* Edit NACM configuration */
#undef NODE_XPATH
#define NODE_XPATH "/ietf-netconf-acm:nacm/rule-list[name='acl1']/rule[name='deny-link-discovered']"
    /*  -> delete rule that restricts delivery of this event notification from ACL1 */
    rc = sr_delete_item(nacm_edit_session, NODE_XPATH, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);
    /*  -> apply changes to NACM configuration */
    rc = sr_commit(nacm_edit_session);
    assert_int_equal(rc, SR_ERR_OK);
    wait_ms(NACM_RELOAD_DELAY);

    /* test Event notification "link-discovered", again */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-discovered"
    /*  -> sysrepo-user1 */
    subscribe_dummy_event_notif_callback(sessions[0], NULL, &en_subscription);
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);
    rc = sr_unsubscribe(NULL, en_subscription);
    assert_int_equal(rc, SR_ERR_OK);
    /*  -> sysrepo-user2 */
    subscribe_dummy_event_notif_callback(sessions[1], NULL, &en_subscription);
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);
    rc = sr_unsubscribe(NULL, en_subscription);
    assert_int_equal(rc, SR_ERR_OK);
    /*  -> sysrepo-user3 */
    subscribe_dummy_event_notif_callback(sessions[2], NULL, &en_subscription);
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "deny-test-module", "Deny everything not explicitly permitted in test-module.");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "deny-test-module", "Deny everything not explicitly permitted in test-module.");
    rc = sr_unsubscribe(NULL, en_subscription);
    assert_int_equal(rc, SR_ERR_OK);
    /*  -> sysrepo-user4 */
    subscribe_dummy_event_notif_callback(sessions[3], NULL, &en_subscription);
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);
    rc = sr_unsubscribe(NULL, en_subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* Edit NACM configuration */
#undef NODE_XPATH
#define NODE_XPATH "/ietf-netconf-acm:nacm/read-default"
    /*  -> deny read operation by default */
    rc = sr_set_item_str(nacm_edit_session, NODE_XPATH, "deny", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    /*  -> apply changes to NACM configuration */
    rc = sr_commit(nacm_edit_session);
    assert_int_equal(rc, SR_ERR_OK);
    wait_ms(NACM_RELOAD_DELAY);

    /* test Event notification "link-discovered", for the third time */
#undef EVENT_NOTIF_XPATH
#define EVENT_NOTIF_XPATH "/test-module:link-discovered"
    /*  -> sysrepo-user1 */
    subscribe_dummy_event_notif_callback(sessions[0], NULL, &en_subscription);
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "", "");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "", "");
    rc = sr_unsubscribe(NULL, en_subscription);
    assert_int_equal(rc, SR_ERR_OK);
    /*  -> sysrepo-user2 */
    subscribe_dummy_event_notif_callback(sessions[1], NULL, &en_subscription);
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "", "");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "", "");
    rc = sr_unsubscribe(NULL, en_subscription);
    assert_int_equal(rc, SR_ERR_OK);
    /*  -> sysrepo-user3 */
    subscribe_dummy_event_notif_callback(sessions[2], NULL, &en_subscription);
    EVENT_NOTIF_DENIED(EVENT_NOTIF_XPATH, NULL, 0, "deny-test-module", "Deny everything not explicitly permitted in test-module.");
    EVENT_NOTIF_DENIED_TREE(EVENT_NOTIF_XPATH, NULL, 0, "deny-test-module", "Deny everything not explicitly permitted in test-module.");
    rc = sr_unsubscribe(NULL, en_subscription);
    assert_int_equal(rc, SR_ERR_OK);
    /*  -> sysrepo-user4 */
    subscribe_dummy_event_notif_callback(sessions[3], NULL, &en_subscription);
    EVENT_NOTIF_PERMITED(EVENT_NOTIF_XPATH, NULL, 0);
    EVENT_NOTIF_PERMITED_TREE(EVENT_NOTIF_XPATH, NULL, 0);
    rc = sr_unsubscribe(NULL, en_subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop sessions */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        rc = sr_session_stop(sessions[i]);
        assert_int_equal(rc, SR_ERR_OK);
    }
    rc = sr_session_stop(nacm_edit_session);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_stop(handler_session);
    assert_int_equal(rc, SR_ERR_OK);
}

int
main() {
    const struct CMUnitTest tests[] = {
        /* RPC */
            cmocka_unit_test_setup_teardown(nacm_cl_test_rpc_nacm_with_empty_nacm_cfg, sysrepo_setup_with_empty_nacm_cfg, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(nacm_cl_test_rpc_nacm, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(nacm_cl_test_rpc_nacm_with_denied_exec_by_dflt, sysrepo_setup_with_denied_exec_by_dflt, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(nacm_cl_test_rpc_nacm_with_ext_groups, sysrepo_setup_with_ext_groups, sysrepo_teardown),
        /* Event notification */
            cmocka_unit_test_setup_teardown(nacm_cl_test_event_notif_nacm_with_empty_nacm_cfg, sysrepo_setup_with_empty_nacm_cfg, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(nacm_cl_test_event_notif_nacm, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(nacm_cl_test_event_notif_nacm_with_denied_read_by_dflt, sysrepo_setup_with_denied_read_by_dflt, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(nacm_cl_test_event_notif_nacm_with_ext_groups, sysrepo_setup_with_ext_groups, sysrepo_teardown),
        /* Commit */
            cmocka_unit_test_setup_teardown(nacm_cl_test_commit_nacm_with_empty_nacm_cfg, sysrepo_setup_with_empty_nacm_cfg, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(nacm_cl_test_commit_nacm, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(nacm_cl_test_commit_nacm_with_permitted_write_by_dflt, sysrepo_setup_with_permitted_write_by_dflt, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(nacm_cl_test_commit_nacm_with_ext_groups, sysrepo_setup_with_ext_groups, sysrepo_teardown),
        /* Copy-config */
            cmocka_unit_test_setup_teardown(nacm_cl_test_copy_config_cand_to_run, sysrepo_setup_for_copy_config, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(nacm_cl_test_copy_config_cand_to_start, sysrepo_setup_for_copy_config, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(nacm_cl_test_copy_config_run_to_start, sysrepo_setup_for_copy_config, sysrepo_teardown),
        /* NACM reload */
            cmocka_unit_test_setup_teardown(nacm_cl_test_reload_nacm, sysrepo_setup, sysrepo_teardown),
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

    int ret = cmocka_run_group_tests(tests, NULL, NULL);
    sr_list_cleanup(log_history.logs);
    return ret;
}
