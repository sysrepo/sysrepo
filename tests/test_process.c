/**
 * @file test_process.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test for concurrent execution of several sysrepo processes
 *
 * @copyright
 * Copyright 2020 Deutsche Telekom AG.
 * Copyright 2020 CESNET, z.s.p.o.
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
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "tests/config.h"
#include "sysrepo.h"

#define sr_assert(cond) if (!(cond)) { fprintf(stderr, "\"%s\" not true\n", #cond); sr_assert_line(); abort(); }

#define sr_assert_line() printf("[   LINE    ] --- %s:%d: error: Failure!\n", __FILE__, __LINE__)

#define sr_assert_true(cond) if (!(cond)) { fprintf(stderr, "\"%s\" not true\n", #cond); sr_assert_line(); return 1; }

#define sr_assert_int_equal(val1, val2) { \
    int ret1, ret2; \
    ret1 = val1; ret2 = val2; \
    if (ret1 != ret2) { fprintf(stderr, "%d != %d\n", ret1, ret2); sr_assert_line(); return 1; } }

#define sr_assert_int_nequal(val1, val2) { \
    int ret1, ret2; \
    ret1 = val1; ret2 = val2; \
    if (ret1 == ret2) { fprintf(stderr, "%d == %d\n", ret1, ret2); sr_assert_line(); return 1; } }

#define sr_assert_string_equal(str1, str2) { \
    const char *s1, *s2; \
    s1 = str1; s2 = str2; \
    if (strcmp(s1, s2)) { fprintf(stderr, "\"%s\"\n!=\n\"%s\"\n", s1, s2); sr_assert_line(); return 1; } }

#define sr_assert_nstring_equal(str1, str2, n) { \
    const char *s1, *s2; \
    s1 = str1; s2 = str2; \
    if (strncmp(s1, s2, n)) { fprintf(stderr, "\"%.*s\"\n!=\n\"%.*s\"\n", n, s1, n, s2); sr_assert_line(); return 1; } }

typedef int (*test_proc)(int, int);
typedef void (*test_prep)(void);

struct test {
    const char *name;
    test_proc p1;
    test_proc p2;
    test_prep setup;
    test_prep teardown;
};

static void
barrier(int rp, int wp)
{
    char buf[5];

    sr_assert(write(wp, "ready", 5) == 5);
    sr_assert(read(rp, buf, 5) == 5);
    sr_assert(!strncmp(buf, "ready", 5));
}

static void
run_tests(struct test *tests, uint32_t test_count)
{
    int pipes[4], wstatus, fail = 0;
    const char *child_status, *parent_status;
    size_t i;

    pipe(pipes);
    pipe(pipes + 2);

    printf("[===========] Running %u test(s).\n", test_count);

    for (i = 0; i < test_count; ++i) {
        if (tests[i].setup) {
            tests[i].setup();
        }

        printf("[ %3s %2s %2s ] test %s\n", "RUN", "", "", tests[i].name);

        if (fork()) {
            /* run parent process */
            if (tests[i].p1(pipes[0], pipes[3])) {
                parent_status = "FAIL";
                fail = 1;
            } else {
                parent_status = "OK";
            }

            /* wait for child */
            sr_assert(wait(&wstatus) != -1);

            if (WIFEXITED(wstatus)) {
                if (WEXITSTATUS(wstatus)) {
                    child_status = "FAIL";
                    fail = 1;
                } else {
                    child_status = "OK";
                }
            } else {
                sr_assert(WIFSIGNALED(wstatus));
                child_status = "SIGNAL";
                fail = 1;
            }
        } else {
            /* run child process */
            exit(tests[i].p2(pipes[2], pipes[1]));
        }

        printf("[ %3s %2s %2s ] test %s\n", "", parent_status, child_status, tests[i].name);

        if (tests[i].teardown) {
            tests[i].teardown();
        }

        if (fail) {
            printf("Test failed, aborting.\n");
            abort();
        }
    }

    printf("[===========] %u test(s) run.\n", test_count);
    printf("[  PASSED   ] %u test(s).\n", test_count);

    close(pipes[0]);
    close(pipes[1]);
    close(pipes[2]);
    close(pipes[3]);
}

static void
test_log_cb(sr_log_level_t level, const char *message)
{
    const char *severity;

    switch (level) {
    case SR_LL_ERR:
        severity = "ERR";
        break;
    case SR_LL_WRN:
        severity = "WRN";
        break;
    case SR_LL_INF:
        severity = "INF";
        break;
    case SR_LL_DBG:
        /*severity = "DBG";
        break;*/
        return;
    case SR_LL_NONE:
        sr_assert(0);
        return;
    }

    fprintf(stderr, "[%ld][%s]: %s\n", (long)getpid(), severity, message);
}

/* TEST FUNCS */
static void
setup(void)
{
    sr_conn_ctx_t *conn;
    const char *en_feat = "feat1";

    sr_assert(sr_connect(0, &conn) == SR_ERR_OK);

    sr_assert(sr_install_module(conn, TESTS_DIR "/files/ops-ref.yang", TESTS_DIR "/files", &en_feat, 1) == SR_ERR_OK);
    sr_assert(sr_install_module(conn, TESTS_DIR "/files/ops.yang", TESTS_DIR "/files", NULL, 0) == SR_ERR_OK);
    sr_assert(sr_install_module(conn, TESTS_DIR "/files/ietf-interfaces.yang", TESTS_DIR "/files", NULL, 0) == SR_ERR_OK);
    sr_assert(sr_install_module(conn, TESTS_DIR "/files/iana-if-type.yang", TESTS_DIR "/files", NULL, 0) == SR_ERR_OK);

    sr_disconnect(conn);
}

static void
teardown(void)
{
    sr_conn_ctx_t *conn;

    sr_assert(sr_connect(0, &conn) == SR_ERR_OK);

    sr_remove_module(conn, "iana-if-type");
    sr_remove_module(conn, "ietf-interfaces");
    sr_remove_module(conn, "ops");
    sr_remove_module(conn, "ops-ref");

    sr_disconnect(conn);
}

/* TEST */
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

static int
test_rpc_sub1(int rp, int wp)
{
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *sub;
    int ret, i;

    ret = sr_connect(0, &conn);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_start(conn, SR_DS_RUNNING, &sess);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* wait for the other process */
    barrier(rp, wp);

    /* subscribe and unsubscribe to RPCs/actions */
    for (i = 0; i < 20; ++i) {
        sub = NULL;

        ret = sr_rpc_subscribe(sess, "/ops:rpc1", rpc_sub_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &sub);
        sr_assert_int_equal(ret, SR_ERR_OK);
        ret = sr_rpc_subscribe(sess, "/ops:rpc2", rpc_sub_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &sub);
        sr_assert_int_equal(ret, SR_ERR_OK);
        ret = sr_rpc_subscribe(sess, "/ops:rpc3", rpc_sub_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &sub);
        sr_assert_int_equal(ret, SR_ERR_OK);
        ret = sr_rpc_subscribe(sess, "/ops:cont/list1/cont2/act1", rpc_sub_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &sub);
        sr_assert_int_equal(ret, SR_ERR_OK);
        ret = sr_rpc_subscribe(sess, "/ops:cont/list1/act2", rpc_sub_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &sub);
        sr_assert_int_equal(ret, SR_ERR_OK);

        sr_unsubscribe(sub);
    }

    sr_disconnect(conn);
    return 0;
}

static int
test_rpc_sub2(int rp, int wp)
{
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *sub;
    int ret, i;

    ret = sr_connect(0, &conn);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_start(conn, SR_DS_RUNNING, &sess);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* wait for the other process */
    barrier(rp, wp);

    /* subscribe and unsubscribe to RPCs/actions */
    for (i = 0; i < 20; ++i) {
        sub = NULL;

        ret = sr_rpc_subscribe(sess, "/ops:rpc1", rpc_sub_cb, NULL, 1, SR_SUBSCR_CTX_REUSE, &sub);
        sr_assert_int_equal(ret, SR_ERR_OK);
        ret = sr_rpc_subscribe(sess, "/ops:rpc2", rpc_sub_cb, NULL, 1, SR_SUBSCR_CTX_REUSE, &sub);
        sr_assert_int_equal(ret, SR_ERR_OK);
        ret = sr_rpc_subscribe(sess, "/ops:rpc3", rpc_sub_cb, NULL, 1, SR_SUBSCR_CTX_REUSE, &sub);
        sr_assert_int_equal(ret, SR_ERR_OK);
        ret = sr_rpc_subscribe(sess, "/ops:cont/list1/cont2/act1", rpc_sub_cb, NULL, 1, SR_SUBSCR_CTX_REUSE, &sub);
        sr_assert_int_equal(ret, SR_ERR_OK);
        ret = sr_rpc_subscribe(sess, "/ops:cont/list1/act2", rpc_sub_cb, NULL, 1, SR_SUBSCR_CTX_REUSE, &sub);
        sr_assert_int_equal(ret, SR_ERR_OK);

        sr_unsubscribe(sub);
    }

    sr_disconnect(conn);
    return 0;
}

/* TEST */
static int
test_rpc_crash1(int rp, int wp)
{
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    struct lyd_node *rpc, *output;
    int ret;

    ret = sr_connect(0, &conn);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_start(conn, SR_DS_RUNNING, &sess);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* wait for the other process */
    barrier(rp, wp);

    rpc = lyd_new_path(NULL, sr_get_context(conn), "/ops:rpc3/l4", "value", 0, 0);
    sr_assert_true(rpc);

    /* this should crash the other process */
    ret = sr_rpc_send_tree(sess, rpc, 2000, &output);
    sr_assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);

    lyd_free(rpc);
    sr_disconnect(conn);
    return 0;
}

static int
rpc_crash_cb(sr_session_ctx_t *session, const char *op_path, const sr_val_t *input, const size_t input_cnt,
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

    /* callback crashes */
    exit(0);

    return SR_ERR_OK;
}

static int
test_rpc_crash2(int rp, int wp)
{
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *sub;
    int ret;

    ret = sr_connect(0, &conn);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_start(conn, SR_DS_RUNNING, &sess);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* do not create thread to avoid leaks */
    ret = sr_rpc_subscribe(sess, "/ops:rpc3", rpc_crash_cb, NULL, 0, SR_SUBSCR_NO_THREAD, &sub);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* wait for the other process */
    barrier(rp, wp);

    /* will block until crash */
    while (1) {
        sr_process_events(sub, NULL, NULL);
    }

    /* unreachable */
    sr_unsubscribe(sub);
    sr_disconnect(conn);
    return 0;
}

/* TEST */
static void
notif_instid_cb(sr_session_ctx_t *session, const sr_ev_notif_type_t notif_type, const char *xpath,
        const sr_val_t *values, const size_t values_cnt, time_t timestamp, void *private_data)
{
    (void)session;
    (void)notif_type;
    (void)xpath;
    (void)values;
    (void)values_cnt;
    (void)timestamp;
    (void)private_data;
}

static int
notif_instid_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    (void)session;
    (void)module_name;
    (void)xpath;
    (void)event;
    (void)request_id;
    (void)private_data;

    return SR_ERR_OK;
}

static int
test_notif_instid1(int rp, int wp)
{
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *sub;
    struct lyd_node *notif;
    int ret, i;

    ret = sr_connect(0, &conn);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_start(conn, SR_DS_RUNNING, &sess);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* create instid target */
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth0']/type", "iana-if-type:ethernetCsmacd",
            NULL, 0);
    sr_assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0, 1);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to it so it appears in operational */
    ret = sr_module_change_subscribe(sess, "ietf-interfaces", NULL, notif_instid_change_cb, NULL, 0, 0, &sub);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to the notification */
    ret = sr_event_notif_subscribe(sess, "ops", "/ops:notif3", 0, 0, notif_instid_cb, NULL, SR_SUBSCR_CTX_REUSE, &sub);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* create the notification */
    notif = lyd_new_path(NULL, sr_get_context(conn), "/ops:notif3/list2[k='key']/l15",
            "/ietf-interfaces:interfaces/interface[name='eth0']", 0, 0);
    sr_assert(notif);

    /* wait for the other process */
    barrier(rp, wp);

    /* keep sending notification with instance-identifier */
    for (i = 0; i < 50; ++i) {
        ret = sr_event_notif_send_tree(sess, notif);
        sr_assert_int_equal(ret, SR_ERR_OK);
    }

    lyd_free(notif);

    sr_unsubscribe(sub);
    sr_disconnect(conn);
    return 0;
}

static int
test_notif_instid2(int rp, int wp)
{
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    int ret, i;

    ret = sr_connect(0, &conn);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_start(conn, SR_DS_RUNNING, &sess);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* wait for the other process */
    barrier(rp, wp);

    /* keep changing data in some arbitrary way */
    for (i = 0; i < 50; ++i) {
        ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth0']/enabled", "false", NULL, 0);
        sr_assert_int_equal(ret, SR_ERR_OK);
        ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth0']/description", "desc", NULL, 0);
        sr_assert_int_equal(ret, SR_ERR_OK);
        ret = sr_apply_changes(sess, 0, 1);
        sr_assert_int_equal(ret, SR_ERR_OK);

        ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth0']/enabled", "true", NULL, 0);
        sr_assert_int_equal(ret, SR_ERR_OK);
        ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth0']/description", "desc2", NULL, 0);
        sr_assert_int_equal(ret, SR_ERR_OK);
        ret = sr_apply_changes(sess, 0, 1);
        sr_assert_int_equal(ret, SR_ERR_OK);
    }

    sr_disconnect(conn);
    return 0;
}

int
main(void)
{
    struct test tests[] = {
        {"rpc sub", test_rpc_sub1, test_rpc_sub2, setup, teardown},
        {"rpc crash", test_rpc_crash1, test_rpc_crash2, setup, teardown},
        {"notif instid", test_notif_instid1, test_notif_instid2, setup, teardown},
    };

    sr_log_set_cb(test_log_cb);
    run_tests(tests, sizeof tests / sizeof *tests);
    return 0;
}

