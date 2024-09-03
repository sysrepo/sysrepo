/**
 * @file test_process.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test for concurrent execution of several sysrepo processes
 *
 * @copyright
 * Copyright (c) 2018 - 2021 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common_types.h"
#include "plugins_datastore.h"
#include "sysrepo.h"
#include "tests/tcommon.h"

#define sr_assert(cond) if (!(cond)) { TLOG_ERR("\"%s\" not true", #cond); sr_assert_line(); abort(); }

#define sr_assert_line() TLOG_ERR("[   LINE    ] --- %s:%d: Failure!", __FILE__, __LINE__)

#define sr_assert_true(cond) if (!(cond)) { TLOG_ERR("\"%s\" not true", #cond); sr_assert_line(); return 1; }

#define sr_assert_true_ret(cond, ret) if (!(cond)) { TLOG_ERR("\"%s\" not true", #cond); sr_assert_line(); return ret; }

#define sr_assert_int_equal(val1, val2) { \
    int ret1, ret2; \
    ret1 = val1; ret2 = val2; \
    if (ret1 != ret2) { TLOG_ERR("%d != %d", ret1, ret2); sr_assert_line(); return 1; } }

#define sr_assert_int_nequal(val1, val2) { \
    int ret1, ret2; \
    ret1 = val1; ret2 = val2; \
    if (ret1 == ret2) { TLOG_ERR("%d == %d", ret1, ret2); sr_assert_line(); return 1; } }

#define sr_assert_string_equal(str1, str2) { \
    const char *s1, *s2; \
    s1 = str1; s2 = str2; \
    if (strcmp(s1, s2)) { TLOG_ERR("\"%s\"\n!=\n\"%s\"", s1, s2); sr_assert_line(); return 1; } }

#define sr_assert_nstring_equal(str1, str2, n) { \
    const char *s1, *s2; \
    s1 = str1; s2 = str2; \
    if (strncmp(s1, s2, n)) { TLOG_ERR("\"%.*s\"\n!=\n\"%.*s\"", n, s1, n, s2); sr_assert_line(); return 1; } }

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

    sr_assert(pipe(pipes) == 0);
    sr_assert(pipe(pipes + 2) == 0);

    TLOG_INF("[===========] Running %u test(s).", test_count);

    for (i = 0; i < test_count; ++i) {
        if (tests[i].setup) {
            tests[i].setup();
        }

        TLOG_INF("[ %3s %2s %2s ] test %s", "RUN", "", "", tests[i].name);

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

        TLOG_INF("[ %3s %2s %2s ] test %s", "", parent_status, child_status, tests[i].name);

        if (tests[i].teardown) {
            tests[i].teardown();
        }

        if (fail) {
            TLOG_ERR("Test failed, aborting.");
            abort();
        }
    }

    TLOG_INF("[===========] %u test(s) run.", test_count);
    TLOG_INF("[  PASSED   ] %u test(s).", test_count);

    close(pipes[0]);
    close(pipes[1]);
    close(pipes[2]);
    close(pipes[3]);
}

/* TEST FUNCS */
static void
setup(void)
{
    sr_conn_ctx_t *conn;
    const char *schema_paths[] = {
        TESTS_SRC_DIR "/files/ops-ref.yang",
        TESTS_SRC_DIR "/files/ops.yang",
        TESTS_SRC_DIR "/files/ietf-interfaces.yang",
        TESTS_SRC_DIR "/files/iana-if-type.yang",
        TESTS_SRC_DIR "/files/mod1.yang",
        TESTS_SRC_DIR "/files/test.yang",
        NULL
    };
    const char *ops_ref_feats[] = {"feat1", NULL};
    const char *mod1_feats[] = {"f1", NULL};
    const char **features[] = {
        ops_ref_feats,
        NULL,
        NULL,
        NULL,
        mod1_feats,
        NULL
    };

    sr_assert(sr_connect(0, &conn) == SR_ERR_OK);
    sr_assert(sr_install_modules(conn, schema_paths, TESTS_SRC_DIR "/files", features) == SR_ERR_OK);
    sr_disconnect(conn);
}

static void
teardown(void)
{
    sr_conn_ctx_t *conn;
    const char *module_names[] = {
        "mod1",
        "ietf-interfaces",
        "iana-if-type",
        "ops",
        "ops-ref",
        "test",
        NULL
    };

    sr_assert(sr_connect(0, &conn) == SR_ERR_OK);

    sr_assert(sr_remove_modules(conn, module_names, 0) == SR_ERR_OK);

    sr_disconnect(conn);
}

/* TEST */
static int
rpc_sub_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const sr_val_t *input, const size_t input_cnt,
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
    (void)session;
    (void)sub_id;
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
    sr_subscription_ctx_t *sub = NULL;
    int ret, i;

    ret = sr_connect(0, &conn);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_start(conn, SR_DS_RUNNING, &sess);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* wait for the other process */
    barrier(rp, wp);

    /* subscribe and unsubscribe to RPCs/actions */
    for (i = 0; i < 20; ++i) {
        ret = sr_rpc_subscribe(sess, "/ops:rpc1", rpc_sub_cb, NULL, 0, 0, &sub);
        sr_assert_int_equal(ret, SR_ERR_OK);
        ret = sr_rpc_subscribe(sess, "/ops:rpc2", rpc_sub_cb, NULL, 0, 0, &sub);
        sr_assert_int_equal(ret, SR_ERR_OK);
        ret = sr_rpc_subscribe(sess, "/ops:rpc3", rpc_sub_cb, NULL, 0, 0, &sub);
        sr_assert_int_equal(ret, SR_ERR_OK);
        ret = sr_rpc_subscribe(sess, "/ops:cont/list1/cont2/act1", rpc_sub_cb, NULL, 0, 0, &sub);
        sr_assert_int_equal(ret, SR_ERR_OK);
        ret = sr_rpc_subscribe(sess, "/ops:cont/list1/act2", rpc_sub_cb, NULL, 0, 0, &sub);
        sr_assert_int_equal(ret, SR_ERR_OK);

        sr_unsubscribe(sub);
        sub = NULL;
    }

    sr_disconnect(conn);
    return 0;
}

static int
test_rpc_sub2(int rp, int wp)
{
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *sub = NULL;
    int ret, i;

    ret = sr_connect(0, &conn);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_start(conn, SR_DS_RUNNING, &sess);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* wait for the other process */
    barrier(rp, wp);

    /* subscribe and unsubscribe to RPCs/actions */
    for (i = 0; i < 20; ++i) {
        ret = sr_rpc_subscribe(sess, "/ops:rpc1", rpc_sub_cb, NULL, 1, 0, &sub);
        sr_assert_int_equal(ret, SR_ERR_OK);
        ret = sr_rpc_subscribe(sess, "/ops:rpc2", rpc_sub_cb, NULL, 1, 0, &sub);
        sr_assert_int_equal(ret, SR_ERR_OK);
        ret = sr_rpc_subscribe(sess, "/ops:rpc3", rpc_sub_cb, NULL, 1, 0, &sub);
        sr_assert_int_equal(ret, SR_ERR_OK);
        ret = sr_rpc_subscribe(sess, "/ops:cont/list1/cont2/act1", rpc_sub_cb, NULL, 1, 0, &sub);
        sr_assert_int_equal(ret, SR_ERR_OK);
        ret = sr_rpc_subscribe(sess, "/ops:cont/list1/act2", rpc_sub_cb, NULL, 1, 0, &sub);
        sr_assert_int_equal(ret, SR_ERR_OK);

        sr_unsubscribe(sub);
        sub = NULL;
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
    struct lyd_node *rpc;
    sr_data_t *output;
    int ret;

    ret = sr_connect(0, &conn);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_start(conn, SR_DS_RUNNING, &sess);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* wait for the other process */
    barrier(rp, wp);

    sr_assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, sr_acquire_context(conn), "/ops:rpc3/l4", "value", 0, &rpc));

    /* this should crash the other process */
    ret = sr_rpc_send_tree(sess, rpc, 2000, &output);
    sr_assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);

    lyd_free_tree(rpc);
    sr_release_context(conn);
    sr_disconnect(conn);
    return 0;
}

static int
rpc_crash_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const sr_val_t *input, const size_t input_cnt,
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
    (void)session;
    (void)sub_id;
    (void)op_path;
    (void)input;
    (void)input_cnt;
    (void)event;
    (void)request_id;
    (void)output;
    (void)output_cnt;
    (void)private_data;

    /* avoid leaks (valgrind probably cannot keep track of leafref attributes because they are shared) */
    ly_ctx_destroy((struct ly_ctx *)sr_acquire_context(sr_session_get_connection(session)));
    sr_release_context(sr_session_get_connection(session));
    for (uint32_t i = 0; i < session->conn->ds_handle_count; ++i) {
        if (session->conn->ds_handles[i].init) {
            session->conn->ds_handles[i].plugin->conn_destroy_cb(session->conn, session->conn->ds_handles[i].plg_data);
        }
    }

    /* callback crashes */
    exit(0);

    return SR_ERR_OK;
}

static int
test_rpc_crash2(int rp, int wp)
{
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *sub = NULL;
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
        sr_subscription_process_events(sub, NULL, NULL);
    }

    /* unreachable */
    sr_unsubscribe(sub);
    sr_disconnect(conn);
    return 0;
}

/* TEST */
static int
test_oper_crash_set1(int rp, int wp)
{
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    sr_data_t *data;
    char *str1;
    const char *str2;
    int ret;

    ret = sr_connect(0, &conn);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_start(conn, SR_DS_OPERATIONAL, &sess);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* set some operational data */
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces-state/interface[name='eth0']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    sr_assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces-state/interface[name='eth0']/speed",
            "512", NULL, 0);
    sr_assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces-state/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    sr_assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces-state/interface[name='eth1']/speed",
            "1024", NULL, 0);
    sr_assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* read the data */
    ret = sr_get_data(sess, "/ietf-interfaces:interfaces-state", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    sr_assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
            " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">\n"
            "  <interface>\n"
            "    <name>eth0</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <speed>512</speed>\n"
            "  </interface>\n"
            "  <interface>\n"
            "    <name>eth1</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <speed>1024</speed>\n"
            "  </interface>\n"
            "</interfaces-state>\n";

    sr_assert_string_equal(str1, str2);
    free(str1);

    /* wait for the other process */
    barrier(rp, wp);

    /* avoid leaks (valgrind probably cannot keep track of leafref attributes because they are shared) */
    ly_ctx_destroy((struct ly_ctx *)sr_acquire_context(sr_session_get_connection(sess)));
    sr_release_context(sr_session_get_connection(sess));
    for (uint32_t i = 0; i < sess->conn->ds_handle_count; ++i) {
        if (sess->conn->ds_handles[i].init) {
            sess->conn->ds_handles[i].plugin->conn_destroy_cb(sess->conn, sess->conn->ds_handles[i].plg_data);
        }
    }

    /* crash */
    exit(0);

    /* unreachable */
    return 1;
}

static int
test_oper_crash_set2(int rp, int wp)
{
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    sr_data_t *data;
    char *str1;
    const char *str2, *str3;
    int ret;

    /* wait for the other process */
    barrier(rp, wp);
    sleep(1);

    ret = sr_connect(0, &conn);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_start(conn, SR_DS_OPERATIONAL, &sess);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* set the same operational data in two commits */
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces-state/interface[name='eth0']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    sr_assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces-state/interface[name='eth0']/speed",
            "512", NULL, 0);
    sr_assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* commit the second part */
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces-state/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    sr_assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces-state/interface[name='eth1']/speed",
            "1024", NULL, 0);
    sr_assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* read the data */
    ret = sr_get_data(sess, "/ietf-interfaces:interfaces-state", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    sr_assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
            " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">\n"
            "  <interface>\n"
            "    <name>eth0</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <speed>512</speed>\n"
            "  </interface>\n"
            "  <interface>\n"
            "    <name>eth1</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <speed>1024</speed>\n"
            "  </interface>\n"
            "</interfaces-state>\n";

    str3 =
            "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
            " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">\n"
            "  <interface>\n"
            "    <name>eth1</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <speed>1024</speed>\n"
            "  </interface>\n"
            "  <interface>\n"
            "    <name>eth0</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <speed>512</speed>\n"
            "  </interface>\n"
            "</interfaces-state>\n";

    /* order of the operational state data might not be deterministic (e.g. system ordered lists)
        across all datastore plugins, so check for both possibilities */
    sr_assert_true(!strcmp(str1, str2) || !strcmp(str1, str3));
    free(str1);

    sr_disconnect(conn);
    return 0;
}

/* TEST */
struct notif_nowait_crash_arg {
    int rp;
    int wp;
    sr_session_ctx_t *sess;
};

static void
notif_nowait_crash_cb1(sr_session_ctx_t *UNUSED(session), uint32_t UNUSED(sub_id), const sr_ev_notif_type_t UNUSED(notif_type),
        const char *UNUSED(xpath), const sr_val_t *UNUSED(values), const size_t UNUSED(values_cnt),
        struct timespec *UNUSED(timestamp), void *private_data)
{
    struct notif_nowait_crash_arg *arg = private_data;

    /* avoid leaks (valgrind probably cannot keep track of leafref attributes because they are shared) */
    ly_ctx_destroy((struct ly_ctx *)sr_session_acquire_context(arg->sess));
    sr_session_release_context(arg->sess);
    for (uint32_t i = 0; i < arg->sess->conn->ds_handle_count; ++i) {
        if (arg->sess->conn->ds_handles[i].init) {
            arg->sess->conn->ds_handles[i].plugin->conn_destroy_cb(arg->sess->conn, arg->sess->conn->ds_handles[i].plg_data);
        }
    }

    /* signal the crash */
    barrier(arg->rp, arg->wp);

    exit(0);
}

static void
notif_nowait_crash_cb2(sr_session_ctx_t *UNUSED(session), uint32_t UNUSED(sub_id), const sr_ev_notif_type_t UNUSED(notif_type),
        const char *UNUSED(xpath), const sr_val_t *UNUSED(values), const size_t UNUSED(values_cnt),
        struct timespec *UNUSED(timestamp), void *UNUSED(private_data))
{

}

static int
test_notif_nowait_crash1(int rp, int wp)
{
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *sub = NULL;
    struct notif_nowait_crash_arg arg;
    int ret;

    ret = sr_connect(0, &conn);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_start(conn, SR_DS_RUNNING, &sess);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to notif without a thread */
    arg.rp = rp;
    arg.wp = wp;
    arg.sess = sess;
    ret = sr_notif_subscribe(sess, "ops", NULL, NULL, NULL, notif_nowait_crash_cb1, &arg, SR_SUBSCR_NO_THREAD, &sub);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* wait for the other process */
    barrier(rp, wp);

    /* wait for the other process */
    barrier(rp, wp);

    /* process a notification, crashes */
    ret = sr_subscription_process_events(sub, NULL, NULL);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* unreachable */
    return 1;
}

#include <sched.h>

static int
test_notif_nowait_crash2(int rp, int wp)
{
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *sub = NULL;
    int ret;

    ret = sr_connect(0, &conn);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_start(conn, SR_DS_RUNNING, &sess);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to notif without a thread */
    ret = sr_notif_subscribe(sess, "ops", NULL, NULL, NULL, notif_nowait_crash_cb2, NULL, SR_SUBSCR_NO_THREAD, &sub);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* signal subscription was created */
    barrier(rp, wp);

    /* send a notif without waiting */
    ret = sr_notif_send(sess, "/ops:notif4", NULL, 0, 0, 0);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* signal notif was sent */
    barrier(rp, wp);

    /* wait until the crash */
    barrier(rp, wp);
    usleep(50000);

    /* process it */
    ret = sr_subscription_process_events(sub, NULL, NULL);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* should have crashed, send a notif again */
    ret = sr_notif_send(sess, "/ops:notif4", NULL, 0, 0, 0);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* should be normally processed */
    ret = sr_subscription_process_events(sub, NULL, NULL);
    sr_assert_int_equal(ret, SR_ERR_OK);

    sr_unsubscribe(sub);
    sr_disconnect(conn);
    return 0;
}

/* TEST */
static void
notif_instid_cb(sr_session_ctx_t *session, uint32_t sub_id, const sr_ev_notif_type_t notif_type, const char *xpath,
        const sr_val_t *values, const size_t values_cnt, struct timespec *timestamp, void *private_data)
{
    (void)session;
    (void)sub_id;
    (void)notif_type;
    (void)sub_id;
    (void)xpath;
    (void)values;
    (void)values_cnt;
    (void)timestamp;
    (void)private_data;
}

static int
dummy_change_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    (void)session;
    (void)sub_id;
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
    sr_subscription_ctx_t *sub = NULL;
    struct lyd_node *tree;
    sr_data_t *notif;
    int ret, i;

    ret = sr_connect(0, &conn);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_start(conn, SR_DS_RUNNING, &sess);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* create instid target */
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth0']/type", "iana-if-type:ethernetCsmacd",
            NULL, 0);
    sr_assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to it so it appears in operational */
    ret = sr_module_change_subscribe(sess, "ietf-interfaces", NULL, dummy_change_cb, NULL, 0, 0, &sub);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to the notification */
    ret = sr_notif_subscribe(sess, "ops", "/ops:notif3", 0, 0, notif_instid_cb, NULL, 0, &sub);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* create the notification */
    lyd_new_path(NULL, sr_acquire_context(conn), "/ops:notif3/list2[k='key']/l15",
            "/ietf-interfaces:interfaces/interface[name='eth0']", 0, &tree);
    sr_assert(tree);
    ret = sr_acquire_data(conn, tree, &notif);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* wait for the other process */
    barrier(rp, wp);

    /* keep sending notification with instance-identifier */
    for (i = 0; i < 50; ++i) {
        ret = sr_notif_send_tree(sess, notif->tree, 0, 0);
        sr_assert_int_equal(ret, SR_ERR_OK);
    }

    sr_release_data(notif);
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
        ret = sr_apply_changes(sess, 0);
        sr_assert_int_equal(ret, SR_ERR_OK);

        ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth0']/enabled", "true", NULL, 0);
        sr_assert_int_equal(ret, SR_ERR_OK);
        ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth0']/description", "desc2", NULL, 0);
        sr_assert_int_equal(ret, SR_ERR_OK);
        ret = sr_apply_changes(sess, 0);
        sr_assert_int_equal(ret, SR_ERR_OK);
    }

    sr_disconnect(conn);
    return 0;
}

/* TEST */
static int
pull_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *path,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    const struct ly_ctx *ly_ctx = sr_acquire_context(sr_session_get_connection(session));
    LY_ERR ret;

    (void)sub_id;
    (void)module_name;
    (void)path;
    (void)request_xpath;
    (void)request_id;
    (void)private_data;

    ret = lyd_new_path(NULL, ly_ctx, "/ietf-interfaces:interfaces-state/interface[name='lo']/statistics/discontinuity-time",
            "2021-03-01T00:00:00Z", 0, parent);
    sr_assert_int_equal(ret, LY_SUCCESS);
    ret = lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='lo']/statistics/in-octets",
            "42", 0, NULL);
    sr_assert_int_equal(ret, LY_SUCCESS);
    ret = lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='lo']/statistics/out-octets",
            "42", 0, NULL);
    sr_assert_int_equal(ret, LY_SUCCESS);

    sr_release_context(sr_session_get_connection(session));
    return SR_ERR_OK;
}

static int
test_pull_push_oper1(int rp, int wp)
{
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *sub = NULL;
    int ret, i;

    ret = sr_connect(0, &conn);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_start(conn, SR_DS_OPERATIONAL, &sess);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to providing operational data */
    ret = sr_oper_get_subscribe(sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state/interface/statistics",
            pull_oper_cb, NULL, 0, &sub);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* wait for the other process */
    barrier(rp, wp);

    /* keep changing push operational data */
    for (i = 0; i < 200; ++i) {
        ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces-state/interface[name='lo']/phys-address",
                (i % 2) ? "00:00:00:00:00:00" : "11:11:11:11:11:11", NULL, 0);
        sr_assert_int_equal(ret, SR_ERR_OK);
        ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces-state/interface[name='lo']/oper-status",
                (i % 2) ? "unknown" : "down", NULL, 0);
        sr_assert_int_equal(ret, SR_ERR_OK);
        ret = sr_apply_changes(sess, 0);
        sr_assert_int_equal(ret, SR_ERR_OK);
    }

    sr_unsubscribe(sub);
    sr_disconnect(conn);
    return 0;
}

static int
test_pull_push_oper2(int rp, int wp)
{
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    sr_data_t *data;
    int ret, i;

    ret = sr_connect(0, &conn);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_start(conn, SR_DS_OPERATIONAL, &sess);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* wait for the other process */
    barrier(rp, wp);

    /* keep getting the operational data */
    for (i = 0; i < 200; ++i) {
        ret = sr_get_data(sess, "/ietf-interfaces:interfaces/interface", 0, 0, 0, &data);
        sr_assert_int_equal(ret, SR_ERR_OK);
        sr_release_data(data);
    }

    sr_disconnect(conn);
    return 0;
}

/* TEST */
static int
test_context_change(int rp, int wp)
{
    sr_conn_ctx_t *conn;
    int ret;

    ret = sr_connect(0, &conn);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* sync #1 */
    barrier(rp, wp);

    /* try to disable f1, succeeds */
    ret = sr_disable_module_feature(conn, "mod1", "f1");
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* enable f1 back */
    ret = sr_enable_module_feature(conn, "mod1", "f1");
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* install deviating module */
    ret = sr_install_module(conn, TESTS_SRC_DIR "/files/mod2.yang", TESTS_SRC_DIR "/files", NULL);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* remove the module */
    ret = sr_remove_module(conn, "mod2", 0);
    sr_assert_int_equal(ret, SR_ERR_OK);

    sr_disconnect(conn);
    return 0;
}

static int
module_change_dummy_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    (void)session;
    (void)sub_id;
    (void)module_name;
    (void)xpath;
    (void)event;
    (void)request_id;
    (void)private_data;

    return SR_ERR_OK;
}

static int
rpc_dummy_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data)
{
    (void)session;
    (void)sub_id;
    (void)op_path;
    (void)input;
    (void)event;
    (void)request_id;
    (void)output;
    (void)private_data;

    return SR_ERR_OK;
}

static int
test_context_change_sub(int rp, int wp)
{
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *sub = NULL;
    sr_data_t *data;
    const struct ly_ctx *ly_ctx;
    struct lyd_node *ly_action;
    char buf[32];
    int ret, i;

    ret = sr_connect(0, &conn);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_start(conn, SR_DS_RUNNING, &sess);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* subscribe */
    ret = sr_module_change_subscribe(sess, "mod1", "/mod1:cont/l3", module_change_dummy_cb, NULL, 0, 0, &sub);
    sr_assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe_tree(sess, "/mod1:cont/a", rpc_dummy_cb, NULL, 0, 0, &sub);
    sr_assert_int_equal(ret, SR_ERR_OK);

    /* sync #1 */
    barrier(rp, wp);

    /* keep triggering the subscriptions */
    for (i = 0; i < 200; ++i) {
        /* changes in the data */
        sprintf(buf, "val%d", i);
        ret = sr_set_item_str(sess, "/mod1:cont/l3", buf, NULL, 0);
        sr_assert_int_equal(ret, SR_ERR_OK);
        ret = sr_apply_changes(sess, 0);
        sr_assert_int_equal(ret, SR_ERR_OK);

        /* action */
        ly_ctx = sr_acquire_context(conn);
        sr_assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, ly_ctx, "/mod1:cont/a/l4", "50", 0, &ly_action));
        ret = sr_rpc_send_tree(sess, ly_action, 0, &data);
        lyd_free_tree(ly_action);
        sr_release_context(conn);
        sr_release_data(data);
        sr_assert_int_equal(ret, SR_ERR_OK);
    }

    sr_unsubscribe(sub);
    sr_disconnect(conn);
    return 0;
}

/* TEST */
static void *
test_conn_create_thread(void *arg)
{
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    int r;

    (void)arg;

    /* keep creating and destroying connections */
    for (int i = 0; i < 3; ++i) {
        r = sr_connect(0, &conn);
        sr_assert_true_ret(r == SR_ERR_OK, (void *)1);
        r = sr_session_start(conn, SR_DS_RUNNING, &sess);
        sr_assert_true_ret(r == SR_ERR_OK, (void *)1);

        r = sr_session_stop(sess);
        sr_assert_true_ret(r == SR_ERR_OK, (void *)1);
        r = sr_disconnect(conn);
        sr_assert_true_ret(r == SR_ERR_OK, (void *)1);
    }

    return NULL;
}

static int
test_conn_create(int rp, int wp)
{
    const int NUM_THREADS = 3;
    const int NUM_ITERS = 2;
    void *tret;
    int i, j, ret = 0;

    /* wait for the other process */
    barrier(rp, wp);

    pthread_t tid[NUM_THREADS];

    /* keep creating and destroying connections */
    for (j = 0; !ret && (j < NUM_ITERS); j++) {
        for (i = 0; i < NUM_THREADS; ++i) {
            pthread_create(&tid[i], NULL, test_conn_create_thread, NULL);
        }

        for (i = 0; i < NUM_THREADS; ++i) {
            pthread_join(tid[i], &tret);
            if (tret) {
                ret = 1;
            }
        }
    }

    return ret;
}

/* TEST */
typedef struct state_s {
    sr_conn_ctx_t *conn;
    int tid;
} state_t;

static void *
test_apply_thread(void *arg)
{
    state_t *state = (state_t *) arg;

    const int NUM_ITERS = 20;
    sr_session_ctx_t *sess;
    int r, i;

    r = sr_session_start(state->conn, SR_DS_RUNNING, &sess);
    sr_assert_true_ret(r == SR_ERR_OK, (void *)1);

    char key[128];

    snprintf(key, sizeof(key), "/ietf-interfaces:interfaces/interface[name='eth%d']/type", state->tid);

    for (i = 0; i < NUM_ITERS; i++) {
        r = sr_set_item_str(sess, key, "iana-if-type:ethernetCsmacd", NULL, 0);
        sr_assert_true_ret(r == SR_ERR_OK, (void *)1);
        r = sr_apply_changes(sess, 0);
        sr_assert_true_ret(r == SR_ERR_OK, (void *)1);

        r = sr_set_item_str(sess, key, "iana-if-type:other", NULL, 0);
        sr_assert_true_ret(r == SR_ERR_OK, (void *)1);
        r = sr_apply_changes(sess, 0);
        sr_assert_true_ret(r == SR_ERR_OK, (void *)1);
    }

    sr_session_stop(sess);
    return NULL;
}

static int
test_apply(int rp, int wp)
{
    int ret = 0, r, i, j;
    sr_conn_ctx_t *conn;
    void *tret;
    const int NUM_ITERS = 10;
    const int NUM_THREADS = 2;
    pthread_t tid[NUM_THREADS];
    state_t states[NUM_THREADS];

    r = sr_connect(0, &conn);
    sr_assert_true(r == SR_ERR_OK);

    barrier(rp, wp);
    for (j = 0; !ret && (j < NUM_ITERS); j++) {
        for (i = 0; i < NUM_THREADS; ++i) {
            states[i].tid = i;
            states[i].conn = conn;
            pthread_create(&tid[i], NULL, test_apply_thread, &states[i]);
        }

        for (i = 0; i < NUM_THREADS; ++i) {
            pthread_join(tid[i], &tret);
            if (tret) {
                ret = 1;
            }
        }
    }

    sr_disconnect(conn);
    return ret;
}

static void *
test_sub_thread(void *arg)
{
    const int NUM_ITERS = 20;
    state_t *state = (state_t *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *sub = NULL;
    int r, i;

    r = sr_session_start(state->conn, SR_DS_RUNNING, &sess);
    sr_assert_true_ret(r == SR_ERR_OK, (void *)1);

    for (i = 0; i < NUM_ITERS; i++) {
        r = sr_module_change_subscribe(sess, "ietf-interfaces", NULL, dummy_change_cb, NULL, 0, 0, &sub);
        sr_assert_true_ret(r == SR_ERR_OK, (void *)1);
        r = sr_unsubscribe(sub);
        sub = NULL;
        sr_assert_true_ret(r == SR_ERR_OK, (void *)1);
    }

    sr_session_stop(sess);
    return NULL;
}

static int
test_sub(int rp, int wp)
{
    int ret, i, j;
    sr_conn_ctx_t *conn;
    const int NUM_ITERS = 25;
    const int NUM_THREADS = 3;
    pthread_t tid[NUM_THREADS];
    state_t states[NUM_THREADS];

    ret = sr_connect(0, &conn);
    sr_assert_true(ret == SR_ERR_OK);

    barrier(rp, wp);
    for (j = 0; j < NUM_ITERS; j++) {
        for (i = 0; i < NUM_THREADS; ++i) {
            states[i].tid = i;
            states[i].conn = conn;
            pthread_create(&tid[i], NULL, test_sub_thread, &states[i]);
        }

        for (i = 0; i < NUM_THREADS; ++i) {
            pthread_join(tid[i], NULL);
        }
    }

    sr_disconnect(conn);
    return 0;
}

typedef enum test_sr_event_e {
    SR_EV_OPER_GET = (SR_EV_RPC + 1),
    SR_EV_NOTIF,
    SR_EV_NONE,
    SR_EV_ALL
} test_sr_event_t;

static const char *
ev_to_str(uint32_t ev)
{
    switch (ev) {
    case SR_EV_UPDATE:
        return "update";
    case SR_EV_CHANGE:
        return "change";
    case SR_EV_DONE:
        return "done";
    case SR_EV_ABORT:
        return "abort";
    case SR_EV_RPC:
        return "rpc";
    case SR_EV_OPER_GET:
        return "oper-get";
    case SR_EV_NOTIF:
        return "notif";
    case SR_EV_NONE:
        return "none";
    default:
        return "all";
    }
}

typedef enum {
    CREATE_CHANGE_SUB,
    CREATE_OPER_GET_SUB,
    CREATE_OPER_POLL_SUB,
    CREATE_NOTIF_SUB,
    CREATE_RPC_SUB
} subscr_type_t;

static const char *subscr_type_strings[] = {
    "change sub", "oper-get sub", "oper-poll sub", "notif sub", "rpc sub"
};

struct cb_data {
    uint32_t exit_mask;
    uint32_t exit_rc;
};

static void
conditional_exit(struct cb_data *data, int ev, sr_session_ctx_t *session, struct lyd_node **parent)
{
    uint32_t event = (uint32_t)ev;
    sr_conn_ctx_t *conn = NULL;

    if (data->exit_mask & (1 << event)) {
        if (parent && *parent) {
            lyd_free_all(*parent);
            *parent = NULL;
        }
        /* avoid leaks (valgrind probably cannot keep track of leafref attributes because they are shared) */
        conn = sr_session_get_connection(session);
        for (uint32_t i = 0; i < session->conn->ds_handle_count; ++i) {
            if (session->conn->ds_handles[i].init) {
                session->conn->ds_handles[i].plugin->conn_destroy_cb(session->conn, session->conn->ds_handles[i].plg_data);
            }
        }
        sr_session_stop(session);
        ly_ctx_destroy((struct ly_ctx *)sr_acquire_context(conn));
        sr_release_context(conn);
        /* exit_rc is set to EXIT_FAILURE if callback was not expected to be called */
        TLOG_INF("Exiting with %d as event \"%s\" received", data->exit_rc, ev_to_str(event));
        sr_assert(data->exit_rc == EXIT_SUCCESS);
        exit(EXIT_SUCCESS);
    }
}

static int
wait_for_children()
{
    int ret = 0;
    pid_t pid;

    TLOG_INF("wait for spawned processes to finish");
    while ((pid = wait(&ret)) > 0) {
        sr_assert_true(WIFEXITED(ret));
        TLOG_INF("pid %d exited status %d", pid, WEXITSTATUS(ret));
        sr_assert_int_equal(WEXITSTATUS(ret), EXIT_SUCCESS);
    }
    return 0;
}

static int
module_change_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data)
{
    struct cb_data *pvt_data = (struct cb_data *)private_data;

    (void)session;
    (void)sub_id;
    (void)module_name;
    (void)xpath;
    (void)event;
    (void)request_id;
    conditional_exit(pvt_data, event, session, NULL);
    return SR_ERR_OK;
}

static int
cond_fail_oper_get_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    struct cb_data *pvt_data = (struct cb_data *)private_data;

    (void)session;
    (void)sub_id;
    (void)module_name;
    (void)xpath;
    (void)request_xpath;
    (void)request_id;
    (void)parent;

    conditional_exit(pvt_data, SR_EV_OPER_GET, session, parent);
    return SR_ERR_OK;
}

static void
cond_fail_notif_cb(sr_session_ctx_t *session, uint32_t sub_id, const sr_ev_notif_type_t notif_type, const char *path,
        const sr_val_t *values, const size_t values_cnt, struct timespec *timestamp, void *private_data)
{
    struct cb_data *pvt_data = (struct cb_data *)private_data;

    (void)session;
    (void)sub_id;
    (void)notif_type;
    (void)path;
    (void)values;
    (void)values_cnt;
    (void)timestamp;
    switch (notif_type) {
    case SR_EV_NOTIF_TERMINATED:
    case SR_EV_NOTIF_SUSPENDED:
        /* Ignore these events as they are not on the handler thread */
        return;
    default:
        break;
    }
    conditional_exit(pvt_data, SR_EV_NOTIF, session, NULL);
}

static int
cond_fail_rpc_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const sr_val_t *input, const size_t input_cnt,
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
    struct cb_data *pvt_data = (struct cb_data *)private_data;

    (void)session;
    (void)sub_id;
    (void)op_path;
    (void)input;
    (void)input_cnt;
    (void)event;
    (void)request_id;
    (void)output;
    (void)output_cnt;
    conditional_exit(pvt_data, event, session, NULL);
    return SR_ERR_OK;
}

static int
keep_subs_alive(sr_session_ctx_t *sess)
{
    int ret;

    ret = sr_session_switch_ds(sess, SR_DS_OPERATIONAL);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(sess, "/test:test-leaf", "1", NULL, 0);
    sr_assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    sr_assert_int_equal(ret, SR_ERR_OK);
    return 0;
}

static void
fork_and_create_subs(subscr_type_t subscr_type, uint32_t priority, uint32_t fail_ev)
{
    struct cb_data pvt_data;
    sr_subscription_ctx_t *subscr = NULL;
    sr_conn_ctx_t *conn = NULL;
    sr_session_ctx_t *sess = NULL;
    char data[32] = "";
    int ret, pipe_fds[2];
    char xpath[512];
    uint32_t opts = SR_SUBSCR_NO_THREAD;

    pipe(pipe_fds);
    sr_data_t *sr_data = NULL;

    switch (fork()) {
    case 0:
        /* child */
        break;
    case -1:
        /* fork failed */
        sr_assert(0);
    default:
        /* parent */
        close(pipe_fds[1]);
        read(pipe_fds[0], &data, sizeof("sub-ready"));
        close(pipe_fds[0]);
        return;
    }

    pvt_data.exit_mask = 1 << fail_ev;
    pvt_data.exit_rc = EXIT_SUCCESS;

    sprintf(xpath, "/ietf-interfaces:interfaces-state/interface[name='eth%u']/statistics", priority);
    ret = sr_connect(0, &conn);
    sr_assert(ret == SR_ERR_OK);
    ret = sr_session_start(conn, SR_DS_RUNNING, &sess);
    sr_assert(ret == SR_ERR_OK);

    TLOG_INF("Creating subscription %s failing for event %s priority %u", subscr_type_strings[subscr_type], ev_to_str(fail_ev), priority);
    switch (subscr_type) {
    case CREATE_CHANGE_SUB:
        /* create a sub that fails during update event */
        ret = sr_module_change_subscribe(sess, "ietf-interfaces", NULL, module_change_cb, &pvt_data, priority, opts | SR_SUBSCR_UPDATE, &subscr);
        sr_assert(ret == SR_ERR_OK);
        break;
    case CREATE_OPER_GET_SUB:
        ret = sr_session_switch_ds(sess, SR_DS_OPERATIONAL);
        sr_assert(ret == SR_ERR_OK);

        ret = sr_oper_get_subscribe(sess, "ietf-interfaces", xpath, cond_fail_oper_get_cb,
                &pvt_data, opts | SR_SUBSCR_OPER_MERGE, &subscr);
        sr_assert(ret == SR_ERR_OK);
        break;
    case CREATE_OPER_POLL_SUB:
        ret = sr_session_switch_ds(sess, SR_DS_OPERATIONAL);
        sr_assert(ret == SR_ERR_OK);

        ret = sr_oper_poll_subscribe(sess, "ietf-interfaces", xpath, 300, opts, &subscr);
        sr_assert(ret == SR_ERR_OK);
        if (fail_ev != SR_EV_NONE) {
            write(pipe_fds[1], "sub-ready", sizeof("sub-ready"));
            close(pipe_fds[1]);
            conditional_exit(&pvt_data, fail_ev, sess, NULL);
        }
        break;
    case CREATE_NOTIF_SUB:
        ret = sr_notif_subscribe(sess, "ops", NULL, 0, 0, cond_fail_notif_cb, &pvt_data, opts, &subscr);
        sr_assert(ret == SR_ERR_OK);
        break;
    case CREATE_RPC_SUB:
        ret = sr_rpc_subscribe(sess, "/ops:rpc3", cond_fail_rpc_cb, &pvt_data, priority, opts, &subscr);
        sr_assert(ret == SR_ERR_OK);
        break;
    default:
        break;
    }
    write(pipe_fds[1], "sub-ready", sizeof("sub-ready"));
    close(pipe_fds[1]);
    TLOG_INF("Created subscription %s failing for event %s priority %u", subscr_type_strings[subscr_type], ev_to_str(fail_ev), priority);

    ret = sr_session_switch_ds(sess, SR_DS_OPERATIONAL);
    sr_assert(ret == SR_ERR_OK);
    do {
        sr_release_data(sr_data);
        sr_data = NULL;
        sr_subscription_process_events(subscr, NULL, NULL);
        usleep(10000);
        ret = sr_get_node(sess, "/test:test-leaf", 0, &sr_data);
    } while (!ret && sr_data);

    /* make sure we weren't supposed to crash */
    sr_assert(fail_ev == SR_EV_NONE);
    sr_disconnect(conn);
    exit(EXIT_SUCCESS);
}

static int
test_recover_change_sub_apply(int rp, int wp)
{
    sr_conn_ctx_t *conn = NULL;
    sr_session_ctx_t *sess = NULL;
    int i, ret;

    ret = sr_connect(0, &conn);
    sr_assert_int_equal(ret, SR_ERR_OK);
    ret = sr_session_start(conn, SR_DS_OPERATIONAL, &sess);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = keep_subs_alive(sess);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_switch_ds(sess, SR_DS_RUNNING);
    sr_assert_int_equal(ret, SR_ERR_OK);

    barrier(rp, wp);
    TLOG_INF("wait for subs to be ready");
    barrier(rp, wp);
    TLOG_INF("make changes that will cause the crashes");

    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth0']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    sr_assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    sr_assert_int_equal(ret, SR_ERR_OK);

    for (i = 0, ret = 1; ret && i < 10; i++) {
        ret = sr_apply_changes(sess, 500);
    }

    /* Few attempts above can fail because subscribers are dying */
    ret = sr_apply_changes(sess, 0);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = sr_disconnect(conn);
    sr_assert_int_equal(ret, SR_ERR_OK);

    barrier(rp, wp);
    return 0;
}

static int
test_recover_change_sub(int rp, int wp)
{
    int ret;

    barrier(rp, wp);

    TLOG_INF("create subscriptions that don't crash at priority 1");
    fork_and_create_subs(CREATE_CHANGE_SUB, 1, SR_EV_NONE);

    TLOG_INF("create subscriptions crash at an appropriate event");
    fork_and_create_subs(CREATE_CHANGE_SUB, 10, SR_EV_UPDATE);
    fork_and_create_subs(CREATE_CHANGE_SUB, 11, SR_EV_UPDATE);
    fork_and_create_subs(CREATE_CHANGE_SUB, 12, SR_EV_CHANGE);
    fork_and_create_subs(CREATE_CHANGE_SUB, 13, SR_EV_DONE);
    fork_and_create_subs(CREATE_CHANGE_SUB, 14, SR_EV_ABORT);

    TLOG_INF("signal all subs setup");
    barrier(rp, wp);
    TLOG_INF("wait for crashes to happen");
    barrier(rp, wp);
    TLOG_INF("create subscription to recover the ext SHM");
    fork_and_create_subs(CREATE_CHANGE_SUB, 0, SR_EV_NONE);
    ret = wait_for_children();
    sr_assert_int_equal(ret, SR_ERR_OK);
    return 0;
}

static int
test_recover_oper_sub_get(int rp, int wp)
{
    sr_conn_ctx_t *conn = NULL;
    sr_session_ctx_t *sess = NULL;
    int i, ret;
    sr_data_t *data = NULL;

    ret = sr_connect(0, &conn);
    sr_assert_int_equal(ret, SR_ERR_OK);
    ret = sr_session_start(conn, SR_DS_OPERATIONAL, &sess);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = keep_subs_alive(sess);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces-state/interface[name='eth0']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces-state/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    sr_assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    sr_assert_int_equal(ret, SR_ERR_OK);

    barrier(rp, wp);
    TLOG_INF("wait for subs to be ready");
    barrier(rp, wp);
    TLOG_INF("read oper data to cause crashes");

    /* for oper get */
    for (i = 0; i < 3; i++) {
        data = NULL;
        ret = sr_get_data(sess, "/ietf-interfaces:*", 0, 100, 0, &data);
        sr_release_data(data);
    }

    ret = sr_disconnect(conn);
    sr_assert_int_equal(ret, SR_ERR_OK);

    barrier(rp, wp);
    return 0;
}

static int
test_recover_oper_sub(int rp, int wp)
{
    int ret;

    barrier(rp, wp);
    /* now create the ones that would die for eth0 */
    fork_and_create_subs(CREATE_OPER_GET_SUB, 0, SR_EV_OPER_GET);
    fork_and_create_subs(CREATE_OPER_GET_SUB, 0, SR_EV_NONE);
    fork_and_create_subs(CREATE_OPER_POLL_SUB, 0, SR_EV_ALL);

    barrier(rp, wp);
    barrier(rp, wp);

    TLOG_INF("create subscriptions to recover the ext SHM");
    fork_and_create_subs(CREATE_OPER_GET_SUB, 0, SR_EV_NONE);
    fork_and_create_subs(CREATE_OPER_POLL_SUB, 0, SR_EV_NONE);

    ret = wait_for_children();
    sr_assert_int_equal(ret, SR_ERR_OK);
    return 0;
}

static int
test_recover_rpc_sub_send(int rp, int wp)
{
    sr_conn_ctx_t *conn = NULL;
    sr_session_ctx_t *sess = NULL;
    int ret;
    sr_val_t input, *output;
    size_t output_count;

    ret = sr_connect(0, &conn);
    sr_assert_int_equal(ret, SR_ERR_OK);
    ret = sr_session_start(conn, SR_DS_OPERATIONAL, &sess);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = keep_subs_alive(sess);
    sr_assert_int_equal(ret, SR_ERR_OK);
    barrier(rp, wp);
    TLOG_INF("wait for subs to be ready");
    barrier(rp, wp);
    TLOG_INF("send rpc to cause crash");

    /* rpc sub */
    input.xpath = "/ops:rpc3/l4";
    input.type = SR_STRING_T;
    input.data.string_val = "dummy";
    input.dflt = 0;

    ret = sr_rpc_send(sess, "/ops:rpc3", &input, 1, 1000, &output, &output_count);
    sr_assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);

    ret = sr_rpc_send(sess, "/ops:rpc3", &input, 1, 0, &output, &output_count);
    sr_assert_int_equal(ret, SR_ERR_OK);

    sr_free_values(output, output_count);
    ret = sr_disconnect(conn);
    sr_assert_int_equal(ret, SR_ERR_OK);

    barrier(rp, wp);
    return 0;
}

static int
test_recover_rpc_sub(int rp, int wp)
{
    int ret;

    barrier(rp, wp);
    /* now create the ones that can die */

    fork_and_create_subs(CREATE_RPC_SUB, 10, SR_EV_RPC);
    fork_and_create_subs(CREATE_RPC_SUB, 11, SR_EV_ABORT);

    /* create subscriptions that don't crash at priority 0 */
    fork_and_create_subs(CREATE_RPC_SUB, 0, SR_EV_NONE);

    barrier(rp, wp);
    barrier(rp, wp);

    TLOG_INF("create subscriptions to recover the ext SHM");
    fork_and_create_subs(CREATE_RPC_SUB, 1, SR_EV_NONE);

    ret = wait_for_children();
    sr_assert_int_equal(ret, SR_ERR_OK);
    return 0;
}

static int
test_recover_notif_sub_send(int rp, int wp)
{
    sr_conn_ctx_t *conn = NULL;
    sr_session_ctx_t *sess = NULL;
    int ret, i;

    ret = sr_connect(0, &conn);
    sr_assert_int_equal(ret, SR_ERR_OK);
    ret = sr_session_start(conn, SR_DS_OPERATIONAL, &sess);
    sr_assert_int_equal(ret, SR_ERR_OK);

    ret = keep_subs_alive(sess);
    sr_assert_int_equal(ret, SR_ERR_OK);
    barrier(rp, wp);
    TLOG_INF("wait for subs to be ready");
    barrier(rp, wp);
    TLOG_INF("send rpc to cause crash");

    /* notif sub */
    for (i = 0; i < 3; i++) {
        ret = sr_notif_send(sess, "/ops:notif4", NULL, 0, 100, 1);
        sr_assert_int_equal(ret, SR_ERR_OK);
    }

    ret = sr_disconnect(conn);
    sr_assert_int_equal(ret, SR_ERR_OK);

    barrier(rp, wp);
    return 0;
}

static int
test_recover_notif_sub(int rp, int wp)
{
    int ret;

    barrier(rp, wp);
    /* now create the ones that can die */
    fork_and_create_subs(CREATE_NOTIF_SUB, 10, SR_EV_NOTIF);
    fork_and_create_subs(CREATE_NOTIF_SUB, 11, SR_EV_NONE);

    /* create subscriptions that don't crash at priority 0 */
    fork_and_create_subs(CREATE_RPC_SUB, 0, SR_EV_NONE);

    barrier(rp, wp);
    barrier(rp, wp);

    TLOG_INF("create subscriptions to recover the ext SHM");
    fork_and_create_subs(CREATE_NOTIF_SUB, 0, SR_EV_NONE);

    ret = wait_for_children();
    sr_assert_int_equal(ret, SR_ERR_OK);
    return 0;
}

int
main(void)
{
    struct test tests[] = {
        {"rpc sub", test_rpc_sub1, test_rpc_sub2, setup, teardown},
        {"rpc crash", test_rpc_crash1, test_rpc_crash2, setup, teardown},
        {"oper crash", test_oper_crash_set2, test_oper_crash_set1, setup, teardown},
        {"notif nowait crash", test_notif_nowait_crash2, test_notif_nowait_crash1, setup, teardown},
        {"notif instid", test_notif_instid1, test_notif_instid2, setup, teardown},
        {"pull push oper data", test_pull_push_oper1, test_pull_push_oper2, setup, teardown},
        {"context change", test_context_change, test_context_change_sub, setup, teardown},
        {"conn create", test_conn_create, test_conn_create, setup, teardown},
        {"sub apply", test_sub, test_apply, setup, teardown},
        {"recover-change-sub", test_recover_change_sub_apply, test_recover_change_sub, setup, teardown},
        {"recover-oper-sub", test_recover_oper_sub_get, test_recover_oper_sub, setup, teardown},
        {"recover-rpc-sub", test_recover_rpc_sub_send, test_recover_rpc_sub, setup, teardown},
        {"recover-notif-sub", test_recover_notif_sub_send, test_recover_notif_sub, setup, teardown},
    };

    test_log_init();
    run_tests(tests, sizeof tests / sizeof *tests);
    return 0;
}
