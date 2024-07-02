/**
 * @file test_multi_connection.c
 * @author Ian Miller <imiller@adva.com>
 * @brief test for edits performed using multiple connections
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
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "sysrepo.h"
#include "tests/tcommon.h"

struct state {
    sr_conn_ctx_t *conn1;
    sr_conn_ctx_t *conn2;
    sr_conn_ctx_t *conn3;
    sr_session_ctx_t *sess1;
    sr_session_ctx_t *sess2;
    sr_session_ctx_t *sess3;
    pthread_barrier_t barrier;
};

static int
setup_f(void **state)
{
    struct state *st;
    const char *schema_paths[] = {
        TESTS_SRC_DIR "/files/test.yang",
        TESTS_SRC_DIR "/files/ietf-interfaces.yang",
        TESTS_SRC_DIR "/files/iana-if-type.yang",
        TESTS_SRC_DIR "/files/ops.yang",
        NULL
    };

    st = calloc(1, sizeof *st);
    *state = st;

    /* connection 1 */
    if (sr_connect(0, &(st->conn1)) != SR_ERR_OK) {
        return 1;
    }
    if (sr_session_start(st->conn1, SR_DS_RUNNING, &st->sess1) != SR_ERR_OK) {
        return 1;
    }

    /* connection 2 */
    if (sr_connect(0, &(st->conn2)) != SR_ERR_OK) {
        return 1;
    }
    if (sr_session_start(st->conn2, SR_DS_RUNNING, &st->sess2) != SR_ERR_OK) {
        return 1;
    }

    /* connection 3 */
    if (sr_connect(0, &(st->conn3)) != SR_ERR_OK) {
        return 1;
    }
    if (sr_session_start(st->conn3, SR_DS_RUNNING, &st->sess3) != SR_ERR_OK) {
        return 1;
    }

    if (sr_install_modules(st->conn1, schema_paths, TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }

    return 0;
}

static int
teardown_f(void **state)
{
    struct state *st = (struct state *)*state;
    const char *module_names[] = {
        "ietf-interfaces",
        "iana-if-type",
        "test",
        "ops",
        NULL
    };

    sr_remove_modules(st->conn1, module_names, 0);

    sr_disconnect(st->conn1);
    sr_disconnect(st->conn2);
    sr_disconnect(st->conn3);
    free(st);
    return 0;
}

static int
clear_interfaces(void **state)
{
    struct state *st = (struct state *)*state;

    sr_delete_item(st->sess1, "/ietf-interfaces:interfaces", 0);
    sr_apply_changes(st->sess1, 0);

    sr_discard_oper_changes(st->conn1, NULL, NULL, 0);
    sr_discard_oper_changes(st->conn2, NULL, NULL, 0);
    sr_discard_oper_changes(st->conn3, NULL, NULL, 0);

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

static void
test_create1(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *subtree;
    char *str;
    int ret;

    /* Create via two connections, retrieve by a third */
    ret = sr_set_item_str(st->sess1, "/ietf-interfaces:interfaces/interface[name='ethS1']", NULL, NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess1, "/ietf-interfaces:interfaces/interface[name='ethS1']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess1, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess2, "/ietf-interfaces:interfaces/interface[name='ethS2']", NULL, NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess2, "/ietf-interfaces:interfaces/interface[name='ethS2']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess2, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_subtree(st->sess3, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    lyd_print_mem(&str, subtree->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    sr_release_data(subtree);

    const char *ptr = strstr(str, "ethS1");

    assert_non_null(ptr);
    ptr = strstr(str, "ethS2");
    assert_non_null(ptr);
    ptr = strstr(str, "ethS3");
    assert_null(ptr);

    free(str);
}

static void *
new_conn_thread(void *arg)
{
    sr_conn_ctx_t *conn;

    (void)arg;

    assert_int_equal(SR_ERR_OK, sr_connect(0, &conn));
    sr_disconnect(conn);

    return NULL;
}

static void
test_new(void **state)
{
    struct state *st = (struct state *)*state;
    const int thread_count = 10;
    int i;
    pthread_t tid[thread_count];

    pthread_barrier_init(&st->barrier, NULL, thread_count);

    for (i = 0; i < thread_count; ++i) {
        pthread_create(&tid[i], NULL, new_conn_thread, NULL);
    }
    for (i = 0; i < thread_count; ++i) {
        pthread_join(tid[i], NULL);
    }

    pthread_barrier_destroy(&st->barrier);
}

static void
test_sub_suspend_helper(sr_subscription_ctx_t *subscr, int suspend)
{
    uint32_t sub_id;
    int ret;

    if (!suspend) {
        return;
    }
    sub_id = sr_subscription_get_last_sub_id(subscr);
    ret = sr_subscription_suspend(subscr, sub_id);
    assert_int_equal(ret, 0);
}

struct cb_data {
    uint32_t exit_mask;
    uint32_t exit_rc;
};

static void
conditional_exit(struct cb_data *data, int ev)
{
    uint32_t event = (uint32_t)ev;

    if (data->exit_mask & (1 << event)) {
        /* exit_rc is set to EXIT_FAILURE if callback was not expected to be called */
        assert_int_equal(data->exit_rc, EXIT_SUCCESS);
        TLOG_INF("Exiting as event \"%s\" received", ev_to_str(event));
        exit(0);
    }
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
    conditional_exit(pvt_data, event);
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
    conditional_exit(pvt_data, SR_EV_OPER_GET);
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

    conditional_exit(pvt_data, SR_EV_NOTIF);
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
    conditional_exit(pvt_data, event);
    return SR_ERR_OK;
}

static void
test_sub_suspend(void **state)
{
    struct state *st = (struct state *)*state;
    int i, j, ret;
    sr_subscription_ctx_t *subscr[5] = {NULL};
    struct cb_data pvt_data[2];
    char xpath[128] = "";
    const char *rpc_xpath[] = {
        "/ops:rpc3",
        "/ops:rpc2"
    };

    sr_val_t input, *output;
    size_t output_count;

    sr_data_t *data;

    /* Create two subscriptions of each kind and suspend the second */
    for (i = 1; i >= 0; i--) {
        j = 0;
        /* make the first one fail if invoked in a suspended state */
        pvt_data[i].exit_mask = i ? 0xFFFFFFFF : 0;
        pvt_data[i].exit_rc = EXIT_FAILURE;

        /* change_sub */
        ret = sr_module_change_subscribe(st->sess1, "ietf-interfaces", NULL, module_change_cb, &pvt_data[i], 0, 0, &subscr[j]);
        assert_int_equal(ret, SR_ERR_OK);
        test_sub_suspend_helper(subscr[j], i);
        j++;
        /* oper get sub */
        sprintf(xpath, "/ietf-interfaces:interfaces-state/interface[name='eth%d']/statistics", i);
        ret = sr_oper_get_subscribe(st->sess1, "ietf-interfaces", xpath, cond_fail_oper_get_cb,
                &pvt_data[i], 0, &subscr[j]);
        assert_int_equal(ret, SR_ERR_OK);
        test_sub_suspend_helper(subscr[j], i);
        j++;

        /* oper poll sub */
        ret = sr_oper_poll_subscribe(st->sess1, "ietf-interfaces", xpath, 3000, 0, &subscr[j]);
        assert_int_equal(ret, SR_ERR_OK);
        test_sub_suspend_helper(subscr[j], i);
        j++;

        /* notification subscriptions */
        ret = sr_notif_subscribe(st->sess1, "ops", NULL, 0, 0, cond_fail_notif_cb, &pvt_data[i], 0, &subscr[j]);
        assert_int_equal(ret, SR_ERR_OK);
        test_sub_suspend_helper(subscr[j], i);
        j++;

        /* RPC/action subscriptions */
        ret = sr_rpc_subscribe(st->sess1, rpc_xpath[i], cond_fail_rpc_cb, &pvt_data[i], 0, 0, &subscr[j]);
        assert_int_equal(ret, SR_ERR_OK);
        test_sub_suspend_helper(subscr[j], i);
    }

    /* for change_sub */
    ret = sr_set_item_str(st->sess1, "/ietf-interfaces:interfaces/interface[name='eth0']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess1, "/ietf-interfaces:interfaces/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess1, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_switch_ds(st->sess2, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess2, "/ietf-interfaces:interfaces-state/interface[name='eth0']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess2, "/ietf-interfaces:interfaces-state/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess2, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_switch_ds(st->sess3, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* for oper get */
    for (i = 0; i < 10; i++) {
        ret = sr_get_data(st->sess3, "/ietf-interfaces:*", 0, 0, 0, &data);
        assert_int_equal(ret, SR_ERR_OK);
        assert_non_null(data);
        sr_release_data(data);
    }

    ret = sr_session_switch_ds(st->sess3, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
    /* notif sub */
    ret = sr_notif_send(st->sess3, "/ops:notif4", NULL, 0, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* rpc sub */
    input.xpath = "/ops:rpc3/l4";
    input.type = SR_STRING_T;
    input.data.string_val = "dummy";
    input.dflt = 0;

    ret = sr_rpc_send(st->sess3, "/ops:rpc3", &input, 1, 0, &output, &output_count);
    assert_int_equal(ret, SR_ERR_OK);

    sr_free_values(output, output_count);
    /* unsubscribe and clean up */
    while (j >= 0) {
        ret = sr_unsubscribe(subscr[j]);
        assert_int_equal(ret, SR_ERR_OK);
        j--;
    }

    /* discard all operational data */
    ret = sr_discard_items(st->sess2, NULL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess2, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_switch_ds(st->sess2, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
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

static void
wait_for_test_to_finish(sr_session_ctx_t *sess)
{
    sr_data_t *data = NULL;
    int count = 300;
    int ret = 0;

    ret = sr_session_switch_ds(sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);
    do {
        sr_release_data(data);
        data = NULL;
        /* avoid running forever */
        assert_true(--count > 0);
        usleep(100000);
        ret = sr_get_node(sess, "/test:test-leaf", 0, &data);
    } while (!ret && data);
}

static void
keep_subs_alive(sr_session_ctx_t *sess)
{
    int ret;

    ret = sr_session_switch_ds(sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(sess, "/test:test-leaf", "1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
stop_subscriptions(sr_session_ctx_t *sess)
{
    int ret = 0;

    ret = sr_discard_items(sess, "/test:test-leaf");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
    /* wait for spawned processes to finish */
    while (wait(&ret) > 0) {
        assert_true(WIFEXITED(ret));
        assert_int_equal(WEXITSTATUS(ret), EXIT_SUCCESS);
    }
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

    pipe(pipe_fds);

    sprintf(xpath, "/ietf-interfaces:interfaces-state/interface[name='eth%u']/statistics", priority);
    switch (fork()) {
    case 0:
        /* child */
        break;
    case -1:
        /* fork failed */
        fail();
    default:
        /* parent */
        close(pipe_fds[1]);
        read(pipe_fds[0], &data, sizeof("sub-ready"));
        close(pipe_fds[0]);
        return;
    }

    pvt_data.exit_mask = 1 << fail_ev;
    pvt_data.exit_rc = EXIT_SUCCESS;
    ret = sr_connect(0, &conn);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_session_start(conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Creating subscription %s failing for event %s priority %u", subscr_type_strings[subscr_type], ev_to_str(fail_ev), priority);

    switch (subscr_type) {
    case CREATE_CHANGE_SUB:
        /* create a sub that fails during update event */
        ret = sr_module_change_subscribe(sess, "ietf-interfaces", NULL, module_change_cb, &pvt_data, priority, SR_SUBSCR_UPDATE, &subscr);
        assert_int_equal(ret, SR_ERR_OK);
        break;
    case CREATE_OPER_GET_SUB:
        ret = sr_session_switch_ds(sess, SR_DS_OPERATIONAL);
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_oper_get_subscribe(sess, "ietf-interfaces", xpath, cond_fail_oper_get_cb,
                &pvt_data, 0, &subscr);
        assert_int_equal(ret, SR_ERR_OK);
        break;
    case CREATE_OPER_POLL_SUB:
        ret = sr_session_switch_ds(sess, SR_DS_OPERATIONAL);
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_oper_poll_subscribe(sess, "ietf-interfaces", xpath, 300, 0, &subscr);
        assert_int_equal(ret, SR_ERR_OK);
        if (fail_ev != SR_EV_NONE) {
            exit(0);
        }
        break;
    case CREATE_NOTIF_SUB:
        ret = sr_notif_subscribe(sess, "ops", NULL, 0, 0, cond_fail_notif_cb, &pvt_data, 0, &subscr);
        assert_int_equal(ret, SR_ERR_OK);
        break;
    case CREATE_RPC_SUB:
        ret = sr_rpc_subscribe(sess, "/ops:rpc3", cond_fail_rpc_cb, &pvt_data, priority, 0, &subscr);
        assert_int_equal(ret, SR_ERR_OK);
        break;
    default:
        break;
    }

    write(pipe_fds[1], "sub-ready", sizeof("sub-ready"));
    close(pipe_fds[1]);
    TLOG_INF("Created subscription %s failing for event %s priority %u", subscr_type_strings[subscr_type], ev_to_str(fail_ev), priority);

    /* wait until parent wants us to */
    wait_for_test_to_finish(sess);

    sr_disconnect(conn);
    assert_int_equal(fail_ev, SR_EV_NONE);
    exit(EXIT_SUCCESS);
}

static void
test_recover_change_sub(void **state)
{
    struct state *st = (struct state *)*state;
    int i, ret;

    ret = sr_session_switch_ds(st->sess3, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);
    keep_subs_alive(st->sess3);

    /* create subscriptions that don't crash at priority 0 */
    fork_and_create_subs(CREATE_CHANGE_SUB, 10, SR_EV_UPDATE);
    fork_and_create_subs(CREATE_CHANGE_SUB, 11, SR_EV_UPDATE);
    fork_and_create_subs(CREATE_CHANGE_SUB, 12, SR_EV_CHANGE);
    fork_and_create_subs(CREATE_CHANGE_SUB, 13, SR_EV_DONE);
    fork_and_create_subs(CREATE_CHANGE_SUB, 14, SR_EV_ABORT);
    fork_and_create_subs(CREATE_CHANGE_SUB, 0, SR_EV_NONE);

    /* for change_sub */
    ret = sr_set_item_str(st->sess1, "/ietf-interfaces:interfaces/interface[name='eth0']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess1, "/ietf-interfaces:interfaces/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    for (i = 0, ret = 1; ret && i < 10; i++) {
        ret = sr_apply_changes(st->sess1, 100);
    }

    /* Few attempts above can fail because subscribers are dying */
    ret = sr_apply_changes(st->sess1, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for spawned processes to finish */
    stop_subscriptions(st->sess3);
    TLOG_INF("create subscription to recover the ext SHM");
    fork_and_create_subs(CREATE_CHANGE_SUB, 0, SR_EV_NONE);
    stop_subscriptions(st->sess3);
}

static void
test_recover_oper_sub(void **state)
{
    struct state *st = (struct state *)*state;
    int i, ret;
    sr_data_t *data;

    keep_subs_alive(st->sess3);

    ret = sr_session_switch_ds(st->sess2, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess2, "/ietf-interfaces:interfaces-state/interface[name='eth0']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess2, "/ietf-interfaces:interfaces-state/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess2, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* now create the ones that would die for eth0 */
    fork_and_create_subs(CREATE_OPER_GET_SUB, 0, SR_EV_OPER_GET);
    fork_and_create_subs(CREATE_OPER_POLL_SUB, 0, SR_EV_ALL);

    /* create subscriptions that don't crash for eth1 */
    fork_and_create_subs(CREATE_OPER_GET_SUB, 1, SR_EV_NONE);

    /* this should recover the previous oper poll sub */
    fork_and_create_subs(CREATE_OPER_POLL_SUB, 0, SR_EV_NONE);

    /* for oper get */
    for (i = 0; i < 1; i++) {
        data = NULL;
        ret = sr_get_data(st->sess3, "/ietf-interfaces:*", 0, 1000, 0, &data);
        sr_release_data(data);
    }

    stop_subscriptions(st->sess3);

    TLOG_INF("create subscriptions to recover the ext SHM");
    fork_and_create_subs(CREATE_OPER_GET_SUB, 0, SR_EV_NONE);

    stop_subscriptions(st->sess3);
}

static void
test_recover_rpc_sub(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;
    sr_val_t input, *output;
    size_t output_count;

    ret = sr_session_switch_ds(st->sess3, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);
    keep_subs_alive(st->sess3);

    /* now create the ones that can die */

    fork_and_create_subs(CREATE_RPC_SUB, 10, SR_EV_RPC);
    fork_and_create_subs(CREATE_RPC_SUB, 11, SR_EV_ABORT);

    /* create subscriptions that don't crash at priority 0 */
    fork_and_create_subs(CREATE_RPC_SUB, 0, SR_EV_NONE);

    /* rpc sub */
    input.xpath = "/ops:rpc3/l4";
    input.type = SR_STRING_T;
    input.data.string_val = "dummy";
    input.dflt = 0;

    ret = sr_rpc_send(st->sess3, "/ops:rpc3", &input, 1, 1000, &output, &output_count);
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);

    ret = sr_rpc_send(st->sess3, "/ops:rpc3", &input, 1, 0, &output, &output_count);
    assert_int_equal(ret, SR_ERR_OK);

    sr_free_values(output, output_count);

    stop_subscriptions(st->sess3);

    TLOG_INF("create subscriptions to recover the ext SHM");
    fork_and_create_subs(CREATE_RPC_SUB, 1, SR_EV_NONE);

    stop_subscriptions(st->sess3);
}

static void
test_recover_notif_sub(void **state)
{
    struct state *st = (struct state *)*state;
    int i, ret;

    ret = sr_session_switch_ds(st->sess3, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);
    keep_subs_alive(st->sess3);

    fork_and_create_subs(CREATE_NOTIF_SUB, 10, SR_EV_NOTIF);
    fork_and_create_subs(CREATE_NOTIF_SUB, 11, SR_EV_NONE);

    /* notif sub */
    for (i = 0; i < 3; i++) {
        ret = sr_notif_send(st->sess3, "/ops:notif4", NULL, 0, 100, 1);
        assert_int_equal(ret, SR_ERR_OK);
    }
    stop_subscriptions(st->sess3);

    TLOG_INF("create subscriptions to recover the ext SHM");
    fork_and_create_subs(CREATE_NOTIF_SUB, 0, SR_EV_NONE);

    stop_subscriptions(st->sess3);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_create1, clear_interfaces),
        cmocka_unit_test(test_new),
        cmocka_unit_test_teardown(test_sub_suspend, clear_interfaces),
        cmocka_unit_test_teardown(test_recover_change_sub, clear_interfaces),
        cmocka_unit_test_teardown(test_recover_oper_sub, clear_interfaces),
        cmocka_unit_test_teardown(test_recover_rpc_sub, clear_interfaces),
        cmocka_unit_test_teardown(test_recover_notif_sub, clear_interfaces),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    test_log_init();
    return cmocka_run_group_tests(tests, setup_f, teardown_f);
}
