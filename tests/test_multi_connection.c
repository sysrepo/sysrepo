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
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "common.h"
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
        TESTS_SRC_DIR "/files/alarms.yang",
        TESTS_SRC_DIR "/files/example-module.yang",
        TESTS_SRC_DIR "/files/mixed-config.yang",
        TESTS_SRC_DIR "/files/simple.yang",
        TESTS_SRC_DIR "/files/test-module.yang",
        TESTS_SRC_DIR "/files/when1.yang",
        TESTS_SRC_DIR "/files/when2.yang",
        NULL
    };

    st = calloc(1, sizeof *st);
    *state = st;

    /* connection 1 */
    if (sr_connect(SR_CONN_CACHE_RUNNING, &(st->conn1)) != SR_ERR_OK) {
        return 1;
    }
    if (sr_session_start(st->conn1, SR_DS_RUNNING, &st->sess1) != SR_ERR_OK) {
        return 1;
    }

    /* connection 2 */
    if (sr_connect(SR_CONN_CACHE_RUNNING, &(st->conn2)) != SR_ERR_OK) {
        return 1;
    }
    if (sr_session_start(st->conn2, SR_DS_RUNNING, &st->sess2) != SR_ERR_OK) {
        return 1;
    }

    /* connection 3 */
    if (sr_connect(SR_CONN_CACHE_RUNNING, &(st->conn3)) != SR_ERR_OK) {
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
        "alarms",
        "example-module",
        "mixed-config",
        "simple",
        "test-module",
        "when1",
        "when2",
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

    /* restart sessions to flush Ext SHM data */
    sr_session_stop(st->sess1);
    sr_session_stop(st->sess2);
    sr_session_stop(st->sess3);

    sr_session_start(st->conn1, SR_DS_RUNNING, &st->sess1);
    sr_session_start(st->conn2, SR_DS_RUNNING, &st->sess2);
    sr_session_start(st->conn3, SR_DS_RUNNING, &st->sess3);

    return 0;
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
test_new_conn(void **state)
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
    int fail;
};

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
    if (pvt_data->fail) {
        /* was not expected to be called */
        fail();
    }
    return SR_ERR_OK;
}

static int
suspend_oper_get_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
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
    if (pvt_data->fail) {
        /* was not expected to be called */
        fail();
    }
    return SR_ERR_OK;
}

static void
suspend_notif_cb(sr_session_ctx_t *session, uint32_t sub_id, const sr_ev_notif_type_t notif_type, const char *path,
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

    if (pvt_data->fail) {
        /* was not expected to be called */
        fail();
    }
}

static int
suspend_rpc_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const sr_val_t *input, const size_t input_cnt,
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
    if (pvt_data->fail) {
        /* was not expected to be called */
        fail();
    }
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
        pvt_data[i].fail = i;

        /* change_sub */
        ret = sr_module_change_subscribe(st->sess1, "ietf-interfaces", NULL, module_change_cb, &pvt_data[i], 0, 0, &subscr[j]);
        assert_int_equal(ret, SR_ERR_OK);
        test_sub_suspend_helper(subscr[j], i);
        j++;
        /* oper get sub */
        sprintf(xpath, "/ietf-interfaces:interfaces-state/interface[name='eth%d']/statistics", i);
        ret = sr_oper_get_subscribe(st->sess1, "ietf-interfaces", xpath, suspend_oper_get_cb,
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
        ret = sr_notif_subscribe(st->sess1, "ops", NULL, 0, 0, suspend_notif_cb, &pvt_data[i], 0, &subscr[j]);
        assert_int_equal(ret, SR_ERR_OK);
        test_sub_suspend_helper(subscr[j], i);
        j++;

        /* RPC/action subscriptions */
        ret = sr_rpc_subscribe(st->sess1, rpc_xpath[i], suspend_rpc_cb, &pvt_data[i], 0, 0, &subscr[j]);
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
    ret = sr_discard_oper_changes(NULL, st->sess2, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_switch_ds(st->sess2, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
}

static void *
test_oper_read_helper(void *state)
{
    struct state *st = (struct state *)state;
    sr_session_ctx_t *sess = NULL;
    int i, ret;
    sr_data_t *data;
    static ATOMIC_T thread_id = 0;
    uint32_t id = ATOMIC_INC_RELAXED(thread_id);

    ret = sr_session_start(st->conn2, SR_DS_OPERATIONAL, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    for (i = 0; i < 3; i++) {
        ret = sr_get_data(sess, (id % 2) ? "/test:*" : "/ietf-interfaces:*", 0, 0, 0, &data);
        assert_int_equal(ret, SR_ERR_OK);
        sr_release_data(data);
    }

    ret = sr_session_stop(sess);
    assert_int_equal(ret, SR_ERR_OK);

    return NULL;
}

/* TEST */
static int
slow_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    (void)session;
    (void)sub_id;
    (void)module_name;
    (void)xpath;
    (void)request_xpath;
    (void)request_id;
    (void)parent;
    (void)private_data;

    /* Wait longer than run cache lock timeout */
    usleep(1000 * (1 + SR_CONN_RUN_CACHE_LOCK_TIMEOUT));

    return SR_ERR_OK;
}

static void
test_run_change_oper_get(void **state)
{
    struct state *st = (struct state *)*state;
    const int thread_count = 2;
    int i, ret;
    pthread_t tid[thread_count];
    sr_subscription_ctx_t *subscr = NULL;

    pthread_barrier_init(&st->barrier, NULL, thread_count + 1);
    /* register as a oper get subscriber */
    ret = sr_oper_get_subscribe(st->sess1, "ietf-interfaces", "/ietf-interfaces:interfaces-state", slow_oper_cb,
            NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_oper_get_subscribe(st->sess1, "test", "/test:l1", slow_oper_cb,
            NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    for (i = 0; i < thread_count; ++i) {
        pthread_create(&tid[i], NULL, test_oper_read_helper, st);
    }

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /* modify running datastore to invalidate run-cache */
    ret = sr_set_item_str(st->sess1, "/ietf-interfaces:interfaces/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess1, "/test:l1[k='key1']/v", "1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess1, 0);
    assert_int_equal(ret, SR_ERR_OK);

    sr_delete_item(st->sess1, "/ietf-interfaces:interfaces", 0);
    assert_int_equal(ret, SR_ERR_OK);

    sr_delete_item(st->sess1, "/test:l1", 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess1, 0);
    assert_int_equal(ret, SR_ERR_OK);

    for (i = 0; i < thread_count; ++i) {
        pthread_join(tid[i], NULL);
    }

    ret = sr_unsubscribe(subscr);
    assert_int_equal(ret, SR_ERR_OK);
    pthread_barrier_destroy(&st->barrier);
}

static void *
test_add_del_change_sub(void *arg)
{
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr;
    static ATOMIC_T id = 0;
    char id_str[20] = "";
    int i, j, k, ret;

    (void)arg;
    struct cb_data pvt_data = {0};
    uint32_t local_id = ATOMIC_INC_RELAXED(id);
    const int ITERATIONS = 20;
    char *module_name[] = {
        "ietf-interfaces",
        "test",
        "alarms",
        "example-module",
        "mixed-config",
        "simple",
        "test-module",
        "when1",
        "when2",
        "ops",
    };
    const int MODULE_COUNT = 10;
    char xpath[32] = "";

    ret = sr_connect(0, &conn);
    assert_int_equal(ret, SR_ERR_OK);
    snprintf(id_str, sizeof id_str, "%u", local_id);
    for (j = 0; j < ITERATIONS; j++) {
        /* start a new session */
        sess = NULL;
        subscr = NULL;
        ret = sr_session_start(conn, SR_DS_OPERATIONAL, &sess);
        assert_int_equal(ret, SR_ERR_OK);

        /* create many oper change subs */
        for (i = 0; i < MODULE_COUNT; i++) {
            snprintf(xpath, sizeof xpath, "/%s:*", module_name[i]);
            for (k = 0; k < 10; k++) {
                ret = sr_module_change_subscribe(sess, module_name[i], xpath, module_change_cb, &pvt_data, 0, 0, &subscr);
                assert_int_equal(ret, SR_ERR_OK);
            }
        }

        if (local_id == 0) {
            /* push some operational data */
            ret = sr_set_item_str(sess, "/test:test-leaf", id_str, NULL, 0);
            assert_int_equal(ret, SR_ERR_OK);

            ret = sr_apply_changes(sess, 0);
            assert_int_equal(ret, SR_ERR_OK);
        }

        ret = sr_unsubscribe(subscr);
        assert_int_equal(ret, SR_ERR_OK);

        /* stop the session */
        ret = sr_session_stop(sess);
        assert_int_equal(ret, SR_ERR_OK);
    }
    sr_disconnect(conn);
    return NULL;
}

static void
test_ext_shm_remap(void **state)
{
    (void)state;
    const int thread_count = getenv("SR_TEST_SCALE") ? 10 : 2;
    int i;
    pthread_t tid[thread_count];

    for (i = 0; i < thread_count; ++i) {
        pthread_create(&tid[i], NULL, test_add_del_change_sub, NULL);
    }
    for (i = 0; i < thread_count; ++i) {
        pthread_join(tid[i], NULL);
    }
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_create1, clear_interfaces),
        cmocka_unit_test(test_new_conn),
        cmocka_unit_test_teardown(test_sub_suspend, clear_interfaces),
        cmocka_unit_test_teardown(test_run_change_oper_get, clear_interfaces),
        cmocka_unit_test(test_ext_shm_remap),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    test_log_init();
    return cmocka_run_group_tests(tests, setup_f, teardown_f);
}
