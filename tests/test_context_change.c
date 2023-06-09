/**
 * @file test_context_change.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test for runtime context changes
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

#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "common.h"
#include "sysrepo.h"
#include "tests/tcommon.h"

struct state {
    sr_conn_ctx_t *conn;
    ATOMIC_T cb_called;
    pthread_barrier_t barrier;
};

static int
setup(void **state)
{
    struct state *st;
    const char *schema_paths[] = {
        TESTS_SRC_DIR "/files/mod1.yang",
        NULL
    };
    const char *mod1_features[] = {"f1", NULL};
    const char **features[] = {
        mod1_features
    };

    st = calloc(1, sizeof *st);
    *state = st;

    if (sr_connect(0, &(st->conn)) != SR_ERR_OK) {
        return 1;
    }

    if (sr_install_modules(st->conn, schema_paths, TESTS_SRC_DIR "/files", features) != SR_ERR_OK) {
        return 1;
    }

    return 0;
}

static int
teardown(void **state)
{
    struct state *st = (struct state *)*state;
    const char *module_names[] = {
        "mod1",
        NULL
    };

    sr_remove_modules(st->conn, module_names, 0);

    sr_disconnect(st->conn);
    free(st);
    return 0;
}

static int
setup_f(void **state)
{
    struct state *st = (struct state *)*state;

    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    pthread_barrier_init(&st->barrier, NULL, 2);
    return 0;
}

static int
teardown_f(void **state)
{
    struct state *st = (struct state *)*state;

    pthread_barrier_destroy(&st->barrier);
    return 0;
}

/* TEST */
static int
module_change_st_called_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;

    (void)session;
    (void)sub_id;
    (void)module_name;
    (void)xpath;
    (void)event;
    (void)request_id;

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static int
oper_deviation_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *path,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    struct state *st = (struct state *)private_data;

    (void)session;
    (void)sub_id;
    (void)module_name;
    (void)path;
    (void)request_xpath;
    (void)request_id;
    (void)parent;

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void *
context_change_deviation_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    int ret;

    /* wait until subscriptions are created */

    /* sync #1 */
    pthread_barrier_wait(&st->barrier);

    /* try to install new module, should fail */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/mod2.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

    /* sync #2 */
    pthread_barrier_wait(&st->barrier);

    /* try to install the module again, should still fail */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/mod2.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

    /* sync #3 */
    pthread_barrier_wait(&st->barrier);

    /* sync #4 */
    pthread_barrier_wait(&st->barrier);

    /* try to install the module, succeeds */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/mod2.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* remove the module */
    ret = sr_remove_module(st->conn, "mod2", 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* sync #5 */
    pthread_barrier_wait(&st->barrier);

    return NULL;
}

static void *
subscribe_deviation_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    sr_data_t *data;
    int ret;
    uint32_t sub_id1, sub_id2;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to 2 leaves, one oper sub */
    ret = sr_module_change_subscribe(sess, "mod1", "/mod1:cont/l1", module_change_st_called_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    sub_id1 = sr_subscription_get_last_sub_id(subscr);
    ret = sr_oper_get_subscribe(sess, "mod1", "/mod1:cont/l1", oper_deviation_cb, st, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    sub_id2 = sr_subscription_get_last_sub_id(subscr);
    ret = sr_module_change_subscribe(sess, "mod1", "/mod1:cont/l3", module_change_st_called_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* sync #1 */
    pthread_barrier_wait(&st->barrier);

    /* do arbitrary changes */
    ret = sr_set_item_str(sess, "/mod1:cont/l1", "val1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/mod1:cont/l3", "val1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* get oper data */
    sr_session_switch_ds(sess, SR_DS_OPERATIONAL);
    ret = sr_get_data(sess, "/mod1:cont/l1", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    sr_release_data(data);
    assert_int_equal(st->cb_called, 5);

    /* sync #2 */
    pthread_barrier_wait(&st->barrier);

    /* unsubscribe the first subscription */
    ret = sr_unsubscribe_sub(subscr, sub_id1);
    assert_int_equal(ret, SR_ERR_OK);

    /* sync #3 */
    pthread_barrier_wait(&st->barrier);

    /* unsubscribe the second subscription */
    ret = sr_unsubscribe_sub(subscr, sub_id2);
    assert_int_equal(ret, SR_ERR_OK);

    /* sync #4 */
    pthread_barrier_wait(&st->barrier);

    /* do some more changes on the second subscription  */
    sr_session_switch_ds(sess, SR_DS_RUNNING);
    ret = sr_set_item_str(sess, "/mod1:cont/l3", "val2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/mod1:cont/l3", "val3", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(st->cb_called, 9);

    /* sync #5 */
    pthread_barrier_wait(&st->barrier);

    /* cleanup */
    ret = sr_unsubscribe(subscr);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_delete_item(sess, "/mod1:cont", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    sr_session_stop(sess);
    return NULL;
}

static void
test_deviation(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, context_change_deviation_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_deviation_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
rpc_feature_change_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data)
{
    struct state *st = (struct state *)private_data;

    (void)session;
    (void)sub_id;
    (void)op_path;
    (void)input;
    (void)event;
    (void)request_id;
    (void)output;

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void
notif_feature_change_cb(sr_session_ctx_t *session, uint32_t sub_id, const sr_ev_notif_type_t notif_type,
        const struct lyd_node *notif, struct timespec *timestamp, void *private_data)
{
    struct state *st = (struct state *)private_data;

    (void)session;
    (void)sub_id;
    (void)notif_type;
    (void)notif;
    (void)timestamp;

    ATOMIC_INC_RELAXED(st->cb_called);
}

static void *
context_change_feature_change_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    int ret;

    /* wait until subscriptions are created */

    /* sync #1 */
    pthread_barrier_wait(&st->barrier);

    /* try to enable f2, should fail */
    ret = sr_enable_module_feature(st->conn, "mod1", "f2");
    assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

    /* try to disable f1, should fail */
    ret = sr_disable_module_feature(st->conn, "mod1", "f1");
    assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

    /* sync #2 */
    pthread_barrier_wait(&st->barrier);

    /* sync #3 */
    pthread_barrier_wait(&st->barrier);

    /* try to disable f1, should still fail */
    ret = sr_disable_module_feature(st->conn, "mod1", "f1");
    assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

    /* sync #4 */
    pthread_barrier_wait(&st->barrier);

    /* sync #5 */
    pthread_barrier_wait(&st->barrier);

    /* try to disable f1, succeeds */
    ret = sr_disable_module_feature(st->conn, "mod1", "f1");
    assert_int_equal(ret, SR_ERR_OK);

    /* sync #6 */
    pthread_barrier_wait(&st->barrier);

    /* enable f1 back */
    ret = sr_enable_module_feature(st->conn, "mod1", "f1");
    assert_int_equal(ret, SR_ERR_OK);

    return NULL;
}

static void *
subscribe_feature_change_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    sr_data_t *data;
    const struct ly_ctx *ly_ctx;
    struct lyd_node *ly_notif, *ly_action;
    int ret;
    uint32_t sub_id1, sub_id2;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to 2 leaves, action, and notif */
    ret = sr_module_change_subscribe(sess, "mod1", "/mod1:cont/l2", module_change_st_called_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    sub_id1 = sr_subscription_get_last_sub_id(subscr);
    ret = sr_module_change_subscribe(sess, "mod1", "/mod1:cont/l3", module_change_st_called_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe_tree(sess, "/mod1:cont/a", rpc_feature_change_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_notif_subscribe_tree(sess, "mod1", "/mod1:cont/n/l5 = 5", NULL, NULL, notif_feature_change_cb, st,
            0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    sub_id2 = sr_subscription_get_last_sub_id(subscr);

    /* sync #1 */
    pthread_barrier_wait(&st->barrier);

    /* sync #2 */
    pthread_barrier_wait(&st->barrier);

    /* unsubscribe the first subscription */
    ret = sr_unsubscribe_sub(subscr, sub_id1);
    assert_int_equal(ret, SR_ERR_OK);

    /* sync #3 */
    pthread_barrier_wait(&st->barrier);

    /* sync #4 */
    pthread_barrier_wait(&st->barrier);

    /* send notif */
    ly_ctx = sr_acquire_context(st->conn);
    assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, ly_ctx, "/mod1:cont/n/l5", "5", 0, &ly_notif));
    ret = sr_notif_send_tree(sess, ly_notif, 0, 1);
    lyd_free_tree(ly_notif);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(st->cb_called, 1);

    /* unsubscribe the second subscription */
    ret = sr_unsubscribe_sub(subscr, sub_id2);
    assert_int_equal(ret, SR_ERR_OK);

    /* sync #5 */
    pthread_barrier_wait(&st->barrier);

    /* do some changes in the data */
    ret = sr_set_item_str(sess, "/mod1:cont/l3", "val1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(st->cb_called, 4);

    /* send action */
    ly_ctx = sr_acquire_context(st->conn);
    assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, ly_ctx, "/mod1:cont/a/l4", "50", 0, &ly_action));
    ret = sr_rpc_send_tree(sess, ly_action, 0, &data);
    lyd_free_tree(ly_action);
    sr_release_context(st->conn);
    sr_release_data(data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(st->cb_called, 5);

    /* sync #6 */
    pthread_barrier_wait(&st->barrier);

    /* cleanup */
    ret = sr_unsubscribe(subscr);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_delete_item(sess, "/mod1:cont", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    sr_session_stop(sess);
    return NULL;
}

static void
test_feature_change(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, context_change_feature_change_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_feature_change_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* MAIN */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_deviation, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_feature_change, setup_f, teardown_f),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    test_log_init();
    return cmocka_run_group_tests(tests, setup, teardown);
}
