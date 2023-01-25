/**
 * @file test_thread.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test for correct thread synchronization
 *
 * @copyright
 * Copyright (c) 2023 Deutsche Telekom AG.
 * Copyright (c) 2023 CESNET, z.s.p.o.
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "common.h"
#include "sysrepo.h"
#include "tests/tcommon.h"

struct state {
    sr_conn_ctx_t *conn;
    sr_subscription_ctx_t *subscr;
    ATOMIC_T sub_id;
    pthread_barrier_t barrier3;
};

#define TEST_ITER_COUNT 100

static int
setup(void **state)
{
    struct state *st;
    const char *schema_paths[] = {
        TESTS_SRC_DIR "/files/test.yang",
        NULL
    };

    st = calloc(1, sizeof *st);
    *state = st;

    if (sr_connect(0, &st->conn) != SR_ERR_OK) {
        return 1;
    }

    if (sr_install_modules(st->conn, schema_paths, TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }

    pthread_barrier_init(&st->barrier3, NULL, 3);

    return 0;
}

static int
teardown(void **state)
{
    struct state *st = (struct state *)*state;
    const char *module_names[] = {
        "test",
        NULL
    };

    sr_unsubscribe(st->subscr);
    sr_remove_modules(st->conn, module_names, 0);

    sr_disconnect(st->conn);
    pthread_barrier_destroy(&st->barrier3);
    free(st);
    return 0;
}

static int
dummy_change_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data)
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

/* TEST */
static void *
module_change_subscribe_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    int i, ret;

    ATOMIC_STORE_RELAXED(st->sub_id, 0);

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    for (i = 0; i < TEST_ITER_COUNT; ++i) {
        ret = sr_module_change_subscribe(sess, "test", NULL, dummy_change_cb, NULL, 0, 0, &st->subscr);
        assert_int_equal(ret, SR_ERR_OK);

        if (!ATOMIC_LOAD_RELAXED(st->sub_id)) {
            ATOMIC_STORE_RELAXED(st->sub_id, sr_subscription_get_last_sub_id(st->subscr));
        }
    }

    /* signal that the first batch of subscriptions is done */
    pthread_barrier_wait(&st->barrier3);

    for (i = 0; i < TEST_ITER_COUNT; ++i) {
        ret = sr_module_change_subscribe(sess, "test", NULL, dummy_change_cb, NULL, 0, 0, &st->subscr);
        assert_int_equal(ret, SR_ERR_OK);
    }

    /* wait until the first batch of subscriptions is unsubscribed */
    pthread_barrier_wait(&st->barrier3);

    sr_session_stop(sess);
    return NULL;
}

static void *
module_change_unsubscribe_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    int i, ret;

    /* wait until the first batch of subscriptions is done */
    pthread_barrier_wait(&st->barrier3);

    for (i = 0; i < TEST_ITER_COUNT; ++i) {
        ret = sr_unsubscribe_sub(st->subscr, ATOMIC_LOAD_RELAXED(st->sub_id) + i);
        assert_int_equal(ret, SR_ERR_OK);
    }

    /* signal that the first batch was unsubscribed */
    pthread_barrier_wait(&st->barrier3);

    return NULL;
}

static void *
module_change_apply_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    int i, ret;
    char num_str[4];

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait until the first batch of subscriptions is done */
    pthread_barrier_wait(&st->barrier3);

    for (i = 0; i < TEST_ITER_COUNT; ++i) {
        sprintf(num_str, "%d", i);
        ret = sr_set_item_str(sess, "/test:test-leaf", num_str, NULL, 0);
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_apply_changes(sess, 0);
        assert_int_equal(ret, SR_ERR_OK);
    }

    /* signal that we are done applying changes */
    pthread_barrier_wait(&st->barrier3);

    return NULL;
}

static void
test_module_changes(void **state)
{
    pthread_t tid[3];

    pthread_create(&tid[0], NULL, module_change_subscribe_thread, *state);
    pthread_create(&tid[1], NULL, module_change_unsubscribe_thread, *state);
    pthread_create(&tid[2], NULL, module_change_apply_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
    pthread_join(tid[2], NULL);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_module_changes),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    test_log_init();
    return cmocka_run_group_tests(tests, setup, teardown);
}
