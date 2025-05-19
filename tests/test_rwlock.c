/**
 * @file test_rwlock.c
 * @author Irfan <irfan.haslanded@gmail.com>
 * @brief tests for sr_rwlock_t functionality.
 *
 * @copyright
 * Copyright 2025 Graphiant
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
#define _GNU_SOURCE

#include <setjmp.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "common.h"
#include "sysrepo.h"
#include "tests/tcommon.h"

struct state {
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    int conn_per_thread;
    pthread_barrier_t barrier;
};

static int
setup_f(void **state)
{
    struct state *st;
    const char *schema_paths[] = {
        TESTS_SRC_DIR "/files/test.yang",
        NULL
    };

    st = calloc(1, sizeof *st);
    *state = st;

    if (sr_connect(0, &(st->conn)) != SR_ERR_OK) {
        return 1;
    }

    if (sr_install_modules(st->conn, schema_paths, TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }
    pthread_barrier_init(&st->barrier, NULL, 2);
    return 0;
}

static int
teardown_f(void **state)
{
    struct state *st = (struct state *)*state;
    const char *module_names[] = {
        "test",
        NULL
    };

    if (sr_remove_modules(st->conn, module_names, 0) != SR_ERR_OK) {
        return 1;
    }

    sr_disconnect(st->conn);
    free(st);
    return 0;
}

/* TEST */
static int
module_change_slow_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name,
        const char *xpath, sr_event_t event, uint32_t request_id, void *private_data)
{
    (void)module_name;
    (void)sub_id;
    (void)xpath;
    (void)event;
    (void)request_id;
    (void)private_data;
    (void)session;

    sleep(1 + SR_SUBSCR_LOCK_TIMEOUT / 1000);

    return 0;
}

static void
test_unsubscribe_retry(void **arg)
{
    struct state *st = (struct state *)*arg;
    sr_subscription_ctx_t *subscr = NULL;
    int ret;

    subscr = NULL;
    ret = sr_session_start(st->conn, SR_DS_RUNNING, &st->sess);
    assert_int_equal(ret, 0);

    /* Start a slow subscr to test.yang */
    ret = sr_module_change_subscribe(st->sess, "test", NULL, module_change_slow_cb, NULL,
            0, SR_SUBSCR_DONE_ONLY, &subscr);
    assert_int_equal(ret, 0);

    ret = sr_set_item_str(st->sess, "/test:l1[k='some-key']/v", "25", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 100);
    assert_int_equal(ret, SR_ERR_OK);

    /* timeout due to slow cb */
    ret = sr_unsubscribe(subscr);
    assert_int_equal(ret, SR_ERR_TIME_OUT);

    /* cb must be finished by now */
    ret = sr_unsubscribe(subscr);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_stop(st->sess);
    assert_int_equal(ret, SR_ERR_OK);
    st->sess = NULL;
}

static void *
test_lock_acquire_context_thread(void *arg)
{
    struct state *st = (struct state *)arg;

    pthread_barrier_wait(&st->barrier);
    assert_non_null(sr_acquire_context(st->conn));
    pthread_barrier_wait(&st->barrier);

    sr_release_context(st->conn);

    return NULL;
}

static void
test_lock_reader_limit(void **arg)
{
    const int NUM_CIDS = SR_RWLOCK_READ_LIMIT;
    struct state *st = (struct state *)*arg;
    sr_conn_ctx_t *conn[NUM_CIDS];
    int i, ret;
    pthread_t tid;

    for (i = 0; i < NUM_CIDS; i++) {
        ret = sr_connect(0, &conn[i]);
        assert_int_equal(ret, SR_ERR_OK);
        assert_non_null(sr_acquire_context(conn[i]));
    }

    TLOG_INF("context lock is exhausted, acquire context should fail");
    assert_null(sr_acquire_context(st->conn));

    /* start a thread so it can acquire the context as soon as the first reader unlocks */
    pthread_create(&tid, NULL, test_lock_acquire_context_thread, st);
    pthread_barrier_wait(&st->barrier);
    /* release one context, so the above thread grabs the last available spot after unlock */
    sr_release_context(conn[0]);
    pthread_barrier_wait(&st->barrier);

    /* try to acquire the context once the thread releases it */
    assert_non_null(sr_acquire_context(conn[0]));

    for (i = 0; i < NUM_CIDS; i++) {
        ret = sr_disconnect(conn[i]);
        assert_int_equal(ret, SR_ERR_OK);
    }

    pthread_join(tid, NULL);

    /* Recover the context READ lock (dead CID) */
    assert_non_null(sr_acquire_context(st->conn));
    sr_release_context(st->conn);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_lock_reader_limit),
        cmocka_unit_test(test_unsubscribe_retry),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    setenv("SR_TEST_LOG_DEBUG", "1", 1);
    test_log_init();
    return cmocka_run_group_tests(tests, setup_f, teardown_f);
}
