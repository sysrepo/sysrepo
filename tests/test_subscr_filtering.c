/**
 * @file test_subscr_filtering.c
 * @author Irfan <irfan@graphiant.com>
 * @brief test for optimization of subscription filtering
 *
 * @copyright
 * Copyright 2022 Graphiant
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

#include <string.h>
#include <unistd.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdlib.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "sysrepo.h"
#include "common.h"
#include "tests/test_common.h"

struct state {
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
};

static int
setup_f(void **state)
{
    struct state *st;

    st = calloc(1, sizeof *st);
    if (!st) {
        return 1;
    }
    *state = st;

    if (sr_connect(0, &st->conn) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_DIR "/files/test.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_DIR "/files/ietf-interfaces.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_DIR "/files/iana-if-type.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        return 1;
    }

    sr_disconnect(st->conn);

    if (sr_connect(0, &st->conn) != SR_ERR_OK) {
        return 1;
    }

    return 0;
}

static int
teardown_f(void **state)
{
    struct state *st = (struct state *)*state;

    sr_remove_module(st->conn, "ietf-interfaces");
    sr_remove_module(st->conn, "iana-if-type");
    sr_remove_module(st->conn, "test");

    sr_disconnect(st->conn);
    free(st);
    return 0;
}

typedef struct {
    ATOMIC_T count;
} cb_stats;

static int
module_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data)
{
    (void)session;
    (void)module_name;
    (void)xpath;
    (void)event;
    (void)request_id;
    cb_stats *stats = (cb_stats *)private_data;
    ATOMIC_INC_RELAXED(stats->count);
    return 0;
}

static void
test_subscription_filtering(void **arg)
{
    struct state *st = (struct state *)*arg;
    sr_subscription_ctx_t *subscr[4];
    sr_subscr_options_t opts = SR_SUBSCR_PRODUCER_FILTERING;
    int i = 0, ret;
    cb_stats stats[4];
    const int expected_counts[] = {2, 2, 0, 0};

    sr_session_start(st->conn, SR_DS_RUNNING, &st->sess);

    memset(subscr, 0, sizeof(subscr));
    memset(stats, 0, sizeof(stats));

    // Start some subscriptions to test.yang
    ret = sr_module_change_subscribe(st->sess, "test", "/test:l1[k='interested_key']", module_change_cb, &stats[i],
            0, opts, &subscr[i]);
    assert_int_equal(ret, 0);
    i++;

    ret = sr_module_change_subscribe(st->sess, "test", NULL, module_change_cb, &stats[i], 0, opts, &subscr[i]);
    assert_int_equal(ret, 0);
    i++;

    ret = sr_module_change_subscribe(st->sess, "test", "/test:l1[k='other_key']", module_change_cb, &stats[i],
                0, opts, &subscr[i]);
    assert_int_equal(ret, 0);
    i++;

    /* This will test producer side filtering because there is no thread that will call process_events
     * If the event is not filtered at producer, the apply_changes call has to time out
     */
    opts |= SR_SUBSCR_NO_THREAD;
    ret = sr_module_change_subscribe(st->sess, "test", "/test:l1[k='other_key']", module_change_cb, &stats[i],
                0, opts, &subscr[i]);
    assert_int_equal(ret, 0);

    ret = sr_set_item_str(st->sess, "/test:l1[k='interested_key']/v", "25", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* perform 1st change */
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);
    for (i = 0; i < 4; i++) {
        assert_int_equal(expected_counts[i], stats[i].count);
    }

    memset(stats, 0, sizeof(stats));
    ret = sr_set_item_str(st->sess, "/test:l1[k='interested_key']/v", "0", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* perform 2nd change */
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    for (i = 0; i < 4; i++) {
        assert_int_equal(expected_counts[i], stats[i].count);
    }

    memset(stats, 0, sizeof(stats));
    ret = sr_delete_item(st->sess, "/test:l1[k='interested_key']/v", 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* perform 3rd change */
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    for (i = 0; i < 4; i++) {
        assert_int_equal(expected_counts[i], stats[i].count);
    }

    for (i = 0; i < 4; i++) {
        sr_unsubscribe(subscr[i]);
    }
}

static void
test_multisub_filtering(void **arg)
{
    struct state *st = (struct state *)*arg;
    sr_subscription_ctx_t *subscr = NULL;
    sr_subscr_options_t opts = SR_SUBSCR_PRODUCER_FILTERING;
    int ret, i = 0;
    const int expected_counts[3] = {2, 0, 2};
    cb_stats stats[3];
    memset(stats, 0, sizeof(stats));

    sr_session_start(st->conn, SR_DS_RUNNING, &st->sess);

    // Start some subscriptions to test.yang
    ret = sr_module_change_subscribe(st->sess, "test", "/test:l1[k='interested_key']", module_change_cb, &stats[i++],
            0, opts, &subscr);
    assert_int_equal(ret, 0);

    ret = sr_module_change_subscribe(st->sess, "test", "/test:l1[k='other_key']", module_change_cb, &stats[i++],
            0, opts, &subscr);
    assert_int_equal(ret, 0);

    ret = sr_module_change_subscribe(st->sess, "test", NULL, module_change_cb, &stats[i++],
            0, opts, &subscr);
    assert_int_equal(ret, 0);

    ret = sr_set_item_str(st->sess, "/test:l1[k='interested_key']/v", "25", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);
    for (i = 0; i < 3; i++) {
        assert_int_equal(stats[i].count, expected_counts[i]);
    }
    sr_unsubscribe(subscr);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_subscription_filtering),
        cmocka_unit_test(test_multisub_filtering),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    sr_log_stderr(SR_LL_INF);
    return cmocka_run_group_tests(tests, setup_f, teardown_f);
}
