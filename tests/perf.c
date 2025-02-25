/**
 * @file perf.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @author Ondrej Kusnirik <Ondrej.Kusnirik@cesnet.cz>
 * @brief performance tests
 *
 * Copyright (c) 2021 - 2024 Deutsche Telekom AG.
 * Copyright (c) 2021 - 2024 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

#include <libyang/libyang.h>

#include "common.h"
#include "config.h"
#include "plugins_datastore.h"
#include "sysrepo.h"
#include "tests/tcommon.h"

#ifdef SR_HAVE_CALLGRIND
# include <valgrind/callgrind.h>
#endif

#define TABLE_WIDTH 67
#define NAME_FIXED_LEN 33
#define COL_FIXED_LEN 15
#define MILLION 1000000

#define ABS(x) (x < 0) * (-x) + (x >= 0) * x

/**
 * @brief Test state structure.
 */
struct test_state {
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *sub;
    const struct lys_module *mod;
    uint32_t count;
};

typedef int (*setup_cb)(struct test_state *state);
typedef int (*test_cb)(struct test_state *state, struct timespec *ts_start, struct timespec *ts_end);
typedef void (*teardown_cb)(struct test_state *state);

/**
 * @brief Single test structure.
 */
struct test {
    const char *name;
    setup_cb setup;
    test_cb test;
    teardown_cb teardown;
};

/**
 * @brief Get current time as timespec.
 *
 * @param[out] ts Timespect to fill.
 */
static void
time_get(struct timespec *ts)
{
#ifdef CLOCK_MONOTONIC_RAW
    clock_gettime(CLOCK_MONOTONIC_RAW, ts);
#elif defined (CLOCK_MONOTONIC)
    clock_gettime(CLOCK_MONOTONIC, ts);
#elif defined (CLOCK_REALTIME)
    /* no monotonic clock available, return realtime */
    clock_gettime(CLOCK_REALTIME, ts);
#else
    int rc;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    ts->tv_sec = (time_t)tv.tv_sec;
    ts->tv_nsec = 1000L * (long)tv.tv_usec;
#endif
}

/**
 * @brief Get the difference of 2 timespecs in microseconds.
 *
 * @param[in] ts1 Smaller (older) timespec.
 * @param[in] ts2 Larger (later) timespec.
 * @return Difference of timespecs in usec.
 */
static uint64_t
time_diff(const struct timespec *ts1, const struct timespec *ts2)
{
    uint64_t usec_diff = 0;

    assert(ts1->tv_sec <= ts2->tv_sec);

    /* seconds diff */
    usec_diff += (ts2->tv_sec - ts1->tv_sec) * 1000000;

    /* nanoseconds diff */
    usec_diff += (ts2->tv_nsec - ts1->tv_nsec) / 1000;

    return usec_diff;
}

/**
 * @brief Create data tree with list instances.
 *
 * @param[in] mod Module of the top-level node.
 * @param[in] offset Starting offset of the identifier number values.
 * @param[in] count Number of list instances to create, with increasing identifier numbers.
 * @param[out] data Created data.
 * @return SR ERR value.
 */
static int
create_list_inst(const struct lys_module *mod, uint32_t offset, uint32_t count, struct lyd_node **data)
{
    uint32_t i;
    char k1_val[32], k2_val[32], l_val[32];
    struct lyd_node *list;

    if (lyd_new_inner(NULL, mod, "cont", 0, data)) {
        return SR_ERR_LY;
    }

    for (i = 0; i < count; ++i) {
        sprintf(k1_val, "%" PRIu32, i + offset);
        sprintf(k2_val, "str%" PRIu32, i + offset);
        sprintf(l_val, "l%" PRIu32, i + offset);

        if (lyd_new_list(*data, NULL, "lst", 0, &list, k1_val, k2_val)) {
            return SR_ERR_LY;
        }
        if (lyd_new_term(list, NULL, "l", l_val, 0, NULL)) {
            return SR_ERR_LY;
        }
    }

    return SR_ERR_OK;
}

/**
 * @brief Create data tree with user ordered list instances.
 *
 * @param[in] mod Module of the top-level node.
 * @param[in] offset Starting offset of the identifier number values.
 * @param[in] count Number of list instances to create, with increasing identifier numbers.
 * @param[out] data Created data.
 * @return SR ERR value.
 */
static int
create_user_order_list_inst(const struct lys_module *mod, uint32_t offset, uint32_t count, struct lyd_node **data)
{
    uint32_t i;
    char k_val[32], l_val[32];
    struct lyd_node *list;

    if (lyd_new_inner(NULL, mod, "cont", 0, data)) {
        return SR_ERR_LY;
    }

    for (i = 0; i < count; ++i) {
        sprintf(k_val, "%" PRIu32, i + offset);
        sprintf(l_val, "l%" PRIu32, i + offset);

        if (lyd_new_list(*data, NULL, "usr-lst", 0, &list, k_val)) {
            return SR_ERR_LY;
        }
        if (lyd_new_term(list, NULL, "l", l_val, 0, NULL)) {
            return SR_ERR_LY;
        }
    }

    return SR_ERR_OK;
}

/**
 * @brief Execute a test.
 *
 * @param[in] setup Setup callback to call once.
 * @param[in] test Test callback.
 * @param[in] name Name of the test.
 * @param[in] count Count of list instances, size of the testing data set.
 * @param[in] tries Number of (re)tries of the test to get more accurate measurements.
 * @return SR ERR value.
 */
static int
exec_test(setup_cb setup, test_cb test, teardown_cb teardown, uint32_t tries, int64_t *time, struct test_state *state)
{
    int ret;
    struct timespec ts_start, ts_end;
    uint32_t i;
    uint64_t time_usec = 0;

    /* setup */
    if ((ret = setup(state))) {
        return ret;
    }

    /* test */
    for (i = 0; i < tries; ++i) {
        if ((ret = test(state, &ts_start, &ts_end))) {
            return ret;
        }
        time_usec += time_diff(&ts_start, &ts_end);
    }
    time_usec /= tries;

    /* save time for later printing */
    *time = (int64_t)time_usec;

    /* teardown */
    teardown(state);
    return SR_ERR_OK;
}

static void
TEST_START(struct timespec *ts)
{
    time_get(ts);

#ifdef SR_HAVE_CALLGRIND
    CALLGRIND_START_INSTRUMENTATION;
#endif
}

static void
TEST_END(struct timespec *ts)
{
    time_get(ts);

#ifdef SR_HAVE_CALLGRIND
    CALLGRIND_STOP_INSTRUMENTATION;
#endif
}

/* TEST SYSREPO CB */
static int
oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *path,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    struct test_state *state = private_data;

    (void)session;
    (void)sub_id;
    (void)module_name;
    (void)path;
    (void)request_xpath;
    (void)request_id;

    return create_list_inst(state->mod, 0, state->count, parent);
}

/* TEST SETUPS */
static int
setup_empty(struct test_state *state)
{
    int r;

    if ((r = sr_connect(SR_CONN_DEFAULT, &state->conn))) {
        return r;
    }
    if ((r = sr_session_start(state->conn, SR_DS_RUNNING, &(state->sess)))) {
        return r;
    }
    state->mod = ly_ctx_get_module_implemented(sr_acquire_context(state->conn), "perf");

    return SR_ERR_OK;
}

static int
setup_empty_oper(struct test_state *state)
{
    int r;

    if ((r = sr_connect(SR_CONN_DEFAULT, &state->conn))) {
        return r;
    }
    if ((r = sr_session_start(state->conn, SR_DS_OPERATIONAL, &(state->sess)))) {
        return r;
    }
    state->mod = ly_ctx_get_module_implemented(sr_acquire_context(state->conn), "perf");

    return SR_ERR_OK;
}

static int
setup_running(struct test_state *state)
{
    int r;
    struct lyd_node *data;

    if ((r = sr_connect(SR_CONN_DEFAULT, &state->conn))) {
        return r;
    }
    if ((r = sr_session_start(state->conn, SR_DS_RUNNING, &(state->sess)))) {
        return r;
    }
    state->mod = ly_ctx_get_module_implemented(sr_acquire_context(state->conn), "perf");

    /* set running data */
    if ((r = create_list_inst(state->mod, 0, state->count, &data))) {
        return r;
    }
    if ((r = sr_edit_batch(state->sess, data, "merge"))) {
        return r;
    }
    if ((r = sr_apply_changes(state->sess, state->count * 100))) {
        return r;
    }
    lyd_free_siblings(data);

    return SR_ERR_OK;
}

static int
setup_running_cached(struct test_state *state)
{
    int r;
    struct lyd_node *data;

    if ((r = sr_connect(SR_CONN_CACHE_RUNNING, &state->conn))) {
        return r;
    }
    if ((r = sr_session_start(state->conn, SR_DS_RUNNING, &state->sess))) {
        return r;
    }
    state->mod = ly_ctx_get_module_implemented(sr_acquire_context(state->conn), "perf");

    /* set running data */
    if ((r = create_list_inst(state->mod, 0, state->count, &data))) {
        return r;
    }
    if ((r = sr_edit_batch(state->sess, data, "merge"))) {
        return r;
    }
    if ((r = sr_apply_changes(state->sess, state->count * 100))) {
        return r;
    }
    lyd_free_siblings(data);

    return SR_ERR_OK;
}

static int
setup_oper(struct test_state *state)
{
    int r;
    struct lyd_node *data;

    if ((r = sr_connect(SR_CONN_DEFAULT, &state->conn))) {
        return r;
    }
    if ((r = sr_session_start(state->conn, SR_DS_OPERATIONAL, &(state->sess)))) {
        return r;
    }
    state->mod = ly_ctx_get_module_implemented(sr_acquire_context(state->conn), "perf");

    /* set operational data */
    if ((r = create_list_inst(state->mod, 0, state->count, &data))) {
        return r;
    }
    if ((r = sr_edit_batch(state->sess, data, "merge"))) {
        return r;
    }
    if ((r = sr_apply_changes(state->sess, state->count * 100))) {
        return r;
    }
    lyd_free_siblings(data);

    return SR_ERR_OK;
}

static int
setup_userordered_running(struct test_state *state)
{
    int r;
    struct lyd_node *data;

    if ((r = sr_connect(SR_CONN_DEFAULT, &state->conn))) {
        return r;
    }
    if ((r = sr_session_start(state->conn, SR_DS_RUNNING, &(state->sess)))) {
        return r;
    }
    state->mod = ly_ctx_get_module_implemented(sr_acquire_context(state->conn), "perf");

    /* set running data */
    if ((r = create_user_order_list_inst(state->mod, 0, state->count, &data))) {
        return r;
    }
    if ((r = sr_edit_batch(state->sess, data, "merge"))) {
        return r;
    }
    if ((r = sr_apply_changes(state->sess, state->count * 100))) {
        return r;
    }
    lyd_free_siblings(data);

    return SR_ERR_OK;
}

static int
setup_subscribe_oper(struct test_state *state)
{
    int r;

    if ((r = sr_connect(SR_CONN_DEFAULT, &state->conn))) {
        return r;
    }
    if ((r = sr_session_start(state->conn, SR_DS_OPERATIONAL, &state->sess))) {
        return r;
    }
    if ((r = sr_oper_get_subscribe(state->sess, "perf", "/perf:cont", oper_cb, state, 0, &state->sub))) {
        return r;
    }
    state->mod = ly_ctx_get_module_implemented(sr_acquire_context(state->conn), "perf");

    return SR_ERR_OK;
}

static void
teardown_empty(struct test_state *state)
{
    sr_session_stop(state->sess);
    sr_release_context(state->conn);
    sr_disconnect(state->conn);
}

static void
teardown_running(struct test_state *state)
{
    sr_delete_item(state->sess, "/perf:cont", 0);
    sr_apply_changes(state->sess, state->count * 100);
    sr_session_stop(state->sess);
    sr_release_context(state->conn);
    sr_disconnect(state->conn);
}

static void
teardown_oper(struct test_state *state)
{
    sr_delete_item(state->sess, "/perf:cont", 0);
    sr_apply_changes(state->sess, state->count * 100);
    sr_session_stop(state->sess);
    sr_release_context(state->conn);
    sr_disconnect(state->conn);
}

static void
teardown_subscribe_oper(struct test_state *state)
{
    sr_session_switch_ds(state->sess, SR_DS_RUNNING);
    sr_unsubscribe(state->sub);
    state->sub = NULL;
    sr_session_stop(state->sess);
    sr_release_context(state->conn);
    sr_disconnect(state->conn);
}

static int
test_get_tree(struct test_state *state, struct timespec *ts_start, struct timespec *ts_end)
{
    int r;
    sr_data_t *data;
    char path[64];

    sprintf(path, "/perf:cont/lst[k1='%" PRIu32 "' and k2='str%" PRIu32 "']/l", state->count / 2, state->count / 2);

    TEST_START(ts_start);

    if ((r = sr_get_data(state->sess, path, 0, 0, 0, &data))) {
        return r;
    }

    TEST_END(ts_end);

    sr_release_data(data);

    return SR_ERR_OK;
}

static int
test_get_item(struct test_state *state, struct timespec *ts_start, struct timespec *ts_end)
{
    int r;
    sr_val_t *val;
    char path[64];

    sprintf(path, "/perf:cont/lst[k1='%" PRIu32 "' and k2='str%" PRIu32 "']/l", state->count / 2, state->count / 2);

    TEST_START(ts_start);

    if ((r = sr_get_item(state->sess, path, 0, &val))) {
        return r;
    }

    TEST_END(ts_end);

    sr_free_val(val);

    return SR_ERR_OK;
}

static int
test_get_tree_hash(struct test_state *state, struct timespec *ts_start, struct timespec *ts_end)
{
    int r;
    sr_data_t *data;
    char path[64];

    sprintf(path, "/perf:cont/lst[k1='%" PRIu32 "'][k2='str%" PRIu32 "']/l", state->count / 2, state->count / 2);

    TEST_START(ts_start);

    if ((r = sr_get_data(state->sess, path, 0, 0, 0, &data))) {
        return r;
    }

    TEST_END(ts_end);

    sr_release_data(data);

    return SR_ERR_OK;
}

static int
test_get_user_order_tree(struct test_state *state, struct timespec *ts_start, struct timespec *ts_end)
{
    int r;
    sr_data_t *data;

    TEST_START(ts_start);

    if ((r = sr_get_data(state->sess, "/perf:cont", 0, 0, 0, &data))) {
        return r;
    }

    TEST_END(ts_end);

    sr_release_data(data);

    return SR_ERR_OK;
}

static int
test_get_oper_tree(struct test_state *state, struct timespec *ts_start, struct timespec *ts_end)
{
    int r;
    sr_data_t *data;

    TEST_START(ts_start);

    if ((r = sr_get_data(state->sess, "/perf:cont", 0, 0, 0, &data))) {
        return r;
    }

    TEST_END(ts_end);

    sr_release_data(data);
    return SR_ERR_OK;
}

static int
test_batch_create(struct test_state *state, struct timespec *ts_start, struct timespec *ts_end)
{
    int r;
    struct lyd_node *data;

    TEST_START(ts_start);

    if ((r = create_list_inst(state->mod, 0, state->count, &data))) {
        return r;
    }

    if ((r = sr_edit_batch(state->sess, data, "merge"))) {
        return r;
    }

    if ((r = sr_apply_changes(state->sess, state->count * 100))) {
        return r;
    }

    TEST_END(ts_end);

    lyd_free_siblings(data);

    if ((r = sr_delete_item(state->sess, "/perf:cont/lst", 0))) {
        return r;
    }
    if ((r = sr_apply_changes(state->sess, state->count * 100))) {
        return r;
    }

    return SR_ERR_OK;
}

static int
test_user_order_items_create(struct test_state *state, struct timespec *ts_start, struct timespec *ts_end)
{
    int r;
    uint32_t i;
    char path[64], l_val[32];

    TEST_START(ts_start);

    for (i = 0; i < state->count; ++i) {
        sprintf(path, "/perf:cont/usr-lst[k='%" PRIu32 "']/l", i);
        sprintf(l_val, "l%" PRIu32, i);
        if ((r = sr_set_item_str(state->sess, path, l_val, NULL, 0))) {
            return r;
        }
    }

    if ((r = sr_apply_changes(state->sess, state->count * 100))) {
        return r;
    }

    TEST_END(ts_end);

    if ((r = sr_delete_item(state->sess, "/perf:cont/usr-lst", 0))) {
        return r;
    }
    if ((r = sr_apply_changes(state->sess, state->count * 100))) {
        return r;
    }

    return SR_ERR_OK;
}

static int
test_items_create(struct test_state *state, struct timespec *ts_start, struct timespec *ts_end)
{
    int r;
    uint32_t i;
    char path[64], l_val[32];

    TEST_START(ts_start);

    for (i = 0; i < state->count; ++i) {
        sprintf(path, "/perf:cont/lst[k1='%" PRIu32 "'][k2='str%" PRIu32 "']/l", i, i);
        sprintf(l_val, "l%" PRIu32, i);
        if ((r = sr_set_item_str(state->sess, path, l_val, NULL, 0))) {
            return r;
        }
    }

    if ((r = sr_apply_changes(state->sess, state->count * 100))) {
        return r;
    }

    TEST_END(ts_end);

    if ((r = sr_delete_item(state->sess, "/perf:cont/lst", 0))) {
        return r;
    }
    if ((r = sr_apply_changes(state->sess, state->count * 100))) {
        return r;
    }

    return SR_ERR_OK;
}

static int
test_items_create_oper(struct test_state *state, struct timespec *ts_start, struct timespec *ts_end)
{
    int r;
    uint32_t i;
    char path[64], l_val[32];

    TEST_START(ts_start);

    for (i = 0; i < state->count; ++i) {
        sprintf(path, "/perf:cont/lst[k1='%" PRIu32 "'][k2='str%" PRIu32 "']/l", i, i);
        sprintf(l_val, "l%" PRIu32, i);
        if ((r = sr_set_item_str(state->sess, path, l_val, NULL, 0))) {
            return r;
        }
    }

    if ((r = sr_apply_changes(state->sess, state->count * 100))) {
        return r;
    }

    TEST_END(ts_end);

    if ((r = sr_delete_item(state->sess, "/perf:cont/lst", 0))) {
        return r;
    }
    if ((r = sr_apply_changes(state->sess, state->count * 100))) {
        return r;
    }

    return SR_ERR_OK;
}

static int
test_items_remove(struct test_state *state, struct timespec *ts_start, struct timespec *ts_end)
{
    int r;

    TEST_START(ts_start);

    if ((r = sr_delete_item(state->sess, "/perf:cont/lst", 0))) {
        return r;
    }
    if ((r = sr_apply_changes(state->sess, state->count * 100))) {
        return r;
    }

    TEST_END(ts_end);

    return SR_ERR_OK;
}

static int
test_items_remove_subtree(struct test_state *state, struct timespec *ts_start, struct timespec *ts_end)
{
    int r;

    TEST_START(ts_start);

    if ((r = sr_delete_item(state->sess, "/perf:cont", 0))) {
        return r;
    }
    if ((r = sr_apply_changes(state->sess, state->count * 100))) {
        return r;
    }

    TEST_END(ts_end);

    return SR_ERR_OK;
}

static int
test_item_create(struct test_state *state, struct timespec *ts_start, struct timespec *ts_end)
{
    int r;
    char path[64], l_val[32];

    sprintf(path, "/perf:cont/lst[k1='%" PRIu32 "'][k2='str%" PRIu32 "']/l", state->count / 2, state->count / 2);
    if ((r = sr_delete_item(state->sess, path, 0))) {
        return r;
    }
    if ((r = sr_apply_changes(state->sess, 0))) {
        return r;
    }

    TEST_START(ts_start);

    sprintf(l_val, "l%" PRIu32, 0);
    if ((r = sr_set_item_str(state->sess, path, l_val, NULL, SR_EDIT_STRICT))) {
        return r;
    }
    if ((r = sr_apply_changes(state->sess, 0))) {
        return r;
    }

    TEST_END(ts_end);

    return SR_ERR_OK;
}

static int
test_item_create_oper(struct test_state *state, struct timespec *ts_start, struct timespec *ts_end)
{
    int r;
    char path[64], l_val[32];

    sprintf(path, "/perf:cont/lst[k1='%" PRIu32 "'][k2='str%" PRIu32 "']/l", state->count / 2, state->count / 2);
    if ((r = sr_delete_item(state->sess, path, 0))) {
        return r;
    }
    if ((r = sr_apply_changes(state->sess, 0))) {
        return r;
    }

    TEST_START(ts_start);

    sprintf(l_val, "l%" PRIu32, 0);
    if ((r = sr_set_item_str(state->sess, path, l_val, NULL, 0))) {
        return r;
    }
    if ((r = sr_apply_changes(state->sess, 0))) {
        return r;
    }

    TEST_END(ts_end);

    return SR_ERR_OK;
}

static int
test_item_modify(struct test_state *state, struct timespec *ts_start, struct timespec *ts_end)
{
    int r;
    char path[64], l_val[32];

    TEST_START(ts_start);

    sprintf(path, "/perf:cont/lst[k1='%" PRIu32 "'][k2='str%" PRIu32 "']/l", state->count / 2, state->count / 2);
    sprintf(l_val, "l%" PRIu32, 1);
    if ((r = sr_set_item_str(state->sess, path, l_val, NULL, 0))) {
        return r;
    }
    if ((r = sr_apply_changes(state->sess, 0))) {
        return r;
    }

    TEST_END(ts_end);

    return SR_ERR_OK;
}

static int
test_item_remove(struct test_state *state, struct timespec *ts_start, struct timespec *ts_end)
{
    int r;
    char path[64], l_val[32];

    TEST_START(ts_start);

    sprintf(path, "/perf:cont/lst[k1='%" PRIu32 "'][k2='str%" PRIu32 "']/l", state->count / 2, state->count / 2);
    sprintf(l_val, "l%" PRIu32, 0);
    if ((r = sr_delete_item(state->sess, path, 0))) {
        return r;
    }
    if ((r = sr_apply_changes(state->sess, 0))) {
        return r;
    }

    TEST_END(ts_end);

    return SR_ERR_OK;
}

static int
sysrepo_init(const char *plg_name, struct test_state *state, uint32_t count)
{
    int ret, i;
    sr_conn_ctx_t *conn;
    sr_module_ds_t mod_ds;

    for (i = 0; i < 5; ++i) {
        mod_ds.plugin_name[i] = plg_name;
    }
    mod_ds.plugin_name[5] = "JSON notif";

    /* turn on logging */
    sr_log_stderr(SR_LL_WRN);

    /* create connection */
    if ((ret = sr_connect(SR_CONN_DEFAULT, &conn))) {
        return ret;
    }

    /* disable logging */
    sr_log_stderr(SR_LL_NONE);

    /* remove module if it was installed previously */
    ret = sr_remove_module(conn, "perf", 1);
    if (ret && (ret != SR_ERR_NOT_FOUND)) {
        return ret;
    }

    /* install module */
    ret = sr_install_module2(conn, TESTS_SRC_DIR "/files/perf.yang", NULL, NULL, &mod_ds, NULL, NULL, 0, NULL, NULL, LYD_XML);
    if (ret) {
        return ret;
    }

    /* turn on logging */
    sr_log_stderr(SR_LL_WRN);

    /* disconnect */
    sr_disconnect(conn);

    state->count = count;

    return SR_ERR_OK;
}

static int
sysrepo_destroy(void)
{
    int ret;
    sr_conn_ctx_t *conn;

    /* create connection */
    if ((ret = sr_connect(0, &conn))) {
        return ret;
    }

    /* remove module */
    ret = sr_remove_module(conn, "perf", 0);

    /* disconnect */
    sr_disconnect(conn);

    if (ret) {
        return ret;
    }

    return SR_ERR_OK;
}

struct test tests[] = {
    {"get tree", setup_running, test_get_tree, teardown_running},
    {"get item", setup_running, test_get_item, teardown_running},
    {"get tree hash", setup_running, test_get_tree_hash, teardown_running},
    {"get tree hash cached", setup_running_cached, test_get_tree_hash, teardown_running},
    {"get user ordered tree", setup_userordered_running, test_get_user_order_tree, teardown_running},
    {"get oper tree", setup_subscribe_oper, test_get_oper_tree, teardown_subscribe_oper},
    {"create batch", setup_empty, test_batch_create, teardown_empty},
    {"create user ordered items", setup_empty, test_user_order_items_create, teardown_empty},
    {"create all items", setup_empty, test_items_create, teardown_empty},
    {"create all items oper", setup_empty_oper, test_items_create_oper, teardown_empty},
    {"remove all items", setup_running, test_items_remove, teardown_empty},
    {"remove all items cached", setup_running_cached, test_items_remove, teardown_empty},
    {"remove whole subtree", setup_running, test_items_remove_subtree, teardown_empty},
    {"remove whole subtree cached", setup_running_cached, test_items_remove_subtree, teardown_empty},
    {"create an item", setup_running, test_item_create, teardown_running},
    {"create an item cached", setup_running_cached, test_item_create, teardown_running},
    {"create an item oper", setup_oper, test_item_create_oper, teardown_oper},
    {"modify an item", setup_running, test_item_modify, teardown_running},
    {"modify an item cached", setup_running_cached, test_item_modify, teardown_running},
    {"remove an item", setup_running, test_item_remove, teardown_running},
    {"remove an item cached", setup_running_cached, test_item_remove, teardown_running},
};

void
print_top_table_boundary(const char *plugin_name)
{
    uint32_t i;
    const char *first = " test name ", *second = " time ";
    const char *third = " comparison ";

    printf("\n  %s\n", plugin_name);

    printf(" ");
    for (i = 0; i < TABLE_WIDTH; ++i) {
        printf("_");
    }
    printf(" \n|");
    for (i = 0; i < TABLE_WIDTH; ++i) {
        printf(" ");
    }

    printf("|\n|");
    printf("%s", first);
    for (i = strlen(first); i <= NAME_FIXED_LEN + 2; ++i) {
        printf(" ");
    }
    printf("|");
    for (i = strlen(second); i < COL_FIXED_LEN - 1; ++i) {
        printf(" ");
    }
    printf("%s", second);
    printf("|");
    for (i = strlen(third); i < COL_FIXED_LEN; ++i) {
        printf(" ");
    }
    printf("%s", third);
    printf("|\n");

    // top table boundary
    printf("|");
    for (i = 0; i < TABLE_WIDTH; ++i) {
        printf("_");
    }
    printf("|\n");

    printf("|");
    for (i = 0; i < TABLE_WIDTH; ++i) {
        printf(" ");
    }

    printf("|\n");
}

void
print_test_results(const char *test_name, int64_t time, int64_t dflt_time)
{
    uint32_t printed;
    long double ratio = 1.0f;
    uint64_t ratio_decimal;

    printf("| %s ", test_name);
    printed = strlen(test_name);
    while (printed < NAME_FIXED_LEN) {
        printf(".");
        printed += 1;
    }
    printf(" | %3" PRId64 ".%06" PRId64 " s |", time / MILLION, time % MILLION);
    printf(" ");

    if (time < dflt_time) {
        printf("\033[0;32;1m");
        ratio = ABS((long double)(dflt_time) / (long double)(time));
    } else if (time > dflt_time) {
        printf("\033[0;31;1m");
        ratio = ABS((long double)(time) / (long double)(dflt_time));
    }
    ratio_decimal = (uint64_t)((ratio - (uint64_t)(ratio)) * 1000);

    printf("%7" PRIu64 ".%03" PRIu64 " x ", (uint64_t)(ratio), ratio_decimal);
    printf("\033[0;37;1m");
    printf("|\n");
}

void
print_bottom_table_boundary()
{
    uint32_t i;

    printf("|");
    for (i = 0; i < TABLE_WIDTH; ++i) {
        printf("_");
    }
    printf("|\n\n");
}

int
main(int argc, char **argv)
{
    int ret = 0;
    uint32_t i, j, count, tries, plg_cnt, test_cnt;
    const char *plg_name;
    int64_t *times = NULL, time;
    struct test_state state = {0};

    /* change print color */
    printf("\033[0;37;1m");

    /* handle arguments */
    if (argc < 3) {
        fprintf(stderr, "Usage:\n%s list-instance-count test-tries\n\n", argv[0]);
        return SR_ERR_INVAL_ARG;
    }

    count = atoi(argv[1]);
    if (count <= 0) {
        fprintf(stderr, "Invalid count \"%s\".\n", argv[1]);
        return SR_ERR_INVAL_ARG;
    }

    tries = atoi(argv[2]);
    if (tries <= 0) {
        fprintf(stderr, "Invalid tries \"%s\".\n", argv[2]);
        return SR_ERR_INVAL_ARG;
    }

    /* establish the number of plugins and tests */
    plg_cnt = sr_ds_plugin_int_count();
    test_cnt = (sizeof tests / sizeof(struct test));

    /* allocate a time var for every test of the default plugin */
    times = calloc(test_cnt, sizeof *times);
    if (!times) {
        fprintf(stderr, "Out of memory.\n");
        return SR_ERR_NO_MEMORY;
    }

    printf("\n| Options\n\n  Data set size      : %" PRIu32 "\n  Each test executed : %" PRIu32 " %s\n\n", count, tries,
            (tries > 1) ? "times" : "time");
    printf("\n| Performance tests\n");

    /* for every plugin run a set of tests */
    for (i = 0; i < plg_cnt; ++i) {
        /* plugin name */
        plg_name = sr_internal_ds_plugins[i]->name;

        print_top_table_boundary(plg_name);

        /* init */
        if ((ret = sysrepo_init(plg_name, &state, count))) {
            goto cleanup;
        }

        /* tests */
        for (j = 0; j < test_cnt; ++j) {
            if ((ret = exec_test(tests[j].setup, tests[j].test, tests[j].teardown, tries, &time, &state))) {
                /* one of the tests failed */
                goto cleanup;
            }

            /* store defaults plugin times to calculate the differences */
            if (i == 0) {
                times[j] = time;
            }

            print_test_results(tests[j].name, time, times[j]);
        }

        /* destroy */
        if ((ret = sysrepo_destroy())) {
            goto cleanup;
        }

        print_bottom_table_boundary();
    }

    printf("\nAll comparisons refer to how many times faster (green) or slower (red) the current plugin is compared to the first plugin.\n\n");

    /* change print color */
    printf(" \033[0;37m");

cleanup:
    free(times);
    return ret;
}
