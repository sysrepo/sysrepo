/**
 * @file perf.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief performance tests
 *
 * Copyright (c) 2021 CESNET, z.s.p.o.
 * Copyright (c) 2021 Deutsche Telekom AG.
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
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

#include <libyang/libyang.h>

#include "config.h"
#include "sysrepo.h"
#include "tests/tcommon.h"

#ifdef SR_HAVE_CALLGRIND
# include <valgrind/callgrind.h>
#endif

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

typedef int (*setup_cb)(uint32_t count, struct test_state *state);

typedef int (*test_cb)(struct test_state *state, struct timespec *ts_start, struct timespec *ts_end);

/**
 * @brief Single test structure.
 */
struct test {
    const char *name;
    setup_cb setup;
    test_cb test;
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
    int64_t nsec_diff;

    assert(ts1->tv_sec <= ts2->tv_sec);

    /* seconds diff */
    usec_diff += (ts2->tv_sec - ts1->tv_sec) * 1000000;

    /* nanoseconds diff */
    nsec_diff = ts2->tv_nsec - ts1->tv_nsec;
    usec_diff += nsec_diff ? nsec_diff / 1000 : 0;

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
exec_test(setup_cb setup, test_cb test, const char *name, uint32_t count, uint32_t tries)
{
    int ret;
    struct timespec ts_start, ts_end;
    struct test_state state = {0};
    const uint32_t name_fixed_len = 37;
    char str[name_fixed_len + 1];
    uint32_t i, printed;
    uint64_t time_usec = 0;

    /* print test start */
    printed = sprintf(str, "| %s ", name);
    while (printed + 2 < name_fixed_len) {
        printed += sprintf(str + printed, ".");
    }
    if (printed + 1 < name_fixed_len) {
        printed += sprintf(str + printed, " ");
    }
    sprintf(str + printed, "|");
    fputs(str, stdout);
    fflush(stdout);

    /* setup */
    if ((ret = setup(count, &state))) {
        return ret;
    }

    /* test */
    for (i = 0; i < tries; ++i) {
        if ((ret = test(&state, &ts_start, &ts_end))) {
            return ret;
        }
        time_usec += time_diff(&ts_start, &ts_end);
    }
    time_usec /= tries;

    /* teardown */
    sr_delete_item(state.sess, "/perf:cont", 0);
    sr_apply_changes(state.sess, 0);
    sr_unsubscribe(state.sub);
    sr_release_context(state.conn);
    sr_disconnect(state.conn);

    /* print time */
    printf(" %3" PRIu64 ".%06" PRIu64 " s |\n", time_usec / 1000000, time_usec % 1000000);

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
change_item_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data)
{
    int r;
    char change_path[32];
    sr_change_iter_t *it = NULL;
    sr_change_oper_t oper;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;

    (void)sub_id;
    (void)xpath;
    (void)event;
    (void)request_id;
    (void)private_data;

    sprintf(change_path, "/%s:*//.", module_name);

    if ((r = sr_get_changes_iter(session, change_path, &it))) {
        goto cleanup;
    }

    while (!sr_get_change_next(session, it, &oper, &old_value, &new_value)) {
        sr_free_val(old_value);
        sr_free_val(new_value);
    }

cleanup:
    sr_free_change_iter(it);
    return SR_ERR_OK;
}

static int
change_tree_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data)
{
    int r;
    char change_path[32];
    sr_change_iter_t *it = NULL;
    sr_change_oper_t oper;
    const struct lyd_node *node;

    (void)sub_id;
    (void)xpath;
    (void)event;
    (void)request_id;
    (void)private_data;

    sprintf(change_path, "/%s:*//.", module_name);

    if ((r = sr_get_changes_iter(session, change_path, &it))) {
        goto cleanup;
    }

    while (!sr_get_change_tree_next(session, it, &oper, &node, NULL, NULL, NULL)) {}

cleanup:
    sr_free_change_iter(it);
    return SR_ERR_OK;
}

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

/* TEST SETUP */
static int
setup_running(uint32_t count, struct test_state *state)
{
    int r;
    struct lyd_node *data;

    if ((r = sr_connect(0, &state->conn))) {
        return r;
    }
    if ((r = sr_session_start(state->conn, SR_DS_RUNNING, &state->sess))) {
        return r;
    }
    state->mod = ly_ctx_get_module_implemented(sr_acquire_context(state->conn), "perf");
    state->count = count;

    /* set running data */
    if ((r = create_list_inst(state->mod, 0, state->count, &data))) {
        return r;
    }
    if ((r = sr_edit_batch(state->sess, data, "merge"))) {
        return r;
    }
    if ((r = sr_apply_changes(state->sess, 0))) {
        return r;
    }
    lyd_free_siblings(data);

    return SR_ERR_OK;
}

static int
setup_running_cached(uint32_t count, struct test_state *state)
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
    state->count = count;

    /* set running data */
    if ((r = create_list_inst(state->mod, 0, state->count, &data))) {
        return r;
    }
    if ((r = sr_edit_batch(state->sess, data, "merge"))) {
        return r;
    }
    if ((r = sr_apply_changes(state->sess, 0))) {
        return r;
    }
    lyd_free_siblings(data);

    return SR_ERR_OK;
}

static int
setup_subscribe_change_item(uint32_t count, struct test_state *state)
{
    int r;

    if ((r = sr_connect(0, &state->conn))) {
        return r;
    }
    if ((r = sr_session_start(state->conn, SR_DS_RUNNING, &state->sess))) {
        return r;
    }
    if ((r = sr_module_change_subscribe(state->sess, "perf", NULL, change_item_cb, NULL, 0, 0, &state->sub))) {
        return r;
    }
    state->mod = ly_ctx_get_module_implemented(sr_acquire_context(state->conn), "perf");
    state->count = count;

    return SR_ERR_OK;
}

static int
setup_subscribe_change_tree(uint32_t count, struct test_state *state)
{
    int r;

    if ((r = sr_connect(0, &state->conn))) {
        return r;
    }
    if ((r = sr_session_start(state->conn, SR_DS_RUNNING, &state->sess))) {
        return r;
    }
    if ((r = sr_module_change_subscribe(state->sess, "perf", NULL, change_tree_cb, NULL, 0, 0, &state->sub))) {
        return r;
    }
    state->mod = ly_ctx_get_module_implemented(sr_acquire_context(state->conn), "perf");
    state->count = count;

    return SR_ERR_OK;
}

static int
setup_subscribe_oper(uint32_t count, struct test_state *state)
{
    int r;

    if ((r = sr_connect(0, &state->conn))) {
        return r;
    }
    if ((r = sr_session_start(state->conn, SR_DS_RUNNING, &state->sess))) {
        return r;
    }
    if ((r = sr_oper_get_subscribe(state->sess, "perf", "/perf:cont", oper_cb, state, 0, &state->sub))) {
        return r;
    }
    state->mod = ly_ctx_get_module_implemented(sr_acquire_context(state->conn), "perf");
    state->count = count;

    return SR_ERR_OK;
}

/* TEST CB */
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
test_edit_item_create(struct test_state *state, struct timespec *ts_start, struct timespec *ts_end)
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
test_edit_batch_create(struct test_state *state, struct timespec *ts_start, struct timespec *ts_end)
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
test_oper_get_tree(struct test_state *state, struct timespec *ts_start, struct timespec *ts_end)
{
    int r;
    sr_data_t *data;

    sr_session_switch_ds(state->sess, SR_DS_OPERATIONAL);

    TEST_START(ts_start);

    if ((r = sr_get_data(state->sess, "/perf:cont", 0, 0, 0, &data))) {
        return r;
    }

    TEST_END(ts_end);

    sr_release_data(data);
    sr_session_switch_ds(state->sess, SR_DS_RUNNING);

    return SR_ERR_OK;
}

struct test tests[] = {
    {"get tree", setup_running, test_get_tree},
    {"get item", setup_running, test_get_item},
    {"get tree hash", setup_running, test_get_tree_hash},
    {"get tree hash cached", setup_running_cached, test_get_tree_hash},
    {"edit item create", setup_subscribe_change_item, test_edit_item_create},
    {"edit batch create", setup_subscribe_change_tree, test_edit_batch_create},
    {"oper get tree", setup_subscribe_oper, test_oper_get_tree},
};

static int
sysrepo_init(void)
{
    int ret;
    sr_conn_ctx_t *conn;

    /* setup env */
    if ((ret = setenv("SYSREPO_REPOSITORY_PATH", TESTS_REPO_DIR "/test_repositories/sr_perf", 1))) {
        return ret;
    }
    if ((ret = setenv("SYSREPO_SHM_PREFIX", "_tests_sr_sr_perf", 1))) {
        return ret;
    }

    /* turn on logging */
    sr_log_stderr(SR_LL_WRN);

    /* create connection */
    if ((ret = sr_connect(0, &conn))) {
        return ret;
    }

    /* disable logging */
    sr_log_stderr(SR_LL_NONE);

    /* install module */
    ret = sr_install_module(conn, TESTS_SRC_DIR "/files/perf.yang", NULL, NULL);

    /* turn on logging */
    sr_log_stderr(SR_LL_WRN);

    /* disconnect */
    sr_disconnect(conn);

    if (ret && (ret != SR_ERR_EXISTS)) {
        return ret;
    }

    /* turn on logging */
    sr_log_stderr(SR_LL_WRN);

    return SR_ERR_OK;
}

int
main(int argc, char **argv)
{
    int ret;
    uint32_t i, count, tries;

    if (argc < 3) {
        fprintf(stderr, "Usage:\n%s list-instance-count test-tries\n\n", argv[0]);
        return SR_ERR_INVAL_ARG;
    }

    count = atoi(argv[1]);
    if (!count) {
        fprintf(stderr, "Invalid count \"%s\".\n", argv[1]);
        return SR_ERR_INVAL_ARG;
    }

    tries = atoi(argv[2]);
    if (!tries) {
        fprintf(stderr, "Invalid tries \"%s\".\n", argv[2]);
        return SR_ERR_INVAL_ARG;
    }

    printf("\nsr_perf:\n\tdata set size: %" PRIu32 "\n\teach test executed: %" PRIu32 " %s\n\n", count, tries,
            (tries > 1) ? "times" : "time");

    /* init */
    if ((ret = sysrepo_init())) {
        return ret;
    }

    /* tests */
    for (i = 0; i < (sizeof tests / sizeof(struct test)); ++i) {
        if ((ret = exec_test(tests[i].setup, tests[i].test, tests[i].name, count, tries))) {
            return ret;
        }
    }
    printf("\n");

    return SR_ERR_OK;
}
