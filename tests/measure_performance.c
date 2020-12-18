/**
 * @file measure_performance.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief File measure performance of the sysrepo operations
 *
 * @copyright
 * Copyright 2016 Cisco Systems, Inc.
 * Copyright 2019 CESNET, z.s.p.o.
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

#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdbool.h>
#include <libyang/libyang.h>

#include "tests/config.h"
#include "sysrepo.h"

/* Constants defining how many times the operation is performed to compute an average ops/sec */

/**@brief all operations except commit */
#define OP_COUNT 50000

/**@brief used with larger data files */
#define OP_COUNT_LOW 30000

/**@brief constant for commit operation */
#define OP_COUNT_COMMIT 1000

#define TEST_SCHEMA_SEARCH_DIR "/home/vasko/Documents/sysrepo/build/repository/yang/"
#define TEST_DATA_PREFIX "/dev/shm/sr_"
#define SR_RUNNING_FILE_EXT ".running"
#define EXAMPLE_MODULE_DATA_FILE_NAME TEST_DATA_PREFIX "example-module" SR_RUNNING_FILE_EXT

int instance_cnt = 1;

/* Computes diff of two timeval structures
 * @see http://www.gnu.org/software/libc/manual/html_node/Elapsed-Time.html
 */
int
timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y)
{
    /* Perform the carry for the later subtraction by updating y. */
    if (x->tv_usec < y->tv_usec) {
        int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
        y->tv_usec -= 1000000 * nsec;
        y->tv_sec += nsec;
    }
    if (x->tv_usec - y->tv_usec > 1000000) {
        int nsec = (x->tv_usec - y->tv_usec) / 1000000;
        y->tv_usec += 1000000 * nsec;
        y->tv_sec -= nsec;
    }

    /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
    result->tv_sec = x->tv_sec - y->tv_sec;
    result->tv_usec = x->tv_usec - y->tv_usec;

    /* Return 1 if result is negative. */
    return x->tv_sec < y->tv_sec;
}

typedef struct test_s{
    void ( *function)(void **, int, int *);
    char *op_name;
    int op_count;
    void (*setup)(void **);
    void (*teardown)(void **);
} test_t;

void
print_measure_header(const char *title)
{
    printf("\n\n\t\t%s", title);
    printf("\n%-32s| %10s | %10s | %13s | %10s | %10s\n",
            "Operation", "ops/sec", "items/op", "ops performed", "items/sec", "test time");
    printf("---------------------------------------------------------------------------------------------------\n");
}

/**
 * @brief Handles the process of time measurement.
 * 1. runs setup
 * 2. starts timer
 * 3. execute function being measured
 * 4. stops timer
 * 5. runs cleanup
 * 6. computes and prints the output
 *
 * Function being measured accepts:
 * - the state argument created by setup,
 * - the repeat count - how man times the operation should be performed
 * - pointer where the number of influenced items is returned
 */
void
measure(void (*func)(void **, int, int *), const char *name, int op_count, void (*setup)(void **), void (*teardown)(void **))
{
    struct timeval tv1 = {0, };
    struct timeval tv2 = {0, };
    struct timeval diff = {0, };
    void *state = NULL;
    double seconds = 0.0;
    int items = 0;

    setup(&state);

    gettimeofday(&tv1, NULL);

    func(&state, op_count, &items);

    gettimeofday(&tv2, NULL);
    teardown(&state);

    timeval_subtract(&diff, &tv2, &tv1);

    seconds = diff.tv_sec + 0.000001*diff.tv_usec;
    printf("%-32s| %10.0f | %10d | %13d | %10.0f | %10.2f\n",
            name, items ? ((double) op_count)/ seconds : 0, items, op_count, items ? ((double) op_count * items)/ seconds : 0, seconds);
}

void
sysrepo_setup(void **state)
{

    sr_conn_ctx_t *conn = NULL;
    int rc = SR_ERR_OK;

    /* turn off all logging */
    sr_log_stderr(SR_LL_WRN);
    sr_log_syslog("perf_test", SR_LL_NONE);

    /* connect to sysrepo */
    rc = sr_connect(SR_CONN_CACHE_RUNNING, &conn);
    assert_int_equal(rc, SR_ERR_OK);

    *state = (void*)conn;

}

void
sysrepo_teardown(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    /* disconnect from sysrepo */
    sr_disconnect(conn);
}

void
libyang_setup(void **state)
{
    struct ly_ctx *ctx = ly_ctx_new(TEST_SCHEMA_SEARCH_DIR, 0);
    const struct lys_module *module = ly_ctx_load_module(ctx, "example-module", NULL);
    assert_non_null(module);
    *state = (void *) ctx;
}

void
libyang_teardown(void **state)
{
    struct ly_ctx *ctx = *state;
    ly_ctx_destroy(ctx, NULL);
}

typedef struct dp_setup_s {
    sr_subscription_ctx_t *subs;
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *session;
    size_t if_count;
}dp_setup_t;


int
data_provide_cb(sr_session_ctx_t *session, const char *module_name, const char *path, const char *request_xpath,
        uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    size_t if_count = *((size_t *) private_data);
    int rc = SR_ERR_OK;
    struct lyd_node *list, *node, *stats;
    char *xpath;

    (void)session;
    (void)module_name;
    (void)path;
    (void)request_xpath;
    (void)request_id;

    for (size_t i = 0; i < if_count; i++) {
        asprintf(&xpath, "interface[name='eth%zu']", i);
        list = lyd_new_path(*parent, NULL, xpath, NULL, 0, 0);
        free(xpath);
        assert_non_null(list);

        node = lyd_new_leaf(list, NULL, "oper-status", "up");
        assert_non_null(node);

        stats = lyd_new(list, NULL, "statistics");
        assert_non_null(stats);

        node = lyd_new_leaf(stats, NULL, "in-octets", "456213");
        assert_non_null(node);

        node = lyd_new_leaf(stats, NULL, "in-unicast-pkts", "45213");
        assert_non_null(node);

        node = lyd_new_leaf(stats, NULL, "in-broadcast-pkts", "4213");
        assert_non_null(node);
    }

    return rc;
}

void
data_provide_setup(void **state)
{

    dp_setup_t *dp_setup = calloc(1, sizeof(*dp_setup));
    assert_non_null(dp_setup);
    int rc = SR_ERR_OK;

    /* turn off all logging */
    sr_log_stderr(SR_LL_NONE);
    sr_log_syslog(NULL, SR_LL_NONE);

    /* connect to sysrepo */
    rc = sr_connect(SR_CONN_DEFAULT, &dp_setup->conn);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_start(dp_setup->conn, SR_DS_RUNNING, &dp_setup->session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_oper_get_items_subscribe(dp_setup->session, "ietf-interfaces", "/ietf-interfaces:interfaces-state/interface",
            data_provide_cb, &dp_setup->if_count, SR_SUBSCR_DEFAULT, &dp_setup->subs);
    assert_int_equal(rc, SR_ERR_OK);

    sr_session_switch_ds(dp_setup->session, SR_DS_OPERATIONAL);

    *state = (void *) dp_setup;
}

void
data_provide_teardown(void **state)
{
    dp_setup_t *dp_setup = (dp_setup_t *) *state;

    sr_unsubscribe(dp_setup->subs);
    sr_session_stop(dp_setup->session);
    sr_disconnect(dp_setup->conn);

}

static void
perf_data_provide_test(void **state, int op_num, int *items)
{
    dp_setup_t *dp_setup = *state;
    assert_non_null(dp_setup);

    sr_val_t *value = NULL;
    size_t val_cnt = 0;
    int rc = 0;

    dp_setup->if_count = instance_cnt;

    /* perform get call*/
    for (int i = 0; i < op_num; i++){
        val_cnt = 0;
        value = NULL;

        rc = sr_get_items(dp_setup->session, "/ietf-interfaces:interfaces-state/interface/statistics//*", 0, 0, &value, &val_cnt);
        assert_int_equal(SR_ERR_OK, rc);

        sr_free_values(value, val_cnt);
    }

    /* stop the session */
    *items = val_cnt;
}

static void
perf_get_item_test(void **state, int op_num, int *items)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_val_t *value = NULL;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_RUNNING, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform a get-item request */
    for (int i = 0; i<op_num; i++){

        /* existing leaf */
        rc = sr_get_item(session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", 0, &value);
        assert_int_equal(rc, SR_ERR_OK);
        assert_non_null(value);
        assert_int_equal(SR_STRING_T, value->type);
        sr_free_val(value);
    }

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
    *items = 1;
}

static void
perf_get_item_first_test(void **state, int op_num, int *items)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_val_t *value = NULL;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_RUNNING, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform a get-item request */
    for (int i = 0; i<op_num; i++){

        /* existing first node in data tree */
        rc = sr_get_item(session, "/example-module:container", 0, &value);
        if (SR_ERR_OK == rc) {
            *items = 1;
            assert_non_null(value);
            assert_int_equal(SR_CONTAINER_T, value->type);
            sr_free_val(value);
        } else{
            *items = 0;
        }
    }

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
perf_get_item_with_data_load_test(void **state, int op_num, int *items)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_val_t *value = NULL;
    int rc = 0;


    /* perform session_start, get-item, session-stop requests */
    for (int i = 0; i<op_num; i++){
        /* start a session */
        rc = sr_session_start(conn, SR_DS_RUNNING, &session);
        assert_int_equal(rc, SR_ERR_OK);


        /* existing leaf */
        rc = sr_get_item(session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", 0, &value);
        assert_int_equal(rc, SR_ERR_OK);
        assert_non_null(value);
        assert_int_equal(SR_STRING_T, value->type);
        sr_free_val(value);

        /* stop the session */
        rc = sr_session_stop(session);
        assert_int_equal(rc, SR_ERR_OK);
    }


    *items = 1;
}

static void
perf_get_items_test(void **state, int op_num, int *items)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_val_t *values = NULL;
    size_t count = 0;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_RUNNING, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform a get-items request */
    for (int i = 0; i<op_num; i++){
        /* existing leaf */
        rc = sr_get_items(session, "/example-module:container/list/leaf", 0, 0, &values, &count);
        assert_int_equal(SR_ERR_OK, rc);
        sr_free_values(values, count);
    }

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
    *items = count;
}

static void
perf_get_items_iter_test(void **state, int op_num, int *items)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    (void)op_num;

    *items = 0;
}

static size_t
get_nodes_cnt(struct lyd_node *trees)
{
    struct lyd_node *root, *next, *elem;
    size_t count = 0;

    LY_TREE_FOR(trees, root) {
        LY_TREE_DFS_BEGIN(root, next, elem) {
            ++count;
            LY_TREE_DFS_END(root, next, elem);
        }
    }

    return count;
}

static void
perf_get_ietf_intefaces_test(void **state, int op_num, int *items)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    struct lyd_node *data;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_RUNNING, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform a get-items_iter request */
    size_t count = 0;
    for (int i = 0; i<op_num; i++){
        count = 0;
        /* existing leaf */
        rc = sr_get_data(session, "/ietf-interfaces:interfaces/*", 0, 0, 0, &data);
        assert_int_equal(SR_ERR_OK, rc);
        count += get_nodes_cnt(data);
        lyd_free_withsiblings(data);
    }

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
    *items = count;
}

static void
perf_get_subtree_test(void **state, int op_num, int *items)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    struct lyd_node *tree = NULL;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_RUNNING, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform a get-item request */
    for (int i = 0; i<op_num; i++){
        /* existing leaf */
        rc = sr_get_subtree(session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", 0, &tree);
        assert_int_equal(rc, SR_ERR_OK);
        assert_non_null(tree);
        assert_int_equal(LY_TYPE_STRING, ((struct lys_node_leaf *)tree->schema)->type.base);
        lyd_free(tree);
    }

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
    *items = 1;
}

static void
perf_get_subtree_with_data_load_test(void **state, int op_num, int *items)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    struct lyd_node *tree = NULL;
    int rc = 0;

    /* perform session_start, get-item, session-stop requests */
    for (int i = 0; i<op_num; i++){
        /* start a session */
        rc = sr_session_start(conn, SR_DS_RUNNING, &session);
        assert_int_equal(rc, SR_ERR_OK);

        /* existing leaf */
        rc = sr_get_subtree(session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", 0, &tree);
        assert_int_equal(rc, SR_ERR_OK);
        assert_non_null(tree);
        assert_int_equal(LY_TYPE_STRING, ((struct lys_node_leaf *)tree->schema)->type.base);
        lyd_free(tree);

        /* stop the session */
        rc = sr_session_stop(session);
        assert_int_equal(rc, SR_ERR_OK);
    }

    *items = 1;
}

static void
perf_get_subtrees_test(void **state, int op_num, int *items)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    struct lyd_node *trees = NULL;
    size_t count = 0;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_RUNNING, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform a get-subtrees request */
    for (int i = 0; i<op_num; i++){
        count = 0;
        /* existing leaf */
        rc = sr_get_data(session, "/example-module:container/list/leaf", 0, 0, 0, &trees);
        assert_int_equal(SR_ERR_OK, rc);
        /* skip 2 keys */
        assert_string_equal(trees->child->child->next->next->schema->name, "leaf");
        count += get_nodes_cnt(trees);
        lyd_free_withsiblings(trees);
    }

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
    *items = count;
}

static void
perf_get_ietf_intefaces_tree_test(void **state, int op_num, int *items)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    struct lyd_node *trees = NULL;
    size_t total_cnt = 0;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_RUNNING, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform a get-subtrees request */
    for (int i = 0; i<op_num; i++){
        rc = sr_get_data(session, "/ietf-interfaces:interfaces/.", 0, 0, 0, &trees);
        assert_int_equal(rc, SR_ERR_OK);
        if (0 == i) {
            total_cnt = get_nodes_cnt(trees);
        }
        lyd_free_withsiblings(trees);
    }

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
    *items = total_cnt;
}

static void
perf_set_delete_test(void **state, int op_num, int *items)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    (void)op_num;
//     sr_session_ctx_t *session = NULL;
//     char xpath[PATH_MAX] = { 0, };
//     int rc = 0;
//
//     /* start a session */
//     rc = sr_session_start(conn, SR_DS_RUNNING, &session);
//     assert_int_equal(rc, SR_ERR_OK);
//
//     /* perform edit, commit request */
//     sr_val_t value = {0,};
//     for (size_t i = 0; i < op_num; i++) {
//
//         /* set a list instance */
//         sprintf(xpath, "/example-module:container/list[key1='set_del'][key2='set_1']/leaf");
//         value.type = SR_STRING_T;
//         value.data.string_val = strdup("Leaf");
//         assert_non_null(value.data.string_val);
//         rc = sr_set_item(session, xpath, &value, SR_EDIT_DEFAULT);
//         assert_int_equal(rc, SR_ERR_OK);
//
//         /* delete a list instance */
//         sprintf(xpath, "/example-module:container/list[key1='set_del'][key2='set_1']");
//         rc = sr_delete_item(session, xpath, SR_EDIT_DEFAULT);
//         assert_int_equal(rc, SR_ERR_OK);
//     }
//
//     /* stop the session */
//     rc = sr_session_stop(session);
//     assert_int_equal(rc, SR_ERR_OK);
//
//     *items = 1 /* list instances */ * 3 /* leaves */ * 2 /* set + delete */ ;
    *items = 0;
}

static void
perf_set_delete_100_test(void **state, int op_num, int *items)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    (void)op_num;
//     sr_session_ctx_t *session = NULL;
//     char xpath[PATH_MAX] = { 0, };
//     int rc = 0;
//
//     /* start a session */
//     rc = sr_session_start(conn, SR_DS_RUNNING, &session);
//     assert_int_equal(rc, SR_ERR_OK);
//
//     /* perform edit, commit request */
//     sr_val_t value = {0,};
//     for (size_t i = 0; i < op_num; i++) {
//
//         /* set 100 list instances */
//         for (size_t j = 0; j <= 100; j++) {
//             sprintf(xpath, "/example-module:container/list[key1='set_del'][key2='set_%zu']/leaf", j);
//             value.type = SR_STRING_T;
//             value.data.string_val = strdup("Leaf");
//             assert_non_null(value.data.string_val);
//             rc = sr_set_item(session, xpath, &value, SR_EDIT_DEFAULT);
//             assert_int_equal(rc, SR_ERR_OK);
//         }
//
//         /* delete 100 list instances */
//         for (size_t j = 0; j <= 100; j++) {
//             sprintf(xpath, "/example-module:container/list[key1='set_del'][key2='set_%zu']", j);
//             rc = sr_delete_item(session, xpath, SR_EDIT_DEFAULT);
//             assert_int_equal(rc, SR_ERR_OK);
//         }
//     }
//
//     /* stop the session */
//     rc = sr_session_stop(session);
//     assert_int_equal(rc, SR_ERR_OK);
//
//     *items = 100 /* list instances */ * 3 /* leaves */ * 2 /* set + delete */ ;
    *items = 0;
}

static void
perf_commit_test(void **state, int op_num, int *items)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_RUNNING, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform edit, commit request */
    bool even = true;
    for (int i = 0; i<op_num; i++){
        if (even) {
            rc = sr_delete_item(session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", SR_EDIT_DEFAULT);
        } else {
            sr_val_t value = {0,};
            value.type = SR_STRING_T;
            value.data.string_val = strdup("Leaf");
            assert_non_null(value.data.string_val);
            rc = sr_set_item(session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &value, SR_EDIT_DEFAULT);
        }
        assert_int_equal(rc, SR_ERR_OK);
        rc = sr_apply_changes(session, 0, 1);
        assert_int_equal(rc, SR_ERR_OK);
        even = !even;
    }

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
    *items = 1;
}

static int
test_rpc_cb(sr_session_ctx_t *session, const char *op_path, const sr_val_t *input, const size_t input_cnt,
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
    sr_val_t *v = NULL;
    (void)session;
    (void)op_path;
    (void)input;
    (void)event;
    (void)request_id;
    (void)private_data;

    /* check input */
    assert_true(input_cnt > 0);

    v = calloc(1, sizeof *v);
    assert_non_null(v);

    v->xpath = strdup("/test-module:activate-software-image/status");
    v->type = SR_STRING_T;
    v->data.string_val = strdup("The image acmefw-2.3 is being installed.");

    *output = v;
    *output_cnt = 1;

    return SR_ERR_OK;
}

static int
test_dummy_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data)
{
    (void)session;
    (void)module_name;
    (void)xpath;
    (void)event;
    (void)request_id;
    (void)private_data;
    return SR_ERR_OK;
}

static void
perf_rpc_test(void **state, int op_num, int *items)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_val_t input = { 0, };
    sr_val_t *output = NULL;
    size_t output_cnt = 0;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_RUNNING, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe for RPC */
    rc = sr_rpc_subscribe(session, "/test-module:activate-software-image", test_rpc_cb, NULL, 0, SR_SUBSCR_DEFAULT,
            &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe to a default leaf so that it is present in operational */
    rc = sr_module_change_subscribe(session, "test-module", "/test-module:top-level-default", test_dummy_cb, NULL, 0,
            SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    input.xpath = "/test-module:activate-software-image/image-name";
    input.type = SR_STRING_T;
    input.data.string_val = "acmefw-2.3";

    /* send the RPC */
    for (int i = 0; i < op_num; i++) {
        rc = sr_rpc_send(session, "/test-module:activate-software-image", &input, 1, 0, &output, &output_cnt);
        assert_int_equal(rc, SR_ERR_OK);
        assert_true(output_cnt > 0);
        sr_free_values(output, output_cnt);
    }

    /* unsubscribe from RPCs */
    rc = sr_unsubscribe(subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
    *items = 1;
}

static void
test_event_notif_link_discovery_cb(sr_session_ctx_t *session, const sr_ev_notif_type_t notif_type, const char *path,
        const sr_val_t *values, const size_t values_cnt, time_t timestamp, void *private_data)
{
    (void)session;
    (void)notif_type;
    (void)path;
    (void)values;
    (void)timestamp;
    (void)private_data;
    assert_true(values_cnt > 0);
}

static void
perf_ev_notification_test(void **state, int op_num, int *items, bool ephemeral)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_val_t values[4] = { { 0, }, };
    int rc = 0;

    if (ephemeral) {
        rc = sr_set_module_replay_support(conn, "test-module", 0);
        assert_int_equal(rc, SR_ERR_OK);
    } else {
        rc = sr_set_module_replay_support(conn, "test-module", 1);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* start a session */
    rc = sr_session_start(conn, SR_DS_RUNNING, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* enable notification buffering */
    rc = sr_session_notif_buffer(session);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe for event notification */
    rc = sr_event_notif_subscribe(session, "test-module", "/test-module:link-discovered", 0, 0,
            test_event_notif_link_discovery_cb, NULL, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* send event notification - link discovery */
    values[0].xpath = "/test-module:link-discovered/source/address";
    values[0].type = SR_STRING_T;
    values[0].data.string_val = "10.10.1.5";
    values[1].xpath = "/test-module:link-discovered/source/interface";
    values[1].type = SR_STRING_T;
    values[1].data.string_val = "eth1";
    values[2].xpath = "/test-module:link-discovered/destination/address";
    values[2].type = SR_STRING_T;
    values[2].data.string_val = "10.10.1.8";
    values[3].xpath = "/test-module:link-discovered/destination/interface";
    values[3].type = SR_STRING_T;
    values[3].data.string_val = "eth0";

    /* send the notification */
    for (int i = 0; i < op_num; i++) {
        rc = sr_event_notif_send(session, "/test-module:link-discovered", values, 4);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* unsubscribe from notifications */
    rc = sr_unsubscribe(subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
    *items = 1;
}

static void
perf_ev_notification_ephemeral_test(void **state, int op_num, int *items)
{
    perf_ev_notification_test(state, op_num, items, true);
}

static void
perf_ev_notification_store_test(void **state, int op_num, int *items)
{
    perf_ev_notification_test(state, op_num, items, false);
}

static void
perf_libyang_get_node(void **state, int op_num, int *items)
{
    struct ly_ctx *ctx = *state;
    assert_non_null(ctx);

    struct lyd_node *root = lyd_parse_path(ctx, EXAMPLE_MODULE_DATA_FILE_NAME, LYD_LYB, LYD_OPT_CONFIG | LYD_OPT_STRICT);
    assert_non_null(root);

    /* perform a lyd_get_node op */
    for (int i = 0; i<op_num; i++){

        /* existing leaf */
        struct ly_set *set = lyd_find_path(root, "/example-module:container/list[key1='key1'][key2='key2']/leaf");
        assert_non_null(set);
        ly_set_free(set);
    }

    lyd_free_withsiblings(root);
    *items = 1;
}

static void
perf_libyang_get_all_list(void **state, int op_num, int *items)
{
    struct ly_ctx *ctx = *state;
    assert_non_null(ctx);

    struct lyd_node *root = lyd_parse_path(ctx, EXAMPLE_MODULE_DATA_FILE_NAME, LYD_LYB, LYD_OPT_CONFIG | LYD_OPT_STRICT);
    assert_non_null(root);

    /* perform a lyd_get_node op */
    for (int i = 0; i<op_num; i++){

        /* existing leaf */
        struct ly_set *set = lyd_find_path(root, "/example-module:container/list/leaf");
        *items = set->number;
        assert_non_null(set);
        ly_set_free(set);
    }

    lyd_free_withsiblings(root);

}

void
test_perf(test_t *ts, int test_count, const char *title, int selection)
{
    print_measure_header(title);
    for (int i = 0; i < test_count; i++) {
        test_t *t = &ts[i];
        if (-1 == selection || i == selection){
            measure(t->function, t->op_name, t->op_count, t->setup, t->teardown);
        }
    }
}

static void
createDataTreeExampleModule(sr_session_ctx_t *sess)
{
    const struct ly_ctx *ctx = NULL;
    struct lyd_node *root = NULL;

    ctx = sr_get_context(sr_session_get_connection(sess));

    const struct lys_module *module = ly_ctx_get_module(ctx, "example-module", NULL, 1);
    assert_non_null(module);

#define XPATH "/example-module:container/list[key1='key1'][key2='key2']/leaf"

    root = lyd_new_path(NULL, ctx, XPATH, "Leaf value", 0, 0);
    assert_non_null(root);
    assert_int_equal(0, lyd_validate(&root, LYD_OPT_STRICT | LYD_OPT_CONFIG, NULL));
    assert_int_equal(SR_ERR_OK, sr_replace_config(sess, "example-module", root, 0, 1));
}

static void
createDataTreeLargeExampleModule(sr_session_ctx_t *sess, int list_count)
{
    const struct ly_ctx *ctx = NULL;
    struct lyd_node *root = NULL, *node = NULL;

    ctx = sr_get_context(sr_session_get_connection(sess));

    const struct lys_module *module = ly_ctx_get_module(ctx, "example-module", NULL, 1);
    assert_non_null(module);

#define MAX_XP_LEN 100
    const char *template = "/example-module:container/list[key1='k1%d'][key2='k2%d']/leaf";
    char xpath[MAX_XP_LEN] = {0,};


    for (int i = 0; i < list_count; i++){
        snprintf(xpath, MAX_XP_LEN, template, i, i);
        node = lyd_new_path(root, ctx, xpath, "Leaf value", 0, 0);
        if (NULL == root) {
            root = node;
        }
    }
    lyd_new_path(root, ctx, "/example-module:container/list[key1='key1'][key2='key2']/leaf", "Leaf value", 0, 0);

    assert_int_equal(0, lyd_validate(&root, LYD_OPT_STRICT | LYD_OPT_CONFIG, NULL));
    assert_int_equal(SR_ERR_OK, sr_replace_config(sess, "example-module", root, 0, 1));
}

static void
createDataTreeLargeIETFinterfacesModule(sr_session_ctx_t *sess, size_t if_count)
{

    const struct ly_ctx *ctx = sr_get_context(sr_session_get_connection(sess));

    struct lyd_node *root = NULL;

    #define MAX_IF_LEN 150
    const char *template_prefix_len = "/ietf-interfaces:interfaces/interface[name='eth%d']/ietf-ip:ipv4/ietf-ip:address[ietf-ip:ip='192.168.%d.%d']/ietf-ip:prefix-length";
    const char *template_type = "/ietf-interfaces:interfaces/interface[name='eth%d']/type";
    const char *template_desc = "/ietf-interfaces:interfaces/interface[name='eth%d']/description";
    const char *template_enabled = "/ietf-interfaces:interfaces/interface[name='eth%d']/enabled";
    const char *template_ipv4_enabled = "/ietf-interfaces:interfaces/interface[name='eth%d']/ietf-ip:ipv4/ietf-ip:enabled";
    const char *template_ipv4_mtu = "/ietf-interfaces:interfaces/interface[name='eth%d']/ietf-ip:ipv4/ietf-ip:mtu";
    char xpath[MAX_IF_LEN] = {0,};

    const struct lys_module *module_interfaces = ly_ctx_get_module(ctx, "ietf-interfaces", NULL, 1);
    assert_non_null(module_interfaces);
    const struct lys_module *module_ip = ly_ctx_get_module(ctx, "ietf-ip", NULL, 1);
    assert_non_null(module_ip);
    const struct lys_module *module = ly_ctx_get_module(ctx, "iana-if-type", "2014-05-08", 1);
    assert_non_null(module);
    struct lyd_node *node = NULL;

    for (size_t i = 1; i < (if_count+1); i++) {
        snprintf(xpath, MAX_IF_LEN, template_prefix_len, i, (i/244 +1), i % 244);
        node = lyd_new_path(root, ctx, xpath, "24", 0, 0);
        if (NULL == root) {
            root = node;
        }
        snprintf(xpath, MAX_IF_LEN, template_type, i);
        lyd_new_path(root, ctx, xpath, "iana-if-type:ethernetCsmacd", 0, 0);

        snprintf(xpath, MAX_IF_LEN, template_desc, i);
        lyd_new_path(root, ctx, xpath, "ethernet interface", 0, 0);

        snprintf(xpath, MAX_IF_LEN, template_enabled, i);
        lyd_new_path(root, ctx, xpath, "true", 0, 0);

        snprintf(xpath, MAX_IF_LEN, template_ipv4_enabled, i);
        lyd_new_path(root, ctx, xpath, "true", 0, 0);

        snprintf(xpath, MAX_IF_LEN, template_ipv4_mtu, i);
        lyd_new_path(root, ctx, xpath, "1500", 0, 0);

    }


    assert_int_equal(0, lyd_validate(&root, LYD_OPT_STRICT | LYD_OPT_CONFIG, NULL));
    assert_int_equal(SR_ERR_OK, sr_replace_config(sess, "ietf-interfaces", root, 0, 1));
}

int
main(int argc, char **argv)
{
    test_t tests[] = {
        {perf_get_item_test, "Get item one leaf", OP_COUNT, sysrepo_setup, sysrepo_teardown},
        {perf_get_item_first_test, "Get item first leaf", OP_COUNT, sysrepo_setup, sysrepo_teardown},
        {perf_get_item_with_data_load_test, "Get item incl session start", OP_COUNT, sysrepo_setup, sysrepo_teardown},
        {perf_get_items_test, "Get items all lists", OP_COUNT, sysrepo_setup, sysrepo_teardown},
        {perf_get_items_iter_test, "Get items iter all lists", OP_COUNT, sysrepo_setup, sysrepo_teardown},
        {perf_get_ietf_intefaces_test, "Get items ietf-if config", OP_COUNT, sysrepo_setup, sysrepo_teardown},
        {perf_get_subtree_test, "Get subtree one leaf", OP_COUNT, sysrepo_setup, sysrepo_teardown},
        {perf_get_subtree_with_data_load_test, "Get subtree incl session start", OP_COUNT, sysrepo_setup, sysrepo_teardown},
        {perf_get_subtrees_test, "Get subtrees all lists", OP_COUNT, sysrepo_setup, sysrepo_teardown},
        {perf_get_ietf_intefaces_tree_test, "Get subtrees ietf-if config", OP_COUNT, sysrepo_setup, sysrepo_teardown},
        {perf_set_delete_test, "Set & delete one list", OP_COUNT, sysrepo_setup, sysrepo_teardown},
        {perf_set_delete_100_test, "Set & delete 100 lists", OP_COUNT_COMMIT, sysrepo_setup, sysrepo_teardown},
        {perf_commit_test, "Commit one leaf change", OP_COUNT_COMMIT, sysrepo_setup, sysrepo_teardown},
        {perf_data_provide_test, "Operational data provide", OP_COUNT_COMMIT, data_provide_setup, data_provide_teardown},
        {perf_rpc_test, "RPC", OP_COUNT_COMMIT, sysrepo_setup, sysrepo_teardown},
        {perf_ev_notification_ephemeral_test, "Event notification - ephemeral", OP_COUNT_COMMIT, sysrepo_setup, sysrepo_teardown},
        {perf_ev_notification_store_test, "Event notification - store", OP_COUNT_COMMIT, sysrepo_setup, sysrepo_teardown},
        {perf_libyang_get_node, "Libyang get one node", OP_COUNT, libyang_setup, libyang_teardown},
        {perf_libyang_get_all_list, "Libyang get all list", OP_COUNT, libyang_setup, libyang_teardown},
    };

    size_t test_count = sizeof(tests)/sizeof(*tests);
    sr_conn_ctx_t *conn = NULL;
    sr_session_ctx_t *sess;
    int rc, ret = -1, selection = -1;
    uint32_t conn_count;

    if (argc > 1) {
        rc = sscanf(argv[1], "%d", &selection);
        assert_int_equal(rc, 1);
    }

    sr_connection_count(&conn_count);
    if (conn_count) {
        puts("There can be no running connections.\n");
        goto cleanup;
    }

    sr_connect(0, &conn);

    /* install required modules */
    rc = sr_install_module(conn, TESTS_DIR "/files/example-module.yang", TESTS_DIR "/files", NULL, 0);
    if (rc && (rc != SR_ERR_EXISTS)) {
        goto cleanup;
    }
    rc = sr_install_module(conn, TESTS_DIR "/files/referenced-data.yang", TESTS_DIR "/files", NULL, 0);
    if (rc && (rc != SR_ERR_EXISTS)) {
        goto cleanup;
    }
    rc = sr_install_module(conn, TESTS_DIR "/files/test-module.yang", TESTS_DIR "/files", NULL, 0);
    if (rc && (rc != SR_ERR_EXISTS)) {
        goto cleanup;
    }
    rc = sr_install_module(conn, TESTS_DIR "/files/ietf-ip.yang", TESTS_DIR "/files", NULL, 0);
    if (rc && (rc != SR_ERR_EXISTS)) {
        goto cleanup;
    }
    rc = sr_install_module(conn, TESTS_DIR "/files/iana-if-type.yang", TESTS_DIR "/files", NULL, 0);
    if (rc && (rc != SR_ERR_EXISTS)) {
        goto cleanup;
    }

    sr_disconnect(conn);
    sr_connect(0, &conn);
    sr_session_start(conn, SR_DS_RUNNING, &sess);

    /* one list instance */
    createDataTreeExampleModule(sess);
    createDataTreeLargeIETFinterfacesModule(sess, 1);
    instance_cnt = 1;
    test_perf(tests, test_count, "Data file with one list instance", selection);

    /* 20 list instances*/
    createDataTreeLargeExampleModule(sess, 20);
    createDataTreeLargeIETFinterfacesModule(sess, 20);
    instance_cnt = 20;
    test_perf(tests, test_count, "Data file with 20 list instances", selection);


    /* decrease the number of performed operation on larger file */
    for (size_t i = 0; i < test_count; i++){
        if (OP_COUNT_COMMIT != tests[i].op_count){
            tests[i].op_count = OP_COUNT_LOW;
        }
    }

    /* 100 list instances*/
    createDataTreeLargeExampleModule(sess, 100);
    createDataTreeLargeIETFinterfacesModule(sess, 100);
    instance_cnt = 100;
    test_perf(tests, test_count, "Data file with 100 list instances", selection);
    puts("\n\n");
    ret = 0;

cleanup:
    /* uninstall modules */
    sr_remove_module(conn, "example-module");
    sr_remove_module(conn, "test-module");
    sr_remove_module(conn, "referenced-data");
    sr_remove_module(conn, "ietf-ip");
    sr_remove_module(conn, "iana-if-type");
    sr_remove_module(conn, "ietf-interfaces");
    sr_disconnect(conn);
    return ret;
}
