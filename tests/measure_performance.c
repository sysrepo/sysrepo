/**
 * @file measure_performance.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief File measure performance of the sysrepo operations
 *
 * @copyright
 * Copyright 2016 Cisco Systems, Inc.
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

#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdbool.h>
#include <libyang/libyang.h>
#include "sysrepo.h"
#include "test_module_helper.h"

/* Constants defining how many times the operation is performed to compute an average ops/sec */

/**@brief all operations except commit */
#define OP_COUNT 50000

/**@brief used with larger data files */
#define OP_COUNT_LOW 30000

/**@brief constant for commit operation */
#define OP_COUNT_COMMIT 1000

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
}test_t;

void
print_measure_header(const char *title){
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
            name, ((double) op_count)/ seconds, items, op_count, ((double) op_count * items)/ seconds, seconds);
}

void
sysrepo_setup(void **state)
{

    sr_conn_ctx_t *conn = NULL;
    int rc = SR_ERR_OK;

    /* turn off all logging */
    sr_log_stderr(SR_LL_NONE);
    sr_log_syslog(SR_LL_NONE);

    /* connect to sysrepo */
    rc = sr_connect("perf_test", SR_CONN_DEFAULT, &conn);
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
    struct ly_ctx *ctx = ly_ctx_new(TEST_SCHEMA_SEARCH_DIR);
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

static void
perf_get_item_test(void **state, int op_num, int *items) {
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_val_t *value = NULL;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform a get-item request */
    for (size_t i = 0; i<op_num; i++){

        /* existing leaf */
        rc = sr_get_item(session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &value);
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
perf_get_item_first_test(void **state, int op_num, int *items) {
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_val_t *value = NULL;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform a get-item request */
    for (size_t i = 0; i<op_num; i++){

        /* existing first node in data tree */
        rc = sr_get_item(session, "/example-module:container", &value);
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
perf_get_item_with_data_load_test(void **state, int op_num, int *items) {
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_val_t *value = NULL;
    int rc = 0;


    /* perform session_start, get-item, session-stop requests */
    for (size_t i = 0; i<op_num; i++){
        /* start a session */
        rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
        assert_int_equal(rc, SR_ERR_OK);


        /* existing leaf */
        rc = sr_get_item(session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &value);
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
perf_get_items_test(void **state, int op_num, int *items) {
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_val_t *values = NULL;
    size_t count = 0;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform a get-items request */
    for (size_t i = 0; i<op_num; i++){
        /* existing leaf */
        rc = sr_get_items(session, "/example-module:container/list/leaf", &values, &count);
        assert_int_equal(SR_ERR_OK, rc);
        sr_free_values(values, count);
    }

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
    *items = count;
}

static void
perf_get_items_iter_test(void **state, int op_num, int *items) {
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_val_t *value = NULL;
    sr_val_iter_t *iter = NULL;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform a get-items_iter request */
    size_t count = 0;
    for (size_t i = 0; i<op_num; i++){
        count = 0;
        /* existing leaf */
        rc = sr_get_items_iter(session, "/example-module:container/list/leaf", &iter);
        assert_int_equal(SR_ERR_OK, rc);
        while (SR_ERR_OK == sr_get_item_next(session, iter, &value)){
            sr_free_val(value);
            count++;
        }
        sr_free_val_iter(iter);
    }

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
    *items = count;
}

static void
perf_get_ietf_intefaces_test(void **state, int op_num, int *items) {
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_val_t *value = NULL;
    sr_val_iter_t *iter = NULL;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform a get-items_iter request */
    size_t count = 0;
    for (size_t i = 0; i<op_num; i++){
        count = 0;
        /* existing leaf */
        rc = sr_get_items_iter(session, "/ietf-interfaces:interfaces//*", &iter);
        assert_int_equal(SR_ERR_OK, rc);
        while (SR_ERR_OK == sr_get_item_next(session, iter, &value)){
            sr_free_val(value);
            count++;
        }
        sr_free_val_iter(iter);
    }

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
    *items = count;
}

static void
perf_get_subtree_test(void **state, int op_num, int *items) {
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_node_t *tree = NULL;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform a get-item request */
    for (size_t i = 0; i<op_num; i++){
        /* existing leaf */
        rc = sr_get_subtree(session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", 0, &tree);
        assert_int_equal(rc, SR_ERR_OK);
        assert_non_null(tree);
        assert_int_equal(SR_STRING_T, tree->type);
        sr_free_tree(tree);
    }

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
    *items = 1;
}

static void
perf_get_subtree_with_data_load_test(void **state, int op_num, int *items) {
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_node_t *tree = NULL;
    int rc = 0;

    /* perform session_start, get-item, session-stop requests */
    for (size_t i = 0; i<op_num; i++){
        /* start a session */
        rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
        assert_int_equal(rc, SR_ERR_OK);

        /* existing leaf */
        rc = sr_get_subtree(session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", 0, &tree);
        assert_int_equal(rc, SR_ERR_OK);
        assert_non_null(tree);
        assert_int_equal(SR_STRING_T, tree->type);
        sr_free_tree(tree);

        /* stop the session */
        rc = sr_session_stop(session);
        assert_int_equal(rc, SR_ERR_OK);
    }

    *items = 1;
}

static void
perf_get_subtrees_test(void **state, int op_num, int *items) {
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_node_t *trees = NULL;
    size_t count = 0;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform a get-subtrees request */
    for (size_t i = 0; i<op_num; i++){
        /* existing leaf */
        rc = sr_get_subtrees(session, "/example-module:container/list/leaf", 0, &trees, &count);
        assert_int_equal(SR_ERR_OK, rc);
        assert_null(trees[0].first_child);
        sr_free_trees(trees, count);
    }

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
    *items = count;
}

static size_t
get_nodes_cnt(sr_node_t *trees, size_t tree_cnt)
{
    sr_node_t *node = NULL;
    bool count_children = true;
    size_t count = 0;

    for (size_t i = 0; i < tree_cnt; ++i) {
        node = trees+i;
        count_children = true;
        do {
            if (count_children) {
                while (node->first_child) {
                    node = node->first_child;
                }
            }
            ++count;
            if (node->next) {
                node = node->next;
                count_children = true;
            } else {
                node = node->parent;
                count_children = false;
            }
        } while(node);
    }

    return count;
}

static void
perf_get_ietf_intefaces_tree_test(void **state, int op_num, int *items) {
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_node_t *trees = NULL;
    size_t count = 0;
    size_t total_cnt = 0;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform a get-subtrees request */
    for (size_t i = 0; i<op_num; i++){
        rc = sr_get_subtrees(session, "/ietf-interfaces:interfaces/.", 0, &trees, &count);
        assert_int_equal(rc, SR_ERR_OK);
        if (0 == i) {
            total_cnt = get_nodes_cnt(trees, count);
        }
        sr_free_trees(trees, count);
    }

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
    *items = total_cnt;
}

static void
perf_set_delete_test(void **state, int op_num, int *items) {
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    char xpath[PATH_MAX] = { 0, };
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform edit, commit request */
    sr_val_t value = {0,};
    for (size_t i = 0; i < op_num; i++) {

        /* set a list instance */
        sprintf(xpath, "/example-module:container/list[key1='set_del'][key2='set_1']/leaf");
        value.type = SR_STRING_T;
        value.data.string_val = strdup("Leaf");
        assert_non_null(value.data.string_val);
        rc = sr_set_item(session, xpath, &value, SR_EDIT_DEFAULT);
        assert_int_equal(rc, SR_ERR_OK);

        /* delete a list instance */
        sprintf(xpath, "/example-module:container/list[key1='set_del'][key2='set_1']");
        rc = sr_delete_item(session, xpath, SR_EDIT_DEFAULT);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);

    *items = 1 /* list instances */ * 3 /* leaves */ * 2 /* set + delete */ ;
}

static void
perf_set_delete_100_test(void **state, int op_num, int *items) {
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    char xpath[PATH_MAX] = { 0, };
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform edit, commit request */
    sr_val_t value = {0,};
    for (size_t i = 0; i < op_num; i++) {

        /* set 100 list instances */
        for (size_t j = 0; j <= 100; j++) {
            sprintf(xpath, "/example-module:container/list[key1='set_del'][key2='set_%zu']/leaf", j);
            value.type = SR_STRING_T;
            value.data.string_val = strdup("Leaf");
            assert_non_null(value.data.string_val);
            rc = sr_set_item(session, xpath, &value, SR_EDIT_DEFAULT);
            assert_int_equal(rc, SR_ERR_OK);
        }

        /* delete 100 list instances */
        for (size_t j = 0; j <= 100; j++) {
            sprintf(xpath, "/example-module:container/list[key1='set_del'][key2='set_%zu']", j);
            rc = sr_delete_item(session, xpath, SR_EDIT_DEFAULT);
            assert_int_equal(rc, SR_ERR_OK);
        }
    }

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);

    *items = 100 /* list instances */ * 3 /* leaves */ * 2 /* set + delete */ ;
}

static void
perf_commit_test(void **state, int op_num, int *items) {
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform edit, commit request */
    bool even = true;
    for (size_t i = 0; i<op_num; i++){
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
        rc = sr_commit(session);
        assert_int_equal(rc, SR_ERR_OK);
        even = !even;
    }

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
    *items = 1;
}

static void
perf_libyang_get_node(void **state, int op_num, int *items)
{
    struct ly_ctx *ctx = *state;
    assert_non_null(ctx);

    struct lyd_node *root = lyd_parse_path(ctx, EXAMPLE_MODULE_DATA_FILE_NAME, LYD_XML, LYD_OPT_CONFIG | LYD_OPT_STRICT);
    assert_non_null(root);

    /* perform a lyd_get_node op */
    for (size_t i = 0; i<op_num; i++){

        /* existing leaf */
        struct ly_set *set = lyd_find_xpath(root, "/example-module:container/list[key1='key1'][key2='key2']/leaf");
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

    struct lyd_node *root = lyd_parse_path(ctx, EXAMPLE_MODULE_DATA_FILE_NAME, LYD_XML, LYD_OPT_CONFIG | LYD_OPT_STRICT);
    assert_non_null(root);

    /* perform a lyd_get_node op */
    for (size_t i = 0; i<op_num; i++){

        /* existing leaf */
        struct ly_set *set = lyd_find_xpath(root, "/example-module:container/list/leaf");
        *items = set->number;
        assert_non_null(set);
        ly_set_free(set);
    }

    lyd_free_withsiblings(root);

}

void test_perf(test_t *ts, int test_count, const char *title,  int selection)
{
    print_measure_header(title);
    for (int i = 0; i < test_count; i++) {
        test_t *t = &ts[i];
        if (-1 == selection || i == selection){
            measure(t->function, t->op_name, t->op_count, t->setup, t->teardown);
        }
    }
}

int
main (int argc, char **argv)
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
        {perf_libyang_get_node, "Libyang get one node", OP_COUNT, libyang_setup, libyang_teardown},
        {perf_libyang_get_all_list, "Libyang get all list", OP_COUNT, libyang_setup, libyang_teardown},
    };

    size_t test_count = sizeof(tests)/sizeof(*tests);

    int selection = -1, ret = -1;
    if (argc > 1) {
        ret = sscanf(argv[1], "%d", &selection);
        assert_int_equal(ret, 1);
    }
    /* one list instance */
    createDataTreeExampleModule();
    createDataTreeLargeIETFinterfacesModule(1);
    test_perf(tests, test_count, "Data file with one list instance", selection);

    /* 20 list instances*/
    createDataTreeLargeExampleModule(20);
    createDataTreeLargeIETFinterfacesModule(20);
    test_perf(tests, test_count, "Data file with 20 list instances", selection);


    /* decrease the number of performed operation on larger file*/
    for (size_t i = 0; i<test_count; i++){
        if (OP_COUNT_COMMIT != tests[i].op_count){
            tests[i].op_count = OP_COUNT_LOW;
        }
    }

    /* 100 list instances*/
    createDataTreeLargeExampleModule(100);
    createDataTreeLargeIETFinterfacesModule(100);
    test_perf(tests, test_count, "Data file with 100 list instances", selection);
    puts("\n\n");

    return 0;
}
