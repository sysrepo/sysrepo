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

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_create1, clear_interfaces),
        cmocka_unit_test(test_new),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    test_log_init();
    return cmocka_run_group_tests(tests, setup_f, teardown_f);
}
