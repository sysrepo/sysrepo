/**
 * @file test_multi_connection.c
 * @author Ian Miller <imiller@adva.com>
 * @brief test for edits performed using multiple connections
 *
 * @copyright
 * Copyright 2020 ADVA Optical Networking Inc.
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

#include "tests/config.h"
#include "sysrepo.h"

struct state {
    sr_conn_ctx_t *conn1;
    sr_conn_ctx_t *conn2;
    sr_conn_ctx_t *conn3;
    sr_session_ctx_t *sess1;
    sr_session_ctx_t *sess2;
    sr_session_ctx_t *sess3;
};

static int
setup_f(void **state)
{
    struct state *st;
    uint32_t conn_count;

    st = malloc(sizeof *st);
    if (!st) {
        return 1;
    }
    *state = st;

    sr_connection_count(&conn_count);
    assert_int_equal(conn_count, 0);

    if (sr_connect(0, &st->conn1) != SR_ERR_OK) {
        return 1;
    }

    if (sr_install_module(st->conn1, TESTS_DIR "/files/test.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn1, TESTS_DIR "/files/ietf-interfaces.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn1, TESTS_DIR "/files/iana-if-type.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        return 1;
    }
    sr_disconnect(st->conn1);

    // Connection 1
    if (sr_connect(0, &(st->conn1)) != SR_ERR_OK) {
        return 1;
    }
    if (sr_session_start(st->conn1, SR_DS_RUNNING, &st->sess1) != SR_ERR_OK) {
        return 1;
    }

    // Connection 2
    if (sr_connect(0, &(st->conn2)) != SR_ERR_OK) {
        return 1;
    }
    if (sr_session_start(st->conn2, SR_DS_RUNNING, &st->sess2) != SR_ERR_OK) {
        return 1;
    }

    // Connection 3
    if (sr_connect(0, &(st->conn3)) != SR_ERR_OK) {
        return 1;
    }
    if (sr_session_start(st->conn3, SR_DS_RUNNING, &st->sess3) != SR_ERR_OK) {
        return 1;
    }

    return 0;
}

static int
teardown_f(void **state)
{
    struct state *st = (struct state *)*state;

    sr_remove_module(st->conn1, "ietf-interfaces");
    sr_remove_module(st->conn1, "iana-if-type");
    sr_remove_module(st->conn1, "test");

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
    sr_apply_changes(st->sess1, 0, 1);

    return 0;
}

static void
test_connection_count(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;
    uint32_t count = 0;

    ret = sr_connection_count(&count);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(count, 3);

    sr_disconnect(st->conn2);

    ret = sr_connection_count(&count);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(count, 2);

    ret = sr_connect(0, &(st->conn2));
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_session_start(st->conn2, SR_DS_RUNNING, &st->sess2);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_connection_count(&count);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(count, 3);
}

static void
test_create1(void **state)
{
    struct state *st = (struct state *)*state;
    struct lyd_node *subtree;
    char *str;
    //const char *str2;
    int ret;

    /* Create via two connections, retrieve by a third */
    ret = sr_set_item_str(st->sess1, "/ietf-interfaces:interfaces/interface[name='ethS1']", NULL, NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess1, "/ietf-interfaces:interfaces/interface[name='ethS1']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess1, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess2, "/ietf-interfaces:interfaces/interface[name='ethS2']", NULL, NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess2, "/ietf-interfaces:interfaces/interface[name='ethS2']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess2, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_subtree(st->sess3, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    lyd_print_mem(&str, subtree, LYD_XML, LYP_WITHSIBLINGS);
    lyd_free(subtree);
    const char *ptr = strstr(str, "ethS1");
    assert_non_null(ptr);
    ptr = strstr(str, "ethS2");
    assert_non_null(ptr);
    ptr = strstr(str, "ethS3");
    assert_null(ptr);

    free(str);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_connection_count),
        cmocka_unit_test_teardown(test_create1, clear_interfaces),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    sr_log_stderr(SR_LL_INF);
    return cmocka_run_group_tests(tests, setup_f, teardown_f);
}
