/**
 * @file test_validation.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test of validating various datastore content
 *
 * @copyright
 * Copyright 2018 Deutsche Telekom AG.
 * Copyright 2018 - 2019 CESNET, z.s.p.o.
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
#include <stdlib.h>
#include <stdarg.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "tests/config.h"
#include "sysrepo.h"

struct state {
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
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

    if (sr_connect(0, &st->conn) != SR_ERR_OK) {
        return 1;
    }

    if (sr_install_module(st->conn, TESTS_DIR "/files/test.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_DIR "/files/refs.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        return 1;
    }
    sr_disconnect(st->conn);

    if (sr_connect(0, &(st->conn)) != SR_ERR_OK) {
        return 1;
    }

    if (sr_session_start(st->conn, SR_DS_RUNNING, &st->sess) != SR_ERR_OK) {
        return 1;
    }

    return 0;
}

static int
teardown_f(void **state)
{
    struct state *st = (struct state *)*state;

    sr_remove_module(st->conn, "test");
    sr_remove_module(st->conn, "refs");

    sr_disconnect(st->conn);
    free(st);
    return 0;
}

static int
clear_test_refs(void **state)
{
    struct state *st = (struct state *)*state;

    sr_delete_item(st->sess, "/test:test-leaf", 0);
    sr_delete_item(st->sess, "/test:ll1[.='-3000']", 0);

    sr_delete_item(st->sess, "/refs:cont", 0);
    sr_delete_item(st->sess, "/refs:inst-id", 0);
    sr_delete_item(st->sess, "/refs:lref", 0);
    sr_delete_item(st->sess, "/refs:l", 0);
    sr_delete_item(st->sess, "/refs:ll[.='y']", 0);
    sr_delete_item(st->sess, "/refs:ll[.='z']", 0);
    sr_delete_item(st->sess, "/refs:lll[key='1']", 0);
    sr_apply_changes(st->sess, 0, 1);

    return 0;
}

static void
test_leafref(void **state)
{
    struct state *st = (struct state *)*state;
    struct lyd_node *data;
    int ret;

    /* create valid data */
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "10", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/refs:lref", "10", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    /* cause leafref not to point at a node (2x) */
    ret = sr_set_item_str(st->sess, "/refs:lref", "8", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_validate(st->sess, NULL, 0);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/test:test-leaf", "8", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_validate(st->sess, NULL, 0);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* check final datastore contents */
    ret = sr_get_data(st->sess, "/test:* | /refs:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_string_equal(data->schema->name, "lref");
    assert_string_equal(((struct lyd_node_leaf_list *)data)->value_str, "10");
    assert_string_equal(data->next->schema->name, "cont");
    assert_string_equal(data->next->next->schema->name, "test-leaf");
    assert_string_equal(((struct lyd_node_leaf_list *)data->next->next)->value_str, "10");

    lyd_free_withsiblings(data);
}

static void
test_instid(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;

    /* inst-id target does not exist */
    ret = sr_set_item_str(st->sess, "/refs:inst-id", "/refs:l", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    /* create the target */
    ret = sr_set_item_str(st->sess, "/refs:l", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    /* point to a leaf-list */
    ret = sr_set_item_str(st->sess, "/refs:inst-id", "/refs:ll[.='z']", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    ret = sr_set_item_str(st->sess, "/refs:ll", "y", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/refs:ll", "z", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    /* point to a list */
    ret = sr_set_item_str(st->sess, "/refs:inst-id", "/refs:lll[refs:key='1']", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    ret = sr_set_item_str(st->sess, "/refs:lll[key='1']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    /* foreign leaf */
    ret = sr_set_item_str(st->sess, "/refs:inst-id", "/test:test-leaf", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    ret = sr_set_item_str(st->sess, "/test:test-leaf", "5", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    /* default inst-id */
    ret = sr_set_item_str(st->sess, "/refs:cont", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    ret = sr_set_item_str(st->sess, "/test:ll1", "-3000", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_operational(void **state)
{
    struct state *st = (struct state *)*state;
    const char *data =
    "{"
        "\"test:test-leaf\": 12"
    "}";
    struct lyd_node *edit;
    int ret;

    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* parse it with default values, which are invalid */
    edit = lyd_parse_mem((struct ly_ctx *)sr_get_context(st->conn), data, LYD_JSON, LYD_OPT_DATA_NO_YANGLIB);
    assert_non_null(edit);

    ret = sr_edit_batch(st->sess, edit, "replace");
    lyd_free_withsiblings(edit);
    assert_int_equal(ret, SR_ERR_OK);

    /* validate operational with an invalid change */
    ret = sr_validate(st->sess, "test", 0);
    assert_int_equal(ret, SR_ERR_UNSUPPORTED);

    /* try to apply, with the same result */
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_UNSUPPORTED);

    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* parse it properly now */
    edit = lyd_parse_mem((struct ly_ctx *)sr_get_context(st->conn), data, LYD_JSON, LYD_OPT_EDIT);
    assert_non_null(edit);

    ret = sr_edit_batch(st->sess, edit, "replace");
    lyd_free_withsiblings(edit);
    assert_int_equal(ret, SR_ERR_OK);

    /* validate operational, should be fine now */
    ret = sr_validate(st->sess, "test", 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* so we can apply it */
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_leafref, clear_test_refs),
        cmocka_unit_test_teardown(test_instid, clear_test_refs),
        cmocka_unit_test(test_operational),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    sr_log_stderr(SR_LL_INF);
    return cmocka_run_group_tests(tests, setup_f, teardown_f);
}
