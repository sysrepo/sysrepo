/**
 * @file test_validation.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test of validating various datastore content
 *
 * @copyright
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#define _GNU_SOURCE

#include <string.h>
#include <unistd.h>
#include <setjmp.h>
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

    st = malloc(sizeof *st);
    if (!st) {
        return 1;
    }
    *state = st;

    if (sr_connect("test1", 0, &st->conn) != SR_ERR_OK) {
        return 1;
    }

    if (sr_install_module(st->conn, TESTS_DIR "/files/test.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_DIR "/files/refs.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
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
    sr_apply_changes(st->sess);

    return 0;
}

static void
test_leafref(void **state)
{
    struct state *st = (struct state *)*state;
    struct ly_set *subtrees;
    int ret;

    /* create valid data */
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "10", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/refs:lref", "10", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* cause leafref not to point at a node (2x) */
    ret = sr_set_item_str(st->sess, "/refs:lref", "8", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_validate(st->sess);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/test:test-leaf", "8", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_validate(st->sess);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* check final datastore contents */
    ret = sr_get_subtrees(st->sess, "/test:* | /refs:*", &subtrees);
    assert_int_equal(ret, SR_ERR_OK);

    assert_int_equal(subtrees->number, 3);

    assert_string_equal(subtrees->set.d[0]->schema->name, "cont");
    assert_string_equal(subtrees->set.d[1]->schema->name, "test-leaf");
    assert_string_equal(((struct lyd_node_leaf_list *)subtrees->set.d[1])->value_str, "10");
    assert_string_equal(subtrees->set.d[2]->schema->name, "lref");
    assert_string_equal(((struct lyd_node_leaf_list *)subtrees->set.d[2])->value_str, "10");

    lyd_free_withsiblings(subtrees->set.d[0]);
    lyd_free_withsiblings(subtrees->set.d[1]);
    lyd_free_withsiblings(subtrees->set.d[2]);
    ly_set_free(subtrees);
}

static void
test_instid(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;

    /* inst-id target does not exist */
    ret = sr_set_item_str(st->sess, "/refs:inst-id", "/refs:l", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    /* create the target */
    ret = sr_set_item_str(st->sess, "/refs:l", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* point to a leaf-list */
    ret = sr_set_item_str(st->sess, "/refs:inst-id", "/refs:ll[.='z']", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    ret = sr_set_item_str(st->sess, "/refs:ll", "y", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/refs:ll", "z", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* point to a list */
    ret = sr_set_item_str(st->sess, "/refs:inst-id", "/refs:lll[refs:key='1']", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    ret = sr_set_item_str(st->sess, "/refs:lll[key='1']", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* foreign leaf */
    ret = sr_set_item_str(st->sess, "/refs:inst-id", "/test:test-leaf", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    ret = sr_set_item_str(st->sess, "/test:test-leaf", "5", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* default inst-id */
    ret = sr_set_item_str(st->sess, "/refs:cont", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    ret = sr_set_item_str(st->sess, "/test:ll1", "-3000", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_leafref, clear_test_refs),
        cmocka_unit_test_teardown(test_instid, clear_test_refs),
    };

    sr_log_stderr(SR_LL_INF);
    return cmocka_run_group_tests(tests, setup_f, teardown_f);
}
