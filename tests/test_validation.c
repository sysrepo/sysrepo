/**
 * @file test_validation.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test of validating various datastore content
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
    sr_conn_ctx_t *conn;
    const struct ly_ctx *ly_ctx;
    sr_session_ctx_t *sess;
};

static int
setup_f(void **state)
{
    struct state *st;
    const char *schema_paths[] = {
        TESTS_SRC_DIR "/files/test.yang",
        TESTS_SRC_DIR "/files/refs.yang",
        NULL
    };

    st = calloc(1, sizeof *st);
    *state = st;

    if (sr_connect(0, &st->conn) != SR_ERR_OK) {
        return 1;
    }

    if (sr_install_modules(st->conn, schema_paths, TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }

    st->ly_ctx = sr_acquire_context(st->conn);

    if (sr_session_start(st->conn, SR_DS_RUNNING, &st->sess) != SR_ERR_OK) {
        return 1;
    }

    return 0;
}

static int
teardown_f(void **state)
{
    struct state *st = (struct state *)*state;
    const char *module_names[] = {
        "refs",
        "test",
        NULL
    };

    if (st->ly_ctx) {
        sr_release_context(st->conn);
    }

    sr_remove_modules(st->conn, module_names, 0);

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
    sr_apply_changes(st->sess, 0);

    return 0;
}

static void
test_leafref(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    int ret;

    /* create valid data */
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "10", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/refs:lref", "10", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
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

    assert_string_equal(data->tree->schema->name, "lref");
    assert_string_equal(lyd_get_value(data->tree), "10");
    assert_string_equal(data->tree->next->schema->name, "test-leaf");
    assert_string_equal(lyd_get_value(data->tree->next), "10");
    assert_string_equal(data->tree->next->next->schema->name, "cont");

    sr_release_data(data);
}

static void
test_instid(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;

    /* inst-id target does not exist */
    ret = sr_set_item_str(st->sess, "/refs:inst-id", "/refs:l", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    /* create the target */
    ret = sr_set_item_str(st->sess, "/refs:l", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* point to a leaf-list */
    ret = sr_set_item_str(st->sess, "/refs:inst-id", "/refs:ll[.='z']", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    ret = sr_set_item_str(st->sess, "/refs:ll", "y", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/refs:ll", "z", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* point to a list */
    ret = sr_set_item_str(st->sess, "/refs:inst-id", "/refs:lll[key='1']", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    ret = sr_set_item_str(st->sess, "/refs:lll[key='1']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* foreign leaf */
    ret = sr_set_item_str(st->sess, "/refs:inst-id", "/test:test-leaf", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    ret = sr_set_item_str(st->sess, "/test:test-leaf", "5", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* default inst-id */
    ret = sr_set_item_str(st->sess, "/refs:cont", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    ret = sr_set_item_str(st->sess, "/test:ll1", "-3000", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_operational(void **state)
{
    struct state *st = (struct state *)*state;
    const char *data =
            "{"
            "  \"test:test-leaf\": 12"
            "}";
    struct lyd_node *edit;
    int ret;

    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* parse it with "sysrepo" default values, which are invalid */
    assert_int_equal(LY_SUCCESS, lyd_parse_data_mem(st->ly_ctx, data, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &edit));
    ret = lyd_new_implicit_all(&edit, st->ly_ctx, 0, NULL);
    assert_int_equal(ret, 0);

    ret = sr_edit_batch(st->sess, edit, "merge");
    lyd_free_all(edit);
    assert_int_equal(ret, SR_ERR_OK);

    /* validate operational with an invalid change */
    ret = sr_validate(st->sess, "test", 0);
    assert_int_equal(ret, SR_ERR_UNSUPPORTED);

    /* try to apply, with the same result */
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_UNSUPPORTED);

    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* parse it properly now */
    assert_int_equal(LY_SUCCESS, lyd_parse_data_mem(st->ly_ctx, data, LYD_JSON, LYD_PARSE_ONLY, 0, &edit));

    ret = sr_edit_batch(st->sess, edit, "merge");
    lyd_free_all(edit);
    assert_int_equal(ret, SR_ERR_OK);

    /* validate operational, should be fine now */
    ret = sr_validate(st->sess, "test", 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* so we can apply it */
    ret = sr_apply_changes(st->sess, 0);
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
    test_log_init();
    return cmocka_run_group_tests(tests, setup_f, teardown_f);
}
