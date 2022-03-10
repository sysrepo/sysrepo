/**
 * @file test_nacm.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test for NACM
 *
 * @copyright
 * Copyright (c) 2022 Deutsche Telekom AG.
 * Copyright (c) 2022 CESNET, z.s.p.o.
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "sysrepo.h"
#include "sysrepo/netconf_acm.h"
#include "tests/test_common.h"

struct state {
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *sub;
};

static int
setup_f(void **state)
{
    struct state *st;

    st = calloc(1, sizeof *st);
    *state = st;

    if (sr_connect(0, &st->conn)) {
        return 1;
    }

    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/test.yang", TESTS_SRC_DIR "/files", NULL)) {
        return 1;
    }

    if (sr_session_start(st->conn, SR_DS_RUNNING, &st->sess)) {
        return 1;
    }

    if (sr_nacm_init(st->sess, 0, &st->sub)) {
        return 1;
    }

    return 0;
}

static int
teardown_f(void **state)
{
    struct state *st = (struct state *)*state;

    sr_remove_module(st->conn, "test", 0);

    sr_unsubscribe(st->sub);
    sr_nacm_destroy();
    sr_disconnect(st->conn);
    free(st);
    return 0;
}

static int
setup_basic_nacm(void **state)
{
    struct state *st = (struct state *)*state;

    /* set some data */
    if (sr_set_item_str(st->sess, "/test:cont/l2[k='k1']/v", "10", NULL, 0)) {
        return 1;
    }
    if (sr_set_item_str(st->sess, "/test:cont/ll2", "25", NULL, 0)) {
        return 1;
    }
    if (sr_apply_changes(st->sess, 0)) {
        return 1;
    }

    /* set user */
    if (sr_nacm_set_user(st->sess, "test-user")) {
        return 1;
    }

    return 0;
}

static void
test_basic(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    char *str;
    int ret;

    /* read some data, allowed by default */
    ret = sr_get_data(st->sess, "/test:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, LY_SUCCESS);
    sr_release_data(data);
    assert_string_equal(str,
            "<cont xmlns=\"urn:test\">\n"
            "  <l2>\n"
            "    <k>k1</k>\n"
            "    <v>10</v>\n"
            "  </l2>\n"
            "  <ll2>25</ll2>\n"
            "</cont>\n");
    free(str);

    /* write some data, disabled by default */
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "10", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_UNAUTHORIZED);
    sr_discard_changes(st->sess);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_basic, setup_basic_nacm),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    test_log_init();
    return cmocka_run_group_tests(tests, setup_f, teardown_f);
}
