/**
 * @file test_get.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test of getting data
 *
 * @copyright
 * Copyright 2018 Deutsche Telekom AG.
 * Copyright 2018 - 2020 CESNET, z.s.p.o.
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
#include <unistd.h>
#include <sys/types.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "tests/config.h"
#include "sysrepo.h"

struct state {
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
};

static int
setup(void **state, int cached)
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

    if (sr_install_module(st->conn, TESTS_DIR "/files/simple.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_DIR "/files/simple-aug.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_DIR "/files/defaults.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        return 1;
    }
    sr_disconnect(st->conn);

    if (sr_connect(cached ? SR_CONN_CACHE_RUNNING : 0, &(st->conn)) != SR_ERR_OK) {
        return 1;
    }

    if (sr_session_start(st->conn, SR_DS_RUNNING, &st->sess) != SR_ERR_OK) {
        return 1;
    }

    return 0;
}

static int
setup_f(void **state)
{
    return setup(state, 0);
}

static int
setup_cached_f(void **state)
{
    return setup(state, 1);
}

static int
teardown_f(void **state)
{
    struct state *st = (struct state *)*state;

    sr_remove_module(st->conn, "simple");
    sr_remove_module(st->conn, "simple-aug");
    sr_remove_module(st->conn, "defaults");

    sr_disconnect(st->conn);
    free(st);
    return 0;
}

/* TEST */
static void
test_cached_datastore(void **state)
{
    struct state *st = (struct state *)*state;
    struct lyd_node *data;
    int ret;

    /* try to get RUNNING data */
    ret = sr_get_data(st->sess, "/*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_non_null(data);
    lyd_free_withsiblings(data);

    /* try to get STARTUP data */
    ret = sr_session_switch_ds(st->sess, SR_DS_STARTUP);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_non_null(data);
    lyd_free_withsiblings(data);

    /* try to get CANDIDATE data */
    ret = sr_session_switch_ds(st->sess, SR_DS_CANDIDATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_non_null(data);
    lyd_free_withsiblings(data);

    /* try to get OPERATIONAL data */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_non_null(data);
    lyd_free_withsiblings(data);

    /* switch DS back */
    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
}

/* TEST */
static int
enable_cached_get_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data)
{
    sr_val_t *values = NULL;
    size_t count = 0;
    int ret;
    char *xp;

    (void)xpath;
    (void)event;
    (void)request_id;
    (void)private_data;

    /* get current config */
    asprintf(&xp, "/%s:*//.", module_name);
    ret = sr_get_items(session, xp, 0, 0, &values, &count);
    free(xp);
    assert_int_equal(ret, SR_ERR_OK);

    sr_free_values(values, count);

    return SR_ERR_OK;
}

static void
test_enable_cached_get(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *sub = NULL;
    int ret;

    /* subscribe to both modules with enabled flag */
    ret = sr_module_change_subscribe(st->sess, "simple", NULL, enable_cached_get_cb, NULL, 0,
            SR_SUBSCR_ENABLED | SR_SUBSCR_CTX_REUSE, &sub);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(st->sess, "simple-aug", NULL, enable_cached_get_cb, NULL, 0,
            SR_SUBSCR_ENABLED | SR_SUBSCR_CTX_REUSE, &sub);
    assert_int_equal(ret, SR_ERR_OK);

    /* cleanup */
    sr_unsubscribe(sub);
}

/* TEST */
static void
test_no_read_access(void **state)
{
    struct state *st = (struct state *)*state;
    struct lyd_node *data;
    int ret;

    if (!geteuid()) {
        /* test does not work for root */
        return;
    }

    /* set no permissions for default module */
    ret = sr_set_module_access(st->conn, "defaults", NULL, NULL, 00200);
    assert_int_equal(ret, SR_ERR_OK);

    /* try to get its data */
    ret = sr_get_data(st->sess, "/defaults:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    /* no data should be returned, not even defaults */
    assert_null(data);

    /* try to get all data */
    ret = sr_get_data(st->sess, "/*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    /* only some default values */
    assert_non_null(data);
    assert_int_equal(data->dflt, 1);
    lyd_free_withsiblings(data);

    /* set permissions back so that it can be removed */
    ret = sr_set_module_access(st->conn, "defaults", NULL, NULL, 00600);
    assert_int_equal(ret, SR_ERR_OK);
}

/* TEST */
static void
test_explicit_default(void **state)
{
    struct state *st = (struct state *)*state;
    struct lyd_node *data;
    int ret;

    /* get defaults data */
    ret = sr_get_data(st->sess, "/defaults:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_non_null(data);
    assert_string_equal(data->schema->name, "cont");
    assert_int_equal(data->dflt, 1);
    assert_non_null(data->child);
    assert_string_equal(data->child->schema->name, "interval");
    assert_int_equal(data->child->dflt, 1);

    lyd_free_withsiblings(data);

    /* set explicit default value */
    ret = sr_set_item_str(st->sess, "/defaults:cont/interval", "30", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read it back */
    ret = sr_get_data(st->sess, "/defaults:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_non_null(data);
    assert_string_equal(data->schema->name, "cont");
    assert_int_equal(data->dflt, 0);
    assert_non_null(data->child);
    assert_string_equal(data->child->schema->name, "interval");
    assert_int_equal(data->child->dflt, 0);

    lyd_free_withsiblings(data);

    /* cleanup */
    sr_delete_item(st->sess, "/defaults:cont", 0);
    sr_apply_changes(st->sess, 0, 0);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_cached_datastore, setup_cached_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_enable_cached_get, setup_cached_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_no_read_access, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_no_read_access, setup_cached_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_explicit_default, setup_f, teardown_f),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    sr_log_stderr(SR_LL_INF);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
