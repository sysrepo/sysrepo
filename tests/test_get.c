/**
 * @file test_get.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test of getting data
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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "sysrepo.h"
#include "tests/config.h"

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

    if (sr_install_module(st->conn, TESTS_DIR "/files/simple.yang", TESTS_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_DIR "/files/simple-aug.yang", TESTS_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_DIR "/files/defaults.yang", TESTS_DIR "/files", NULL) != SR_ERR_OK) {
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
test_invalid(void **state)
{
    struct state *st = (struct state *)*state;
    struct lyd_node *data;
    int ret;

    /* invalid xpath */
    ret = sr_get_data(st->sess, "/simple:*/name()//.", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_LY);
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
    lyd_free_all(data);

    /* try to get STARTUP data */
    ret = sr_session_switch_ds(st->sess, SR_DS_STARTUP);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_non_null(data);
    lyd_free_all(data);

    /* try to get CANDIDATE data */
    ret = sr_session_switch_ds(st->sess, SR_DS_CANDIDATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_non_null(data);
    lyd_free_all(data);

    /* try to get OPERATIONAL data */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_non_null(data);
    lyd_free_all(data);

    /* switch DS back */
    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
}

/* TEST */
static int
enable_cached_get_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data)
{
    sr_val_t *values = NULL;
    size_t count = 0;
    int ret;
    char *xp;

    (void)sub_id;
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
    assert_true(data->flags & LYD_DEFAULT);
    lyd_free_all(data);

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
    assert_true(data->flags & LYD_DEFAULT);
    assert_non_null(lyd_child(data));
    assert_string_equal(lyd_child(data)->next->schema->name, "interval");
    assert_true(lyd_child(data)->next->flags & LYD_DEFAULT);

    lyd_free_all(data);

    /* set explicit default value */
    ret = sr_set_item_str(st->sess, "/defaults:cont/interval", "30", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read it back */
    ret = sr_get_data(st->sess, "/defaults:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_non_null(data);
    assert_string_equal(data->schema->name, "cont");
    assert_false(data->flags & LYD_DEFAULT);
    assert_non_null(lyd_child(data));
    assert_string_equal(lyd_child(data)->next->schema->name, "interval");
    assert_false(lyd_child(data)->next->flags & LYD_DEFAULT);

    lyd_free_all(data);

    /* cleanup */
    sr_delete_item(st->sess, "/defaults:cont", 0);
    sr_apply_changes(st->sess, 0);
}

/* TEST */
static int
dummy_change_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data)
{
    (void)session;
    (void)sub_id;
    (void)module_name;
    (void)xpath;
    (void)event;
    (void)request_id;
    (void)private_data;

    return SR_ERR_OK;
}

static int
union_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    const struct ly_ctx *ctx;
    const struct lys_module *mod;

    (void)session;
    (void)sub_id;
    (void)request_xpath;
    (void)request_id;
    (void)parent;
    (void)private_data;

    assert_string_equal(module_name, "simple");
    assert_string_equal(xpath, "/simple:ac1/simple-aug:bauga2");

    /* get augment module */
    ctx = sr_get_context(sr_session_get_connection(session));
    mod = ly_ctx_get_module_implemented(ctx, "simple-aug");
    assert_non_null(mod);

    assert_int_equal(SR_ERR_OK, lyd_new_term(*parent, mod, "bauga2", "val", 0, NULL));

    return SR_ERR_OK;
}

static void
test_union(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr;
    struct lyd_node *data;
    char *str1;
    const char *str2;
    int ret;

    /* set some configuration data */
    ret = sr_set_item_str(st->sess, "/simple-aug:bc1/bcl1[bcs1='key']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to both modules so they are present in operational */
    ret = sr_module_change_subscribe(st->sess, "simple", NULL, dummy_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(st->sess, "simple-aug", NULL, dummy_change_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* provide config false data */
    ret = sr_oper_get_items_subscribe(st->sess, "simple", "/simple:ac1/simple-aug:bauga2", union_oper_cb, NULL,
            SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);

    /* get operational data of each module first first */
    ret = sr_get_data(st->sess, "/simple:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK | LYD_PRINT_WD_IMPL_TAG);
    assert_int_equal(ret, 0);
    lyd_free_all(data);

    str2 =
    "<ac1 xmlns=\"s\">"
        "<acd1 xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">true</acd1>"
        "<bauga1 xmlns=\"sa\" xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" "
                "ncwd:default=\"true\">true</bauga1>"
        "<bauga2 xmlns=\"sa\">val</bauga2>"
    "</ac1>";

    assert_string_equal(str1, str2);
    free(str1);

    ret = sr_get_data(st->sess, "/simple-aug:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK | LYD_PRINT_WD_IMPL_TAG);
    assert_int_equal(ret, 0);
    lyd_free_all(data);

    str2 =
    "<bc1 xmlns=\"sa\">"
        "<bcd1 xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">true</bcd1>"
        "<bcl1>"
            "<bcs1>key</bcs1>"
        "</bcl1>"
    "</bc1>";

    assert_string_equal(str1, str2);
    free(str1);

    /* get data from both modules */
    ret = sr_get_data(st->sess, "/simple-aug:* | /simple:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK | LYD_PRINT_WD_IMPL_TAG);
    assert_int_equal(ret, 0);
    lyd_free_all(data);

    str2 =
    "<ac1 xmlns=\"s\">"
        "<acd1 xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">true</acd1>"
        "<bauga1 xmlns=\"sa\" xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" "
                "ncwd:default=\"true\">true</bauga1>"
        "<bauga2 xmlns=\"sa\">val</bauga2>"
    "</ac1>"
    "<bc1 xmlns=\"sa\">"
        "<bcd1 xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">true</bcd1>"
        "<bcl1>"
            "<bcs1>key</bcs1>"
        "</bcl1>"
    "</bc1>";

    assert_string_equal(str1, str2);
    free(str1);

    /* get specific subtrees from both modules */
    ret = sr_get_data(st->sess, "/simple-aug:bc1/bcl1 | /simple:ac1/simple-aug:bauga2", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK | LYD_PRINT_WD_IMPL_TAG);
    assert_int_equal(ret, 0);
    lyd_free_all(data);

    str2 =
    "<ac1 xmlns=\"s\">"
        "<bauga2 xmlns=\"sa\">val</bauga2>"
    "</ac1>"
    "<bc1 xmlns=\"sa\">"
        "<bcl1>"
            "<bcs1>key</bcs1>"
        "</bcl1>"
    "</bc1>";

    assert_string_equal(str1, str2);
    free(str1);

    /* cleanup */
    sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    sr_unsubscribe(subscr);
}

/* TEST */
static void
test_key(void **state)
{
    struct state *st = (struct state *)*state;
    struct lyd_node *data;
    char *str1;
    const char *str2;
    int ret;

    /* set a list */
    ret = sr_set_item_str(st->sess, "/defaults:l1[k='val']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read it back */
    ret = sr_get_data(st->sess, "/defaults:l1[k='val']/k", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);
    lyd_free_all(data);

    str2 =
    "<l1 xmlns=\"urn:defaults\">"
        "<k>val</k>"
    "</l1>";

    assert_string_equal(str1, str2);
    free(str1);

    /* cleanup */
    sr_delete_item(st->sess, "/defaults:l1", 0);
    sr_apply_changes(st->sess, 0);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_invalid, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_cached_datastore, setup_cached_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_enable_cached_get, setup_cached_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_no_read_access, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_no_read_access, setup_cached_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_explicit_default, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_union, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_key, setup_f, teardown_f),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    sr_log_stderr(SR_LL_INF);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
