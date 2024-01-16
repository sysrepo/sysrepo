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

#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "sysrepo.h"
#include "tests/tcommon.h"

struct state {
    sr_conn_ctx_t *conn;
    sr_conn_ctx_t *cconn;
    sr_session_ctx_t *sess;
    sr_session_ctx_t *csess;
};

static int
setup(void **state)
{
    struct state *st;
    const char *schema_paths[] = {
        TESTS_SRC_DIR "/files/simple.yang",
        TESTS_SRC_DIR "/files/simple-aug.yang",
        TESTS_SRC_DIR "/files/defaults.yang",
        NULL
    };

    st = calloc(1, sizeof *st);
    *state = st;

    if (sr_connect(0, &st->conn) != SR_ERR_OK) {
        return 1;
    }
    if (sr_connect(SR_CONN_CACHE_RUNNING, &st->cconn) != SR_ERR_OK) {
        return 1;
    }

    if (sr_install_modules(st->conn, schema_paths, TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }

    if (sr_session_start(st->conn, SR_DS_RUNNING, &st->sess) != SR_ERR_OK) {
        return 1;
    }
    if (sr_session_start(st->cconn, SR_DS_RUNNING, &st->csess) != SR_ERR_OK) {
        return 1;
    }

    return 0;
}

static int
teardown(void **state)
{
    struct state *st = (struct state *)*state;
    const char *module_names[] = {
        "simple-aug",
        "simple",
        "defaults",
        NULL
    };

    sr_remove_modules(st->conn, module_names, 0);

    sr_disconnect(st->conn);
    sr_disconnect(st->cconn);
    free(st);
    return 0;
}

/* TEST */
static void
test_invalid(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
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
    sr_data_t *data;
    int ret;

    /* try to get RUNNING data */
    ret = sr_get_data(st->csess, "/*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_non_null(data);
    sr_release_data(data);

    /* try to get STARTUP data */
    ret = sr_session_switch_ds(st->csess, SR_DS_STARTUP);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->csess, "/*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_non_null(data);
    sr_release_data(data);

    /* try to get CANDIDATE data */
    ret = sr_session_switch_ds(st->csess, SR_DS_CANDIDATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->csess, "/*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_non_null(data);
    sr_release_data(data);

    /* try to get OPERATIONAL data */
    ret = sr_session_switch_ds(st->csess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->csess, "/*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_non_null(data);
    sr_release_data(data);

    /* switch DS back */
    ret = sr_session_switch_ds(st->csess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
}

/* TEST */
static void *
cached_thread1(void *arg)
{
    sr_conn_ctx_t *conn = arg;
    sr_session_ctx_t *sess;
    sr_data_t *data;
    int ret;

    ret = sr_session_start(conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(sess, "/simple:ac1/acl1", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    sr_release_data(data);

    sr_session_stop(sess);
    return NULL;
}

static void *
cached_thread2(void *arg)
{
    sr_conn_ctx_t *conn = arg;
    sr_session_ctx_t *sess;
    sr_data_t *data;
    int ret;

    ret = sr_session_start(conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(sess, "/simple:ac1/acd1", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    sr_release_data(data);

    sr_session_stop(sess);
    return NULL;
}

static void
test_cached_thread(void **state)
{
    const uint32_t loop_count = 3;

    struct state *st = (struct state *)*state;
    sr_conn_ctx_t *conn;
    uint32_t i;
    pthread_t tid[2];
    int ret;

    /* set some data to read */
    ret = sr_set_item_str(st->sess, "/simple:ac1/acl1[acs1='key1']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/simple:ac1/acl1[acs1='key2']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    for (i = 0; i < loop_count; ++i) {
        ret = sr_connect(SR_CONN_CACHE_RUNNING, &conn);
        assert_int_equal(ret, SR_ERR_OK);

        pthread_create(&tid[0], NULL, cached_thread1, conn);
        pthread_create(&tid[1], NULL, cached_thread2, conn);

        pthread_join(tid[0], NULL);
        pthread_join(tid[1], NULL);

        sr_disconnect(conn);
    }

    /* cleanup */
    ret = sr_delete_item(st->sess, "/simple:ac1", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
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
    assert_return_code(asprintf(&xp, "/%s:*//.", module_name), 0);
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
    ret = sr_module_change_subscribe(st->csess, "simple", NULL, enable_cached_get_cb, NULL, 0, SR_SUBSCR_ENABLED, &sub);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(st->csess, "simple-aug", NULL, enable_cached_get_cb, NULL, 0,
            SR_SUBSCR_ENABLED, &sub);
    assert_int_equal(ret, SR_ERR_OK);

    /* cleanup */
    sr_unsubscribe(sub);
}

/* TEST */
static void
test_no_read_access(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    int ret;

    if (!geteuid()) {
        /* test does not work for root */
        return;
    }

    /* set no permissions for default module */
    ret = sr_set_module_ds_access(st->cconn, "defaults", SR_DS_RUNNING, NULL, NULL, 00200);
    assert_int_equal(ret, SR_ERR_OK);

    /* try to get its data */
    ret = sr_get_data(st->csess, "/defaults:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    /* no data should be returned, not even defaults */
    assert_null(data);

    /* try to get all data */
    ret = sr_get_data(st->csess, "/*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    /* only some default values */
    assert_non_null(data);
    assert_true(data->tree->flags & LYD_DEFAULT);
    sr_release_data(data);

    /* set permissions back so that it can be removed */
    ret = sr_set_module_ds_access(st->cconn, "defaults", SR_DS_RUNNING, NULL, NULL, 00600);
    assert_int_equal(ret, SR_ERR_OK);
}

/* TEST */
static void
test_explicit_default(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    int ret;

    /* get defaults data */
    ret = sr_get_data(st->sess, "/defaults:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_non_null(data);
    assert_string_equal(data->tree->schema->name, "cont");
    assert_true(data->tree->flags & LYD_DEFAULT);
    assert_non_null(lyd_child(data->tree));
    assert_string_equal(lyd_child(data->tree)->next->schema->name, "interval");
    assert_true(lyd_child(data->tree)->next->flags & LYD_DEFAULT);

    sr_release_data(data);

    /* set explicit default value */
    ret = sr_set_item_str(st->sess, "/defaults:cont/interval", "30", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read it back */
    ret = sr_get_data(st->sess, "/defaults:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_non_null(data);
    assert_string_equal(data->tree->schema->name, "cont");
    assert_false(data->tree->flags & LYD_DEFAULT);
    assert_non_null(lyd_child(data->tree));
    assert_string_equal(lyd_child(data->tree)->next->schema->name, "interval");
    assert_false(lyd_child(data->tree)->next->flags & LYD_DEFAULT);

    sr_release_data(data);

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
    const struct ly_ctx *ly_ctx;
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
    ly_ctx = sr_acquire_context(sr_session_get_connection(session));
    mod = ly_ctx_get_module_implemented(ly_ctx, "simple-aug");
    assert_non_null(mod);

    assert_int_equal(SR_ERR_OK, lyd_new_term(*parent, mod, "bauga2", "val", 0, NULL));

    sr_release_context(sr_session_get_connection(session));
    return SR_ERR_OK;
}

static void
test_union(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr = NULL;
    sr_data_t *data;
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
    ret = sr_module_change_subscribe(st->sess, "simple-aug", NULL, dummy_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* provide config false data */
    ret = sr_oper_get_subscribe(st->sess, "simple", "/simple:ac1/simple-aug:bauga2", union_oper_cb, NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);

    /* get operational data of each module first first */
    ret = sr_get_data(st->sess, "/simple:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_IMPL_TAG);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<ac1 xmlns=\"s\">\n"
            "  <acd1 xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">true</acd1>\n"
            "  <bauga1 xmlns=\"sa\" xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\""
            " ncwd:default=\"true\">true</bauga1>\n"
            "  <bauga2 xmlns=\"sa\">val</bauga2>\n"
            "</ac1>\n";

    assert_string_equal(str1, str2);
    free(str1);

    ret = sr_get_data(st->sess, "/simple-aug:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_IMPL_TAG);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<bc1 xmlns=\"sa\">\n"
            "  <bcd1 xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">true</bcd1>\n"
            "  <bcl1>\n"
            "    <bcs1>key</bcs1>\n"
            "  </bcl1>\n"
            "</bc1>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* get data from both modules */
    ret = sr_get_data(st->sess, "/simple-aug:* | /simple:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_IMPL_TAG);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<ac1 xmlns=\"s\">\n"
            "  <acd1 xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">true</acd1>\n"
            "  <bauga1 xmlns=\"sa\" xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\""
            " ncwd:default=\"true\">true</bauga1>\n"
            "  <bauga2 xmlns=\"sa\">val</bauga2>\n"
            "</ac1>\n"
            "<bc1 xmlns=\"sa\">\n"
            "  <bcd1 xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">true</bcd1>\n"
            "  <bcl1>\n"
            "    <bcs1>key</bcs1>\n"
            "  </bcl1>\n"
            "</bc1>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* get specific subtrees from both modules */
    ret = sr_get_data(st->sess, "/simple-aug:bc1/bcl1 | /simple:ac1/simple-aug:bauga2", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_IMPL_TAG);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<ac1 xmlns=\"s\">\n"
            "  <bauga2 xmlns=\"sa\">val</bauga2>\n"
            "</ac1>\n"
            "<bc1 xmlns=\"sa\">\n"
            "  <bcl1>\n"
            "    <bcs1>key</bcs1>\n"
            "  </bcl1>\n"
            "</bc1>\n";

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
    sr_data_t *data;
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

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<l1 xmlns=\"urn:defaults\">\n"
            "  <k>val</k>\n"
            "</l1>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* cleanup */
    sr_delete_item(st->sess, "/defaults:l1", 0);
    sr_apply_changes(st->sess, 0);
}

/* TEST */
static void
test_factory_default(void **state)
{
    struct state *st = (struct state *)*state;
    const char *init_data;
    sr_data_t *data;
    char *str1;
    const char *str2;
    int ret;

    /* install module with factory-default data */
    init_data =
            "<container xmlns=\"urn:ietf:params:xml:ns:yang:example\">\n"
            "  <list>\n"
            "    <key1>k1a</key1>\n"
            "    <key2>k2a</key2>\n"
            "  </list>\n"
            "</container>\n"
            "<number xmlns=\"urn:ietf:params:xml:ns:yang:example\">20</number>\n";
    ret = sr_install_module2(st->conn, TESTS_SRC_DIR "/files/example-module.yang", TESTS_SRC_DIR "/files", NULL, NULL,
            NULL, NULL, 0, init_data, NULL, LYD_XML);
    assert_int_equal(SR_ERR_OK, ret);

    /* set some startup data */
    sr_session_switch_ds(st->sess, SR_DS_STARTUP);
    ret = sr_set_item_str(st->sess, "/example-module:number", "25", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/example-module:container/list[key1='k1b'][key2='k2b']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read factory-default data */
    sr_session_switch_ds(st->sess, SR_DS_FACTORY_DEFAULT);
    ret = sr_get_data(st->sess, "/example-module:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);
    str2 = init_data;
    assert_string_equal(str1, str2);
    free(str1);

    /* read startup data */
    sr_session_switch_ds(st->sess, SR_DS_STARTUP);
    ret = sr_get_data(st->sess, "/example-module:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);
    str2 =
            "<container xmlns=\"urn:ietf:params:xml:ns:yang:example\">\n"
            "  <list>\n"
            "    <key1>k1a</key1>\n"
            "    <key2>k2a</key2>\n"
            "  </list>\n"
            "  <list>\n"
            "    <key1>k1b</key1>\n"
            "    <key2>k2b</key2>\n"
            "  </list>\n"
            "</container>\n"
            "<number xmlns=\"urn:ietf:params:xml:ns:yang:example\">20</number>\n"
            "<number xmlns=\"urn:ietf:params:xml:ns:yang:example\">25</number>\n";
    assert_string_equal(str1, str2);
    free(str1);

    /* cleanup */
    sr_remove_module(st->conn, "example-module", 0);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_invalid),
        cmocka_unit_test(test_cached_datastore),
        cmocka_unit_test(test_cached_thread),
        cmocka_unit_test(test_enable_cached_get),
        cmocka_unit_test(test_no_read_access),
        cmocka_unit_test(test_no_read_access),
        cmocka_unit_test(test_explicit_default),
        cmocka_unit_test(test_union),
        cmocka_unit_test(test_key),
        cmocka_unit_test(test_factory_default),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    test_log_init();
    return cmocka_run_group_tests(tests, setup, teardown);
}
