/**
 * @file test_edit.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test for edits performed in a datastore
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
setup_f(void **state)
{
    struct state *st;

    st = calloc(1, sizeof *st);
    *state = st;

    if (sr_connect(0, &st->conn) != SR_ERR_OK) {
        return 1;
    }

    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/test.yang", TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/ietf-interfaces.yang", TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/iana-if-type.yang", TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/decimal.yang", TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/referenced-data.yang", TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/test-module.yang", TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/ops-ref.yang", TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/ops.yang", TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
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

    sr_remove_module(st->conn, "decimal", 0);
    sr_remove_module(st->conn, "ietf-interfaces", 0);
    sr_remove_module(st->conn, "iana-if-type", 0);
    sr_remove_module(st->conn, "test", 0);
    sr_remove_module(st->conn, "test-module", 0);
    sr_remove_module(st->conn, "referenced-data", 0);
    sr_remove_module(st->conn, "ops", 0);
    sr_remove_module(st->conn, "ops-ref", 0);

    sr_disconnect(st->conn);
    free(st);
    return 0;
}

static int
clear_interfaces(void **state)
{
    struct state *st = (struct state *)*state;

    sr_delete_item(st->sess, "/ietf-interfaces:interfaces", 0);
    sr_apply_changes(st->sess, 0);

    return 0;
}

static int
clear_test(void **state)
{
    struct state *st = (struct state *)*state;

    sr_delete_item(st->sess, "/test:l1", 0);
    sr_delete_item(st->sess, "/test:ll1", 0);
    sr_delete_item(st->sess, "/test:cont", 0);
    sr_delete_item(st->sess, "/test:l3", 0);
    sr_apply_changes(st->sess, 0);

    return 0;
}

static void
test_edit_item(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;

    /* invalid xpath */
    ret = sr_set_item_str(st->sess, "//test:cont/ll2", "15", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);

    /* non-existing xpath */
    ret = sr_set_item_str(st->sess, "/test:cont/no", "15", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);

    /* key edit */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='val']/name", "val", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);

    /* same edits are ignored */
    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* should also work for leaf-lists */
    ret = sr_set_item_str(st->sess, "/test:cont/ll2", "15", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:cont/ll2", "16", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:cont/ll2", "15", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:cont/ll2[.='16']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(st->sess, "/test:cont/ll2[.='16']", 0);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* user-ordered lists */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/enabled",
            "false", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_move_item(st->sess, "/ietf-interfaces:interfaces/interface[name='eth2']",
            SR_MOVE_FIRST, NULL, NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    assert_true(sr_has_changes(st->sess));
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_delete(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *subtree;
    char *str;
    int ret;

    /* remove on no data */
    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* delete on no data */
    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type", SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_NOT_FOUND);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* delete a leaf without exact value */
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "16", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_delete_item(st->sess, "/test:test-leaf", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check final datastore contents */
    ret = sr_get_subtree(st->sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, subtree->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_null(str);
    sr_release_data(subtree);
}

static void
test_create1(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *subtree;
    char *str;
    const char *str2;
    int ret;

    /* one-by-one create */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']", NULL, NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_subtree(st->sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, subtree->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    sr_release_data(subtree);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth64</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str, str2);
    free(str);

    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* create with non-existing parents */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_NON_RECURSIVE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_NOT_FOUND);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_create2(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *subtree;
    char *str;
    const char *str2;
    int ret;

    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces/interface[name='eth68']", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_subtree(st->sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, subtree->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    sr_release_data(subtree);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth64</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str, str2);
    free(str);

    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_subtree(st->sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, subtree->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_null(str);
    sr_release_data(subtree);
}

static void
test_create_np_cont(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *subtree;
    int ret;

    ret = sr_get_subtree(st->sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    assert_string_equal(subtree->tree->schema->name, "interfaces");
    assert_true(subtree->tree->flags & LYD_DEFAULT);
    sr_release_data(subtree);

    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces", NULL, NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_subtree(st->sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    assert_string_equal(subtree->tree->schema->name, "interfaces");
    assert_true(subtree->tree->flags & LYD_DEFAULT);
    sr_release_data(subtree);

    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces", NULL, NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces", NULL, NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_move(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    char *str, *str2;
    int ret;

    /* create top-level testing data */
    ret = sr_set_item_str(st->sess, "/test:l1[k='key1']/v", "1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:l1[k='key2']/v", "2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_move_item(st->sess, "/test:l1[k='key3']", SR_MOVE_AFTER, "[k='key2']", NULL, NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:l1[k='key3']/v", "3", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:ll1", "-1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:ll1", "-2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:ll1", "-3", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* perform some move operations */
    ret = sr_move_item(st->sess, "/test:l1[k='key3']", SR_MOVE_FIRST, NULL, NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_move_item(st->sess, "/test:l1[k='key1']", SR_MOVE_AFTER, "[test:k='key2']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_move_item(st->sess, "/test:ll1[.='-3']", SR_MOVE_FIRST, NULL, NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_move_item(st->sess, "/test:ll1[.='-1']", SR_MOVE_AFTER, NULL, "-2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/test:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    /* should be in reversed order */
    lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);

    str2 =
    "<l1 xmlns=\"urn:test\">"
        "<k>key3</k>"
        "<v>3</v>"
    "</l1>"
    "<l1 xmlns=\"urn:test\">"
        "<k>key2</k>"
        "<v>2</v>"
    "</l1>"
    "<l1 xmlns=\"urn:test\">"
        "<k>key1</k>"
        "<v>1</v>"
    "</l1>"
    "<ll1 xmlns=\"urn:test\">-3</ll1>"
    "<ll1 xmlns=\"urn:test\">-2</ll1>"
    "<ll1 xmlns=\"urn:test\">-1</ll1>";
    assert_string_equal(str, str2);

    free(str);
    sr_release_data(data);

    /* create nested testing data */
    ret = sr_set_item_str(st->sess, "/test:cont/l2[k='key1']/v", "1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:cont/l2[k='key2']/v", "2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:cont/l2[k='key3']/v", "3", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:cont/ll2", "-1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:cont/ll2", "-2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:cont/ll2", "-3", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* perform some move operations */
    ret = sr_move_item(st->sess, "/test:cont/l2[k='key1']", SR_MOVE_LAST, NULL, NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_move_item(st->sess, "/test:cont/l2[k='key3']", SR_MOVE_BEFORE, "[k='key2']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_move_item(st->sess, "/test:cont/ll2[.='-1']", SR_MOVE_LAST, NULL, NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_move_item(st->sess, "/test:cont/ll2[.='-3']", SR_MOVE_BEFORE, NULL, "-2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/test:cont", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    /* should be in reversed order */
    lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_SHRINK);

    str2 =
    "<cont xmlns=\"urn:test\">"
        "<l2><k>key3</k><v>3</v></l2>"
        "<l2><k>key2</k><v>2</v></l2>"
        "<l2><k>key1</k><v>1</v></l2>"
        "<ll2>-3</ll2>"
        "<ll2>-2</ll2>"
        "<ll2>-1</ll2>"
    "</cont>";
    assert_string_equal(str, str2);

    free(str);
    sr_release_data(data);
}

static void
test_replace(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *subtree;
    char *str, *str2;
    int ret;

    /* create some data */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']", NULL, NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* remove and create some other data, internally transformed into replace */
    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth32']", NULL, NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth32']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check final datastore contents */
    ret = sr_get_subtree(st->sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, subtree->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    sr_release_data(subtree);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth32</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str, str2);
    free(str);
}

static void
test_replace_userord(void **state)
{
    struct state *st = (struct state *)*state;
    const struct ly_ctx *ly_ctx;
    struct lyd_node *edit;
    sr_data_t *data;
    char *str, *str2;
    int ret;

    /* create some data */
    ret = sr_set_item_str(st->sess, "/test:l3[k='one']", NULL, NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* replace some data with a custom edit */
    str2 =
    "<l3 xmlns=\"urn:test\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"replace\">"
        "<k>one</k>"
        "<ll3>3</ll3>"
    "</l3>";
    ly_ctx = sr_acquire_context(st->conn);
    assert_int_equal(LY_SUCCESS, lyd_parse_data_mem(ly_ctx, str2, LYD_XML, LYD_PARSE_ONLY, 0, &edit));
    ret = sr_edit_batch(st->sess, edit, "merge");
    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check final datastore contents */
    ret = sr_get_data(st->sess, "/test:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    sr_release_data(data);

    str2 =
    "<l3 xmlns=\"urn:test\">"
        "<k>one</k>"
        "<ll3>3</ll3>"
    "</l3>";

    assert_string_equal(str, str2);
    free(str);
}

static void
test_isolate(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *subtree;
    char *str, *str2;
    int ret;

    /* data fails to be applied */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT | SR_EDIT_ISOLATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:softwareLoopback", NULL, SR_EDIT_STRICT | SR_EDIT_ISOLATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_EXISTS);

    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* data successfully applied when not strict */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT | SR_EDIT_ISOLATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:softwareLoopback", NULL, SR_EDIT_ISOLATE);
    assert_int_equal(ret, SR_ERR_OK);
    /* invalid edit but keeps the previous one */
    ret = sr_move_item(st->sess, "/ietf-interfaces:interfaces/interface[name='eth32']",
            SR_MOVE_FIRST, NULL, NULL, NULL, SR_EDIT_ISOLATE);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check datastore contents */
    ret = sr_get_subtree(st->sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, subtree->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    sr_release_data(subtree);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth64</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:softwareLoopback</type>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str, str2);
    free(str);

    /* try some more isolated edits, with data from one module not next to each other */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/enabled",
            "false", NULL, SR_EDIT_ISOLATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']", SR_EDIT_STRICT | SR_EDIT_ISOLATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "15", NULL, SR_EDIT_STRICT | SR_EDIT_ISOLATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:other", NULL, SR_EDIT_STRICT | SR_EDIT_ISOLATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(st->sess, "/test:test-leaf", SR_EDIT_STRICT | SR_EDIT_ISOLATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check datastore contents */
    ret = sr_get_subtree(st->sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, subtree->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    sr_release_data(subtree);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth64</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:other</type>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str, str2);
    free(str);
}

static void
test_purge(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *subtree;
    int ret;

    /* create some list instances */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth65']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth66']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth67']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* delete all instances */
    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces/interface", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check datastore contents */
    ret = sr_get_subtree(st->sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_true(subtree->tree->flags & LYD_DEFAULT);
    sr_release_data(subtree);

    /* repeat with leaf-list */
    ret = sr_set_item_str(st->sess, "/test:ll1", "12", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:ll1", "13", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:ll1", "14", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_delete_item(st->sess, "/test:ll1", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_subtree(st->sess, "/test:ll1", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_null(subtree);
}

static void
test_top_op(void **state)
{
    struct state *st = (struct state *)*state;
    const struct ly_ctx *ly_ctx;
    struct lyd_node *edit;
    sr_data_t *subtree;
    const char *str;
    int ret;

    /* create some data */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']", NULL, NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth65']", NULL, NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth65']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* replace the top-level container with an empty one */
    str = "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\" nc:operation=\"replace\" xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\"/>";
    ly_ctx = sr_acquire_context(st->conn);
    assert_int_equal(LY_SUCCESS, lyd_parse_data_mem(ly_ctx, str, LYD_XML, LYD_PARSE_ONLY | LYD_PARSE_STRICT, 0, &edit));

    ret = sr_edit_batch(st->sess, edit, "merge");
    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check datastore contents */
    ret = sr_get_subtree(st->sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    assert_true(subtree->tree->flags & LYD_DEFAULT);
    sr_release_data(subtree);
}

static void
test_union(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *subtree;
    const char *str2;
    char *str;
    int ret;

    /* create some host */
    ret = sr_set_item_str(st->sess, "/test:cont/server", "fe80::42:39ff:fe67:1fb3", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* change it */
    ret = sr_set_item_str(st->sess, "/test:cont/server", "192.168.1.10", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check datastore contents */
    ret = sr_get_subtree(st->sess, "/test:cont", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, subtree->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    sr_release_data(subtree);

    str2 =
    "<cont xmlns=\"urn:test\">"
        "<server>192.168.1.10</server>"
    "</cont>";

    assert_string_equal(str, str2);
    free(str);
}

static void
test_decimal64(void **state)
{
    struct state *st = (struct state *)*state;
    sr_val_t val = {.type = SR_DECIMAL64_T};
    sr_data_t *subtree;
    int ret;

    /* set item_str */
    ret = sr_set_item_str(st->sess, "/decimal:d1", "255.5", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/decimal:d1", "255.55", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);

    ret = sr_set_item_str(st->sess, "/decimal:d1", "+00255.50", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/decimal:d1", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_string_equal(lyd_get_value(subtree->tree), "255.5");
    sr_release_data(subtree);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/decimal:d-uni-2-18", "10.0000000000000001", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);

    ret = sr_set_item_str(st->sess, "/decimal:d-uni-2-18", "9.0000000000000001", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/decimal:d-uni-2-18", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_string_equal(lyd_get_value(subtree->tree), "9.0000000000000001");
    sr_release_data(subtree);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/decimal:d-uni-2-18", "2.01", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/decimal:d-uni-2-18", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_string_equal(lyd_get_value(subtree->tree), "2.01");
    sr_release_data(subtree);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* set item (value) */
    val.data.decimal64_val = 255.5;
    ret = sr_set_item(st->sess, "/decimal:d1", &val, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* value gets rounded automatically because it is impossible to know what value was originally set
     * (because of precision loss) */
    val.data.decimal64_val = 255.55;
    ret = sr_set_item(st->sess, "/decimal:d1", &val, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/decimal:d1", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_string_equal(lyd_get_value(subtree->tree), "255.6");
    sr_release_data(subtree);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* it is valid with 2 fraction digits, resolved as such because of rounding */
    val.data.decimal64_val = 10.0000000000000001;
    ret = sr_set_item(st->sess, "/decimal:d-uni-2-18", &val, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/decimal:d-uni-2-18", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_string_equal(lyd_get_value(subtree->tree), "10.0");
    sr_release_data(subtree);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* outside double precision */
    val.data.decimal64_val = 9.0000000000000001;
    ret = sr_set_item(st->sess, "/decimal:d-uni-2-18", &val, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/decimal:d-uni-2-18", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_string_equal(lyd_get_value(subtree->tree), "9.0");
    sr_release_data(subtree);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* rounded to 2 fraction digits */
    val.data.decimal64_val = 2.01;
    ret = sr_set_item(st->sess, "/decimal:d-uni-2-18", &val, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/decimal:d-uni-2-18", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_string_equal(lyd_get_value(subtree->tree), "2.01");
    sr_release_data(subtree);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_mutiple_types(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *subtree;
    char *str, *str2;
    int ret;
    sr_val_t val = {0};

    /* type string */
    val.type = SR_STRING_T;
    val.data.string_val = "string\"\"\'";
    ret = sr_set_item(st->sess, "/test-module:main/string", &val, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/test-module:main/string", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_string_equal(lyd_get_value(subtree->tree), "string\"\"\'");
    sr_release_data(subtree);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* type binary */
    val.type = SR_BINARY_T;
    val.data.string_val = "VGhpcyBpcyBleGFtcGxlIG1lc3NhZ2Uu";
    ret = sr_set_item(st->sess, "/test-module:main/raw", &val, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/test-module:main/raw", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_string_equal(lyd_get_value(subtree->tree), "VGhpcyBpcyBleGFtcGxlIG1lc3NhZ2Uu");
    sr_release_data(subtree);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* type bit */
    val.type = SR_BITS_T;
    val.data.string_val = "strict";
    ret = sr_set_item(st->sess, "/test-module:main/options", &val, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/test-module:main/options", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_string_equal(lyd_get_value(subtree->tree), "strict");
    sr_release_data(subtree);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* type enum */
    val.type = SR_ENUM_T;
    val.data.string_val = "yes";
    ret = sr_set_item(st->sess, "/test-module:main/enum", &val, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/test-module:main/enum", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_string_equal(lyd_get_value(subtree->tree), "yes");
    sr_release_data(subtree);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* type identityref */
    val.type = SR_IDENTITYREF_T;
    val.data.string_val = "id_1";
    ret = sr_set_item(st->sess, "/test-module:main/id_ref", &val, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/test-module:main/id_ref", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_string_equal(lyd_get_value(subtree->tree), "test-module:id_1");
    sr_release_data(subtree);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* type instance-identifier */
    val.type = SR_INSTANCEID_T;
    val.data.string_val = "/test-module:main/options";
    ret = sr_set_item(st->sess, "/test-module:main/instance_id", &val, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/test-module:main/instance_id", 0, 0, 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    lyd_print_mem(&str, subtree->tree, LYD_XML, LYD_PRINT_SHRINK);
    assert_return_code(asprintf(&str2,
    "<main xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">"
        "<instance_id xmlns:tm=\"urn:ietf:params:xml:ns:yang:test-module\">/tm:main/tm:options</instance_id>"
    "</main>"), 0);
    assert_string_equal(str, str2);
    free(str);
    free(str2);
    sr_release_data(subtree);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* anydata */
    val.type = SR_ANYDATA_T;
    val.data.string_val = "test";
    ret = sr_set_item(st->sess, "/test-module:main/any-data", &val, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/test-module:main/any-data", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_string_equal(((struct lyd_node_any *)subtree->tree)->value.str, "test");
    sr_release_data(subtree);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* type empty */
    val.type = SR_LEAF_EMPTY_T;
    ret = sr_set_item(st->sess, "/test-module:main/empty", &val, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/test-module:main/empty", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_string_equal(lyd_get_value(subtree->tree), "");
    sr_release_data(subtree);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* type boolean */
    val.type = SR_BOOL_T;
    val.data.bool_val = 1;
    ret = sr_set_item(st->sess, "/test-module:main/boolean", &val, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/test-module:main/boolean", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(((struct lyd_node_term *)subtree->tree)->value.boolean, 1);
    sr_release_data(subtree);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* type uint8 */
    val.type = SR_UINT8_T;
    val.data.uint8_val = UINT8_MAX;
    ret = sr_set_item(st->sess, "/test-module:main/ui8", &val, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/test-module:main/ui8", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(((struct lyd_node_term *)subtree->tree)->value.uint8, UINT8_MAX);
    sr_release_data(subtree);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* type uint16 */
    val.type = SR_UINT16_T;
    val.data.uint16_val = UINT16_MAX;
    ret = sr_set_item(st->sess, "/test-module:main/ui16", &val, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/test-module:main/ui16", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(((struct lyd_node_term *)subtree->tree)->value.uint16, UINT16_MAX);
    sr_release_data(subtree);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* type uint32 */
    val.type = SR_UINT32_T;
    val.data.uint32_val = UINT32_MAX;
    ret = sr_set_item(st->sess, "/test-module:main/ui32", &val, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/test-module:main/ui32", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(((struct lyd_node_term *)subtree->tree)->value.uint32, UINT32_MAX);
    sr_release_data(subtree);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* type uint64 */
    val.type = SR_UINT64_T;
    val.data.uint64_val = UINT64_MAX;
    ret = sr_set_item(st->sess, "/test-module:main/ui64", &val, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/test-module:main/ui64", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(((struct lyd_node_term *)subtree->tree)->value.uint64, UINT64_MAX);
    sr_release_data(subtree);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* type int8 */
    val.type = SR_INT8_T;
    val.data.int8_val = INT8_MAX;
    ret = sr_set_item(st->sess, "/test-module:main/i8", &val, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/test-module:main/i8", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(((struct lyd_node_term *)subtree->tree)->value.int8, INT8_MAX);
    sr_release_data(subtree);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* type int16 */
    val.type = SR_INT16_T;
    val.data.int16_val = INT16_MAX;
    ret = sr_set_item(st->sess, "/test-module:main/i16", &val, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/test-module:main/i16", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(((struct lyd_node_term *)subtree->tree)->value.int16, INT16_MAX);
    sr_release_data(subtree);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* type int32 */
    val.type = SR_INT32_T;
    val.data.int32_val = INT32_MAX;
    ret = sr_set_item(st->sess, "/test-module:main/i32", &val, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/test-module:main/i32", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(((struct lyd_node_term *)subtree->tree)->value.int32, INT32_MAX);
    sr_release_data(subtree);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* type int64 */
    val.type = SR_INT64_T;
    val.data.int64_val = INT64_MAX;
    ret = sr_set_item(st->sess, "/test-module:main/i64", &val, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/test-module:main/i64", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(((struct lyd_node_term *)subtree->tree)->value.int64, INT64_MAX);
    sr_release_data(subtree);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);
}

/* rpc/action/notification node not allowed to be edited */
static void
test_edit_forbid_node_types(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *subtree;
    char *str;
    const char *str2;
    int ret;

    /* set some data needed for validation */
    ret = sr_set_item_str(st->sess, "/ops:cont/list1[k='key']", NULL, NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* rpc node cannot be created */
    ret = sr_set_item_str(st->sess, "/ops:rpc3/l4", "val", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/ops:rpc3/l4", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_null(subtree);

    /* action node cannot be created */
    ret = sr_set_item_str(st->sess, "/ops:cont/list1[k='k']/cont2/act1/l6", "val", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/ops:cont/list1[k='k']/cont2/act1/l6", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_null(subtree);

    /* notification node cannot be created */
    ret = sr_set_item_str(st->sess, "/ops:notif3/list2[k='k']", NULL, NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_subtree(st->sess, "/ops:notif3/list2[k='k']", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_null(subtree);

    /* not throw away the whole edit, the successfully created node still exists */
    ret = sr_get_subtree(st->sess, "/ops:cont", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    lyd_print_mem(&str, subtree->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);

    str2 =
    "<cont xmlns=\"urn:ops\">"
        "<list1>"
            "<k>key</k>"
        "</list1>"
    "</cont>";

    assert_string_equal(str, str2);
    sr_release_data(subtree);
    free(str);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_edit_item),
        cmocka_unit_test_teardown(test_delete, clear_interfaces),
        cmocka_unit_test_teardown(test_create1, clear_interfaces),
        cmocka_unit_test_teardown(test_create2, clear_interfaces),
        cmocka_unit_test_teardown(test_create_np_cont, clear_interfaces),
        cmocka_unit_test_teardown(test_move, clear_test),
        cmocka_unit_test_teardown(test_replace, clear_interfaces),
        cmocka_unit_test_teardown(test_replace_userord, clear_test),
        cmocka_unit_test_teardown(test_isolate, clear_interfaces),
        cmocka_unit_test(test_purge),
        cmocka_unit_test(test_top_op),
        cmocka_unit_test_teardown(test_union, clear_test),
        cmocka_unit_test(test_decimal64),
        cmocka_unit_test(test_mutiple_types),
        cmocka_unit_test(test_edit_forbid_node_types),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    sr_log_stderr(SR_LL_INF);
    return cmocka_run_group_tests(tests, setup_f, teardown_f);
}
