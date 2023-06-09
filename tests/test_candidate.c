/**
 * @file test_candidate.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test for candidate datastore
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
    sr_session_ctx_t *sess;
};

static int
setup_f(void **state)
{
    struct state *st;
    const char *schema_paths[] = {
        TESTS_SRC_DIR "/files/test.yang",
        TESTS_SRC_DIR "/files/ietf-interfaces.yang",
        TESTS_SRC_DIR "/files/iana-if-type.yang",
        TESTS_SRC_DIR "/files/when1.yang",
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
        "when1",
        "ietf-interfaces",
        "iana-if-type",
        "test",
        NULL
    };

    sr_remove_modules(st->conn, module_names, 0);

    sr_disconnect(st->conn);
    free(st);
    return 0;
}

static int
clear_interfaces(void **state)
{
    struct state *st = (struct state *)*state;

    sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    sr_delete_item(st->sess, "/ietf-interfaces:interfaces", 0);
    sr_apply_changes(st->sess, 0);

    return 0;
}

static void
test_basic(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    char *str;
    const char *str2;
    int ret;

    /* empty datastore */
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_true(data->tree->flags & LYD_DEFAULT);
    sr_release_data(data);

    ret = sr_session_switch_ds(st->sess, SR_DS_CANDIDATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_true(data->tree->flags & LYD_DEFAULT);
    sr_release_data(data);

    /* modified running */
    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_switch_ds(st->sess, SR_DS_CANDIDATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_false(data->tree->flags & LYD_DEFAULT);
    sr_release_data(data);

    /* modify candidate */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth32']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    sr_release_data(data);
    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
            "  <interface>\n"
            "    <name>eth64</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "  </interface>\n"
            "</interfaces>\n";
    assert_string_equal(str, str2);
    free(str);

    ret = sr_session_switch_ds(st->sess, SR_DS_CANDIDATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    sr_release_data(data);
    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
            "  <interface>\n"
            "    <name>eth32</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "  </interface>\n"
            "</interfaces>\n";
    assert_string_equal(str, str2);
    free(str);

    /* locking not allowed anymore */
    ret = sr_lock(st->sess, NULL, 0);
    assert_int_equal(ret, SR_ERR_UNSUPPORTED);

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    /* copy-config to running, should also reset candidate */
    ret = sr_copy_config(st->sess, NULL, SR_DS_CANDIDATE, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    sr_release_data(data);
    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
            "  <interface>\n"
            "    <name>eth32</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "  </interface>\n"
            "</interfaces>\n";
    assert_string_equal(str, str2);
    free(str);

    ret = sr_lock(st->sess, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_unlock(st->sess, NULL);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_invalid(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    char *str;
    const char *str2;
    int ret;

    /* empty datastore */
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_true(data->tree->flags & LYD_DEFAULT);
    sr_release_data(data);

    ret = sr_session_switch_ds(st->sess, SR_DS_CANDIDATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_true(data->tree->flags & LYD_DEFAULT);
    sr_release_data(data);

    /* modify candidate */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth32']", NULL, NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check content */
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    sr_release_data(data);
    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
            "  <interface>\n"
            "    <name>eth32</name>\n"
            "  </interface>\n"
            "</interfaces>\n";
    assert_string_equal(str, str2);
    free(str);

    /* is not valid */
    ret = sr_validate(st->sess, "ietf-interfaces", 0);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    /* copy-config to candidate, should reset it */
    ret = sr_copy_config(st->sess, NULL, SR_DS_RUNNING, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_true(data->tree->flags & LYD_DEFAULT);
    sr_release_data(data);
    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_when(void **state)
{
    struct state *st = (struct state *)*state;
    struct lyd_node *tree;
    sr_data_t *data;
    char *str;
    const char *str2 = "<l3 xmlns=\"urn:when1\">hi</l3>\n";
    int ret;

    ret = sr_session_switch_ds(st->sess, SR_DS_CANDIDATE);
    assert_int_equal(ret, SR_ERR_OK);

    /* modify candidate */
    ret = sr_set_item_str(st->sess, "/when1:l3", "hi", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/when1:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    sr_release_data(data);
    assert_string_equal(str, str2);
    free(str);

    /* is not valid */
    ret = sr_validate(st->sess, "when1", 0);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    ret = sr_delete_item(st->sess, "/when1:l3", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* should be valid again (empty) */
    ret = sr_validate(st->sess, "when1", 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* the same change but with replace config */
    assert_int_equal(LY_SUCCESS, lyd_parse_data_mem(sr_acquire_context(st->conn), str2, LYD_XML, LYD_PARSE_NO_STATE |
            LYD_PARSE_ONLY | LYD_PARSE_STRICT, 0, &tree));
    ret = sr_replace_config(st->sess, "when1", tree, 0);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/when1:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    sr_release_data(data);
    assert_string_equal(str, str2);
    free(str);

    /* is not valid */
    ret = sr_validate(st->sess, NULL, 0);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    /* copy-config to running, should fail */
    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_copy_config(st->sess, NULL, SR_DS_CANDIDATE, 0);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    /* copy-config to candidate, should reset it */
    ret = sr_session_switch_ds(st->sess, SR_DS_CANDIDATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_copy_config(st->sess, NULL, SR_DS_RUNNING, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_reset_unlock(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    char *str;
    const char *str2;
    int ret;

    /* empty datastore */
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_true(data->tree->flags & LYD_DEFAULT);
    sr_release_data(data);

    ret = sr_session_switch_ds(st->sess, SR_DS_CANDIDATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_true(data->tree->flags & LYD_DEFAULT);
    sr_release_data(data);

    /* lock candidate */
    ret = sr_lock(st->sess, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* modify candidate */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth32']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth32']/enabled",
            "false", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check content */
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    sr_release_data(data);
    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
            "  <interface>\n"
            "    <name>eth32</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <enabled>false</enabled>\n"
            "  </interface>\n"
            "</interfaces>\n";
    assert_string_equal(str, str2);
    free(str);

    /* unlock, should reset candidate */
    ret = sr_unlock(st->sess, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* check content */
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_true(data->tree->flags & LYD_DEFAULT);
    sr_release_data(data);

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_reset_session_stop(void **state)
{
    struct state *st = (struct state *)*state;
    sr_session_ctx_t *sess2;
    sr_data_t *data;
    char *str;
    const char *str2;
    int ret;

    /* start another session */
    ret = sr_session_start(st->conn, SR_DS_CANDIDATE, &sess2);
    assert_int_equal(ret, SR_ERR_OK);

    /* empty datastore */
    ret = sr_get_data(sess2, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_true(data->tree->flags & LYD_DEFAULT);
    sr_release_data(data);

    ret = sr_session_switch_ds(st->sess, SR_DS_CANDIDATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_true(data->tree->flags & LYD_DEFAULT);
    sr_release_data(data);

    /* lock candidate */
    ret = sr_lock(sess2, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* modify candidate */
    ret = sr_set_item_str(sess2, "/ietf-interfaces:interfaces/interface[name='eth32']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess2, "/ietf-interfaces:interfaces/interface[name='eth32']/enabled",
            "false", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess2, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check content */
    ret = sr_get_data(sess2, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    sr_release_data(data);
    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
            "  <interface>\n"
            "    <name>eth32</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <enabled>false</enabled>\n"
            "  </interface>\n"
            "</interfaces>\n";
    assert_string_equal(str, str2);
    free(str);

    /* stop session, should reset candidate */
    ret = sr_session_stop(sess2);
    assert_int_equal(ret, SR_ERR_OK);

    /* check content */
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_true(data->tree->flags & LYD_DEFAULT);
    sr_release_data(data);

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_basic, clear_interfaces),
        cmocka_unit_test_teardown(test_invalid, clear_interfaces),
        cmocka_unit_test(test_when),
        cmocka_unit_test(test_reset_unlock),
        cmocka_unit_test(test_reset_session_stop),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    test_log_init();
    return cmocka_run_group_tests(tests, setup_f, teardown_f);
}
