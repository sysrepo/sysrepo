/**
 * @file test_candidate.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test for candidate datastore
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
#include <stdarg.h>
#include <stdlib.h>

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
    if (sr_install_module(st->conn, TESTS_DIR "/files/ietf-interfaces.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_DIR "/files/iana-if-type.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_DIR "/files/when1.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
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

    sr_remove_module(st->conn, "when1");
    sr_remove_module(st->conn, "ietf-interfaces");
    sr_remove_module(st->conn, "iana-if-type");
    sr_remove_module(st->conn, "test");

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
    sr_apply_changes(st->sess, 0, 1);

    return 0;
}

static void
test_basic(void **state)
{
    struct state *st = (struct state *)*state;
    struct lyd_node *data;
    char *str;
    const char *str2;
    int ret;

    /* empty datastore */
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(data->dflt, 1);
    lyd_free_withsiblings(data);

    ret = sr_session_switch_ds(st->sess, SR_DS_CANDIDATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(data->dflt, 1);
    lyd_free_withsiblings(data);

    /* modified running */
    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_switch_ds(st->sess, SR_DS_CANDIDATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(data->dflt, 0);
    lyd_free_withsiblings(data);

    /* modify candidate */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth32']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, data, LYD_XML, LYP_WITHSIBLINGS);
    lyd_free_withsiblings(data);
    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth64</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
    "</interfaces>";
    assert_string_equal(str, str2);
    free(str);

    ret = sr_session_switch_ds(st->sess, SR_DS_CANDIDATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, data, LYD_XML, LYP_WITHSIBLINGS);
    lyd_free_withsiblings(data);
    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth32</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
    "</interfaces>";
    assert_string_equal(str, str2);
    free(str);

    /* locking not allowed anymore */
    ret = sr_lock(st->sess, NULL);
    assert_int_equal(ret, SR_ERR_UNSUPPORTED);

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    /* copy-config to running, should also reset candidate */
    ret = sr_copy_config(st->sess, NULL, SR_DS_CANDIDATE, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, data, LYD_XML, LYP_WITHSIBLINGS);
    lyd_free_withsiblings(data);
    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth32</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
    "</interfaces>";
    assert_string_equal(str, str2);
    free(str);

    ret = sr_lock(st->sess, NULL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_unlock(st->sess, NULL);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_invalid(void **state)
{
    struct state *st = (struct state *)*state;
    struct lyd_node *data;
    char *str;
    const char *str2;
    int ret;

    /* empty datastore */
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(data->dflt, 1);
    lyd_free_withsiblings(data);

    ret = sr_session_switch_ds(st->sess, SR_DS_CANDIDATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(data->dflt, 1);
    lyd_free_withsiblings(data);

    /* modify candidate */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth32']", NULL, NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    /* check content */
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, data, LYD_XML, LYP_WITHSIBLINGS);
    lyd_free_withsiblings(data);
    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth32</name>"
        "</interface>"
    "</interfaces>";
    assert_string_equal(str, str2);
    free(str);

    /* is not valid */
    ret = sr_validate(st->sess, "ietf-interfaces", 0);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    /* copy-config to candidate, should reset it */
    ret = sr_copy_config(st->sess, NULL, SR_DS_RUNNING, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(data->dflt, 1);
    lyd_free_withsiblings(data);
    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_when(void **state)
{
    struct state *st = (struct state *)*state;
    struct lyd_node *data;
    char *str;
    const char *str2 = "<l3 xmlns=\"urn:when1\">hi</l3>";
    int ret;

    ret = sr_session_switch_ds(st->sess, SR_DS_CANDIDATE);
    assert_int_equal(ret, SR_ERR_OK);

    /* modify candidate */
    ret = sr_set_item_str(st->sess, "/when1:l3", "hi", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/when1:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, data, LYD_XML, LYP_WITHSIBLINGS);
    lyd_free_withsiblings(data);
    assert_string_equal(str, str2);
    free(str);

    /* is not valid */
    ret = sr_validate(st->sess, "when1", 0);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    ret = sr_delete_item(st->sess, "/when1:l3", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    /* should be valid again (empty) */
    ret = sr_validate(st->sess, "when1", 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* the same change but with replace config */
    data = lyd_parse_mem((struct ly_ctx *)sr_get_context(st->conn), str2, LYD_XML, LYD_OPT_CONFIG | LYD_OPT_TRUSTED | LYD_OPT_STRICT);
    assert_non_null(data);
    ret = sr_replace_config(st->sess, "when1", data, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/when1:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, data, LYD_XML, LYP_WITHSIBLINGS);
    lyd_free_withsiblings(data);
    assert_string_equal(str, str2);
    free(str);

    /* is not valid */
    ret = sr_validate(st->sess, NULL, 0);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    /* copy-config to running, should fail */
    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_copy_config(st->sess, NULL, SR_DS_CANDIDATE, 0, 1);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    /* copy-config to candidate, should reset it */
    ret = sr_session_switch_ds(st->sess, SR_DS_CANDIDATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_copy_config(st->sess, NULL, SR_DS_RUNNING, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_reset_unlock(void **state)
{
    struct state *st = (struct state *)*state;
    struct lyd_node *data;
    char *str;
    const char *str2;
    int ret;

    /* empty datastore */
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(data->dflt, 1);
    lyd_free_withsiblings(data);

    ret = sr_session_switch_ds(st->sess, SR_DS_CANDIDATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(data->dflt, 1);
    lyd_free_withsiblings(data);

    /* lock candidate */
    ret = sr_lock(st->sess, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* modify candidate */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth32']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth32']/enabled",
            "false", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    /* check content */
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, data, LYD_XML, LYP_WITHSIBLINGS);
    lyd_free_withsiblings(data);
    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth32</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<enabled>false</enabled>"
        "</interface>"
    "</interfaces>";
    assert_string_equal(str, str2);
    free(str);

    /* unlock, should reset candidate */
    ret = sr_unlock(st->sess, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* check content */
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(data->dflt, 1);
    lyd_free_withsiblings(data);

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_reset_session_stop(void **state)
{
    struct state *st = (struct state *)*state;
    sr_session_ctx_t *sess2;
    struct lyd_node *data;
    char *str;
    const char *str2;
    int ret;

    /* start another session */
    ret = sr_session_start(st->conn, SR_DS_CANDIDATE, &sess2);
    assert_int_equal(ret, SR_ERR_OK);

    /* empty datastore */
    ret = sr_get_data(sess2, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(data->dflt, 1);
    lyd_free_withsiblings(data);

    ret = sr_session_switch_ds(st->sess, SR_DS_CANDIDATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(data->dflt, 1);
    lyd_free_withsiblings(data);

    /* lock candidate */
    ret = sr_lock(sess2, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* modify candidate */
    ret = sr_set_item_str(sess2, "/ietf-interfaces:interfaces/interface[name='eth32']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess2, "/ietf-interfaces:interfaces/interface[name='eth32']/enabled",
            "false", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess2, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    /* check content */
    ret = sr_get_data(sess2, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, data, LYD_XML, LYP_WITHSIBLINGS);
    lyd_free_withsiblings(data);
    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth32</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<enabled>false</enabled>"
        "</interface>"
    "</interfaces>";
    assert_string_equal(str, str2);
    free(str);

    /* stop session, should reset candidate */
    ret = sr_session_stop(sess2);
    assert_int_equal(ret, SR_ERR_OK);

    /* check content */
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(data->dflt, 1);
    lyd_free_withsiblings(data);

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
    sr_log_stderr(SR_LL_INF);
    return cmocka_run_group_tests(tests, setup_f, teardown_f);
}
