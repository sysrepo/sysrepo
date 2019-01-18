/**
 * @file test_operational.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test for operational datastore behavior
 *
 * @copyright
 * Copyright (c) 2019 CESNET, z.s.p.o.
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

#include <cmocka.h>
#include <libyang/libyang.h>

#include "tests/config.h"
#include "sysrepo.h"

struct state {
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
};

static int
setup(void **state)
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
    if (sr_install_module(st->conn, TESTS_DIR "/files/ietf-interfaces.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_DIR "/files/iana-if-type.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        return 1;
    }

    if (sr_session_start(st->conn, SR_DS_RUNNING, 0, &st->sess) != SR_ERR_OK) {
        return 1;
    }

    return 0;
}

static int
teardown(void **state)
{
    struct state *st = (struct state *)*state;

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
    sr_apply_changes(st->sess);

    return 0;
}

/* TEST 1 (no threads) */
static int
dummy_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_notif_event_t event,
        void *private_data)
{
    (void)session;
    (void)module_name;
    (void)xpath;
    (void)event;
    (void)private_data;

    return SR_ERR_OK;
}

static void
test_enabled_partial(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr;
    struct lyd_node *subtree;
    char *str;
    const char *str2;
    int ret;

    /* create some data */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth128']/type",
            "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* read them back from "running" */
    ret = sr_get_subtree(st->sess, "/ietf-interfaces:interfaces", &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, subtree, LYD_XML, LYP_WITHSIBLINGS);
    lyd_free(subtree);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth64</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
        "<interface>"
            "<name>eth128</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str, str2);
    free(str);

    /* they should not be in "operational" because there is no subscription */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_subtree(st->sess, "/ietf-interfaces:interfaces", &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    assert_null(subtree);

    /* subscribe to one specific interface */
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface[name='eth128']",
            dummy_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* that is the only interface that should now be in "operational" */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_subtree(st->sess, "/ietf-interfaces:interfaces", &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, subtree, LYD_XML, LYP_WITHSIBLINGS);
    lyd_free(subtree);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth128</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str, str2);
    free(str);

    /* unsusbcribe */
    sr_unsubscribe(subscr);

    /* subscribe to a not-present interface */
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface[name='eth256']",
            dummy_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* "operational" should be empty again */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_subtree(st->sess, "/ietf-interfaces:interfaces", &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    assert_null(subtree);

    /* unsusbcribe */
    sr_unsubscribe(subscr);
}

/* TEST 2 */
static int
simple_dp_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, struct lyd_node **parent,
        void *private_data)
{
    struct ly_ctx *ly_ctx = (struct ly_ctx *)private_data;
    struct lyd_node *node;

    (void)session;
    (void)private_data;

    assert_string_equal(module_name, "ietf-interfaces");
    assert_string_equal(xpath, "/ietf-interfaces:interfaces-state");
    assert_non_null(parent);
    assert_null(*parent);

    node = lyd_new_path(NULL, ly_ctx, "/ietf-interfaces:interfaces-state/interface[name='eth5']/type",
            "iana-if-type:ethernetCsmacd", 0, 0);
    assert_non_null(node);
    *parent = node;

    node = lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth5']/oper-status",
            "testing", 0, 0);
    assert_non_null(node);

    return SR_ERR_OK;
}

static void
test_simple(void **state)
{
    struct state *st = (struct state *)*state;
    const struct ly_ctx *ly_ctx;
    struct ly_set *subtrees;
    sr_subscription_ctx_t *subscr;
    char *str1;
    const char *str2;
    int ret;

    ret = sr_get_context(st->conn, &ly_ctx);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some configuration data */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to all configuration data just to enable them */
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces", dummy_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* try to read them back from operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_subtrees(st->sess, "/ietf-interfaces:*", &subtrees);
    assert_int_equal(ret, SR_ERR_OK);

    assert_int_equal(subtrees->number, 1);
    ret = lyd_print_mem(&str1, subtrees->set.d[0], LYD_XML, LYP_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    lyd_free_withsiblings(subtrees->set.d[0]);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth1</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str1, str2);
    free(str1);

    ly_set_free(subtrees);

    /* subscribe as state data provider and actually listen */
    ret = sr_dp_get_items_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", simple_dp_cb,
            (void *)ly_ctx, SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_subscription_listen(subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* read all data from operational again */
    ret = sr_get_subtrees(st->sess, "/ietf-interfaces:*", &subtrees);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(subtrees->number, 2);

    /* print first subtree */
    ret = lyd_print_mem(&str1, subtrees->set.d[0], LYD_XML, LYP_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    lyd_free_withsiblings(subtrees->set.d[0]);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth1</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str1, str2);
    free(str1);

    /* print second subtree */
    ret = lyd_print_mem(&str1, subtrees->set.d[1], LYD_XML, LYP_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    lyd_free_withsiblings(subtrees->set.d[1]);

    str2 =
    "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth5</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<oper-status>testing</oper-status>"
        "</interface>"
    "</interfaces-state>";

    assert_string_equal(str1, str2);
    free(str1);

    ly_set_free(subtrees);

    sr_unsubscribe(subscr);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_enabled_partial, clear_interfaces),
        cmocka_unit_test_teardown(test_simple, clear_interfaces),
    };

    sr_log_stderr(SR_LL_INF);
    return cmocka_run_group_tests(tests, setup, teardown);
}
