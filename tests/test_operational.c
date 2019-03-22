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

    if (sr_session_start(st->conn, SR_DS_RUNNING, &st->sess) != SR_ERR_OK) {
        return 1;
    }

    sr_session_set_nc_id(st->sess, 64);

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

    sr_session_switch_ds(st->sess, SR_DS_STARTUP);

    sr_delete_item(st->sess, "/ietf-interfaces:interfaces", 0);
    sr_apply_changes(st->sess);

    sr_session_switch_ds(st->sess, SR_DS_RUNNING);

    sr_delete_item(st->sess, "/ietf-interfaces:interfaces", 0);
    sr_apply_changes(st->sess);

    return 0;
}

/* TEST 1 (no threads) */
static int
enabled_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_notif_event_t event,
        void *private_data)
{
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    int ret, *called = (int *)private_data;

    if (!strcmp(xpath, "/ietf-interfaces:interfaces/interface[name='eth128']")) {
        assert_string_equal(module_name, "ietf-interfaces");

        if (*called == 0) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth128']");

        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth128']/name");

        sr_free_val(new_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth128']/type");

        sr_free_val(new_val);

        /* 5th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth128']/enabled");
        assert_int_equal(new_val->dflt, 1);

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
    } else {
        fail();
    }

    ++(*called);
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
    int ret, called;

    /* create some configuration data */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth128']/type",
            "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* nothing should be in "operational" because there is no subscription */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_subtree(st->sess, "/ietf-interfaces:interfaces", &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    assert_null(subtree);

    /* subscribe to one specific interface and also expect to be notified */
    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    called = 0;
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface[name='eth128']",
            enabled_change_cb, &called, 0, SR_SUBSCR_ENABLED, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(called, 2);

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
    called = 0;
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface[name='eth256']",
            enabled_change_cb, &called, 0, SR_SUBSCR_ENABLED, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(called, 0);

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
    const struct ly_ctx *ly_ctx;
    struct lyd_node *node;

    assert_int_equal(sr_session_get_nc_id(session), 64);
    (void)private_data;

    ly_ctx = sr_get_context(sr_session_get_connection(session));

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

    node = lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth5']/statistics/discontinuity-time",
            "2000-01-01T00:00:00Z", 0, 0);
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

    ly_ctx = sr_get_context(st->conn);
    assert_non_null(ly_ctx);

    /* set some configuration data */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to all configuration data just to enable them */
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces", enabled_change_cb, NULL, 0, 0, &subscr);
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

    /* subscribe as state data provider */
    ret = sr_dp_get_items_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", simple_dp_cb,
            NULL, SR_SUBSCR_CTX_REUSE, &subscr);
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
            "<statistics>"
                "<discontinuity-time>2000-01-01T00:00:00Z</discontinuity-time>"
            "</statistics>"
        "</interface>"
    "</interfaces-state>";

    assert_string_equal(str1, str2);
    free(str1);

    ly_set_free(subtrees);

    sr_unsubscribe(subscr);
}

/* TEST 3 */
static int
fail_dp_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, struct lyd_node **parent,
        void *private_data)
{
    (void)session;
    (void)private_data;

    assert_string_equal(module_name, "ietf-interfaces");
    assert_string_equal(xpath, "/ietf-interfaces:interfaces-state");
    assert_non_null(parent);
    assert_null(*parent);

    sr_set_error(session, "Callback failed with an error", "/no/special/xpath");
    return SR_ERR_UNAUTHORIZED;
}

static void
test_fail(void **state)
{
    struct state *st = (struct state *)*state;
    struct ly_set *subtrees;
    sr_subscription_ctx_t *subscr;
    int ret;

    /* set some configuration data */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe as state data provider*/
    ret = sr_dp_get_items_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", fail_dp_cb,
            NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* read all data from operational */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_subtrees(st->sess, "/ietf-interfaces:*", &subtrees);
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);

    sr_unsubscribe(subscr);
}

/* TEST 4 */
static int
config_dp_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, struct lyd_node **parent,
        void *private_data)
{
    const struct ly_ctx *ly_ctx;

    (void)private_data;

    ly_ctx = sr_get_context(sr_session_get_connection(session));

    assert_string_equal(module_name, "ietf-interfaces");
    assert_string_equal(xpath, "/ietf-interfaces:interfaces");
    assert_non_null(parent);
    assert_null(*parent);

    *parent = lyd_new_path(NULL, ly_ctx, "/ietf-interfaces:interfaces/interface[name='eth5']/type",
            "iana-if-type:ethernetCsmacd", 0, 0);
    assert_non_null(*parent);

    return SR_ERR_OK;
}

static void
test_config(void **state)
{
    struct state *st = (struct state *)*state;
    struct ly_set *subtrees;
    sr_subscription_ctx_t *subscr;
    char *str1;
    const char *str2;
    int ret;

    /* set some configuration data */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth2']/type",
            "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to all configuration data just to enable them */
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces", enabled_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe as config data provider and listen */
    ret = sr_dp_get_items_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces", config_dp_cb,
            NULL, SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* read all data from operational */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_subtrees(st->sess, "/ietf-interfaces:*", &subtrees);
    assert_int_equal(subtrees->number, 2);

    /* print first subtree */
    ret = lyd_print_mem(&str1, subtrees->set.d[0], LYD_XML, LYP_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    lyd_free_withsiblings(subtrees->set.d[0]);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth5</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str1, str2);
    free(str1);

    /* check second subtree */
    assert_string_equal(subtrees->set.d[1]->schema->name, "interfaces-state");
    assert_int_equal(subtrees->set.d[1]->dflt, 1);

    lyd_free_withsiblings(subtrees->set.d[1]);

    ly_set_free(subtrees);

    sr_unsubscribe(subscr);
}

/* TEST 5 */
static int
list_dp_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, struct lyd_node **parent,
        void *private_data)
{
    struct lyd_node *node;

    (void)session;
    (void)private_data;

    assert_string_equal(module_name, "ietf-interfaces");
    assert_non_null(parent);
    assert_non_null(*parent);

    if (!strcmp(xpath, "/ietf-interfaces:interfaces/interface[name='eth2']")) {
        node = lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces/interface[name='eth2']/type",
                "iana-if-type:ethernetCsmacd", 0, 0);
        assert_non_null(node);
    } else if (!strcmp(xpath, "/ietf-interfaces:interfaces/interface[name='eth3']")) {
        node = lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces/interface[name='eth3']/type",
                "iana-if-type:ethernetCsmacd", 0, 0);
        assert_non_null(node);
    } else {
        fail();
    }

    return SR_ERR_OK;
}

static void
test_list(void **state)
{
    struct state *st = (struct state *)*state;
    struct ly_set *subtrees;
    sr_subscription_ctx_t *subscr;
    char *str1;
    const char *str2;
    int ret;

    /* set some configuration data */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to all configuration data just to enable them */
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces", enabled_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe as 2 list instances data provider and listen */
    ret = sr_dp_get_items_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface[name='eth2']",
            list_dp_cb, NULL, SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_dp_get_items_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface[name='eth3']",
            list_dp_cb, NULL, SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* read all data from operational */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_subtrees(st->sess, "/ietf-interfaces:*", &subtrees);
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
        "<interface>"
            "<name>eth2</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
        "<interface>"
            "<name>eth3</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str1, str2);
    free(str1);

    /* check second subtree */
    assert_string_equal(subtrees->set.d[1]->schema->name, "interfaces-state");
    assert_int_equal(subtrees->set.d[1]->dflt, 1);

    lyd_free_withsiblings(subtrees->set.d[1]);

    ly_set_free(subtrees);

    sr_unsubscribe(subscr);
}

/* TEST 6 */
static int
nested_dp_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, struct lyd_node **parent,
        void *private_data)
{
    const struct ly_ctx *ly_ctx;
    struct lyd_node *node;

    (void)private_data;

    ly_ctx = sr_get_context(sr_session_get_connection(session));

    assert_string_equal(module_name, "ietf-interfaces");
    assert_non_null(parent);

    if (!strcmp(xpath, "/ietf-interfaces:interfaces-state/interface[name='eth2']/phys-address")) {
        assert_non_null(*parent);

        node = lyd_new_path(*parent, NULL, "phys-address",
                "01:23:45:67:89:ab", 0, 0);
        assert_non_null(node);
    } else if (!strcmp(xpath, "/ietf-interfaces:interfaces-state")) {
        assert_null(*parent);

        node = lyd_new_path(NULL, ly_ctx, "/ietf-interfaces:interfaces-state/interface[name='eth2']/type",
                "iana-if-type:ethernetCsmacd", 0, 0);
        assert_non_null(node);
        *parent = node;

        node = lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth2']/oper-status",
                "testing", 0, 0);
        assert_non_null(node);

        node = lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth2']/statistics/discontinuity-time",
                "2000-01-01T00:00:00Z", 0, 0);
        assert_non_null(node);

        node = lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth3']/type",
                "iana-if-type:ethernetCsmacd", 0, 0);
        assert_non_null(node);

        node = lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth3']/oper-status",
                "dormant", 0, 0);
        assert_non_null(node);

        node = lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth3']/statistics/discontinuity-time",
                "2005-01-01T00:00:00Z", 0, 0);
        assert_non_null(node);
    } else {
        fail();
    }

    return SR_ERR_OK;
}

static void
test_nested(void **state)
{
    struct state *st = (struct state *)*state;
    struct ly_set *subtrees;
    sr_subscription_ctx_t *subscr;
    char *str1;
    const char *str2;
    int ret;

    /* set some configuration data */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to all configuration data just to enable them */
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces", enabled_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe as state data provider and listen, it should be called only 2x */
    ret = sr_dp_get_items_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state/interface[name='eth4']/phys-address",
            nested_dp_cb, NULL, SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_dp_get_items_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state",
            nested_dp_cb, NULL, SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_dp_get_items_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state/interface[name='eth2']/phys-address",
            nested_dp_cb, NULL, SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* read all data from operational */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_subtrees(st->sess, "/ietf-interfaces:*", &subtrees);
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
            "<name>eth2</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<oper-status>testing</oper-status>"
            "<statistics>"
                "<discontinuity-time>2000-01-01T00:00:00Z</discontinuity-time>"
            "</statistics>"
            "<phys-address>01:23:45:67:89:ab</phys-address>"
        "</interface>"
        "<interface>"
            "<name>eth3</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<oper-status>dormant</oper-status>"
            "<statistics>"
                "<discontinuity-time>2005-01-01T00:00:00Z</discontinuity-time>"
            "</statistics>"
        "</interface>"
    "</interfaces-state>";

    assert_string_equal(str1, str2);
    free(str1);

    ly_set_free(subtrees);

    sr_unsubscribe(subscr);
}

/* TEST 7 */
static int
mixed_dp_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, struct lyd_node **parent,
        void *private_data)
{
    const struct ly_ctx *ly_ctx;
    struct lyd_node *node;

    (void)private_data;

    ly_ctx = sr_get_context(sr_session_get_connection(session));

    assert_string_equal(module_name, "ietf-interfaces");
    assert_string_equal(xpath, "/ietf-interfaces:*");
    assert_non_null(parent);
    assert_null(*parent);

    /* config */
    *parent = lyd_new_path(NULL, ly_ctx, "/ietf-interfaces:interfaces/interface[name='eth10']/type",
            "iana-if-type:ethernetCsmacd", 0, 0);
    assert_non_null(*parent);

    /* state */
    node = lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth11']/type",
            "iana-if-type:ethernetCsmacd", 0, 0);
    assert_non_null(node);

    node = lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth11']/oper-status",
            "down", 0, 0);
    assert_non_null(node);

    node = lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth11']/statistics/discontinuity-time",
            "2000-01-01T00:00:00Z", 0, 0);
    assert_non_null(node);

    return SR_ERR_OK;
}

static void
test_mixed(void **state)
{
    struct state *st = (struct state *)*state;
    struct ly_set *subtrees;
    sr_subscription_ctx_t *subscr;
    char *str1;
    const char *str2;
    int ret;

    /* set some configuration data */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to all configuration data just to enable them */
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces", enabled_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe as config data provider and listen */
    ret = sr_dp_get_items_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:*", mixed_dp_cb,
            NULL, SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* read all data from operational */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_subtrees(st->sess, "/ietf-interfaces:*", &subtrees);
    assert_int_equal(subtrees->number, 2);

    /* print first subtree */
    ret = lyd_print_mem(&str1, subtrees->set.d[0], LYD_XML, LYP_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    lyd_free_withsiblings(subtrees->set.d[0]);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth10</name>"
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
            "<name>eth11</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<oper-status>down</oper-status>"
            "<statistics>"
                "<discontinuity-time>2000-01-01T00:00:00Z</discontinuity-time>"
            "</statistics>"
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
        cmocka_unit_test_teardown(test_fail, clear_interfaces),
        cmocka_unit_test_teardown(test_config, clear_interfaces),
        cmocka_unit_test_teardown(test_list, clear_interfaces),
        cmocka_unit_test_teardown(test_nested, clear_interfaces),
        cmocka_unit_test_teardown(test_mixed, clear_interfaces),
    };

    sr_log_stderr(SR_LL_INF);
    return cmocka_run_group_tests(tests, setup, teardown);
}
