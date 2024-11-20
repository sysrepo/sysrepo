/**
 * @file test_oper_push.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test for stored data in operational datastore behavior
 *
 * @copyright
 * Copyright (c) 2018 - 2024 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2024 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "common.h"
#include "sysrepo.h"
#include "tests/tcommon.h"

struct state {
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    ATOMIC_T cb_called;
    pthread_barrier_t barrier2;
    pthread_barrier_t barrier5;
};

static int
setup(void **state)
{
    struct state *st;
    const char *schema_paths[] = {
        TESTS_SRC_DIR "/files/test.yang",
        TESTS_SRC_DIR "/files/ietf-interfaces.yang",
        TESTS_SRC_DIR "/files/iana-if-type.yang",
        TESTS_SRC_DIR "/files/ietf-if-aug.yang",
        TESTS_SRC_DIR "/files/ietf-interface-protection.yang",
        TESTS_SRC_DIR "/files/ietf-microwave-radio-link.yang",
        TESTS_SRC_DIR "/files/ietf-interfaces-new.yang",
        TESTS_SRC_DIR "/files/mixed-config.yang",
        TESTS_SRC_DIR "/files/defaults.yang",
        TESTS_SRC_DIR "/files/ops-ref.yang",
        TESTS_SRC_DIR "/files/ops.yang",
        TESTS_SRC_DIR "/files/czechlight-roadm-device@2019-09-30.yang",
        TESTS_SRC_DIR "/files/oper-group-test.yang",
        TESTS_SRC_DIR "/files/sm.yang",
        TESTS_SRC_DIR "/files/alarms.yang",
        TESTS_SRC_DIR "/files/list-test.yang",
        NULL
    };
    const char *rd_feats[] = {"hw-line-9", NULL};
    const char **features[] = {
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        rd_feats,
        NULL,
        NULL,
        NULL,
        NULL
    };

    st = calloc(1, sizeof *st);
    *state = st;

    if (sr_connect(0, &st->conn) != SR_ERR_OK) {
        return 1;
    }

    if (sr_install_modules(st->conn, schema_paths, TESTS_SRC_DIR "/files", features) != SR_ERR_OK) {
        return 1;
    }

    if (sr_session_start(st->conn, SR_DS_RUNNING, &st->sess) != SR_ERR_OK) {
        return 1;
    }

    ATOMIC_STORE_RELAXED(st->cb_called, 0);

    pthread_barrier_init(&st->barrier2, NULL, 2);
    pthread_barrier_init(&st->barrier5, NULL, 5);

    return 0;
}

static int
teardown(void **state)
{
    struct state *st = (struct state *)*state;
    const char *module_names[] = {
        "list-test",
        "alarms",
        "sm",
        "oper-group-test",
        "czechlight-roadm-device",
        "ops",
        "ops-ref",
        "defaults",
        "mixed-config",
        "ietf-interfaces-new",
        "ietf-microwave-radio-link",
        "ietf-interface-protection",
        "ietf-if-aug",
        "iana-if-type",
        "ietf-interfaces",
        "test",
        NULL
    };

    sr_remove_modules(st->conn, module_names, 0);

    sr_disconnect(st->conn);
    pthread_barrier_destroy(&st->barrier2);
    pthread_barrier_destroy(&st->barrier5);
    free(st);
    return 0;
}

static int
clear_up(void **state)
{
    struct state *st = (struct state *)*state;

    sr_discard_oper_changes(NULL, st->sess, NULL, 0);

    sr_session_switch_ds(st->sess, SR_DS_STARTUP);
    sr_delete_item(st->sess, "/ietf-interfaces:interfaces", 0);
    sr_delete_item(st->sess, "/test:cont", 0);
    sr_apply_changes(st->sess, 0);

    sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    sr_delete_item(st->sess, "/ietf-interfaces:interfaces", 0);
    sr_delete_item(st->sess, "/test:cont", 0);
    sr_delete_item(st->sess, "/mixed-config:test-state", 0);
    sr_delete_item(st->sess, "/czechlight-roadm-device:channel-plan", 0);
    sr_delete_item(st->sess, "/czechlight-roadm-device:media-channels", 0);
    sr_apply_changes(st->sess, 0);

    return 0;
}

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

/* TEST */
static void
test_conn_owner1(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    char *str1;
    const char *str2;
    int ret;

    /* create another connection and session */
    ret = sr_connect(0, &conn);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_session_start(conn, SR_DS_OPERATIONAL, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some operational data */
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces-state/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the data */
    ret = sr_get_data(sess, "/ietf-interfaces:interfaces-state", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
            " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">\n"
            "  <interface>\n"
            "    <name>eth1</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "  </interface>\n"
            "</interfaces-state>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* disconnect, operational data should be removed */
    sr_disconnect(conn);

    /* read the data again */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces-state", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_true(data->tree->flags & LYD_DEFAULT);

    sr_release_data(data);
}

/* TEST */
static void
test_conn_owner2(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    char *str1;
    const char *str2;
    int ret;

    /* create another connection and session */
    ret = sr_connect(0, &conn);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_session_start(conn, SR_DS_OPERATIONAL, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some operational data */
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces-state/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces-state/interface[name='eth1']/oper-status",
            "up", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces-state/interface[name='eth1']/speed",
            "1024", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the data */
    ret = sr_get_data(sess, "/ietf-interfaces:interfaces-state", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
            " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">\n"
            "  <interface>\n"
            "    <name>eth1</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <oper-status>up</oper-status>\n"
            "    <speed>1024</speed>\n"
            "  </interface>\n"
            "</interfaces-state>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* set oper data owned by another session */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces-state/interface[name='eth1']/statistics/discontinuity-time",
            "2019-10-29T09:43:12-00:00", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the data */
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces-state", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
            "  <interface>\n"
            "    <name>eth1</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <oper-status>up</oper-status>\n"
            "    <speed>1024</speed>\n"
            "    <statistics>\n"
            "      <discontinuity-time>2019-10-29T09:43:12-00:00</discontinuity-time>\n"
            "    </statistics>\n"
            "  </interface>\n"
            "</interfaces-state>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* disconnect, some operational data should be removed */
    sr_disconnect(conn);

    /* read the data again */
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces-state", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
            " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">\n"
            "  <interface>\n"
            "    <name>eth1</name>\n"
            "    <statistics>\n"
            "      <discontinuity-time>2019-10-29T09:43:12-00:00</discontinuity-time>\n"
            "    </statistics>\n"
            "  </interface>\n"
            "</interfaces-state>\n";

    assert_string_equal(str1, str2);
    free(str1);
}

/* TEST */
static void
test_conn_owner_same_data(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    char *str1;
    const char *str2;
    int ret;

    /* create another connection and session */
    ret = sr_connect(0, &conn);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_session_start(conn, SR_DS_OPERATIONAL, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some operational data */
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces-state/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces-state/interface[name='eth1']/oper-status",
            "up", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces-state/interface[name='eth1']/speed",
            "1024", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the data */
    ret = sr_get_data(sess, "/ietf-interfaces:interfaces-state", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
            " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">\n"
            "  <interface>\n"
            "    <name>eth1</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <oper-status>up</oper-status>\n"
            "    <speed>1024</speed>\n"
            "  </interface>\n"
            "</interfaces-state>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* set same oper data owned by another session */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces-state/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces-state/interface[name='eth1']/oper-status",
            "up", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces-state/interface[name='eth1']/speed",
            "1024", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* disconnect, no operational data should actually be removed */
    sr_disconnect(conn);

    /* read the data */
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces-state", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
            " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">\n"
            "  <interface>\n"
            "    <name>eth1</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <oper-status>up</oper-status>\n"
            "    <speed>1024</speed>\n"
            "  </interface>\n"
            "</interfaces-state>\n";
    assert_string_equal(str1, str2);
    free(str1);
}

/* TEST */
static int
state_change_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    int ret;

    (void)sub_id;
    (void)request_id;

    assert_string_equal(module_name, "ietf-interfaces");
    assert_string_equal(xpath, "/ietf-interfaces:interfaces-state");

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
    case 1:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 0) {
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
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces-state");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces-state/interface[name='eth1']");

        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces-state/interface[name='eth1']/name");

        sr_free_val(new_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces-state/interface[name='eth1']/type");
        assert_string_equal(new_val->data.string_val, "iana-if-type:ethernetCsmacd");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 2:
    case 3:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 2) {
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

        assert_int_equal(op, SR_OP_MODIFIED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces-state/interface[name='eth1']/type");
        assert_string_equal(old_val->data.string_val, "iana-if-type:ethernetCsmacd");
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces-state/interface[name='eth1']/type");
        assert_string_equal(new_val->data.string_val, "iana-if-type:softwareLoopback");

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    default:
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void
test_state(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr = NULL;
    char *str1;
    const char *str2;
    int ret;

    /* switch to operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to operational data changes */
    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state",
            state_change_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some operational data */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces-state/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* callback was called */
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 2);

    /* read the data */
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces-state", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);
    str2 =
            "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
            " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">\n"
            "  <interface>\n"
            "    <name>eth1</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "  </interface>\n"
            "</interfaces-state>\n";
    assert_string_equal(str1, str2);
    free(str1);

    /* change operational data */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces-state/interface[name='eth1']/type",
            "iana-if-type:softwareLoopback", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* callback was called */
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 4);

    /* read the data */
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces-state", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);
    str2 =
            "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
            " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">\n"
            "  <interface>\n"
            "    <name>eth1</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:softwareLoopback</type>\n"
            "  </interface>\n"
            "</interfaces-state>\n";
    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
stored_state_list_change_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    const struct lyd_node *node;
    const char *prev_value;
    int ret;

    (void)sub_id;
    (void)request_id;

    assert_string_equal(module_name, "mixed-config");
    assert_null(xpath);

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
    case 1:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 0) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/mixed-config:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "test-state");
        assert_null(prev_value);

        /* 2nd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "l");
        assert_string_equal(prev_value, "");

        /* 3rd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "l1");
        assert_null(prev_value);

        /* 4th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "l");
        assert_string_equal(prev_value, "1");

        /* 5th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "l1");
        assert_null(prev_value);

        /* 6th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "ll");
        assert_string_equal(prev_value, "");

        /* 7th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "ll");
        assert_string_equal(prev_value, "1");

        /* no more changes */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 2:
    case 3:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 2) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/mixed-config:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* list inst deleted */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "l");
        assert_null(prev_value);

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "l1");
        assert_null(prev_value);

        /* list inst created */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "l");
        assert_string_equal(prev_value, "1");

        /* leaf-list inst deleted */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "ll");
        assert_null(prev_value);

        /* no more changes */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 4:
    case 5:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 4) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/mixed-config:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "ll");
        assert_string_equal(prev_value, "1");

        /* 2nd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "ll");
        assert_string_equal(prev_value, "2");

        /* no more changes */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 6:
    case 7:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 6) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/mixed-config:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "test-state");

        /* 2nd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "l");

        /* 3rd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "l1");

        /* 4th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "l");

        /* 5th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "ll");

        /* 6th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "ll");

        /* 7th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "ll");

        /* no more changes */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    default:
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void
test_state_list(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr = NULL;
    char *str1;
    const char *str2;
    int ret;
    struct lyd_node *node;

    /* switch to operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to operational data changes */
    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_module_change_subscribe(st->sess, "mixed-config", NULL, stored_state_list_change_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some operational data */
    ret = sr_set_item_str(st->sess, "/mixed-config:test-state/l[1]/l1", "val1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/mixed-config:test-state/l[2]/l1", "val2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/mixed-config:test-state/ll", "val1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/mixed-config:test-state/ll", "val2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* callback called */
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 2);

    /* read the data */
    ret = sr_get_data(st->sess, "/mixed-config:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);
    str2 =
            "<test-state xmlns=\"urn:sysrepo:mixed-config\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\""
            " or:origin=\"or:intended\">\n"
            "  <l or:origin=\"or:unknown\">\n"
            "    <l1>val1</l1>\n"
            "  </l>\n"
            "  <l or:origin=\"or:unknown\">\n"
            "    <l1>val2</l1>\n"
            "  </l>\n"
            "  <ll or:origin=\"or:unknown\">val1</ll>\n"
            "  <ll or:origin=\"or:unknown\">val2</ll>\n"
            "</test-state>\n";
    assert_string_equal(str1, str2);
    free(str1);

    /* remove some oper data */
    ret = sr_get_oper_changes(st->sess, NULL, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_find_path(data->tree, "/mixed-config:test-state/l[2]/l1", 0, &node);
    assert_int_equal(ret, LY_SUCCESS);
    lyd_free_tree(node);
    ret = lyd_find_path(data->tree, "/mixed-config:test-state/ll[2]", 0, &node);
    assert_int_equal(ret, LY_SUCCESS);
    lyd_free_tree(node);
    ret = sr_edit_batch(st->sess, data->tree, "replace");
    assert_int_equal(ret, SR_ERR_OK);
    sr_release_data(data);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* callback called */
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 4);

    /* read the data */
    ret = sr_get_data(st->sess, "/mixed-config:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);
    str2 =
            "<test-state xmlns=\"urn:sysrepo:mixed-config\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\""
            " or:origin=\"or:intended\">\n"
            "  <l or:origin=\"or:unknown\">\n"
            "    <l1>val1</l1>\n"
            "  </l>\n"
            "  <l or:origin=\"or:unknown\"/>\n"
            "  <ll or:origin=\"or:unknown\">val1</ll>\n"
            "</test-state>\n";
    assert_string_equal(str1, str2);
    free(str1);

    /* create some new oper data */
    ret = sr_get_oper_changes(st->sess, "mixed-config", &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_new_term(data->tree, NULL, "ll", "val2", 0, &node);
    assert_int_equal(ret, LY_SUCCESS);
    ret = lyd_new_meta(NULL, node, NULL, "ietf-origin:origin", "ietf-origin:unknown", 0, NULL);
    assert_int_equal(ret, LY_SUCCESS);
    ret = lyd_new_term(data->tree, NULL, "ll", "val3", 0, &node);
    assert_int_equal(ret, LY_SUCCESS);
    ret = lyd_new_meta(NULL, node, NULL, "ietf-origin:origin", "ietf-origin:unknown", 0, NULL);
    assert_int_equal(ret, LY_SUCCESS);
    ret = sr_edit_batch(st->sess, data->tree, "replace");
    sr_release_data(data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* callback called */
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 6);

    /* read the data */
    ret = sr_get_data(st->sess, "/mixed-config:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);
    str2 =
            "<test-state xmlns=\"urn:sysrepo:mixed-config\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\""
            " or:origin=\"or:intended\">\n"
            "  <l or:origin=\"or:unknown\">\n"
            "    <l1>val1</l1>\n"
            "  </l>\n"
            "  <l or:origin=\"or:unknown\"/>\n"
            "  <ll or:origin=\"or:unknown\">val1</ll>\n"
            "  <ll or:origin=\"or:unknown\">val2</ll>\n"
            "  <ll or:origin=\"or:unknown\">val3</ll>\n"
            "</test-state>\n";
    assert_string_equal(str1, str2);
    free(str1);

    /* discard everything */
    ret = sr_discard_oper_changes(NULL, st->sess, "mixed-config", 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* callback called */
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 8);

    /* read the data */
    ret = sr_get_data(st->sess, "/mixed-config:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);
    assert_null(str1);

    /* invalid operations */
    ret = sr_delete_item(st->sess, "/mixed-config:test-state/ll[.='val3']", 0);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    ret = sr_move_item(st->sess, "/mixed-config:test-state/ll[.='val3']", SR_MOVE_BEFORE, NULL, "val2", NULL, 0);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
state_leaflist_change_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    const struct lyd_node *node;
    const char *prev_value;
    int ret;

    (void)sub_id;
    (void)request_id;

    assert_string_equal(module_name, "alarms");
    assert_null(xpath);

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
    case 1:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) % 2 == 0) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/alarms:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "active-alarm-list");
        assert_null(prev_value);

        /* 2nd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "alarm-inventory");
        assert_null(prev_value);

        /* 1st list instance */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "alarm-type");
        assert_null(prev_value);

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "alarm-type-id");
        assert_null(prev_value);

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "alarm-type-qualifier");
        assert_null(prev_value);

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "resource");
        assert_string_equal(prev_value, "");

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "resource");
        assert_string_equal(prev_value, "1");

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "resource");
        assert_string_equal(prev_value, "2");

        /* 2nd list instance */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "alarm-type");
        assert_null(prev_value);

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "alarm-type-id");
        assert_null(prev_value);

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "alarm-type-qualifier");
        assert_null(prev_value);

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "resource");
        assert_string_equal(prev_value, "");

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "resource");
        assert_string_equal(prev_value, "1");

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "resource");
        assert_string_equal(prev_value, "2");

        /* no more changes */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 2:
    case 3:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) % 2 == 0) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/alarms:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "active-alarm-list");
        assert_null(prev_value);

        /* 2nd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "alarm-inventory");
        assert_null(prev_value);

        /* 1st list instance */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "alarm-type");
        assert_null(prev_value);

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "alarm-type-id");
        assert_null(prev_value);

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "alarm-type-qualifier");
        assert_null(prev_value);

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "resource");
        assert_null(prev_value);

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "resource");
        assert_null(prev_value);

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "resource");
        assert_null(prev_value);

        /* 2nd list instance */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "alarm-type");
        assert_null(prev_value);

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "alarm-type-id");
        assert_null(prev_value);

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "alarm-type-qualifier");
        assert_null(prev_value);

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "resource");
        assert_null(prev_value);

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "resource");
        assert_null(prev_value);

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "resource");
        assert_null(prev_value);

        /* no more changes */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    default:
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void
test_state_leaflist(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr = NULL;
    const struct ly_ctx *ctx;
    struct lyd_node *edit;
    sr_data_t *data;
    char *str1;
    const char *json, *str2;
    int ret;

    json = "{\n"
            "  \"alarms:active-alarm-list\": {\n"
            "    \"@\": {\n"
            "      \"ietf-origin:origin\": \"ietf-origin:intended\"\n"
            "    },\n"
            "    \"alarm-inventory\": {\n"
            "      \"@\": {\n"
            "        \"ietf-origin:origin\": \"ietf-origin:unknown\"\n"
            "      },\n"
            "      \"alarm-type\": [\n"
            "        {\n"
            "          \"@\": {\n"
            "            \"ietf-origin:origin\": \"ietf-origin:unknown\"\n"
            "          },\n"
            "          \"alarm-type-id\": \"sensor-high-value-alarm\",\n"
            "          \"alarm-type-qualifier\": \"\",\n"
            "          \"resource\": [\n"
            "            \"/ietf-interfaces:interfaces/interface[name='eth0']\",\n"
            "            \"/ietf-interfaces:interfaces/interface[name='eth1']\",\n"
            "            \"/ietf-interfaces:interfaces/interface[name='lo0']\"\n"
            "          ]\n"
            "        },\n"
            "        {\n"
            "          \"alarm-type-id\": \"sensor-low-value-alarm\",\n"
            "          \"alarm-type-qualifier\": \"\",\n"
            "          \"resource\": [\n"
            "            \"/ietf-interfaces:interfaces/interface[name='eth0']\",\n"
            "            \"/ietf-interfaces:interfaces/interface[name='eth1']\",\n"
            "            \"/ietf-interfaces:interfaces/interface[name='lo0']\"\n"
            "          ]\n"
            "        }\n"
            "      ]\n"
            "    }\n"
            "  }\n"
            "}\n";

    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe */
    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_module_change_subscribe(st->sess, "alarms", NULL, state_leaflist_change_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* set oper data */
    ctx = sr_acquire_context(st->conn);
    sr_release_context(st->conn);
    ret = lyd_parse_data_mem(ctx, json, LYD_JSON, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);
    ret = sr_edit_batch(st->sess, edit, "merge");
    assert_int_equal(ret, SR_ERR_OK);
    lyd_free_siblings(edit);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ATOMIC_STORE_RELAXED(st->cb_called, 2);

    /* read the operational data #1 */
    ret = sr_get_data(st->sess, "/alarms:active-alarm-list", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_JSON, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "{\n"
            "  \"alarms:active-alarm-list\": {\n"
            "    \"alarm-inventory\": {\n"
            "      \"alarm-type\": [\n"
            "        {\n"
            "          \"alarm-type-id\": \"sensor-high-value-alarm\",\n"
            "          \"alarm-type-qualifier\": \"\",\n"
            "          \"resource\": [\n"
            "            \"/ietf-interfaces:interfaces/interface[name='eth0']\",\n"
            "            \"/ietf-interfaces:interfaces/interface[name='eth1']\",\n"
            "            \"/ietf-interfaces:interfaces/interface[name='lo0']\"\n"
            "          ]\n"
            "        },\n"
            "        {\n"
            "          \"alarm-type-id\": \"sensor-low-value-alarm\",\n"
            "          \"alarm-type-qualifier\": \"\",\n"
            "          \"resource\": [\n"
            "            \"/ietf-interfaces:interfaces/interface[name='eth0']\",\n"
            "            \"/ietf-interfaces:interfaces/interface[name='eth1']\",\n"
            "            \"/ietf-interfaces:interfaces/interface[name='lo0']\"\n"
            "          ]\n"
            "        }\n"
            "      ]\n"
            "    }\n"
            "  }\n"
            "}\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* delete oper data */
    ret = sr_discard_oper_changes(NULL, st->sess, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ATOMIC_STORE_RELAXED(st->cb_called, 4);

    sr_unsubscribe(subscr);
}

/* TEST */
static void
test_config(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr = NULL;
    struct lyd_node *node;
    char *str1;
    const char *str2;
    int ret;

    /* set some configuration data */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/description",
            "config-description", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to all configuration data just to enable them */
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces", dummy_change_cb, NULL,
            0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* switch to operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /*
     * 1) store oper data changing only the default flag
     */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/enabled",
            "true", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the operational data */
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
            " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">\n"
            "  <interface>\n"
            "    <name>eth1</name>\n"
            "    <description>config-description</description>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <enabled or:origin=\"or:unknown\">true</enabled>\n"
            "  </interface>\n"
            "</interfaces>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /*
     * 2) store oper data changing the value now
     */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/enabled", "false", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the operational data */
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
            " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">\n"
            "  <interface>\n"
            "    <name>eth1</name>\n"
            "    <description>config-description</description>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <enabled or:origin=\"or:unknown\">false</enabled>\n"
            "  </interface>\n"
            "</interfaces>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /*
     * 3) overwrite running data by some operational config data
     */
    ret = sr_get_oper_changes(st->sess, NULL, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_new_path(data->tree, NULL, "/ietf-interfaces:interfaces/interface[name='eth1']/description",
            "oper-description", 0, &node);
    assert_int_equal(ret, LY_SUCCESS);
    ret = lyd_new_meta(NULL, node, NULL, "ietf-origin:origin", "ietf-origin:unknown", 0, NULL);
    assert_int_equal(ret, LY_SUCCESS);
    ret = lyd_find_path(data->tree, "/ietf-interfaces:interfaces/interface[name='eth1']/enabled", 0, &node);
    assert_int_equal(ret, LY_SUCCESS);
    lyd_free_tree(node);
    ret = sr_edit_batch(st->sess, data->tree, "replace");
    assert_int_equal(ret, SR_ERR_OK);
    sr_release_data(data);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the operational data */
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
            " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">\n"
            "  <interface>\n"
            "    <name>eth1</name>\n"
            "    <description or:origin=\"or:unknown\">oper-description</description>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <enabled or:origin=\"or:default\">true</enabled>\n"
            "  </interface>\n"
            "</interfaces>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /*
     * 4) delete the interface
     */
    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']", SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* the operational data remain */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
            " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">\n"
            "  <interface>\n"
            "    <name>eth1</name>\n"
            "    <description or:origin=\"or:unknown\">oper-description</description>\n"
            "  </interface>\n"
            "</interfaces>\n";

    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static void
test_top_list(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr = NULL;
    sr_data_t *data;
    char *str1;
    const char *str2;
    int ret;

    /* subscribe to data */
    ret = sr_module_change_subscribe(st->sess, "czechlight-roadm-device", NULL, dummy_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some configuration data */
    ret = sr_set_item_str(st->sess, "/czechlight-roadm-device:channel-plan/channel[name='13.5']/lower-frequency",
            "191325000", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/czechlight-roadm-device:channel-plan/channel[name='13.5']/upper-frequency",
            "191375000", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/czechlight-roadm-device:channel-plan/channel[name='14.0']/lower-frequency",
            "191375000", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/czechlight-roadm-device:channel-plan/channel[name='14.0']/upper-frequency",
            "191425000", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/czechlight-roadm-device:media-channels[channel='13.5']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* switch to operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/czechlight-roadm-device:media-channels[channel='13.5']/power/common-in",
            "0.1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/czechlight-roadm-device:media-channels[channel='13.5']/power/common-out",
            "0.2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the operational data */
    ret = sr_get_data(st->sess, "/czechlight-roadm-device:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<channel-plan xmlns=\"http://czechlight.cesnet.cz/yang/czechlight-roadm-device\""
            " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">\n"
            "  <channel>\n"
            "    <name>13.5</name>\n"
            "    <lower-frequency>191325000</lower-frequency>\n"
            "    <upper-frequency>191375000</upper-frequency>\n"
            "  </channel>\n"
            "  <channel>\n"
            "    <name>14.0</name>\n"
            "    <lower-frequency>191375000</lower-frequency>\n"
            "    <upper-frequency>191425000</upper-frequency>\n"
            "  </channel>\n"
            "</channel-plan>\n"
            "<media-channels xmlns=\"http://czechlight.cesnet.cz/yang/czechlight-roadm-device\""
            " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">\n"
            "  <channel>13.5</channel>\n"
            "  <power or:origin=\"or:unknown\">\n"
            "    <common-in>0.1</common-in>\n"
            "    <common-out>0.2</common-out>\n"
            "  </power>\n"
            "</media-channels>\n"
            "<line xmlns=\"http://czechlight.cesnet.cz/yang/czechlight-roadm-device\""
            " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">\n"
            "  <output-voa or:origin=\"or:default\">0.0</output-voa>\n"
            "</line>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* switch to running DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/czechlight-roadm-device:media-channels[channel='14.0']/drop/port",
            "E2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/czechlight-roadm-device:media-channels[channel='14.0']/drop/attenuation",
            "3.7", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* switch to operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/czechlight-roadm-device:media-channels[channel='13.5']/power/common-in",
            "0.9", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/czechlight-roadm-device:media-channels[channel='13.5']/power/common-out",
            "1.0", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/czechlight-roadm-device:media-channels[channel='14.0']/power/common-in",
            "1.2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/czechlight-roadm-device:media-channels[channel='14.0']/power/common-out",
            "1.3", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/czechlight-roadm-device:media-channels[channel='14.0']/power/leaf-out",
            "1.4", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* switch to running DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_delete_item(st->sess, "/czechlight-roadm-device:media-channels[channel='14.0']", SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* switch to operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the operational data */
    ret = sr_get_data(st->sess, "/czechlight-roadm-device:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<channel-plan xmlns=\"http://czechlight.cesnet.cz/yang/czechlight-roadm-device\""
            " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">\n"
            "  <channel>\n"
            "    <name>13.5</name>\n"
            "    <lower-frequency>191325000</lower-frequency>\n"
            "    <upper-frequency>191375000</upper-frequency>\n"
            "  </channel>\n"
            "  <channel>\n"
            "    <name>14.0</name>\n"
            "    <lower-frequency>191375000</lower-frequency>\n"
            "    <upper-frequency>191425000</upper-frequency>\n"
            "  </channel>\n"
            "</channel-plan>\n"
            "<media-channels xmlns=\"http://czechlight.cesnet.cz/yang/czechlight-roadm-device\""
            " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">\n"
            "  <channel>13.5</channel>\n"
            "  <power or:origin=\"or:unknown\">\n"
            "    <common-in>0.9</common-in>\n"
            "    <common-out>1.0</common-out>\n"
            "  </power>\n"
            "</media-channels>\n"
            "<media-channels xmlns=\"http://czechlight.cesnet.cz/yang/czechlight-roadm-device\""
            " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">\n"
            "  <channel>14.0</channel>\n"
            "  <power or:origin=\"or:unknown\">\n"
            "    <common-in>1.2</common-in>\n"
            "    <common-out>1.3</common-out>\n"
            "    <leaf-out>1.4</leaf-out>\n"
            "  </power>\n"
            "</media-channels>\n"
            "<line xmlns=\"http://czechlight.cesnet.cz/yang/czechlight-roadm-device\""
            " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">\n"
            "  <output-voa or:origin=\"or:default\">0.0</output-voa>\n"
            "</line>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* cleanup */
    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
    sr_unsubscribe(subscr);
}

/* TEST */
static void
test_top_leaf(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr = NULL;
    sr_data_t *data;
    char *str1;
    const char *str2;
    int ret;

    /* subscribe to data */
    ret = sr_module_change_subscribe(st->sess, "test", NULL, dummy_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some configuration data */
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "20", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* switch to operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* delete the node */
    ret = sr_discard_items(st->sess, "/test:test-leaf");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the operational data */
    ret = sr_get_data(st->sess, "/test:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);
    assert_string_equal(str1,
            "<cont xmlns=\"urn:test\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">\n"
            "  <dflt-leaf or:origin=\"or:default\">default-value</dflt-leaf>\n"
            "</cont>\n");
    free(str1);

    /* discard the oper change */
    ret = sr_discard_oper_changes(NULL, st->sess, "test", 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the operational data */
    ret = sr_get_data(st->sess, "/test:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<test-leaf xmlns=\"urn:test\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\""
            " or:origin=\"or:intended\">20</test-leaf>\n"
            "<cont xmlns=\"urn:test\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">\n"
            "  <dflt-leaf or:origin=\"or:default\">default-value</dflt-leaf>\n"
            "</cont>\n";
    assert_string_equal(str1, str2);
    free(str1);

    /* cleanup */
    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
    sr_unsubscribe(subscr);
}

/* TEST */
static void
test_discard(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_session_ctx_t *sess;
    char *str1;
    const char *str2;
    int ret;

    /* create another session */
    ret = sr_session_start(st->conn, SR_DS_OPERATIONAL, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);

    /* create an interface */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/type",
            "ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/speed",
            "0", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* on another session create more children and discard the speed */
    ret = sr_set_item_str(sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/link-up-down-trap-enable",
            "disabled", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/admin-status",
            "testing", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_discard_items(sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/speed");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the data */
    ret = sr_get_data(st->sess, "/ietf-interfaces-new:interfaces", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces-new\""
            " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">\n"
            "  <interface or:origin=\"or:unknown\">\n"
            "    <name>mixed</name>\n"
            "    <type>ethernetCsmacd</type>\n"
            "    <link-up-down-trap-enable or:origin=\"or:unknown\">disabled</link-up-down-trap-enable>\n"
            "    <admin-status or:origin=\"or:unknown\">testing</admin-status>\n"
            "  </interface>\n"
            "</interfaces>\n";
    assert_string_equal(str1, str2);
    free(str1);

    sr_session_stop(sess);
}

/* TEST */
static void
test_invalid(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;

    /* set invalid operational data */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:test-leafref", "25", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* validate */
    ret = sr_validate(st->sess, "test", 0);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    /* make stored oper data valid */
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "25", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* validate */
    ret = sr_validate(st->sess, "test", 0);
    assert_int_equal(ret, SR_ERR_OK);
}

/* TEST */
static void
test_np_cont1(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr = NULL;
    char *str1;
    const char *str2;
    int ret;

    /* set some configuration data */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth0']/description", "", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth0']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to all configuration data just to enable them */
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface",
            dummy_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* switch to operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some operational data */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-if-aug:c1/oper1", "val", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the operational data */
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
            " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">\n"
            "  <interface>\n"
            "    <name>eth0</name>\n"
            "    <description/>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <enabled or:origin=\"or:default\">true</enabled>\n"
            "    <c1 xmlns=\"urn:ietf-if-aug\" or:origin=\"or:unknown\">\n"
            "      <oper1>val</oper1>\n"
            "    </c1>\n"
            "  </interface>\n"
            "</interfaces>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* change the list instance */
    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth0']/description", "test-desc", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check operational data again */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
            " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">\n"
            "  <interface>\n"
            "    <name>eth0</name>\n"
            "    <description>test-desc</description>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <enabled or:origin=\"or:default\">true</enabled>\n"
            "    <c1 xmlns=\"urn:ietf-if-aug\" or:origin=\"or:unknown\">\n"
            "      <oper1>val</oper1>\n"
            "    </c1>\n"
            "  </interface>\n"
            "</interfaces>\n";

    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static void
test_np_cont2(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr = NULL;
    char *str1;
    const char *str2;
    int ret;

    /* set some configuration data */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth0']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to all configuration data just to enable them */
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", NULL, dummy_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some operational data */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-if-aug:c1/oper1", "val", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check operational data */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
            " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">\n"
            "  <interface>\n"
            "    <name>eth0</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <enabled or:origin=\"or:default\">true</enabled>\n"
            "    <c1 xmlns=\"urn:ietf-if-aug\" or:origin=\"or:unknown\">\n"
            "      <oper1>val</oper1>\n"
            "    </c1>\n"
            "  </interface>\n"
            "</interfaces>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* unsubscribe */
    sr_unsubscribe(subscr);
}

/* TEST */
static void
test_schema_mount(void **state)
{
    struct state *st = (struct state *)*state;
    sr_session_ctx_t *sess;
    sr_data_t *data;
    char *str1;
    const char *str2;
    int ret;

    /* switch to operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* set oper ext data */
    ret = sr_set_item_str(st->sess,
            "/ietf-yang-schema-mount:schema-mounts/mount-point[module='sm'][label='root']/shared-schema", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* create a session just to update LY ext data */
    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);
    sr_session_stop(sess);

    /* set some data */
    ret = sr_set_item_str(st->sess, "/sm:root/ietf-interfaces:interfaces/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/sm:root/ietf-interfaces:interfaces/interface[name='eth1']/description",
            "config-description", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the operational data */
    ret = sr_get_data(st->sess, "/sm:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<root xmlns=\"urn:sm\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">\n"
            "  <interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
            "    <interface>\n"
            "      <name>eth1</name>\n"
            "      <description or:origin=\"or:unknown\">config-description</description>\n"
            "      <type or:origin=\"or:unknown\" xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    </interface>\n"
            "  </interfaces>\n"
            "</root>\n";

    assert_string_equal(str1, str2);
    free(str1);
}

/* TEST */
static int
change_cb_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    sr_session_ctx_t *sess;
    char *str;
    int ret;

    (void)sub_id;
    (void)request_id;

    assert_string_equal(module_name, "ietf-interfaces");
    assert_null(xpath);

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
        assert_int_equal(event, SR_EV_CHANGE);

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth1']");

        /* store some operational data */
        ret = sr_session_start(sr_session_get_connection(session), SR_DS_OPERATIONAL, &sess);
        assert_int_equal(ret, SR_ERR_OK);
        assert_return_code(asprintf(&str, "%s/description", new_val->xpath), 0);
        ret = sr_set_item_str(sess, str, "descr1", NULL, 0);
        assert_int_equal(ret, SR_ERR_OK);
        free(str);
        ret = sr_apply_changes(sess, 0);
        assert_int_equal(ret, SR_ERR_OK);
        sr_session_stop(sess);

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth1']/name");

        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth1']/type");

        sr_free_val(new_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth1']/enabled");
        assert_int_equal(new_val->dflt, 1);

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 1:
        assert_int_equal(event, SR_EV_DONE);

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth1']");

        /* store some other operational data */
        ret = sr_session_start(sr_session_get_connection(session), SR_DS_OPERATIONAL, &sess);
        assert_int_equal(ret, SR_ERR_OK);
        assert_return_code(asprintf(&str, "%s/description", new_val->xpath), 0);
        ret = sr_set_item_str(sess, str, "descr2", NULL, 0);
        assert_int_equal(ret, SR_ERR_OK);
        free(str);
        ret = sr_apply_changes(sess, 0);
        assert_int_equal(ret, SR_ERR_OK);
        sr_session_stop(sess);

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth1']/name");

        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth1']/type");

        sr_free_val(new_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth1']/enabled");
        assert_int_equal(new_val->dflt, 1);

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    default:
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void
test_change_cb(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr = NULL;
    char *str1;
    const char *str2;
    int ret;

    /* subscribe to all configuration data */
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", NULL, change_cb_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some configuration data and trigger the callback */
    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 500000);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 2);

    /* read all data from operational */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_true(data->tree->next->flags & LYD_DEFAULT);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\""
            " or:origin=\"or:intended\">\n"
            "  <interface>\n"
            "    <name>eth1</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <enabled or:origin=\"or:default\">true</enabled>\n"
            "  </interface>\n"
            "</interfaces>\n";

    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
change_filter_change_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    const struct lyd_node *node;
    const char *prev_value;
    int ret;

    (void)sub_id;
    (void)xpath;
    (void)request_id;

    assert_string_equal(module_name, "ietf-interfaces");

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
    case 1:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) % 2 == 0) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "interfaces-state");
        assert_null(prev_value);

        /* list instance */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "interface");
        assert_null(prev_value);

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "name");
        assert_null(prev_value);

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "type");
        assert_null(prev_value);

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "oper-status");
        assert_null(prev_value);

        /* no more changes */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 2:
    case 3:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) % 2 == 0) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_MODIFIED);
        assert_string_equal(node->schema->name, "oper-status");

        /* no more changes */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    default:
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void
test_change_filter(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr = NULL;
    int ret;

    /* switch to operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to operational data changes */
    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces",
            "/ietf-interfaces:interfaces-state/interface[derived-from-or-self(type, 'iana-if-type:ethernetCsmacd')]/oper-status",
            change_filter_change_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some operational data */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces-state/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces-state/interface[name='eth1']/oper-status",
            "dormant", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* callback was called */
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 2);

    /* change the status */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces-state/interface[name='eth1']/oper-status",
            "up", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* callback was called */
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 4);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
oper_list_enabled_change_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    const struct lyd_node *node;
    const char *prev_value;
    int ret;

    (void)sub_id;
    (void)request_id;

    assert_string_equal(module_name, "mixed-config");
    assert_string_equal(xpath, "/mixed-config:test-state/ll");

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
    case 1:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) % 2 == 0) {
            assert_int_equal(event, SR_EV_ENABLED);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/mixed-config:test-state/ll//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(prev_value, "");
        assert_string_equal(node->schema->name, "ll");

        /* no more changes */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    default:
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void
test_oper_list_enabled(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr = NULL;
    int ret;

    /* switch to operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some operational data */
    ret = sr_set_item_str(st->sess, "/mixed-config:test-state/ll[1]", "a1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to operational data changes */
    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_module_change_subscribe(st->sess, "mixed-config", "/mixed-config:test-state/ll",
            oper_list_enabled_change_cb, st, 0, SR_SUBSCR_ENABLED, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ATOMIC_STORE_RELAXED(st->cb_called, 2);

    sr_unsubscribe(subscr);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_conn_owner1, clear_up),
        cmocka_unit_test_teardown(test_conn_owner2, clear_up),
        cmocka_unit_test_teardown(test_conn_owner_same_data, clear_up),
        cmocka_unit_test_teardown(test_state, clear_up),
        cmocka_unit_test_teardown(test_state_list, clear_up),
        cmocka_unit_test_teardown(test_state_leaflist, clear_up),
        cmocka_unit_test_teardown(test_config, clear_up),
        cmocka_unit_test_teardown(test_top_list, clear_up),
        cmocka_unit_test_teardown(test_top_leaf, clear_up),
        cmocka_unit_test_teardown(test_discard, clear_up),
        cmocka_unit_test_teardown(test_invalid, clear_up),
        cmocka_unit_test_teardown(test_np_cont1, clear_up),
        cmocka_unit_test_teardown(test_np_cont2, clear_up),
        cmocka_unit_test_teardown(test_schema_mount, clear_up),
        cmocka_unit_test_teardown(test_change_cb, clear_up),
        cmocka_unit_test_teardown(test_change_filter, clear_up),
        cmocka_unit_test_teardown(test_oper_list_enabled, clear_up),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    test_log_init();
    return cmocka_run_group_tests(tests, setup, teardown);
}
