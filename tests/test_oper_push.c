/**
 * @file test_oper_push.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test for stored data in operational datastore behavior
 *
 * @copyright
 * Copyright (c) 2018 - 2022 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2022 CESNET, z.s.p.o.
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

    sr_discard_oper_changes(st->conn, NULL, NULL, 0);

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

    /* resd the data again */
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

    /* set nested oper data owned by another connection */
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

    /* set same oper data owned by another connection */
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
static void
test_delete(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data = NULL;
    int ret;
    sr_conn_ctx_t *conn = NULL;

    ret = sr_connect(0, &conn);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_session_start(st->conn, SR_DS_OPERATIONAL, &st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* create an interface */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/enabled",
            "false", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* deliberate redundant create of an interface */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/type",
            "ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/oper-status",
            "up", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/admin-status",
            "up", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/speed", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/last-change", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check get */
    ret = sr_get_data(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/type", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    sr_release_data(data);
    data = NULL;

    /* create the interface again */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']",
            NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/enabled",
            "false", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/type",
            "ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/speed", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check get */
    ret = sr_get_data(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/type", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    sr_release_data(data);
    data = NULL;

    /* cleanup */
    sr_disconnect(conn);
}

/* TEST */
static void
test_delete2(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data = NULL;
    int ret;
    sr_conn_ctx_t *conn = NULL;

    ret = sr_connect(0, &conn);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_session_start(st->conn, SR_DS_OPERATIONAL, &st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* create an interface without speed */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/type",
            "ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/speed", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* create speed */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/speed",
            "0", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check get */
    ret = sr_get_data(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/type", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    sr_release_data(data);
    data = NULL;

    /* delete speed again */
    ret = sr_delete_item(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/speed", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* cleanup */
    sr_disconnect(conn);
}

/* TEST */
static void
test_create_delete(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data = NULL;
    int i, ret;
    sr_conn_ctx_t *conn = NULL;

    ret = sr_connect(0, &conn);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_session_start(st->conn, SR_DS_OPERATIONAL, &st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    for (i = 0; i < 2; i++) {
        /* create the interface */
        ret = sr_set_item_str(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']",
                NULL, NULL, 0);
        assert_int_equal(ret, SR_ERR_OK);
        ret = sr_set_item_str(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/enabled",
                "false", NULL, 0);
        assert_int_equal(ret, SR_ERR_OK);
        ret = sr_set_item_str(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/type",
                "ethernetCsmacd", NULL, 0);
        assert_int_equal(ret, SR_ERR_OK);
        ret = sr_set_item_str(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/oper-status",
                "up", NULL, 0);
        assert_int_equal(ret, SR_ERR_OK);
        ret = sr_set_item_str(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/admin-status",
                "up", NULL, 0);
        assert_int_equal(ret, SR_ERR_OK);

        /* with some nodes to delete */
        ret = sr_delete_item(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/speed", 0);
        assert_int_equal(ret, SR_ERR_OK);
        ret = sr_delete_item(st->sess, "/ietf-interfaces-new:interfaces/interface[name=\'mixed\']/statistics/in-octets", 0);
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_apply_changes(st->sess, 0);
        assert_int_equal(ret, SR_ERR_OK);

        /* check data */
        ret = sr_get_data(st->sess, "/ietf-interfaces-new:*", 0, 0, 0, &data);
        assert_int_equal(ret, SR_ERR_OK);
        sr_release_data(data);
        data = NULL;
    }

    sr_disconnect(conn);
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

        /* 1st change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "l1");
        assert_null(prev_value);

        /* 2nd change */
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

        /* 3rd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "ll");
        assert_string_equal(prev_value, "3");

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
        assert_string_equal(node->schema->name, "ll");

        /* no more changes */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 8:
    case 9:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 8) {
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

        /* 8th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "ll");

        /* 9th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "ll");

        /* no more changes */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 10:
    case 11:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) % 2 == 0) {
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

        /* 2nd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "ll");
        assert_string_equal(prev_value, "");

        /* 3rd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "ll");
        assert_string_equal(prev_value, "1");

        /* 4th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "ll");
        assert_string_equal(prev_value, "2");

        /* 5th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "ll");
        assert_string_equal(prev_value, "3");

        /* no more changes */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 12:
    case 13:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) % 2 == 0) {
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
        assert_string_equal(node->schema->name, "ll");

        /* 2nd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "ll");

        /* 3rd change */
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
    ret = sr_discard_items(st->sess, "/mixed-config:test-state/l[2]/l1");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_discard_items(st->sess, "/mixed-config:test-state/ll[2]");
    assert_int_equal(ret, SR_ERR_OK);
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
    ret = sr_set_item_str(st->sess, "/mixed-config:test-state/ll", "val3", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/mixed-config:test-state/ll", "val2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/mixed-config:test-state/ll", "val3", NULL, 0);
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
            "  <ll or:origin=\"or:unknown\">val3</ll>\n"
            "  <ll or:origin=\"or:unknown\">val2</ll>\n"
            "  <ll or:origin=\"or:unknown\">val3</ll>\n"
            "</test-state>\n";
    assert_string_equal(str1, str2);
    free(str1);

    /* add some oper data actually removing previously set value */
    ret = sr_delete_item(st->sess, "/mixed-config:test-state/ll[2]", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* callback called */
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 8);

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
    ret = sr_discard_items(st->sess, "/mixed-config:test-state");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* callback called */
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 10);

    /* read the data */
    ret = sr_get_data(st->sess, "/mixed-config:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);
    assert_null(str1);

    /* create only leaf-lists */
    ret = sr_set_item_str(st->sess, "/mixed-config:test-state/ll", "val1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/mixed-config:test-state/ll", "val2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/mixed-config:test-state/ll", "val1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/mixed-config:test-state/ll", "val2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* callback called */
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 12);

    /* discard 3 leaf-lists */
    ret = sr_discard_items(st->sess, "/mixed-config:test-state/ll[4]");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_discard_items(st->sess, "/mixed-config:test-state/ll[3]");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_discard_items(st->sess, "/mixed-config:test-state/ll[2]");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* callback called */
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 14);

    /* read the data */
    ret = sr_get_data(st->sess, "/mixed-config:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);
    str2 =
            "<test-state xmlns=\"urn:sysrepo:mixed-config\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\""
            " or:origin=\"or:intended\">\n"
            "  <ll or:origin=\"or:unknown\">val1</ll>\n"
            "</test-state>\n";
    assert_string_equal(str1, str2);
    free(str1);

    /* invalid predicate type */
    ret = sr_delete_item(st->sess, "/mixed-config:test-state/ll[.='val3']", 0);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    sr_unsubscribe(subscr);
}

/* TEST */
static void
test_state_list2(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    char *str1;
    const char *str2;
    int ret;

    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* set oper data */
    ret = sr_set_item_str(st->sess, "/alarms:active-alarm-list/active-alarms[1]/fault-id", "1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/alarms:active-alarm-list/active-alarms[1]/fault-source", "fm", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/alarms:active-alarm-list/active-alarms[1]/affected-objects[name='obj']",
            NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/alarms:active-alarm-list/active-alarms[1]/fault-severity", "MAJOR", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/alarms:active-alarm-list/active-alarms[1]/is-cleared", "false", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/alarms:active-alarm-list/active-alarms[1]/event-time",
            "2023-05-17T13:18:21-00:00", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/alarms:active-alarm-list/active-alarms[2]/fault-id", "4", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/alarms:active-alarm-list/active-alarms[2]/fault-source", "fan", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/alarms:active-alarm-list/active-alarms[2]/affected-objects[name='obj2']",
            NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/alarms:active-alarm-list/active-alarms[2]/fault-severity", "CRITICAL", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/alarms:active-alarm-list/active-alarms[2]/is-cleared", "false", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/alarms:active-alarm-list/active-alarms[2]/event-time",
            "2023-05-18T20:08:55-00:00", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the operational data #1 */
    ret = sr_get_data(st->sess, "/alarms:active-alarm-list", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<active-alarm-list xmlns=\"urn:alarms\">\n"
            "  <active-alarms>\n"
            "    <fault-id>1</fault-id>\n"
            "    <fault-source>fm</fault-source>\n"
            "    <affected-objects>\n"
            "      <name>obj</name>\n"
            "    </affected-objects>\n"
            "    <fault-severity>MAJOR</fault-severity>\n"
            "    <is-cleared>false</is-cleared>\n"
            "    <event-time>2023-05-17T13:18:21-00:00</event-time>\n"
            "  </active-alarms>\n"
            "  <active-alarms>\n"
            "    <fault-id>4</fault-id>\n"
            "    <fault-source>fan</fault-source>\n"
            "    <affected-objects>\n"
            "      <name>obj2</name>\n"
            "    </affected-objects>\n"
            "    <fault-severity>CRITICAL</fault-severity>\n"
            "    <is-cleared>false</is-cleared>\n"
            "    <event-time>2023-05-18T20:08:55-00:00</event-time>\n"
            "  </active-alarms>\n"
            "</active-alarm-list>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* modify existing list instance */
    ret = sr_set_item_str(st->sess, "/alarms:active-alarm-list/active-alarms[1]/fault-id", "2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/alarms:active-alarm-list/active-alarms[1]/fault-source", "fm2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the operational data #2 */
    ret = sr_get_data(st->sess, "/alarms:active-alarm-list", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<active-alarm-list xmlns=\"urn:alarms\">\n"
            "  <active-alarms>\n"
            "    <fault-id>2</fault-id>\n"
            "    <fault-source>fm2</fault-source>\n"
            "    <affected-objects>\n"
            "      <name>obj</name>\n"
            "    </affected-objects>\n"
            "    <fault-severity>MAJOR</fault-severity>\n"
            "    <is-cleared>false</is-cleared>\n"
            "    <event-time>2023-05-17T13:18:21-00:00</event-time>\n"
            "  </active-alarms>\n"
            "  <active-alarms>\n"
            "    <fault-id>4</fault-id>\n"
            "    <fault-source>fan</fault-source>\n"
            "    <affected-objects>\n"
            "      <name>obj2</name>\n"
            "    </affected-objects>\n"
            "    <fault-severity>CRITICAL</fault-severity>\n"
            "    <is-cleared>false</is-cleared>\n"
            "    <event-time>2023-05-18T20:08:55-00:00</event-time>\n"
            "  </active-alarms>\n"
            "</active-alarm-list>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* add another list instance */
    ret = sr_set_item_str(st->sess, "/alarms:active-alarm-list/active-alarms[3]/fault-id", "9", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/alarms:active-alarm-list/active-alarms[3]/fault-source", "fm", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/alarms:active-alarm-list/active-alarms[3]/affected-objects[name='obj3']",
            NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/alarms:active-alarm-list/active-alarms[3]/fault-severity", "MINOR", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/alarms:active-alarm-list/active-alarms[3]/is-cleared", "false", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/alarms:active-alarm-list/active-alarms[3]/event-time",
            "2023-05-20T01:17:35-00:00", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the operational data #3 */
    ret = sr_get_data(st->sess, "/alarms:active-alarm-list", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<active-alarm-list xmlns=\"urn:alarms\">\n"
            "  <active-alarms>\n"
            "    <fault-id>2</fault-id>\n"
            "    <fault-source>fm2</fault-source>\n"
            "    <affected-objects>\n"
            "      <name>obj</name>\n"
            "    </affected-objects>\n"
            "    <fault-severity>MAJOR</fault-severity>\n"
            "    <is-cleared>false</is-cleared>\n"
            "    <event-time>2023-05-17T13:18:21-00:00</event-time>\n"
            "  </active-alarms>\n"
            "  <active-alarms>\n"
            "    <fault-id>4</fault-id>\n"
            "    <fault-source>fan</fault-source>\n"
            "    <affected-objects>\n"
            "      <name>obj2</name>\n"
            "    </affected-objects>\n"
            "    <fault-severity>CRITICAL</fault-severity>\n"
            "    <is-cleared>false</is-cleared>\n"
            "    <event-time>2023-05-18T20:08:55-00:00</event-time>\n"
            "  </active-alarms>\n"
            "  <active-alarms>\n"
            "    <fault-id>9</fault-id>\n"
            "    <fault-source>fm</fault-source>\n"
            "    <affected-objects>\n"
            "      <name>obj3</name>\n"
            "    </affected-objects>\n"
            "    <fault-severity>MINOR</fault-severity>\n"
            "    <is-cleared>false</is-cleared>\n"
            "    <event-time>2023-05-20T01:17:35-00:00</event-time>\n"
            "  </active-alarms>\n"
            "</active-alarm-list>\n";

    assert_string_equal(str1, str2);
    free(str1);
}

/* TEST */
static void
test_config(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr = NULL;
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
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/description",
            "oper-description", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_discard_oper_changes(st->conn, st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/enabled", 0);
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
    ret = sr_delete_item(st->sess, "/test:test-leaf", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the operational data */
    ret = sr_get_data(st->sess, "/test:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);
    assert_null(str1);

    /* discard the oper change */
    ret = sr_discard_oper_changes(st->conn, st->sess, "/test:test-leaf", 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the operational data */
    ret = sr_get_data(st->sess, "/test:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<test-leaf xmlns=\"urn:test\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\""
            " or:origin=\"or:intended\">20</test-leaf>\n";
    assert_string_equal(str1, str2);
    free(str1);

    /* cleanup */
    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
    sr_unsubscribe(subscr);
}

/* TEST */
static int
discard_change_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
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

    assert_string_equal(module_name, "ietf-interfaces");
    assert_null(xpath);

    if (ATOMIC_LOAD_RELAXED(st->cb_called) % 2 == 0) {
        assert_int_equal(event, SR_EV_CHANGE);
    } else {
        assert_int_equal(event, SR_EV_DONE);
    }

    /* get changes iter */
    ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
    assert_int_equal(ret, SR_ERR_OK);

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
    case 1:
        /* 1st change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "interfaces");
        assert_null(prev_value);

        /* 2nd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "interface");
        assert_null(prev_value);

        /* 3rd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "name");
        assert_string_equal(lyd_get_value(node), "eth1");
        assert_null(prev_value);

        /* 4th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "description");
        assert_null(prev_value);

        /* 5th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "type");
        assert_null(prev_value);

        /* 6th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "interface");
        assert_null(prev_value);

        /* 7th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "name");
        assert_string_equal(lyd_get_value(node), "eth2");
        assert_null(prev_value);

        /* 8th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "type");
        assert_null(prev_value);

        /* 9th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "interface");
        assert_null(prev_value);

        /* 10th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "name");
        assert_string_equal(lyd_get_value(node), "eth3");
        assert_null(prev_value);

        /* 11th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "type");
        assert_null(prev_value);

        /* no more changes */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);
        break;
    case 2:
    case 3:
        /* 1st change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "interface");
        assert_null(prev_value);

        /* 2nd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "name");
        assert_string_equal(lyd_get_value(node), "eth1");
        assert_null(prev_value);

        /* 3rd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "description");
        assert_null(prev_value);

        /* 4th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "type");
        assert_null(prev_value);

        /* 5th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "interface");
        assert_null(prev_value);

        /* 6th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "name");
        assert_string_equal(lyd_get_value(node), "eth2");
        assert_null(prev_value);

        /* 7th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "type");
        assert_null(prev_value);

        /* 8th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "interface");
        assert_null(prev_value);

        /* 9th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "name");
        assert_string_equal(lyd_get_value(node), "eth3");
        assert_null(prev_value);

        /* 10th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "type");
        assert_null(prev_value);

        /* 11th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "interface");
        assert_null(prev_value);

        /* 12th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "name");
        assert_string_equal(lyd_get_value(node), "eth4");
        assert_null(prev_value);

        /* 13th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "type");
        assert_null(prev_value);

        /* no more changes */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);
        break;
    case 4:
    case 5:
        /* 1st change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "interfaces");
        assert_null(prev_value);

        /* 2nd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "interface");
        assert_null(prev_value);

        /* 3rd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "name");
        assert_string_equal(lyd_get_value(node), "eth4");
        assert_null(prev_value);

        /* 4th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_string_equal(node->schema->name, "type");
        assert_null(prev_value);

        /* no more changes */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_value, NULL, NULL);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);
        break;
    default:
        fail();
    }

    sr_free_change_iter(iter);
    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void
test_discard(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr = NULL;
    sr_data_t *data;
    char *str1;
    const char *str2;
    int ret;

    /* switch to operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to data changes */
    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", NULL, discard_change_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* #1 create some list instances */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/description",
            "config-description", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth2']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth3']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the operational data */
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);
    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
            "  <interface>\n"
            "    <name>eth1</name>\n"
            "    <description>config-description</description>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "  </interface>\n"
            "  <interface>\n"
            "    <name>eth2</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "  </interface>\n"
            "  <interface>\n"
            "    <name>eth3</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "  </interface>\n"
            "</interfaces>\n";
    assert_string_equal(str1, str2);
    free(str1);

    /* #2 discard list instances and create a new one */
    ret = sr_discard_items(st->sess, "/ietf-interfaces:interfaces/interface");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth4']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the operational data */
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);
    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
            "  <interface>\n"
            "    <name>eth4</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "  </interface>\n"
            "</interfaces>\n";
    assert_string_equal(str1, str2);
    free(str1);

    /* #3 discard everything */
    ret = sr_discard_items(st->sess, NULL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the operational data */
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);
    assert_null(str1);

    /* cleanup */
    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
    sr_unsubscribe(subscr);
}

/* TEST */
static int
stored_edit_ether_diff_remove_change_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name,
        const char *xpath, sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    int ret;

    (void)sub_id;
    (void)request_id;

    assert_string_equal(module_name, "mixed-config");
    assert_string_equal(xpath, "/mixed-config:test-state/test-case/a");

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
        assert_int_equal(event, SR_EV_DONE);

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/mixed-config:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/mixed-config:test-state");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/mixed-config:test-state/test-case[name='a']");

        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/mixed-config:test-state/test-case[name='a']/name");

        sr_free_val(new_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/mixed-config:test-state/test-case[name='a']/a");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 1:
        assert_int_equal(event, SR_EV_DONE);

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/mixed-config:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/mixed-config:test-state/test-case[name='a']");
        assert_null(new_val);

        sr_free_val(old_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/mixed-config:test-state/test-case[name='a']/name");
        assert_null(new_val);

        sr_free_val(old_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/mixed-config:test-state/test-case[name='a']/a");
        assert_null(new_val);

        sr_free_val(old_val);

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
test_edit_ether_diff_remove(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr = NULL;
    int ret;

    /* switch to operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    /* subscribe to all configuration data */
    ret = sr_module_change_subscribe(st->sess, "mixed-config", "/mixed-config:test-state/test-case/a",
            stored_edit_ether_diff_remove_change_cb, st, 0, SR_SUBSCR_DONE_ONLY, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 0);

    /* create a list instance */
    ret = sr_set_item_str(st->sess, "/mixed-config:test-state/test-case[name='a']/a", "vala", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 1);

    /* remove the list instance */
    ret = sr_discard_oper_changes(st->conn, st->sess, "/mixed-config:test-state/test-case[name='a']", 0);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 2);

    /* remove all stored data, there should be none for the callback */
    ret = sr_discard_oper_changes(st->conn, st->sess, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 2);

    sr_unsubscribe(subscr);
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
test_edit_merge_leaf(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    char *str1;
    const char *str2;
    int ret;

    /* switch to operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some operational data */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/description",
            "oper-description", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/enabled",
            "false", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the data */
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
            "    <type or:origin=\"or:unknown\" xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <enabled or:origin=\"or:unknown\">false</enabled>\n"
            "  </interface>\n"
            "</interfaces>\n";
    assert_string_equal(str1, str2);
    free(str1);

    /* set some other operational data, should be merged with the previous data */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/description",
            "oper-description2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the data */
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
            "  <interface>\n"
            "    <name>eth1</name>\n"
            "    <description>oper-description2</description>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <enabled>false</enabled>\n"
            "  </interface>\n"
            "</interfaces>\n";
    assert_string_equal(str1, str2);
    free(str1);

    /* remove the leaf, should be merged with the previous data */
    ret = sr_discard_oper_changes(st->conn, st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/enabled", 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the data */
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
            "    <description or:origin=\"or:unknown\">oper-description2</description>\n"
            "    <type or:origin=\"or:unknown\" xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "  </interface>\n"
            "</interfaces>\n";
    assert_string_equal(str1, str2);
    free(str1);

    /* remove the whole interface */
    ret = sr_discard_oper_changes(st->conn, st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']", 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the data */
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);
    assert_null(str1);
}

/* TEST */
static void
test_diff_merge_userord(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr = NULL;
    char *str1;
    const char *str2;
    int ret;

    /* set some running data */
    ret = sr_set_item_str(st->sess, "/test:cont/l2[k='key1']/v", "25", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:cont/l2[k='key2']/v", "26", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to all configuration data just to enable them */
    ret = sr_module_change_subscribe(st->sess, "test", "/test:cont", dummy_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* switch to operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some operational data (move list and create list) */
    ret = sr_move_item(st->sess, "/test:cont/l2[k='key2']", SR_MOVE_BEFORE, "[k='key1']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:cont/l2[k='key3']/v", "27", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the data */
    ret = sr_get_data(st->sess, "/test:cont", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<cont xmlns=\"urn:test\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">\n"
            "  <l2 or:origin=\"or:unknown\">\n"
            "    <k>key2</k>\n"
            "    <v>26</v>\n"
            "  </l2>\n"
            "  <l2>\n"
            "    <k>key1</k>\n"
            "    <v>25</v>\n"
            "  </l2>\n"
            "  <l2>\n"
            "    <k>key3</k>\n"
            "    <v or:origin=\"or:unknown\">27</v>\n"
            "  </l2>\n"
            "</cont>\n";
    assert_string_equal(str1, str2);
    free(str1);

    /* merge some operational data (merge move into move) */
    ret = sr_move_item(st->sess, "/test:cont/l2[k='key2']", SR_MOVE_AFTER, "[k='key1']", NULL, "learned", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:cont/l2[k='key2']/v", "20", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the data */
    ret = sr_get_data(st->sess, "/test:cont", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<cont xmlns=\"urn:test\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">\n"
            "  <l2>\n"
            "    <k>key1</k>\n"
            "    <v>25</v>\n"
            "  </l2>\n"
            "  <l2 or:origin=\"or:learned\">\n"
            "    <k>key2</k>\n"
            "    <v or:origin=\"or:unknown\">20</v>\n"
            "  </l2>\n"
            "  <l2>\n"
            "    <k>key3</k>\n"
            "    <v or:origin=\"or:unknown\">27</v>\n"
            "  </l2>\n"
            "</cont>\n";
    assert_string_equal(str1, str2);
    free(str1);

    /* merge some operational data (merge move into none) */
    ret = sr_move_item(st->sess, "/test:cont/l2[k='key2']", SR_MOVE_BEFORE, "[k='key1']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the data */
    ret = sr_get_data(st->sess, "/test:cont", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<cont xmlns=\"urn:test\">\n"
            "  <l2>\n"
            "    <k>key2</k>\n"
            "    <v>20</v>\n"
            "  </l2>\n"
            "  <l2>\n"
            "    <k>key1</k>\n"
            "    <v>25</v>\n"
            "  </l2>\n"
            "  <l2>\n"
            "    <k>key3</k>\n"
            "    <v>27</v>\n"
            "  </l2>\n"
            "</cont>\n";
    assert_string_equal(str1, str2);
    free(str1);

    /* merge some operational data (merge move into create) */
    ret = sr_move_item(st->sess, "/test:cont/l2[k='key3']", SR_MOVE_BEFORE, "[k='key2']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the data */
    ret = sr_get_data(st->sess, "/test:cont", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<cont xmlns=\"urn:test\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">\n"
            "  <l2 or:origin=\"or:unknown\">\n"
            "    <k>key3</k>\n"
            "    <v>27</v>\n"
            "  </l2>\n"
            "  <l2 or:origin=\"or:unknown\">\n"
            "    <k>key2</k>\n"
            "    <v>20</v>\n"
            "  </l2>\n"
            "  <l2>\n"
            "    <k>key1</k>\n"
            "    <v>25</v>\n"
            "  </l2>\n"
            "</cont>\n";
    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static void
test_purge(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr = NULL;
    char *str1;
    const char *str2;
    int ret;

    /* set some running list instances */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth0']/type", "iana-if-type:ethernetCsmacd",
            NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/type", "iana-if-type:ethernetCsmacd",
            NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to all configuration data just to enable them */
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", NULL, dummy_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* switch to operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some operational data list instances as well */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth2']/type", "iana-if-type:ethernetCsmacd",
            NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth3']/type", "iana-if-type:ethernetCsmacd",
            NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the data #1 */
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\""
            " or:origin=\"or:intended\">\n"
            "  <interface>\n"
            "    <name>eth0</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <enabled or:origin=\"or:default\">true</enabled>\n"
            "  </interface>\n"
            "  <interface>\n"
            "    <name>eth1</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <enabled or:origin=\"or:default\">true</enabled>\n"
            "  </interface>\n"
            "  <interface>\n"
            "    <name>eth2</name>\n"
            "    <type or:origin=\"or:unknown\" xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "  </interface>\n"
            "  <interface>\n"
            "    <name>eth3</name>\n"
            "    <type or:origin=\"or:unknown\" xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "  </interface>\n"
            "</interfaces>\n";
    assert_string_equal(str1, str2);
    free(str1);

    /* purge all the list instances */
    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces/interface", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the data #2 */
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);
    assert_null(str1);

    /* fail to create a new list instance */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='wlo1']/type", "iana-if-type:ethernetCsmacd",
            NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_UNSUPPORTED);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

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
            "    <description or:origin=\"or:unknown\">descr2</description>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <enabled or:origin=\"or:default\">true</enabled>\n"
            "  </interface>\n"
            "</interfaces>\n";

    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static void
test_oper_set_del_leaflist(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;
    sr_data_t *data = NULL;
    const char *xp_base = "/ietf-interfaces-new:interfaces/interface[name=\'eth0\']";
    const char *xp_attr = "/ietf-interfaces-new:interfaces/interface[name=\'eth0\']/attributes";

    /* switch to operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* unsupported */
    ret = sr_set_item_str(st->sess, xp_base, "", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(st->sess, xp_attr, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, xp_attr, "1", NULL, 0);
    assert_int_equal(ret, SR_ERR_UNSUPPORTED);
    sr_discard_changes(st->sess);

    ret = sr_set_item_str(st->sess, xp_base, "", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(st->sess, xp_attr, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, xp_base, 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    sr_release_data(data);

    ret = sr_delete_item(st->sess, xp_base, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_conn_owner1, clear_up),
        cmocka_unit_test_teardown(test_conn_owner2, clear_up),
        cmocka_unit_test_teardown(test_conn_owner_same_data, clear_up),
        cmocka_unit_test_teardown(test_delete, clear_up),
        cmocka_unit_test_teardown(test_delete2, clear_up),
        cmocka_unit_test_teardown(test_create_delete, clear_up),
        cmocka_unit_test_teardown(test_state, clear_up),
        cmocka_unit_test_teardown(test_state_list, clear_up),
        cmocka_unit_test_teardown(test_state_list2, clear_up),
        cmocka_unit_test_teardown(test_config, clear_up),
        cmocka_unit_test_teardown(test_top_list, clear_up),
        cmocka_unit_test_teardown(test_top_leaf, clear_up),
        cmocka_unit_test_teardown(test_discard, clear_up),
        cmocka_unit_test_teardown(test_edit_ether_diff_remove, clear_up),
        cmocka_unit_test_teardown(test_invalid, clear_up),
        cmocka_unit_test_teardown(test_np_cont1, clear_up),
        cmocka_unit_test_teardown(test_np_cont2, clear_up),
        cmocka_unit_test_teardown(test_edit_merge_leaf, clear_up),
        cmocka_unit_test_teardown(test_diff_merge_userord, clear_up),
        cmocka_unit_test_teardown(test_purge, clear_up),
        cmocka_unit_test_teardown(test_schema_mount, clear_up),
        cmocka_unit_test_teardown(test_change_cb, clear_up),
        cmocka_unit_test_teardown(test_oper_set_del_leaflist, clear_up),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    test_log_init();
    return cmocka_run_group_tests(tests, setup, teardown);
}
