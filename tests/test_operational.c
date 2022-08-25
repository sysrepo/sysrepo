/**
 * @file test_operational.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test for operational datastore behavior
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

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
    uint32_t nc_id;
    const char *act_feats[] = {"advanced-testing", NULL}, *rd_feats[] = {"hw-line-9", NULL};

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
    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/ietf-if-aug.yang", TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/ietf-interface-protection.yang", TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/ietf-microwave-radio-link.yang", TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/mixed-config.yang", TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/act.yang", TESTS_SRC_DIR "/files", act_feats) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/act2.yang", TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/act3.yang", TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/defaults.yang", TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/ops-ref.yang", TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/ops.yang", TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/czechlight-roadm-device@2019-09-30.yang", TESTS_SRC_DIR "/files",
            rd_feats) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/oper-group-test.yang", TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/sm.yang", TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }

    if (sr_session_start(st->conn, SR_DS_RUNNING, &st->sess) != SR_ERR_OK) {
        return 1;
    }

    sr_session_set_orig_name(st->sess, "test_operational");
    nc_id = 64;
    sr_session_push_orig_data(st->sess, sizeof nc_id, &nc_id);
    sr_session_push_orig_data(st->sess, 12, "test_string");

    ATOMIC_STORE_RELAXED(st->cb_called, 0);

    pthread_barrier_init(&st->barrier2, NULL, 2);
    pthread_barrier_init(&st->barrier5, NULL, 5);

    return 0;
}

static int
teardown(void **state)
{
    struct state *st = (struct state *)*state;

    sr_remove_module(st->conn, "sm", 0);
    sr_remove_module(st->conn, "oper-group-test", 0);
    sr_remove_module(st->conn, "czechlight-roadm-device", 0);
    sr_remove_module(st->conn, "ops", 0);
    sr_remove_module(st->conn, "ops-ref", 0);
    sr_remove_module(st->conn, "defaults", 0);
    sr_remove_module(st->conn, "act3", 0);
    sr_remove_module(st->conn, "act2", 0);
    sr_remove_module(st->conn, "act", 0);
    sr_remove_module(st->conn, "mixed-config", 0);
    sr_remove_module(st->conn, "ietf-microwave-radio-link", 0);
    sr_remove_module(st->conn, "ietf-interface-protection", 0);
    sr_remove_module(st->conn, "ietf-if-aug", 0);
    sr_remove_module(st->conn, "iana-if-type", 0);
    sr_remove_module(st->conn, "ietf-interfaces", 0);
    sr_remove_module(st->conn, "test", 0);

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

/**
 * @brief Delete content between two strings.
 *
 * The content between consecutive pairs of open and close will be deleted. For
 * example with open="<cid>" and close="</cid>" the string <cid>1234</cid> will
 * be replaced with <cid></cid>.
 *
 * @param[in,out] input String to be modified
 * @param[in] open String which starts the section(s) to be deleted.
 * @param[in] close String which ends the section(s) to be deleted.
 */
static void
sr_str_del(char *input, const char *open, const char *close)
{
    int idx = 0;
    int len = strlen(input);
    int segment_len = 0;
    char *open_idx = NULL;
    char *close_idx = NULL;
    char *resp = calloc(1, len + 1);

    assert_true(resp);
    for (idx = 0; idx < len; ) {
        open_idx = strstr(&input[idx], open);
        close_idx = strstr(&input[idx], close);
        if (!open_idx || !close_idx) {
            break;
        }

        segment_len = open_idx + strlen(open) - input - idx;
        strncat(resp, &input[idx], segment_len);
        strcat(resp, close);
        segment_len += strlen(close);
        resp[idx + segment_len] = 0;
        idx = close_idx - input + strlen(close);
    }

    /* pick up any remaining content */
    strncat(resp, &input[idx], len);

    /* copy the modified string to the input */
    strcpy(input, resp);
    free(resp);
}

/* TEST */
static int
yang_lib_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    (void)session;
    (void)sub_id;
    (void)module_name;
    (void)xpath;
    (void)request_xpath;
    (void)request_id;
    (void)parent;
    (void)private_data;

    return SR_ERR_OK;
}

static void
test_yang_lib(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr = NULL;
    int ret;

    /* read ietf-yang-library data */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/ietf-yang-library:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

#if SR_YANGLIB_REVISION == 2019 - 01 - 04
    assert_non_null(data);
    assert_string_equal(data->tree->schema->name, "yang-library");
    assert_string_equal(lyd_child(data->tree)->schema->name, "module-set");
    assert_string_equal(lyd_child(data->tree)->next->schema->name, "schema");
    assert_string_equal(lyd_child(data->tree)->next->next->schema->name, "datastore");
    assert_string_equal(lyd_child(data->tree)->next->next->next->schema->name, "datastore");
    assert_string_equal(lyd_child(data->tree)->next->next->next->next->schema->name, "datastore");
    assert_string_equal(lyd_child(data->tree)->next->next->next->next->next->schema->name, "datastore");
    assert_string_equal(lyd_child(data->tree)->next->next->next->next->next->next->schema->name, "content-id");
    assert_string_equal(data->tree->next->schema->name, "modules-state");
#else
    assert_non_null(data);
    assert_string_equal(data->tree->schema->name, "modules-state");
    assert_string_equal(lyd_child(data->tree)->prev->schema->name, "module-set-id");
#endif

    /* they must be valid */
    ret = lyd_validate_module(&data->tree, data->tree->schema->module, 0, NULL);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    /* subscribe as dummy state data provider, they should get deleted */
#if SR_YANGLIB_REVISION == 2019 - 01 - 04
    ret = sr_oper_get_subscribe(st->sess, "ietf-yang-library", "/ietf-yang-library:yang-library", yang_lib_oper_cb,
            NULL, 0, &subscr);
#else
    ret = sr_oper_get_subscribe(st->sess, "ietf-yang-library", "/ietf-yang-library:modules-state", yang_lib_oper_cb,
            NULL, 0, &subscr);
#endif
    assert_int_equal(ret, SR_ERR_OK);

    /* read ietf-yang-library data again */
    ret = sr_get_data(st->sess, "/ietf-yang-library:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

#if SR_YANGLIB_REVISION == 2019 - 01 - 04
    assert_non_null(data);
    assert_string_equal(data->tree->schema->name, "modules-state");
    assert_false(data->tree->flags & LYD_DEFAULT);
    assert_null(data->tree->next);
#else
    assert_null(data);
#endif
    sr_release_data(data);

    /* cleanup */
    sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    sr_unsubscribe(subscr);
}

/* TEST */
static int
dummy_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    (void)session;
    (void)sub_id;
    (void)module_name;
    (void)xpath;
    (void)request_xpath;
    (void)request_id;
    (void)parent;
    (void)private_data;

    return SR_ERR_OK;
}

static void
dummy_notif_cb(sr_session_ctx_t *session, uint32_t sub_id, const sr_ev_notif_type_t notif_type, const char *path,
        const sr_val_t *values, const size_t values_cnt, struct timespec *timestamp, void *private_data)
{
    (void)session;
    (void)sub_id;
    (void)notif_type;
    (void)path;
    (void)values;
    (void)values_cnt;
    (void)timestamp;
    (void)private_data;
}

static int
dummy_rpc_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const sr_val_t *input, const size_t input_cnt,
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
    (void)session;
    (void)sub_id;
    (void)op_path;
    (void)input;
    (void)input_cnt;
    (void)event;
    (void)request_id;
    (void)output;
    (void)output_cnt;
    (void)private_data;

    return SR_ERR_OK;
}

static void
test_sr_mon(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr = NULL;
    char *str1, *str2 = malloc(9216);
    int ret;

    /* get almost empty monitoring data */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/sysrepo-monitoring:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    /* check their content */
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    strcpy(str2, "<sysrepo-state xmlns=\"http://www.sysrepo.org/yang/sysrepo-monitoring\">"
        "<module>"
            "<name>yang</name>"
        "</module>"
        "<module>"
            "<name>ietf-yang-schema-mount</name>"
        "</module>"
        "<module>"
            "<name>ietf-datastores</name>"
        "</module>"
        "<module>"
            "<name>ietf-yang-library</name>"
        "</module>"
        "<module>"
            "<name>ietf-netconf-acm</name>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:startup</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</name>"
                "<last-modified></last-modified>"
            "</datastore>"
        "</module>"
        "<module>"
            "<name>sysrepo-monitoring</name>"
            "<data-lock>"
                "<cid></cid>"
                "<datastore xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</datastore>"
                "<mode>read</mode>"
            "</data-lock>"
            "<data-lock>"
                "<cid></cid>"
                "<datastore xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:operational</datastore>"
                "<mode>read</mode>"
            "</data-lock>"
        "</module>"
        "<module>"
            "<name>sysrepo-plugind</name>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:startup</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</name>"
                "<last-modified></last-modified>"
            "</datastore>"
        "</module>"
        "<module>"
            "<name>ietf-netconf</name>"
        "</module>"
        "<module>"
            "<name>ietf-netconf-with-defaults</name>"
        "</module>"
        "<module>"
            "<name>ietf-netconf-notifications</name>"
        "</module>"
        "<module>"
            "<name>ietf-origin</name>"
        "</module>"
        "<module>"
            "<name>test</name>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:startup</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</name>"
                "<last-modified></last-modified>"
            "</datastore>"
        "</module>"
        "<module>"
            "<name>ietf-interfaces</name>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:startup</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:operational</name>"
                "<last-modified></last-modified>"
            "</datastore>"
        "</module>"
        "<module>"
            "<name>iana-if-type</name>"
        "</module>"
        "<module>"
            "<name>ietf-if-aug</name>"
        "</module>"
        "<module>"
            "<name>ietf-interface-protection</name>"
        "</module>"
        "<module>"
            "<name>ietf-microwave-radio-link</name>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:startup</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</name>"
                "<last-modified></last-modified>"
            "</datastore>"
        "</module>"
        "<module>"
            "<name>mixed-config</name>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:startup</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</name>"
                "<last-modified></last-modified>"
            "</datastore>"
        "</module>");

    strcat(str2, "<module>"
            "<name>act</name>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:startup</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:operational</name>"
                "<last-modified></last-modified>"
            "</datastore>"
        "</module>"
        "<module>"
            "<name>act2</name>"
        "</module>"
        "<module>"
            "<name>act3</name>"
        "</module>"
        "<module>"
            "<name>defaults</name>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:startup</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</name>"
                "<last-modified></last-modified>"
            "</datastore>"
        "</module>"
        "<module>"
            "<name>ops-ref</name>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:startup</name>"
                "<last-modified></last-modified>"
            "</datastore>"
        "</module>"
        "<module>"
            "<name>ops</name>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:startup</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</name>"
                "<last-modified></last-modified>"
            "</datastore>"
        "</module>"
        "<module>"
            "<name>czechlight-roadm-device</name>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:startup</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</name>"
                "<last-modified></last-modified>"
            "</datastore>"
        "</module>"
        "<module>"
            "<name>oper-group-test</name>"
        "</module>"
        "<module>"
            "<name>sm</name>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:startup</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</name>"
                "<last-modified></last-modified>"
            "</datastore>"
        "</module>"
        "<connection>"
            "<cid></cid>"
            "<pid></pid>"
        "</connection>"
        "</sysrepo-state>");
    sr_str_del(str1, "<last-modified>","</last-modified>");
    sr_str_del(str1, "<cid>","</cid>");
    sr_str_del(str1, "<pid>","</pid>");
    assert_string_equal(str1, str2);
    free(str1);

    /* make some change subscriptions */
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces", dummy_change_cb, NULL,
            3, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(st->sess, "mixed-config", NULL, dummy_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* make some operational subscriptions */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", dummy_oper_cb,
            NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_oper_get_subscribe(st->sess, "act", "/act:basics/subbasics/act2:complex_number/imaginary_part",
            dummy_oper_cb, NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* make some notification subscriptions */
    ret = sr_notif_subscribe(st->sess, "ops", "/ops:notif4", 0, 0, dummy_notif_cb, NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_notif_subscribe(st->sess, "ops", "/ops:cont/cont3/notif2[l13='/ops:cont']", 0, 0, dummy_notif_cb,
            NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* make some RPC/action subscriptions */
    ret = sr_rpc_subscribe(st->sess, "/act:capitalize", dummy_rpc_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe(st->sess, "/act:basics/animals/convert[direction='false']", dummy_rpc_cb, NULL, 5,
            0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe(st->sess, "/act:basics/animals/convert", dummy_rpc_cb, NULL, 4, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* lock modules */
    ret = sr_lock(st->sess, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* get new monitoring data */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(st->sess, "/sysrepo-monitoring:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    /* check their content */
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    strcpy(str2, "<sysrepo-state xmlns=\"http://www.sysrepo.org/yang/sysrepo-monitoring\">"
        "<module>"
            "<name>yang</name>"
        "</module>"
        "<module>"
            "<name>ietf-yang-schema-mount</name>"
        "</module>"
        "<module>"
            "<name>ietf-datastores</name>"
        "</module>"
        "<module>"
            "<name>ietf-yang-library</name>"
        "</module>"
        "<module>"
            "<name>ietf-netconf-acm</name>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:startup</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<ds-lock>"
                "<datastore xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</datastore>"
                "<sid></sid>"
                "<timestamp></timestamp>"
            "</ds-lock>"
        "</module>"
        "<module>"
            "<name>sysrepo-monitoring</name>"
            "<data-lock>"
                "<cid></cid>"
                "<datastore xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</datastore>"
                "<mode>read</mode>"
            "</data-lock>"
            "<data-lock>"
                "<cid></cid>"
                "<datastore xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:operational</datastore>"
                "<mode>read</mode>"
            "</data-lock>"
        "</module>"
        "<module>"
            "<name>sysrepo-plugind</name>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:startup</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<ds-lock>"
                "<datastore xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</datastore>"
                "<sid></sid>"
                "<timestamp></timestamp>"
            "</ds-lock>"
        "</module>"
        "<module>"
            "<name>ietf-netconf</name>"
        "</module>"
        "<module>"
            "<name>ietf-netconf-with-defaults</name>"
        "</module>"
        "<module>"
            "<name>ietf-netconf-notifications</name>"
        "</module>"
        "<module>"
            "<name>ietf-origin</name>"
        "</module>"
        "<module>"
            "<name>test</name>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:startup</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<ds-lock>"
                "<datastore xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</datastore>"
                "<sid></sid>"
                "<timestamp></timestamp>"
            "</ds-lock>"
        "</module>"
        "<module>"
            "<name>ietf-interfaces</name>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:startup</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:operational</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<ds-lock>"
                "<datastore xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</datastore>"
                "<sid></sid>"
                "<timestamp></timestamp>"
            "</ds-lock>"
            "<subscriptions>"
                "<change-sub>"
                    "<datastore xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:operational</datastore>"
                    "<xpath xmlns:if=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">/if:interfaces</xpath>"
                    "<priority>3</priority>"
                    "<cid></cid>"
                    "<suspended>false</suspended>"
                "</change-sub>"
                "<operational-get-sub>"
                    "<xpath xmlns:if=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">/if:interfaces-state</xpath>"
                    "<xpath-sub>"
                        "<cid></cid>"
                        "<suspended>false</suspended>"
                    "</xpath-sub>"
                "</operational-get-sub>"
            "</subscriptions>"
        "</module>"
        "<module>"
            "<name>iana-if-type</name>"
        "</module>"
        "<module>"
            "<name>ietf-if-aug</name>"
        "</module>"
        "<module>"
            "<name>ietf-interface-protection</name>"
        "</module>"
        "<module>"
            "<name>ietf-microwave-radio-link</name>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:startup</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<ds-lock>"
                "<datastore xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</datastore>"
                "<sid></sid>"
                "<timestamp></timestamp>"
            "</ds-lock>"
        "</module>");

    strcat(str2, "<module>"
            "<name>mixed-config</name>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:startup</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<ds-lock>"
                "<datastore xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</datastore>"
                "<sid></sid>"
                "<timestamp></timestamp>"
            "</ds-lock>"
            "<subscriptions>"
                "<change-sub>"
                    "<datastore xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</datastore>"
                    "<priority>0</priority>"
                    "<cid></cid>"
                    "<suspended>false</suspended>"
                "</change-sub>"
            "</subscriptions>"
        "</module>"
        "<module>"
            "<name>act</name>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:startup</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:operational</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<ds-lock>"
                "<datastore xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</datastore>"
                "<sid></sid>"
                "<timestamp></timestamp>"
            "</ds-lock>"
            "<subscriptions>"
                "<operational-get-sub>"
                    "<xpath xmlns:a=\"urn:act\" xmlns:a2=\"urn:act2\">/a:basics/a:subbasics/a2:complex_number/a2:imaginary_part</xpath>"
                    "<xpath-sub>"
                        "<cid></cid>"
                        "<suspended>false</suspended>"
                    "</xpath-sub>"
                "</operational-get-sub>"
            "</subscriptions>"
        "</module>"
        "<module>"
            "<name>act2</name>"
        "</module>"
        "<module>"
            "<name>act3</name>"
        "</module>"
        "<module>"
            "<name>defaults</name>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:startup</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<ds-lock>"
                "<datastore xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</datastore>"
                "<sid></sid>"
                "<timestamp></timestamp>"
            "</ds-lock>"
        "</module>"
        "<module>"
            "<name>ops-ref</name>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:startup</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<ds-lock>"
                "<datastore xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</datastore>"
                "<sid></sid>"
                "<timestamp></timestamp>"
            "</ds-lock>"
        "</module>"
        "<module>"
            "<name>ops</name>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:startup</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<ds-lock>"
                "<datastore xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</datastore>"
                "<sid></sid>"
                "<timestamp></timestamp>"
            "</ds-lock>"
            "<subscriptions>"
                "<notification-sub>"
                    "<cid></cid>"
                    "<suspended>false</suspended>"
                "</notification-sub>"
                "<notification-sub>"
                    "<cid></cid>"
                    "<suspended>false</suspended>"
                "</notification-sub>"
            "</subscriptions>"
        "</module>"
        "<module>"
            "<name>czechlight-roadm-device</name>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:startup</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<ds-lock>"
                "<datastore xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</datastore>"
                "<sid></sid>"
                "<timestamp></timestamp>"
            "</ds-lock>"
        "</module>"
        "<module>"
            "<name>oper-group-test</name>"
        "</module>"
        "<module>"
            "<name>sm</name>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:startup</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<datastore>"
                "<name xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</name>"
                "<last-modified></last-modified>"
            "</datastore>"
            "<ds-lock>"
                "<datastore xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</datastore>"
                "<sid></sid>"
                "<timestamp></timestamp>"
            "</ds-lock>"
        "</module>");

    strcat(str2, "<rpc>"
            "<path xmlns:a=\"urn:act\">/a:basics/a:animals/a:convert</path>"
            "<rpc-sub>"
                "<xpath xmlns:a=\"urn:act\">/a:basics/a:animals/a:convert[a:direction='false']</xpath>"
                "<priority>5</priority>"
                "<cid></cid>"
                "<suspended>false</suspended>"
            "</rpc-sub>"
            "<rpc-sub>"
                "<xpath xmlns:a=\"urn:act\">/a:basics/a:animals/a:convert</xpath>"
                "<priority>4</priority>"
                "<cid></cid>"
                "<suspended>false</suspended>"
            "</rpc-sub>"
        "</rpc>"
        "<rpc>"
            "<path xmlns:a=\"urn:act\">/a:capitalize</path>"
            "<rpc-sub>"
                "<xpath xmlns:a=\"urn:act\">/a:capitalize</xpath>"
                "<priority>0</priority>"
                "<cid></cid>"
                "<suspended>false</suspended>"
            "</rpc-sub>"
        "</rpc>"
        "<connection>"
            "<cid></cid>"
            "<pid></pid>"
        "</connection>"
        "</sysrepo-state>");
    sr_str_del(str1, "<last-modified>","</last-modified>");
    sr_str_del(str1, "<cid>","</cid>");
    sr_str_del(str1, "<pid>","</pid>");
    sr_str_del(str1, "<timestamp>","</timestamp>");
    sr_str_del(str1, "<sid>","</sid>");
    assert_string_equal(str1, str2);
    free(str1);

    sr_session_switch_ds(st->sess, SR_DS_RUNNING);

    sr_unsubscribe(subscr);
    ret = sr_unlock(st->sess, NULL);
    assert_int_equal(ret, SR_ERR_OK);
    free(str2);
}

/* TEST */
static int
enabled_change_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data)
{
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    int ret, *called = (int *)private_data;

    (void)sub_id;

    assert_int_equal(request_id, 0);

    if (!strcmp(xpath, "/ietf-interfaces:interfaces/interface[name='eth128']")) {
        assert_string_equal(module_name, "ietf-interfaces");

        if (*called == 0) {
            assert_int_equal(event, SR_EV_ENABLED);
        } else if (*called == 1) {
            assert_int_equal(event, SR_EV_DONE);
        } else {
            fail();
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

        /* 6th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth128']/ietf-if-aug:c1");
        assert_int_equal(new_val->dflt, 1);

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
    } else if (!strcmp(xpath, "/ietf-interfaces:interfaces/interface[name='eth256']")) {
        assert_string_equal(module_name, "ietf-interfaces");

        if (*called == 0) {
            assert_int_equal(event, SR_EV_ENABLED);
        } else if (*called == 1) {
            assert_int_equal(event, SR_EV_DONE);
        } else {
            fail();
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
    sr_subscription_ctx_t *subscr = NULL;
    sr_data_t *data;
    char *str;
    const char *str2;
    int ret, called;

    /* create some configuration data */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth128']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* nothing should be in "operational" because there is no subscription */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_non_null(data);
    assert_true(data->tree->flags & LYD_DEFAULT);
    sr_release_data(data);

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

    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    sr_release_data(data);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<interface>"
            "<name>eth128</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<enabled or:origin=\"or:default\">true</enabled>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str, str2);
    free(str);

    /* unsusbcribe */
    sr_unsubscribe(subscr);
    subscr = NULL;

    /* subscribe to a not-present interface */
    called = 0;
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface[name='eth256']",
            enabled_change_cb, &called, 0, SR_SUBSCR_ENABLED, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(called, 2);

    /* "operational" should be empty again */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_non_null(data);
    assert_true(data->tree->flags & LYD_DEFAULT);
    sr_release_data(data);

    /* unsusbcribe */
    sr_unsubscribe(subscr);
}

/* TEST */
static int
simple_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    const struct ly_ctx *ly_ctx;
    uint32_t size, *nc_id;
    const char *str;

    (void)sub_id;
    (void)request_id;
    (void)private_data;

    assert_string_equal(request_xpath, "/ietf-interfaces:*");
    assert_string_equal(sr_session_get_orig_name(session), "test_operational");
    assert_int_equal(sr_session_get_orig_data(session, 0, &size, (const void **)&nc_id), SR_ERR_OK);
    assert_int_equal(size, sizeof *nc_id);
    assert_int_equal(*nc_id, 64);
    assert_int_equal(sr_session_get_orig_data(session, 1, &size, (const void **)&str), SR_ERR_OK);
    assert_int_equal(size, 12);
    assert_string_equal(str, "test_string");
    assert_int_equal(sr_session_get_orig_data(session, 2, &size, (const void **)&str), SR_ERR_NOT_FOUND);

    ly_ctx = sr_acquire_context(sr_session_get_connection(session));

    assert_string_equal(module_name, "ietf-interfaces");
    assert_string_equal(xpath, "/ietf-interfaces:interfaces-state");
    assert_non_null(parent);
    assert_null(*parent);

    assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, ly_ctx, "/ietf-interfaces:interfaces-state/interface[name='eth5']/type",
            "iana-if-type:ethernetCsmacd", 0, parent));
    assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth5']/"
            "oper-status", "testing", 0, NULL));
    assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth5']/"
            "statistics/discontinuity-time", "2000-01-01T02:00:00-00:00", 0, NULL));
    sr_release_context(sr_session_get_connection(session));

    return SR_ERR_OK;
}

static void
test_simple(void **state)
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
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to all configuration data just to enable them */
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces", enabled_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* try to read them back from operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<interface>"
            "<name>eth1</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<enabled or:origin=\"or:default\">true</enabled>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str1, str2);
    free(str1);

    /* subscribe as state data provider */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", simple_oper_cb,
            NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* read all data from operational again */
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<interface>"
            "<name>eth1</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<enabled or:origin=\"or:default\">true</enabled>"
        "</interface>"
    "</interfaces>"
    "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">"
        "<interface>"
            "<name>eth5</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<oper-status>testing</oper-status>"
            "<statistics>"
                "<discontinuity-time>2000-01-01T02:00:00-00:00</discontinuity-time>"
            "</statistics>"
        "</interface>"
    "</interfaces-state>";

    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
fail_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    struct state *st = (struct state *)private_data;
    int ret = SR_ERR_OK;

    (void)session;
    (void)sub_id;
    (void)request_id;

    assert_string_equal(request_xpath, "/ietf-interfaces:*");

    assert_string_equal(module_name, "ietf-interfaces");
    assert_string_equal(xpath, "/ietf-interfaces:interfaces-state");
    assert_non_null(parent);
    assert_null(*parent);

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
        sr_session_set_error_message(session, "Callback failed with an error.");
        ret = SR_ERR_UNAUTHORIZED;
        break;
    case 1:
        /* success */
        break;
    default:
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return ret;
}

static void
test_fail(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr = NULL;
    int ret;

    /* set some configuration data */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe as state data provider*/
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", fail_oper_cb,
            st, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* read all data from operational, fails */
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 1);

    /* read all data from operational, succeeds */
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 2);
    sr_release_data(data);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
config_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    const struct ly_ctx *ly_ctx;

    (void)sub_id;
    (void)request_id;
    (void)private_data;

    assert_string_equal(request_xpath, "/ietf-interfaces:*");
    assert_string_equal(module_name, "ietf-interfaces");
    assert_string_equal(xpath, "/ietf-interfaces:interfaces");
    assert_non_null(parent);
    assert_null(*parent);

    ly_ctx = sr_acquire_context(sr_session_get_connection(session));

    assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, ly_ctx, "/ietf-interfaces:interfaces/interface[name='eth5']/type",
            "iana-if-type:ethernetCsmacd", 0, parent));

    sr_release_context(sr_session_get_connection(session));

    return SR_ERR_OK;
}

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
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth2']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to all configuration data just to enable them */
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces", enabled_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe as config data provider and listen */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces", config_oper_cb,
            NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* read all data from operational */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_true(data->tree->next->flags & LYD_DEFAULT);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">"
        "<interface>"
            "<name>eth5</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
list_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    (void)session;
    (void)sub_id;
    (void)request_id;
    (void)private_data;

    assert_string_equal(request_xpath, "/ietf-interfaces:*");
    assert_string_equal(module_name, "ietf-interfaces");
    assert_non_null(parent);
    assert_non_null(*parent);

    if (!strcmp(xpath, "/ietf-interfaces:interfaces/interface[name='eth2']")) {
        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces/interface[name='eth2']/type",
                "iana-if-type:ethernetCsmacd", 0, NULL));
    } else if (!strcmp(xpath, "/ietf-interfaces:interfaces/interface[name='eth3']")) {
        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces/interface[name='eth3']/type",
                "iana-if-type:ethernetCsmacd", 0, NULL));
    } else {
        fail();
    }

    return SR_ERR_OK;
}

static void
test_list(void **state)
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
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to all configuration data just to enable them */
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces", enabled_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe as 2 list instances data provider and listen */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface[name='eth2']",
            list_oper_cb, NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface[name='eth3']",
            list_oper_cb, NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* read all data from operational */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_true(data->tree->next->flags & LYD_DEFAULT);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<interface>"
            "<name>eth1</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<enabled or:origin=\"or:default\">true</enabled>"
        "</interface>"
        "<interface or:origin=\"or:unknown\">"
            "<name>eth2</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
        "<interface or:origin=\"or:unknown\">"
            "<name>eth3</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
nested_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    const struct ly_ctx *ly_ctx;

    (void)sub_id;
    (void)request_id;
    (void)private_data;

    assert_string_equal(request_xpath, "/ietf-interfaces:*");
    assert_string_equal(module_name, "ietf-interfaces");
    assert_non_null(parent);

    if (!strcmp(xpath, "/ietf-interfaces:interfaces-state/interface[name='eth2']/phys-address")) {
        assert_non_null(*parent);

        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "phys-address", "01:23:45:67:89:ab", 0, NULL));
    } else if (!strcmp(xpath, "/ietf-interfaces:interfaces-state")) {
        assert_null(*parent);
        ly_ctx = sr_acquire_context(sr_session_get_connection(session));

        assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, ly_ctx, "/ietf-interfaces:interfaces-state/interface[name='eth2']/type",
                "iana-if-type:ethernetCsmacd", 0, parent));
        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth2']/"
                "oper-status", "testing", 0, NULL));
        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth2']/"
                "statistics/discontinuity-time", "2000-01-01T03:00:00-00:00", 0, NULL));
        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth3']/"
                "type", "iana-if-type:ethernetCsmacd", 0, NULL));
        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth3']/"
                "oper-status", "dormant", 0, NULL));
        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth3']/"
                "statistics/discontinuity-time", "2000-01-01T03:00:00-00:00", 0, NULL));

        sr_release_context(sr_session_get_connection(session));
    } else {
        fail();
    }

    return SR_ERR_OK;
}

static void
test_nested(void **state)
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
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to all configuration data just to enable them */
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces", enabled_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe as state data provider and listen, it should be called only 2x */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state/interface[name='eth4']/phys-address",
            nested_oper_cb, NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state",
            nested_oper_cb, NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state/interface[name='eth2']/phys-address",
            nested_oper_cb, NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* read all data from operational */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<interface>"
            "<name>eth1</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<enabled or:origin=\"or:default\">true</enabled>"
        "</interface>"
    "</interfaces>"
    "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">"
        "<interface>"
            "<name>eth2</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<oper-status>testing</oper-status>"
            "<phys-address>01:23:45:67:89:ab</phys-address>"
            "<statistics>"
                "<discontinuity-time>2000-01-01T03:00:00-00:00</discontinuity-time>"
            "</statistics>"
        "</interface>"
        "<interface>"
            "<name>eth3</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<oper-status>dormant</oper-status>"
            "<statistics>"
                "<discontinuity-time>2000-01-01T03:00:00-00:00</discontinuity-time>"
            "</statistics>"
        "</interface>"
    "</interfaces-state>";

    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
choice_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    struct state *st = private_data;
    const struct ly_ctx *ly_ctx;
    char xp_resdesc[256];
    char xp_g1leaf1[256];
    char xp_g2leaf1[256];
    char xp_nongroup[256];

    (void)sub_id;
    (void)request_xpath;
    (void)request_id;
    (void)private_data;

    assert_string_equal(module_name, "oper-group-test");
    if (!strcmp(xpath, "/oper-group-test:oper-data-choice") || !strcmp(xpath, "/oper-group-test:oper-data-direct")) {
        sprintf(xp_resdesc, "%s/results-description", xpath);
        sprintf(xp_g1leaf1, "%s/g1container/g1leaf1", xpath);
        sprintf(xp_g2leaf1, "%s/g2container/g2leaf1", xpath);
        sprintf(xp_nongroup, "%s/nongroup", xpath);

        ly_ctx = sr_acquire_context(sr_session_get_connection(session));

        switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
        case 0:
        case 1:
            assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, ly_ctx, xp_resdesc, "Grouping 1 values", 0, parent));
            assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, xp_g1leaf1, "value2", 0, NULL));
            break;
        case 2:
        case 3:
            assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, ly_ctx, xp_resdesc, "Grouping 2 values", 0, parent));
            assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, xp_g2leaf1, "value3", 0, NULL));
            break;
        case 4:
        case 5:
            assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, ly_ctx, xp_resdesc, "Non-grouping values", 0, parent));
            assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, xp_nongroup, "value4", 0, NULL));
            break;
        default:
            fail();
        }

        sr_release_context(sr_session_get_connection(session));
    } else {
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void
test_choice(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr = NULL;
    char *str1;
    const char *str2;
    int ret;

    /* subscribe as state data provider */
    ret = sr_oper_get_subscribe(st->sess, "oper-group-test", "/oper-group-test:oper-data-direct", choice_oper_cb,
            st, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_oper_get_subscribe(st->sess, "oper-group-test", "/oper-group-test:oper-data-choice", choice_oper_cb,
            st, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ATOMIC_STORE_RELAXED(st->cb_called, 0);

    /* read the data from operational (#1 and #2) */
    str2 =
    "<oper-data-direct xmlns=\"http://example.org/oper-group-test\">"
        "<results-description>Grouping 1 values</results-description>"
        "<g1container>"
            "<g1leaf1>value2</g1leaf1>"
        "</g1container>"
    "</oper-data-direct>";

    ret = sr_get_data(st->sess, "/oper-group-test:oper-data-direct", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    assert_string_equal(str1, str2);
    free(str1);

    str2 =
    "<oper-data-choice xmlns=\"http://example.org/oper-group-test\">"
        "<results-description>Grouping 1 values</results-description>"
        "<g1container>"
            "<g1leaf1>value2</g1leaf1>"
        "</g1container>"
    "</oper-data-choice>";

    ret = sr_get_data(st->sess, "/oper-group-test:oper-data-choice", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    assert_string_equal(str1, str2);
    free(str1);

    /* read the data from operational (#3 and #4) */
    str2 =
    "<oper-data-direct xmlns=\"http://example.org/oper-group-test\">"
        "<results-description>Grouping 2 values</results-description>"
        "<g2container>"
            "<g2leaf1>value3</g2leaf1>"
        "</g2container>"
    "</oper-data-direct>";

    ret = sr_get_data(st->sess, "/oper-group-test:oper-data-direct", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    assert_string_equal(str1, str2);
    free(str1);

    str2 =
    "<oper-data-choice xmlns=\"http://example.org/oper-group-test\">"
        "<results-description>Grouping 2 values</results-description>"
        "<g2container>"
            "<g2leaf1>value3</g2leaf1>"
        "</g2container>"
    "</oper-data-choice>";

    ret = sr_get_data(st->sess, "/oper-group-test:oper-data-choice", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    assert_string_equal(str1, str2);
    free(str1);

    /* read the data from operational (#5 and #6) */
    str2 =
    "<oper-data-direct xmlns=\"http://example.org/oper-group-test\">"
        "<results-description>Non-grouping values</results-description>"
        "<nongroup>value4</nongroup>"
    "</oper-data-direct>";

    ret = sr_get_data(st->sess, "/oper-group-test:oper-data-direct", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    assert_string_equal(str1, str2);
    free(str1);

    str2 =
    "<oper-data-choice xmlns=\"http://example.org/oper-group-test\">"
        "<results-description>Non-grouping values</results-description>"
        "<nongroup>value4</nongroup>"
    "</oper-data-choice>";

    ret = sr_get_data(st->sess, "/oper-group-test:oper-data-choice", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    assert_string_equal(str1, str2);
    free(str1);

    /* cleanup */
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 6);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
invalid_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    const struct ly_ctx *ly_ctx;

    (void)sub_id;
    (void)request_id;
    (void)private_data;

    assert_string_equal(xpath, "/test:test-leafref");
    assert_string_equal(request_xpath, "/test:*");
    assert_string_equal(module_name, "test");
    assert_non_null(parent);

    ly_ctx = sr_acquire_context(sr_session_get_connection(session));

    assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, ly_ctx, "/test:test-leafref", "25", 0, parent));

    sr_release_context(sr_session_get_connection(session));

    return SR_ERR_OK;
}

static void
test_invalid(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr = NULL;
    char *str1;
    const char *str2;
    int ret;

    /* set some configuration data */
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "25", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to all configuration data just to enable them */
    ret = sr_module_change_subscribe(st->sess, "test", NULL, dummy_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe as state data provider and listen, it should be called only 2x */
    ret = sr_oper_get_subscribe(st->sess, "test", "/test:test-leafref", invalid_oper_cb, NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* read all data from operational */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/test:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<test-leaf xmlns=\"urn:test\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" "
        "or:origin=\"or:intended\">25</test-leaf>"
    "<test-leafref xmlns=\"urn:test\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" "
        "or:origin=\"or:unknown\">25</test-leafref>";

    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
mixed_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    const struct ly_ctx *ly_ctx;

    (void)sub_id;
    (void)request_id;
    (void)private_data;

    assert_string_equal(request_xpath, "/ietf-interfaces:*");
    assert_string_equal(module_name, "ietf-interfaces");
    assert_string_equal(xpath, "/ietf-interfaces:*");
    assert_non_null(parent);
    assert_null(*parent);

    ly_ctx = sr_acquire_context(sr_session_get_connection(session));

    /* config */
    assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, ly_ctx, "/ietf-interfaces:interfaces/interface[name='eth10']/type",
            "iana-if-type:ethernetCsmacd", 0, parent));

    /* state */
    assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth11']/type",
            "iana-if-type:ethernetCsmacd", 0, NULL));
    assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth11']/"
            "oper-status", "down", 0, NULL));
    assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth11']/"
            "statistics/discontinuity-time", "2000-01-01T03:00:00-00:00", 0, NULL));

    sr_release_context(sr_session_get_connection(session));

    return SR_ERR_OK;
}

static void
test_mixed(void **state)
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
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to all configuration data just to enable them */
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces", enabled_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe as config data provider and listen */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:*", mixed_oper_cb,
            NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* read all data from operational */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">"
        "<interface>"
            "<name>eth10</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
    "</interfaces>"
    "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">"
        "<interface>"
            "<name>eth11</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<oper-status>down</oper-status>"
            "<statistics>"
                "<discontinuity-time>2000-01-01T03:00:00-00:00</discontinuity-time>"
            "</statistics>"
        "</interface>"
    "</interfaces-state>";

    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
xpath_check_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    struct state *st = (struct state *)private_data;

    (void)session;
    (void)sub_id;
    (void)module_name;
    (void)xpath;
    (void)request_xpath;
    (void)request_id;
    (void)parent;

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void
test_xpath_check(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr = NULL;
    int ret;

    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe as state data provider */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", xpath_check_oper_cb,
            st, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* read interfaces from operational, callback not called */
    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    sr_release_data(data);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 0);

    /* read all from operational, callback called */
    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    sr_release_data(data);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 1);

    sr_unsubscribe(subscr);
    subscr = NULL;

    /* subscribe as state data provider */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state/interface[name='eth0']",
            xpath_check_oper_cb, st, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* read interfaces from operational, callback not called */
    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces-state/interface[name='eth1']", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    sr_release_data(data);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 0);

    /* read all from operational, callback called */
    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces-state/interface[name='eth0']/type", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    sr_release_data(data);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 1);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
state_only_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    struct state *st = (struct state *)private_data;
    const struct ly_ctx *ly_ctx;

    (void)sub_id;
    (void)request_xpath;
    (void)request_id;

    assert_string_equal(module_name, "mixed-config");

    if (!strcmp(xpath, "/mixed-config:test-state")) {
        assert_non_null(parent);
        assert_null(*parent);

        ly_ctx = sr_acquire_context(sr_session_get_connection(session));

        assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, ly_ctx, "/mixed-config:test-state/test-case[name='one']/result",
                "101", 0, parent));
        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/mixed-config:test-state/test-case[name='one']/x",
                "0.5000", 0, NULL));
        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/mixed-config:test-state/test-case[name='one']/y",
                "-0.5000", 0, NULL));
        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/mixed-config:test-state/test-case[name='one']/z",
                "-0.2500", 0, NULL));

        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/mixed-config:test-state/test-case[name='two']", NULL,
                0, NULL));

        sr_release_context(sr_session_get_connection(session));
    } else if (!strcmp(xpath, "/mixed-config:test-state/test-case/result")) {
        assert_non_null(parent);
        assert_non_null(*parent);

        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "result", "100", 0, NULL));
    } else {
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void
test_state_only(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr = NULL;
    char *str1;
    const char *str2;
    int ret;

    /* subscribe as mixed data provider and listen */
    ret = sr_oper_get_subscribe(st->sess, "mixed-config", "/mixed-config:test-state", state_only_oper_cb,
            st, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* read all state-only data */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_get_data(st->sess, "/mixed-config:*", 0, 0, SR_OPER_NO_CONFIG | SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 1);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<test-state xmlns=\"urn:sysrepo:mixed-config\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">"
        "<test-case>"
            "<name>one</name>"
            "<result>101</result>"
            "<x>0.5</x>"
            "<y>-0.5</y>"
            "<z>-0.25</z>"
        "</test-case>"
    "</test-state>";

    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
    subscr = NULL;

    /* set some configuration data */
    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/mixed-config:test-state/test-case[name='three']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to all configuration data just to enable them */
    ret = sr_module_change_subscribe(st->sess, "mixed-config", "/mixed-config:test-state", dummy_change_cb, NULL,
            0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe as nested state data provider and listen */
    ret = sr_oper_get_subscribe(st->sess, "mixed-config", "/mixed-config:test-state/test-case/result", state_only_oper_cb,
            st, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* read all state-only data */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_get_data(st->sess, "/mixed-config:*", 0, 0, SR_OPER_NO_CONFIG | SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 1);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<test-state xmlns=\"urn:sysrepo:mixed-config\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<test-case>"
            "<name>three</name>"
            "<result or:origin=\"or:unknown\">100</result>"
        "</test-case>"
    "</test-state>";

    assert_string_equal(str1, str2);
    free(str1);

    /* set some more configuration data */
    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/mixed-config:test-state/test-case[name='four']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/mixed-config:test-state/test-case[name='five']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read some state data (callback should not be called for a filtered-out parent) */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_get_data(st->sess, "/mixed-config:test-state/test-case[name='four']", 0, 0,
            SR_OPER_NO_CONFIG | SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 1);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<test-state xmlns=\"urn:sysrepo:mixed-config\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<test-case>"
            "<name>four</name>"
            "<result or:origin=\"or:unknown\">100</result>"
        "</test-case>"
    "</test-state>";

    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static void
test_config_only(void **state)
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
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to all configuration data just to enable them */
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces", enabled_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe as config data provider and listen */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:*", mixed_oper_cb,
            NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* read all state-only data */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, SR_OPER_NO_STATE | SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">"
        "<interface>"
            "<name>eth10</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
union_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    struct state *st = (struct state *)private_data;

    (void)session;
    (void)sub_id;
    (void)request_xpath;
    (void)request_id;

    assert_string_equal(module_name, "mixed-config");
    assert_non_null(parent);
    assert_non_null(*parent);

    if (!strcmp(xpath, "/mixed-config:test-state/test-case/a")) {
        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "a", "strval", 0, NULL));
    } else if (!strcmp(xpath, "/mixed-config:test-state/test-case/result")) {
        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "result", "100", 0, NULL));
    } else {
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void
test_union(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr = NULL;
    char *str1;
    const char *str2;
    int ret;

    ATOMIC_STORE_RELAXED(st->cb_called, 0);

    /* set some configuration data */
    ret = sr_set_item_str(st->sess, "/mixed-config:test-state/test-case[name='one']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/mixed-config:test-state/test-case[name='two']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to all configuration data to enable them */
    ret = sr_module_change_subscribe(st->sess, "mixed-config", "/mixed-config:*", dummy_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to list member */
    ret = sr_oper_get_subscribe(st->sess, "mixed-config", "/mixed-config:test-state/test-case/a", union_oper_cb,
            st, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_oper_get_subscribe(st->sess, "mixed-config", "/mixed-config:test-state/test-case/result", union_oper_cb,
            st, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* try to read the data with union xpaths */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* read data #1 */
    ret = sr_get_data(st->sess, "/mixed-config:test-state/test-case[name='one']/a", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 1);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<test-state xmlns=\"urn:sysrepo:mixed-config\">"
        "<test-case>"
            "<name>one</name>"
            "<a>strval</a>"
        "</test-case>"
    "</test-state>";

    assert_string_equal(str1, str2);
    free(str1);

    /* read data #2 */
    ret = sr_get_data(st->sess, "/mixed-config:test-state/test-case[name='one']/a|"
            "/mixed-config:test-state/test-case[name='one']/result|"
            "/mixed-config:test-state/test-case[name='two']", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 5);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<test-state xmlns=\"urn:sysrepo:mixed-config\">"
        "<test-case>"
            "<name>one</name>"
            "<a>strval</a>"
            "<result>100</result>"
        "</test-case>"
        "<test-case>"
            "<name>two</name>"
            "<a>strval</a>"
            "<result>100</result>"
        "</test-case>"
    "</test-state>";

    assert_string_equal(str1, str2);
    free(str1);

    /* read data #3 */
    ret = sr_get_data(st->sess, "/mixed-config:test-state/test-case[name='three']/result|"
            "/mixed-config:test-state/test-case[name='one']/a|"
            "/mixed-config:test-state/test-case[name='one']/result", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 7);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<test-state xmlns=\"urn:sysrepo:mixed-config\">"
        "<test-case>"
            "<name>one</name>"
            "<a>strval</a>"
            "<result>100</result>"
        "</test-case>"
    "</test-state>";

    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
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

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">"
        "<interface>"
            "<name>eth1</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
    "</interfaces-state>";

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

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">"
        "<interface>"
            "<name>eth1</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<oper-status>up</oper-status>"
            "<speed>1024</speed>"
        "</interface>"
    "</interfaces-state>";

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

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth1</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<oper-status>up</oper-status>"
            "<speed>1024</speed>"
            "<statistics>"
                "<discontinuity-time>2019-10-29T09:43:12-00:00</discontinuity-time>"
            "</statistics>"
        "</interface>"
    "</interfaces-state>";

    assert_string_equal(str1, str2);
    free(str1);

    /* disconnect, some operational data should be removed */
    sr_disconnect(conn);

    /* read the data again */
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces-state", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">"
        "<interface>"
            "<name>eth1</name>"
            "<statistics>"
                "<discontinuity-time>2019-10-29T09:43:12-00:00</discontinuity-time>"
            "</statistics>"
        "</interface>"
    "</interfaces-state>";

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

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">"
        "<interface>"
            "<name>eth1</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<oper-status>up</oper-status>"
            "<speed>1024</speed>"
        "</interface>"
    "</interfaces-state>";

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

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">"
        "<interface>"
            "<name>eth1</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<oper-status>up</oper-status>"
            "<speed>1024</speed>"
        "</interface>"
    "</interfaces-state>";

    assert_string_equal(str1, str2);
    free(str1);
}

/* TEST */
static int
stored_state_change_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
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

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces-state/interface[name='eth1']/type");
        assert_string_equal(new_val->data.string_val, "iana-if-type:softwareLoopback");

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
test_stored_state(void **state)
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
            stored_state_change_cb, st, 0, 0, &subscr);
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

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">"
        "<interface>"
            "<name>eth1</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
    "</interfaces-state>";

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

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">"
        "<interface>"
            "<name>eth1</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:softwareLoopback</type>"
        "</interface>"
    "</interfaces-state>";

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
    sr_val_t *old_val, *new_val;
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
        assert_string_equal(new_val->xpath, "/mixed-config:test-state/l[1]");

        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/mixed-config:test-state/l[1]/l1");

        sr_free_val(new_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/mixed-config:test-state/l[1]");
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/mixed-config:test-state/l[2]");

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* 5th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/mixed-config:test-state/l[2]/l1");

        sr_free_val(new_val);

        /* 6th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/mixed-config:test-state/ll[1]");

        sr_free_val(new_val);

        /* 7th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/mixed-config:test-state/ll[1]");
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/mixed-config:test-state/ll[2]");

        sr_free_val(old_val);
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
        ret = sr_get_changes_iter(session, "/mixed-config:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/mixed-config:test-state/l[1]/l1");
        assert_null(new_val);

        sr_free_val(old_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
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
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/mixed-config:test-state/ll[1]");
        assert_null(new_val);

        sr_free_val(old_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
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
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/mixed-config:test-state/ll[1]");
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/mixed-config:test-state/ll[1]");

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/mixed-config:test-state/ll[2]");
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/mixed-config:test-state/ll[2]");

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/mixed-config:test-state/ll[3]");
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/mixed-config:test-state/ll[3]");

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
test_stored_state_list(void **state)
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

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<test-state xmlns=\"urn:sysrepo:mixed-config\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" "
            "or:origin=\"or:intended\">"
        "<l or:origin=\"or:unknown\">"
            "<l1>val1</l1>"
        "</l>"
        "<l or:origin=\"or:unknown\">"
            "<l1>val2</l1>"
        "</l>"
        "<ll or:origin=\"or:unknown\">val1</ll>"
        "<ll or:origin=\"or:unknown\">val2</ll>"
    "</test-state>";

    assert_string_equal(str1, str2);
    free(str1);

    /* remove some oper data */
    ret = sr_discard_oper_changes(st->conn, st->sess, "/mixed-config:test-state/l[2]/l1", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_discard_oper_changes(st->conn, st->sess, "/mixed-config:test-state/ll[2]", 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* callback called */
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 6);

    /* read the data */
    ret = sr_get_data(st->sess, "/mixed-config:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<test-state xmlns=\"urn:sysrepo:mixed-config\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" "
            "or:origin=\"or:intended\">"
        "<l or:origin=\"or:unknown\">"
            "<l1>val1</l1>"
        "</l>"
        "<l or:origin=\"or:unknown\"/>"
        "<ll or:origin=\"or:unknown\">val1</ll>"
    "</test-state>";

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
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 8);

    /* read the data */
    ret = sr_get_data(st->sess, "/mixed-config:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<test-state xmlns=\"urn:sysrepo:mixed-config\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" "
            "or:origin=\"or:intended\">"
        "<l or:origin=\"or:unknown\">"
            "<l1>val1</l1>"
        "</l>"
        "<l or:origin=\"or:unknown\"/>"
        "<ll or:origin=\"or:unknown\">val1</ll>"
        "<ll or:origin=\"or:unknown\">val3</ll>"
        "<ll or:origin=\"or:unknown\">val2</ll>"
        "<ll or:origin=\"or:unknown\">val3</ll>"
    "</test-state>";

    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static void
test_stored_config(void **state)
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

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<interface>"
            "<name>eth1</name>"
            "<description>config-description</description>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<enabled or:origin=\"or:unknown\">true</enabled>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str1, str2);
    free(str1);

    /*
     * 2) store oper data changing the value now
     */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/enabled",
            "false", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the operational data */
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<interface>"
            "<name>eth1</name>"
            "<description>config-description</description>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<enabled or:origin=\"or:unknown\">false</enabled>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str1, str2);
    free(str1);

    /*
     * 3) overwrite running data by some operational config data
     */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/description",
            "oper-description", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_oper_delete_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/enabled", "false", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the operational data */
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<interface>"
            "<name>eth1</name>"
            "<description or:origin=\"or:unknown\">oper-description</description>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<enabled or:origin=\"or:unknown\">true</enabled>"
        "</interface>"
    "</interfaces>";

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

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<interface>"
            "<name>eth1</name>"
            "<description or:origin=\"or:unknown\">oper-description</description>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static void
test_stored_top_list(void **state)
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

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<channel-plan xmlns=\"http://czechlight.cesnet.cz/yang/czechlight-roadm-device\" "
            "xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<channel>"
            "<name>13.5</name>"
            "<lower-frequency>191325000</lower-frequency>"
            "<upper-frequency>191375000</upper-frequency>"
        "</channel>"
        "<channel>"
            "<name>14.0</name>"
            "<lower-frequency>191375000</lower-frequency>"
            "<upper-frequency>191425000</upper-frequency>"
        "</channel>"
    "</channel-plan>"
    "<media-channels xmlns=\"http://czechlight.cesnet.cz/yang/czechlight-roadm-device\" "
            "xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<channel>13.5</channel>"
        "<power or:origin=\"or:unknown\">"
            "<common-in>0.1</common-in>"
            "<common-out>0.2</common-out>"
        "</power>"
    "</media-channels>"
    "<line xmlns=\"http://czechlight.cesnet.cz/yang/czechlight-roadm-device\" "
            "xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<output-voa or:origin=\"or:default\">0.0</output-voa>"
    "</line>";

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

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<channel-plan xmlns=\"http://czechlight.cesnet.cz/yang/czechlight-roadm-device\" "
            "xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<channel>"
            "<name>13.5</name>"
            "<lower-frequency>191325000</lower-frequency>"
            "<upper-frequency>191375000</upper-frequency>"
        "</channel>"
        "<channel>"
            "<name>14.0</name>"
            "<lower-frequency>191375000</lower-frequency>"
            "<upper-frequency>191425000</upper-frequency>"
        "</channel>"
    "</channel-plan>"
    "<media-channels xmlns=\"http://czechlight.cesnet.cz/yang/czechlight-roadm-device\" "
            "xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<channel>13.5</channel>"
        "<power or:origin=\"or:unknown\">"
            "<common-in>0.9</common-in>"
            "<common-out>1.0</common-out>"
        "</power>"
    "</media-channels>"
    "<media-channels xmlns=\"http://czechlight.cesnet.cz/yang/czechlight-roadm-device\" "
            "xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<channel>14.0</channel>"
        "<power or:origin=\"or:unknown\">"
            "<common-in>1.2</common-in>"
            "<common-out>1.3</common-out>"
            "<leaf-out>1.4</leaf-out>"
        "</power>"
    "</media-channels>"
    "<line xmlns=\"http://czechlight.cesnet.cz/yang/czechlight-roadm-device\" "
            "xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<output-voa or:origin=\"or:default\">0.0</output-voa>"
    "</line>";

    assert_string_equal(str1, str2);
    free(str1);

    /* cleanup */
    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
    sr_unsubscribe(subscr);
}

/* TEST */
static void
test_stored_change_revert(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;

    /* switch to operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* create a list instance */
    ret = sr_set_item_str(st->sess, "/mixed-config:test-state/test-case[name='a']/a", "vala", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* remove the list instance */
    ret = sr_oper_delete_item_str(st->sess, "/mixed-config:test-state/test-case[name='a']", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* remove all stored data */
    ret = sr_discard_oper_changes(st->conn, st->sess, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
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
test_stored_edit_ether_diff_remove(void **state)
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
    ret = sr_oper_delete_item_str(st->sess, "/mixed-config:test-state/test-case[name='a']", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
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
test_stored_np_cont1(void **state)
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

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<interface>"
            "<name>eth0</name>"
            "<description/>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<enabled or:origin=\"or:default\">true</enabled>"
            "<c1 xmlns=\"urn:ietf-if-aug\" or:origin=\"or:unknown\">"
                "<oper1>val</oper1>"
            "</c1>"
        "</interface>"
    "</interfaces>";

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

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<interface>"
            "<name>eth0</name>"
            "<description>test-desc</description>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<enabled or:origin=\"or:default\">true</enabled>"
            "<c1 xmlns=\"urn:ietf-if-aug\" or:origin=\"or:unknown\">"
                "<oper1>val</oper1>"
            "</c1>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static void
test_stored_np_cont2(void **state)
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

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<interface>"
            "<name>eth0</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<enabled or:origin=\"or:default\">true</enabled>"
            "<c1 xmlns=\"urn:ietf-if-aug\" or:origin=\"or:unknown\">"
                "<oper1>val</oper1>"
            "</c1>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str1, str2);
    free(str1);

    /* unsubscribe */
    sr_unsubscribe(subscr);
}

/* TEST */
static void
test_stored_edit_merge_leaf(void **state)
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
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<interface>"
            "<name>eth1</name>"
            "<description or:origin=\"or:unknown\">oper-description</description>"
            "<type or:origin=\"or:unknown\" xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<enabled or:origin=\"or:unknown\">false</enabled>"
        "</interface>"
    "</interfaces>";
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
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth1</name>"
            "<description>oper-description2</description>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<enabled>false</enabled>"
        "</interface>"
    "</interfaces>";
    assert_string_equal(str1, str2);
    free(str1);

    /* remove the leaf, should be merged with the previous data */
    ret = sr_discard_oper_changes(st->conn, st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/enabled", 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the data */
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<interface>"
            "<name>eth1</name>"
            "<description or:origin=\"or:unknown\">oper-description2</description>"
            "<type or:origin=\"or:unknown\" xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
    "</interfaces>";
    assert_string_equal(str1, str2);
    free(str1);

    /* remove the whole interface */
    ret = sr_discard_oper_changes(st->conn, st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']", 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the data */
    ret = sr_get_data(st->sess, "/ietf-interfaces:interfaces", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);
    sr_release_data(data);
    assert_null(str1);
}

/* TEST */
static void
test_stored_diff_merge_userord(void **state)
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
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
    "<cont xmlns=\"urn:test\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<l2 or:origin=\"or:unknown\">"
            "<k>key2</k>"
            "<v>26</v>"
        "</l2>"
        "<l2>"
            "<k>key1</k>"
            "<v>25</v>"
        "</l2>"
        "<l2>"
            "<k>key3</k>"
            "<v or:origin=\"or:unknown\">27</v>"
        "</l2>"
    "</cont>";
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
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
    "<cont xmlns=\"urn:test\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<l2>"
            "<k>key1</k>"
            "<v>25</v>"
        "</l2>"
        "<l2 or:origin=\"or:learned\">"
            "<k>key2</k>"
            "<v or:origin=\"or:unknown\">20</v>"
        "</l2>"
        "<l2>"
            "<k>key3</k>"
            "<v or:origin=\"or:unknown\">27</v>"
        "</l2>"
    "</cont>";
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
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
    "<cont xmlns=\"urn:test\">"
        "<l2>"
            "<k>key2</k>"
            "<v>20</v>"
        "</l2>"
        "<l2>"
            "<k>key1</k>"
            "<v>25</v>"
        "</l2>"
        "<l2>"
            "<k>key3</k>"
            "<v>27</v>"
        "</l2>"
    "</cont>";
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
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
    "<cont xmlns=\"urn:test\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<l2 or:origin=\"or:unknown\">"
            "<k>key3</k>"
            "<v>27</v>"
        "</l2>"
        "<l2 or:origin=\"or:unknown\">"
            "<k>key2</k>"
            "<v>20</v>"
        "</l2>"
        "<l2>"
            "<k>key1</k>"
            "<v>25</v>"
        "</l2>"
    "</cont>";
    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static LY_ERR
ly_ext_data_cb(const struct lysc_ext_instance *ext, void *user_data, void **ext_data, ly_bool *ext_data_free)
{
    struct state *st = (struct state *)user_data;
    LY_ERR r;
    const struct ly_ctx *ly_ctx;
    struct lyd_node *data = NULL;
    const char *xml = "<yang-library xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-library\" "
            "    xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">"
            "  <module-set>"
            "    <name>test-set</name>"
            "    <module>"
            "      <name>ietf-datastores</name>"
            "      <revision>2018-02-14</revision>"
            "      <namespace>urn:ietf:params:xml:ns:yang:ietf-datastores</namespace>"
            "    </module>"
            "    <module>"
            "      <name>ietf-yang-library</name>"
            "      <revision>2019-01-04</revision>"
            "      <namespace>urn:ietf:params:xml:ns:yang:ietf-yang-library</namespace>"
            "    </module>"
            "    <module>"
            "      <name>ietf-yang-schema-mount</name>"
            "      <revision>2019-01-14</revision>"
            "      <namespace>urn:ietf:params:xml:ns:yang:ietf-yang-schema-mount</namespace>"
            "    </module>"
            "    <module>"
            "      <name>ietf-interfaces</name>"
            "      <revision>2014-05-08</revision>"
            "      <namespace>urn:ietf:params:xml:ns:yang:ietf-interfaces</namespace>"
            "    </module>"
            "    <module>"
            "      <name>iana-if-type</name>"
            "      <revision>2014-05-08</revision>"
            "      <namespace>urn:ietf:params:xml:ns:yang:iana-if-type</namespace>"
            "    </module>"
            "    <module>"
            "      <name>ietf-netconf</name>"
            "      <revision>2013-09-29</revision>"
            "      <namespace>urn:ietf:params:xml:ns:netconf:base:1.0</namespace>"
            "    </module>"
            "    <module>"
            "      <name>ietf-origin</name>"
            "      <revision>2018-02-14</revision>"
            "      <namespace>urn:ietf:params:xml:ns:yang:ietf-origin</namespace>"
            "    </module>"
            "    <import-only-module>"
            "      <name>ietf-yang-types</name>"
            "      <revision>2013-07-15</revision>"
            "      <namespace>urn:ietf:params:xml:ns:yang:ietf-yang-types</namespace>"
            "    </import-only-module>"
            "    <import-only-module>"
            "      <name>ietf-netconf-acm</name>"
            "      <revision>2018-02-14</revision>"
            "      <namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-acm</namespace>"
            "    </import-only-module>"
            "  </module-set>"
            "  <schema>"
            "    <name>test-schema</name>"
            "    <module-set>test-set</module-set>"
            "  </schema>"
            "  <datastore>"
            "    <name>ds:running</name>"
            "    <schema>test-schema</schema>"
            "  </datastore>"
            "  <datastore>"
            "    <name>ds:operational</name>"
            "    <schema>test-schema</schema>"
            "  </datastore>"
            "  <content-id>1</content-id>"
            "</yang-library>"
            "<modules-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-library\">"
            "  <module-set-id>1</module-set-id>"
            "</modules-state>"
            "<schema-mounts xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-schema-mount\">"
            "  <mount-point>"
            "    <module>sm</module>"
            "    <label>root</label>"
            "    <shared-schema/>"
            "  </mount-point>"
            "</schema-mounts>";

    (void)ext;

    ly_ctx = sr_acquire_context(st->conn);
    r = lyd_parse_data_mem(ly_ctx, xml, LYD_XML, LYD_PARSE_STRICT, LYD_VALIDATE_PRESENT, &data);
    sr_release_context(st->conn);
    assert_int_equal(r, LY_SUCCESS);

    *ext_data = data;
    *ext_data_free = 1;
    return LY_SUCCESS;
}

static void
test_stored_schema_mount(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    char *str1;
    const char *str2;
    int ret;

    /* set ext cb */
    sr_set_ext_data_cb(st->conn, ly_ext_data_cb, st);

    /* switch to operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

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

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<root xmlns=\"urn:sm\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
            "<interface>"
                "<name>eth1</name>"
                "<description or:origin=\"or:unknown\">config-description</description>"
                "<type or:origin=\"or:unknown\" "
                    "xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "</interface>"
        "</interfaces>"
    "</root>";

    assert_string_equal(str1, str2);
    free(str1);
}

/* TEST */
static int
change_cb_stored_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath, sr_event_t event,
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
test_change_cb_stored(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr = NULL;
    char *str1;
    const char *str2;
    int ret;

    /* subscribe to all configuration data */
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", NULL, change_cb_stored_cb, st, 0, 0, &subscr);
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

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\""
            " or:origin=\"or:intended\">"
        "<interface>"
            "<name>eth1</name>"
            "<description or:origin=\"or:unknown\">descr2</description>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<enabled or:origin=\"or:default\">true</enabled>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static void
test_default_when(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    char *str1;
    const char *str2;
    int ret;

    /* switch to operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the operational data */
    ret = sr_get_data(st->sess, "/act:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_KEEPEMPTYCONT | LYD_PRINT_WD_ALL | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
    "<basics xmlns=\"urn:act\">"
        "<subbasics>"
            "<complex_number xmlns=\"urn:act2\"/>"
        "</subbasics>"
    "</basics>"
    "<advanced xmlns=\"urn:act\"/>";
    assert_string_equal(str1, str2);
    free(str1);
}

/* TEST */
static int
nested_default_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    const struct ly_ctx *ly_ctx;

    (void)sub_id;
    (void)request_id;
    (void)private_data;

    assert_string_equal(request_xpath, "/defaults:*");
    assert_string_equal(module_name, "defaults");
    assert_non_null(parent);

    if (!strcmp(xpath, "/defaults:l1/cont1/ll")) {
        assert_non_null(*parent);

        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "ll", "valuee", 0, NULL));
    } else if (!strcmp(xpath, "/defaults:l1")) {
        assert_null(*parent);

        ly_ctx = sr_acquire_context(sr_session_get_connection(session));
        assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, ly_ctx, "/defaults:l1[k='val']/cont1/cont2/dflt1", "64", 0, parent));
        sr_release_context(sr_session_get_connection(session));
    } else {
        fail();
    }

    return SR_ERR_OK;
}

static void
test_nested_default(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr = NULL;
    char *str1;
    const char *str2;
    int ret;

    /* subscribe as state data provider and listen */
    ret = sr_oper_get_subscribe(st->sess, "defaults", "/defaults:l1", nested_default_oper_cb, NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_oper_get_subscribe(st->sess, "defaults", "/defaults:l1/cont1/ll",
            nested_default_oper_cb, NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* read all data from operational */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/defaults:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<l1 xmlns=\"urn:defaults\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">"
        "<k>val</k>"
        "<cont1>"
            "<cont2>"
                "<dflt1>64</dflt1>"
            "</cont2>"
            "<ll>valuee</ll>"
        "</cont1>"
    "</l1>";

    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static void
test_disabled_default(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr = NULL;
    char *str1;
    const char *str2;
    int ret;

    /* set some configuration data */
    ret = sr_set_item_str(st->sess, "/defaults:pcont", NULL, NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to some configuration data just to enable them */
    ret = sr_module_change_subscribe(st->sess, "defaults", "/defaults:pcont/ll",
            dummy_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* switch to operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the operational data */
    ret = sr_get_data(st->sess, "/defaults:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<pcont xmlns=\"urn:defaults\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:intended\">"
        "<ll or:origin=\"or:default\">1</ll>"
        "<ll or:origin=\"or:default\">2</ll>"
        "<ll or:origin=\"or:default\">3</ll>"
    "</pcont>";

    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
merge_flag_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    (void)session;
    (void)sub_id;
    (void)request_id;
    (void)private_data;

    assert_string_equal(module_name, "ietf-interfaces");
    assert_string_equal(xpath, "/ietf-interfaces:interfaces/interface");
    assert_string_equal(request_xpath, "/ietf-interfaces:*");

    /* create new interface */
    assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "interface[name='eth3']/type", "iana-if-type:softwareLoopback",
            0, NULL));

    /* add node into an interface */
    assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "interface[name='eth1']/description", "operational-desc",
            0, NULL));

    /* change nodes in an interface */
    assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "interface[name='eth2']/enabled", "true", 0, NULL));
    assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "interface[name='eth2']/type", "iana-if-type:frameRelay",
            0, NULL));

    return SR_ERR_OK;
}

static void
test_merge_flag(void **state)
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
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth2']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth2']/enabled",
            "false", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to all configuration data just to enable them */
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces", dummy_change_cb, NULL,
            0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe as state data provider and listen */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface",
            merge_flag_oper_cb, NULL, SR_SUBSCR_OPER_MERGE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* read all data from operational */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth1</name>"
            "<description>operational-desc</description>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
        "<interface>"
            "<name>eth2</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:frameRelay</type>"
            "<enabled>true</enabled>"
        "</interface>"
        "<interface>"
            "<name>eth3</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:softwareLoopback</type>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
state_default_merge_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    struct lyd_node *node;

    (void)session;
    (void)sub_id;
    (void)request_id;
    (void)private_data;

    assert_string_equal(module_name, "mixed-config");
    assert_string_equal(xpath, "/mixed-config:test-state/test-case");
    assert_string_equal(request_xpath, "/mixed-config:*");

    assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "test-case[name='a']/result", "1", 0, NULL));
    assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "test-case[name='a']/z", "4.4", 0, &node));
    node->flags |= LYD_DEFAULT;
    assert_int_equal(LY_SUCCESS, lyd_new_meta(NULL, node, NULL, "ietf-origin:origin", "ietf-origin:default", 0, NULL));
    assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "test-case[name='b']/x", "2.2", 0, NULL));

    return SR_ERR_OK;
}

static void
test_state_default_merge(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr = NULL;
    char *str1;
    const char *str2;
    int ret;

    /* set some configuration data */
    ret = sr_set_item_str(st->sess, "/mixed-config:test-state/test-case[name='a']/a", "vala", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/mixed-config:test-state/test-case[name='b']/a", "valb", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to all configuration data just to enable them */
    ret = sr_module_change_subscribe(st->sess, "mixed-config", NULL, dummy_change_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* read all data from operational */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/mixed-config:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<test-state xmlns=\"urn:sysrepo:mixed-config\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" "
            "or:origin=\"or:intended\">"
        "<test-case>"
            "<name>a</name>"
            "<a>vala</a>"
        "</test-case>"
        "<test-case>"
            "<name>b</name>"
            "<a>valb</a>"
        "</test-case>"
    "</test-state>";

    assert_string_equal(str1, str2);
    free(str1);

    /* subscribe as state data provider and listen */
    ret = sr_oper_get_subscribe(st->sess, "mixed-config", "/mixed-config:test-state/test-case",
            state_default_merge_oper_cb, NULL, SR_SUBSCR_OPER_MERGE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* read all data from operational */
    ret = sr_get_data(st->sess, "/mixed-config:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<test-state xmlns=\"urn:sysrepo:mixed-config\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" "
            "or:origin=\"or:intended\">"
        "<test-case>"
            "<name>a</name>"
            "<a>vala</a>"
            "<result>1</result>"
            "<z or:origin=\"or:default\">4.4</z>"
        "</test-case>"
        "<test-case>"
            "<name>b</name>"
            "<a>valb</a>"
            "<x>2.2</x>"
        "</test-case>"
    "</test-state>";

    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
same_xpath_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    const struct ly_ctx *ly_ctx;

    (void)sub_id;
    (void)request_xpath;
    (void)request_id;
    (void)private_data;

    ly_ctx = sr_session_acquire_context(session);

    assert_string_equal(module_name, "ietf-interfaces");
    assert_string_equal(xpath, "/ietf-interfaces:interfaces-state");
    assert_non_null(parent);
    assert_null(*parent);

    assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, ly_ctx, "/ietf-interfaces:interfaces-state/interface[name='eth5']/type",
            "iana-if-type:ethernetCsmacd", 0, parent));
    assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth5']/"
            "oper-status", "testing", 0, NULL));
    assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth5']/"
            "statistics/discontinuity-time", "2000-01-01T02:00:00-00:00", 0, NULL));
    sr_session_release_context(session);

    return SR_ERR_OK;
}

static int
same_xpath_oper_cb2(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    const struct ly_ctx *ly_ctx;

    (void)sub_id;
    (void)request_xpath;
    (void)request_id;
    (void)private_data;

    ly_ctx = sr_session_acquire_context(session);

    assert_string_equal(module_name, "ietf-interfaces");
    assert_string_equal(xpath, "/ietf-interfaces:interfaces-state");
    assert_non_null(parent);
    assert_null(*parent);

    assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, ly_ctx, "/ietf-interfaces:interfaces-state/interface[name='eth5']/type",
            "iana-if-type:ethernetCsmacd", 0, parent));
    assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth5']/"
            "oper-status", "unknown", 0, NULL));
    sr_session_release_context(session);

    return SR_ERR_OK;
}

static int
same_xpath_oper_cb3(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    const struct ly_ctx *ly_ctx;

    (void)sub_id;
    (void)request_xpath;
    (void)request_id;
    (void)private_data;

    ly_ctx = sr_session_acquire_context(session);

    assert_string_equal(module_name, "ietf-interfaces");
    assert_string_equal(xpath, "/ietf-interfaces:interfaces-state");
    assert_non_null(parent);
    assert_null(*parent);

    assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, ly_ctx, "/ietf-interfaces:interfaces-state/interface[name='eth5']/"
            "statistics/discontinuity-time", "2001-01-01T02:00:00-00:00", 0, parent));
    assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth5']/"
            "statistics/in-octets", "1", 0, NULL));
    sr_session_release_context(session);

    return SR_ERR_OK;
}

static void
test_same_xpath(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr = NULL;
    char *str1;
    const char *str2, *str3;
    int ret;

    /* subscribe as state data provider */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", same_xpath_oper_cb,
            NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe as state data provider */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", same_xpath_oper_cb,
            NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);

    /* subscribe as state data provider */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", same_xpath_oper_cb2,
            NULL, SR_SUBSCR_OPER_MERGE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* try to read them back from operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* read all data from operational again */
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">"
        "<interface>"
            "<name>eth5</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<oper-status>unknown</oper-status>"
            "<statistics>"
                "<discontinuity-time>2000-01-01T02:00:00-00:00</discontinuity-time>"
            "</statistics>"
        "</interface>"
    "</interfaces-state>";

    assert_string_equal(str1, str2);
    free(str1);

    /* subscribe as state data provider */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", same_xpath_oper_cb3,
            NULL, SR_SUBSCR_OPER_MERGE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* read all data from operational again */
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str3 =
    "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">"
        "<interface>"
            "<name>eth5</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<oper-status>unknown</oper-status>"
            "<statistics>"
                "<discontinuity-time>2001-01-01T02:00:00-00:00</discontinuity-time>"
                "<in-octets>1</in-octets>"
            "</statistics>"
        "</interface>"
    "</interfaces-state>";

    assert_string_equal(str1, str3);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
same_xpath_parallel_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    struct state *st = (struct state *)private_data;

    (void)session;
    (void)sub_id;
    (void)module_name;
    (void)xpath;
    (void)request_xpath;
    (void)request_id;
    (void)parent;

    /* wait for all the threads so that we assure getting data is parallel */
    pthread_barrier_wait(&st->barrier5);

    return SR_ERR_OK;
}

static void
test_same_xpath_parallel(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr1 = NULL, *subscr2 = NULL, *subscr3 = NULL, *subscr4 = NULL, *subscr5 = NULL;

    /* subscribe as state data provider */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", same_xpath_parallel_cb,
            st, 0, &subscr1);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe as state data provider */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", same_xpath_parallel_cb,
            st, SR_SUBSCR_OPER_MERGE, &subscr2);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe as state data provider */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", same_xpath_parallel_cb,
            st, SR_SUBSCR_OPER_MERGE, &subscr3);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe as state data provider */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", same_xpath_parallel_cb,
            st, SR_SUBSCR_OPER_MERGE, &subscr4);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe as state data provider */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", same_xpath_parallel_cb,
            st, SR_SUBSCR_OPER_MERGE, &subscr5);
    assert_int_equal(ret, SR_ERR_OK);

    /* try to read them back from operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* read all data from operational again */
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    sr_release_data(data);

    sr_unsubscribe(subscr1);
    sr_unsubscribe(subscr2);
    sr_unsubscribe(subscr3);
    sr_unsubscribe(subscr4);
    sr_unsubscribe(subscr5);
}

/* TEST */
static int
same_xpath_fail_successful_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    struct state *st = (struct state *)private_data;

    (void)session;
    (void)sub_id;
    (void)module_name;
    (void)xpath;
    (void)request_xpath;
    (void)request_id;
    (void)parent;

    /* wait for all the threads so that we assure getting data is parallel */
    pthread_barrier_wait(&st->barrier5);

    return SR_ERR_OK;
}

static int
same_xpath_fail_failed_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    struct state *st = (struct state *)private_data;

    (void)session;
    (void)sub_id;
    (void)module_name;
    (void)xpath;
    (void)request_xpath;
    (void)request_id;
    (void)parent;

    /* wait for all the threads so that we assure getting data is parallel */
    pthread_barrier_wait(&st->barrier5);

    return SR_ERR_CALLBACK_FAILED;
}

static void
test_same_xpath_fail(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr1 = NULL, *subscr2 = NULL, *subscr3 = NULL, *subscr4 = NULL, *subscr5 = NULL;

    /* subscribe as state data provider */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", same_xpath_fail_successful_cb,
            *state, 0, &subscr1);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe as state data provider */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", same_xpath_fail_successful_cb,
            *state, SR_SUBSCR_OPER_MERGE, &subscr2);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe as state data provider */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", same_xpath_fail_failed_cb,
            *state, SR_SUBSCR_OPER_MERGE, &subscr3);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe as state data provider */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", same_xpath_fail_successful_cb,
            *state, SR_SUBSCR_OPER_MERGE, &subscr4);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe as state data provider */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", same_xpath_fail_successful_cb,
            *state, SR_SUBSCR_OPER_MERGE, &subscr5);
    assert_int_equal(ret, SR_ERR_OK);

    /* try to read them back from operational DS */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    /* read all data from operational again */
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);

    sr_release_data(data);

    sr_unsubscribe(subscr1);
    sr_unsubscribe(subscr2);
    sr_unsubscribe(subscr3);
    sr_unsubscribe(subscr4);
    sr_unsubscribe(subscr5);
}

/* TEST */
static int
cache_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    struct state *st = private_data;
    const struct ly_ctx *ly_ctx;

    (void)sub_id;
    (void)request_xpath;
    (void)request_id;
    (void)private_data;

    ly_ctx = sr_acquire_context(sr_session_get_connection(session));

    assert_string_equal(module_name, "ietf-interfaces");
    assert_string_equal(xpath, "/ietf-interfaces:interfaces-state");
    assert_non_null(parent);
    assert_null(*parent);

    assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, ly_ctx, "/ietf-interfaces:interfaces-state/interface[name='eth5']/type",
            "iana-if-type:ethernetCsmacd", 0, parent));
    assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth5']/"
            "oper-status", "testing", 0, NULL));
    assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth5']/"
            "statistics/discontinuity-time", "2000-01-01T02:00:00-00:00", 0, NULL));
    sr_release_context(sr_session_get_connection(session));

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void
test_cache(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr1 = NULL, *subscr2 = NULL;
    char *str1;
    const char *str2;
    int ret;

    ATOMIC_STORE_RELAXED(st->cb_called, 0);

    /* subscribe as state data provider */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", cache_oper_cb,
            st, 0, &subscr1);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe for oper poll */
    ret = sr_oper_poll_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", 3000, 0, &subscr2);
    assert_int_equal(ret, SR_ERR_OK);

    /* another subscribe fails */
    ret = sr_oper_poll_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", 1000, 0, &subscr2);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);

    /* read the data from operational #1 */
    sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">"
        "<interface>"
            "<name>eth5</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<oper-status>testing</oper-status>"
            "<statistics>"
                "<discontinuity-time>2000-01-01T02:00:00-00:00</discontinuity-time>"
            "</statistics>"
        "</interface>"
    "</interfaces-state>";

    assert_string_equal(str1, str2);
    free(str1);

    /* read the data from operational #2 */
    sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth5</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<oper-status>testing</oper-status>"
            "<statistics>"
                "<discontinuity-time>2000-01-01T02:00:00-00:00</discontinuity-time>"
            "</statistics>"
        "</interface>"
    "</interfaces-state>";

    assert_string_equal(str1, str2);
    free(str1);

    /* read the data from operational #3 */
    sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
    "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
        " xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">"
        "<interface>"
            "<name>eth5</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<oper-status>testing</oper-status>"
            "<statistics>"
                "<discontinuity-time>2000-01-01T02:00:00-00:00</discontinuity-time>"
            "</statistics>"
        "</interface>"
    "</interfaces-state>";

    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr1);
    sr_unsubscribe(subscr2);

    /* only a single callback call expected, cache used otherwise */
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 1);
}

/* TEST */
static void
test_cache_no_sub(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    sr_subscription_ctx_t *subscr1 = NULL, *subscr2 = NULL;
    char *str1;
    const char *str2;
    int ret;

    ATOMIC_STORE_RELAXED(st->cb_called, 0);

    /* subscribe for oper poll */
    ret = sr_oper_poll_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", 3000, 0, &subscr2);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the data from operational #1 */
    sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);
    sr_release_data(data);
    assert_null(str1);

    /* oper get subscribe */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", cache_oper_cb,
            st, 0, &subscr1);
    assert_int_equal(ret, SR_ERR_OK);

    /* manually fill the cache */
    ret = sr_subscription_process_events(subscr2, NULL, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the data from operational #2 */
    sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);
    sr_release_data(data);
    str2 =
    "<interfaces-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth5</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<oper-status>testing</oper-status>"
            "<statistics>"
                "<discontinuity-time>2000-01-01T02:00:00-00:00</discontinuity-time>"
            "</statistics>"
        "</interface>"
    "</interfaces-state>";
    assert_string_equal(str1, str2);
    free(str1);

    /* unsubscribe oper get */
    sr_unsubscribe(subscr1);

    /* manually clear the cache */
    ret = sr_subscription_process_events(subscr2, NULL, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* read the data from operational #3 */
    sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);
    sr_release_data(data);
    assert_null(str1);

    sr_unsubscribe(subscr2);

    /* only a single callback call expected, cache used otherwise */
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 1);
}

/* TEST */
static int
cache_diff_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    struct state *st = private_data;
    const struct ly_ctx *ly_ctx;

    (void)sub_id;
    (void)request_xpath;
    (void)request_id;
    (void)private_data;

    assert_string_equal(module_name, "ietf-interfaces");
    assert_string_equal(xpath, "/ietf-interfaces:interfaces-state");
    assert_non_null(parent);
    assert_null(*parent);

    ly_ctx = sr_acquire_context(sr_session_get_connection(session));
    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
        assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, ly_ctx, "/ietf-interfaces:interfaces-state/interface[name='eth5']/type",
                "iana-if-type:ethernetCsmacd", 0, parent));
        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth5']/"
                "oper-status", "testing", 0, NULL));
        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth5']/"
                "statistics/discontinuity-time", "2000-01-01T02:00:00-00:00", 0, NULL));
        break;
    case 2:
        assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, ly_ctx, "/ietf-interfaces:interfaces-state/interface[name='eth5']/type",
                "iana-if-type:ethernetCsmacd", 0, parent));
        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth5']/"
                "oper-status", "dormant", 0, NULL));
        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth5']/"
                "statistics/discontinuity-time", "2000-01-01T02:00:00-00:00", 0, NULL));
        break;
    case 4:
        assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, ly_ctx, "/ietf-interfaces:interfaces-state/interface[name='eth5']/type",
                "iana-if-type:softwareLoopback", 0, parent));
        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth5']/"
                "oper-status", "dormant", 0, NULL));
        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ietf-interfaces:interfaces-state/interface[name='eth5']/"
                "statistics/discontinuity-time", "2010-01-01T02:00:00-00:00", 0, NULL));
        break;
    default:
        fail();
    }
    sr_release_context(sr_session_get_connection(session));

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static int
cache_diff_change_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
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
    assert_string_equal(xpath, "/ietf-interfaces:*");

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
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
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces-state");

        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces-state/interface[name='eth5']");

        sr_free_val(new_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces-state/interface[name='eth5']/name");

        sr_free_val(new_val);

        /* 5th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces-state/interface[name='eth5']/type");

        sr_free_val(new_val);

        /* 6th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces-state/interface[name='eth5']/oper-status");

        sr_free_val(new_val);

        /* 7th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces-state/interface[name='eth5']/statistics");

        sr_free_val(new_val);

        /* 8th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces-state/interface[name='eth5']/statistics/discontinuity-time");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 3:
        assert_int_equal(event, SR_EV_DONE);

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_MODIFIED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces-state/interface[name='eth5']/oper-status");
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces-state/interface[name='eth5']/oper-status");

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 5:
        assert_int_equal(event, SR_EV_DONE);

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_MODIFIED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces-state/interface[name='eth5']/type");
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces-state/interface[name='eth5']/type");

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_MODIFIED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces-state/interface[name='eth5']/statistics/discontinuity-time");
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces-state/interface[name='eth5']/statistics/discontinuity-time");

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
test_cache_diff(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr1 = NULL, *subscr2 = NULL;
    int ret;

    ATOMIC_STORE_RELAXED(st->cb_called, 0);

    /* subscribe as state data provider */
    ret = sr_oper_get_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", cache_diff_oper_cb,
            st, 0, &subscr1);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe for oper data changes */
    sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:*", cache_diff_change_cb, st, 0,
            SR_SUBSCR_DONE_ONLY, &subscr1);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe for oper poll with diff, no thread */
    ret = sr_oper_poll_subscribe(st->sess, "ietf-interfaces", "/ietf-interfaces:interfaces-state", 1,
            SR_SUBSCR_NO_THREAD | SR_SUBSCR_OPER_POLL_DIFF, &subscr2);
    assert_int_equal(ret, SR_ERR_OK);

    /* update cache #1 */
    usleep(1000);
    ret = sr_subscription_process_events(subscr2, NULL, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* update cache #2 */
    usleep(1000);
    ret = sr_subscription_process_events(subscr2, NULL, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    sr_unsubscribe(subscr1);
    sr_unsubscribe(subscr2);

    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 6);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_yang_lib),
        cmocka_unit_test(test_sr_mon),
        cmocka_unit_test_teardown(test_enabled_partial, clear_up),
        cmocka_unit_test_teardown(test_simple, clear_up),
        cmocka_unit_test_teardown(test_fail, clear_up),
        cmocka_unit_test_teardown(test_config, clear_up),
        cmocka_unit_test_teardown(test_list, clear_up),
        cmocka_unit_test_teardown(test_nested, clear_up),
        cmocka_unit_test_teardown(test_choice, clear_up),
        cmocka_unit_test_teardown(test_invalid, clear_up),
        cmocka_unit_test_teardown(test_mixed, clear_up),
        cmocka_unit_test_teardown(test_xpath_check, clear_up),
        cmocka_unit_test_teardown(test_state_only, clear_up),
        cmocka_unit_test_teardown(test_config_only, clear_up),
        cmocka_unit_test_teardown(test_union, clear_up),
        cmocka_unit_test_teardown(test_conn_owner1, clear_up),
        cmocka_unit_test_teardown(test_conn_owner2, clear_up),
        cmocka_unit_test_teardown(test_conn_owner_same_data, clear_up),
        cmocka_unit_test_teardown(test_stored_state, clear_up),
        cmocka_unit_test_teardown(test_stored_state_list, clear_up),
        cmocka_unit_test_teardown(test_stored_config, clear_up),
        cmocka_unit_test_teardown(test_stored_top_list, clear_up),
        cmocka_unit_test_teardown(test_stored_change_revert, clear_up),
        cmocka_unit_test_teardown(test_stored_edit_ether_diff_remove, clear_up),
        cmocka_unit_test_teardown(test_stored_np_cont1, clear_up),
        cmocka_unit_test_teardown(test_stored_np_cont2, clear_up),
        cmocka_unit_test_teardown(test_stored_edit_merge_leaf, clear_up),
        cmocka_unit_test_teardown(test_stored_diff_merge_userord, clear_up),
        cmocka_unit_test_teardown(test_stored_schema_mount, clear_up),
        cmocka_unit_test_teardown(test_change_cb_stored, clear_up),
        cmocka_unit_test_teardown(test_default_when, clear_up),
        cmocka_unit_test_teardown(test_nested_default, clear_up),
        cmocka_unit_test_teardown(test_disabled_default, clear_up),
        cmocka_unit_test_teardown(test_merge_flag, clear_up),
        cmocka_unit_test_teardown(test_state_default_merge, clear_up),
        cmocka_unit_test_teardown(test_same_xpath, clear_up),
        cmocka_unit_test_teardown(test_same_xpath_parallel, clear_up),
        cmocka_unit_test_teardown(test_same_xpath_fail, clear_up),
        cmocka_unit_test_teardown(test_cache, clear_up),
        cmocka_unit_test_teardown(test_cache_no_sub, clear_up),
        cmocka_unit_test_teardown(test_cache_diff, clear_up),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    test_log_init();
    return cmocka_run_group_tests(tests, setup, teardown);
}
