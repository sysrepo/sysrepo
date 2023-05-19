/**
 * @file test_nacm.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test for NACM
 *
 * @copyright
 * Copyright (c) 2022 Deutsche Telekom AG.
 * Copyright (c) 2022 CESNET, z.s.p.o.
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
#include "utils/netconf_acm.h"

struct state {
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *sub;
};

static int
setup_f(void **state)
{
    struct state *st;
    const char *schema_paths[] = {
        TESTS_SRC_DIR "/files/test.yang",
        NULL
    };

    st = calloc(1, sizeof *st);
    *state = st;

    if (sr_connect(0, &st->conn)) {
        return 1;
    }

    if (sr_install_modules(st->conn, schema_paths, TESTS_SRC_DIR "/files", NULL)) {
        return 1;
    }

    if (sr_session_start(st->conn, SR_DS_RUNNING, &st->sess)) {
        return 1;
    }

    if (sr_nacm_init(st->sess, 0, &st->sub)) {
        return 1;
    }

    return 0;
}

static int
teardown_f(void **state)
{
    struct state *st = (struct state *)*state;
    const char *module_names[] = {
        "test",
        NULL
    };

    sr_remove_modules(st->conn, module_names, 0);

    sr_unsubscribe(st->sub);
    sr_nacm_destroy();
    sr_disconnect(st->conn);
    free(st);
    return 0;
}

/* TEST */
static int
setup_basic_nacm(void **state)
{
    struct state *st = (struct state *)*state;
    const struct ly_ctx *ctx;
    const char *data;
    struct lyd_node *edit;

    /* set some data */
    data = "<cont xmlns=\"urn:test\">\n"
            "  <l2>\n"
            "    <k>k1</k>\n"
            "    <v>10</v>\n"
            "  </l2>\n"
            "  <ll2>25</ll2>\n"
            "</cont>\n";
    ctx = sr_acquire_context(st->conn);
    if (lyd_parse_data_mem(ctx, data, LYD_XML, LYD_PARSE_STRICT | LYD_PARSE_ONLY, 0, &edit)) {
        return 1;
    }
    if (sr_edit_batch(st->sess, edit, "merge")) {
        return 1;
    }
    lyd_free_siblings(edit);
    sr_release_context(st->conn);
    if (sr_apply_changes(st->sess, 0)) {
        return 1;
    }

    /* set user */
    if (sr_nacm_set_user(st->sess, "test-user")) {
        return 1;
    }

    return 0;
}

static int
dummy_rpc_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *xpath, const sr_val_t *input,
        const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt,
        void *private_data)
{
    (void)session;
    (void)sub_id;
    (void)xpath;
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
test_basic(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *sub = NULL;
    sr_data_t *data;
    sr_val_t *output;
    size_t output_cnt;
    char *str;
    int ret;

    /* read some data, allowed by default */
    ret = sr_get_data(st->sess, "/test:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, LY_SUCCESS);
    sr_release_data(data);
    assert_string_equal(str,
            "<cont xmlns=\"urn:test\">\n"
            "  <l2>\n"
            "    <k>k1</k>\n"
            "    <v>10</v>\n"
            "  </l2>\n"
            "  <ll2>25</ll2>\n"
            "</cont>\n");
    free(str);

    /* write some data, disabled by default */
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "10", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_UNAUTHORIZED);
    sr_discard_changes(st->sess);

    /* execute an operation, allowed by default */
    ret = sr_rpc_subscribe(st->sess, "/test:r1", dummy_rpc_cb, NULL, 0, 0, &sub);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_send(st->sess, "/test:r1", NULL, 0, 0, &output, &output_cnt);
    assert_int_equal(ret, SR_ERR_OK);

    /* execute default-deny operation, denied */
    ret = sr_rpc_subscribe(st->sess, "/test:r2", dummy_rpc_cb, NULL, 0, 0, &sub);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_send(st->sess, "/test:r2", NULL, 0, 0, &output, &output_cnt);
    assert_int_equal(ret, SR_ERR_UNAUTHORIZED);

    sr_unsubscribe(sub);
}

/* TEST */
static int
setup_read_nacm(void **state)
{
    struct state *st = (struct state *)*state;
    const struct ly_ctx *ctx;
    const char *data;
    struct lyd_node *edit;

    /* set NACM and some data */
    data = "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <read-default>deny</read-default>\n"
            "  <enable-external-groups>false</enable-external-groups>\n"
            "  <groups>\n"
            "    <group>\n"
            "      <name>test-group</name>\n"
            "      <user-name>test-user</user-name>\n"
            "    </group>\n"
            "  </groups>\n"
            "  <rule-list>\n"
            "    <name>rule1</name>\n"
            "    <group>test-group</group>\n"
            "    <rule>\n"
            "      <name>allow-key</name>\n"
            "      <module-name>test</module-name>\n"
            "      <path xmlns:t=\"urn:test\">/t:cont/t:l2/t:k</path>\n"
            "      <access-operations>read</access-operations>\n"
            "      <action>permit</action>\n"
            "    </rule>\n"
            "  </rule-list>\n"
            "</nacm>\n"
            "<cont xmlns=\"urn:test\">\n"
            "  <l2>\n"
            "    <k>k1</k>\n"
            "    <v>10</v>\n"
            "  </l2>\n"
            "  <ll2>25</ll2>\n"
            "</cont>\n";
    ctx = sr_acquire_context(st->conn);
    if (lyd_parse_data_mem(ctx, data, LYD_XML, LYD_PARSE_STRICT | LYD_PARSE_ONLY, 0, &edit)) {
        return 1;
    }
    if (sr_edit_batch(st->sess, edit, "merge")) {
        return 1;
    }
    lyd_free_siblings(edit);
    sr_release_context(st->conn);
    if (sr_apply_changes(st->sess, 0)) {
        return 1;
    }

    /* set user */
    if (sr_nacm_set_user(st->sess, "test-user")) {
        return 1;
    }

    return 0;
}

static int
teardown_nacm(void **state)
{
    struct state *st = (struct state *)*state;

    /* clear user */
    if (sr_nacm_set_user(st->sess, NULL)) {
        return 1;
    }

    /* clear data */
    if (sr_delete_item(st->sess, "/test:cont", 0)) {
        return 1;
    }
    if (sr_delete_item(st->sess, "/ietf-netconf-acm:nacm", 0)) {
        return 1;
    }
    if (sr_apply_changes(st->sess, 0)) {
        return 1;
    }

    return 0;
}

static void
test_read(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    char *str;
    int ret;

    /* read data #1 */
    ret = sr_get_data(st->sess, "/test:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, LY_SUCCESS);
    sr_release_data(data);
    assert_string_equal(str,
            "<cont xmlns=\"urn:test\">\n"
            "  <l2>\n"
            "    <k>k1</k>\n"
            "  </l2>\n"
            "</cont>\n");
    free(str);

    /* read data #2 */
    ret = sr_get_data(st->sess, "/test:cont/l2", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, LY_SUCCESS);
    sr_release_data(data);
    assert_string_equal(str,
            "<cont xmlns=\"urn:test\">\n"
            "  <l2>\n"
            "    <k>k1</k>\n"
            "  </l2>\n"
            "</cont>\n");
    free(str);

    /* read data #3 */
    ret = sr_get_data(st->sess, "/test:cont/l2/k", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, LY_SUCCESS);
    sr_release_data(data);
    assert_string_equal(str,
            "<cont xmlns=\"urn:test\">\n"
            "  <l2>\n"
            "    <k>k1</k>\n"
            "  </l2>\n"
            "</cont>\n");
    free(str);

    /* read no data */
    ret = sr_get_data(st->sess, "/test:cont/l2/v", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_null(data);
}

/* TEST */
static int
setup_filter_denied_nacm(void **state)
{
    struct state *st = (struct state *)*state;
    const struct ly_ctx *ctx;
    const char *data;
    struct lyd_node *edit;

    /* set NACM and some data */
    data = "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <enable-external-groups>false</enable-external-groups>\n"
            "  <groups>\n"
            "    <group>\n"
            "      <name>test-group</name>\n"
            "      <user-name>test-user</user-name>\n"
            "    </group>\n"
            "  </groups>\n"
            "  <rule-list>\n"
            "    <name>rule1</name>\n"
            "    <group>test-group</group>\n"
            "    <rule>\n"
            "      <name>forbid-v</name>\n"
            "      <module-name>test</module-name>\n"
            "      <path xmlns:t=\"urn:test\">/t:cont/t:l2/t:v</path>\n"
            "      <access-operations>read</access-operations>\n"
            "      <action>deny</action>\n"
            "    </rule>\n"
            "    <rule>\n"
            "      <name>forbid-k2-list</name>\n"
            "      <module-name>test</module-name>\n"
            "      <path xmlns:t=\"urn:test\">/t:cont/t:l2[t:k='k2']</path>\n"
            "      <access-operations>read</access-operations>\n"
            "      <action>deny</action>\n"
            "    </rule>\n"
            "  </rule-list>\n"
            "</nacm>\n"
            "<cont xmlns=\"urn:test\">\n"
            "  <l2>\n"
            "    <k>k1</k>\n"
            "    <v>10</v>\n"
            "  </l2>\n"
            "  <l2>\n"
            "    <k>k2</k>\n"
            "    <v>15</v>\n"
            "  </l2>\n"
            "  <l2>\n"
            "    <k>k3</k>\n"
            "    <v>20</v>\n"
            "  </l2>\n"
            "  <l2>\n"
            "    <k>k4</k>\n"
            "    <v>25</v>\n"
            "  </l2>\n"
            "</cont>\n";
    ctx = sr_acquire_context(st->conn);
    if (lyd_parse_data_mem(ctx, data, LYD_XML, LYD_PARSE_STRICT | LYD_PARSE_ONLY, 0, &edit)) {
        return 1;
    }
    if (sr_edit_batch(st->sess, edit, "merge")) {
        return 1;
    }
    lyd_free_siblings(edit);
    sr_release_context(st->conn);
    if (sr_apply_changes(st->sess, 0)) {
        return 1;
    }

    /* set user */
    if (sr_nacm_set_user(st->sess, "test-user")) {
        return 1;
    }

    return 0;
}

static void
test_filter_denied(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    char *str;
    int ret;

    /* read data #1 filtering based on denied leaf */
    ret = sr_get_data(st->sess, "/test:cont/l2[v < 21]", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, LY_SUCCESS);
    sr_release_data(data);
    assert_string_equal(str,
            "<cont xmlns=\"urn:test\">\n"
            "  <l2>\n"
            "    <k>k1</k>\n"
            "  </l2>\n"
            "  <l2>\n"
            "    <k>k3</k>\n"
            "  </l2>\n"
            "</cont>\n");
    free(str);

    /* read data #1 filtering based on denied leaf */
    ret = sr_get_data(st->sess, "/test:cont/l2[v > 21]", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, LY_SUCCESS);
    sr_release_data(data);
    assert_string_equal(str,
            "<cont xmlns=\"urn:test\">\n"
            "  <l2>\n"
            "    <k>k4</k>\n"
            "  </l2>\n"
            "</cont>\n");
    free(str);

    /* read no data */
    ret = sr_get_data(st->sess, "/test:cont/l2[v = 22]", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_null(data);
}

/* TEST */
static int
setup_write_nacm(void **state)
{
    struct state *st = (struct state *)*state;
    const struct ly_ctx *ctx;
    const char *data;
    struct lyd_node *edit;

    /* set NACM and some data */
    data = "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <enable-external-groups>false</enable-external-groups>\n"
            "  <groups>\n"
            "    <group>\n"
            "      <name>test-group</name>\n"
            "      <user-name>test-user</user-name>\n"
            "    </group>\n"
            "  </groups>\n"
            "  <rule-list>\n"
            "    <name>rule1</name>\n"
            "    <group>test-group</group>\n"
            "    <rule>\n"
            "      <name>deny-list-v</name>\n"
            "      <module-name>test</module-name>\n"
            "      <path xmlns:t=\"urn:test\">/t:cont/t:l2/t:v</path>\n"
            "      <access-operations>create update</access-operations>\n"
            "      <action>deny</action>\n"
            "    </rule>\n"
            "    <rule>\n"
            "      <name>allow-list-create</name>\n"
            "      <module-name>test</module-name>\n"
            "      <path xmlns:t=\"urn:test\">/t:cont/t:l2</path>\n"
            "      <access-operations>create delete</access-operations>\n"
            "      <action>permit</action>\n"
            "    </rule>\n"
            "  </rule-list>\n"
            "</nacm>\n"
            "<cont xmlns=\"urn:test\">\n"
            "  <l2>\n"
            "    <k>k1</k>\n"
            "    <v>10</v>\n"
            "  </l2>\n"
            "  <ll2>25</ll2>\n"
            "</cont>\n";
    ctx = sr_acquire_context(st->conn);
    if (lyd_parse_data_mem(ctx, data, LYD_XML, LYD_PARSE_STRICT | LYD_PARSE_ONLY, 0, &edit)) {
        return 1;
    }
    if (sr_edit_batch(st->sess, edit, "merge")) {
        return 1;
    }
    lyd_free_siblings(edit);
    sr_release_context(st->conn);
    if (sr_apply_changes(st->sess, 0)) {
        return 1;
    }

    /* set user */
    if (sr_nacm_set_user(st->sess, "test-user")) {
        return 1;
    }

    return 0;
}

static void
test_write(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    char *str;
    int ret;

    /* create list permit */
    ret = sr_set_item_str(st->sess, "/test:cont/l2[k='k2']", NULL, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* create list v deny */
    ret = sr_set_item_str(st->sess, "/test:cont/l2[k='k2']/v", "15", 0, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_UNAUTHORIZED);
    sr_discard_changes(st->sess);

    /* update list v deny */
    ret = sr_set_item_str(st->sess, "/test:cont/l2[k='k1']/v", "15", 0, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_UNAUTHORIZED);
    sr_discard_changes(st->sess);

    /* read data */
    ret = sr_get_data(st->sess, "/test:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, LY_SUCCESS);
    sr_release_data(data);
    assert_string_equal(str,
            "<cont xmlns=\"urn:test\">\n"
            "  <l2>\n"
            "    <k>k1</k>\n"
            "    <v>10</v>\n"
            "  </l2>\n"
            "  <l2>\n"
            "    <k>k2</k>\n"
            "  </l2>\n"
            "  <ll2>25</ll2>\n"
            "</cont>\n");
    free(str);

    /* delete list permit */
    ret = sr_delete_item(st->sess, "/test:cont/l2[k='k1']", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* delete leaf-list deny */
    ret = sr_delete_item(st->sess, "/test:cont/ll2[.='25']", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_UNAUTHORIZED);
    sr_discard_changes(st->sess);

    /* read data */
    ret = sr_get_data(st->sess, "/test:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, LY_SUCCESS);
    sr_release_data(data);
    assert_string_equal(str,
            "<cont xmlns=\"urn:test\">\n"
            "  <l2>\n"
            "    <k>k2</k>\n"
            "  </l2>\n"
            "  <ll2>25</ll2>\n"
            "</cont>\n");
    free(str);
}

/* TEST */
static int
setup_exec_nacm(void **state)
{
    struct state *st = (struct state *)*state;
    const struct ly_ctx *ctx;
    const char *data;
    struct lyd_node *edit;

    /* set NACM and some data */
    data = "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <exec-default>deny</exec-default>\n"
            "  <enable-external-groups>false</enable-external-groups>\n"
            "  <groups>\n"
            "    <group>\n"
            "      <name>test-group</name>\n"
            "      <user-name>test-user</user-name>\n"
            "    </group>\n"
            "  </groups>\n"
            "  <rule-list>\n"
            "    <name>rule1</name>\n"
            "    <group>test-group</group>\n"
            "    <rule>\n"
            "      <name>allow-r2</name>\n"
            "      <module-name>test</module-name>\n"
            "      <rpc-name>r2</rpc-name>\n"
            "      <access-operations>exec</access-operations>\n"
            "      <action>permit</action>\n"
            "    </rule>\n"
            "  </rule-list>\n"
            "</nacm>\n";
    ctx = sr_acquire_context(st->conn);
    if (lyd_parse_data_mem(ctx, data, LYD_XML, LYD_PARSE_STRICT | LYD_PARSE_ONLY, 0, &edit)) {
        return 1;
    }
    if (sr_edit_batch(st->sess, edit, "merge")) {
        return 1;
    }
    lyd_free_siblings(edit);
    sr_release_context(st->conn);
    if (sr_apply_changes(st->sess, 0)) {
        return 1;
    }

    /* set user */
    if (sr_nacm_set_user(st->sess, "test-user")) {
        return 1;
    }

    return 0;
}

static void
test_exec(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *sub = NULL;
    sr_val_t *output;
    size_t output_cnt;
    int ret;

    /* deny r1 exec */
    ret = sr_rpc_subscribe(st->sess, "/test:r1", dummy_rpc_cb, NULL, 0, 0, &sub);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_send(st->sess, "/test:r1", NULL, 0, 0, &output, &output_cnt);
    assert_int_equal(ret, SR_ERR_UNAUTHORIZED);

    /* allow r2 exec */
    ret = sr_rpc_subscribe(st->sess, "/test:r2", dummy_rpc_cb, NULL, 0, 0, &sub);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_send(st->sess, "/test:r2", NULL, 0, 0, &output, &output_cnt);
    assert_int_equal(ret, SR_ERR_OK);

    sr_unsubscribe(sub);
}

/* TEST */
static int
setup_read_var_nacm(void **state)
{
    struct state *st = (struct state *)*state;
    const struct ly_ctx *ctx;
    const char *data;
    struct lyd_node *edit;

    /* set NACM and some data */
    data = "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <read-default>deny</read-default>\n"
            "  <enable-external-groups>false</enable-external-groups>\n"
            "  <groups>\n"
            "    <group>\n"
            "      <name>test-group</name>\n"
            "      <user-name>test-user</user-name>\n"
            "    </group>\n"
            "  </groups>\n"
            "  <rule-list>\n"
            "    <name>rule1</name>\n"
            "    <group>test-group</group>\n"
            "    <rule>\n"
            "      <name>allow-user-key</name>\n"
            "      <module-name>test</module-name>\n"
            "      <path xmlns:t=\"urn:test\">/t:cont/t:l2[t:k=$USER]</path>\n"
            "      <access-operations>read</access-operations>\n"
            "      <action>permit</action>\n"
            "    </rule>\n"
            "  </rule-list>\n"
            "</nacm>\n"
            "<cont xmlns=\"urn:test\">\n"
            "  <l2>\n"
            "    <k>test-user</k>\n"
            "    <v>10</v>\n"
            "  </l2>\n"
            "  <l2>\n"
            "    <k>test-user2</k>\n"
            "    <v>15</v>\n"
            "  </l2>\n"
            "  <l2>\n"
            "    <k>test-user3</k>\n"
            "    <v>20</v>\n"
            "  </l2>\n"
            "  <ll2>25</ll2>\n"
            "</cont>\n";
    ctx = sr_acquire_context(st->conn);
    if (lyd_parse_data_mem(ctx, data, LYD_XML, LYD_PARSE_STRICT | LYD_PARSE_ONLY, 0, &edit)) {
        return 1;
    }
    if (sr_edit_batch(st->sess, edit, "merge")) {
        return 1;
    }
    lyd_free_siblings(edit);
    sr_release_context(st->conn);
    if (sr_apply_changes(st->sess, 0)) {
        return 1;
    }

    /* set user */
    if (sr_nacm_set_user(st->sess, "test-user")) {
        return 1;
    }

    return 0;
}

static void
test_read_var(void **state)
{
    struct state *st = (struct state *)*state;
    sr_data_t *data;
    char *str;
    int ret;

    /* read data #1 */
    ret = sr_get_data(st->sess, "/test:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, LY_SUCCESS);
    sr_release_data(data);
    assert_string_equal(str,
            "<cont xmlns=\"urn:test\">\n"
            "  <l2>\n"
            "    <k>test-user</k>\n"
            "    <v>10</v>\n"
            "  </l2>\n"
            "</cont>\n");
    free(str);

    /* read data #2 */
    ret = sr_get_data(st->sess, "/test:cont/l2", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, LY_SUCCESS);
    sr_release_data(data);
    assert_string_equal(str,
            "<cont xmlns=\"urn:test\">\n"
            "  <l2>\n"
            "    <k>test-user</k>\n"
            "    <v>10</v>\n"
            "  </l2>\n"
            "</cont>\n");
    free(str);

    /* read data #3 */
    ret = sr_get_data(st->sess, "/test:cont/l2/k", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, LY_SUCCESS);
    sr_release_data(data);
    assert_string_equal(str,
            "<cont xmlns=\"urn:test\">\n"
            "  <l2>\n"
            "    <k>test-user</k>\n"
            "  </l2>\n"
            "</cont>\n");
    free(str);

    /* read data #4 */
    ret = sr_get_data(st->sess, "/test:cont/l2/v", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, LY_SUCCESS);
    sr_release_data(data);
    assert_string_equal(str,
            "<cont xmlns=\"urn:test\">\n"
            "  <l2>\n"
            "    <k>test-user</k>\n"
            "    <v>10</v>\n"
            "  </l2>\n"
            "</cont>\n");
    free(str);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_basic, setup_basic_nacm, teardown_nacm),
        cmocka_unit_test_setup_teardown(test_read, setup_read_nacm, teardown_nacm),
        cmocka_unit_test_setup_teardown(test_filter_denied, setup_filter_denied_nacm, teardown_nacm),
        cmocka_unit_test_setup_teardown(test_write, setup_write_nacm, teardown_nacm),
        cmocka_unit_test_setup_teardown(test_exec, setup_exec_nacm, teardown_nacm),
        cmocka_unit_test_setup_teardown(test_read_var, setup_read_var_nacm, teardown_nacm),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    test_log_init();
    return cmocka_run_group_tests(tests, setup_f, teardown_f);
}
