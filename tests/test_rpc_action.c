/**
 * @file test_rpc_action.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test for sending/receiving RPCs/actions
 *
 * @copyright
 * Copyright (c) 2018 - 2023 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2023 CESNET, z.s.p.o.
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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "common.h"
#include "sysrepo.h"
#include "tests/tcommon.h"
#include "utils/values.h"

struct state {
    sr_conn_ctx_t *conn;
    const struct ly_ctx *ly_ctx;
    sr_session_ctx_t *sess;
    ATOMIC_T cb_called;
    ATOMIC_T cb2_called;
    pthread_barrier_t barrier;
};

static int
setup(void **state)
{
    struct state *st;
    uint32_t nc_id;
    const char *ops_ref_feats[] = {"feat1", NULL}, *act_feats[] = {"advanced-testing", NULL}, *init_data;
    sr_install_mod_t new_mods[] = {
        {.schema_path = TESTS_SRC_DIR "/files/test.yang"},
        {.schema_path = TESTS_SRC_DIR "/files/ietf-interfaces.yang"},
        {.schema_path = TESTS_SRC_DIR "/files/iana-if-type.yang"},
        {.schema_path = TESTS_SRC_DIR "/files/ops-ref.yang", .features = ops_ref_feats},
        {.schema_path = TESTS_SRC_DIR "/files/ops.yang"},
        {.schema_path = TESTS_SRC_DIR "/files/act.yang", .features = act_feats},
        {.schema_path = TESTS_SRC_DIR "/files/act2.yang"},
        {.schema_path = TESTS_SRC_DIR "/files/act3.yang"},
        {.schema_path = TESTS_SRC_DIR "/files/sm.yang"},
    };

    st = calloc(1, sizeof *st);
    *state = st;

    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ATOMIC_STORE_RELAXED(st->cb2_called, 0);
    pthread_barrier_init(&st->barrier, NULL, 2);

    if (sr_connect(0, &(st->conn))) {
        return 1;
    }

    /* set factory-default data */
    init_data =
            "<test-leaf xmlns=\"urn:test\">1</test-leaf>\n"
            "<cont xmlns=\"urn:test\">\n"
            "  <l2>\n"
            "    <k>key</k>\n"
            "    <v>5</v>\n"
            "  </l2>\n"
            "</cont>\n"
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
            "  <interface>\n"
            "    <name>bu</name>\n"
            "    <type xmlns:ii=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ii:ethernetCsmacd</type>\n"
            "  </interface>\n"
            "</interfaces>\n";
    if (sr_install_modules2(st->conn, new_mods, 9, TESTS_SRC_DIR "/files", init_data, NULL, LYD_XML)) {
        return 1;
    }

    st->ly_ctx = sr_acquire_context(st->conn);

    if (sr_session_start(st->conn, SR_DS_RUNNING, &st->sess)) {
        return 1;
    }

    /* clear running DS */
    if (sr_delete_item(st->sess, "/test:test-leaf", 0)) {
        return 1;
    }
    if (sr_delete_item(st->sess, "/test:cont", 0)) {
        return 1;
    }
    if (sr_delete_item(st->sess, "/ietf-interfaces:interfaces", 0)) {
        return 1;
    }
    if (sr_apply_changes(st->sess, 0)) {
        return 1;
    }

    sr_session_set_orig_name(st->sess, "test_rpc_action");
    nc_id = 128;
    sr_session_push_orig_data(st->sess, sizeof nc_id, &nc_id);

    return 0;
}

static int
teardown(void **state)
{
    struct state *st = (struct state *)*state;
    int ret = 0;
    const char *module_names[] = {
        "sm",
        "act3",
        "act2",
        "act",
        "ops",
        "ops-ref",
        "iana-if-type",
        "ietf-interfaces",
        "test",
        NULL
    };

    if (st->ly_ctx) {
        sr_release_context(st->conn);
    }

    ret += sr_remove_modules(st->conn, module_names, 0);

    sr_disconnect(st->conn);
    pthread_barrier_destroy(&st->barrier);
    free(st);
    return ret;
}

static int
clear_ops(void **state)
{
    struct state *st = (struct state *)*state;

    sr_delete_item(st->sess, "/ops-ref:l1", 0);
    sr_delete_item(st->sess, "/ops-ref:l2", 0);
    sr_delete_item(st->sess, "/ops:cont", 0);
    sr_apply_changes(st->sess, 0);

    return 0;
}

/* TEST */
static int
rpc_fail_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *xpath, const struct lyd_node *input, sr_event_t event,
        uint32_t request_id, struct lyd_node *output, void *private_data)
{
    char *str1;
    const char *str2;
    int ret;
    uint32_t size;
    const uint32_t *nc_id;

    (void)sub_id;
    (void)event;
    (void)request_id;
    (void)output;
    (void)private_data;

    assert_string_equal(sr_session_get_orig_name(session), "test_rpc_action");
    assert_int_equal(sr_session_get_orig_data(session, 0, &size, (const void **)&nc_id), SR_ERR_OK);
    assert_int_equal(size, sizeof *nc_id);
    assert_int_equal(*nc_id, 128);
    assert_int_equal(sr_session_get_orig_data(session, 1, &size, (const void **)&nc_id), SR_ERR_NOT_FOUND);
    assert_string_equal(xpath, "/ops:rpc1");

    /* check input data tree */
    ret = lyd_print_mem(&str1, input, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    str2 = "<rpc1 xmlns=\"urn:ops\"/>";

    assert_string_equal(str1, str2);
    free(str1);

    /* error */
    sr_session_set_error_message(session, "RPC FAIL");
    return SR_ERR_SYS;
}

static void
test_fail(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr = NULL;
    const sr_error_info_t *err_info = NULL;
    struct lyd_node *input;
    sr_data_t *output;
    int ret;

    /* subscribe */
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:rpc1", rpc_fail_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* send RPC */
    assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, st->ly_ctx, "/ops:rpc1", NULL, 0, &input));

    /* expect an error */
    ret = sr_rpc_send_tree(st->sess, input, 0, &output);
    lyd_free_all(input);
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);
    ret = sr_session_get_error(st->sess, &err_info);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(err_info->err_count, 2);
    assert_int_equal(err_info->err[0].err_code, SR_ERR_SYS);
    assert_string_equal(err_info->err[0].message, "RPC FAIL");
    assert_null(err_info->err[0].error_format);
    assert_null(output);

    /* try to send an action */
    assert_int_equal(LY_SUCCESS, lyd_new_path2(NULL, st->ly_ctx, "/ops:cont/list1[k='1']/cont2/act1", NULL,
            0, 0, 0, NULL, &input));

    ret = sr_rpc_send_tree(st->sess, input, 0, &output);
    lyd_free_all(input);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
rpc_rpc_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *xpath, const sr_val_t *input, const size_t input_cnt,
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
    static int rpc2_called = 0;

    (void)session;
    (void)sub_id;
    (void)event;
    (void)request_id;
    (void)private_data;

    if (!strcmp(xpath, "/ops:rpc1")) {
        /* check input data */
        assert_int_equal(input_cnt, 2);
        assert_string_equal(input[0].xpath, "/ops:rpc1/l1");
        assert_string_equal(input[1].xpath, "/ops:rpc1/l2");
        assert_int_equal(input[1].dflt, 1);

        /* create (empty) output data */
    } else if (!strcmp(xpath, "/ops:rpc2")) {
        /* check (empty) input data tree */
        assert_int_equal(input_cnt, 0);

        if (rpc2_called == 0) {
            /* create (invalid) output data */
            *output_cnt = 1;
            *output = calloc(*output_cnt, sizeof **output);

            (*output)[0].xpath = strdup("/ops:rpc2/cont/l3");
            (*output)[0].type = SR_STRING_T;
            (*output)[0].data.string_val = strdup("inval-ref");
        } else if (rpc2_called == 1) {
            /* create output data */
            *output_cnt = 1;
            *output = calloc(*output_cnt, sizeof **output);

            (*output)[0].xpath = strdup("/ops:rpc2/cont/l3");
            (*output)[0].type = SR_STRING_T;
            (*output)[0].data.string_val = strdup("l2-val");
        } else {
            fail();
        }
        ++rpc2_called;
    } else if (!strcmp(xpath, "/ops:rpc3")) {
        /* check input data */
        assert_int_equal(input_cnt, 1);
        assert_string_equal(input[0].xpath, "/ops:rpc3/l4");

        /* create output data */
        *output_cnt = 1;
        *output = calloc(*output_cnt, sizeof **output);

        (*output)[0].xpath = strdup("/ops:rpc3/l5");
        (*output)[0].type = SR_UINT16_T;
        (*output)[0].data.uint16_val = 256;
    } else {
        fail();
    }

    return SR_ERR_OK;
}

static int
module_change_dummy_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
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

static void
test_rpc(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr = NULL;
    const sr_error_info_t *err_info = NULL;
    sr_val_t input, *output;
    size_t output_count;
    int ret;

    /* subscribe */
    ret = sr_rpc_subscribe(st->sess, "/ops:rpc1", rpc_rpc_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe(st->sess, "/ops:rpc2", rpc_rpc_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe(st->sess, "/ops:rpc3", rpc_rpc_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some data needed for validation */
    ret = sr_set_item_str(st->sess, "/ops-ref:l1", "l1-val", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ops-ref:l2", "l2-val", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /*
     * create first RPC
     */
    input.xpath = "/ops:rpc1/l1";
    input.type = SR_STRING_T;
    input.data.string_val = "l1-val";
    input.dflt = 0;

    /* try to send first RPC, expect an error */
    ret = sr_rpc_send(st->sess, "/ops:rpc1", &input, 1, 0, &output, &output_count);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);
    ret = sr_session_get_error(st->sess, &err_info);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(err_info->err_count, 2);
    assert_string_equal(err_info->err[0].message, "Invalid leafref value \"l1-val\" - no target instance \"/or:l1\" with the same value. "
            "(Data location \"/ops:rpc1/l1\".)");
    assert_null(err_info->err[0].error_format);
    assert_string_equal(err_info->err[1].message, "RPC input validation failed.");
    assert_null(err_info->err[1].error_format);
    assert_null(output);
    assert_int_equal(output_count, 0);

    /* subscribe to the data so they are actually present in operational */
    ret = sr_module_change_subscribe(st->sess, "ops-ref", NULL, module_change_dummy_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* try to send first RPC again, now should succeed */
    ret = sr_rpc_send(st->sess, "/ops:rpc1", &input, 1, 0, &output, &output_count);
    assert_int_equal(ret, SR_ERR_OK);

    /* check output data tree */
    assert_null(output);
    assert_int_equal(output_count, 0);

    /*
     * create second RPC (no input)
     */

    /* try to send second RPC, expect an error */
    ret = sr_rpc_send(st->sess, "/ops:rpc2", NULL, 0, 0, &output, &output_count);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);
    ret = sr_session_get_error(st->sess, &err_info);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(err_info->err_count, 2);
    assert_string_equal(err_info->err[0].message, "Invalid leafref value \"inval-ref\" - no target instance \"/or:l2\" "
            "with the same value. (Data location \"/ops:rpc2/cont/l3\".)");
    assert_null(err_info->err[0].error_format);
    assert_string_equal(err_info->err[1].message, "RPC output validation failed.");
    assert_null(err_info->err[1].error_format);

    /* try to send second RPC again, should succeed now */
    ret = sr_rpc_send(st->sess, "/ops:rpc2", NULL, 0, 0, &output, &output_count);
    assert_int_equal(ret, SR_ERR_OK);

    /* check output data tree */
    assert_non_null(output);
    assert_int_equal(output_count, 2);

    assert_string_equal(output[0].xpath, "/ops:rpc2/cont");
    assert_string_equal(output[1].xpath, "/ops:rpc2/cont/l3");
    assert_string_equal(output[1].data.string_val, "l2-val");

    sr_free_values(output, output_count);

    /*
     * create third RPC
     */
    input.xpath = "/ops:rpc3/l4";
    input.type = SR_STRING_T;
    input.data.string_val = "some-val";
    input.dflt = 0;

    /* send third RPC */
    ret = sr_rpc_send(st->sess, "/ops:rpc3", &input, 1, 0, &output, &output_count);
    assert_int_equal(ret, SR_ERR_OK);

    /* check output data tree */
    assert_non_null(output);
    assert_int_equal(output_count, 1);

    assert_string_equal(output[0].xpath, "/ops:rpc3/l5");
    assert_int_equal(output[0].data.uint16_val, 256);

    sr_free_values(output, output_count);

    /*
     * try to send a non-existing RPC, expect an error
     */
    ret = sr_rpc_send(st->sess, "/ops:invalid", &input, 1, 0, &output, &output_count);
    assert_int_equal(ret, SR_ERR_LY);
    ret = sr_session_get_error(st->sess, &err_info);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(err_info->err_count, 1);
    assert_string_equal(err_info->err[0].message, "Not found node \"invalid\" in path.");
    assert_null(output);
    assert_int_equal(output_count, 0);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
rpc_action_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data)
{
    struct lyd_node *node;
    char *str1;
    const char *str2;
    LY_ERR ret;

    (void)session;
    (void)sub_id;
    (void)event;
    (void)request_id;
    (void)private_data;

    if (!strcmp(op_path, "/ops:cont/list1/cont2/act1")) {
        /* check input data */
        ret = lyd_print_mem(&str1, input, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
        assert_int_equal(ret, LY_SUCCESS);
        str2 = "<act1 xmlns=\"urn:ops\"><l6>val</l6><l7>val</l7></act1>";
        assert_string_equal(str1, str2);
        free(str1);

        /* create output data */
        assert_int_equal(LY_SUCCESS, lyd_new_path(output, NULL, "l9", "l12-val", LYD_NEW_PATH_OUTPUT, &node));
    } else if (!strcmp(op_path, "/ops:cont/list1/act2")) {
        /* check input data */
        ret = lyd_print_mem(&str1, input, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
        assert_int_equal(ret, LY_SUCCESS);
        str2 = "<act2 xmlns=\"urn:ops\"><l10>e3</l10></act2>";
        assert_string_equal(str1, str2);
        free(str1);

        /* create output data */
        assert_int_equal(LY_SUCCESS, lyd_new_path(output, NULL, "l11", "-65536", LYD_NEW_PATH_OUTPUT, &node));
    } else {
        fail();
    }

    return SR_ERR_OK;
}

static void
test_action(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr = NULL;
    struct lyd_node *input_op;
    sr_data_t *output_op;
    char *str1;
    const char *str2;
    int ret;

    /* subscribe */
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:cont/list1/cont2/act1", rpc_action_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:cont/list1/act2", rpc_action_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some data needed for validation and executing the actions */
    ret = sr_set_item_str(st->sess, "/ops:cont/list1[k='key']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ops:cont/l12", "l12-val", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to the data so they are actually present in operational */
    ret = sr_module_change_subscribe(st->sess, "ops", NULL, module_change_dummy_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /*
     * create first action
     */
    assert_int_equal(LY_SUCCESS, lyd_new_path2(NULL, st->ly_ctx, "/ops:cont/list1[k='key']/cont2/act1",
            NULL, 0, 0, 0, NULL, &input_op));
    assert_non_null(input_op);
    assert_int_equal(LY_SUCCESS, lyd_new_path(input_op, NULL, "l6", "val", 0, NULL));
    assert_int_equal(LY_SUCCESS, lyd_new_path(input_op, NULL, "l7", "val", 0, NULL));

    /* send first action */
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    lyd_free_all(input_op);
    assert_int_equal(ret, SR_ERR_OK);

    /* check output data tree */
    assert_non_null(output_op);
    ret = lyd_print_mem(&str1, output_op->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    sr_release_data(output_op);
    assert_int_equal(ret, 0);
    str2 = "<act1 xmlns=\"urn:ops\"><l9>l12-val</l9></act1>";
    assert_string_equal(str1, str2);
    free(str1);

    /*
     * create second action
     */
    assert_int_equal(LY_SUCCESS, lyd_new_path2(NULL, st->ly_ctx, "/ops:cont/list1[k='key']/act2", NULL, 0,
            0, 0, NULL, &input_op));
    assert_int_equal(LY_SUCCESS, lyd_new_path(input_op, NULL, "l10", "e3", 0, NULL));

    /* send second action */
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    lyd_free_all(input_op);
    assert_int_equal(ret, SR_ERR_OK);

    /* check output data tree */
    assert_non_null(output_op);
    ret = lyd_print_mem(&str1, output_op->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    sr_release_data(output_op);
    assert_int_equal(ret, 0);
    str2 = "<act2 xmlns=\"urn:ops\"><l11>-65536</l11></act2>";
    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
rpc_action_pred_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data)
{
    char *str1;
    const char *str2;
    LY_ERR ret;

    (void)session;
    (void)sub_id;
    (void)event;
    (void)request_id;
    (void)output;
    (void)private_data;

    if (!strcmp(op_path, "/ops:cont/list1[k='one' or k='two']/cont2/act1")) {
        /* check input data */
        ret = lyd_print_mem(&str1, input, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
        assert_int_equal(ret, 0);
        str2 = "<act1 xmlns=\"urn:ops\"><l6>val2</l6><l7>val2</l7></act1>";
        assert_string_equal(str1, str2);
        free(str1);
    } else if (!strcmp(op_path, "/ops:cont/list1[k='three' or k='four']/cont2/act1")) {
        /* check input data */
        ret = lyd_print_mem(&str1, input, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
        assert_int_equal(ret, 0);
        str2 = "<act1 xmlns=\"urn:ops\"><l6>val3</l6><l7>val3</l7></act1>";
        assert_string_equal(str1, str2);
        free(str1);
    } else {
        fail();
    }

    return SR_ERR_OK;
}

static void
test_action_pred(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr = NULL;
    struct lyd_node *input_op;
    sr_data_t *output_op;
    int ret;

    /* you cannot subscribe to more actions */
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:cont/list1/cont2/act1 or /ops:rpc1", rpc_action_pred_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_LY);

    /* subscribe with some predicates */
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:cont/list1[k='one' or k='two']/cont2/act1", rpc_action_pred_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:cont/list1[k='three' or k='four']/cont2/act1", rpc_action_pred_cb, NULL,
            1, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some data needed for validation and executing the actions */
    ret = sr_set_item_str(st->sess, "/ops:cont/list1[k='zero']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ops:cont/list1[k='one']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ops:cont/list1[k='two']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ops:cont/list1[k='three']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ops:cont/list1[k='key']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to the data so they are actually present in operational */
    ret = sr_module_change_subscribe(st->sess, "ops", NULL, module_change_dummy_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /*
     * create first action
     */
    assert_int_equal(LY_SUCCESS, lyd_new_path2(NULL, st->ly_ctx, "/ops:cont/list1[k='zero']/cont2/act1",
            NULL, 0, 0, 0, NULL, &input_op));
    assert_int_equal(LY_SUCCESS, lyd_new_path(input_op, NULL, "l6", "val", 0, NULL));
    assert_int_equal(LY_SUCCESS, lyd_new_path(input_op, NULL, "l7", "val", 0, NULL));

    /* send action, fails */
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    lyd_free_all(input_op);
    assert_int_equal(ret, SR_ERR_UNSUPPORTED);

    /*
     * create second action
     */
    assert_int_equal(LY_SUCCESS, lyd_new_path2(NULL, st->ly_ctx, "/ops:cont/list1[k='one']/cont2/act1",
            NULL, 0, 0, 0, NULL, &input_op));
    assert_int_equal(LY_SUCCESS, lyd_new_path(input_op, NULL, "l6", "val2", 0, NULL));
    assert_int_equal(LY_SUCCESS, lyd_new_path(input_op, NULL, "l7", "val2", 0, NULL));

    /* send action, should be fine */
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    lyd_free_all(input_op);
    sr_release_data(output_op);

    assert_int_equal(ret, SR_ERR_OK);

    /*
     * create third action
     */
    assert_int_equal(LY_SUCCESS, lyd_new_path2(NULL, st->ly_ctx, "/ops:cont/list1[k='three']/cont2/act1",
            NULL, 0, 0, 0, NULL, &input_op));
    assert_int_equal(LY_SUCCESS, lyd_new_path(input_op, NULL, "l6", "val3", 0, NULL));
    assert_int_equal(LY_SUCCESS, lyd_new_path(input_op, NULL, "l7", "val3", 0, NULL));

    /* send action, should be fine */
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    lyd_free_all(input_op);
    sr_release_data(output_op);

    assert_int_equal(ret, SR_ERR_OK);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
rpc_multi_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data)
{
    struct state *st = (struct state *)private_data;

    (void)session;
    (void)sub_id;
    (void)op_path;
    (void)input;
    (void)event;
    (void)request_id;
    (void)output;

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void
test_multi(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr = NULL;
    struct lyd_node *input_op;
    sr_data_t *output_op;
    int ret;

    /* subscribe */
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:cont/list1/cont2/act1", rpc_multi_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:cont/list1[k='one' or k='two']/cont2/act1", rpc_multi_cb, st,
            1, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:cont/list1[k='two' or k='three' or k='four']/cont2/act1",
            rpc_multi_cb, st, 2, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some data needed for validation and executing the actions */
    ret = sr_set_item_str(st->sess, "/ops:cont/list1[k='zero']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ops:cont/list1[k='one']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ops:cont/list1[k='two']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ops:cont/list1[k='three']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ops:cont/list1[k='key']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to the data so they are actually present in operational */
    ret = sr_module_change_subscribe(st->sess, "ops", NULL, module_change_dummy_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /*
     * create first action
     */
    assert_int_equal(LY_SUCCESS, lyd_new_path2(NULL, st->ly_ctx, "/ops:cont/list1[k='zero']/cont2/act1",
            NULL, 0, 0, 0, NULL, &input_op));
    assert_int_equal(LY_SUCCESS, lyd_new_path(input_op, NULL, "l6", "val", 0, NULL));
    assert_int_equal(LY_SUCCESS, lyd_new_path(input_op, NULL, "l7", "val", 0, NULL));

    /* send action */
    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    lyd_free_all(input_op);
    sr_release_data(output_op);

    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 1);

    /*
     * create second action
     */
    assert_int_equal(LY_SUCCESS, lyd_new_path2(NULL, st->ly_ctx, "/ops:cont/list1[k='one']/cont2/act1",
            NULL, 0, 0, 0, NULL, &input_op));
    assert_int_equal(LY_SUCCESS, lyd_new_path(input_op, NULL, "l6", "val2", 0, NULL));
    assert_int_equal(LY_SUCCESS, lyd_new_path(input_op, NULL, "l7", "val2", 0, NULL));

    /* send action */
    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    lyd_free_all(input_op);
    sr_release_data(output_op);

    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 2);

    /*
     * create third action
     */
    assert_int_equal(LY_SUCCESS, lyd_new_path2(NULL, st->ly_ctx, "/ops:cont/list1[k='two']/cont2/act1",
            NULL, 0, 0, 0, NULL, &input_op));
    assert_int_equal(LY_SUCCESS, lyd_new_path(input_op, NULL, "l6", "val3", 0, NULL));
    assert_int_equal(LY_SUCCESS, lyd_new_path(input_op, NULL, "l7", "val3", 0, NULL));

    /* send action */
    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    lyd_free_all(input_op);
    sr_release_data(output_op);

    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 3);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
rpc_multi_fail0_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data)
{
    struct state *st = (struct state *)private_data;
    static int call_no = 1;
    int ret = SR_ERR_OK;

    (void)session;
    (void)sub_id;
    (void)op_path;
    (void)input;
    (void)request_id;

    ATOMIC_INC_RELAXED(st->cb_called);

    /* create output data in all cases, it should always be freed */
    assert_int_equal(LY_SUCCESS, lyd_new_path(output, NULL, "l5", "0", LYD_NEW_PATH_OUTPUT, NULL));

    switch (call_no) {
    case 1:
        assert_int_equal(event, SR_EV_RPC);
        assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 3);
        /* callback fails */
        ret = SR_ERR_NO_MEMORY;
        ++call_no;
        break;
    case 2:
        assert_int_equal(event, SR_EV_RPC);
        assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 3);
        ++call_no;
        break;
    default:
        fail();
    }

    return ret;
}

static int
rpc_multi_fail1_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data)
{
    struct state *st = (struct state *)private_data;
    static int call_no = 1;
    int ret = SR_ERR_OK;

    (void)session;
    (void)sub_id;
    (void)op_path;
    (void)input;
    (void)request_id;

    ATOMIC_INC_RELAXED(st->cb_called);

    /* create output data in all cases, it should always be freed */
    assert_int_equal(LY_SUCCESS, lyd_new_path(output, NULL, "l5", "1", LYD_NEW_PATH_OUTPUT, NULL));

    switch (call_no) {
    case 1:
        if (event == SR_EV_RPC) {
            assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 2);
        } else {
            assert_int_equal(event, SR_EV_ABORT);
            assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 5);
            ++call_no;
        }
        break;
    case 2:
        assert_int_equal(event, SR_EV_RPC);
        assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 2);
        /* callback fails */
        ret = SR_ERR_NOT_FOUND;
        ++call_no;
        break;
    case 3:
        assert_int_equal(event, SR_EV_RPC);
        assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 2);
        ++call_no;
        break;
    default:
        fail();
    }

    return ret;
}

static int
rpc_multi_fail2_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data)
{
    struct state *st = (struct state *)private_data;
    static int call_no = 1;
    int ret = SR_ERR_OK;

    (void)session;
    (void)sub_id;
    (void)op_path;
    (void)input;
    (void)request_id;

    ATOMIC_INC_RELAXED(st->cb_called);

    /* create output data in all cases, it should always be freed */
    assert_int_equal(LY_SUCCESS, lyd_new_path(output, NULL, "l5", "2", LYD_NEW_PATH_OUTPUT, NULL));

    switch (call_no) {
    case 1:
        if (event == SR_EV_RPC) {
            assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 1);
        } else {
            assert_int_equal(event, SR_EV_ABORT);
            assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 4);
            ++call_no;
        }
        break;
    case 2:
        if (event == SR_EV_RPC) {
            assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 1);
        } else {
            assert_int_equal(event, SR_EV_ABORT);
            assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 3);
            ++call_no;
        }
        break;
    case 3:
        assert_int_equal(event, SR_EV_RPC);
        assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 1);
        /* callback fails, last callback (but there is no callback for abort, synchronizing would block) */
        ret = SR_ERR_LOCKED;
        ++call_no;
        break;
    case 4:
        assert_int_equal(event, SR_EV_RPC);
        assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 1);
        ++call_no;
        break;
    default:
        fail();
    }

    return ret;
}

static void
test_multi_fail(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr = NULL;
    struct lyd_node *input_op;
    sr_data_t *output_op;
    int ret;

    /* subscribe */
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:rpc3", rpc_multi_fail0_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:rpc3", rpc_multi_fail1_cb, st, 1, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:rpc3", rpc_multi_fail2_cb, st, 2, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /*
     * create first RPC
     */
    assert_int_equal(LY_SUCCESS, lyd_new_path2(NULL, st->ly_ctx, "/ops:rpc3", NULL, 0, 0, 0, NULL, &input_op));
    assert_int_equal(LY_SUCCESS, lyd_new_path(input_op, NULL, "l4", "val", 0, NULL));

    /* send RPC */
    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    lyd_free_all(input_op);
    sr_release_data(output_op);

    /* it should fail with 5 total callback calls */
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 5);

    /*
     * create second RPC
     */
    assert_int_equal(LY_SUCCESS, lyd_new_path2(NULL, st->ly_ctx, "/ops:rpc3", NULL, 0, 0, 0, NULL, &input_op));
    assert_int_equal(LY_SUCCESS, lyd_new_path(input_op, NULL, "l4", "val", 0, NULL));

    /* send RPC */
    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    lyd_free_all(input_op);
    sr_release_data(output_op);

    /* it should fail with 3 total callback calls */
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 3);

    /*
     * create third RPC
     */
    assert_int_equal(LY_SUCCESS, lyd_new_path2(NULL, st->ly_ctx, "/ops:rpc3", NULL, 0, 0, 0, NULL, &input_op));
    assert_int_equal(LY_SUCCESS, lyd_new_path(input_op, NULL, "l4", "val", 0, NULL));

    /* send RPC */
    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    lyd_free_all(input_op);
    sr_release_data(output_op);

    /* it should fail with 1 total callback calls */
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 1);

    /*
     * create fourth RPC
     */
    assert_int_equal(LY_SUCCESS, lyd_new_path2(NULL, st->ly_ctx, "/ops:rpc3", NULL, 0, 0, 0, NULL, &input_op));
    assert_int_equal(LY_SUCCESS, lyd_new_path(input_op, NULL, "l4", "val", 0, NULL));

    /* send RPC */
    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    lyd_free_all(input_op);

    /* it should not fail */
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 3);

    /* check output */
    assert_string_equal(lyd_child(output_op->tree)->schema->name, "l5");
    assert_int_equal(((struct lyd_node_term *)lyd_child(output_op->tree))->value.uint16, 0);
    sr_release_data(output_op);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
action_deps_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data)
{
    struct state *st = (struct state *)private_data;

    (void)session;
    (void)sub_id;
    (void)op_path;
    (void)input;
    (void)event;
    (void)request_id;
    (void)output;

    ATOMIC_INC_RELAXED(st->cb_called);

    return SR_ERR_OK;
}

static void
test_action_deps(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr = NULL;
    struct lyd_node *input_op;
    sr_data_t *output_op;
    int ret;

    /* subscribe */
    ret = sr_rpc_subscribe_tree(st->sess, "/act:advanced/act3:conditional/conditional_action", action_deps_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe_tree(st->sess, "/act:advanced/act3:conditional_action2", action_deps_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* create the action */
    assert_int_equal(LY_SUCCESS, lyd_new_path2(NULL, st->ly_ctx, "/act:advanced/act3:conditional/"
            "conditional_action", NULL, 0, 0, 0, NULL, &input_op));

    /* send action, its parent does not exist so it should fail */
    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    assert_null(output_op);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 0);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    /* create the necessary data in operational */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/act:advanced/condition", "true", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/act:advanced/act3:conditional", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    /* send the action again, should succeed now */
    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    assert_int_equal(ret, SR_ERR_OK);
    sr_release_data(output_op);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 1);
    lyd_free_all(input_op);

    /* create another action */
    assert_int_equal(LY_SUCCESS, lyd_new_path2(NULL, st->ly_ctx, "/act:advanced/act3:conditional_action2",
            NULL, 0, 0, 0, NULL, &input_op));

    /* send the action, should succeed */
    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    assert_int_equal(ret, SR_ERR_OK);
    sr_release_data(output_op);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 1);
    lyd_free_all(input_op);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
action_change_config_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *xpath, const sr_val_t *input,
        const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt,
        void *private_data)
{
    struct state *st = (struct state *)private_data;
    int ret;

    (void)sub_id;
    (void)input;
    (void)input_cnt;
    (void)event;
    (void)request_id;

    assert_string_equal(xpath, "/ops:cont/list1[k='val']/cont2/act1");

    /* change some running configuration */
    ret = sr_session_switch_ds(session, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(session, "/ops:cont/list1[k='val2']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(session, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ATOMIC_INC_RELAXED(st->cb_called);

    /* create some output data */
    sr_new_values(1, output);
    *output_cnt = 1;
    ret = sr_val_build_xpath(*output, "%s/l8", xpath);
    assert_int_equal(ret, 0);
    ret = sr_val_set_str_data(*output, SR_INSTANCEID_T, "/ops:cont");
    assert_int_equal(ret, 0);

    return SR_ERR_OK;
}

static void
test_action_change_config(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr1 = NULL, *subscr2 = NULL;
    struct lyd_node *input_op;
    sr_data_t *output_op, *data;
    int ret;

    /* subscribe */
    ret = sr_rpc_subscribe(st->sess, "/ops:cont/list1/cont2/act1", action_change_config_cb, st, 0, 0, &subscr1);
    assert_int_equal(ret, SR_ERR_OK);

    /* create the data in running and subscribe to them */
    ret = sr_set_item_str(st->sess, "/ops:cont/list1[k='val']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(st->sess, "ops", NULL, module_change_dummy_cb, NULL, 0, 0, &subscr2);
    assert_int_equal(ret, SR_ERR_OK);

    /* create the action */
    assert_int_equal(LY_SUCCESS, lyd_new_path2(NULL, st->ly_ctx, "/ops:cont/list1[k='val']/cont2/act1",
            NULL, 0, 0, 0, NULL, &input_op));

    /* send the action */
    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    sr_release_data(output_op);

    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 1);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(input_op);

    /* check that the data were changed */
    ret = sr_get_data(st->sess, "/ops:cont", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_string_equal(lyd_child(data->tree)->schema->name, "list1");
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(data->tree))), "val");
    assert_string_equal(lyd_child(data->tree)->next->schema->name, "list1");
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(data->tree)->next)), "val2");
    assert_string_equal(lyd_child(data->tree)->next->next->schema->name, "cont3");
    sr_release_data(data);

    sr_unsubscribe(subscr1);
    sr_unsubscribe(subscr2);
}

/* TEST */
static int
rpc_shelve_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data)
{
    struct state *st = (struct state *)private_data;

    (void)session;
    (void)sub_id;
    (void)op_path;
    (void)input;
    (void)event;
    (void)request_id;

    /* callback called */
    ATOMIC_INC_RELAXED(st->cb_called);
    if (ATOMIC_LOAD_RELAXED(st->cb_called) == 1) {
        return SR_ERR_CALLBACK_SHELVE;
    }

    /* create output data */
    assert_int_equal(LY_SUCCESS, lyd_new_path(output, NULL, "l5", "256", LYD_NEW_PATH_OUTPUT, NULL));

    return SR_ERR_OK;
}

static void *
send_rpc_shelve_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    struct lyd_node *input_op;
    sr_data_t *output_op;
    int ret;

    ATOMIC_STORE_RELAXED(st->cb_called, 0);

    /* create the RPC */
    assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, st->ly_ctx, "/ops:rpc3/l4", "vall", 0, &input_op));

    /* wait for subscription before sending the RPC */
    pthread_barrier_wait(&st->barrier);

    /* send the RPC */
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    lyd_free_all(input_op);
    assert_int_equal(ret, SR_ERR_OK);

    /* check output */
    assert_string_equal(lyd_child(output_op->tree)->schema->name, "l5");
    assert_string_equal(lyd_get_value(lyd_child(output_op->tree)), "256");

    sr_release_data(output_op);

    /* signal that we are done */
    pthread_barrier_wait(&st->barrier);
    return NULL;
}

static void *
subscribe_rpc_shelve_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int count, ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe */
    ret = sr_rpc_subscribe_tree(sess, "/ops:rpc3", rpc_shelve_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    count = 0;
    while ((ATOMIC_LOAD_RELAXED(st->cb_called) < 1) && (count < 1500)) {
        usleep(10000);
        ++count;
    }
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 1);

    /* callback was shelved, process it again */
    ret = sr_subscription_process_events(subscr, NULL, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    count = 0;
    while ((ATOMIC_LOAD_RELAXED(st->cb_called) < 2) && (count < 1500)) {
        usleep(10000);
        ++count;
    }
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 2);

    /* wait for the other thread to finish */
    pthread_barrier_wait(&st->barrier);

    sr_unsubscribe(subscr);
    sr_session_stop(sess);
    return NULL;
}

static void
test_rpc_shelve(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, subscribe_rpc_shelve_thread, *state);
    pthread_create(&tid[1], NULL, send_rpc_shelve_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
rpc_dummy_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *xpath, const sr_val_t *input, const size_t input_cnt,
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
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
test_input_parameters(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr = NULL;
    struct lyd_node *input_op;
    sr_data_t *output_op;
    int ret;

    /* invalid xpath */
    ret = sr_rpc_subscribe_tree(st->sess, NULL, rpc_action_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:cont/list1[[k='one']/cont2/act1", rpc_action_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:cont/list1[k='one']]/cont2/act1", rpc_action_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:cont/list1[k='one' or k=\"two']/cont2/act1", rpc_action_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    ret = sr_rpc_subscribe_tree(st->sess, "cont/list1[k='one']/cont2/act1", rpc_action_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    ret = sr_rpc_subscribe_tree(st->sess, "/cont/list1[k='one']/cont2/act1", rpc_action_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    ret = sr_rpc_subscribe_tree(st->sess, ":cont/list1[k='one']/cont2/act1", rpc_action_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    ret = sr_rpc_subscribe_tree(st->sess, "/1_ops:cont/list1[k='one']/cont2/act1", rpc_action_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    ret = sr_rpc_subscribe_tree(st->sess, "/ops$:cont/list1[k='one']/cont2/act1", rpc_action_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    ret = sr_rpc_subscribe_tree(st->sess, "//ops:cont/list1[k='one']/cont2/act1", rpc_action_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_LY);

    /* non-existing module in xpath */
    ret = sr_rpc_subscribe_tree(st->sess, "/no-mod:cont/list1[k='one']/cont2/act1", rpc_action_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_NOT_FOUND);

    /* non-existing node in xpath */
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:cont/list1[k='one']/cont2/no-node", rpc_action_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_LY);

    /* rpc or action node not in xpath */
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:cont", rpc_action_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);

    /* data tree must be created with the session connection libyang context */
    struct ly_ctx *ctx;
    struct lys_module *mod;

    assert_int_equal(LY_SUCCESS, ly_ctx_new(TESTS_SRC_DIR "/files/", 0, &ctx));
    assert_int_equal(LY_SUCCESS, lys_parse_path(ctx, TESTS_SRC_DIR "/files/simple.yang", LYS_IN_YANG, &mod));
    assert_int_equal(LY_SUCCESS, lyd_new_path2(NULL, ctx, "/simple:ac1", NULL, 0, 0, 0, NULL, &input_op));
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    lyd_free_all(input_op);
    ly_ctx_destroy(ctx);

    /* data tree not a valid RPC or action */
    assert_int_equal(LY_SUCCESS, lyd_new_path2(NULL, st->ly_ctx, "/ops:cont/list1[k='key']/cont2", NULL,
            0, 0, 0, NULL, &input_op));
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    lyd_free_all(input_op);

    /* equal priority */
    ret = sr_rpc_subscribe(st->sess, "/ops:rpc1", rpc_dummy_cb, NULL, 5, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe(st->sess, "/ops:rpc1", rpc_dummy_cb, NULL, 5, 0, &subscr);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    sr_unsubscribe(subscr);
}

/* TEST */
static void
test_rpc_action_with_no_thread(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr = NULL, *subscr2 = NULL;
    struct lyd_node *input_op;
    sr_data_t *output_op;
    sr_val_t input, *output;
    size_t output_count;
    int ret;

    /* rpc subscribe */
    ret = sr_rpc_subscribe(st->sess, "/ops:rpc1", rpc_rpc_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe(st->sess, "/ops:rpc2", rpc_rpc_cb, NULL, 0, SR_SUBSCR_NO_THREAD, &subscr2);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe(st->sess, "/ops:rpc3", rpc_rpc_cb, NULL, 0, SR_SUBSCR_NO_THREAD, &subscr2);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some data needed for validation */
    ret = sr_set_item_str(st->sess, "/ops-ref:l1", "l1-val", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ops-ref:l2", "l2-val", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* create first RPC */
    input.xpath = "/ops:rpc1/l1";
    input.type = SR_STRING_T;
    input.data.string_val = "l1-val";
    input.dflt = 0;

    /* subscribe to the data so they are actually present in operational */
    ret = sr_module_change_subscribe(st->sess, "ops-ref", NULL, module_change_dummy_cb, NULL, 0,
            SR_SUBSCR_NO_THREAD, &subscr2);
    assert_int_equal(ret, SR_ERR_OK);

    /* try to send first RPC, should succeed */
    ret = sr_rpc_send(st->sess, "/ops:rpc1", &input, 1, 0, &output, &output_count);
    assert_int_equal(ret, SR_ERR_OK);

    /* try to send second RPC, expect an error */
    ret = sr_rpc_send(st->sess, "/ops:rpc2", NULL, 0, 50, &output, &output_count);
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);

    /* try to send third RPC, expect an error */
    ret = sr_rpc_send(st->sess, "/ops:rpc3", NULL, 0, 50, &output, &output_count);
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);

    /* process events on rpc subscriptions with the flag is SR_SUBSCR_NO_THREAD */
    ret = sr_subscription_process_events(subscr2, st->sess, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    sr_unsubscribe(subscr);
    sr_unsubscribe(subscr2);
    subscr2 = NULL;

    /* action subscribe */
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:cont/list1/cont2/act1", rpc_action_cb, NULL, 0, SR_SUBSCR_NO_THREAD, &subscr2);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some data needed for validation and executing the actions */
    ret = sr_set_item_str(st->sess, "/ops:cont/list1[k='key']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to the data so they are actually present in operational */
    ret = sr_module_change_subscribe(st->sess, "ops", NULL, module_change_dummy_cb, NULL, 0,
            SR_SUBSCR_NO_THREAD, &subscr2);
    assert_int_equal(ret, SR_ERR_OK);

    /* create first action */
    assert_int_equal(LY_SUCCESS, lyd_new_path2(NULL, st->ly_ctx, "/ops:cont/list1[k='key']/cont2/act1",
            NULL, 0, 0, 0, NULL, &input_op));

    /* send first action */
    ret = sr_rpc_send_tree(st->sess, input_op, 50, &output_op);
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);

    /* process events on action subscriptions when the flag is SR_SUBSCR_NO_THREAD */
    ret = sr_subscription_process_events(subscr2, st->sess, NULL);
    lyd_free_all(input_op);
    assert_int_equal(ret, SR_ERR_OK);

    sr_unsubscribe(subscr2);
}

/* TEST */
static int
oper_rpc_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
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

    fail();
    return SR_ERR_UNSUPPORTED;
}

static int
rpc_rpc_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data)
{
    struct state *st = (struct state *)private_data;
    struct lyd_node *node;

    (void)session;
    (void)sub_id;
    (void)op_path;
    (void)input;
    (void)event;
    (void)request_id;

    /* callback called */
    ATOMIC_INC_RELAXED(st->cb_called);

    /* create output data */
    lyd_new_path(output, NULL, "l5", "256", LYD_NEW_PATH_OUTPUT, &node);
    assert_non_null(node);

    return SR_ERR_OK;
}

static void
test_rpc_oper(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr = NULL;
    sr_val_t input, *output;
    size_t output_count;
    int ret;

    /* rpc subscribe */
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:rpc3", rpc_rpc_oper_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* oper subscribe, should not be called */
    ret = sr_oper_get_subscribe(st->sess, "ops", "/ops:cont", oper_rpc_oper_cb, NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* create and send the RPC */
    input.xpath = "/ops:rpc3/l4";
    input.type = SR_STRING_T;
    input.data.string_val = "l4-val";
    input.dflt = 0;

    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ret = sr_rpc_send(st->sess, "/ops:rpc3", &input, 1, 0, &output, &output_count);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 1);

    sr_free_values(output, output_count);
    sr_unsubscribe(subscr);
}

/* TEST */
static int
rpc_schema_mount_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data)
{
    struct state *st = (struct state *)private_data;

    (void)session;
    (void)sub_id;
    (void)input;
    (void)event;
    (void)request_id;

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
        assert_string_equal(op_path, "/sm:root/ops:rpc1");
        break;
    case 1:
        assert_string_equal(op_path, "/sm:root/ops:rpc2");
        assert_int_equal(LY_SUCCESS, lyd_new_path(output, NULL, "cont/l3", "val2", LYD_NEW_PATH_OUTPUT, NULL));
        break;
    case 2:
        assert_string_equal(op_path, "/sm:root/ops:cont/list1/cont2/act1");
        assert_int_equal(LY_SUCCESS, lyd_new_path(output, NULL, "l9", "val12", LYD_NEW_PATH_OUTPUT, NULL));
        break;
    default:
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static int
schema_mount_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    struct state *st = (struct state *)private_data;

    (void)session;
    (void)sub_id;
    (void)request_xpath;
    (void)request_id;
    (void)private_data;

    if (!strcmp(module_name, "sm") && !strcmp(xpath, "/sm:root")) {
        assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, st->ly_ctx, "/sm:root/ops-ref:l1", "val", 0, parent));
        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/sm:root/ops-ref:l2", "val2", 0, NULL));
        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/sm:root/ops:cont/list1[k='key']", NULL, 0, NULL));
    } else if (!strcmp(module_name, "ops") && !strcmp(xpath, "/ops:cont/l12")) {
        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ops:cont/l12", "val12", 0, NULL));
    } else if (!strcmp(module_name, "ops") && !strcmp(xpath, "/ops:cont/list1")) {
        assert_int_equal(LY_SUCCESS, lyd_new_path(*parent, NULL, "/ops:cont/list1[k='key']/cont2", NULL, 0, NULL));
    } else {
        fail();
    }

    return SR_ERR_OK;
}

static void
test_schema_mount(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *sub = NULL;
    sr_session_ctx_t *sess;
    struct lyd_node *rpc;
    sr_data_t *output;
    int ret;

    ATOMIC_STORE_RELAXED(st->cb_called, 0);

    /* set oper ext data */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-yang-schema-mount:schema-mounts/namespace[prefix='ops']/uri", "urn:ops", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess,
            "/ietf-yang-schema-mount:schema-mounts/mount-point[module='sm'][label='root']/shared-schema/parent-reference",
            "/ops:cont", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* create a session just to update LY ext data */
    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);
    sr_session_stop(sess);

    /* subscribe for rpc1 */
    ret = sr_rpc_subscribe_tree(st->sess, "/sm:root/ops:rpc1", rpc_schema_mount_cb, st, 0, 0, &sub);
    assert_int_equal(ret, SR_ERR_OK);

    /* send rpc1, validation fails */
    assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, st->ly_ctx, "/sm:root/ops:rpc1/l1", "val", 0, &rpc));
    ret = sr_rpc_send_tree(st->sess, rpc, 0, &output);
    sr_release_data(output);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    /* subscribe for providing mounted and dependency data */
    ret = sr_oper_get_subscribe(st->sess, "sm", "/sm:root", schema_mount_oper_cb, st, 0, &sub);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_oper_get_subscribe(st->sess, "ops", "/ops:cont/l12", schema_mount_oper_cb, st, 0, &sub);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_oper_get_subscribe(st->sess, "ops", "/ops:cont/list1", schema_mount_oper_cb, st, 0, &sub);
    assert_int_equal(ret, SR_ERR_OK);

    /* send rpc1, succeeds */
    ret = sr_rpc_send_tree(st->sess, rpc, 0, &output);
    lyd_free_all(rpc);
    sr_release_data(output);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe for rpc2 */
    ret = sr_rpc_subscribe_tree(st->sess, "/sm:root/ops:rpc2", rpc_schema_mount_cb, st, 0, 0, &sub);
    assert_int_equal(ret, SR_ERR_OK);

    /* send rpc2, succeeds */
    assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, st->ly_ctx, "/sm:root/ops:rpc2", NULL, 0, &rpc));
    ret = sr_rpc_send_tree(st->sess, rpc, 0, &output);
    lyd_free_all(rpc);
    sr_release_data(output);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe for act1 */
    ret = sr_rpc_subscribe_tree(st->sess, "/sm:root/ops:cont/list1/cont2/act1", rpc_schema_mount_cb, st, 0, 0, &sub);
    assert_int_equal(ret, SR_ERR_OK);

    /* send act1, succeeds */
    assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, st->ly_ctx, "/sm:root/ops:cont/list1[k='key']/cont2/act1/l6", "in-val", 0, &rpc));
    assert_int_equal(LY_SUCCESS, lyd_new_path(rpc, NULL, "/sm:root/ops:cont/list1[k='key']/cont2/act1/l7", "in-val", 0, NULL));
    ret = sr_rpc_send_tree(st->sess, rpc, 0, &output);
    lyd_free_all(rpc);
    sr_release_data(output);
    assert_int_equal(ret, SR_ERR_OK);

    assert_int_equal(3, ATOMIC_LOAD_RELAXED(st->cb_called));

    sr_unsubscribe(sub);
}

/* TEST */
static int
rpc_factory_reset_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data)
{
    struct state *st = private_data;
    const char *modules[] = {"ietf-netconf-acm", "sysrepo-plugind", "test", "ietf-interfaces", "ops-ref", "ops", "act", "sm"};
    struct ly_set *set;
    uint32_t i;
    int ret;

    (void)session;
    (void)sub_id;
    (void)op_path;
    (void)event;
    (void)request_id;
    (void)output;

    /* check the modules being reset */
    ret = lyd_find_xpath(input, "sysrepo-factory-default:module", &set);
    assert_int_equal(ret, LY_SUCCESS);
    assert_int_equal(set->count, 8);
    for (i = 0; i < set->count; ++i) {
        assert_string_equal(modules[i], lyd_get_value(set->dnodes[i]));
    }
    ly_set_free(set, NULL);

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static int
factory_reset_change_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    const struct lyd_node *node;
    int ret;

    (void)sub_id;
    (void)xpath;
    (void)request_id;

    switch (ATOMIC_LOAD_RELAXED(st->cb2_called)) {
    case 0:
    case 2:
    case 4:
    case 6:
        assert_string_equal(module_name, "ietf-interfaces");
        if (ATOMIC_LOAD_RELAXED(st->cb2_called) % 4 == 0) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "interface");

        /* 2nd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "name");

        /* 3rd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "type");

        /* 4th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "enabled");

        /* no more changes */
        ret = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 1:
    case 3:
    case 5:
    case 7:
        assert_string_equal(module_name, "test");
        if (ATOMIC_LOAD_RELAXED(st->cb2_called) % 4 == 1) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/test:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "test-leaf");

        /* 2nd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "l2");

        /* 3rd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "k");

        /* 4th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_string_equal(node->schema->name, "v");

        /* no more changes */
        ret = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    default:
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb2_called);
    return SR_ERR_OK;
}

static void
test_factory_reset(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr = NULL;
    struct lyd_node *input;
    sr_data_t *data, *output;
    char *str;
    const char *xml;
    sr_datastore_t ds;
    int ret;

    /* clear startup DS */
    sr_session_switch_ds(st->sess, SR_DS_STARTUP);
    ret = sr_copy_config(st->sess, NULL, SR_DS_RUNNING, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* modify candidate DS */
    sr_session_switch_ds(st->sess, SR_DS_CANDIDATE);
    ret = sr_set_item_str(st->sess, "/test:cont/l2[k='cand']/v", "0", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth100']/type", "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* equal priority */
    ret = sr_rpc_subscribe_tree(st->sess, "/ietf-factory-default:factory-reset", rpc_factory_reset_cb, st, 10, 0, &subscr);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);

    /* subscribe x2 */
    ret = sr_rpc_subscribe_tree(st->sess, "/ietf-factory-default:factory-reset", rpc_factory_reset_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe_tree(st->sess, "/ietf-factory-default:factory-reset", rpc_factory_reset_cb, st, 20, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* check DS contents */
    sr_session_switch_ds(st->sess, SR_DS_STARTUP);
    ret = sr_get_data(st->sess, "/*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_non_null(data);
    ret = lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    sr_release_data(data);
    assert_int_equal(ret, LY_SUCCESS);
    assert_null(str);

    sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    ret = sr_get_data(st->sess, "/*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_non_null(data);
    ret = lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    sr_release_data(data);
    assert_int_equal(ret, LY_SUCCESS);
    assert_null(str);

    sr_session_switch_ds(st->sess, SR_DS_CANDIDATE);
    ret = sr_get_data(st->sess, "/*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_non_null(data);
    ret = lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    sr_release_data(data);
    assert_int_equal(ret, LY_SUCCESS);
    assert_string_equal(str,
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
            "<interface><name>eth100</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "</interface></interfaces>"
            "<cont xmlns=\"urn:test\"><l2><k>cand</k><v>0</v></l2></cont>");
    free(str);

    /* subscribe to changes as well */
    for (ds = SR_DS_STARTUP; ds <= SR_DS_RUNNING; ++ds) {
        sr_session_switch_ds(st->sess, ds);

        ret = sr_module_change_subscribe(st->sess, "ietf-interfaces", NULL, factory_reset_change_cb, st, 0, 0, &subscr);
        assert_int_equal(ret, SR_ERR_OK);
        ret = sr_module_change_subscribe(st->sess, "test", NULL, factory_reset_change_cb, st, 0, 0, &subscr);
        assert_int_equal(ret, SR_ERR_OK);
    }

    /* execute */
    ret = lyd_new_path(NULL, st->ly_ctx, "/ietf-factory-default:factory-reset", NULL, 0, &input);
    assert_int_equal(ret, SR_ERR_OK);
    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ATOMIC_STORE_RELAXED(st->cb2_called, 0);
    ret = sr_rpc_send_tree(st->sess, input, 0, &output);
    lyd_free_tree(input);
    assert_int_equal(ret, SR_ERR_OK);
    sr_release_data(output);
    assert_int_equal(2, ATOMIC_LOAD_RELAXED(st->cb_called));
    assert_int_equal(8, ATOMIC_LOAD_RELAXED(st->cb2_called));

    /* check DS contents */
    xml = "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
            "<interface><name>bu</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type></interface>"
            "</interfaces>"
            "<test-leaf xmlns=\"urn:test\">1</test-leaf>"
            "<cont xmlns=\"urn:test\"><l2><k>key</k><v>5</v></l2></cont>";
    sr_session_switch_ds(st->sess, SR_DS_STARTUP);
    ret = sr_get_data(st->sess, "/*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_non_null(data);
    ret = lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    sr_release_data(data);
    assert_int_equal(ret, LY_SUCCESS);
    assert_string_equal(str, xml);
    free(str);

    sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    ret = sr_get_data(st->sess, "/*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_non_null(data);
    ret = lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    sr_release_data(data);
    assert_int_equal(ret, LY_SUCCESS);
    assert_string_equal(str, xml);
    free(str);

    sr_session_switch_ds(st->sess, SR_DS_CANDIDATE);
    ret = sr_get_data(st->sess, "/*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_non_null(data);
    ret = lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    sr_release_data(data);
    assert_int_equal(ret, LY_SUCCESS);
    assert_string_equal(str, xml);
    free(str);

    /* cleanup */
    sr_unsubscribe(subscr);
}

/* MAIN */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_fail),
        cmocka_unit_test_teardown(test_rpc, clear_ops),
        cmocka_unit_test_teardown(test_action, clear_ops),
        cmocka_unit_test_teardown(test_action_pred, clear_ops),
        cmocka_unit_test_teardown(test_multi, clear_ops),
        cmocka_unit_test(test_multi_fail),
        cmocka_unit_test(test_action_deps),
        cmocka_unit_test_teardown(test_action_change_config, clear_ops),
        cmocka_unit_test(test_rpc_shelve),
        cmocka_unit_test(test_input_parameters),
        cmocka_unit_test_teardown(test_rpc_action_with_no_thread, clear_ops),
        cmocka_unit_test(test_rpc_oper),
        cmocka_unit_test(test_schema_mount),
        cmocka_unit_test(test_factory_reset),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    test_log_init();
    return cmocka_run_group_tests(tests, setup, teardown);
}
