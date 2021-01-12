/**
 * @file test_rpc_action.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test for sending/receiving RPCs/actions
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

#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "tests/config.h"
#include "sysrepo.h"
#include "utils/values.h"

struct state {
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    volatile int cb_called;
    pthread_barrier_t barrier;
};

static int
setup(void **state)
{
    struct state *st;
    uint32_t conn_count;
    const char *ops_ref_feat = "feat1", *act_feat = "advanced-testing";

    st = calloc(1, sizeof *st);
    *state = st;

    sr_connection_count(&conn_count);
    assert_int_equal(conn_count, 0);

    st->cb_called = 0;
    pthread_barrier_init(&st->barrier, NULL, 2);

    if (sr_connect(0, &(st->conn)) != SR_ERR_OK) {
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
    if (sr_install_module(st->conn, TESTS_DIR "/files/ops-ref.yang", TESTS_DIR "/files", &ops_ref_feat, 1) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_DIR "/files/ops.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_DIR "/files/act.yang", TESTS_DIR "/files", &act_feat, 1) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_DIR "/files/act2.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_DIR "/files/act3.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        return 1;
    }
    sr_disconnect(st->conn);

    if (sr_connect(0, &(st->conn)) != SR_ERR_OK) {
        return 1;
    }

    if (sr_session_start(st->conn, SR_DS_RUNNING, &st->sess) != SR_ERR_OK) {
        return 1;
    }

    sr_session_set_nc_id(st->sess, 128);

    return 0;
}

static int
teardown(void **state)
{
    struct state *st = (struct state *)*state;
    int ret = 0;

    ret += sr_remove_module(st->conn, "act3");
    ret += sr_remove_module(st->conn, "act2");
    ret += sr_remove_module(st->conn, "act");
    ret += sr_remove_module(st->conn, "ops");
    ret += sr_remove_module(st->conn, "ops-ref");
    ret += sr_remove_module(st->conn, "iana-if-type");
    ret += sr_remove_module(st->conn, "ietf-interfaces");
    ret += sr_remove_module(st->conn, "test");

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
    sr_apply_changes(st->sess, 0, 1);

    return 0;
}

/* TEST */
static int
rpc_fail_cb(sr_session_ctx_t *session, const char *xpath, const struct lyd_node *input, sr_event_t event,
        uint32_t request_id, struct lyd_node *output, void *private_data)
{
    char *str1;
    const char *str2;
    int ret;

    (void)event;
    (void)request_id;
    (void)output;
    (void)private_data;

    assert_int_equal(sr_session_get_nc_id(session), 128);
    assert_string_equal(xpath, "/ops:rpc1");

    /* check input data tree */
    ret = lyd_print_mem(&str1, input, LYD_XML, LYP_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    str2 = "<rpc1 xmlns=\"urn:ops\"></rpc1>";

    assert_string_equal(str1, str2);
    free(str1);

    /* error */
    sr_set_error(session, NULL, "RPC FAIL");
    return SR_ERR_SYS;
}

static void
test_fail(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr;
    const sr_error_info_t *err_info = NULL;
    struct lyd_node *input, *output;
    int ret;

    /* subscribe */
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:rpc1", rpc_fail_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* send RPC */
    input = lyd_new_path(NULL, sr_get_context(st->conn), "/ops:rpc1", NULL, 0, 0);
    assert_non_null(input);

    /* expect an error */
    ret = sr_rpc_send_tree(st->sess, input, 0, &output);
    lyd_free_withsiblings(input);
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);
    ret = sr_get_error(st->sess, &err_info);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(err_info->err_count, 1);
    assert_string_equal(err_info->err[0].message, "RPC FAIL");
    assert_null(err_info->err[0].xpath);
    assert_null(output);

    /* try to send an action */
    input = lyd_new_path(NULL, sr_get_context(st->conn), "/ops:cont/list1[k='1']/cont2/act1", NULL, 0, LYD_PATH_OPT_NOPARENTRET);
    assert_non_null(input);

    ret = sr_rpc_send_tree(st->sess, input, 0, &output);
    for (; input->parent; input = input->parent);
    lyd_free_withsiblings(input);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
rpc_rpc_cb(sr_session_ctx_t *session, const char *xpath, const sr_val_t *input, const size_t input_cnt, sr_event_t event,
        uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
    static int rpc2_called = 0;

    (void)session;
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
module_change_dummy_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data)
{
    (void)session;
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
    sr_subscription_ctx_t *subscr;
    const sr_error_info_t *err_info = NULL;
    sr_val_t input, *output;
    size_t output_count;
    int ret;

    /* subscribe */
    ret = sr_rpc_subscribe(st->sess, "/ops:rpc1", rpc_rpc_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe(st->sess, "/ops:rpc2", rpc_rpc_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe(st->sess, "/ops:rpc3", rpc_rpc_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some data needed for validation */
    ret = sr_set_item_str(st->sess, "/ops-ref:l1", "l1-val", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ops-ref:l2", "l2-val", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
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
    ret = sr_get_error(st->sess, &err_info);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(err_info->err_count, 2);
    assert_string_equal(err_info->err[0].message, "Leafref \"/ops-ref:l1\" of value \"l1-val\" points to a non-existing leaf.");
    assert_string_equal(err_info->err[0].xpath, "/ops:rpc1/l1");
    assert_string_equal(err_info->err[1].message, "RPC input validation failed.");
    assert_null(err_info->err[1].xpath);
    assert_null(output);
    assert_int_equal(output_count, 0);

    /* subscribe to the data so they are actually present in operational */
    ret = sr_module_change_subscribe(st->sess, "ops-ref", NULL, module_change_dummy_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &subscr);
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
    ret = sr_get_error(st->sess, &err_info);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(err_info->err_count, 2);
    assert_string_equal(err_info->err[0].message, "Leafref \"/ops-ref:l2\" of value \"inval-ref\" points to a non-existing leaf.");
    assert_string_equal(err_info->err[0].xpath, "/ops:rpc2/cont/l3");
    assert_string_equal(err_info->err[1].message, "RPC output validation failed.");
    assert_null(err_info->err[1].xpath);

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
    ret = sr_get_error(st->sess, &err_info);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(err_info->err_count, 1);
    assert_string_equal(err_info->err[0].message, "Schema node not found.");
    assert_string_equal(err_info->err[0].xpath, "/ops:invalid");
    assert_null(output);
    assert_int_equal(output_count, 0);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
rpc_action_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input, sr_event_t event,
        uint32_t request_id, struct lyd_node *output, void *private_data)
{
    struct lyd_node *node;
    char *str1;
    const char *str2;
    int ret;

    (void)session;
    (void)event;
    (void)request_id;
    (void)private_data;

    if (!strcmp(op_path, "/ops:cont/list1/cont2/act1")) {
        /* check input data */
        ret = lyd_print_mem(&str1, input, LYD_XML, LYP_WITHSIBLINGS);
        assert_int_equal(ret, 0);
        str2 = "<act1 xmlns=\"urn:ops\"><l6>val</l6><l7>val</l7></act1>";
        assert_string_equal(str1, str2);
        free(str1);

        /* create output data */
        node = lyd_new_path(output, NULL, "l9", "l12-val", 0, LYD_PATH_OPT_OUTPUT);
        assert_non_null(node);
    } else if (!strcmp(op_path, "/ops:cont/list1/act2")) {
        /* check input data */
        ret = lyd_print_mem(&str1, input, LYD_XML, LYP_WITHSIBLINGS);
        assert_int_equal(ret, 0);
        str2 = "<act2 xmlns=\"urn:ops\"><l10>e3</l10></act2>";
        assert_string_equal(str1, str2);
        free(str1);

        /* create output data */
        node = lyd_new_path(output, NULL, "l11", "-65536", 0, LYD_PATH_OPT_OUTPUT);
        assert_non_null(node);
    } else {
        fail();
    }

    return SR_ERR_OK;
}

static void
test_action(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr;
    struct lyd_node *node, *input_op, *output_op;
    char *str1;
    const char *str2;
    int ret;

    /* subscribe */
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:cont/list1/cont2/act1", rpc_action_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:cont/list1/act2", rpc_action_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some data needed for validation and executing the actions */
    ret = sr_set_item_str(st->sess, "/ops:cont/list1[k='key']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ops:cont/l12", "l12-val", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to the data so they are actually present in operational */
    ret = sr_module_change_subscribe(st->sess, "ops", NULL, module_change_dummy_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /*
     * create first action
     */
    input_op = lyd_new_path(NULL, sr_get_context(st->conn), "/ops:cont/list1[k='key']/cont2/act1", NULL, 0, LYD_PATH_OPT_NOPARENTRET);
    assert_non_null(input_op);
    node = lyd_new_path(input_op, NULL, "l6", "val", 0, 0);
    assert_non_null(node);
    node = lyd_new_path(input_op, NULL, "l7", "val", 0, 0);
    assert_non_null(node);

    /* send first action */
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    for (; input_op->parent; input_op = input_op->parent);
    lyd_free_withsiblings(input_op);
    assert_int_equal(ret, SR_ERR_OK);

    /* check output data tree */
    assert_non_null(output_op);
    ret = lyd_print_mem(&str1, output_op, LYD_XML, LYP_WITHSIBLINGS);
    for (; output_op->parent; output_op = output_op->parent);
    lyd_free_withsiblings(output_op);
    assert_int_equal(ret, 0);
    str2 = "<act1 xmlns=\"urn:ops\"><l9>l12-val</l9></act1>";
    assert_string_equal(str1, str2);
    free(str1);

    /*
     * create second action
     */
    input_op = lyd_new_path(NULL, sr_get_context(st->conn), "/ops:cont/list1[k='key']/act2", NULL, 0, LYD_PATH_OPT_NOPARENTRET);
    assert_non_null(input_op);
    node = lyd_new_path(input_op, NULL, "l10", "e3", 0, 0);
    assert_non_null(node);

    /* send second action */
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    for (; input_op->parent; input_op = input_op->parent);
    lyd_free_withsiblings(input_op);
    assert_int_equal(ret, SR_ERR_OK);

    /* check output data tree */
    assert_non_null(output_op);
    ret = lyd_print_mem(&str1, output_op, LYD_XML, LYP_WITHSIBLINGS);
    for (; output_op->parent; output_op = output_op->parent);
    lyd_free_withsiblings(output_op);
    assert_int_equal(ret, 0);
    str2 = "<act2 xmlns=\"urn:ops\"><l11>-65536</l11></act2>";
    assert_string_equal(str1, str2);
    free(str1);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
rpc_action_pred_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input, sr_event_t event,
        uint32_t request_id, struct lyd_node *output, void *private_data)
{
    char *str1;
    const char *str2;
    int ret;

    (void)session;
    (void)event;
    (void)request_id;
    (void)output;
    (void)private_data;

    if (!strcmp(op_path, "/ops:cont/list1[k='one' or k='two']/cont2/act1")) {
        /* check input data */
        ret = lyd_print_mem(&str1, input, LYD_XML, LYP_WITHSIBLINGS);
        assert_int_equal(ret, 0);
        str2 = "<act1 xmlns=\"urn:ops\"><l6>val2</l6><l7>val2</l7></act1>";
        assert_string_equal(str1, str2);
        free(str1);
    } else if (!strcmp(op_path, "/ops:cont/list1[k='three' or k='four']/cont2/act1")) {
        /* check input data */
        ret = lyd_print_mem(&str1, input, LYD_XML, LYP_WITHSIBLINGS);
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
    sr_subscription_ctx_t *subscr;
    struct lyd_node *node, *input_op, *output_op;
    int ret;

    /* you cannot subscribe to more actions */
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:cont/list1/cont2/act1 or /ops:rpc1", rpc_action_pred_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_LY);

    /* subscribe with some predicates */
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:cont/list1[k='one' or k='two']/cont2/act1", rpc_action_pred_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:cont/list1[k='three' or k='four']/cont2/act1", rpc_action_pred_cb, NULL,
            1, SR_SUBSCR_CTX_REUSE, &subscr);
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
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to the data so they are actually present in operational */
    ret = sr_module_change_subscribe(st->sess, "ops", NULL, module_change_dummy_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /*
     * create first action
     */
    input_op = lyd_new_path(NULL, sr_get_context(st->conn), "/ops:cont/list1[k='zero']/cont2/act1", NULL, 0, LYD_PATH_OPT_NOPARENTRET);
    assert_non_null(input_op);
    node = lyd_new_path(input_op, NULL, "l6", "val", 0, 0);
    assert_non_null(node);
    node = lyd_new_path(input_op, NULL, "l7", "val", 0, 0);
    assert_non_null(node);

    /* send action, fails */
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    for (; input_op->parent; input_op = input_op->parent);
    lyd_free_withsiblings(input_op);
    assert_int_equal(ret, SR_ERR_UNSUPPORTED);

    /*
     * create second action
     */
    input_op = lyd_new_path(NULL, sr_get_context(st->conn), "/ops:cont/list1[k='one']/cont2/act1", NULL, 0, LYD_PATH_OPT_NOPARENTRET);
    assert_non_null(input_op);
    node = lyd_new_path(input_op, NULL, "l6", "val2", 0, 0);
    assert_non_null(node);
    node = lyd_new_path(input_op, NULL, "l7", "val2", 0, 0);
    assert_non_null(node);

    /* send action, should be fine */
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    for (; input_op->parent; input_op = input_op->parent);
    lyd_free_withsiblings(input_op);
    for (; output_op->parent; output_op = output_op->parent);
    lyd_free_withsiblings(output_op);

    assert_int_equal(ret, SR_ERR_OK);

    /*
     * create third action
     */
    input_op = lyd_new_path(NULL, sr_get_context(st->conn), "/ops:cont/list1[k='three']/cont2/act1", NULL, 0, LYD_PATH_OPT_NOPARENTRET);
    assert_non_null(input_op);
    node = lyd_new_path(input_op, NULL, "l6", "val3", 0, 0);
    assert_non_null(node);
    node = lyd_new_path(input_op, NULL, "l7", "val3", 0, 0);
    assert_non_null(node);

    /* send action, should be fine */
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    for (; input_op->parent; input_op = input_op->parent);
    lyd_free_withsiblings(input_op);
    for (; output_op->parent; output_op = output_op->parent);
    lyd_free_withsiblings(output_op);

    assert_int_equal(ret, SR_ERR_OK);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
rpc_multi_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input, sr_event_t event,
        uint32_t request_id, struct lyd_node *output, void *private_data)
{
    struct state *st = (struct state *)private_data;

    (void)session;
    (void)op_path;
    (void)input;
    (void)event;
    (void)request_id;
    (void)output;

    ++st->cb_called;
    return SR_ERR_OK;
}

static void
test_multi(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr;
    struct lyd_node *node, *input_op, *output_op;
    int ret;

    /* subscribe */
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:cont/list1/cont2/act1", rpc_multi_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:cont/list1[k='one' or k='two']/cont2/act1", rpc_multi_cb, st,
            1, SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:cont/list1[k='two' or k='three' or k='four']/cont2/act1",
            rpc_multi_cb, st, 2, SR_SUBSCR_CTX_REUSE, &subscr);
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
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to the data so they are actually present in operational */
    ret = sr_module_change_subscribe(st->sess, "ops", NULL, module_change_dummy_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /*
     * create first action
     */
    input_op = lyd_new_path(NULL, sr_get_context(st->conn), "/ops:cont/list1[k='zero']/cont2/act1", NULL, 0, LYD_PATH_OPT_NOPARENTRET);
    assert_non_null(input_op);
    node = lyd_new_path(input_op, NULL, "l6", "val", 0, 0);
    assert_non_null(node);
    node = lyd_new_path(input_op, NULL, "l7", "val", 0, 0);
    assert_non_null(node);

    /* send action */
    st->cb_called = 0;
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    for (; input_op->parent; input_op = input_op->parent);
    lyd_free_withsiblings(input_op);
    for (; output_op->parent; output_op = output_op->parent);
    lyd_free_withsiblings(output_op);

    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(st->cb_called, 1);

    /*
     * create second action
     */
    input_op = lyd_new_path(NULL, sr_get_context(st->conn), "/ops:cont/list1[k='one']/cont2/act1", NULL, 0, LYD_PATH_OPT_NOPARENTRET);
    assert_non_null(input_op);
    node = lyd_new_path(input_op, NULL, "l6", "val2", 0, 0);
    assert_non_null(node);
    node = lyd_new_path(input_op, NULL, "l7", "val2", 0, 0);
    assert_non_null(node);

    /* send action */
    st->cb_called = 0;
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    for (; input_op->parent; input_op = input_op->parent);
    lyd_free_withsiblings(input_op);
    for (; output_op->parent; output_op = output_op->parent);
    lyd_free_withsiblings(output_op);

    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(st->cb_called, 2);

    /*
     * create third action
     */
    input_op = lyd_new_path(NULL, sr_get_context(st->conn), "/ops:cont/list1[k='two']/cont2/act1", NULL, 0, LYD_PATH_OPT_NOPARENTRET);
    assert_non_null(input_op);
    node = lyd_new_path(input_op, NULL, "l6", "val3", 0, 0);
    assert_non_null(node);
    node = lyd_new_path(input_op, NULL, "l7", "val3", 0, 0);
    assert_non_null(node);

    /* send action */
    st->cb_called = 0;
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    for (; input_op->parent; input_op = input_op->parent);
    lyd_free_withsiblings(input_op);
    for (; output_op->parent; output_op = output_op->parent);
    lyd_free_withsiblings(output_op);

    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(st->cb_called, 3);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
rpc_multi_fail0_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input, sr_event_t event,
        uint32_t request_id, struct lyd_node *output, void *private_data)
{
    struct state *st = (struct state *)private_data;
    struct lyd_node *node;
    static int call_no = 1;
    int ret = SR_ERR_OK;

    (void)session;
    (void)op_path;
    (void)input;
    (void)request_id;

    ++st->cb_called;

    /* create output data in all cases, it should always be freed */
    node = lyd_new_path(output, NULL, "l5", "0", 0, LYD_PATH_OPT_OUTPUT);
    assert_non_null(node);

    switch (call_no) {
    case 1:
        assert_int_equal(event, SR_EV_RPC);
        assert_int_equal(st->cb_called, 3);
        /* callback fails */
        ret = SR_ERR_NOMEM;
        ++call_no;
        break;
    case 2:
        assert_int_equal(event, SR_EV_RPC);
        assert_int_equal(st->cb_called, 3);
        ++call_no;
        break;
    default:
        fail();
    }

    return ret;
}

static int
rpc_multi_fail1_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input, sr_event_t event,
        uint32_t request_id, struct lyd_node *output, void *private_data)
{
    struct state *st = (struct state *)private_data;
    struct lyd_node *node;
    static int call_no = 1;
    int ret = SR_ERR_OK;

    (void)session;
    (void)op_path;
    (void)input;
    (void)request_id;

    ++st->cb_called;

    /* create output data in all cases, it should always be freed */
    node = lyd_new_path(output, NULL, "l5", "1", 0, LYD_PATH_OPT_OUTPUT);
    assert_non_null(node);

    switch (call_no) {
    case 1:
        if (event == SR_EV_RPC) {
            assert_int_equal(st->cb_called, 2);
        } else {
            assert_int_equal(event, SR_EV_ABORT);
            assert_int_equal(st->cb_called, 5);
            ++call_no;
        }
        break;
    case 2:
        assert_int_equal(event, SR_EV_RPC);
        assert_int_equal(st->cb_called, 2);
        /* callback fails */
        ret = SR_ERR_NOT_FOUND;
        ++call_no;
        break;
    case 3:
        assert_int_equal(event, SR_EV_RPC);
        assert_int_equal(st->cb_called, 2);
        ++call_no;
        break;
    default:
        fail();
    }

    return ret;
}

static int
rpc_multi_fail2_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input, sr_event_t event,
        uint32_t request_id, struct lyd_node *output, void *private_data)
{
    struct state *st = (struct state *)private_data;
    struct lyd_node *node;
    static int call_no = 1;
    int ret = SR_ERR_OK;

    (void)session;
    (void)op_path;
    (void)input;
    (void)request_id;

    ++st->cb_called;

    /* create output data in all cases, it should always be freed */
    node = lyd_new_path(output, NULL, "l5", "2", 0, LYD_PATH_OPT_OUTPUT);
    assert_non_null(node);

    switch (call_no) {
    case 1:
        if (event == SR_EV_RPC) {
            assert_int_equal(st->cb_called, 1);
        } else {
            assert_int_equal(event, SR_EV_ABORT);
            assert_int_equal(st->cb_called, 4);
            ++call_no;
        }
        break;
    case 2:
        if (event == SR_EV_RPC) {
            assert_int_equal(st->cb_called, 1);
        } else {
            assert_int_equal(event, SR_EV_ABORT);
            assert_int_equal(st->cb_called, 3);
            ++call_no;
        }
        break;
    case 3:
        assert_int_equal(event, SR_EV_RPC);
        assert_int_equal(st->cb_called, 1);
        /* callback fails, last callback (but there is no callback for abort, synchronizing would block) */
        ret = SR_ERR_LOCKED;
        ++call_no;
        break;
    case 4:
        assert_int_equal(event, SR_EV_RPC);
        assert_int_equal(st->cb_called, 1);
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
    sr_subscription_ctx_t *subscr;
    struct lyd_node *node, *input_op, *output_op;
    int ret;

    /* subscribe */
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:rpc3", rpc_multi_fail0_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:rpc3", rpc_multi_fail1_cb, st, 1, SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:rpc3", rpc_multi_fail2_cb, st, 2, SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /*
     * create first RPC
     */
    input_op = lyd_new_path(NULL, sr_get_context(st->conn), "/ops:rpc3", NULL, 0, LYD_PATH_OPT_NOPARENTRET);
    assert_non_null(input_op);
    node = lyd_new_path(input_op, NULL, "l4", "val", 0, 0);
    assert_non_null(node);

    /* send RPC */
    st->cb_called = 0;
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    lyd_free_withsiblings(input_op);
    lyd_free_withsiblings(output_op);

    /* it should fail with 5 total callback calls */
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);
    assert_int_equal(st->cb_called, 5);

    /*
     * create second RPC
     */
    input_op = lyd_new_path(NULL, sr_get_context(st->conn), "/ops:rpc3", NULL, 0, LYD_PATH_OPT_NOPARENTRET);
    assert_non_null(input_op);
    node = lyd_new_path(input_op, NULL, "l4", "val", 0, 0);
    assert_non_null(node);

    /* send RPC */
    st->cb_called = 0;
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    lyd_free_withsiblings(input_op);
    lyd_free_withsiblings(output_op);

    /* it should fail with 3 total callback calls */
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);
    assert_int_equal(st->cb_called, 3);

    /*
     * create third RPC
     */
    input_op = lyd_new_path(NULL, sr_get_context(st->conn), "/ops:rpc3", NULL, 0, LYD_PATH_OPT_NOPARENTRET);
    assert_non_null(input_op);
    node = lyd_new_path(input_op, NULL, "l4", "val", 0, 0);
    assert_non_null(node);

    /* send RPC */
    st->cb_called = 0;
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    lyd_free_withsiblings(input_op);
    lyd_free_withsiblings(output_op);

    /* it should fail with 1 total callback calls */
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);
    assert_int_equal(st->cb_called, 1);

    /*
     * create fourth RPC
     */
    input_op = lyd_new_path(NULL, sr_get_context(st->conn), "/ops:rpc3", NULL, 0, LYD_PATH_OPT_NOPARENTRET);
    assert_non_null(input_op);
    node = lyd_new_path(input_op, NULL, "l4", "val", 0, 0);
    assert_non_null(node);

    /* send RPC */
    st->cb_called = 0;
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    lyd_free_withsiblings(input_op);

    /* it should not fail */
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(st->cb_called, 3);

    /* check output */
    assert_string_equal(output_op->child->schema->name, "l5");
    assert_int_equal(((struct lyd_node_leaf_list *)output_op->child)->value.uint16, 0);
    lyd_free_withsiblings(output_op);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
action_deps_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input, sr_event_t event,
        uint32_t request_id, struct lyd_node *output, void *private_data)
{
    struct state *st = (struct state *)private_data;

    (void)session;
    (void)op_path;
    (void)input;
    (void)event;
    (void)request_id;
    (void)output;

    ++st->cb_called;

    return SR_ERR_OK;
}

static void
test_action_deps(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr;
    struct lyd_node *input_op, *output_op;
    int ret;

    /* subscribe */
    ret = sr_rpc_subscribe_tree(st->sess, "/act:advanced/act3:conditional/conditional_action", action_deps_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe_tree(st->sess, "/act:advanced/act3:conditional_action2", action_deps_cb, st, 0, SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* create the action */
    input_op = lyd_new_path(NULL, sr_get_context(st->conn), "/act:advanced/act3:conditional/conditional_action",
            NULL, 0, LYD_PATH_OPT_NOPARENTRET);
    assert_non_null(input_op);

    /* send action, its parent does not exist so it should fail */
    st->cb_called = 0;
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    assert_null(output_op);
    assert_int_equal(st->cb_called, 0);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    /* create the necessary data in operational */
    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/act:advanced/condition", "true", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    /* send the action again, should succeed now */
    st->cb_called = 0;
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    assert_int_equal(ret, SR_ERR_OK);
    while (output_op->parent) {
        output_op = output_op->parent;
    }
    lyd_free_withsiblings(output_op);
    assert_int_equal(st->cb_called, 1);

    while (input_op->parent) {
        input_op = input_op->parent;
    }
    lyd_free_withsiblings(input_op);

    /* create another action */
    input_op = lyd_new_path(NULL, sr_get_context(st->conn), "/act:advanced/act3:conditional_action2",
            NULL, 0, LYD_PATH_OPT_NOPARENTRET);
    assert_non_null(input_op);

    /* send the action, should succeed */
    st->cb_called = 0;
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    assert_int_equal(ret, SR_ERR_OK);
    while (output_op->parent) {
        output_op = output_op->parent;
    }
    lyd_free_withsiblings(output_op);
    assert_int_equal(st->cb_called, 1);

    while (input_op->parent) {
        input_op = input_op->parent;
    }
    lyd_free_withsiblings(input_op);

    sr_unsubscribe(subscr);
}

/* TEST */
static int
action_change_config_cb(sr_session_ctx_t *session, const char *xpath, const sr_val_t *input, const size_t input_cnt,
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
    struct state *st = (struct state *)private_data;
    int ret;

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
    ret = sr_apply_changes(session, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    ++st->cb_called;

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
    sr_subscription_ctx_t *subscr1, *subscr2;
    struct lyd_node *input_op, *output_op, *data;
    int ret;

    /* subscribe */
    ret = sr_rpc_subscribe(st->sess, "/ops:cont/list1/cont2/act1", action_change_config_cb, st, 0, 0, &subscr1);
    assert_int_equal(ret, SR_ERR_OK);

    /* create the data in running and subscribe to them */
    ret = sr_set_item_str(st->sess, "/ops:cont/list1[k='val']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(st->sess, "ops", NULL, module_change_dummy_cb, NULL, 0, 0, &subscr2);
    assert_int_equal(ret, SR_ERR_OK);

    /* create the action */
    input_op = lyd_new_path(NULL, sr_get_context(st->conn), "/ops:cont/list1[k='val']/cont2/act1",
            NULL, 0, LYD_PATH_OPT_NOPARENTRET);
    assert_non_null(input_op);

    /* send the action */
    st->cb_called = 0;
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    while (output_op->parent) {
        output_op = output_op->parent;
    }
    lyd_free_withsiblings(output_op);

    assert_int_equal(st->cb_called, 1);
    assert_int_equal(ret, SR_ERR_OK);

    while (input_op->parent) {
        input_op = input_op->parent;
    }
    lyd_free_withsiblings(input_op);

    /* check that the data were changed */
    ret = sr_get_data(st->sess, "/ops:cont", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_string_equal(data->child->schema->name, "cont3");
    assert_string_equal(data->child->next->schema->name, "list1");
    assert_string_equal(((struct lyd_node_leaf_list *)data->child->next->child)->value_str, "val");
    assert_string_equal(data->child->next->next->schema->name, "list1");
    assert_string_equal(((struct lyd_node_leaf_list *)data->child->next->next->child)->value_str, "val2");
    lyd_free_withsiblings(data);

    sr_unsubscribe(subscr1);
    sr_unsubscribe(subscr2);
}

/* TEST */
static int
rpc_shelve_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input, sr_event_t event,
        uint32_t request_id, struct lyd_node *output, void *private_data)
{
    struct state *st = (struct state *)private_data;
    struct lyd_node *node;

    (void)session;
    (void)op_path;
    (void)input;
    (void)event;
    (void)request_id;

    /* callback called */
    ++st->cb_called;
    if (st->cb_called == 1) {
        return SR_ERR_CALLBACK_SHELVE;
    }

    /* create output data */
    node = lyd_new_path(output, NULL, "l5", "256", 0, LYD_PATH_OPT_OUTPUT);
    assert_non_null(node);

    return SR_ERR_OK;
}

static void *
send_rpc_shelve_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    struct lyd_node *input_op, *output_op;
    int ret;

    st->cb_called = 0;

    /* create the RPC */
    input_op = lyd_new_path(NULL, sr_get_context(st->conn), "/ops:rpc3/l4", "vall", 0, 0);
    assert_non_null(input_op);

    /* wait for subscription before sending the RPC */
    pthread_barrier_wait(&st->barrier);

    /* send the RPC */
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    while (input_op->parent) {
        input_op = input_op->parent;
    }
    lyd_free_withsiblings(input_op);
    assert_int_equal(ret, SR_ERR_OK);

    /* check output */
    /* TODO */

    while (output_op->parent) {
        output_op = output_op->parent;
    }
    lyd_free_withsiblings(output_op);

    /* signal that we are done */
    pthread_barrier_wait(&st->barrier);
    return NULL;
}

static void *
subscribe_rpc_shelve_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr;
    int count, ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe */
    ret = sr_rpc_subscribe_tree(sess, "/ops:rpc3", rpc_shelve_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    count = 0;
    while ((st->cb_called < 1) && (count < 1500)) {
        usleep(10000);
        ++count;
    }
    assert_int_equal(st->cb_called, 1);

    /* callback was shelved, process it again */
    ret = sr_process_events(subscr, NULL, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    count = 0;
    while ((st->cb_called < 2) && (count < 1500)) {
        usleep(10000);
        ++count;
    }
    assert_int_equal(st->cb_called, 2);

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
rpc_dummy_cb(sr_session_ctx_t *session, const char *xpath, const sr_val_t *input, const size_t input_cnt,
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
    (void)session;
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
    sr_subscription_ctx_t *subscr;
    struct lyd_node *input_op, *output_op;
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
    struct ly_ctx *ctx = ly_ctx_new(TESTS_DIR"/files/", 0);
    assert_non_null(ctx);
    const struct lys_module *mod = lys_parse_path(ctx, TESTS_DIR"/files/simple.yang", LYS_IN_YANG);
    assert_non_null(mod);
    input_op = lyd_new_path(NULL, ctx, "/simple:ac1", NULL, 0, LYD_PATH_OPT_NOPARENTRET);
    assert_non_null(input_op);
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    lyd_free_withsiblings(input_op);
    ly_ctx_destroy(ctx, NULL);

    /* data tree not a valid RPC or action */
    input_op = lyd_new_path(NULL, sr_get_context(st->conn), "/ops:cont/list1[k='key']/cont2", NULL, 0, LYD_PATH_OPT_NOPARENTRET);
    assert_non_null(input_op);
    ret = sr_rpc_send_tree(st->sess, input_op, 0, &output_op);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    for(; input_op->parent; input_op = input_op->parent);
    lyd_free_withsiblings(input_op);

    /* equal priority */
    ret = sr_rpc_subscribe(st->sess, "/ops:rpc1", rpc_dummy_cb, NULL, 5, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe(st->sess, "/ops:rpc1", rpc_dummy_cb, NULL, 5, SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    sr_unsubscribe(subscr);
}

/* TEST */
static void
test_rpc_action_with_no_thread(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr, *subscr2;
    struct lyd_node *input_op, *output_op;
    sr_val_t input, *output;
    size_t output_count;
    int ret;

    /* rpc subscribe */
    ret = sr_rpc_subscribe(st->sess, "/ops:rpc1", rpc_rpc_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe(st->sess, "/ops:rpc2", rpc_rpc_cb, NULL, 0, SR_SUBSCR_NO_THREAD, &subscr2);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_rpc_subscribe(st->sess, "/ops:rpc3", rpc_rpc_cb, NULL, 0, SR_SUBSCR_NO_THREAD | SR_SUBSCR_CTX_REUSE, &subscr2);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some data needed for validation */
    ret = sr_set_item_str(st->sess, "/ops-ref:l1", "l1-val", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ops-ref:l2", "l2-val", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    /* create first RPC */
    input.xpath = "/ops:rpc1/l1";
    input.type = SR_STRING_T;
    input.data.string_val = "l1-val";
    input.dflt = 0;

    /* subscribe to the data so they are actually present in operational */
    ret = sr_module_change_subscribe(st->sess, "ops-ref", NULL, module_change_dummy_cb, NULL, 0,
            SR_SUBSCR_NO_THREAD | SR_SUBSCR_CTX_REUSE, &subscr2);
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
    ret = sr_process_events(subscr2, st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    sr_unsubscribe(subscr);
    sr_unsubscribe(subscr2);

    /* action subscribe */
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:cont/list1/cont2/act1", rpc_action_cb, NULL, 0, SR_SUBSCR_NO_THREAD, &subscr2);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some data needed for validation and executing the actions */
    ret = sr_set_item_str(st->sess, "/ops:cont/list1[k='key']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to the data so they are actually present in operational */
    ret = sr_module_change_subscribe(st->sess, "ops", NULL, module_change_dummy_cb, NULL, 0, SR_SUBSCR_NO_THREAD, &subscr2);
    assert_int_equal(ret, SR_ERR_OK);

    /* create first action */
    input_op = lyd_new_path(NULL, sr_get_context(st->conn), "/ops:cont/list1[k='key']/cont2/act1", NULL, 0, LYD_PATH_OPT_NOPARENTRET);
    assert_non_null(input_op);

    /* send first action */
    ret = sr_rpc_send_tree(st->sess, input_op, 50, &output_op);
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);

    /* process events on action subscriptions when the flag is SR_SUBSCR_NO_THREAD */
    ret = sr_process_events(subscr2, st->sess, 0);
    for (; input_op->parent; input_op = input_op->parent);
    lyd_free_withsiblings(input_op);
    assert_int_equal(ret, SR_ERR_OK);

    sr_unsubscribe(subscr2);
}

/* TEST */
static int
oper_rpc_oper_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, const char *request_xpath,
        uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    (void)session;
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
rpc_rpc_oper_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input, sr_event_t event,
        uint32_t request_id, struct lyd_node *output, void *private_data)
{
    struct state *st = (struct state *)private_data;
    struct lyd_node *node;

    (void)session;
    (void)op_path;
    (void)input;
    (void)event;
    (void)request_id;

    /* callback called */
    ++st->cb_called;

    /* create output data */
    node = lyd_new_path(output, NULL, "l5", "256", 0, LYD_PATH_OPT_OUTPUT);
    assert_non_null(node);

    return SR_ERR_OK;
}

static void
test_rpc_oper(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr;
    sr_val_t input, *output;
    size_t output_count;
    int ret;

    /* rpc subscribe */
    ret = sr_rpc_subscribe_tree(st->sess, "/ops:rpc3", rpc_rpc_oper_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* oper subscribe, should not be called */
    ret = sr_oper_get_items_subscribe(st->sess, "ops", "/ops:cont", oper_rpc_oper_cb, NULL, SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* create and send the RPC */
    input.xpath = "/ops:rpc3/l4";
    input.type = SR_STRING_T;
    input.data.string_val = "l4-val";
    input.dflt = 0;

    st->cb_called = 0;
    ret = sr_rpc_send(st->sess, "/ops:rpc3", &input, 1, 0, &output, &output_count);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(st->cb_called, 1);

    sr_free_values(output, output_count);
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
        cmocka_unit_test(test_rpc_action_with_no_thread),
        cmocka_unit_test(test_rpc_oper),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    sr_log_stderr(SR_LL_INF);
    return cmocka_run_group_tests(tests, setup, teardown);
}
