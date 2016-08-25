/**
 * @file sr_rpc_tree_example.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Example usage of RPC using the "tree API".
 *
 * @copyright
 * Copyright 2016 Cisco Systems, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include "sysrepo.h"
#include "sysrepo/trees.h"

#define NUM_OF_REQUESTS   1000
#define OUTPUT_LOG_SIZE   100

#define NEW_API  1

#define assert_int_equal(a, b)     assert(a == b)
#define assert_string_equal(a, b)  assert(0 == strcmp(a, b))
#define assert_true(a)             assert(a)
#define assert_false(a)            assert(!a)
#define assert_null(a)             assert(NULL == a)
#define assert_non_null(a)         assert(NULL != a)

static int
test_rpc_cb(const char *xpath, const sr_node_t *input, const size_t input_cnt,
        sr_node_t **output, size_t *output_cnt, void *private_ctx)
{
    int *callback_called = (int*)private_ctx;
    char msg_str[32] = { 0, };
    *callback_called += 1;

    /* check input */
    assert_int_equal(2, input_cnt);
    /*   /test-module:activate-software-image/input/image-name */
    const sr_node_t *sr_in_node = input;
    assert_string_equal("image-name", sr_in_node->name);
    assert_string_equal("test-module", sr_in_node->module_name);
    assert_false(sr_in_node->dflt);
    assert_int_equal(SR_STRING_T, sr_in_node->type);
    assert_string_equal("acmefw-2.3", sr_in_node->data.string_val);
    assert_null(sr_in_node->first_child);
    assert_null(sr_in_node->last_child);
    /*   /test-module:activate-software-image/input/location */
    sr_in_node = input + 1;
    assert_string_equal("location", sr_in_node->name);
    assert_string_equal("test-module", sr_in_node->module_name);
    assert_true(sr_in_node->dflt);
    assert_int_equal(SR_STRING_T, sr_in_node->type);
    assert_string_equal("/", sr_in_node->data.string_val);
    assert_null(sr_in_node->first_child);
    assert_null(sr_in_node->last_child);

    *output_cnt = 3;
#ifdef NEW_API
    assert_int_equal(0, sr_new_trees(*output_cnt, output));
    sr_node_set_name(*output, "status");
    (*output)[0].type = SR_STRING_T;
    sr_node_set_string(*output, "The image acmefw-2.3 is being installed.");
    sr_node_set_name(*output + 1, "version");
    (*output)[1].type = SR_STRING_T;
    sr_node_set_string(*output + 1, "2.3");
    sr_node_set_name(*output + 2, "init-log");
    (*output)[2].type = SR_CONTAINER_T;
#else
    *output = calloc(*output_cnt, sizeof(**output));
    (*output)[0].name = strdup("status");
    (*output)[0].type = SR_STRING_T;
    (*output)[0].data.string_val = strdup("The image acmefw-2.3 is being installed.");
    (*output)[1].name = strdup("version");
    (*output)[1].type = SR_STRING_T;
    (*output)[1].data.string_val = strdup("2.3");
    (*output)[2].name = strdup("init-log");
    (*output)[2].type = SR_CONTAINER_T;
#endif

    for (size_t i = 0; i < OUTPUT_LOG_SIZE; ++i) {
        snprintf(msg_str, 32, "Message number: %lu", i);
        sr_node_t *log_msg = NULL, *child = NULL;
#ifdef NEW_API
        assert_int_equal(0, sr_node_add_child((*output) + 2, "log-msg", NULL, &log_msg));
        log_msg->type = SR_LIST_T;
        assert_int_equal(0, sr_node_add_child(log_msg, "msg", NULL, &child));
        child->type = SR_STRING_T;
        sr_node_set_string(child, msg_str);
        assert_int_equal(0, sr_node_add_child(log_msg, "time", NULL, &child));
        child->type = SR_UINT32_T;
        child->data.uint32_val = i;
        assert_int_equal(0, sr_node_add_child(log_msg, "msg-type", NULL, &child));
        child->type = SR_ENUM_T;
        sr_node_set_string(child, "debug");
#else
        assert_int_equal(0, sr_node_add_child((*output) + 2, "log-msg", NULL, &log_msg));
        log_msg->type = SR_LIST_T;
        assert_int_equal(0, sr_node_add_child(log_msg, "msg", NULL, &child));
        child->type = SR_STRING_T;
        child->data.string_val = strdup(msg_str);
        assert_int_equal(0, sr_node_add_child(log_msg, "time", NULL, &child));
        child->type = SR_UINT32_T;
        child->data.uint32_val = i;
        assert_int_equal(0, sr_node_add_child(log_msg, "msg-type", NULL, &child));
        child->type = SR_ENUM_T;
        child->data.string_val = strdup("debug");
#endif
    }

    return SR_ERR_OK;
}

int
main(int argc, char **argv)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;
    int callback_called = 0;
    char msg_str[32] = { 0, };
    sr_log_stderr(SR_LL_ERR);

    /* connect to sysrepo */
    rc = sr_connect("rpc-example", SR_CONN_DEFAULT, &connection);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    /* start session */
    rc = sr_session_start(connection, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    /* subscribe for RPC */
    rc = sr_rpc_subscribe_tree(session, "/test-module:activate-software-image", test_rpc_cb, &callback_called,
            SR_SUBSCR_DEFAULT, &subscription);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    sr_node_t *input = NULL;
#ifdef NEW_API
    assert_int_equal(SR_ERR_OK, sr_new_tree("image-name", NULL, &input));
    assert_non_null(input);
    assert_non_null(input->_sr_mem);
    input->type = SR_STRING_T;
    sr_node_set_string(input, "acmefw-2.3");
#else
    input = calloc(1, sizeof *input);
    assert_non_null(input);
    assert_null(input->sr_mem);
    input->name = strdup("image-name");
    input->type = SR_STRING_T;
    input->data.string_val = strdup("acmefw-2.3");
#endif

    sr_node_t *output = NULL;
    size_t output_cnt = 0;

    for (int i = 0; i < NUM_OF_REQUESTS; ++i) {
        /* send a RPC */
        rc = sr_rpc_send_tree(session, "/test-module:activate-software-image", input, 1, &output, &output_cnt);
        if (SR_ERR_OK != rc) {
            goto cleanup;
        }

        assert_int_equal(i + 1, callback_called);

        /* check output */
        sr_node_t *sr_node = output, *log_msg = NULL, *child = NULL;
        size_t log_msg_cnt = 0;
        assert_int_equal(4, output_cnt);
        /*   /test-module:activate-software-image/output/status */
        assert_string_equal("status", sr_node->name);
        assert_string_equal("test-module", sr_node->module_name);
        assert_false(sr_node->dflt);
        assert_int_equal(SR_STRING_T, sr_node->type);
        assert_string_equal("The image acmefw-2.3 is being installed.", sr_node->data.string_val);
        assert_null(sr_node->first_child);
        assert_null(sr_node->last_child);
        /*   /test-module:activate-software-image/output/version */
        sr_node = output + 1;
        assert_string_equal("version", sr_node->name);
        assert_string_equal("test-module", sr_node->module_name);
        assert_false(sr_node->dflt);
        assert_int_equal(SR_STRING_T, sr_node->type);
        assert_string_equal("2.3", sr_node->data.string_val);
        assert_null(sr_node->first_child);
        assert_null(sr_node->last_child);
        /*   /test-module:activate-software-image/output/location */
        sr_node = output + 2;
        assert_string_equal("location", sr_node->name);
        assert_string_equal("test-module", sr_node->module_name);
        assert_true(sr_node->dflt);
        assert_int_equal(SR_STRING_T, sr_node->type);
        assert_string_equal("/", sr_node->data.string_val);
        assert_null(sr_node->first_child);
        assert_null(sr_node->last_child);
        /*   /test-module:activate-software-image/output/init-log */
        sr_node = output + 3;
        assert_string_equal("init-log", sr_node->name);
        assert_string_equal("test-module", sr_node->module_name);
        assert_false(sr_node->dflt);
        assert_int_equal(SR_CONTAINER_T, sr_node->type);

        log_msg_cnt = 0;
        log_msg = sr_node->first_child;
        while (log_msg) {
            snprintf(msg_str, 32, "Message number: %lu", log_msg_cnt);
            /*   /test-module:activate-software-image/output/init-log/log-msg */
            assert_string_equal("log-msg", log_msg->name);
            assert_null(log_msg->module_name);
            assert_false(log_msg->dflt);
            assert_int_equal(SR_LIST_T, log_msg->type);
            /*   /test-module:activate-software-image/output/init-log/log-msg/msg */
            child = log_msg->first_child;
            assert_non_null(child);
            assert_string_equal("msg", child->name);
            assert_null(child->module_name);
            assert_false(child->dflt);
            assert_int_equal(SR_STRING_T, child->type);
            assert_string_equal(msg_str, child->data.string_val);
            /*   /test-module:activate-software-image/output/init-log/log-msg/time */
            child = log_msg->first_child->next;
            assert_non_null(child);
            assert_string_equal("time", child->name);
            assert_null(child->module_name);
            assert_false(child->dflt);
            assert_int_equal(SR_UINT32_T, child->type);
            assert_int_equal(log_msg_cnt, child->data.uint32_val);
            /*   /test-module:activate-software-image/output/init-log/log-msg/msg-type */
            child = log_msg->first_child->next->next;
            assert_non_null(child);
            assert_string_equal("msg-type", child->name);
            assert_null(child->module_name);
            assert_false(child->dflt);
            assert_int_equal(SR_ENUM_T, child->type);
            assert_string_equal("debug", child->data.enum_val);
            assert_null(log_msg->first_child->next->next->next);

            log_msg = log_msg->next;
            ++log_msg_cnt;
        }
        assert_int_equal(OUTPUT_LOG_SIZE, log_msg_cnt);

        sr_free_trees(output, output_cnt);
    }

    sr_free_tree(input);

    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    printf("OK\n");

cleanup:
    if (NULL != session) {
        sr_session_stop(session);
    }
    if (NULL != connection) {
        sr_disconnect(connection);
    }
    return rc;
}
