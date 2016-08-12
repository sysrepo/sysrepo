/**
 * @file sr_rpc_example.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Example usage of RPC.
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

#include "sysrepo.h"
#include "sr_experimental.h"

#define NUM_OF_REQUESTS   1000
#define OUTPUT_LOG_SIZE   100

#define PERF_TEST             1
#define EXPERIMENTAL_MEM_MGMT 1
//#define API_ONLY              1

#ifndef PERF_TEST
#include <assert.h>
#endif

#define assert_int_equal(a, b)     assert(a == b)
#define assert_string_equal(a, b)  assert(0 == strcmp(a, b))
#define assert_true(a)             assert(a)
#define assert_false(a)            assert(!a)
#define assert_null(a)             assert(NULL == a)
#define assert_non_null(a)         assert(NULL != a)

static int
test_rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt,
        sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    int *callback_called = (int*)private_ctx;
    char log_msg[256] = { 0, };
    *callback_called += 1;

#ifndef PERF_TEST
    /* check input */
    assert_int_equal(2, input_cnt);
    assert_string_equal("/test-module:activate-software-image/image-name", input[0].xpath);
    assert_false(input[0].dflt);
    assert_int_equal(SR_STRING_T, input[0].type);
    assert_string_equal("acmefw-2.3", input[0].data.string_val);

    assert_string_equal("/test-module:activate-software-image/location", input[1].xpath);
    assert_true(input[1].dflt);
    assert_int_equal(SR_STRING_T, input[1].type);
    assert_string_equal("/", input[1].data.string_val);
#endif

    *output_cnt = 2 + OUTPUT_LOG_SIZE;
#ifdef EXPERIMENTAL_MEM_MGMT
    sr_new_values(*output_cnt, output);
    sr_val_set_xpath(*output, "/test-module:activate-software-image/status");
    (*output)[0].type = SR_STRING_T;
    sr_val_set_string(*output, "The image acmefw-2.3 is being installed.");

    sr_val_set_xpath(*output + 1, "/test-module:activate-software-image/version");
    (*output)[1].type = SR_STRING_T;
    sr_val_set_string(*output + 1, "2.3");
#else
    *output = calloc(*output_cnt, sizeof(**output));
    (*output)[0].xpath = strdup("/test-module:activate-software-image/status");
    (*output)[0].type = SR_STRING_T;
    (*output)[0].data.string_val = strdup("The image acmefw-2.3 is being installed.");

    (*output)[1].xpath = strdup("/test-module:activate-software-image/version");
    (*output)[1].type = SR_STRING_T;
    (*output)[1].data.string_val = strdup("2.3");
#endif

    for (size_t i = 0; i < OUTPUT_LOG_SIZE; ++i) {
        snprintf(log_msg, 256, "/test-module:activate-software-image/init-log/log-msg[msg='Message number: %lu'][time='%lu']/msg-type",
                 i, i);
#ifdef EXPERIMENTAL_MEM_MGMT
        sr_val_set_xpath(*output + i + 2, log_msg);
        (*output)[i + 2].type = SR_ENUM_T;
        sr_val_set_string(*output + i + 2, "debug");
#else
        (*output)[i + 2].xpath = strdup(log_msg);
        (*output)[i + 2].type = SR_ENUM_T;
        (*output)[i + 2].data.enum_val = strdup("debug");
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
#ifndef PERF_TEST
    char log_msg[256] = { 0, }, msg_str[32] = { 0, };
    char *log_msg_tail = NULL;
#endif
    sr_log_stderr(SR_LL_ERR);

#if !defined(API_ONLY) || !defined(PERF_TEST)
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
    rc = sr_rpc_subscribe(session, "/test-module:activate-software-image", test_rpc_cb, &callback_called,
            SR_SUBSCR_DEFAULT, &subscription);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }
#endif

    sr_val_t *input = NULL;
#ifdef EXPERIMENTAL_MEM_MGMT
    assert_int_equal(SR_ERR_OK, sr_new_val("/test-module:activate-software-image/image-name", &input));
    assert_non_null(input);
    assert_non_null(input->sr_mem);
    input->type = SR_STRING_T;
    sr_val_set_string(input, "acmefw-2.3");
#else
    input = calloc(1, sizeof *input);
    assert_non_null(input);
    assert_null(input->sr_mem);
    input->xpath = strdup("/test-module:activate-software-image/image-name");
    input->type = SR_STRING_T;
    input->data.string_val = strdup("acmefw-2.3");
#endif

    sr_val_t *output = NULL;
    size_t output_cnt = 0;

    for (int i = 0; i < NUM_OF_REQUESTS; ++i) {
#if defined(API_ONLY) && defined(PERF_TEST)
        test_rpc_cb("/test-module:activate-software-image", input, 1, &output, &output_cnt, &callback_called);
#else
        /* send a RPC */
        rc = sr_rpc_send(session, "/test-module:activate-software-image", input, 1, &output, &output_cnt);
        if (SR_ERR_OK != rc) {
            goto cleanup;
        }
#endif

        assert_int_equal(i + 1, callback_called);

#ifndef PERF_TEST
        /* check output */
        assert_int_equal(4 + 4 * OUTPUT_LOG_SIZE, output_cnt);
        assert_string_equal("/test-module:activate-software-image/status", output[0].xpath);
        assert_false(output[0].dflt);
        assert_int_equal(SR_STRING_T, output[0].type);
        assert_string_equal("The image acmefw-2.3 is being installed.", output[0].data.string_val);

        assert_string_equal("/test-module:activate-software-image/version", output[1].xpath);
        assert_false(output[1].dflt);
        assert_int_equal(SR_STRING_T, output[1].type);
        assert_string_equal("2.3", output[1].data.string_val);

        assert_string_equal("/test-module:activate-software-image/location", output[2].xpath);
        assert_true(output[2].dflt);
        assert_int_equal(SR_STRING_T, output[2].type);
        assert_string_equal("/", output[2].data.string_val);

        assert_string_equal("/test-module:activate-software-image/init-log", output[3].xpath);
        assert_false(output[3].dflt);
        assert_int_equal(SR_CONTAINER_T, output[3].type);

        for (size_t i = 0; i < OUTPUT_LOG_SIZE; ++i) {
            snprintf(log_msg, 256, "/test-module:activate-software-image/init-log/log-msg[msg='Message number: %lu'][time='%lu']",
                     i, i);
            snprintf(msg_str, 32, "Message number: %lu", i);
            log_msg_tail = log_msg + strlen(log_msg);

            assert_string_equal(log_msg, output[4 + 4*i].xpath);
            assert_false(output[4 + 4*i].dflt);
            assert_int_equal(SR_LIST_T, output[4 + 4*i].type);

            strcat(log_msg, "/msg");
            assert_string_equal(log_msg, output[5 + 4*i].xpath);
            assert_false(output[5 + 4*i].dflt);
            assert_int_equal(SR_STRING_T, output[5 + 4*i].type);
            assert_string_equal(msg_str, output[5 + 4*i].data.string_val);

            *log_msg_tail = '\0';
            strcat(log_msg, "/time");
            assert_string_equal(log_msg, output[6 + 4*i].xpath);
            assert_false(output[6 + 4*i].dflt);
            assert_int_equal(SR_UINT32_T, output[6 + 4*i].type);
            assert_int_equal(i, output[6 + 4*i].data.uint32_val);

            *log_msg_tail = '\0';
            strcat(log_msg, "/msg-type");
            assert_string_equal(log_msg, output[7 + 4*i].xpath);
            assert_false(output[7 + 4*i].dflt);
            assert_int_equal(SR_ENUM_T, output[7 + 4*i].type);
            assert_string_equal("debug", output[7 + 4*i].data.enum_val);
        }
#endif

        sr_free_values(output, output_cnt);
    }

    sr_free_val(input);

#if !defined(API_ONLY) || !defined(PERF_TEST)
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);
#endif

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
