/**
 * @file rpc_tree_example.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Example usage of the tree variant of RPC API.
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
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <limits.h>

#include "sysrepo.h"
#include "sysrepo/trees.h"

volatile int exit_application = 0;

static int
rpc_cb(const char *xpath, const sr_node_t *input, const size_t input_cnt,
       sr_node_t **output, size_t *output_cnt, void *private_ctx)
{
    int rc = SR_ERR_OK;
    sr_session_ctx_t *session = (sr_session_ctx_t *)private_ctx;

    /* print input data */
    printf("\n\n ========== RECEIVED RPC REQUEST ==========\n\n");
    printf(">>> RPC Input:\n\n");
    for (size_t i = 0; i < input_cnt; ++i) {
        sr_print_tree(input+i, INT_MAX);
    }
    printf("\n");

    /**
     * Here you would actually run the operation against the provided input data
     * and obtained the output data.
     */
    printf(">>> Executing RPC...\n\n");

    /* allocate output sub-trees */
    rc = sr_new_trees(2, output);
    if (SR_ERR_OK != rc) {
        return rc;
    }

    /* set 'output/step-count' leaf */
    rc = sr_node_set_name(&(*output)[0], "step-count");
    if (SR_ERR_OK != rc) {
        return rc;
    }
    (*output)[0].type = SR_UINT64_T;
    (*output)[0].data.uint64_val = 256;

    /* set 'output/halted' leaf */
    rc = sr_node_set_name(&(*output)[1], "halted");
    if (SR_ERR_OK != rc) {
        return rc;
    }
    (*output)[1].type = SR_BOOL_T;
    (*output)[1].data.bool_val = false;

    /* inform sysrepo about the number of output sub-trees */
    *output_cnt = 2;

    printf(">>> RPC Output:\n\n");
    for (size_t i = 0; i < *output_cnt; ++i) {
        sr_print_tree(&(*output)[i], INT_MAX);
    }
    printf("\n");

    /* send notification for event_notif_sub(_tree)_example */
    printf(">>> Sending event notification for '/turing-machine:paused'...\n");
    /* note: we can re-use input trees as Sysrepo trees are not bind to xpath */
    rc = sr_event_notif_send_tree(session, "/turing-machine:paused", input, input_cnt, SR_EV_NOTIF_DEFAULT);
    if (SR_ERR_NOT_FOUND == rc) {
        printf("No application subscribed for '/turing-machine:paused', skipping.\n"
               "(run event_notif_sub_example or event_notif_sub_tree_example)\n\n");
        rc = SR_ERR_OK;
    }

    /**
     * Do not deallocate input trees!
     * They will get freed automatically by sysrepo.
     */
    printf(">>> RPC finished.\n\n");
    return rc;
}

static void
sigint_handler(int signum)
{
    exit_application = 1;
}

static int
rpc_handler(sr_session_ctx_t *session)
{
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;

    /* subscribe for handling RPC */
    rc = sr_rpc_subscribe_tree(session, "/turing-machine:run-until", rpc_cb,
            (void *)session, SR_SUBSCR_DEFAULT, &subscription);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_rpc_subscribe: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    printf("\n\n ========== SUBSCRIBED FOR HANDLING RPC ==========\n\n");

    /* loop until ctrl-c is pressed / SIGINT is received */
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);
    while (!exit_application) {
        sleep(1000);  /* or do some more useful work... */
    }

    printf("Application exit requested, exiting.\n");

cleanup:
    if (NULL != subscription) {
        sr_unsubscribe(session, subscription);
    }
    return rc;
}

static int
rpc_caller(sr_session_ctx_t *session)
{
    sr_node_t *input = NULL, *list = NULL, *leaf = NULL, *output = NULL;
    size_t input_cnt = 0, output_cnt = 0;
    int rc = SR_ERR_OK;

    /* allocate input sub-trees */
    input_cnt = 3;
    rc = sr_new_trees(input_cnt, &input);
    if (SR_ERR_OK != rc) {
        return rc;
    }

    /* set 'input/state' leaf */
    rc = sr_node_set_name(&input[0], "state");
    if (SR_ERR_OK != rc) {
        return rc;
    }
    input[0].type = SR_UINT16_T;
    input[0].data.uint16_val = 10;

    /* set 'input/head-position' leaf */
    rc = sr_node_set_name(&input[1], "head-position");
    if (SR_ERR_OK != rc) {
        return rc;
    }
    input[1].type = SR_INT64_T;
    input[1].data.uint16_val = 123;

    /* build 'input/tape' subtree */
    rc = sr_node_set_name(&input[2], "tape");
    if (SR_ERR_OK != rc) {
        return rc;
    }
    input[2].type = SR_CONTAINER_T;
    for (size_t i = 0; i < 5; ++i) {
        /* - list instance */
        rc = sr_node_add_child(&input[2], "cell", NULL, &list);
        if (SR_ERR_OK != rc) {
            return rc;
        }
        list->type = SR_LIST_T;
        /* - 'coord' */
        rc = sr_node_add_child(list, "coord", NULL, &leaf);
        if (SR_ERR_OK != rc) {
            return rc;
        }
        leaf->type = SR_INT64_T;
        leaf->data.int64_val = i;
        /* - 'symbol' */
        rc = sr_node_add_child(list, "symbol", NULL, &leaf);
        if (SR_ERR_OK != rc) {
            return rc;
        }
        sr_node_build_str_data(leaf, SR_STRING_T, "%c", 'A'+i);
    }

    printf("\n\n ========== EXECUTING RPC ==========\n\n");
    printf(">>> RPC Input:\n\n");
    for (size_t i = 0; i < input_cnt; ++i) {
        sr_print_tree(&input[i], INT_MAX);
    }
    printf("\n");

    /* execute RPC */
    rc = sr_rpc_send_tree(session, "/turing-machine:run-until", input, input_cnt, &output, &output_cnt);
    if (SR_ERR_OK != rc) {
        return rc;
    }

    /* print output data */
    printf("\n>>> Received an RPC response:\n\n");
    for (size_t i = 0; i < output_cnt; ++i) {
        sr_print_tree(output+i, INT_MAX);
    }

    /* don't forget to de-allocate the output trees */
    sr_free_trees(output, output_cnt);
    return SR_ERR_OK;
}

int
main(int argc, char **argv)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;

    /* connect to sysrepo */
    rc = sr_connect("example_application", SR_CONN_DEFAULT, &connection);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_connect: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    /* start session */
    rc = sr_session_start(connection, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_session_start: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    if (1 == argc) {
        /* run as a RPC handler */
        printf("This application will be an RPC handler for 'run-until' operation of 'turing-machine'.\n");
        printf("Run the same executable (or rpc_example) with one (any) argument to execute the RPC.\n");
        rc = rpc_handler(session);
    } else {
        /* run as a RPC caller */
        printf("Executing RPC 'run-until' of 'turing-machine':\n");
        rc = rpc_caller(session);
    }

cleanup:
    if (NULL != session) {
        sr_session_stop(session);
    }
    if (NULL != connection) {
        sr_disconnect(connection);
    }
    return rc;
}
