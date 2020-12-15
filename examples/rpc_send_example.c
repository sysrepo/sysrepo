/**
 * @file rpc_send_example.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief example of an application that sends an RPC
 *
 * @copyright
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#define _GNU_SOURCE

#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "sysrepo.h"

static void
print_val(const sr_val_t *value)
{
    if (NULL == value) {
        return;
    }

    printf("%s ", value->xpath);

    switch (value->type) {
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
        printf("(container)");
        break;
    case SR_LIST_T:
        printf("(list instance)");
        break;
    case SR_STRING_T:
        printf("= %s", value->data.string_val);
        break;
    case SR_BOOL_T:
        printf("= %s", value->data.bool_val ? "true" : "false");
        break;
    case SR_DECIMAL64_T:
        printf("= %g", value->data.decimal64_val);
        break;
    case SR_INT8_T:
        printf("= %" PRId8, value->data.int8_val);
        break;
    case SR_INT16_T:
        printf("= %" PRId16, value->data.int16_val);
        break;
    case SR_INT32_T:
        printf("= %" PRId32, value->data.int32_val);
        break;
    case SR_INT64_T:
        printf("= %" PRId64, value->data.int64_val);
        break;
    case SR_UINT8_T:
        printf("= %" PRIu8, value->data.uint8_val);
        break;
    case SR_UINT16_T:
        printf("= %" PRIu16, value->data.uint16_val);
        break;
    case SR_UINT32_T:
        printf("= %" PRIu32, value->data.uint32_val);
        break;
    case SR_UINT64_T:
        printf("= %" PRIu64, value->data.uint64_val);
        break;
    case SR_IDENTITYREF_T:
        printf("= %s", value->data.identityref_val);
        break;
    case SR_INSTANCEID_T:
        printf("= %s", value->data.instanceid_val);
        break;
    case SR_BITS_T:
        printf("= %s", value->data.bits_val);
        break;
    case SR_BINARY_T:
        printf("= %s", value->data.binary_val);
        break;
    case SR_ENUM_T:
        printf("= %s", value->data.enum_val);
        break;
    case SR_LEAF_EMPTY_T:
        printf("(empty leaf)");
        break;
    default:
        printf("(unprintable)");
        break;
    }

    switch (value->type) {
    case SR_UNKNOWN_T:
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
    case SR_LIST_T:
    case SR_LEAF_EMPTY_T:
        printf("\n");
        break;
    default:
        printf("%s\n", value->dflt ? " [default]" : "");
        break;
    }
}

int
main(int argc, char **argv)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;
    sr_val_t *output = NULL;
    size_t i, output_count = 0;
    const char *path;

    if (argc != 2) {
        printf("%s <rpc-path>\n", argv[0]);
        return EXIT_FAILURE;
    }
    path = argv[1];

    printf("Application will send RPC \"%s\".\n\n", path);

    /* turn logging on */
    sr_log_stderr(SR_LL_WRN);

    /* connect to sysrepo */
    rc = sr_connect(0, &connection);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* start session */
    rc = sr_session_start(connection, SR_DS_RUNNING, &session);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* send the RPC */
    rc = sr_rpc_send(session, path, NULL, 0, 0, &output, &output_count);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* print output */
    printf("\n ========== RECEIVED OUTPUT: ==========\n\n");
    for (i = 0; i < output_count; ++i) {
        print_val(&output[i]);
    }

cleanup:
    sr_free_values(output, output_count);
    sr_disconnect(connection);
    return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
