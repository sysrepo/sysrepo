/**
 * @file sr_set_item_example.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief example of an application that sets a value
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

#include "sysrepo.h"

int
main(int argc, char **argv)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;
    const char *xpath, *value;

    if (argc != 3) {
        printf("%s <xpath-to-set> <value-to-set>\n", argv[0]);
        return EXIT_FAILURE;
    }
    xpath = argv[1];
    value = argv[2];

    printf("Application will set \"%s\" to \"%s\".\n", xpath, value);

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

    /* set the value */
    rc = sr_set_item_str(session, xpath, value, NULL, 0);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* apply the change */
    rc = sr_apply_changes(session, 0);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

cleanup:
    sr_disconnect(connection);
    return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
