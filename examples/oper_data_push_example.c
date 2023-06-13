/**
 * @file oper_data_push_example.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief example of an application storing some operational data
 *
 * @copyright
 * Copyright (c) 2021 CESNET, z.s.p.o.
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

volatile int exit_application = 0;

static void
sigint_handler(int signum)
{
    (void)signum;

    exit_application = 1;
}

int
main(int argc, const char **argv)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;
    const char *path, *filepath = NULL, *value = NULL;
    const struct ly_ctx *ly_ctx = NULL;
    struct lyd_node *edit = NULL;

    if (argc < 2) {
        printf("%s <file-to-set> / ( <path-to-set> (<value-to-set>) )\n", argv[0]);
        return EXIT_FAILURE;
    }
    path = argv[1];
    if (argc > 2) {
        value = argv[2];
    }

    if (strrchr(path, '.')) {
        filepath = path;
    }

    if (filepath) {
        printf("Application will parse and set \"%s\".\n\n", filepath);
    } else if (value) {
        printf("Application will set \"%s\" to value \"%s\".\n\n", path, value);
    } else {
        printf("Application will set \"%s\".\n\n", path);
    }

    /* turn logging on */
    sr_log_stderr(SR_LL_WRN);

    /* connect to sysrepo */
    rc = sr_connect(0, &connection);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* start session in operational datastore */
    rc = sr_session_start(connection, SR_DS_OPERATIONAL, &session);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    if (filepath) {
        /* parse the edit */
        ly_ctx = sr_session_acquire_context(session);
        rc = lyd_parse_data_path(ly_ctx, filepath, LYD_UNKNOWN, LYD_PARSE_ONLY | LYD_PARSE_STRICT, 0, &edit);
        if (rc != LY_SUCCESS) {
            printf("LY ERR: %s\n", ly_last_errmsg());
            goto cleanup;
        }

        /* set it */
        rc = sr_edit_batch(session, edit, "merge");
        if (rc != SR_ERR_OK) {
            goto cleanup;
        }
    } else {
        /* set push operational data (their lifetime is limited by the lifetime of the connection) */
        rc = sr_set_item_str(session, path, value, NULL, 0);
        if (rc != SR_ERR_OK) {
            goto cleanup;
        }
    }
    rc = sr_apply_changes(session, 0);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    printf("\n\n ========== WAITING AS OWNER OF SET DATA ==========\n\n");

    /* loop until ctrl-c is pressed / SIGINT is received */
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);
    while (!exit_application) {
        sleep(1000);
    }

    printf("Application exit requested, exiting.\n");

cleanup:
    if (ly_ctx) {
        lyd_free_siblings(edit);
        sr_session_release_context(session);
    }
    sr_disconnect(connection);
    return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
