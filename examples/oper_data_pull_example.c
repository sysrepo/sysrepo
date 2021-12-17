/**
 * @file oper_data_pull_example.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief example of an application providing some operational data by a callback
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

#define _QNX_SOURCE /* sleep() */
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

static int
dp_get_items_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    (void)session;
    (void)sub_id;
    (void)request_id;
    (void)private_data;

    printf("\n\n ========== DATA FOR \"%s\" \"%s\" \"%s\" REQUESTED =======================\n\n", module_name, xpath, request_xpath);

    if (!strcmp(module_name, "examples")) {
        if (strstr(request_xpath, "/examples:stats")) {
            lyd_new_path(NULL, sr_get_context(sr_session_get_connection(session)), "/examples:stats/counter", "852", 0, parent);
            lyd_new_path(*parent, NULL, "/examples:stats/counter2", "1052", 0, NULL);
        } else if (strstr(request_xpath, "/examples:cont/l2")) {
            lyd_new_path(NULL, sr_get_context(sr_session_get_connection(session)), "/examples:cont/l2", "plugh", 0, parent);
        }
    }

    return SR_ERR_OK;
}

static void
sigint_handler(int signum)
{
    (void)signum;

    exit_application = 1;
}

int
main(int argc, char **argv)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_subscr_options_t opt = SR_SUBSCR_OPER_MERGE;
//    sr_subscr_options_t opt = SR_SUBSCR_DEFAULT;
    int rc = SR_ERR_OK;
    const char *mod_name;

    if (argc < 3) {
        printf("%s <module-to-provide-data-from> <path-to-provide> [<path-to-provide> ...]\n", argv[0]);
        return EXIT_FAILURE;
    }
    mod_name = argv[1];

    for (int i = 2; i < argc; i++) {
    	printf("Application will provide data \"%s\" of \"%s\".\n\n", argv[i], mod_name);
    }

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

    for (int i = 2; i < argc; i++) {
        /* subscribe for providing the operational data */
        rc = sr_oper_get_items_subscribe(session, mod_name, argv[i], dp_get_items_cb, NULL, opt, &subscription);
        if (rc != SR_ERR_OK) {
            goto cleanup;
        }
        opt |= SR_SUBSCR_CTX_REUSE;
    }

    printf("\n\n ========== LISTENING FOR REQUESTS ==========\n\n");

    /* loop until ctrl-c is pressed / SIGINT is received */
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);
    while (!exit_application) {
        sleep(1000);
    }

    printf("Application exit requested, exiting.\n");

cleanup:
    sr_disconnect(connection);
    return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
