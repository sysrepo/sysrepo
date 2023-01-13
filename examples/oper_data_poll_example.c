/**
 * @file oper_data_poll_example.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief example of an application subscribing for oper data polling
 *
 * @copyright
 * Copyright (c) 2022 CESNET, z.s.p.o.
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
    sr_subscription_ctx_t *subscr = NULL;
    int rc = SR_ERR_OK, valid_ms, gen_diff = 0;
    const char *mod_name, *xpath;

    if (argc < 4) {
        printf("%s <module-to-subscribe> <xpath-to-subscribe> <poll-interval-ms> [gen-diff]\n", argv[0]);
        return EXIT_FAILURE;
    }
    mod_name = argv[1];
    xpath = argv[2];
    valid_ms = atoi(argv[3]);
    if ((argc > 4) && !strcmp(argv[4], "gen-diff")) {
        gen_diff = 1;
    }

    printf("Application will poll oper get subscription on module \"%s\" xpath \"%s\" every %d ms%s.\n\n",
            mod_name, xpath, valid_ms, gen_diff ? " and generate changes" : "");

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

    /* start the oper poll subscription */
    rc = sr_oper_poll_subscribe(session, mod_name, xpath, valid_ms, gen_diff ? SR_SUBSCR_OPER_POLL_DIFF : 0, &subscr);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    printf("\n\n ========== OPERATIONAL DATA ARE BEING POLLED ==========\n\n");

    /* loop until ctrl-c is pressed / SIGINT is received */
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);
    while (!exit_application) {
        sleep(1000);
    }

    printf("Application exit requested, exiting.\n");

cleanup:
    sr_unsubscribe(subscr);
    sr_disconnect(connection);
    return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
