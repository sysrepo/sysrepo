/**
 * @file oper_pull_push_example.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief example of an application providing some operational data
 *
 * @copyright
 * Copyright (c) 2020 CESNET, z.s.p.o.
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

static int
dp_get_items_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, const char *request_xpath,
        uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    (void)session;
    (void)request_xpath;
    (void)request_id;
    (void)private_data;

    if (!strcmp(module_name, "examples") && !strcmp(xpath, "/examples:stats")) {
        *parent = lyd_new_path(NULL, sr_get_context(sr_session_get_connection(session)), "/examples:stats/counter", "852", 0, 0);
        lyd_new_path(*parent, NULL, "/examples:stats/counter2", "1052", 0, 0);
    }

    return SR_ERR_OK;
}

int
main(void)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;
    const char *mod_name, *path;
    struct lyd_node *data;

    path = "/examples:stats";
    mod_name = "examples";

    /* turn logging on */
    sr_log_stderr(SR_LL_WRN);

    /* connect to sysrepo */
    rc = sr_connect(0, &connection);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    if (!ly_ctx_get_module(sr_get_context(connection), mod_name, NULL, 1)) {
        fprintf(stderr, "Module \"%s\" must be installed in sysrepo for this example to work.\n", mod_name);
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    /* start session in operational datastore */
    rc = sr_session_start(connection, SR_DS_OPERATIONAL, &session);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    printf("Application will provide data \"%s\" of \"%s\" using both pull and push operational data subscription.\n\n",
            path, mod_name);

    /* subscribe for providing pull operational data */
    rc = sr_oper_get_items_subscribe(session, mod_name, path, dp_get_items_cb, NULL, 0, &subscription);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* get data */
    printf("======= PULL OPERATIONAL DATA \"%s\" REQUESTED ========\n\n", path);
    rc = sr_get_data(session, path, 0, 0, 0, &data);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* print data */
    lyd_print_file(stdout, data, LYD_XML, LYP_FORMAT | LYP_WITHSIBLINGS);
    printf("\n");
    lyd_free_withsiblings(data);

    /* unsubscribe */
    sr_unsubscribe(subscription);

    /* set push operational data (their lifetime is limited by the lifetime of the connection!) */
    rc = sr_set_item_str(session, "/examples:stats/counter", "852", NULL, 0);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }
    rc = sr_set_item_str(session, "/examples:stats/counter2", "1052", NULL, 0);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }
    rc = sr_apply_changes(session, 0, 1);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* get data */
    printf("======= PUSH OPERATIONAL DATA \"%s\" REQUESTED ========\n\n", path);
    rc = sr_get_data(session, path, 0, 0, 0, &data);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* print data */
    lyd_print_file(stdout, data, LYD_XML, LYP_FORMAT | LYP_WITHSIBLINGS);
    printf("\n");
    lyd_free_withsiblings(data);

cleanup:
    sr_disconnect(connection);
    return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
