/**
 * @file application_example.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Example application that uses sysrepo as the configuration datastore.
 * The application can be used for testing purposes. It enables the module
 * specified as the first argument, or ietf-interfaces by default, in running
 * data store.
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
#include <inttypes.h>

#include "sysrepo.h"
#include "sysrepo/values.h"

volatile int exit_application = 0;

#define XPATH_MAX_LEN 100

static void
print_current_config(sr_session_ctx_t *session, const char *module_name)
{
    sr_val_t *values = NULL;
    size_t count = 0;
    int rc = SR_ERR_OK;
    char xpath[XPATH_MAX_LEN] = {0};
    snprintf(xpath, XPATH_MAX_LEN, "/%s:*//.", module_name);

    rc = sr_get_items(session, xpath, &values, &count);
    if (SR_ERR_OK != rc) {
        printf("Error by sr_get_items: %s\n", sr_strerror(rc));
        return;
    }
    for (size_t i = 0; i < count; i++){
        sr_print_val(&values[i]);
    }
    sr_free_values(values, count);
}

static int
module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    printf("\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG %s: ==========\n\n", module_name);

    print_current_config(session, module_name);

    return SR_ERR_OK;
}

static void
sigint_handler(int signum)
{
    exit_application = 1;
}

int
main(int argc, char **argv)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;

    if (argc == 1) {
        fprintf(stderr, "No modules specified.\n");
        return 1;
    }

    /* connect to sysrepo */
    rc = sr_connect("example_application", SR_CONN_DEFAULT, &connection);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_connect: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    /* start session */
    rc = sr_session_start(connection, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_session_start: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    for (int i = 1; i < argc; ++i) {
        /* read startup config */
        printf("\n\n ========== READING STARTUP CONFIG %s: ==========\n\n", argv[i]);
        print_current_config(session, argv[i]);

        /* subscribe for changes in running config */
        rc = sr_module_change_subscribe(session, argv[i], module_change_cb, NULL,
                0, SR_SUBSCR_DEFAULT | SR_SUBSCR_APPLY_ONLY, &subscription);
        if (SR_ERR_OK != rc) {
            fprintf(stderr, "Error by sr_module_change_subscribe: %s\n", sr_strerror(rc));
            goto cleanup;
        }

        printf("\n\n ========== STARTUP CONFIG %s APPLIED AS RUNNING ==========\n\n", argv[i]);
    }

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
    if (NULL != session) {
        sr_session_stop(session);
    }
    if (NULL != connection) {
        sr_disconnect(connection);
    }
    return rc;
}

