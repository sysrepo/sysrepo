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

volatile int exit_application = 0;

#define XPATH_MAX_LEN 100

static void
print_value(sr_val_t *value)
{
    printf("%s ", value->xpath);

    switch (value->type) {
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
        printf("(container)\n");
        break;
    case SR_LIST_T:
        printf("(list instance)\n");
        break;
    case SR_STRING_T:
        printf("= %s\n", value->data.string_val);
        break;
    case SR_BOOL_T:
        printf("= %s\n", value->data.bool_val ? "true" : "false");
        break;
    case SR_ENUM_T:
        printf("= %s\n", value->data.enum_val);
        break;
    case SR_DECIMAL64_T:
        printf("= %g\n", value->data.decimal64_val);
        break;
    case SR_INT8_T:
        printf("= %" PRId8 "\n", value->data.int8_val);
        break;
    case SR_INT16_T:
        printf("= %" PRId16 "\n", value->data.int16_val);
        break;
    case SR_INT32_T:
        printf("= %" PRId32 "\n", value->data.int32_val);
        break;
    case SR_INT64_T:
        printf("= %" PRId64 "\n", value->data.int64_val);
        break;
    case SR_UINT8_T:
        printf("= %" PRIu8 "\n", value->data.uint8_val);
        break;
    case SR_UINT16_T:
        printf("= %" PRIu16 "\n", value->data.uint16_val);
        break;
    case SR_UINT32_T:
        printf("= %" PRIu32 "\n", value->data.uint32_val);
        break;
    case SR_UINT64_T:
        printf("= %" PRIu64 "\n", value->data.uint64_val);
        break;
    case SR_IDENTITYREF_T:
        printf("= %s\n", value->data.identityref_val);
        break;
    case SR_BITS_T:
        printf("= %s\n", value->data.bits_val);
        break;
    case SR_BINARY_T:
        printf("= %s\n", value->data.binary_val);
        break;
    default:
        printf("(unprintable)\n");
    }
}

static void
print_current_config(sr_session_ctx_t *session, const char *module_name)
{
    sr_val_t *values = NULL;
    size_t count = 0;
    int rc = SR_ERR_OK;
    char xpath[XPATH_MAX_LEN] = {0};
    snprintf(xpath, XPATH_MAX_LEN, "/%s:*//*", module_name);

    rc = sr_get_items(session, xpath, &values, &count);
    if (SR_ERR_OK != rc) {
        printf("Error by sr_get_items: %s", sr_strerror(rc));
        return;
    }
    for (size_t i = 0; i < count; i++){
        print_value(&values[i]);
    }
    sr_free_values(values, count);
}

static int
module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    printf("\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG: ==========\n\n");

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

    char *module_name = "ietf-interfaces";
    if (argc > 1) {
        module_name = argv[1];
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

    /* read startup config */
    printf("\n\n ========== READING STARTUP CONFIG: ==========\n\n");
    print_current_config(session, module_name);

    /* subscribe for changes in running config */
    rc = sr_module_change_subscribe(session, module_name, module_change_cb, NULL,
            0, SR_SUBSCR_DEFAULT | SR_SUBSCR_APPLY_ONLY, &subscription);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_module_change_subscribe: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    printf("\n\n ========== STARTUP CONFIG APPLIED AS RUNNING ==========\n\n");

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

