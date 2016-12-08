/**
 * @file notifications_test_app.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Subscribes to be notified about the changes under selected xpath. Saves
 * the changes into a file
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

typedef struct settings_s{
    char *filename;
    char *xpath;
}settings_t;

static void
print_value(FILE *f, sr_val_t *value)
{
    fprintf(f, "%s|", value->xpath);

    switch (value->type) {
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
        fprintf(f, "(container)");
        break;
    case SR_LIST_T:
        fprintf(f, "(list instance)");
        break;
    case SR_STRING_T:
        fprintf(f, "%s", value->data.string_val);
        break;
    case SR_BOOL_T:
        fprintf(f, "%s", value->data.bool_val ? "true" : "false");
        break;
    case SR_ENUM_T:
        fprintf(f, "%s", value->data.enum_val);
        break;
    case SR_DECIMAL64_T:
        fprintf(f, "%g", value->data.decimal64_val);
        break;
    case SR_INT8_T:
        fprintf(f, "%" PRId8, value->data.int8_val);
        break;
    case SR_INT16_T:
        fprintf(f, "%" PRId16, value->data.int16_val);
        break;
    case SR_INT32_T:
        fprintf(f, "%" PRId32, value->data.int32_val);
        break;
    case SR_INT64_T:
        fprintf(f, "%" PRId64, value->data.int64_val);
        break;
    case SR_UINT8_T:
        fprintf(f, "%" PRIu8, value->data.uint8_val);
        break;
    case SR_UINT16_T:
        fprintf(f, "%" PRIu16, value->data.uint16_val);
        break;
    case SR_UINT32_T:
        fprintf(f, "%" PRIu32, value->data.uint32_val);
        break;
    case SR_UINT64_T:
        fprintf(f, "%" PRIu64, value->data.uint64_val);
        break;
    case SR_IDENTITYREF_T:
        fprintf(f, "%s", value->data.identityref_val);
        break;
    case SR_BITS_T:
        fprintf(f, "%s", value->data.bits_val);
        break;
    case SR_BINARY_T:
        fprintf(f, "%s", value->data.binary_val);
        break;
    default:
        fprintf(f, "(unprintable)");
    }
}

static void
print_change(FILE *f, sr_change_oper_t op, sr_val_t *old_val, sr_val_t *new_val)
{
    switch (op) {
    case SR_OP_CREATED:
        if (NULL != new_val) {
            fprintf(f, "CREATED|");
            print_value(f, new_val);
        }
        break;
    case SR_OP_DELETED:
        if (NULL != old_val) {
            fprintf(f, "DELETED|");
            print_value(f, old_val);
        }
        break;
    case SR_OP_MODIFIED:
        if (NULL != old_val && NULL != new_val) {
            fprintf(f, "MODIFIED|");
            print_value(f, old_val);
            fprintf(f, "|");
            print_value(f, new_val);
        }
        break;
    case SR_OP_MOVED:
        if (NULL != new_val) {
            fprintf(f, "MOVED|%s|%s", new_val->xpath, NULL != old_val ? old_val->xpath : NULL);
        }
        break;
    }
    fprintf(f, "\n");
}

static int
subtree_change_cb(sr_session_ctx_t *session, const char *xpath, sr_notif_event_t event, void *private_ctx)
{
    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    settings_t *settings = (settings_t *) private_ctx;

    FILE *out = settings->filename ? fopen(settings->filename, "w") : stdout;
    if (NULL == out) {
        printf("File %s can not be opened", settings->filename);
        return SR_ERR_INTERNAL;
    }

    rc = sr_get_changes_iter(session, xpath, &it);
    if (SR_ERR_OK != rc) {
        printf("Get changes iter failed for xpath %s", xpath);
        goto cleanup;
    }

    while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
            &oper, &old_value, &new_value))) {
        print_change(out, oper, old_value, new_value);
        sr_free_val(old_value);
        sr_free_val(new_value);
    }


cleanup:
    if (out != stdin) {
        fclose(out);
    }
    sr_free_change_iter(it);

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
    settings_t settings = {0};

    if (argc < 2) {
        printf("Usage: %s path_to_subscribe [output_file]\n\n", argv[0]);
        return 1;
    }

    settings.xpath = argv[1];
    settings.filename = argc == 3 ? argv[2] : NULL;


    printf("Application will watch for changes under xpath %s\n", settings.xpath);
    /* connect to sysrepo */
    rc = sr_connect("notification_test_application", SR_CONN_DEFAULT, &connection);
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


    /* subscribe for changes in running config - try three times because in test
     * multiple client might try to subscribe for the same model */
    for (int i = 0; i < 3; i++) {
        rc = sr_subtree_change_subscribe(session, settings.xpath, subtree_change_cb, &settings, 0, SR_SUBSCR_DEFAULT, &subscription);
        if (SR_ERR_LOCKED == rc) {
            fprintf(stderr, "Retrying to subscribe...\n");
            usleep(10);
        } else {
            break;
        }
    }

    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_module_change_subscribe: %s %s\n", sr_strerror(rc), settings.xpath);
        goto cleanup;
    }

    /* loop until ctrl-c is pressed / SIGINT is received */
    signal(SIGINT, sigint_handler);
    while (!exit_application) {
        sleep(1000); /* or do some more useful work... */
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
