/**
 * @file application_example.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Example application that uses sysrepo as the configuraton datastore.
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
#include "sysrepo.h"

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
    case SR_UINT8_T:
        printf("= %u\n", value->data.uint8_val);
        break;
    case SR_UINT16_T:
        printf("= %u\n", value->data.uint16_val);
        break;
    case SR_UINT32_T:
        printf("= %u\n", value->data.uint32_val);
        break;
    case SR_IDENTITYREF_T:
        printf("= %s\n", value->data.identityref_val);
        break;
    default:
        printf("(unprintable)\n");
    }
}

static void
print_current_config(sr_session_ctx_t *session)
{
    sr_val_t *values = NULL;
    size_t count = 0;
    int rc = SR_ERR_OK;

    rc = sr_get_items(session, "/ietf-interfaces:*//*", &values, &count);
    if (SR_ERR_OK != rc) {
        printf("Error: %s", sr_strerror(rc));
        return;
    }
    for (size_t i = 0; i < count; i++){
        print_value(&values[i]);
    }
    sr_free_values(values, count);
}

static void
module_change_cb(sr_session_ctx_t *session, const char *module_name, void *private_ctx)
{
    printf("\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG: ==========\n\n");
    print_current_config(session);
}

int
main(int argc, char **argv)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;

    sr_log_stderr(SR_LL_DBG);

    /* connect to sysrepo */
    rc = sr_connect("example_application", SR_CONN_DEFAULT, &connection);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    /* start session */
    rc = sr_session_start(connection, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    /* read startup config */
    printf("\n\n ========== READING STARTUP CONFIG: ==========\n\n");
    print_current_config(session);

    /* subscribe for changes in running config */
    rc = sr_module_change_subscribe(session, "ietf-interfaces", true, module_change_cb, NULL, &subscription);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    printf("\n\n ========== STARTUP CONFIG APPLIED AS RUNNING ==========\n\n");

    while (1) {
        /* do some work... */
        sleep(1);
    }

cleanup:
    if (NULL != subscription) {
        sr_unsubscribe(subscription);
    }
    if (NULL != session) {
        sr_session_stop(session);
    }
    if (NULL != connection) {
        sr_disconnect(connection);
    }
    return rc;
}

