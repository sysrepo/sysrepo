/**
 * @file oper_data_example.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Example usage operational data API.
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
#include <string.h>
#include <inttypes.h>

#include "sysrepo.h"
#include "sysrepo/values.h"
#include "sysrepo/xpath.h"

volatile int exit_application = 0;

static int
data_provider_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    sr_val_t *v = NULL;

    printf("Data for '%s' requested.\n", xpath);

    if (0 == strcmp(sr_xpath_node_name(xpath), "interface")) {
        /* return all list instances with their details */

        sr_new_values(4, &v);

        sr_val_set_xpath(&v[0], "/ietf-interfaces:interfaces-state/interface[name='eth0']/type");
        v[0].type = SR_IDENTITYREF_T;
        sr_val_set_string(&v[0], "ethernetCsmacd");

        sr_val_set_xpath(&v[1], "/ietf-interfaces:interfaces-state/interface[name='eth0']/oper-status");
        v[1].type = SR_IDENTITYREF_T;
        sr_val_set_string(&v[1], "testing");

        sr_val_set_xpath(&v[2], "/ietf-interfaces:interfaces-state/interface[name='eth1']/type");
        v[2].type = SR_IDENTITYREF_T;
        sr_val_set_string(&v[2], "ethernetCsmacd");

        sr_val_set_xpath(&v[3], "/ietf-interfaces:interfaces-state/interface[name='eth1']/oper-status");
        v[3].type = SR_IDENTITYREF_T;
        sr_val_set_string(&v[3], "up");

        *values = v;
        *values_cnt = 4;
    } else {
        /* statistics, ipv4 and ipv6 nested containers not implemented in this example */
        *values = NULL;
        values_cnt = 0;
    }

    return SR_ERR_OK;
}

static void
sigint_handler(int signum)
{
    exit_application = 1;
}

static int
data_provider(sr_session_ctx_t *session)
{
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;

    /* subscribe for providing operational data */
    rc = sr_dp_get_items_subscribe(session, "/ietf-interfaces:interfaces-state/interface", data_provider_cb, NULL,
            SR_SUBSCR_DEFAULT, &subscription);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_dp_get_items_subscribe: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    printf("\n\n ========== SUBSCRIBED FOR PROVIDING OPER DATA ==========\n\n");

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
    return rc;
}

void
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

static int
data_requester(sr_session_ctx_t *session)
{
    sr_val_t *value = NULL;
    sr_val_iter_t *iter = NULL;
    int rc = SR_ERR_OK;

    /* get all list instances with their content (recursive) */
    rc = sr_get_items_iter(session, "/ietf-interfaces:interfaces-state/interface//*", &iter);
    if (SR_ERR_OK != rc) {
        return rc;
    }

    while (SR_ERR_OK == sr_get_item_next(session, iter, &value)) {
        print_value(value);
        sr_free_val(value);
    }
    sr_free_val_iter(iter);

    return SR_ERR_OK;
}

int
main(int argc, char **argv)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;

    /* connect to sysrepo */
    rc = sr_connect("example_application", SR_CONN_DEFAULT, &connection);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_connect: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    /* start session */
    rc = sr_session_start(connection, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_session_start: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    if (1 == argc) {
        /* run as a data provider */
        printf("This application will be a data provider for state data of ietf-interfaces.\n");
        printf("Run the same executable with one (any) argument to request some data.\n");
        rc = data_provider(session);
    } else {
        /* run as a data requester */
        printf("Requesting state data of ietf-inetrfaces:\n");
        rc = data_requester(session);
    }

cleanup:
    if (NULL != session) {
        sr_session_stop(session);
    }
    if (NULL != connection) {
        sr_disconnect(connection);
    }
    return rc;
}
