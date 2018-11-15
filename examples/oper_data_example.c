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
data_provider_cb(const char *xpath, sr_val_t **values, size_t *values_cnt,
        uint64_t request_id, const char *original_xpath, void *private_ctx)
{
    sr_val_t *v = NULL;
    sr_xpath_ctx_t xp_ctx = {0};
    int rc = SR_ERR_OK;

    printf("Data for '%s' requested.\n", xpath);

    if (sr_xpath_node_name_eq(xpath, "interface")) {
        /* return all 'interface' list instances with their details */

        /* allocate space for data to return */
        rc = sr_new_values(4, &v);
        if (SR_ERR_OK != rc) {
            return rc;
        }

        sr_val_set_xpath(&v[0], "/ietf-interfaces:interfaces-state/interface[name='eth0']/type");
        sr_val_set_str_data(&v[0], SR_IDENTITYREF_T, "ethernetCsmacd");

        sr_val_set_xpath(&v[1], "/ietf-interfaces:interfaces-state/interface[name='eth0']/oper-status");
        sr_val_set_str_data(&v[1], SR_ENUM_T, "down");

        sr_val_set_xpath(&v[2], "/ietf-interfaces:interfaces-state/interface[name='eth1']/type");
        sr_val_set_str_data(&v[2], SR_IDENTITYREF_T, "iana-if-type:ethernetCsmacd");

        sr_val_set_xpath(&v[3], "/ietf-interfaces:interfaces-state/interface[name='eth1']/oper-status");
        sr_val_set_str_data(&v[3], SR_ENUM_T, "up");

        *values = v;
        *values_cnt = 4;
    } else if (sr_xpath_node_name_eq(xpath, "statistics")) {
        /* return contents of 'statistics' NESTED container for the given list instance */

        /* allocate space for data to return */
        rc = sr_new_values(1, &v);
        if (SR_ERR_OK != rc) {
            return rc;
        }

        sr_val_build_xpath(&v[0], "%s/%s", xpath, "discontinuity-time");

        /* just to return something different for eth0 and eth1 */
        if (0 == strcmp(sr_xpath_key_value((char*)xpath, "interface", "name", &xp_ctx), "eth0")) {
            sr_val_set_str_data(&v[0], SR_STRING_T, "1987-08-31T17:00:30.44Z");
        } else {
            sr_val_set_str_data(&v[0], SR_STRING_T, "2016-10-06T15:12:50.52Z");
        }
        sr_xpath_recover(&xp_ctx); /* we modified const string! - let's recover it */

        *values = v;
        *values_cnt = 1;
    } else {
        /* ipv4 and ipv6 nested containers not implemented in this example */
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
    rc = sr_dp_get_items_subscribe(session, "/ietf-interfaces:interfaces-state", data_provider_cb, NULL,
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
        sr_print_val(value);
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
