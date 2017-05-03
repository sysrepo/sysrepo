/**
 * @file event_notif_sub_example.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Example usage of sr_event_notif_subscribe function.
 * Use this example in combination with rpc_example or rpc_tree_example,
 * both of which send the notification as part of the RPC handling procedure.
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
#include <time.h>

#include "sysrepo.h"
#include "sysrepo/values.h"

volatile int exit_application = 0;

static void
event_notif_cb(const sr_ev_notif_type_t notif_type, const char *xpath, const sr_val_t *values, const size_t value_cnt,
       time_t timestamp, void *private_ctx)
{
    /* print notification */
    printf("\n\n ========== RECEIVED EVENT NOTIFICATION ======%s\n\n", ctime(&timestamp));
    printf(">>> Notification content:\n\n");
    for (size_t i = 0; i < value_cnt; ++i) {
        sr_print_val(values+i);
    }
    printf("\n");

    /**
     * Here you would normally handle the notification.
     */

    /**
     * Do not deallocate the notification content!
     * Values will get freed automatically by sysrepo.
     */
}

static void
sigint_handler(int signum)
{
    exit_application = 1;
}

static int
event_notif_subscriber(sr_session_ctx_t *session)
{
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;

    /* subscribe for the notification */
    rc = sr_event_notif_subscribe(session, "/turing-machine:paused", event_notif_cb, NULL,
            SR_SUBSCR_DEFAULT, &subscription);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_event_notif_subscribe: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    printf("\n\n ========== SUBSCRIBED FOR EVENT NOTIFICATION ==========\n\n");

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

    /* run as an event notification subscriber */
    printf("This application will be a subscriber for the 'paused' event notification of 'turing-machine'.\n");
    printf("This notification is sent by the RPC handler in rpc_example and rpc_tree_example.\n");
    rc = event_notif_subscriber(session);

cleanup:
    if (NULL != session) {
        sr_session_stop(session);
    }
    if (NULL != connection) {
        sr_disconnect(connection);
    }
    return rc;
}
