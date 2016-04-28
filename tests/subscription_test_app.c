/**
 * @file subscription_test_app.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Application subscribes for the ietf-interfaces notifications, when it
 * receives SIGUSR1 it cancels the subscription.
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
#include <stdbool.h>
#include "sysrepo.h"

bool usr_interrupt = false;

void sig_handler(int num)
{ 
   if (SIGUSR1 == num) {
      usr_interrupt = true;
   }
}

static void
module_change_cb(sr_session_ctx_t *session, const char *module_name, void *private_ctx)
{
    printf("\n\n ========== CONFIG HAS CHANGED ==========\n\n");
}

int main(int argc, char **argv){
   sigset_t mask, oldmask;
   /* Set up the mask of signals to temporarily block. */
   sigemptyset (&mask);
   sigaddset (&mask, SIGUSR1);
   sigprocmask (SIG_BLOCK, &mask, &oldmask);
   printf("Pid: %d\n", getpid());
   signal(SIGUSR1, sig_handler);

    
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

   /* subscribe for changes in running config */
   rc = sr_module_change_subscribe(session, "ietf-interfaces", true, module_change_cb, NULL, &subscription);
   if (SR_ERR_OK != rc) {
       goto cleanup;
   }

   printf("\n\n ========== STARTUP CONFIG APPLIED AS RUNNING ==========\n\n");

   /* Wait for a signal to arrive. */
   while (!usr_interrupt) {
      sigsuspend (&oldmask);
   }  

   sigprocmask (SIG_UNBLOCK, &mask, NULL);
   printf("Signal received\n");

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
