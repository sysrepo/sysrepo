/**
 * @file cpp_turing_rpc_example.cpp
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @brief Example usage of rpc(), rpc_tree(), rpc_subscribe_tree(),
 * rpc_send() and others related to the Remote procedure call (RPC)
 * mechanism
 *
 * @copyright
 * Copyright 2018 Deutsche Telekom AG.
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

#include <unistd.h>
#include <iostream>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "Session.hpp"

volatile int exit_application = 0;

class My_Callback:public sysrepo::Callback {
    int rpc(const char *xpath, const sysrepo::S_Vals input, sysrepo::S_Vals_Holder holder, void *private_ctx) {
        int rc = SR_ERR_OK;
        try {
            sysrepo::S_Session *session = (sysrepo::S_Session *)private_ctx;

            /* print input values */
            std::cout << std::endl << std::endl << " ========== RECEIVED RPC REQUEST ==========" << std::endl << std::endl;
            std::cout << ">>> RPC Input:" << std::endl << std::endl;
            for (size_t i = 0; i < input->val_cnt(); ++i) {
                std::cout << input->val(i)->to_string();
            }
            std::cout << std::endl;

            /**
             * Here you would actually run the operation against the provided input values
             * and obtained the output values.
             */
            std::cout << ">>> Executing RPC..." << std::endl << std::endl;

            /* allocate output values */
            auto output = holder->allocate(2);

            /* set 'output/step-count' leaf */
            output->val(0)->set("/turing-machine:run-until/step-count", (uint64_t) 256, SR_UINT64_T);
            /* set 'output/halted' leaf */
            output->val(1)->set("/turing-machine:run-until/halted", false, SR_BOOL_T);

            std::cout << ">>> RPC Output:" << std::endl << std::endl;
            for (size_t i = 0; i < output->val_cnt(); ++i) {
                std::cout << output->val(i)->to_string();
            }
            std::cout << std::endl;

            auto notif = input->dup();

            /* note: sysrepo values are bind to xpath, which is different for the notification */
            for (size_t i = 0; i < notif->val_cnt(); ++i) {
                char xpath[100] = {0};
                sprintf(xpath, "/turing-machine:paused/%s", notif->val(i)->xpath()+strlen("/turing-machine:run-until/"));
                notif->val(i)->xpath_set(xpath);
            }

            /* send notification for event_notif_sub(_tree)_example */
            std::cout << ">>> Sending event notification for '/turing-machine:paused'..." << std::endl;
            (*session)->event_notif_send("/turing-machine:paused", notif);

            std::cout << ">>> RPC finished." << std::endl << std::endl;
        } catch( const std::exception& e ) {
            std::cout << e.what() << std::endl;
            return SR_ERR_INTERNAL;
        }
        return rc;
    };
};

static void
sigint_handler(int signum)
{
    exit_application = 1;
}

static int
rpc_handler(sysrepo::S_Session sess)
{
    int rc = SR_ERR_OK;
    try {
        sysrepo::S_Subscribe subscribe(new sysrepo::Subscribe(sess));
        sysrepo::S_Callback cb(new My_Callback());

        subscribe->rpc_subscribe("/turing-machine:run-until", cb, &sess);

        std::cout << "\n ========== SUBSCRIBE FOR HANDLING RPC ==========\n" << std::endl;

        signal(SIGINT, sigint_handler);
        signal(SIGPIPE, SIG_IGN);
        while (!exit_application) {
            sleep(1000);  /* or do some more useful work... */
        }

        std::cout << "Application exit requested, exiting." << std::endl;
    } catch( const std::exception& e ) {
        std::cout << e.what() << std::endl;
        return SR_ERR_INTERNAL;
    }
    return rc;
}

static int
rpc_caller(sysrepo::S_Session sess)
{
    int rc = SR_ERR_OK;
    try {

        /* allocate input values */
        sysrepo::S_Vals input(new sysrepo::Vals(7));

        /* set 'input/state' leaf */
        input->val(0)->set("/turing-machine:run-until/state", (uint16_t) 10, SR_UINT16_T);
        input->val(1)->set("/turing-machine:run-until/head-position", (int64_t) 123, SR_INT64_T);
        /* set 'input/tape' list entries */
        for (int i = 0; i < 5; ++i) {
            // WTF
            char value[2] = {0};
            char xpath_str[100] = {0};
            sprintf(xpath_str, "/turing-machine:run-until/tape/cell[coord='%d']/symbol", i);
            sprintf(value, "%c", 'A'+i);
            input->val(i+2)->set(xpath_str, value, SR_STRING_T);
        }

        std::cout << std::endl << std::endl << " ========== EXECUTING RPC ==========" << std::endl << std::endl;
        std::cout << ">>> RPC Input:" << std::endl << std::endl;
        for (size_t i = 0; i < input->val_cnt(); ++i) {
            std::cout << input->val(i)->to_string();
        }
        std::cout << std::endl;

        /* execute RPC */
        auto output = sess->rpc_send("/turing-machine:run-until", input);

        /* print output values */
        std::cout << std::endl << ">>> Received an RPC response:" << std::endl << std::endl;
        for (size_t i = 0; i < output->val_cnt(); ++i) {
            std::cout << output->val(i)->to_string();
        }
        std::cout << std::endl;
    } catch( const std::exception& e ) {
        std::cout << e.what() << std::endl;
        return SR_ERR_INTERNAL;
    }
    return rc;
}

int
main(int argc, char **argv)
{
    int rc = SR_ERR_OK;
    try {
        /* connect to sysrepo */
        sysrepo::S_Connection conn(new sysrepo::Connection("example_application"));

        /* start session */
        sysrepo::S_Session sess(new sysrepo::Session(conn));

        if (1 == argc) {
            /* run as a RPC handler */
            std::cout << "This application will be an RPC handler for 'run-until' operation of 'turing-machine'." << std::endl;
            std::cout << "Run the same executable (or rpc_tree_example) with one (any) argument to execute the RPC." << std::endl;
            rc = rpc_handler(sess);
        } else {
            /* run as a RPC caller */
            std::cout << "Executing RPC 'run-until' of 'turing-machine':" << std::endl;
            rc = rpc_caller(sess);
        }
    } catch( const std::exception& e ) {
        std::cout << e.what() << std::endl;
        return SR_ERR_INTERNAL;
    }
    return rc;
}
