/**
 * @file cpp_application_example.cpp
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @brief Example application that uses sysrepo as the configuraton datastore.
 *
 * @copyright
 * Copyright 2016 Deutsche Telekom AG.
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

#include "Session.hpp"

#define MAX_LEN 100

using namespace std;

volatile int exit_application = 0;

/* Function to print current configuration state.
 * It does so by loading all the items of a session and printing them out. */
static void
print_current_config(sysrepo::S_Session session, const char *module_name)
{
    char select_xpath[MAX_LEN];
    try {
        snprintf(select_xpath, MAX_LEN, "/%s:*//*", module_name);

        auto values = session->get_items(&select_xpath[0]);
        if (values == nullptr)
            return;

        for(unsigned int i = 0; i < values->val_cnt(); i++)
            cout << values->val(i)->to_string();
    } catch( const std::exception& e ) {
        cout << e.what() << endl;
    }
}

class My_Callback:public sysrepo::Callback {
    public:
    /* Function to be called for subscribed client of given session whenever configuration changes. */
    int module_change(sysrepo::S_Session sess, const char *module_name, sr_notif_event_t event, void *private_ctx)
    {
        cout << "\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG: ==========\n" << endl;

        print_current_config(sess, module_name);
        return SR_ERR_OK;
    }
};

static void
sigint_handler(int signum)
{
    exit_application = 1;
}

/* Notable difference between c implementation is using exception mechanism for open handling unexpected events.
 * Here it is useful because `Conenction`, `Session` and `Subscribe` could throw an exception. */
int
main(int argc, char **argv)
{
    const char *module_name = "ietf-interfaces";
    try {
        if (argc > 1) {
            module_name = argv[1];
        } else {
            cout << "\nYou can pass the module name to be subscribed as the first argument" << endl;
        }

        cout << "Application will watch for changes in "<< module_name << endl;
        sysrepo::S_Connection conn(new sysrepo::Connection("examples_application"));

        sysrepo::S_Session sess(new sysrepo::Session(conn));

        /* read startup config */
        cout << "\n\n ========== READING STARTUP CONFIG: ==========\n" << endl;

        sysrepo::S_Subscribe subscribe(new sysrepo::Subscribe(sess));
        sysrepo::S_Callback cb(new My_Callback());

        subscribe->module_change_subscribe(module_name, cb, nullptr, 0, SR_SUBSCR_DEFAULT | SR_SUBSCR_APPLY_ONLY);

        print_current_config(sess, module_name);

        cout << "\n\n ========== STARTUP CONFIG APPLIED AS RUNNING ==========\n" << endl;

        /* loop until ctrl-c is pressed / SIGINT is received */
        signal(SIGINT, sigint_handler);
        while (!exit_application) {
            sleep(1000);  /* or do some more useful work... */
        }

        cout << "Application exit requested, exiting." << endl;

    } catch( const std::exception& e ) {
        cout << e.what() << endl;
        return -1;
    }

    return 0;
}
