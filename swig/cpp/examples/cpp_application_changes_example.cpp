/**
 * @file application_changes_example.cpp
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @brief Example application that uses sysrepo as the configuration datastore. It
 * prints the changes made in running data store.
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

#include "Session.h"

#define MAX_LEN 100

using namespace std;

volatile int exit_application = 0;

void
print_value(S_Val value)
{
    cout << value->xpath();
    cout << " ";
    switch (value->type()) {
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
        cout << "(container)" << endl;
        break;
    case SR_LIST_T:
        cout << "(list instance)" << endl;
        break;
    case SR_STRING_T:
        cout << "= " << value->data()->get_string() << endl;;
        break;
    case SR_BOOL_T:
	if (value->data()->get_bool())
            cout << "= true" << endl;
	else
            cout << "= false" << endl;
        break;
    case SR_ENUM_T:
        cout << "= " << value->data()->get_enum() << endl;;
        break;
    case SR_UINT8_T:
        cout << "= " << unsigned(value->data()->get_uint8()) << endl;
        break;
    case SR_UINT16_T:
        cout << "= " << unsigned(value->data()->get_uint16()) << endl;
        break;
    case SR_UINT32_T:
        cout << "= " << unsigned(value->data()->get_uint32()) << endl;
        break;
    case SR_UINT64_T:
        cout << "= " << unsigned(value->data()->get_uint64()) << endl;
        break;
    case SR_INT8_T:
        cout << "= " << value->data()->get_int8() << endl;
        break;
    case SR_INT16_T:
        cout << "= " << value->data()->get_int16() << endl;
        break;
    case SR_INT32_T:
        cout << "= " << value->data()->get_int32() << endl;
        break;
    case SR_INT64_T:
        cout << "= " << value->data()->get_int64() << endl;
        break;
     case SR_IDENTITYREF_T:
        cout << "= " << value->data()->get_identityref() << endl;
        break;
    case SR_BITS_T:
        cout << "= " << value->data()->get_bits() << endl;
        break;
    case SR_BINARY_T:
        cout << "= " << value->data()->get_binary() << endl;
        break;
    default:
        cout << "(unprintable)" << endl;
    }
    return;
}

static void
print_change(S_Change change) {
    switch(change->oper()) {
    case SR_OP_CREATED:
        if (NULL != change->new_val()) {
           printf("CREATED: ");
           print_value(change->new_val());
        }
        break;
    case SR_OP_DELETED:
        if (NULL != change->old_val()) {
           printf("DELETED: ");
           print_value(change->old_val());
        }
	break;
    case SR_OP_MODIFIED:
        if (NULL != change->old_val() && NULL != change->new_val()) {
           printf("MODIFIED: ");
           printf("old value");
           print_value(change->old_val());
           printf("new value");
           print_value(change->new_val());
        }
	break;
    case SR_OP_MOVED:
        if (NULL != change->new_val()) {
	    cout<<"MOVED: " << change->new_val()->xpath() << " after " << change->old_val()->xpath() << endl;
        }
	break;
    }
}

static void
print_current_config(S_Session session, const char *module_name)
{
    char select_xpath[MAX_LEN];
    try {
        snprintf(select_xpath, MAX_LEN, "/%s:*//*", module_name);

        auto values = session->get_items(&select_xpath[0]);
        if (values == NULL)
            return;

        for(unsigned int i = 0; i < values->val_cnt(); i++)
            print_value(values->val(i));
    } catch( const std::exception& e ) {
        cout << e.what() << endl;
    }
}

class My_Callback:public Callback {
    void module_change(S_Session sess, const char *module_name, sr_notif_event_t event, void *private_ctx)
    {
        char change_path[MAX_LEN];

        try {
            printf("\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG: ==========\n\n");

            print_current_config(sess, module_name);

            printf("\n\n ========== CHANGES: =============================================\n\n");

            snprintf(change_path, MAX_LEN, "/%s:*", module_name);

            S_Subscribe subscribe(new Subscribe(sess));
            auto it = subscribe->get_changes_iter(&change_path[0]);

            while (auto change = subscribe->get_change_next(it)) {
                print_change(change);
            }

            printf("\n\n ========== END OF CHANGES =======================================\n\n");

        } catch( const std::exception& e ) {
            cout << e.what() << endl;
        }
    }
};

static void
sigint_handler(int signum)
{
    exit_application = 1;
}

int
main(int argc, char **argv)
{
    const char *module_name = "ietf-interfaces";
    try {
        if (argc > 1) {
            module_name = argv[1];
        } else {
            printf("\nYou can pass the module name to be subscribed as the first argument\n");
        }

        printf("Application will watch for changes in %s\n", module_name);
        /* connect to sysrepo */
        S_Connection conn(new Connection("example_application"));

        /* start session */
        S_Session sess(new Session(conn));

        /* subscribe for changes in running config */
        S_Subscribe subscribe(new Subscribe(sess));
	S_Callback cb(new My_Callback());

        subscribe->module_change_subscribe(module_name, cb);

        /* read startup config */
        printf("\n\n ========== READING STARTUP CONFIG: ==========\n\n");
        print_current_config(sess, module_name);

        cout << "\n\n ========== STARTUP CONFIG APPLIED AS RUNNING ==========\n" << endl;

        /* loop until ctrl-c is pressed / SIGINT is received */
        signal(SIGINT, sigint_handler);
        while (!exit_application) {
            sleep(1000);  /* or do some more useful work... */
        }

        printf("Application exit requested, exiting.\n");

    } catch( const std::exception& e ) {
        cout << e.what() << endl;
        return -1;
    }

    return 0;
}
