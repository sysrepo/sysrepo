/**
 * @file cpp_notif_example.cpp
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Example usage of notification C++ API
 *
 * @copyright
 * Copyright 2019 Deutsche Telekom AG.
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

#include <libyang/Tree_Data.hpp>

#include "Session.hpp"

#define MAX_LEN 100

using namespace std;

void
print_value(sysrepo::S_Val value)
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

int
main(int argc, char **argv)
{
    const char *module_name = "test-examples";
    try {

        printf("Application will send notification in %s\n", module_name);
        /* connect to sysrepo */
        auto conn = std::make_shared<sysrepo::Connection>();

        /* start session */
        auto sess = std::make_shared<sysrepo::Session>(conn);

        /* subscribe for changes in running config */
        auto subscribe = std::make_shared<sysrepo::Subscribe>(sess);
        auto cbVals = [] (sysrepo::S_Session session, const sr_ev_notif_type_t notif_type, const char *path,
            const sysrepo::S_Vals vals, time_t timestamp) {
            cout << "\n ========== NOTIF RECEIVED ==========\n" << endl;

            for(size_t n = 0; n < vals->val_cnt(); ++n) {
                print_value(vals->val(n));
            }
        };

        auto cbTree = [] (sysrepo::S_Session session, const sr_ev_notif_type_t notif_type,
            const libyang::S_Data_Node notif, time_t timestamp) {
            cout << "\n ========== NOTIF TREE RECEIVED ==========\n" << endl;
            cout << notif->print_mem(LYD_XML, LYP_FORMAT);
        };

        cout << "\n ========== SUBSCRIBE TO NOTIF ==========\n" << endl;

        subscribe->event_notif_subscribe(module_name, cbVals);

        auto in_vals = std::make_shared<sysrepo::Vals>(2);

        in_vals->val(0)->set("/test-examples:test-notif/val1", "some-value", SR_STRING_T);
        in_vals->val(1)->set("/test-examples:test-notif/val2", "some-other-value", SR_STRING_T);

        cout << "\n ========== START NOTIF SEND ==========\n" << endl;
        sess->event_notif_send("/test-examples:test-notif", in_vals);

        cout << "\n ========== SUBSCRIBE TO NOTIF TREE ==========\n" << endl;
        subscribe->event_notif_subscribe_tree(module_name, cbTree);

        libyang::S_Context ctx = conn->get_context();
        libyang::S_Module mod = ctx->get_module(module_name);
        auto in_trees = std::make_shared<libyang::Data_Node>(ctx, "/test-examples:test-notif", nullptr, LYD_ANYDATA_CONSTSTRING, 0);
        std::make_shared<libyang::Data_Node>(libyang::Data_Node(in_trees, mod, "val1", "some-value"));
        std::make_shared<libyang::Data_Node>(libyang::Data_Node(in_trees, mod, "val2", "some-other-value"));

        cout << "\n ========== START NOTIF TREE SEND ==========\n" << endl;
        sess->event_notif_send(in_trees);

        cout << "\n ========== END PROGRAM ==========\n" << endl;
    } catch( const std::exception& e ) {
        cout << e.what() << endl;
        return -1;
    }
    return 0;
}
