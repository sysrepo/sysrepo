/**
 * @file cpp_rpc_example.cpp
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Example usage of rpc(), rpc_tree(), rpc_subscribe_tree(),
 * rpc_send() and others related to the Remote procedure call (RPC)
 * mechanism
 *
 * @copyright
 * Copyright 2016 - 2019 Deutsche Telekom AG.
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

        printf("Application will make an rpc call in %s\n", module_name);
        /* connect to sysrepo */
        auto conn = std::make_shared<sysrepo::Connection>();

        /* start session */
        auto sess = std::make_shared<sysrepo::Session>(conn);

        /* subscribe for changes in running config */
        auto subscribe = std::make_shared<sysrepo::Subscribe>(sess);
        auto cbVals = [](sysrepo::S_Session session, const char* op_path, const sysrepo::S_Vals input, sr_event_t event, uint32_t request_id, sysrepo::S_Vals_Holder output) {
            cout << "\n ========== RPC CALLED ==========\n" << endl;

            auto out_vals = output->allocate(3);

            for(size_t n = 0; n < input->val_cnt(); ++n)
                print_value(input->val(n));

            out_vals->val(0)->set("/test-examples:activate-software-image/status",
                    "The image acmefw-2.3 is being installed.",
                    SR_STRING_T);
            out_vals->val(1)->set("/test-examples:activate-software-image/version",
                    "2.3",
                    SR_STRING_T);
            out_vals->val(2)->set("/test-examples:activate-software-image/location",
                    "/root/",
                    SR_STRING_T);

            return SR_ERR_OK;
        };

        auto cbTree = [] (sysrepo::S_Session session, const char *op_path, const libyang::S_Data_Node input, sr_event_t event,
                uint32_t request_id, libyang::S_Data_Node output) {
            cout << "\n ========== RPC TREE CALLED ==========\n" << endl;
            cout << input->print_mem(LYD_XML, LYP_FORMAT);

            libyang::S_Context ctx = session->get_context();

            output->new_path(ctx, "status", "The image acmefw-2.3 is being installed.", LYD_ANYDATA_CONSTSTRING, LYD_PATH_OPT_OUTPUT);
            output->new_path(ctx, "version", "2.3", LYD_ANYDATA_CONSTSTRING, LYD_PATH_OPT_OUTPUT);
            output->new_path(ctx, "location", "/root/", LYD_ANYDATA_CONSTSTRING, LYD_PATH_OPT_OUTPUT);

            return SR_ERR_OK;
        };

        cout << "\n ========== SUBSCRIBE TO RPC CALL ==========\n" << endl;

        subscribe->rpc_subscribe("/test-examples:activate-software-image", cbVals, 1);

        auto in_vals = std::make_shared<sysrepo::Vals>(2);

        in_vals->val(0)->set("/test-examples:activate-software-image/image-name",
                           "acmefw-2.3",
               SR_STRING_T);
        in_vals->val(1)->set("/test-examples:activate-software-image/location",
                           "/root/",
                           SR_STRING_T);

        cout << "\n ========== START RPC CALL ==========\n" << endl;
        auto out_vals = sess->rpc_send("/test-examples:activate-software-image", in_vals);

        cout << "\n ========== PRINT RETURN VALUE ==========\n" << endl;
        for(size_t n=0; n < out_vals->val_cnt(); ++n)
            print_value(out_vals->val(n));

        cout << "\n ========== SUBSCRIBE TO RPC TREE CALL ==========\n" << endl;
        subscribe->rpc_subscribe_tree("/test-examples:activate-software-image", cbTree, 0, SR_SUBSCR_CTX_REUSE);

        libyang::S_Context ctx = conn->get_context();
        libyang::S_Module mod = ctx->get_module(module_name);
        auto in_trees = std::make_shared<libyang::Data_Node>(ctx, "/test-examples:activate-software-image", nullptr, LYD_ANYDATA_CONSTSTRING, 0);
        std::make_shared<libyang::Data_Node>(libyang::Data_Node(in_trees, mod, "image-name", "acmefw-2.3"));
        std::make_shared<libyang::Data_Node>(libyang::Data_Node(in_trees, mod, "location", "/root/"));

        cout << "\n ========== START RPC TREE CALL ==========\n" << endl;
        auto out_trees = sess->rpc_send(in_trees);

        cout << "\n ========== PRINT RETURN VALUE ==========\n" << endl;
        cout << out_trees->print_mem(LYD_XML, LYP_FORMAT);

        cout << "\n ========== END PROGRAM ==========\n" << endl;
    } catch( const std::exception& e ) {
        cout << e.what() << endl;
        return -1;
    }
    return 0;
}
