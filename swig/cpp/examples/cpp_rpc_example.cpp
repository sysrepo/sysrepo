/**
 * @file cpp_rpc_example.cpp
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @brief Example usage of rpc(), rpc_tree(), rpc_subscribe_tree(),
 * rpc_send() and others related to the Remote procedure call (RPC)
 * mechanism
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

void
print_tree(sysrepo::S_Tree tree)
{
    cout << tree->name();
    cout << " ";
    switch (tree->type()) {
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
        cout << "(container)" << endl;
        break;
    case SR_LIST_T:
        cout << "(list instance)" << endl;
        break;
    case SR_STRING_T:
        cout << "= " << tree->data()->get_string() << endl;;
        break;
    case SR_BOOL_T:
    if (tree->data()->get_bool())
            cout << "= true" << endl;
    else
            cout << "= false" << endl;
        break;
    case SR_ENUM_T:
        cout << "= " << tree->data()->get_enum() << endl;;
        break;
    case SR_UINT8_T:
        cout << "= " << unsigned(tree->data()->get_uint8()) << endl;
        break;
    case SR_UINT16_T:
        cout << "= " << unsigned(tree->data()->get_uint16()) << endl;
        break;
    case SR_UINT32_T:
        cout << "= " << unsigned(tree->data()->get_uint32()) << endl;
        break;
    case SR_UINT64_T:
        cout << "= " << unsigned(tree->data()->get_uint64()) << endl;
        break;
    case SR_INT8_T:
        cout << "= " << tree->data()->get_int8() << endl;
        break;
    case SR_INT16_T:
        cout << "= " << tree->data()->get_int16() << endl;
        break;
    case SR_INT32_T:
        cout << "= " << tree->data()->get_int32() << endl;
        break;
    case SR_INT64_T:
        cout << "= " << tree->data()->get_int64() << endl;
        break;
     case SR_IDENTITYREF_T:
        cout << "= " << tree->data()->get_identityref() << endl;
        break;
    case SR_BITS_T:
        cout << "= " << tree->data()->get_bits() << endl;
        break;
    case SR_BINARY_T:
        cout << "= " << tree->data()->get_binary() << endl;
        break;
    default:
        cout << "(unprintable)" << endl;
    }
    return;
}

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

class My_Callback:public sysrepo::Callback {
    int rpc(const char *xpath, const sysrepo::S_Vals in_vals, sysrepo::S_Vals_Holder holder, void *private_ctx) {
        cout << "\n ========== RPC CALLED ==========\n" << endl;

        auto out_vals = holder->allocate(3);

        for(size_t n=0; n < in_vals->val_cnt(); ++n)
            print_value(in_vals->val(n));

        out_vals->val(0)->set("/test-module:activate-software-image/status",\
                              "The image acmefw-2.3 is being installed.",\
                              SR_STRING_T);
        out_vals->val(1)->set("/test-module:activate-software-image/version",\
                            "2.3",\
                            SR_STRING_T);
        out_vals->val(2)->set("/test-module:activate-software-image/location",\
                            "/root/",\
                            SR_STRING_T);

    return SR_ERR_OK;
    }

    int rpc_tree(const char *xpath, const sysrepo::S_Trees in_trees, sysrepo::S_Trees_Holder holder, void *private_ctx) {
        cout << "\n ========== RPC TREE CALLED ==========\n" << endl;

        auto out_trees = holder->allocate(3);

        for(size_t n=0; n < in_trees->tree_cnt(); ++n)
            print_tree(in_trees->tree(n));

        out_trees->tree(0)->set_name("status");
        out_trees->tree(0)->set("The image acmefw-2.3 is being installed.");
        out_trees->tree(1)->set_name("version");
        out_trees->tree(1)->set("2.3");
        out_trees->tree(2)->set_name("location");
        out_trees->tree(2)->set("/root/");

    return SR_ERR_OK;
    }
};

int
main(int argc, char **argv)
{
    const char *module_name = "test-module";
    try {

        printf("Application will make an rpc call in %s\n", module_name);
        /* connect to sysrepo */
        sysrepo::S_Connection conn(new sysrepo::Connection("example_application"));

        /* start session */
        sysrepo::S_Session sess(new sysrepo::Session(conn));

        /* subscribe for changes in running config */
        sysrepo::S_Subscribe subscribe(new sysrepo::Subscribe(sess));
        sysrepo::S_Callback cb(new My_Callback());

        cout << "\n ========== SUBSCRIBE TO RPC CALL ==========\n" << endl;

        subscribe->rpc_subscribe("/test-module:activate-software-image", cb);

        sysrepo::S_Vals in_vals(new sysrepo::Vals(2));

        in_vals->val(0)->set("/test-module:activate-software-image/image-name",\
                           "acmefw-2.3",\
               SR_STRING_T);
        in_vals->val(1)->set("/test-module:activate-software-image/location",\
                           "/root/",\
                           SR_STRING_T);

        cout << "\n ========== START RPC CALL ==========\n" << endl;
        auto out_vals = sess->rpc_send("/test-module:activate-software-image", in_vals);

        cout << "\n ========== PRINT RETURN VALUE ==========\n" << endl;
        for(size_t n=0; n < out_vals->val_cnt(); ++n)
            print_value(out_vals->val(n));

        cout << "\n ========== SUBSCRIBE TO RPC TREE CALL ==========\n" << endl;
        subscribe->rpc_subscribe_tree("/test-module:activate-software-image", cb);

        sysrepo::S_Trees in_trees(new sysrepo::Trees(1));

        in_trees->tree(0)->set_name("image-name");
        in_trees->tree(0)->set("acmefw-2.3");

        cout << "\n ========== START RPC TREE CALL ==========\n" << endl;
        auto out_trees = sess->rpc_send("/test-module:activate-software-image", in_trees);

        cout << "\n ========== PRINT RETURN VALUE ==========\n" << endl;
        for(size_t n=0; n < out_trees->tree_cnt(); ++n)
            print_tree(out_trees->tree(n));

        cout << "\n ========== END PROGRAM ==========\n" << endl;
    } catch( const std::exception& e ) {
        cout << e.what() << endl;
        return -1;
    }
    return 0;
}
