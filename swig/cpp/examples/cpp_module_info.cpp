/**
 * @file cpp_module_info.cpp
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Example application that prints module information of a connection.
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
#include <cstring>
#include <cassert>
#include <iostream>

#include <libyang/Libyang.hpp>

#include "Connection.hpp"
#include "Session.hpp"

using namespace std;

int
main(int argc, char **argv)
{
    try {
        /* connect to sysrepo */
        sysrepo::Connection conn{};

        /* get module information data */
        libyang::S_Data_Node info = conn.get_module_info();

        cout << "Installed modules in sysrepo:" << endl;

        /* print all module names */
        for (libyang::S_Data_Node mod = info->child(); mod; mod = mod->next()) {
            assert(mod->child()->schema()->nodetype() == LYS_LEAF);

            /* print name */
            libyang::Data_Node_Leaf_List name(mod->child());
            cout << "  " << name.value_str();

            if (mod->child()->next() && !strcmp(mod->child()->next()->schema()->name(), "revision")) {
                /* print revision */
                libyang::Data_Node_Leaf_List rev(mod->child()->next());
                cout << "@" << rev.value_str();
            }

            cout << endl;
        }

    } catch( const std::exception& e ) {
        cout << e.what() << endl;
        return -1;
    }

    return 0;
}
