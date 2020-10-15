/**
 * @file cpp_get_data_example.cpp
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Example usage of get_items function
 *
 * @copyright
 * Copyright 2020 CESNET, z.s.p.o.
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

#include <iostream>
#include <cstring>

#include <libyang/Tree_Data.hpp>
#include "Session.hpp"

using namespace std;

static const char *
nodetype2str(LYS_NODE type)
{
    switch (type) {
    case LYS_CONTAINER:
        return "container";
    case LYS_LEAF:
        return "leaf";
    case LYS_LEAFLIST:
        return "leaf-list";
    case LYS_LIST:
        return "list";
    case LYS_ANYXML:
        return "anyxml";
    case LYS_NOTIF:
        return "notification";
    case LYS_RPC:
        return "rpc";
    case LYS_ACTION:
        return "action";
    case LYS_ANYDATA:
        return "anydata";
    default:
        break;
    }

    return NULL;
}

static void
print_node(libyang::S_Data_Node &node)
{
    libyang::S_Schema_Node schema = node->schema();

    cout << nodetype2str(schema->nodetype()) << " \"" << schema->name() << '\"' << endl;
    cout << '\t' << "Path: " << node->path() << endl;
    cout << '\t' << "Default: " << (node->dflt() ? "yes" : "no") << endl;

    /* type-specific print */
    switch (schema->nodetype()) {
    case LYS_CONTAINER:
    {
        libyang::Schema_Node_Container scont(schema);

        cout << '\t' << "Presence: " << (scont.presence() ? "yes" : "no") << endl;
        break;
    }
    case LYS_LEAF:
    {
        libyang::Data_Node_Leaf_List leaf(node);
        libyang::Schema_Node_Leaf sleaf(schema);

        cout << '\t' << "Value: \"" << leaf.value_str() << '\"' << endl;
        cout << '\t' << "Is key: " << (sleaf.is_key() ? "yes" : "no") << endl;
        break;
    }
    case LYS_LEAFLIST:
    {
        libyang::Data_Node_Leaf_List leaflist(node);

        cout << '\t' << "Value: \"" << leaflist.value_str() << '\"' << endl;
        break;
    }
    case LYS_LIST:
    {
        libyang::Schema_Node_List slist(schema);

        cout << '\t' << "Keys:";
        for (libyang::S_Schema_Node_Leaf &key : slist.keys()) {
            cout << ' ' << key->name();
        }
        cout << endl;
        break;
    }
    default:
        break;
    }

    cout << endl;
}

int
main(int argc, char **argv)
{
    sr_datastore_t ds = SR_DS_RUNNING;
    const char *xpath;

    if ((argc < 2) || (argc > 3)) {
        cout << argv[0] << " <xpath-to-get> [running/operational]" << endl;
        return EXIT_FAILURE;
    }
    xpath = argv[1];
    if (argc == 3) {
        if (!strcmp(argv[2], "running")) {
            ds = SR_DS_RUNNING;
        } else if (!strcmp(argv[2], "operational")) {
            ds = SR_DS_OPERATIONAL;
        } else {
            cout << "Invalid datastore " << argv[2] << endl;
            return EXIT_FAILURE;
        }
    }

    try {
        auto conn = std::make_shared<sysrepo::Connection>();
        auto sess = std::make_shared<sysrepo::Session>(conn, ds);

        libyang::S_Data_Node data = sess->get_data(xpath);

        /* go through all top-level siblings */
        for (libyang::S_Data_Node &root : data->tree_for()) {
            /* go through all the children of a top-level sibling */
            for (libyang::S_Data_Node &node : root->tree_dfs()) {
                print_node(node);
            }
        }
    } catch( const std::exception& e ) {
        cout << e.what() << endl;
    }

    return EXIT_SUCCESS;
}
