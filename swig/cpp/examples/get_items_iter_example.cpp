/**
 * @file get_items_iter_example.cpp
 * @author Mislav Novakovic <mislav.novakovic@gmail.com>
 * @brief Example usage of get_items_iter function
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

#include <iostream>

#include "Session.h"

using namespace std;

void
print_value(shared_ptr<Value> value)
{
    cout << value->get_xpath();
    cout << " ";

    switch (value->get_type()) {
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
        cout << "(container)" << endl;
        break;
    case SR_LIST_T:
        cout << "(list instance)" << endl;
        break;
    case SR_STRING_T:
        cout << "= " << value->get_string() << endl;;
        break;
    case SR_BOOL_T:
	if (value->get_bool())
            cout << "= true" << endl;
	else
            cout << "= false" << endl;
        break;
    case SR_UINT8_T:
        cout << "= " << unsigned(value->get_uint8()) << endl;
        break;
    case SR_UINT16_T:
        cout << "= " << unsigned(value->get_uint16()) << endl;
        break;
    case SR_UINT32_T:
        cout << "= " << unsigned(value->get_uint32()) << endl;
        break;
    case SR_IDENTITYREF_T:
        cout << "= " << value->get_identityref() << endl;
        break;
    default:
        cout << "(unprintable)" << endl;
    }
    return;
}


int
main(int argc, char **argv)
{
    try {
        Connection conn("app3");

        Session sess(conn);

        const char *xpath = "/ietf-interfaces:interfaces/interface//*";

	shared_ptr<Value> value;
	shared_ptr<Iter_Value> iter;

	iter = sess.get_items_iter(xpath);
        if (iter == NULL)
            return 0;

        while (value = sess.get_item_next(iter)) {
            print_value(value);
        }

    } catch( const std::exception& e ) {
        cout << e.what() << endl;
    }

    return 0;
}
