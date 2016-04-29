/**
 * @file get_items_example.c
 * @author Mislav Novakovic <mislav.novakovic@gmail.com>
 * @brief Example usage of get_items function
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

#include <iostream>

#include "Session.h"

using namespace std;

int
main(int argc, char **argv)
{
    try {
        Connection conn("app2");

        Session sess(conn);

        const char *xpath = "/ietf-interfaces:interfaces/interface";

	Value value;
	sess.get_items(xpath, &value);
	Value *tmp = &value;

        while (tmp) {
            cout << tmp->get_xpath() << endl;
	    tmp = tmp->Next();
        }
    } catch( const std::exception& e ) {
        cout << e.what() << endl;
    }

    return 0;
}
