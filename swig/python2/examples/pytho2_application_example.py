#!/usr/bin/env python

__author__ = "Mislav Novakovic <mislav.novakovic@sartura.hr>"
__copyright__ = "Copyright 2016, Deutsche Telekom AG"
__license__ = "Apache 2.0"

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import libsysrepoPython2 as sr
import sys

def print_value(value):
    print value.get_xpath() + " ",

    if (value.get_type() == sr.SR_CONTAINER_T):
        print "(container)"
    elif (value.get_type() == sr.SR_CONTAINER_PRESENCE_T):
        print "(container)"
    elif (value.get_type() == sr.SR_LIST_T):
        print "(list instance)"
    elif (value.get_type() == sr.SR_STRING_T):
        print "= " + value.get_string()
    elif (value.get_type() == sr.SR_BOOL_T):
        if (value.get_bool()):
            print "= true"
        else:
            print "= true"
    elif (value.get_type() == sr.SR_UINT8_T):
        print "= " + repr(value.get_uint8())
    elif (value.get_type() == sr.SR_UINT16_T):
        print "= " + repr(value.get_uint16())
    elif (value.get_type() == sr.SR_UINT32_T):
        print "= " + repr(value.get_uint32())
    elif (value.get_type() == sr.SR_IDENTITYREF_T):
        print "= " + repr(value.get_identityref())
    else:
        print "(unprintable)"

def print_current_config(session, module_name):
    select_xpath = "/" + module_name + ":*//*"

    values = session.get_items(select_xpath)

    while True:
        print_value(values)
        if (values.Next() == False):
            break

def module_change_cb(session, module_name, event, private_ctx):
    print "\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG: ==========\n"

    sess = sr.Session(session)
    print_current_config(sess, module_name)

try:
    module_name = "ietf-interfaces"
    if len(sys.argv) > 1:
        module_name = sys.argv[1]
    else:
        print "\nYou can pass the module name to be subscribed as the first argument"

    # connect to sysrepo
    conn = sr.Connection("example_application")

    # start session
    sess = sr.Session(conn)

    # subscribe for changes in running config */
    subscribe = sr.Subscribe(sess)

    subscribe.module_change_subscribe(module_name, module_change_cb)

    print "\n\n ========== READING STARTUP CONFIG: ==========\n"
    try:
        print_current_config(sess, module_name)
    except Exception as e:
        print e

    print "\n\n ========== STARTUP CONFIG APPLIED AS RUNNING ==========\n"

    sr.global_loop()

    print "Application exit requested, exiting.\n";

except Exception as e:
    print e
