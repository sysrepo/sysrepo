#!/usr/bin/env python
from __future__ import print_function

__author__ = "Mislav Novakovic <mislav.novakovic@sartura.hr>"
__copyright__ = "Copyright 2018, Deutsche Telekom AG"
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

# This sample application demonstrates use of Python programming language bindings for sysrepo library.
# Original c application was rewritten in Python to show similarities and differences
# between the two.
#
# Most notable difference is in the very different nature of languages, c is weakly statically typed language
# while Python is strongly dynamiclally typed. Python code is much easier to read and logic easier to comprehend
# for smaller scripts. Memory safety is not an issue but lower performance can be expected.
#
# The original c implementation is also available in the source, so one can refer to it to evaluate trade-offs.


import sysrepo as sr
import sys
import gc

def oper_get_items_cb1(session, module_name, path, request_xpath, request_id, parent, private_data):
    print ("\n\n ========== CALLBACK CALLED TO PROVIDE \"" + path + "\" DATA ==========\n")
    try:
        ctx = session.get_context()
        mod = ctx.get_module(module_name)

        parent.reset(sr.Data_Node(ctx, "/ietf-interfaces:interfaces-state", None, sr.LYD_ANYDATA_CONSTSTRING, 0))
        ifc = sr.Data_Node(parent, mod, "interface")
        name = sr.Data_Node(ifc, mod, "name", "eth100")
        typ = sr.Data_Node(ifc, mod, "type", "iana-if-type:ethernetCsmacd")
        oper_status = sr.Data_Node(ifc, mod, "oper-status", "down")

        ifc.reset(sr.Data_Node(parent, mod, "interface"));
        name.reset(sr.Data_Node(ifc, mod, "name", "eth101"));
        typ.reset(sr.Data_Node(ifc, mod, "type", "iana-if-type:ethernetCsmacd"));
        oper_status.reset(sr.Data_Node(ifc, mod, "oper-status", "up"));

        ifc.reset(sr.Data_Node(parent, mod, "interface"));
        name.reset(sr.Data_Node(ifc, mod, "name", "eth102"));
        typ.reset(sr.Data_Node(ifc, mod, "type", "iana-if-type:ethernetCsmacd"));
        oper_status.reset(sr.Data_Node(ifc, mod, "oper-status", "dormant"));

        ifc.reset(sr.Data_Node(parent, mod, "interface"));
        name.reset(sr.Data_Node(ifc, mod, "name", "eth105"));
        typ.reset(sr.Data_Node(ifc, mod, "type", "iana-if-type:ethernetCsmacd"));
        oper_status.reset(sr.Data_Node(ifc, mod, "oper-status", "not-present"));

    except Exception as e:
        print (e)
        return sr.SR_ERR_OK
    return sr.SR_ERR_OK

def oper_get_items_cb2(session, module_name, path, request_xpath, request_id, parent, private_data):
    print ("\n\n ========== CALLBACK CALLED TO PROVIDE \"" + path + "\" DATA ==========\n")
    try:
        ctx = session.get_context()
        mod = ctx.get_module(module_name)

        stats = sr.Data_Node(parent, mod, "statistics")
        dis_time = sr.Data_Node(stats, mod, "discontinuity-time", "2019-01-01T00:00:00Z")
        in_oct = sr.Data_Node(stats, mod, "in-octets", "22")

    except Exception as e:
        print (e)
        return sr.SR_ERR_OK
    return sr.SR_ERR_OK

# Notable difference between c implementation is using exception mechanism for open handling unexpected events.
# Here it is useful because `Conenction`, `Session` and `Subscribe` could throw an exception.
try:
    module_name = "ietf-interfaces"
    if len(sys.argv) > 1:
        module_name = sys.argv[1]
    else:
        print ("\nYou can pass the module name to be subscribed as the first argument")

    # connect to sysrepo
    conn = sr.Connection(sr.SR_CONN_DEFAULT)

    # start session 
    sess = sr.Session(conn)

    # subscribe for changes in running config */
    subscribe = sr.Subscribe(sess)

    print ("\nApplication will provide data of " + module_name + " module\n")

    #try:
    subscribe.oper_get_items_subscribe(module_name, "/ietf-interfaces:interfaces-state", oper_get_items_cb1)
    #except Exception as e:
    #    print (e)

    sr.global_loop()

    subscribe.unsubscribe()

    sess.session_stop()

    conn=None

    print ("Application exit requested, exiting.\n")

except Exception as e:
    print (e)
