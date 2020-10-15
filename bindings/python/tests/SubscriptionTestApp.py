#!/usr/bin/env python

__author__ = "Antonio Paunovic <antonio.paunovic@sartura.hr>"
__copyright__ = "Copyright 2017, Deutsche Telekom AG"
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

import sysrepo as sr
import sys
import os
import signal
from time import sleep
from os import getpid


usr_interrupt=False
subscribe = None

def oper_get_items_cb(session, module_name, path, request_xpath, request_id, parent, private_data):
    print("\n\n ========== CALLBACK CALLED TO PROVIDE \"" + path + "\" DATA ==========\n")
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
        print(e)
        return sr.SR_ERR_OK
    sys.stdout.flush()
    return sr.SR_ERR_OK

if __name__ == "__main__":
    module_name = "ietf-interfaces"
    xpath = "/ietf-interfaces:interfaces-state"
    if len(sys.argv) > 2:
        module_name = sys.argv[1]


    # connect to sysrepo
    conn = sr.Connection(sr.SR_CONN_DEFAULT)

    # start session
    sess = sr.Session(conn)

    # subscribe for changes in running config */
    subscribe = sr.Subscribe(sess)

    subscribe.oper_get_items_subscribe(module_name, xpath, oper_get_items_cb)
    
    with open("pipe_subscription_test", "w") as fifo:
        fifo.write("subscribed")
    

    sr.global_loop()

    sess.session_stop()

    conn = None

    print("Application exit requested, exiting.")
