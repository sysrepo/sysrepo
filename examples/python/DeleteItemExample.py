#!/usr/bin/env python

__author__ = "Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>"
__copyright__ = "Copyright 2016, Cisco Systems, Inc."
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
#
# Note: to run the example sysrepo python bindings must be generated and in PYTHONPATH
#
from SysrepoWrappers import *

class EditSysrepo:

    def __init__(self):
        # connect to sysrepo
        sr = Sysrepo("GetItemExample")
        # start a session
        self.sessionA = Session(sr, SR_DS_STARTUP)
        self.sessionB = Session(sr, SR_DS_STARTUP)

    def printAddr(self):
        # load changes done by the other session
        self.sessionA.refresh()
        items = self.sessionA.get_items("/ietf-interfaces:interfaces/interface/*/address")
        print "Found addresses"
        for it in items:
            print it.xpath

        print ""

    def delete_ip_addr(self):
        xpath = "/ietf-interfaces:interfaces/interface[name='gigaeth0']/ietf-ip:ipv6/address"
        # remove item specified by the xpath
        self.sessionB.delete_item(xpath)
        self.sessionB.commit()
        print "ipv6 address remove from gigaeth0"

if __name__ == "__main__":
    edit = EditSysrepo()
    try:
        edit.printAddr()
        edit.delete_ip_addr()
        edit.printAddr()
    except RuntimeError as e:
        print "Error occurred", e.message
