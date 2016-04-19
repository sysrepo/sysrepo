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

def set_ip_addr():
    # connect to sysrepo
    sr = Sysrepo("GetItemExample")
    # start a session
    session = Session(sr, SR_DS_STARTUP)
    xpath = "/ietf-interfaces:interfaces/interface[name='gigaeth0']/ietf-ip:ipv6/address[ip='fe80::ab8']/prefix-length"

    v = Value(xpath, SR_UINT8_T, 64)
    session.set_item(v.xpath, v)
    session.commit()

    print "ipv6 added to interface gigaeth0"

if __name__ == "__main__":
    set_ip_addr()
