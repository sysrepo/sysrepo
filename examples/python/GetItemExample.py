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


def is_if_enabled(ifname='eth0'):
    #connect to sysrepo
    sr = Sysrepo("GetItemExample")
    #start a session
    session = Session(sr, SR_DS_STARTUP)
    xpath = "/ietf-interfaces:interfaces/interface[name='{0}']/enabled".format(ifname)

    try:
        #fetch an item
        item = session.get_item(xpath)
        print "Value of", xpath, "is",item.value
    except RuntimeError as e:
        print "Error occurred", e.message

if __name__ == "__main__":
    is_if_enabled()
