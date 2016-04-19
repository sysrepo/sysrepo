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


def print_if_setup():
    # connect to sysrepo
    sr = Sysrepo("GetItemExample")
    # start a session
    session = Session(sr, SR_DS_STARTUP)
    xpath = "/ietf-interfaces:*//*"

    try:
        # create an iterator
        it = session.get_items_iter(xpath)
        level = []
        while it.hasNext():
            # fetch next item
            item = it.getNext()

            while len(level) != 0 and level[-1] not in item.xpath:
                del level[-1]

            if item.type in [SR_LIST_T, SR_CONTAINER_PRESENCE_T, SR_CONTAINER_T]:
                level.append(item.xpath)
                # print xpath with appropriate indent
                print "  " * (len(level)-1), item.xpath
            else:
                print "  " * len(level), item.xpath[len(level[-1]):], "=", item.value

    except RuntimeError as e:
        print "Error occurred", e.message

if __name__ == "__main__":
    print_if_setup()
