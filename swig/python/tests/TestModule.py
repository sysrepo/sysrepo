#!/usr/bin/env python
# -*- coding: utf-8 -*-
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

import sysrepo as sr

XP_TEST_MODULE_ENUM = "/test-module:main/enum"
XP_TEST_MODULE_ENUM_VALUE = "maybe"

XP_TEST_MODULE_RAW = "/test-module:main/raw"
XP_TEST_MODULE_RAW_VALUE = "SGVsbG8gd29ybGQh"

XP_TEST_MODULE_BITS = "/test-module:main/options"
XP_TEST_MODULE_BITS_VALUE = "strict"

XP_TEST_MODULE_BOOL = "/test-module:main/boolean"
XP_TEST_MODULE_BOOL_VALUE_T = True

XP_TEST_MODULE_DEC64 = "/test-module:main/dec64"
XP_TEST_MODULE_DEC64_VALUE_T = 9.85

XP_TEST_MODULE_EMPTY = "/test-module:main/empty"

XP_TEST_MODULE_IDREF = "/test-module:main/id_ref"
XP_TEST_MODULE_IDREF_VALUE = "id_1"

XP_TEST_MODULE_INT8 = "/test-module:main/i8"
XP_TEST_MODULE_INT8_VALUE_T = 8

XP_TEST_MODULE_INT16 = "/test-module:main/i16"
XP_TEST_MODULE_INT16_VALUE_T = 16

XP_TEST_MODULE_INT32 = "/test-module:main/i32"
XP_TEST_MODULE_INT32_VALUE_T = 32

XP_TEST_MODULE_INT64 = "/test-module:main/i64"
XP_TEST_MODULE_INT64_VALUE_T = 64

XP_TEST_MODULE_STRING = "/test-module:main/string"
XP_TEST_MODULE_STRING_VALUE = "str"

XP_TEST_MODULE_UINT8 = "/test-module:main/ui8"
XP_TEST_MODULE_UINT8_VALUE_T = 8

XP_TEST_MODULE_UINT16 = "/test-module:main/ui16"
XP_TEST_MODULE_UINT16_VALUE_T = 16

XP_TEST_MODULE_UINT32 = "/test-module:main/ui32"
XP_TEST_MODULE_UINT32_VALUE_T = 32

XP_TEST_MODULE_UINT64 = "/test-module:main/ui64"
XP_TEST_MODULE_UINT64_VALUE_T = 64

def create_test_module():
    connection = sr.Connection("test-module")

    session = sr.Session(connection, sr.SR_DS_STARTUP)
    session.delete_item("/test-module:*")

    v = sr.Val(XP_TEST_MODULE_ENUM_VALUE, sr.SR_ENUM_T)
    session.set_item(XP_TEST_MODULE_ENUM, v)

    v = sr.Val(XP_TEST_MODULE_RAW_VALUE, sr.SR_BINARY_T)
    session.set_item(XP_TEST_MODULE_RAW, v)

    v = sr.Val(XP_TEST_MODULE_BITS_VALUE, sr.SR_BITS_T)
    session.set_item(XP_TEST_MODULE_BITS, v)

    v = sr.Val(XP_TEST_MODULE_BOOL_VALUE_T, sr.SR_BOOL_T)
    session.set_item(XP_TEST_MODULE_BOOL, v)

    v = sr.Val(XP_TEST_MODULE_DEC64_VALUE_T)
    session.set_item(XP_TEST_MODULE_DEC64, v)

    v = sr.Val(None, sr.SR_LEAF_EMPTY_T)
    session.set_item(XP_TEST_MODULE_EMPTY, v)

    v = sr.Val(XP_TEST_MODULE_IDREF_VALUE, sr.SR_IDENTITYREF_T)
    session.set_item(XP_TEST_MODULE_IDREF, v)

    v = sr.Val(XP_TEST_MODULE_STRING_VALUE, sr.SR_STRING_T)
    session.set_item(XP_TEST_MODULE_STRING, v)

    v = sr.Val(XP_TEST_MODULE_INT8_VALUE_T, sr.SR_INT8_T)
    session.set_item(XP_TEST_MODULE_INT8, v)

    v = sr.Val(XP_TEST_MODULE_INT16_VALUE_T, sr.SR_INT16_T)
    session.set_item(XP_TEST_MODULE_INT16, v)

    v = sr.Val(XP_TEST_MODULE_INT32_VALUE_T, sr.SR_INT32_T)
    session.set_item(XP_TEST_MODULE_INT32, v)

    v = sr.Val(XP_TEST_MODULE_INT64_VALUE_T, sr.SR_INT64_T)
    session.set_item(XP_TEST_MODULE_INT64, v)

    v = sr.Val(XP_TEST_MODULE_UINT8_VALUE_T, sr.SR_UINT8_T)
    session.set_item(XP_TEST_MODULE_UINT8, v)

    v = sr.Val(XP_TEST_MODULE_UINT16_VALUE_T, sr.SR_UINT16_T)
    session.set_item(XP_TEST_MODULE_UINT16, v)

    v = sr.Val(XP_TEST_MODULE_UINT32_VALUE_T, sr.SR_UINT32_T)
    session.set_item(XP_TEST_MODULE_UINT32, v)

    v = sr.Val(XP_TEST_MODULE_UINT64_VALUE_T, sr.SR_UINT64_T)
    session.set_item(XP_TEST_MODULE_UINT64, v)

    for num in [1, 2, 42]:
        v = sr.Val(num, sr.SR_UINT8_T)
        session.set_item("/test-module:main/numbers", v)

    session.set_item("/test-module:list[key='k1']", None)
    v = sr.Val("id_1", sr.SR_IDENTITYREF_T)
    session.set_item("/test-module:list[key='k1']/id_ref", v)

    v = sr.Val(None, sr.SR_CONTAINER_PRESENCE_T)
    session.set_item("/test-module:list[key='k1']/wireless", v)

    session.set_item("/test-module:list[key='k2']", None)
    v = sr.Val("id_2", sr.SR_IDENTITYREF_T)
    session.set_item("/test-module:list[key='k2']/id_ref", v)

    session.commit()

def create_example_module():
    connection = sr.Connection("test-module")

    session = sr.Session(connection, sr.SR_DS_STARTUP)
    session.delete_item("/example-module:*")
    v = sr.Val("Leaf value", sr.SR_STRING_T)
    session.set_item("/example-module:container/list[key1='key1'][key2='key2']/leaf", v)
    session.commit()

def create_ietf_interfaces():
    connection = sr.Connection("ietf-interfaces")

    session = sr.Session(connection, sr.SR_DS_STARTUP)
    session.delete_item("/ietf-interfaces:*")

    v = sr.Val("iana-if-type:ethernetCsmacd", sr.SR_IDENTITYREF_T)
    session.set_item("/ietf-interfaces:interfaces/interface[name='eth0']/type", v)

    v = sr.Val("Ethernet 0", sr.SR_STRING_T);
    session.set_item("/ietf-interfaces:interfaces/interface[name='eth0']/description", v)

    v = sr.Val(True, sr.SR_BOOL_T);
    session.set_item("/ietf-interfaces:interfaces/interface[name='eth0']/enabled", v)

    v = sr.Val(24, sr.SR_UINT8_T)
    session.set_item("/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/address[ip='192.168.2.100']/prefix-length", v)

    v = sr.Val(True, sr.SR_BOOL_T)
    session.set_item("/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/enabled", v)

    v = sr.Val(1500, sr.SR_UINT16_T)
    session.set_item("/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/mtu", v)

    v = sr.Val("iana-if-type:ethernetCsmacd", sr.SR_IDENTITYREF_T)
    session.set_item("/ietf-interfaces:interfaces/interface[name='eth1']/type", v)

    v = sr.Val("Ethernet 1", sr.SR_STRING_T);
    session.set_item("/ietf-interfaces:interfaces/interface[name='eth1']/description", v)

    v = sr.Val(True, sr.SR_BOOL_T)
    session.set_item("/ietf-interfaces:interfaces/interface[name='eth1']/ietf-ip:ipv4/enabled", v)

    v = sr.Val(1500, sr.SR_UINT16_T)
    session.set_item("/ietf-interfaces:interfaces/interface[name='eth1']/ietf-ip:ipv4/mtu", v)

    v = sr.Val("iana-if-type:ethernetCsmacd", sr.SR_IDENTITYREF_T)
    session.set_item("/ietf-interfaces:interfaces/interface[name='gigaeth0']/type", v)

    v = sr.Val("GigabitEthernet 0", sr.SR_STRING_T);
    session.set_item("/ietf-interfaces:interfaces/interface[name='gigaeth0']/description", v)

    v = sr.Val(False, sr.SR_BOOL_T);
    session.set_item("/ietf-interfaces:interfaces/interface[name='gigaeth0']/enabled", v)

    session.commit()


if __name__ == "__main__":
    create_test_module()
