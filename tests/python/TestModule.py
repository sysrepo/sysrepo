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

from SysrepoWrappers import *

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
    sr = Sysrepo("test-module")

    session = Session(sr, SR_DS_STARTUP)
    session.delete_item("/test-module:")

    v = Value(XP_TEST_MODULE_ENUM, SR_ENUM_T, XP_TEST_MODULE_ENUM_VALUE)
    session.set_item(v.xpath, v)

    v = Value(XP_TEST_MODULE_RAW, SR_BINARY_T, XP_TEST_MODULE_RAW_VALUE)
    session.set_item(v.xpath, v)

    v = Value(XP_TEST_MODULE_BITS, SR_BITS_T, XP_TEST_MODULE_BITS_VALUE)
    session.set_item(v.xpath, v)

    v = Value(XP_TEST_MODULE_BOOL, SR_BOOL_T, XP_TEST_MODULE_BOOL_VALUE_T)
    session.set_item(v.xpath, v)

    v = Value(XP_TEST_MODULE_DEC64, SR_DECIMAL64_T, XP_TEST_MODULE_DEC64_VALUE_T)
    session.set_item(v.xpath, v)

    v = Value(XP_TEST_MODULE_EMPTY, SR_LEAF_EMPTY_T, None)
    session.set_item(v.xpath, v)

    v = Value(XP_TEST_MODULE_IDREF, SR_IDENTITYREF_T, XP_TEST_MODULE_IDREF_VALUE)
    session.set_item(v.xpath, v)

    v = Value(XP_TEST_MODULE_STRING, SR_STRING_T, XP_TEST_MODULE_STRING_VALUE)
    session.set_item(v.xpath, v)

    v = Value(XP_TEST_MODULE_INT8, SR_INT8_T, XP_TEST_MODULE_INT8_VALUE_T)
    session.set_item(v.xpath, v)

    v = Value(XP_TEST_MODULE_INT16, SR_INT16_T, XP_TEST_MODULE_INT16_VALUE_T)
    session.set_item(v.xpath, v)

    v = Value(XP_TEST_MODULE_INT32, SR_INT32_T, XP_TEST_MODULE_INT32_VALUE_T)
    session.set_item(v.xpath, v)

    v = Value(XP_TEST_MODULE_INT64, SR_INT64_T, XP_TEST_MODULE_INT64_VALUE_T)
    session.set_item(v.xpath, v)

    v = Value(XP_TEST_MODULE_UINT8, SR_UINT8_T, XP_TEST_MODULE_UINT8_VALUE_T)
    session.set_item(v.xpath, v)

    v = Value(XP_TEST_MODULE_UINT16, SR_UINT16_T, XP_TEST_MODULE_UINT16_VALUE_T)
    session.set_item(v.xpath, v)

    v = Value(XP_TEST_MODULE_UINT32, SR_UINT32_T, XP_TEST_MODULE_UINT32_VALUE_T)
    session.set_item(v.xpath, v)

    v = Value(XP_TEST_MODULE_UINT64, SR_UINT64_T, XP_TEST_MODULE_UINT64_VALUE_T)
    session.set_item(v.xpath, v)

    for num in [1, 2, 42]:
        v = Value("/test-module:main/numbers", SR_UINT8_T, num)
        session.set_item(v.xpath, v)

    session.set_item("/test-module:list[key='k1']", None)
    v = Value("/test-module:list[key='k1']/id_ref", SR_IDENTITYREF_T, "id_1")
    session.set_item(v.xpath, v)

    v = Value("/test-module:list[key='k1']/wireless", SR_CONTAINER_PRESENCE_T, None)
    session.set_item(v.xpath, v)

    session.set_item("/test-module:list[key='k2']", None)
    v = Value("/test-module:list[key='k2']/id_ref", SR_IDENTITYREF_T, "id_2")
    session.set_item(v.xpath, v)

    session.commit()


if __name__ == "__main__":
    create_test_module()
