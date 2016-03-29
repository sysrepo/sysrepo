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
import unittest
import TestModule
from SysrepoWrappers import *


class SysrepoBasicTest(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        TestModule.create_test_module()
        self.s = Sysrepo("abc", SR_CONN_DEFAULT)

    def setUp(self):
        self.session = Session(self.s, SR_DS_STARTUP)

    def test_connection(self):
        with self.assertRaises(RuntimeError):
            broken = Sysrepo('Reuqire daemon', 1)

    def test_logg_stderr(self):
        Sysrepo.log_stderr(SR_LL_DBG)
        Sysrepo.log_stderr(SR_LL_NONE)

    def test_get_item(self):
        item = self.session.get_item("/test-module:main/i32")
        self.assertEqual(item.xpath, "/test-module:main/i32")
        self.assertEqual(item.type, SR_INT32_T)

    def test_list_schema(self):
        schemas = self.session.list_schemas()

    def test_get_items(self):
        vals = self.session.get_items("/test-module:main")
        for v in vals:
            self.assertRegexpMatches(v.xpath, "/test-module:main*")

    def test_get_items_iter(self):
        iter = self.session.get_items_iter("/test-module:main", True)
        while True:
            try:
                item = self.session.get_item_next(iter)
                self.assertRegexpMatches(item.xpath, "/test-module:main*")
            except RuntimeError as e:
                if e.message == "Item not found":
                    break
                else:
                    raise e

    def test_set_item(self):
        xpath = "/example-module:container/list[key1='abc'][key2='def']/leaf"
        v = Value(xpath, SR_STRING_T, "Hey hou")
        self.session.set_item(v.xpath, v, SR_EDIT_DEFAULT)

        new_value = self.session.get_item(xpath)
        self.assertEqual(new_value.type, SR_STRING_T)
        self.assertEqual(new_value.value, v.value)

    def test_delete_item(self):
        lists = ["/test-module:user[name='A']", "/test-module:user[name='B']", "/test-module:user[name='C']" ]
        for l in lists:
            self.session.set_item(l, None)

        items = self.session.get_items("/test-module:user")
        self.assertEqual(len(lists), len(items))
        self.session.delete_item("/test-module:user")

    def test_move_item(self):
        lists = ["/test-module:user[name='A']", "/test-module:user[name='B']", "/test-module:user[name='C']" ]
        for l in lists:
            self.session.set_item(l, None)

        items = self.session.get_items("/test-module:user")
        for i in range(0, len(lists)):
            self.assertEqual(items[i].xpath, lists[i])

        self.session.move_item(lists[1], SR_MOVE_UP)
        lists.insert(0, lists.pop(1))

        items = self.session.get_items("/test-module:user")
        for i in range(0, len(lists)):
            self.assertEqual(items[i].xpath, lists[i])

    def test_validate(self):
        v = Value("/test-module:main/numbers", SR_UINT8_T, 42)
        self.session.set_item(v.xpath,v)
        with self.assertRaises(RuntimeError):
            self.session.validate()

if __name__ == '__main__':
    unittest.main()
