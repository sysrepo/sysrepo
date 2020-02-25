#!/usr/bin/env python
from __future__ import print_function

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
import sysrepo as sr

class SysrepoBasicTest(unittest.TestCase):

    def remove_modules(self):
        TestModule.remove_example_module()
        TestModule.remove_test_module()
        TestModule.remove_referenced_data_module()

    @classmethod
    def setUpClass(self):
        self.remove_modules(self)
        self.conn= sr.Connection(sr.SR_CONN_DEFAULT)

    @classmethod
    def tearDownClass(self):
        self.conn=None
        self.remove_modules(self)

    @classmethod
    def setUp(self):
        if not TestModule.create_referenced_data_module():
            self.remove_modules(self)
            self.skipTest(self,"Test environment is not clean!")
            print("Environment is not clean!")
            return
        if not TestModule.create_test_module():
            self.remove_modules(self)
            self.skipTest(self,"Test environment is not clean!")
            print("Environment is not clean!")
            return
        if not TestModule.create_example_module():
            self.remove_modules(self)
            self.skipTest(self,"Test environment is not clean!")
            print("Environment is not clean!")
            return
        self.session = sr.Session(self.conn, sr.SR_DS_STARTUP)
        self.conn= sr.Connection(sr.SR_CONN_DEFAULT)

    @classmethod
    def tearDown(self):
        self.remove_modules(self)
        self.session.session_stop()
        self.conn=None

    def test_logg_stderr(self):
        log = sr.Logs()
        log.set_stderr(sr.SR_LL_NONE)

    def test_get_item(self):
        item = self.session.get_item("/test-module:main/i32")
        self.assertEqual(item.xpath(), "/test-module:main/i32")
        self.assertEqual(item.type(), sr.SR_INT32_T)

    def test_list_schema(self):
        schemas = self.conn.get_module_info()

    def test_get_items(self):
        vals = self.session.get_items("/test-module:main")
        for i in range(vals.val_cnt()):
            v = vals.val(i)
            self.assertRegex(v.xpath(), "/test-module:main*")

    def test_set_item(self):
        xpath = "/example-module:container/list[key1='abc'][key2='def']/leaf"
        v = sr.Val("Hey hou", sr.SR_STRING_T)
        self.session.set_item(xpath, v)
        self.session.apply_changes()
        new_value = self.session.get_item(xpath)
        self.assertEqual(new_value.type(), sr.SR_STRING_T)
        self.assertEqual(new_value.data().get_string(), v.data().get_string())

    # This test used to put values to None in loop below. At the moment that segfaults.
    # It also did not add 'type' and 'full' name to xpath.
    def test_delete_item(self):
        lists = ["/test-module:user[name='A']", "/test-module:user[name='B']", "/test-module:user[name='C']" ]
        v = sr.Val("", sr.SR_STRING_T)
        for l in lists:
            self.session.set_item(l+'/type', v)
            self.session.set_item(l+'/full-name', v)
        self.session.apply_changes()
        items = self.session.get_items("/test-module:user")

        self.assertEqual(len(lists), items.val_cnt())
        for l in lists:
            self.session.delete_item(l)
        self.session.apply_changes()

    # Setting item to None segfaults...
    def test_move_item(self):
        lists = ["/test-module:user[name='A']", "/test-module:user[name='B']", "/test-module:user[name='C']" ]
        for l in lists:
            v = sr.Val(None, sr.SR_LIST_T)
            self.session.set_item(l, v)

        self.session.apply_changes()
        items = self.session.get_items("/test-module:user")
        for i in range(0, len(lists)):
            self.assertEqual(items.val(i).xpath(), lists[i])

        self.session.move_item(lists[1], sr.SR_MOVE_FIRST)

        lists.insert(0, lists.pop(1))

        items = self.session.get_items("/test-module:user")
        for i in range(0, len(lists)):
            self.assertEqual(items.val(i).xpath(), lists[i])

    def test_validate(self):
        v = sr.Val(42, sr.SR_UINT8_T)
        self.session.set_item("/test-module:main/numbers", v)

    def test_commit_empty(self):
        TestModule.create_test_module()
        v_old = self.session.get_item("/test-module:main/string")
        TestModule.delete_all_items_test(self.session)
        self.session.apply_changes()
        #test random leaf that was deleted
        v_none = self.session.get_item("/test-module:main/string")
        self.assertIsNone(v_none)
        self.session.set_item("/test-module:main/string", v_old)
        self.session.apply_changes()
        TestModule.create_test_module()

if __name__ == '__main__':
    unittest.main()
