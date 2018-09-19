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

    @classmethod
    def setUpClass(self):
        TestModule.create_test_module()
        self.conn= sr.Connection("abc", sr.SR_DS_STARTUP)

    def setUp(self):
        TestModule.create_test_module()
        self.session = sr.Session(self.conn, sr.SR_DS_STARTUP)

    # No point in test?
    # def test_connection(self):
    #     with self.assertRaises(RuntimeError):
    #         broken = sr.Connection('Reuqire daemon', 1)

    def test_logg_stderr(self):
        # sr.Connection.set_stderr(sr.SR_LL_DBG)
        log = sr.Logs()
        log.set_stderr(sr.SR_LL_NONE)

    def test_get_item(self):
        item = self.session.get_item("/test-module:main/i32")
        print (item.to_string(),end='')
        self.assertEqual(item.xpath(), "/test-module:main/i32")
        self.assertEqual(item.type(), sr.SR_INT32_T)

    def test_list_schema(self):
        schemas = self.session.list_schemas()

    def test_get_items(self):
        vals = self.session.get_items("/test-module:main")
        for i in range(vals.val_cnt()):
            v = vals.val(i)
            self.assertRegexpMatches(v.xpath(), "/test-module:main*")
            print (v.to_string(),end='')

    # Infinite loop on 'None' values
    def test_get_items_iter(self):
        it = self.session.get_items_iter("/test-module:main//*")
        while True:
            val = self.session.get_item_next(it)
            if val is None: break
            self.assertRegexpMatches(val.xpath(), "/test-module:main*")

    def test_set_item(self):
        xpath = "/example-module:container/list[key1='abc'][key2='def']/leaf"
        v = sr.Val("Hey hou", sr.SR_STRING_T)
        self.session.set_item(xpath, v)

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
            # set_item(None...)
        items = self.session.get_items("/test-module:user")
        self.assertEqual(len(lists), items.val_cnt())
        self.session.delete_item("/test-module:user")

    # Setting item to None segfaults...
    def test_move_item(self):
        lists = ["/test-module:user[name='A']", "/test-module:user[name='B']", "/test-module:user[name='C']" ]
        for l in lists:
            self.session.set_item(l, None)

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
        connection = sr.Connection("name")
        session = sr.Session(self.conn, sr.SR_DS_STARTUP)
        v_old = self.session.get_item("/test-module:main/string")
        self.session.delete_item("/test-module:*")
        self.session.commit()
        #test random leaf that was deleted
        v_none = self.session.get_item("/test-module:main/string")
        self.assertIsNone(v_none)
        self.session.set_item("/test-module:main/string", v_old)
        self.session.commit()
        TestModule.create_test_module()

if __name__ == '__main__':
    unittest.main()
