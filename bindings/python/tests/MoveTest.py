# !/usr/bin/env python
from csv import excel

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

class MoveTest(unittest.TestCase):


    def remove_modules(self):
        TestModule.remove_test_module()
        TestModule.remove_referenced_data_module()

    @classmethod
    def setUpClass(self):
        self.remove_modules(self)

    @classmethod
    def tearDownClass(self):
        self.remove_modules(self)

    @classmethod
    def tearDown(self):
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
        conn = sr.Connection(sr.SR_CONN_DEFAULT)
        session = sr.Session(conn, sr.SR_DS_STARTUP)
        session.delete_item("/test-module:user[name='A']")
        session.delete_item("/test-module:user[name='B']")
        session.delete_item("/test-module:user[name='C']")
        session.delete_item("/test-module:user[name='D']")
        session.apply_changes()
        session.set_item("/test-module:user[name='A']", sr.Val(None, sr.SR_LIST_T))
        session.set_item("/test-module:user[name='B']", sr.Val(None, sr.SR_LIST_T))
        session.set_item("/test-module:user[name='C']", sr.Val(None, sr.SR_LIST_T))
        session.set_item("/test-module:user[name='D']", sr.Val(None, sr.SR_LIST_T))
        session.apply_changes()

        session.session_stop()

        conn=None

    def compareListItems(self, items, expected):
        for i in range(len(expected)):
            self.assertEqual(items.val(i).xpath(), "/test-module:user[name='{0}']".format(expected[i]))

    def test_move_after_last(self):
        conn = sr.Connection(sr.SR_CONN_DEFAULT)
        self.session = sr.Session(conn, sr.SR_DS_STARTUP)
        items = self.session.get_items("/test-module:user")
        self.compareListItems(items, ["A", "B", "C", "D"])
        self.session.move_item("/test-module:user[name='B']", sr.SR_MOVE_AFTER, "[name='D']","B")
        self.session.apply_changes()
        items = self.session.get_items("/test-module:user")
        self.compareListItems(items, ["A", "C", "D", "B"])
        self.session.session_stop()

        conn=None

    def test_move_before_first(self):
        conn = sr.Connection(sr.SR_CONN_DEFAULT)
        self.session = sr.Session(conn, sr.SR_DS_STARTUP)
        self.session.move_item("/test-module:user[name='C']", sr.SR_MOVE_BEFORE, "[name='A']", "C")
        self.session.apply_changes()
        items = self.session.get_items("/test-module:user")
        self.compareListItems(items, ["C", "A", "B", "D"])
        self.session.session_stop()

        conn=None

    def test_move_after_unknown(self):
        conn = sr.Connection(sr.SR_CONN_DEFAULT)
        self.session = sr.Session(conn, sr.SR_DS_STARTUP)
        with self.assertRaises(RuntimeError):
            self.session.move_item("/test-module:user[name='B']", sr.SR_MOVE_AFTER, "[name='XY']", "B")
            self.session.apply_changes()
        self.session.session_stop()

        conn=None


    def test_move_last_first(self):
        conn = sr.Connection(sr.SR_CONN_DEFAULT)
        self.session = sr.Session(conn, sr.SR_DS_STARTUP)
        self.session.move_item("/test-module:user[name='C']", sr.SR_MOVE_LAST)
        items = self.session.get_items("/test-module:user")
        self.compareListItems(items, ["A", "B", "D", "C"])
        self.session.session_stop()

        conn=None

if __name__ == '__main__':
    unittest.main()
