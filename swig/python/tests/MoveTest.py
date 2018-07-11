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

    @classmethod
    def tearDownClass(cls):
        TestModule.create_example_module()

    def setUp(self):
        conn = sr.Connection("move_test")
        session = sr.Session(conn, sr.SR_DS_STARTUP)
        session.delete_item("/test-module:*")
        session.set_item("/test-module:user[name='nameA']", None)
        session.set_item("/test-module:user[name='nameB']", None)
        session.set_item("/test-module:user[name='nameC']", None)
        session.set_item("/test-module:user[name='nameD']", None)
        session.commit()

    def compareListItems(self, items, expected):
        for i in range(len(expected)):
            self.assertEquals(items.val(i).xpath(), "/test-module:user[name='name{0}']".format(expected[i]))

    def test_move_after_last(self):
        conn = sr.Connection("move_test1")
        self.session = sr.Session(conn, sr.SR_DS_STARTUP)
        print("move")
        self.session.move_item("/test-module:user[name='nameB']", sr.SR_MOVE_AFTER, "/test-module:user[name='nameD']")
        items = self.session.get_items("/test-module:user")
        self.compareListItems(items, ["A", "C", "D", "B"])

    def test_move_before_first(self):
        conn = sr.Connection("move_test2")
        self.session = sr.Session(conn, sr.SR_DS_STARTUP)
        self.session.move_item("/test-module:user[name='nameC']", sr.SR_MOVE_BEFORE, "/test-module:user[name='nameA']")
        items = self.session.get_items("/test-module:user")
        self.compareListItems(items, ["C", "A", "B", "D"])

    def test_move_after_unknown(self):
        conn = sr.Connection("move_test3")
        self.session = sr.Session(conn, sr.SR_DS_STARTUP)
        with self.assertRaises(RuntimeError):
            self.session.move_item("/test-module:user[name='nameB']", sr.SR_MOVE_AFTER, "/test-module:user[name='nameXY']")

    def test_move_last_first(self):
        conn = sr.Connection("move_test4")
        self.session = sr.Session(conn, sr.SR_DS_STARTUP)
        self.session.move_item("/test-module:user[name='nameC']", sr.SR_MOVE_LAST)
        items = self.session.get_items("/test-module:user")
        self.compareListItems(items, ["A", "B", "D", "C"])

if __name__ == '__main__':
    unittest.main()
