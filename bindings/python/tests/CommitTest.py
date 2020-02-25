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

from ConcurrentHelpers import *
import TestModule
import sysrepo as sr

class CommitTester(SysrepoTester):
    def setup(self):
        super(CommitTester, self).setup()
        self.add_step(self.setItemStep)
        self.add_step(self.commitFailStep)
        self.add_step(self.checkItemStep)
        self.add_step(self.commitStep)
        self.add_step(self.checkItemStep)
        self.add_step(self.stopSession)
        self.add_step(self.disconnect)

    def setItemStep(self):
        v = sr.Val(99, sr.SR_INT8_T)
        self.session.set_item("/test-module:main/i8", v)

    def checkItemStep(self):
        v = self.session.get_item("/test-module:main/i8")
        self.tc.assertEqual(99, v.data().get_int8())

class CommitTest(unittest.TestCase):

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

    @classmethod
    def tearDown(self):
        self.remove_modules(self)

    def test_CommitAndDsLock(self):
        tm = TestManager()

        first = SysrepoTester("First")
        first.add_step(first.lockStep)
        first.add_step(first.waitStep)
        first.add_step(first.unlockStep)
        first.add_step(first.stopSession)
        first.add_step(first.disconnect)
        tm.add_tester(first)

        tm.add_tester(CommitTester("Second"))
        tm.run()


if __name__ == '__main__':
    unittest.main()

