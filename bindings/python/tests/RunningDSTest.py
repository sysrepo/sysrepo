#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = "Ian Miller <imiller@adva.com>"
__copyright__ = "Copyright 2020, ADVA Inc."
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
import unittest
import TestModule
import sysrepo as sr

TEST_PATH="/test-module:main/string"
class RunningDSTester(SysrepoTester):

    def copyStartup(self):
        self.session.copy_config(sr.SR_DS_STARTUP)

    def isInitialized(self):
        # Validate that the SR_DS_RUNNING is initialized from SR_DS_STARTUP
        item = self.session.get_item(TEST_PATH)
        self.tc.assertEqual(item.type(), sr.SR_STRING_T)
        self.tc.assertEqual(item.data().get_string(), "str")

    def changeRunning(self):
        # Modify the running and apply
        v = sr.Val("in_running", sr.SR_STRING_T)
        self.session.set_item(TEST_PATH, v)
        self.commitStep()

    def addModule(self):
        TestModule.create_iana_if_type_module()

    def verifyRunningChange(self):
        item = self.session.get_item(TEST_PATH)
        self.tc.assertEqual(item.type(), sr.SR_STRING_T)
        self.tc.assertEqual(item.data().get_string(), "in_running")

    def verifyStartup(self):
        startSession = sr.Session(self.sr, sr.SR_DS_STARTUP)
        item = startSession.get_item(TEST_PATH)
        self.tc.assertEqual(item.type(), sr.SR_STRING_T)
        self.tc.assertEqual(item.data().get_string(), "str")


class RunningDSTest(unittest.TestCase):

    def remove_interfaces(self):
        TestModule.remove_iana_if_type_module()
        TestModule.remove_test_module()
        TestModule.remove_referenced_data_module()

    @classmethod
    def setUpClass(self):
        self.remove_interfaces(self)

    @classmethod
    def tearDownClass(self):
        self.remove_interfaces(self)

    @classmethod
    def setUp(self):
        if not TestModule.create_referenced_data_module():
            self.remove_interfaces(self)
            self.skipTest(self,"Test environment is not clean!")
            print("Environment is not clean!")
            return
        if not TestModule.create_test_module():
            self.remove_interfaces(self)
            self.skipTest(self,"Test environment is not clean!")
            print("Environment is not clean!")
            return

    @classmethod
    def tearDown(self):
        self.remove_interfaces(self)

    def test_copy_startup_running(self):
        #tm = TestManager()

        tester = RunningDSTester("Tester1", ds=sr.SR_DS_RUNNING, connectInSetup=True)

        # Initialize running from startup as baseline
        tester.add_step( tester.copyStartup )

        # Verify running
        tester.add_step( tester.isInitialized )

        # modify running
        tester.add_step( tester.changeRunning )

        # Add a new module
        tester.add_step( tester.addModule )

        # Ensure all connections are stopped so that the new module is loaded
        tester.add_step( tester.stopSession )
        tester.add_step( tester.disconnect )

        # Reconnect
        tester.add_step( tester.restartConnection )

        # Verify that the running datastore retained the change we made
        tester.add_step( tester.verifyRunningChange )

        # Verify that the startup datastore has not changed
        tester.add_step( tester.verifyStartup )

        tester.run()
        #tm.add_tester(tester)
        #tm.run()

        return

if __name__ == '__main__':
    unittest.main()

