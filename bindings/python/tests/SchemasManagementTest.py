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
import subprocess
import TestModule
import sysrepo


class SysrepoModuleTester(SysrepoTester):
    sysrepoctl = "sysrepoctl"

    def installModuleStep(self, schema_path):
        rc = self.sr.install_module(os.environ['TESTS_DIR']+"/files/" + schema_path, os.environ['TESTS_DIR']+"/files", [])
        self.tc.assertEqual(rc, None)

    def uninstallModuleFailStep(self, module_name):
        rc = self.sr.remove_module(module_name)
        self.tc.assertNotEqual(rc, None)

    def uninstallModuleStep(self, module_name, log_level = sr.SR_LL_INF):
        rc = self.sr.remove_module(module_name)
        self.tc.assertEqual(rc, None)


class SchemasManagementTest(unittest.TestCase):

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

    def test_ModuleLoading(self):
         """Schemas are loaded on demand. Try to send multiple requests targeting the same model
         simultaneously. All of the should receive correct data.
         """
         tm = TestManager()
         tester1 = SysrepoTester("First", sr.SR_DS_STARTUP)
         tester2 = SysrepoTester("Second", sr.SR_DS_STARTUP)
         tester3 = SysrepoTester("Third", sr.SR_DS_STARTUP)
         tester4 = SysrepoTester("Fourth", sr.SR_DS_STARTUP)

         tester1.add_step(tester1.getItemsStepExpectedCount,
                          "/test-module:main/*", 19)
         tester2.add_step(tester2.getItemsStepExpectedCount,
                          "/test-module:main/*", 19)
         tester3.add_step(tester3.getItemsStepExpectedCount,
                          "/test-module:main/*", 19)
         tester4.add_step(tester4.getItemsStepExpectedCount,
                          "/test-module:main/*", 19)

         tester1.add_step(tester1.stopSession)
         tester2.add_step(tester2.stopSession)
         tester3.add_step(tester3.stopSession)
         tester4.add_step(tester4.stopSession)

         tester1.add_step(tester1.disconnect)
         tester2.add_step(tester2.disconnect)
         tester3.add_step(tester3.disconnect)
         tester4.add_step(tester4.disconnect)

         tm.add_tester(tester1)
         tm.add_tester(tester2)
         tm.add_tester(tester3)
         tm.add_tester(tester4)
         tm.run()

    def test_module_uninstall(self):
        test_module_file = "test-module.yang"
        referenced_data_file = "referenced-data.yang"
        file_location = "/tmp/"
        tm = TestManager()

        tester1 = SysrepoTester("First", sr.SR_DS_STARTUP)
        tester2 = SysrepoTester("Second", sr.SR_DS_STARTUP)
        tester3 = SysrepoTester("Third", sr.SR_DS_STARTUP)
        admin = SysrepoModuleTester()

        tester1.add_step(tester1.getItemsStepExpectedCount, "/test-module:main/*", 19)
        tester2.add_step(tester2.setItemStep, "/test-module:main/string", sr.Val("abcd", sr.SR_STRING_T))
        tester3.add_step(tester3.waitStep)
        tester1.add_step(tester1.waitStep)
        admin.add_step(admin.waitStep)

        tester1.add_step(tester1.commitStep)
        tester2.add_step(tester2.commitStep)
        tester3.add_step(tester3.waitStep)
        admin.add_step(admin.waitStep)

        admin.add_step(admin.stopSession)
        tester1.add_step(tester1.stopSession)
        tester2.add_step(tester2.stopSession)
        tester3.add_step(tester3.waitStep)

        admin.add_step(admin.disconnect)
        tester1.add_step(tester1.disconnect)
        tester2.add_step(tester2.disconnect)
        tester3.add_step(tester3.waitStep)

        admin.add_step(admin.waitStep)
        tester3.add_step(tester3.stopSession)

        tester3.add_step(tester3.uninstallModuleStep, "test-module")
        admin.add_step(admin.waitStep)

        admin.add_step(admin.waitStep)
        tester3.add_step(tester3.disconnect)

        admin.add_step(admin.restartConnection)
        tester3.add_step(tester3.restartConnection )

        admin.add_step(admin.waitStep)
        tester3.add_step(tester3.setItemFailStep, "/test-module:main/string", sr.Val("abcd", sr.SR_STRING_T))

        tester3.add_step(tester3.commitStep)
        admin.add_step(admin.waitStep)

        admin.add_step(admin.installModuleStep, test_module_file)
        tester3.add_step(tester3.waitStep)

        admin.add_step(admin.stopSession)
        tester3.add_step(tester3.stopSession)

        admin.add_step(admin.disconnect)
        tester3.add_step(tester3.disconnect)

        admin.add_step(admin.restartConnection)
        tester3.add_step(tester3.restartConnection)

        admin.add_step(admin.waitStep)
        tester3.add_step(tester3.setItemStep, "/test-module:main/string", sr.Val("abcd", sr.SR_STRING_T))

        admin.add_step(admin.stopSession)
        tester3.add_step(tester3.stopSession)

        admin.add_step(admin.disconnect)
        tester3.add_step(tester3.disconnect)

        tm.add_tester(tester1)
        tm.add_tester(tester2)
        tm.add_tester(tester3)
        tm.add_tester(admin)
        tm.run()


if __name__ == '__main__':
    unittest.main()
