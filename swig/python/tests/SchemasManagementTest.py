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
#
# sysrepod must be in PATH

from ConcurrentHelpers import *
import subprocess
import TestModule
import sysrepo


class SysrepoctlTester(SysrepoTester):

    sysrepoctl = "{}/src/sysrepoctl".format(os.path.realpath(os.curdir))

    def installModuleStep(self, yang_file, log_level = sr.SR_LL_INF):
        self.process = subprocess.Popen([self.sysrepoctl, "-i", "--yang={0}".format(yang_file), "-L {0}".format(log_level)])
        rc = self.process.wait()
        self.tc.assertEqual(rc, 0)

    def uninstallModuleFailStep(self, module_name, log_level = sr.SR_LL_INF):
        self.process = subprocess.Popen([self.sysrepoctl, "--uninstall", "--module={0}".format(module_name), "-L {0}".format(log_level)])
        rc = self.process.wait()
        self.tc.assertNotEquals(rc, 0)

    def uninstallModuleStep(self, module_name, log_level = sr.SR_LL_INF):
        self.process = subprocess.Popen([self.sysrepoctl, "--uninstall", "--module={0}".format(module_name), "-L {0}".format(log_level)])
        rc = self.process.wait()
        self.tc.assertEqual(rc, 0)


class SchemasManagementTest(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        TestModule.create_test_module()

    def test_ModuleLoading(self):
        """Schemas are loaded on demand. Try to send multiple requests targeting the same model
        simultaneously. All of the should receive correct data.
        """
        tm = TestManager()

        srd = SysrepodDaemonTester("Srd")
        tester1 = SysrepoTester("First", sr.SR_DS_STARTUP, sr.SR_CONN_DAEMON_REQUIRED, False)
        tester2 = SysrepoTester("Second", sr.SR_DS_STARTUP, sr.SR_CONN_DAEMON_REQUIRED, False)
        tester3 = SysrepoTester("Third", sr.SR_DS_STARTUP, sr.SR_CONN_DAEMON_REQUIRED, False)
        tester4 = SysrepoTester("Fourth", sr.SR_DS_STARTUP, sr.SR_CONN_DAEMON_REQUIRED, False)


        srd.add_step(srd.startDaemonStep)
        tester1.add_step(tester1.waitStep)
        tester2.add_step(tester2.waitStep)
        tester3.add_step(tester3.waitStep)
        tester4.add_step(tester4.waitStep)

        srd.add_step(srd.waitStep)
        tester1.add_step(tester1.restartConnection)
        tester2.add_step(tester2.restartConnection)
        tester3.add_step(tester3.restartConnection)
        tester4.add_step(tester4.restartConnection)

        srd.add_step(srd.waitStep)
        tester1.add_step(tester1.getItemsStepExpectedCount, "/test-module:main/*", 19)
        tester2.add_step(tester2.getItemsStepExpectedCount, "/test-module:main/*", 19)
        tester3.add_step(tester3.getItemsStepExpectedCount, "/test-module:main/*", 19)
        tester4.add_step(tester4.getItemsStepExpectedCount, "/test-module:main/*", 19)

        srd.add_step(srd.stopDaemonStep)

        tm.add_tester(srd)
        tm.add_tester(tester1)
        tm.add_tester(tester2)
        tm.add_tester(tester3)
        tm.add_tester(tester4)
        tm.run()

    def test_module_uninstall(self):
        """A schema can not be uninstalled until it is used by a session.
        Test simulates the request of sysrepoctl trying to uninstall/install module.
        """
        tmp_file = "/tmp/test-module.yang"  # used to reinstall 'test-module' after uninstall
        dep_file = "/tmp/referenced-data.yang"  # 'test-module' depends on 'referenced-data'
        tm = TestManager()

        srd = SysrepodDaemonTester("Srd")
        tester1 = SysrepoTester("First", sr.SR_DS_STARTUP, sr.SR_CONN_DAEMON_REQUIRED, False)
        tester2 = SysrepoTester("Second", sr.SR_DS_STARTUP, sr.SR_CONN_DAEMON_REQUIRED, False)
        tester3 = SysrepoTester("Third", sr.SR_DS_STARTUP, sr.SR_CONN_DAEMON_REQUIRED, False)
        admin = SysrepoctlTester()


        srd.add_step(srd.startDaemonStep)
        tester1.add_step(tester1.waitStep)
        tester2.add_step(tester2.waitStep)
        tester3.add_step(tester3.waitStep)
        admin.add_step(admin.waitStep)

        srd.add_step(srd.waitStep)
        tester1.add_step(tester1.restartConnection)
        tester2.add_step(tester2.restartConnection)
        tester3.add_step(tester3.restartConnection)
        admin.add_step(admin.waitStep)

        srd.add_step(srd.waitStep)
        tester1.add_step(tester1.getItemsStepExpectedCount, "/test-module:main/*", 19)
        tester2.add_step(tester2.setItemStep, "/test-module:main/string", sr.Val("abcd", sr.SR_STRING_T))
        tester3.add_step(tester3.lockModelStep, "test-module")
        admin.add_step(admin.waitStep)

        #unsuccesful try to uninstall
        srd.add_step(srd.waitStep)
        tester1.add_step(tester1.waitStep)
        tester2.add_step(tester2.waitStep)
        tester3.add_step(tester3.waitStep)
        admin.add_step(admin.uninstallModuleFailStep, "test-module")

        #export schema to file before uninstall and release lock
        srd.add_step(srd.waitStep)
        admin.add_step(admin.waitStep)
        tester1.add_step(tester1.getSchemaToFileStep, "test-module", tmp_file)
        tester2.add_step(tester2.getSchemaToFileStep, "referenced-data", dep_file)
        tester3.add_step(tester3.unlockModelStep, "test-module")


        #testers 1,2 close the session, tester 3 releases the lock -> module can be uninstalled
        srd.add_step(srd.waitStep)
        admin.add_step(admin.waitStep)
        tester1.add_step(tester1.stopSession)
        tester2.add_step(tester2.stopSession)
        tester3.add_step(tester3.waitStep)

        #uninstall succeed
        srd.add_step(srd.waitStep)
        admin.add_step(admin.uninstallModuleStep, "test-module")
        tester3.add_step(tester3.waitStep)

        #module is uninstalled
        srd.add_step(srd.waitStep)
        admin.add_step(admin.waitStep)
        tester3.add_step(tester3.setItemFailStep, "/test-module:main/string", sr.Val("abcd", sr.SR_STRING_T))

        #install module back
        srd.add_step(srd.waitStep)
        admin.add_step(admin.installModuleStep, tmp_file)
        tester3.add_step(tester3.waitStep)

        #request work again
        srd.add_step(srd.waitStep)
        tester3.add_step(tester3.setItemStep, "/test-module:main/string", sr.Val("abcd", sr.SR_STRING_T))

        srd.add_step(srd.stopDaemonStep)

        tm.add_tester(srd)
        tm.add_tester(tester1)
        tm.add_tester(tester2)
        tm.add_tester(tester3)
        tm.add_tester(admin)
        tm.run()


if __name__ == '__main__':
    unittest.main()
