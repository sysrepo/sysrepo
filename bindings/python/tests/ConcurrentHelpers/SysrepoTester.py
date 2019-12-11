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
from time import sleep
import sysrepo as sr


class SysrepoTester(Tester):
    def __init__(self, name="SysrepoUser", ds=sr.SR_DS_STARTUP, conn_mode=sr.SR_CONN_DEFAULT, connectInSetup=True):
        super(SysrepoTester, self).__init__(name)
        self.ds = ds
        self.conn = conn_mode
        self.autoconnect = connectInSetup

    def setup(self):
        if self.autoconnect:
            self.sr = sr.Connection(self.conn)
            self.session = sr.Session(self.sr, self.ds)

    def restartConnection(self):
        try:
            self.sr = sr.Connection(self.conn)
        except RuntimeError as r:
            raise r
        self.session = sr.Session(self.sr, self.ds)

    def disconnect(self):
        self.sr=None

    def stopSession(self):
        self.session.session_stop()
        self.session = None

    def startSession(self):
        self.tc.assertNotEqual(self.sr, None)
        self.tc.assertEqual(self.session, None)
        self.session = sr.Session(self.sr, self.ds)

    def lockStep(self):
        self.session.lock()

    def lockFailStep(self):
        with self.tc.assertRaises(RuntimeError):
            self.session.lock()

    def unlockStep(self):
        self.session.unlock()

    def lockModelStep(self, module_name):
        self.session.lock(module_name)

    def lockFailModelStep(self, module_name):
        with self.tc.assertRaises(RuntimeError):
            self.session.lock(module_name)

    def unlockModelStep(self, module_name):
        self.session.unlock(module_name)

    def commitFailStep(self):
        with self.tc.assertRaises(RuntimeError):
            self.session.apply_changes()

    def commitStep(self):
        self.session.apply_changes()

    def getItemsStep(self, xpath):
        self.session.get_items(xpath)
        self.session.get_items(xpath)

    def getItemsStepExpectedCount(self, xpath, count):
        items = self.session.get_items(xpath)
        self.tc.assertEqual(items.val_cnt(), count)

    def getItemsFailStep(self, xpath):
        with self.tc.assertRaisesRegex(RuntimeError, ".* found"):
            vs = self.session.get_items(xpath)
            if vs is None:
                raise (RuntimeError(".* found"))

    def deleteItemStep(self, xpath):
        self.session.delete_item(xpath)

    def setItemStep(self, xpath, value):
        self.session.set_item(xpath, value)

    def setItemFailStep(self, xpath, value):
        with self.tc.assertRaises(RuntimeError):
            self.session.set_item(xpath, value)

    def waitTimeoutStep(self, timeout):
        sleep(timeout)

    def uninstallModuleStep(self, module_name):
        rc = self.sr.remove_module(module_name)
        self.tc.assertEqual(rc, None)

    def uninstallModuleFailStep(self, module_name):
        rc = self.sr.remove_module(module_name)
        self.tc.assertNotEqual(rc, None)
