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
# sysrepod and subscription_test_app must be in PATH

from ConcurrentHelpers import *
from SysrepoWrappers import *
import signal
import os
import subprocess
import TestModule

class SubscriptionTester(SysrepoTester):

    def subscribeStep(self):
        self.process = subprocess.Popen("subscription_test_app")
        self.report_pid(self.process.pid)
        # wait for running data file to be copied
        time.sleep(0.1)

    def cancelSubscriptionStep(self):
        os.kill(self.process.pid, signal.SIGUSR1)
        self.process.wait()

    def killStep(self):
        os.kill(self.process.pid, signal.SIGTERM)
        self.process.wait()

class SysrepodTester(SysrepoTester):

    def startDaemonStep(self):
        self.process = subprocess.Popen(["sysrepod", "-d"])
        self.report_pid(self.process.pid)

    def stopDaemonStep(self):
        os.kill(self.process.pid, signal.SIGTERM)
        self.process.wait()


class SubscriptionTest(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        TestModule.create_ietf_interfaces()

    def test_SubscribeUnsubscribe(self):
        tm = TestManager()

        srd = SysrepodTester("Srd")
        reader = SysrepoTester("First", SR_DS_RUNNING, SR_CONN_DAEMON_REQUIRED, False)
        subscriber = SubscriptionTester("Second")

        srd.add_step(srd.startDaemonStep)
        reader.add_step(reader.waitStep)
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.waitStep)
        reader.add_step(reader.restartConnection)
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.waitStep)
        reader.add_step(reader.getItemsFailStep, "/ietf-interfaces:*")
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.waitStep)
        reader.add_step(reader.waitStep)
        subscriber.add_step(subscriber.subscribeStep)

        srd.add_step(srd.waitStep)
        reader.add_step(reader.refreshStep)
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.waitStep)
        reader.add_step(reader.getItemsStep, "/ietf-interfaces:*")
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.waitStep)
        reader.add_step(reader.waitStep)
        subscriber.add_step(subscriber.cancelSubscriptionStep)

        srd.add_step(srd.waitStep)
        reader.add_step(reader.getItemsFailStep, "/ietf-interfaces:*")
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.stopDaemonStep)

        tm.add_tester(srd)
        tm.add_tester(reader)
        tm.add_tester(subscriber)
        tm.run()

    def test_SubscribeKill(self):
        tm = TestManager()

        srd = SysrepodTester("Srd")
        reader = SysrepoTester("First", SR_DS_RUNNING)
        subscriber = SubscriptionTester("Second")

        srd.add_step(srd.startDaemonStep)
        reader.add_step(reader.waitStep)
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.waitStep)
        reader.add_step(reader.restartConnection)
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.waitStep)
        reader.add_step(reader.getItemsFailStep, "/ietf-interfaces:*")
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.waitStep)
        reader.add_step(reader.waitStep)
        subscriber.add_step(subscriber.subscribeStep)

        srd.add_step(srd.waitStep)
        reader.add_step(reader.refreshStep)
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.waitStep)
        reader.add_step(reader.getItemsStep, "/ietf-interfaces:*")
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.waitStep)
        reader.add_step(reader.waitStep)
        subscriber.add_step(subscriber.killStep)

        srd.add_step(srd.waitStep)
        reader.add_step(reader.getItemsFailStep, "/ietf-interfaces:*")
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.stopDaemonStep)

        tm.add_tester(srd)
        tm.add_tester(reader)
        tm.add_tester(subscriber)
        tm.run()

if __name__ == '__main__':
    unittest.main()
