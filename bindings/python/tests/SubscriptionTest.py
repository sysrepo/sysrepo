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
import signal
import os
import subprocess
import TestModule
import sysrepo as sr
import unittest
from time import sleep

class SubscriptionTester(SysrepoTester):

    def subscribeStep(self):
        self.process = subprocess.Popen(
            ['python3','SubscriptionTestApp.py'])
        self.report_pid(self.process.pid)
        # wait for running data file to be copied
        sleep(0.1)

    def cancelSubscriptionStep(self):
        os.kill(self.process.pid, signal.SIGUSR1)
        self.process.wait()

    def killStep(self):
        os.kill(self.process.pid, signal.SIGTERM)
        self.process.wait()

    def getOperationalData(self, xpath, expected):
        if(self.session):
            vals = self.session.get_items(xpath)
            self.tc.assertEqual(len(expected), vals.val_cnt())
            for i in range(len(expected)):
                self.tc.assertEqual(vals.val(i).xpath(), expected[i])
        

class SubscriptionTest(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        TestModule.create_ietf_interfaces()

    def test_SubscribeUnsubscribe(self):
        tm = TestManager()

        reader = SubscriptionTester("First", sr.SR_DS_OPERATIONAL)
        subscriber = SubscriptionTester("Second")

        reader.add_step(reader.getOperationalData, "/ietf-interfaces:interfaces-state/interface[name='eth100']", [])
        subscriber.add_step(subscriber.waitStep)

        reader.add_step(reader.waitStep)
        subscriber.add_step(subscriber.subscribeStep)

        reader.add_step(reader.getOperationalData, "/ietf-interfaces:interfaces-state/interface[name='eth100']", ["/ietf-interfaces:interfaces-state/interface[name='eth100']"])
        subscriber.add_step(subscriber.waitStep)

        reader.add_step(reader.waitStep)
        subscriber.add_step(subscriber.cancelSubscriptionStep)
        
        reader.add_step(reader.waitStep)
        subscriber.add_step(subscriber.waitTimeoutStep, 1)

        reader.add_step(reader.getOperationalData, "/ietf-interfaces:interfaces-state/interface[name='eth100']", [])
        subscriber.add_step(subscriber.waitStep)

        tm.add_tester(reader)
        tm.add_tester(subscriber)
        tm.run()

    def test_SubscribeKill(self):
        tm = TestManager()

        reader = SubscriptionTester("First", sr.SR_DS_OPERATIONAL)
        subscriber = SubscriptionTester("Second")

        reader.add_step(reader.getOperationalData, "/ietf-interfaces:interfaces-state/interface[name='eth100']", [])
        subscriber.add_step(subscriber.waitStep)

        reader.add_step(reader.waitStep)
        subscriber.add_step(subscriber.subscribeStep)

        reader.add_step(reader.getOperationalData, "/ietf-interfaces:interfaces-state/interface[name='eth100']", ["/ietf-interfaces:interfaces-state/interface[name='eth100']"])
        subscriber.add_step(subscriber.waitStep)

        reader.add_step(reader.waitStep)
        subscriber.add_step(subscriber.cancelSubscriptionStep)
        
        reader.add_step(reader.waitStep)
        subscriber.add_step(subscriber.waitTimeoutStep, 1)

        reader.add_step(reader.getOperationalData, "/ietf-interfaces:interfaces-state/interface[name='eth100']", [])
        subscriber.add_step(subscriber.waitStep)

        tm.add_tester(reader)
        tm.add_tester(subscriber)
        tm.run()

if __name__ == '__main__':
    unittest.main()
