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
import signal
import os
import errno
import subprocess
import TestModule
import sysrepo as sr
import unittest
from time import sleep

class SubscriptionTester(SysrepoTester):

    def subscribeStep(self):
        # wait for running data file to be copied

        try:
            os.mkfifo("pipe_subscription_test")
        except OSError as oe:
            if oe.errno != errno.EEXIST:
                raise

        self.process = subprocess.Popen(['python3','SubscriptionTestApp.py', format(os.getpid())])
        self.report_pid(self.process.pid)
        output = ""
        with open("pipe_subscription_test", "r") as fifo:
            output = fifo.readline()

        os.unlink("pipe_subscription_test")
        self.tc.assertEqual(str(output), "subscribed")

    def cancelSubscriptionStep(self):
        os.kill(self.process.pid, signal.SIGUSR1)
        self.process.wait()

    def killStep(self):
        os.kill(self.process.pid, signal.SIGTERM)
        self.process.wait()

    def getOperationalData(self, xpath, expected):
        if(self.session):
            vals = self.session.get_items(xpath)
            if len(expected):
                self.tc.assertEqual(len(expected), vals.val_cnt())
                for i in range(len(expected)):
                    self.tc.assertEqual(vals.val(i).xpath(), expected[i])
            else:
                self.tc.assertFalse(vals)


class SubscriptionTest(unittest.TestCase):

    def remove_interfaces(self):
        TestModule.remove_ietf_interfaces_module()
        TestModule.remove_iana_if_type_module()
        TestModule.remove_ietf_ip_module()
    @classmethod
    def setUpClass(self):
        self.remove_interfaces(self)

    @classmethod
    def tearDownClass(self):
        self.remove_interfaces(self)

    @classmethod
    def setUp(self):
        if not TestModule.create_ietf_interfaces_module():
            self.remove_interfaces(self)
            self.skipTest(self,"Test environment is not clean!")
            print("Environment is not clean!")
            return
        if not TestModule.create_iana_if_type_module():
            self.remove_interfaces(self)
            self.skipTest(self,"Test environment is not clean!")
            print("Environment is not clean!")
            return
        if not TestModule.create_ietf_ip_module():
            self.remove_interfaces(self)
            self.skipTest(self,"Test environment is not clean!")
            print("Environment is not clean!")
            return
        if not TestModule.create_ietf_interfaces():
            self.remove_interfaces(self)
            self.skipTest(self,"Test environment is not clean!")
            print("Environment is not clean!")
            return

    @classmethod
    def tearDown(self):
        self.remove_interfaces(self)


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

        reader.add_step(reader.getOperationalData, "/ietf-interfaces:interfaces-state/interface[name='eth100']", [])
        subscriber.add_step(subscriber.waitStep)

        reader.add_step(reader.stopSession)
        subscriber.add_step(subscriber.stopSession)

        reader.add_step(reader.disconnect)
        subscriber.add_step(subscriber.disconnect)

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

        reader.add_step(reader.getOperationalData, "/ietf-interfaces:interfaces-state/interface[name='eth100']", [])
        subscriber.add_step(subscriber.waitStep)

        reader.add_step(reader.stopSession)
        subscriber.add_step(subscriber.stopSession)

        reader.add_step(reader.disconnect)
        subscriber.add_step(subscriber.disconnect)

        tm.add_tester(reader)
        tm.add_tester(subscriber)
        tm.run()

if __name__ == '__main__':
    unittest.main()
