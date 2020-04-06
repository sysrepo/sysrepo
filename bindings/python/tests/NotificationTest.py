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
from random import randint
import signal
import os
import errno
import subprocess
import TestModule
import sysrepo as sr


class NotificationTester(SysrepoTester):

    def cleanup(self):
        if self.filename and os.path.isfile(self.filename):
            os.unlink(self.filename)

    def subscribeStep(self, module_name, xpath):
        self.filename = "notifications_test_" + str(randint(0, 9999))
        try:
            os.mkfifo("pipe_"+self.filename)
        except OSError as oe:
            if oe.errno != errno.EEXIST:
                raise

        self.process = subprocess.Popen(
            ['python3','NotificationTestApp.py', module_name, xpath, self.filename])
        self.report_pid(self.process.pid)
        # wait for running data file to be copied
        output = ""
        with open("pipe_"+self.filename, "r") as fifo:
            output = fifo.readline()

        os.unlink("pipe_"+self.filename)
        self.tc.assertEqual(str(output), "subscribed")

    def cancelSubscriptionStep(self):
        os.kill(self.process.pid, signal.SIGINT)
        self.process.wait()

    def checkNotificationStep(self, expected):
        try:
            with open(self.filename, "r") as f:
                self.notifications = []
                for line in f:
                    self.notifications.append(line.split("|"))

            self.tc.assertEqual(len(expected), len(self.notifications))

            ex_sorted = sorted(expected, key=lambda e: e[1])
            notif_sorted = sorted(self.notifications, key=lambda e: e[1])
            for i in range(len(expected)):
                self.tc.assertEqual(ex_sorted[i][0], notif_sorted[i][0])
                self.tc.assertEqual(ex_sorted[i][1], notif_sorted[i][1])
        except Exception as e:
            print(e)

    def checkNoNotificationArrived(self):
        self.tc.assertFalse(os.path.isfile(self.filename))

    def deleteNotifications(self):
        if os.path.isfile(self.filename):
            os.unlink(self.filename)


class NotificationTest(unittest.TestCase):


    def remove_interfaces(self):
        TestModule.remove_ietf_interfaces_module()
        TestModule.remove_iana_if_type_module()
        TestModule.remove_ietf_ip_module()
        TestModule.remove_example_module()
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
        if not TestModule.create_example_module():
            self.remove_interfaces(self)
            self.skipTest(self,"Test environment is not clean!")
            print("Environment is not clean!")
            return

    @classmethod
    def tearDown(self):
        self.remove_interfaces(self)

    def test_notify_delete(self):
        tm = TestManager()

        tester = SysrepoTester("Tester", sr.SR_DS_RUNNING)
        subscriber = NotificationTester("Subscriber")
        subscriber2 = NotificationTester("Subscriber2")
        subscriber3 = NotificationTester("Subscriber3")

        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.subscribeStep,
                            "ietf-interfaces", "/ietf-interfaces:interfaces")
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.subscribeStep,
                             "example-module", "/example-module:container")

        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.subscribeStep,
                             "ietf-interfaces", "/ietf-interfaces:interfaces/interface/ietf-ip:ipv4/address")
        subscriber3.add_step(subscriber3.waitStep)

        tester.add_step(tester.deleteItemStep, "/ietf-interfaces:interfaces/interface[name='eth0']")
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        tester.add_step(tester.commitStep)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.checkNotificationStep,
                            [["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']"],
                             ["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']/name"],
                                ["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']/type"],
                                ["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']/enabled"],
                                ["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']/description"],
                                ["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4"],
                                ["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/address[ip='192.168.2.100']"],
                                ["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/address[ip='192.168.2.100']/ip"],
                                ["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/address[ip='192.168.2.100']/prefix-length"],
                                ["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/mtu"],
                                ["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/enabled"],
                                ["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/forwarding"]])
        subscriber2.add_step(subscriber2.checkNotificationStep,
                              [["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/address[ip='192.168.2.100']"],
                               ["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/address[ip='192.168.2.100']/ip"],
                                  ["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/address[ip='192.168.2.100']/prefix-length"],
                               ])
        subscriber3.add_step(subscriber3.checkNoNotificationArrived)

        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.cancelSubscriptionStep)
        subscriber2.add_step(subscriber2.cancelSubscriptionStep)
        subscriber3.add_step(subscriber3.cancelSubscriptionStep)

        tester.add_step(tester.stopSession)
        subscriber.add_step(subscriber.stopSession)
        subscriber2.add_step(subscriber2.stopSession)
        subscriber3.add_step(subscriber3.stopSession)

        tester.add_step(tester.disconnect)
        subscriber.add_step(subscriber.disconnect)
        subscriber2.add_step(subscriber2.disconnect)
        subscriber3.add_step(subscriber3.disconnect)

        tm.add_tester(tester)
        tm.add_tester(subscriber)
        tm.add_tester(subscriber2)
        tm.add_tester(subscriber3)
        tm.run()

    def test_notify_modify(self):
        tm = TestManager()

        tester = SysrepoTester("Tester", sr.SR_DS_RUNNING, False)
        subscriber = NotificationTester("Subscriber")
        subscriber2 = NotificationTester("Subscriber2")
        subscriber3 = NotificationTester("Subscriber3")

        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.subscribeStep, "ietf-interfaces",
                            "/ietf-interfaces:interfaces")
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.subscribeStep, "example-module",
                             "/example-module:container")

        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.subscribeStep, "ietf-interfaces",
                             "/ietf-interfaces:interfaces/interface/ietf-ip:ipv4")
        subscriber3.add_step(subscriber3.waitStep)

        tester.add_step(
            tester.setItemStep, "/ietf-interfaces:interfaces/interface[name='eth0']/type", sr.Val("iana-if-type:ethernetCsmacd", sr.SR_IDENTITYREF_T))
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        tester.add_step(
            tester.setItemStep, "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/enabled", sr.Val(False, sr.SR_BOOL_T))
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        tester.add_step(tester.commitStep)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.checkNotificationStep,
                            [["MODIFIED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/enabled"]])
        subscriber2.add_step(subscriber2.checkNotificationStep,
                             [["MODIFIED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/enabled"]])
        subscriber3.add_step(subscriber3.checkNoNotificationArrived)

        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.cancelSubscriptionStep)
        subscriber2.add_step(subscriber2.cancelSubscriptionStep)
        subscriber3.add_step(subscriber3.cancelSubscriptionStep)

        tester.add_step(tester.stopSession)
        subscriber.add_step(subscriber.stopSession)
        subscriber2.add_step(subscriber2.stopSession)
        subscriber3.add_step(subscriber3.stopSession)

        tester.add_step(tester.disconnect)
        subscriber.add_step(subscriber.disconnect)
        subscriber2.add_step(subscriber2.disconnect)
        subscriber3.add_step(subscriber3.disconnect)

        tm.add_tester(tester)
        tm.add_tester(subscriber)
        tm.add_tester(subscriber2)
        tm.add_tester(subscriber3)
        tm.run()

    def test_notify_changes_in_multiple_modules(self):
        tm = TestManager()

        tester = SysrepoTester("Tester", sr.SR_DS_RUNNING, False)
        subscriber = NotificationTester("Subscriber")
        subscriber2 = NotificationTester("Subscriber2")
        subscriber3 = NotificationTester("Subscriber3")

        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.subscribeStep, "ietf-interfaces",
                            "/ietf-interfaces:interfaces")
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.subscribeStep, "example-module",
                             "/example-module:container")

        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.subscribeStep, "ietf-interfaces",
                             "/ietf-interfaces:interfaces/interface/ietf-ip:ipv4/address")
        subscriber3.add_step(subscriber3.waitStep)

        tester.add_step(
            tester.setItemStep, "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/enabled", sr.Val(False, sr.SR_BOOL_T))
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        tester.add_step(
            tester.setItemStep, "/example-module:container/list[key1='abc'][key2='def']/leaf", sr.Val("new value", sr.SR_STRING_T))
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        tester.add_step(tester.commitStep)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        tester.add_step(tester.deleteItemStep,
                        "/example-module:container/list[key1='key1'][key2='key2']/leaf")
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        tester.add_step(tester.commitStep)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.checkNotificationStep,
                            [["MODIFIED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/enabled"]])
        subscriber2.add_step(subscriber2.checkNoNotificationArrived)
        subscriber3.add_step(subscriber3.checkNotificationStep, [
            ["DELETED", "/example-module:container/list[key1='key1'][key2='key2']/leaf"],
            ["CREATED", "/example-module:container/list[key1='abc'][key2='def']"],
            ["CREATED", "/example-module:container/list[key1='abc'][key2='def']/key1"],
            ["CREATED", "/example-module:container/list[key1='abc'][key2='def']/key2"],
            ["CREATED", "/example-module:container/list[key1='abc'][key2='def']/leaf"]
        ])

        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.cancelSubscriptionStep)
        subscriber2.add_step(subscriber2.cancelSubscriptionStep)
        subscriber3.add_step(subscriber3.cancelSubscriptionStep)

        tester.add_step(tester.stopSession)
        subscriber.add_step(subscriber.stopSession)
        subscriber2.add_step(subscriber2.stopSession)
        subscriber3.add_step(subscriber3.stopSession)

        tester.add_step(tester.disconnect)
        subscriber.add_step(subscriber.disconnect)
        subscriber2.add_step(subscriber2.disconnect)
        subscriber3.add_step(subscriber3.disconnect)

        tm.add_tester(tester)
        tm.add_tester(subscriber)
        tm.add_tester(subscriber2)
        tm.add_tester(subscriber3)
        tm.run()

    def test_notify_same_path(self):
        """
        Four testers are subscribed for the same notifications. The changes
        are generated when the request from the first of them arrives.
        """
        tm = TestManager()

        tester = SysrepoTester("Tester", sr.SR_DS_RUNNING, False)
        subscriber = NotificationTester("Subscriber")
        subscriber2 = NotificationTester("Subscriber2")
        subscriber3 = NotificationTester("Subscriber3")
        subscriber4 = NotificationTester("Subscriber4")

        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.subscribeStep, "ietf-interfaces",
                            "/ietf-interfaces:interfaces")
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)
        subscriber4.add_step(subscriber4.waitStep)

        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.subscribeStep, "ietf-interfaces",
                             "/ietf-interfaces:interfaces")
        subscriber3.add_step(subscriber3.waitStep)
        subscriber4.add_step(subscriber4.waitStep)

        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.subscribeStep, "ietf-interfaces",
                             "/ietf-interfaces:interfaces")
        subscriber4.add_step(subscriber4.waitStep)

        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)
        subscriber4.add_step(subscriber4.subscribeStep, "ietf-interfaces",
                             "/ietf-interfaces:interfaces")

        tester.add_step(tester.deleteItemStep,
                        "/ietf-interfaces:interfaces/interface[name='eth0']")
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)
        subscriber4.add_step(subscriber4.waitStep)

        tester.add_step(tester.commitStep)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)
        subscriber4.add_step(subscriber4.waitStep)

        expected_changes = [["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']"],
                            ["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']/name"],
                            ["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']/type"],
                            ["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']/description"],
                            ["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']/enabled"],
                            ["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4"],
                            ["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/address[ip='192.168.2.100']"],
                            ["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/address[ip='192.168.2.100']/ip"],
                            ["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/address[ip='192.168.2.100']/prefix-length"],
                            ["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/enabled"],
                            ["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/mtu"],
                            ["DELETED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/forwarding"]]

        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.checkNotificationStep, expected_changes)
        subscriber2.add_step(
            subscriber2.checkNotificationStep, expected_changes)
        subscriber3.add_step(
            subscriber3.checkNotificationStep, expected_changes)
        subscriber4.add_step(
            subscriber4.checkNotificationStep, expected_changes)

        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.cancelSubscriptionStep)
        subscriber2.add_step(subscriber2.cancelSubscriptionStep)
        subscriber3.add_step(subscriber3.cancelSubscriptionStep)
        subscriber4.add_step(subscriber4.cancelSubscriptionStep)

        tester.add_step(tester.stopSession)
        subscriber.add_step(subscriber.stopSession)
        subscriber2.add_step(subscriber2.stopSession)
        subscriber3.add_step(subscriber3.stopSession)
        subscriber4.add_step(subscriber4.stopSession)

        tester.add_step(tester.disconnect)
        subscriber.add_step(subscriber.disconnect)
        subscriber2.add_step(subscriber2.disconnect)
        subscriber3.add_step(subscriber3.disconnect)
        subscriber4.add_step(subscriber4.disconnect)

        tm.add_tester(tester)
        tm.add_tester(subscriber)
        tm.add_tester(subscriber2)
        tm.add_tester(subscriber3)
        tm.add_tester(subscriber4)
        tm.run()

    def test_delete_default_node(self):
        tm = TestManager()

        tester = SysrepoTester("Tester", sr.SR_DS_RUNNING, False)
        subscriber = NotificationTester("Subscriber")

        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.subscribeStep, "ietf-interfaces",
                            "/ietf-interfaces:interfaces")

        tester.add_step(
            tester.setItemStep, "/ietf-interfaces:interfaces/interface[name='eth0']/type", sr.Val("iana-if-type:ethernetCsmacd", sr.SR_IDENTITYREF_T))
        subscriber.add_step(subscriber.waitStep)

        tester.add_step(
            tester.setItemStep, "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/enabled", sr.Val(False, sr.SR_BOOL_T))
        subscriber.add_step(subscriber.waitStep)

        tester.add_step(tester.commitStep)
        subscriber.add_step(subscriber.waitStep)

        tester.add_step(tester.deleteItemStep,
                        "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/enabled")
        subscriber.add_step(subscriber.waitStep)

        tester.add_step(tester.commitStep)
        subscriber.add_step(subscriber.waitStep)

        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.checkNotificationStep, [
                            ["MODIFIED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/forwarding"]])

        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.cancelSubscriptionStep)


        tester.add_step(tester.stopSession)
        subscriber.add_step(subscriber.stopSession)

        tester.add_step(tester.disconnect)
        subscriber.add_step(subscriber.disconnect)

        tm.add_tester(tester)
        tm.add_tester(subscriber)

        tm.run()

    def test_change_default_node(self):
        tm = TestManager()

        tester = SysrepoTester("Tester", sr.SR_DS_RUNNING, False)
        subscriber = NotificationTester("Subscriber")

        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.subscribeStep, "ietf-interfaces",
                            "/ietf-interfaces:interfaces")

        tester.add_step(
            tester.setItemStep, "/ietf-interfaces:interfaces/interface[name='eth0']/type", sr.Val("iana-if-type:ethernetCsmacd", sr.SR_IDENTITYREF_T))
        subscriber.add_step(subscriber.waitStep)

        tester.add_step(
            tester.setItemStep, "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/forwarding", sr.Val(True, sr.SR_BOOL_T))
        subscriber.add_step(subscriber.waitStep)

        tester.add_step(tester.commitStep)
        subscriber.add_step(subscriber.waitStep)

        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.checkNotificationStep, [
                            ["MODIFIED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/forwarding"]])

        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.cancelSubscriptionStep)


        tester.add_step(tester.stopSession)
        subscriber.add_step(subscriber.stopSession)

        tester.add_step(tester.disconnect)
        subscriber.add_step(subscriber.disconnect)

        tm.add_tester(tester)
        tm.add_tester(subscriber)

        tm.run()


if __name__ == '__main__':
    unittest.main()
