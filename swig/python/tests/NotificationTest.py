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
# sysrepod and notifications_test_app must be in PATH

from ConcurrentHelpers import *
from random import randint
import signal
import os
import subprocess
import TestModule
import sysrepo as sr


class NotificationTester(SysrepoTester):

    def cleanup(self):
        if self.filename and os.path.isfile(self.filename):
            os.unlink(self.filename)

    def subscribeStep(self, xpath):
        self.filename = "notifications_test_" + str(randint(0, 9999))
        self.process = subprocess.Popen(['NotificationTestApp.py', xpath, self.filename])
        self.report_pid(self.process.pid)
        # wait for running data file to be copied
        time.sleep(0.1)

    def cancelSubscriptionStep(self):
        os.kill(self.process.pid, signal.SIGINT)
        self.process.wait()

    def checkNotificationStep(self, expected):
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

    def checkNoNotificationArrived(self):
        self.tc.assertFalse(os.path.isfile(self.filename))

    def deleteNotifications(self):
        if os.path.isfile(self.filename):
            os.unlink(self.filename)

class NotificationTest(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        TestModule.create_ietf_interfaces()
        TestModule.create_example_module()

    def test_notify_delete(self):
        tm = TestManager()

        srd = SysrepodDaemonTester("Srd")
        tester = SysrepoTester("Tester", sr.SR_DS_RUNNING, sr.SR_CONN_DAEMON_REQUIRED, False)
        subscriber = NotificationTester("Subscriber")
        subscriber2 = NotificationTester("Subscriber2")
        subscriber3 = NotificationTester("Subscriber3")

        srd.add_step(srd.startDaemonStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.restartConnection)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.subscribeStep, "/ietf-interfaces:interfaces")
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.subscribeStep, "/example-module:container")

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.subscribeStep, "/ietf-interfaces:interfaces/interface/ietf-ip:ipv4/address")
        subscriber3.add_step(subscriber3.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.deleteItemStep, "/ietf-interfaces:interfaces/interface[name='eth0']")
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.commitStep)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.waitTimeoutStep, 0.4)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        srd.add_step(srd.waitStep)
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

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.cancelSubscriptionStep)
        subscriber2.add_step(subscriber2.cancelSubscriptionStep)
        subscriber3.add_step(subscriber3.cancelSubscriptionStep)

        srd.add_step(srd.stopDaemonStep)

        tm.add_tester(srd)
        tm.add_tester(tester)
        tm.add_tester(subscriber)
        tm.add_tester(subscriber2)
        tm.add_tester(subscriber3)
        tm.run()


    def test_notify_modify(self):
        tm = TestManager()

        srd = SysrepodDaemonTester("Srd")
        tester = SysrepoTester("Tester", sr.SR_DS_RUNNING, sr.SR_CONN_DAEMON_REQUIRED, False)
        subscriber = NotificationTester("Subscriber")
        subscriber2 = NotificationTester("Subscriber2")
        subscriber3 = NotificationTester("Subscriber3")

        srd.add_step(srd.startDaemonStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.restartConnection)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.subscribeStep, "/ietf-interfaces:interfaces")
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.subscribeStep, "/example-module:container")

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.subscribeStep, "/ietf-interfaces:interfaces/interface/ietf-ip:ipv4")
        subscriber3.add_step(subscriber3.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.setItemStep, "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/enabled", sr.Val(False, sr.SR_BOOL_T))
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.commitStep)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.waitTimeoutStep, 0.4)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.checkNotificationStep,
        [["MODIFIED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/enabled"]])
        subscriber2.add_step(subscriber2.checkNotificationStep,
        [["MODIFIED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/enabled"]])
        subscriber3.add_step(subscriber3.checkNoNotificationArrived)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.cancelSubscriptionStep)
        subscriber2.add_step(subscriber2.cancelSubscriptionStep)
        subscriber3.add_step(subscriber3.cancelSubscriptionStep)

        srd.add_step(srd.stopDaemonStep)

        tm.add_tester(srd)
        tm.add_tester(tester)
        tm.add_tester(subscriber)
        tm.add_tester(subscriber2)
        tm.add_tester(subscriber3)
        tm.run()

    def test_notify_changes_in_multiple_modules(self):
        tm = TestManager()

        srd = SysrepodDaemonTester("Srd")
        tester = SysrepoTester("Tester", sr.SR_DS_RUNNING, sr.SR_CONN_DAEMON_REQUIRED, False)
        subscriber = NotificationTester("Subscriber")
        subscriber2 = NotificationTester("Subscriber2")
        subscriber3 = NotificationTester("Subscriber3")

        srd.add_step(srd.startDaemonStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.restartConnection)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.subscribeStep, "/ietf-interfaces:interfaces")
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.subscribeStep, "/example-module:container")

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.subscribeStep, "/ietf-interfaces:interfaces/interface/ietf-ip:ipv4/address")
        subscriber3.add_step(subscriber3.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.setItemStep, "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/enabled", sr.Val(False, sr.SR_BOOL_T))
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.setItemStep, "/example-module:container/list[key1='abc'][key2='def']/leaf", sr.Val("new value", sr.SR_STRING_T))
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.deleteItemStep, "/example-module:container/list[key1='key1'][key2='key2']/leaf")
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.commitStep)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitTimeoutStep, 0.4)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)

        srd.add_step(srd.waitStep)
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

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.cancelSubscriptionStep)
        subscriber2.add_step(subscriber2.cancelSubscriptionStep)
        subscriber3.add_step(subscriber3.cancelSubscriptionStep)

        srd.add_step(srd.stopDaemonStep)

        tm.add_tester(srd)
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

        srd = SysrepodDaemonTester("Srd")
        tester = SysrepoTester("Tester", sr.SR_DS_RUNNING, sr.SR_CONN_DAEMON_REQUIRED, False)
        subscriber = NotificationTester("Subscriber")
        subscriber2 = NotificationTester("Subscriber2")
        subscriber3 = NotificationTester("Subscriber3")
        subscriber4 = NotificationTester("Subscriber4")

        srd.add_step(srd.startDaemonStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)
        subscriber4.add_step(subscriber4.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.restartConnection)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)
        subscriber4.add_step(subscriber4.waitStep)

        #subscribe synchronously
        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.subscribeStep, "/ietf-interfaces:interfaces")
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)
        subscriber4.add_step(subscriber4.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.subscribeStep, "/ietf-interfaces:interfaces")
        subscriber3.add_step(subscriber3.waitStep)
        subscriber4.add_step(subscriber4.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.subscribeStep, "/ietf-interfaces:interfaces")
        subscriber4.add_step(subscriber4.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)
        subscriber4.add_step(subscriber4.subscribeStep, "/ietf-interfaces:interfaces")

        srd.add_step(srd.waitStep)
        tester.add_step(tester.deleteItemStep, "/ietf-interfaces:interfaces/interface[name='eth0']")
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)
        subscriber4.add_step(subscriber4.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.commitStep)
        subscriber.add_step(subscriber.waitStep)
        subscriber2.add_step(subscriber2.waitStep)
        subscriber3.add_step(subscriber3.waitStep)
        subscriber4.add_step(subscriber4.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitTimeoutStep, 0.4)
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

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.checkNotificationStep, expected_changes)
        subscriber2.add_step(subscriber2.checkNotificationStep, expected_changes)
        subscriber3.add_step(subscriber3.checkNotificationStep, expected_changes)
        subscriber4.add_step(subscriber4.checkNotificationStep, expected_changes)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.cancelSubscriptionStep)
        subscriber2.add_step(subscriber2.cancelSubscriptionStep)
        subscriber3.add_step(subscriber3.cancelSubscriptionStep)
        subscriber4.add_step(subscriber4.cancelSubscriptionStep)

        srd.add_step(srd.stopDaemonStep)

        tm.add_tester(srd)
        tm.add_tester(tester)
        tm.add_tester(subscriber)
        tm.add_tester(subscriber2)
        tm.add_tester(subscriber3)
        tm.add_tester(subscriber4)
        tm.run()

    def test_delete_default_node(self):
        TestModule.create_ietf_interfaces()
        tm = TestManager()

        srd = SysrepodDaemonTester("Srd")
        tester = SysrepoTester("Tester", sr.SR_DS_RUNNING, sr.SR_CONN_DAEMON_REQUIRED, False)
        subscriber = NotificationTester("Subscriber")

        srd.add_step(srd.startDaemonStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.restartConnection)
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.subscribeStep, "/ietf-interfaces:interfaces")

        #set to non default value
        srd.add_step(srd.waitStep)
        tester.add_step(tester.setItemStep, "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/forwarding", sr.Val(True, sr.SR_BOOL_T))
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.commitStep)
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.deleteItemStep, "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/forwarding")
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.commitStep)
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitTimeoutStep, 0.2)
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        #deleted value -> default according to the YANG
        subscriber.add_step(subscriber.checkNotificationStep, [["MODIFIED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/forwarding"]])

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.cancelSubscriptionStep)

        srd.add_step(srd.stopDaemonStep)

        tm.add_tester(srd)
        tm.add_tester(tester)
        tm.add_tester(subscriber)

        tm.run()

    def test_change_default_node(self):

        TestModule.create_ietf_interfaces()
        tm = TestManager()
        srd = SysrepodDaemonTester("Srd")
        tester = SysrepoTester("Tester", sr.SR_DS_RUNNING, sr.SR_CONN_DAEMON_REQUIRED, False)
        subscriber = NotificationTester("Subscriber")

        srd.add_step(srd.startDaemonStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.restartConnection)
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.subscribeStep, "/ietf-interfaces:interfaces")

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.setItemStep, "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/forwarding", sr.Val(True, sr.SR_BOOL_T))
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.commitStep)
        subscriber.add_step(subscriber.waitStep)

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitTimeoutStep, 0.4)
        subscriber.add_step(subscriber.waitStep)


        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        #setting a leaf with default value -> MODIFIED
        subscriber.add_step(subscriber.checkNotificationStep, [["MODIFIED", "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/forwarding"]])

        srd.add_step(srd.waitStep)
        tester.add_step(tester.waitStep)
        subscriber.add_step(subscriber.cancelSubscriptionStep)

        srd.add_step(srd.stopDaemonStep)

        tm.add_tester(srd)
        tm.add_tester(tester)
        tm.add_tester(subscriber)

        tm.run()


if __name__ == '__main__':
    unittest.main()
