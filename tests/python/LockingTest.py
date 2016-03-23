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
from SysrepoWrappers import *

class User1(Tester):
    def __init__(self):
        super(User1, self).__init__()

    def setup(self):
        self.sr = Sysrepo("User1", SR_CONN_DEFAULT)
        self.session = Session(self.sr, SR_DS_STARTUP)

        self.add_step(self.lockStep)
        self.add_step(self.waitStep)
        self.add_step(self.unlockStep)


    def lockStep(self):
        self.session.lock_datastore()

    def unlockStep(self):
        self.session.unlock_datastore()
        print("Unlocking")

class User2(Tester):
    def __init__(self):
        super(User2, self).__init__()

    def setup(self):
        self.sr = Sysrepo("User2", SR_CONN_DEFAULT)
        self.session = Session(self.sr, SR_DS_STARTUP)
        self.sr.log_stderr(SR_LL_INF)

        self.add_step(self.waitStep)
        self.add_step(self.lockFailStep)
        self.add_step(self.waitStep)
        self.add_step(self.lockStep)
        self.add_step(self.unlockStep)

    def sleepStep(self):
        time.sleep(5)

    def lockStep(self):
        self.session.lock_datastore()

    def lockFailStep(self):
        with self.assertRaises(RuntimeError):
            self.session.lock_datastore()

    def unlockStep(self):
        self.session.unlock_datastore()

class LockUser(Tester):
    def __init__(self, name="LockUser"):
        super(LockUser, self).__init__()
        self.name = name

    def setup(self):
        self.sr = Sysrepo(self.name, SR_CONN_DEFAULT)
        self.session = Session(self.sr, SR_DS_STARTUP)
        self.sr.log_stderr(SR_LL_INF)

    def lockStep(self):
        self.session.lock_datastore()

    def lockFailStep(self):
        with self.assertRaises(RuntimeError):
            self.session.lock_datastore()

    def unlockStep(self):
        self.session.unlock_datastore()

class LockingTest(unittest.TestCase):

    def test_abc(self):
        self.assertTrue(True)

    #@unittest.skip(False)
    def test_ConcurrentLocking(self):
        tm = TestManager()

        first = LockUser("First")
        first.add_step(first.lockStep)
        first.add_step(first.waitStep)
        first.add_step(first.unlockStep)
        tm.add_tester(first)

        #tm.add_tester(User1())
        tm.add_tester(User2())
        tm.run()

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(LockingTest)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.wasSuccessful():
        sys.exit(0)
    else:
        sys.exit(1)

