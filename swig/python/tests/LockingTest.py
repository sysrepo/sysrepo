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
import sysrepo as sr


class User2(SysrepoTester):
    def __init__(self, name):
        super(User2, self).__init__()

    def setup(self):
        super(User2, self).setup()

        self.add_step(self.waitStep)
        self.add_step(self.lockFailStep)
        self.add_step(self.waitStep)
        self.add_step(self.lockStep)
        self.add_step(self.unlockStep)


class LockingTest(unittest.TestCase):

    def test_ConcurrentDataStoreLocking(self):
        tm = TestManager()

        first = SysrepoTester("First")
        first.add_step(first.lockStep)
        first.add_step(first.waitStep)
        first.add_step(first.unlockStep)
        tm.add_tester(first)

        tm.add_tester(User2("Second"))
        tm.run()

    def test_ConcurrentModelLocking(self):
        tm = TestManager()

        first = SysrepoTester("First")
        second = SysrepoTester("Second")

        first.add_step(first.lockModelStep, "example-module")
        second.add_step(second.waitStep)

        first.add_step(first.waitStep)
        second.add_step(second.lockFailModelStep, "example-module")

        first.add_step(first.unlockModelStep, "example-module")
        second.add_step(second.waitStep)

        second.add_step(second.lockModelStep, "example-module")
        second.add_step(second.unlockModelStep, "example-module")

        tm.add_tester(first)
        tm.add_tester(second)
        tm.run()

if __name__ == '__main__':
    unittest.main()

