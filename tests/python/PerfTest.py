#!/usr/bin/env python
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
import unittest
import time
import TestModule
from SysrepoWrappers import *

class PerfTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        sr = Sysrepo("perf_test")
        session = Session(sr, SR_DS_STARTUP)
        session.delete_item("/example-module:*")
        for i in range(0, 8000):
            v = Value(None, SR_STRING_T, "abcd")
            session.set_item("/example-module:container/list[key1='a{0}'][key2='b{0}']/leaf".format(i), v)
        session.commit()

    @classmethod
    def tearDownClass(cls):
        TestModule.create_example_module()


    def setUp(self):
        sr = Sysrepo("perf_test")
        self.session = Session(sr, SR_DS_STARTUP)
        self.session.get_item("/example-module:*")
        self.beginTime = time.time()

    def tearDown(self):
        t = time.time() - self.beginTime
        print "%s: %.3f" % (self.id(), t)

    def test_getItems(self):
        sr = Sysrepo("perf_test")
        self.session = Session(sr, SR_DS_STARTUP)
        try:
            vals = self.session.get_items("/example-module:container/list")
        except RuntimeError as e:
            self.assertEquals("Time out has expired", e.message)

    def test_iter(self):
        iter = self.session.get_items_iter("/example-module:container/list")
        while iter.hasNext():
            item = iter.getNext()


if __name__ == '__main__':
    unittest.main()
