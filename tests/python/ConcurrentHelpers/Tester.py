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

from random import randint
import os, time
import unittest


class Tester(unittest.TestCase):
    """
    Class instance simulates the steps executed by tester.

    A step can be added by add_step function. Steps are executed in synchronized order
    with other testers.

    Attributes:
        steps (list) - list of steps to be executed
        _current_step(int) - index of the step to be executed

    """
    def __init__(self):
        super(Tester, self).__init__()
        self._current_step = 0
        self.steps = []

    def setup(self):
        """Method executed before steps"""
        pass

    def add_step(self, step):
        """Adds the step to the end of the list"""
        self.steps.append(step)

    def has_next(self):
        """Checks whether there is a step to be executed"""
        return self._current_step < (len(self.steps))

    def run(self, done = None, next_step= None, rand_sleep=False, lock=None, id=-1, queue = None):
        """Executes the tester steps

            Arguments:
                done        (Semaphore) - to be acquired before step execution
                next_step   (Semaphore) - to be released on step completion
                rand_sleep  (bool)      - flag whether sleep before each step
                id          (int)       - identification used for queue message
                queue       (Queue)     - message for notification whether there is a step to be executed
        """
        self.setup()
        for step in range(len(self.steps)):
            err = None
            next_step.acquire()
            if rand_sleep:
                time.sleep(randint(1,1000)*0.00001)
            print 'Step: ', step, ", pid: ", os.getpid()

            try:
                #step execution
                self.steps[step]()
            except Exception as e:
                err = e
            finally:
                self._current_step += 1
                #report to test manager if there is any step left
                if err is not None:
                    queue.put((id, err))
                elif self.has_next():
                    queue.put((id, True))
                else:
                    queue.put((id, False))
                done.release()


    def waitStep(self):
        """Step that can be used by tester, to do nothing"""
        pass

    def runTest(self):
        """This needs to be here to make unit test happy"""
        pass