#!/usr/bin/env python
from __future__ import print_function

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
import traceback
import sys


class Tester(object):
    """
    Class instance simulates the steps executed by tester.

    A step can be added by add_step function. Steps are executed in synchronized order
    with other testers.

    Attributes:
        steps (list) - list of steps to be executed
        _current_step(int) - index of the step to be executed

    """
    def __init__(self, name=None):
        self.name = name
        self.tc = unittest.TestCase('__init__')
        self.steps = []

    def setup(self):
        """Method executed before steps"""
        pass

    def cleanup(self):
        """Method executed after steps"""
        pass

    def add_step(self, step, *args):
        """Adds the step to the end of the list"""
        self.steps.append((step, args))

    def has_next(self):
        """Checks whether there is a step to be executed"""
        return self._current_step < (len(self.steps))

    def report_pid(self, pid):
        """Insert pid into notification queue"""
        if self.sub_proc is not None:
            self.sub_proc.put(pid)

    def print_with_lock(self, *args):
        """Print to stdout with acquired lock"""
        if self.lock is not None:
            self.lock.acquire()
            print(args)
            self.lock.release()
        else:
            print(args)

    def execute_step(self, index):
        step, args = self.steps[index]
        if len(args) != 0:
            step(*args)
        else:
            step()

    def run_sync(self, done, next_step, rand_sleep, id, queue):
        """run steps in sync with other tester and inform test manager"""
        if self.name is None:
            self.name = id
        #empty steps check
        if len(self.steps) == 0:
            next_step.acquire()
            queue.put((id, self.name, False))
            done.release()

        for step in range(len(self.steps)):
            err = None
            next_step.acquire()
            if rand_sleep:
                time.sleep(randint(1,1000)*0.00001)
            #self.print_with_lock('Step: ', step, ", pid: ", os.getpid())

            try:
                self.execute_step(step)
            except Exception as e:
                _, _, tb = sys.exc_info()
                traceback.print_tb(tb) # Print traceback
                print("\n\n", file=sys.stderr)
                err = e
            finally:
                self._current_step += 1
                #report to test manager if there is any step left
                if err is not None:
                    queue.put((id, self.name, err))
                elif self.has_next():
                    queue.put((id, self.name, True))
                else:
                    queue.put((id, self.name, False))
                done.release()

    def run_without_sync(self):
        """run steps independently"""
        for step in range(len(self.steps)):
            self.execute_step(step)

    def run(self, done=None, next_step=None, rand_sleep=False, lock=None, sub_proc=None, pids=None, id=-1, queue=None):
        """Executes the tester steps

            Arguments:
                done        (Semaphore) - to be acquired before step execution
                next_step   (Semaphore) - to be released on step completion
                rand_sleep  (bool)      - flag whether sleep before each step
                lock        (Lock)      - stdout synchronization
                sub_proc    (Queue)     - queue to report pids of created process in tester to be terminated by testmanager
                pids        (Array)     - pids of other testers
                id          (int)       - identification used for queue messages index of the tester pid in pids
                queue       (Queue)     - message for notification whether there is a step to be executed
        """
        self.setup()
        self.lock = lock
        self._current_step = 0
        self.pids = pids
        self.sub_proc = sub_proc

        if done is not None and next_step is not None and queue is not None:
            self.run_sync(done, next_step, rand_sleep, id, queue)
        else:
            self.run_without_sync()

        self.cleanup()

    def waitStep(self):
        """Step that can be used by tester, to do nothing"""
        pass

    def runTest(self):
        """This needs to be here to make unit test happy"""
        pass
