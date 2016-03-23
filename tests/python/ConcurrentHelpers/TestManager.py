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

from multiprocessing import Process, Manager


class TestManager:
    """
    Class manages the testers and helps them to execute steps in synchronized order.
    Each tester is executed in a separeted process.
    """
    def __init__(self):
        self.manager = Manager()
        self.lock = self.manager.Lock()
        self.process_done = self.manager.Semaphore(0)
        self.queue = self.manager.Queue()
        self._setup()

    def _setup(self):
        self.testers = []
        self.next_steps = []
        self.proc_ids = []

    def add_tester(self, scenario):
        self.testers.append(scenario)

    def run(self):
        """Execute tester steps"""
        id = 0

        #create process for each tester
        for ts in self.testers:
            self.process_done.release()
            next_s = self.manager.Semaphore(0)

            p = Process(target=ts.run, args=(self.process_done, next_s, True, self.lock, id, self.queue))
            self.proc_ids.append(p)
            self.next_steps.append(next_s)
            p.start()
            id +=1

        step = 0
        will_continue = range(len(self.next_steps))
        wait_for = range(len(self.next_steps))
        while True:
            print("=================== TestManager step ", step, wait_for)
            for _ in wait_for:
                self.process_done.acquire()
                if step > 0:
                    proc, status = self.queue.get()
                    print ("Received ", proc, status)
                    if status == True:
                        will_continue.append(proc)
                    elif isinstance(status, RuntimeError):
                        for p in self.proc_ids:
                            p.terminate()
                        raise status

            if len(will_continue) == 0:
                break

            for id in will_continue:
                self.next_steps[id].release()

            wait_for = will_continue[:]
            will_continue = []
            step += 1

        #wait for all process to finish
        for p in self.proc_ids:
            p.join()

        self.lock.acquire()
        print("end")
        self.lock.release()