#!/usr/bin/env python3

__author__ = "Antonio Paunovic <antonio.paunovic@sartura.hr>"
__copyright__ = "Copyright 2017, Deutsche Telekom AG"
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

import libsysrepoPython3 as sr
import sys
import signal
from os import getpid
from time import sleep

usr_interrupt = False

# Function to be called for subscribed client of given session whenever configuration changes.
def module_change_cb(sess, module_name, event, private_ctx):
    print("\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG: ==========\n")
    return sr.SR_ERR_OK

def sig_handler(signum, stack):
    sys.exit(0)

if __name__ == "__main__":
    module_name = "ietf-interfaces"
    # signal handling
    signal.signal(signal.SIGUSR1, sig_handler)
    signal.signal(signal.SIGUSR2, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)


    # connect to sysrepo
    conn = sr.Connection("example_application")
    if conn is None:
        print('Error while connecting', flush=True)

    # start session
    sess = sr.Session(conn)
    if sess is None:
        print('Error while sessioning', flush=True)

    # subscribe for changes in running config */
    subscribe = sr.Subscribe(sess)
    if subscribe is None:
        print('Error while subscribing', flush=True)

    subscribe.module_change_subscribe(module_name, module_change_cb, None, 0, sr.SR_SUBSCR_DEFAULT)

    while True:
        sleep(10.0/10e2)

    print('Signal received', flush=True)
