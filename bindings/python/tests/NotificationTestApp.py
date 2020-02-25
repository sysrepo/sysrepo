#!/usr/bin/env python
from __future__ import print_function

__author__ = "Antonio Paunovic <antonio.paunovic@sartura.hr>"
__copyright__ = "Copyright 2018, Deutsche Telekom AG"
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

import sysrepo as sr
import sys
import os
from time import sleep
from datetime import datetime

# def print_val(val, fd=sys.stdout):
#     print(val+'|', file=fd, end='')

# Helper function for printing changes given operation, old and new value.
def print_change(fd, op, old_val, new_val):
    if (op == sr.SR_OP_CREATED):
           print("CREATED|", file=fd, end='')
           print("CREATED|", file=sys.stderr, end='')
           print(new_val.to_string().replace(' = ', '|').replace(' ', '|'), file=fd, end='')
    elif (op == sr.SR_OP_DELETED):
           print("DELETED|", file=fd, end='')
           vstr = old_val.to_string().replace(' = ', '|').replace(' ', '|')
           print(vstr, file=fd, end='')
    elif (op == sr.SR_OP_MODIFIED):
           print("MODIFIED|", file=sys.stderr, end='')
           print("MODIFIED|", file=fd, end='')

           vstr=old_val.to_string().replace(' = ', '|').replace(' ', '|')+'|'+new_val.to_string().replace(' = ', '|').replace(' ', '|')
           vstr = vstr.replace('\n', '')
           print(vstr, file=fd, end='')
    elif (op == sr.SR_OP_MOVED):
            print('MOVE', file=sys.stderr, end='')
            print("MOVED|" + new_val.xpath() + "|" + old_val.xpath(), file=fd, end='')


# Function to be called for subscribed client of given session whenever configuration changes.
def module_change_cb(sess, module_name, xpath, event, request_id, private_data):

    settings = private_data
    if not 'module_name' in settings:
        print >> sys.stderr, "private_data error", private_data
        return sr.SR_ERR_INTERNAL
    if not 'xpath' in settings:
        print >> sys.stderr, "private_data error", private_data
        return sr.SR_ERR_INTERNAL


    out = open(settings['filename'], 'w') if 'filename' in settings else sys.stdout

    if out is None:
        print('File', settings['filename'], 'could not be opened')
        return sr.SR_ERR_INTERNAL

    change_path = "/" + module_name + ":*//."
    try:
        it = sess.get_changes_iter(change_path);
        if it is None:
            print("Get changes iter failed for path", change_path, file=sys.stderr)
            return sr.SR_ERR_OK

        while True:
            try:
                change = sess.get_change_next(it)
                if change == None:
                    break
            except Exception as e:
                break
            print_change(out, change.oper(), change.old_val(), change.new_val())

    except Exception as e:
        pass

    out.close()

    return sr.SR_ERR_OK

if __name__ == "__main__":

    if len(sys.argv) < 3:
        print("Usage: %s module_name xpath [output_file]\n\n")
        sys.exit(1)

    settings = { 'module_name' : sys.argv[1], 'xpath' : sys.argv[2], 'filename' : sys.argv[3] }
    # connect to sysrepo
    conn = sr.Connection(sr.SR_CONN_DEFAULT)

    # start session
    sess = sr.Session(conn)

    # subscribe for changes in running config */
    subscribe = sr.Subscribe(sess)

    # Subscribe for changes in running config - try multiple times because in test
    # multiple client might try to subscribe to the same model
    for i in range(3):
        try:
            subscribe.module_change_subscribe(settings['module_name'], module_change_cb, settings['xpath'], settings, 0, sr.SR_SUBSCR_DONE_ONLY)
        except Exception as e:
            # Multiple clients might try to subscribe to the same model.
            sleep(10.0/10e6)
            continue
        break
    with open("pipe_"+settings['filename'], "w") as fifo:
        fifo.write("subscribed")
    sr.global_loop()
    subscribe.unsubscribe()

    sess.session_stop()
    
    conn = None

    print("Application exit requested, exiting.")
