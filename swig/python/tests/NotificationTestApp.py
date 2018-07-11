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
def subtree_change_cb(sess, xpath, event, private_ctx):

    settings = private_ctx

    if not 'xpath' in settings:
        print >> sys.stderr, "private_ctx error", private_ctx
        return sr.SR_ERR_INTERNAL

    out = open(settings['filename'], 'w') if 'filename' in settings else sys.stdout

    if out is None:
        print('File', settings['filename'], 'could not be opened')
        return sr.SR_ERR_INTERNAL

    try:
        it = sess.get_changes_iter(xpath);
        if it is None:
            print("Get changes iter failed for xpath", xpath, file=sys.stderr)
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

# Notable difference between c implementation is using exception mechanism for open handling unexpected events.
# Here it is useful because `Conenction`, `Session` and `Subscribe` could throw an exception.
if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: %s path_to_subscribe [output_file]\n\n")
        sys.exit(1)

    settings = { 'xpath' : sys.argv[1], 'filename' : sys.argv[2] }

    print("Application will watch for changes under xpath " +  settings['xpath'] + "\n")

    # connect to sysrepo
    conn = sr.Connection("notification_test_application")

    # start session
    sess = sr.Session(conn)

    # subscribe for changes in running config */
    subscribe = sr.Subscribe(sess)

    # Subscribe for changes in running config - try multiple times because in test
    # multiple client might try to subscribe to the same model
    for i in xrange(3):
        try:
            subscribe.subtree_change_subscribe(settings['xpath'], subtree_change_cb, settings)
        except Exception as e:
            # Multiple clients might try to subscribe to the same model.
            print >> sys.stderr, "Retrying to subscribe..."
            sleep(10.0/10e6)
            continue
        break;

    sr.global_loop()

    print("Application exit requested, exiting.")
