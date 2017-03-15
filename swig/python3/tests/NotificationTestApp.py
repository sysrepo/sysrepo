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

# Helper function for printing changes given operation, old and new value.
def print_change(fd, op, old_val, new_val):

    def print_value(fd, value):
        if value is None or fd is None :
            raise Exception('print_value: value must not be none')
        fd.write(value.xpath()+'|')
        if (value.type() ==  sr.SR_CONTAINER_T) or (value.type() == sr.SR_CONTAINER_PRESENCE_T):
            fd.write("(container)")
        elif value.type() == sr.SR_LIST_T:
            fd.write("(list instance)")
        elif value.type() == sr.SR_STRING_T:
            fd.write(value.data().get_string())
        elif value.type() == sr.SR_BOOL_T:
            fd.write(str(value.data().get_bool()))
        elif value.type() == sr.SR_ENUM_T:
            fd.write(value.data().get_enum())
        elif value.type() == sr.SR_DECIMAL64_T:
            fd.write(str(value.data().get_decimal64()))
        elif value.type() == sr.SR_INT8_T:
            fd.write(str(value.data().get_int8()))
        elif value.type() == sr.SR_INT16_T:
            fd.write(str(value.data().get_int16()))
        elif value.type() == sr.SR_INT32_T:
            fd.write(str(value.data().get_int32()))
        elif value.type() == sr.SR_INT64_T:
            fd.write(str(value.data().get_int64()))
        elif value.type() == sr.SR_UINT8_T:
            fd.write(str(value.data().get_uint8()))
        elif value.type() == sr.SR_UINT16_T:
            fd.write(str(value.data().get_uint16()))
        elif value.type() == sr.SR_UINT32_T:
            fd.write(str(value.data().get_uint32()))
        elif value.type() == sr.SR_UINT64_T:
            fd.write(str(value.data().get_uint64()))
        elif value.type() == sr.SR_IDENTITYREF_T:
            fd.write(value.data().get_identityref())
        elif value.type() == sr.SR_BITS_T:
            fd.write(value.data().get_bits())
        # elif value.type() == sr.SR_BINARY_T:
        #     fd.write(value.data().get_binary())
        else:
            fd.write("(unprintable)")

    if (op == sr.SR_OP_CREATED):
           fd.write('CREATED|')
           print_value(fd, new_val)
    elif (op == sr.SR_OP_MODIFIED):
           fd.write('MODIFIED|')
           nstr = new_val.to_string().replace(' = ', '|').replace(' ', '|').strip()
           ostr = old_val.to_string().replace(' = ', '|').replace(' ', '|').strip()
           vstr = ostr.rstrip()+'|'+nstr.lstrip()
           fd.write(vstr)
    elif (op == sr.SR_OP_DELETED):
           fd.write('DELETED|')
           print_value(fd, old_val)
    elif (op == sr.SR_OP_MOVED):
           vstr = new_val.xpath().strip() + "|" + old_val.xpath().strip()
           fd.write("MOVED|"+vstr)
    fd.write('\n')

# Function to be called for subscribed client of given session whenever configuration changes.
def subtree_change_cb(sess, xpath, event, private_ctx):

    settings = private_ctx
    # Skip 'abort' event.
    if event == sr.SR_EV_ABORT:
        return sr.SR_ERR_OK

    if not 'xpath' in settings:
        print("private_ctx error", file=sys.stderr)
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
                print_change(out, change.oper(), change.old_val(), change.new_val())
            except Exception as e:
                print('next change failed', file=sys.stderr)
                break
    except Exception as e:
        print('get changes iter failed', file=sys.stderr)

    if out is not sys.stdout:
        out.close()

    return sr.SR_ERR_OK

# Notable difference between c implementation is using exception mechanism for open handling unexpected events.
# Here it is useful because `Conenction`, `Session` and `Subscribe` could throw an exception.
if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: %s path_to_subscribe [output_file]\n")
        sys.exit(1)

    settings = { 'xpath' : sys.argv[1], 'filename' : sys.argv[2] }

    print("Application will watch for changes under xpath " +  settings['xpath'] + "\n", flush=True)

    # connect to sysrepo
    conn = sr.Connection("notification_test_application")

    # start session
    sess = sr.Session(conn)

    # subscribe for changes in running config */
    subscribe = sr.Subscribe(sess)

    # Subscribe for changes in running config - try multiple times because in test
    # multiple client might try to subscribe to the same model
    for i in range(3):
        try:
            subscribe.subtree_change_subscribe(settings['xpath'], subtree_change_cb, settings)
            break
        except Exception as e:
            # Multiple clients might try to subscribe to the same model.
            print("Retrying to subscribe...", file=sys.stderr, flush=True)
            sleep(10.0/10e6)

    sr.global_loop()

    print("Application exit requested, exiting.", flush=True)
