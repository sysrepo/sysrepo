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
import sysrepoPy as sr


class Iter(object):
    def __init__(self, session, iter):
        self.session = session
        self.iter = iter
        self.value = None

    def __del__(self):
        sr.sr_free_val_iter(self.iter)

    def hasNext(self):
        if self.value is not None:
            return True
        else:
            try:
                self.value = self.session.get_item_next(self.iter)
            except RuntimeError as e:
                if e.message == "Item not found":
                    return False
                else:
                    raise e
            return True

    def getNext(self):
        if self.value is not None:
            v = self.value
            self.value = None
            return v
        else:
            return self.session.get_item_next(self.iter)

