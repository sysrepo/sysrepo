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
import sysrepoPy as sr


class Sysrepo:

    def __init__(self, app_name, options = sr.SR_CONN_DEFAULT):
        self.connection = sr.sr_connect(app_name, options)

    def __del__(self):
        try:
            sr.sr_disconnect(self.connection)
        except AttributeError:
            pass

    @classmethod
    def log_stderr(self, level):
        sr.sr_log_stderr(level)

    @classmethod
    def log_syslog(self, level):
        sr.sr_log_syslog(level)
