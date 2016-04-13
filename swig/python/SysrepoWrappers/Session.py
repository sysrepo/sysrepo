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
from Value import Value
from Iter import Iter

class Session:

    def __init__(self, sysrepo, datastore, user_name=None, options = sr.SR_SESS_DEFAULT):
        if user_name is None:
            self.session = sr.sr_session_start(sysrepo.connection, datastore, options)
        else:
            self.session = sr.sr_session_start_user(sysrepo.connection, user_name, datastore, options)
        self.sr = sysrepo #store sr reference to be freed in valid order

    def __del__(self):
        sr.sr_session_stop(self.session)

    def get_last_error(self):
        return sr.sr_get_last_error(self.session)

    def get_last_errors(self):
        return sr.sr_get_last_errors(self.session)

    def list_schemas(self):
        return sr.sr_list_schemas(self.session)

    def get_schema(self, module_name, revision, submodule_name, schema_format):
        return sr.sr_get_schema(self.session, module_name, submodule_name, schema_format)

    def get_item(self, path):
        return Value(cobj=sr.sr_get_item(self.session, path))

    def get_items(self, path):
        return map(lambda v: Value(cobj=v),sr.sr_get_items(self.session, path))

    def get_items_iter(self, path):
        return Iter(self, sr.sr_get_items_iter(self.session, path))

    def get_item_next(self, iter):
        if isinstance(iter, Iter):
            return Value(cobj=sr.sr_get_item_next(self.session, iter.iter))
        else:
            return Value(cobj=sr.sr_get_item_next(self.session, iter))

    def set_item(self, path, value, options=sr.SR_EDIT_DEFAULT):
        if isinstance(value, Value):
            value = value._cObject
        sr.sr_set_item(self.session, path, value, options)

    def delete_item(self, path, options=sr.SR_EDIT_DEFAULT):
        sr.sr_delete_item(self.session, path, options)

    def move_item(self, path, direction):
        sr.sr_move_item(self.session, path, direction)

    def refresh(self):
        sr.sr_session_refresh(self.session)

    def validate(self):
        sr.sr_validate(self.session)

    def commit(self):
        sr.sr_commit(self.session)

    def lock_datastore(self):
        sr.sr_lock_datastore(self.session)

    def unlock_datastore(self):
        sr.sr_unlock_datastore(self.session)

    def lock_module(self, module_name):
        sr.sr_lock_module(self.session, module_name)

    def unlock_module(self, module_name):
        sr.sr_unlock_module(self.session, module_name)
