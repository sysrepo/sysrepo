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


class Value(object):

    def __init__(self, xpath = None, leaf_type = None, value = None, cobj = None):
        if cobj is not None:
            if isinstance(cobj, sr.sr_val_t):
                self._cObject = cobj
                return
        self._cObject = sr.sr_val_t()
        if xpath is not None:
            self.xpath = xpath
        if leaf_type is not None:
            self.value = (leaf_type, value)

    @property
    def xpath(self):
        return self._cObject.xpath

    @xpath.setter
    def xpath(self, xpath):
        self._cObject.xpath = xpath

    @property
    def data(self):
        return self._cObject.data

    @property
    def value(self):
        if self.type == sr.SR_BINARY_T:
            return self._cObject.data.binary_val
        elif self.type == sr.SR_BITS_T:
            return self._cObject.data.bits_val
        elif self.type == sr.SR_BOOL_T:
            return self._cObject.data.bool_val
        elif self.type == sr.SR_DECIMAL64_T:
            return self._cObject.data.decimal64_val
        elif self.type == sr.SR_ENUM_T:
            return self._cObject.data.enum_val
        elif self.type == sr.SR_IDENTITYREF_T:
            return self._cObject.data.identityref_val
        elif self.type == sr.SR_INSTANCEID_T:
            return self._cObject.data.instanceid_val
        elif self.type == sr.SR_INT8_T:
            return self._cObject.data.int8_val
        elif self.type == sr.SR_INT16_T:
            return self._cObject.data.int16_val
        elif self.type == sr.SR_INT32_T:
            return self._cObject.data.int32_val
        elif self.type == sr.SR_INT64_T:
            return self._cObject.data.int64_val
        elif self.type == sr.SR_LEAFREF_T:
            return self._cObject.data.leafref_val
        elif self.type == sr.SR_STRING_T:
            return self._cObject.data.string_val
        elif self.type == sr.SR_UINT8_T:
            return self._cObject.data.uint8_val
        elif self.type == sr.SR_UINT16_T:
            return self._cObject.data.uint16_val
        elif self.type == sr.SR_UINT32_T:
            return self._cObject.data.uint32_val
        elif self.type == sr.SR_UINT64_T:
            return self._cObject.data.uint64_val
        else:
            return None

    @value.setter
    def value(self, value):
        try:
            leaf_type, val = value
        except ValueError:
            raise ValueError("To set a value pass a tuple with type and value")

        self._cObject.type = leaf_type

        if self.type == sr.SR_BINARY_T:
            self._cObject.data.binary_val = val
        elif self.type == sr.SR_BITS_T:
            self._cObject.data.bits_val = val
        elif self.type == sr.SR_BOOL_T:
            self._cObject.data.bool_val = val
        elif self.type == sr.SR_DECIMAL64_T:
            self._cObject.data.decimal64_val = val
        elif self.type == sr.SR_ENUM_T:
            self._cObject.data.enum_val = val
        elif self.type == sr.SR_IDENTITYREF_T:
            self._cObject.data.identityref_val = val
        elif self.type == sr.SR_INSTANCEID_T:
            self._cObject.data.instanceid_val = val
        elif self.type == sr.SR_INT8_T:
            self._cObject.data.int8_val = val
        elif self.type == sr.SR_INT16_T:
            self._cObject.data.int16_val = val
        elif self.type == sr.SR_INT32_T:
            self._cObject.data.int32_val = val
        elif self.type == sr.SR_INT64_T:
            self._cObject.data.int64_val = val
        elif self.type == sr.SR_LEAFREF_T:
            self._cObject.data.leafref_val = val
        elif self.type == sr.SR_STRING_T:
            self._cObject.data.string_val = val
        elif self.type == sr.SR_UINT8_T:
            self._cObject.data.uint8_val = val
        elif self.type == sr.SR_UINT16_T:
            self._cObject.data.uint16_val = val
        elif self.type == sr.SR_UINT32_T:
            self._cObject.data.uint32_val = val
        elif self.type == sr.SR_UINT64_T:
            self._cObject.data.uint64_val = val

    @property
    def type(self):
        return self._cObject.type

    @property
    def cobject(self):
        return self._cObject


