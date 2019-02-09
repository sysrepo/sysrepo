/**
 * @file Struct.cpp
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @brief Sysrepo class header implementation for C struts.
 *
 * @copyright
 * Copyright 2016 Deutsche Telekom AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <iostream>
#include <memory>
#include <string.h>

#include "Struct.hpp"
#include "Sysrepo.hpp"
#include "Internal.hpp"

extern "C" {
#include "sysrepo.h"
#include "sysrepo/values.h"
#include "sysrepo/trees.h"
}

namespace sysrepo {

// Data
Data::Data(sr_data_t data, sr_type_t type, S_Deleter deleter) {_d = data; _t = type; _deleter = deleter;}
Data::~Data() {}
char *Data::get_binary() const {
    if (_t != SR_BINARY_T) throw_exception(SR_ERR_DATA_MISSING);
    return _d.binary_val;
}
char *Data::get_bits() const {
    if (_t != SR_BITS_T) throw_exception(SR_ERR_DATA_MISSING);
    return _d.bits_val;
}
bool Data::get_bool() const {
    if (_t != SR_BOOL_T) throw_exception(SR_ERR_DATA_MISSING);
    return _d.bool_val;
}
double Data::get_decimal64() const {
    if (_t != SR_DECIMAL64_T) throw_exception(SR_ERR_DATA_MISSING);
    return _d.decimal64_val;
}
char *Data::get_enum() const {
    if (_t != SR_ENUM_T) throw_exception(SR_ERR_DATA_MISSING);
    return _d.enum_val;
}
char *Data::get_identityref() const {
    if (_t != SR_IDENTITYREF_T) throw_exception(SR_ERR_DATA_MISSING);
    return _d.identityref_val;
}
char *Data::get_instanceid() const {
    if (_t != SR_INSTANCEID_T) throw_exception(SR_ERR_DATA_MISSING);
    return _d.instanceid_val;
}
int8_t Data::get_int8() const {
    if (_t != SR_INT8_T) throw_exception(SR_ERR_DATA_MISSING);
    return _d.int8_val;
}
int16_t Data::get_int16() const {
    if (_t != SR_INT16_T) throw_exception(SR_ERR_DATA_MISSING);
    return _d.uint32_val;
}
int32_t Data::get_int32() const {
    if (_t != SR_INT32_T) throw_exception(SR_ERR_DATA_MISSING);
    return _d.int32_val;
}
int64_t Data::get_int64() const {
    if (_t != SR_INT64_T) throw_exception(SR_ERR_DATA_MISSING);
    return _d.int64_val;
}
char *Data::get_string() const {
    if (_t != SR_STRING_T) throw_exception(SR_ERR_DATA_MISSING);
    return _d.string_val;
}
uint8_t Data::get_uint8() const {
    if (_t != SR_UINT8_T) throw_exception(SR_ERR_DATA_MISSING);
    return _d.uint8_val;
}
uint16_t Data::get_uint16() const {
    if (_t != SR_UINT16_T) throw_exception(SR_ERR_DATA_MISSING);
    return _d.uint16_val;
}
uint32_t Data::get_uint32() const {
    if (_t != SR_UINT32_T) throw_exception(SR_ERR_DATA_MISSING);
    return _d.uint32_val;
}
uint64_t Data::get_uint64() const {
    if (_t != SR_UINT64_T) throw_exception(SR_ERR_DATA_MISSING);
    return _d.uint64_val;
}

// Val
Val::Val(sr_val_t *val, S_Deleter deleter) {
    if (val == nullptr)
        throw_exception(SR_ERR_INVAL_ARG);
    _val = val;
    _deleter = deleter;
}
Val::Val() {
    _val = nullptr;
    _deleter = S_Deleter(new Deleter(_val));
}
Val::~Val() {}
Val::Val(const char *value, sr_type_t type) {
    _val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (_val == nullptr)
        throw_exception(SR_ERR_NOMEM);
    set(nullptr,value,type);
    _deleter = S_Deleter(new Deleter(_val));
}
Val::Val(bool bool_val, sr_type_t type) {
    if (type != SR_BOOL_T)
        throw_exception(SR_ERR_INVAL_ARG);
    _val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (_val == nullptr)
        throw_exception(SR_ERR_NOMEM);
    set(nullptr,bool_val,type);
    _deleter = S_Deleter(new Deleter(_val));
}
Val::Val(double decimal64_val) {
    _val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (_val == nullptr)
        throw_exception(SR_ERR_NOMEM);
    set(nullptr,decimal64_val);
    _deleter = S_Deleter(new Deleter(_val));
}
Val::Val(int8_t int8_val) {
    _val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (_val == nullptr)
        throw_exception(SR_ERR_NOMEM);
    set(nullptr,int8_val);
    _deleter = S_Deleter(new Deleter(_val));
}
Val::Val(int16_t int16_val) {
    _val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (_val == nullptr)
        throw_exception(SR_ERR_NOMEM);
    set(nullptr,int16_val);
    _deleter = S_Deleter(new Deleter(_val));
}
Val::Val(int32_t int32_val) {
    _val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (_val == nullptr)
        throw_exception(SR_ERR_NOMEM);
    set(nullptr,int32_val);
    _deleter = S_Deleter(new Deleter(_val));
}
Val::Val(int64_t int64_val, sr_type_t type) {
    _val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (_val == nullptr)
        throw_exception(SR_ERR_NOMEM);
    set(nullptr,int64_val,type);
    _deleter = S_Deleter(new Deleter(_val));
}
Val::Val(uint8_t uint8_val) {
    _val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (_val == nullptr)
        throw_exception(SR_ERR_NOMEM);
    set(nullptr,uint8_val);
    _deleter = S_Deleter(new Deleter(_val));
}
Val::Val(uint16_t uint16_val) {
    _val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (_val == nullptr)
        throw_exception(SR_ERR_NOMEM);
    set(nullptr,uint16_val);
    _deleter = S_Deleter(new Deleter(_val));
}
Val::Val(uint32_t uint32_val) {
    _val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (_val == nullptr)
        throw_exception(SR_ERR_NOMEM);
    set(nullptr,uint32_val);
    _deleter = S_Deleter(new Deleter(_val));
}
Val::Val(uint64_t uint64_val) {
    _val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (_val == nullptr)
        throw_exception(SR_ERR_NOMEM);
    set(nullptr,uint64_val);
    _deleter = S_Deleter(new Deleter(_val));
}
void Val::set(const char *xpath, const char *value, sr_type_t type) {
    switch (type)
    {
        case SR_LIST_T:
        case SR_CONTAINER_T:
        case SR_CONTAINER_PRESENCE_T:
        case SR_LEAF_EMPTY_T: {
            if ((value != nullptr) && (*value))
                throw_exception(SR_ERR_INVAL_ARG);
            xpath_set(xpath);
            _val->type = type;
            break;
        }

        case SR_BINARY_T:
        case SR_BITS_T:
        case SR_ENUM_T:
        case SR_IDENTITYREF_T:
        case SR_INSTANCEID_T:
        case SR_STRING_T: {
            xpath_set(xpath);
            int ret = sr_val_set_str_data(_val, type, value);
            if (ret != SR_ERR_OK)
                throw_exception(ret);
            _val->type = type;
            break;
        }

        case SR_BOOL_T: {
            set(xpath,(!strcasecmp(value,"true") ? true : false));
            break;
        }

        case SR_DECIMAL64_T: {
            set(xpath,std::atof(value));
            break;
        }

        case SR_INT8_T:
        case SR_INT16_T:
        case SR_INT32_T:
        case SR_INT64_T:
        case SR_UINT8_T:
        case SR_UINT16_T:
        case SR_UINT32_T:
        case SR_UINT64_T: {
            set(xpath,int64_t{std::atoll(value)},type);
            break;
        }

        case SR_UNKNOWN_T:
        case SR_ANYXML_T:
        case SR_TREE_ITERATOR_T:
        case SR_NOTIFICATION_T:
        case SR_ANYDATA_T:
        default: {
            throw_exception(SR_ERR_INVAL_ARG);
            break;
        }
    }
}
void Val::set(const char *xpath, bool bool_val, sr_type_t type) {
    if (type != SR_BOOL_T)
        throw_exception(SR_ERR_INVAL_ARG);

    xpath_set(xpath);

    _val->data.bool_val = bool_val;
    _val->type = SR_BOOL_T;
}
void Val::set(const char *xpath, double decimal64_val) {
    xpath_set(xpath);

    _val->data.decimal64_val = decimal64_val;

    _val->type = SR_DECIMAL64_T;
}
void Val::set(const char *xpath, int8_t int8_val) {
    xpath_set(xpath);

    _val->data.int8_val = int8_val;
    _val->type = SR_INT8_T;
}
void Val::set(const char *xpath, int16_t int16_val) {
    xpath_set(xpath);

    _val->data.int16_val = int16_val;
    _val->type = SR_INT16_T;
}
void Val::set(const char *xpath, int32_t int32_val) {
    xpath_set(xpath);

    _val->data.int32_val = int32_val;
    _val->type = SR_INT32_T;
}

void Val::set(const char *xpath, int64_t int64_val, sr_type_t type) {
    xpath_set(xpath);

    if (type == SR_UINT64_T) {
        _val->data.uint64_val = (uint64_t) int64_val;
    } else if (type == SR_UINT32_T) {
        _val->data.uint32_val = (uint32_t) int64_val;
    } else if (type == SR_UINT16_T) {
        _val->data.uint16_val = (uint16_t) int64_val;
    } else if (type == SR_UINT8_T) {
        _val->data.uint8_val = (uint8_t) int64_val;
    } else if (type == SR_INT64_T) {
        _val->data.int64_val = (int64_t) int64_val;
    } else if (type == SR_INT32_T) {
        _val->data.int32_val = (int32_t) int64_val;
    } else if (type == SR_INT16_T) {
        _val->data.int16_val = (int16_t) int64_val;
    } else if (type == SR_INT8_T) {
        _val->data.int8_val = (int8_t) int64_val;
    } else {
        throw_exception(SR_ERR_INVAL_ARG);
    }

    _val->type = type;
}
void Val::set(const char *xpath, uint8_t uint8_val) {
    xpath_set(xpath);

    _val->data.uint8_val = uint8_val;
    _val->type = SR_UINT8_T;
}
void Val::set(const char *xpath, uint16_t uint16_val) {
    xpath_set(xpath);

    _val->data.uint16_val = uint16_val;
    _val->type = SR_UINT16_T;
}
void Val::set(const char *xpath, uint32_t uint32_val) {
    xpath_set(xpath);

    _val->data.uint32_val = uint32_val;
    _val->type = SR_UINT32_T;
}
void Val::set(const char *xpath, uint64_t uint64_val) {
    xpath_set(xpath);

    _val->data.uint64_val = uint64_val;
    _val->type = SR_UINT64_T;
}
char *Val::xpath() {
    if (_val == nullptr)
        throw_exception(SR_ERR_OPERATION_FAILED);
    return _val->xpath;
}
void Val::xpath_set(const char *xpath) {
    if ((_val == nullptr) || ((xpath == nullptr) && (_val->xpath != nullptr)))
        throw_exception(SR_ERR_OPERATION_FAILED);

    if (xpath != nullptr) {
        int ret = sr_val_set_xpath(_val, xpath);
        if (ret != SR_ERR_OK)
            throw_exception(ret);
    }
}
sr_type_t Val::type() {
    if (_val == nullptr)
        throw_exception(SR_ERR_OPERATION_FAILED);
    return _val->type;
}
bool Val::dflt() {
    if (_val == nullptr)
        throw_exception(SR_ERR_OPERATION_FAILED);
    return _val->dflt;
}
void Val::dflt_set(bool data) {
    if (_val == nullptr)
        throw_exception(SR_ERR_OPERATION_FAILED);
    _val->dflt = data;
}
S_Data Val::data() {
    S_Data data(new Data(_val->data, _val->type, _deleter));
    return data;
}
bool Val::empty() {
    return !_val;
}
std::string Val::to_string() {
    char *mem = nullptr;

    int ret = sr_print_val_mem(&mem, _val);
    if (SR_ERR_OK == ret) {
        if (!mem) {
            return std::string();
        }
        std::string string_val = mem;
        free(mem);
        return string_val;
    }
    if (SR_ERR_NOT_FOUND == ret) {
        return nullptr;
    }
    throw_exception(ret);
}
std::string Val::val_to_string() {
    char *value = sr_val_to_str(_val);
    if (value == nullptr) {
        throw_exception(SR_ERR_OPERATION_FAILED);
    }
    std::string string_val = value;
    free(value);

    return string_val;
}

S_Val Val::dup() {
    sr_val_t *new_val = nullptr;
    int ret = sr_dup_val(_val, &new_val);
    if (ret != SR_ERR_OK)
        throw_exception(ret);

    S_Deleter deleter(new Deleter(new_val));
    S_Val val(new Val(new_val, deleter));
    return val;
}

// Vals
Vals::Vals(const sr_val_t *vals, const size_t cnt, S_Deleter deleter) {
    _vals = (sr_val_t *) vals;
    _cnt = (size_t) cnt;

    _deleter = deleter;
}
Vals::Vals(sr_val_t **vals, size_t *cnt, S_Deleter deleter) {
    if (!vals || !cnt || (!*vals && *cnt))
        throw_exception(SR_ERR_INVAL_ARG);
    _vals = *vals;
    _cnt = *cnt;
    _deleter = deleter;
}
Vals::Vals(size_t cnt): Vals() {
    if (cnt) {
        int ret = sr_new_values(cnt, &_vals);
        if (ret != SR_ERR_OK)
            throw_exception(ret);

        _cnt = cnt;
        _deleter = S_Deleter(new Deleter(_vals, _cnt));
    }
}
Vals::Vals(): _cnt(0), _vals(nullptr) {}
Vals::~Vals() {}
S_Val Vals::val(size_t n) {
    if (n >= _cnt)
        throw std::out_of_range("Vals::val: index out of range");
    if (!_vals)
        throw std::logic_error("Vals::val: called on null Vals");

    S_Val val(new Val(&_vals[n], _deleter));
    return val;
}
S_Vals Vals::dup() {
    sr_val_t *new_val = nullptr;
    int ret = sr_dup_values(_vals, _cnt, &new_val);
    if (ret != SR_ERR_OK)
        throw_exception(ret);

    S_Deleter deleter(new Deleter(new_val, _cnt));
    S_Vals vals(new Vals(new_val, _cnt, deleter));
    return vals;
}
sr_val_t* Vals::reallocate(size_t n) {
    int ret = sr_realloc_values(_cnt,n,&_vals);
    if (ret != SR_ERR_OK)
        throw_exception(ret);
    _cnt = n;
    if (_deleter)
        _deleter->update_vals_with_count(_vals, _cnt);
    return _vals;
}

// Vals_Holder
Vals_Holder::Vals_Holder(sr_val_t **vals, size_t *cnt) {
    if (!vals || !cnt || (!*vals && *cnt))
        throw_exception(SR_ERR_INVAL_ARG);
    p_vals = vals;
    p_cnt = cnt;
    _allocate = true;
}
S_Vals Vals_Holder::vals(void) {
    return p_Vals;
}
S_Vals Vals_Holder::allocate(size_t n) {
    if (_allocate == false)
        throw_exception(SR_ERR_DATA_EXISTS);

    if (n == 0)
        return nullptr;

    int ret = sr_new_values(n, p_vals);
    if (ret != SR_ERR_OK)
        throw_exception(ret);

    *p_cnt = n;
    _allocate = false;

    p_Vals = S_Vals(new Vals(p_vals, p_cnt, nullptr));
    return p_Vals;
}
S_Vals Vals_Holder::reallocate(size_t n) {
    if (_allocate == true) {
        return allocate(n);
    }
    *p_vals = p_Vals->reallocate(n);
    *p_cnt = n;
    return p_Vals;
}
Vals_Holder::~Vals_Holder() {}

// Val_iter
Val_Iter::Val_Iter(sr_val_iter_t *iter) {_iter = iter;}
Val_Iter::~Val_Iter() {}

// Change_Iter
Change_Iter::Change_Iter(sr_change_iter_t *iter) {_iter = iter;}
Change_Iter::~Change_Iter() {}

// Error
Error::Error() {_info = nullptr;}
Error::Error(const sr_error_info_t *info) {_info = info;}
Error::~Error() {}

// Errors
Errors::Errors() {_info = nullptr; _cnt = 0;}
Errors::~Errors() {}
S_Error Errors::error(size_t n) {
    if (n >= _cnt)
        throw std::out_of_range("Errors:error: index out of range");

    S_Error error(new Error(&_info[n]));
    return error;
}

// Schema_Revision
Schema_Revision::Schema_Revision(sr_sch_revision_t rev) {_rev = rev;}
Schema_Revision::~Schema_Revision() {}

// Schema_Submodule
Schema_Submodule::Schema_Submodule(sr_sch_submodule_t sub, S_Deleter deleter) {
    _sub = sub;
    _deleter = deleter;
}
Schema_Submodule::~Schema_Submodule() {}
S_Schema_Revision Schema_Submodule::revision() {
    S_Schema_Revision rev(new Schema_Revision(_sub.revision));
    return rev;
}

// Yang_Schema
Yang_Schema::Yang_Schema(sr_schema_t *sch, S_Deleter deleter) {_sch = sch; _deleter = deleter;}
Yang_Schema::~Yang_Schema() {}
S_Schema_Revision Yang_Schema::revision() {
    S_Schema_Revision rev(new Schema_Revision(_sch->revision));
    return rev;
}
S_Schema_Submodule Yang_Schema::submodule(size_t n) {
    if (n >= _sch->submodule_count)
        throw std::out_of_range("Schema_Submodule::submodule: index out of range");

    S_Schema_Submodule sub(new Schema_Submodule(_sch->submodules[n], _deleter));
    return sub;
}
char *Yang_Schema::enabled_features(size_t n) {
    if (n >= _sch->enabled_feature_cnt)
        throw std::out_of_range("Yang_Schema::enabled_features: index out of range");

   return _sch->enabled_features[n];
}

// Yang_Schemas
Yang_Schemas::Yang_Schemas() {
    _sch = nullptr;
    _cnt = 0;
    _deleter = S_Deleter(new Deleter(_sch, _cnt));
}
Yang_Schemas::~Yang_Schemas() {}
S_Yang_Schema Yang_Schemas::schema(size_t n) {
    if (n >= _cnt)
        throw std::out_of_range("Yang_Schema::schema: index out of range");

    S_Yang_Schema rev(new Yang_Schema((sr_schema_t *) &_sch[n], _deleter));
    return rev;
}

// Fd_Change
Fd_Change::Fd_Change(sr_fd_change_t *ch) {_ch = ch;}
Fd_Change::~Fd_Change() {}

// Fd_Changes
Fd_Changes::Fd_Changes(sr_fd_change_t *ch, size_t cnt) {_ch = ch; _cnt = cnt;}
Fd_Changes::~Fd_Changes() {}
S_Fd_Change Fd_Changes::fd_change(size_t n) {
    if (n >= _cnt)
        throw std::out_of_range("Fd_Changes::fd_change: index out of range");

    S_Fd_Change change(new Fd_Change(&_ch[n]));
    return change;
}

Iter_Value::Iter_Value(sr_val_iter_t *iter) {_iter = iter;}
Iter_Value::~Iter_Value() {if (_iter) sr_free_val_iter(_iter);}
void Iter_Value::Set(sr_val_iter_t *iter) {
    if (_iter)
        sr_free_val_iter(_iter);
    _iter = iter;
}

Iter_Change::Iter_Change(sr_change_iter_t *iter) {_iter = iter;}
Iter_Change::~Iter_Change() {if (_iter) sr_free_change_iter(_iter);}

Change::Change() {
    _oper = SR_OP_CREATED;
    _new = nullptr;
    _old = nullptr;

    _deleter_old = S_Deleter(new Deleter(_old));
    _deleter_new = S_Deleter(new Deleter(_new));
}
S_Val Change::new_val() {
    if (_new == nullptr) return nullptr;

    S_Val new_val(new Val(_new, _deleter_new));
    return new_val;
}
S_Val Change::old_val() {
    if (_old == nullptr) return nullptr;

    S_Val old_val(new Val(_old, _deleter_old));
    return old_val;
}
Change::~Change() {
    if (_new)
        sr_free_val(_new);
    if (_old)
        sr_free_val(_old);
}

}
