/**
 * @file Value.cpp
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @brief Sysrepo Value class implementation.
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
#include <stdexcept>

#include "Sysrepo.h"
#include "Value.h"

extern "C" {
#include "sysrepo.h"
#include <stdlib.h>
}

using namespace std;

char *Value::get_xpath()
{
    if (!_val) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->xpath;
}

sr_type_t Value::get_type()
{
    if (!_val) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->type;
}

bool Value::get_dflt()
{
    if (!_val) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->dflt;
}

char *Value::get_binary()
{
    if (!_val || (_val && _val->type != SR_BINARY_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.binary_val;
}

char *Value::get_bits()
{
    if (!_val || (_val && _val->type != SR_BITS_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.bits_val;
}

bool Value::get_bool()
{
    if (!_val || (_val && _val->type != SR_BOOL_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.bool_val;
}

double Value::get_decimal64()
{
    if (!_val || (_val && _val->type != SR_DECIMAL64_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.decimal64_val;
}

char *Value::get_enum()
{
    if (!_val || (_val && _val->type != SR_ENUM_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.enum_val;
}

char *Value::get_identityref()
{
    if (!_val || (_val && _val->type != SR_IDENTITYREF_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.identityref_val;
}

char *Value::get_instanceid()
{
    if (!_val || (_val && _val->type != SR_INSTANCEID_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.instanceid_val;
}

int8_t Value::get_int8()
{
    if (!_val || (_val && _val->type != SR_INT8_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.int8_val;
}

int16_t Value::get_int16()
{
    if (!_val || (_val && _val->type != SR_INT16_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.uint32_val;
}

int32_t Value::get_int32()
{
    if (!_val || (_val && _val->type != SR_INT32_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.int32_val;
}

int64_t Value::get_int64()
{
    if (!_val || (_val && _val->type != SR_INT64_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.int64_val;
}

char *Value::get_string()
{
    if (!_val || (_val && _val->type != SR_STRING_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.string_val;
}

uint8_t Value::get_uint8()
{
    if (!_val || (_val && _val->type != SR_UINT8_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.uint32_val;
}

uint16_t Value::get_uint16()
{
    if (!_val || (_val && _val->type != SR_UINT16_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.uint16_val;
}

uint32_t Value::get_uint32()
{
    if (!_val || (_val && _val->type != SR_UINT32_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.uint32_val;
}

uint64_t Value::get_uint64()
{
    if (!_val || (_val && _val->type != SR_UINT64_T)) {
        throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.uint64_val;
}

Value::Value(char *value, sr_type_t type)
{
    sr_val_t *val = NULL;
    val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (val == NULL)
        throw_exception(SR_ERR_NOMEM);
    if (type == SR_BINARY_T) {
	val->data.binary_val = value;
    } else if (type == SR_BITS_T) {
	val->data.bits_val = value;
    } else if (type == SR_ENUM_T) {
	val->data.enum_val = value;
    } else if (type == SR_IDENTITYREF_T) {
	val->data.identityref_val = value;
    } else if (type == SR_INSTANCEID_T) {
	val->data.instanceid_val = value;
    } else if (type == SR_STRING_T) {
	val->data.string_val = value;
    } else {
        free(val);
        throw_exception(SR_ERR_INVAL_ARG);
    }

    val->type = type;
    _val = val;
}

Value::Value(bool bool_val, sr_type_t type)
{
    sr_val_t *val = NULL;
    val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (val == NULL)
        throw_exception(SR_ERR_NOMEM);
    if (type == SR_BOOL_T) {
	val->data.bool_val = bool_val;
    } else {
        free(val);
        throw_exception(SR_ERR_INVAL_ARG);
    }

    val->type = type;
    _val = val;
}

Value::Value(double decimal64_val, sr_type_t type)
{
    sr_val_t *val = NULL;
    val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (val == NULL)
        throw_exception(SR_ERR_NOMEM);
    if (type == SR_DECIMAL64_T) {
	val->data.decimal64_val = decimal64_val;
    } else {
        free(val);
        throw_exception(SR_ERR_INVAL_ARG);
    }

    val->type = type;
    _val = val;
}

Value::Value(int8_t int8_val, sr_type_t type)
{
    sr_val_t *val = NULL;
    val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (val == NULL)
        throw_exception(SR_ERR_NOMEM);
    if (type == SR_INT8_T) {
	val->data.int8_val = int8_val;
    } else {
        free(val);
        throw_exception(SR_ERR_INVAL_ARG);
    }

    val->type = type;
    _val = val;
}

Value::Value(int16_t int16_val, sr_type_t type)
{
    sr_val_t *val = NULL;
    val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (val == NULL)
        throw_exception(SR_ERR_NOMEM);
    if (type == SR_INT16_T) {
	val->data.int16_val = int16_val;
    } else {
        free(val);
        throw_exception(SR_ERR_INVAL_ARG);
    }

    val->type = type;
    _val = val;
}

Value::Value(int32_t int32_val, sr_type_t type)
{
    sr_val_t *val = NULL;
    val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (val == NULL)
        throw_exception(SR_ERR_NOMEM);
    if (type == SR_INT32_T) {
	val->data.int32_val = int32_val;
    } else {
        free(val);
        throw_exception(SR_ERR_INVAL_ARG);
    }

    val->type = type;
    _val = val;
}

Value::Value(int64_t int64_val, sr_type_t type)
{
    sr_val_t *val = NULL;
    val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (val == NULL)
        throw_exception(SR_ERR_NOMEM);
    if (type == SR_DECIMAL64_T) {
	val->data.uint64_val = (double) int64_val;
    } else if (type == SR_UINT64_T) {
        val->data.uint64_val = (uint64_t) int64_val;
    } else if (type == SR_UINT32_T) {
        val->data.uint32_val = (uint32_t) int64_val;
    } else if (type == SR_UINT16_T) {
        val->data.uint16_val = (uint16_t) int64_val;
    } else if (type == SR_UINT8_T) {
        val->data.uint8_val = (uint8_t) int64_val;
    } else if (type == SR_INT64_T) {
        val->data.int64_val = (int64_t) int64_val;
    } else if (type == SR_INT32_T) {
        val->data.int32_val = (int32_t) int64_val;
    } else if (type == SR_INT16_T) {
        val->data.int16_val = (int16_t) int64_val;
    } else if (type == SR_INT8_T) {
        val->data.int8_val = (int8_t) int64_val;
    } else {
	    printf("\nERROR \n\n\n\n");
        free(val);
        throw_exception(SR_ERR_INVAL_ARG);
    }

    val->type = type;
    _val = val;
}

Value::Value(uint8_t uint8_val, sr_type_t type)
{
    sr_val_t *val = NULL;
    val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (val == NULL)
        throw_exception(SR_ERR_NOMEM);
    if (type == SR_UINT8_T) {
	val->data.uint8_val = uint8_val;
    } else {
        free(val);
        throw_exception(SR_ERR_INVAL_ARG);
    }

    val->type = type;
    _val = val;
}

Value::Value(uint16_t uint16_val, sr_type_t type)
{
    sr_val_t *val = NULL;
    val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (val == NULL)
        throw_exception(SR_ERR_NOMEM);
    if (type == SR_UINT16_T) {
	val->data.uint16_val = uint16_val;
    } else {
        free(val);
        throw_exception(SR_ERR_INVAL_ARG);
    }

    val->type = type;
    _val = val;
}

Value::Value(uint32_t uint32_val, sr_type_t type)
{
    sr_val_t *val = NULL;
    val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (val == NULL)
        throw_exception(SR_ERR_NOMEM);
    if (type == SR_UINT32_T) {
	val->data.uint32_val = uint32_val;
    } else {
        free(val);
        throw_exception(SR_ERR_INVAL_ARG);
    }

    val->type = type;
    _val = val;
}

Value::Value(uint64_t uint64_val, sr_type_t type)
{
    sr_val_t *val = NULL;
    val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (val == NULL)
        throw_exception(SR_ERR_NOMEM);
    if (type == SR_UINT64_T) {
	val->data.uint64_val = uint64_val;
    } else {
        free(val);
        throw_exception(SR_ERR_INVAL_ARG);
    }

    val->type = type;
    _val = val;
}

Value::Value(sr_val_t *val)
{
    _val = val;
}

void Value::Set(sr_val_t *val)
{
    if (_val != NULL) {
        sr_free_val(_val);
        _val = NULL;
    }

    _val = val;
}

sr_val_t **Value::Get()
{
    return &_val;
}

Value::~Value()
{
    if (_val != NULL) {
        sr_free_val(_val);
        _val = NULL;
    }
}

Iter_Value::~Iter_Value()
{
    if (_iter)
        sr_free_val_iter(_iter);
}

Iter_Value::Iter_Value()
{
    _iter = NULL;
}

Iter_Value::Iter_Value(sr_val_iter_t *iter)
{
    _iter = iter;
}

sr_val_iter_t *Iter_Value::Get()
{
    return _iter;

}

void Iter_Value::Set(sr_val_iter_t *iter)
{
    if (_iter)
        sr_free_val_iter(_iter);
    _iter = iter;
}

Iter_Change::~Iter_Change()
{
    if (_iter)
        sr_free_change_iter(_iter);
}

Iter_Change::Iter_Change()
{
    _iter = NULL;
}

Iter_Change::Iter_Change(sr_change_iter_t *iter)
{
    _iter = iter;
}

sr_change_iter_t *Iter_Change::Get()
{
    return _iter;

}

Values::Values(sr_val_t *val, size_t cnt)
{
    _values = val;
    _cnt = cnt;
    _pos = 0;

    if (_values)
        _val = &(_values[_pos]);
}

Values::~Values()
{
    if (_values != NULL) {
        sr_free_values(_values, _cnt);
        _val = NULL;
    }
}

void Values::Set(sr_val_t *val, size_t cnt)
{
    if (_values != NULL) {
        sr_free_values(_values, _cnt);
        _val = NULL;
    }

    _values = val;
    if (_values) {
        _cnt = cnt;
        _pos = 0;
        _val = &(_values[_pos]);
    }
}

sr_val_t *Values::Get_val()
{
    return _values;
}

size_t *Values::Get_cnt()
{
    return &_cnt;
}

bool Values::Next()
{
    if (_pos + 1 < _cnt) {
        _val = &(_values[++_pos]);
        return true;
    }

    return false;
}

bool Values::Prev()
{
    if (_pos - 1 > 0) {
        _val = &(_values[--_pos]);
        return true;
    }

    return false;
}

Operation::Operation(sr_change_oper_t oper)
{
    _oper = oper;
}

Operation::~Operation()
{
    return;
}

sr_change_oper_t Operation::Get()
{
    return _oper;
}
