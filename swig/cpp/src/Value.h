/**
 * @file Value.h
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @brief Sysrepo Value class header.
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

#ifndef VALUE_H
#define VALUE_H

#include <iostream>

#include "Sysrepo.h"

extern "C" {
#include "sysrepo.h"
}

class Value:public Throw_Exception
{

public:
    char      *get_xpath();
    sr_type_t  get_type();
    bool       get_dflt();

    char *get_binary();
    char *get_bits();
    bool get_bool();
    double get_decimal64();
    char *get_enum();
    char *get_identityref();
    char *get_instanceid();
    int8_t get_int8();
    int16_t get_int16();
    int32_t get_int32();
    int64_t get_int64();
    char *get_string();
    uint8_t get_uint8();
    uint16_t get_uint16();
    uint32_t get_uint32();
    uint64_t get_uint64();

    Value(sr_val_t *val = NULL);

    Value(char *val, sr_type_t type = SR_STRING_T);
    Value(bool bool_val, sr_type_t type = SR_BOOL_T);
    Value(double decimal64_val, sr_type_t type = SR_DECIMAL64_T);
    Value(int8_t int8_val, sr_type_t type = SR_INT16_T);
    Value(int16_t int16_val, sr_type_t type = SR_INT16_T);
    Value(int32_t int32_val, sr_type_t type = SR_INT32_T);
    Value(int64_t int64_val, sr_type_t type = SR_INT64_T);
    Value(uint8_t uint8_val, sr_type_t type = SR_UINT8_T);
    Value(uint16_t uint16_val, sr_type_t type = SR_UINT16_T);
    Value(uint32_t uint32_val, sr_type_t type = SR_UINT32_T);
    Value(uint64_t uint64_val, sr_type_t type = SR_UINT64_T);

    ~Value();
    sr_val_t **Get();
    void Set(sr_val_t *val = NULL);

protected:
    sr_val_t *_val;
};

class Iter_Value
{

public:
    Iter_Value();
    Iter_Value(sr_val_iter_t *iter);
    ~Iter_Value();
    sr_val_iter_t *Get();
    void Set(sr_val_iter_t *iter);

private:
    sr_val_iter_t *_iter;

};

class Iter_Change
{

public:
    Iter_Change();
    Iter_Change(sr_change_iter_t *iter);
    ~Iter_Change();
    sr_change_iter_t *Get();

private:
    sr_change_iter_t *_iter;

};

class Values:public Value
{

public:
    Values(sr_val_t *val = NULL, size_t cnt = 0);
    ~Values();
    bool Next();
    bool Prev();
    void Set(sr_val_t *val, size_t cnt);
    sr_val_t *Get_val();
    size_t *Get_cnt();

private:
    sr_val_t *_values;
    size_t _cnt;
    size_t _pos;
};

class Operation
{
public:
    Operation(sr_change_oper_t oper);
    ~Operation();
    sr_change_oper_t Get();

private:
    sr_change_oper_t _oper;
};

#endif
