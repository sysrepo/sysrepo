/**
 * @file Struct.h
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @brief Sysrepo class header for C struts.
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

#ifndef STRUCT_H
#define STRUCT_H

#include <iostream>
#include <memory>

#include "Sysrepo.h"

extern "C" {
#include "sysrepo.h"
}

using namespace std;

// Operation type wrapeer class
class Operation
{
public:
    Operation(sr_change_oper_t oper);
    ~Operation();
    sr_change_oper_t get() {return _oper;};

private:
    sr_change_oper_t _oper;
};

// class for sysrepo C union sr_data_t
class Data:public Throw_Exception
{
public:
    Data(sr_data_t data, sr_type_t type);
    ~Data();
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

private:
    sr_data_t _d;
    sr_type_t _t;
};

// class for sysrepo C struct sr_val_t
class Val:public Throw_Exception
{
public:
    Val(sr_val_t *val, bool free = true);
    Val(const char *val, sr_type_t type = SR_STRING_T);
    Val(bool bool_val, sr_type_t type = SR_BOOL_T);
    Val(double decimal64_val, sr_type_t type = SR_DECIMAL64_T);
    Val(int8_t int8_val, sr_type_t type = SR_INT16_T);
    Val(int16_t int16_val, sr_type_t type = SR_INT16_T);
    Val(int32_t int32_val, sr_type_t type = SR_INT32_T);
    Val(int64_t int64_val, sr_type_t type = SR_INT64_T);
    Val(uint8_t uint8_val, sr_type_t type = SR_UINT8_T);
    Val(uint16_t uint16_val, sr_type_t type = SR_UINT16_T);
    Val(uint32_t uint32_val, sr_type_t type = SR_UINT32_T);
    Val(uint64_t uint64_val, sr_type_t type = SR_UINT64_T);
    ~Val();
    char *xpath() {return _val->xpath;};
    void xpath_set(char *data) {_val->xpath = data;};
    sr_type_t type() {return _val->type;};
    bool dflt() {return _val->dflt;};
    void dflt_set(bool data) {_val->dflt = data;};
    shared_ptr<Data> data() {shared_ptr<Data> data(new Data(_val->data, _val->type)); return data;};
    sr_val_t *get() {return _val;};

private:
    sr_val_t *_val;
    bool _free;
};


// class for sysrepo C double pointer struct sr_val_t
class Val_Holder
{
public:
    Val_Holder(sr_val_t *val = NULL);
    ~Val_Holder();
    sr_val_t **get() {return &_val;};
    shared_ptr<Val> val();

private:
    sr_val_t *_val;
};

// class for list of sysrepo C structs sr_val_t
class Vals
{
public:
    Vals(sr_val_t *vals, size_t cnt);
    ~Vals();
    shared_ptr<Val> val(size_t n);
    size_t val_cnt() {return _cnt;};

private:
    size_t _cnt;
    sr_val_t *_vals;
};

class Val_Iter
{
public:
    Val_Iter(sr_val_iter_t *iter = NULL);
    ~Val_Iter();
    sr_val_iter_t *iter() {return _iter;};

private:
    sr_val_iter_t *_iter;
};

class Change_Iter
{
public:
    Change_Iter(sr_change_iter_t *iter = NULL);
    ~Change_Iter();
    sr_change_iter_t *iter() {return _iter;};

private:
    sr_change_iter_t *_iter;
};

// class for sysrepo C struct sr_error_info_t
class Error
{
public:
    Error(const sr_error_info_t *info);
    ~Error();
    const char *message() {return _info->message;};
    const char *xpath() {return _info->xpath;};

private:
    const sr_error_info_t *_info;
};

// class for list of sysrepo C structs sr_error_info_t
class Errors
{
public:
    Errors(const sr_error_info_t *info, size_t cnt);
    ~Errors();
    shared_ptr<Error> error(size_t n);
    size_t error_cnt() {return _cnt;};

private:
    size_t _cnt;
    const sr_error_info_t *_info;
};

// class for sysrepo C struct sr_error_info_t
class Node
{
public:
    Node(const sr_node_t *node);
    ~Node();
    sr_mem_ctx_t *_sr_mem() {return _node->_sr_mem;};
    char *name() {return _node->name;};
    sr_type_t type() {return _node->type;};
    bool dflt() {return _node->dflt;};
    shared_ptr<Data> data() {shared_ptr<Data> data(new Data(_node->data, _node->type)); return data;};
    char *module_name() {return _node->module_name;};
    shared_ptr<Node> parent();
    shared_ptr<Node> next();
    shared_ptr<Node> prev();
    shared_ptr<Node> first_child();
    shared_ptr<Node> last_child();

private:
    const sr_node_t *_node;
};

// class for sysrepo C struct sr_sch_revision_t
class Schema_Revision
{
public:
    Schema_Revision(sr_sch_revision_t rev);
    ~Schema_Revision();
    const char *revision() {return _rev.revision;};
    const char *file_path_yang() {return _rev.file_path_yang;};
    const char *file_path_yin() {return _rev.file_path_yin;};

private:
    sr_sch_revision_t _rev;
};

// class for sysrepo C struct sr_sch_submodule_t
class Schema_Submodule
{
public:
    Schema_Submodule(sr_sch_submodule_t sub);
    ~Schema_Submodule();
    const char *submodule_name() {return _sub.submodule_name;};
    shared_ptr<Schema_Revision> revision();

private:
    sr_sch_submodule_t _sub;
};

// class for sysrepo C struct sr_schema_t
class Yang_Schema
{
public:
    Yang_Schema(sr_schema_t *sch);
    ~Yang_Schema();
    const char *module_name() {return _sch->module_name;};
    const char *ns() {return _sch->ns;};
    const char *prefix() {return _sch->prefix;};
    shared_ptr<Schema_Revision> revision();
    shared_ptr<Schema_Submodule> submodule(size_t n);
    size_t submodule_cnt() {return _sch->submodule_count;};
    char *enabled_features(size_t n);
    size_t enabled_feature_cnt() {return _sch->enabled_feature_cnt;};

private:
    sr_schema_t *_sch;
};

// class for list of sysrepo C structs sr_schema_t
class Yang_Schemas
{
public:
    Yang_Schemas(sr_schema_t *sch, size_t cnt);
    ~Yang_Schemas();
    shared_ptr<Yang_Schema> schema(size_t n);
    size_t schema_cnt() {return _cnt;};

private:
    size_t _cnt;
    const sr_schema_t *_sch;
};

// class for sysrepo C struct sr_fd_change_t
class Fd_Change
{
public:
    Fd_Change(sr_fd_change_t *ch);
    ~Fd_Change();
    int fd() {return _ch->fd;};
    int events() {return _ch->events;};
    sr_fd_action_t action() {return _ch->action;};

private:
    sr_fd_change_t *_ch;
};

// class for list of sysrepo C structs sr_fd_change_t
class Fd_Changes
{
public:
    Fd_Changes(sr_fd_change_t *ch, size_t cnt);
    ~Fd_Changes();
    shared_ptr<Fd_Change> fd_change(size_t n);

private:
    sr_fd_change_t *_ch;
    size_t _cnt;
};

class Iter_Value
{

public:
    Iter_Value(sr_val_iter_t *iter = NULL);
    ~Iter_Value();
    sr_val_iter_t *get() {return _iter;};
    void Set(sr_val_iter_t *iter);

private:
    sr_val_iter_t *_iter;
};

class Iter_Change
{

public:
    Iter_Change(sr_change_iter_t *iter = NULL);
    ~Iter_Change();
    sr_change_iter_t *get() {return _iter;};

private:
    sr_change_iter_t *_iter;
};

#endif
