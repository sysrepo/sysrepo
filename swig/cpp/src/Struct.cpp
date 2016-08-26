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

#include "Struct.h"
#include "Sysrepo.h"

extern "C" {
#include "sysrepo.h"
}

using namespace std;

Operation::Operation(sr_change_oper_t oper) {_oper = oper;}
Operation::~Operation() {return;}

Char_val::Char_val(char *data) {_data = data;}
Char_val::~Char_val() {return;}
Bool_val::Bool_val(bool data) {_data = data;}
Bool_val::~Bool_val() {return;}
Double_val::Double_val(double data) {_data = data;}
Double_val::~Double_val() {return;}
Int8_val::Int8_val(int8_t data) {_data = data;}
Int8_val::~Int8_val() {return;}
Int16_val::Int16_val(int16_t data) {_data = data;}
Int16_val::~Int16_val() {return;}
Int32_val::Int32_val(int32_t data) {_data = data;}
Int32_val::~Int32_val() {return;}
Int64_val::Int64_val(int64_t data) {_data = data;}
Int64_val::~Int64_val() {return;}
Uint8_val::Uint8_val(int8_t data) {_data = data;}
Uint8_val::~Uint8_val() {return;}
Uint16_val::Uint16_val(int16_t data) {_data = data;}
Uint16_val::~Uint16_val() {return;}
Uint32_val::Uint32_val(int32_t data) {_data = data;}
Uint32_val::~Uint32_val() {return;}
Uint64_val::Uint64_val(int64_t data) {_data = data;}
Uint64_val::~Uint64_val() {return;}

// Data
Data::Data(sr_data_t data, sr_type_t type) {_d = data; _t = type;}
Data::~Data() {return;}
shared_ptr<Char_val> Data::get_binary() {
    if (_t != SR_BINARY_T)
        return NULL;

    shared_ptr<Char_val> data(new Char_val(_d.binary_val));
    return data;
}
shared_ptr<Char_val> Data::get_bits() {
    if (_t != SR_BITS_T)
        return NULL;

    shared_ptr<Char_val> data(new Char_val(_d.bits_val));
    return data;
}
shared_ptr<Bool_val> Data::get_bool() {
    if (_t != SR_BOOL_T)
        return NULL;

    shared_ptr<Bool_val> data(new Bool_val(_d.bool_val));
    return data;
}
shared_ptr<Double_val> Data::get_decimal64() {
    if (_t != SR_DECIMAL64_T)
        return NULL;

    shared_ptr<Double_val> data(new Double_val(_d.decimal64_val));
    return data;
}
shared_ptr<Char_val> Data::get_enum() {
    if (_t != SR_ENUM_T)
        return NULL;

    shared_ptr<Char_val> data(new Char_val(_d.enum_val));
    return data;
}
shared_ptr<Char_val> Data::get_identityref() {
    if (_t != SR_IDENTITYREF_T)
        return NULL;

    shared_ptr<Char_val> data(new Char_val(_d.identityref_val));
    return data;
}
shared_ptr<Char_val> Data::get_instanceid() {
    if (_t != SR_INSTANCEID_T)
        return NULL;

    shared_ptr<Char_val> data(new Char_val(_d.instanceid_val));
    return data;
}
shared_ptr<Int8_val> Data::get_int8() {
    if (_t != SR_INT8_T)
        return NULL;

    shared_ptr<Int8_val> data(new Int8_val(_d.int8_val));
    return data;
}
shared_ptr<Int16_val> Data::get_int16() {
    if (_t != SR_INT16_T)
        return NULL;

    shared_ptr<Int16_val> data(new Int16_val(_d.int16_val));
    return data;
}
shared_ptr<Int32_val> Data::get_int32() {
    if (_t != SR_INT32_T)
        return NULL;

    shared_ptr<Int32_val> data(new Int32_val(_d.int32_val));
    return data;
}
shared_ptr<Int64_val> Data::get_int64() {
    if (_t != SR_INT64_T)
        return NULL;

    shared_ptr<Int64_val> data(new Int64_val(_d.int64_val));
    return data;
}
shared_ptr<Char_val> Data::get_string() {
    if (_t != SR_STRING_T)
        return NULL;

    shared_ptr<Char_val> data(new Char_val(_d.string_val));
    return data;
}
shared_ptr<Uint8_val> Data::get_uint8() {
    if (_t != SR_UINT8_T)
        return NULL;

    shared_ptr<Uint8_val> data(new Uint8_val(_d.uint8_val));
    return data;
}
shared_ptr<Uint16_val> Data::get_uint16() {
    if (_t != SR_UINT16_T)
        return NULL;

    shared_ptr<Uint16_val> data(new Uint16_val(_d.uint16_val));
    return data;
}
shared_ptr<Uint32_val> Data::get_uint32() {
    if (_t != SR_UINT32_T)
        return NULL;

    shared_ptr<Uint32_val> data(new Uint32_val(_d.uint32_val));
    return data;
}
shared_ptr<Uint64_val> Data::get_uint64() {
    if (_t != SR_UINT64_T)
        return NULL;

    shared_ptr<Uint64_val> data(new Uint64_val(_d.uint64_val));
    return data;
}

// Val
Val::Val(sr_val_t *val, bool free) {_val = val; _free = free;}
Val::~Val() {
    if (_free && _val != NULL)
        sr_free_val(_val);
    return;
}
Val::Val(char *value, sr_type_t type) {
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
Val::Val(bool bool_val, sr_type_t type) {
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
Val::Val(double decimal64_val, sr_type_t type) {
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
Val::Val(int8_t int8_val, sr_type_t type) {
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
Val::Val(int16_t int16_val, sr_type_t type) {
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
Val::Val(int32_t int32_val, sr_type_t type) {
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
Val::Val(int64_t int64_val, sr_type_t type) {
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
Val::Val(uint8_t uint8_val, sr_type_t type) {
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
Val::Val(uint16_t uint16_val, sr_type_t type) {
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
Val::Val(uint32_t uint32_val, sr_type_t type) {
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
Val::Val(uint64_t uint64_val, sr_type_t type) {
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

// Vals
Vals::Vals(sr_val_t *vals, size_t cnt) {_vals = vals; _cnt = cnt;}
Vals::~Vals() {
    if (_vals != NULL)
        sr_free_values(_vals, _cnt);
    return;
}
shared_ptr<Val> Vals::val(size_t n) {
    if (n >= _cnt)
        return NULL;

    shared_ptr<Val> val(new Val(&_vals[n]));
    return val;
}

// Val_iter
Val_Iter::Val_Iter(sr_val_iter_t *iter) {_iter = iter;}
Val_Iter::~Val_Iter() {return;}

// Change_Iter
Change_Iter::Change_Iter(sr_change_iter_t *iter) {_iter = iter;}
Change_Iter::~Change_Iter() {return;}

// Error
Error::Error(const sr_error_info_t *info) {_info = info;}
Error::~Error() {return;}

// Errors
Errors::Errors(const sr_error_info_t *info, size_t cnt) {_info = info; _cnt = cnt;}
Errors::~Errors() {return;}
shared_ptr<Error> Errors::error(size_t n) {
    if (n >= _cnt)
        return NULL;

    shared_ptr<Error> error(new Error(&_info[n]));
    return error;
}

// Node
Node::Node(const sr_node_t *node) {_node = node;}
Node::~Node() {return;}
shared_ptr<Node> Node::parent() {
    if (_node->parent == NULL)
        return NULL;

    shared_ptr<Node> node(new Node(_node->parent));
    return NULL;
}
shared_ptr<Node> Node::next() {
    if (_node->next == NULL)
        return NULL;

    shared_ptr<Node> node(new Node(_node->next));
    return NULL;
}
shared_ptr<Node> Node::prev() {
    if (_node->prev == NULL)
        return NULL;

    shared_ptr<Node> node(new Node(_node->prev));
    return NULL;
}
shared_ptr<Node> Node::first_child() {
    if (_node->first_child == NULL)
        return NULL;

    shared_ptr<Node> node(new Node(_node->first_child));
    return NULL;
}
shared_ptr<Node> Node::last_child() {
    if (_node->last_child == NULL)
        return NULL;

    shared_ptr<Node> node(new Node(_node->last_child));
    return NULL;
}

// Schema_Revision
Schema_Revision::Schema_Revision(sr_sch_revision_t rev) {_rev = rev;}
Schema_Revision::~Schema_Revision() {return;}

// Schema_Submodule
Schema_Submodule::Schema_Submodule(sr_sch_submodule_t sub) {_sub = sub;}
Schema_Submodule::~Schema_Submodule() {return;}
shared_ptr<Schema_Revision> Schema_Submodule::revision() {
    shared_ptr<Schema_Revision> rev(new Schema_Revision(_sub.revision));
    return rev;
}

// Yang_Schema
Yang_Schema::Yang_Schema(sr_schema_t *sch) {_sch = sch;}
Yang_Schema::~Yang_Schema() {return;}
shared_ptr<Schema_Revision> Yang_Schema::revision() {
    shared_ptr<Schema_Revision> rev(new Schema_Revision(_sch->revision));
    return rev;
}
shared_ptr<Schema_Submodule> Yang_Schema::submodule(size_t n) {
    if (n >= _sch->submodule_count)
        return NULL;

    shared_ptr<Schema_Submodule> sub(new Schema_Submodule(_sch->submodules[n]));
    return sub;
}
char *Yang_Schema::enabled_features(size_t n) {
    if (n >= _sch->enabled_feature_cnt)
        return NULL;

   return _sch->enabled_features[n];
}

// Yang_Schemas
Yang_Schemas::Yang_Schemas(sr_schema_t *sch, size_t cnt) {_sch = sch; _cnt = cnt;}
Yang_Schemas::~Yang_Schemas() {return;}
shared_ptr<Yang_Schema> Yang_Schemas::schema(size_t n) {
    if (n >= _cnt)
        return NULL;

    shared_ptr<Yang_Schema> rev(new Yang_Schema((sr_schema_t *) &_sch[n]));
    return rev;
}

// Fd_Change
Fd_Change::Fd_Change(sr_fd_change_t *ch) {_ch = ch;}
Fd_Change::~Fd_Change() {return;}

// Fd_Changes
Fd_Changes::Fd_Changes(sr_fd_change_t *ch, size_t cnt) {_ch = ch; _cnt = cnt;}
Fd_Changes::~Fd_Changes() {return;}
shared_ptr<Fd_Change> Fd_Changes::fd_change(size_t n) {
    if (n >= _cnt)
        return NULL;

    shared_ptr<Fd_Change> change(new Fd_Change(&_ch[n]));
    return change;
}
