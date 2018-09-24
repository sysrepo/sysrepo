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

#include "Sysrepo.hpp"
#include "Internal.hpp"

extern "C" {
#include "sysrepo.h"
}

namespace sysrepo {

/**
 * @defgroup classes C++/Python
 * @{
 */

/**
 * @brief Class for wrapping sr_data_t.
 * @class Data
 */
class Data
{
public:
    /** Wrapper for [sr_data_t](@ref sr_data_t), for internal use only.*/
    Data(sr_data_t data, sr_type_t type, S_Deleter deleter);
    ~Data();
    /** Getter for binary data.*/
    char *get_binary() const;
    /** Getter for bits.*/
    char *get_bits() const;
    /** Getter for bool.*/
    bool get_bool() const;
    /** Getter for decimal64.*/
    double get_decimal64() const;
    /** Getter for enum.*/
    char *get_enum() const;
    /** Getter for identityref.*/
    char *get_identityref() const;
    /** Getter for instanceid.*/
    char *get_instanceid() const;
    /** Getter for int8.*/
    int8_t get_int8() const;
    /** Getter for int16.*/
    int16_t get_int16() const;
    /** Getter for int32.*/
    int32_t get_int32() const;
    /** Getter for int64.*/
    int64_t get_int64() const;
    /** Getter for string.*/
    char *get_string() const;
    /** Getter for uint8.*/
    uint8_t get_uint8() const;
    /** Getter for uint16.*/
    uint16_t get_uint16() const;
    /** Getter for uint32.*/
    uint32_t get_uint32() const;
    /** Getter for uint64.*/
    uint64_t get_uint64() const;

private:
    sr_data_t _d;
    sr_type_t _t;
    S_Deleter _deleter;
};

/**
 * @brief Class for wrapping sr_val_t.
 * @class Val
 */
class Val
{
public:
    /** Constructor for an empty value.*/
    Val();
    /** Wrapper for [sr_val_t](@ref sr_val_t).*/
    Val(sr_val_t *val, S_Deleter deleter);
    /** Constructor for string value, type can be SR_STRING_T, SR_BINARY_T, SR_BITS_T, SR_ENUM_T,
     * SR_IDENTITYREF_T and SR_INSTANCEID_T.*/
    Val(const char *val, sr_type_t type = SR_STRING_T);
    /** Constructor for bool value.*/
    Val(bool bool_val, sr_type_t type = SR_BOOL_T);
    /** Constructor for decimal64 value.*/
    Val(double decimal64_val);
    /** Constructor for int8 value, C++ only.*/
    Val(int8_t int8_val, sr_type_t type);
    /** Constructor for int16 value, C++ only.*/
    Val(int16_t int16_val, sr_type_t type);
    /** Constructor for int32 value, C++ only.*/
    Val(int32_t int32_val, sr_type_t type);
    /** Constructor for int64 value, type can be SR_INT8_T, SR_INT16_T, SR_INT32_T,
     * SR_INT64_T, SR_UINT8_T, SR_UINT16_T and SR_UINT32_T,*/
    Val(int64_t int64_val, sr_type_t type);
    /** Constructor for uint8 value, C++ only.*/
    Val(uint8_t uint8_val, sr_type_t type);
    /** Constructor for uint16 value, C++ only.*/
    Val(uint16_t uint16_val, sr_type_t type);
    /** Constructor for uint32 value, C++ only.*/
    Val(uint32_t uint32_val, sr_type_t type);
    /** Constructor for uint64 value, C++ only.*/
    Val(uint64_t uint64_val, sr_type_t type);
   ~Val();
    /** Setter for string value, type can be SR_STRING_T, SR_BINARY_T, SR_BITS_T, SR_ENUM_T,
     * SR_IDENTITYREF_T and SR_INSTANCEID_T.*/
    void set(const char *xpath, const char *val, sr_type_t type = SR_STRING_T);
    /** Setter for bool value.*/
    void set(const char *xpath, bool bool_val, sr_type_t type = SR_BOOL_T);
    /** Setter for decimal64 value.*/
    void set(const char *xpath, double decimal64_val);
    /** Setter for int8 value, C++ only.*/
    void set(const char *xpath, int8_t int8_val, sr_type_t type);
    /** Setter for int16 value, C++ only.*/
    void set(const char *xpath, int16_t int16_val, sr_type_t type);
    /** Setter for int32 value, C++ only.*/
    void set(const char *xpath, int32_t int32_val, sr_type_t type);
    /** Setter for int64 value, type can be SR_INT8_T, SR_INT16_T, SR_INT32_T,
     * SR_INT64_T, SR_UINT8_T, SR_UINT16_T and SR_UINT32_T,*/
    void set(const char *xpath, int64_t int64_val, sr_type_t type);
    /** Setter for uint8 value, C++ only.*/
    void set(const char *xpath, uint8_t uint8_val, sr_type_t type);
    /** Setter for uint16 value, C++ only.*/
    void set(const char *xpath, uint16_t uint16_val, sr_type_t type);
    /** Setter for uint32 value, C++ only.*/
    void set(const char *xpath, uint32_t uint32_val, sr_type_t type);
    /** Setter for uint64 value, C++ only.*/
    void set(const char *xpath, uint64_t uint64_val, sr_type_t type);
    /** Getter for xpath.*/
    char *xpath() {return _val->xpath;};
    /** Setter for xpath.*/
    void xpath_set(char *xpath);
    /** Getter for type.*/
    sr_type_t type() {return _val->type;};
    /** Getter for dflt.*/
    bool dflt() {return _val->dflt;};
    /** Setter for dflt.*/
    void dflt_set(bool data) {_val->dflt = data;};
    /** Getter for data.*/
    S_Data data() {S_Data data(new Data(_val->data, _val->type, _deleter)); return data;};
    /** Wrapper for [sr_print_val_mem](@ref sr_print_val_mem) */
    std::string to_string();
    /** Wrapper for [sr_val_to_string](@ref sr_val_to_string) */
    std::string val_to_string();
    /** Wrapper for [sr_dup_val](@ref sr_dup_val) */
    S_Val dup();

    friend class Session;
    friend class Subscribe;

private:
    sr_val_t *_val;
    S_Deleter _deleter;
};

/**
 * @brief Class for wrapping sr_val_t array.
 * @class Vals
 */
class Vals
{
public:
    /** Wrapper for [sr_val_t](@ref sr_val_t) array, internal use only.*/
    Vals(const sr_val_t *vals, const size_t cnt, S_Deleter deleter = nullptr);
    /** Wrapper for [sr_val_t](@ref sr_val_t) array, internal use only.*/
    Vals(sr_val_t **vals, size_t *cnt, S_Deleter deleter = nullptr);
    /** Wrapper for [sr_val_t](@ref sr_val_t) array, create n-array.*/
    Vals(size_t cnt);
    /** Constructor for an empty [sr_val_t](@ref sr_val_t) array.*/
    Vals();
    ~Vals();
    /** Getter for [sr_val_t](@ref sr_val_t), get the n-th element in array.*/
    S_Val val(size_t n);
    /** Getter for array size */
    size_t val_cnt() {return _cnt;};
    /** Wrapper for [sr_dup_values](@ref sr_dup_values) */
    S_Vals dup();

    friend class Session;
    friend class Subscribe;

private:
    size_t _cnt;
    sr_val_t *_vals;
    S_Deleter _deleter;
};

/**
 * @brief Class for wrapping sr_val_t in callbacks.
 * @class Vals_holder
 */
class Vals_Holder
{
public:
    /** Wrapper for [sr_val_t](@ref sr_val_t) array, used only in callbacks.*/
    Vals_Holder(sr_val_t **vals, size_t *cnt);
    /** Create [sr_val_t](@ref sr_val_t) array of n size.*/
    S_Vals allocate(size_t n);
    ~Vals_Holder();

private:
    size_t *p_cnt;
    sr_val_t **p_vals;
    bool _allocate;
};

/**
 * @brief Class for wrapping sr_val_iter_t.
 * @class Val_Iter
 */
class Val_Iter
{
public:
    /** Wrapper for [sr_val_iter_t](@ref sr_val_iter_t).*/
    Val_Iter(sr_val_iter_t *iter = nullptr);
    ~Val_Iter();
    /** Getter for [sr_val_iter_t](@ref sr_val_iter_t).*/
    sr_val_iter_t *iter() {return _iter;};

private:
    sr_val_iter_t *_iter;
};

/**
 * @brief Class for wrapping sr_change_iter_t.
 * @class Change_Iter
 */
class Change_Iter
{
public:
    /** Wrapper for [sr_change_iter_t](@ref sr_change_iter_t).*/
    Change_Iter(sr_change_iter_t *iter = nullptr);
    ~Change_Iter();
    /** Getter for [sr_change_iter_t](@ref sr_change_iter_t).*/
    sr_change_iter_t *iter() {return _iter;};

private:
    sr_change_iter_t *_iter;
};

/**
 * @brief Class for wrapping sr_error_info_t.
 * @class Error
 */
class Error
{
public:
    /** Constructor for an empty [sr_error_info_t](@ref sr_error_info_t).*/
    Error();
    /** Wrapper for [sr_error_info_t](@ref sr_error_info_t).*/
    Error(const sr_error_info_t *info);
    ~Error();
    /** Getter for message.*/
    const char *message() const {if (_info) return _info->message; else return nullptr;};
    /** Getter for xpath.*/
    const char *xpath() const {if (_info) return _info->xpath; else return nullptr;};

    friend class Session;

private:
    const sr_error_info_t *_info;
};

/**
 * @brief Class for wrapping sr_error_info_t array.
 * @class Errors
 */
class Errors
{
public:
    /** Constructor for an empty [sr_error_info_t](@ref sr_error_info_t) array.*/
    Errors();
    ~Errors();
    /** Getter for [sr_error_info_t](@ref sr_error_info_t), get the n-th element in array.*/
    S_Error error(size_t n);
    /** Getter for array size.*/
    size_t error_cnt() {return _cnt;};

    friend class Session;

private:
    size_t _cnt;
    const sr_error_info_t *_info;
};

/**
 * @brief Class for wrapping sr_sch_revision_t array.
 * @class Schema_Revision
 */
class Schema_Revision
{
public:
    /** Wrapper for [sr_sch_revision_t](@ref sr_sch_revision_t).*/
    Schema_Revision(sr_sch_revision_t rev);
    ~Schema_Revision();
    /** Getter for revision.*/
    const char *revision() const {return _rev.revision;};
    /** Getter for file_path_yang.*/
    const char *file_path_yang() const {return _rev.file_path_yang;};
    /** Getter for file_path_yin.*/
    const char *file_path_yin() const {return _rev.file_path_yin;};

private:
    sr_sch_revision_t _rev;
};

/**
 * @brief Class for wrapping sr_sch_submodule_t.
 * @class Schema_Submodule
 */
class Schema_Submodule
{
public:
    /** Wrapper for [sr_sch_submodule_t](@ref sr_sch_submodule_t).*/
    Schema_Submodule(sr_sch_submodule_t sub, S_Deleter deleter);
    ~Schema_Submodule();
    /** Getter for submodule_name.*/
    const char *submodule_name() const {return _sub.submodule_name;};
    /** Getter for revision.*/
    S_Schema_Revision revision();

private:
    sr_sch_submodule_t _sub;
    S_Deleter _deleter;
};

/**
 * @brief Class for wrapping sr_schema_t.
 * @class Yang_Schema
 */
class Yang_Schema
{
public:
    /** Wrapper for [sr_schema_t](@ref sr_schema_t).*/
    Yang_Schema(sr_schema_t *sch, S_Deleter deleter);
    ~Yang_Schema();
    /** Getter for module_name.*/
    const char *module_name() const {return _sch->module_name;};
    /** Getter for ns.*/
    const char *ns() const {return _sch->ns;};
    /** Getter for prefix.*/
    const char *prefix() const {return _sch->prefix;};
    /** Getter for implemented.*/
    bool implemented() const {return _sch->implemented;};
    /** Getter for revision.*/
    S_Schema_Revision revision();
    /** Getter for submodule.*/
    S_Schema_Submodule submodule(size_t n);
    /** Getter for submodule_cnt.*/
    size_t submodule_cnt() const {return _sch->submodule_count;};
    /** Getter for enabled_features.*/
    char *enabled_features(size_t n);
    /** Getter for enabled_features_cnt.*/
    size_t enabled_feature_cnt() const {return _sch->enabled_feature_cnt;};

    friend class Session;

private:
    sr_schema_t *_sch;
    S_Deleter _deleter;
};

/**
 * @brief Class for wrapping sr_schema_t array.
 * @class Yang_Schemas
 */
class Yang_Schemas
{
public:
    /** Constructor for an empty [sr_schema_t](@ref sr_schema_t) array.*/
    Yang_Schemas();
    ~Yang_Schemas();
    /** Getter for [sr_schema_t](@ref sr_schema_t) array, get the n-th element in array.*/
    S_Yang_Schema schema(size_t n);
    /** Getter for array size.*/
    size_t schema_cnt() const {return _cnt;};

    friend class Session;

private:
    size_t _cnt;
    sr_schema_t *_sch;
    S_Deleter _deleter;
};

/**
 * @brief Class for wrapping sr_fd_change_t.
 * @class Fd_Change
 */
class Fd_Change
{
public:
    /** Wrapper for [sr_fd_change_t](@ref sr_fd_change_t).*/
    Fd_Change(sr_fd_change_t *ch);
    ~Fd_Change();
    /** Getter for fd.*/
    int fd() const {return _ch->fd;};
    /** Getter for events.*/
    int events() const {return _ch->events;};
    /** Getter for action.*/
    sr_fd_action_t action() const {return _ch->action;};

private:
    sr_fd_change_t *_ch;
};

/**
 * @brief Class for wrapping sr_fd_change_t array.
 * @class Fd_Changes
 */
class Fd_Changes
{
public:
    /** Wrapper for [sr_fd_change_t](@ref sr_fd_change_t) array.*/
    Fd_Changes(sr_fd_change_t *ch, size_t cnt);
    ~Fd_Changes();
    /** Getter for [sr_fd_change_t](@ref sr_fd_change_t) array, get the n-th element in array.*/
    S_Fd_Change fd_change(size_t n);

private:
    sr_fd_change_t *_ch;
    size_t _cnt;
};

/**
 * @brief Class for wrapping sr_val_iter_t.
 * @class Fd_Changes
 */
class Iter_Value
{

public:
    /** Wrapper for [sr_val_iter_t](@ref sr_val_iter_t).*/
    Iter_Value(sr_val_iter_t *iter = nullptr);
    ~Iter_Value();
    /** Setter for [sr_val_iter_t](@ref sr_val_iter_t).*/
    void Set(sr_val_iter_t *iter);

    friend class Session;

private:
    sr_val_iter_t *_iter;
};

/**
 * @brief Class for wrapping sr_change_iter_t.
 * @class Iter_Change
 */
class Iter_Change
{

public:
    /** Wrapper for [sr_change_iter_t](@ref sr_change_iter_t).*/
    Iter_Change(sr_change_iter_t *iter = nullptr);
    ~Iter_Change();

    friend class Session;

private:
    sr_change_iter_t *_iter;
};

/**
 * @brief Class for wrapping sr_change_oper_t.
 * @class Change
 */
class Change
{
public:
    /** Constructor for an empty [sr_change_oper_t](@ref sr_change_oper_t).*/
    Change();
    ~Change();
    /** Getter for sr_change_oper_t.*/
    sr_change_oper_t oper() {return _oper;};
    /** Getter for new sr_val_t.*/
    S_Val new_val();
    /** Getter for old sr_val_t.*/
    S_Val old_val();

    friend class Session;

private:
    sr_change_oper_t _oper;
    sr_val_t *_new;
    sr_val_t *_old;
    S_Deleter _deleter_new;
    S_Deleter _deleter_old;
};

/**@} */
}
#endif
