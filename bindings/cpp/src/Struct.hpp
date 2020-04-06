/**
 * @file Struct.hpp
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Sysrepo class header for C struts.
 *
 * @copyright
 * Copyright 2016 - 2019 Deutsche Telekom AG.
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
#include <libyang/Tree_Data.hpp>

#include "sysrepo.h"

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
   /** Constructor for string value, , type can be any type except SR_UNKNOWN_T,
      *  SR_ANYXML_T, SR_TREE_ITERATOR_T, SR_NOTIFICATION_T, and SR_ANYDATA_T */
     Val(const char *val, sr_type_t type = SR_STRING_T);
    /** Constructor for bool value.*/
    explicit Val(bool bool_val, sr_type_t type = SR_BOOL_T);
    /** Constructor for decimal64 value.*/
    explicit Val(double decimal64_val);
    /** Constructor for int8 value, C++ only.*/
    explicit Val(int8_t int8_val);
    /** Constructor for int16 value, C++ only.*/
    explicit Val(int16_t int16_val);
    /** Constructor for int32 value, C++ only.*/
    explicit Val(int32_t int32_val);
    /** Constructor for int64 value, type can be SR_INT8_T, SR_INT16_T, SR_INT32_T,
     * SR_INT64_T, SR_UINT8_T, SR_UINT16_T, SR_UINT32_T, and SR_UINT64_T*/
    Val(int64_t int64_val, sr_type_t type = SR_INT64_T);
    /** Constructor for uint8 value, C++ only.*/
    explicit Val(uint8_t uint8_val);
    /** Constructor for uint16 value, C++ only.*/
    explicit Val(uint16_t uint16_val);
    /** Constructor for uint32 value, C++ only.*/
    explicit Val(uint32_t uint32_val);
    /** Constructor for uint64 value, C++ only.*/
    explicit Val(uint64_t uint64_val);
   ~Val();
    /** Setter for string value, type can be any type except SR_UNKNOWN_T,
      * SR_ANYXML_T,S SR_TREE_ITERATOR_T, SR_NOTIFICATION_T, and SR_ANYDATA_T */
    void set(const char *xpath, const char *val, sr_type_t type = SR_STRING_T);
    /** Setter for bool value.*/
    void set(const char *xpath, bool bool_val, sr_type_t type = SR_BOOL_T);
    /** Setter for decimal64 value.*/
    void set(const char *xpath, double decimal64_val);
    /** Setter for int8 value, C++ only.*/
    void set(const char *xpath, int8_t int8_val);
    /** Setter for int16 value, C++ only.*/
    void set(const char *xpath, int16_t int16_val);
    /** Setter for int32 value, C++ only.*/
    void set(const char *xpath, int32_t int32_val);
    /** Setter for int64 value, type can be SR_INT8_T, SR_INT16_T, SR_INT32_T,
     * SR_INT64_T, SR_UINT8_T, SR_UINT16_T, SR_UINT32_T, and SR_UINT64_T*/
    void set(const char *xpath, int64_t int64_val, sr_type_t type = SR_INT64_T);
    /** Setter for uint8 value, C++ only.*/
    void set(const char *xpath, uint8_t uint8_val);
    /** Setter for uint16 value, C++ only.*/
    void set(const char *xpath, uint16_t uint16_val);
    /** Setter for uint32 value, C++ only.*/
    void set(const char *xpath, uint32_t uint32_val);
    /** Setter for uint64 value, C++ only.*/
    void set(const char *xpath, uint64_t uint64_val);
    /** Getter for xpath.*/
    char *xpath();
    /** Setter for xpath.*/
    void xpath_set(const char *xpath);
    /** Getter for type.*/
    sr_type_t type();
    /** Getter for dflt.*/
    bool dflt();
    /** Setter for dflt.*/
    void dflt_set(bool data);
    /** Getter for data.*/
    S_Data data();
    /** true if Val is empty */
    bool empty();
    /** Wrapper for [sr_print_val_mem](@ref sr_print_val_mem) */
    std::string to_string();
    /** Wrapper for [sr_val_to_str](@ref sr_val_to_str) */
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
    /** Wrapper for [sr_realloc_values](@ref sr_realloc_values) */
    sr_val_t* reallocate(size_t n);

    friend class Session;
    friend class Subscribe;

private:
    size_t _cnt;
    sr_val_t *_vals;
    S_Deleter _deleter;
};

/**
 * @brief Class for wrapping sr_val_t in callbacks.
 * @class Vals_Holder
 */
class Vals_Holder
{
public:
    /** Wrapper for [sr_val_t](@ref sr_val_t) array, used only in callbacks.*/
    Vals_Holder(sr_val_t **vals, size_t *cnt);
    /** Create [sr_val_t](@ref sr_val_t) array of n size.*/
    S_Vals allocate(size_t n);
    /** Resize [sr_val_t](@ref sr_val_t) array to n size.*/
    S_Vals reallocate(size_t n);
    size_t val_cnt(void) { return *p_cnt; }
    S_Vals vals(void);
    ~Vals_Holder();

private:
    size_t *p_cnt;
    sr_val_t **p_vals;
    S_Vals p_Vals;
    bool _allocate;
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
 * @class Errors
 */
class Errors
{
public:
    /** Constructor for an empty [sr_error_info_t](@ref sr_error_info_t).*/
    Errors();
    ~Errors();
    /** Getter for error code.*/
    sr_error_t error_code() {return _info->err_code;};
    /** Getter for messages. */
    const char *message(size_t idx) {return _info->err[idx].message;};
    /** Getter for xpaths. */
    const char *xpath(size_t idx) {return _info->err[idx].xpath;};
    /** Getter for array size.*/
    size_t error_cnt() {return _info->err_count;};

    friend class Session;

private:
    const sr_error_info_t *_info;
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
    /** Getter for sr_change_oper_t. */
    sr_change_oper_t oper() {return _oper;};
    /** Getter for new sr_val_t. */
    S_Val new_val();
    /** Getter for old sr_val_t. */
    S_Val old_val();

    friend class Session;

private:
    sr_change_oper_t _oper;
    sr_val_t *_new;
    sr_val_t *_old;
    S_Deleter _deleter_new;
    S_Deleter _deleter_old;
};

/**
 * @brief Class for wrapping tree sr_change_oper_t.
 * @class Tree_Change
 */
class Tree_Change
{
public:
    /** Constructor for an empty [sr_change_oper_t](@ref sr_change_oper_t).*/
    Tree_Change();
    ~Tree_Change();
    /** Getter for sr_change_oper_t. */
    sr_change_oper_t oper() {return _oper;};
    /** Getter for the node.*/
    libyang::S_Data_Node node();
    /** Getter for previous value. */
    const char *prev_value() {return _prev_value;};
    /** Getter for previous list. */
    const char *prev_list() {return _prev_list;};
    /** Getter for previous default. */
    bool prev_dflt() {return _prev_dflt;};

    friend class Session;

private:
    sr_change_oper_t _oper;
    const struct lyd_node *_node;
    const char *_prev_value;
    const char *_prev_list;
    bool _prev_dflt;
};

/** @} */

}

#endif
