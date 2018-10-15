/**
 * @file Xpath.h
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @brief Sysrepo class header for C header xpath_utils.h.
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

#ifndef XPATH_H
#define XPATH_H

#include <iostream>

extern "C" {
#include "sysrepo/xpath.h"
}

namespace sysrepo {

/**
 * @defgroup classes C++/Python
 * @{
 */

/**
 * @brief Class for wrapping sr_xpath_ctx_t.
 * @class Xpath_Ctx
 */
class Xpath_Ctx
{
public:
    /** Constructor for an empty [sr_xpath_ctx_t](@ref sr_xpath_ctx_t).*/
    Xpath_Ctx();
    /** Getter for begining.*/
    char *begining() {if (_state != nullptr) return _state->begining; return nullptr;};
    /** Getter for current_node.*/
    char *current_node() {if (_state != nullptr) return _state->current_node; return nullptr;};
    /** Getter for replaced_position.*/
    char *replaced_position() {if (_state != nullptr) return _state->replaced_position; return nullptr;};
    /** Getter for replaced_char.*/
    char replaced_char() {if (_state != nullptr) return _state->replaced_char; return (char) 0;};
    ~Xpath_Ctx();
    /** Wrapper for [sr_xpath_next_node](@ref sr_xpath_next_node).*/
    char *next_node(char *xpath) {return sr_xpath_next_node(xpath, _state);};
    /** Wrapper for [sr_xpath_next_node_with_ns](@ref sr_xpath_next_node_with_ns).*/
    char *next_node_with_ns(char *xpath) {return sr_xpath_next_node_with_ns(xpath, _state);};
    /** Wrapper for [sr_xpath_next_key_name](@ref sr_xpath_next_key_name).*/
    char *next_key_name(char *xpath) {return sr_xpath_next_key_name(xpath, _state);};
    /** Wrapper for [sr_xpath_next_key_value](@ref sr_xpath_next_key_value).*/
    char *next_key_value(char *xpath) {return sr_xpath_next_key_value(xpath, _state);};
    /** Wrapper for [sr_xpath_node](@ref sr_xpath_node).*/
    char *node(char *xpath, const char *node_name) {return sr_xpath_node(xpath, node_name, _state);};
    /** Wrapper for [sr_xpath_node_rel](@ref sr_xpath_node_rel).*/
    char *node_rel(char *xpath, const char *node_name) {return sr_xpath_node_rel(xpath, node_name, _state);};
    /** Wrapper for [sr_xpath_node_idx](@ref sr_xpath_node_idx).*/
    char *node_idx(char *xpath, size_t index) {return sr_xpath_node_idx(xpath, index, _state);};
    /** Wrapper for [sr_xpath_node_idx_rel](@ref sr_xpath_node_idx_rel).*/
    char *node_idx_rel(char *xpath, size_t index) {return sr_xpath_node_idx_rel(xpath, index, _state);};
    /** Wrapper for [sr_xpath_node_key_value](@ref sr_xpath_node_key_value).*/
    char *node_key_value(char *xpath, const char *key) {return sr_xpath_node_key_value(xpath, key, _state);};
    /** Wrapper for [sr_xpath_node_key_value_idx](@ref sr_xpath_node_key_value_idx).*/
    char *node_key_value_idx(char *xpath, size_t index) {return sr_xpath_node_key_value_idx(xpath, index, _state);};
    /** Wrapper for [sr_xpath_key_value](@ref sr_xpath_key_value).*/
    char *key_value(char *xpath, const char *node_name, const char *key_name) {
                    return sr_xpath_key_value(xpath, node_name, key_name, _state);};
    /** Wrapper for [sr_xpath_key_value_idx](@ref sr_xpath_key_value_idx).*/
    char *key_value_idx(char *xpath, size_t node_index, size_t key_index) {
                        return sr_xpath_key_value_idx(xpath, node_index, key_index, _state);};
    /** Wrapper for [sr_xpath_last_node](@ref sr_xpath_last_node).*/
    char *last_node(char *xpath) {return sr_xpath_last_node(xpath, _state);};
    /** Wrapper for [sr_xpath_node_name](@ref sr_xpath_node_name).*/
    char *node_name(const char *xpath) {return sr_xpath_node_name(xpath);};
    /** Wrapper for [sr_xpath_node_name_eq](@ref sr_xpath_node_name_eq).*/
    bool node_name_eq(const char *xpath, const char *node_str) {return sr_xpath_node_name_eq(xpath, node_str);};
    /** Wrapper for [sr_xpath_recover](@ref sr_xpath_recover).*/
    void recover() {return sr_xpath_recover(_state);};

private:
    sr_xpath_ctx_t *_state;
};

/**@} */
}
#endif
