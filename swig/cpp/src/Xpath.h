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

using namespace std;

class Xpath_Ctx:public Throw_Exception
{
public:
    Xpath_Ctx();
    Xpath_Ctx(sr_xpath_ctx_t *state);
    ~Xpath_Ctx();
    char *next_node(char *xpath) {return sr_xpath_next_node(xpath, _state);};
    char *next_node_with_ns(char *xpath) {return sr_xpath_next_node_with_ns(xpath, _state);};
    char *next_key_name(char *xpath) {return sr_xpath_next_key_name(xpath, _state);};
    char *next_key_value(char *xpath) {return sr_xpath_next_key_value(xpath, _state);};
    char *node(char *xpath, const char *node_name) {return sr_xpath_node(xpath, node_name, _state);};
    char *node_rel(char *xpath, const char *node_name) {return sr_xpath_node_rel(xpath, node_name, _state);};
    char *node_idx(char *xpath, size_t index) {return sr_xpath_node_idx(xpath, index, _state);};
    char *node_idx_rel(char *xpath, size_t index) {return sr_xpath_node_idx_rel(xpath, index, _state);};
    char *node_key_value(char *xpath, const char *key) {return sr_xpath_node_key_value(xpath, key, _state);};
    char *node_key_value_idx(char *xpath, size_t index) {return sr_xpath_node_key_value_idx(xpath, index, _state);};
    char *key_value(char *xpath, const char *node_name, const char *key_name) {
                    return sr_xpath_key_value(xpath, node_name, key_name, _state);};
    char *key_value_idx(char *xpath, size_t node_index, size_t key_index) {
                        return sr_xpath_key_value_idx(xpath, node_index, key_index, _state);};
    char *last_node(char *xpath) {return sr_xpath_last_node(xpath, _state);};
    char *node_name(const char *xpath) {return sr_xpath_node_name(xpath);};
    void recover() {return sr_xpath_recover(_state);};

private:
    sr_xpath_ctx_t *_state;
    bool _free;
};

#endif
