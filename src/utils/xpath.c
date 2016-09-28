/**
 * @file xpath_utils.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 * @brief Sysrepo xpath util functions.
 *
 * @copyright
 * Copyright 2016 Cisco Systems, Inc.
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

#include <stdlib.h>
#include "sr_common.h"
#include "sysrepo/xpath.h"

static char *
sr_get_next_node_internal(char *xpath, sr_xpath_ctx_t *state, bool skip_namespace)
{
    char *index = NULL;
    if (NULL == state) {
        SR_LOG_ERR_MSG("NULL passed as state argument");
        return NULL;
    }

    if (NULL != xpath) {
        state->begining = xpath;
        state->current_node = NULL;
        state->replaced_position = xpath;
        state->replaced_char = *xpath;
    } else {
        sr_xpath_recover(state);
    }

    index = state->replaced_position;

    while (*index != 0 && *index != '/') {
        index++;
    }

    if (*index == 0) {
        /* end of input */
        return NULL;
    }

    state->current_node = index + 1;
    index++;

    while (*index != 0 && *index != '/' && *index != ':' && *index != '[') {
        index++;
    }

    if (*index == ':') {
        if (skip_namespace){
            /* skip namespace */
            state->current_node = index + 1;
            index++;
        }

        while (*index != 0 && *index != '/' && *index != '[') {
            index++;
        }
    }

    state->replaced_char = *index;
    state->replaced_position = index;
    (*index) = 0;

    return state->current_node;

}

char *
sr_xpath_next_node(char *xpath, sr_xpath_ctx_t *state)
{
    return sr_get_next_node_internal(xpath, state, true);
}

char *
sr_xpath_next_node_with_ns(char *xpath, sr_xpath_ctx_t *state)
{
    return sr_get_next_node_internal(xpath, state, false);
}

char *
sr_xpath_next_key_name(char *xpath, sr_xpath_ctx_t *state)
{
    char *index = NULL, *key = NULL;
    if (NULL == state) {
        SR_LOG_ERR_MSG("NULL passed as state argument");
        return NULL;
    }

    if (NULL != xpath) {
        state->begining = xpath;
        state->current_node = NULL;
        state->replaced_position = xpath;
        state->replaced_char = *xpath;
    } else {
        sr_xpath_recover(state);
    }

    index = state->replaced_position;


    while (*index != 0 && *index != '[' && *index != '/') {
        index++;
    }

    if (*index == 0 || *index == '/') {
        /* end of input or end of node */
        return NULL;
    }

    key = ++index;

    while (*index != 0 && *index != '=') {
        index++;
    }

    if (*index == '=') {
        state->replaced_char = *index;
        state->replaced_position = index;
        (*index) = 0;
    }

    return key;
}

char *
sr_xpath_next_key_value(char *xpath, sr_xpath_ctx_t *state)
{
    char *index = NULL, *value = NULL;
    if (NULL == state) {
        SR_LOG_ERR_MSG("NULL passed as state argument");
        return NULL;
    }

    if (NULL != xpath) {
        state->begining = xpath;
        state->current_node = NULL;
        state->replaced_position = xpath;
        state->replaced_char = *xpath;
    } else {
        sr_xpath_recover(state);
    }

    index = state->replaced_position;

    if (state->replaced_char == '\'') {
        index++;
    }


    while (*index != 0 && *index != '\'' && *index != '/') {
        index++;
    }

    if (*index == 0 || *index == '/') {
        /* end of input or end of node */
        return NULL;
    }

    value = ++index;

    while (*index != 0 && *index != '\'') {
        index++;
    }

    if (*index == '\'') {
        state->replaced_char = *index;
        state->replaced_position = index;
        (*index) = 0;
    }

    return value;
}

char *
sr_xpath_node(char *xpath, const char *node_name, sr_xpath_ctx_t *state)
{
    char *index = NULL;
    if (NULL == state || NULL == node_name || (NULL == state->begining && NULL == xpath)) {
        SR_LOG_ERR_MSG("NULL passed as node_name or state argument");
        return NULL;
    }

    if (NULL != xpath) {
        state->begining = xpath;
        state->current_node = NULL;
        state->replaced_position = xpath;
        state->replaced_char = *xpath;
    } else {
        sr_xpath_recover(state);
    }

    char *old_pos = state->replaced_position;
    char old_char = state->replaced_char;

    /* start search from the beginning */
    state->current_node = NULL;
    state->replaced_position = state->begining;
    state->replaced_char = *state->begining;

    while (NULL != (index = sr_xpath_next_node(NULL, state))) {
        if (0 == strcmp(node_name, index)) {
            break;
        }
    }

    if (NULL == index) {
        /* restore state in case of unsuccessful search */
        state->replaced_position = old_pos;
        state->replaced_char = old_char;
    }

    return index;

}

char *
sr_xpath_node_rel(char *xpath, const char *node_name, sr_xpath_ctx_t *state)
{
    char *index = NULL;
    if (NULL == state || NULL == node_name) {
        SR_LOG_ERR_MSG("NULL passed as node_name or state argument");
        return NULL;
    }

    if (NULL != xpath) {
        state->begining = xpath;
        state->current_node = NULL;
        state->replaced_position = xpath;
        state->replaced_char = *xpath;

    } else {
        sr_xpath_recover(state);
    }

    char *old_pos = state->replaced_position;
    char old_char = state->replaced_char;

    while (NULL != (index = sr_xpath_next_node(NULL, state))) {
        if (0 == strcmp(node_name, index)) {
            break;
        }
    }

    if (NULL == state->current_node) {
        /* restore state in case of unsuccessful search */
        state->replaced_position = old_pos;
        state->replaced_char = old_char;
    }

    return state->current_node;

}

char *
sr_xpath_node_idx(char* xpath, size_t index, sr_xpath_ctx_t* state)
{
    char *node = NULL;
    size_t cnt = 0;
    if (NULL == state || (NULL == state->begining && NULL == xpath)) {
        SR_LOG_ERR_MSG("NULL passed as state argument");
        return NULL;
    }

    if (NULL != xpath) {
        state->begining = xpath;
        state->current_node = NULL;
        state->replaced_position = xpath;
        state->replaced_char = *xpath;
    } else {
        sr_xpath_recover(state);
    }

    char *old_pos = state->replaced_position;
    char old_char = state->replaced_char;

    /* start search from the beginning */
    state->current_node = NULL;
    state->replaced_position = state->begining;
    state->replaced_char = *state->begining;

    while (NULL != (node = sr_xpath_next_node(NULL, state)) && cnt++ < index);

    if (NULL == node) {
        /* restore state in case of unsuccessful search */
        state->replaced_position = old_pos;
        state->replaced_char = old_char;
    }

    return node;
}

char *
sr_xpath_node_idx_rel(char* xpath, size_t index, sr_xpath_ctx_t* state)
{
    char *node = NULL;
    size_t cnt = 0;
    if (NULL == state) {
        SR_LOG_ERR_MSG("NULL passed as state argument");
        return NULL;
    }

    if (NULL != xpath) {
        state->begining = xpath;
        state->current_node = NULL;
        state->replaced_position = xpath;
        state->replaced_char = *xpath;
    } else {
        sr_xpath_recover(state);
    }

    char *old_pos = state->replaced_position;
    char old_char = state->replaced_char;

    while (NULL != (node = sr_xpath_next_node(NULL, state)) && cnt++ < index);

    if (NULL == node) {
        /* restore state in case of unsuccessful search */
        state->replaced_position = old_pos;
        state->replaced_char = old_char;
    }

    return node;
}

char *
sr_xpath_node_key_value(char *xpath, const char *key, sr_xpath_ctx_t *state)
{
    char *index = NULL, *key_xp = NULL;
    if (NULL == state || NULL == key) {
        SR_LOG_ERR_MSG("NULL passed as state or key argument");
        return NULL;
    }

    if (NULL != xpath) {
        state->begining = xpath;
        state->current_node = NULL;
        state->replaced_position = xpath;
        state->replaced_char = *xpath;
    } else {
        sr_xpath_recover(state);
    }

    char *old_pos = state->replaced_position;
    char old_char = state->replaced_char;

    if (NULL == state->current_node) {
        index = sr_xpath_next_node(NULL, state);
        sr_xpath_recover(state);
        if (NULL == index) {
            return NULL;
        }
    }

    state->replaced_position = state->current_node;
    state->replaced_char = *state->current_node;

    while (NULL != (key_xp = sr_xpath_next_key_name(NULL, state))) {
        if (0 == strcmp(key, key_xp)) {
            break;
        }
    }

    if (NULL == key_xp) {
        state->replaced_position = old_pos;
        state->replaced_char = old_char;
        return NULL;
    }

    return sr_xpath_next_key_value(NULL, state);
}

char *
sr_xpath_node_key_value_idx(char *xpath, size_t index, sr_xpath_ctx_t *state)
{
    char *res = NULL;
    size_t cnt = 0;
    if (NULL == state) {
        SR_LOG_ERR_MSG("NULL passed as state argument");
        return NULL;
    }

    if (NULL != xpath) {
        state->begining = xpath;
        state->current_node = NULL;
        state->replaced_position = xpath;
        state->replaced_char = *xpath;
    } else {
        sr_xpath_recover(state);
    }

    char *old_pos = state->replaced_position;
    char old_char = state->replaced_char;

    if (NULL == state->current_node) {
        res = sr_xpath_next_node(NULL, state);
        sr_xpath_recover(state);
        if (NULL == res) {
            return NULL;
        }
    }

    state->replaced_position = state->current_node;
    state->replaced_char = *state->current_node;

    while (NULL != (res = sr_xpath_next_key_name(NULL, state)) && cnt++ < index);

    if (NULL == res) {
        state->replaced_position = old_pos;
        state->replaced_char = old_char;
        return NULL;
    }

    return sr_xpath_next_key_value(NULL, state);
}

char *
sr_xpath_key_value(char *xpath, const char *node_name, const char *key_name, sr_xpath_ctx_t *state)
{
    char *res = NULL;
    if (NULL == state) {
        SR_LOG_ERR_MSG("NULL passed as state argument");
        return NULL;
    }

    if (NULL != xpath) {
        state->begining = xpath;
        state->current_node = NULL;
        state->replaced_position = xpath;
        state->replaced_char = *xpath;
    } else {
        sr_xpath_recover(state);
    }

    char *old_pos = state->replaced_position;
    char old_char = state->replaced_char;

    res = sr_xpath_node(NULL, node_name, state);

    if (NULL == res) {
        return NULL;
    }

    res = sr_xpath_node_key_value(NULL, key_name, state);

    if (NULL == res) {
        state->replaced_position = old_pos;
        state->replaced_char = old_char;
    }

    return res;

}

char *
sr_xpath_key_value_idx(char *xpath, size_t node_index, size_t key_index, sr_xpath_ctx_t *state)
{
    char *res = NULL;
    if (NULL == state) {
        SR_LOG_ERR_MSG("NULL passed as state argument");
        return NULL;
    }

    if (NULL != xpath) {
        state->begining = xpath;
        state->current_node = NULL;
        state->replaced_position = xpath;
        state->replaced_char = *xpath;
    } else {
        sr_xpath_recover(state);
    }

    char *old_pos = state->replaced_position;
    char old_char = state->replaced_char;

    res = sr_xpath_node_idx(NULL, node_index, state);

    if (NULL == res) {
        return NULL;
    }

    res = sr_xpath_node_key_value_idx(NULL, key_index, state);

    if (NULL == res) {
        state->replaced_position = old_pos;
        state->replaced_char = old_char;
    }

    return res;
}

char *
sr_xpath_last_node(char *xpath, sr_xpath_ctx_t *state)
{
    char *res = NULL;
    if (NULL == state) {
        SR_LOG_ERR_MSG("NULL passed as state argument");
        return NULL;
    }

    if (NULL != xpath) {
        state->begining = xpath;
        state->current_node = NULL;
        state->replaced_position = xpath;
        state->replaced_char = *xpath;
    } else {
        sr_xpath_recover(state);
    }

    while (NULL != (res = sr_xpath_next_node(NULL, state)));

    return state->current_node;
}


void sr_xpath_recover(sr_xpath_ctx_t *state)
{
    if (NULL != state) {
       if (NULL != state->replaced_position) {
           *state->replaced_position = state->replaced_char;
       }
    }
}

char *
sr_xpath_node_name(const char *xpath)
{
    char *res = NULL;
    if (NULL != xpath) {
        res = rindex(xpath, '/');
        if (NULL != res){
            res++;
        }
    }
    return res;
}
