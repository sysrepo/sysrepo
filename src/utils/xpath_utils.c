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
#include "xpath_utils.h"

char *
sr_get_next_node(char *xpath, sr_address_state_t *state)
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
        sr_recover_parsed_input(state);
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
        /* skip namespace */
        state->current_node = index + 1;
        index++;
        
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
sr_get_node(char *xpath, const char *node_name, sr_address_state_t *state)
{
    char *index = NULL;
    if (NULL == state || NULL == node_name) {
        SR_LOG_ERR_MSG("NULL passed as node_name or state argument");
        return NULL;
    }
    
    if (NULL != xpath) {
        state->begining = xpath;
    } else {
        sr_recover_parsed_input(state);
    
    }
    
    char *old_pos = state->replaced_position;
    char old_char = state->replaced_char;
    
    /* start search from the beginning */
    state->current_node = NULL;
    state->replaced_position = state->begining;
    state->replaced_char = *state->begining;
        
    while (NULL != (index = sr_get_next_node(NULL, state))) {
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
sr_get_node_rel(char *xpath, const char *node_name, sr_address_state_t *state)
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
        sr_recover_parsed_input(state);
    }
    
    char *old_pos = state->replaced_position;
    char old_char = state->replaced_char;
        
    while (NULL != (index = sr_get_next_node(NULL, state))) {
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

void sr_recover_parsed_input(sr_address_state_t *state)
{
    if (NULL != state) {
       if (NULL != state->replaced_position) {
           *state->replaced_position = state->replaced_char;
       }
    }
}
