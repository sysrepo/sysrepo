/**
 * @file xpath_processor.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief xpath addressing helpers
 *
 * @copyright
 * Copyright 2015 Cisco Systems, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "xpath_processor.h"

/**@brief The xp_states of parsing xpath*/
enum xp_states {
    S_START,
    S_NS,
    S_NODE,
    S_KEY_NAME,
    S_KEY,
};


/** @brief helper function return char representation of token*/
static char xp_token_to_ch(xp_token_t t)
{
    switch (t) {
    case T_SLASH:
        return '/';
    case T_COLON:
        return ':';
    case T_LSQB:
        return '[';
    case T_RSQB:
        return ']';
    case T_APOS:
        return '\'';
    case T_KEY_NAME:
        return 'k';
    case T_KEY_VALUE:
        return 'v';
    case T_NS:
        return 'n';
    case T_NODE:
        return 'i';
    case T_EQUAL:
        return '=';
    case T_ZERO:
        return '0';
    default:
        return '-';
    }
}

/** @brief helper function return string representation of token*/
static char *xp_token_to_str(xp_token_t t)
{
    switch (t) {
    case T_SLASH:
        return "T_SLASH";
    case T_COLON:
        return "T_COLON";
    case T_LSQB:
        return "T_LSQB";
    case T_RSQB:
        return "T_RSQB";
    case T_APOS:
        return "T_APOS";
    case T_KEY_NAME:
        return "T_KEY_NAME";
    case T_KEY_VALUE:
        return "T_KEY_VALUE";
    case T_NS:
        return "T_NAMESPACE";
    case T_NODE:
        return "T_NODE";
    case T_EQUAL:
        return "T_EQUAL";
    case T_ZERO:
        return "T_ZERO";
    default:
        return "(UNKNOWN_TOKEN)";
    }
}

/**
 * Allocates xp_loc_id structure with specified token and node count.
 * @param [in] xpath
 * @param [in] node_count
 * @param [in] token_count
 * @return allocated structure or NULL in case of error
 */
static xp_loc_id_t* alloc_loction_id(const char *xpath, size_t node_count, size_t token_count)
{
    xp_loc_id_t *l = (xp_loc_id_t *) malloc(sizeof(xp_loc_id_t));
    if (l == NULL) {
        return l;
    }
    if (xpath != NULL) {
        l->xpath = strdup(xpath);
    } else {
        l->xpath = NULL;
    }
    l->positions = malloc(token_count * sizeof(size_t));
    l->tokens = malloc(token_count * sizeof(xp_token_t));
    l->cnt = token_count;
    l->node_index = malloc(node_count * sizeof(size_t));
    l->node_count = node_count;

    if (l->positions == NULL || l->tokens == NULL || l->node_index == NULL) {
        free(l->positions);
        free(l->tokens);
        free(l->node_index);
        free(l);
        l = NULL;
    }

    return l;
}

static sr_error_t validate_token_order(xp_token_t *tokens, size_t token_count, size_t *err_token)
{
    if(err_token == NULL){
        return SR_ERR_INVAL_ARG;
    }
    xp_token_t curr = T_SLASH;
    xp_token_t t = tokens[0];
    if (t != T_SLASH)
        return SR_ERR_INVAL_ARG;
    int i;
    for (i = 1; i < token_count; i++) {
        t = tokens[i];
        switch (curr) {
        case T_SLASH:
            if (t == T_NS || t == T_NODE) {
                curr = t;
            } else {
                *err_token = i;
                return SR_ERR_INVAL_ARG;
            }
            break;
        case T_NODE:
            if (t == T_SLASH || t == T_LSQB || t == T_ZERO) {
                curr = t;
            } else {
                *err_token = i;
                return SR_ERR_INVAL_ARG;
            }
            break;
        case T_LSQB:
            if (t == T_APOS || t == T_KEY_NAME) {
                curr = t;
            } else {
                *err_token = i;
                return SR_ERR_INVAL_ARG;
            }
            break;
        case T_RSQB:
            if (t == T_LSQB || t == T_ZERO || t == T_SLASH) {
                curr = t;
            } else {
                *err_token = i;
                return SR_ERR_INVAL_ARG;
            }
            break;
        case T_APOS:
            if (t == T_KEY_VALUE || t == T_RSQB) {
                curr = t;
            } else {
                *err_token = i;
                return SR_ERR_INVAL_ARG;
            }
            break;
        case T_NS:
            if (t == T_COLON) {
                curr = t;
            } else {
                *err_token = i;
                return SR_ERR_INVAL_ARG;
            }
            break;
        case T_KEY_NAME:
            if (t == T_EQUAL) {
                curr = t;
            } else {
                *err_token = i;
                return SR_ERR_INVAL_ARG;
            }
            break;
        case T_KEY_VALUE:
            if (t == T_APOS) {
                curr = t;
            } else {
                *err_token = i;
                return SR_ERR_INVAL_ARG;
            }
            break;
        case T_COLON:
            if (t == T_NODE) {
                curr = t;
            } else {
                *err_token = i;
                return SR_ERR_INVAL_ARG;
            }
            break;
        case T_EQUAL:
            if (t == T_APOS) {
                curr = t;
            } else {
                *err_token = i;
                return SR_ERR_INVAL_ARG;
            }
            break;
        case T_ZERO:
                curr=T_ZERO;
            break;
        default:
            *err_token = i;
            return SR_ERR_INVAL_ARG;
        }
    }

    if (t != T_ZERO) {
        *err_token = i;
        return SR_ERR_INVAL_ARG;
    }
    return SR_ERR_OK;
}

/**
 * @brief if the last token is ::T_NS namespace it is changed to ::T_NODE node
 */
inline static void change_ns_to_node(const size_t cnt, xp_token_t *tokens, size_t *node_index, size_t *node_count)
{
    if (cnt > 0 && tokens[cnt - 1] == T_NS) {
        tokens[cnt - 1] = T_NODE;
        node_index[*node_count] = cnt - 1;
        (*node_count)++;
    }
}
/**
 * TODO more tokens than MAX_TOKENS
 */
sr_error_t xp_char_to_loc_id(const char *xpath, xp_loc_id_t **loc)
{
    CHECK_NULL_ARG2(xpath, loc);
    xp_token_t tokens[MAX_TOKENS];
    size_t positions[MAX_TOKENS] = { 0, };
    size_t node_index[MAX_TOKENS] = { 0, };
    size_t cnt = 0;
    size_t i = 0;
    size_t node_count = 0;
    enum xp_states state = S_START;

    /* Saves the token type and marks the position */
#define MARK_TOKEN(T) do{tokens[cnt]=T; positions[cnt]=i;  cnt++;}while(0)

    /*parse the input xpath*/
    while (xpath[i] != '\0') {
        switch (state) {
        case S_START:
            if ('/' == xpath[i]) {
                MARK_TOKEN(T_SLASH);
                state = S_NS;
            }
            else{
                SR_LOG_ERR("Invalid lexem '%c' in xpath: %s at position %zu", xpath[i], xpath, i);
                                    return SR_ERR_INVAL_ARG;
            }
            break;
        case S_NS:
            if (':' == xpath[i]) {
                MARK_TOKEN(T_COLON);
                state = S_NODE;
            } else if ('/' == xpath[i]) {
                change_ns_to_node(cnt, tokens, node_index, &node_count);
                MARK_TOKEN(T_SLASH);
                state = S_NS;
            } else if ('[' == xpath[i]) {
                change_ns_to_node(cnt, tokens, node_index, &node_count);
                MARK_TOKEN(T_LSQB);
                state = S_KEY_NAME;
            } else if (cnt > 0 && tokens[cnt - 1] == T_NS) {
                if (!(isalnum(xpath[i]) || xpath[i] == '_' || xpath[i] == '-' || xpath[i] == '.')) {
                    SR_LOG_ERR("Invalid lexem '%c' in xpath: %s at position %zu", xpath[i], xpath, i);
                    return SR_ERR_INVAL_ARG;
                }
            } else {
                if (!(isalpha(xpath[i]) || xpath[i] == '_')) {
                    SR_LOG_ERR("Invalid lexem '%c' in xpath: %s at position %zu", xpath[i], xpath, i);
                    return SR_ERR_INVAL_ARG;
                }
            }
            break;
        case S_NODE:
            if ('[' == xpath[i]) {
                change_ns_to_node(cnt, tokens, node_index, &node_count);
                MARK_TOKEN(T_LSQB);
                state = S_KEY_NAME;
            } else if ('/' == xpath[i]) {
                change_ns_to_node(cnt, tokens, node_index, &node_count);
                MARK_TOKEN(T_SLASH);
                state = S_NS;
            } else if (cnt > 0 && tokens[cnt - 1] == T_KEY_NAME) {
                if (!(isalnum(xpath[i]) || xpath[i] == '_' || xpath[i] == '-' || xpath[i] == '.')) {
                    SR_LOG_ERR("Invalid lexem '%c' in xpath: %s at position %zu", xpath[i], xpath, i);
                    return SR_ERR_INVAL_ARG;
                }
            } else {
                if (!(isalpha(xpath[i]) || xpath[i] == '_')) {
                    SR_LOG_ERR("Invalid lexem '%c' in xpath: %s at position %zu", xpath[i], xpath, i);
                    return SR_ERR_INVAL_ARG;
                }
            }
            break;
        case S_KEY_NAME:
            if ('=' == xpath[i]) {
                MARK_TOKEN(T_EQUAL);
            } else if (']' == xpath[i]) {
                if (cnt > 0 && tokens[cnt - 1] == T_KEY_NAME) {
                    tokens[cnt - 1] = T_KEY_VALUE;
                }
                MARK_TOKEN(T_LSQB);
            } else if ('\'' == xpath[i]) {
                MARK_TOKEN(T_APOS);
                state = S_KEY;
            } else if (cnt > 0 && tokens[cnt - 1] == T_KEY_NAME) {
                if (!(isalnum(xpath[i]) || xpath[i] == '_' || xpath[i] == '-' || xpath[i] == '.')) {
                    SR_LOG_ERR("Invalid lexem '%c' in xpath: %s at position %zu", xpath[i], xpath, i);
                    return SR_ERR_INVAL_ARG;
                }
            } else {
                if (!(isalpha(xpath[i]) || xpath[i] == '_')) {
                    SR_LOG_ERR("Invalid lexem '%c' in xpath: %s at position %zu", xpath[i], xpath, i);
                    return SR_ERR_INVAL_ARG;
                }
            }
            break;
        case S_KEY:
            if (']' == xpath[i]) {
                MARK_TOKEN(T_RSQB);
                state = S_NODE;
            } else if ('\'' == xpath[i]) {
                MARK_TOKEN(T_APOS);
            }
            break;
        }

        /*check if we process character right after the token*/
        if (cnt > 0 && positions[cnt - 1] == (i - 1)) {
            if (state == S_NS && tokens[cnt - 1] != T_NS) {
                MARK_TOKEN(T_NS);
            } else if (state == S_NODE && tokens[cnt - 1] != T_NODE) {
                tokens[cnt] = T_NODE;
                positions[cnt] = i;
                node_index[node_count] = cnt;
                node_count++;
                cnt++;
            } else if (state == S_KEY_NAME && tokens[cnt - 1] != T_KEY_NAME) {
                MARK_TOKEN(T_KEY_NAME);
            } else if (state == S_KEY && tokens[cnt - 1] != T_KEY_VALUE) {
                MARK_TOKEN(T_KEY_VALUE);
            }
        }

        i++;
        if (cnt > MAX_TOKENS) {
            return SR_ERR_INVAL_ARG;
        }

    }
    change_ns_to_node(cnt, tokens, node_index, &node_count);
    MARK_TOKEN(T_ZERO);

    /*Validate token order*/
    size_t err_token=0;
    if (validate_token_order(tokens, cnt, &err_token) != SR_ERR_OK) {
        SR_LOG_ERR("Invalid token %s occured in xpath %s on position %zu.", xp_token_to_str(tokens[err_token]), xpath, positions[err_token]);
        return SR_ERR_INVAL_ARG;
    }

    /*Allocate structure*/
    xp_loc_id_t *l = alloc_loction_id(xpath, node_count, cnt);
    if (l == NULL) {
        SR_LOG_ERR_MSG("Cannot allocate memory for xp_loc_id_t.");
        return SR_ERR_NOMEM;
    }

    for (int j = 0; j < cnt; j++) {
        l->tokens[j] = tokens[j];
        l->positions[j] = positions[j];
    }
    for (int j = 0; j < node_count; j++) {
        l->node_index[j] = node_index[j];
    }

    *loc = l;
    return 0;
}

void xp_free_loc_id(xp_loc_id_t *l)
{
    if(l!=NULL){
        free(l->xpath);
        free(l->tokens);
        free(l->positions);
        free(l->node_index);
        free(l);
    }
}

sr_error_t xp_print_location_id(const xp_loc_id_t *l)
{
    CHECK_NULL_ARG(l);
    puts(l->xpath);
    for (size_t i = 0; i < l->cnt; i++) {
        printf("%c\t%zu\n", xp_token_to_ch(l->tokens[i]), l->positions[i]);
    }
    return SR_ERR_OK;
}

int xp_node_key_count(const xp_loc_id_t *l, size_t node)
{
    size_t token_index = XP_GET_NODE_TOKEN(l, node);
    int key_count = 0;
    while (XP_GET_TOKEN(l,token_index) != T_SLASH && XP_GET_TOKEN(l,token_index) != T_ZERO) {
        if (XP_GET_TOKEN(l,token_index) == T_KEY_VALUE) {
            key_count++;
        }
        token_index++;
    }
    return key_count;
}
