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

enum states {
    S_START, S_NS, S_NODE, S_KEY_NAME, S_KEY,
};

#define EOK 0
#define BAD_ALLOC 1
#define BAD_LEX 2
#define BAD_TOKEN 4
#define TOO_MANY_TOKENS 5

static char token_to_ch(xp_token_t t)
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

static xp_loc_id_p alloc_loction_id(char *xpath, size_t node_count, size_t token_count)
{
    xp_loc_id_p l = (xp_loc_id_p) malloc(sizeof(xp_loc_id_t));
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

static int validate_token_order(xp_token_t *tokens, size_t token_count)
{
    xp_token_t curr = T_SLASH;
    xp_token_t t = tokens[0];
    if (t != T_SLASH)
        return BAD_TOKEN;
    for (int i = 1; i < token_count; i++) {
        t = tokens[i];
        switch (curr) {
        case T_SLASH:
            if (t == T_NS || t == T_NODE) {
                curr = t;
            } else {
                return BAD_TOKEN;
            }
            break;
        case T_NODE:
            if (t == T_SLASH || t == T_LSQB || t == T_ZERO) {
                curr = t;
            } else {
                return BAD_TOKEN;
            }
            break;
        case T_LSQB:
            if (t == T_APOS || t == T_KEY_NAME) {
                curr = t;
            } else {
                return BAD_TOKEN;
            }
            break;
        case T_RSQB:
            if (t == T_LSQB || t == T_ZERO || t == T_SLASH) {
                curr = t;
            } else {
                return BAD_TOKEN;
            }
            break;
        case T_APOS:
            if (t == T_KEY_VALUE || t == T_RSQB) {
                curr = t;
            } else {
                return BAD_TOKEN;
            }
            break;
        case T_NS:
            if (t == T_COLON) {
                curr = t;
            } else {
                return BAD_TOKEN;
            }
            break;
        case T_KEY_NAME:
            if (t == T_EQUAL) {
                curr = t;
            } else {
                return BAD_TOKEN;
            }
            break;
        case T_KEY_VALUE:
            if (t == T_APOS) {
                curr = t;
            } else {
                return BAD_TOKEN;
            }
            break;
        case T_COLON:
            if (t == T_NODE) {
                curr = t;
            } else {
                return BAD_TOKEN;
            }
            break;
        case T_EQUAL:
            if (t == T_APOS) {
                curr = t;
            } else {
                return BAD_TOKEN;
            }
            break;
        case T_ZERO:
            break;
        default:
            return BAD_TOKEN;
        }
    }

    if (t != T_ZERO) {
        return BAD_TOKEN;
    }
    return EOK;
}

/**
 * if the last token is T_NS namespace it is changed to T_NODE node
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
int xp_char_to_loc_id(char *xpath, xp_loc_id_p *loc)
{
    xp_token_t tokens[MAX_TOKENS];
    size_t positions[MAX_TOKENS] = { 0, };
    size_t node_index[MAX_TOKENS] = { 0, };
    int cnt = 0;
    int i = 0;
    size_t node_count = 0;
    enum states state = S_START;

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
                if (!(isalpha(xpath[i]) || xpath[i] == '_' || xpath[i] == '-' || xpath[i] == '.')) {
                    return BAD_LEX;
                }
            } else {
                if (!(isalpha(xpath[i]) || xpath[i] == '_')) {
                    return BAD_LEX;
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
            } else if (cnt > 0 && tokens[cnt - 1] == T_NODE) {
                if (!(isalpha(xpath[i]) || xpath[i] == '_' || xpath[i] == '-' || xpath[i] == '.')) {
                    return BAD_LEX;
                }
            } else {
                if (!(isalpha(xpath[i]) || xpath[i] == '_')) {
                    return BAD_LEX;
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
            return TOO_MANY_TOKENS;
        }

    }
    change_ns_to_node(cnt, tokens, node_index, &node_count);
    MARK_TOKEN(T_ZERO);

    /*Validate token order*/
    if (validate_token_order(tokens, cnt) != EOK) {
        return BAD_TOKEN;
    }

    /*Allocate structure*/
    xp_loc_id_p l = alloc_loction_id(xpath, node_count, cnt);
    if (l == NULL) {
        return BAD_ALLOC;
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

void xp_free_loc_id(xp_loc_id_p l)
{
    free(l->xpath);
    free(l->tokens);
    free(l->positions);
    free(l->node_index);
    free(l);
}

void xp_print_location_id(const xp_loc_id_p l)
{
    if (l != NULL) {
        puts(l->xpath);
        for (int i = 0; i < l->cnt; i++) {
            printf("%c\t%d\n", token_to_ch(l->tokens[i]), (int) l->positions[i]);
        }
    }
}

int xp_node_key_count(xp_loc_id_p l, size_t node)
{
    size_t token_index = GET_NODE_TOKEN(l, node);
    int key_count = 0;
    while (GET_TOKEN(l,token_index) != T_SLASH && GET_TOKEN(l,token_index) != T_ZERO) {
        if (GET_TOKEN(l,token_index) == T_KEY_VALUE) {
            key_count++;
        }
        token_index++;
    }
    return key_count;
}
