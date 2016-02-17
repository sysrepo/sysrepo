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

/**@brief The number of token that is allocated at the beginning for a conversion*/
#define DEF_TOKEN_COUNT 50

/**@brief The xp_states of parsing xpath*/
enum xp_states {
    S_START,
    S_NS,
    S_NODE,
    S_KEY_NAME,
    S_KEY,
};

enum xp_keys_state {
    K_UNKNOWN,
    K_LISTED,
    K_OMITTED
};

/** @brief helper function return char representation of token*/
static char
xp_token_to_ch(xp_token_t t)
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
static char *
xp_token_to_str(xp_token_t t)
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

static sr_error_t
xp_validate_token_order(xp_token_t *tokens, size_t token_count, size_t *err_token)
{
    CHECK_NULL_ARG(err_token);
    xp_token_t curr = T_SLASH;
    xp_token_t t = tokens[0];
    if (t != T_SLASH)
        return SR_ERR_INVAL_ARG;
    if (token_count > 1 && T_NS != tokens[1]) {
        /* leading slash must be followed by T_NS token*/
        *err_token = 1;
        return SR_ERR_INVAL_ARG;
    }
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
            /* prevent the xpath like this /cont/list[k=']*/
            if (t == T_KEY_VALUE || (t == T_RSQB && tokens[i - 2] != T_EQUAL)) {
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
            if (t == T_NODE || (t == T_ZERO && (XP_MODULE_XPATH_TOKEN_COUNT-1) == i)) {
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
            curr = T_ZERO;
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

/**@brief check if all list keynames are specified or all is omitted */
static sr_error_t
xp_validate_list_nodes(xp_token_t *tokens, size_t token_count, size_t *err_token)
{
    CHECK_NULL_ARG(err_token);
    enum xp_keys_state k = K_UNKNOWN;
    bool key_name = false; /* set for each square bracket pair if the key_name is listed */

    for (size_t i = 1; i < token_count; i++) {
        xp_token_t curr = tokens[i];
        switch (curr) {
        case T_NODE:
            k = K_UNKNOWN;
            *err_token = i;
            break;
        case T_LSQB:
            key_name = false;
            break;
        case T_KEY_NAME:
            if (K_UNKNOWN == k) {
                k = K_LISTED;
            } else if (K_OMITTED == k) {
                return SR_ERR_INVAL_ARG;
            }
            key_name = true;
            break;
        case T_KEY_VALUE:
            if (K_UNKNOWN == k) {
                k = K_OMITTED;
            } else if (K_LISTED == k && !key_name) {
                return SR_ERR_INVAL_ARG;
            }
            break;
        default:
            break;
        }

    }
    *err_token = 0;
    return SR_ERR_OK;
}

/**
 * @brief if the last token is ::T_NS namespace it is changed to ::T_NODE node
 */
inline static void
xp_change_ns_to_node(const size_t cnt, xp_token_t *tokens, size_t *node_index, size_t *node_count)
{
    if (cnt > 0 && tokens[cnt - 1] == T_NS) {
        tokens[cnt - 1] = T_NODE;
        node_index[*node_count] = cnt - 1;
        (*node_count)++;
    }
}

sr_error_t
xp_char_to_loc_id(const char *xpath, xp_loc_id_t **loc)
{
    CHECK_NULL_ARG2(xpath, loc);
    size_t arr_size = DEF_TOKEN_COUNT;
    int rc = SR_ERR_INVAL_ARG;
    xp_token_t *tokens = NULL;
    size_t *positions = NULL;
    size_t *node_index = NULL;
    size_t cnt = 0;
    size_t i = 0;
    size_t node_count = 0;
    enum xp_states state = S_START;

    tokens = calloc(arr_size, sizeof(*tokens));
    positions = calloc(arr_size, sizeof(*positions));
    node_index = calloc(arr_size, sizeof(*node_index));
    if (NULL == tokens || NULL == positions || NULL == node_index) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    /* Saves the token type and marks the position */
#define MARK_TOKEN(T) do{tokens[cnt]=T; positions[cnt]=i;  cnt++;}while(0)

    /*parse the input xpath*/
    while (xpath[i] != '\0') {
        switch (state) {
        case S_START:
            if ('/' == xpath[i]) {
                MARK_TOKEN(T_SLASH);
                state = S_NS;
            } else {
                SR_LOG_ERR("Invalid lexem '%c' in xpath: %s at position %zu", xpath[i], xpath, i);
                goto cleanup;
            }
            break;
        case S_NS:
            if (':' == xpath[i]) {
                MARK_TOKEN(T_COLON);
                state = S_NODE;
            } else if ('/' == xpath[i]) {
                xp_change_ns_to_node(cnt, tokens, node_index, &node_count);
                MARK_TOKEN(T_SLASH);
                state = S_NS;
            } else if ('[' == xpath[i]) {
                xp_change_ns_to_node(cnt, tokens, node_index, &node_count);
                MARK_TOKEN(T_LSQB);
                state = S_KEY_NAME;
            } else if (cnt > 0 && tokens[cnt - 1] == T_NS) {
                if (!(isalnum(xpath[i]) || xpath[i] == '_' || xpath[i] == '-' || xpath[i] == '.')) {
                    SR_LOG_ERR("Invalid lexem '%c' in xpath: %s at position %zu", xpath[i], xpath, i);
                    goto cleanup;
                }
            } else {
                if (!(isalpha(xpath[i]) || xpath[i] == '_')) {
                    SR_LOG_ERR("Invalid lexem '%c' in xpath: %s at position %zu", xpath[i], xpath, i);
                    goto cleanup;
                }
            }
            break;
        case S_NODE:
            if ('[' == xpath[i]) {
                xp_change_ns_to_node(cnt, tokens, node_index, &node_count);
                MARK_TOKEN(T_LSQB);
                state = S_KEY_NAME;
            } else if ('/' == xpath[i]) {
                xp_change_ns_to_node(cnt, tokens, node_index, &node_count);
                MARK_TOKEN(T_SLASH);
                state = S_NS;
            } else if (cnt > 0 && tokens[cnt - 1] == T_NODE) {
                if (!(isalnum(xpath[i]) || xpath[i] == '_' || xpath[i] == '-' || xpath[i] == '.')) {
                    SR_LOG_ERR("Invalid lexem '%c' in xpath: %s at position %zu", xpath[i], xpath, i);
                    goto cleanup;
                }
            } else {
                if (!(isalpha(xpath[i]) || xpath[i] == '_')) {
                    SR_LOG_ERR("Invalid lexem '%c' in xpath: %s at position %zu", xpath[i], xpath, i);
                    goto cleanup;
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
                    goto cleanup;
                }
            } else {
                if (!(isalpha(xpath[i]) || xpath[i] == '_')) {
                    SR_LOG_ERR("Invalid lexem '%c' in xpath: %s at position %zu", xpath[i], xpath, i);
                    goto cleanup;
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
        if (cnt >= arr_size) {
            arr_size *= 2; /*double the allocated size*/
            xp_token_t *tokens_tmp = realloc(tokens, arr_size * sizeof(*tokens));
            size_t *positions_tmp = realloc(positions, arr_size * sizeof(*positions));
            size_t *node_index_tmp = realloc(node_index, arr_size * sizeof(*node_index));
            if (NULL == tokens_tmp || NULL == positions_tmp || NULL == node_index_tmp) {
                free(tokens_tmp);
                free(positions_tmp);
                free(node_index_tmp);
                rc = SR_ERR_NOMEM;
                SR_LOG_ERR_MSG("Memory allocation failed");
                goto cleanup;
            } else {
                positions = positions_tmp;
                tokens = tokens_tmp;
                node_index = node_index_tmp;
            }
        }

    }
    xp_change_ns_to_node(cnt, tokens, node_index, &node_count);
    MARK_TOKEN(T_ZERO);

    /*Validate token order*/
    size_t err_token = 0;
    if (xp_validate_token_order(tokens, cnt, &err_token) != SR_ERR_OK) {
        SR_LOG_ERR("Invalid token %s occured in xpath %s on position %zu.", xp_token_to_str(tokens[err_token]), xpath, positions[err_token]);
        goto cleanup;
    }

    if (xp_validate_list_nodes(tokens, cnt, &err_token) != SR_ERR_OK) {
        SR_LOG_ERR("Invalid list node occured in xpath %s on position %zu.", xpath, positions[err_token]);
        goto cleanup;
    }

    /*Allocate structure*/
    xp_loc_id_t *l = NULL;
    l = calloc(1, sizeof(*l));
    if (NULL == l) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }
    l->xpath = strdup(xpath);
    if (NULL == l->xpath) {
        free(l);
        SR_LOG_ERR_MSG("Memory allocation failed");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }
    l->cnt = cnt;
    l->node_count = node_count;

    /* shrink the space to the used length*/
    l->tokens = realloc(tokens, cnt * sizeof(*tokens));
    l->positions = realloc(positions, cnt * sizeof(*positions));
    l->node_index = realloc(node_index, node_count * sizeof(*node_index));
    if (NULL == l->tokens || NULL == l->positions || (NULL == l->node_index && 0 != node_count)) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        xp_free_loc_id(l);
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    *loc = l;
    return SR_ERR_OK;

cleanup:
    if (NULL != positions) {
        free(positions);
    }
    if (NULL != node_index) {
        free(node_index);
    }
    if (NULL != tokens) {
        free(tokens);
    }
    return rc;
}

void
xp_free_loc_id(xp_loc_id_t *l)
{
    if (l != NULL) {
        free(l->xpath);
        free(l->tokens);
        free(l->positions);
        free(l->node_index);
        free(l);
    }
}

sr_error_t
xp_print_location_id(const xp_loc_id_t *l)
{
    CHECK_NULL_ARG(l);
    puts(l->xpath);
    for (size_t i = 0; i < l->cnt; i++) {
        printf("%c\t%zu\n", xp_token_to_ch(l->tokens[i]), l->positions[i]);
    }
    return SR_ERR_OK;
}

int
xp_node_key_count(const xp_loc_id_t *l, size_t node)
{
    size_t token_index = XP_GET_NODE_TOKEN(l, node);
    int key_count = 0;
    while (XP_GET_TOKEN(l, token_index) != T_SLASH && XP_GET_TOKEN(l, token_index) != T_ZERO) {
        if (XP_GET_TOKEN(l, token_index) == T_KEY_VALUE) {
            key_count++;
        }
        token_index++;
    }
    return key_count;
}
