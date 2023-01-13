/**
 * @file xpath.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Sysrepo xpath util functions.
 *
 * @copyright
 * Copyright (c) 2018 - 2021 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "xpath.h"

#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "config.h"

static char *
sr_get_next_node_internal(char *xpath, sr_xpath_ctx_t *state, int skip_namespace)
{
    char *index = NULL, *quot = NULL;

    if (NULL == state) {
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
    if ((state->replaced_char == '\'') || (state->replaced_char == '\"')) {
        index++;
    }

    while (*index != 0 && (quot != NULL || *index != '/')) {
        if ((quot != NULL) && (*index == *quot)) {
            /* quote ended */
            quot = NULL;
        } else if ((quot == NULL) && ((*index == '\'') || (*index == '\"'))) {
            quot = index;
        }
        index++;
    }

    if (*index == 0) {
        /* end of input */
        return NULL;
    }

    state->current_node = index + 1;
    index++;

    while (*index != 0 && (quot != NULL || (*index != '/' && *index != ':' && *index != '['))) {
        index++;
    }

    if (*index == ':') {
        if (skip_namespace) {
            /* skip namespace */
            state->current_node = index + 1;
            index++;
        }

        while (*index != 0 && (quot != NULL || (*index != '/' && *index != '['))) {
            index++;
        }
    }

    state->replaced_char = *index;
    state->replaced_position = index;
    (*index) = 0;

    return state->current_node;

}

API char *
sr_xpath_next_node(char *xpath, sr_xpath_ctx_t *state)
{
    return sr_get_next_node_internal(xpath, state, 1);
}

API char *
sr_xpath_next_node_with_ns(char *xpath, sr_xpath_ctx_t *state)
{
    return sr_get_next_node_internal(xpath, state, 0);
}

API char *
sr_xpath_next_key_name(char *xpath, sr_xpath_ctx_t *state)
{
    char *index = NULL, *key = NULL, *quot = NULL;

    if (NULL == state) {
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
    if ((state->replaced_char == '\'') || (state->replaced_char == '\"')) {
        index++;
    }

    while (*index != 0 && (quot != NULL || (*index != '[' && *index != '/'))) {
        if ((quot != NULL) && (*index == *quot)) {
            /* quote ended */
            quot = NULL;
        } else if ((quot == NULL) && ((*index == '\'') || (*index == '\"'))) {
            quot = index;
        }
        index++;
    }

    if ((*index == 0) || (*index == '/')) {
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

API char *
sr_xpath_next_key_value(char *xpath, sr_xpath_ctx_t *state)
{
    char *index = NULL, *value = NULL, *val_quot = NULL;

    if (NULL == state) {
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
    if ((state->replaced_char == '\'') || (state->replaced_char == '\"')) {
        index++;
    }

    while (*index != 0 && *index != '\'' && *index != '\"' && *index != '/') {
        index++;
    }

    if ((*index == 0) || (*index == '/')) {
        /* end of input or end of node */
        return NULL;
    }

    val_quot = index;
    value = ++index;

    while (*index != 0 && *index != *val_quot) {
        index++;
    }

    if (*index == *val_quot) {
        state->replaced_char = *index;
        state->replaced_position = index;
        (*index) = 0;
    }

    return value;
}

API char *
sr_xpath_node(char *xpath, const char *node_name, sr_xpath_ctx_t *state)
{
    char *index = NULL;

    if ((NULL == state) || (NULL == node_name) || ((NULL == state->begining) && (NULL == xpath))) {
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

API char *
sr_xpath_node_rel(char *xpath, const char *node_name, sr_xpath_ctx_t *state)
{
    char *index = NULL;

    if ((NULL == state) || (NULL == node_name)) {
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

API char *
sr_xpath_node_idx(char *xpath, size_t index, sr_xpath_ctx_t *state)
{
    char *node = NULL;
    size_t cnt = 0;

    if ((NULL == state) || ((NULL == state->begining) && (NULL == xpath))) {
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

    while (NULL != (node = sr_xpath_next_node(NULL, state)) && cnt++ < index) {}

    if (NULL == node) {
        /* restore state in case of unsuccessful search */
        state->replaced_position = old_pos;
        state->replaced_char = old_char;
    }

    return node;
}

API char *
sr_xpath_node_idx_rel(char *xpath, size_t index, sr_xpath_ctx_t *state)
{
    char *node = NULL;
    size_t cnt = 0;

    if (NULL == state) {
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

    while (NULL != (node = sr_xpath_next_node(NULL, state)) && cnt++ < index) {}

    if (NULL == node) {
        /* restore state in case of unsuccessful search */
        state->replaced_position = old_pos;
        state->replaced_char = old_char;
    }

    return node;
}

API char *
sr_xpath_node_key_value(char *xpath, const char *key, sr_xpath_ctx_t *state)
{
    char *index = NULL, *key_xp = NULL;

    if ((NULL == state) || (NULL == key)) {
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

API char *
sr_xpath_node_key_value_idx(char *xpath, size_t index, sr_xpath_ctx_t *state)
{
    char *res = NULL;
    size_t cnt = 0;

    if (NULL == state) {
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

    while (NULL != (res = sr_xpath_next_key_name(NULL, state)) && cnt++ < index) {}

    if (NULL == res) {
        state->replaced_position = old_pos;
        state->replaced_char = old_char;
        return NULL;
    }

    return sr_xpath_next_key_value(NULL, state);
}

API char *
sr_xpath_key_value(char *xpath, const char *node_name, const char *key_name, sr_xpath_ctx_t *state)
{
    char *res = NULL;

    if (NULL == state) {
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

API char *
sr_xpath_key_value_idx(char *xpath, size_t node_index, size_t key_index, sr_xpath_ctx_t *state)
{
    char *res = NULL;

    if (NULL == state) {
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

API char *
sr_xpath_last_node(char *xpath, sr_xpath_ctx_t *state)
{
    char *res = NULL;

    if (NULL == state) {
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

    while (NULL != (res = sr_xpath_next_node(NULL, state))) {}

    return state->current_node;
}

API char *
sr_xpath_node_name(const char *xpath)
{
    const char *res = NULL, *quot = NULL;

    if (NULL != xpath) {
        res = xpath + strlen(xpath) - 1;
        while (res != xpath && (quot != NULL || *res != '/')) {
            if ((quot != NULL) && (*res == *quot)) {
                /* quote ended */
                quot = NULL;
            } else if ((quot == NULL) && ((*res == '\'') || (*res == '\"'))) {
                quot = res;
            }
            --res;
        }
        if (res == xpath) {
            res = NULL;
        } else {
            ++res;
        }
    }

    return (char *)res;
}

API int
sr_xpath_node_name_eq(const char *xpath, const char *node_name)
{
    char *xp_node_name = NULL;

    xp_node_name = sr_xpath_node_name(xpath);

    if ((NULL == xp_node_name) || (NULL == node_name)) {
        return 0;
    } else {
        return 0 == strcmp(xp_node_name, node_name);
    }
}

API void
sr_xpath_recover(sr_xpath_ctx_t *state)
{
    if (NULL != state) {
        if (NULL != state->replaced_position) {
            *state->replaced_position = state->replaced_char;
        }
    }
}
