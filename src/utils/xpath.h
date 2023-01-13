/**
 * @file xpath.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Sysrepo helpers for node's address manipulation.
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

#ifndef SYSREPO_XPATH_H_
#define SYSREPO_XPATH_H_

#include "../sysrepo.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup utils_xpath XPath Processing Utilities
 * @{
 *
 * @brief Set of helpers working on a subset of xpath expressions used of node identification
 * Functions modify inputs arguments by placing termination zero at appropriate places to save up
 * string duplication. The state of processing is stored in ::sr_xpath_ctx_t opaque for user.
 * It allows to continue in processing where the processing stopped or recover processed input.
 *
 * Similarly to strtok function in all subsequent calls that is supposed to work with the same
 * input xpath must be NULL.
 *
 * @note All of these functions are quite inefficient! If that matters, it is best not to use them.
 */

/**
 * @brief State of xpath parsing. User must not modify nor rely on the content
 * of the structure.
 */
typedef struct sr_xpath_ctx_s {
    char *begining;          /**< Pointer to the begining of the processed string */
    char *current_node;      /**< Pointer to the currently processed node, used as a context for key search */
    char *replaced_position; /**< Pointer to the posistion where the last terminating 0 by was written */
    char replaced_char;      /**< Character that was overwritten by the last termination 0 */
} sr_xpath_ctx_t;

/**
 * @brief The function returns a pointer to  the following node. If xpath is
 * not NULL returns the first node name, otherwise returns the subsequent node
 * according to the state.
 *
 * The state is modified upon function successful return from function, so the subsequent
 * calls can continue in processing or xpath can be recovered by calling ::sr_xpath_recover.
 *
 * @note It writes terminating zero at the and of the node name.
 *
 * @note Skips the namespace if it is present to get node name qualified by namespace use ::sr_xpath_next_node_with_ns
 *
 * @param [in] xpath - xpath to be processed, can be NULL
 * @param [in] state
 * @return Pointer to the node name, NULL if there are no more node names
 */
char *sr_xpath_next_node(char *xpath, sr_xpath_ctx_t *state);

/**
 * @brief Returns pointer to the last node.
 * @param [in] xpath
 * @param [in] state
 * @return Pointer to the last node
 */
char *sr_xpath_last_node(char *xpath, sr_xpath_ctx_t *state);

/**
 * @brief Same as ::sr_xpath_next_node with the difference that namespace is included in result if present in xpath
 *
 * @param [in] xpath - xpath to be processed, can be NULL if the user wants to continue in processing of previous input
 * @param [in] state
 * @return Pointer to the node name including namespace, NULL if there are no more node names
 */
char *sr_xpath_next_node_with_ns(char *xpath, sr_xpath_ctx_t *state);

/**
 * @brief Returns the name of the next key at the current level in processed xpath.
 *
 * @param [in] xpath
 * @param [in] state
 * @return Pointer to the key name, NULL if there are no more keys at the current level
 */
char *sr_xpath_next_key_name(char *xpath, sr_xpath_ctx_t *state);

/**
 * @brief Returns the value of the next key at the current level in processed xpath.
 *
 * @param [in] xpath
 * @param [in] state
 * @return Pointer to the key value, NULL if there are no more keys at the current level
 */
char *sr_xpath_next_key_value(char *xpath, sr_xpath_ctx_t *state);

/**
 * @brief Returns a pointer to the node specified by name. It searches from the beginning of the xpath, returns first match.
 * Can be used to jump at the desired node xpath and subsequent analysis of key values.
 *
 * @param [in] xpath
 * @param [in] node_name
 * @param [in] state
 * @return Pointer to the node, NULL if the node with the specified name is not found
 */
char *sr_xpath_node(char *xpath, const char *node_name, sr_xpath_ctx_t *state);

/**
 * @brief Similar to ::sr_xpath_node. The difference is that search start at current node
 * according to the state.
 *
 * @param [in] xpath
 * @param [in] node_name
 * @param [in] state
 * @return Pointer to the node, NULL if the node with the specified name is not found
 */
char *sr_xpath_node_rel(char *xpath, const char *node_name, sr_xpath_ctx_t *state);

/**
 * @brief Returns node specified by index starting at the begin of expression.
 * First node has index 0.
 *
 * @param [in] xpath
 * @param [in] index
 * @param [in] state
 * @return Pointer to the specified node, NULL if the index is out of bounds
 */
char *sr_xpath_node_idx(char *xpath, size_t index, sr_xpath_ctx_t *state);

/**
 * @brief Return node specified by index. Following node has index zero.
 *
 * @param [in] xpath
 * @param [in] index
 * @param [in] state
 * @return Pointer to the specified node, NULL if the index is out of bounds
 */
char *sr_xpath_node_idx_rel(char *xpath, size_t index, sr_xpath_ctx_t *state);

/**
 * @brief Looks up the value for the key at the current level in xpath.
 *
 * @param [in] xpath
 * @param [in] key - key name to be looked up
 * @param [in] state
 * @return Key value, NULL if the key with the specified name is not found
 */
char *sr_xpath_node_key_value(char *xpath, const char *key, sr_xpath_ctx_t *state);

/**
 * @brief Looks up the value for the key at the current level in xpath specified by index.
 * First key has index zero.
 *
 * @param [in] xpath
 * @param [in] index
 * @param [in] state
 * @return Key value, NULL if the index is out of bound
 */
char *sr_xpath_node_key_value_idx(char *xpath, size_t index, sr_xpath_ctx_t *state);

/**
 * @brief Looks up the value of the key in a node specified by name.
 *
 * @param [in] xpath
 * @param [in] node_name
 * @param [in] key_name
 * @param [in] state
 * @return Pointer to the key value, NULL if not found
 */
char *sr_xpath_key_value(char *xpath, const char *node_name, const char *key_name, sr_xpath_ctx_t *state);

/**
 * @brief Looks up the value of the key in a node specified by index. First node has index zero.
 *
 * @param [in] xpath
 * @param [in] node_index
 * @param [in] key_index
 * @param [in] state
 * @return Pointer to the key value, NULL if not found or index out of bound
 */
char *sr_xpath_key_value_idx(char *xpath, size_t node_index, size_t key_index, sr_xpath_ctx_t *state);

/**
 * @brief Returns pointer to the string after the last slash in xpath (node name).
 *
 * @note The returned string can also contain namespace and/or key values
 * if they were specified for the last node in xpath.
 *
 * @param [in] xpath
 * @return Result, NULL in case of the slash was not found
 */
char *sr_xpath_node_name(const char *xpath);

/**
 * @brief Compares string after the last slash in xpath (node name) with provided string.
 *
 * @note The returned string can also contain namespace and/or key values
 * if they were specified for the last node in xpath.
 *
 * @param [in] xpath
 * @param [in] node_str String to test for equality.
 * @return true in case that the Node names are equal, false otherwise
 */
int sr_xpath_node_name_eq(const char *xpath, const char *node_str);

/**
 * @brief Recovers the xpath string to the original state (puts back the character
 * that was replaced by termination zero).
 *
 * @param [in] state
 */
void sr_xpath_recover(sr_xpath_ctx_t *state);

/** @} xpath_utils */

#ifdef __cplusplus
}
#endif

#endif /* SYSREPO_XPATH_H_ */
