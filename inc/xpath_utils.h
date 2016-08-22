/**
 * @file addressing_utils.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo helpers for node's address manipulation.
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

#ifndef XPATH_UTILS_H
#define XPATH_UTILS_H

/** Set of helpers working on a subset of xpath expressions used of node identification
 *  Functions modify inputs arguments by placing termination zero at appropriate places to save up
 *  string duplication. The state of processing is stored in ::sr_address_state_t opaque for user.
 *  It allows to continue in processing where the processing stopped or recover processed input.
 *
 *  Similarly to strtok function in all susbsequent calls where the user want to continue
 *  in processing the same input xpath must be NULL.
 *
 *  @note Functions expects that node names and key values do not contain
 *  characters like ',[=/
 */

/**
 * State of xpath parsing. User is supposed to not modify nor rely on the content
 * of the structure.
 */
typedef struct sr_address_state_s {
    char *begining;          /**< Pointer to the begining of the processed string */
    char *current_node;      /**< Pointer to the currently processed node, used as a context for key search */
    char *replaced_position; /**< Pointer to the posistion where the last terminating 0 by was written */
    char replaced_char;      /**< Character that was overwrition by the last termination 0 */
} sr_address_state_t;

/**
 * @brief The function returns the pointer of the following node. If xpath is
 * not NULL returns the first node name, otherwise returns the subsequent node
 * according to the state.
 *
 * The state is modified upon function successful return from function, so the subsequent
 * calls can continue in processing or xpath can be recovered by calling ::sr_recover_parsed_input.
 *
 * @note Function skips the characters up to / (slash) or : (colon) if the namespace is specified.
 * It places terminating zero at the and of the node name.
 *
 *
 * @param [in] xpath - xpath to be processed, can be NULL
 * @param [in] state
 * @return Pointer to the node node name, NULL if there are no more node names
 */
char *sr_get_next_node(char *xpath, sr_address_state_t *state);

char *sr_get_next_node_with_ns(char *xpath, sr_address_state_t *state);

char *sr_get_next_key_name(char *xpath, sr_address_state_t *state);

char *sr_get_next_key_value(char *xpath, sr_address_state_t *state);


char *sr_get_node(char *xpath, const char *node_name, sr_address_state_t *state);

char *sr_get_node_rel(char *xpath, const char *node_name, sr_address_state_t *state);

/**
 * @brief Returns token specified by index starting at the begin of expression.
 * First node name has index 0.
 *
 * @param [in] xpath
 * @param [in] index
 * @param [in] state
 * @return
 */
char *sr_get_node_idx(char *xpath, size_t index, sr_address_state_t *state);

char *sr_get_node_idx_rel(char *xpath, size_t index, sr_address_state_t *state);


/* current node*/
char *sr_get_node_key_value(char *xpath, const char *key, sr_address_state_t *state);

char *sr_get_node_key_value_idx(char *xpath, size_t index, sr_address_state_t *state);


/* absolute */
char *sr_get_key_value(char *xpath, const char *node_name, const char *key_name, sr_address_state_t *state);

char *sr_get_key_value_idx(char *xpath, size_t node_index, size_t key_index, sr_address_state_t *state);


char *sr_get_last_node(char *xpath, sr_address_state_t *state);

/**
 * @brief
 * @param [in] xpath
 * @return Result, NULL in case of the slash was not found
 */
char *sr_xpath_node_name(const char *xpath);

/**
 * @brief Function puts back the character that was replaced by termination zero.
 *
 *
 * @param [in] state
 */
void sr_recover_parsed_input(sr_address_state_t *state);


#endif /* ADDRESSING_UTILS_H */

