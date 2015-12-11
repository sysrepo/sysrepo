/**
 * @defgroup xpath_process xPath processor
 * @{
 * @file xpath_processor.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief xPath helpers for addressing the nodes
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


#ifndef SRC_XPATH_PROCESSOR_H_
#define SRC_XPATH_PROCESSOR_H_

/**@brief Maximum number of tokens location_id can contain*/
#define MAX_TOKENS 500

#include <string.h>
#include "sr_common.h"
#define _POSIX_C_SOURCE 200809L

/**
 * @brief Enum of tokens that can be found in xpath
 */
typedef enum xp_token_e{
    T_NS,               /**< Namespace token*/
    T_NODE,             /**< Node(leaf,container,list) token */
    T_KEY_NAME,         /**< Name of the key list token*/
    T_KEY_VALUE,        /**< Value of the key list token*/

    T_SLASH,            /**< Slash tokens between the nodes*/
    T_COLON,            /**< Colon token separating the namespace and the node*/
    T_LSQB,             /**< Left square bracket */
    T_EQUAL,            /**< Equal sign token between key value and key name*/
    T_RSQB,             /**< Right square bracket */
    T_APOS,             /**< Apostrophe surrounding the key value*/
    T_ZERO,             /**< Ending zero char*/

}xp_token_t;

/**
 * @brief The structure indexing xPath
 */
typedef struct xp_loc_id_s{
    xp_token_t *tokens; /**< The array of tokens type that can be found in the ::xp_loc_id_s#xpath */
    size_t *positions;  /**< Positions of ::xp_loc_id_s#tokens in ::xp_loc_id_s#xpath string */
    size_t cnt;         /**< Token count */
    size_t *node_index; /**< Positions of the ::T_NODE tokens in ::xp_loc_id_s#tokens */
    size_t node_count;  /**< Length of the ::xp_loc_id_s#node_index array*/
    char *xpath;        /**< xPath string value */
}xp_loc_id_t;

/**
 * @brief Transforms the xpath string to xp_loc_id structure for
 * faster access to the parts of it
 * @param [in] xpath
 * @param [out] loc
 * @return err_code
 */
sr_error_t xp_char_to_loc_id(const char *xpath, xp_loc_id_t **loc);

/**
 * @brief Frees the xp_loc_id structure. If null is passed to the function, nothing is done
 * @param [in] l
 */
void xp_free_loc_id(xp_loc_id_t *l);

/**
 * @brief Returns the number of keys for node
 * @param [in] l
 * @param [in] node
 */
int xp_node_key_count(const xp_loc_id_t *l, const size_t node);

/**
 * @brief Prints the location_id for debug purposes
 * @param [in] l
 * @return err_code
 */
sr_error_t xp_print_location_id(const xp_loc_id_t *l);

/*
 * -start returns pointer to XPATH
 * -token return value of token
 * -index integer
 * -length return integer
 */

/**@brief Returns ORD-th token from ::xp_loc_id_t. ORD must be in a valid range.*/
#define XP_GET_TOKEN(L,ORD) ((L)->tokens[ORD])
/**@brief Returns ORD-th ::T_NODE token. ORD must be in a valid range. */
#define XP_GET_NODE_TOKEN(L,ORD) ((L)->node_index[ORD])
/**@brief Returns the pointer to the position in ::xp_loc_id_t#xpath referenced by ORD-th token. ORD must be in a valid range.*/
#define XP_GET_TOKEN_START(L, ORD) (&(L)->xpath[(L)->positions[ORD]])
/**@brief Returns the pointer to the position in ::xp_loc_id_t#xpath referenced by ORD-th ::T_NODE token. ORD must be in a valid range.*/
#define XP_GET_NODE_START(L,ORD) XP_GET_TOKEN_START(L,(L)->node_index[ORD])

/**@brief Returns the length of the ORD-th token. ORD must be in a valid range. */
#define XP_TOKEN_LENGTH(L,ORD) ((L)->positions[ORD+1] - (L)->positions[ORD])
/**@brief Returns the length of the ORD-th ::T_NODE token. ORD must be in a valid range. */
#define XP_NODE_LENGTH(L,ORD) XP_TOKEN_LENGTH(L, XP_GET_NODE_TOKEN(L, ORD))
/**@brief Returns the copied content of the ORD-th. ORD must be in a valid range. */
#define XP_CPY_TOKEN(L,ORD) (strndup(XP_GET_TOKEN_START(L,ORD),XP_TOKEN_LENGTH(L,ORD)))

/**@brief String compare of the ORD-th token with VAL */
#define XP_CMP_TOKEN_STR(L,ORD,VAL) (strncmp(XP_GET_TOKEN_START(L,ORD),(VAL), XP_TOKEN_LENGTH(L,ORD)) ==0)
/**@brief String compare of the ORD-th ::T_NODE token with VAL*/
#define XP_CMP_NODE(L,ORD,VAL) (strncmp(XP_GET_NODE_START(L,ORD), (VAL), XP_NODE_LENGTH(L,ORD) ) == 0)


//NAMESPACE
#define HAS_NS(L,NODE) (XP_GET_NODE_TOKEN(L,NODE)>2 && XP_GET_TOKEN(L,XP_GET_NODE_TOKEN(L,NODE)-2)==T_NS)
#define GET_NODE_NS_INDEX(L,NODE) (XP_GET_NODE_TOKEN(L,NODE)-2)
#define COMPARE_NODE_NS(L,NODE,VAL) XP_CMP_TOKEN_STR(L,GET_NODE_NS_INDEX(L,NODE),VAL)

//KEYS (Key names are mandatory)
#define HAS_KEY_NAMES(L,NODE) (XP_GET_TOKEN(L,XP_GET_NODE_TOKEN(L,NODE)+2)==T_KEY_NAME)
#define GET_KEY_NAME_INDEX(L,NODE,K) (XP_GET_NODE_TOKEN(L,NODE)+(K)*7+2)
#define GET_KEY_VALUE_INDEX(L,NODE,K) (HAS_KEY_NAMES(L,NODE) ? (XP_GET_NODE_TOKEN(L,NODE)+(K)*7+5) : (XP_GET_NODE_TOKEN(L,NODE)+(K)*5+3))
#define COMPARE_KEY_NAME(L,NODE,K,VAL) XP_CMP_TOKEN_STR(L,GET_KEY_NAME_INDEX(L,NODE,K),VAL)
#define COMPARE_KEY_VALUE(L,NODE,K,VAL) XP_CMP_TOKEN_STR(L,GET_KEY_VALUE_INDEX(L,NODE,K),VAL)
/**@} xPath processor */
#endif /* SRC_XPATH_PROCESSOR_H_ */
