/**
 * @file xp_internal.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief 
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


#ifndef SRC_XP_INTERNAL_H_
#define SRC_XP_INTERNAL_H_

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
 * @brief Number of token in xpath for module T_SLASH, T_NS, T_COLON, T_ZERO
 * e.g: "/module:"
 */
#define XP_MODULE_XPATH_TOKEN_COUNT 4

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

/**@brief Returns the length of the ORD-th token. ORD must be in a valid range. */
#define XP_GET_TOKEN_LENGTH(L,ORD) ((L)->positions[ORD+1] - (L)->positions[ORD])

/**@brief Returns the length up to the ORD-th token. ORD must be in a valid range. */
#define XP_GET_UP_TO_TOKEN_LENGTH(L,ORD) ((L)->positions[ORD+1] - (L)->positions[0])


/**@brief Returns the copied content of the ORD-th token . ORD must be in a valid range. */
#define XP_CPY_TOKEN(L,ORD) (strndup(XP_GET_TOKEN_START(L,ORD),XP_GET_TOKEN_LENGTH(L,ORD)))

/**@brief String compare of the ORD-th token with VAL, returns true by match, false otherwise */
#define XP_EQ_TOKEN_STR(L,ORD,VAL) (strncmp(XP_GET_TOKEN_START(L,ORD),(VAL), XP_GET_TOKEN_LENGTH(L,ORD)) == 0)

/**@brief String compare of the ORD-th token with VAL, returns the return value of strncmp */
#define XP_CMP_TOKEN_STR(L,ORD,VAL) (strncmp(XP_GET_TOKEN_START(L,ORD),(VAL), XP_GET_TOKEN_LENGTH(L,ORD)))

#define XP_GET_NODE_NS_INDEX(L,NODE) (XP_GET_NODE_TOKEN(L,NODE)-2)

#define XP_GET_KEY_NAME_INDEX(L,NODE,K) (XP_GET_NODE_TOKEN(L,NODE)+(K)*7+2)

#define XP_GET_KEY_VALUE_INDEX(L,NODE,K) (XP_HAS_KEY_NAMES(L,NODE) ? (XP_GET_NODE_TOKEN(L,NODE)+(K)*7+5) : (XP_GET_NODE_TOKEN(L,NODE)+(K)*5+3))


#endif /* SRC_XP_INTERNAL_H_ */
