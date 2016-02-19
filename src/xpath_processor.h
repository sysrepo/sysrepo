/**
 * @defgroup xpath_process xPath Processor
 * @{
 * @brief xpath helpers for addressing the nodes
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

#include <string.h>
#include "xp_internal.h"
#include "sr_common.h"

#define _POSIX_C_SOURCE 200809L



/**
 * @brief The structure indexing xPath
 */
typedef struct xp_loc_id_s {
    xp_token_t *tokens; /**< The array of tokens type that can be found in the ::xp_loc_id_s#xpath */
    size_t *positions;  /**< Positions of ::xp_loc_id_s#tokens in ::xp_loc_id_s#xpath string */
    size_t cnt;         /**< Token count */
    size_t *node_index; /**< Positions of the ::T_NODE tokens in ::xp_loc_id_s#tokens */
    size_t node_count;  /**< Length of the ::xp_loc_id_s#node_index array*/
    char *xpath;        /**< xPath string value */
} xp_loc_id_t;

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

/**
 * @brief Returns true if the provided xpath identifies the whole moduel
 * @param [in] L pointer to ::xp_loc_id_t
 */
#define XP_IS_MODULE_XPATH(L) ((XP_MODULE_XPATH_TOKEN_COUNT == (L)->cnt) && (T_SLASH == XP_GET_TOKEN(L,0)) && (T_NS == XP_GET_TOKEN(L,1)) && (T_COLON == XP_GET_TOKEN(L,2)))

/**
 * @brief Returns the copy of the xpath up to the node. If the provided location id identifies whole module the whole xpath is duplicated
 * @param [in] L pointer to ::xp_loc_id_t
 * @param [in] ORD index of node
 */
#define XP_CPY_UP_TO_NODE(L, ORD) (XP_IS_MODULE_XPATH(L) ? strdup((L)->xpath) : strndup((L)->xpath, XP_GET_UP_TO_TOKEN_LENGTH(L, XP_GET_NODE_TOKEN(L, ORD))))

//NODES
/**@brief Returns the node count
 * @param [in] L pointer to ::xp_loc_id_t
 * @return size_t
 */
#define XP_GET_NODE_COUNT(L) (L->node_count)

/**@brief Returns the pointer to the position in xpath string. ORD must be in a valid range.
 * @param [in] L pointer to ::xp_loc_id_t
 * @param [in] ORD index of node
 * @return char*
 */
#define XP_GET_NODE_START(L,ORD) XP_GET_TOKEN_START(L,(L)->node_index[ORD])

/**@brief Returns the length of the node. ORD must be in a valid range.
 * @param [in] L pointer to ::xp_loc_id_t
 * @param [in] ORD index of node
 * @return size_t
 * */
#define XP_GET_NODE_LENGTH(L,ORD) XP_TOKEN_LENGTH(L, XP_GET_NODE_TOKEN(L, ORD))

/**@brief Returns the copied content of node's name. ORD must be in a valid range.
 * @param [in] L pointer to ::xp_loc_id_t
 * @param [in] ORD index of node
 * @return char* */
#define XP_CPY_NODE(L,ORD) XP_CPY_TOKEN(L,XP_GET_NODE_TOKEN(L,ORD))

/**@brief String compare of the ORD-th ::T_NODE token with VAL
 * @param [in] L pointer to ::xp_loc_id_t
 * @param [in] ORD index of node
 * @param [in] VAL to be compare with
 * @return true if nodes names are equal, false otherwise
 * */
#define XP_EQ_NODE(L,ORD,VAL) XP_EQ_TOKEN_STR(L,XP_GET_NODE_TOKEN(L,ORD),VAL)


//NAMESPACE
/**@brief Returns true if the node's namespace is explicitly specified
 * @param [in] L pointer to ::xp_loc_id_t
 * @param [in] NODE index of node
 * */
#define XP_HAS_NODE_NS(L,NODE) (XP_GET_NODE_TOKEN(L,NODE)>2 && XP_GET_TOKEN(L,XP_GET_NODE_TOKEN(L,NODE)-2)==T_NS)

/**@brief Returns the pointer to the position in xpath string where the namespace of NODE starts
 * @param [in] L pointer to ::xp_loc_id_t
 * @param [in] NODE index of node
 */
#define XP_GET_NODE_NS_START(L,NODE) XP_GET_TOKEN_START(L,XP_GET_NODE_NS_INDEX(L,NODE))

/**@brief Returns the node's namespace length.
 * @param [in] L pointer to ::xp_loc_id_t
 * @param [in] NODE index of node
 */
#define XP_GET_NODE_NS_LENGTH(L,NODE) XP_GET_TOKEN_LENGTH(L,XP_GET_NODE_NS_INDEX(L,NODE))

/**@brief Returns the copied content of the node's namespace
 * @param [in] L pointer to ::xp_loc_id_t
 * @param [in] NODE index of node
 */
#define XP_CPY_NODE_NS(L,NODE) XP_CPY_TOKEN(L,XP_GET_NODE_NS_INDEX(L,NODE))


/**
 * @brief Returns the copied content of the first namespace
 * @param [in] L pointer to ::xp_loc_id_t
 */
#define XP_CPY_FIRST_NS(L) XP_CPY_TOKEN(L, 1)

/**@brief String compare of node's namespace
 * @param [in] L pointer to ::xp_loc_id_t
 * @param [in] NODE index of node
 * @param [in] VAL value to be compared with
 * @return true if node namespaces are equal, false otherwise
 */
#define XP_EQ_NODE_NS(L,NODE,VAL) XP_EQ_TOKEN_STR(L,XP_GET_NODE_NS_INDEX(L,NODE),VAL)

/**@brief String compare of node's namespace
 * @param [in] L pointer to ::xp_loc_id_t
 * @param [in] NODE index of node
 * @param [in] VAL value to be compared with
 * @return return value of strncmp
 */
#define XP_CMP_NODE_NS(L,NODE,VAL) XP_CMP_TOKEN_STR(L,XP_GET_NODE_NS_INDEX(L,NODE),VAL)

/**
 * @briefString compare of the first namespace
 * @param [in] VAL value to be compared with
 * @return return value of strncmp
 */
#define XP_CMP_FIRST_NS(L,VAL) XP_CMP_TOKEN_STR(L,1,VAL)


//KEYS
/**@brief Returns the number of the keys for the node
 * @param [in] L pointer to ::xp_loc_id_t
 * @param [in] NODE index of node
 */
#define XP_GET_KEY_COUNT(L,NODE) xp_node_key_count(L,NODE)

/**@brief Returns true if the key names are explicitly specified
 * @param [in] L pointer to ::xp_loc_id_t
 * @param [in] NODE index of node
 */
#define XP_HAS_KEY_NAMES(L,NODE) (XP_GET_TOKEN(L,XP_GET_NODE_TOKEN(L,NODE)+2)==T_KEY_NAME)

/**@brief Returns the pointer to the position in xpath string where nodes's K'th keyname starts. All indexes must be in a valid range.
 * @param [in] L pointer to ::xp_loc_id_t
 * @param [in] NODE index of node
 * @param [in] K key index
 */
#define XP_GET_KEY_NAME_START(L,NODE,K) XP_GET_TOKEN_START(L,XP_GET_KEY_VALUE_INDEX(L,NODE,K))

/**@brief Returns the length NODES's K'th keyname. All indexes must be in a valid range.
 * @param [in] L pointer to ::xp_loc_id_t
 * @param [in] NODE index of node
 * @param [in] K key index
 */
#define XP_GET_KEY_NAME_LENGTH(L,NODE,K) XP_GET_TOKEN_LENGTH(L,XP_GET_KEY_NAME_INDEX(L,NODE,K))

/**@brief String compare of the NODES's K'th keyname. All indexes must be in a valid range.
 * @param [in] L pointer to ::xp_loc_id_t
 * @param [in] NODE index of node
 * @param [in] K key index
 * @return true if key names are equal, false otherwise
 */
#define XP_EQ_KEY_NAME(L,NODE,K,VAL) XP_EQ_TOKEN_STR(L,XP_GET_KEY_NAME_INDEX(L,NODE,K),VAL)

/**@brief Returns the copied content of the NODE's K'th keyname
 * @param [in] L pointer to ::xp_loc_id_t
 * @param [in] NODE index of node
 * @param [in] K key index
 */
#define XP_CPY_KEY_NAME(L,NODE,K) XP_CPY_TOKEN(L,XP_GET_KEY_NAME_INDEX(L,NODE,K))

/**@brief Returns the pointer to the position in xpath string where the NODES's K'th keyvalue starts. All indexes must be in a valid range.
 * @param [in] L pointer to ::xp_loc_id_t
 * @param [in] NODE index of node
 * @param [in] K key index
 */
#define XP_GET_KEY_VALUE_START(L,NODE,K) XP_GET_TOKEN_START(L,XP_GET_KEY_VALUE_INDEX(L,NODE,K))

/**@brief Returns the length of NODES's K'th keyvalue. All indexes must be in a valid range.
 * @param [in] L pointer to ::xp_loc_id_t
 * @param [in] NODE index of node
 * @param [in] K key index
 */
#define XP_GET_KEY_VALUE_LENGTH(L,NODE,K) XP_GET_TOKEN_LENGTH(L,XP_GET_KEY_VALUE_INDEX(L,NODE,K))

/**@brief String compare of the NODES's K'th keyvalue. All indexes must be in a valid range.
 * @param [in] L pointer to ::xp_loc_id_t
 * @param [in] NODE index of node
 * @param [in] K key index
 * @return true if key values are equal, false otherwise
 */
#define XP_EQ_KEY_VALUE(L,NODE,K,VAL) XP_EQ_TOKEN_STR(L,XP_GET_KEY_VALUE_INDEX(L,NODE,K),VAL)

/**@brief Returns the copied content of the NODE's K'th keyvalue
 * @param [in] L pointer to ::xp_loc_id_t
 * @param [in] NODE index of node
 * @param [in] K key index
 */
#define XP_CPY_KEY_VALUE(L,NODE,K) XP_CPY_TOKEN(L,XP_GET_KEY_VALUE_INDEX(L,NODE,K))
/**
 * @} xPath processor 
 */
#endif /* SRC_XPATH_PROCESSOR_H_ */
