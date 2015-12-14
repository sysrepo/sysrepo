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
#include "xp_internal.h"
#include "sr_common.h"

#define _POSIX_C_SOURCE 200809L



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

//NODES
/**@brief returns the node count*/
#define XP_GET_NODE_COUNT(L) (L->node_count)

/**@brief Returns the pointer to the position in ::xp_loc_id_t#xpath referenced by ORD-th ::T_NODE token. ORD must be in a valid range.*/
#define XP_GET_NODE_START(L,ORD) XP_GET_TOKEN_START(L,(L)->node_index[ORD])

/**@brief Returns the length of the ORD-th ::T_NODE token. ORD must be in a valid range. */
#define XP_GET_NODE_LENGTH(L,ORD) XP_TOKEN_LENGTH(L, XP_GET_NODE_TOKEN(L, ORD))

/**@brief Returns the copied content of the ORD-th T_NODE_TOKEN. ORD must be in a valid range. */
#define XP_CPY_NODE(L,ORD) XP_CPY_TOKEN(L,XP_GET_NODE_TOKEN(L,ORD))

/**@brief String compare of the ORD-th ::T_NODE token with VAL*/
#define XP_CMP_NODE(L,ORD,VAL) XP_CMP_TOKEN_STR(L,XP_GET_NODE_TOKEN(L,ORD),VAL)


//NAMESPACE
/**@brief Returns true if the NODE's namespace is explicitly specified*/
#define XP_HAS_NODE_NS(L,NODE) (XP_GET_NODE_TOKEN(L,NODE)>2 && XP_GET_TOKEN(L,XP_GET_NODE_TOKEN(L,NODE)-2)==T_NS)

/**@brief Returns the pointer to the position in ::xp_loc_id_t#xpath where the namespace of NODE starts*/
#define XP_GET_NODE_NS_START(L,NODE) XP_GET_TOKEN_START(L,XP_GET_NODE_NS_INDEX(L,NODE))

/**@brief Returns the NODE's namespace length.*/
#define XP_GET_NODE_NS_LENGTH(L,NODE) XP_GET_TOKEN_LENGTH(L,XP_GET_NODE_NS_INDEX(L,NODE))
/**@brief Returns the copied content of the NODE's namespace*/
#define XP_CPY_NODE_NS(L,NODE) XP_CPY_TOKEN(L,XP_GET_NODE_NS_INDEX(L,NODE))

/**@brief String compare of NODE's namespace*/
#define XP_CMP_NODE_NS(L,NODE,VAL) XP_CMP_TOKEN_STR(L,XP_GET_NODE_NS_INDEX(L,NODE),VAL)

//KEYS (Key names are mandatory)
/**@brief Return the number of the keys for the NODE*/
#define XP_GET_KEY_COUNT(L,NODE) xp_node_key_count(L,NODE)
/**@brief Returns true if the key names are explictly specified*/
#define XP_HAS_KEY_NAMES(L,NODE) (XP_GET_TOKEN(L,XP_GET_NODE_TOKEN(L,NODE)+2)==T_KEY_NAME)

/**@brief Returns the pointer to the position in ::xp_loc_id_t#xpath where NODES's K'th keyname starts. All indexes must be in a valid range.*/
#define XP_GET_KEY_NAME_START(L,NODE,K) XP_GET_TOKEN_START(L,XP_GET_KEY_VALUE_INDEX(L,NODE,K))
/**@brief Returns the length NODES's K'th keyname. All indexes must be in a valid range.*/
#define XP_GET_KEY_NAME_LENGTH(L,NODE,K) XP_GET_TOKEN_LENGTH(L,XP_GET_KEY_NAME_INDEX(L,NODE,K))
/**@brief String compare of the NODES's K'th keyname. All indexes must be in a valid range.*/
#define XP_CMP_KEY_NAME(L,NODE,K,VAL) XP_CMP_TOKEN_STR(L,XP_GET_KEY_NAME_INDEX(L,NODE,K),VAL)
/**@brief Returns the copied content of the NODE's K'th keyname*/
#define XP_CPY_KEY_NAME(L,NODE,K) XP_CPY_TOKEN(L,XP_GET_KEY_NAME_INDEX(L,NODE,K))

/**@brief Returns the pointer to the position in ::xp_loc_id_t#xpath where the NODES's K'th keyvalue starts. All indexes must be in a valid range. */
#define XP_GET_KEY_VALUE_START(L,NODE,K) XP_GET_TOKEN_START(L,XP_GET_KEY_VALUE_INDEX(L,NODE,K))
/**@brief Returns the length of NODES's K'th keyvalue. All indexes must be in a valid range.*/
#define XP_GET_KEY_VALUE_LENGTH(L,NODE,K) XP_GET_TOKEN_LENGTH(L,XP_GET_KEY_VALUE_INDEX(L,NODE,K))
/**@brief String compare of the NODES's K'th keyvalue. All indexes must be in a valid range.*/
#define XP_CMP_KEY_VALUE(L,NODE,K,VAL) XP_CMP_TOKEN_STR(L,XP_GET_KEY_VALUE_INDEX(L,NODE,K),VAL)
/**@brief Returns the copied content of the NODE's K'th keyvalue*/
#define XP_CPY_KEY_VALUE(L,NODE,K) XP_CPY_TOKEN(L,XP_GET_KEY_VALUE_INDEX(L,NODE,K))
/**@} xPath processor */
#endif /* SRC_XPATH_PROCESSOR_H_ */
