/**
 * @file xpath_processor.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief 
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

#define MAX_TOKENS 100

#include <string.h>
#define _POSIX_C_SOURCE 200809L


typedef enum token{
    NAMESPACE,
    NODE,
    KEY_NAME,
    KEY_VALUE,

    /*optional*/
    SLASH,
    COLON,
    LSQB,
    EQUAL,
    RSQB,
    APOSTROPH,
    ZERO,

}token_t;

typedef struct location_id_s{
    token_t *tokens;
    size_t *positions;
    size_t *node_index;
    size_t node_count;
    size_t cnt;
    char *xpath;
}location_id_t;
typedef location_id_t * location_id_p;


int xpath_to_location_id(char *xpath, location_id_p *loc);
void free_location_id(location_id_p l);

/*
 * -start returns pointer to XPATH
 * -token return value of token
 * -index integer
 * -length return integer
 *
 */

#define GET_TOKEN(L,ORD) ((L)->tokens[ORD])
#define GET_NODE_TOKEN(L,ORD) ((L)->node_index[ORD])
#define GET_TOKEN_START(L, ORD) (&(L)->xpath[(L)->positions[ORD]])
#define GET_NODE_START(L,ORD) GET_TOKEN_START(L,(L)->node_index[ORD])


#define TOKEN_LENGTH(L,ORD) ((L)->positions[ORD+1] - (L)->positions[ORD])
#define NODE_LENGTH(L,ORD) TOKEN_LENGTH(L, GET_NODE_TOKEN(L, ORD))

#define CPY_TOKEN(L,ORD) (strndup(GET_TOKEN_START(L,ORD),TOKEN_LENGTH(L,ORD)))

#define COMPARE_NODE(L,ORD,VAL) (strncmp(GET_NODE_START(L,ORD), (VAL), NODE_LENGTH(L,ORD) ) == 0)
#define COMPARE_TOKEN_STR(L,ORD,VAL) (strncmp(GET_TOKEN_START(L,ORD),(VAL), TOKEN_LENGTH(L,ORD)) ==0)

//NAMESPACE
#define HAS_NS(L,NODE) (GET_NODE_TOKEN(L,NODE)>2 && GET_TOKEN(L,GET_NODE_TOKEN(L,NODE)-2)==NAMESPACE)
#define GET_NODE_NS_INDEX(L,NODE) (GET_NODE_TOKEN(L,NODE)-2)
#define COMPARE_NODE_NS(L,NODE,VAL) COMPARE_TOKEN_STR(L,GET_NODE_NS_INDEX(L,NODE),VAL)

//KEYS (Key names are mandatory)
#define HAS_KEY_NAMES(L,NODE) (GET_TOKEN(L,GET_NODE_TOKEN(L,NODE)+2)==KEY_NAME)
#define GET_KEY_NAME_INDEX(L,NODE,K) (GET_NODE_TOKEN(L,NODE)+(K)*7+2)
#define GET_KEY_VALUE_INDEX(L,NODE,K) (HAS_KEY_NAMES(L,NODE) ? (GET_NODE_TOKEN(L,NODE)+(K)*7+5) : (GET_NODE_TOKEN(L,NODE)+(K)*5+3))
#define COMPARE_KEY_NAME(L,NODE,K,VAL) COMPARE_TOKEN_STR(L,GET_KEY_NAME_INDEX(L,NODE,K),VAL)
#define COMPARE_KEY_VALUE(L,NODE,K,VAL) COMPARE_TOKEN_STR(L,GET_KEY_VALUE_INDEX(L,NODE,K),VAL)


int node_key_count(location_id_p l, size_t node);

void print_location_id(location_id_p l);




#endif /* SRC_XPATH_PROCESSOR_H_ */
