/**
 * @defgroup rp_ns Request Processor's Node Stack
 * @{
 * @brief Provides stack of libyang data nodes.
 * @file rp_node_stack.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief
 *
 * @copyright
 * Copyright 2016 Cisco Systems, Inc.
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

#ifndef SRC_RP_NODE_STACK_H_
#define SRC_RP_NODE_STACK_H_

#include <libyang/libyang.h>
#include "sr_common.h"

typedef struct rp_node_stack_s{
    struct lyd_node *node;
    struct rp_node_stack_s *next;
} rp_node_stack_t;

/**
 * @brief Allocates and pushes an item to the stack
 * @param [in] stack
 * @param [in] node
 * @return err_code
 */
int rp_ns_push(rp_node_stack_t **stack, struct lyd_node *node);

/**
 * @brief Removes the item from top of the stack
 * @param [in] stack
 * @param [out] item
 * @return err_code
 */
int rp_ns_pop(rp_node_stack_t **stack, rp_node_stack_t **item);

/**
 * @brief Returns the pointer to the first item on the stack
 * @param [in] stack
 * @param [out] item
 * @return err_code
 */
int rp_ns_top(rp_node_stack_t **stack, rp_node_stack_t **item);

/**
 * @brief Test if the stack is empty
 * @param [in] stack
 * @return true if there are some items on the stack, false otherwise
 */
bool rp_ns_is_empty(rp_node_stack_t **stack);

/**
 * @brief Frees all values on stack
 * @param [in] stack
 */
int rp_ns_clean(rp_node_stack_t **stack);

/**
 * @}
 */
#endif /* SRC_RP_NODE_STACK_H_ */
