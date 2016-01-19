/**
 * @file rp_node_stack.c
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

#include "rp_node_stack.h"

int
rp_ns_push(rp_node_stack_t **stack, struct lyd_node *node){
    CHECK_NULL_ARG2(stack, node);
    rp_node_stack_t *item = NULL;
    item = calloc(1, sizeof(*item));
    if (NULL == item){
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }
    item->node = node;
    item->next = *stack;
    *stack = item;

    return SR_ERR_OK;
}

int
rp_ns_pop(rp_node_stack_t **stack, rp_node_stack_t **item){
    CHECK_NULL_ARG2(stack, item);
    if (NULL == *stack){
        *item = NULL;
        SR_LOG_ERR_MSG("Pop called on empty stack");
        return SR_ERR_INVAL_ARG;
    }
    *item = *stack;
    *stack = (*item)->next;
    (*item)->next = NULL;
    return SR_ERR_OK;
}

int
rp_ns_top(rp_node_stack_t **stack, rp_node_stack_t **item){
    CHECK_NULL_ARG2(stack, item);
    *item = *stack;
    return SR_ERR_OK;
}

bool
rp_ns_is_empty(rp_node_stack_t **stack){
    if (NULL == stack){
        return true;
    }
    return NULL == *stack;
}

int
rp_ns_clean(rp_node_stack_t **stack){
    CHECK_NULL_ARG(stack);

    rp_node_stack_t *item = NULL;
    while (!rp_ns_is_empty(stack)){
        rp_ns_pop(stack, &item);
        free(item);
        item = NULL;
    }
    *stack = NULL;
    return SR_ERR_OK;
}
