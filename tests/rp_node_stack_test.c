/**
 * @file rp_node_stack_test.c
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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdlib.h>
#include <stdio.h>
#include "rp_node_stack.h"
#include "sr_common.h"



void rp_node_stack_test(void **state)
{
    rp_node_stack_t *stack = NULL;
    rp_node_stack_t *item = NULL;

    struct lyd_node *n = NULL;
    n = calloc(1, sizeof(*n));
    assert_non_null(n);

    /* check is_empty, cleanup*/
    assert_true(rp_ns_is_empty(&stack));
    assert_int_equal(SR_ERR_INVAL_ARG, rp_ns_pop(&stack, &item));
    assert_int_equal(SR_ERR_OK, rp_ns_top(&stack, &item));
    assert_null(item);
    rp_ns_clean(&stack);


    /* init, check, empty, push, pop, top, cleanup*/
    rp_ns_push(&stack, n);
    assert_false(rp_ns_is_empty(&stack));

    rp_ns_push(&stack, n);

    /* pop and free two items*/
    rp_ns_pop(&stack, &item);
    free(item);

    rp_ns_pop(&stack, &item);
    free(item);

    /* push item access item using top*/
    rp_ns_push(&stack, n);
    rp_ns_top(&stack, &item);
    assert_non_null(item);

    rp_ns_push(&stack, n);
    rp_ns_push(&stack, n);

    /* clean up removes all remaining items on stack*/
    rp_ns_clean(&stack);

    free(n);
}

int main(){

    const struct CMUnitTest tests[] = {
            cmocka_unit_test(rp_node_stack_test),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

