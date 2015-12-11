/**
 * @file xpath_processor_parser.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief 
 *
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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdlib.h>
#include <stdio.h>
#include "xpath_processor.h"

#define XPATH_TO_PARSE "/model:container/list[k1='key1'][k2='key2']/leaf"


int setup(void **state){
    xp_loc_id_t *l;
    assert_int_equal(0, xp_char_to_loc_id(XPATH_TO_PARSE, &l));
    (*state) = (void *) l;
    return 0;
}

int teardown(void **state){
    xp_loc_id_t *l = (xp_loc_id_t *) *state;
    xp_free_loc_id(l);
    return 0;
}

void check_tokens(void **state){
    xp_loc_id_t *l = (xp_loc_id_t *) *state;
    assert_true(XP_GET_TOKEN(l,0)==T_SLASH);
    assert_true(XP_GET_TOKEN(l,1)==T_NS);
    assert_true(XP_GET_TOKEN(l,2)==T_COLON);
    assert_true(XP_GET_TOKEN(l,3)==T_NODE);
}

void check_nodes(void **state){
    xp_loc_id_t *l = (xp_loc_id_t *) *state;
    assert_true(l->node_count  == 3);

    assert_true(XP_CMP_NODE(l,0,"container"));
    assert_true(XP_CMP_NODE(l,1,"list"));
    assert_true(XP_CMP_NODE(l,2,"leaf"));

    assert_false(XP_CMP_NODE(l,0,"asfadsf"));

}

void check_ns(void **state){
    xp_loc_id_t *l = (xp_loc_id_t *) *state;

    assert_true(HAS_NS(l,0));
    assert_int_equal(1,GET_NODE_NS_INDEX(l,0));
    assert_true(COMPARE_NODE_NS(l,0,"model"));
    assert_false(COMPARE_NODE_NS(l,0,"asfaafafa"));
    assert_false(HAS_NS(l,1));

}

void check_keys(void **state){
    xp_loc_id_t *l = (xp_loc_id_t *) *state;
    assert_int_equal(xp_node_key_count(l,0),0);
    assert_int_equal(xp_node_key_count(l,1),2);

    assert_true(HAS_KEY_NAMES(l,1));

    assert_true(COMPARE_KEY_NAME(l,1,0,"k1"));
    assert_true(COMPARE_KEY_VALUE(l,1,0,"key1"));

    char *keyVal = XP_CPY_TOKEN(l,GET_KEY_VALUE_INDEX(l,1,0));
    char *keyName = XP_CPY_TOKEN(l,GET_KEY_NAME_INDEX(l,1,0));

    assert_string_equal(keyName,"k1");
    assert_string_equal(keyVal,"key1");

    free(keyName);
    free(keyVal);

    assert_true(COMPARE_KEY_NAME(l,1,1,"k2"));
    assert_true(COMPARE_KEY_VALUE(l,1,1,"key2"));

}

void test1(void **state){
    xp_loc_id_t *l = (xp_loc_id_t *) *state;

    for(int i=0; i < l->node_count; i++){
        puts(XP_GET_NODE_START(l,i));
    }

    char* second = XP_CPY_TOKEN(l,XP_GET_NODE_TOKEN(l,0));
    printf("%s\n",second);
    free(second);

}

void check_parsing(void **state){
   xp_loc_id_t *l;
   assert_int_not_equal(0,xp_char_to_loc_id("abc", &l));
   /* path must not end with slash */
   assert_int_not_equal(0,xp_char_to_loc_id("/model:leaf/", &l));

   assert_int_not_equal(0,xp_char_to_loc_id("//container", &l));
   assert_int_not_equal(0,xp_char_to_loc_id("/ns:cont/list[", &l));
   /* apostroph can not be ommitted */
   assert_int_not_equal(0,xp_char_to_loc_id("/cont/l[k=abc]", &l));
   assert_int_not_equal(0,xp_char_to_loc_id("/c/l[abc]", &l));

   assert_int_not_equal(0,xp_char_to_loc_id("/ns:ns:c/l[abc]", &l));
   assert_int_not_equal(0,xp_char_to_loc_id("/c/l[abc]", &l));
}

int main(){

    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(test1, setup, teardown),
            cmocka_unit_test_setup_teardown(check_tokens, setup, teardown),
            cmocka_unit_test_setup_teardown(check_nodes, setup, teardown),
            cmocka_unit_test_setup_teardown(check_ns, setup, teardown),
            cmocka_unit_test_setup_teardown(check_keys, setup, teardown),
            cmocka_unit_test(check_parsing),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

