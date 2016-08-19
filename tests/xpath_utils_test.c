/**
 * @file xpath_utils_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo xpath_utils unit tests.
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <setjmp.h>
#include <cmocka.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>

#include "xpath_utils.h"


static void
sr_get_next_node_test (void **st)
{
    char xpath[] = "/example-module:container/list[key1='keyA'][key2='keyB']/leaf";
    sr_address_state_t state;
    
    char *res = NULL;
    
    res = sr_get_next_node(xpath, &state);
    assert_non_null(res);
    assert_string_equal(res, "container");
    
    res = sr_get_next_node(NULL, &state);
    assert_non_null(res);
    assert_string_equal(res, "list");
    
    res = sr_get_next_node(NULL, &state);
    assert_non_null(res);
    assert_string_equal(res, "leaf");
    
    sr_recover_parsed_input(&state);
    
    assert_string_equal(xpath, "/example-module:container/list[key1='keyA'][key2='keyB']/leaf");

}

static void
sr_get_node_test (void **st)
{
    char xpath[] = "/example-module:container/list[key1='keyA'][key2='keyB']/leaf";
    sr_address_state_t state;
    
    char *res = NULL;
    
    res = sr_get_node(xpath, "leaf", &state);
    assert_non_null(res);
    assert_string_equal(res, "leaf");
        
    res = sr_get_node(NULL, "container",&state);
    assert_non_null(res);
    assert_string_equal(res, "container");
    
    res = sr_get_node(NULL, "list",&state);
    assert_non_null(res);
    assert_string_equal(res, "list");

    res = sr_get_next_node(NULL, &state);
    assert_non_null(res);
    assert_string_equal(res, "leaf");
    
    res = sr_get_node(NULL, "container",&state);
    assert_non_null(res);
    assert_string_equal(res, "container");
    
    res = sr_get_node(NULL, "unknown", &state);
    assert_null(res);
    
    /*unsuccessful call left state untouched */
    res = sr_get_next_node(NULL, &state);
    assert_non_null(res);
    assert_string_equal(res, "list");

    
    sr_recover_parsed_input(&state);
    
    assert_string_equal(xpath, "/example-module:container/list[key1='keyA'][key2='keyB']/leaf");

}

static void
sr_get_node_rel_test (void **st)
{
    char xpath[] = "/example-module:container/list[key1='keyA'][key2='keyB']/leaf";
    sr_address_state_t state;
    
    char *res = NULL;
    
    res = sr_get_node_rel(xpath, "container", &state);
    assert_non_null(res);
    assert_string_equal(res, "container");
        
    res = sr_get_node_rel(NULL, "leaf", &state);
    assert_non_null(res);
    assert_string_equal(res, "leaf");
    
    res = sr_get_node(NULL, "list",&state);
    assert_non_null(res);
    assert_string_equal(res, "list");

    res = sr_get_next_node(NULL, &state);
    assert_non_null(res);
    assert_string_equal(res, "leaf");
    
    sr_recover_parsed_input(&state);
    
    assert_string_equal(xpath, "/example-module:container/list[key1='keyA'][key2='keyB']/leaf");

}

int
main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(sr_get_next_node_test),
        cmocka_unit_test(sr_get_node_test),
        cmocka_unit_test(sr_get_node_rel_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
