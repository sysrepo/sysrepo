/**
 * @file rp_dt_running_test.c
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <setjmp.h>
#include <cmocka.h>

#include "sr_common.h"
#include "rp_data_tree.h"
#include "test_data.h"
#include "test_module_helper.h"
#include "dt_xpath_helpers.h"

int setup(void **state){
   createDataTreeTestModule();
   int rc = 0;
   dm_ctx_t *ctx;
   rc = dm_init(TEST_SCHEMA_SEARCH_DIR, TEST_DATA_SEARCH_DIR, &ctx);
   assert_int_equal(SR_ERR_OK,rc);
   *state = ctx;
   return rc;
}

int teardown(void **state){
    dm_ctx_t *ctx = *state;
    dm_cleanup(ctx);
    return 0;
}

void
no_subscription_test(void **state)
{
    int rc = 0;
   dm_ctx_t *ctx = *state;
   dm_session_t *session = NULL;
    //no enable subtree has been called all request should return SR_ERR_NOT_FOUND
   rc = dm_session_start(ctx, SR_DS_RUNNING, &session);
   assert_int_equal(SR_ERR_OK, rc);

   sr_val_t **values = NULL;
   size_t count = 0;

   rc = rp_dt_get_values_wrapper(ctx, session, "/test-module:containera", &values, &count);
   assert_int_equal(SR_ERR_BAD_ELEMENT, rc);

   rc = rp_dt_get_values_wrapper(ctx, session, "/test-module:", &values, &count);
   assert_int_equal(SR_ERR_NOT_FOUND, rc);

   rc = rp_dt_get_values_wrapper(ctx, session, "/test-module:main", &values, &count);
   assert_int_equal(SR_ERR_NOT_FOUND, rc);

   rc = rp_dt_delete_item_wrapper(ctx, session, "/test-module:main", SR_EDIT_DEFAULT);
   assert_int_equal(SR_ERR_OK, rc);

   sr_val_t value = {0,};
   value.type = SR_INT8_T;
   value.data.int8_val = 42;
   rc = rp_dt_set_item_xpath(ctx, session, "/test-module:main/i8", SR_EDIT_DEFAULT, &value);
   assert_int_equal(SR_ERR_INVAL_ARG, rc);

   dm_session_stop(ctx, session);
}


void
enable_subtree_test(void **state)
{

   int rc = 0;
   dm_ctx_t *ctx = *state;
   dm_session_t *session = NULL;
   const struct lys_module *module = NULL;
   struct lys_node *match = NULL;
   xp_loc_id_t *l = NULL;

   rc = dm_session_start(ctx, SR_DS_RUNNING, &session);
   assert_int_equal(SR_ERR_OK, rc);

   rc = xp_char_to_loc_id("/ietf-interfaces:interfaces/interface/ietf-ip:ipv4/address", &l);
   assert_int_equal(SR_ERR_OK, rc);

   rc = rp_dt_enable_xpath(ctx, session, l);
   assert_int_equal(SR_ERR_OK, rc);


   rc = rp_dt_validate_node_xpath(ctx, session, l, &module, &match);
   assert_int_equal(SR_ERR_OK, rc);

   /* check address node */
   assert_true(dm_is_node_enabled_with_children(match));

   /* check ipv4 container*/
   assert_true(dm_is_node_enabled(match->parent));

   /* check ietf-interfaces:interfaces */
   assert_true(dm_is_node_enabled(module->data));

   rc = rp_dt_enable_xpath(ctx, session, l);
   assert_int_equal(SR_ERR_OK, rc);

   xp_free_loc_id(l);
   dm_session_stop(ctx, session);

   /* enable list keys implicitly */
   dm_session_start(ctx, SR_DS_RUNNING, &session);

   l = NULL;
   rc = xp_char_to_loc_id("/example-module:container/list/leaf", &l);
   assert_int_equal(SR_ERR_OK, rc);

   rc = rp_dt_enable_xpath(ctx, session, l);
   assert_int_equal(SR_ERR_OK, rc);

   module = NULL;
   match = NULL;
   rc = rp_dt_validate_node_xpath(ctx, session, l, &module, &match);
   assert_int_equal(SR_ERR_OK, rc);

   /* check leaf node */
   assert_true(dm_is_node_enabled(match));

   /* key nodes should be enabled implicitly*/
   assert_true(dm_is_node_enabled(match->prev));
   assert_true(dm_is_node_enabled(match->prev->prev));

   /* list */
   assert_true(dm_is_node_enabled(match->parent));

   /* container*/
   assert_true(dm_is_node_enabled(match->parent->parent));

   xp_free_loc_id(l);
   dm_session_stop(ctx, session);
}

void
edit_enabled(void **state)
{
   int rc = 0;
   dm_ctx_t *ctx = NULL;
   rc = dm_init(SR_SCHEMA_SEARCH_DIR, SR_DATA_SEARCH_DIR, &ctx);
   assert_int_equal(SR_ERR_OK, rc);

   dm_session_t *session = NULL;
   xp_loc_id_t *l = NULL;

   rc = dm_session_start(ctx, SR_DS_RUNNING, &session);
   assert_int_equal(SR_ERR_OK, rc);

   sr_val_t val = {0,};
   val.type = SR_STRING_T;
   val.data.string_val = strdup("abc");


   rc = rp_dt_set_item_xpath(ctx, session, "/example-module:container/list[key1='a'][key2='b']/leaf", SR_EDIT_DEFAULT, &val);
   assert_int_equal(SR_ERR_INVAL_ARG, rc);

   rc = xp_char_to_loc_id("/example-module:container/list/leaf", &l);
   assert_int_equal(SR_ERR_OK, rc);

   rc = rp_dt_enable_xpath(ctx, session, l);
   assert_int_equal(SR_ERR_OK, rc);

   rc = rp_dt_set_item_xpath(ctx, session, "/example-module:container/list[key1='a'][key2='b']/leaf", SR_EDIT_DEFAULT, &val);
   assert_int_equal(SR_ERR_OK, rc);


   sr_val_t *v = NULL;
   rc = rp_dt_get_value_wrapper(ctx, session, "/example-module:container/list[key1='a'][key2='b']/leaf" ,&v);
   assert_int_equal(SR_ERR_OK, rc);
   assert_string_equal(v->xpath, "/example-module:container/list[key1='a'][key2='b']/leaf");
   assert_string_equal(v->data.string_val, val.data.string_val);

   sr_free_val_content(&val);
   sr_free_val(v);
   xp_free_loc_id(l);
   dm_session_stop(ctx, session);
   dm_cleanup(ctx);
}

int
main() {
    sr_log_stderr(SR_LL_ERR);
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(no_subscription_test),
        cmocka_unit_test(enable_subtree_test),
        cmocka_unit_test(edit_enabled),
    };

    return cmocka_run_group_tests(tests, setup, teardown);
}
