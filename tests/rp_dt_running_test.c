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
#include "rp_dt_context_helper.h"
#include "rp_internal.h"

int setup(void **state){
   test_rp_ctx_create((rp_ctx_t**)state);
   return 0;
}

int teardown(void **state){
    rp_ctx_t *ctx = *state;
    test_rp_ctx_cleanup(ctx);
    return 0;
}

void
no_subscription_test(void **state)
{
    int rc = 0;
   rp_ctx_t *ctx = *state;
   rp_session_t *session = NULL;
    //no enable subtree has been called all request should return SR_ERR_NOT_FOUND
   test_rp_sesssion_create(ctx, SR_DS_RUNNING, &session);

   sr_val_t **values = NULL;
   size_t count = 0;

   rc = rp_dt_get_values_wrapper(ctx, session, "/test-module:containera", &values, &count);
   assert_int_equal(SR_ERR_BAD_ELEMENT, rc);

   rc = rp_dt_get_values_wrapper(ctx, session, "/test-module:*", &values, &count);
   assert_int_equal(SR_ERR_NOT_FOUND, rc);

   rc = rp_dt_get_values_wrapper(ctx, session, "/test-module:main", &values, &count);
   assert_int_equal(SR_ERR_NOT_FOUND, rc);

   rc = rp_dt_delete_item_wrapper(ctx, session, "/test-module:main", SR_EDIT_DEFAULT);
   assert_int_equal(SR_ERR_OK, rc);

   sr_val_t value = {0,};
   value.type = SR_INT8_T;
   value.data.int8_val = 42;
   rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/test-module:main/i8", SR_EDIT_DEFAULT, &value);
   assert_int_equal(SR_ERR_INVAL_ARG, rc);

   test_rp_session_cleanup(ctx, session);
}


void
enable_subtree_test(void **state)
{

   int rc = 0;
   rp_ctx_t *ctx = *state;
   rp_session_t *session = NULL;
   const struct lys_module *module = NULL;
   struct lys_node *match = NULL;

   test_rp_sesssion_create(ctx, SR_DS_RUNNING, &session);

   rc = rp_dt_enable_xpath(ctx->dm_ctx, session->dm_session, "/ietf-interfaces:interfaces/interface/ietf-ip:ipv4/address");
   assert_int_equal(SR_ERR_OK, rc);


   rc = rp_dt_validate_node_xpath(ctx->dm_ctx, session->dm_session, "/ietf-interfaces:interfaces/interface/ietf-ip:ipv4/address", &module, &match);
   assert_int_equal(SR_ERR_OK, rc);

   /* check address node */
   assert_true(dm_is_node_enabled_with_children(match));

   /* check ipv4 container*/
   assert_true(dm_is_node_enabled(match->parent));

   /* check ietf-interfaces:interfaces */
   assert_true(dm_is_node_enabled(module->data));

   rc = rp_dt_enable_xpath(ctx->dm_ctx, session->dm_session, "/ietf-interfaces:interfaces/interface/ietf-ip:ipv4/address");
   assert_int_equal(SR_ERR_OK, rc);

   test_rp_session_cleanup(ctx, session);

   /* enable list keys implicitly */
   test_rp_sesssion_create(ctx, SR_DS_RUNNING, &session);

   rc = rp_dt_enable_xpath(ctx->dm_ctx, session->dm_session, "/example-module:container/list/leaf");
   assert_int_equal(SR_ERR_OK, rc);

   module = NULL;
   match = NULL;
   rc = rp_dt_validate_node_xpath(ctx->dm_ctx, session->dm_session, "/example-module:container/list/leaf", &module, &match);
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

   test_rp_session_cleanup(ctx, session);
}

void
edit_enabled(void **state)
{
   int rc = 0;
   rp_ctx_t *ctx = *state;
   rp_session_t *session = NULL;

   test_rp_sesssion_create(ctx, SR_DS_RUNNING, &session);

   sr_val_t val = {0,};
   val.type = SR_STRING_T;
   val.data.string_val = strdup("abc");

   rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/example-module:container/list[key1='a'][key2='b']/leaf", SR_EDIT_DEFAULT, &val);
   assert_int_equal(SR_ERR_INVAL_ARG, rc);

   rc = rp_dt_enable_xpath(ctx->dm_ctx, session->dm_session, "/example-module:container/list/leaf");
   assert_int_equal(SR_ERR_OK, rc);

   rc = rp_dt_set_item(ctx->dm_ctx, session->dm_session, "/example-module:container/list[key1='a'][key2='b']/leaf", SR_EDIT_DEFAULT, &val);
   assert_int_equal(SR_ERR_OK, rc);


   sr_val_t *v = NULL;
   rc = rp_dt_get_value_wrapper(ctx, session, "/example-module:container/list[key1='a'][key2='b']/leaf" ,&v);
   assert_int_equal(SR_ERR_OK, rc);
   assert_string_equal(v->xpath, "/example-module:container/list[key1='a'][key2='b']/leaf");
   assert_string_equal(v->data.string_val, val.data.string_val);

   sr_free_val_content(&val);
   sr_free_val(v);
   test_rp_session_cleanup(ctx, session);
}

int
main() {
    sr_log_stderr(SR_LL_ERR);

    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(no_subscription_test, setup, teardown),
            cmocka_unit_test_setup_teardown(enable_subtree_test, setup, teardown),
            cmocka_unit_test_setup_teardown(edit_enabled, setup, teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
