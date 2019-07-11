/**
 * @file dm_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Data Manager unit tests.
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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdlib.h>
#include <stdio.h>
#include "data_manager.h"
#include "test_data.h"
#include "sr_common.h"
#include "test_module_helper.h"
#include "rp_dt_lookup.h"
#include "rp_dt_xpath.h"
#include "rp_dt_context_helper.h"
#include "system_helper.h"

int setup(void **state)
{
    /* make sure that test-module data is created */
    createDataTreeTestModule();
    createDataTreeExampleModule();
    createDataTreeReferencedModule(123);
    createDataTreeIETFinterfacesModule();
    return 0;
}

void dm_create_cleanup(void **state){
   int rc;
   dm_ctx_t *ctx;
   rc = dm_init(NULL, NULL, NULL, CM_MODE_LOCAL, TEST_SCHEMA_SEARCH_DIR, TEST_DATA_SEARCH_DIR, &ctx);
   assert_int_equal(SR_ERR_OK,rc);

   dm_cleanup(ctx);

}

static struct lyd_node *
dm_lyd_new_leaf(dm_data_info_t *data_info, struct lyd_node *parent, const struct lys_module *module, const char *node_name, const char *value)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_ARG_NORET4(rc, data_info, module, node_name, value);
    if (SR_ERR_OK != rc){
        return NULL;
    }

    struct lyd_node *new = NULL;
    new = lyd_new_leaf(parent, module, node_name, value);

    if (NULL == parent) {
        if (NULL == data_info->node) {
            data_info->node = new;
        } else {
            struct lyd_node *last_sibling = data_info->node;
            while (NULL != last_sibling->next) {
                last_sibling = last_sibling->next;
            }
            if (0 != lyd_insert_after(last_sibling, new)) {
                SR_LOG_ERR_MSG("Append of top level node failed");
                lyd_free(new);
                return NULL;
            }
        }
    }

    return new;
}

void dm_get_data_tree(void **state)
{
    int rc;
    dm_ctx_t *ctx;
    dm_session_t *ses_ctx;
    struct lyd_node *data_tree;

    rc = dm_init(NULL, NULL, NULL, CM_MODE_LOCAL, TEST_SCHEMA_SEARCH_DIR, TEST_DATA_SEARCH_DIR, &ctx);
    assert_int_equal(SR_ERR_OK, rc);

    dm_session_start(ctx, NULL, SR_DS_STARTUP, &ses_ctx);
    /* Load from file */
    assert_int_equal(SR_ERR_OK, dm_get_datatree(ctx, ses_ctx ,"example-module", &data_tree));
    /* Get from avl tree */
    assert_int_equal(SR_ERR_OK, dm_get_datatree(ctx, ses_ctx ,"example-module", &data_tree));
    /* Module without data */
    assert_int_equal(SR_ERR_OK, dm_get_datatree(ctx, ses_ctx ,"small-module", &data_tree));
    /* Not existing module should return an error*/
    assert_int_equal(SR_ERR_UNKNOWN_MODEL, dm_get_datatree(ctx, ses_ctx ,"not-existing-module", &data_tree));

    dm_session_stop(ctx, ses_ctx);

    dm_cleanup(ctx);

}

void
dm_list_schema_test(void **state)
{
    int rc;
    dm_ctx_t *ctx;
    dm_session_t *ses_ctx;
    sr_schema_t *schemas;
    size_t count;

    rc = dm_init(NULL, NULL, NULL, CM_MODE_LOCAL, TEST_SCHEMA_SEARCH_DIR, TEST_DATA_SEARCH_DIR, &ctx);
    assert_int_equal(SR_ERR_OK, rc);

    rc = dm_session_start(ctx, NULL, SR_DS_STARTUP, &ses_ctx);
    assert_int_equal(SR_ERR_OK, rc);

    rc = dm_list_schemas(ctx, ses_ctx, &schemas, &count);
    assert_int_equal(SR_ERR_OK, rc);

    for (size_t i = 0; i < count; i++) {
        printf("\n\nSchema #%zu:\n%s\n%s\n%s\n", i,
                schemas[i].module_name,
                schemas[i].ns,
                schemas[i].prefix);
            printf("\t%s\n\t%s\n\t%s\n\n",
                    schemas[i].revision.revision,
                    schemas[i].revision.file_path_yang,
                    schemas[i].revision.file_path_yin);


        for (size_t s = 0; s < schemas[i].submodule_count; s++) {
            printf("\t%s\n", schemas[i].submodules[s].submodule_name);

               printf("\t\t%s\n\t\t%s\n\t\t%s\n\n",
                       schemas[i].submodules[s].revision.revision,
                       schemas[i].submodules[s].revision.file_path_yang,
                       schemas[i].submodules[s].revision.file_path_yin);

        }
    }

    sr_free_schemas(schemas, count);

    dm_session_stop(ctx, ses_ctx);

    dm_cleanup(ctx);
}

void
dm_get_schema_test(void **state)
{
    int rc;
    dm_ctx_t *ctx;
    char *schema = NULL;

    rc = dm_init(NULL, NULL, NULL, CM_MODE_LOCAL, TEST_SCHEMA_SEARCH_DIR, TEST_DATA_SEARCH_DIR, &ctx);
    assert_int_equal(SR_ERR_OK, rc);

    /* module latest revision */
    rc = dm_get_schema(ctx, "module-a", NULL, NULL, NULL, true, &schema);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(schema);
    free(schema);

    /* module latest revision  yin format*/
    rc = dm_get_schema(ctx, "module-a", NULL, NULL, NULL, false, &schema);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(schema);
    free(schema);

    /* module-b latest revision which depends on module-a older revision */
    rc = dm_get_schema(ctx, "module-b", NULL, NULL, NULL, true, &schema);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(schema);
    free(schema);

    /* module selected revision */
    rc = dm_get_schema(ctx, "module-a", "2016-02-02", NULL, NULL, true, &schema);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(schema);
    free(schema);

    /* submodule latest revision */
    rc = dm_get_schema(ctx, NULL, NULL, "sub-a-one", NULL, true, &schema);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(schema);
    free(schema);

    /* submodule selected revision */
    rc = dm_get_schema(ctx, "module-a", NULL, "sub-a-one", "2016-02-02", true, &schema);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(schema);
    free(schema);

    dm_cleanup(ctx);

}

void
dm_get_schema_negative_test(void **state)
{

    int rc;
    dm_ctx_t *ctx;
    char *schema = NULL;

    rc = dm_init(NULL, NULL, NULL, CM_MODE_LOCAL, TEST_SCHEMA_SEARCH_DIR, TEST_DATA_SEARCH_DIR, &ctx);
    assert_int_equal(SR_ERR_OK, rc);

    /* unknown module */
    rc = dm_get_schema(ctx, "unknown", NULL, NULL, NULL, true, &schema);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    assert_null(schema);


    /* module unknown revision */
    rc = dm_get_schema(ctx, "module-a", "2018-02-02", NULL, NULL, true, &schema);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    assert_null(schema);


    /* unknown submodule */
    rc = dm_get_schema(ctx, "module-a", NULL, "sub-unknown", NULL, true, &schema);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    assert_null(schema);

    /* submodule unknown revision */
    rc = dm_get_schema(ctx, "module-a", NULL, "sub-a-one", "2018-02-10", true, &schema);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    assert_null(schema);

    dm_cleanup(ctx);
}

void
dm_validate_data_trees_test(void **state)
{
    int rc;
    dm_ctx_t *ctx = NULL;
    dm_session_t *ses_ctx = NULL;
    struct lyd_node *node = NULL;
    dm_data_info_t *info = NULL;
    sr_error_info_t *errors = NULL;
    size_t err_cnt = 0;

    rc = dm_init(NULL, NULL, NULL, CM_MODE_LOCAL, TEST_SCHEMA_SEARCH_DIR, TEST_DATA_SEARCH_DIR, &ctx);
    assert_int_equal(SR_ERR_OK, rc);

    rc = dm_session_start(ctx, NULL, SR_DS_STARTUP, &ses_ctx);
    assert_int_equal(SR_ERR_OK, rc);

    /* test validation with no data trees copied */
    rc = dm_validate_session_data_trees(ctx, ses_ctx, &errors, &err_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_errors(errors, err_cnt);

    /* copy a couple data trees to session*/
    rc = dm_get_data_info(ctx, ses_ctx, "example-module", &info);
    assert_int_equal(SR_ERR_OK, rc);

    rc = dm_get_data_info(ctx, ses_ctx, "test-module", &info);
    assert_int_equal(SR_ERR_OK, rc);

    rc = dm_validate_session_data_trees(ctx, ses_ctx, &errors, &err_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_errors(errors, err_cnt);

    /* make an invalid  change */
    info->modified = true;
    /* already existing leaf */
    node = dm_lyd_new_leaf(info, info->node, info->schema->module, "i8", "42");
    assert_non_null(node);


    rc = dm_validate_session_data_trees(ctx, ses_ctx, &errors, &err_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);
    sr_free_errors(errors, err_cnt);

    dm_session_stop(ctx, ses_ctx);
    dm_cleanup(ctx);
}

void
dm_discard_changes_test(void **state)
{
    int rc;
    dm_ctx_t *ctx = NULL;
    dm_session_t *ses_ctx = NULL;
    dm_data_info_t *info = NULL;

    rc = dm_init(NULL, NULL, NULL, CM_MODE_LOCAL, TEST_SCHEMA_SEARCH_DIR, TEST_DATA_SEARCH_DIR, &ctx);
    assert_int_equal(SR_ERR_OK, rc);

    rc = dm_session_start(ctx, NULL, SR_DS_STARTUP, &ses_ctx);
    assert_int_equal(SR_ERR_OK, rc);

    rc = dm_get_data_info(ctx, ses_ctx, "test-module", &info);
    assert_int_equal(SR_ERR_OK, rc);

    rc = dm_discard_changes(ctx, ses_ctx, "test-module");
    assert_int_equal(SR_ERR_OK, rc);

    rc = dm_get_data_info(ctx, ses_ctx, "test-module", &info);
    assert_int_equal(SR_ERR_OK, rc);

    /* check current value */
    assert_int_equal(8, ((struct lyd_node_leaf_list *)info->node->child->next->next->next->next)->value.int8);


    /* change leaf i8 value */
    info->modified = true;
    //TODO change to lyd_change_leaf
    ((struct lyd_node_leaf_list *)info->node->child->next->next->next->next)->value.int8 = 100;

    /* we should have the value changed*/
    rc = dm_get_data_info(ctx, ses_ctx, "test-module", &info);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(100, ((struct lyd_node_leaf_list *)info->node->child->next->next->next->next)->value.int8);

    /* discard changes to get current datastore value*/
    rc = dm_discard_changes(ctx, ses_ctx, NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = dm_get_data_info(ctx, ses_ctx, "test-module", &info);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(8, ((struct lyd_node_leaf_list *)info->node->child->next->next->next->next)->value.int8);

    dm_session_stop(ctx, ses_ctx);
    dm_cleanup(ctx);
}

void
dm_add_operation_test(void **state)
{
    int rc;
    dm_ctx_t *ctx = NULL;
    dm_session_t *ses_ctx = NULL;
    char *str_val = NULL;

    rc = dm_init(NULL, NULL, NULL, CM_MODE_LOCAL, TEST_SCHEMA_SEARCH_DIR, TEST_DATA_SEARCH_DIR, &ctx);
    assert_int_equal(SR_ERR_OK, rc);

    dm_session_start(ctx, NULL, SR_DS_STARTUP, &ses_ctx);

    rc = dm_add_del_operation(ses_ctx, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    sr_val_t *val = NULL;
    val = calloc(1, sizeof(*val));
    assert_non_null(val);

    val->type = SR_INT8_T;
    val->data.int8_val = 42;

    rc = dm_add_set_operation(ses_ctx, "/abc:def", val, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    str_val = strdup("def val");
    assert_non_null(str_val);
    rc = dm_add_set_operation(ses_ctx, "/abc:def", NULL, str_val, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = dm_add_del_operation(ses_ctx, "/abc:def", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    sr_val_t *val1 = NULL;
    val1 = calloc(1, sizeof(*val1));
    assert_non_null(val1);
    val1->type = SR_STRING_T;
    val1->data.string_val = strdup("abc");

    /* NULL passed in loc_id argument, val1 should be freed */
    rc = dm_add_set_operation(ses_ctx, NULL, val1, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    dm_session_stop(ctx, ses_ctx);
    dm_cleanup(ctx);

}

void
dm_locking_test(void **state)
{
   int rc;
   dm_ctx_t *ctx = NULL;
   dm_session_t *sessionA = NULL, *sessionB = NULL;

   rc = dm_init(NULL, NULL, NULL, CM_MODE_LOCAL, TEST_SCHEMA_SEARCH_DIR, TEST_DATA_SEARCH_DIR, &ctx);
   assert_int_equal(SR_ERR_OK, rc);

   dm_session_start(ctx, NULL, SR_DS_STARTUP, &sessionA);
   dm_session_start(ctx, NULL, SR_DS_STARTUP, &sessionB);

   rc = dm_lock_module(ctx, sessionA, "example-module");
   assert_int_equal(SR_ERR_OK, rc);

   rc = dm_lock_module(ctx, sessionB, "example-module");
   assert_int_equal(SR_ERR_LOCKED, rc);

   /* automatically release lock by session stop */
   dm_session_stop(ctx, sessionA);

   rc = dm_lock_module(ctx, sessionB, "example-module");
   assert_int_equal(SR_ERR_OK, rc);
   dm_session_stop(ctx, sessionB);
   dm_cleanup(ctx);
}

void
dm_copy_module_test(void **state)
{
   int rc = SR_ERR_OK;
   dm_ctx_t *ctx = NULL;
   dm_session_t *sessionA = NULL;
   dm_schema_info_t *si = NULL;

   rc = dm_init(NULL, NULL, NULL, CM_MODE_LOCAL, TEST_SCHEMA_SEARCH_DIR, TEST_DATA_SEARCH_DIR, &ctx);
   assert_int_equal(SR_ERR_OK, rc);

   rc = dm_session_start(ctx, NULL, SR_DS_STARTUP, &sessionA);
   assert_int_equal(SR_ERR_OK, rc);

   /* not enabled */
   rc = dm_copy_module(ctx, sessionA, "test-module", SR_DS_STARTUP, SR_DS_STARTUP, NULL, 0, NULL, NULL);
   assert_int_equal(SR_ERR_OPERATION_FAILED, rc);

   rc = dm_get_module_without_lock(ctx, "test-module", &si);
   assert_int_equal(SR_ERR_OK, rc);

   rc = rp_dt_enable_xpath(ctx, sessionA, si, "/test-module:main");
   assert_int_equal(SR_ERR_OK, rc);

   /* now enabled */
   rc = dm_copy_module(ctx, sessionA, "test-module", SR_DS_STARTUP, SR_DS_STARTUP, NULL, 0, NULL, NULL);
   assert_int_equal(SR_ERR_OK, rc);

   rc = dm_copy_all_models(ctx, sessionA, SR_DS_STARTUP, SR_DS_STARTUP, 0, NULL, NULL);
   assert_int_equal(SR_ERR_OK, rc);

   dm_session_stop(ctx, sessionA);
   dm_cleanup(ctx);
}

void
dm_rpc_test(void **state)
{
    int rc = SR_ERR_OK;
    rp_ctx_t *ctx = NULL;
    rp_session_t *session = NULL;
    sr_val_t *input = NULL, *output = NULL, *with_def = NULL;
    sr_node_t *with_def_tree = NULL;
    dm_schema_info_t *schema_info = NULL;
    size_t input_cnt = 0, output_cnt = 0, with_def_cnt = 0, with_def_tree_cnt = 0;

    test_rp_ctx_create(CM_MODE_LOCAL, &ctx);
    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    /* load test-module */
    rc = dm_get_module_without_lock(ctx->dm_ctx, "test-module", &schema_info);
    assert_int_equal(SR_ERR_OK, rc);

    /* non-existing RPC */
    rc = dm_validate_rpc(ctx, session, "/test-module:non-existing-rpc", input, input_cnt, true,
            NULL, &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);
    assert_null(with_def);
    assert_null(with_def_tree);

    /* RPC input */
    input_cnt = 1;
    input = calloc(input_cnt, sizeof(*input));
    input[0].xpath = strdup("/test-module:activate-software-image/image-name");
    input[0].type = SR_STRING_T;
    input[0].data.string_val = strdup("acmefw-2.3");

    rc = dm_validate_rpc(ctx, session, "/test-module:activate-software-image", input, input_cnt, true,
            NULL, &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, with_def_cnt); /* including default leaf */
    assert_int_equal(2, with_def_tree_cnt);
    sr_free_values(with_def, with_def_cnt);
    sr_free_trees(with_def_tree, with_def_tree_cnt);

    /* invalid RPC input */
    free(input[0].xpath);
    input[0].xpath = strdup("/test-module:activate-software-image/non-existing-input");
    rc = dm_validate_rpc(ctx, session, "/test-module:activate-software-image", input, input_cnt, true,
            NULL, &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);

    /* RPC output */
    output_cnt = 2;
    output = calloc(output_cnt, sizeof(*output));
    output[0].xpath = strdup("/test-module:activate-software-image/status");
    output[0].type = SR_STRING_T;
    output[0].data.string_val = strdup("The image acmefw-2.3 is being installed.");
    output[1].xpath = strdup("/test-module:activate-software-image/version");
    output[1].type = SR_STRING_T;
    output[1].data.string_val = strdup("2.3");

    rc = dm_validate_rpc(ctx, session, "/test-module:activate-software-image", output, output_cnt, false,
            NULL, &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(4, with_def_cnt); /* including default leaf and empty container */
    assert_int_equal(4, with_def_tree_cnt);
    sr_free_values(with_def, with_def_cnt);
    sr_free_trees(with_def_tree, with_def_tree_cnt);

    /* invalid RPC output */
    free(output[1].xpath);
    output[1].xpath = strdup("/test-module:activate-software-image/non-existing-output");
    rc = dm_validate_rpc(ctx, session, "/test-module:activate-software-image", output, output_cnt, false,
            NULL, &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);

    sr_free_values(input, input_cnt);
    sr_free_values(output, output_cnt);

    test_rp_session_cleanup(ctx, session);
    test_rp_ctx_cleanup(ctx);
}

void
dm_state_data_test(void **state)
{
    int rc = SR_ERR_OK;
    dm_ctx_t *ctx = NULL;
    dm_session_t *session = NULL;
    bool has_state_data = false;

    rc = dm_init(NULL, NULL, NULL, CM_MODE_LOCAL, TEST_SCHEMA_SEARCH_DIR, TEST_DATA_SEARCH_DIR, &ctx);
    assert_int_equal(SR_ERR_OK, rc);

    rc = dm_session_start(ctx, NULL, SR_DS_STARTUP, &session);
    assert_int_equal(SR_ERR_OK, rc);

    rc = dm_has_state_data(ctx, "ietf-ip", &has_state_data);
    assert_int_equal(SR_ERR_OK, rc);
    assert_false(has_state_data);

    rc = dm_has_state_data(ctx, "ietf-interfaces", &has_state_data);
    assert_int_equal(SR_ERR_OK, rc);
    assert_true(has_state_data);

    rc = dm_has_state_data(ctx, "info-module", &has_state_data);
    assert_int_equal(SR_ERR_OK, rc);
    assert_false(has_state_data);

    rc = dm_has_state_data(ctx, "test-module", &has_state_data);
    assert_int_equal(SR_ERR_OK, rc);
    assert_false(has_state_data);

    rc = dm_has_state_data(ctx, "state-module", &has_state_data);
    assert_int_equal(SR_ERR_OK, rc);
    assert_true(has_state_data);

    dm_session_stop(ctx, session);
    dm_cleanup(ctx);
}

void
dm_event_notif_test(void **state)
{
    int rc = SR_ERR_OK;
    rp_ctx_t *ctx = NULL;
    rp_session_t *session = NULL;
    sr_val_t *values = NULL, *with_def = NULL;
    sr_node_t *with_def_tree = NULL;
    dm_schema_info_t *schema_info = NULL;
    size_t values_cnt = 0, with_def_cnt = 0, with_def_tree_cnt = 0;
    char *error_msg = NULL, *error_xpath = NULL;

    test_rp_ctx_create(CM_MODE_LOCAL, &ctx);
    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    /* load test-module */
    rc = dm_get_module_and_lock(ctx->dm_ctx, "test-module", &schema_info);
    assert_int_equal(SR_ERR_OK, rc);

    /* non-existing event notification */
    rc = dm_validate_event_notif(ctx, session, "/test-module:non-existing-event-notif", values, values_cnt,
            NULL, &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt, NULL, NULL);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);
    dm_copy_errors(session->dm_session, NULL, &error_msg, &error_xpath);
    assert_string_equal("target node is not present in the schema tree", error_msg);
    assert_string_equal("/test-module:non-existing-event-notif", error_xpath);
    free(error_msg);
    free(error_xpath);
    error_msg = NULL;
    error_xpath = NULL;

    /* valid event notification */
    values_cnt = 6;
    values = calloc(values_cnt, sizeof(*values));
    values[0].xpath = strdup("/test-module:link-removed/source");
    values[0].type = SR_CONTAINER_T;
    values[0].data.uint64_val = 0;
    values[1].xpath = strdup("/test-module:link-removed/source/address");
    values[1].type = SR_STRING_T;
    values[1].data.string_val = strdup("10.10.2.4");
    values[2].xpath = strdup("/test-module:link-removed/source/interface");
    values[2].type = SR_STRING_T;
    values[2].data.string_val = strdup("eth0");
    values[3].xpath = strdup("/test-module:link-removed/destination");
    values[3].type = SR_CONTAINER_T;
    values[3].data.uint64_val = 0;
    values[4].xpath = strdup("/test-module:link-removed/destination/address");
    values[4].type = SR_STRING_T;
    values[4].data.string_val = strdup("10.10.2.5");
    values[5].xpath = strdup("/test-module:link-removed/destination/interface");
    values[5].type = SR_STRING_T;
    values[5].data.string_val = strdup("eth2");

    rc = dm_validate_event_notif(ctx, session, "/test-module:link-removed", values, values_cnt,
            NULL, &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt, NULL, NULL);
    assert_int_equal(SR_ERR_OK, rc);
    /* including default leaf */
    assert_int_equal(7, with_def_cnt);
    assert_int_equal(3, with_def_tree_cnt);
    assert_string_equal("/test-module:link-removed/MTU", with_def[6].xpath);
    assert_int_equal(SR_UINT16_T, with_def[6].type);
    assert_int_equal(1500, with_def[6].data.uint16_val);

    /* invalid event notification values */
    free(with_def[6].xpath);
    with_def[6].xpath = strdup("/test-module:link-removed/non-existing-node");
    rc = dm_validate_event_notif(ctx, session, "/test-module:link-removed", with_def, with_def_cnt,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);
    dm_copy_errors(session->dm_session, NULL, &error_msg, &error_xpath);
    assert_string_equal("Unable to evaluate xpath", error_msg);
    assert_string_equal("/test-module:link-removed/non-existing-node", error_xpath);
    free(error_msg);
    free(error_xpath);
    error_msg = NULL;
    error_xpath = NULL;

    sr_free_values(values, values_cnt);
    sr_free_values(with_def, with_def_cnt);
    sr_free_trees(with_def_tree, with_def_tree_cnt);

    /* nested event notifications */
    values_cnt = 2;
    values = calloc(values_cnt, sizeof(*values));
    values[0].xpath = strdup("/test-module:kernel-modules/kernel-module[name=\"irqbypass.ko\"]/status-change/loaded");
    values[0].type = SR_BOOL_T;
    values[0].data.bool_val = true;
    values[1].xpath = strdup("/test-module:kernel-modules/kernel-module[name=\"irqbypass.ko\"]/status-change/time-of-change");
    values[1].type = SR_UINT32_T;
    values[1].data.uint32_val = 56;

    /* non-existing location of the notification in the data tree */
    rc = dm_validate_event_notif(ctx, session, "/test-module:kernel-modules/kernel-module[name=\"non-existent-module\"]/status-change",
            values, values_cnt, NULL, &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt, NULL, NULL);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);
    dm_copy_errors(session->dm_session, NULL, &error_msg, &error_xpath);
    assert_string_equal("target node is not present in the data tree", error_msg);
    assert_string_equal("/test-module:kernel-modules/kernel-module[name=\"non-existent-module\"]/status-change", error_xpath);
    free(error_msg);
    free(error_xpath);
    error_msg = NULL;
    error_xpath = NULL;

    /* more than one target matched by the notification's xpath */
    rc = dm_validate_action(ctx, session, "/test-module:kernel-modules/kernel-module/status-change",
            values, values_cnt, true, NULL, &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);
    dm_copy_errors(session->dm_session, NULL, &error_msg, &error_xpath);
    assert_string_equal("xpath references more than one node in the data tree.", error_msg);
    assert_string_equal("/test-module:kernel-modules/kernel-module/status-change", error_xpath);
    free(error_msg);
    free(error_xpath);
    error_msg = NULL;
    error_xpath = NULL;

    /* unsatisfied "must" condition */
    rc = dm_validate_event_notif(ctx, session, "/test-module:kernel-modules/kernel-module[name=\"irqbypass.ko\"]/status-change",
            values, values_cnt, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);
    dm_copy_errors(session->dm_session, NULL, &error_msg, &error_xpath);
    assert_string_equal("time-of-change must be greater than magic_number", error_msg);
    assert_string_equal("/test-module:kernel-modules/kernel-module[name='irqbypass.ko']/status-change/time-of-change", error_xpath);
    free(error_msg);
    free(error_xpath);
    error_msg = NULL;
    error_xpath = NULL;

    /* satisfied "must" condition */
    values[1].data.uint32_val = 132;
    rc = dm_validate_event_notif(ctx, session, "/test-module:kernel-modules/kernel-module[name=\"irqbypass.ko\"]/status-change",
            values, values_cnt, NULL, &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt, NULL, NULL);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, with_def_cnt);
    assert_int_equal(2, with_def_tree_cnt);

    sr_free_values(values, values_cnt);
    sr_free_values(with_def, with_def_cnt);
    sr_free_trees(with_def_tree, with_def_tree_cnt);

    /* load id-ref-aug module */
    rc = dm_get_module_and_lock(ctx->dm_ctx, "id-ref-hello", &schema_info);
    assert_int_equal(SR_ERR_OK, rc);

    /* valid event notification */
    values_cnt = 1;
    values = calloc(values_cnt, sizeof(*values));
    values[0].xpath = strdup("/id-ref-hello:hello/id-ref");
    values[0].type = SR_IDENTITYREF_T;
    values[0].data.identityref_val = strdup("id-def-extended:external-derived-id");

    rc = dm_validate_event_notif(ctx, session, "/id-ref-hello:hello", values, values_cnt,
            NULL, &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt, NULL, NULL);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal(with_def[0].data.identityref_val, "id-def-extended:external-derived-id");

    sr_free_values(values, values_cnt);
    sr_free_values(with_def, with_def_cnt);
    sr_free_trees(with_def_tree, with_def_tree_cnt);

    test_rp_session_cleanup(ctx, session);
    test_rp_ctx_cleanup(ctx);
}

void
dm_event_notif_parse_test(void **state)
{
    int rc = SR_ERR_OK;
    rp_ctx_t *ctx = NULL;
    rp_session_t *session = NULL;
    dm_schema_info_t *schema_info = NULL;
    np_ev_notification_t *notification = NULL;
    struct lyxml_elem *xml = NULL;

    test_rp_ctx_create(CM_MODE_LOCAL, &ctx);
    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    /* load test-module */
    rc = dm_get_module_and_lock(ctx->dm_ctx, "test-module", &schema_info);
    assert_int_equal(SR_ERR_OK, rc);

    /* prepare lyxml with the notification */
    const char *xml_str = "\
      <link-removed xmlns=\"urn:ietf:params:xml:ns:yang:test-module\"> \
        <source> \
          <address>10.10.2.4</address> \
          <interface>eth0</interface> \
        </source> \
        <destination> \
          <address>10.10.2.5</address> \
          <interface>eth2</interface> \
        </destination> \
      </link-removed>";
    xml = lyxml_parse_mem(schema_info->ly_ctx, xml_str, 0);
    assert_non_null(xml);

    /* prepare ev. notification ctx */
    notification = calloc(1, sizeof(*notification));
    assert_non_null(notification);
    notification->xpath = strdup("/test-module:link-removed");
    assert_non_null(notification->xpath);
    notification->data.xml = xml;
    notification->data_type = NP_EV_NOTIF_DATA_XML;

    /* parse to values */
    rc = dm_parse_event_notif(ctx, session, NULL, notification, SR_API_VALUES);
    assert_int_equal(SR_ERR_OK, rc);
    assert_true(NP_EV_NOTIF_DATA_VALUES == notification->data_type);

    assert_int_equal(notification->data_cnt, 7); /* including the default node */
    assert_string_equal(notification->data.values[1].xpath, "/test-module:link-removed/source/address");
    assert_string_equal(notification->data.values[1].data.string_val, "10.10.2.4");
    assert_string_equal(notification->data.values[6].xpath, "/test-module:link-removed/MTU");
    assert_true(notification->data.values[6].dflt);

    np_event_notification_cleanup(notification);

    /* prepare ev. notification ctx */
    notification = calloc(1, sizeof(*notification));
    assert_non_null(notification);
    notification->xpath = strdup("/test-module:link-removed");
    assert_non_null(notification->xpath);
    notification->data.xml = xml;
    notification->data_type = NP_EV_NOTIF_DATA_XML;

    /* parse to values */
    rc = dm_parse_event_notif(ctx, session, NULL, notification, SR_API_TREES);
    assert_int_equal(SR_ERR_OK, rc);
    assert_true(NP_EV_NOTIF_DATA_TREES == notification->data_type);

    assert_int_equal(notification->data_cnt, 3); /* including the default node */
    assert_string_equal(notification->data.trees[0].name, "source");
    assert_non_null(notification->data.trees[0].first_child);
    assert_string_equal(notification->data.trees[0].first_child->data.string_val, "10.10.2.4");
    assert_string_equal(notification->data.trees[2].name, "MTU");
    assert_true(notification->data.trees[2].dflt);

    np_event_notification_cleanup(notification);

    /* cleanup the lyxml */
    lyxml_free(schema_info->ly_ctx, xml);

    test_rp_session_cleanup(ctx, session);
    test_rp_ctx_cleanup(ctx);
}

void
dm_action_test(void **state)
{
    int rc = SR_ERR_OK;
    rp_ctx_t *ctx = NULL;
    rp_session_t *session = NULL;
    sr_val_t *input = NULL, *output = NULL, *with_def = NULL;
    sr_node_t *input_tree = NULL, *with_def_tree = NULL;
    dm_schema_info_t *schema_info = NULL;
    size_t input_cnt = 0, output_cnt = 0, with_def_cnt = 0, with_def_tree_cnt = 0;
    char *error_msg = NULL, *error_xpath = NULL;

    test_rp_ctx_create(CM_MODE_LOCAL, &ctx);
    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    /* load test-module */
    rc = dm_get_module_without_lock(ctx->dm_ctx, "test-module", &schema_info);
    assert_int_equal(SR_ERR_OK, rc);

    /* non-existing action in the schema tree */
    rc = dm_validate_action(ctx, session, "/test-module:non-existing-action", input, input_cnt, true,
            NULL, &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);
    dm_copy_errors(session->dm_session, NULL, &error_msg, &error_xpath);
    assert_string_equal("target node is not present in the schema tree", error_msg);
    assert_string_equal("/test-module:non-existing-action", error_xpath);
    free(error_msg);
    free(error_xpath);
    error_msg = NULL;
    error_xpath = NULL;
    assert_null(with_def);
    assert_null(with_def_tree);

    /* action input */
    input_cnt = 1;
    input = calloc(input_cnt, sizeof(*input));
    input[0].xpath = strdup("/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load/params");
    input[0].type = SR_STRING_T;
    input[0].data.string_val = strdup("--log-level 2");

    rc = dm_validate_action(ctx, session, "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load",
            input, input_cnt, true, NULL, &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, with_def_cnt); /* including default leafs */
    assert_int_equal(3, with_def_tree_cnt); /* including default leafs */
    /* -> valued with defaults */
    assert_string_equal("/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load/params", with_def[0].xpath);
    assert_int_equal(SR_STRING_T, with_def[0].type);
    assert_string_equal("--log-level 2", with_def[0].data.string_val);
    assert_string_equal("/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load/force", with_def[1].xpath);
    assert_int_equal(SR_BOOL_T, with_def[1].type);
    assert_false(with_def[1].data.bool_val);
    assert_string_equal("/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load/dry-run", with_def[2].xpath);
    assert_int_equal(SR_BOOL_T, with_def[2].type);
    assert_false(with_def[2].data.bool_val);
    /* -> subtrees with defaults */
    assert_string_equal("params", with_def_tree[0].name);
    assert_string_equal("test-module", with_def_tree[0].module_name);
    assert_int_equal(SR_STRING_T, with_def_tree[0].type);
    assert_string_equal("--log-level 2", with_def_tree[0].data.string_val);
    assert_string_equal("force", with_def_tree[1].name);
    assert_string_equal("test-module", with_def_tree[1].module_name);
    assert_int_equal(SR_BOOL_T, with_def_tree[1].type);
    assert_false(with_def_tree[1].data.bool_val);
    assert_string_equal("dry-run", with_def_tree[2].name);
    assert_string_equal("test-module", with_def_tree[2].module_name);
    assert_int_equal(SR_BOOL_T, with_def_tree[2].type);
    assert_false(with_def_tree[2].data.bool_val);

    sr_free_values(input, input_cnt);
    sr_free_values(with_def, with_def_cnt);
    input_tree = with_def_tree;
    input_cnt = with_def_tree_cnt;
    for (int i = 0; i < input_cnt; ++i) {
        input_tree[i].dflt = false;
    }

    /* unsatisfied "when" condition */
    rc = dm_validate_action_tree(ctx, session, "/test-module:kernel-modules/kernel-module[name='irqbypass.ko']/load",
            input_tree, input_cnt, true, NULL, &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);
    dm_copy_errors(session->dm_session, NULL, &error_msg, &error_xpath);
    assert_string_equal("When condition \"../../loaded = 'false'\" not satisfied.",
                        error_msg);
    free(error_msg);
    free(error_xpath);
    error_msg = NULL;
    error_xpath = NULL;

    /* non-existing location of the Action in the data tree */
    rc = dm_validate_action_tree(ctx, session, "/test-module:kernel-modules/kernel-module[name='non-existent-module']/load",
            input_tree, input_cnt, true, NULL, &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);
    dm_copy_errors(session->dm_session, NULL, &error_msg, &error_xpath);
    assert_string_equal("target node is not present in the data tree", error_msg);
    assert_string_equal("/test-module:kernel-modules/kernel-module[name='non-existent-module']/load", error_xpath);
    free(error_msg);
    free(error_xpath);
    error_msg = NULL;
    error_xpath = NULL;

    /* more than one target matched by the Action's xpath */
    rc = dm_validate_action_tree(ctx, session, "/test-module:kernel-modules/kernel-module/load",
            input_tree, input_cnt, true, NULL, &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);
    dm_copy_errors(session->dm_session, NULL, &error_msg, &error_xpath);
    assert_string_equal("xpath references more than one node in the data tree.", error_msg);
    assert_string_equal("/test-module:kernel-modules/kernel-module/load", error_xpath);
    free(error_msg);
    free(error_xpath);
    error_msg = NULL;
    error_xpath = NULL;

    /* invalid action input */
    input_tree[2].type = SR_UINT16_T;
    input_tree[2].data.uint16_val = 1;
    rc = dm_validate_action_tree(ctx, session, "/test-module:kernel-modules/kernel-module[name='irqbypass.ko']/load",
            input_tree, input_cnt, true,  NULL, &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);
    dm_copy_errors(session->dm_session, NULL, &error_msg, &error_xpath);
    assert_string_equal("Unable to convert sysrepo tree into a libyang tree", error_msg);
    assert_string_equal("/test-module:kernel-modules/kernel-module[name='irqbypass.ko']/load/dry-run", error_xpath);
    free(error_msg);
    free(error_xpath);
    error_msg = NULL;
    error_xpath = NULL;

    /* action output */
    output_cnt = 3;
    output = calloc(output_cnt, sizeof(*output));
    output[0].xpath = strdup("/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/get-dependencies/dependency");
    output[0].type = SR_STRING_T;
    output[0].data.string_val = strdup("drm");
    output[1].xpath = strdup("/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/get-dependencies/dependency");
    output[1].type = SR_STRING_T;
    output[1].data.string_val = strdup("drm_kms_helper");
    output[2].xpath = strdup("/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/get-dependencies/dependency");
    output[2].type = SR_STRING_T;
    output[2].data.string_val = strdup("ttm");

    rc = dm_validate_action(ctx, session, "/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/get-dependencies",
            output, output_cnt, false,  NULL, &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(with_def_cnt, 3);
    assert_int_equal(with_def_tree_cnt, 3);
    sr_free_values(with_def, with_def_cnt);
    sr_free_trees(with_def_tree, with_def_tree_cnt);

    /* invalid action output -- invalid leafref value */
    free(output[2].xpath);
    free(output[2].data.string_val);
    output[2].xpath = strdup("/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/get-dependencies/location");
    output[2].type = SR_STRING_T;
    output[2].data.string_val = strdup("/lib/modules/kernel/"); /* invalid */
    rc = dm_validate_action(ctx, session, "/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/get-dependencies",
            output, output_cnt, false, NULL, &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);
    dm_copy_errors(session->dm_session, NULL, &error_msg, &error_xpath);
    assert_string_equal("Leafref \"/kernel-modules/kernel-module[name = current()/../../name]/location\" "
                        "of value \"/lib/modules/kernel/\" points to a non-existing leaf.", error_msg);
    assert_string_equal("/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/get-dependencies/location", error_xpath);
    free(error_msg);
    free(error_xpath);
    error_msg = NULL;
    error_xpath = NULL;

    /* valid action output -- fixed leafref value */
    free(output[2].data.string_val);
    output[2].data.string_val = strdup("/lib/modules/kernel/misc");
    rc = dm_validate_action(ctx, session, "/test-module:kernel-modules/kernel-module[name='vboxvideo.ko']/get-dependencies",
            output, output_cnt, false,  NULL, &with_def, &with_def_cnt, &with_def_tree, &with_def_tree_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(with_def_cnt, 3);
    assert_int_equal(with_def_tree_cnt, 3);
    sr_free_values(with_def, with_def_cnt);
    sr_free_trees(with_def_tree, with_def_tree_cnt);

    sr_free_trees(input_tree, input_cnt);
    sr_free_values(output, output_cnt);

    test_rp_session_cleanup(ctx, session);
    test_rp_ctx_cleanup(ctx);
}

static struct lyd_node *
get_single_node(struct lyd_node *data_tree, const char *xpath)
{
    struct ly_set *res = NULL;
    struct lyd_node *node = NULL;

    assert_non_null(data_tree);
    assert_non_null(xpath);

    res = lyd_find_path(data_tree, xpath);
    assert_non_null(res);
    assert_int_equal(1, res->number);
    node = res->set.d[0];
    assert_non_null(node);
    ly_set_free(res);

    return node;
}

static void
verify_xpath_hash(struct lyd_node *node, uint32_t expected)
{
    assert_non_null(node);
    assert_non_null(node->schema->priv);
    assert_int_equal(expected, dm_get_node_xpath_hash(node->schema));
}

static void
verify_data_depth(struct lyd_node *node, uint16_t expected)
{
    assert_non_null(node);
    assert_non_null(node->schema->priv);
    assert_int_equal(expected, dm_get_node_data_depth(node->schema));
}
void
dm_schema_node_xpath_hash(void **state)
{
    int rc;
    dm_ctx_t *ctx;
    dm_session_t *ses_ctx;
    uint32_t hash = 0;
    struct lyd_node *node = NULL;
    struct lyd_node *data_tree;

    rc = dm_init(NULL, NULL, NULL, CM_MODE_LOCAL, TEST_SCHEMA_SEARCH_DIR, TEST_DATA_SEARCH_DIR, &ctx);
    assert_int_equal(SR_ERR_OK, rc);

    dm_session_start(ctx, NULL, SR_DS_STARTUP, &ses_ctx);
    assert_int_equal(SR_ERR_OK, dm_get_datatree(ctx, ses_ctx, "ietf-interfaces", &data_tree));

    node = get_single_node(data_tree, "/ietf-interfaces:interfaces");
    hash = sr_str_hash("ietf-interfaces:interfaces");
    verify_xpath_hash(node, hash);
    verify_data_depth(node, 0);

    node = get_single_node(data_tree, "/ietf-interfaces:interfaces/interface[name='eth0']");
    hash = sr_str_hash("ietf-interfaces:interfaces") + sr_str_hash("ietf-interfaces:interface");
    verify_xpath_hash(node, hash);
    verify_data_depth(node, 1);

    node = get_single_node(data_tree, "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4");
    hash = sr_str_hash("ietf-interfaces:interfaces") + sr_str_hash("ietf-interfaces:interface")
           + sr_str_hash("ietf-ip:ipv4");
    verify_xpath_hash(node, hash);
    verify_data_depth(node, 2);

    node = get_single_node(data_tree, "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/ietf-ip:enabled");
    hash = sr_str_hash("ietf-interfaces:interfaces") + sr_str_hash("ietf-interfaces:interface")
           + sr_str_hash("ietf-ip:ipv4") + sr_str_hash("ietf-ip:enabled");
    verify_xpath_hash(node, hash);
    verify_data_depth(node, 3);

    node = get_single_node(data_tree, "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/ietf-ip:address[ietf-ip:ip='192.168.2.100']/ietf-ip:ip");
    hash = sr_str_hash("ietf-interfaces:interfaces") + sr_str_hash("ietf-interfaces:interface")
           + sr_str_hash("ietf-ip:ipv4") + sr_str_hash("ietf-ip:address") + sr_str_hash("ietf-ip:ip");
    verify_xpath_hash(node, hash);
    verify_data_depth(node, 4);

    assert_int_equal(SR_ERR_OK, dm_get_datatree(ctx, ses_ctx, "test-module", &data_tree));

    node = get_single_node(data_tree, "/test-module:main/i32");
    hash = sr_str_hash("test-module:main") + sr_str_hash("test-module:i32");
    verify_xpath_hash(node, hash);
    verify_data_depth(node, 1);

    node = get_single_node(data_tree, "/test-module:list[key='k1']/wireless");
    hash = sr_str_hash("test-module:list") + sr_str_hash("test-module:wireless");
    verify_xpath_hash(node, hash);
    verify_data_depth(node, 1);

    node = get_single_node(data_tree, "/test-module:university/classes/class[title='CCNA']/student[name='nameB']/age");
    hash = sr_str_hash("test-module:university") + sr_str_hash("test-module:classes")
           + sr_str_hash("test-module:class") + sr_str_hash("test-module:student") + sr_str_hash("test-module:age");
    verify_xpath_hash(node, hash);
    verify_data_depth(node, 4);

    assert_int_equal(SR_ERR_OK, dm_get_datatree(ctx, ses_ctx, "example-module", &data_tree));

    node = get_single_node(data_tree, "/example-module:container");
    hash = sr_str_hash("example-module:container");
    verify_xpath_hash(node, hash);
    verify_data_depth(node, 0);

    node = get_single_node(data_tree, "/example-module:container/list[key1='key1'][key2='key2']");
    hash = sr_str_hash("example-module:container") + sr_str_hash("example-module:list");
    verify_xpath_hash(node, hash);
    verify_data_depth(node, 1);

    node = get_single_node(data_tree, "/example-module:container/list[key1='key1'][key2='key2']/leaf");
    hash = sr_str_hash("example-module:container") + sr_str_hash("example-module:list")
           + sr_str_hash("example-module:leaf");
    verify_xpath_hash(node, hash);
    verify_data_depth(node, 2);

    dm_session_stop(ctx, ses_ctx);
    dm_cleanup(ctx);
}

int
main()
{
    sr_log_stderr(SR_LL_DBG);

    const struct CMUnitTest tests[] = {
            cmocka_unit_test(dm_create_cleanup),
            cmocka_unit_test(dm_get_data_tree),
            cmocka_unit_test(dm_list_schema_test),
            cmocka_unit_test(dm_validate_data_trees_test),
            cmocka_unit_test(dm_discard_changes_test),
            cmocka_unit_test(dm_get_schema_test),
            cmocka_unit_test(dm_get_schema_negative_test),
            cmocka_unit_test(dm_add_operation_test),
            cmocka_unit_test(dm_locking_test),
            cmocka_unit_test(dm_copy_module_test),
            cmocka_unit_test(dm_rpc_test),
            cmocka_unit_test(dm_state_data_test),
            cmocka_unit_test(dm_event_notif_test),
            cmocka_unit_test(dm_event_notif_parse_test),
            cmocka_unit_test(dm_action_test),
            cmocka_unit_test(dm_schema_node_xpath_hash),
    };

    return cmocka_run_group_tests(tests, setup, NULL);
}

