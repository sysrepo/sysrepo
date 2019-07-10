/**
 * @file rp_dt_edit_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief
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
#include <unistd.h>
#include "data_manager.h"
#include "test_data.h"
#include "sr_common.h"
#include "rp_dt_get.h"
#include "rp_dt_edit.h"
#include "rp_dt_xpath.h"
#include "test_module_helper.h"
#include "rp_dt_context_helper.h"
#include "rp_internal.h"
#include "system_helper.h"

int
createData(void **state)
{
    createDataTreeExampleModule();
    createDataTreeTestModule();
    createDataTreeIETFinterfacesModule();
    return 0;
}

int setup(void **state){
    createData(state);
    test_rp_ctx_create(CM_MODE_LOCAL, (rp_ctx_t**)state);
    return 0;
}

int teardown(void **state){
    rp_ctx_t *ctx = *state;
    test_rp_ctx_cleanup(ctx);
    return 0;
}

static void set_item(const char *path, const char *value, sr_type_t type, rp_ctx_t *ctx,
                     rp_session_t *session)
{
    sr_val_t *val = NULL;
    int rc;
    sr_new_val(path, &val);
    if (type != SR_LIST_T) {
        sr_val_set_str_data(val, type, value);
    }
    val->type = type;
    SR_LOG_INF("Adding item %s", path);
    assert_int_equal(val->type, type);

    rc = rp_dt_set_item_wrapper(ctx, session, val->xpath, val, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);
}

static int set_items_data_and_feature_import_setup(void **state)
{
    exec_shell_command("../src/sysrepoctl --install --yang=" TEST_SOURCE_DIR "/yang/data-feat-enable-A.yang", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "data-feat-enable-A.yang", true);
    exec_shell_command("../src/sysrepoctl --install --yang=" TEST_SOURCE_DIR "/yang/data-feat-enable-B.yang", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "data-feat-enable-B.yang", true);
    exec_shell_command("../src/sysrepoctl --install --yang=" TEST_SOURCE_DIR "/yang/data-feat-enable-C.yang", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "data-feat-enable-C.yang", true);
    exec_shell_command("../src/sysrepoctl --install --yang=" TEST_SOURCE_DIR "/yang/data-feat-enable-D.yang", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "data-feat-enable-D.yang", true);

    exec_shell_command("../src/sysrepoctl --feature-enable c-feature --module data-feat-enable-C", ".*", true, 0);

    exec_shell_command("../src/sysrepoctl --install --yang=" TEST_SOURCE_DIR "/yang/data-imp-dep-A.yang", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "data-imp-dep-A.yang", true);
    exec_shell_command("../src/sysrepoctl --install --yang=" TEST_SOURCE_DIR "/yang/data-imp-dep-B.yang", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "data-imp-dep-B.yang", true);
    exec_shell_command("../src/sysrepoctl --install --yang=" TEST_SOURCE_DIR "/yang/data-imp-dep-C.yang", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "data-imp-dep-C.yang", true);

    exec_shell_command("../src/sysrepoctl --install --yang=" TEST_SOURCE_DIR "/yang/data-submodule-main.yang", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "data-submodule-main.yang", true);

    exec_shell_command("../src/sysrepoctl --install --yang=" TEST_SOURCE_DIR "/yang/feature-submodule-main.yang", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "feature-submodule-main.yang", true);

    exec_shell_command("../src/sysrepoctl --feature-enable test-submodule-feature --module feature-submodule-main", ".*", true, 0);

    setup(state);

    return 0;
}

static int set_items_data_and_feature_import_teardown(void **state)
{
    exec_shell_command("../src/sysrepoctl --feature-disable c-feature --module data-feat-enable-C", ".*", true, 0);

    exec_shell_command("../src/sysrepoctl --uninstall --module=data-feat-enable-A", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "data-feat-enable-A.yang", false);
    exec_shell_command("../src/sysrepoctl --uninstall --module=data-feat-enable-B", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "data-feat-enable-B.yang", false);
    exec_shell_command("../src/sysrepoctl --uninstall --module=data-feat-enable-C", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "data-feat-enable-C.yang", false);
    exec_shell_command("../src/sysrepoctl --uninstall --module=data-feat-enable-D", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "data-feat-enable-D.yang", false);

    exec_shell_command("../src/sysrepoctl --uninstall --module=data-imp-dep-A", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "data-imp-dep-A.yang", false);
    exec_shell_command("../src/sysrepoctl --uninstall --module=data-imp-dep-B", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "data-imp-dep-B.yang", false);
    exec_shell_command("../src/sysrepoctl --uninstall --module=data-imp-dep-C", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "data-imp-dep-C.yang", false);
    exec_shell_command("../src/sysrepoctl --uninstall --module=data-submodule-main", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "data-submodule-main.yang", false);

    exec_shell_command("../src/sysrepoctl --uninstall --module=feature-submodule-main", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "feature-submodule-main.yang", false);

    teardown(state);

    return 0;
}

static int set_data_and_feature_import_data_imp_per_setup(void **state)
{
    exec_shell_command("../src/sysrepoctl --install --yang=" TEST_SOURCE_DIR "/yang/data-imp-per-B.yang", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "data-imp-per-B.yang", true);
    exec_shell_command("../src/sysrepoctl --install --yang=" TEST_SOURCE_DIR "/yang/data-imp-per-C.yang", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "data-imp-per-C.yang", true);

    exec_shell_command("../src/sysrepoctl --feature-enable c-feature --module data-imp-per-C", ".*", true, 0);

    setup(state);

    return 0;
}

static int set_data_and_feature_import_data_imp_per_without_identity_setup(void **state)
{
    exec_shell_command("../src/sysrepoctl --install --yang=" TEST_SOURCE_DIR "/yang/data-imp-per-D.yang", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "data-imp-per-D.yang", true);

    return set_data_and_feature_import_data_imp_per_setup(state);
}

static int set_data_and_feature_import_data_imp_per_with_identity_setup(void **state)
{
    exec_shell_command("../src/sysrepoctl --install --yang=" TEST_SOURCE_DIR "/yang/data-imp-per-D-with-identity.yang", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "data-imp-per-D-with-identity.yang", true);

    return set_data_and_feature_import_data_imp_per_setup(state);
}

static int set_data_and_feature_import_data_imp_per_teardown(void **state)
{
    exec_shell_command("../src/sysrepoctl --feature-disable c-feature --module data-imp-per-C", ".*", true, 0);

    exec_shell_command("../src/sysrepoctl --uninstall --module=data-imp-per-C", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "data-imp-per-C.yang", false);
    exec_shell_command("../src/sysrepoctl --uninstall --module=data-imp-per-B,data-imp-per-A", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "data-imp-per-B-standalone.yang", false);

    teardown(state);

    return 0;
}

static int set_data_and_feature_import_data_imp_per_without_identity_teardown(void **state)
{
    exec_shell_command("../src/sysrepoctl --uninstall --module=data-imp-per-D", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "data-imp-per-D.yang", false);

    return set_data_and_feature_import_data_imp_per_teardown(state);
}

static int set_data_and_feature_import_data_imp_per_with_identity_teardown(void **state)
{
    exec_shell_command("../src/sysrepoctl --uninstall --module=data-imp-per-D-with-identity", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "data-imp-per-D-with-identity.yang", false);

    return set_data_and_feature_import_data_imp_per_teardown(state);
}

void set_items_data_and_feature_import(void **state)
{
    int rc;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;
    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;
    dm_commit_context_t *c_ctx = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    set_item("/data-feat-enable-D:d-con/d-list[name='d-foo']", NULL, SR_LIST_T,
             ctx, session);
    set_item("/data-feat-enable-D:d-con/data-feat-enable-A:a-leaf", "a-bar", SR_STRING_T,
             ctx, session);
    set_item("/data-feat-enable-B:b-con/b-list[name='b-foo']", NULL, SR_LIST_T,
             ctx, session);
    set_item("/data-feat-enable-B:b-con/b-list[name='b-foo']/ref", "d-foo", SR_STRING_T,
             ctx, session);


    rc = rp_dt_commit(ctx, session, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(e_cnt, 0);
    assert_ptr_equal(errors, NULL);

    test_rp_session_cleanup(ctx, session);
}

void set_items_data_and_import_implemented(void **state)
{
    int rc;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;
    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;
    dm_commit_context_t *c_ctx = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    set_item("/data-imp-dep-A:a-con/a-list[name='a-foo']", NULL, SR_LIST_T,
             ctx, session);
    set_item("/data-imp-dep-A:a-con/a-list[name='a-foo']/ref", "c-foo", SR_STRING_T,
             ctx, session);
    set_item("/data-imp-dep-C:c-con/c-list[name='c-foo']", NULL, SR_LIST_T,
             ctx, session);
    set_item("/data-imp-dep-C:c-con/data-imp-dep-B:b-leaf", "b-foo", SR_STRING_T,
             ctx, session);


    rc = rp_dt_commit(ctx, session, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(e_cnt, 0);
    assert_ptr_equal(errors, NULL);

    test_rp_session_cleanup(ctx, session);
}

#define D_LEAF_WITHOUT_IDENTITY "/data-imp-per-D:d-cont/d-leaf"
#define D_LEAF_WITH_IDENTITY "/data-imp-per-D-with-identity:d-cont/d-leaf"

void set_items_data_and_imported_augment(void **state, const char* d_leaf_path)
{
    int rc;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL, *session2 = NULL;
    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;
    dm_commit_context_t *c_ctx = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);
    test_rp_session_create(ctx, SR_DS_STARTUP, &session2);

    set_item("/data-imp-per-A:a-cont/a-leaf", "a-foo", SR_STRING_T,
             ctx, session);
    set_item("/data-imp-per-A:a-cont/data-imp-per-C:c-cont/c-leaf", "c-foo", SR_STRING_T,
             ctx, session);

    rc = rp_dt_commit(ctx, session, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(e_cnt, 0);
    assert_ptr_equal(errors, NULL);

    set_item(d_leaf_path, "a-foo", SR_STRING_T,
             ctx, session2);

    rc = rp_dt_commit(ctx, session2, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(e_cnt, 0);
    assert_ptr_equal(errors, NULL);

    test_rp_session_cleanup(ctx, session);
    test_rp_session_cleanup(ctx, session2);
}

void set_items_data_and_imported_augment_without_identity(void **state)
{
    set_items_data_and_imported_augment(state, D_LEAF_WITHOUT_IDENTITY);
}

void set_items_data_and_imported_augment_with_identity(void **state)
{
    set_items_data_and_imported_augment(state, D_LEAF_WITH_IDENTITY);
}

void set_and_get_items_from_top_level_in_submodule(void **state)
{
    int rc;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;
    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;
    dm_commit_context_t *c_ctx = NULL;
    sr_val_t *val = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);

    set_item("/data-submodule-main:foo/bar", "test", SR_STRING_T, ctx, session);

    rc = rp_dt_commit(ctx, session, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(e_cnt, 0);
    assert_ptr_equal(errors, NULL);

    rc = rp_dt_get_value_wrapper(ctx, session, NULL, "/data-submodule-main:foo/bar", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_int_equal(SR_STRING_T, val->type);
    assert_string_equal("test", val->data.string_val);
    sr_free_val(val);

    test_rp_session_cleanup(ctx, session);
}

void set_and_get_items_from_feature_of_submodule(void **state)
{
    int rc;
    rp_ctx_t *ctx = *state;
    rp_session_t *session = NULL;
    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;
    dm_commit_context_t *c_ctx = NULL;
    sr_val_t *val = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &session);
    set_item("/feature-submodule-mod:mod-container/feature-submodule-main:augmented-data-val", "aug-data", SR_STRING_T, ctx, session);

    rc = rp_dt_commit(ctx, session, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(e_cnt, 0);
    assert_ptr_equal(errors, NULL);

    rc = rp_dt_get_value_wrapper(ctx, session, NULL, "/feature-submodule-mod:mod-container/feature-submodule-main:augmented-data-val", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_int_equal(SR_STRING_T, val->type);
    assert_string_equal("aug-data", val->data.string_val);
    sr_free_val(val);

    test_rp_session_cleanup(ctx, session);
}

int main(){

    sr_log_stderr(SR_LL_DBG);

    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(set_items_data_and_feature_import, set_items_data_and_feature_import_setup, set_items_data_and_feature_import_teardown),
            cmocka_unit_test_setup_teardown(set_items_data_and_import_implemented, set_items_data_and_feature_import_setup, set_items_data_and_feature_import_teardown),
            cmocka_unit_test_setup_teardown(set_items_data_and_imported_augment_without_identity, set_data_and_feature_import_data_imp_per_without_identity_setup, set_data_and_feature_import_data_imp_per_without_identity_teardown),
            cmocka_unit_test_setup_teardown(set_items_data_and_imported_augment_with_identity, set_data_and_feature_import_data_imp_per_with_identity_setup, set_data_and_feature_import_data_imp_per_with_identity_teardown),
            cmocka_unit_test_setup_teardown(set_and_get_items_from_top_level_in_submodule, set_items_data_and_feature_import_setup, set_items_data_and_feature_import_teardown),
            cmocka_unit_test_setup_teardown(set_and_get_items_from_feature_of_submodule, set_items_data_and_feature_import_setup, set_items_data_and_feature_import_teardown)
    };

    return cmocka_run_group_tests(tests, setup, teardown);
}
