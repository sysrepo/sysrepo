/**
 * @file rp_dt_xpath_test.c
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
#include "rp_dt_xpath.h"
#include "sr_common.h"
#include "data_manager.h"
#include "test_data.h"

int validate_node_wrapper(dm_ctx_t *dm_ctx, dm_session_t *session, const char *xpath, struct lys_node **match){
    int rc = SR_ERR_OK;
    xp_loc_id_t *l = NULL;
    rc = xp_char_to_loc_id(xpath, &l);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_validate_node_xpath(dm_ctx, session, l, NULL, match);
    xp_free_loc_id(l);

    return rc;
}

int setup(void **state){
    int rc = 0;
    dm_ctx_t *ctx = NULL;
    rc = dm_init(NULL, NULL, NULL, TEST_SCHEMA_SEARCH_DIR, TEST_DATA_SEARCH_DIR, &ctx);
    *state = ctx;
    return rc;
}

int teardown(void **state){
    dm_ctx_t *ctx = *state;
    dm_cleanup(ctx);
    return 0;
}

void rp_dt_validate_fail(void **state)
{
    int rc = 0;
    dm_ctx_t *ctx = *state;
    dm_session_t *session = NULL;
    dm_session_start(ctx, NULL, SR_DS_STARTUP, &session);

    /* unknown model */
    rc = validate_node_wrapper(ctx, session, "/unknown-module:", NULL);
    assert_int_equal(SR_ERR_UNKNOWN_MODEL, rc);

    /* unknown model */
    rc = validate_node_wrapper(ctx, session, "/unknown-model:container", NULL);
    assert_int_equal(SR_ERR_UNKNOWN_MODEL, rc);

    /* non existing element in existing model*/
    rc = validate_node_wrapper(ctx, session, "/example-module:container/unknown", NULL);
    assert_int_equal(SR_ERR_BAD_ELEMENT, rc);

    /* non existing element in existing model*/
    rc = validate_node_wrapper(ctx, session, "/example-module:container/unknown", NULL);
    assert_int_equal(SR_ERR_BAD_ELEMENT, rc);

    /* key specified for a container*/
    rc = validate_node_wrapper(ctx, session, "/example-module:container[key='abc']", NULL);
    assert_int_equal(SR_ERR_BAD_ELEMENT, rc);

    /* key names do not match */
    rc = validate_node_wrapper(ctx, session, "/example-module:container/list[key1='a'][asf='sf']", NULL);
    assert_int_equal(SR_ERR_BAD_ELEMENT, rc);

    /* key count does not match */
    rc = validate_node_wrapper(ctx, session, "/example-module:container/list[key1='a']", NULL);
    assert_int_equal(SR_ERR_BAD_ELEMENT, rc);

    /* key count does not match */
    rc = validate_node_wrapper(ctx, session, "/example-module:container/list[key1='a'][key2='b'][unkn='as']", NULL);
    assert_int_equal(SR_ERR_BAD_ELEMENT, rc);

    dm_session_stop(ctx, session);
}

void rp_dt_validate_ok(void **state)
{
    int rc = 0;
    dm_ctx_t *ctx = *state;
    dm_session_t *session = NULL;
    dm_session_start(ctx, NULL, SR_DS_STARTUP, &session);

    /* module */
    rc = validate_node_wrapper(ctx, session, "/example-module:", NULL);
    assert_int_equal(SR_ERR_OK, rc);

    /* container */
    rc = validate_node_wrapper(ctx, session, "/example-module:container", NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = validate_node_wrapper(ctx, session, "/test-module:main", NULL);
    assert_int_equal(SR_ERR_OK, rc);

    /* list without keys*/
    rc = validate_node_wrapper(ctx, session, "/example-module:container/list", NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = validate_node_wrapper(ctx, session, "/test-module:list", NULL);
    assert_int_equal(SR_ERR_OK, rc);

    /* list with keys*/
    rc = validate_node_wrapper(ctx, session, "/example-module:container/list[key1='fasd'][key2='sfda']", NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = validate_node_wrapper(ctx, session, "/example-module:container/list[key2='sasffda'][key1='fasd']", NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = validate_node_wrapper(ctx, session, "/test-module:list[key='faaasdfsd']", NULL);
    assert_int_equal(SR_ERR_OK, rc);

    /* leaf */
    rc = validate_node_wrapper(ctx, session, "/example-module:container/list[key1='fasd'][key2='sfda']/leaf", NULL);
    assert_int_equal(SR_ERR_OK, rc);

    rc = validate_node_wrapper(ctx, session, "/test-module:main/i8", NULL);
    assert_int_equal(SR_ERR_OK, rc);

    /* xpath with augment*/
    rc = validate_node_wrapper(ctx, session, "/small-module:item/info-module:info", NULL);
    assert_int_equal(SR_ERR_OK, rc);

    dm_session_stop(ctx, session);

}

void
check_error_reporting(void **state)
{
    int rc = 0;
    dm_ctx_t *ctx = *state;
    dm_session_t *session = NULL;
    dm_session_start(ctx, NULL, SR_DS_STARTUP, &session);

    rc = validate_node_wrapper(ctx, session, "/example-module:", NULL);
    assert_int_equal(SR_ERR_OK, rc);

    assert_false(dm_has_error(session));

    /* unknown element */
    rc = validate_node_wrapper(ctx, session, "/example-module:container/unknown/unknown2", NULL);
    assert_int_equal(SR_ERR_BAD_ELEMENT, rc);

    char *err_msg = NULL;
    char *err_xpath = NULL;
    rc = dm_copy_errors(session, &err_msg, &err_xpath);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("/example-module:container/unknown", err_xpath);

    assert_true(dm_has_error(session));
    free(err_msg);
    free(err_xpath);

    dm_clear_session_errors(session);

    /* unknown model */
    rc = validate_node_wrapper(ctx, session, "/unknown-model:container/list", NULL);
    assert_int_equal(SR_ERR_UNKNOWN_MODEL, rc);

    err_msg = NULL;
    err_xpath = NULL;
    rc = dm_copy_errors(session, &err_msg, &err_xpath);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("/unknown-model:container", err_xpath);

    assert_true(dm_has_error(session));
    free(err_msg);
    free(err_xpath);

    dm_clear_session_errors(session);

    /* unknown augment*/
    rc = validate_node_wrapper(ctx, session, "/example-module:container/unknown-augment:unknown", NULL);
    assert_int_equal(SR_ERR_UNKNOWN_MODEL, rc);

    err_msg = NULL;
    err_xpath = NULL;
    rc = dm_copy_errors(session, &err_msg, &err_xpath);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("/example-module:container/unknown-augment:unknown", err_xpath);

    assert_true(dm_has_error(session));
    free(err_msg);
    free(err_xpath);

    dm_clear_session_errors(session);

    /* missing key for list*/
    rc = validate_node_wrapper(ctx, session, "/example-module:container/list[key1='a']/leaf", NULL);
    assert_int_equal(SR_ERR_BAD_ELEMENT, rc);

    err_msg = NULL;
    err_xpath = NULL;
    rc = dm_copy_errors(session, &err_msg, &err_xpath);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("/example-module:container/list", err_xpath);

    assert_true(dm_has_error(session));
    free(err_msg);
    free(err_xpath);

    dm_session_stop(ctx, session);
}

int main(){
    sr_log_stderr(SR_LL_ERR);

    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(rp_dt_validate_ok, setup, teardown),
            cmocka_unit_test_setup_teardown(rp_dt_validate_fail, setup, teardown),
            cmocka_unit_test_setup_teardown(check_error_reporting, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}


