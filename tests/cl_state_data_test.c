/**
 * @file cl_state_data_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Notifications unit tests.
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
#include <stdbool.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <pthread.h>
#include <rpc/rpc_msg.h>

#include "sysrepo.h"
#include "client_library.h"

#include "sr_common.h"
#include "test_module_helper.h"

static int
sysrepo_setup(void **state)
{
    createDataTreeExampleModule();
    createDataTreeTestModule();
    sr_conn_ctx_t *conn = NULL;
    int rc = SR_ERR_OK;

    sr_log_stderr(SR_LL_DBG);

    /* connect to sysrepo */
    rc = sr_connect("state_data_test", SR_CONN_DEFAULT, &conn);
    assert_int_equal(rc, SR_ERR_OK);

    *state = (void*)conn;
    return 0;
}

static int
sysrepo_teardown(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    /* disconnect from sysrepo */
    sr_disconnect(conn);

    return 0;
}

static int
provide_distance_travalled(sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    sr_list_t *l = (sr_list_t *) private_ctx;
    const char *xpath = "/state-module:bus/distance_travelled";
    if (0 != sr_list_add(l, strdup(xpath))) {
        SR_LOG_ERR_MSG("Error while adding into list");
    }

    *values = calloc(1, sizeof(**values));
    if (NULL == *values) {
        SR_LOG_ERR_MSG("Allocation failed");
        return -2;
    }
    (*values)->xpath = strdup(xpath);
    (*values)->type = SR_UINT32_T;
    (*values)->data.uint32_val = 999;
    *values_cnt = 1;

    return 0;
}

static int
provide_gps_located(sr_val_t **values, size_t *values_cnt, void *private_ctx) {
    sr_list_t *l = (sr_list_t *) private_ctx;
    const char *xpath = "/state-module:bus/gps_located";
    if (0 != sr_list_add(l, strdup(xpath))) {
        SR_LOG_ERR_MSG("Error while adding into list");
    }

    *values = calloc(1, sizeof(**values));
    if (NULL == *values) {
        SR_LOG_ERR_MSG("Allocation failed");
        return -2;
    }
    (*values)->xpath = strdup(xpath);
    (*values)->type = SR_BOOL_T;
    (*values)->data.bool_val = false;
    *values_cnt = 1;

    return 0;
}

int cl_dp_cpu_load (const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    const char *expected_xpath = "/state-module:cpu_load";
    if (0 == strcmp(xpath, expected_xpath)) {
        sr_list_t *l = (sr_list_t *) private_ctx;
        if (0 != sr_list_add(l, strdup(xpath))) {
            SR_LOG_ERR_MSG("Error while adding into list");
        }

        *values = calloc(1, sizeof(**values));
        if (NULL == *values) {
            SR_LOG_ERR_MSG("Allocation failed");
            return -2;
        }
        (*values)->xpath = strdup(xpath);
        (*values)->type = SR_DECIMAL64_T;
        (*values)->data.decimal64_val = 75.25;
        *values_cnt = 1;

        return 0;
    }
    SR_LOG_ERR("Data provider received unexpected xpath %s expected %s", xpath, expected_xpath);
    return -1;
}

int cl_dp_bus (const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    if (0 == strcmp(xpath, "/state-module:bus/distance_travelled"))
    {
        return provide_distance_travalled(values, values_cnt, private_ctx);
    } else if (0 == strcmp(xpath, "/state-module:bus/gps_located")) {
        return provide_gps_located(values, values_cnt, private_ctx);
    }
    SR_LOG_ERR("Data provider received unexpected xpath %s", xpath);
    return -1;
}

int cl_dp_distance_travelled (const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    const char *expected_xpath = "/state-module:bus/distance_travelled";
    if (0 == strcmp(xpath, expected_xpath)) {
        return provide_distance_travalled(values, values_cnt, private_ctx);
    }
    SR_LOG_ERR("Data provider received unexpected xpath %s expected %s", xpath, expected_xpath);
    return -1;
}

int cl_dp_gps_located (const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    const char *expected_xpath = "/state-module:bus/gps_located";
    if (0 == strcmp(xpath, "/state-module:bus/gps_located")) {
        return provide_gps_located(values, values_cnt, private_ctx);
    }
    SR_LOG_ERR("Data provider received unexpected xpath %s expected %s", xpath, expected_xpath);
    return -1;
}

int
cl_dp_incorrect_data(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    sr_list_t *l = (sr_list_t *) private_ctx;
    if (0 != sr_list_add(l, strdup(xpath))) {
        SR_LOG_ERR_MSG("Error while adding into list");
    }

    *values = calloc(1, sizeof(**values));
    if (NULL == *values) {
        SR_LOG_ERR_MSG("Allocation failed");
        return -2;
    }
    /* an attempt to to modify config data */
    (*values)->xpath = strdup("/state-module:bus/vendor_name");
    (*values)->type = SR_STRING_T;
    (*values)->data.string_val = strdup("Bus vendor");
    *values_cnt = 1;
    return 0;
}

int cl_dp_weather (const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    return SR_ERR_OK;
}

int
cl_whole_module_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t ev, void *private_ctx)
{
    /* do nothing on changes */
    return SR_ERR_OK;
}

static void
cl_parent_subscription(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_list_t *xpath_retrieved = NULL;
    sr_val_t *values = NULL;
    size_t cnt = 0;
    int rc = SR_ERR_OK;

    rc = sr_list_init(&xpath_retrieved);
    assert_int_equal(rc, SR_ERR_OK);

    /* start session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "state-module", cl_whole_module_cb, NULL,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe data providers */
    rc = sr_dp_get_items_subscribe(session, "/state-module:bus", cl_dp_bus, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* retrieve data */
    rc = sr_get_items(session, "/state-module:bus/*", &values, &cnt);
    assert_int_equal(rc, SR_ERR_OK);

    /* check data */
    assert_non_null(values);
    assert_int_equal(2, cnt);

    if (0 == strcmp("/state-module:bus/gps_located", values[0].xpath)) {
        assert_string_equal("/state-module:bus/gps_located", values[0].xpath);
        assert_int_equal(SR_BOOL_T, values[0].type);
        assert_int_equal(false, values[0].data.bool_val);

        assert_string_equal("/state-module:bus/distance_travelled", values[1].xpath);
        assert_int_equal(SR_UINT32_T, values[1].type);
        assert_int_equal(999, values[1].data.uint32_val);
    } else {
        assert_string_equal("/state-module:bus/distance_travelled", values[0].xpath);
        assert_int_equal(SR_UINT32_T, values[0].type);
        assert_int_equal(999, values[0].data.uint32_val);

        assert_string_equal("/state-module:bus/gps_located", values[1].xpath);
        assert_int_equal(SR_BOOL_T, values[1].type);
        assert_int_equal(false, values[1].data.bool_val);
    }

    sr_free_values(values, cnt);

    /* check xpath that were retrieved */
    const char *xpath_expected_to_be_loaded [] = {
        "/state-module:bus/gps_located",
        "/state-module:bus/distance_travelled"
    };
    size_t expected_xp_cnt = sizeof(xpath_expected_to_be_loaded) / sizeof(*xpath_expected_to_be_loaded);
    assert_int_equal(expected_xp_cnt, xpath_retrieved->count);

    for (size_t i = 0; i < expected_xp_cnt; i++) {
        bool match = false;
        for (size_t j = 0; xpath_retrieved->count; j++) {
            if (0 == strcmp(xpath_expected_to_be_loaded[i], (char *) xpath_retrieved->data[j])) {
                match = true;
                break;
            }
        }
        if (!match) {
            /* assert xpath that can not be found */
            assert_string_equal("", xpath_expected_to_be_loaded[i]);
        }
    }

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);

    for (size_t i = 0; i < xpath_retrieved->count; i++) {
        free(xpath_retrieved->data[i]);
    }
    sr_list_cleanup(xpath_retrieved);
}

static void
cl_exact_match_subscription(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_list_t *xpath_retrieved = NULL;
    sr_val_t *values = NULL;
    size_t cnt = 0;
    int rc = SR_ERR_OK;

    rc = sr_list_init(&xpath_retrieved);
    assert_int_equal(rc, SR_ERR_OK);

    /* start session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "state-module", cl_whole_module_cb, NULL,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe data providers */
    rc = sr_dp_get_items_subscribe(session, "/state-module:bus/distance_travelled", cl_dp_distance_travelled, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_dp_get_items_subscribe(session, "/state-module:bus/gps_located", cl_dp_gps_located, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_dp_get_items_subscribe(session, "/state-module:cpu_load", cl_dp_cpu_load, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* retrieve data */
    rc = sr_get_items(session, "/state-module:bus/*", &values, &cnt);
    assert_int_equal(rc, SR_ERR_OK);

    /* check data */
    assert_non_null(values);
    assert_int_equal(2, cnt);

    assert_string_equal("/state-module:bus/gps_located", values[0].xpath);
    assert_int_equal(SR_BOOL_T, values[0].type);
    assert_int_equal(false, values[0].data.bool_val);

    assert_string_equal("/state-module:bus/distance_travelled", values[1].xpath);
    assert_int_equal(SR_UINT32_T, values[1].type);
    assert_int_equal(999, values[1].data.uint32_val);

    sr_free_values(values, cnt);

    /* check xpath that were retrieved */
    const char *xpath_expected_to_be_loaded [] = {
        "/state-module:bus/gps_located",
        "/state-module:bus/distance_travelled"
    };
    size_t expected_xp_cnt = sizeof(xpath_expected_to_be_loaded) / sizeof(*xpath_expected_to_be_loaded);
    assert_int_equal(expected_xp_cnt, xpath_retrieved->count);

    for (size_t i = 0; i < expected_xp_cnt; i++) {
        bool match = false;
        for (size_t j = 0; xpath_retrieved->count; j++) {
            if (0 == strcmp(xpath_expected_to_be_loaded[i], (char *) xpath_retrieved->data[j])) {
                match = true;
                break;
            }
        }
        if (!match) {
            /* assert xpath that can not be found */
            assert_string_equal("", xpath_expected_to_be_loaded[i]);
        }
    }

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);

    for (size_t i = 0; i < xpath_retrieved->count; i++) {
        free(xpath_retrieved->data[i]);
    }
    sr_list_cleanup(xpath_retrieved);
}

static void
cl_partialy_covered_by_subscription(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_list_t *xpath_retrieved = NULL;
    sr_val_t *values = NULL;
    size_t cnt = 0;
    int rc = SR_ERR_OK;

    rc = sr_list_init(&xpath_retrieved);
    assert_int_equal(rc, SR_ERR_OK);

    /* start session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "state-module", cl_whole_module_cb, NULL,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe data providers - provider for distance_travelled is missing */
    rc = sr_dp_get_items_subscribe(session, "/state-module:bus/gps_located", cl_dp_gps_located, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* retrieve data */
    rc = sr_get_items(session, "/state-module:bus/*", &values, &cnt);
    assert_int_equal(rc, SR_ERR_OK);

    /* check data */
    assert_non_null(values);
    assert_int_equal(1, cnt);

    assert_string_equal("/state-module:bus/gps_located", values[0].xpath);
    assert_int_equal(SR_BOOL_T, values[0].type);
    assert_int_equal(false, values[0].data.bool_val);

    sr_free_values(values, cnt);

    /* check xpath that were retrieved */
    const char *xpath_expected_to_be_loaded [] = {
        "/state-module:bus/gps_located",
    };
    size_t expected_xp_cnt = sizeof(xpath_expected_to_be_loaded) / sizeof(*xpath_expected_to_be_loaded);
    assert_int_equal(expected_xp_cnt, xpath_retrieved->count);

    for (size_t i = 0; i < expected_xp_cnt; i++) {
        bool match = false;
        for (size_t j = 0; xpath_retrieved->count; j++) {
            if (0 == strcmp(xpath_expected_to_be_loaded[i], (char *) xpath_retrieved->data[j])) {
                match = true;
                break;
            }
        }
        if (!match) {
            /* assert xpath that can not be found */
            assert_string_equal("", xpath_expected_to_be_loaded[i]);
        }
    }

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);

    for (size_t i = 0; i < xpath_retrieved->count; i++) {
        free(xpath_retrieved->data[i]);
    }
    sr_list_cleanup(xpath_retrieved);
}

static void
cl_incorrect_data_subscription(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_list_t *xpath_retrieved = NULL;
    sr_val_t *values = NULL;
    size_t cnt = 0;
    int rc = SR_ERR_OK;

    rc = sr_list_init(&xpath_retrieved);
    assert_int_equal(rc, SR_ERR_OK);

    /* start session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "state-module", cl_whole_module_cb, NULL,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe data providers - data subscriber will try to provide config data */
    rc = sr_dp_get_items_subscribe(session, "/state-module:bus/gps_located", cl_dp_incorrect_data, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* retrieve data */
    rc = sr_get_items(session, "/state-module:bus/*", &values, &cnt);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

    /* check data */
    assert_null(values);
    assert_int_equal(0, cnt);

    /* check xpath that were retrieved */
    const char *xpath_expected_to_be_loaded [] = {
        "/state-module:bus/gps_located",
    };
    size_t expected_xp_cnt = sizeof(xpath_expected_to_be_loaded) / sizeof(*xpath_expected_to_be_loaded);
    assert_int_equal(expected_xp_cnt, xpath_retrieved->count);

    for (size_t i = 0; i < expected_xp_cnt; i++) {
        bool match = false;
        for (size_t j = 0; xpath_retrieved->count; j++) {
            if (0 == strcmp(xpath_expected_to_be_loaded[i], (char *) xpath_retrieved->data[j])) {
                match = true;
                break;
            }
        }
        if (!match) {
            /* assert xpath that can not be found */
            assert_string_equal("", xpath_expected_to_be_loaded[i]);
        }
    }

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);

    for (size_t i = 0; i < xpath_retrieved->count; i++) {
        free(xpath_retrieved->data[i]);
    }
    sr_list_cleanup(xpath_retrieved);
}

static void
cl_missing_subscription(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_list_t *xpath_retrieved = NULL;
    sr_val_t *values = NULL;
    size_t cnt = 0;
    int rc = SR_ERR_OK;

    rc = sr_list_init(&xpath_retrieved);
    assert_int_equal(rc, SR_ERR_OK);

    /* start session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "state-module", cl_whole_module_cb, NULL,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe data providers - provider for distance_travelled is missing */
    rc = sr_dp_get_items_subscribe(session, "/state-module:bus/gps_located", cl_dp_gps_located, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_dp_get_items_subscribe(session, "/state-module:bus/distance_travelled", cl_dp_distance_travelled, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* retrieve data */
    rc = sr_get_items(session, "/state-module:cpu_load", &values, &cnt);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

    /* check data */
    assert_null(values);
    assert_int_equal(0, cnt);

    /* check xpath that were retrieved */
    assert_int_equal(0, xpath_retrieved->count);

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);

    for (size_t i = 0; i < xpath_retrieved->count; i++) {
        free(xpath_retrieved->data[i]);
    }
    sr_list_cleanup(xpath_retrieved);
}

int
main()
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(cl_exact_match_subscription, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_parent_subscription, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_partialy_covered_by_subscription, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_missing_subscription, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_incorrect_data_subscription, sysrepo_setup, sysrepo_teardown),

    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
