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
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>

#include "sysrepo.h"
#include "client_library.h"

#include "sr_common.h"
#include "test_module_helper.h"
#include "sysrepo/xpath.h"
#include "sysrepo/values.h"
#include "system_helper.h"

#define CHECK_LIST_OF_STRINGS(list, expected)                           \
    do {                                                                \
        size_t exp_cnt = sizeof(expected) / sizeof(*expected);          \
        assert_int_equal(exp_cnt, list->count);                         \
        for (size_t i = 0; i < exp_cnt; i++) {                          \
            bool match = false;                                         \
            for (size_t j = 0; list->count; j++) {                      \
                if (0 == strcmp(expected[i], (char *)list->data[j])) {  \
                    match = true;                                       \
                    break;                                              \
                }                                                       \
            }                                                           \
            if (!match) {                                               \
                /* assert string that can not be found */               \
                assert_string_equal("", expected[i]);                   \
            }                                                           \
        }                                                               \
    } while (0)


static int
sysrepo_setup(void **state)
{
    createDataTreeExampleModule();
    createDataTreeTestModule();
    createDataTreeStateModule();

    truncate(TEST_DATA_SEARCH_DIR "state-module.persist", 0);

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

static sr_val_t *
sr_val_get_by_xpath(sr_val_t *values, size_t value_cnt, const char *xpath_fmt, ...)
{
    char xpath[PATH_MAX] = { 0, };
    va_list va;

    va_start(va, xpath_fmt);
    vsnprintf(xpath, PATH_MAX, xpath_fmt, va);
    va_end(va);

    for (size_t i = 0; i < value_cnt; ++i) {
        if (0 == strcmp(values[i].xpath, xpath)) {
            return values+i;
        }
    }

    return NULL;
}

static sr_node_t *
sr_node_get_child_by_name(sr_session_ctx_t *session, sr_node_t *parent, const char *name)
{
    sr_node_t *child = NULL;

    child = sr_node_get_child(session, parent);
    while (NULL != child && 0 != strcmp(name, child->name)) {
        child = sr_node_get_next_sibling(session, child);
    }

    return child;
}

static bool
sr_list_matches_key(sr_session_ctx_t *session, sr_node_t *list, const char *key_name, const char *key_val)
{
    sr_node_t *child = NULL;

    child = sr_node_get_child(session, list);
    while (NULL != child) {
        if (0 == strcmp(key_name, child->name)) {
            switch (child->type) {
                case SR_STRING_T:
                    if (0 == strcmp(child->data.string_val, key_val)) {
                        return true;
                    }
                    break;
                case SR_UINT32_T:
                    if (atoi(key_val) == child->data.uint32_val) {
                        return true;
                    }
                    break;
                case SR_INT32_T:
                    if (atoi(key_val) == child->data.int32_val) {
                        return true;
                    }
                    break;
                default:
                    break; /* not used in unit tests */
            }
        }
        child = sr_node_get_next_sibling(session, child);
    }

    return false;
}

static sr_node_t *
sr_node_get_list_by_key(sr_session_ctx_t *session, sr_node_t *parent, const char *list_name,
        const char *key_name, const char *key_val)
{
    sr_node_t *child = NULL;

    child = sr_node_get_child(session, parent);
    while (NULL != child) {
        if (SR_LIST_T == child->type && 0 == strcmp(list_name, child->name)) {
            if (sr_list_matches_key(session, child, key_name, key_val)) {
                break;
            }
        }
        child = sr_node_get_next_sibling(session, child);
    }

    return child;
}

static int
sr_node_get_child_cnt(sr_session_ctx_t *session, sr_node_t *parent)
{
    int cnt = 0;
    sr_node_t *child = NULL;

    child = sr_node_get_child(session, parent);
    while (NULL != child) {
        ++cnt;
        child = sr_node_get_next_sibling(session, child);
    }

    return cnt;
}

static int
provide_distance_travalled_without_type(sr_val_t **values, size_t *values_cnt, void *private_ctx)
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
    /* type not set */
    (*values)->data.uint32_val = 999;
    *values_cnt = 1;

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

static int
provide_seats_reserved(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    sr_list_t *l = (sr_list_t *) private_ctx;
    int ret = 0;

    char *xp = strdup(xpath);

    if (0 != sr_list_add(l, xp)) {
        SR_LOG_ERR_MSG("Error while adding into list");
    }

    if (0 != sr_new_val(xpath, values)) {
        SR_LOG_ERR_MSG("Allocation failed");
        return -2;
    }

    sr_xpath_ctx_t xp_ctx = {0};

    char *number = sr_xpath_key_value(xp, "seats", "number", &xp_ctx);
    int num_val = 0;

    ret = sscanf(number, "%d", &num_val);
    assert_int_equal(1, ret);

    sr_xpath_recover(&xp_ctx);

    (*values)[0].type = SR_BOOL_T;
    (*values)[0].data.bool_val = (0 == num_val % 2);

    *values_cnt = 1;

    return 0;
}

int cl_dp_cpu_load (const char *xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, const char *original_xpath, void *private_ctx)
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

int cl_dp_bus (const char *xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, const char *original_xpath, void *private_ctx)
{
    if (0 == strcmp(xpath, "/state-module:bus/distance_travelled"))
    {
        return provide_distance_travalled(values, values_cnt, private_ctx);
    } else if (0 == strcmp(xpath, "/state-module:bus/gps_located")) {
        return provide_gps_located(values, values_cnt, private_ctx);
    } else if (sr_xpath_node_name_eq(xpath, "reserved")) {
        return provide_seats_reserved(xpath, values, values_cnt, private_ctx);
    }
    SR_LOG_ERR("Data provider received unexpected xpath %s", xpath);
    return -1;
}

int cl_dp_bus_req_id (const char *xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, const char *original_xpath, void *private_ctx)
{
    sr_list_t *l = (sr_list_t *) private_ctx;
    if (0 != sr_list_add(l, (char *)request_id)) {
        SR_LOG_ERR_MSG("Error while adding into list");
    }
    return 0;
}

int cl_dp_distance_travelled (const char *xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, const char *original_xpath, void *private_ctx)
{
    const char *expected_xpath = "/state-module:bus/distance_travelled";
    if (0 == strcmp(xpath, expected_xpath)) {
        return provide_distance_travalled(values, values_cnt, private_ctx);
    }
    SR_LOG_ERR("Data provider received unexpected xpath %s expected %s", xpath, expected_xpath);
    return -1;
}

int cl_dp_gps_located (const char *xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, const char *original_xpath, void *private_ctx)
{
    const char *expected_xpath = "/state-module:bus/gps_located";
    if (0 == strcmp(xpath, "/state-module:bus/gps_located")) {
        return provide_gps_located(values, values_cnt, private_ctx);
    }
    SR_LOG_ERR("Data provider received unexpected xpath %s expected %s", xpath, expected_xpath);
    return -1;
}

int cl_dp_seats_reserved (const char *xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, const char *original_xpath, void *private_ctx)
{
    const char *expected_xpath = "/state-module:bus/seats/reserved";
    if (sr_xpath_node_name_eq(xpath, "reserved")) {
        return provide_seats_reserved(xpath, values, values_cnt, private_ctx);
    }
    SR_LOG_ERR("Data provider received unexpected xpath %s expected %s", xpath, expected_xpath);
    return -1;
}

int cl_dp_missing_type_bus (const char *xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, const char *original_xpath, void *private_ctx)
{
    if (0 == strcmp(xpath, "/state-module:bus/distance_travelled"))
    {
        return provide_distance_travalled_without_type(values, values_cnt, private_ctx);
    } else if (0 == strcmp(xpath, "/state-module:bus/gps_located")) {
        return provide_gps_located(values, values_cnt, private_ctx);
    } else if (sr_xpath_node_name_eq(xpath, "reserved")) {
        return provide_seats_reserved(xpath, values, values_cnt, private_ctx);
    }
    SR_LOG_ERR("Data provider received unexpected xpath %s", xpath);
    return -1;
}

int
cl_dp_incorrect_data(const char *xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, const char *original_xpath, void *private_ctx)
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

int cl_dp_weather (const char *xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, const char *original_xpath, void *private_ctx)
{
    return SR_ERR_OK;
}

int cl_dp_sky (const char *xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, const char *original_xpath, void *private_ctx)
{
    const char *expected_xpath = "/state-module:weather/sky";
    if (0 == strcmp(xpath, expected_xpath)) {
        sr_list_t *l = (sr_list_t *) private_ctx;
        if (0 != sr_list_add(l, strdup(xpath))) {
            SR_LOG_ERR_MSG("Error while adding into list");
        }

        sr_new_val(xpath, values);
        sr_val_set_str_data(*values, SR_ENUM_T, "cloudy");
        *values_cnt = 1;

        return 0;
    }
    SR_LOG_ERR("Data provider received unexpected xpath %s expected %s", xpath, expected_xpath);
    return -1;
}

int cl_dp_humidity (const char *xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, const char *original_xpath, void *private_ctx)
{
    const char *expected_xpath = "/state-module:weather/humidity";
    if (0 == strcmp(xpath, expected_xpath)) {
        sr_list_t *l = (sr_list_t *) private_ctx;
        if (0 != sr_list_add(l, strdup(xpath))) {
            SR_LOG_ERR_MSG("Error while adding into list");
        }

        sr_new_val(xpath, values);
        (*values)[0].type = SR_UINT8_T;
        (*values)[0].data.uint8_val = 42;
        *values_cnt = 1;

        return 0;
    }
    SR_LOG_ERR("Data provider received unexpected xpath %s expected %s", xpath, expected_xpath);
    return -1;
}

int
cl_whole_module_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t ev, void *private_ctx)
{
    /* do nothing on changes */
    return SR_ERR_OK;
}

int
cl_dp_traffic_stats(const char *xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, const char *original_xpath, void *private_ctx)
{
    sr_list_t *l = (sr_list_t *) private_ctx;
    int rc = SR_ERR_OK;
    #define MAX_LEN 200
    if (0 != sr_list_add(l, strdup(xpath))) {
        SR_LOG_ERR_MSG("Error while adding into list");
    }

    if (0 == strcmp("/state-module:traffic_stats", xpath)) {
        *values = calloc(2, sizeof(**values));
        if (NULL == *values) {
            SR_LOG_ERR_MSG("Allocation failed");
            return -2;
        }
        (*values)[0].xpath = strdup("/state-module:traffic_stats/number_of_accidents");
        (*values)[0].type = SR_UINT8_T;
        (*values)[0].data.uint8_val = 2;

        (*values)[1].xpath = strdup("/state-module:traffic_stats/cross_roads_offline_count");
        (*values)[1].type = SR_UINT8_T;
        (*values)[1].data.uint8_val = 9;
        *values_cnt = 2;
    } else if (0 == strcmp("/state-module:traffic_stats/cross_road", xpath)) {
        *values = calloc(5, sizeof(**values));
        if (NULL == *values) {
            SR_LOG_ERR_MSG("Allocation failed");
            return -2;
        }
        (*values)[0].xpath = strdup("/state-module:traffic_stats/cross_road[id='0']");
        (*values)[0].type = SR_LIST_T;

        (*values)[1].xpath = strdup("/state-module:traffic_stats/cross_road[id='0']/status");
        (*values)[1].type = SR_ENUM_T;
        (*values)[1].data.enum_val = strdup("manual");

        (*values)[2].xpath = strdup("/state-module:traffic_stats/cross_road[id='1']/status");
        (*values)[2].type = SR_ENUM_T;
        (*values)[2].data.enum_val = strdup("automatic");

        (*values)[3].xpath = strdup("/state-module:traffic_stats/cross_road[id='2']/status");
        (*values)[3].type = SR_ENUM_T;
        (*values)[3].data.enum_val = strdup("automatic");

        (*values)[4].xpath = strdup("/state-module:traffic_stats/cross_road[id='2']/average_wait_time");
        (*values)[4].type = SR_UINT32_T;
        (*values)[4].data.uint32_val = 15;
        *values_cnt = 5;
    } else if (0 == strncmp("traffic_light", sr_xpath_node_name(xpath), strlen("traffic_light"))) {
        char xp[MAX_LEN] = {0};
        const char *colors[] = {"red", "orange", "green"};
        sr_xpath_ctx_t xp_ctx = {0};

        *values = calloc(3, sizeof(**values));
        if (NULL == *values) {
            SR_LOG_ERR_MSG("Allocation failed");
            return -2;
        }

        char *cross_road_id = NULL;
        int cr_index = -1;
        char *xp_dup = strdup(xpath);

        if (NULL != xp_dup) {
            cross_road_id = sr_xpath_key_value(xp_dup, "cross_road", "id", &xp_ctx);
            if (NULL != cross_road_id) {
                cr_index = atoi(cross_road_id);
            }
        }
        free(xp_dup);

        for (int i = 0; i < 3; i++) {
            snprintf(xp, MAX_LEN, "%s[name='%c']/color", xpath, 'a'+i );
            (*values)[i].xpath = strdup(xp);
            (*values)[i].type = SR_ENUM_T;
            (*values)[i].data.enum_val = strdup(colors[(cr_index + i)%3]);
        }
        *values_cnt = 3;
    } else if (0 == strncmp("advanced_info", sr_xpath_node_name(xpath), strlen("advanced_info"))) {
        char xp[MAX_LEN] = {0};
        sr_xpath_ctx_t xp_ctx = {0};
        char *cross_road_id = NULL;
        int cr_index = -1;
        char *xp_dup = strdup(xpath);

        if (NULL != xp_dup) {
            cross_road_id = sr_xpath_key_value(xp_dup, "cross_road", "id", &xp_ctx);
            if (NULL != cross_road_id) {
                cr_index = atoi(cross_road_id);
            }
        }
        free(xp_dup);

        if (0 == cr_index) {
            /* advanced_info container is only in the first list instance */
            *values_cnt = 2;
            rc = sr_new_values(*values_cnt, values);
            if (SR_ERR_OK != rc) return rc;
        } else {
            *values = NULL;
            *values_cnt = 0;
            return 0;
        }

        snprintf(xp, MAX_LEN, "%s/latitude", xpath);
        sr_val_set_xpath(&(*values)[0], xp);
        sr_val_set_str_data(&(*values)[0], SR_STRING_T, "48.729885N");

        snprintf(xp, MAX_LEN, "%s/longitude", xpath);
        sr_val_set_xpath(&(*values)[1], xp);
        sr_val_set_str_data(&(*values)[1], SR_STRING_T, "19.137425E");
    }
    else {
        *values = NULL;
        *values_cnt = 0;
    }

    return 0;
}

int
cl_dp_cross_road(const char *xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, const char *original_xpath, void *private_ctx)
{
    sr_list_t *l = (sr_list_t *) private_ctx;
    if (0 != sr_list_add(l, strdup(xpath))) {
        SR_LOG_ERR_MSG("Error while adding into list");
    }

    if (0 == strcmp("/state-module:traffic_stats/cross_road", xpath)) {
        *values = calloc(5, sizeof(**values));
        if (NULL == *values) {
            SR_LOG_ERR_MSG("Allocation failed");
            return -2;
        }
        (*values)[0].xpath = strdup("/state-module:traffic_stats/cross_road[id='0']");
        (*values)[0].type = SR_LIST_T;

        (*values)[1].xpath = strdup("/state-module:traffic_stats/cross_road[id='0']/status");
        (*values)[1].type = SR_ENUM_T;
        (*values)[1].data.enum_val = strdup("manual");

        (*values)[2].xpath = strdup("/state-module:traffic_stats/cross_road[id='1']/status");
        (*values)[2].type = SR_ENUM_T;
        (*values)[2].data.enum_val = strdup("automatic");

        (*values)[3].xpath = strdup("/state-module:traffic_stats/cross_road[id='2']/status");
        (*values)[3].type = SR_ENUM_T;
        (*values)[3].data.enum_val = strdup("automatic");

        (*values)[4].xpath = strdup("/state-module:traffic_stats/cross_road[id='2']/average_wait_time");
        (*values)[4].type = SR_UINT32_T;
        (*values)[4].data.uint32_val = 15;
        *values_cnt = 5;
    } else {
        *values = NULL;
        *values_cnt = 0;
    }

    return 0;
}

int
cl_dp_wind(const char *xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, const char *original_xpath, void *private_ctx)
{
    sr_list_t *l = (sr_list_t *) private_ctx;
    if (0 != sr_list_add(l, strdup(xpath))) {
        SR_LOG_ERR_MSG("Error while adding into list");
    }

    if (0 == strcmp("/state-module:weather/wind", xpath)) {
        *values = calloc(2, sizeof(**values));
        if (NULL == *values) {
            SR_LOG_ERR_MSG("Allocation failed");
            return -2;
        }
        (*values)[0].xpath = strdup("/state-module:weather/wind/speed");
        (*values)[0].type = SR_UINT8_T;
        (*values)[0].data.uint8_val = 42;

        (*values)[1].xpath = strdup("/state-module:weather/wind/direction");
        (*values)[1].type = SR_STRING_T;
        (*values)[1].data.string_val = strdup("north");

        *values_cnt = 2;
    } else {
        *values = NULL;
        *values_cnt = 0;
    }

    return 0;
}

int
cl_dp_wind_speed(const char *xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, const char *original_xpath, void *private_ctx)
{
    sr_list_t *l = (sr_list_t *) private_ctx;
    if (0 != sr_list_add(l, strdup(xpath))) {
        SR_LOG_ERR_MSG("Error while adding into list");
    }

    if (0 == strcmp("/state-module:weather/wind/speed", xpath)) {
        *values = calloc(1, sizeof(**values));
        if (NULL == *values) {
            SR_LOG_ERR_MSG("Allocation failed");
            return -2;
        }
        (*values)[0].xpath = strdup("/state-module:weather/wind/speed");
        (*values)[0].type = SR_UINT8_T;
        (*values)[0].data.uint8_val = 54;

        *values_cnt = 1;
    } else {
        *values = NULL;
        *values_cnt = 0;
    }

    return 0;
}

int
cl_dp_traffic_light(const char *xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, const char *original_xpath, void *private_ctx)
{
    sr_list_t *l = (sr_list_t *) private_ctx;
    if (0 != sr_list_add(l, strdup(xpath))) {
        SR_LOG_ERR_MSG("Error while adding into list");
    }

    if (0 == strncmp("traffic_light", sr_xpath_node_name(xpath), strlen("traffic_light"))) {
        char xp[MAX_LEN] = {0};
        const char *colors[] = {"red", "orange", "green"};
        sr_xpath_ctx_t xp_ctx = {0};

        *values = calloc(3, sizeof(**values));
        if (NULL == *values) {
            SR_LOG_ERR_MSG("Allocation failed");
            return -2;
        }

        char *cross_road_id = NULL;
        int cr_index = -1;
        char *xp_dup = strdup(xpath);

        if (NULL != xp_dup) {
            cross_road_id = sr_xpath_key_value(xp_dup, "cross_road", "id", &xp_ctx);
            if (NULL != cross_road_id) {
                cr_index = atoi(cross_road_id);
            }
        }
        free(xp_dup);

        for (int i = 0; i < 3; i++) {
            snprintf(xp, MAX_LEN, "%s[name='%c']/color", xpath, 'a'+i );
            (*values)[i].xpath = strdup(xp);
            (*values)[i].type = SR_ENUM_T;
            (*values)[i].data.enum_val = strdup(colors[(cr_index + i)%3]);
        }
        *values_cnt = 3;
    } else {
        *values = NULL;
        *values_cnt = 0;
    }

    return 0;
}

static int
cl_dp_card_state(const char *xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, const char *original_xpath, void *private_ctx)
{
    sr_val_t *v = NULL;
    int rc = SR_ERR_OK;

    sr_list_t *l = (sr_list_t *) private_ctx;
    if (0 != sr_list_add(l, strdup(xpath))) {
        SR_LOG_ERR_MSG("Error while adding into list");
    }

    /* allocate space for data to return */
    rc = sr_new_values(1, &v);
    if (SR_ERR_OK != rc) {
        return rc;
    }

    sr_val_build_xpath(&v[0], "%s/%s", xpath, "c_state");
    sr_val_set_str_data(&v[0], SR_STRING_T, "OK");

    *values = v;
    *values_cnt = 1;

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
    sr_val_t *values = NULL, *value = NULL;
    size_t cnt = 0;
    char buf[10] = { 0, };
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
    rc = sr_get_items(session, "/state-module:bus//*", &values, &cnt);
    assert_int_equal(rc, SR_ERR_OK);

    /* check data */
    assert_non_null(values);
    assert_int_equal(42, cnt);

    value = sr_val_get_by_xpath(values, cnt, "/state-module:bus/gps_located");
    assert_non_null(value);
    assert_int_equal(SR_BOOL_T, value->type);
    assert_int_equal(false, value->data.bool_val);

    value = sr_val_get_by_xpath(values, cnt, "/state-module:bus/distance_travelled");
    assert_non_null(value);
    assert_int_equal(SR_UINT32_T, value->type);
    assert_int_equal(999, value->data.uint32_val);

    for (size_t i = 0; i < 10; ++i) {
        /* list instance */
        value = sr_val_get_by_xpath(values, cnt, "/state-module:bus/seats[number='%d']", i);
        assert_non_null(value);
        assert_int_equal(SR_LIST_T, value->type);
        /* number */
        value = sr_val_get_by_xpath(values, cnt, "/state-module:bus/seats[number='%d']/number", i);
        assert_non_null(value);
        assert_int_equal(SR_INT32_T, value->type);
        assert_int_equal(i, value->data.int32_val);
        /* name */
        value = sr_val_get_by_xpath(values, cnt, "/state-module:bus/seats[number='%d']/name", i);
        assert_non_null(value);
        assert_int_equal(SR_STRING_T, value->type);
        snprintf(buf, 10, "seat-%lu", i);
        assert_string_equal(buf, value->data.string_val);
        /* reserved */
        value = sr_val_get_by_xpath(values, cnt, "/state-module:bus/seats[number='%d']/reserved", i);
        assert_non_null(value);
        assert_int_equal(SR_BOOL_T, value->type);
        if (0 == i % 2) {
            assert_true(value->data.bool_val);
        } else {
            assert_false(value->data.bool_val);
        }
    }

    sr_free_values(values, cnt);

    /* check xpath that were retrieved */
    const char *xpath_expected_to_be_loaded [] = {
        "/state-module:bus/gps_located",
        "/state-module:bus/distance_travelled",
        "/state-module:bus/seats[number='0']/reserved",
        "/state-module:bus/seats[number='1']/reserved",
        "/state-module:bus/seats[number='2']/reserved",
        "/state-module:bus/seats[number='3']/reserved",
        "/state-module:bus/seats[number='4']/reserved",
        "/state-module:bus/seats[number='5']/reserved",
        "/state-module:bus/seats[number='6']/reserved",
        "/state-module:bus/seats[number='7']/reserved",
        "/state-module:bus/seats[number='8']/reserved",
        "/state-module:bus/seats[number='9']/reserved",
    };
    CHECK_LIST_OF_STRINGS(xpath_retrieved, xpath_expected_to_be_loaded);

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);

    for (size_t i = 0; i < xpath_retrieved->count; i++) {
        free(xpath_retrieved->data[i]);
    }
    sr_list_cleanup(xpath_retrieved);
}

static void
cl_parent_subscription_tree(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_list_t *xpath_retrieved = NULL;
    sr_node_t *tree = NULL, *node = NULL;
    char buf[10] = { 0, };
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

    for (int j = 0; j < 2; ++j) {
        /* retrieve data using the tree API */
        rc = sr_get_subtree(session, "/state-module:bus", 0 == j ? 0 : SR_GET_SUBTREE_ITERATIVE, &tree);
        assert_int_equal(rc, SR_ERR_OK);

        /* check data */
        assert_non_null(tree);
        assert_string_equal("bus", tree->name);
        assert_string_equal("state-module", tree->module_name);
        assert_false(tree->dflt);
        assert_int_equal(SR_CONTAINER_T, tree->type);
        assert_int_equal(12, sr_node_get_child_cnt(session, tree));
        /* gps located */
        node = sr_node_get_child_by_name(session, tree, "gps_located");
        assert_non_null(node);
        assert_string_equal("gps_located", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_BOOL_T, node->type);
        assert_false(node->data.bool_val);
        assert_null(node->first_child);
        /* distance travelled */
        node = sr_node_get_child_by_name(session, tree, "distance_travelled");
        assert_non_null(node);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_UINT32_T, node->type);
        assert_int_equal(999, node->data.uint32_val);
        assert_null(node->first_child);
        /* seats */
        for (size_t i = 0; i < 10; ++i) {
            /* list instance */
            snprintf(buf, 10, "%lu", i);
            node = sr_node_get_list_by_key(session, tree, "seats", "number", buf);
            assert_non_null(node);
            assert_null(node->module_name);
            assert_false(node->dflt);
            assert_int_equal(SR_LIST_T, node->type);
            assert_int_equal(3, sr_node_get_child_cnt(session, node));
            /* number */
            node = sr_node_get_child_by_name(session, node, "number");
            assert_non_null(node);
            assert_string_equal("number", node->name);
            assert_null(node->module_name);
            assert_false(node->dflt);
            assert_int_equal(SR_INT32_T, node->type);
            assert_int_equal(i, node->data.int32_val);
            assert_null(node->first_child);
            node = node->parent;
            /* name */
            snprintf(buf, 10, "seat-%lu", i);
            node = sr_node_get_child_by_name(session, node, "name");
            assert_non_null(node);
            assert_string_equal("name", node->name);
            assert_null(node->module_name);
            assert_false(node->dflt);
            assert_int_equal(SR_STRING_T, node->type);
            assert_string_equal(buf, node->data.string_val);
            assert_null(node->first_child);
            node = node->parent;
            /* reserved */
            node = sr_node_get_child_by_name(session, node, "reserved");
            assert_non_null(node);
            assert_string_equal("reserved", node->name);
            assert_null(node->module_name);
            assert_false(node->dflt);
            assert_int_equal(SR_BOOL_T, node->type);
            if (0 == i % 2) {
                assert_true(node->data.bool_val);
            } else {
                assert_false(node->data.bool_val);
            }
            assert_null(node->first_child);
        }

        sr_free_tree(tree);

        /* check xpath that were retrieved */
        if (0 == j) {
            const char *xpath_expected_to_be_loaded [] = {
                "/state-module:bus/gps_located",
                "/state-module:bus/distance_travelled",
                "/state-module:bus/seats[number='0']/reserved",
                "/state-module:bus/seats[number='1']/reserved",
                "/state-module:bus/seats[number='2']/reserved",
                "/state-module:bus/seats[number='3']/reserved",
                "/state-module:bus/seats[number='4']/reserved",
                "/state-module:bus/seats[number='5']/reserved",
                "/state-module:bus/seats[number='6']/reserved",
                "/state-module:bus/seats[number='7']/reserved",
                "/state-module:bus/seats[number='8']/reserved",
                "/state-module:bus/seats[number='9']/reserved",
            };
            CHECK_LIST_OF_STRINGS(xpath_retrieved, xpath_expected_to_be_loaded);
        } else {
            const char *xpath_expected_to_be_loaded [] = {
                "/state-module:bus/gps_located",
                "/state-module:bus/distance_travelled",
                "/state-module:bus/gps_located",
                "/state-module:bus/distance_travelled",
                "/state-module:bus/seats[number='0']/reserved",
                "/state-module:bus/seats[number='1']/reserved",
                "/state-module:bus/seats[number='2']/reserved",
                "/state-module:bus/seats[number='3']/reserved",
                "/state-module:bus/seats[number='4']/reserved",
                "/state-module:bus/seats[number='5']/reserved",
                "/state-module:bus/seats[number='6']/reserved",
                "/state-module:bus/seats[number='7']/reserved",
                "/state-module:bus/seats[number='8']/reserved",
                "/state-module:bus/seats[number='9']/reserved",
            };
            CHECK_LIST_OF_STRINGS(xpath_retrieved, xpath_expected_to_be_loaded);
        }

        for (size_t i = 0; i < xpath_retrieved->count; i++) {
            free(xpath_retrieved->data[i]);
        }
        xpath_retrieved->count = 0;
    }

    /* cleanup */
    sr_list_cleanup(xpath_retrieved);
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);
}

static void
cl_exact_match_subscription(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_list_t *xpath_retrieved = NULL;
    sr_val_t *values = NULL, *value = NULL;
    size_t cnt = 0;
    char buf[10] = { 0, };
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

    rc = sr_dp_get_items_subscribe(session, "/state-module:bus/seats/reserved", cl_dp_seats_reserved, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_dp_get_items_subscribe(session, "/state-module:cpu_load", cl_dp_cpu_load, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* retrieve data */
    rc = sr_get_items(session, "/state-module:bus//*", &values, &cnt);
    assert_int_equal(rc, SR_ERR_OK);

    /* check data */
    assert_non_null(values);
    assert_int_equal(42, cnt);

    value = sr_val_get_by_xpath(values, cnt, "/state-module:bus/gps_located");
    assert_non_null(value);
    assert_int_equal(SR_BOOL_T, value->type);
    assert_int_equal(false, value->data.bool_val);

    value = sr_val_get_by_xpath(values, cnt, "/state-module:bus/distance_travelled");
    assert_non_null(value);
    assert_int_equal(SR_UINT32_T, value->type);
    assert_int_equal(999, value->data.uint32_val);

    for (size_t i = 0; i < 10; ++i) {
        /* list instance */
        value = sr_val_get_by_xpath(values, cnt, "/state-module:bus/seats[number='%d']", i);
        assert_non_null(value);
        assert_int_equal(SR_LIST_T, value->type);
        /* number */
        value = sr_val_get_by_xpath(values, cnt, "/state-module:bus/seats[number='%d']/number", i);
        assert_non_null(value);
        assert_int_equal(SR_INT32_T, value->type);
        assert_int_equal(i, value->data.int32_val);
        /* name */
        value = sr_val_get_by_xpath(values, cnt, "/state-module:bus/seats[number='%d']/name", i);
        assert_non_null(value);
        assert_int_equal(SR_STRING_T, value->type);
        snprintf(buf, 10, "seat-%lu", i);
        assert_string_equal(buf, value->data.string_val);
        /* reserved */
        value = sr_val_get_by_xpath(values, cnt, "/state-module:bus/seats[number='%d']/reserved", i);
        assert_non_null(value);
        assert_int_equal(SR_BOOL_T, value->type);
        if (0 == i % 2) {
            assert_true(value->data.bool_val);
        } else {
            assert_false(value->data.bool_val);
        }
    }

    sr_free_values(values, cnt);

    /* check xpath that were retrieved */
    const char *xpath_expected_to_be_loaded [] = {
        "/state-module:bus/gps_located",
        "/state-module:bus/distance_travelled",
        "/state-module:bus/seats[number='0']/reserved",
        "/state-module:bus/seats[number='1']/reserved",
        "/state-module:bus/seats[number='2']/reserved",
        "/state-module:bus/seats[number='3']/reserved",
        "/state-module:bus/seats[number='4']/reserved",
        "/state-module:bus/seats[number='5']/reserved",
        "/state-module:bus/seats[number='6']/reserved",
        "/state-module:bus/seats[number='7']/reserved",
        "/state-module:bus/seats[number='8']/reserved",
        "/state-module:bus/seats[number='9']/reserved",
    };
    CHECK_LIST_OF_STRINGS(xpath_retrieved, xpath_expected_to_be_loaded);

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);

    for (size_t i = 0; i < xpath_retrieved->count; i++) {
        free(xpath_retrieved->data[i]);
    }
    sr_list_cleanup(xpath_retrieved);
}

static void
cl_exact_match_subscription_tree(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_list_t *xpath_retrieved = NULL;
    sr_node_t *tree = NULL, *node = NULL;
    char buf[10] = { 0, };
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

    rc = sr_dp_get_items_subscribe(session, "/state-module:bus/seats/reserved", cl_dp_seats_reserved, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    for (int j = 0; j < 2; ++j) {
        /* retrieve data using the tree API */
        rc = sr_get_subtree(session, "/state-module:bus", 0 == j ? 0 : SR_GET_SUBTREE_ITERATIVE, &tree);
        assert_int_equal(rc, SR_ERR_OK);

        /* check data */
        assert_non_null(tree);
        assert_string_equal("bus", tree->name);
        assert_string_equal("state-module", tree->module_name);
        assert_false(tree->dflt);
        assert_int_equal(SR_CONTAINER_T, tree->type);
        assert_int_equal(12, sr_node_get_child_cnt(session, tree));
        /* gps located */
        node = sr_node_get_child_by_name(session, tree, "gps_located");
        assert_non_null(node);
        assert_string_equal("gps_located", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_BOOL_T, node->type);
        assert_false(node->data.bool_val);
        assert_null(node->first_child);
        /* distance travelled */
        node = sr_node_get_child_by_name(session, tree, "distance_travelled");
        assert_non_null(node);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_UINT32_T, node->type);
        assert_int_equal(999, node->data.uint32_val);
        assert_null(node->first_child);
        /* seats */
        for (size_t i = 0; i < 10; ++i) {
            /* list instance */
            snprintf(buf, 10, "%lu", i);
            node = sr_node_get_list_by_key(session, tree, "seats", "number", buf);
            assert_non_null(node);
            assert_null(node->module_name);
            assert_false(node->dflt);
            assert_int_equal(SR_LIST_T, node->type);
            assert_int_equal(3, sr_node_get_child_cnt(session, node));
            /* number */
            node = sr_node_get_child_by_name(session, node, "number");
            assert_non_null(node);
            assert_string_equal("number", node->name);
            assert_null(node->module_name);
            assert_false(node->dflt);
            assert_int_equal(SR_INT32_T, node->type);
            assert_int_equal(i, node->data.int32_val);
            assert_null(node->first_child);
            node = node->parent;
            /* name */
            snprintf(buf, 10, "seat-%lu", i);
            node = sr_node_get_child_by_name(session, node, "name");
            assert_non_null(node);
            assert_string_equal("name", node->name);
            assert_null(node->module_name);
            assert_false(node->dflt);
            assert_int_equal(SR_STRING_T, node->type);
            assert_string_equal(buf, node->data.string_val);
            assert_null(node->first_child);
            node = node->parent;
            /* reserved */
            node = sr_node_get_child_by_name(session, node, "reserved");
            assert_non_null(node);
            assert_string_equal("reserved", node->name);
            assert_null(node->module_name);
            assert_false(node->dflt);
            assert_int_equal(SR_BOOL_T, node->type);
            if (0 == i % 2) {
                assert_true(node->data.bool_val);
            } else {
                assert_false(node->data.bool_val);
            }
            assert_null(node->first_child);
        }

        sr_free_tree(tree);

        /* check xpath that were retrieved */
        if (0 == j) {
            const char *xpath_expected_to_be_loaded [] = {
                "/state-module:bus/gps_located",
                "/state-module:bus/distance_travelled",
                "/state-module:bus/seats[number='0']/reserved",
                "/state-module:bus/seats[number='1']/reserved",
                "/state-module:bus/seats[number='2']/reserved",
                "/state-module:bus/seats[number='3']/reserved",
                "/state-module:bus/seats[number='4']/reserved",
                "/state-module:bus/seats[number='5']/reserved",
                "/state-module:bus/seats[number='6']/reserved",
                "/state-module:bus/seats[number='7']/reserved",
                "/state-module:bus/seats[number='8']/reserved",
                "/state-module:bus/seats[number='9']/reserved",
            };
            CHECK_LIST_OF_STRINGS(xpath_retrieved, xpath_expected_to_be_loaded);
        } else {
            const char *xpath_expected_to_be_loaded [] = {
                "/state-module:bus/gps_located",
                "/state-module:bus/distance_travelled",
                "/state-module:bus/gps_located",
                "/state-module:bus/distance_travelled",
                "/state-module:bus/seats[number='0']/reserved",
                "/state-module:bus/seats[number='1']/reserved",
                "/state-module:bus/seats[number='2']/reserved",
                "/state-module:bus/seats[number='3']/reserved",
                "/state-module:bus/seats[number='4']/reserved",
                "/state-module:bus/seats[number='5']/reserved",
                "/state-module:bus/seats[number='6']/reserved",
                "/state-module:bus/seats[number='7']/reserved",
                "/state-module:bus/seats[number='8']/reserved",
                "/state-module:bus/seats[number='9']/reserved",
            };
            CHECK_LIST_OF_STRINGS(xpath_retrieved, xpath_expected_to_be_loaded);
        }

        for (size_t i = 0; i < xpath_retrieved->count; i++) {
            free(xpath_retrieved->data[i]);
        }
        xpath_retrieved->count = 0;
    }

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);

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
    sr_val_t *values = NULL, *value = NULL;
    size_t cnt = 0;
    char buf[10] = { 0, };
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
    rc = sr_get_items(session, "/state-module:bus//*", &values, &cnt);
    assert_int_equal(rc, SR_ERR_OK);

    /* check data */
    assert_non_null(values);
    assert_int_equal(31, cnt);

    value = sr_val_get_by_xpath(values, cnt, "/state-module:bus/gps_located");
    assert_non_null(value);
    assert_int_equal(SR_BOOL_T, value->type);
    assert_int_equal(false, value->data.bool_val);

    for (size_t i = 0; i < 10; ++i) {
        /* list instance */
        value = sr_val_get_by_xpath(values, cnt, "/state-module:bus/seats[number='%d']", i);
        assert_non_null(value);
        assert_int_equal(SR_LIST_T, value->type);
        /* number */
        value = sr_val_get_by_xpath(values, cnt, "/state-module:bus/seats[number='%d']/number", i);
        assert_non_null(value);
        assert_int_equal(SR_INT32_T, value->type);
        assert_int_equal(i, value->data.int32_val);
        /* name */
        value = sr_val_get_by_xpath(values, cnt, "/state-module:bus/seats[number='%d']/name", i);
        assert_non_null(value);
        assert_int_equal(SR_STRING_T, value->type);
        snprintf(buf, 10, "seat-%lu", i);
        assert_string_equal(buf, value->data.string_val);
    }

    sr_free_values(values, cnt);

    /* check xpath that were retrieved */
    const char *xpath_expected_to_be_loaded [] = {
        "/state-module:bus/gps_located",
    };
    CHECK_LIST_OF_STRINGS(xpath_retrieved, xpath_expected_to_be_loaded);

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);

    for (size_t i = 0; i < xpath_retrieved->count; i++) {
        free(xpath_retrieved->data[i]);
    }
    sr_list_cleanup(xpath_retrieved);
}

static void
cl_partialy_covered_by_subscription_tree(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_list_t *xpath_retrieved = NULL;
    sr_node_t *tree = NULL, *node = NULL;
    char buf[10] = { 0, };
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

    for (int j = 0; j < 2; ++j) {
        /* retrieve data */
        rc = sr_get_subtree(session, "/state-module:bus", 0 == j ? 0 : SR_GET_SUBTREE_ITERATIVE, &tree);
        assert_int_equal(rc, SR_ERR_OK);

        /* check data */
        assert_non_null(tree);
        assert_string_equal("bus", tree->name);
        assert_string_equal("state-module", tree->module_name);
        assert_false(tree->dflt);
        assert_int_equal(SR_CONTAINER_T, tree->type);
        assert_int_equal(11, sr_node_get_child_cnt(session, tree));
        /* gps located */
        node = sr_node_get_child_by_name(session, tree, "gps_located");
        assert_non_null(node);
        assert_string_equal("gps_located", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_BOOL_T, node->type);
        assert_false(node->data.bool_val);
        assert_null(node->first_child);
        /* seats */
        for (size_t i = 0; i < 10; ++i) {
            /* list instance */
            snprintf(buf, 10, "%lu", i);
            node = sr_node_get_list_by_key(session, tree, "seats", "number", buf);
            assert_non_null(node);
            assert_null(node->module_name);
            assert_false(node->dflt);
            assert_int_equal(SR_LIST_T, node->type);
            assert_int_equal(2, sr_node_get_child_cnt(session, node));
            /* number */
            node = sr_node_get_child_by_name(session, node, "number");
            assert_non_null(node);
            assert_string_equal("number", node->name);
            assert_null(node->module_name);
            assert_false(node->dflt);
            assert_int_equal(SR_INT32_T, node->type);
            assert_int_equal(i, node->data.int32_val);
            assert_null(node->first_child);
            node = node->parent;
            /* name */
            snprintf(buf, 10, "seat-%lu", i);
            node = sr_node_get_child_by_name(session, node, "name");
            assert_non_null(node);
            assert_string_equal("name", node->name);
            assert_null(node->module_name);
            assert_false(node->dflt);
            assert_int_equal(SR_STRING_T, node->type);
            assert_string_equal(buf, node->data.string_val);
            assert_null(node->first_child);
        }

        sr_free_tree(tree);

        /* check xpath that were retrieved */
        if (0 == j) {
            const char *xpath_expected_to_be_loaded [] = {
                "/state-module:bus/gps_located",
            };
            CHECK_LIST_OF_STRINGS(xpath_retrieved, xpath_expected_to_be_loaded);
        } else {
            const char *xpath_expected_to_be_loaded [] = {
                "/state-module:bus/gps_located",
                "/state-module:bus/gps_located",
            };
            CHECK_LIST_OF_STRINGS(xpath_retrieved, xpath_expected_to_be_loaded);
        }

        for (size_t i = 0; i < xpath_retrieved->count; i++) {
            free(xpath_retrieved->data[i]);
        }
        xpath_retrieved->count = 0;
    }

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);
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
    rc = sr_get_items(session, "/state-module:bus/gps_located", &values, &cnt);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

    /* check data */
    assert_null(values);
    assert_int_equal(0, cnt);

    /* check xpath that were retrieved */
    const char *xpath_expected_to_be_loaded [] = {
        "/state-module:bus/gps_located",
    };
    CHECK_LIST_OF_STRINGS(xpath_retrieved, xpath_expected_to_be_loaded);

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);

    for (size_t i = 0; i < xpath_retrieved->count; i++) {
        free(xpath_retrieved->data[i]);
    }
    sr_list_cleanup(xpath_retrieved);
}

static void
cl_incorrect_data_subscription_tree(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_list_t *xpath_retrieved = NULL;
    sr_node_t *tree = NULL;
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
    rc = sr_get_subtree(session, "/state-module:bus/gps_located", 0, &tree);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

    /* check data */
    assert_null(tree);

    /* check xpath that were retrieved */
    const char *xpath_expected_to_be_loaded [] = {
        "/state-module:bus/gps_located",
    };
    CHECK_LIST_OF_STRINGS(xpath_retrieved, xpath_expected_to_be_loaded);

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

    /* subscribe data providers - provider for cpu_load is missing */
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

static void
cl_missing_subscription_tree(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_list_t *xpath_retrieved = NULL;
    sr_node_t *tree = NULL;
    int rc = SR_ERR_OK;

    rc = sr_list_init(&xpath_retrieved);
    assert_int_equal(rc, SR_ERR_OK);

    /* start session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "state-module", cl_whole_module_cb, NULL,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe data providers - provider for cpu_load is missing */
    rc = sr_dp_get_items_subscribe(session, "/state-module:bus/gps_located", cl_dp_gps_located, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_dp_get_items_subscribe(session, "/state-module:bus/distance_travelled", cl_dp_distance_travelled, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* retrieve data */
    rc = sr_get_subtree(session, "/state-module:cpu_load", 0, &tree);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

    /* check data */
    assert_null(tree);

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

static void
cl_dp_neg_subscription(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;

    int rc = SR_ERR_OK;

    /* start session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "state-module", cl_whole_module_cb, NULL,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe data not existing node */
    rc = sr_dp_get_items_subscribe(session, "/state-module:bus/unknown", cl_dp_gps_located, NULL, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_BAD_ELEMENT);

    /* subscribe not existing module */
    rc = sr_dp_get_items_subscribe(session, "/unknown-module:state-data", cl_dp_distance_travelled, NULL, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_UNKNOWN_MODEL);

    sr_unsubscribe(session, subscription);
    sr_session_stop(session);
}

static void
cl_nested_data_subscription(void **state)
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

    /* subscribe data provider */
    rc = sr_dp_get_items_subscribe(session, "/state-module:traffic_stats", cl_dp_traffic_stats, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* retrieve data */
    rc = sr_get_items(session, "/state-module:traffic_stats/*", &values, &cnt);
    assert_int_equal(rc, SR_ERR_OK);

    /* check data */
    assert_non_null(values);
    assert_int_equal(5, cnt);

    sr_free_values(values, cnt);

    /* check xpath that were retrieved */
    const char *xpath_expected_to_be_loaded [] = {
        "/state-module:traffic_stats",
        "/state-module:traffic_stats/cross_road",
        "/state-module:traffic_stats/cross_road[id='0']/traffic_light",
        "/state-module:traffic_stats/cross_road[id='0']/advanced_info",
        "/state-module:traffic_stats/cross_road[id='1']/traffic_light",
        "/state-module:traffic_stats/cross_road[id='1']/advanced_info",
        "/state-module:traffic_stats/cross_road[id='2']/traffic_light",
        "/state-module:traffic_stats/cross_road[id='2']/advanced_info",
    };
    CHECK_LIST_OF_STRINGS(xpath_retrieved, xpath_expected_to_be_loaded);

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);

    for (size_t i = 0; i < xpath_retrieved->count; i++) {
        free(xpath_retrieved->data[i]);
    }
    sr_list_cleanup(xpath_retrieved);
}

static void
cl_nested_data_subscription_tree(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_list_t *xpath_retrieved = NULL;
    sr_node_t *tree = NULL, *node = NULL;
    int rc = SR_ERR_OK;

    rc = sr_list_init(&xpath_retrieved);
    assert_int_equal(rc, SR_ERR_OK);

    /* start session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "state-module", cl_whole_module_cb, NULL,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe data provider */
    rc = sr_dp_get_items_subscribe(session, "/state-module:traffic_stats", cl_dp_traffic_stats, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    for (int j = 0; j < 2; ++j) {
        /* retrieve data */
        rc = sr_get_subtree(session, "/state-module:traffic_stats", 0 == j ? 0 : SR_GET_SUBTREE_ITERATIVE, &tree);
        assert_int_equal(rc, SR_ERR_OK);

        /* check data */
        // traffic stats
        node = tree;
        assert_non_null(node);
        assert_string_equal("traffic_stats", node->name);
        assert_string_equal("state-module", node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_CONTAINER_T, node->type);
        assert_null(node->next);
        assert_int_equal(5, sr_node_get_child_cnt(session, node));
        // num. of accidents
        node = sr_node_get_child_by_name(session, node, "number_of_accidents");
        assert_non_null(node);
        assert_string_equal("number_of_accidents", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_UINT8_T, node->type);
        assert_int_equal(2, node->data.uint8_val);
        assert_null(node->first_child);
        // cross roads offline count
        node = sr_node_get_child_by_name(session, node->parent, "cross_roads_offline_count");
        assert_non_null(node);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_UINT8_T, node->type);
        assert_int_equal(9, node->data.uint8_val);
        assert_null(node->first_child);
        // cross road, id=0
        node = sr_node_get_list_by_key(session, node->parent, "cross_road", "id", "0");
        assert_non_null(node);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_LIST_T, node->type);
        assert_true(node->first_child);
        assert_int_equal(6, sr_node_get_child_cnt(session, node));
        // id
        node = sr_node_get_child_by_name(session, node, "id");
        assert_non_null(node);
        assert_string_equal("id", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_UINT32_T, node->type);
        assert_int_equal(0, node->data.uint32_val);
        assert_null(node->first_child);
        // status
        node = sr_node_get_child_by_name(session, node->parent, "status");
        assert_non_null(node);
        assert_string_equal("status", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_ENUM_T, node->type);
        assert_string_equal("manual", node->data.enum_val);
        assert_null(node->first_child);
        // traffic light, name = a
        node = sr_node_get_list_by_key(session, node->parent, "traffic_light", "name", "a");
        assert_non_null(node);
        assert_string_equal("traffic_light", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_LIST_T, node->type);
        assert_non_null(node->first_child);
        assert_int_equal(2, sr_node_get_child_cnt(session, node));
        // traffic light, name
        node = sr_node_get_child_by_name(session, node, "name");
        assert_non_null(node);
        assert_string_equal("name", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_STRING_T, node->type);
        assert_string_equal("a", node->data.enum_val);
        assert_null(node->first_child);
        // traffic light, color
        node = sr_node_get_child_by_name(session, node->parent, "color");
        assert_non_null(node);
        assert_string_equal("color", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_ENUM_T, node->type);
        assert_string_equal("red", node->data.enum_val);
        assert_null(node->first_child);
        // traffic light, name = b
        node = sr_node_get_list_by_key(session, node->parent->parent, "traffic_light", "name", "b");
        assert_non_null(node);
        assert_string_equal("traffic_light", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_LIST_T, node->type);
        assert_int_equal(2, sr_node_get_child_cnt(session, node));
        // traffic light, name
        node = sr_node_get_child_by_name(session, node, "name");
        assert_non_null(node);
        assert_string_equal("name", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_STRING_T, node->type);
        assert_string_equal("b", node->data.enum_val);
        assert_null(node->first_child);
        // traffic light, color
        node = sr_node_get_child_by_name(session, node->parent, "color");
        assert_string_equal("color", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_ENUM_T, node->type);
        assert_string_equal("orange", node->data.enum_val);
        assert_null(node->first_child);
        // traffic light, name = c
        node = sr_node_get_list_by_key(session, node->parent->parent, "traffic_light", "name", "c");
        assert_non_null(node);
        assert_string_equal("traffic_light", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_LIST_T, node->type);
        assert_int_equal(2, sr_node_get_child_cnt(session, node));
        // traffic light, name
        node = sr_node_get_child_by_name(session, node, "name");
        assert_non_null(node);
        assert_string_equal("name", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_STRING_T, node->type);
        assert_string_equal("c", node->data.enum_val);
        assert_null(node->first_child);
        // traffic light, color
        node = sr_node_get_child_by_name(session, node->parent, "color");
        assert_non_null(node);
        assert_string_equal("color", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_ENUM_T, node->type);
        assert_string_equal("green", node->data.enum_val);
        assert_null(node->first_child);
        // advanced info
        node = sr_node_get_child_by_name(session, node->parent->parent, "advanced_info");
        assert_non_null(node);
        assert_string_equal("advanced_info", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_CONTAINER_T, node->type);
        assert_int_equal(2, sr_node_get_child_cnt(session, node));
        // latitude
        node = sr_node_get_child_by_name(session, node, "latitude");
        assert_non_null(node);
        assert_string_equal("latitude", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_STRING_T, node->type);
        assert_string_equal("48.729885N", node->data.string_val);
        // longitude
        node = sr_node_get_child_by_name(session, node->parent, "longitude");
        assert_non_null(node);
        assert_string_equal("longitude", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_STRING_T, node->type);
        assert_string_equal("19.137425E", node->data.string_val);
        // cross road, id=1
        node = sr_node_get_list_by_key(session, node->parent->parent->parent, "cross_road", "id", "1");
        assert_non_null(node);
        assert_string_equal("cross_road", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_LIST_T, node->type);
        assert_non_null(node->first_child);
        assert_int_equal(5, sr_node_get_child_cnt(session, node));
        // id
        node = sr_node_get_child_by_name(session, node, "id");
        assert_non_null(node);
        assert_string_equal("id", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_UINT32_T, node->type);
        assert_int_equal(1, node->data.uint32_val);
        assert_null(node->first_child);
        // status
        node = sr_node_get_child_by_name(session, node->parent, "status");
        assert_non_null(node);
        assert_string_equal("status", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_ENUM_T, node->type);
        assert_string_equal("automatic", node->data.enum_val);
        assert_null(node->first_child);
        // traffic light, name = a
        node = sr_node_get_list_by_key(session, node->parent, "traffic_light", "name", "a");
        assert_non_null(node);
        assert_string_equal("traffic_light", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_LIST_T, node->type);
        assert_int_equal(2, sr_node_get_child_cnt(session, node));
        // traffic light, name
        node = sr_node_get_child_by_name(session, node, "name");
        assert_non_null(node);
        assert_string_equal("name", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_STRING_T, node->type);
        assert_string_equal("a", node->data.enum_val);
        assert_null(node->first_child);
        // traffic light, color
        node = sr_node_get_child_by_name(session, node->parent, "color");
        assert_non_null(node);
        assert_string_equal("color", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_ENUM_T, node->type);
        assert_string_equal("orange", node->data.enum_val);
        assert_null(node->first_child);
        // traffic light, name = b
        node = sr_node_get_list_by_key(session, node->parent->parent, "traffic_light", "name", "b");
        assert_non_null(node);
        assert_string_equal("traffic_light", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_LIST_T, node->type);
        assert_int_equal(2, sr_node_get_child_cnt(session, node));
        // traffic light, name
        node = sr_node_get_child_by_name(session, node, "name");
        assert_non_null(node);
        assert_string_equal("name", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_STRING_T, node->type);
        assert_string_equal("b", node->data.enum_val);
        assert_null(node->first_child);
        // traffic light, color
        node = sr_node_get_child_by_name(session, node->parent, "color");
        assert_non_null(node);
        assert_string_equal("color", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_ENUM_T, node->type);
        assert_string_equal("green", node->data.enum_val);
        assert_null(node->first_child);
        // traffic light, name = c
        node = sr_node_get_list_by_key(session, node->parent->parent, "traffic_light", "name", "c");
        assert_non_null(node);
        assert_string_equal("traffic_light", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_LIST_T, node->type);
        assert_int_equal(2, sr_node_get_child_cnt(session, node));
        // traffic light, name
        node = sr_node_get_child_by_name(session, node, "name");
        assert_string_equal("name", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_STRING_T, node->type);
        assert_string_equal("c", node->data.enum_val);
        assert_null(node->first_child);
        // traffic light, color
        node = sr_node_get_child_by_name(session, node->parent, "color");
        assert_string_equal("color", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_ENUM_T, node->type);
        assert_string_equal("red", node->data.enum_val);
        assert_null(node->first_child);
        // no advanced info
        assert_null(sr_node_get_child_by_name(session, node->parent->parent, "advanced_info"));
        // cross road, id=2
        node = sr_node_get_list_by_key(session, node->parent->parent->parent, "cross_road", "id", "2");
        assert_non_null(node);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_LIST_T, node->type);
        assert_non_null(node->first_child);
        assert_int_equal(6, sr_node_get_child_cnt(session, node));
        // id
        node = sr_node_get_child_by_name(session, node, "id");
        assert_non_null(node);
        assert_string_equal("id", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_UINT32_T, node->type);
        assert_int_equal(2, node->data.uint32_val);
        assert_null(node->first_child);
        // status
        node = sr_node_get_child_by_name(session, node->parent, "status");
        assert_non_null(node);
        assert_string_equal("status", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_ENUM_T, node->type);
        assert_string_equal("automatic", node->data.enum_val);
        assert_null(node->first_child);
        // average wait time
        node = sr_node_get_child_by_name(session, node->parent, "average_wait_time");
        assert_non_null(node);
        assert_string_equal("average_wait_time", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_UINT32_T, node->type);
        assert_int_equal(15, node->data.uint32_val);
        assert_null(node->first_child);
        // traffic light, name = a
        node = sr_node_get_list_by_key(session, node->parent, "traffic_light", "name", "a");
        assert_non_null(node);
        assert_string_equal("traffic_light", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_LIST_T, node->type);
        assert_int_equal(2, sr_node_get_child_cnt(session, node));
        // traffic light, name
        node = sr_node_get_child_by_name(session, node, "name");
        assert_non_null(node);
        assert_string_equal("name", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_STRING_T, node->type);
        assert_string_equal("a", node->data.enum_val);
        assert_null(node->first_child);
        // traffic light, color
        node = sr_node_get_child_by_name(session, node->parent, "color");
        assert_non_null(node);
        assert_string_equal("color", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_ENUM_T, node->type);
        assert_string_equal("green", node->data.enum_val);
        assert_null(node->first_child);
        // traffic light, name = b
        node = sr_node_get_list_by_key(session, node->parent->parent, "traffic_light", "name", "b");
        assert_non_null(node);
        assert_string_equal("traffic_light", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_LIST_T, node->type);
        assert_int_equal(2, sr_node_get_child_cnt(session, node));
        // traffic light, name
        node = sr_node_get_child_by_name(session, node, "name");
        assert_non_null(node);
        assert_string_equal("name", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_STRING_T, node->type);
        assert_string_equal("b", node->data.enum_val);
        assert_null(node->first_child);
        // traffic light, color
        node = sr_node_get_child_by_name(session, node->parent, "color");
        assert_non_null(node);
        assert_string_equal("color", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_ENUM_T, node->type);
        assert_string_equal("red", node->data.enum_val);
        assert_null(node->first_child);
        // traffic light, name = c
        node = sr_node_get_list_by_key(session, node->parent->parent, "traffic_light", "name", "c");
        assert_non_null(node);
        assert_string_equal("traffic_light", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_LIST_T, node->type);
        assert_int_equal(2, sr_node_get_child_cnt(session, node));
        // traffic light, name
        node = sr_node_get_child_by_name(session, node, "name");
        assert_non_null(node);
        assert_string_equal("name", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_STRING_T, node->type);
        assert_string_equal("c", node->data.enum_val);
        assert_null(node->first_child);
        // traffic light, color
        node = sr_node_get_child_by_name(session, node->parent, "color");
        assert_non_null(node);
        assert_string_equal("color", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_ENUM_T, node->type);
        assert_string_equal("orange", node->data.enum_val);
        assert_null(node->first_child);
        // no advanced info
        assert_null(sr_node_get_child_by_name(session, node->parent->parent, "advanced_info"));
        // no more cross roads
        assert_null(sr_node_get_list_by_key(session, node->parent->parent->parent, "cross_road", "id", "3"));
        sr_free_tree(tree);

        /* check xpath that were retrieved */
        if (0 == j) {
            const char *xpath_expected_to_be_loaded [] = {
                "/state-module:traffic_stats",
                "/state-module:traffic_stats/cross_road",
                "/state-module:traffic_stats/cross_road[id='0']/traffic_light",
                "/state-module:traffic_stats/cross_road[id='0']/advanced_info",
                "/state-module:traffic_stats/cross_road[id='1']/traffic_light",
                "/state-module:traffic_stats/cross_road[id='1']/advanced_info",
                "/state-module:traffic_stats/cross_road[id='2']/traffic_light",
                "/state-module:traffic_stats/cross_road[id='2']/advanced_info",
            };
            CHECK_LIST_OF_STRINGS(xpath_retrieved, xpath_expected_to_be_loaded);
        } else {
            const char *xpath_expected_to_be_loaded [] = { /**< complete subtree loaded twice */
                "/state-module:traffic_stats",
                "/state-module:traffic_stats/cross_road",
                "/state-module:traffic_stats/cross_road[id='0']/traffic_light",
                "/state-module:traffic_stats/cross_road[id='0']/advanced_info",
                "/state-module:traffic_stats/cross_road[id='1']/traffic_light",
                "/state-module:traffic_stats/cross_road[id='1']/advanced_info",
                "/state-module:traffic_stats/cross_road[id='2']/traffic_light",
                "/state-module:traffic_stats/cross_road[id='2']/advanced_info",
                "/state-module:traffic_stats",
                "/state-module:traffic_stats/cross_road",
                "/state-module:traffic_stats/cross_road[id='0']/traffic_light",
                "/state-module:traffic_stats/cross_road[id='0']/advanced_info",
                "/state-module:traffic_stats/cross_road[id='1']/traffic_light",
                "/state-module:traffic_stats/cross_road[id='1']/advanced_info",
                "/state-module:traffic_stats/cross_road[id='2']/traffic_light",
                "/state-module:traffic_stats/cross_road[id='2']/advanced_info",
            };
            CHECK_LIST_OF_STRINGS(xpath_retrieved, xpath_expected_to_be_loaded);
        }

        for (size_t i = 0; i < xpath_retrieved->count; i++) {
            free(xpath_retrieved->data[i]);
        }
        xpath_retrieved->count = 0;
    }

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);
    sr_list_cleanup(xpath_retrieved);
}

static void
cl_nested_data_subscription2(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_list_t *xpath_retrieved = NULL;
    sr_val_t *values = NULL, *value = NULL;
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

    rc = sr_dp_get_items_subscribe(session, "/state-module:traffic_stats", cl_dp_traffic_stats, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* retrieve data */
    rc = sr_get_items(session, "/state-module:traffic_stats/cross_road[id='0']/advanced_info/*", &values, &cnt);
    assert_int_equal(rc, SR_ERR_OK);

    /* check data */
    assert_non_null(values);
    assert_int_equal(2, cnt);

#define LATITUDE_XPATH "/state-module:traffic_stats/cross_road[id='0']/advanced_info/latitude"
#define LONGITUDE_XPATH "/state-module:traffic_stats/cross_road[id='0']/advanced_info/longitude"

    value = sr_val_get_by_xpath(values, cnt, LATITUDE_XPATH);
    assert_non_null(value);
    assert_int_equal(value->type, SR_STRING_T);
    assert_string_equal(value->data.string_val, "48.729885N");

    value = sr_val_get_by_xpath(values, cnt, LONGITUDE_XPATH);
    assert_non_null(value);
    assert_int_equal(value->type, SR_STRING_T);
    assert_string_equal(value->data.string_val, "19.137425E");

    sr_free_values(values, cnt);

    /* check xpath that were retrieved */
    const char *xpath_expected_to_be_loaded [] = {
        "/state-module:traffic_stats",
        "/state-module:traffic_stats/cross_road",
        "/state-module:traffic_stats/cross_road[id='0']/traffic_light",
        "/state-module:traffic_stats/cross_road[id='0']/advanced_info",
        "/state-module:traffic_stats/cross_road[id='1']/traffic_light",
        "/state-module:traffic_stats/cross_road[id='1']/advanced_info",
        "/state-module:traffic_stats/cross_road[id='2']/traffic_light",
        "/state-module:traffic_stats/cross_road[id='2']/advanced_info",
    };
    CHECK_LIST_OF_STRINGS(xpath_retrieved, xpath_expected_to_be_loaded);

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);

    for (size_t i = 0; i < xpath_retrieved->count; i++) {
        free(xpath_retrieved->data[i]);
    }
    sr_list_cleanup(xpath_retrieved);
}

static void
cl_nested_data_subscription2_tree(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_list_t *xpath_retrieved = NULL;
    sr_node_t *tree = NULL, *node = NULL;
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

    rc = sr_dp_get_items_subscribe(session, "/state-module:traffic_stats", cl_dp_traffic_stats, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    for (int j = 0; j < 2; ++j) {
        /* retrieve data */
        rc = sr_get_subtree(session, "/state-module:traffic_stats/cross_road[id='0']/advanced_info",
                0 == j ? 0 : SR_GET_SUBTREE_ITERATIVE, &tree);
        assert_int_equal(rc, SR_ERR_OK);

        /* check data */
        assert_non_null(tree);
        // advanced info
        node = tree;
        assert_string_equal("advanced_info", node->name);
        assert_string_equal("state-module", node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_CONTAINER_T, node->type);
        assert_non_null(node->first_child);
        assert_null(node->next);
        assert_int_equal(2, sr_node_get_child_cnt(session, node));
        // latitude
        node = sr_node_get_child_by_name(session, node, "latitude");
        assert_non_null(node);
        assert_string_equal("latitude", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_STRING_T, node->type);
        assert_string_equal("48.729885N", node->data.string_val);
        assert_null(node->first_child);
        // longitude
        node = sr_node_get_child_by_name(session, node->parent, "longitude");
        assert_non_null(node);
        assert_string_equal("longitude", node->name);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(SR_STRING_T, node->type);
        assert_string_equal("19.137425E", node->data.string_val);
        assert_null(node->first_child);

        sr_free_tree(tree);

        /* check xpath that were retrieved */
        const char *xpath_expected_to_be_loaded [] = {
            "/state-module:traffic_stats",
            "/state-module:traffic_stats/cross_road",
            "/state-module:traffic_stats/cross_road[id='0']/traffic_light",
            "/state-module:traffic_stats/cross_road[id='0']/advanced_info",
            "/state-module:traffic_stats/cross_road[id='1']/traffic_light",
            "/state-module:traffic_stats/cross_road[id='1']/advanced_info",
            "/state-module:traffic_stats/cross_road[id='2']/traffic_light",
            "/state-module:traffic_stats/cross_road[id='2']/advanced_info",
        };
        CHECK_LIST_OF_STRINGS(xpath_retrieved, xpath_expected_to_be_loaded);

        for (size_t i = 0; i < xpath_retrieved->count; i++) {
            free(xpath_retrieved->data[i]);
        }
        xpath_retrieved->count = 0;
    }

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);
    sr_list_cleanup(xpath_retrieved);
}

static void
cl_all_state_data(void **state)
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

    rc = sr_dp_get_items_subscribe(session, "/state-module:traffic_stats", cl_dp_traffic_stats, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* retrieve data */
    rc = sr_get_items(session, "/state-module:*//*", &values, &cnt);
    assert_int_equal(rc, SR_ERR_OK);

    /* check data */
    assert_non_null(values);
    assert_int_equal(84, cnt);

    sr_free_values(values, cnt);

    /* check xpath that were retrieved */
    const char *xpath_expected_to_be_loaded [] = {
        "/state-module:bus/gps_located",
        "/state-module:bus/distance_travelled",
        "/state-module:bus/seats[number='0']/reserved",
        "/state-module:bus/seats[number='1']/reserved",
        "/state-module:bus/seats[number='2']/reserved",
        "/state-module:bus/seats[number='3']/reserved",
        "/state-module:bus/seats[number='4']/reserved",
        "/state-module:bus/seats[number='5']/reserved",
        "/state-module:bus/seats[number='6']/reserved",
        "/state-module:bus/seats[number='7']/reserved",
        "/state-module:bus/seats[number='8']/reserved",
        "/state-module:bus/seats[number='9']/reserved",
        "/state-module:traffic_stats",
        "/state-module:traffic_stats/cross_road",
        "/state-module:traffic_stats/cross_road[id='0']/traffic_light",
        "/state-module:traffic_stats/cross_road[id='0']/advanced_info",
        "/state-module:traffic_stats/cross_road[id='1']/traffic_light",
        "/state-module:traffic_stats/cross_road[id='1']/advanced_info",
        "/state-module:traffic_stats/cross_road[id='2']/traffic_light",
        "/state-module:traffic_stats/cross_road[id='2']/advanced_info",
    };
    CHECK_LIST_OF_STRINGS(xpath_retrieved, xpath_expected_to_be_loaded);

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);

    for (size_t i = 0; i < xpath_retrieved->count; i++) {
        free(xpath_retrieved->data[i]);
    }
    sr_list_cleanup(xpath_retrieved);
}

static void
cl_request_id(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_list_t *reqid_retrieved = NULL;
    sr_val_t *values = NULL;
    size_t cnt = 0;
    uint32_t count = 0;
    int rc = SR_ERR_OK;

    rc = sr_list_init(&reqid_retrieved);
    assert_int_equal(rc, SR_ERR_OK);

    /* start session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "state-module", cl_whole_module_cb, NULL,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe data providers */
    rc = sr_dp_get_items_subscribe(session, "/state-module:bus", cl_dp_bus_req_id, reqid_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* retrieve data once */
    rc = sr_get_items(session, "/state-module:*//*", &values, &cnt);
    assert_int_equal(rc, SR_ERR_OK);

    sr_free_values(values, cnt);

    /* check that reqid is always the same */
    for (size_t i = 1; i < reqid_retrieved->count; i++) {
        assert_int_equal(reqid_retrieved->data[i - 1], reqid_retrieved->data[i]);
    }
    count = reqid_retrieved->count;

    /* retrieve data a second time */
    rc = sr_get_items(session, "/state-module:*//*", &values, &cnt);
    assert_int_equal(rc, SR_ERR_OK);

    sr_free_values(values, cnt);

    /* check that reqids are different for the first and second request */
    assert_int_not_equal(reqid_retrieved->data[0], reqid_retrieved->data[count]);

    sr_list_cleanup(reqid_retrieved);

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);
}

static void
cl_partial_covered_dp_subtree(void **state)
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
    rc = sr_dp_get_items_subscribe(session, "/state-module:weather/sky", cl_dp_sky, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_dp_get_items_subscribe(session, "/state-module:weather/humidity", cl_dp_humidity, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* retrieve data */
    rc = sr_get_items(session, "/state-module:weather//*", &values, &cnt);
    assert_int_equal(rc, SR_ERR_OK);

    /* check data */
    assert_non_null(values);
    assert_int_equal(2, cnt);

    if (0 == strcmp(values[0].xpath, "/state-module:weather/sky")) {
        assert_string_equal(values[1].xpath, "/state-module:weather/humidity");
    } else {
        assert_string_equal(values[0].xpath, "/state-module:weather/humidity");
        assert_string_equal(values[1].xpath, "/state-module:weather/sky");
    }

    sr_free_values(values, cnt);

    /* check xpath that were retrieved */
    const char *xpath_expected_to_be_loaded [] = {
        "/state-module:weather/sky",
        "/state-module:weather/humidity",
    };
    CHECK_LIST_OF_STRINGS(xpath_retrieved, xpath_expected_to_be_loaded);

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);

    for (size_t i = 0; i < xpath_retrieved->count; i++) {
        free(xpath_retrieved->data[i]);
    }
    sr_list_cleanup(xpath_retrieved);
}

static void
cl_missing_list_dp(void **state)
{
    /*
     * container (not covered)
     *  -> list (not covered)
     *      -> list (1. data provider) - will not be called missing provider for parent list
     *      -> container (not covered)
     */
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
    rc = sr_dp_get_items_subscribe(session, "/state-module:traffic_stats/cross_road/traffic_light", cl_dp_traffic_light, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* retrieve data */
    rc = sr_get_items(session, "/state-module:traffic_stats//*", &values, &cnt);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

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

static void
cl_subscribe_list_in_state_container_dp(void **state)
{
    /*
     * container (not covered)
     *  -> list (1. data provider)
     *      ...
     */
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
    rc = sr_dp_get_items_subscribe(session, "/state-module:traffic_stats/cross_road", cl_dp_cross_road, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* retrieve data */
    rc = sr_get_items(session, "/state-module:traffic_stats/cross_road", &values, &cnt);
    assert_int_equal(rc, SR_ERR_OK);

    /* check data */
    assert_non_null(values);
    assert_int_equal(3, cnt);

    sr_free_values(values, cnt);

    /* check xpath that were retrieved */
    const char *xpath_expected_to_be_loaded [] = {
        "/state-module:traffic_stats/cross_road",
        "/state-module:traffic_stats/cross_road[id='0']/traffic_light",
        "/state-module:traffic_stats/cross_road[id='0']/advanced_info",
        "/state-module:traffic_stats/cross_road[id='1']/traffic_light",
        "/state-module:traffic_stats/cross_road[id='1']/advanced_info",
        "/state-module:traffic_stats/cross_road[id='2']/traffic_light",
        "/state-module:traffic_stats/cross_road[id='2']/advanced_info"
    };
    CHECK_LIST_OF_STRINGS(xpath_retrieved, xpath_expected_to_be_loaded);

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);

    for (size_t i = 0; i < xpath_retrieved->count; i++) {
        free(xpath_retrieved->data[i]);
    }
    sr_list_cleanup(xpath_retrieved);
}

static void
cl_subscribe_list_in_state_container_dp2(void **state)
{
    /*
     * container (not covered)
     *  -> list (1. data provider)
     *      ...
     */
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_list_t *xpath_retrieved = NULL;
    sr_val_t *value = NULL;
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
    rc = sr_dp_get_items_subscribe(session, "/state-module:traffic_stats/cross_road", cl_dp_cross_road, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* retrieve data */
    rc = sr_get_item(session, "/state-module:traffic_stats", &value);
    assert_int_equal(rc, SR_ERR_OK);

    /* check data */
    assert_non_null(value);
    assert_int_equal(SR_CONTAINER_T, value->type);
    sr_free_val(value);

    /* check xpath that were retrieved */
    const char *xpath_expected_to_be_loaded [] = {
        "/state-module:traffic_stats/cross_road",
        "/state-module:traffic_stats/cross_road[id='0']/traffic_light",
        "/state-module:traffic_stats/cross_road[id='0']/advanced_info",
        "/state-module:traffic_stats/cross_road[id='1']/traffic_light",
        "/state-module:traffic_stats/cross_road[id='1']/advanced_info",
        "/state-module:traffic_stats/cross_road[id='2']/traffic_light",
        "/state-module:traffic_stats/cross_road[id='2']/advanced_info"
    };
    CHECK_LIST_OF_STRINGS(xpath_retrieved, xpath_expected_to_be_loaded);

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);

    for (size_t i = 0; i < xpath_retrieved->count; i++) {
        free(xpath_retrieved->data[i]);
    }
    sr_list_cleanup(xpath_retrieved);
}

static void
cl_divided_providers_dp(void **state)
{
    /*
     * container (not covered)
     *  -> list (1. data provider)
     *      -> list (2. data provider)
     *      -> container (notcovered)
     */
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
    rc = sr_dp_get_items_subscribe(session, "/state-module:traffic_stats/cross_road", cl_dp_cross_road, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_dp_get_items_subscribe(session, "/state-module:traffic_stats/cross_road/traffic_light", cl_dp_traffic_light, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* retrieve data */
    rc = sr_get_items(session, "/state-module:traffic_stats/cross_road/traffic_light", &values, &cnt);
    assert_int_equal(rc, SR_ERR_OK);

    /* check data */
    assert_non_null(values);
    assert_int_equal(9, cnt);

    sr_free_values(values, cnt);

    /* check xpath that were retrieved */
    const char *xpath_expected_to_be_loaded [] = {
        "/state-module:traffic_stats/cross_road",
        "/state-module:traffic_stats/cross_road[id='0']/traffic_light",
        "/state-module:traffic_stats/cross_road[id='0']/advanced_info",
        "/state-module:traffic_stats/cross_road[id='1']/traffic_light",
        "/state-module:traffic_stats/cross_road[id='1']/advanced_info",
        "/state-module:traffic_stats/cross_road[id='2']/traffic_light",
        "/state-module:traffic_stats/cross_road[id='2']/advanced_info"
    };
    CHECK_LIST_OF_STRINGS(xpath_retrieved, xpath_expected_to_be_loaded);

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);

    for (size_t i = 0; i < xpath_retrieved->count; i++) {
        free(xpath_retrieved->data[i]);
    }
    sr_list_cleanup(xpath_retrieved);
}

static void
cl_only_nested_container_dp(void **state)
{
    /*
     * container (not covered)
     *  -> container (1. data provider)
     */
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
    rc = sr_dp_get_items_subscribe(session, "/state-module:weather/wind", cl_dp_wind, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* retrieve data */
    rc = sr_get_items(session, "/state-module:weather//*", &values, &cnt);
    assert_int_equal(rc, SR_ERR_OK);

    /* check data */
    assert_non_null(values);
    assert_int_equal(3, cnt);

    sr_free_values(values, cnt);

    /* check xpath that were retrieved */
    const char *xpath_expected_to_be_loaded [] = {
        "/state-module:weather/wind",
    };
    CHECK_LIST_OF_STRINGS(xpath_retrieved, xpath_expected_to_be_loaded);

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);

    for (size_t i = 0; i < xpath_retrieved->count; i++) {
        free(xpath_retrieved->data[i]);
    }
    sr_list_cleanup(xpath_retrieved);
}

static void
cl_extraleaf_dp(void **state)
{
    /*
     * container (not covered)
     *  -> container (1. data provider)
     *      ->leaf (2.data provider)
     */
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_list_t *xpath_retrieved = NULL, *xpath_retrieved2 = NULL;
    sr_val_t *values = NULL;
    size_t cnt = 0;
    int rc = SR_ERR_OK;

    rc = sr_list_init(&xpath_retrieved);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_list_init(&xpath_retrieved2);
    assert_int_equal(rc, SR_ERR_OK);

    /* start session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "state-module", cl_whole_module_cb, NULL,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe data providers */
    rc = sr_dp_get_items_subscribe(session, "/state-module:weather/wind", cl_dp_wind, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_dp_get_items_subscribe(session, "/state-module:weather/wind/speed", cl_dp_wind_speed, xpath_retrieved2, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* retrieve data */
    rc = sr_get_items(session, "/state-module:weather//*", &values, &cnt);
    assert_int_equal(rc, SR_ERR_OK);

    /* check data */
    assert_non_null(values);
    assert_int_equal(3, cnt);

    sr_free_values(values, cnt);

    /* check xpath that were retrieved */
    const char *xpath_expected_to_be_loaded [] = {
        "/state-module:weather/wind",
    };
    CHECK_LIST_OF_STRINGS(xpath_retrieved, xpath_expected_to_be_loaded);

    const char *xpath_expected_to_be_loaded2 [] = {
        "/state-module:weather/wind/speed",
    };
    CHECK_LIST_OF_STRINGS(xpath_retrieved2, xpath_expected_to_be_loaded2);

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);

    for (size_t i = 0; i < xpath_retrieved->count; i++) {
        free(xpath_retrieved->data[i]);
    }
    sr_list_cleanup(xpath_retrieved);

    for (size_t i = 0; i < xpath_retrieved2->count; i++) {
        free(xpath_retrieved2->data[i]);
    }
    sr_list_cleanup(xpath_retrieved2);
}

static void
cl_no_dp_subscription(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    sr_val_t *values = NULL;
    size_t cnt = 0;
    int rc = SR_ERR_OK;


    /* start session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "state-module", cl_whole_module_cb, NULL,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* retrieve data */
    rc = sr_get_items(session, "/state-module:bus/vendor_name", &values, &cnt);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

    /* check data */
    assert_null(values);
    assert_int_equal(0, cnt);

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);
}

static void
cl_type_not_filled_by_dp(void **state)
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
    rc = sr_dp_get_items_subscribe(session, "/state-module:bus", cl_dp_missing_type_bus, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* retrieve data */
    rc = sr_get_items(session, "/state-module:bus//*", &values, &cnt);
    assert_int_equal(rc, SR_ERR_OK);

    /* check data */
    sr_free_values(values, cnt);

    /* check xpath that were retrieved */
    const char *xpath_expected_to_be_loaded [] = {
        "/state-module:bus/gps_located",
        "/state-module:bus/distance_travelled",
        "/state-module:bus/seats[number='0']/reserved",
        "/state-module:bus/seats[number='1']/reserved",
        "/state-module:bus/seats[number='2']/reserved",
        "/state-module:bus/seats[number='3']/reserved",
        "/state-module:bus/seats[number='4']/reserved",
        "/state-module:bus/seats[number='5']/reserved",
        "/state-module:bus/seats[number='6']/reserved",
        "/state-module:bus/seats[number='7']/reserved",
        "/state-module:bus/seats[number='8']/reserved",
        "/state-module:bus/seats[number='9']/reserved",
    };
    CHECK_LIST_OF_STRINGS(xpath_retrieved, xpath_expected_to_be_loaded);


    /* one more time */
    for (size_t i = 0; i < xpath_retrieved->count; i++) {
        free(xpath_retrieved->data[i]);
    }
    xpath_retrieved->count = 0;

    /* retrieve data */
    rc = sr_get_items(session, "/state-module:bus//*", &values, &cnt);
    assert_int_equal(rc, SR_ERR_OK);

    /* check data */
    sr_free_values(values, cnt);

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);

    for (size_t i = 0; i < xpath_retrieved->count; i++) {
        free(xpath_retrieved->data[i]);
    }
    sr_list_cleanup(xpath_retrieved);

}

static void
cl_state_data_in_grouping(void **state)
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
    rc = sr_dp_get_items_subscribe(session, "/state-module:cards/card/state", cl_dp_card_state, xpath_retrieved, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_set_item(session, "/state-module:cards/card[dn='abc']", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_set_item(session, "/state-module:cards/card[dn='def']", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);


    /* retrieve data */
    rc = sr_get_items(session, "/state-module:cards//*", &values, &cnt);
    assert_int_equal(rc, SR_ERR_OK);

    /* check data */
    sr_free_values(values, cnt);

    /* check xpath that were retrieved */
    const char *xpath_expected_to_be_loaded [] = {
        "/state-module:cards/card[dn='abc']/state",
        "/state-module:cards/card[dn='def']/state",
    };
    CHECK_LIST_OF_STRINGS(xpath_retrieved, xpath_expected_to_be_loaded);

    for (size_t i = 0; i < xpath_retrieved->count; i++) {
        free(xpath_retrieved->data[i]);
    }
    sr_list_cleanup(xpath_retrieved);

    /* cleanup */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);

}

int
main()
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(cl_exact_match_subscription, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_exact_match_subscription_tree, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_parent_subscription, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_parent_subscription_tree, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_partialy_covered_by_subscription, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_partialy_covered_by_subscription_tree, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_missing_subscription, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_missing_subscription_tree, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_incorrect_data_subscription, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_incorrect_data_subscription_tree, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_dp_neg_subscription, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_nested_data_subscription, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_nested_data_subscription_tree, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_nested_data_subscription2, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_nested_data_subscription2_tree, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_all_state_data, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_request_id, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_partial_covered_dp_subtree, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_missing_list_dp, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_subscribe_list_in_state_container_dp, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_subscribe_list_in_state_container_dp2, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_divided_providers_dp, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_only_nested_container_dp, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_extraleaf_dp, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_no_dp_subscription, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_type_not_filled_by_dp, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_state_data_in_grouping, sysrepo_setup, sysrepo_teardown),
    };

    watchdog_start(300);
    int ret = cmocka_run_group_tests(tests, NULL, NULL);
    watchdog_stop();
    return ret;
}
