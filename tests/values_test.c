/**
 * @file values_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Unit tests targeting functions from "sysrepo/values.h".
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
#include <stdarg.h>
#include <unistd.h>
#include <setjmp.h>
#include <cmocka.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "sr_common.h"


#define XPATH1 "/example-module:container/list[key1='key1'][key2='key2']/leaf"
#define XPATH2 "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4"
#define XPATH3 "/ietf-interfaces:interfaces/interface[name='gigaeth0']"

#define XPATH_TEMPLATE1 "/example-module:container/list[key1='key1-%d'][key2='key2-%d']/leaf"
#define XPATH_TEMPLATE2 "/test-module:main/numbers[.='%d']"

static void
sr_new_val_test(void **state)
{
    int rc = 0;
    sr_val_t *value = NULL;

    rc = sr_new_val(NULL, &value);
    assert_int_equal(SR_ERR_OK, rc);
#ifdef USE_SR_MEM_MGMT
    assert_non_null(value->_sr_mem);
    assert_int_equal(1, value->_sr_mem->obj_count);
    assert_true(0 < value->_sr_mem->used_total);
#else
    assert_null(value->_sr_mem);
#endif
    assert_null(value->xpath);
    assert_false(value->dflt);
    assert_int_equal(SR_UNKNOWN_T, value->type);
    assert_int_equal(0, value->data.uint64_val);
    sr_free_val(value);

    rc = sr_new_val(XPATH1, &value);
    assert_int_equal(SR_ERR_OK, rc);
#ifdef USE_SR_MEM_MGMT
    assert_non_null(value->_sr_mem);
    assert_int_equal(1, value->_sr_mem->obj_count);
    assert_true(0 < value->_sr_mem->used_total);
#else
    assert_null(value->_sr_mem);
#endif
    assert_string_equal(XPATH1, value->xpath);
    assert_false(value->dflt);
    assert_int_equal(SR_UNKNOWN_T, value->type);
    assert_int_equal(0, value->data.uint64_val);
    sr_free_val(value);
}

static void
sr_new_values_test(void **state)
{
    int rc = 0;
    sr_val_t *values = NULL;

    rc = sr_new_values(0, &values);
    assert_int_equal(SR_ERR_OK, rc);
    assert_null(values);
    sr_free_values(values, 0);

    rc = sr_new_values(10, &values);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(values);
#ifdef USE_SR_MEM_MGMT
    assert_non_null(values->_sr_mem);
    assert_int_equal(1, values->_sr_mem->obj_count);
    assert_true(0 < values->_sr_mem->used_total);
#else
    assert_null(values->_sr_mem);
#endif
    for (int i = 0; i < 10; ++i) {
#ifdef USE_SR_MEM_MGMT
        if (0 < i) {
            assert_ptr_equal(values[i-1]._sr_mem, values[i]._sr_mem);
        }
#endif
        assert_null(values[i].xpath);
        assert_false(values[i].dflt);
        assert_int_equal(SR_UNKNOWN_T, values[i].type);
        assert_int_equal(0, values[i].data.uint64_val);
    }
    sr_free_values(values, 10);
}

static void
sr_val_set_xpath_test(void **state)
{
    int rc = 0;
    sr_val_t *value = NULL, *values = NULL;
    char xpath[PATH_MAX] = { 0, };

    rc = sr_new_val(NULL, &value);
    assert_int_equal(SR_ERR_OK, rc);
    assert_null(value->xpath);
    rc = sr_val_set_xpath(value, XPATH1);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal(XPATH1, value->xpath);
    rc = sr_val_set_xpath(value, XPATH2);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal(XPATH2, value->xpath);
    sr_free_val(value);

    rc = sr_new_values(10, &values);
    assert_int_equal(SR_ERR_OK, rc);
    for (int i = 0; i < 10; ++i) {
        assert_null(values[i].xpath);
        snprintf(xpath, PATH_MAX, XPATH_TEMPLATE1, i, i);
        rc = sr_val_set_xpath(values + i, xpath);
        assert_int_equal(SR_ERR_OK, rc);
        assert_string_equal(xpath, values[i].xpath);
        snprintf(xpath, PATH_MAX, XPATH_TEMPLATE2, i);
        rc = sr_val_set_xpath(values + i, xpath);
        assert_int_equal(SR_ERR_OK, rc);
        assert_string_equal(xpath, values[i].xpath);
    }
    sr_free_values(values, 10);
}

static void
sr_val_set_string_test(void **state)
{
    int rc = 0;
    sr_val_t *value = NULL;

    rc = sr_new_val(NULL, &value);
    assert_int_equal(SR_ERR_OK, rc);
    assert_null(value->data.string_val);

    rc = sr_val_set_string(value, "string value");
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    value->type = SR_STRING_T;
    rc = sr_val_set_string(value, "string value");
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("string value", value->data.string_val);

    value->type = SR_BINARY_T;
    rc = sr_val_set_string(value, "binary value");
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("binary value", value->data.binary_val);

    value->type = SR_ENUM_T;
    rc = sr_val_set_string(value, "enum value");
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("enum value", value->data.enum_val);

    value->type = SR_BITS_T;
    rc = sr_val_set_string(value, "bits");
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("bits", value->data.bits_val);

    value->type = SR_IDENTITYREF_T;
    rc = sr_val_set_string(value, "identityref value");
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("identityref value", value->data.identityref_val);

    value->type = SR_INSTANCEID_T;
    rc = sr_val_set_string(value, "instance ID");
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("instance ID", value->data.instanceid_val);

    sr_free_val(value);
}

static void
sr_dup_val_test(void **state)
{
    int rc = 0;
    sr_val_t *value = NULL, *value_dup = NULL;

    /* create a new value using the API */
    rc = sr_new_val(NULL, &value);
    value->type = SR_STRING_T;
    rc = sr_val_set_string(value, "string value");
    assert_int_equal(SR_ERR_OK, rc);
    rc = sr_val_set_xpath(value, XPATH1);
    assert_int_equal(SR_ERR_OK, rc);

    /* duplicate */
    rc = sr_dup_val(value, &value_dup);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(value_dup);
#ifdef USE_SR_MEM_MGMT
    assert_non_null(value_dup->_sr_mem);
    assert_ptr_not_equal(value->_sr_mem, value_dup->_sr_mem);
    assert_int_equal(1, value_dup->_sr_mem->obj_count);
    assert_true(0 < value_dup->_sr_mem->used_total);
#else
    assert_null(value_dup->_sr_mem);
#endif
    assert_string_equal(XPATH1, value_dup->xpath);
    assert_false(value_dup->dflt);
    assert_int_equal(SR_STRING_T, value_dup->type);
    assert_string_equal("string value", value_dup->data.string_val);
    sr_free_val(value_dup);

    /* set dflt to true, change XPATH and duplicate */
    value->dflt = true;
    rc = sr_val_set_xpath(value, XPATH2);
    assert_int_equal(SR_ERR_OK, rc);
    rc = sr_dup_val(value, &value_dup);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(value_dup);
#ifdef USE_SR_MEM_MGMT
    assert_non_null(value_dup->_sr_mem);
    assert_ptr_not_equal(value->_sr_mem, value_dup->_sr_mem);
    assert_int_equal(1, value_dup->_sr_mem->obj_count);
    assert_true(0 < value_dup->_sr_mem->used_total);
#else
    assert_null(value_dup->_sr_mem);
#endif
    assert_string_equal(XPATH2, value_dup->xpath);
    assert_true(value_dup->dflt);
    assert_int_equal(SR_STRING_T, value_dup->type);
    assert_string_equal("string value", value_dup->data.string_val);
    sr_free_val(value_dup);

    /* change string and duplicate */
    rc = sr_val_set_string(value, "string value2");
    assert_int_equal(SR_ERR_OK, rc);
    rc = sr_dup_val(value, &value_dup);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(value_dup);
#ifdef USE_SR_MEM_MGMT
    assert_non_null(value_dup->_sr_mem);
    assert_ptr_not_equal(value->_sr_mem, value_dup->_sr_mem);
    assert_int_equal(1, value_dup->_sr_mem->obj_count);
    assert_true(0 < value_dup->_sr_mem->used_total);
#else
    assert_null(value_dup->_sr_mem);
#endif
    assert_string_equal(XPATH2, value_dup->xpath);
    assert_true(value_dup->dflt);
    assert_int_equal(SR_STRING_T, value_dup->type);
    assert_string_equal("string value2", value_dup->data.string_val);
    sr_free_val(value_dup);

    /* duplicate manually created value */
    sr_free_val(value);
    value = calloc(1, sizeof *value);
    assert_non_null(value);
    value->xpath = strdup(XPATH1);
    assert_non_null(value->xpath);
    value->type = SR_STRING_T;
    value->data.string_val = strdup("string value");
    assert_non_null(value->data.string_val);

    /* duplicate */
    rc = sr_dup_val(value, &value_dup);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(value_dup);
#ifdef USE_SR_MEM_MGMT
    assert_non_null(value_dup->_sr_mem);
    assert_int_equal(1, value_dup->_sr_mem->obj_count);
    assert_true(0 < value_dup->_sr_mem->used_total);
#else
    assert_null(value_dup->_sr_mem);
#endif
    assert_string_equal(XPATH1, value_dup->xpath);
    assert_false(value_dup->dflt);
    assert_int_equal(SR_STRING_T, value_dup->type);
    assert_string_equal("string value", value_dup->data.string_val);
    sr_free_val(value_dup);
    sr_free_val(value);
}

static void
sr_dup_values_test(void **state)
{
    int rc = 0;
    sr_val_t *values = NULL, *values_dup = NULL;
    char xpath[PATH_MAX] = { 0, }, string_val[10] = { 0, };

    /* create new array of values using the API */
    rc = sr_new_values(10, &values);
    assert_int_equal(SR_ERR_OK, rc);
    for (int i = 0; i < 10; ++i) {
        snprintf(xpath, PATH_MAX, XPATH_TEMPLATE1, i, i);
        rc = sr_val_set_xpath(values + i, xpath);
        assert_int_equal(SR_ERR_OK, rc);
        values[i].type = SR_STRING_T;
        snprintf(string_val, 10, "%d", i);
        rc = sr_val_set_string(values + i, string_val);
        assert_int_equal(SR_ERR_OK, rc);
    }

    /* duplicate */
    rc = sr_dup_values(values, 10, &values_dup);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(values_dup);
#ifdef USE_SR_MEM_MGMT
    assert_non_null(values_dup->_sr_mem);
    assert_int_equal(1, values_dup->_sr_mem->obj_count);
    assert_true(0 < values_dup->_sr_mem->used_total);
#else
    assert_null(values_dup->_sr_mem);
#endif
    for (int i = 0; i < 10; ++i) {
#ifdef USE_SR_MEM_MGMT
        if (0 < i) {
            assert_ptr_equal(values_dup[i-1]._sr_mem, values_dup[i]._sr_mem);
        }
#endif
        snprintf(xpath, PATH_MAX, XPATH_TEMPLATE1, i, i);
        assert_string_equal(xpath, values_dup[i].xpath);
        assert_false(values_dup[i].dflt);
        assert_int_equal(SR_STRING_T, values_dup[i].type);
        snprintf(string_val, 10, "%d", i);
        assert_string_equal(string_val, values_dup[i].data.string_val);
    }
    sr_free_values(values_dup, 10);

    /* set dflt to true, change XPATH and data */
    for (int i = 0; i < 10; ++i) {
        snprintf(xpath, PATH_MAX, XPATH_TEMPLATE2, i);
        rc = sr_val_set_xpath(values + i, xpath);
        assert_int_equal(SR_ERR_OK, rc);
        values[i].dflt = true;
        values[i].type = SR_UINT8_T;
#ifndef USE_SR_MEM_MGMT
        free(values[i].data.string_val);
#endif
        values[i].data.uint8_val = i;
    }

    /* duplicate */
    rc = sr_dup_values(values, 10, &values_dup);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(values_dup);
#ifdef USE_SR_MEM_MGMT
    assert_non_null(values_dup->_sr_mem);
    assert_int_equal(1, values_dup->_sr_mem->obj_count);
    assert_true(0 < values_dup->_sr_mem->used_total);
#else
    assert_null(values_dup->_sr_mem);
#endif
    for (int i = 0; i < 10; ++i) {
#ifdef USE_SR_MEM_MGMT
        if (0 < i) {
            assert_ptr_equal(values_dup[i-1]._sr_mem, values_dup[i]._sr_mem);
        }
#endif
        snprintf(xpath, PATH_MAX, XPATH_TEMPLATE2, i);
        assert_string_equal(xpath, values_dup[i].xpath);
        assert_true(values_dup[i].dflt);
        assert_int_equal(SR_UINT8_T, values_dup[i].type);
        assert_int_equal(i, values_dup[i].data.uint8_val);
    }
    sr_free_values(values_dup, 10);
    sr_free_values(values, 10);

    /* duplicate manually created array */
    values = calloc(10, sizeof *values);
    assert_non_null(values);
    for (int i = 0; i < 10; ++i) {
        snprintf(xpath, PATH_MAX, XPATH_TEMPLATE1, i, i);
        values[i].xpath = strdup(xpath);
        assert_non_null(values[i].xpath);
        values[i].type = SR_STRING_T;
        snprintf(string_val, 10, "%d", i);
        values[i].data.string_val = strdup(string_val);
        assert_non_null(values[i].data.string_val);
    }

    /* duplicate */
    rc = sr_dup_values(values, 10, &values_dup);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(values_dup);
#ifdef USE_SR_MEM_MGMT
    assert_non_null(values_dup->_sr_mem);
    assert_int_equal(1, values_dup->_sr_mem->obj_count);
    assert_true(0 < values_dup->_sr_mem->used_total);
#else
    assert_null(values_dup->_sr_mem);
#endif
    for (int i = 0; i < 10; ++i) {
#ifdef USE_SR_MEM_MGMT
        if (0 < i) {
            assert_ptr_equal(values_dup[i-1]._sr_mem, values_dup[i]._sr_mem);
        }
#endif
        snprintf(xpath, PATH_MAX, XPATH_TEMPLATE1, i, i);
        assert_string_equal(xpath, values_dup[i].xpath);
        assert_false(values_dup[i].dflt);
        assert_int_equal(SR_STRING_T, values_dup[i].type);
        snprintf(string_val, 10, "%d", i);
        assert_string_equal(string_val, values_dup[i].data.string_val);
    }
    sr_free_values(values_dup, 10);
    sr_free_values(values, 10);
}

int
main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(sr_new_val_test),
        cmocka_unit_test(sr_new_values_test),
        cmocka_unit_test(sr_val_set_xpath_test),
        cmocka_unit_test(sr_val_set_string_test),
        cmocka_unit_test(sr_dup_val_test),
        cmocka_unit_test(sr_dup_values_test)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
