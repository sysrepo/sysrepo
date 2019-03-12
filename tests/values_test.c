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
#include "system_helper.h"

#define XPATH1 "/example-module:container/list[key1='key1'][key2='key2']/leaf"
#define XPATH2 "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4"
#define XPATH3 "/ietf-interfaces:interfaces/interface[name='gigaeth0']"
#define XPATH4 "/ietf-interfaces:interfaces"

#define XPATH_TEMPLATE1 "/example-module:container/list[key1='key1-%d'][key2='key2-%d']/leaf"
#define XPATH_TEMPLATE2 "/test-module:main/numbers[.='%d']"

static void
sr_test_all_printers(sr_val_t *value, const char *expected)
{
    int rc = SR_ERR_OK;
    char *mem = NULL;
    char filepath1[] = "/tmp/sr_values_test1.XXXXXX", filepath2[] = "/tmp/sr_values_test2.XXXXXX";
    int fd = 0;
    FILE *stream = NULL;
    mode_t orig_umask = umask(S_IRWXO|S_IRWXG);

    /* memory */
    rc = sr_print_val_mem(&mem, value);
    assert_int_equal(SR_ERR_OK, rc);
    if (NULL == expected) {
        assert_null(mem);
    } else {
        assert_non_null(mem);
        assert_string_equal(expected, mem);
    }
    free(mem);

    /* fd */
    fd = mkstemp(filepath1);
    assert_true(0 < fd);
    rc = sr_print_val_fd(fd, value);
    assert_int_equal(SR_ERR_OK, rc);
    close(fd);
    test_file_content(filepath1, expected ? expected : "", false);
    unlink(filepath1);

    /* stream */
    fd = mkstemp(filepath2);
    assert_true(0 < fd);
    stream = fdopen(fd, "w");
    assert_non_null(stream);
    rc = sr_print_val_stream(stream, value);
    assert_int_equal(SR_ERR_OK, rc);
    fclose(stream);
    test_file_content(filepath2, expected ? expected : "", false);
    unlink(filepath2);
    umask(orig_umask);
}

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
sr_realloc_values_test(void **state)
{
    int rc = 0;
    sr_val_t *values = NULL;

    rc = sr_realloc_values(0, 0, &values);
    assert_int_equal(SR_ERR_OK, rc);
    assert_null(values);
    sr_free_values(values, 0);

    rc = sr_realloc_values(0, 5, &values);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(values);
#ifdef USE_SR_MEM_MGMT
    assert_non_null(values->_sr_mem);
    assert_int_equal(1, values->_sr_mem->obj_count);
    assert_true(0 < values->_sr_mem->used_total);
#else
    assert_null(values->_sr_mem);
#endif
    for (int i = 0; i < 5; ++i) {
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

    for (int i = 0; i < 5; ++i) {
        values[i].data.uint64_val = i;
    }

    rc = sr_realloc_values(5, 10, &values);
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
        if (i < 5) {
            assert_int_equal(i, values[i].data.uint64_val);
        } else {
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
sr_val_build_xpath_test(void **state)
{
    int rc = 0;
    sr_val_t *values = NULL;
    char xpath[PATH_MAX] = { 0, };

    rc = sr_new_values(10, &values);
    assert_int_equal(SR_ERR_OK, rc);
    for (int i = 0; i < 10; ++i) {
        assert_null(values[i].xpath);
        snprintf(xpath, PATH_MAX, XPATH_TEMPLATE1, i, i);
        rc = sr_val_build_xpath(values + i, XPATH_TEMPLATE1, i, i);
        assert_int_equal(SR_ERR_OK, rc);
        assert_string_equal(xpath, values[i].xpath);
        snprintf(xpath, PATH_MAX, XPATH_TEMPLATE2, i);
        rc = sr_val_build_xpath(values + i, xpath, i);
        assert_int_equal(SR_ERR_OK, rc);
        assert_string_equal(xpath, values[i].xpath);
    }
    sr_free_values(values, 10);
}

static void
sr_val_set_str_data_test(void **state)
{
    int rc = 0;
    sr_val_t *value = NULL;

    rc = sr_new_val(NULL, &value);
    assert_int_equal(SR_ERR_OK, rc);
    assert_null(value->data.string_val);

    rc = sr_val_set_str_data(value, SR_UINT32_T, "string value");
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    rc = sr_val_set_str_data(value, SR_STRING_T, "string value");
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("string value", value->data.string_val);

    rc = sr_val_set_str_data(value, SR_BINARY_T, "binary value");
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("binary value", value->data.binary_val);

    rc = sr_val_set_str_data(value, SR_ENUM_T, "enum value");
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("enum value", value->data.enum_val);

    rc = sr_val_set_str_data(value, SR_BITS_T, "bits");
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("bits", value->data.bits_val);

    rc = sr_val_set_str_data(value, SR_IDENTITYREF_T, "identityref value");
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("identityref value", value->data.identityref_val);

    rc = sr_val_set_str_data(value, SR_INSTANCEID_T, "instance ID");
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("instance ID", value->data.instanceid_val);

    sr_free_val(value);
}

static void
sr_val_build_str_data_test(void **state)
{
    int rc = 0;
    sr_val_t *value = NULL;

    rc = sr_new_val(NULL, &value);
    assert_int_equal(SR_ERR_OK, rc);
    assert_null(value->data.string_val);

    rc = sr_val_build_str_data(value, SR_UINT32_T, "string value n. %d", 1);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    rc = sr_val_build_str_data(value, SR_STRING_T, "string value n. %d", 1);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("string value n. 1", value->data.string_val);

    rc = sr_val_build_str_data(value, SR_BINARY_T, "binary value n. %d", 2);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("binary value n. 2", value->data.binary_val);

    rc = sr_val_build_str_data(value, SR_ENUM_T, "enum value n. %d", 3);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("enum value n. 3", value->data.enum_val);

    rc = sr_val_build_str_data(value, SR_BITS_T, "bits value n. %d", 4);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("bits value n. 4", value->data.bits_val);

    rc = sr_val_build_str_data(value, SR_IDENTITYREF_T, "identityref value n. %d", 5);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("identityref value n. 5", value->data.identityref_val);

    rc = sr_val_build_str_data(value, SR_INSTANCEID_T, "instance ID value n. %d", 6);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("instance ID value n. 6", value->data.instanceid_val);

    sr_free_val(value);
}

static void
sr_dup_val_test(void **state)
{
    int rc = 0;
    sr_val_t *value = NULL, *value_dup = NULL;

    /* create a new value using the API */
    rc = sr_new_val(NULL, &value);
    rc = sr_val_set_str_data(value, SR_STRING_T, "string value");
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
    rc = sr_val_set_str_data(value, SR_STRING_T, "string value2");
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
        snprintf(string_val, 10, "%d", i);
        rc = sr_val_set_str_data(values + i, SR_STRING_T, string_val);
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

static void
sr_print_val_test(void **state)
{
    sr_val_t *value = NULL;

    /* empty tree */
    sr_test_all_printers(value, NULL);

    assert_int_equal(SR_ERR_OK, sr_new_val(XPATH1, &value));
    value->type = SR_UINT32_T;
    value->data.uint32_val = 123;
    value->dflt = true;
    sr_test_all_printers(value, XPATH1" = 123 [default]\n");
    value->dflt = false;
    sr_test_all_printers(value, XPATH1" = 123\n");
    sr_free_val(value);

    assert_int_equal(SR_ERR_OK, sr_new_val(XPATH1, &value));
    value->type = SR_BOOL_T;
    value->data.bool_val = true;
    value->dflt = true;
    sr_test_all_printers(value, XPATH1" = true [default]\n");
    value->dflt = false;
    sr_test_all_printers(value, XPATH1" = true\n");
    sr_free_val(value);

    assert_int_equal(SR_ERR_OK, sr_new_val(XPATH3, &value));
    value->type = SR_LIST_T;
    value->dflt = true;
    sr_test_all_printers(value, XPATH3" (list instance)\n");
    value->dflt = false;
    sr_test_all_printers(value, XPATH3" (list instance)\n");
    sr_free_val(value);

    assert_int_equal(SR_ERR_OK, sr_new_val(XPATH4, &value));
    value->type = SR_CONTAINER_T;
    value->dflt = true;
    sr_test_all_printers(value, XPATH4" (container)\n");
    value->dflt = false;
    sr_test_all_printers(value, XPATH4" (container)\n");
    sr_free_val(value);

    assert_int_equal(SR_ERR_OK, sr_new_val(XPATH2, &value));
    sr_val_set_str_data(value, SR_STRING_T, "192.168.1.1");
    value->dflt = true;
    sr_test_all_printers(value, XPATH2" = 192.168.1.1 [default]\n");
    value->dflt = false;
    sr_test_all_printers(value, XPATH2" = 192.168.1.1\n");
    sr_free_val(value);
}

static void
sr_val_to_str_test(void **state)
{
    sr_val_t v = {0};
    char *val = NULL;

    v.data.binary_val = "bindata";
    v.type = SR_BINARY_T;
    val = sr_val_to_str(&v);
    assert_non_null(val);
    assert_string_equal(val, v.data.binary_val);
    free(val);

    v.data.bits_val = "bitA";
    v.type = SR_BITS_T;
    val = sr_val_to_str(&v);
    assert_non_null(val);
    assert_string_equal(val, v.data.bits_val);
    free(val);

    v.data.bool_val = true;
    v.type = SR_BOOL_T;
    val = sr_val_to_str(&v);
    assert_non_null(val);
    assert_string_equal(val, "true");
    free(val);

    v.data.bool_val = false;
    v.type = SR_BOOL_T;
    val = sr_val_to_str(&v);
    assert_non_null(val);
    assert_string_equal(val, "false");
    free(val);

    v.data.decimal64_val = -6.92;
    v.type = SR_DECIMAL64_T;
    val = sr_val_to_str(&v);
    assert_non_null(val);
    assert_string_equal(val, "-6.92");
    free(val);

    v.data.enum_val = "enumA";
    v.type = SR_ENUM_T;
    val = sr_val_to_str(&v);
    assert_non_null(val);
    assert_string_equal(val, "enumA");
    free(val);

    v.type = SR_LIST_T;
    val = sr_val_to_str(&v);
    assert_non_null(val);
    assert_string_equal(val, "");
    free(val);

    v.data.identityref_val = "identityA";
    v.type = SR_IDENTITYREF_T;
    val = sr_val_to_str(&v);
    assert_non_null(val);
    assert_string_equal(val, "identityA");
    free(val);

    v.data.instanceid_val = "/test-module:main/i8";
    v.type = SR_INSTANCEID_T;
    val = sr_val_to_str(&v);
    assert_non_null(val);
    assert_string_equal(val, v.data.instanceid_val);
    free(val);

    v.data.uint8_val = 8;
    v.type = SR_UINT8_T;
    val = sr_val_to_str(&v);
    assert_non_null(val);
    assert_string_equal(val, "8");
    free(val);

    v.data.uint16_val = 16;
    v.type = SR_UINT16_T;
    val = sr_val_to_str(&v);
    assert_non_null(val);
    assert_string_equal(val, "16");
    free(val);

    v.data.uint32_val = 32;
    v.type = SR_UINT32_T;
    val = sr_val_to_str(&v);
    assert_non_null(val);
    assert_string_equal(val, "32");
    free(val);

    v.data.uint64_val = 64;
    v.type = SR_UINT64_T;
    val = sr_val_to_str(&v);
    assert_non_null(val);
    assert_string_equal(val, "64");
    free(val);

    v.data.int8_val = -8;
    v.type = SR_INT8_T;
    val = sr_val_to_str(&v);
    assert_non_null(val);
    assert_string_equal(val, "-8");
    free(val);

    v.data.int16_val = -16;
    v.type = SR_INT16_T;
    val = sr_val_to_str(&v);
    assert_non_null(val);
    assert_string_equal(val, "-16");
    free(val);

    v.data.int32_val = -32;
    v.type = SR_INT32_T;
    val = sr_val_to_str(&v);
    assert_non_null(val);
    assert_string_equal(val, "-32");
    free(val);

    v.data.int64_val = -42;
    v.type = SR_INT64_T;
    val = sr_val_to_str(&v);
    assert_non_null(val);
    assert_string_equal(val, "-42");
    free(val);

    v.data.string_val = "---";
    v.type = SR_STRING_T;
    val = sr_val_to_str(&v);
    assert_non_null(val);
    assert_string_equal(val, v.data.string_val);
    free(val);

    v.data.anyxml_val = "<abc></abc>";
    v.type = SR_ANYXML_T;
    val = sr_val_to_str(&v);
    assert_non_null(val);
    assert_string_equal(val, v.data.anyxml_val);
    free(val);

    v.data.anydata_val = "<data></data>";
    v.type = SR_ANYDATA_T;
    val = sr_val_to_str(&v);
    assert_non_null(val);
    assert_string_equal(val, v.data.anydata_val);
    free(val);

    //type not filled
    v.type = SR_UNKNOWN_T;
    val = sr_val_to_str(&v);
    assert_null(val);

}

static void
sr_val_to_buff_test(void **state)
{
#define BUFF_MAX_SIZE 200
    sr_val_t v = {0};

    char buffer[BUFF_MAX_SIZE] = {0};
    int ret = 0;

    ret = sr_val_to_buff(NULL, buffer, BUFF_MAX_SIZE);
    assert_int_equal(0, ret);

    v.type = SR_UNKNOWN_T;
    ret = sr_val_to_buff(&v, buffer, BUFF_MAX_SIZE);
    assert_int_equal(0, ret);
    assert_string_equal("", buffer);

    v.type = SR_BINARY_T;
    v.data.binary_val = "abcd";
    ret = sr_val_to_buff(&v, NULL, 0);
    assert_int_equal(4, ret);

    ret = sr_val_to_buff(&v, buffer, 4);
    assert_int_equal(4, ret);
    assert_string_equal("abc", buffer);
    memset(buffer, 0, BUFF_MAX_SIZE);

    ret = sr_val_to_buff(&v, buffer, 5);
    assert_int_equal(4, ret);
    assert_string_equal("abcd", buffer);
    memset(buffer, 0, BUFF_MAX_SIZE);

    v.type = SR_BITS_T;
    v.data.bits_val = "bit1 bit2";
    ret = sr_val_to_buff(&v, buffer, BUFF_MAX_SIZE);
    assert_string_equal(buffer, v.data.bits_val);
    memset(buffer, 0, BUFF_MAX_SIZE);

    v.type = SR_BOOL_T;
    v.data.bool_val = true;
    ret = sr_val_to_buff(&v, buffer, BUFF_MAX_SIZE);
    assert_string_equal(buffer, "true");
    memset(buffer, 0, BUFF_MAX_SIZE);

    v.type = SR_DECIMAL64_T;
    v.data.decimal64_val = -42.68;
    ret = sr_val_to_buff(&v, buffer, BUFF_MAX_SIZE);
    assert_string_equal(buffer, "-42.68");
    memset(buffer, 0, BUFF_MAX_SIZE);

    v.type = SR_ENUM_T;
    v.data.enum_val = "enumA";
    ret = sr_val_to_buff(&v, buffer, BUFF_MAX_SIZE);
    assert_string_equal(buffer, v.data.enum_val);
    memset(buffer, 0, BUFF_MAX_SIZE);

    v.type = SR_LIST_T;
    ret = sr_val_to_buff(&v, buffer, BUFF_MAX_SIZE);
    assert_string_equal(buffer, "");
    memset(buffer, 0, BUFF_MAX_SIZE);

    v.type = SR_IDENTITYREF_T;
    v.data.identityref_val = "identityOne";
    ret = sr_val_to_buff(&v, buffer, BUFF_MAX_SIZE);
    assert_string_equal(buffer, v.data.identityref_val);
    memset(buffer, 0, BUFF_MAX_SIZE);

    v.type = SR_INSTANCEID_T;
    v.data.instanceid_val = "/example-module:container";
    ret = sr_val_to_buff(&v, buffer, BUFF_MAX_SIZE);
    assert_string_equal(buffer, v.data.instanceid_val);
    memset(buffer, 0, BUFF_MAX_SIZE);

    v.type = SR_INT8_T;
    v.data.int8_val = -8;
    ret = sr_val_to_buff(&v, buffer, BUFF_MAX_SIZE);
    assert_string_equal(buffer, "-8");
    memset(buffer, 0, BUFF_MAX_SIZE);

    v.type = SR_INT16_T;
    v.data.int16_val = -16;
    ret = sr_val_to_buff(&v, buffer, BUFF_MAX_SIZE);
    assert_string_equal(buffer, "-16");
    memset(buffer, 0, BUFF_MAX_SIZE);

    v.type = SR_INT32_T;
    v.data.int32_val = -32;
    ret = sr_val_to_buff(&v, buffer, BUFF_MAX_SIZE);
    assert_string_equal(buffer, "-32");
    memset(buffer, 0, BUFF_MAX_SIZE);

    v.type = SR_INT64_T;
    v.data.int64_val = -64;
    ret = sr_val_to_buff(&v, buffer, BUFF_MAX_SIZE);
    assert_string_equal(buffer, "-64");
    memset(buffer, 0, BUFF_MAX_SIZE);

    v.type = SR_STRING_T;
    v.data.string_val = "string";
    ret = sr_val_to_buff(&v, buffer, BUFF_MAX_SIZE);
    assert_string_equal(buffer, v.data.string_val);
    memset(buffer, 0, BUFF_MAX_SIZE);

    v.type = SR_UINT8_T;
    v.data.uint8_val = 8;
    ret = sr_val_to_buff(&v, buffer, BUFF_MAX_SIZE);
    assert_string_equal(buffer, "8");
    memset(buffer, 0, BUFF_MAX_SIZE);

    v.type = SR_UINT16_T;
    v.data.uint16_val = 16;
    ret = sr_val_to_buff(&v, buffer, BUFF_MAX_SIZE);
    assert_string_equal(buffer, "16");
    memset(buffer, 0, BUFF_MAX_SIZE);

    v.type = SR_UINT32_T;
    v.data.uint32_val = 32;
    ret = sr_val_to_buff(&v, buffer, BUFF_MAX_SIZE);
    assert_string_equal(buffer, "32");
    memset(buffer, 0, BUFF_MAX_SIZE);

    v.type = SR_UINT64_T;
    v.data.uint64_val = 64;
    ret = sr_val_to_buff(&v, buffer, BUFF_MAX_SIZE);
    assert_string_equal(buffer, "64");
    memset(buffer, 0, BUFF_MAX_SIZE);

    v.type = SR_ANYXML_T;
    v.data.anyxml_val = "<abc></abc>";
    ret = sr_val_to_buff(&v, buffer, BUFF_MAX_SIZE);
    assert_string_equal(buffer, v.data.anyxml_val);
    memset(buffer, 0, BUFF_MAX_SIZE);

    v.type = SR_ANYDATA_T;
    v.data.anydata_val = "<data></data>";
    ret = sr_val_to_buff(&v, buffer, BUFF_MAX_SIZE);
    assert_string_equal(buffer, v.data.anydata_val);
    memset(buffer, 0, BUFF_MAX_SIZE);
}

int
main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(sr_new_val_test),
        cmocka_unit_test(sr_new_values_test),
        cmocka_unit_test(sr_realloc_values_test),
        cmocka_unit_test(sr_val_set_xpath_test),
        cmocka_unit_test(sr_val_build_xpath_test),
        cmocka_unit_test(sr_val_set_str_data_test),
        cmocka_unit_test(sr_val_build_str_data_test),
        cmocka_unit_test(sr_dup_val_test),
        cmocka_unit_test(sr_dup_values_test),
        cmocka_unit_test(sr_print_val_test),
        cmocka_unit_test(sr_val_to_str_test),
        cmocka_unit_test(sr_val_to_buff_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
