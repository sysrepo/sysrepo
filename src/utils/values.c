/**
 * @file values.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Functions for simplified manipulation with Sysrepo values.
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

#include <unistd.h>
#include <inttypes.h>
#include <stdarg.h>

#include "sr_common.h"
#include "sysrepo/values.h"
#include "values_internal.h"

/**
 * @brief Returns pointer to the string where data of given string type is stored.
 */
static char **
sr_val_str_data_ptr(sr_val_t *value, sr_type_t type)
{
    switch (type) {
        case SR_BINARY_T:
            return &value->data.binary_val;
            break;
        case SR_BITS_T:
            return &value->data.bits_val;
            break;
        case SR_ENUM_T:
            return &value->data.enum_val;
            break;
        case SR_IDENTITYREF_T:
            return &value->data.identityref_val;
            break;
        case SR_INSTANCEID_T:
            return &value->data.instanceid_val;
            break;
        case SR_STRING_T:
            return &value->data.string_val;
            break;
        default:
            return NULL;
    }
}

/**
 * @brief Create a new instance of sysrepo value.
 */
static int
sr_new_val_ctx(sr_mem_ctx_t *sr_mem, const char *xpath, sr_val_t **value_p)
{
    int ret = SR_ERR_OK;
    bool new_ctx = false;
    sr_val_t *value = NULL;

    CHECK_NULL_ARG(value_p);

    if (NULL == sr_mem) {
        ret = sr_mem_new(sizeof *value + (xpath ? strlen(xpath) + 1 : 0), &sr_mem);
        CHECK_RC_MSG_RETURN(ret, "Failed to obtain new sysrepo memory.");
        new_ctx = true;
    }

    value = (sr_val_t *)sr_calloc(sr_mem, 1, sizeof *value);
    if (NULL == value) {
        if (new_ctx) {
            sr_mem_free(sr_mem);
        }
        return SR_ERR_INTERNAL;
    }
    value->_sr_mem = sr_mem;

    if (xpath) {
        ret = sr_val_set_xpath(value, xpath);
        if (SR_ERR_OK != ret) {
            if (new_ctx) {
                if (sr_mem) {
                    sr_mem_free(sr_mem);
                } else {
                    free(value);
                }
            } /**
               * Else leave the allocated data there, saving and restoring snapshot would be
               * expensive for such a small function.
               */
            return SR_ERR_INTERNAL;
        }
    }

    if (sr_mem) {
        ATOMIC_INC(&sr_mem->obj_count);
    }
    *value_p = value;
    return SR_ERR_OK;
}

int
sr_new_val(const char *xpath, sr_val_t **value_p)
{
    return sr_new_val_ctx(NULL, xpath, value_p);
}

/**
 * @brief Create an array of sysrepo values.
 */
static int
sr_new_values_ctx(sr_mem_ctx_t *sr_mem, size_t count, sr_val_t **values_p)
{
    int ret = SR_ERR_OK;
    bool new_ctx = false;
    sr_val_t *values = NULL;

    CHECK_NULL_ARG(values_p);

    if (0 == count) {
        *values_p = NULL;
        return SR_ERR_OK;
    }

    if (NULL == sr_mem) {
        ret = sr_mem_new((sizeof *values) * count, &sr_mem);
        CHECK_RC_MSG_RETURN(ret, "Failed to obtain new sysrepo memory.");
        new_ctx = true;
    }

    values = (sr_val_t *)sr_calloc(sr_mem, count, sizeof *values);
    if (NULL == values) {
        if (new_ctx) {
            if (sr_mem) {
                sr_mem_free(sr_mem);
            } else {
                free(values);
            }
        }
        return SR_ERR_INTERNAL;
    }
    if (sr_mem) {
        for (size_t i = 0; i < count; ++i) {
            values[i]._sr_mem = sr_mem;
        }
        ATOMIC_INC(&sr_mem->obj_count); /* 1 for the entire array */
    }

    *values_p = values;
    return SR_ERR_OK;
}

int
sr_new_values(size_t count, sr_val_t **values_p)
{
    return sr_new_values_ctx(NULL, count, values_p);
}

int
sr_realloc_values(size_t old_value_cnt, size_t new_value_cnt, sr_val_t **values_p)
{
    int ret = SR_ERR_OK;
    bool new_ctx = false;
    sr_val_t *values = NULL;
    sr_mem_ctx_t *sr_mem = NULL;

    CHECK_NULL_ARG(values_p);

    if (0 == new_value_cnt) {
        *values_p = NULL;
        return SR_ERR_OK;
    }

    if (0 == old_value_cnt) {
        ret = sr_mem_new((sizeof *values) * new_value_cnt, &sr_mem);
        CHECK_RC_MSG_RETURN(ret, "Failed to obtain new sysrepo memory.");
        new_ctx = true;
    } else {
        sr_mem = values_p[0]->_sr_mem;
    }

    values = (sr_val_t *)sr_realloc(sr_mem, *values_p, old_value_cnt * sizeof *values, new_value_cnt * sizeof *values);
    if (NULL == values) {
        if (new_ctx) {
            if (sr_mem) {
                sr_mem_free(sr_mem);
            } else {
                free(values);
            }
        }
        return SR_ERR_INTERNAL;
    }

    if (new_value_cnt > old_value_cnt) {
        /* zero the new memory */
        memset(values + old_value_cnt, 0, (new_value_cnt - old_value_cnt) * sizeof *values);
    }

    if (sr_mem) {
        for (size_t i = old_value_cnt; i < new_value_cnt; ++i) {
            values[i]._sr_mem = sr_mem;
        }
        if (0 == old_value_cnt) {
            ATOMIC_INC(&sr_mem->obj_count); /* 1 for the entire array */
        }
    }

    *values_p = values;
    return SR_ERR_OK;
}

int
sr_val_set_xpath(sr_val_t *value, const char *xpath)
{
    CHECK_NULL_ARG2(value, xpath);

    return sr_mem_edit_string(value->_sr_mem, &value->xpath, xpath);
}

int
sr_val_build_xpath(sr_val_t *value, const char *format, ...)
{
    va_list arg_list;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(value, format);

    va_start(arg_list, format);
    rc = sr_mem_edit_string_va(value->_sr_mem, &value->xpath, format, arg_list);
    va_end(arg_list);

    return rc;
}

int
sr_val_set_str_data(sr_val_t *value, sr_type_t type, const char *string_val)
{
    char **str_to_edit = NULL;

    CHECK_NULL_ARG2(value, string_val);

    str_to_edit = sr_val_str_data_ptr(value, type);
    if (NULL == str_to_edit) {
        return SR_ERR_INVAL_ARG;
    }
    value->type = type;

    return sr_mem_edit_string(value->_sr_mem, str_to_edit, string_val);
}

int
sr_val_build_str_data_va(sr_val_t *value, sr_type_t type, const char *format, va_list args)
{
    char **str_to_edit = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(value, format);

    str_to_edit = sr_val_str_data_ptr(value, type);
    if (NULL == str_to_edit) {
        return SR_ERR_INVAL_ARG;
    }
    value->type = type;

    rc = sr_mem_edit_string_va(value->_sr_mem, str_to_edit, format, args);

    return rc;
}

int
sr_val_build_str_data(sr_val_t *value, sr_type_t type, const char *format, ...)
{
    va_list arg_list;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(value, format);

    va_start(arg_list, format);
    rc = sr_val_build_str_data_va(value, type, format, arg_list);
    va_end(arg_list);

    return rc;
}

int
sr_dup_val_data(sr_val_t *dest, const sr_val_t *source)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_ARG2(source, dest);

    dest->dflt = source->dflt;

    switch (source->type) {
        case SR_BINARY_T:
            rc = sr_val_set_str_data(dest, source->type, source->data.binary_val);
            break;
        case SR_BITS_T:
            rc = sr_val_set_str_data(dest, source->type, source->data.bits_val);
            break;
        case SR_ENUM_T:
            rc = sr_val_set_str_data(dest, source->type, source->data.enum_val);
            break;
        case SR_IDENTITYREF_T:
            rc = sr_val_set_str_data(dest, source->type, source->data.identityref_val);
            break;
        case SR_INSTANCEID_T:
            rc = sr_val_set_str_data(dest, source->type, source->data.instanceid_val);
            break;
        case SR_STRING_T:
            rc = sr_val_set_str_data(dest, source->type, source->data.string_val);
            break;
        case SR_BOOL_T:
        case SR_DECIMAL64_T:
        case SR_INT8_T:
        case SR_INT16_T:
        case SR_INT32_T:
        case SR_INT64_T:
        case SR_UINT8_T:
        case SR_UINT16_T:
        case SR_UINT32_T:
        case SR_UINT64_T:
        case SR_TREE_ITERATOR_T:
            dest->data = source->data;
            dest->type = source->type;
            break;
        default:
            dest->type = source->type;
            break;
    }

    return rc;
}

int
sr_dup_val_ctx(const sr_val_t *value, sr_mem_ctx_t *sr_mem_dest, sr_val_t **value_dup_p)
{
    int rc = SR_ERR_OK;
    sr_val_t *val_dup = NULL;

    CHECK_NULL_ARG2(value, value_dup_p);

    rc = sr_new_val_ctx(sr_mem_dest, value->xpath, &val_dup);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create new sysrepo value.");

    rc = sr_dup_val_data(val_dup, value);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to duplicate sysrepo value data.");

    *value_dup_p = val_dup;

cleanup:
    if (SR_ERR_OK != rc) {
        sr_free_val(val_dup);
    }

    return rc;
}

int
sr_dup_val(const sr_val_t *value, sr_val_t **value_dup_p)
{
    return sr_dup_val_ctx(value, NULL, value_dup_p);
}

int
sr_dup_values_ctx(const sr_val_t *values, size_t count, sr_mem_ctx_t *sr_mem_dest, sr_val_t **values_dup_p)
{
    int rc = SR_ERR_OK;
    sr_val_t *values_dup = NULL;

    CHECK_NULL_ARG2(values, values_dup_p);

    rc = sr_new_values_ctx(sr_mem_dest, count, &values_dup);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create new array of sysrepo values.");

    for (size_t i = 0; i < count; ++i) {
        sr_val_set_xpath(values_dup + i, values[i].xpath);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to duplicate sysrepo value xpath.");
        rc = sr_dup_val_data(values_dup + i, values + i);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to duplicate sysrepo value data.");
    }

    *values_dup_p = values_dup;

cleanup:
    if (SR_ERR_OK != rc) {
        sr_free_values(values_dup, count);
    }

    return rc;
}

int
sr_dup_values(const sr_val_t *values, size_t count, sr_val_t **values_dup_p)
{
    return sr_dup_values_ctx(values, count, NULL, values_dup_p);
}

int
sr_print_val_ctx(sr_print_ctx_t *print_ctx, const sr_val_t *value)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(print_ctx);

    if (NULL == value) {
        return rc;
    }

    rc = sr_print(print_ctx, "%s ", value->xpath);
    CHECK_RC_MSG_RETURN(rc, "Failed to print xpath of a sysrepo value");

    switch (value->type) {
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
        rc = sr_print(print_ctx, "(container)");
        break;
    case SR_LIST_T:
        rc = sr_print(print_ctx, "(list instance)");
        break;
    case SR_STRING_T:
        rc = sr_print(print_ctx, "= %s", value->data.string_val);
        break;
    case SR_BOOL_T:
        rc = sr_print(print_ctx, "= %s", value->data.bool_val ? "true" : "false");
        break;
    case SR_DECIMAL64_T:
        rc = sr_print(print_ctx, "= %g", value->data.decimal64_val);
        break;
    case SR_INT8_T:
        rc = sr_print(print_ctx, "= %" PRId8, value->data.int8_val);
        break;
    case SR_INT16_T:
        rc = sr_print(print_ctx, "= %" PRId16, value->data.int16_val);
        break;
    case SR_INT32_T:
        rc = sr_print(print_ctx, "= %" PRId32, value->data.int32_val);
        break;
    case SR_INT64_T:
        rc = sr_print(print_ctx, "= %" PRId64, value->data.int64_val);
        break;
    case SR_UINT8_T:
        rc = sr_print(print_ctx, "= %" PRIu8, value->data.uint8_val);
        break;
    case SR_UINT16_T:
        rc = sr_print(print_ctx, "= %" PRIu16, value->data.uint16_val);
        break;
    case SR_UINT32_T:
        rc = sr_print(print_ctx, "= %" PRIu32, value->data.uint32_val);
        break;
    case SR_UINT64_T:
        rc = sr_print(print_ctx, "= %" PRIu64, value->data.uint64_val);
        break;
    case SR_IDENTITYREF_T:
        rc = sr_print(print_ctx, "= %s", value->data.identityref_val);
        break;
    case SR_INSTANCEID_T:
        rc = sr_print(print_ctx, "= %s", value->data.instanceid_val);
        break;
    case SR_BITS_T:
        rc = sr_print(print_ctx, "= %s", value->data.bits_val);
        break;
    case SR_BINARY_T:
        rc = sr_print(print_ctx, "= %s", value->data.binary_val);
        break;
    case SR_ENUM_T:
        rc = sr_print(print_ctx, "= %s", value->data.enum_val);
        break;
    case SR_LEAF_EMPTY_T:
        rc = sr_print(print_ctx, "(empty leaf)");
        break;
    default:
        rc = sr_print(print_ctx, "(unprintable)");
    }

    if (SR_ERR_OK == rc) {
        switch (value->type) {
        case SR_UNKNOWN_T:
        case SR_TREE_ITERATOR_T:
        case SR_CONTAINER_T:
        case SR_CONTAINER_PRESENCE_T:
        case SR_LIST_T:
        case SR_LEAF_EMPTY_T:
            rc = sr_print(print_ctx, "\n");
            break;
        default:
            rc = sr_print(print_ctx, "%s\n", value->dflt ? " [default]" : "");
        }
    }

    CHECK_RC_MSG_RETURN(rc, "Failed to print data of a sysrepo value");
    return rc;
}

int
sr_print_val(const sr_val_t *value)
{
    sr_print_ctx_t print_ctx = { 0, };

    print_ctx.type = SR_PRINT_STREAM;
    print_ctx.method.stream = stdout;

    return sr_print_val_ctx(&print_ctx, value);
}

int
sr_print_val_fd(int fd, const sr_val_t *value)
{
    sr_print_ctx_t print_ctx = { 0, };

    print_ctx.type = SR_PRINT_FD;
    print_ctx.method.fd = fd;

    return sr_print_val_ctx(&print_ctx, value);
}

int
sr_print_val_stream(FILE *stream, const sr_val_t *value)
{
    sr_print_ctx_t print_ctx = { 0, };

    print_ctx.type = SR_PRINT_STREAM;
    print_ctx.method.stream = stream;

    return sr_print_val_ctx(&print_ctx, value);
}

int
sr_print_val_mem(char **mem_p, const sr_val_t *value)
{
    int rc = SR_ERR_OK;
    sr_print_ctx_t print_ctx = { 0, };

    CHECK_NULL_ARG(mem_p);

    print_ctx.type = SR_PRINT_MEM;
    print_ctx.method.mem.buf = NULL;
    print_ctx.method.mem.len = 0;
    print_ctx.method.mem.size = 0;

    rc = sr_print_val_ctx(&print_ctx, value);
    if (SR_ERR_OK == rc) {
        *mem_p = print_ctx.method.mem.buf;
    } else {
        free(print_ctx.method.mem.buf);
    }
    return rc;
}

char *
sr_val_to_str(const sr_val_t *value)
{
    int rc = SR_ERR_OK;
    char *out = NULL;

    if (NULL != value) {
        switch (value->type) {
        case SR_BINARY_T:
            if (NULL != value->data.binary_val) {
                out = strdup(value->data.binary_val);
                CHECK_NULL_NOMEM_GOTO(out, rc, cleanup);
            }
            break;
        case SR_BITS_T:
            if (NULL != value->data.bits_val) {
                out = strdup(value->data.bits_val);
                CHECK_NULL_NOMEM_GOTO(out, rc, cleanup);
            }
            break;
        case SR_BOOL_T:
            out = value->data.bool_val ? strdup("true") : strdup("false");
            CHECK_NULL_NOMEM_GOTO(out, rc, cleanup);
            break;
        case SR_DECIMAL64_T:
            rc = sr_asprintf(&out, "%g", value->data.decimal64_val);
            break;
        case SR_ENUM_T:
            if (NULL != value->data.enum_val) {
                out = strdup(value->data.enum_val);
                CHECK_NULL_NOMEM_GOTO(out, rc, cleanup);
            }
            break;
        case SR_LIST_T:
        case SR_CONTAINER_T:
        case SR_CONTAINER_PRESENCE_T:
        case SR_LEAF_EMPTY_T:
            out = strdup("");
            CHECK_NULL_NOMEM_GOTO(out, rc, cleanup);
            break;
        case SR_IDENTITYREF_T:
            if (NULL != value->data.identityref_val) {
                out = strdup(value->data.identityref_val);
                CHECK_NULL_NOMEM_GOTO(out, rc, cleanup);
            }
            break;
        case SR_INSTANCEID_T:
            if (NULL != value->data.instanceid_val) {
                out = strdup(value->data.instanceid_val);
                CHECK_NULL_NOMEM_GOTO(out, rc, cleanup);
            }
            break;
        case SR_INT8_T:
            rc = sr_asprintf(&out, "%"PRId8, value->data.int8_val);
            break;
        case SR_INT16_T:
            rc = sr_asprintf(&out, "%"PRId16, value->data.int16_val);
            break;
        case SR_INT32_T:
            rc = sr_asprintf(&out, "%"PRId32, value->data.int32_val);
            break;
        case SR_INT64_T:
            rc = sr_asprintf(&out, "%"PRId64, value->data.int64_val);
            break;
        case SR_STRING_T:
            if (NULL != value->data.string_val){
                out = strdup(value->data.string_val);
                CHECK_NULL_NOMEM_GOTO(out, rc, cleanup);
            }
            break;
        case SR_UINT8_T:
            rc = sr_asprintf(&out, "%"PRIu8, value->data.uint8_val);
            break;
        case SR_UINT16_T:
            rc = sr_asprintf(&out, "%"PRIu16, value->data.uint16_val);
            break;
        case SR_UINT32_T:
            rc = sr_asprintf(&out, "%"PRIu32, value->data.uint32_val);
            break;
        case SR_UINT64_T:
            rc = sr_asprintf(&out, "%"PRIu64, value->data.uint64_val);
            break;
        case SR_ANYXML_T:
            if (NULL != value->data.anyxml_val){
                out = strdup(value->data.anyxml_val);
                CHECK_NULL_NOMEM_GOTO(out, rc, cleanup);
            }
            break;
        case SR_ANYDATA_T:
            if (NULL != value->data.anydata_val){
                out = strdup(value->data.anydata_val);
                CHECK_NULL_NOMEM_GOTO(out, rc, cleanup);
            }
            break;
        default:
            SR_LOG_ERR_MSG("Conversion of value_t to string failed");
        }
    }
cleanup:
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Failed to duplicate string");
    }
    return out;
}

int
sr_val_to_buff(const sr_val_t *value, char buffer[], size_t size)
{
    size_t len = 0;

    if (NULL == value) {
        SR_LOG_WRN_MSG("NULL provided as value argument");
        return 0;
    }

    switch (value->type) {
    case SR_BINARY_T:
        if (NULL != value->data.binary_val) {
            len = snprintf(buffer, size, "%s", value->data.binary_val);
        }
        break;
    case SR_BITS_T:
        if (NULL != value->data.bits_val) {
            len = snprintf(buffer, size, "%s", value->data.bits_val);
        }
        break;
    case SR_BOOL_T:
        len = snprintf(buffer, size, "%s", value->data.bool_val ? "true" : "false");
        break;
    case SR_DECIMAL64_T:
        len = snprintf(buffer, size, "%g", value->data.decimal64_val);
        break;
    case SR_ENUM_T:
        if (NULL != value->data.enum_val) {
            len = snprintf(buffer, size, "%s", value->data.enum_val);
        }
        break;
    case SR_LIST_T:
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
    case SR_LEAF_EMPTY_T:
        len = snprintf(buffer, size, "%s", "");
        break;
    case SR_IDENTITYREF_T:
        if (NULL != value->data.identityref_val) {
            len = snprintf(buffer, size, "%s", value->data.identityref_val);
        }
        break;
    case SR_INSTANCEID_T:
        if (NULL != value->data.instanceid_val) {
            len = snprintf(buffer, size, "%s", value->data.instanceid_val);
        }
        break;
    case SR_INT8_T:
        len = snprintf(buffer, size, "%"PRId8, value->data.int8_val);
        break;
    case SR_INT16_T:
        len = snprintf(buffer, size, "%"PRId16, value->data.int16_val);
        break;
    case SR_INT32_T:
        len = snprintf(buffer, size, "%"PRId32, value->data.int32_val);
        break;
    case SR_INT64_T:
        len = snprintf(buffer, size, "%"PRId64, value->data.int64_val);
        break;
    case SR_STRING_T:
        if (NULL != value->data.string_val) {
            len = snprintf(buffer, size, "%s", value->data.string_val);
        }
        break;
    case SR_UINT8_T:
        len = snprintf(buffer, size, "%"PRIu8, value->data.uint8_val);
        break;
    case SR_UINT16_T:
        len = snprintf(buffer, size, "%"PRIu16, value->data.uint16_val);
        break;
    case SR_UINT32_T:
        len = snprintf(buffer, size, "%"PRIu32, value->data.uint32_val);
        break;
    case SR_UINT64_T:
        len = snprintf(buffer, size, "%"PRIu64, value->data.uint64_val);
        break;
    case SR_ANYXML_T:
        if (NULL != value->data.anyxml_val) {
            len = snprintf(buffer, size, "%s", value->data.anyxml_val);
        }
        break;
    case SR_ANYDATA_T:
        if (NULL != value->data.anydata_val) {
            len = snprintf(buffer, size, "%s", value->data.anydata_val);
        }
        break;
    default:
        SR_LOG_ERR_MSG("Conversion of value_t to string failed");
    }

    if (size < (len+1)) {
        SR_LOG_DBG_MSG("There is not enough space in the buffer to print the value");
    }
    return len;
}
