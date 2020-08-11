/**
 * @file values.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Functions for simplified manipulation with Sysrepo values.
 *
 * @copyright
 * Copyright 2019 CESNET, z.s.p.o.
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
#define _POSIX_C_SOURCE 200809L

#include <unistd.h>
#include <inttypes.h>
#include <stdarg.h>
#include <string.h>

#include "values.h"
#include "common.h"

/** get the larger item */
#define MAX(a, b) ((a) > (b) ? (a) : (b))

/**
 * @brief Type of the destination for the print operation.
 */
typedef enum sr_print_type_e {
    SR_PRINT_STREAM,  /**< File stream. */
    SR_PRINT_FD,      /**< File descriptor. */
    SR_PRINT_MEM      /**< Memory buffer. */
} sr_print_type_t;

/**
 * @brief Context for the print operation.
 */
typedef struct sr_print_ctx_s {
    sr_print_type_t type;
    union {
        int fd;
        FILE *stream;
        struct {
            char *buf;
            size_t len;
            size_t size;
        } mem;
    } method;
} sr_print_ctx_t;

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

API int
sr_new_val(const char *xpath, sr_val_t **value_p)
{
    int ret = SR_ERR_OK;
    sr_val_t *value = NULL;

    value = (sr_val_t *)calloc(1, sizeof *value);
    if (NULL == value) {
        return SR_ERR_INTERNAL;
    }

    if (xpath) {
        ret = sr_val_set_xpath(value, xpath);
        if (SR_ERR_OK != ret) {
            free(value);
            return SR_ERR_INTERNAL;
        }
    }

    *value_p = value;
    return SR_ERR_OK;
}

API int
sr_new_values(size_t count, sr_val_t **values_p)
{
    sr_val_t *values = NULL;

    if (0 == count) {
        *values_p = NULL;
        return SR_ERR_OK;
    }

    values = (sr_val_t *)calloc(count, sizeof *values);
    if (NULL == values) {
        return SR_ERR_INTERNAL;
    }

    *values_p = values;
    return SR_ERR_OK;
}

API int
sr_realloc_values(size_t old_value_cnt, size_t new_value_cnt, sr_val_t **values_p)
{
    sr_val_t *values = NULL;

    if (0 == new_value_cnt) {
        *values_p = NULL;
        return SR_ERR_OK;
    }

    values = (sr_val_t *)realloc(*values_p, new_value_cnt * sizeof *values);
    if (NULL == values) {
        return SR_ERR_INTERNAL;
    }

    if (new_value_cnt > old_value_cnt) {
        /* zero the new memory */
        memset(values + old_value_cnt, 0, (new_value_cnt - old_value_cnt) * sizeof *values);
    }

    *values_p = values;
    return SR_ERR_OK;
}

static int
sr_mem_edit_string(char **string_p, const char *new_val)
{
    char *new_mem = NULL;

    if (NULL != *string_p && strlen(*string_p) >= strlen(new_val)) {
        /* buffer large enough - overwrite */
        strcpy(*string_p, new_val);
        return SR_ERR_OK;
    }

    new_mem = strdup(new_val);
    if (!new_mem) {
        return SR_ERR_NOMEM;
    }

    free(*string_p);
    *string_p = new_mem;

    return SR_ERR_OK;
}

API int
sr_val_set_xpath(sr_val_t *value, const char *xpath)
{
    return sr_mem_edit_string(&value->xpath, xpath);
}

static int
sr_mem_edit_string_va(char **string_p, const char *format, va_list args)
{
    char *new_mem = NULL;
    va_list args_copy;
    size_t len = 0;

    /* determine required length - need to use a copy of args! */
    va_copy(args_copy, args);
    len = vsnprintf(NULL, 0, format, args_copy);
    va_end(args_copy);

    if (NULL != *string_p && strlen(*string_p) >= len) {
        /* buffer large enough - overwrite */
        vsnprintf(*string_p, len + 1, format, args);
        return SR_ERR_OK;
    }

    new_mem = (char *)calloc(len + 1, sizeof(*new_mem));
    if (!new_mem) {
        return SR_ERR_NOMEM;
    }

    vsnprintf(new_mem, len + 1, format, args);
    free(*string_p);
    *string_p = new_mem;

    return SR_ERR_OK;
}

API int
sr_val_build_xpath(sr_val_t *value, const char *format, ...)
{
    va_list arg_list;
    int rc = SR_ERR_OK;

    va_start(arg_list, format);
    rc = sr_mem_edit_string_va(&value->xpath, format, arg_list);
    va_end(arg_list);

    return rc;
}

API int
sr_val_set_str_data(sr_val_t *value, sr_type_t type, const char *string_val)
{
    char **str_to_edit = NULL;

    str_to_edit = sr_val_str_data_ptr(value, type);
    if (NULL == str_to_edit) {
        return SR_ERR_INVAL_ARG;
    }
    value->type = type;

    return sr_mem_edit_string(str_to_edit, string_val);
}

static int
sr_val_build_str_data_va(sr_val_t *value, sr_type_t type, const char *format, va_list args)
{
    char **str_to_edit = NULL;
    int rc = SR_ERR_OK;

    str_to_edit = sr_val_str_data_ptr(value, type);
    if (NULL == str_to_edit) {
        return SR_ERR_INVAL_ARG;
    }
    value->type = type;

    rc = sr_mem_edit_string_va(str_to_edit, format, args);

    return rc;
}

API int
sr_val_build_str_data(sr_val_t *value, sr_type_t type, const char *format, ...)
{
    va_list arg_list;
    int rc = SR_ERR_OK;

    va_start(arg_list, format);
    rc = sr_val_build_str_data_va(value, type, format, arg_list);
    va_end(arg_list);

    return rc;
}

API int
sr_dup_val_data(sr_val_t *dest, const sr_val_t *source)
{
    int rc = SR_ERR_OK;

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
            dest->data = source->data;
            dest->type = source->type;
            break;
        default:
            dest->type = source->type;
            break;
    }

    return rc;
}

API int
sr_dup_val(const sr_val_t *value, sr_val_t **value_dup_p)
{
    int rc = SR_ERR_OK;
    sr_val_t *val_dup = NULL;

    rc = sr_new_val(value->xpath, &val_dup);
    if (rc) {
        goto cleanup;
    }

    rc = sr_dup_val_data(val_dup, value);
    if (rc) {
        goto cleanup;
    }

    *value_dup_p = val_dup;

cleanup:
    if (SR_ERR_OK != rc) {
        sr_free_val(val_dup);
    }

    return rc;
}

API int
sr_dup_values(const sr_val_t *values, size_t count, sr_val_t **values_dup_p)
{
    int rc = SR_ERR_OK;
    sr_val_t *values_dup = NULL;

    rc = sr_new_values(count, &values_dup);
    if (rc) {
        goto cleanup;
    }

    for (size_t i = 0; i < count; ++i) {
        rc = sr_val_set_xpath(values_dup + i, values[i].xpath);
        if (rc) {
            goto cleanup;
        }
        rc = sr_dup_val_data(values_dup + i, values + i);
        if (rc) {
            goto cleanup;
        }
    }

    *values_dup_p = values_dup;

cleanup:
    if (SR_ERR_OK != rc) {
        sr_free_values(values_dup, count);
    }

    return rc;
}

static int
sr_print(sr_print_ctx_t *print_ctx, const char *format, ...)
{
    int rc = SR_ERR_OK, count = 0, len = 0;
    char *str = NULL, *aux = NULL;
    size_t new_size;
    va_list va;

    va_start(va, format);

    switch (print_ctx->type) {
        case SR_PRINT_FD:
            count = vdprintf(print_ctx->method.fd, format, va);
            if (count == -1) {
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            break;
        case SR_PRINT_STREAM:
            count = vfprintf(print_ctx->method.stream, format, va);
            if (count == -1) {
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            break;
        case SR_PRINT_MEM:
            /* print string to a temporary memory buffer */
            len = vsnprintf(NULL, 0, format, va);
            str = calloc(len+1, sizeof *str);
            if (!str) {
                rc = SR_ERR_NOMEM;
                goto cleanup;
            }
            va_end(va); /**< restart va_list */
            va_start(va, format);
            count = vsnprintf(str, len+1, format, va);
            if (count == -1) {
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            /* append the string to already printed data */
            if (print_ctx->method.mem.len + count + 1 > print_ctx->method.mem.size) {
                new_size = MAX(2 * print_ctx->method.mem.size, print_ctx->method.mem.len + count + 1);
                aux = realloc(print_ctx->method.mem.buf, new_size * sizeof *aux);
                if (!aux) {
                    rc = SR_ERR_NOMEM;
                    goto cleanup;
                }
                print_ctx->method.mem.buf = aux;
                print_ctx->method.mem.size = new_size;
            }
            strcpy(print_ctx->method.mem.buf + print_ctx->method.mem.len, str);
            print_ctx->method.mem.len += count;
            break;
    }

cleanup:
    free(str);
    va_end(va);
    return rc;
}

static int
sr_print_val_ctx(sr_print_ctx_t *print_ctx, const sr_val_t *value)
{
    int rc = SR_ERR_OK;

    if (NULL == value) {
        return rc;
    }

    rc = sr_print(print_ctx, "%s ", value->xpath);
    if (rc) {
        return rc;
    }

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

    return rc;
}

API int
sr_print_val(const sr_val_t *value)
{
    sr_print_ctx_t print_ctx = { 0, };

    print_ctx.type = SR_PRINT_STREAM;
    print_ctx.method.stream = stdout;

    return sr_print_val_ctx(&print_ctx, value);
}

API int
sr_print_val_fd(int fd, const sr_val_t *value)
{
    sr_print_ctx_t print_ctx = { 0, };

    print_ctx.type = SR_PRINT_FD;
    print_ctx.method.fd = fd;

    return sr_print_val_ctx(&print_ctx, value);
}

API int
sr_print_val_stream(FILE *stream, const sr_val_t *value)
{
    sr_print_ctx_t print_ctx = { 0, };

    print_ctx.type = SR_PRINT_STREAM;
    print_ctx.method.stream = stream;

    return sr_print_val_ctx(&print_ctx, value);
}

API int
sr_print_val_mem(char **mem_p, const sr_val_t *value)
{
    int rc = SR_ERR_OK;
    sr_print_ctx_t print_ctx = { 0, };

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

static int
sr_vasprintf(char **strp, const char *fmt, va_list ap)
{
    int ret = 0;
    va_list ap1;
    size_t size;
    char *buffer;

    /* get the size of the resulting string */
    va_copy(ap1, ap);
    size = vsnprintf(NULL, 0, fmt, ap1) + 1;
    va_end(ap1);

    /* allocate memory for the string */
    buffer = calloc(size, sizeof *buffer);
    if (!buffer) {
        return SR_ERR_NOMEM;
    }

    /* print */
    ret = vsnprintf(buffer, size, fmt, ap);
    if (ret >= 0) {
        *strp = buffer;
        return SR_ERR_OK;
    } else {
        free(buffer);
        return SR_ERR_INTERNAL;
    }
}

static int
sr_asprintf(char **strp, const char *fmt, ...)
{
    int rc = SR_ERR_OK;
    va_list ap;

    va_start(ap, fmt);
    rc = sr_vasprintf(strp, fmt, ap);
    va_end(ap);

    return rc;
}

API char *
sr_val_to_str(const sr_val_t *value)
{
    char *out = NULL;

    if (NULL != value) {
        switch (value->type) {
        case SR_BINARY_T:
            if (NULL != value->data.binary_val) {
                out = strdup(value->data.binary_val);
                if (!out) {
                    goto cleanup;
                }
            }
            break;
        case SR_BITS_T:
            if (NULL != value->data.bits_val) {
                out = strdup(value->data.bits_val);
                if (!out) {
                    goto cleanup;
                }
            }
            break;
        case SR_BOOL_T:
            out = value->data.bool_val ? strdup("true") : strdup("false");
            if (!out) {
                goto cleanup;
            }
            break;
        case SR_DECIMAL64_T:
            sr_asprintf(&out, "%g", value->data.decimal64_val);
            break;
        case SR_ENUM_T:
            if (NULL != value->data.enum_val) {
                out = strdup(value->data.enum_val);
                if (!out) {
                    goto cleanup;
                }
            }
            break;
        case SR_LIST_T:
        case SR_CONTAINER_T:
        case SR_CONTAINER_PRESENCE_T:
        case SR_LEAF_EMPTY_T:
            out = strdup("");
            if (!out) {
                goto cleanup;
            }
            break;
        case SR_IDENTITYREF_T:
            if (NULL != value->data.identityref_val) {
                out = strdup(value->data.identityref_val);
                if (!out) {
                    goto cleanup;
                }
            }
            break;
        case SR_INSTANCEID_T:
            if (NULL != value->data.instanceid_val) {
                out = strdup(value->data.instanceid_val);
                if (!out) {
                    goto cleanup;
                }
            }
            break;
        case SR_INT8_T:
            sr_asprintf(&out, "%"PRId8, value->data.int8_val);
            break;
        case SR_INT16_T:
            sr_asprintf(&out, "%"PRId16, value->data.int16_val);
            break;
        case SR_INT32_T:
            sr_asprintf(&out, "%"PRId32, value->data.int32_val);
            break;
        case SR_INT64_T:
            sr_asprintf(&out, "%"PRId64, value->data.int64_val);
            break;
        case SR_STRING_T:
            if (NULL != value->data.string_val){
                out = strdup(value->data.string_val);
                if (!out) {
                    goto cleanup;
                }
            }
            break;
        case SR_UINT8_T:
            sr_asprintf(&out, "%"PRIu8, value->data.uint8_val);
            break;
        case SR_UINT16_T:
            sr_asprintf(&out, "%"PRIu16, value->data.uint16_val);
            break;
        case SR_UINT32_T:
            sr_asprintf(&out, "%"PRIu32, value->data.uint32_val);
            break;
        case SR_UINT64_T:
            sr_asprintf(&out, "%"PRIu64, value->data.uint64_val);
            break;
        case SR_ANYXML_T:
            if (NULL != value->data.anyxml_val){
                out = strdup(value->data.anyxml_val);
                if (!out) {
                    goto cleanup;
                }
            }
            break;
        case SR_ANYDATA_T:
            if (NULL != value->data.anydata_val){
                out = strdup(value->data.anydata_val);
                if (!out) {
                    goto cleanup;
                }
            }
            break;
        default:
            break;
        }
    }
cleanup:
    return out;
}

API int
sr_val_to_buff(const sr_val_t *value, char buffer[], size_t size)
{
    size_t len = 0;

    if (NULL == value) {
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
        break;
    }

    return len;
}

API int
sr_tree_to_val(const struct lyd_node *data, const char *path, sr_val_t **value)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set = NULL;

    SR_CHECK_ARG_APIRET(!data || (data->schema->nodetype & (LYS_RPC | LYS_ACTION)) || !path || !value, NULL, err_info);

    *value = NULL;

    if (lyd_find_xpath(data, path, &set)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(data));
        goto cleanup;
    } else if (!set->count) {
        /* Not building err_info to avoid error logs when no item found */
        ly_set_free(set, NULL);
        return SR_ERR_NOT_FOUND;
    } else if (set->count > 1) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "More subtrees match \"%s\".", path);
        goto cleanup;
    }

    /* create return value */
    *value = malloc(sizeof **value);
    SR_CHECK_MEM_GOTO(!*value, err_info, cleanup);

    if ((err_info = sr_val_ly2sr(set->dnodes[0], *value))) {
        goto cleanup;
    }

    /* success */
cleanup:
    ly_set_free(set, NULL);
    return sr_api_ret(NULL, err_info);
}

API int
sr_tree_to_values(const struct lyd_node *data, const char *xpath, sr_val_t **values, size_t *value_cnt)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set = NULL;
    uint32_t i;

    SR_CHECK_ARG_APIRET(!data || !xpath || !values || !value_cnt, NULL, err_info);

    *values = NULL;
    *value_cnt = 0;

    if (lyd_find_xpath(data, xpath, &set)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(data));
        goto cleanup;
    } else if (!set->count) {
        /* Not building err_info to avoid error logs when no item found */
        ly_set_free(set, NULL);
        return SR_ERR_NOT_FOUND;
    } else {
        *values = calloc(set->count, sizeof **values);
        SR_CHECK_MEM_GOTO(!*values, err_info, cleanup);

        for (i = 0; i < set->count; ++i) {
            if (set->dnodes[i]->schema->nodetype & (LYS_RPC | LYS_ACTION)) {
                continue;
            }

            if ((err_info = sr_val_ly2sr(set->dnodes[i], *values + *value_cnt))) {
                goto cleanup;
            }
            ++(*value_cnt);
        }
    }

    /* success */
cleanup:
    ly_set_free(set, NULL);
    if (err_info) {
        sr_free_values(*values, *value_cnt);
        *values = NULL;
        *value_cnt = 0;
    }
    return sr_api_ret(NULL, err_info);
}
