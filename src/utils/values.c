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

#include "sr_common.h"
#include "sysrepo/values.h"
#include "values_internal.h"


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
        sr_mem->obj_count += 1;
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
        sr_mem->obj_count += 1; /* 1 for the entire array */
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
sr_val_set_xpath(sr_val_t *value, const char *xpath)
{
    CHECK_NULL_ARG2(value, xpath);
    return sr_mem_edit_string(value->_sr_mem, &value->xpath, xpath);
}

int
sr_val_set_string(sr_val_t *value, const char *string_val)
{
    char **to_edit = NULL;
    CHECK_NULL_ARG2(value, string_val);

    switch (value->type) {
        case SR_BINARY_T:
            to_edit = &value->data.binary_val;
            break;
        case SR_BITS_T:
            to_edit = &value->data.bits_val;
            break;
        case SR_ENUM_T:
            to_edit = &value->data.enum_val;
            break;
        case SR_IDENTITYREF_T:
            to_edit = &value->data.identityref_val;
            break;
        case SR_INSTANCEID_T:
            to_edit = &value->data.instanceid_val;
            break;
        case SR_STRING_T:
            to_edit = &value->data.string_val;
            break;
        default:
            return SR_ERR_INVAL_ARG;
    }

    return sr_mem_edit_string(value->_sr_mem, to_edit, string_val);
}

int
sr_dup_val_data(sr_val_t *dest, sr_val_t *source)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_ARG2(source, dest);

    dest->dflt = source->dflt;
    dest->type = source->type;

    switch (source->type) {
        case SR_BINARY_T:
            rc = sr_val_set_string(dest, source->data.binary_val);
            break;
        case SR_BITS_T:
            rc = sr_val_set_string(dest, source->data.bits_val);
            break;
        case SR_ENUM_T:
            rc = sr_val_set_string(dest, source->data.enum_val);
            break;
        case SR_IDENTITYREF_T:
            rc = sr_val_set_string(dest, source->data.identityref_val);
            break;
        case SR_INSTANCEID_T:
            rc = sr_val_set_string(dest, source->data.instanceid_val);
            break;
        case SR_STRING_T:
            rc = sr_val_set_string(dest, source->data.string_val);
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
        default:
            break;
    }

    return rc;
}

int
sr_dup_val_ctx(sr_val_t *value, sr_mem_ctx_t *sr_mem_dest, sr_val_t **value_dup_p)
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
sr_dup_val(sr_val_t *value, sr_val_t **value_dup_p)
{
    return sr_dup_val_ctx(value, NULL, value_dup_p);
}

int
sr_dup_values_ctx(sr_val_t *values, size_t count, sr_mem_ctx_t *sr_mem_dest, sr_val_t **values_dup_p)
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
sr_dup_values(sr_val_t *values, size_t count, sr_val_t **values_dup_p)
{
    return sr_dup_values_ctx(values, count, NULL, values_dup_p);
}

