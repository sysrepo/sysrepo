/**
 * @file sr_common.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo common utilities.
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
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>

#include "sr_common.h"

/**
 * Sysrepo error descriptions.
 */
const char *const sr_errlist[] = {
        "Operation succeeded",                  /* SR_ERR_OK */
        "Invalid argument",                     /* SR_ERR_INVAL_ARG */
        "Out of memory",                        /* SR_ERR_NOMEM */
        "Item not found",                       /* SR_ERR_NOT_FOUND */
        "Sysrepo-internal error",               /* SR_ERR_INTERNAL */
        "Initialization failed",                /* SR_ERR_INIT_FAILED */
        "Input/output error",                   /* SR_ERR_IO */
        "The peer disconnected",                /* SR_ERR_DISCONNECT */
        "Malformed message",                    /* SR_ERR_MALFORMED_MSG */
        "Operation not supported",              /* SR_ERR_UNSUPPORTED */
        "Requested schema model is not known",  /* SR_ERR_UNKNOWN_MODEL */
        "Request contains unknown element",     /* SR_ERR_BAD_ELEMENT */
        "Validation of the changes failed",     /* SR_ERR_VALIDATION_FAILED */
        "The operation failed",                 /* SR_ERR_OPERATION_FAILED */
        "The item already exists",              /* SR_ERR_DATA_EXISTS */
        "The item expected to exist is missing",/* SR_ERR_DATA_MISSING */
        "Operation not authorized",             /* SR_ERR_UNAUTHORIZED */
        "Invalid username",                     /* SR_ERR_INVAL_USER */
        "Requested resource is already locked", /* SR_ERR_LOCKED */
        "Timeout has expired",                  /* SR_ERR_TIME_OUT */
        "Sysrepo Engine restart is needed",     /* SR_ERR_RESTART_NEEDED */
        "Sysrepo client library versions are not compatible",  /* SR_ERR_VERSION_MISMATCH */
};

const char *
sr_strerror(int err_code)
{
    if (err_code >= (sizeof(sr_errlist) / (sizeof *sr_errlist))) {
        return "Unknown error";
    } else {
        return sr_errlist[err_code];
    }
}

void
sr_free_val(sr_val_t *value)
{
    if (NULL != value) {
        if (NULL != value->_sr_mem) {
            if (0 == --value->_sr_mem->obj_count) {
                sr_mem_free(value->_sr_mem);
            }
        } else {
            sr_free_val_content(value);
            free(value);
        }
    }
}

void
sr_free_values(sr_val_t *values, size_t count)
{
    if (NULL != values) {
        if (values[0]._sr_mem) {
            if (0 == --values[0]._sr_mem->obj_count) {
                sr_mem_free(values[0]._sr_mem);
            }
        } else {
            for (size_t i = 0; i < count; i++) {
                sr_free_val_content(&values[i]);
            }
            free(values);
        }
    }
}

void
sr_free_schemas(sr_schema_t *schemas, size_t count)
{
    if (NULL != schemas) {
        if (schemas[0]._sr_mem) {
            if (0 == --schemas[0]._sr_mem->obj_count) {
                sr_mem_free(schemas[0]._sr_mem);
            }
            return;
        } else {
            for (size_t i = 0; i < count; i++) {
                sr_free_schema(&schemas[i]);
            }
            free(schemas);
        }
    }
}

void
sr_free_tree(sr_node_t *tree)
{
    if (NULL != tree) {
        if (NULL != tree->_sr_mem) {
            if (0 == --tree->_sr_mem->obj_count) {
                sr_mem_free(tree->_sr_mem);
            }
        } else {
            if (SR_TREE_ITERATOR_T == tree->type) {
                --tree->data.int32_val;
                if (0 < tree->data.int32_val) {
                    /* still used */
                    return;
                }
            }
            sr_free_tree_content(tree);
            free(tree);
        }
    }
}

void
sr_free_trees(sr_node_t *trees, size_t count)
{
    if (NULL != trees) {
        if (NULL != trees[0]._sr_mem) {
            if (0 == --trees[0]._sr_mem->obj_count) {
                sr_mem_free(trees[0]._sr_mem);
            }
        } else {
            for (size_t i = 0; i < count; i++) {
                sr_free_tree_content(trees + i);
            }
            free(trees);
        }
    }
}
