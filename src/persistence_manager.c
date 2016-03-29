/**
 * @file persistence_manager.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief TODO
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

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <pthread.h>
#include <libyang/libyang.h>

#include "sr_common.h"
#include "persistence_manager.h"

#define PM_SCHEMA_FILE "sysrepo-persistent-data.yin"

/**
 * TODO
 */
typedef struct pm_ctx_s {
    struct ly_ctx *ly_ctx;  /**< libyang context holding all loaded schemas */
} pm_ctx_t;

int
pm_init(const char *schema_search_dir, pm_ctx_t **pm_ctx)
{
    pm_ctx_t *ctx = NULL;
    char *schema_filename = NULL;
    const struct lys_module *module = NULL;
    int rc = SR_ERR_OK;

    ctx = calloc(1, sizeof(*ctx));
    CHECK_NULL_NOMEM_GOTO(ctx, rc, cleanup);

    ctx->ly_ctx = ly_ctx_new(schema_search_dir);
    CHECK_NULL_NOMEM_GOTO(ctx->ly_ctx, rc, cleanup);

    rc = sr_str_join(schema_search_dir, PM_SCHEMA_FILE, &schema_filename);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    module = lys_parse_path(ctx->ly_ctx, schema_filename, LYS_IN_YIN);
    free(schema_filename);
    if (module == NULL) {
        SR_LOG_WRN("Unable to parse the schema file '%s': %s", PM_SCHEMA_FILE, ly_errmsg());
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    *pm_ctx = ctx;
    return SR_ERR_OK;

cleanup:
    pm_cleanup(ctx);
    return rc;
}

void
pm_cleanup(pm_ctx_t *pm_ctx)
{
    if (NULL != pm_ctx) {
        if (NULL != pm_ctx->ly_ctx) {
            ly_ctx_destroy(pm_ctx->ly_ctx, NULL);
        }
        free(pm_ctx);
    }
}
