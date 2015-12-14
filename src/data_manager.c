/**
 * @file data_manager.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief 
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

#include "data_manager.h"
#include "sr_common.h"
#include <stdlib.h>
#include <libyang/libyang.h>

typedef struct dm_ctx_s{
    char *search_dir;
    struct ly_ctx *ly_ctx;
}dm_ctx_t;

typedef struct dm_session_s{
    struct lyd_node *modules;
    size_t modules_count;
}dm_session_t;

int dm_init(const char *search_dir, dm_ctx_t **dm_ctx){
    CHECK_NULL_ARG(dm_ctx);

    dm_ctx_t *ctx = NULL;
    ctx = malloc(sizeof(*ctx));
    if(ctx == NULL){
        SR_LOG_ERR_MSG("Cannot allocate memory for Data Manager.");
        return SR_ERR_NOMEM;
    }
    ctx->ly_ctx = ly_ctx_new(search_dir);
    if(ctx->ly_ctx == NULL){
        SR_LOG_ERR_MSG("Cannot allocate memory for libyang context in Data Manager.");
        free(ctx);
        return SR_ERR_NOMEM;
    }

    ctx->search_dir = strdup(search_dir);
    if(ctx->search_dir == NULL){
        SR_LOG_ERR_MSG("Cannot allocate memory for search_dir string in Data Manager.");
        ly_ctx_destroy(ctx->ly_ctx);
        free(ctx);
        return SR_ERR_NOMEM;
    }
    *dm_ctx = ctx;
    return SR_ERR_OK;
}

int dm_cleanup(dm_ctx_t *dm_ctx){
    CHECK_NULL_ARG(dm_ctx);

    free(dm_ctx->search_dir);
    ly_ctx_destroy(dm_ctx->ly_ctx);
    free(dm_ctx);
    return SR_ERR_OK;
}

int dm_session_start(const dm_ctx_t *dm_ctx, dm_session_t **dm_session_ctx){
    CHECK_NULL_ARG(dm_session_ctx);

    dm_session_t *session_ctx;
    session_ctx = malloc(sizeof(*session_ctx));
    if(session_ctx == NULL){
        SR_LOG_ERR_MSG("Cannot allocate session_ctx in Data Manager.");
        return SR_ERR_NOMEM;
    }
    session_ctx->modules = NULL;
    session_ctx->modules_count = 0;
    *dm_session_ctx = session_ctx;

    return SR_ERR_OK;
}

int dm_session_stop(const dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx){
    CHECK_NULL_ARG2(dm_ctx, dm_session_ctx);
    free(dm_session_ctx->modules);
    free(dm_session_ctx);
    return SR_ERR_OK;

}

int dm_get_datatree(const dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx, const char *module_name){
    return SR_ERR_OK;

}


