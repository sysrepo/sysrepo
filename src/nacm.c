/**
 * @file nacm.c
 * @author Milan Lenco <milan.lenco@pantheon.tech>
 * @brief NETCONF Access Control Model implementation (RFC 6536).
 *
 * @copyright
 * Copyright 2016 Pantheon Technologies, s.r.o.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libyang/libyang.h>

#include "nacm.h"

#define NACM_MODULE_NAME    "ietf-netconf-acm"

/* Forward declaration */
static int nacm_cleanup_internal(nacm_ctx_t *nacm_ctx, bool config_only);

static int
nacm_load_config(nacm_ctx_t *nacm_ctx, dm_schema_info_t *schema_info, const sr_datastore_t ds)
{
    int rc = SR_ERR_OK;
    int fd = 0;
    char *ds_filepath = NULL;
    struct lyd_node *data_tree = NULL;
    CHECK_NULL_ARG(nacm_ctx);

    rc = sr_get_data_file_name(nacm_ctx->data_search_dir, NACM_MODULE_NAME, SR_DS_STARTUP, &ds_filepath);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to get the file-path of NACM startup datastore.");
    fd = open(ds_filepath, O_RDONLY);
    CHECK_NOT_MINUS1_LOG_GOTO(fd, rc, SR_ERR_IO, cleanup, "Unable to open the NACM startup datastore ('%s'): %s.",
                              ds_filepath, sr_strerror_safe(errno));
    ly_errno = 0;
    data_tree = lyd_parse_fd(schema_info->ly_ctx, fd, LYD_XML, LYD_OPT_TRUSTED | LYD_OPT_CONFIG);
    if (NULL == data_tree && LY_SUCCESS != ly_errno) {
        SR_LOG_ERR("Parsing of data tree from file %s failed: %s", ds_filepath, ly_errmsg());
        goto cleanup;
    }

    /* TODO: load configuration */
    lyd_print_fd(STDOUT_FILENO, data_tree, LYD_XML, LYP_WITHSIBLINGS | LYP_FORMAT);

cleanup:
    free(ds_filepath);
    if (NULL != data_tree) {
        lyd_free_withsiblings(data_tree);
    }
    return rc;
}

int
nacm_init(dm_ctx_t *dm_ctx, const char *data_search_dir, nacm_ctx_t **nacm_ctx)
{
    int rc = SR_ERR_OK;
    struct lys_node *iter = NULL;
    nacm_ctx_t *ctx = NULL;

    CHECK_NULL_ARG3(dm_ctx, data_search_dir, nacm_ctx);

    SR_LOG_INF_MSG("Initializing NACM.");

    /* allocate context data structure */
    ctx = calloc(1, sizeof *ctx);
    CHECK_NULL_NOMEM_GOTO(ctx, rc, cleanup);

    /* initialize RW lock */
    rc = pthread_rwlock_init(&ctx->lock, NULL);
    CHECK_ZERO_MSG_GOTO(rc, rc, SR_ERR_INTERNAL, cleanup, "RW-lock initialization failed");

    /* copy input arguments */
    ctx->dm_ctx = dm_ctx;
    ctx->data_search_dir = strdup(data_search_dir);
    CHECK_NULL_NOMEM_GOTO(ctx->data_search_dir, rc, cleanup);

    /* get the NACM module schema from data manager */
    rc = dm_get_module_and_lockw(ctx->dm_ctx, NACM_MODULE_NAME, &ctx->schema_info);
    if (SR_ERR_OK != rc || NULL == ctx->schema_info->module) {
        ctx->schema_info = NULL;
        SR_LOG_ERR_MSG("Failed to load NACM module schema.");
        goto cleanup;
    }

    /* increase the schema usage count to prevent the uninstallation */
    pthread_mutex_lock(&ctx->schema_info->usage_count_mutex);
    ctx->schema_info->usage_count++;
    pthread_mutex_unlock(&ctx->schema_info->usage_count_mutex);

    /* load the NACM configuration from startup datastore */
    rc = nacm_load_config(ctx, ctx->schema_info, SR_DS_STARTUP);
    if (SR_ERR_OK != rc) {
        goto unlock;
    }
    SR_LOG_INF_MSG("NACM configuration was loaded from the startup datastore.");

    /* enable module in the running datastore */
    LY_TREE_FOR(ctx->schema_info->module->data, iter)
    {
        if ((LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST) & iter->nodetype) {
            rc = dm_set_node_state(iter, DM_NODE_ENABLED_WITH_CHILDREN);
            CHECK_RC_MSG_GOTO(rc, unlock, "Failed to enable NACM in the running datastore.");
        }
    }

unlock:
    pthread_rwlock_unlock(&ctx->schema_info->model_lock);

    if (SR_ERR_OK == rc) {
        /* copy startup to running */
        rc = dm_copy_module(ctx->dm_ctx, NULL, NACM_MODULE_NAME, SR_DS_STARTUP, SR_DS_RUNNING, NULL);
    }

cleanup:
    if (SR_ERR_OK != rc) {
        if (NULL != ctx) {
            nacm_cleanup_internal(ctx, false);
        }
        *nacm_ctx = NULL;
    } else {
        *nacm_ctx = ctx;
    }
    return rc;
}

int
nacm_reload(nacm_ctx_t *nacm_ctx)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_ARG(nacm_ctx);

    pthread_rwlock_wrlock(&nacm_ctx->lock);

    rc = nacm_cleanup_internal(nacm_ctx, true);
    CHECK_RC_MSG_GOTO(rc, unlock, "Failed to clean the outdated NACM configuration.");

    rc = nacm_load_config(nacm_ctx, nacm_ctx->schema_info, SR_DS_RUNNING);
    CHECK_RC_MSG_GOTO(rc, unlock, "Failed to load NACM configuration from the running datastore.");

unlock:
    pthread_rwlock_unlock(&nacm_ctx->lock);
    return rc;
}

static int
nacm_cleanup_internal(nacm_ctx_t *nacm_ctx, bool config_only)
{
    int rc = SR_ERR_OK;

    if (NULL == nacm_ctx) {
        return rc;
    }

    /* TODO: free configuration (groups, rule_lists) */

    if (config_only) {
        return rc;
    }

    pthread_rwlock_destroy(&nacm_ctx->lock);
    free(nacm_ctx->data_search_dir);

    if (NULL != nacm_ctx->schema_info) {
        /* decrease the NACM module schema usage count */
        pthread_mutex_lock(&nacm_ctx->schema_info->usage_count_mutex);
        nacm_ctx->schema_info->usage_count--;
        pthread_mutex_unlock(&nacm_ctx->schema_info->usage_count_mutex);
    }

    /* free the top-level structure */
    free(nacm_ctx);

    return rc;
}

int
nacm_cleanup(nacm_ctx_t *nacm_ctx)
{
    return nacm_cleanup_internal(nacm_ctx, false);
}
