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
#include <unistd.h>
#include <inttypes.h>
#include <pthread.h>
#include <fcntl.h>
#include <libyang/libyang.h>

#include "sr_common.h"
#include "access_control.h"
#include "persistence_manager.h"

#define PM_SCHEMA_FILE "sysrepo-persistent-data.yin"

#define PM_MODULE_NODE_NAME       "module"
#define PM_MODULE_NAME_NODE_NAME  "module-name"
#define PM_FEATURE_NODE_NAME      "enabled-features"

/**
 * TODO
 */
typedef struct pm_ctx_s {
    ac_ctx_t *ac_ctx;                 /**< Access Control module context. */
    struct ly_ctx *ly_ctx;            /**< libyang context holding all loaded schemas. */
    const struct lys_module *schema;
    const char *data_search_dir;
} pm_ctx_t;

int
pm_init(ac_ctx_t *ac_ctx, const char *schema_search_dir, const char *data_search_dir, pm_ctx_t **pm_ctx)
{
    pm_ctx_t *ctx = NULL;
    char *schema_filename = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(ac_ctx, schema_search_dir, data_search_dir, pm_ctx);

    /* allocate and initialize the context */
    ctx = calloc(1, sizeof(*ctx));
    CHECK_NULL_NOMEM_GOTO(ctx, rc, cleanup);

    ctx->ac_ctx = ac_ctx;
    ctx->data_search_dir = strdup(data_search_dir);
    CHECK_NULL_NOMEM_GOTO(ctx->data_search_dir, rc, cleanup);

    /* initialize libyang and persist files schema */
    ctx->ly_ctx = ly_ctx_new(schema_search_dir);
    CHECK_NULL_NOMEM_GOTO(ctx->ly_ctx, rc, cleanup);

    rc = sr_str_join(schema_search_dir, PM_SCHEMA_FILE, &schema_filename);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    ctx->schema = lys_parse_path(ctx->ly_ctx, schema_filename, LYS_IN_YIN);
    free(schema_filename);
    if (ctx->schema == NULL) {
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
        free((void*)pm_ctx->data_search_dir);
        free(pm_ctx);
    }
}

/**
 * TODO
 */
static int
pm_save_data_tree(pm_ctx_t *pm_ctx, int fd, struct lyd_node *data_tree)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(pm_ctx, data_tree);

    /* empty file content */
    ftruncate(fd, 0);

    /* print data tree to file */
    rc = lyd_print_fd(fd, data_tree, LYD_XML_FORMAT, LYP_WITHSIBLINGS);
    if (0 != rc) {
        SR_LOG_ERR("Saving persist data tree failed: %s", ly_errmsg());
        rc = SR_ERR_INTERNAL;
    } else {
        SR_LOG_DBG_MSG("Persist data tree successfully saved.");
        rc = SR_ERR_OK;
    }

    return rc;
}

static int
pm_create_data_tree(pm_ctx_t *pm_ctx, const char *module_name, struct lyd_node **data_tree)
{
    struct lyd_node *root_node = NULL, *new_node = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(pm_ctx, module_name, data_tree);

    SR_LOG_DBG("Creating new persist data tree for module '%s'.", module_name);

    /* set initial content */
    root_node = lyd_new(NULL, pm_ctx->schema, PM_MODULE_NODE_NAME);
    if (NULL == root_node) {
        SR_LOG_ERR("Unable to create a new 'module' node in persist data tree for '%s'.", module_name);
        rc = SR_ERR_INTERNAL;
    }
    new_node = lyd_new_leaf(root_node, pm_ctx->schema, PM_MODULE_NAME_NODE_NAME, module_name);
    if (NULL == new_node) {
        SR_LOG_ERR("Unable to create a new 'module-name' node in persist data tree for '%s'.", module_name);
        rc = SR_ERR_INTERNAL;
    }

    *data_tree = root_node;
    // TODO: err checks
    return rc;
}

/**
 * TODO
 */
static int
pm_load_data_tree(pm_ctx_t *pm_ctx, ac_ucred_t *user_cred, const char *module_name,  const char *data_filename,
        bool read_only, int *fd_p, struct lyd_node **data_tree)
{
    int fd = -1;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(pm_ctx, user_cred, data_filename, data_tree);

    /* open the file as the proper user */
    ac_set_user_identity(pm_ctx->ac_ctx, user_cred);

    fd = open(data_filename, (read_only ? O_RDONLY : O_RDWR));

    ac_unset_user_identity(pm_ctx->ac_ctx);

    if (-1 == fd) {
        /* error by open */
        if (ENOENT == errno) {
            SR_LOG_DBG("Persist data file '%s' does not exist.", data_filename);
            if (read_only) {
                rc = SR_ERR_DATA_MISSING;
            } else {
                /* create the data tree */
                rc = pm_create_data_tree(pm_ctx, module_name, data_tree);
                /* create the file */
                ac_set_user_identity(pm_ctx->ac_ctx, user_cred);
                fd = open(data_filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
                ac_unset_user_identity(pm_ctx->ac_ctx);
            }
        } else if (EACCES == errno) {
            SR_LOG_ERR("Insufficient permissions to access persist data file '%s'.", data_filename);
            rc = SR_ERR_UNAUTHORIZED;
        } else {
            SR_LOG_ERR("Unable to open persist data file '%s': %s.", data_filename, strerror(errno));
            rc = SR_ERR_INTERNAL;
        }
        if (SR_ERR_OK != rc) {
            return rc;
        }
    }

    /* load the data tree */
    sr_lock_fd(fd, (read_only ? false : true), true);

    if (NULL == *data_tree) {
        *data_tree = lyd_parse_fd(pm_ctx->ly_ctx, fd, LYD_XML, LYD_OPT_STRICT | LYD_OPT_CONFIG);
        if (NULL == *data_tree) {
            SR_LOG_ERR("Parsing persist data from file '%s' failed: %s", data_filename, ly_errmsg());
            rc = SR_ERR_INTERNAL;
        } else {
            SR_LOG_DBG("Persist data successfully loaded from file '%s'.", data_filename);
        }
    }

    if (read_only || NULL == fd_p) {
        sr_unlock_fd(fd);
        close(fd);
    } else {
        *fd_p = fd;
    }

    return rc;
}

int
pm_feature_enable(pm_ctx_t *pm_ctx, ac_ucred_t *user_cred, const char *module_name, const char *feature_name, bool enable)
{
    char *data_filename = NULL;
    struct lyd_node *data_tree = NULL, *new_node = NULL;
    int fd = -1;
    bool skip = false;
    int rc = SR_ERR_OK;

    /* get persist file path */
    rc = sr_get_persist_data_file_name(pm_ctx->data_search_dir, module_name, &data_filename);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Unable to compose persist data file name for '%s'.", module_name);
        return rc;
    }

    /* load the data tree from persist file */
    rc = pm_load_data_tree(pm_ctx, user_cred, module_name, data_filename, false, &fd, &data_tree);
    if (SR_ERR_OK != rc || NULL == data_tree) {
        SR_LOG_ERR("Unable to load persist data tree for module '%s'.", module_name);
        goto cleanup;
    }

    struct lyd_node *curr = data_tree->child;

    while (curr != NULL) {
        /* check node name*/
        // TODO nullchecks
        if (0 == strcmp(PM_FEATURE_NODE_NAME, curr->schema->name)) {
            struct lyd_node_leaf_list *data_leaf = (struct lyd_node_leaf_list *)curr;
            if (0 == strcmp(feature_name, data_leaf->value.string)) {
                SR_LOG_DBG("Feature '%s' already enabled in '%s'.", feature_name, module_name);
                skip = true;
                break;
            }
        }
        curr = curr->next;
    }

    if (!skip) {
        // TODO: remove operation
        new_node = lyd_new_leaf(data_tree, pm_ctx->schema, PM_FEATURE_NODE_NAME, feature_name);
        if (NULL == new_node) {
            SR_LOG_ERR("Unable to create a new feature node in persist data tree for '%s'.", module_name);
            rc = SR_ERR_INTERNAL;
        }

        rc = pm_save_data_tree(pm_ctx, fd, data_tree);
    }

cleanup:
    if (NULL != data_tree) {
        lyd_free_withsiblings(data_tree);
    }
    free(data_filename);

    if (-1 != fd) {
        sr_unlock_fd(fd);
        close(fd);
    }

    return rc;
}

int
pm_get_features(pm_ctx_t *pm_ctx, ac_ucred_t *user_cred, const char *module_name, char *features, size_t feature_cnt)
{
    return SR_ERR_OK;
}
