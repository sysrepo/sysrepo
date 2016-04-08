/**
 * @file persistence_manager.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo's Persistence Manager implementation.
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

#define PM_SCHEMA_FILE            "sysrepo-persistent-data.yin"

#define PM_MODULE_NODE_NAME       "module"
#define PM_MODULE_NAME_NODE_NAME  "module-name"
#define PM_FEATURE_NODE_NAME      "enabled-features"

/**
 * @brief Persistence Manager context.
 */
typedef struct pm_ctx_s {
    ac_ctx_t *ac_ctx;                 /**< Access Control module context. */
    struct ly_ctx *ly_ctx;            /**< libyang context used locally in PM. */
    const struct lys_module *schema;  /**< Schema tree of sysrepo-persistent-data YANG. */
    const char *data_search_dir;      /**< Directory containing the data files. */
} pm_ctx_t;

/**
 * @brief Saves the data tree into the file specified by file descriptor.
 */
static int
pm_save_data_tree(pm_ctx_t *pm_ctx, int fd, struct lyd_node *data_tree)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(pm_ctx, data_tree);

    /* empty file content */
    ftruncate(fd, 0);

    /* print data tree to file */
    rc = lyd_print_fd(fd, data_tree, LYD_XML, LYP_WITHSIBLINGS | LYP_FORMAT);
    if (0 != rc) {
        SR_LOG_ERR("Saving persist data tree failed: %s", ly_errmsg());
        rc = SR_ERR_INTERNAL;
    } else {
        SR_LOG_DBG_MSG("Persist data tree successfully saved.");
        rc = SR_ERR_OK;
    }

    return rc;
}

/**
 * @brief Creates a new data tree of persistent data tied to specified YANG module.
 */
static int
pm_create_data_tree(pm_ctx_t *pm_ctx, const char *module_name, struct lyd_node **data_tree)
{
    struct lyd_node *root_node = NULL, *new_node = NULL;

    CHECK_NULL_ARG3(pm_ctx, module_name, data_tree);

    SR_LOG_DBG("Creating new persist data tree for module '%s'.", module_name);

    /* set initial content */
    root_node = lyd_new(NULL, pm_ctx->schema, PM_MODULE_NODE_NAME);
    if (NULL == root_node) {
        SR_LOG_ERR("Unable to create a new 'module' node in persist data tree for '%s'.", module_name);
        return SR_ERR_INTERNAL;
    }
    new_node = lyd_new_leaf(root_node, pm_ctx->schema, PM_MODULE_NAME_NODE_NAME, module_name);
    if (NULL == new_node) {
        SR_LOG_ERR("Unable to create a new 'module-name' node in persist data tree for '%s'.", module_name);
        lyd_free(root_node);
        return SR_ERR_INTERNAL;
    }

    *data_tree = root_node;
    return SR_ERR_OK;
}

/**
 * @brief Loads the data tree of persistent data file tied to specified YANG module.
 */
static int
pm_load_data_tree(pm_ctx_t *pm_ctx, const ac_ucred_t *user_cred, const char *module_name,  const char *data_filename,
        bool read_only, int *fd_p, struct lyd_node **data_tree)
{
    int fd = -1;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(pm_ctx, data_filename, data_tree);

    /* open the file as the proper user */
    if (NULL != user_cred) {
        ac_set_user_identity(pm_ctx->ac_ctx, user_cred);
    }

    fd = open(data_filename, (read_only ? O_RDONLY : O_RDWR));

    if (NULL != user_cred) {
        ac_unset_user_identity(pm_ctx->ac_ctx);
    }

    if (-1 == fd) {
        /* error by open */
        if (ENOENT == errno) {
            SR_LOG_DBG("Persist data file '%s' does not exist.", data_filename);
            if (read_only) {
                rc = SR_ERR_DATA_MISSING;
            } else {
                /* create the data tree */
                rc = pm_create_data_tree(pm_ctx, module_name, data_tree);
                if (SR_ERR_OK == rc) {
                    /* create the file */
                    ac_set_user_identity(pm_ctx->ac_ctx, user_cred);
                    fd = open(data_filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
                    ac_unset_user_identity(pm_ctx->ac_ctx);
                    if (-1 == fd) {
                        SR_LOG_ERR("Unable to create new persist data file '%s': %s", data_filename, strerror(errno));
                        lyd_free_withsiblings(*data_tree);
                        rc = SR_ERR_INTERNAL;
                    }
                }
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

    /* lock & load the data tree */
    sr_lock_fd(fd, (read_only ? false : true), true);

    if (NULL == *data_tree) {
        *data_tree = lyd_parse_fd(pm_ctx->ly_ctx, fd, LYD_XML, LYD_OPT_STRICT | LYD_OPT_CONFIG);
        if (NULL == *data_tree && LY_SUCCESS != ly_errno) {
            SR_LOG_ERR("Parsing persist data from file '%s' failed: %s", data_filename, ly_errmsg());
            rc = SR_ERR_INTERNAL;
        } else {
            SR_LOG_DBG("Persist data successfully loaded from file '%s'.", data_filename);
        }
    }

    if (read_only || NULL == fd_p) {
        /* unlock and close fd in case of read_only has been requested */
        sr_unlock_fd(fd);
        close(fd);
    } else {
        /* return open fd to locked file otherwise */
        *fd_p = fd;
    }

    return rc;
}

/**
 * @brief Logging callback called from libyang for each log entry.
 */
static void
pm_ly_log_cb(LY_LOG_LEVEL level, const char *msg, const char *path)
{
    if (LY_LLERR == level) {
        SR_LOG_DBG("libyang error: %s", msg);
    }
}

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

    /* initialize libyang */
    ctx->ly_ctx = ly_ctx_new(schema_search_dir);
    if (NULL == ctx->ly_ctx) {
        SR_LOG_ERR("libyang initialization failed: %s", ly_errmsg());
        rc = SR_ERR_INIT_FAILED;
        goto cleanup;
    }

    ly_set_log_clb(pm_ly_log_cb, 0);

    rc = sr_str_join(schema_search_dir, PM_SCHEMA_FILE, &schema_filename);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    /* load persist files schema to context */
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

int
pm_feature_enable(pm_ctx_t *pm_ctx, const ac_ucred_t *user_cred, const char *module_name,
        const char *feature_name, bool enable)
{
    char *data_filename = NULL;
    struct lyd_node *data_tree = NULL, *new_node = NULL, *curr = NULL;
    int fd = -1;
    bool skip = false;
    int rc = SR_ERR_OK, ret = 0;

    /* get persist file path */
    rc = sr_get_persist_data_file_name(pm_ctx->data_search_dir, module_name, &data_filename);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Unable to compose persist data file name for '%s'.", module_name);
        return rc;
    }

    /* load the data tree from persist file */
    rc = pm_load_data_tree(pm_ctx, user_cred, module_name, data_filename, false, &fd, &data_tree);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Unable to load persist data tree for module '%s'.", module_name);
        goto cleanup;
    }

    if (NULL == data_tree) {
        /* create the data tree if it's NULL */
        rc = pm_create_data_tree(pm_ctx, module_name, &data_tree);
        if (SR_ERR_OK != rc) {
            goto cleanup;
        }
    }
    curr = data_tree->child;

    /* find matching feature node (if exists) */
    while (curr != NULL) {
        if ((NULL != curr->schema) && (NULL != curr->schema->name) &&
                (0 == strcmp(PM_FEATURE_NODE_NAME, curr->schema->name))) {
            /* this is a feature leaf-list node */
            struct lyd_node_leaf_list *data_leaf = (struct lyd_node_leaf_list *)curr;
            if ((NULL != data_leaf) && (NULL != data_leaf->value.string) &&
                    (0 == strcmp(data_leaf->value.string, feature_name))) {
                /* feature name matches */
                if (enable) {
                    SR_LOG_DBG("Feature '%s' already enabled in '%s' persist file.", feature_name, module_name);
                    skip = true;
                }
                break;
            }
        }
        curr = curr->next;
    }

    if (!skip) {
        if (enable) {
            /* enable the feature */
            new_node = lyd_new_leaf(data_tree, pm_ctx->schema, PM_FEATURE_NODE_NAME, feature_name);
            if (NULL == new_node) {
                SR_LOG_ERR("Unable to create a new feature node in persist data tree for '%s'.", module_name);
                rc = SR_ERR_INTERNAL;
            } else {
                SR_LOG_DBG("Feature '%s' successfully enabled in '%s' persist file.", feature_name, module_name);
            }
        } else {
            /* disable the feature */
            if (NULL == curr) {
                SR_LOG_DBG("Feature '%s' already disabled in '%s' persist file.", feature_name, module_name);
                skip = true;
            } else {
                ret = lyd_unlink(curr);
                if (0 != ret) {
                    SR_LOG_ERR("Unable to unlink the feature node in persist data tree for '%s'.", module_name);
                    rc = SR_ERR_INTERNAL;
                } else {
                    lyd_free(curr);
                    SR_LOG_DBG("Feature '%s' successfully disabled in '%s' persist file.", feature_name, module_name);
                }
            }
        }
        /* save the changes */
        if (!skip) {
            rc = pm_save_data_tree(pm_ctx, fd, data_tree);
        }
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
pm_get_features(pm_ctx_t *pm_ctx, const char *module_name, char ***features_p, size_t *feature_cnt_p)
{
    char *data_filename = NULL;
    struct lyd_node *data_tree = NULL, *curr = NULL;
    char **features = NULL, **tmp = NULL;
    size_t feature_cnt = 0;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(pm_ctx, module_name, features_p, feature_cnt_p);

    /* get persist file path */
    rc = sr_get_persist_data_file_name(pm_ctx->data_search_dir, module_name, &data_filename);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Unable to compose persist data file name for '%s'.", module_name);
        return rc;
    }

    /* load the data tree from persist file */
    rc = pm_load_data_tree(pm_ctx, NULL, module_name, data_filename, true, NULL, &data_tree);
    if (SR_ERR_OK != rc) {
        SR_LOG_WRN("Unable to load persist data tree for module '%s'.", module_name);
        goto cleanup;
    }

    if (NULL == data_tree) {
        /* empty data file */
        *features_p = NULL;
        *feature_cnt_p = 0;
        goto cleanup;
    }

    curr = data_tree->child;

    /* find feature nodes (if exist) */
    while (curr != NULL) {
        if ((NULL != curr->schema) && (NULL != curr->schema->name) &&
                (0 == strcmp(PM_FEATURE_NODE_NAME, curr->schema->name))) {
            /* this is a feature leaf-list node */
            struct lyd_node_leaf_list *data_leaf = (struct lyd_node_leaf_list *)curr;
            if ((NULL != data_leaf) && (NULL != data_leaf->value.string)) {
                tmp = realloc(features, (feature_cnt + 1) * sizeof(*features));
                CHECK_NULL_NOMEM_GOTO(tmp, rc, cleanup);
                features = tmp;
                features[feature_cnt] = strdup(data_leaf->value.string);
                CHECK_NULL_NOMEM_GOTO(features[feature_cnt], rc, cleanup);
                feature_cnt++;
            }
        }
        curr = curr->next;
    }

    SR_LOG_DBG("Returning %zu features enabled in '%s' persist file.", feature_cnt, module_name);

    *features_p = features;
    *feature_cnt_p = feature_cnt;

cleanup:
    if (NULL != data_tree) {
        lyd_free_withsiblings(data_tree);
    }
    free(data_filename);

    if (SR_ERR_OK != rc) {
        free(features);
    }
    return rc;
}
