/**
 * @file data_manager.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <pthread.h>
#include <fcntl.h>
#include <libyang/libyang.h>
#include <string.h>
#include <inttypes.h>

#include "data_manager.h"
#include "sr_common.h"
#include "rp_dt_xpath.h"
#include "rp_dt_get.h"
#include "access_control.h"
#include "notification_processor.h"
#include "persistence_manager.h"
#include "rp_dt_edit.h"
#include "module_dependencies.h"

/**
 * @brief Data manager context holding loaded schemas, data trees
 * and corresponding locks
 */
typedef struct dm_ctx_s {
    ac_ctx_t *ac_ctx;             /**< Access Control module context */
    np_ctx_t *np_ctx;             /**< Notification Processor context */
    pm_ctx_t *pm_ctx;             /**< Persistence Manager context */
    md_ctx_t *md_ctx;             /**< Module Dependencies context */
    cm_connection_mode_t conn_mode;  /**< Mode in which Connection Manager operates */
    char *schema_search_dir;      /**< location where schema files are located */
    char *data_search_dir;        /**< location where data files are located */
    sr_locking_set_t *locking_ctx;/**< lock context for lock/unlock/commit operations */
    bool *ds_lock;                /**< Flags if the ds lock is hold by a session*/
    pthread_mutex_t ds_lock_mutex;/**< Data store lock mutex */
    sr_btree_t *schema_info_tree; /**< Binary tree holding information about schemas */
    pthread_rwlock_t schema_tree_lock;  /**< rwlock for access schema_info_tree */
    dm_commit_ctxs_t commit_ctxs; /**< Structure holding commit contexts and corresponding lock */
    struct timespec last_commit_time;  /**< Time of the last commit */
} dm_ctx_t;

/**
 * @brief Structure that holds Data Manager's per-session context.
 */
typedef struct dm_session_s {
    dm_ctx_t *dm_ctx;                   /**< dm_ctx where the session belongs to */
    sr_datastore_t datastore;           /**< datastore to which the session is tied */
    const ac_ucred_t *user_credentials; /**< credentials of the user who this session belongs to */
    sr_btree_t **session_modules;       /**< array of binary trees holding session copies of data models for each datastore */
    dm_sess_op_t **operations;          /**< array of list of operations performed in this session */
    size_t *oper_count;                 /**< array of number of performed operation */
    size_t *oper_size;                  /**< array of number of allocated operations */
    char *error_msg;                    /**< description of the last error */
    char *error_xpath;                  /**< xpath of the last error if applicable */
    sr_list_t *locked_files;            /**< set of filename that are locked by this session */
    bool *holds_ds_lock;                /**< flags if the session holds ds lock*/
} dm_session_t;

/**
 * @brief Info structure for the node holds the state of the running data store.
 * (It will hold information about notification subscriptions.)
 */
typedef struct dm_node_info_s {
    dm_node_state_t state;
} dm_node_info_t;

/** @brief Invalid value for the commit context id, used for signaling e.g.: duplicate id */
#define DM_COMMIT_CTX_ID_INVALID 0
/** @brief Number of attempts to generate unique id for commit context */
#define DM_COMMIT_CTX_ID_MAX_ATTEMPTS 100

/**
 * @brief Minimal nanosecond difference between current time and modification timestamp.
 * To allow optimized commit - if timestamp of the file system file and session copy matches
 * overwrite the data file.
 *
 * If this constant were 0 we could lose some changes in 1.read 2.read 1.commit 2.commit scenario.
 * Because the file can be read and write with the same timestamp.
 * See edit_commit_test2 and edit_commit_test3.
 */
#define NANOSEC_THRESHOLD 10000000

/**
 * @brief Compares two data trees by module name
 */
static int
dm_data_info_cmp(const void *a, const void *b)
{
    assert(a);
    assert(b);
    dm_data_info_t *node_a = (dm_data_info_t *) a;
    dm_data_info_t *node_b = (dm_data_info_t *) b;

    int res = strcmp(node_a->schema->module->name, node_b->schema->module->name);
    if (res == 0) {
        return 0;
    } else if (res < 0) {
        return -1;
    } else {
        return 1;
    }
}

/**
 * @brief Compares two schema data info by module name
 */
static int
dm_schema_info_cmp(const void *a, const void *b)
{
    assert(a);
    assert(b);
    dm_schema_info_t *info_a = (dm_schema_info_t *) a;
    dm_schema_info_t *info_b = (dm_schema_info_t *) b;

    int res = strcmp(info_a->module_name, info_b->module_name);
    if (res == 0) {
        return 0;
    } else if (res < 0) {
        return -1;
    } else {
        return 1;
    }
}

/**
 * @brief Compares two schema data info by module name
 */
static int
dm_module_subscription_cmp(const void *a, const void *b)
{
    assert(a);
    assert(b);
    dm_model_subscription_t *sub_a = (dm_model_subscription_t *) a;
    dm_model_subscription_t *sub_b = (dm_model_subscription_t *) b;

    int res = strcmp(sub_a->schema_info->module_name, sub_b->schema_info->module_name);
    if (res == 0) {
        return 0;
    } else if (res < 0) {
        return -1;
    } else {
        return 1;
    }
}

/**
 * @brief Compares two commit context by id
 */
static int
dm_c_ctx_id_cmp(const void *a, const void *b)
{
    assert(a);
    assert(b);
    dm_commit_context_t *cctx_a = (dm_commit_context_t *) a;
    dm_commit_context_t *cctx_b = (dm_commit_context_t *) b;


    if (cctx_a->id == cctx_b->id) {
        return 0;
    } else if (cctx_a->id < cctx_b->id) {
        return -1;
    } else {
        return 1;
    }
}

static void
dm_free_lys_private_data(const struct lys_node *node, void *private)
{
    if (NULL != private) {
        free(private);
    }
}

static void
dm_free_schema_info(void *schema_info)
{
    CHECK_NULL_ARG_VOID(schema_info);
    dm_schema_info_t *si = (dm_schema_info_t *) schema_info;
    free(si->module_name);
    pthread_rwlock_destroy(&si->model_lock);
    pthread_mutex_destroy(&si->usage_count_mutex);
    if (NULL != si->ly_ctx) {
        ly_ctx_destroy(si->ly_ctx, dm_free_lys_private_data);
    }
    free(si);
}

/**
 * @brief frees the dm_data_info stored in binary tree
 */
static void
dm_data_info_free(void *item)
{
    dm_data_info_t *info = (dm_data_info_t *) item;
    if (NULL != info && !info->rdonly_copy) {
        lyd_free_withsiblings(info->node);
        /* decrement the number of usage of the module */
        pthread_mutex_lock(&info->schema->usage_count_mutex);
        info->schema->usage_count--;
        SR_LOG_DBG("Usage count %s decremented (value=%zu)", info->schema->module_name, info->schema->usage_count);
        pthread_mutex_unlock(&info->schema->usage_count_mutex);
    }
    free(info);
}

static void
dm_model_subscription_free(void *sub)
{
    dm_model_subscription_t *ms = (dm_model_subscription_t *) sub;
    if (NULL != ms) {
        for (size_t i = 0; i < ms->subscription_cnt; i++) {
            np_free_subscription(ms->subscriptions[i]);
        }
        free(ms->subscriptions);
        free(ms->nodes);
        lyd_free_diff(ms->difflist);
        if (NULL != ms->changes) {
            for (int i = 0; i < ms->changes->count; i++) {
                sr_free_changes(ms->changes->data[i], 1);
            }
            sr_list_cleanup(ms->changes);
        }
        pthread_rwlock_destroy(&ms->changes_lock);
    }
    free(ms);
}

static int
dm_schema_info_init(const char *schema_search_dir, dm_schema_info_t **schema_info)
{
    CHECK_NULL_ARG2(schema_search_dir, schema_info);
    int rc = SR_ERR_OK;
    dm_schema_info_t *si = NULL;

    si = calloc(1, sizeof(*si));
    CHECK_NULL_NOMEM_RETURN(si);

    si->ly_ctx = ly_ctx_new(schema_search_dir);
    CHECK_NULL_NOMEM_GOTO(si->ly_ctx, rc, cleanup);

    pthread_rwlock_init(&si->model_lock, NULL);
    pthread_mutex_init(&si->usage_count_mutex, NULL);

cleanup:
    if (SR_ERR_OK != rc) {
        free(si);
    } else {
        *schema_info = si;
    }
    return rc;
}

/**
 * @brief Creates the copy of dm_data_info structure and inserts it into binary tree
 * @param [in] tree
 * @param [in] di
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_insert_data_info_copy(sr_btree_t *tree, const dm_data_info_t *di)
{
    CHECK_NULL_ARG2(tree, di);
    int rc = SR_ERR_OK;
    dm_data_info_t *copy = NULL;
    copy = calloc (1, sizeof(*copy));
    CHECK_NULL_NOMEM_RETURN(copy);

    if (NULL != di->node) {
        copy->node = sr_dup_datatree(di->node);
        CHECK_NULL_NOMEM_GOTO(copy->node, rc, cleanup);
    }
    pthread_mutex_lock(&di->schema->usage_count_mutex);
    di->schema->usage_count++;
    SR_LOG_DBG("Usage count %s incremented (value=%zu)", di->schema->module_name, di->schema->usage_count);
    pthread_mutex_unlock(&di->schema->usage_count_mutex);
    copy->schema = di->schema;
    copy->timestamp = di->timestamp;

    rc = sr_btree_insert(tree, (void *) copy);
cleanup:
    if (SR_ERR_OK != rc) {
        dm_data_info_free(copy);
    }
    return rc;
}

/**
 * @brief Function verifies that current module is not used by a session
 * and dis/enable the feature
 *
 * @note Function expects that a schema info is locked for writing.
 *
 * @param [in] dm_ctx
 * @param [in] schema_info - schema info that is locked
 * @param [in] module_name
 * @param [in] feature_name
 * @param [in] enable Flag denoting whether feature should be enabled or disabled
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_feature_enable_internal(dm_ctx_t *dm_ctx, dm_schema_info_t *schema_info, const char *module_name, const char *feature_name, bool enable)
{
    CHECK_NULL_ARG4(dm_ctx, schema_info, module_name, feature_name);
    int rc = SR_ERR_OK;

    pthread_mutex_lock(&schema_info->usage_count_mutex);
    if (0 != schema_info->usage_count) {
        SR_LOG_ERR("Feature state can not be modified because %zu is using the module", schema_info->usage_count);
        pthread_mutex_unlock(&schema_info->usage_count_mutex);
        return SR_ERR_OPERATION_FAILED;
    }

    const struct lys_module *module = ly_ctx_get_module(schema_info->ly_ctx, module_name, NULL);
    if (NULL != module) {
        rc = enable ? lys_features_enable(module, feature_name) : lys_features_disable(schema_info->module, feature_name);
        SR_LOG_DBG("%s feature '%s' in module '%s'", enable ? "Enabling" : "Disabling", feature_name, module_name);
    } else {
        SR_LOG_ERR("Module %s not found in provided context", module_name);
        rc = SR_ERR_UNKNOWN_MODEL;
    }
    pthread_mutex_unlock(&schema_info->usage_count_mutex);

    if (1 == rc) {
        SR_LOG_ERR("Unknown feature %s in model %s", feature_name, module_name);
    }

    return rc;
}

/**
 * @brief Edits module private data - enables all nodes
 *
 * @note Function expects that a schema info is locked for writing.
 *
 * @param [in] ctx
 * @param [in] session
 * @param [in] schema_info
 * @param [in] module_name
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_enable_module_running_internal(dm_ctx_t *ctx, dm_session_t *session, dm_schema_info_t *schema_info, const char *module_name)
{
    CHECK_NULL_ARG3(ctx, schema_info, module_name); /* session can be NULL */
    char xpath[PATH_MAX] = {0,};
    int rc = SR_ERR_OK;
    struct lys_node *node = NULL;

    /* enable each subtree within the module */
    const struct lys_module *module = ly_ctx_get_module(schema_info->ly_ctx, module_name, NULL);
    if (NULL != module) {
        node = module->data;
    } else {
        SR_LOG_ERR("Module %s not found in provided context", module_name);
        rc = SR_ERR_UNKNOWN_MODEL;
    }
    while (NULL != node) {
        if ((LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST) & node->nodetype) {
            snprintf(xpath, PATH_MAX, "/%s:%s", node->module->name, node->name);
            rc = rp_dt_enable_xpath(ctx, session, schema_info, xpath);
            if (SR_ERR_OK != rc) {
                break;
            }
        }
        node = node->next;
    }

    return rc;
}

/**
 *
 * @note Function expects that a schema info is locked for writing.
 *
 * @param [in] ctx
 * @param [in] session
 * @param [in] module_name
 * @param [in] xpath
 * @param [in] schema_info
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_enable_module_subtree_running_internal(dm_ctx_t *ctx, dm_session_t *session, dm_schema_info_t *schema_info, const char *module_name, const char *xpath)
{
    CHECK_NULL_ARG3(ctx, module_name, xpath); /* session can be NULL */
    int rc = SR_ERR_OK;

    /* enable the subtree specified by xpath */
    rc = rp_dt_enable_xpath(ctx, session, schema_info, xpath);
    CHECK_RC_LOG_RETURN(rc, "Enabling of xpath %s failed", xpath);

    return rc;
}

int
dm_get_schema_info(dm_ctx_t *dm_ctx, const char *module_name, dm_schema_info_t **schema_info)
{
    CHECK_NULL_ARG3(dm_ctx, module_name, schema_info);
    int rc = SR_ERR_OK;
    dm_schema_info_t lookup_item = {0,};
    lookup_item.module_name = (char *) module_name;
    RWLOCK_RDLOCK_TIMED_CHECK_RETURN(&dm_ctx->schema_tree_lock);
    *schema_info = sr_btree_search(dm_ctx->schema_info_tree, &lookup_item);
    pthread_rwlock_unlock(&dm_ctx->schema_tree_lock);
    if (NULL == *schema_info) {
        SR_LOG_ERR("Schema info not found for model %s", module_name);
        return SR_ERR_NOT_FOUND;
    }
    return rc;
}

/**
 * @brief Loads a schema file into the schema_info structure.
 *
 * @note Function expects that module write lock is hold by caller if append is true
 *
 * @param [in] dm_ctx
 * @param [in] schema_filepath
 * @param [in] append - flag denoting whether schema_info should be allocated or already allocated schema info
 * has been passed as an argument and schema should be loaded into it
 * @param [out] schema_info
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_load_schema_file(dm_ctx_t *dm_ctx, const char *schema_filepath, bool append, dm_schema_info_t **schema_info)
{
    CHECK_NULL_ARG3(dm_ctx, schema_filepath, schema_info);
    const struct lys_module *module = NULL;

    char **enabled_subtrees = NULL, **features = NULL;
    size_t enabled_subtrees_cnt = 0, features_cnt = 0;
    bool module_enabled = false;
    dm_schema_info_t *si = NULL;
    int rc = SR_ERR_OK;

    if (append) {
        /* schemas will be loaded into provided context */
        CHECK_NULL_ARG(*schema_info);
        si = *schema_info;
    } else {
        /* allocate new structure where schemas will be loaded*/
        rc = dm_schema_info_init(dm_ctx->schema_search_dir, &si);
        CHECK_RC_MSG_RETURN(rc, "Schema info init failed");
    }

    /* load schema tree */
    LYS_INFORMAT fmt = sr_str_ends_with(schema_filepath, SR_SCHEMA_YIN_FILE_EXT) ? LYS_IN_YIN : LYS_IN_YANG;
    module = lys_parse_path(si->ly_ctx, schema_filepath, fmt);
    if (module == NULL) {
        SR_LOG_WRN("Unable to parse a schema file: %s", schema_filepath);
        if (!append) {
            dm_free_schema_info(si);
        }
        return SR_ERR_INTERNAL;
    }

    if (!append) {
        si->module_name = strdup(module->name);
        CHECK_NULL_NOMEM_GOTO(si->module_name, rc, cleanup);
        si->module = module;
    }

    /* load module's persistent data */
    rc = pm_get_module_info(dm_ctx->pm_ctx, module->name, NULL, &module_enabled,
            &enabled_subtrees, &enabled_subtrees_cnt, &features, &features_cnt);
    if (SR_ERR_OK == rc) {
        /* enable active features */
        for (size_t i = 0; i < features_cnt; i++) {
            rc = dm_feature_enable_internal(dm_ctx, si, module->name, features[i], true);
            if (SR_ERR_OK != rc) {
                SR_LOG_WRN("Unable to enable feature '%s' in module '%s' in Data Manager.", features[i], module->name);
            }
        }

        if (SR_ERR_OK == rc) {
            if (module_enabled) {
                /* enable running datastore for whole module */
                rc = dm_enable_module_running_internal(dm_ctx, NULL, si, module->name);
            } else {
                /* enable running datastore for specified subtrees */
                for (size_t i = 0; i < enabled_subtrees_cnt; i++) {
                    rc = dm_enable_module_subtree_running_internal(dm_ctx, NULL, si, module->name, enabled_subtrees[i]);
                    if (SR_ERR_OK != rc) {
                        SR_LOG_WRN("Unable to enable subtree '%s' in module '%s' in running ds.", enabled_subtrees[i], module->name);
                    }
                }
            }
        }

        /* release memory */
        for (size_t i = 0; i < enabled_subtrees_cnt; i++) {
            free(enabled_subtrees[i]);
        }
        free(enabled_subtrees);
        for (size_t i = 0; i < features_cnt; i++) {
            free(features[i]);
        }
        free(features);
    }
    *schema_info = si;
    return SR_ERR_OK;

cleanup:
    dm_free_schema_info(si);
    return rc;
}

/**
 * @brief Loads module and all its dependencies into the libyang context.
 * @param [in] dm_ctx
 * @param [in] module_name
 * @param [in] revision can be NULL
 * @param [out] module_schema
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_load_module(dm_ctx_t *dm_ctx, const char *module_name, const char *revision, dm_schema_info_t **schema_info)
{
    CHECK_NULL_ARG3(dm_ctx, module_name, schema_info); /* revision might be NULL*/
    int rc = SR_ERR_OK;
    dm_schema_info_t *si = NULL;
    md_module_t *module = NULL;
    md_dep_t *dep = NULL;
    sr_llist_node_t *ll_node = NULL;

    /* search for the module to use */
    md_ctx_lock(dm_ctx->md_ctx, false);
    rc = md_get_module_info(dm_ctx->md_ctx, module_name, revision, &module);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Module '%s:%s' is not installed.", module_name, revision ? revision : "<latest>");
        *schema_info = NULL;
        md_ctx_unlock(dm_ctx->md_ctx);
        return SR_ERR_UNKNOWN_MODEL;
    }
    if (module->submodule) {
        SR_LOG_WRN("An attempt to load submodule %s", module_name);
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    /* load the module schema and all its dependencies */
    rc = dm_load_schema_file(dm_ctx, module->filepath, false, &si);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to load schema %s", module->filepath);

    ll_node = module->deps->first;
    while (ll_node) {
        dep = (md_dep_t *)ll_node->data;
        if (dep->type == MD_DEP_EXTENSION || dep->type == MD_DEP_DATA) {
            /**
             * Note:
             *  - imports are automatically loaded by libyang
             *  - module write lock is not required because schema info is not added into schema tree yet
             */
            rc = dm_load_schema_file(dm_ctx, dep->dest->filepath, true, &si);
            if (SR_ERR_OK != rc) {
                *schema_info = NULL;
                md_ctx_unlock(dm_ctx->md_ctx);
                return rc;
            }
        }
        if (dep->type == MD_DEP_DATA) {
            /* mark this module as dependent on data from other modules */
            si->cross_module_data_dependency = true;
        }
        ll_node = ll_node->next;
    }

    /* insert schema info into schema tree */
    RWLOCK_WRLOCK_TIMED_CHECK_GOTO(&dm_ctx->schema_tree_lock, rc, cleanup);

    rc = sr_btree_insert(dm_ctx->schema_info_tree, si);
    if (SR_ERR_OK != rc) {
        if (SR_ERR_DATA_EXISTS != rc) {
            SR_LOG_WRN("Insert into schema binary tree failed. %s", sr_strerror(rc));
            goto unlock;
        } else {
            /* if someone loaded schema meanwhile */
            dm_schema_info_t *lookup = si;
            si = sr_btree_search(dm_ctx->schema_info_tree, lookup);
            dm_free_schema_info(lookup);
            if (NULL != si) {
                rc = SR_ERR_OK;
            } else {
                SR_LOG_ERR_MSG("Failed to find a schema in schema tree");
            }
        }
    }

unlock:
    pthread_rwlock_unlock(&dm_ctx->schema_tree_lock);
cleanup:
    if (SR_ERR_OK == rc) {
        *schema_info = si;
    } else {
        dm_free_schema_info(si);
    }
    md_ctx_unlock(dm_ctx->md_ctx);
    return rc;
}


/**
 * @brief Tries to load data tree from provided opened file.
 * @param [in] dm_ctx
 * @param [in] fd to be read from, function does not close it
 * If NULL passed data info with empty data will be created
 * @param [in] schema_info
 * @param [in] data_info
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_load_data_tree_file(dm_ctx_t *dm_ctx, int fd, const char *data_filename, dm_schema_info_t *schema_info, dm_data_info_t **data_info)
{
    CHECK_NULL_ARG4(dm_ctx, schema_info, data_filename, data_info);
    int rc = SR_ERR_OK;
    struct lyd_node *data_tree = NULL;
    *data_info = NULL;

    dm_data_info_t *data = NULL;
    data = calloc(1, sizeof(*data));
    CHECK_NULL_NOMEM_RETURN(data);

    if (-1 != fd) {
#ifdef HAVE_STAT_ST_MTIM
        struct stat st = {0};
        rc = stat(data_filename, &st);
        if (-1 == rc) {
            SR_LOG_ERR_MSG("Stat failed");
            free(data);
            return SR_ERR_INTERNAL;
        }
        data->timestamp = st.st_mtim;
        SR_LOG_DBG("Loaded module %s: mtime sec=%lld nsec=%lld", schema_info->module->name,
                (long long) st.st_mtim.tv_sec,
                (long long) st.st_mtim.tv_nsec);
#endif
        ly_errno = 0;
        /* use LYD_OPT_TRUSTED, validation will be done later */
        data_tree = lyd_parse_fd(schema_info->ly_ctx, fd, LYD_XML, LYD_OPT_TRUSTED | LYD_OPT_CONFIG);
        if (NULL == data_tree && LY_SUCCESS != ly_errno) {
            SR_LOG_ERR("Parsing data tree from file %s failed: %s", data_filename, ly_errmsg());
            free(data);
            return SR_ERR_INTERNAL;
        }
    }

    /* if there is no data dependency validate it with of LYD_OPT_STRICT, validate it (only non-empty data trees are validated)*/
    if (!schema_info->cross_module_data_dependency && NULL != data_tree && 0 != lyd_validate(&data_tree, LYD_OPT_STRICT | LYD_OPT_CONFIG, schema_info->ly_ctx)) {
        SR_LOG_ERR("Loaded data tree '%s' is not valid", data_filename);
        lyd_free_withsiblings(data_tree);
        free(data);
        return SR_ERR_INTERNAL;
    }

    data->schema = schema_info;
    data->modified = false;
    data->node = data_tree;

    /* increment counter of data tree using the module */
    pthread_mutex_lock(&schema_info->usage_count_mutex);
    schema_info->usage_count++;
    SR_LOG_DBG("Usage count %s incremented (value=%zu)", schema_info->module_name, schema_info->usage_count);
    pthread_mutex_unlock(&schema_info->usage_count_mutex);

    if (NULL == data_tree) {
        SR_LOG_INF("Data file %s is empty", data_filename);
    } else {
        SR_LOG_INF("Data file %s loaded successfully", data_filename);
    }

    *data_info = data;

    return rc;
}

/**
 * @brief Loads data tree from file. Module and datastore argument are used to
 * determine the file name.
 *
 * @note Function expects that a schema info is locked for reading.
 *
 * @param [in] dm_ctx
 * @param [in] dm_session_ctx
 * @param [in] schema_info
 * @param [in] ds
 * @param [out] data_info
 * @return Error code (SR_ERR_OK on success), SR_ERR_INTERAL if the parsing of the data tree fails.
 */
static int
dm_load_data_tree(dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx, dm_schema_info_t *schema_info, sr_datastore_t ds, dm_data_info_t **data_info)
{
    CHECK_NULL_ARG4(dm_ctx, schema_info, schema_info->module, schema_info->module->name);

    char *data_filename = NULL;
    int rc = 0;
    *data_info = NULL;
    rc = sr_get_data_file_name(dm_ctx->data_search_dir, schema_info->module->name, ds, &data_filename);
    CHECK_RC_LOG_RETURN(rc, "Get data_filename failed for %s", schema_info->module->name);

    ac_set_user_identity(dm_ctx->ac_ctx, dm_session_ctx->user_credentials);

    int fd = open(data_filename, O_RDONLY);

    ac_unset_user_identity(dm_ctx->ac_ctx);

    if (-1 != fd) {
        /* lock, read-only, blocking */
        sr_lock_fd(fd, false, true);
    } else if (ENOENT == errno) {
        SR_LOG_DBG("Data file %s does not exist, creating empty data tree", data_filename);
    } else if (EACCES == errno) {
        SR_LOG_DBG("Data file %s can't be read because of access rights", data_filename);
        free(data_filename);
        return SR_ERR_UNAUTHORIZED;
    }

    rc = dm_load_data_tree_file(dm_ctx, fd, data_filename, schema_info, data_info);

    if (-1 != fd) {
        sr_unlock_fd(fd);
        close(fd);
    }

    free(data_filename);
    return rc;
}

static void
dm_free_sess_op(dm_sess_op_t *op)
{
    if (NULL == op) {
        return;
    }
    free(op->xpath);
    if (DM_SET_OP == op->op) {
        sr_free_val(op->detail.set.val);
    } else if (DM_MOVE_OP == op->op) {
        free(op->detail.mov.relative_item);
        op->detail.mov.relative_item = NULL;
    }
}

static void
dm_free_sess_operations(dm_sess_op_t *ops, size_t count)
{
    if (NULL == ops) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        dm_free_sess_op(&ops[i]);
    }
    free(ops);
}

/**
 * @brief Locks a file based on provided file name.
 * @param [in] lock_ctx
 * @param [in] filename
 * @return Error code (SR_ERR_OK on success), SR_ERR_LOCKED if the file is already locked,
 * SR_ERR_UNATHORIZED if the file can not be locked because of the permission.
 */
static int
dm_lock_file(sr_locking_set_t *lock_ctx, char *filename)
{
    CHECK_NULL_ARG2(lock_ctx, filename);
    return sr_locking_set_lock_file_open(lock_ctx, filename, true, false, NULL);
}

/**
 * @brief Unlocks the file based on the filename
 * @param [in] lock_ctx
 * @param [in] filename
 * @return Error code (SR_ERR_OK on success) SR_ERR_INVAL_ARG if the
 * file had not been locked in provided context
 */
static int
dm_unlock_file(sr_locking_set_t *lock_ctx, char *filename)
{
    CHECK_NULL_ARG2(lock_ctx, filename);
    return sr_locking_set_unlock_close_file(lock_ctx, filename);
}

/**
 * @brief Logging callback called from libyang for each log entry.
 */
static void
dm_ly_log_cb(LY_LOG_LEVEL level, const char *msg, const char *path)
{
    if (LY_LLERR == level) {
        SR_LOG_DBG("libyang error: %s", msg);
    }
}

int
dm_lock_module(dm_ctx_t *dm_ctx, dm_session_t *session, const char *modul_name)
{
    CHECK_NULL_ARG3(dm_ctx, session, modul_name);
    int rc = SR_ERR_OK;
    char *lock_file = NULL;
    dm_schema_info_t *si = NULL;

    /* check if module name is valid */
    rc = dm_get_module_and_lock(dm_ctx, modul_name, &si);
    CHECK_RC_LOG_RETURN(rc, "Unknown module %s to lock", modul_name);

    rc = sr_get_lock_data_file_name(dm_ctx->data_search_dir, modul_name, session->datastore, &lock_file);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Lock file name can not be created");

    /* check if already locked by this session */
    for (size_t i = 0; i < session->locked_files->count; i++) {
        if (0 == strcmp(lock_file, (char *) session->locked_files->data[i])) {
            SR_LOG_INF("File %s is already by this session", lock_file);
            free(lock_file);
            goto cleanup;
        }
    }

    /* switch identity */
    ac_set_user_identity(dm_ctx->ac_ctx, session->user_credentials);

    rc = dm_lock_file(dm_ctx->locking_ctx, lock_file);

    /* switch identity back */
    ac_unset_user_identity(dm_ctx->ac_ctx);

    /* log information about locked model */
    if (SR_ERR_OK != rc) {
        free(lock_file);
    } else {
        rc = sr_list_add(session->locked_files, lock_file);
        CHECK_RC_MSG_RETURN(rc, "List add failed");

        pthread_mutex_lock(&si->usage_count_mutex);
        si->usage_count++;
        SR_LOG_DBG("Usage count %s incremented (value=%zu)", si->module_name, si->usage_count);
        pthread_mutex_unlock(&si->usage_count_mutex);
    }
cleanup:
    pthread_rwlock_unlock(&si->model_lock);
    return rc;
}

int
dm_unlock_module(dm_ctx_t *dm_ctx, dm_session_t *session, char *modul_name)
{
    CHECK_NULL_ARG3(dm_ctx, session, modul_name);
    int rc = SR_ERR_OK;
    dm_schema_info_t *si = NULL;
    char *lock_file = NULL;
    size_t i = 0;

    SR_LOG_INF("Unlock request module='%s'", modul_name);

    rc = dm_get_module_and_lock(dm_ctx, modul_name, &si);
    CHECK_RC_LOG_RETURN(rc, "Unknown module %s to unlock", modul_name);

    rc = sr_get_lock_data_file_name(dm_ctx->data_search_dir, modul_name, session->datastore, &lock_file);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Lock file name can not be created");

    /* check if already locked */
    bool found = false;
    for (i = 0; i < session->locked_files->count; i++) {
        if (0 == strcmp(lock_file, (char *) session->locked_files->data[i])) {
            found = true;
            break;
        }
    }

    if (!found) {
        SR_LOG_ERR("File %s has not been locked in this context", lock_file);
        rc = SR_ERR_INVAL_ARG;
    } else {
        rc = dm_unlock_file(dm_ctx->locking_ctx, lock_file);
        free(session->locked_files->data[i]);
        sr_list_rm_at(session->locked_files, i);
        pthread_mutex_lock(&si->usage_count_mutex);
        si->usage_count--;
        SR_LOG_DBG("Usage count %s decremented (value=%zu)", si->module_name, si->usage_count);
        pthread_mutex_unlock(&si->usage_count_mutex);
    }
cleanup:
    free(lock_file);
    pthread_rwlock_unlock(&si->model_lock);
    return rc;
}

int
dm_lock_datastore(dm_ctx_t *dm_ctx, dm_session_t *session)
{
    CHECK_NULL_ARG2(dm_ctx, session);
    int rc = SR_ERR_OK;
    sr_schema_t *schemas = NULL;
    size_t schema_count = 0;

    sr_list_t *locked = NULL;
    rc = sr_list_init(&locked);
    CHECK_RC_MSG_RETURN(rc, "List init failed");

    rc = dm_list_schemas(dm_ctx, session, &schemas, &schema_count);
    CHECK_RC_MSG_GOTO(rc, cleanup, "List schemas failed");

    pthread_mutex_lock(&dm_ctx->ds_lock_mutex);
    if (dm_ctx->ds_lock[session->datastore]) {
        SR_LOG_ERR_MSG("Datastore lock is hold by other session");
        rc = SR_ERR_LOCKED;
        pthread_mutex_unlock(&dm_ctx->ds_lock_mutex);
        goto cleanup;
    }
    dm_ctx->ds_lock[session->datastore] = true;
    pthread_mutex_unlock(&dm_ctx->ds_lock_mutex);
    session->holds_ds_lock[session->datastore] = true;

    for (size_t i = 0; i < schema_count; i++) {
        rc = dm_lock_module(dm_ctx, session, (char *) schemas[i].module_name);
        if (SR_ERR_OK != rc) {
            if (SR_ERR_UNAUTHORIZED == rc) {
                SR_LOG_INF("Not allowed to lock %s, skipping", schemas[i].module_name);
                continue;
            } else if (SR_ERR_LOCKED == rc) {
                SR_LOG_ERR("Model %s is already locked by other session", schemas[i].module_name);
            }
            for (size_t l = 0; l < locked->count; l++) {
                dm_unlock_module(dm_ctx, session, (char *) locked->data[l]);
            }
            pthread_mutex_lock(&dm_ctx->ds_lock_mutex);
            dm_ctx->ds_lock[session->datastore] = false;
            pthread_mutex_unlock(&dm_ctx->ds_lock_mutex);
            session->holds_ds_lock[session->datastore] = false;
            goto cleanup;
        }
        SR_LOG_DBG("Module %s locked", schemas[i].module_name);
        rc = sr_list_add(locked, (char *) schemas[i].module_name);
        CHECK_RC_MSG_GOTO(rc, cleanup, "List add failed");
    }
cleanup:
    sr_free_schemas(schemas, schema_count);
    sr_list_cleanup(locked);
    return rc;
}

/**
 *
 * @brief Extracts the name of the module and lookups the schema info from lock files.
 *
 * Expectes that lock file name are in form [DATA_DIR][MODULE_NAME][DATASTORE].lock
 *
 * @note Schema info read lock is acquired on successful return from function. Must be released by caller.
 *
 * @param [in] dm_ctx
 * @param [in] lock_file
 * @param [out] schema_info
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_get_schema_info_by_lock_file(dm_ctx_t *dm_ctx, const char *lock_file, dm_schema_info_t **schema_info)
{
    CHECK_NULL_ARG3(dm_ctx, lock_file, schema_info);
    int rc = SR_ERR_OK;
    char *begin = NULL;
    char *end = NULL;
    char *module_name = NULL;

    if (NULL == strstr(lock_file, dm_ctx->data_search_dir)){
        return SR_ERR_INTERNAL;
    }
    begin = (char *)lock_file + strlen(dm_ctx->data_search_dir);
    if ((end = strstr(begin, SR_STARTUP_FILE_EXT SR_LOCK_FILE_EXT))
            || (end = strstr(begin, SR_RUNNING_FILE_EXT SR_LOCK_FILE_EXT))
            || (end = strstr(begin, ".candidate" SR_LOCK_FILE_EXT))) {
        /* dup the module name */
        module_name = strndup(begin, end-begin);
        CHECK_NULL_NOMEM_RETURN(module_name);

        rc = dm_get_module_and_lock(dm_ctx, module_name, schema_info);
        free(module_name);
    } else {
        SR_LOG_ERR("Unable to extract module name %s", lock_file);
        rc = SR_ERR_INTERNAL;
    }

    return rc;
}

int
dm_unlock_datastore(dm_ctx_t *dm_ctx, dm_session_t *session)
{
    CHECK_NULL_ARG2(dm_ctx, session);
    SR_LOG_INF_MSG("Unlock datastore request");
    int rc = SR_ERR_OK;
    dm_schema_info_t *si = NULL;

    while (session->locked_files->count > 0) {
        si = NULL;
        rc = dm_get_schema_info_by_lock_file(dm_ctx, (char *) session->locked_files->data[0], &si);
        if (SR_ERR_OK == rc) {
            SR_LOG_DBG("Module_name %s", si->module_name);
            pthread_mutex_lock(&si->usage_count_mutex);
            si->usage_count--;
            SR_LOG_DBG("Usage count %s decremented (value=%zu)", si->module_name, si->usage_count);
            pthread_mutex_unlock(&si->usage_count_mutex);
            pthread_rwlock_unlock(&si->model_lock);
        } else {
            SR_LOG_WRN("Get schema info by lock file failed %s", (char *) session->locked_files->data[0]);
        }

        dm_unlock_file(dm_ctx->locking_ctx, (char *) session->locked_files->data[0]);
        free(session->locked_files->data[0]);
        sr_list_rm_at(session->locked_files, 0);
    }
    for (int i = 0; i < DM_DATASTORE_COUNT; i++) {
        if (session->holds_ds_lock[i]) {
            pthread_mutex_lock(&dm_ctx->ds_lock_mutex);
            dm_ctx->ds_lock[i] = false;
            session->holds_ds_lock[i] = false;
            pthread_mutex_unlock(&dm_ctx->ds_lock_mutex);
        }
    }
    return SR_ERR_OK;
}

/**
 * @brief Returns the state of node. If the NULL is provided as an argument
 * DM_NODE_DISABLED is returned.
 */
static dm_node_state_t
dm_get_node_state(struct lys_node *node)
{
    if (NULL == node || NULL == node->priv) {
        return DM_NODE_DISABLED;
    }
    dm_node_info_t *n_info = (dm_node_info_t *) node->priv;

    if (NULL == n_info) {
        return DM_NODE_DISABLED;
    }
    return n_info->state;
}

int
dm_add_operation(dm_session_t *session, dm_operation_t op, const char *xpath, sr_val_t *val, sr_edit_options_t opts, sr_move_position_t pos, const char *rel_item)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_ARG_NORET2(rc, session, xpath); /* value can be NULL*/
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    if (NULL == session->operations[session->datastore]) {
        session->oper_size[session->datastore] = 1;
        session->operations[session->datastore] = calloc(session->oper_size[session->datastore], sizeof(*session->operations[session->datastore]));
        CHECK_NULL_NOMEM_GOTO(session->operations[session->datastore], rc, cleanup);
    } else if (session->oper_count[session->datastore] == session->oper_size[session->datastore]) {
        session->oper_size[session->datastore] *= 2;
        dm_sess_op_t *tmp_op = realloc(session->operations[session->datastore], session->oper_size[session->datastore] * sizeof(*session->operations[session->datastore]));
        CHECK_NULL_NOMEM_GOTO(tmp_op, rc, cleanup);
        session->operations[session->datastore] = tmp_op;
    }
    int index = session->oper_count[session->datastore];
    session->operations[session->datastore][index].op = op;
    session->operations[session->datastore][index].has_error = false;
    session->operations[session->datastore][index].xpath = strdup(xpath);
    CHECK_NULL_NOMEM_GOTO(session->operations[session->datastore][index].xpath, rc, cleanup);
    if (DM_SET_OP == op) {
        session->operations[session->datastore][index].detail.set.val = val;
        session->operations[session->datastore][index].detail.set.options = opts;
    } else if (DM_DELETE_OP == op) {
        session->operations[session->datastore][index].detail.del.options = opts;
    } else if (DM_MOVE_OP == op) {
        session->operations[session->datastore][index].detail.mov.position = pos;
        if (NULL != rel_item) {
            session->operations[session->datastore][index].detail.mov.relative_item = strdup(rel_item);
            CHECK_NULL_NOMEM_GOTO(session->operations[session->datastore][index].detail.mov.relative_item, rc, cleanup);
        } else {
            session->operations[session->datastore][index].detail.mov.relative_item = NULL;
        }
    }

    session->oper_count[session->datastore]++;
    return rc;
cleanup:
    sr_free_val(val);
    return rc;
}

void
dm_remove_last_operation(dm_session_t *session)
{
    CHECK_NULL_ARG_VOID(session);
    if (session->oper_count[session->datastore] > 0) {
        session->oper_count[session->datastore]--;
        int index = session->oper_count[session->datastore];
        dm_free_sess_op(&session->operations[session->datastore][index]);
        session->operations[session->datastore][index].xpath = NULL;
        session->operations[session->datastore][index].detail.set.val = NULL;
    }
}

void
dm_get_session_operations(dm_session_t *session, dm_sess_op_t **ops, size_t *count)
{
    CHECK_NULL_ARG_VOID3(session, ops, count);
    *ops = session->operations[session->datastore];
    *count = session->oper_count[session->datastore];
}

void
dm_clear_session_errors(dm_session_t *session)
{
    if (NULL == session) {
        return;
    }

    if (NULL != session->error_msg) {
        free(session->error_msg);
        session->error_msg = NULL;
    }

    if (NULL != session->error_xpath) {
        free(session->error_xpath);
        session->error_xpath = NULL;
    }
}

int
dm_report_error(dm_session_t *session, const char *msg, const char *err_path, int rc)
{
    if (NULL == session) {
        return SR_ERR_INTERNAL;
    }

    /* if NULL is provided, message will be generated according to the error code */
    if (NULL == msg) {
        msg = sr_strerror(rc);
    }

    /* error mesage */
    if (NULL != session->error_msg) {
        SR_LOG_DBG("Overwriting session error message %s", session->error_msg);
        free(session->error_msg);
    }
    session->error_msg = strdup(msg);
    CHECK_NULL_NOMEM_RETURN(session->error_msg);

    /* error xpath */
    if (NULL != err_path) {
        if (NULL != session->error_xpath) {
            SR_LOG_DBG("Overwriting session error xpath %s", session->error_xpath);
            free(session->error_xpath);
        }
        session->error_xpath = strdup(err_path);
        CHECK_NULL_NOMEM_RETURN(session->error_xpath);
    } else {
        SR_LOG_DBG_MSG("Error xpath passed to dm_report is NULL");
    }

    return rc;
}

bool
dm_has_error(dm_session_t *session)
{
    if (NULL == session) {
        return false;
    }
    return NULL != session->error_msg || NULL != session->error_xpath;
}

int
dm_copy_errors(dm_session_t *session, sr_mem_ctx_t *sr_mem, char **error_msg, char **err_xpath)
{
    CHECK_NULL_ARG3(session, error_msg, err_xpath);
    if (NULL != session->error_msg) {
        sr_mem_edit_string(sr_mem, error_msg, session->error_msg);
    }
    if (NULL != session->error_xpath) {
        sr_mem_edit_string(sr_mem, err_xpath, session->error_xpath);
    }
    if ((NULL != session->error_msg && NULL == *error_msg) || (NULL != session->error_xpath && NULL == *err_xpath)) {
        SR_LOG_ERR_MSG("Error duplication failed");
        return SR_ERR_INTERNAL;
    }
    return SR_ERR_OK;
}

bool
dm_is_node_enabled(struct lys_node* node)
{
    dm_node_state_t state = dm_get_node_state(node);
    return DM_NODE_ENABLED == state || DM_NODE_ENABLED_WITH_CHILDREN == state;
}

bool
dm_is_node_enabled_with_children(struct lys_node* node)
{
    return DM_NODE_ENABLED_WITH_CHILDREN == dm_get_node_state(node);
}

bool
dm_is_enabled_check_recursively(struct lys_node *node)
{
    if (dm_is_node_enabled(node)) {
        return true;
    }
    node = node->parent;
    while (NULL != node) {
        if (NULL == node->parent && LYS_AUGMENT == node->nodetype) {
            node = ((struct lys_node_augment *) node)->target;
            continue;
        }
        if (dm_is_node_enabled_with_children(node)) {
            return true;
        }
        node = node->parent;
    }
    return false;
}

int
dm_set_node_state(struct lys_node *node, dm_node_state_t state)
{
    CHECK_NULL_ARG(node);
    if (NULL == node->priv) {
        node->priv = calloc(1, sizeof(dm_node_info_t));
        CHECK_NULL_NOMEM_RETURN(node->priv);
    }
    ((dm_node_info_t *) node->priv)->state = state;
    return SR_ERR_OK;
}

bool
dm_is_running_ds_session(dm_session_t *session)
{
    if (NULL != session) {
        return SR_DS_RUNNING == session->datastore;
    }
    return false;
}

/**
 * @brief Function appends data tree from different context to validate
 * cross-module reference
 *
 * @param [in] session
 * @param [in] data_info
 * @param [in] module_name
 *
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_append_data_tree(dm_ctx_t *dm_ctx, dm_session_t *session, dm_data_info_t *data_info, const char *module_name)
{
    CHECK_NULL_ARG4(dm_ctx, session, data_info, module_name);
    int rc = SR_ERR_OK;
    int ret = 0;
    dm_data_info_t *di = NULL;
    char *tmp = NULL;
    struct lyd_node *tmp_node = NULL;

    rc = dm_get_data_info(dm_ctx, session, module_name, &di);
    CHECK_RC_LOG_RETURN(rc, "Get data info failed for module %s", module_name);

    /* transform data from one ctx to another */
    if (NULL != di->node) {
        ret = lyd_print_mem(&tmp, di->node, LYD_XML, LYP_WITHSIBLINGS);
        CHECK_ZERO_LOG_RETURN(ret, SR_ERR_INTERNAL, "Failed to print data of module %s into string", di->schema->module->name);
        tmp_node = lyd_parse_mem(data_info->schema->ly_ctx, tmp, LYD_XML, LYD_OPT_TRUSTED | LYD_OPT_CONFIG);
        if (NULL == tmp_node && LY_SUCCESS != ly_errno) {
            SR_LOG_ERR("Parsing data tree from string failed for module %s failed: %s", module_name, ly_errmsg());
            free(tmp);
            return SR_ERR_INTERNAL;
        }
        free(tmp);
        if (NULL == data_info->node) {
            data_info->node = tmp_node;
        } else if (NULL != tmp_node) {
            ret = lyd_merge(data_info->node, tmp_node, LYD_OPT_EXPLICIT);
            lyd_free_withsiblings(tmp_node);
        }
    } else {
        SR_LOG_DBG("Dependant module %s is empty", di->schema->module->name);
    }

    return rc;
}


/**
 * @brief Function deletes data that do not belong to the main module and was added due to
 * validation of cross-module dependant data
 *
 * @param [in] session
 * @param [in] data_info
 *
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_remove_added_data_trees(dm_session_t *session, dm_data_info_t *data_info)
{
    CHECK_NULL_ARG2(session, data_info);
    if (NULL != data_info->node) {
        if (data_info->schema->module != data_info->node->schema->module) {
            /* verify that the module referencing others has some data */
            lyd_free_withsiblings(data_info->node);
            data_info->node = NULL;
            return SR_ERR_OK;
        }
        const struct lys_module *module = data_info->node->schema->module;
        struct lyd_node *n = data_info->node;
        struct lyd_node *tmp = NULL;

        while (n) {
           tmp = n;
           n = n->next;
           if (module != tmp->schema->module) {
              lyd_free(tmp);
           }
        }
    }
    return SR_ERR_OK;
}

/**
 * @brief Append all dependant data.
 *
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] info
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_load_dependant_data(dm_ctx_t *dm_ctx, dm_session_t *session, dm_data_info_t *info)
{
    CHECK_NULL_ARG3(dm_ctx, session, info);
    sr_llist_node_t *ll_node = NULL;
    md_module_t *module = NULL;
    md_dep_t *dep = NULL;
    int rc = SR_ERR_OK;

    /* remove previously appended data */
    rc = dm_remove_added_data_trees(session, info);
    CHECK_RC_MSG_RETURN(rc, "Removing of added data trees failed");

    if (info->schema->cross_module_data_dependency) {
        md_ctx_lock(dm_ctx->md_ctx, false);
        rc = md_get_module_info(dm_ctx->md_ctx, info->schema->module_name, NULL, &module);
        CHECK_RC_LOG_GOTO(rc, unlock, "Unable to get the list of dependencies for module '%s'.", info->schema->module_name);
        ll_node = module->deps->first;
        while (ll_node) {
            dep = (md_dep_t *)ll_node->data;
            if (MD_DEP_DATA == dep->type && dep->dest->latest_revision) {
                const char *dependant_module = md_get_module_fullname(dep->dest);
                rc = dm_append_data_tree(session->dm_ctx, session, info, dependant_module);
                CHECK_RC_LOG_GOTO(rc, unlock, "Failed to append data tree %s", dependant_module);
                SR_LOG_DBG("Data tree %s appended because of validation", dependant_module);
            }
            ll_node = ll_node->next;
        }
unlock:
        md_ctx_unlock(dm_ctx->md_ctx);
    }
    return rc;
}

int
dm_init(ac_ctx_t *ac_ctx, np_ctx_t *np_ctx, pm_ctx_t *pm_ctx, const cm_connection_mode_t conn_mode,
        const char *schema_search_dir, const char *data_search_dir, dm_ctx_t **dm_ctx)
{
    CHECK_NULL_ARG3(schema_search_dir, data_search_dir, dm_ctx);

    SR_LOG_INF("Initializing Data Manager, schema_search_dir=%s, data_search_dir=%s", schema_search_dir, data_search_dir);

    dm_ctx_t *ctx = NULL;
    int rc = SR_ERR_OK;
    pthread_rwlockattr_t attr;
    pthread_rwlockattr_init(&attr);
    char *internal_schema_search_dir = NULL, *internal_data_search_dir = NULL;
    ctx = calloc(1, sizeof(*ctx));
    CHECK_NULL_NOMEM_GOTO(ctx, rc, cleanup);
    ctx->ac_ctx = ac_ctx;
    ctx->np_ctx = np_ctx;
    ctx->pm_ctx = pm_ctx;
    ctx->conn_mode = conn_mode;

    ly_set_log_clb(dm_ly_log_cb, 1);

    ctx->schema_search_dir = strdup(schema_search_dir);
    CHECK_NULL_NOMEM_GOTO(ctx->schema_search_dir, rc, cleanup);

    ctx->data_search_dir = strdup(data_search_dir);
    CHECK_NULL_NOMEM_GOTO(ctx->data_search_dir, rc, cleanup);

    ctx->ds_lock = calloc(DM_DATASTORE_COUNT, sizeof(*ctx->ds_lock));
    CHECK_NULL_NOMEM_GOTO(ctx->ds_lock, rc, cleanup);

    rc = sr_locking_set_init(&ctx->locking_ctx);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Locking set init failed");

#if defined(HAVE_PTHREAD_RWLOCKATTR_SETKIND_NP)
    pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
#endif

    rc = pthread_rwlock_init(&ctx->schema_tree_lock, &attr);
    CHECK_ZERO_MSG_GOTO(rc, rc, SR_ERR_INTERNAL, cleanup, "lyctx mutex initialization failed");

    rc = sr_btree_init(dm_schema_info_cmp, dm_free_schema_info, &ctx->schema_info_tree);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Schema binary tree allocation failed");

    rc = sr_btree_init(dm_c_ctx_id_cmp, dm_free_commit_context, &ctx->commit_ctxs.tree);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Commit context binary tree initialization failed");

    rc = pthread_rwlock_init(&ctx->commit_ctxs.lock, &attr);
    CHECK_ZERO_MSG_GOTO(rc, rc, SR_ERR_INTERNAL, cleanup, "c_ctxs_lock init failed");

    rc = sr_str_join(schema_search_dir, "internal", &internal_schema_search_dir);
    CHECK_ZERO_MSG_GOTO(rc, rc, SR_ERR_INTERNAL, cleanup, "sr_str_join failed");
    rc = sr_str_join(data_search_dir, "internal", &internal_data_search_dir);
    CHECK_ZERO_MSG_GOTO(rc, rc, SR_ERR_INTERNAL, cleanup, "sr_str_join failed");

    rc = md_init(schema_search_dir, internal_schema_search_dir,
                 internal_data_search_dir, false, &ctx->md_ctx);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to initialize Module Dependencies context.");

    *dm_ctx = ctx;

cleanup:
    free(internal_schema_search_dir);
    free(internal_data_search_dir);
    pthread_rwlockattr_destroy(&attr);
    if (SR_ERR_OK != rc) {
        dm_cleanup(ctx);
    }
    return rc;

}

void
dm_cleanup(dm_ctx_t *dm_ctx)
{
    if (NULL != dm_ctx) {
        sr_btree_cleanup(dm_ctx->commit_ctxs.tree);

        free(dm_ctx->schema_search_dir);
        free(dm_ctx->data_search_dir);
        free(dm_ctx->ds_lock);
        sr_btree_cleanup(dm_ctx->schema_info_tree);
        md_destroy(dm_ctx->md_ctx);
        pthread_rwlock_destroy(&dm_ctx->schema_tree_lock);
        sr_locking_set_cleanup(dm_ctx->locking_ctx);
        pthread_mutex_destroy(&dm_ctx->ds_lock_mutex);

        pthread_rwlock_destroy(&dm_ctx->commit_ctxs.lock);
        free(dm_ctx);
    }
}

int
dm_session_start(dm_ctx_t *dm_ctx, const ac_ucred_t *user_credentials, const sr_datastore_t ds, dm_session_t **dm_session_ctx)
{
    CHECK_NULL_ARG(dm_session_ctx);

    dm_session_t *session_ctx = NULL;
    session_ctx = calloc(1, sizeof(*session_ctx));
    CHECK_NULL_NOMEM_RETURN(session_ctx);
    session_ctx->dm_ctx = dm_ctx;
    session_ctx->user_credentials = user_credentials;
    session_ctx->datastore = ds;

    int rc = SR_ERR_OK;
    session_ctx->session_modules = calloc(DM_DATASTORE_COUNT, sizeof(*session_ctx->session_modules));
    CHECK_NULL_NOMEM_GOTO(session_ctx->session_modules, rc, cleanup);

    for (size_t i = 0; i < DM_DATASTORE_COUNT; i++) {
        rc = sr_btree_init(dm_data_info_cmp, dm_data_info_free, &session_ctx->session_modules[i]);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Session module binary tree init failed");
    }

    rc = sr_list_init(&session_ctx->locked_files);
    CHECK_RC_MSG_GOTO(rc, cleanup, "List init failed");

    session_ctx->holds_ds_lock = calloc(DM_DATASTORE_COUNT, sizeof(*session_ctx->holds_ds_lock));
    CHECK_NULL_NOMEM_GOTO(session_ctx->holds_ds_lock, rc, cleanup);
    session_ctx->operations = calloc(DM_DATASTORE_COUNT, sizeof(*session_ctx->operations));
    CHECK_NULL_NOMEM_GOTO(session_ctx->operations, rc, cleanup);
    session_ctx->oper_count = calloc(DM_DATASTORE_COUNT, sizeof(*session_ctx->oper_count));
    CHECK_NULL_NOMEM_GOTO(session_ctx->oper_count, rc, cleanup);
    session_ctx->oper_size = calloc(DM_DATASTORE_COUNT, sizeof(*session_ctx->oper_size));
    CHECK_NULL_NOMEM_GOTO(session_ctx->oper_size, rc, cleanup);


cleanup:
    if (SR_ERR_OK == rc) {
        *dm_session_ctx = session_ctx;
    } else {
        dm_session_stop((dm_ctx_t *) dm_ctx, session_ctx);
    }
    return rc;
}

void
dm_session_stop(dm_ctx_t *dm_ctx, dm_session_t *session)
{
    CHECK_NULL_ARG_VOID2(dm_ctx, session);
    if (NULL != session->locked_files) {
        dm_unlock_datastore(dm_ctx, session);
        sr_list_cleanup(session->locked_files);
    }
    for (size_t i = 0; i < DM_DATASTORE_COUNT; i++) {
        sr_btree_cleanup(session->session_modules[i]);
    }
    free(session->session_modules);
    dm_clear_session_errors(session);
    for (size_t i = 0; i < DM_DATASTORE_COUNT; i++) {
        dm_free_sess_operations(session->operations[i], session->oper_count[i]);
    }
    free(session->holds_ds_lock);
    free(session->operations);
    free(session->oper_count);
    free(session->oper_size);
    free(session);
}

/**
 * @brief Removes not enabled leaves from data tree.
 *
 * @note Function expects that a schema info is locked for reading.
 *
 * @param [in] info
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_remove_not_enabled_nodes(dm_data_info_t *info)
{
    CHECK_NULL_ARG(info);
    struct lyd_node *iter = NULL, *child = NULL, *next = NULL;
    sr_list_t *stack = NULL;
    int rc = SR_ERR_OK;

    rc = sr_list_init(&stack);
    CHECK_RC_MSG_RETURN(rc, "List init failed");

    /* iterate through top-level nodes */
    LY_TREE_FOR_SAFE(info->node, next, iter)
    {
        if (((LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST) & iter->schema->nodetype)) {
            if (dm_is_node_enabled(iter->schema)) {
                if (!dm_is_node_enabled_with_children(iter->schema) && (LYS_CONTAINER | LYS_LIST) & iter->schema->nodetype) {
                    LY_TREE_FOR(iter->child, child)
                    {
                        if (((LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST) & iter->schema->nodetype) && dm_is_node_enabled(child->schema)) {
                            rc = sr_list_add(stack, child);
                            CHECK_RC_MSG_GOTO(rc, cleanup, "Adding to sr_list failed");
                        }
                    }
                }
            } else {
                sr_lyd_unlink(info, iter);
                lyd_free_withsiblings(iter);
            }

        }
    }

    while (stack->count != 0) {
        iter = stack->data[stack->count - 1];
        if (dm_is_node_enabled(iter->schema)) {
            if (!dm_is_node_enabled_with_children(iter->schema) && (LYS_CONTAINER | LYS_LIST) & iter->schema->nodetype) {

                LY_TREE_FOR(iter->child, child)
                {
                    if (((LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST) & iter->schema->nodetype)) {
                        rc = sr_list_add(stack, child);
                        CHECK_RC_MSG_GOTO(rc, cleanup, "Adding to sr_list failed");
                    }
                }
            }
        } else {
            sr_lyd_unlink(info, iter);
            lyd_free_withsiblings(iter);
        }
        sr_list_rm(stack, iter);
    }

cleanup:
    sr_list_cleanup(stack);
    return rc;
}


/**
 * @brief Test if there is not enabled leaf in the provided data tree
 *
 * @note Function expects that a schema info is locked for reading.
 *
 * @param [in] info
 * @param [out] res
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_has_not_enabled_nodes(dm_data_info_t *info, bool *res)
{
    CHECK_NULL_ARG2(info, res);
    struct lyd_node *iter = NULL, *child = NULL, *next = NULL;
    sr_list_t *stack = NULL;
    int rc = SR_ERR_OK;

    rc = sr_list_init(&stack);
    CHECK_RC_MSG_RETURN(rc, "List init failed");

    /* iterate through top-level nodes */
    LY_TREE_FOR_SAFE(info->node, next, iter)
    {
        if (((LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST) & iter->schema->nodetype)) {
            if (dm_is_node_enabled(iter->schema) || iter->dflt) {
                if (!dm_is_node_enabled_with_children(iter->schema) && (LYS_CONTAINER | LYS_LIST) & iter->schema->nodetype) {
                    LY_TREE_FOR(iter->child, child)
                    {
                        if (((LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST) & iter->schema->nodetype)) {
                            rc = sr_list_add(stack, child);
                            CHECK_RC_MSG_GOTO(rc, cleanup, "Adding to sr_list failed");
                        }
                    }
                }
            } else {
                SR_LOG_DBG("Found not enabled node %s in module %s", iter->schema->name, iter->schema->module->name);
                *res = true;
                goto cleanup;
            }

        }
    }

    while (stack->count != 0) {
        iter = stack->data[stack->count - 1];
        if (dm_is_node_enabled(iter->schema) || iter->dflt) {
            if (!dm_is_node_enabled_with_children(iter->schema) && (LYS_CONTAINER | LYS_LIST) & iter->schema->nodetype) {

                LY_TREE_FOR(iter->child, child)
                {
                    if (((LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST) & iter->schema->nodetype)) {
                        rc = sr_list_add(stack, child);
                        CHECK_RC_MSG_GOTO(rc, cleanup, "Adding to sr_list failed");
                    }
                }
            }
        } else {
            SR_LOG_DBG("Found not enabled node %s in module %s", iter->schema->name, iter->schema->module->name);
            *res = true;
            goto cleanup;
        }
        sr_list_rm(stack, iter);
    }
    *res = false;

cleanup:
    sr_list_cleanup(stack);
    return rc;
}

int
dm_get_data_info(dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx, const char *module_name, dm_data_info_t **info)
{
    CHECK_NULL_ARG4(dm_ctx, dm_session_ctx, module_name, info);
    int rc = SR_ERR_OK;
    dm_data_info_t *exisiting_data_info = NULL;
    dm_schema_info_t *schema_info = NULL;

    rc = dm_get_module_and_lock(dm_ctx, module_name, &schema_info);
    CHECK_RC_LOG_RETURN(rc, "Get module '%s' failed", module_name);

    dm_data_info_t lookup_data = {0};
    lookup_data.schema = schema_info;
    exisiting_data_info = sr_btree_search(dm_session_ctx->session_modules[dm_session_ctx->datastore], &lookup_data);

    if (NULL != exisiting_data_info) {
        *info = exisiting_data_info;
        SR_LOG_DBG("Module %s already loaded", module_name);
        goto cleanup;
    }

    /* session copy not found load it from file system */
    dm_data_info_t *di = NULL;
    if (SR_DS_CANDIDATE == dm_session_ctx->datastore) {
        rc = dm_load_data_tree(dm_ctx, dm_session_ctx, schema_info, SR_DS_RUNNING, &di);
        CHECK_RC_LOG_GOTO(rc, cleanup, "Getting data tree for %s failed.", module_name);
        rc = dm_remove_not_enabled_nodes(di);
        if (SR_ERR_OK != rc) {
            dm_data_info_free(di);
            SR_LOG_ERR("Removing of not enabled nodes in model %s failed", di->schema->module->name);
            goto cleanup;
        }
    }
    else {
        rc = dm_load_data_tree(dm_ctx, dm_session_ctx, schema_info, dm_session_ctx->datastore, &di);
        CHECK_RC_LOG_GOTO(rc, cleanup, "Getting data tree for %s failed.", module_name);
    }

    rc = sr_btree_insert(dm_session_ctx->session_modules[dm_session_ctx->datastore], (void *) di);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Insert into session avl failed module %s", module_name);
        dm_data_info_free(di);
        goto cleanup;
    }

    SR_LOG_DBG("Module %s has been loaded", module_name);
    *info = di;

cleanup:
    pthread_rwlock_unlock(&schema_info->model_lock);
    return rc;
}

int
dm_get_datatree(dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx, const char *module_name, struct lyd_node **data_tree)
{
    CHECK_NULL_ARG4(dm_ctx, dm_session_ctx, module_name, data_tree);
    int rc = SR_ERR_OK;
    dm_data_info_t *info = NULL;
    rc = dm_get_data_info(dm_ctx, dm_session_ctx, module_name, &info);
    CHECK_RC_LOG_RETURN(rc, "Get data info failed for module %s", module_name);
    *data_tree = info->node;
    if (NULL == info->node) {
        return SR_ERR_NOT_FOUND;
    }
    return rc;
}

static int
dm_get_module_internal(dm_ctx_t *dm_ctx, const char *module_name, bool lock, bool write, dm_schema_info_t **schema_info)
{
    CHECK_NULL_ARG3(dm_ctx, module_name, schema_info);

    int rc = SR_ERR_OK;
    dm_schema_info_t lookup = {0};
    dm_schema_info_t *sch_info = NULL;

    lookup.module_name = (char *) module_name;
    RWLOCK_RDLOCK_TIMED_CHECK_RETURN(&dm_ctx->schema_tree_lock);
    sch_info = sr_btree_search(dm_ctx->schema_info_tree, &lookup);

    if (NULL != sch_info) {
        /* there is matching item in schema info tree */
        if (lock) {

            if (write) {
                RWLOCK_WRLOCK_TIMED_CHECK_GOTO(&sch_info->model_lock, rc, cleanup);
            } else {
                RWLOCK_RDLOCK_TIMED_CHECK_GOTO(&sch_info->model_lock, rc, cleanup);
            }

            if (NULL == sch_info->ly_ctx) {
                SR_LOG_DBG("Module %s has been uninstalled", sch_info->module_name);
                pthread_rwlock_unlock(&sch_info->model_lock);
                rc = SR_ERR_UNKNOWN_MODEL;
                goto cleanup;
            }
        }
        *schema_info = sch_info;
        goto cleanup;
    } else {
        /* try to load schema */
        pthread_rwlock_unlock(&dm_ctx->schema_tree_lock);
        rc = dm_load_module(dm_ctx, module_name, NULL, &sch_info);
        if (SR_ERR_OK == rc && lock) {
            if (write) {
                RWLOCK_WRLOCK_TIMED_CHECK_GOTO(&sch_info->model_lock, rc, cleanup);
            } else {
                RWLOCK_RDLOCK_TIMED_CHECK_GOTO(&sch_info->model_lock, rc, cleanup);
            }

            if (NULL == sch_info->ly_ctx) {
                SR_LOG_DBG("Module %s has been uninstalled", sch_info->module_name);
                pthread_rwlock_unlock(&sch_info->model_lock);
                rc = SR_ERR_UNKNOWN_MODEL;
            } else {
                *schema_info = sch_info;
            }

        }
    }

    return rc;

cleanup:
    pthread_rwlock_unlock(&dm_ctx->schema_tree_lock);
    return rc;
}

int
dm_get_module_and_lockw(dm_ctx_t *dm_ctx, const char *module_name, dm_schema_info_t **schema_info)
{
    return dm_get_module_internal(dm_ctx, module_name, true, true, schema_info);
}

int
dm_get_module_and_lock(dm_ctx_t *dm_ctx, const char *module_name, dm_schema_info_t **schema_info)
{
    return dm_get_module_internal(dm_ctx, module_name, true, false, schema_info);
}

int
dm_get_module_without_lock(dm_ctx_t *dm_ctx, const char *module_name, dm_schema_info_t **schema_info)
{
    CHECK_NULL_ARG3(dm_ctx, module_name, schema_info);
    int rc = SR_ERR_OK;

    rc = dm_get_module_and_lock(dm_ctx, module_name, schema_info);
    if (SR_ERR_OK == rc) {
        pthread_rwlock_unlock(&(*schema_info)->model_lock);
    }
    return rc;
}

static int
dm_list_rev_file(dm_ctx_t *dm_ctx, sr_mem_ctx_t *sr_mem, const char *module_name, const char *rev_date, sr_sch_revision_t *rev)
{
    CHECK_NULL_ARG3(dm_ctx, module_name, rev);
    int rc = SR_ERR_OK;
    char *file_name = NULL;

    if (NULL != rev_date && 0 != strcmp("", rev_date)) {
        sr_mem_edit_string(sr_mem, (char **)&rev->revision, rev_date);
        CHECK_NULL_NOMEM_GOTO(rev->revision, rc, cleanup);
    }

    rc = sr_get_schema_file_name(dm_ctx->schema_search_dir, module_name, rev_date, true, &file_name);
    if (SR_ERR_OK == rc) {
        if (-1 != access(file_name, F_OK)) {
            rc = sr_mem_edit_string(sr_mem, (char **)&rev->file_path_yang, file_name);
        }
    }
    CHECK_RC_MSG_GOTO(rc, cleanup, "Get schema file name failed");

    free(file_name);
    file_name = NULL;

    rc = sr_get_schema_file_name(dm_ctx->schema_search_dir, module_name, rev_date, false, &file_name);
    if (SR_ERR_OK == rc) {
        if (-1 != access(file_name, F_OK)) {
            sr_mem_edit_string(sr_mem, (char **)&rev->file_path_yin, file_name);
        }
    }
    CHECK_RC_MSG_GOTO(rc, cleanup, "Get schema file name failed");

    free(file_name);
    return rc;

cleanup:
    free(file_name);
    if (NULL == sr_mem) {
        free((void*) rev->revision);
        free((void*) rev->file_path_yang);
        free((void*) rev->file_path_yin);
    }
    return rc;
}

/**
 * @brief Fills the schema_t structure for one module all its revisions and submodules
 * @param [in] dm_ctx
 * @param [in] module
 * @param [in] schs
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_list_module(dm_ctx_t *dm_ctx, md_module_t *module, sr_schema_t *schema)
{
    CHECK_NULL_ARG3(dm_ctx, module, schema);
    int rc = SR_ERR_OK;
    bool module_enabled = false;
    size_t enabled_subtrees_cnt = 0;
    char **enabled_subtrees = NULL;
    sr_llist_node_t *dep = NULL;
    md_dep_t *dep_mod = NULL;
    size_t submod_cnt = 0;
    sr_mem_ctx_t *sr_mem = schema->_sr_mem;

    sr_mem_edit_string(sr_mem, (char **)&schema->module_name, module->name);
    CHECK_NULL_NOMEM_GOTO(schema->module_name, rc, cleanup);

    sr_mem_edit_string(sr_mem, (char **)&schema->ns, module->ns);
    CHECK_NULL_NOMEM_GOTO(schema->ns, rc, cleanup);

    sr_mem_edit_string(sr_mem, (char **)&schema->prefix, module->prefix);
    CHECK_NULL_NOMEM_GOTO(schema->prefix, rc, cleanup);

    rc = dm_list_rev_file(dm_ctx, sr_mem, module->name, module->revision_date, &schema->revision);
    CHECK_RC_LOG_GOTO(rc, cleanup, "List rev file failed module %s", module->name);

    dep = module->deps->first;
    while (NULL != dep) {
        dep_mod = (md_dep_t *) dep->data;
        dep = dep->next;
        if (!dep_mod->dest->submodule) {
            continue;
        }
        submod_cnt++;
    }

    if (0 < submod_cnt) {
        schema->submodules = sr_calloc(sr_mem, submod_cnt, sizeof(*schema->submodules));
        CHECK_NULL_NOMEM_GOTO(schema->submodules, rc, cleanup);
    }

    dep = module->deps->first;
    size_t s = 0;
    while (NULL != dep) {
        dep_mod = (md_dep_t *) dep->data;
        dep = dep->next;
        if (!dep_mod->dest->submodule) {
            continue;
        }
        sr_mem_edit_string(sr_mem, (char **)&schema->submodules[s].submodule_name, dep_mod->dest->name);
        CHECK_NULL_NOMEM_GOTO(schema->submodules[s].submodule_name, rc, cleanup);

        rc = dm_list_rev_file(dm_ctx, sr_mem, dep_mod->dest->name, dep_mod->dest->revision_date, &schema->submodules[s].revision);
        CHECK_RC_LOG_GOTO(rc, cleanup, "List rev file failed module %s", module->name);

        schema->submodule_count++;
        s++;
    }

    rc = pm_get_module_info(dm_ctx->pm_ctx, module->name, sr_mem, &module_enabled,
            &enabled_subtrees, &enabled_subtrees_cnt, &schema->enabled_features, &schema->enabled_feature_cnt);
    if (SR_ERR_OK == rc) {
        /* release memory */
        for (size_t i = 0; i < enabled_subtrees_cnt; i++) {
            free(enabled_subtrees[i]);
        }
        free(enabled_subtrees);
    } else {
        /* ignore errors in pm */
        rc = SR_ERR_OK;
    }

cleanup:
    if (SR_ERR_OK != rc) {
        sr_free_schema(schema);
    }
    return rc;
}

int
dm_list_schemas(dm_ctx_t *dm_ctx, dm_session_t *dm_session, sr_schema_t **schemas, size_t *schema_count)
{
    CHECK_NULL_ARG4(dm_ctx, dm_session, schemas, schema_count);
    int rc = SR_ERR_OK;
    md_module_t *module = NULL;
    sr_llist_node_t *module_ll_node = NULL;
    size_t i = 0;

    sr_schema_t *sch = NULL;
    size_t sch_count = 0;
    sr_mem_ctx_t *sr_mem = NULL;

    md_ctx_lock(dm_ctx->md_ctx, false);
    module_ll_node = dm_ctx->md_ctx->modules->first;
    while (module_ll_node) {
        module = (md_module_t *) module_ll_node->data;
        module_ll_node = module_ll_node->next;
        if (module->submodule) {
            continue;
        }
        sch_count++;
    }
    if (0 == sch_count) {
        goto cleanup;
    }

    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    sch = sr_calloc(sr_mem, sch_count, sizeof(*sch));
    CHECK_NULL_NOMEM_GOTO(sch, rc, cleanup);

    module_ll_node = dm_ctx->md_ctx->modules->first;
    while (module_ll_node) {
        module = (md_module_t *) module_ll_node->data;
        module_ll_node = module_ll_node->next;
        if (module->submodule) {
            /* skip submodules */
            continue;
        }

        sch[i]._sr_mem = sr_mem;
        rc = dm_list_module(dm_ctx, module, &sch[i]);
        CHECK_RC_LOG_GOTO(rc, cleanup, "List module %s failed", module->name);

        i++;
    }

cleanup:
    md_ctx_unlock(dm_ctx->md_ctx);
    if (SR_ERR_OK == rc) {
        if (NULL != sr_mem) {
            sr_mem->obj_count = 1; /* 1 for the entire array */
        }
        *schemas = sch;
        *schema_count = sch_count;
    } else {
        sr_mem_free(sr_mem);
    }
    return rc;
}

int
dm_get_schema(dm_ctx_t *dm_ctx, const char *module_name, const char *module_revision, const char *submodule_name, bool yang_format, char **schema)
{
    CHECK_NULL_ARG3(dm_ctx, module_name, schema);
    int rc = SR_ERR_OK;
    int ret = 0;
    dm_schema_info_t *si = NULL;
    const struct lys_module *module = NULL;
    md_module_t *md_module = NULL;
    sr_llist_node_t *dep_node = NULL;
    md_dep_t *dependency = NULL;
    const char *main_module = module_name;

    SR_LOG_INF("Get schema '%s', revision: '%s', submodule: '%s'", module_name, module_revision, submodule_name);

    md_ctx_lock(dm_ctx->md_ctx, false);
    rc = md_get_module_info(dm_ctx->md_ctx, module_name, module_revision, &md_module);

    if (NULL != md_module && !md_module->latest_revision) {
        /* find a module in latest revision that includes the requested module
         * this handles the case that requested module is included in older revision by other module */
        dep_node = md_module->inv_deps->first;
        while (NULL != dep_node) {
            dependency = dep_node->data;
            dep_node = dep_node->next;
            if (!dependency->dest->submodule && dependency->dest->latest_revision) {
                main_module = dependency->dest->name;
                break;
            }
        }
    }

    md_ctx_unlock(dm_ctx->md_ctx);
    CHECK_RC_LOG_RETURN(rc, "Module %s in revision %s not found", module_name, module_revision);

    rc = dm_get_module_and_lock(dm_ctx, main_module, &si);
    CHECK_RC_LOG_RETURN(rc, "Get module failed for %s", module_name);

    if (NULL != submodule_name) {
        module = (const struct lys_module *) ly_ctx_get_submodule(si->ly_ctx, module_name, module_revision, submodule_name, NULL);
    } else {
        module = ly_ctx_get_module(si->ly_ctx, module_name, module_revision);
    }

    if (NULL == module) {
        SR_LOG_ERR("Not found module %s submodule %s revision %s", module_name, submodule_name, module_revision);
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }
    ret = lys_print_mem(schema, module, yang_format ? LYS_OUT_YANG : LYS_OUT_YIN, NULL);
    CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_INTERNAL, cleanup, "Module %s print failed.", si->module_name);

cleanup:
    pthread_rwlock_unlock(&si->model_lock);
    return rc;
}

int
dm_validate_session_data_trees(dm_ctx_t *dm_ctx, dm_session_t *session, sr_error_info_t **errors, size_t *err_cnt)
{
    CHECK_NULL_ARG4(dm_ctx, session, errors, err_cnt);
    int rc = SR_ERR_OK, rc_tmp = SR_ERR_OK;

    size_t cnt = 0;
    *err_cnt = 0;
    dm_data_info_t *info = NULL;
    sr_llist_t *session_modules = NULL;
    sr_llist_node_t *node = NULL;

    rc = sr_llist_init(&session_modules);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot initialize temporary linked-list for session modules.");

    /* collect the list of modules first, it may change during the validation */
    while (NULL != (info = sr_btree_get_at(session->session_modules[session->datastore], cnt))) {
        sr_llist_add_new(session_modules, info);
        cnt++;
    }

    node = session_modules->first;
    while (NULL != node) {
        info = (dm_data_info_t *)node->data;
        /* loaded data trees are valid, so check only the modified ones */
        if (info->modified) {
            if (NULL == info->schema->module || NULL == info->schema->module->name) {
                SR_LOG_ERR_MSG("Missing schema information");
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            /* attach data dependant modules */
            if (info->schema->cross_module_data_dependency) {
                rc = dm_load_dependant_data(dm_ctx, session, info);
                CHECK_RC_LOG_GOTO(rc, cleanup, "Loading dependant modules failed for %s", info->schema->module_name);
            }
            if (0 != lyd_validate(&info->node, LYD_OPT_STRICT | LYD_OPT_NOAUTODEL | LYD_OPT_CONFIG, info->schema->ly_ctx)) {
                SR_LOG_DBG("Validation failed for %s module", info->schema->module->name);
                if (SR_ERR_OK != sr_add_error(errors, err_cnt, ly_errpath(), "%s", ly_errmsg())) {
                    SR_LOG_WRN_MSG("Failed to record validation error");
                }
                rc = SR_ERR_VALIDATION_FAILED;
            } else {
                SR_LOG_DBG("Validation succeeded for '%s' module", info->schema->module->name);
            }
            if (info->schema->cross_module_data_dependency) {
                /* remove data appended from other modules for the purpose of validation */
                rc_tmp = dm_remove_added_data_trees(session, info);
                CHECK_RC_MSG_RETURN(rc_tmp, "Removing of added data trees failed");
            }
        }
        node = node->next;
    }

cleanup:
    if (SR_ERR_OK != rc && SR_ERR_VALIDATION_FAILED != rc) {
        sr_free_errors(*errors, *err_cnt);
    }
    sr_llist_cleanup(session_modules);
    return rc;
}

int
dm_discard_changes(dm_ctx_t *dm_ctx, dm_session_t *session)
{
    CHECK_NULL_ARG2(dm_ctx, session);
    int rc = SR_ERR_OK;

    sr_btree_cleanup(session->session_modules[session->datastore]);
    session->session_modules[session->datastore] = NULL;

    rc = sr_btree_init(dm_data_info_cmp, dm_data_info_free, &session->session_modules[session->datastore]);
    CHECK_RC_MSG_RETURN(rc, "Binary tree allocation failed");
    dm_free_sess_operations(session->operations[session->datastore], session->oper_count[session->datastore]);
    session->operations[session->datastore] = NULL;
    session->oper_count[session->datastore] = 0;
    session->oper_size[session->datastore] = 0;

    return SR_ERR_OK;
}

int
dm_remove_modified_flag(dm_session_t* session)
{
    int rc = SR_ERR_OK;
    dm_data_info_t *info = NULL;
    size_t cnt = 0;
    while (NULL != (info = sr_btree_get_at(session->session_modules[session->datastore], cnt))) {
        /* remove modified flag */
        info->modified = false;
        cnt++;
    }
    return rc;
}

int
dm_remove_session_operations(dm_session_t *session)
{
    CHECK_NULL_ARG(session);
    while (session->oper_count[session->datastore] > 0) {
        dm_remove_last_operation(session);
    }
    return SR_ERR_OK;
}

static int
dm_is_info_copy_uptodate(dm_ctx_t *dm_ctx, const char *file_name, const dm_data_info_t *info, bool *res)
{
    CHECK_NULL_ARG4(dm_ctx, file_name, info, res);
    int rc = SR_ERR_OK;
#ifdef HAVE_STAT_ST_MTIM
    struct stat st = {0};
    rc = stat(file_name, &st);
    if (-1 == rc) {
        SR_LOG_ERR_MSG("Stat failed");
        return SR_ERR_INTERNAL;
    }
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    SR_LOG_DBG("Session copy %s: mtime sec=%lld nsec=%lld", info->schema->module->name,
            (long long) info->timestamp.tv_sec,
            (long long) info->timestamp.tv_nsec);
    SR_LOG_DBG("Loaded module %s: mtime sec=%lld nsec=%lld", info->schema->module->name,
            (long long) st.st_mtim.tv_sec,
            (long long) st.st_mtim.tv_nsec);
    SR_LOG_DBG("Current time: mtime sec=%lld nsec=%lld",
            (long long) now.tv_sec,
            (long long) now.tv_nsec);
    /* check if we should update session copy conditions
     * is the negation of the optimized commit */
    if (info->timestamp.tv_sec != st.st_mtim.tv_sec ||
            info->timestamp.tv_nsec != st.st_mtim.tv_nsec ||
            (now.tv_sec == st.st_mtim.tv_sec && difftime(now.tv_nsec, st.st_mtim.tv_nsec) < NANOSEC_THRESHOLD) ||
            info->timestamp.tv_sec < dm_ctx->last_commit_time.tv_sec ||
            (info->timestamp.tv_sec == dm_ctx->last_commit_time.tv_sec && info->timestamp.tv_nsec <= dm_ctx->last_commit_time.tv_nsec) ||
            info->timestamp.tv_nsec == 0) {
        SR_LOG_DBG("Module %s will be refreshed", info->schema->module->name);
        *res = false;

    } else {
        *res = true;
    }
#else
    *res = false;
#endif
    return rc;

}

int
dm_update_session_data_trees(dm_ctx_t *dm_ctx, dm_session_t *session, sr_list_t **up_to_date_models)
{
    CHECK_NULL_ARG3(dm_ctx, session, up_to_date_models);
    int rc = SR_ERR_OK;
    int fd = -1;
    char *file_name = NULL;
    dm_data_info_t *info = NULL;
    size_t i = 0;
    sr_list_t *to_be_refreshed = NULL, *up_to_date = NULL;
    rc = sr_list_init(&to_be_refreshed);
    CHECK_RC_MSG_GOTO(rc, cleanup, "List init failed");

    rc = sr_list_init(&up_to_date);
    CHECK_RC_MSG_GOTO(rc, cleanup, "List init failed");

    while (NULL != (info = sr_btree_get_at(session->session_modules[session->datastore], i++))) {
        rc = sr_get_data_file_name(dm_ctx->data_search_dir,
                info->schema->module->name,
                SR_DS_CANDIDATE == session->datastore ? SR_DS_RUNNING : session->datastore,
                &file_name);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Get data file name failed");
        ac_set_user_identity(dm_ctx->ac_ctx, session->user_credentials);
        fd = open(file_name, O_RDONLY);
        ac_unset_user_identity(dm_ctx->ac_ctx);

        if (-1 == fd) {
            SR_LOG_DBG("File %s can not be opened for read write", file_name);
            if (EACCES == errno) {
                SR_LOG_WRN("File %s can not be opened because of authorization", file_name);
            } else if (ENOENT == errno) {
                SR_LOG_DBG("File %s does not exist, trying to create an empty one", file_name);
            }
            /* skip data trees that was not successfully opened */
            free(file_name);
            file_name = NULL;
            continue;
        }

        /* lock for read, blocking - guards access to the file among processes.
         * Inside the process access to data files is protected by commit_lock in rp.
         * Each request that might need to read data file locks it for read at the beginning
         * of request processing. */
        rc = sr_lock_fd(fd, false, true);

        bool copy_uptodate = false;
        rc = dm_is_info_copy_uptodate(dm_ctx, file_name, info, &copy_uptodate);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("File up to date check failed");
            close(fd);
            goto cleanup;
        }

        if (copy_uptodate) {
            if (info->modified) {
                rc = sr_list_add(up_to_date, (void *) info->schema->module->name);
            }
        } else {
            SR_LOG_DBG("Module %s will be refreshed", info->schema->module->name);
            rc = sr_list_add(to_be_refreshed, info);
        }
        free(file_name);
        file_name = NULL;
        close(fd);

        CHECK_RC_MSG_GOTO(rc, cleanup, "List add failed");

    }

    for (i = 0; i < to_be_refreshed->count; i++) {
        sr_btree_delete(session->session_modules[session->datastore], to_be_refreshed->data[i]);
    }

cleanup:
    sr_list_cleanup(to_be_refreshed);
    if (SR_ERR_OK == rc) {
        *up_to_date_models = up_to_date;
    } else {
        sr_list_cleanup(up_to_date);
    }
    free(file_name);
    return rc;
}

void
dm_remove_operations_with_error(dm_session_t *session)
{
    CHECK_NULL_ARG_VOID(session);
    for (int i = session->oper_count[session->datastore] - 1; i >= 0; i--) {
        dm_sess_op_t *op = &session->operations[session->datastore][i];
        if (op->has_error) {
            dm_free_sess_op(op);
            memmove(&session->operations[session->datastore][i],
                    &session->operations[session->datastore][i + 1],
                    (session->oper_count[session->datastore] - i - 1) * sizeof(*op));
            session->oper_count[session->datastore]--;
        }
    }
}

/**
 * @brief whether the node match the subscribed one - if it is the same node or children
 * of the subscribed one
 * @param [in] sub_node
 * @param [in] node tested node
 * @param [out] res
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_match_subscription(const struct lys_node *sub_node, const struct lyd_node *node, bool *res)
{
    CHECK_NULL_ARG2(node, res);

    if (NULL == sub_node) {
        *res = true;
        return SR_ERR_OK;
    }

    /* check if a node has been changes under subscriptions */
    struct lys_node *n = (struct lys_node *) node->schema;
    while (NULL != n) {
        if (sub_node == n) {
            *res = true;
            return SR_ERR_OK;
        }
        n = lys_parent(n);
    }

    /* if a container/list has been created/deleted check if there
     * a more specific subscription
     * e.g: subscription to /container/list/leaf
     *      container has been deleted
     */
    if ((LYS_CONTAINER | LYS_LIST) & node->schema->nodetype) {
        struct lys_node *n = (struct lys_node *) sub_node;
        bool subsc_under_modif = false;
        while (NULL != n) {
            if (node->schema == n) {
                subsc_under_modif = true;
                break;
            }
            n = lys_parent(n);
        }

        if (!subsc_under_modif) {
            goto not_matched;
        }

        /* check whether a subscribed children has been created/deleted */
        struct lyd_node *next = NULL, *iter = NULL;
        LY_TREE_DFS_BEGIN((struct lyd_node *) node, next, iter){
            if (sub_node == iter->schema){
                *res = true;
                return SR_ERR_OK;
            }
            LYD_TREE_DFS_END(node, next, iter);
        }

    }

not_matched:
    *res = false;
    return SR_ERR_OK;
}

/**
 * @brief Returns the node to be tested whether the changes matches the subscription
 * @param [in] diff
 * @param [in] index
 * @return  Schema node of the change
 */
static const struct lyd_node *
dm_get_notification_match_node(struct lyd_difflist *diff, size_t index)
{
    if (NULL == diff) {
        return NULL;
    }
    switch (diff->type[index]) {
    case LYD_DIFF_MOVEDAFTER2:
    case LYD_DIFF_CREATED:
        return diff->second[index];
    case LYD_DIFF_MOVEDAFTER1:
    case LYD_DIFF_CHANGED:
    case LYD_DIFF_DELETED:
        return diff->first[index];
    default:
        /* LYD_DIFF_END */
        return NULL;
    }
}

/**
 * @brief Returns the xpath of the change
 * @param [in] diff
 * @param [in] index
 * @return Allocated xpath of the changed node
 */
static char *
dm_get_notification_changed_xpath(struct lyd_difflist *diff, size_t index)
{
    if (NULL == diff) {
        return NULL;
    }
    switch (diff->type[index]) {
    case LYD_DIFF_MOVEDAFTER2:
    case LYD_DIFF_CREATED:
        return lyd_path(diff->second[index]);
    case LYD_DIFF_MOVEDAFTER1:
    case LYD_DIFF_CHANGED:
    case LYD_DIFF_DELETED:
        return lyd_path(diff->first[index]);
    default:
        /* LYD_DIFF_END */
        return NULL;
    }
}

/**
 * @brief Returns string representation of the change type
 * @param [in] type
 * @return statically allocated string
 */
static const char *
dm_get_diff_type_to_string(LYD_DIFFTYPE type)
{
    const char *diff_states[] = {
        "End",      /* LYD_DIFF_END = 0*/
        "Deleted",  /* LYD_DIFF_DELETED */
        "Changed",  /* LYD_DIFF_CHANGED */
        "Moved1",   /* LYD_DIFF_MOVEDAFTER1 */
        "Created",  /* LYD_DIFF_CREATED */
        "Moved2",   /* LYD_DIFF_MOVEDAFTER2 */
    };
    if (type >= sizeof(diff_states)/sizeof(*diff_states)){
        return "Unknown";
    }
    return diff_states[type];
}

/**
 * @brief Compares subscriptions by priority.
 */
int
dm_subs_cmp(const void *a, const void *b)
{
    np_subscription_t **sub_a = (np_subscription_t **) a;
    np_subscription_t **sub_b = (np_subscription_t **) b;

    if ((*sub_b)->priority == (*sub_a)->priority) {
        return 0;
    } else if ((*sub_b)->priority > (*sub_a)->priority) {
        return 1;
    } else {
        return -1;
    }
}

/**
 *
 * @note Function acquires and releases read lock for the schema info.
 *
 * @param dm_ctx
 * @param schema_info
 * @param model_sub
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_prepare_module_subscriptions(dm_ctx_t *dm_ctx, dm_schema_info_t *schema_info, dm_model_subscription_t **model_sub)
{
    CHECK_NULL_ARG3(dm_ctx, schema_info, model_sub);
    int rc = SR_ERR_OK;
    dm_model_subscription_t *ms = NULL;

    ms = calloc(1, sizeof(*ms));
    CHECK_NULL_NOMEM_RETURN(ms);

    pthread_rwlock_init(&ms->changes_lock, NULL);

    rc = np_get_module_change_subscriptions(dm_ctx->np_ctx,
            schema_info->module_name,
            &ms->subscriptions,
            &ms->subscription_cnt);

    CHECK_RC_LOG_GOTO(rc, cleanup, "Get module subscription failed for module %s", schema_info->module_name);

    qsort(ms->subscriptions, ms->subscription_cnt, sizeof(*ms->subscriptions), dm_subs_cmp);

    ms->nodes = calloc(ms->subscription_cnt, sizeof(*ms->nodes));
    CHECK_NULL_NOMEM_GOTO(ms->nodes, rc, cleanup);

    for (size_t s = 0; s < ms->subscription_cnt; s++) {
        if (NULL == ms->subscriptions[s]->xpath) {
            ms->nodes[s] = NULL;
        } else {
            rc = rp_dt_validate_node_xpath(dm_ctx, NULL,
                    ms->subscriptions[s]->xpath,
                    NULL,
                    &ms->nodes[s]);
            if (SR_ERR_OK != rc || NULL == ms->nodes[s]) {
                SR_LOG_WRN("Node for xpath %s has not been found", ms->subscriptions[s]->xpath);
            }
        }
    }

    ms->schema_info = schema_info;

cleanup:
    if (SR_ERR_OK != rc) {
        dm_model_subscription_free(ms);
    } else {
        *model_sub = ms;
    }
    return rc;
}

void
dm_free_commit_context(void *commit_ctx)
{
    if (NULL != commit_ctx) {
        dm_commit_context_t *c_ctx = commit_ctx;
        for (size_t i = 0; i < c_ctx->modif_count; i++) {
            close(c_ctx->fds[i]);
        }
        pthread_mutex_destroy(&c_ctx->mutex);
        free(c_ctx->fds);
        free(c_ctx->existed);
        sr_list_cleanup(c_ctx->up_to_date_models);
        c_ctx->up_to_date_models = NULL;
        c_ctx->fds = NULL;
        c_ctx->existed = NULL;
        c_ctx->modif_count = 0;

        sr_btree_cleanup(c_ctx->subscriptions);
        sr_btree_cleanup(c_ctx->prev_data_trees);
        if (NULL != c_ctx->session) {
            dm_session_stop(c_ctx->session->dm_ctx, c_ctx->session);
        }
        if (NULL != c_ctx->err_subs_xpaths) {
            for (size_t i = 0; i < c_ctx->err_subs_xpaths->count; i++) {
                free(c_ctx->err_subs_xpaths->data[i]);
            }
            sr_list_cleanup(c_ctx->err_subs_xpaths);
        }
        if (NULL != c_ctx->errors && 0 != c_ctx->err_cnt) {
            sr_free_errors(c_ctx->errors, c_ctx->err_cnt);
        }
        c_ctx->session = NULL;
        free(c_ctx);
    }
}

static int
dm_insert_commit_context(dm_ctx_t *dm_ctx, dm_commit_context_t *c_ctx)
{
    CHECK_NULL_ARG2(dm_ctx, c_ctx);
    int rc = SR_ERR_OK;
    pthread_rwlock_wrlock(&dm_ctx->commit_ctxs.lock);
    rc = sr_btree_insert(dm_ctx->commit_ctxs.tree, c_ctx);
    pthread_rwlock_unlock(&dm_ctx->commit_ctxs.lock);
    return rc;
}

static int
dm_remove_commit_context(dm_ctx_t *dm_ctx, uint32_t c_ctx_id)
{
    pthread_rwlock_wrlock(&dm_ctx->commit_ctxs.lock);
    dm_commit_context_t *c_ctx = NULL;
    dm_commit_context_t lookup = {0};
    lookup.id = c_ctx_id;
    c_ctx = sr_btree_search(dm_ctx->commit_ctxs.tree, &lookup);
    if (NULL == c_ctx) {
        SR_LOG_WRN("Commit context with id %d not found", c_ctx_id);
    } else {
        sr_btree_delete(dm_ctx->commit_ctxs.tree, c_ctx);
        SR_LOG_DBG("Commit context with id %"PRIu32" removed", c_ctx_id);
    }
    pthread_rwlock_unlock(&dm_ctx->commit_ctxs.lock);
    return SR_ERR_OK;
}

int
dm_commit_notifications_complete(dm_ctx_t *dm_ctx, uint32_t c_ctx_id)
{
    return dm_remove_commit_context(dm_ctx, c_ctx_id);
}

/**
 * @brief Releases resources that are no more needed after SR_EV_APPLY or SR_EV_ABORT
 *
 */
static int
dm_release_resources_commit_context(dm_ctx_t *dm_ctx, dm_commit_context_t *c_ctx)
{
    CHECK_NULL_ARG(c_ctx);
    for (size_t i = 0; i < c_ctx->modif_count; i++) {
        close(c_ctx->fds[i]);
    }
    free(c_ctx->fds);
    free(c_ctx->existed);
    sr_list_cleanup(c_ctx->up_to_date_models);
    c_ctx->up_to_date_models = NULL;
    c_ctx->fds = NULL;
    c_ctx->existed = NULL;
    c_ctx->modif_count = 0;

    dm_unlock_datastore(dm_ctx, c_ctx->session);

    return SR_ERR_OK;
}

int
dm_save_commit_context(dm_ctx_t *dm_ctx, dm_commit_context_t *c_ctx)
{
    CHECK_NULL_ARG(c_ctx);
    int rc = SR_ERR_OK;
    /* assign id to the commit context and save it to th dm_ctx */
    rc = dm_insert_commit_context(dm_ctx, c_ctx);

    return rc;

}

int
dm_commit_prepare_context(dm_ctx_t *dm_ctx, dm_session_t *session, dm_commit_context_t **commit_ctx)
{
    CHECK_NULL_ARG2(session, commit_ctx);
    dm_data_info_t *info = NULL;
    size_t i = 0;
    int rc = SR_ERR_OK;
    dm_model_subscription_t *ms = NULL;
    dm_commit_context_t *c_ctx = NULL;
    c_ctx = calloc(1, sizeof(*c_ctx));
    CHECK_NULL_NOMEM_RETURN(c_ctx);

    size_t attempts = 0;
    /* generate unique id */
    do {
        c_ctx->id = rand();
        if (NULL != sr_btree_search(dm_ctx->commit_ctxs.tree, c_ctx)) {
            c_ctx->id = DM_COMMIT_CTX_ID_INVALID;
        }
        if (++attempts > DM_COMMIT_CTX_ID_MAX_ATTEMPTS) {
            SR_LOG_ERR_MSG("Unable to generate an unique session_id.");
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
    } while (DM_COMMIT_CTX_ID_INVALID == c_ctx->id);

    pthread_mutex_init(&c_ctx->mutex, NULL);

    rc = sr_btree_init(dm_module_subscription_cmp, dm_model_subscription_free, &c_ctx->subscriptions);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Binary tree allocation failed");

    rc = sr_btree_init(dm_data_info_cmp, dm_data_info_free, &c_ctx->prev_data_trees);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Binary tree allocation failed");

    c_ctx->modif_count = 0;
    /* count modified files */
    while (NULL != (info = sr_btree_get_at(session->session_modules[session->datastore], i))) {
        if (info->modified) {
            c_ctx->modif_count++;

            if (SR_DS_STARTUP != session->datastore) {
                rc = dm_prepare_module_subscriptions(dm_ctx, info->schema, &ms);
                CHECK_RC_LOG_GOTO(rc, cleanup, "Prepare module subscription failed %s", info->schema->module->name);

                rc = sr_btree_insert(c_ctx->subscriptions, ms);
                CHECK_RC_LOG_GOTO(rc, cleanup, "Insert into subscription tree failed module %s", info->schema->module->name);
            }
            ms = NULL;
        }
        i++;
    }

    SR_LOG_DBG("Commit: In the session there are %zu / %zu modified models", c_ctx->modif_count, i);

    if (0 == session->oper_count[session->datastore] && 0 != c_ctx->modif_count && SR_DS_CANDIDATE != session->datastore) {
        SR_LOG_WRN_MSG("No operation logged, however data tree marked as modified");
        c_ctx->modif_count = 0;
        *commit_ctx = c_ctx;
        return SR_ERR_OK;
    }

    c_ctx->fds = calloc(c_ctx->modif_count, sizeof(*c_ctx->fds));
    CHECK_NULL_NOMEM_GOTO(c_ctx->fds, rc, cleanup);
    c_ctx->existed = calloc(c_ctx->modif_count, sizeof(*c_ctx->existed));
    CHECK_NULL_NOMEM_GOTO(c_ctx->existed, rc, cleanup);

    /* create commit session */
    rc = dm_session_start(dm_ctx, session->user_credentials, SR_DS_CANDIDATE == session->datastore ? SR_DS_RUNNING : session->datastore, &c_ctx->session);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Commit session initialization failed");

    rc = sr_list_init(&c_ctx->up_to_date_models);
    CHECK_RC_MSG_GOTO(rc, cleanup, "List init failed");

    /* set pointer to the list of operations to be committed */
    c_ctx->operations = session->operations[session->datastore];
    c_ctx->oper_count = session->oper_count[session->datastore];

    *commit_ctx = c_ctx;
    return rc;

cleanup:
    c_ctx->modif_count = 0; /* no fd to be closed*/
    dm_model_subscription_free(ms);
    dm_free_commit_context(c_ctx);
    return rc;
}

/**
 * @brief Acquires locks that are needed to commit changes into the datastore
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] c_ctx
 * @param [in] module_name
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_commit_lock_model(dm_ctx_t *dm_ctx, dm_session_t *session, dm_commit_context_t *c_ctx, const char *module_name)
{
    CHECK_NULL_ARG4(dm_ctx, session, c_ctx, module_name);
    int rc = SR_ERR_OK;
    if (SR_DS_CANDIDATE == session->datastore) {
        /* acquire candidate lock*/
        dm_session_switch_ds(c_ctx->session, SR_DS_CANDIDATE);
        rc = dm_lock_module(dm_ctx, c_ctx->session, module_name);
        if (SR_ERR_LOCKED == rc) {
            /* check if the lock is hold by session that issued commit */
            rc = dm_lock_module(dm_ctx, session, module_name);
        }
        dm_session_switch_ds(c_ctx->session, SR_DS_RUNNING);
        CHECK_RC_LOG_RETURN(rc, "Failed to lock %s in candidate ds", module_name);
        /* acquire running lock*/
        rc = dm_lock_module(dm_ctx, c_ctx->session, module_name);
        if (SR_ERR_LOCKED == rc) {
            /* check if the lock is hold by session that issued commit */
            dm_session_switch_ds(session, SR_DS_RUNNING);
            rc = dm_lock_module(dm_ctx, session, module_name);
            dm_session_switch_ds(session, SR_DS_CANDIDATE);
        }
        CHECK_RC_LOG_RETURN(rc, "Failed to lock %s in running ds", module_name);
    } else {
        /* in case of startup/running ds acquire only startup/running lock*/
        rc = dm_lock_module(dm_ctx, c_ctx->session, module_name);
        if (SR_ERR_LOCKED == rc) {
            /* check if the lock is hold by session that issued commit */
            rc = dm_lock_module(dm_ctx, session, module_name);
        }
    }
    return rc;
}

int
dm_commit_load_modified_models(dm_ctx_t *dm_ctx, const dm_session_t *session, dm_commit_context_t *c_ctx,
        sr_error_info_t **errors, size_t *err_cnt)
{
    CHECK_NULL_ARG3(c_ctx, errors, err_cnt);
    CHECK_NULL_ARG5(dm_ctx, session, c_ctx->session, c_ctx->fds, c_ctx->existed);
    CHECK_NULL_ARG(c_ctx->up_to_date_models);
    dm_data_info_t *info = NULL;
    size_t i = 0;
    size_t count = 0;
    int rc = SR_ERR_OK;
    char *file_name = NULL;
    c_ctx->modif_count = 0; /* how many file descriptors should be closed on cleanup */

    /* lock models that should be committed */
    while (NULL != (info = sr_btree_get_at(session->session_modules[session->datastore], i++))) {
        if (!info->modified) {
            continue;
        }
        rc = dm_commit_lock_model(dm_ctx, (dm_session_t *) session, c_ctx, info->schema->module->name);
        CHECK_RC_LOG_RETURN(rc, "Module %s can not be locked", info->schema->module->name);
        if (SR_DS_CANDIDATE == session->datastore) {
            /* check if all subtrees are enabled */
            bool has_not_enabled = true;
            rc = dm_has_not_enabled_nodes(info, &has_not_enabled);
            CHECK_RC_LOG_RETURN(rc, "Has not enabled check failed for module %s", info->schema->module->name);
            if (has_not_enabled) {
#define ERR_FMT "There is a not enabled node in %s module, it can not be committed to the running"
                if (SR_ERR_OK != sr_add_error(errors, err_cnt, NULL, ERR_FMT, info->schema->module->name)) {
                    SR_LOG_WRN_MSG("Failed to record commit operation error");
                }
                SR_LOG_ERR(ERR_FMT, info->schema->module->name);
                return SR_ERR_OPERATION_FAILED;
#undef ERR_FMT
            }
        }
    }
    i = 0;

    ac_set_user_identity(dm_ctx->ac_ctx, session->user_credentials);

    while (NULL != (info = sr_btree_get_at(session->session_modules[session->datastore], i++))) {
        if (!info->modified) {
            continue;
        }
        rc = sr_get_data_file_name(dm_ctx->data_search_dir, info->schema->module->name, c_ctx->session->datastore, &file_name);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Get data file name failed");

        c_ctx->fds[count] = open(file_name, O_RDWR);
        if (-1 == c_ctx->fds[count]) {
            SR_LOG_DBG("File %s can not be opened for read write", file_name);
            if (EACCES == errno) {
#define ERR_FMT "File %s can not be opened because of authorization"
                if (SR_ERR_OK != sr_add_error(errors, err_cnt, NULL, ERR_FMT, file_name)) {
                    SR_LOG_WRN_MSG("Failed to record commit operation error");
                }
                SR_LOG_ERR(ERR_FMT, file_name);
                rc = SR_ERR_UNAUTHORIZED;
                goto cleanup;
#undef ERR_FMT
            }

            if (ENOENT == errno) {
                SR_LOG_DBG("File %s does not exist, trying to create an empty one", file_name);
                c_ctx->fds[count] = open(file_name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
                CHECK_NOT_MINUS1_LOG_GOTO(c_ctx->fds[count], rc, SR_ERR_IO, cleanup, "File %s can not be created", file_name);
            }
        } else {
            c_ctx->existed[count] = true;
        }
        /* file was opened successfully increment the number of files to be closed */
        c_ctx->modif_count++;
        /* try to lock for write, non-blocking */
        rc = sr_lock_fd(c_ctx->fds[count], true, false);
        if (SR_ERR_OK != rc) {
#define ERR_FMT "Locking of file '%s' failed: %s."
            if (SR_ERR_OK != sr_add_error(errors, err_cnt, NULL, ERR_FMT, file_name, sr_strerror(rc))) {
                SR_LOG_WRN_MSG("Failed to record commit operation error");
            }
            SR_LOG_ERR(ERR_FMT, file_name, sr_strerror(rc));
            rc = SR_ERR_OPERATION_FAILED;
            goto cleanup;
#undef ERR_FMT
        }
        dm_data_info_t *di = NULL;

        bool copy_uptodate = false;
        rc = dm_is_info_copy_uptodate(dm_ctx, file_name, info, &copy_uptodate);
        CHECK_RC_MSG_GOTO(rc, cleanup, "File up to date check failed");

        /* ops are skipped also when candidate is committed to the running */
        if (copy_uptodate || SR_DS_CANDIDATE == session->datastore) {
            SR_LOG_DBG("Timestamp for the model %s matches, ops will be skipped", info->schema->module->name);
            rc = sr_list_add(c_ctx->up_to_date_models, (void *) info->schema->module->name);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Adding to sr_list failed");

            di = calloc(1, sizeof(*di));
            CHECK_NULL_NOMEM_GOTO(di, rc, cleanup);
            di->node = sr_dup_datatree(info->node);
            if (NULL != info->node && NULL == di->node) {
                SR_LOG_ERR_MSG("Data tree duplication failed");
                rc = SR_ERR_INTERNAL;
                dm_data_info_free(di);
                goto cleanup;
            }
            pthread_mutex_lock(&info->schema->usage_count_mutex);
            info->schema->usage_count++;
            SR_LOG_DBG("Usage count %s incremented (value=%zu)", info->schema->module_name, info->schema->usage_count);
            pthread_mutex_unlock(&info->schema->usage_count_mutex);
            di->schema = info->schema;
        } else {
            /* if the file existed pass FILE 'r+', otherwise pass -1 because there is 'w' fd already */
            rc = dm_load_data_tree_file(dm_ctx, c_ctx->existed[count] ? c_ctx->fds[count] : -1, file_name, info->schema, &di);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Loading data file failed");
        }

        rc = sr_btree_insert(c_ctx->session->session_modules[c_ctx->session->datastore], (void *) di);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Insert into commit session avl failed module %s", info->schema->module->name);
            dm_data_info_free(di);
            goto cleanup;
        }

        if (SR_DS_STARTUP != session->datastore) {
            /* for candidate and running we save prev state */
            if (SR_DS_RUNNING != session->datastore || copy_uptodate) {
                /* load data tree from file system */
                rc = dm_load_data_tree_file(dm_ctx, c_ctx->existed[count] ? c_ctx->fds[count] : -1, file_name, info->schema, &di);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Loading data file failed");

                rc = sr_btree_insert(c_ctx->prev_data_trees, (void *) di);
                if (SR_ERR_OK != rc) {
                    SR_LOG_ERR("Insert into prev data trees failed module %s", info->schema->module->name);
                    dm_data_info_free(di);
                    goto cleanup;
                }
            } else {
                /* we can reuse data that were just read from file system */
                rc = dm_insert_data_info_copy(c_ctx->prev_data_trees, di);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Insert data info copy failed");
            }
        }

        free(file_name);
        file_name = NULL;

        count++;
    }

    ac_unset_user_identity(dm_ctx->ac_ctx);

    return rc;

cleanup:
    ac_unset_user_identity(dm_ctx->ac_ctx);
    free(file_name);
    return rc;
}

int
dm_commit_write_files(dm_session_t *session, dm_commit_context_t *c_ctx)
{
    CHECK_NULL_ARG2(session, c_ctx);
    int rc = SR_ERR_OK;
    int ret = 0;
    size_t i = 0;
    size_t count = 0;
    dm_data_info_t *info = NULL;

    /* write data trees */
    i = 0;
    dm_data_info_t *merged_info = NULL;
    while (NULL != (info = sr_btree_get_at(session->session_modules[session->datastore], i++))) {
        if (info->modified) {
            /* get merged info */
            merged_info = sr_btree_search(c_ctx->session->session_modules[c_ctx->session->datastore], info);
            if (NULL == merged_info) {
                SR_LOG_ERR("Merged data info %s not found", info->schema->module->name);
                rc = SR_ERR_INTERNAL;
                continue;
            }
            /* remove attached data trees */
            ret = dm_remove_added_data_trees(session, info);

            if (SR_ERR_OK == ret) {
                ret = ftruncate(c_ctx->fds[count], 0);
            }
            if (0 == ret) {
                ly_errno = LY_SUCCESS; /* needed to check if the error was in libyang or not below */
                ret = lyd_print_fd(c_ctx->fds[count], merged_info->node, LYD_XML, LYP_WITHSIBLINGS | LYP_FORMAT);
            }
            if (0 == ret) {
                ret = fsync(c_ctx->fds[count]);
            }
            if (0 != ret) {
                SR_LOG_ERR("Failed to write data of '%s' module: %s", info->schema->module->name,
                        (ly_errno != LY_SUCCESS) ? ly_errmsg() : sr_strerror_safe(errno));
                rc = SR_ERR_INTERNAL;
            } else {
                SR_LOG_DBG("Data successfully written for module '%s'", info->schema->module->name);
            }
            count++;
        }
    }
    /* save time of the last commit */
    sr_clock_get_time(CLOCK_REALTIME, &session->dm_ctx->last_commit_time);

    return rc;
}
/**
 * @brief Decides whether a subscription should be skipped or not. Takes into account:
 * SR_EV_VERIFY: skip SR_SUBSCR_APPLY_ONLY subscription
 * SR_EV_ABORT: skip subscription that returned an error
 */
static bool
dm_should_skip_subscription(np_subscription_t *subscription, dm_commit_context_t *c_ctx, sr_notif_event_t ev)
{
    if (NULL == subscription || NULL == c_ctx) {
        return false;
    }

    if (SR_EV_VERIFY == ev || SR_EV_ABORT == ev) {
        if (SR__NOTIFICATION_EVENT__VERIFY_EV != subscription->notif_event) {
            return true;
        }
    }

    /* if subscription returned an error don't send him abort */
    if (SR_EV_ABORT == ev && c_ctx->err_subs_xpaths != NULL) {
        for (size_t e = 0; e < c_ctx->err_subs_xpaths->count; e++) {
            if (0 == strcmp((char *) c_ctx->err_subs_xpaths->data[e],
                    NULL == subscription->xpath ?
                    subscription->module_name :
                    subscription->xpath)) {
                return true;
            }
        }
    }

    return false;
}

int
dm_commit_notify(dm_ctx_t *dm_ctx, dm_session_t *session, sr_notif_event_t ev, dm_commit_context_t *c_ctx)
{
    CHECK_NULL_ARG3(dm_ctx, session, c_ctx);
    int rc = SR_ERR_OK;
    size_t i = 0;
    dm_data_info_t *info = NULL, *commit_info = NULL, *prev_info = NULL, lookup_info = {0};
    dm_model_subscription_t *ms = NULL;
    bool match = false;
    sr_list_t *notified_notif = NULL;
    /* notification are sent only when running or candidate is committed*/
    if (SR_DS_STARTUP == session->datastore) {
        c_ctx->state = DM_COMMIT_WRITE;
        return SR_ERR_OK;
    }

    rc = sr_list_init(&notified_notif);
    CHECK_RC_MSG_RETURN(rc, "List init failed");

    SR_LOG_DBG("Sending %s notifications about the changes made in running datastore...", sr_notification_event_sr_to_str(ev));
    while (NULL != (info = sr_btree_get_at(session->session_modules[session->datastore], i++))) {
        if (!info->modified) {
            continue;
        }
        size_t d_cnt = 0;
        dm_model_subscription_t lookup = {0};
        struct lyd_difflist *diff = NULL;

        lookup.schema_info = info->schema;

        ms = sr_btree_search(c_ctx->subscriptions, &lookup);
        if (NULL == ms) {
            SR_LOG_WRN("No subscription found for %s", info->schema->module->name);
            lyd_free_diff(diff);
            continue;
        }

        /* changes are generated only for SR_EV_VERIFY and SR_EV_ABORT */
        if (SR_EV_VERIFY == ev || SR_EV_ABORT == ev) {
            lookup_info.schema = info->schema;
            /* configuration before commit */
            prev_info = sr_btree_search(c_ctx->prev_data_trees, &lookup_info);
            if (NULL == prev_info) {
                SR_LOG_ERR("Current data tree for module %s not found", info->schema->module->name);
                continue;
            }
            /* configuration after commit */
            commit_info = sr_btree_search(c_ctx->session->session_modules[c_ctx->session->datastore], &lookup_info);
            if (NULL == commit_info) {
                SR_LOG_ERR("Commit data tree for module %s not found", info->schema->module->name);
                continue;
            }

            /* for SR_EV_ABORT inverse changes are generated */
            diff = SR_EV_VERIFY == ev ?
                lyd_diff(prev_info->node, commit_info->node, LYD_DIFFOPT_WITHDEFAULTS) :
                lyd_diff(commit_info->node, prev_info->node, LYD_DIFFOPT_WITHDEFAULTS) ;
            if (NULL == diff) {
                SR_LOG_ERR("Lyd diff failed for module %s", info->schema->module->name);
                continue;
            }
            if (diff->type[d_cnt] == LYD_DIFF_END) {
                SR_LOG_DBG("No changes in module %s", info->schema->module->name);
                lyd_free_diff(diff);
                continue;
            }

            lyd_free_diff(ms->difflist);
            /* store differences in commit context */
            ms->difflist = diff;
        }

        /* Log changes */
        if (NULL != diff && (SR_LL_DBG == sr_ll_stderr || SR_LL_DBG == sr_ll_syslog)) {
            while (LYD_DIFF_END != diff->type[d_cnt]) {
                char *path = dm_get_notification_changed_xpath(diff, d_cnt);
                SR_LOG_DBG("%s: %s", dm_get_diff_type_to_string(diff->type[d_cnt]), path);
                free(path);
                d_cnt++;
            }
        }

        if (NULL == ms->difflist) {
            continue;
        }

        /* loop through subscription test if they should be notified */
        for (size_t s = 0; s < ms->subscription_cnt; s++) {
            if (dm_should_skip_subscription(ms->subscriptions[s], c_ctx, ev)) {
                continue;
            }

            for (d_cnt = 0; LYD_DIFF_END != ms->difflist->type[d_cnt]; d_cnt++) {
                const struct lyd_node *cmp_node = dm_get_notification_match_node(ms->difflist, d_cnt);
                rc = dm_match_subscription(ms->nodes[s], cmp_node, &match);
                if (SR_ERR_OK != rc) {
                    SR_LOG_WRN_MSG("Subscription match failed");
                    continue;
                }
                if (match) {
                    break;
                }
            }

            if (match) {
                /* something has been changed for this subscription, send notification */
                rc = np_subscription_notify(dm_ctx->np_ctx, ms->subscriptions[s], ev, c_ctx->id);
                if (SR_ERR_OK != rc) {
                   SR_LOG_WRN("Unable to send notifications about the changes for the subscription in module %s xpath %s.",
                           ms->subscriptions[s]->module_name,
                           ms->subscriptions[s]->xpath);
                }
                rc = sr_list_add(notified_notif, ms->subscriptions[s]);
                if (SR_ERR_OK != rc) {
                   SR_LOG_WRN_MSG("List add failed");
                }
            }
        }
    }

    if (SR_EV_VERIFY == ev) {
        rc = dm_save_commit_context(dm_ctx, c_ctx);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Saving of commit context failed");
        }
    } else {
        /* apply abort */
        dm_release_resources_commit_context(dm_ctx, c_ctx);
        rc = dm_save_commit_context(dm_ctx, c_ctx);
        /* if there is a verify subscription commit context is already saved */
        if (SR_ERR_DATA_EXISTS == rc) {
            rc = SR_ERR_OK;
        }
    }

    if (SR_EV_VERIFY == ev ){
        if (notified_notif->count > 0) {
            c_ctx->state = DM_COMMIT_WAIT_FOR_NOTIFICATIONS;
        } else {
            c_ctx->state = DM_COMMIT_WRITE;
        }
    } else {
        c_ctx->state = DM_COMMIT_FINISHED;
    }

    /* let the np know that the commit has finished */
    if (SR_ERR_OK == rc && notified_notif->count > 0) {
        rc = np_commit_notifications_sent(dm_ctx->np_ctx, c_ctx->id, SR_EV_VERIFY != ev, notified_notif);
    }

    sr_list_cleanup(notified_notif);
    return rc;
}

int
dm_feature_enable(dm_ctx_t *dm_ctx, const char *module_name, const char *feature_name, bool enable)
{
    CHECK_NULL_ARG3(dm_ctx, module_name, feature_name);
    int rc = SR_ERR_OK;
    dm_schema_info_t *schema_info = NULL;

    rc = dm_get_module_and_lockw(dm_ctx, module_name, &schema_info);
    CHECK_RC_LOG_RETURN(rc, "dm_get_module %s and lock failed", module_name);

    rc = dm_feature_enable_internal(dm_ctx, schema_info, module_name, feature_name, enable);

    pthread_rwlock_unlock(&schema_info->model_lock);

    return rc;
}

int
dm_install_module(dm_ctx_t *dm_ctx, const char *module_name, const char *revision, const char *file_name)
{
    CHECK_NULL_ARG3(dm_ctx, module_name, file_name); /* revision can be NULL */

    int rc = 0;
    md_module_t *module = NULL;
    md_dep_t *dep = NULL;
    sr_llist_node_t *ll_node = NULL;
    dm_schema_info_t *si = NULL, *si_ext = NULL;
    dm_schema_info_t lookup = {0};

    /* insert module into the dependency graph */
    md_ctx_lock(dm_ctx->md_ctx, true);
    pthread_rwlock_wrlock(&dm_ctx->schema_tree_lock);

    rc = md_insert_module(dm_ctx->md_ctx, file_name);
    if (SR_ERR_DATA_EXISTS == rc) {
        SR_LOG_WRN("Module '%s' is already installed", file_name);
        rc = SR_ERR_OK; /*< do not treat as error */
    }

    rc = md_get_module_info(dm_ctx->md_ctx, module_name, revision, &module);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Get module %s info failed", module_name);

    lookup.module_name = (char *) module_name;
    si = sr_btree_search(dm_ctx->schema_info_tree, &lookup);
    if (NULL != si) {
        RWLOCK_WRLOCK_TIMED_CHECK_GOTO(&si->model_lock, rc, cleanup);
        if (NULL != si->ly_ctx) {
            SR_LOG_WRN("Module %s already loaded", si->module_name);
            goto unlock;
        }
        /* load module and its dependencies into si */
        si->ly_ctx = ly_ctx_new(dm_ctx->schema_search_dir);
        CHECK_NULL_NOMEM_GOTO(si->ly_ctx, rc, unlock);

        rc = dm_load_schema_file(dm_ctx, module->filepath, true, &si);
        CHECK_RC_LOG_GOTO(rc, unlock, "Failed to load schema %s", module->filepath);

        si->module = ly_ctx_get_module(si->ly_ctx, module_name, NULL);
        if (NULL == si->module){
            rc = SR_ERR_INTERNAL;
            goto unlock;
        }

        ll_node = module->deps->first;
        while (ll_node) {
            dep = (md_dep_t *)ll_node->data;
            if (dep->type == MD_DEP_EXTENSION) {
                /* Note: imports are automatically loaded by libyang */
                rc = dm_load_schema_file(dm_ctx, dep->dest->filepath, true, &si);
                CHECK_RC_LOG_GOTO(rc, unlock, "Loading of %s was not successfull", dep->dest->name);
            }
            ll_node = ll_node->next;
        }

        /* load this module also into contexts of newly augmented modules */
        ll_node = module->inv_deps->first;
        while (ll_node) {
            dep = (md_dep_t *)ll_node->data;
            if (dep->type == MD_DEP_EXTENSION && true == dep->dest->latest_revision) {
                lookup.module_name = (char *)dep->dest->name;
                si_ext = sr_btree_search(dm_ctx->schema_info_tree, &lookup);
                if (NULL != si_ext && NULL != si_ext->ly_ctx) {
                    rc = dm_load_schema_file(dm_ctx, module->filepath, true, &si_ext);
                    CHECK_RC_LOG_GOTO(rc, unlock, "Failed to load schema %s", module->filepath);
                }
            }
            ll_node = ll_node->next;
        }
unlock:
        pthread_rwlock_unlock(&si->model_lock);
    } else {
        /* module is installed for the first time, will be loaded when a request
         * into this module is received */
        SR_LOG_DBG("Module %s will be loaded when a request for it comes", module_name);
    }
cleanup:
    pthread_rwlock_unlock(&dm_ctx->schema_tree_lock);
    md_ctx_unlock(dm_ctx->md_ctx);
    return rc;
}

int
dm_uninstall_module(dm_ctx_t *dm_ctx, const char *module_name, const char *revision)
{
    CHECK_NULL_ARG2(dm_ctx, module_name);
    int rc = SR_ERR_OK;
    md_module_t *module = NULL;
    dm_schema_info_t lookup = {0};
    dm_schema_info_t *schema_info = NULL;

    RWLOCK_RDLOCK_TIMED_CHECK_RETURN(&dm_ctx->schema_tree_lock);
    lookup.module_name = (char *) module_name;

    schema_info = sr_btree_search(dm_ctx->schema_info_tree, &lookup);
    if (NULL != schema_info) {
        pthread_rwlock_wrlock(&schema_info->model_lock);
        if (NULL != schema_info->ly_ctx){
            pthread_mutex_lock(&schema_info->usage_count_mutex);
            if (0 != schema_info->usage_count) {
                rc = SR_ERR_OPERATION_FAILED;
                SR_LOG_ERR("Module %s can not be uninstalled because it is being used. (referenced by %zu)", module_name, schema_info->usage_count);
            } else {
                ly_ctx_destroy(schema_info->ly_ctx, dm_free_lys_private_data);
                schema_info->ly_ctx = NULL;
                schema_info->module = NULL;
                SR_LOG_DBG("Module %s uninstalled", module_name);
            }
            pthread_mutex_unlock(&schema_info->usage_count_mutex);
        }
        pthread_rwlock_unlock(&schema_info->model_lock);
    } else {
        SR_LOG_DBG("Module %s is not loaded, can be uninstalled safely", module_name);
    }

    pthread_rwlock_unlock(&dm_ctx->schema_tree_lock);

    CHECK_RC_LOG_RETURN(rc, "Uninstallation of module %s was not successful", module_name);

    md_ctx_lock(dm_ctx->md_ctx, true);
    rc = md_get_module_info(dm_ctx->md_ctx, module_name, revision, &module);

    if (NULL == module) {
        SR_LOG_ERR("Module %s with revision %s was not found", module_name, revision);
        rc = SR_ERR_NOT_FOUND;
    } else {
        rc = md_remove_module(dm_ctx->md_ctx, module_name, revision);
    }

    md_ctx_unlock(dm_ctx->md_ctx);
    return rc;
}

static int
dm_copy_config(dm_ctx_t *dm_ctx, dm_session_t *session, const sr_list_t *module_names, sr_datastore_t src, sr_datastore_t dst)
{
    CHECK_NULL_ARG2(dm_ctx, module_names);
    int rc = SR_ERR_OK;
    dm_session_t *src_session = NULL;
    dm_session_t *dst_session = NULL;
    char *module_name = NULL;
    dm_data_info_t **src_infos = NULL;
    size_t opened_files = 0;
    char *file_name = NULL;
    int *fds = NULL;

    if (src == dst || 0 == module_names->count) {
        return rc;
    }

    src_infos = calloc(module_names->count, sizeof(*src_infos));
    CHECK_NULL_NOMEM_GOTO(src_infos, rc, cleanup);
    fds = calloc(module_names->count, sizeof(*fds));
    CHECK_NULL_NOMEM_GOTO(fds, rc, cleanup);

    /* create source session */
    if (SR_DS_CANDIDATE != src) {
        rc = dm_session_start(dm_ctx, (session != NULL ? session->user_credentials : NULL), src, &src_session);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Creating of temporary session failed");
    } else {
        src_session = session;
        sr_error_info_t *errors = NULL;
        size_t e_cnt = 0;
        rc = dm_validate_session_data_trees(dm_ctx, session, &errors, &e_cnt);
        if (SR_ERR_OK != rc) {
            rc = dm_report_error(session, errors[0].message, errors[0].xpath, SR_ERR_VALIDATION_FAILED);
            sr_free_errors(errors, e_cnt);
            SR_LOG_ERR_MSG("There is a invalid data tree, can not be copied");
            goto cleanup;
        }
    }

    /* create destination session */
    if (SR_DS_CANDIDATE != dst) {
        rc = dm_session_start(dm_ctx, (session != NULL ? session->user_credentials : NULL), dst, &dst_session);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Creating of temporary session failed");
    } else {
        dst_session = session;
    }

    for (size_t i = 0; i < module_names->count; i++) {
        module_name = module_names->data[i];
        /* lock module in source ds */
        if (SR_DS_CANDIDATE != src) {
            rc = dm_lock_module(dm_ctx, src_session, (char *) module_name);
            if (SR_ERR_LOCKED == rc && NULL != session && src == session->datastore) {
                /* check if the lock is hold by session that issued copy-config */
                rc = dm_lock_module(dm_ctx, session, (char *) module_name);
            }
            CHECK_RC_LOG_GOTO(rc, cleanup, "Module %s can not be locked in source datastore", module_name);
        }

        /* lock module in destination */
        if (SR_DS_CANDIDATE != dst) {
            rc = dm_lock_module(dm_ctx, dst_session, (char *) module_name);
            if (SR_ERR_LOCKED == rc && NULL != session && dst == session->datastore) {
                /* check if the lock is hold by session that issued copy-config */
                rc = dm_lock_module(dm_ctx, session, (char *) module_name);
            }
            CHECK_RC_LOG_GOTO(rc, cleanup, "Module %s can not be locked in destination datastore", module_name);
        }

        /* load data tree to be copied*/
        rc = dm_get_data_info(dm_ctx, src_session, module_name, &(src_infos[i]));
        CHECK_RC_MSG_GOTO(rc, cleanup, "Get data info failed");

        if (SR_DS_CANDIDATE != dst) {
            /* create data file name */
            rc = sr_get_data_file_name(dm_ctx->data_search_dir, module_name, dst_session->datastore, &file_name);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Get data file name failed");

            if (NULL != session) {
                ac_set_user_identity(dm_ctx->ac_ctx, session->user_credentials);
            }
            fds[opened_files] = open(file_name, O_RDWR | O_TRUNC);
            if (NULL != session) {
                ac_unset_user_identity(dm_ctx->ac_ctx);
            }
            if (-1 == fds[opened_files]) {
                SR_LOG_ERR("File %s can not be opened", file_name);
                free(file_name);
                goto cleanup;
            }
            opened_files++;
            free(file_name);
        }
    }

    int ret = 0;
    for (size_t i = 0; i < module_names->count; i++) {
        module_name = module_names->data[i];
        if (SR_DS_CANDIDATE != dst) {
            /* write dest file, dst is either startup or running*/
            if (0 != lyd_print_fd(fds[i], src_infos[i]->node, LYD_XML, LYP_WITHSIBLINGS | LYP_FORMAT)) {
                SR_LOG_ERR("Copy of module %s failed", module_name);
                rc = SR_ERR_INTERNAL;
            }
            ret = fsync(fds[i]);
            if (0 != ret) {
                SR_LOG_ERR("Failed to write data of '%s' module: %s", src_infos[i]->schema->module->name,
                        (ly_errno != LY_SUCCESS) ? ly_errmsg() : sr_strerror_safe(errno));
                rc = SR_ERR_INTERNAL;
            }
        } else {
            /* copy data tree into candidate session */
            struct lyd_node *dup = sr_dup_datatree(src_infos[i]->node);
            dm_data_info_t *di_tmp = NULL;
            if (NULL != src_infos[i]->node && NULL == dup) {
                SR_LOG_ERR("Duplication of data tree %s failed", src_infos[i]->schema->module->name);
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            /* load data tree to be copied*/
            rc = dm_get_data_info(dm_ctx, dst_session, module_name, &di_tmp);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Get data info failed");
            lyd_free_withsiblings(di_tmp->node);
            di_tmp->node = dup;
            di_tmp->modified = true;
        }
    }

    if (SR_DS_CANDIDATE == dst) {
        dm_remove_session_operations(dst_session);
    }

cleanup:
    if (SR_DS_CANDIDATE != src) {
        dm_session_stop(dm_ctx, src_session);
    }
    if (SR_DS_CANDIDATE != dst) {
        dm_session_stop(dm_ctx, dst_session);
    }
    for (size_t i = 0; i < opened_files; i++) {
        close(fds[i]);
    }
    free(fds);
    free(src_infos);
    return rc;
}

int
dm_has_state_data(dm_ctx_t *ctx, const char *module_name, bool *res)
{
    CHECK_NULL_ARG3(ctx, module_name, res);
    md_module_t *module = NULL;
    int rc = SR_ERR_OK;

    md_ctx_lock(ctx->md_ctx, false);
    rc = md_get_module_info(ctx->md_ctx, module_name, NULL, &module);
    if (SR_ERR_OK == rc) {
        *res = (module->op_data_subtrees->first != NULL);
    }
    md_ctx_unlock(ctx->md_ctx);

    return rc;
}

int
dm_has_enabled_subtree(dm_ctx_t *ctx, const char *module_name, dm_schema_info_t **schema, bool *res)
{
    CHECK_NULL_ARG3(ctx, module_name, res);
    int rc = SR_ERR_OK;
    dm_schema_info_t *schema_info = NULL;

    rc = dm_get_module_and_lock(ctx, module_name, &schema_info);
    CHECK_RC_MSG_RETURN(rc, "Get module failed");

    *res = false;
    struct lys_node *node = schema_info->module->data;

    while (NULL != node) {
        if (dm_is_enabled_check_recursively(node)) {
            *res = true;
            break;
        }
        node = node->next;
    }

    if (NULL != schema) {
        *schema = schema_info;
    }
    pthread_rwlock_unlock(&schema_info->model_lock);
    return rc;
}

int
dm_enable_module_running(dm_ctx_t *ctx, dm_session_t *session, const char *module_name,
        bool copy_from_startup)
{
    CHECK_NULL_ARG2(ctx, module_name); /* schema_info, session can be NULL */
    dm_schema_info_t *si = NULL;
    int rc = SR_ERR_OK;

    rc = dm_get_module_and_lockw(ctx, module_name, &si);
    CHECK_RC_LOG_RETURN(rc, "Lock schema %s for write failed", module_name);

    rc = dm_enable_module_running_internal(ctx, session, si, module_name);
    pthread_rwlock_unlock(&si->model_lock);
    CHECK_RC_LOG_RETURN(rc, "Enable module %s running failed", module_name);

    if (SR_ERR_OK == rc && copy_from_startup) {
        /* copy the config if requested - subscription does not contain SR_SUBSCR_PASSIVE flag */
        rc = dm_copy_module(ctx, session, module_name, SR_DS_STARTUP, SR_DS_RUNNING);
    }
    return rc;
}

/**
 * @brief Copies a subtree (specified by xpath) of configuration from startup to running. Replaces
 * the previous configuration under the xpath.
 *
 * @param [in] ctx
 * @param [in] session
 * @param [in] module
 * @param [in] xpath
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_copy_subtree_startup_running(dm_ctx_t *ctx, dm_session_t *session, const char *module_name, dm_schema_info_t *schema_info, const char *xpath)
{
    CHECK_NULL_ARG5(ctx, session, module_name, schema_info, xpath);
    int rc = SR_ERR_OK;
    struct ly_set *nodes = NULL;
    dm_session_t *tmp_session = NULL;
    dm_data_info_t *startup_info = NULL;
    dm_data_info_t *candidate_info = NULL;
    struct lyd_node *node = NULL, *parent = NULL;

    rc = dm_session_start(ctx, session->user_credentials, SR_DS_STARTUP, &tmp_session);
    CHECK_RC_MSG_RETURN(rc, "Failed to start a temporary session");

    /* select nodes by xpath from startup */
    rc = dm_get_data_info(ctx, tmp_session, module_name, &startup_info);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Get info for startup config failed");

    if (NULL == startup_info->node) {
        SR_LOG_DBG("Startup config for module '%s' is empty nothing to copy", module_name);
    }

    /* switch to candidate */
    tmp_session->datastore = SR_DS_CANDIDATE;
    rc = dm_get_data_info(ctx, tmp_session, module_name, &candidate_info);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Get info failed");

    /* remove previous config from running */
    SR_LOG_DBG("Remove previous content of running configuration under %s.", xpath);
    rc = rp_dt_delete_item(ctx, tmp_session, xpath, SR_EDIT_DEFAULT);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Delete of previous values in running failed xpath %s", xpath);

    /* select a part of configuration to be enabled */
    rc = rp_dt_find_nodes(ctx, startup_info->node, xpath, false, &nodes);
    if (SR_ERR_NOT_FOUND == rc) {
        SR_LOG_DBG("Subtree %s of enabled configuration is empty", xpath);
        rc = SR_ERR_OK;
    }
    CHECK_RC_MSG_GOTO(rc, cleanup, "Find nodes for configuration to be enabled failed");

    /* insert selected nodes */
    for (unsigned i = 0; NULL != nodes && i < nodes->number; i++) {
        node = nodes->set.d[i];
        if ((LYS_LEAF | LYS_LEAFLIST) & node->schema->nodetype) {
            char *node_xpath = lyd_path(node);
            CHECK_NULL_NOMEM_GOTO(node_xpath, rc, cleanup);
            dm_lyd_new_path(candidate_info, node_xpath,
                    ((struct lyd_node_leaf_list *) node)->value_str, LYD_PATH_OPT_UPDATE);
            free(node_xpath);
        } else {
            /* list or container */
            if (NULL != node->parent) {
                char *parent_xpath = lyd_path(node->parent);
                dm_lyd_new_path(candidate_info, parent_xpath, NULL, LYD_PATH_OPT_UPDATE);
                /* create or find parent node */
                rc = rp_dt_find_node(ctx, candidate_info->node, parent_xpath, false, &parent);
                free(parent_xpath);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to find parent node");
            }
            /* unlink data tree from session */
            sr_lyd_unlink(startup_info, node);

            /* attach to parent */
            if (NULL != parent) {
                if (0 != lyd_insert(parent, node)) {
                    SR_LOG_ERR_MSG("Node insert failed");
                    lyd_free_withsiblings(node);
                }
            } else {
                rc = sr_lyd_insert_after(candidate_info, candidate_info->node, node);
                if (SR_ERR_OK != rc) {
                    lyd_free_withsiblings(node);
                    SR_LOG_ERR_MSG("Node insert failed");
                }
            }
        }
    }

    /* copy module candidate -> running */
    rc = dm_copy_module(ctx, tmp_session, module_name, SR_DS_CANDIDATE, SR_DS_RUNNING);

cleanup:
    ly_set_free(nodes);
    dm_session_stop(ctx, tmp_session);

    return rc;
}

int
dm_enable_module_subtree_running(dm_ctx_t *ctx, dm_session_t *session, const char *module_name, const char *xpath,
        bool copy_from_startup)
{
    CHECK_NULL_ARG3(ctx, module_name, xpath); /* session can be NULL */
    dm_schema_info_t *si = NULL;
    int rc = SR_ERR_OK;

    rc = dm_get_module_and_lockw(ctx, module_name, &si);
    CHECK_RC_LOG_RETURN(rc, "Lock schema %s for write failed", module_name);

    rc = dm_enable_module_subtree_running_internal(ctx, session, si, module_name, xpath);
    pthread_rwlock_unlock(&si->model_lock);
    CHECK_RC_LOG_RETURN(rc, "Enabling of xpath %s failed", xpath);

    if (copy_from_startup) {
        rc = dm_copy_subtree_startup_running(ctx, session, module_name, si, xpath);
    }
    return rc;
}

int
dm_disable_module_running(dm_ctx_t *ctx, dm_session_t *session, const char *module_name)
{
    CHECK_NULL_ARG2(ctx, module_name);
    int rc = SR_ERR_OK;
    dm_schema_info_t *schema_info = NULL;

    rc = dm_get_module_and_lockw(ctx, module_name, &schema_info);
    CHECK_RC_LOG_RETURN(rc, "Get module failed for module %s", module_name);

    struct lys_node *iter = NULL, *child = NULL;
    sr_list_t *stack = NULL;
    rc = sr_list_init(&stack);
    CHECK_RC_MSG_RETURN(rc, "List init failed");

    /* iterate through top-level nodes */
    LY_TREE_FOR(schema_info->module->data, iter)
    {
        if (((LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST) & iter->nodetype) && dm_is_node_enabled(iter)) {
            rc = dm_set_node_state(iter, DM_NODE_DISABLED);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Set node state failed");

            if ((LYS_CONTAINER | LYS_LIST) & iter->nodetype) {
                LY_TREE_FOR(iter->child, child)
                {
                    if (((LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST) & iter->nodetype) && dm_is_node_enabled(child)) {
                        rc = sr_list_add(stack, child);
                        CHECK_RC_MSG_GOTO(rc, cleanup, "Adding to sr_list failed");
                    }
                }
            }
        }
    }

    /* recursively disable all enabled children*/
    while (stack->count != 0) {
        iter = stack->data[stack->count - 1];
        rc = dm_set_node_state(iter, DM_NODE_DISABLED);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Set node state failed");

        sr_list_rm_at(stack, stack->count - 1);

        if ((LYS_CONTAINER | LYS_LIST) & iter->nodetype) {

            LY_TREE_FOR(iter->child, child)
            {
                if (((LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST) & child->nodetype) && dm_is_node_enabled(child)) {
                    rc = sr_list_add(stack, child);
                    CHECK_RC_MSG_GOTO(rc, cleanup, "Adding to sr_list failed");
                }
            }
        }
    }
cleanup:
    pthread_rwlock_unlock(&schema_info->model_lock);
    sr_list_cleanup(stack);

    return rc;
}

int
dm_copy_module(dm_ctx_t *dm_ctx, dm_session_t *session, const char *module_name, sr_datastore_t src, sr_datastore_t dst)
{
    CHECK_NULL_ARG2(dm_ctx, module_name);
    sr_list_t *module_list = NULL;
    dm_schema_info_t *schema_info = NULL;
    int rc = SR_ERR_OK;

    rc = sr_list_init(&module_list);
    CHECK_RC_MSG_RETURN(rc, "List init failed");

    rc = dm_get_module_and_lock(dm_ctx, module_name, &schema_info);
    CHECK_RC_MSG_GOTO(rc, cleanup, "dm_get_module failed");

    rc = sr_list_add(module_list, schema_info->module_name);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Adding to sr_list failed");

    rc = dm_copy_config(dm_ctx, session, module_list, src, dst);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Dm copy config failed");

cleanup:
    if (NULL != schema_info) {
        pthread_rwlock_unlock(&schema_info->model_lock);
    }
    sr_list_cleanup(module_list);
    return rc;
}

int
dm_copy_all_models(dm_ctx_t *dm_ctx, dm_session_t *session, sr_datastore_t src, sr_datastore_t dst)
{
    CHECK_NULL_ARG2(dm_ctx, session);
    sr_list_t *enabled_modules = NULL;
    int rc = SR_ERR_OK;

    rc = dm_get_all_modules(dm_ctx, session, (SR_DS_RUNNING == src || SR_DS_RUNNING == dst), &enabled_modules);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Get all modules failed");

    rc = dm_copy_config(dm_ctx, session, enabled_modules, src, dst);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Dm copy config failed");

cleanup:
    sr_list_cleanup(enabled_modules);
    return rc;
}

/**
 * @brief Kind of procedure that DM can validate.
 */
typedef enum dm_procedure_e {
    DM_PROCEDURE_RPC,               /**< Remote procedure call */
    DM_PROCEDURE_EVENT_NOTIF,       /**< Event notification */
    DM_PROCEDURE_ACTION,            /**< NETCONF RPC operation connected to a specific data node. */
} dm_procedure_t;

/**
 * @brief Validates arguments of a procedure (RPC, Event notification, Action).
 * @param [in] dm_ctx DM context.
 * @param [in] session DM session.
 * @param [in] type Type of the procedure.
 * @param [in] xpath XPath of the procedure.
 * @param [in] api_variant Variant of the API (values vs. trees)
 * @param [in] args_p Input/output arguments of the procedure.
 * @param [in] arg_cnt_p Number of input/output arguments provided.
 * @param [in] input TRUE if input arguments were provided, FALSE if output.
 * @param [out] with_def Input/Output arguments including default values represented as sysrepo values.
 * @param [out] with_def_cnt Number of items inside the *with_def* array.
 * @param [out] with_def_tree Input/Output arguments including default values represented as sysrepo trees.
 * @param [out] with_def_tree_cnt Number of items inside the *with_def_tree* array.
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_validate_procedure(dm_ctx_t *dm_ctx, dm_session_t *session, dm_procedure_t type, const char *xpath,
        sr_api_variant_t api_variant, void *args_p, size_t arg_cnt, bool input,
        sr_mem_ctx_t *sr_mem, sr_val_t **with_def, size_t *with_def_cnt, sr_node_t **with_def_tree, size_t *with_def_tree_cnt)
{
    sr_val_t *args = NULL;
    sr_node_t *args_tree = NULL;
    dm_data_info_t *di = NULL;
    char root_xpath[PATH_MAX] = { 0, };
    const struct lys_node *proc_node = NULL, *arg_node = NULL, *node = NULL;
    struct lyd_node *data_tree = NULL, *new_node = NULL;
    char *string_value = NULL, *tmp_xpath = NULL;
    struct ly_set *nodeset = NULL;
    char *module_name = NULL;
    const char *procedure_name = NULL;
    int validation_options = 0;
    const char *last_delim = NULL;
    int ret = 0, rc = SR_ERR_OK;
    int allow_update = 0;
    bool ext_ref = false, backtracking = false;

    CHECK_NULL_ARG3(dm_ctx, session, xpath);

    if (SR_API_VALUES == api_variant) {
        args = (sr_val_t *)args_p;
    } else {
        args_tree = (sr_node_t *)args_p;
    }

    /* get name of the procedure - only for error messages */
    switch (type) {
        case DM_PROCEDURE_RPC:
            procedure_name = "RPC";
            break;
        case DM_PROCEDURE_EVENT_NOTIF:
            procedure_name = "Event notification";
            break;
        case DM_PROCEDURE_ACTION:
            procedure_name = "Action";
            break;
    }

    rc = sr_copy_first_ns(xpath, &module_name);
    CHECK_RC_MSG_RETURN(rc, "Error by extracting module name from xpath.");
    rc = dm_get_data_info(dm_ctx, session, module_name, &di);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Dm_get_dat_info failed for module %s", module_name);

    /* test for the presence of the procedure in the schema tree */
    proc_node = sr_find_schema_node(di->schema->module->data, xpath, 0);
    if (NULL == proc_node) {
        SR_LOG_ERR("%s xpath validation failed ('%s'): the target node is not present in the schema tree.",
                procedure_name, xpath);
        rc = dm_report_error(session, "target node is not present in the schema tree", xpath,
                SR_ERR_VALIDATION_FAILED);
        goto cleanup;
    }

    /* test for the presence of the procedure in the data tree */
    if (type == DM_PROCEDURE_EVENT_NOTIF || type == DM_PROCEDURE_ACTION) {
        last_delim = strrchr(xpath, '/');
        if (NULL == last_delim) {
            /* shouldn't really happen */
            SR_LOG_ERR("%s xpath validation failed ('%s'): missing forward slash.", procedure_name, xpath);
            rc = dm_report_error(session, "absolute xpath without a forward slash", xpath, SR_ERR_VALIDATION_FAILED);
            goto cleanup;
        }
        if (last_delim > xpath) {
            tmp_xpath = calloc(last_delim - xpath + 1, sizeof(*tmp_xpath));
            CHECK_NULL_NOMEM_GOTO(tmp_xpath, rc, cleanup);
            strncat(tmp_xpath, xpath, last_delim - xpath);
            nodeset = lyd_find_xpath(di->node, tmp_xpath);
            free(tmp_xpath);
            tmp_xpath = NULL;
            if (NULL == nodeset || 0 == nodeset->number) {
                SR_LOG_ERR("%s xpath validation failed ('%s'): the target node is not present in the data tree.",
                        procedure_name, xpath);
                ly_set_free(nodeset);
                rc = dm_report_error(session, "target node is not present in the data tree", xpath,
                        SR_ERR_VALIDATION_FAILED);
                goto cleanup;
            } else if (1 < nodeset->number) {
                SR_LOG_ERR("%s xpath validation failed ('%s'): xpath references more than one node in the data tree.",
                        procedure_name, xpath);
                ly_set_free(nodeset);
                rc = dm_report_error(session, "xpath references more than one node in the data tree.", xpath,
                        SR_ERR_VALIDATION_FAILED);
                goto cleanup;
            }
            ly_set_free(nodeset);
        }
    }

    /* converse sysrepo values/trees to libyang data tree */
    if (SR_API_VALUES == api_variant) {
        data_tree = lyd_new_path(NULL, di->schema->ly_ctx, xpath, NULL, 0, 0);
        if (NULL == data_tree) {
            SR_LOG_ERR("%s xpath validation failed ('%s'): %s", procedure_name, xpath, ly_errmsg());
            rc = dm_report_error(session, ly_errmsg(), xpath, SR_ERR_VALIDATION_FAILED);
            goto cleanup;
        }

        for (size_t i = 0; i < arg_cnt; i++) {
            /* get argument's schema node */
            arg_node = sr_find_schema_node(di->schema->module->data, args[i].xpath, (input ? 0 : LYS_FIND_OUTPUT));
            if (NULL == arg_node) {
                SR_LOG_ERR("%s argument xpath validation failed( '%s'): %s", procedure_name, args[i].xpath, ly_errmsg());
                rc = dm_report_error(session, ly_errmsg(), args[i].xpath, SR_ERR_VALIDATION_FAILED);
                goto cleanup;
            }
            /* copy argument value to string */
            string_value = NULL;
            if ((SR_CONTAINER_T != args[i].type) && (SR_LIST_T != args[i].type)) {
                rc = sr_val_to_str(&args[i], arg_node, &string_value);
                if (SR_ERR_OK != rc) {
                    SR_LOG_ERR("Unable to convert %s argument value to string.", procedure_name);
                    rc = dm_report_error(session, "Unable to convert argument value to string", args[i].xpath,
                            SR_ERR_VALIDATION_FAILED);
                    goto cleanup;
                }
            }

            allow_update = (LYS_LIST == arg_node->nodetype || sr_is_key_node(arg_node)) ? LYD_PATH_OPT_UPDATE : 0;

            /* create the argument node in the tree */
            new_node = lyd_new_path(data_tree, di->schema->ly_ctx, args[i].xpath, string_value, 0,
                                    (input ? allow_update : allow_update | LYD_PATH_OPT_OUTPUT));
            free(string_value);
            if (NULL == new_node && !allow_update) {
                SR_LOG_ERR("Unable to add new %s argument '%s': %s.", procedure_name, args[i].xpath, ly_errmsg());
                rc = dm_report_error(session, ly_errmsg(), ly_errpath(), SR_ERR_VALIDATION_FAILED);
                goto cleanup;
            }
        }
    } else { /**< SR_API_TREES */
        for (size_t i = 0; i < arg_cnt; i++) {
            snprintf(root_xpath, PATH_MAX, "%s/%s", xpath, args_tree[i].name);
            rc = sr_tree_to_dt(di->schema->ly_ctx, args_tree + i, root_xpath, !input, &data_tree);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Unable to convert sysrepo tree into a libyang tree ('%s').", root_xpath);
                rc = dm_report_error(session, "Unable to convert sysrepo tree into a libyang tree", root_xpath,
                        SR_ERR_VALIDATION_FAILED);
                goto cleanup;
            }
        }
    }

    /* validate the content (and also add default nodes) */
    if (arg_cnt > 0) {
        validation_options = LYD_OPT_STRICT | LYD_OPT_NOAUTODEL;
        switch (type) {
            case DM_PROCEDURE_RPC:
            case DM_PROCEDURE_ACTION:
                validation_options |= (input ? LYD_OPT_RPC : LYD_OPT_RPCREPLY);
                break;
            case DM_PROCEDURE_EVENT_NOTIF:
                validation_options |= LYD_OPT_NOTIF;
        }
        /* TODO: obtain a set of data trees referenced by when/must conditions inside RPC/notification */
        /* load necessary data trees */
        ext_ref = (proc_node->parent != NULL);
        backtracking = false;
        node = proc_node;
        while (false == ext_ref && (!backtracking || node != proc_node)) {
            if (false == backtracking) {
                if (node->flags & LYS_VALID_DEP) {
                    ext_ref = true; /* reference outside the procedure subtree */
                }
                if (node->child) {
                    node = node->child;
                } else if (node->next) {
                    node = node->next;
                } else {
                    backtracking = true;
                }
            } else {
                if (node->next) {
                    node = node->next;
                    backtracking = false;
                } else {
                    node = node->parent;
                }
            }
        }
        if (ext_ref && di->schema->cross_module_data_dependency) {
            rc = dm_load_dependant_data(dm_ctx, session, di);
            CHECK_RC_LOG_GOTO(rc, cleanup, "Loading dependant modules failed for %s", di->schema->module_name);
        }
        if (type == DM_PROCEDURE_ACTION && !input) {
            /* TODO: validation of action output is not yet covered by libyang,
             * see: https://github.com/CESNET/libyang/issues/153 */
            ret = 0;
        } else {
            ret = lyd_validate(&data_tree, validation_options, ext_ref ? di->node : NULL);
        }
        if (ext_ref && di->schema->cross_module_data_dependency) {
            /* remove data appended from other modules for the purpose of validation */
            rc = dm_remove_added_data_trees(session, di);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Removing of added data trees failed");
        }
        if (0 != ret) {
            SR_LOG_ERR("%s content validation failed: %s", procedure_name, ly_errmsg());
            rc = dm_report_error(session, ly_errmsg(), ly_errpath(), SR_ERR_VALIDATION_FAILED);
            goto cleanup;
        }
    }

    /* re-read the arguments from data tree (it can now contain newly added default nodes) */
    if (with_def && with_def_cnt) {
        *with_def = NULL;
        *with_def_cnt = 0;
    }
    if (with_def_tree && with_def_tree_cnt) {
        *with_def_tree = NULL;
        *with_def_tree_cnt = 0;
    }
    if (0 != arg_cnt) {
        if (with_def && with_def_cnt) {
            /* arguments with defaults as values */
            tmp_xpath = calloc(strlen(xpath)+4, sizeof(*tmp_xpath));
            CHECK_NULL_NOMEM_GOTO(tmp_xpath, rc, cleanup);
            if (NULL != tmp_xpath) {
                strcat(tmp_xpath, xpath);
                strcat(tmp_xpath, "//*");
                nodeset = lyd_find_xpath(data_tree, tmp_xpath);
                if (NULL != nodeset) {
                    rc = rp_dt_get_values_from_nodes(sr_mem, nodeset, with_def, with_def_cnt);
                } else {
                    SR_LOG_ERR("No matching nodes returned for xpath '%s'.", tmp_xpath);
                    rc = SR_ERR_INTERNAL;
                }
                ly_set_free(nodeset);
                free(tmp_xpath);
                tmp_xpath = NULL;
                if (SR_ERR_OK != rc) {
                    goto cleanup;
                }
            }
        }
        if (with_def_tree && with_def_tree_cnt) {
            /* arguments with defaults as trees */
            tmp_xpath = calloc(strlen(xpath) + 3 + (type != DM_PROCEDURE_EVENT_NOTIF ? 2 : 0),
                               sizeof(*tmp_xpath));
            CHECK_NULL_NOMEM_GOTO(tmp_xpath, rc, cleanup);
            if (NULL != tmp_xpath) {
                strcat(tmp_xpath, xpath);
                strcat(tmp_xpath, "/");
                if (type != DM_PROCEDURE_EVENT_NOTIF) {
                    strcat(tmp_xpath, "./"); /* skip "input" / "output" */
                }
                strcat(tmp_xpath, "*");
                nodeset = lyd_find_xpath(data_tree, tmp_xpath);
                if (NULL != nodeset) {
                    rc = sr_nodes_to_trees(nodeset, sr_mem, with_def_tree, with_def_tree_cnt);
                } else {
                    SR_LOG_ERR("No matching nodes returned for xpath '%s'.", tmp_xpath);
                    rc = SR_ERR_INTERNAL;
                }
                ly_set_free(nodeset);
                free(tmp_xpath);
                tmp_xpath = NULL;
                if (SR_ERR_OK != rc) {
                    goto cleanup;
                }
            }
        }
    }

cleanup:
    free(module_name);
    if (data_tree) {
        lyd_free_withsiblings(data_tree);
    }

    return rc;
}

int
dm_validate_rpc(dm_ctx_t *dm_ctx, dm_session_t *session, const char *rpc_xpath, sr_val_t *args, size_t arg_cnt, bool input,
        sr_mem_ctx_t *sr_mem, sr_val_t **with_def, size_t *with_def_cnt, sr_node_t **with_def_tree, size_t *with_def_tree_cnt)
{
    return dm_validate_procedure(dm_ctx, session, DM_PROCEDURE_RPC, rpc_xpath, SR_API_VALUES,
            (void *)args, arg_cnt, input, sr_mem, with_def, with_def_cnt, with_def_tree, with_def_tree_cnt);
}

int
dm_validate_rpc_tree(dm_ctx_t *dm_ctx, dm_session_t *session, const char *rpc_xpath, sr_node_t *args, size_t arg_cnt, bool input,
        sr_mem_ctx_t *sr_mem, sr_val_t **with_def, size_t *with_def_cnt, sr_node_t **with_def_tree, size_t *with_def_tree_cnt)
{
    return dm_validate_procedure(dm_ctx, session, DM_PROCEDURE_RPC, rpc_xpath, SR_API_TREES,
            (void *)args, arg_cnt, input, sr_mem, with_def, with_def_cnt, with_def_tree, with_def_tree_cnt);
}

int
dm_validate_action(dm_ctx_t *dm_ctx, dm_session_t *session, const char *action_xpath, sr_val_t *args, size_t arg_cnt, bool input,
        sr_mem_ctx_t *sr_mem, sr_val_t **with_def, size_t *with_def_cnt, sr_node_t **with_def_tree, size_t *with_def_tree_cnt)
{
    return dm_validate_procedure(dm_ctx, session, DM_PROCEDURE_ACTION, action_xpath, SR_API_VALUES,
            (void *)args, arg_cnt, input, sr_mem, with_def, with_def_cnt, with_def_tree, with_def_tree_cnt);
}

int
dm_validate_action_tree(dm_ctx_t *dm_ctx, dm_session_t *session, const char *action_xpath, sr_node_t *args, size_t arg_cnt, bool input,
        sr_mem_ctx_t *sr_mem, sr_val_t **with_def, size_t *with_def_cnt, sr_node_t **with_def_tree, size_t *with_def_tree_cnt)
{
    return dm_validate_procedure(dm_ctx, session, DM_PROCEDURE_ACTION, action_xpath, SR_API_TREES,
            (void *)args, arg_cnt, input, sr_mem, with_def, with_def_cnt, with_def_tree, with_def_tree_cnt);
}

int
dm_validate_event_notif(dm_ctx_t *dm_ctx, dm_session_t *session, const char *event_notif_xpath, sr_val_t *values, size_t value_cnt,
        sr_mem_ctx_t *sr_mem, sr_val_t **with_def, size_t *with_def_cnt, sr_node_t **with_def_tree, size_t *with_def_tree_cnt)
{
    return dm_validate_procedure(dm_ctx, session, DM_PROCEDURE_EVENT_NOTIF, event_notif_xpath, SR_API_VALUES,
            (void *)values, value_cnt, true, sr_mem, with_def, with_def_cnt, with_def_tree, with_def_tree_cnt);
}

int
dm_validate_event_notif_tree(dm_ctx_t *dm_ctx, dm_session_t *session, const char *event_notif_xpath, sr_node_t *trees, size_t tree_cnt,
        sr_mem_ctx_t *sr_mem, sr_val_t **with_def, size_t *with_def_cnt, sr_node_t **with_def_tree, size_t *with_def_tree_cnt)
{
    return dm_validate_procedure(dm_ctx, session, DM_PROCEDURE_EVENT_NOTIF, event_notif_xpath, SR_API_TREES,
            (void *)trees, tree_cnt, true, sr_mem, with_def, with_def_cnt, with_def_tree, with_def_tree_cnt);
}

struct lyd_node *
dm_lyd_new_path(dm_data_info_t *data_info, const char *path, const char *value, int options)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_ARG_NORET2(rc, data_info, path);
    if (SR_ERR_OK != rc){
        return NULL;
    }

    struct lyd_node *new = NULL;
    new = lyd_new_path(data_info->node, data_info->schema->ly_ctx, path, (void *)value, 0, options);
    if (NULL == data_info->node) {
        data_info->node = new;
    }

    return new;
}

int
dm_copy_modified_session_trees(dm_ctx_t *dm_ctx, dm_session_t *from, dm_session_t *to)
{
    CHECK_NULL_ARG3(dm_ctx, from, to);
    int rc = SR_ERR_OK;
    size_t i = 0;
    dm_data_info_t *info = NULL;
    dm_data_info_t *new_info = NULL;
    while (NULL != (info = sr_btree_get_at(from->session_modules[from->datastore], i++))) {
        if (!info->modified) {
            continue;
        }
        bool existed = true;
        new_info = sr_btree_search(to->session_modules[to->datastore], info);
        if (NULL == new_info) {
            existed = false;
            new_info = calloc(1, sizeof(*new_info));
            CHECK_NULL_NOMEM_RETURN(new_info);
        }

        new_info->modified = info->modified;
        new_info->schema = info->schema;
        new_info->timestamp = info->timestamp;
        lyd_free_withsiblings(new_info->node);
        new_info->node = NULL;
        if (NULL != info->node) {
            new_info->node = sr_dup_datatree(info->node);
        }

        if (!existed) {
            pthread_mutex_lock(&info->schema->usage_count_mutex);
            info->schema->usage_count++;
            SR_LOG_DBG("Usage count %s deccremented (value=%zu)", info->schema->module_name, info->schema->usage_count);
            pthread_mutex_unlock(&info->schema->usage_count_mutex);

            rc = sr_btree_insert(to->session_modules[to->datastore], new_info);
            CHECK_RC_MSG_GOTO(rc, fail, "Adding data tree to session modules failed");
        }
    }
    return rc;

fail:
    dm_data_info_free(new_info);
    return rc;
}

int
dm_copy_session_tree(dm_ctx_t *dm_ctx, dm_session_t *from, dm_session_t *to, const char *module_name)
{
    CHECK_NULL_ARG4(dm_ctx, from, to, module_name);
    int rc = SR_ERR_OK;
    dm_data_info_t *info = NULL;
    dm_data_info_t lookup = {0};
    dm_data_info_t *new_info = NULL;
    dm_schema_info_t *schema_info = NULL;
    struct lyd_node *tmp_node = NULL;
    bool existed = true;

    rc = dm_get_module_and_lock(dm_ctx, module_name, &schema_info);
    CHECK_RC_LOG_RETURN(rc, "Get module %s failed.", module_name);

    lookup.schema = schema_info;

    info = sr_btree_search(from->session_modules[from->datastore], &lookup);
    pthread_rwlock_unlock(&schema_info->model_lock);
    if (NULL == info) {
        SR_LOG_DBG("Module %s not loaded in source session", module_name);
        return rc;
    }

    new_info = sr_btree_search(to->session_modules[to->datastore], &lookup);
    if (NULL == new_info) {
        existed = false;
        new_info = calloc(1, sizeof(*new_info));
        CHECK_NULL_NOMEM_RETURN(new_info);
    }

    new_info->modified = info->modified;
    new_info->schema = info->schema;
    new_info->timestamp = info->timestamp;
    if (NULL != info->node) {
        tmp_node = sr_dup_datatree(info->node);
        CHECK_NULL_NOMEM_ERROR(tmp_node, rc);
    }

    if (SR_ERR_OK == rc) {
        lyd_free_withsiblings(new_info->node);
        new_info->node = tmp_node;
    }

    if (!existed) {
        pthread_mutex_lock(&info->schema->usage_count_mutex);
        info->schema->usage_count++;
        SR_LOG_DBG("Usage count %s decremented (value=%zu)", info->schema->module_name, info->schema->usage_count);
        pthread_mutex_unlock(&info->schema->usage_count_mutex);
        if (SR_ERR_OK == rc) {
            rc = sr_btree_insert(to->session_modules[to->datastore], new_info);
        } else {
            dm_data_info_free(new_info);
        }
    }
    return rc;
}

int
dm_create_rdonly_ptr_data_tree(dm_ctx_t *dm_ctx, dm_session_t *from, dm_session_t *to, dm_schema_info_t *schema_info)
{
    CHECK_NULL_ARG4(dm_ctx, from, to, schema_info);
    int rc = SR_ERR_OK;
    dm_data_info_t *info = NULL;
    dm_data_info_t lookup = {0};
    dm_data_info_t *new_info = NULL;
    bool existed = true;

    lookup.schema = schema_info;

    info = sr_btree_search(from->session_modules[from->datastore], &lookup);
    if (NULL == info) {
        SR_LOG_DBG("Module %s not loaded in source session", schema_info->module_name);
        return rc;
    }

    new_info = sr_btree_search(to->session_modules[to->datastore], &lookup);
    if (NULL == new_info) {
        existed = false;
        new_info = calloc(1, sizeof(*new_info));
        CHECK_NULL_NOMEM_RETURN(new_info);
    }

    new_info->modified = info->modified;
    new_info->schema = info->schema;
    new_info->timestamp = info->timestamp;
    new_info->rdonly_copy = true;
    lyd_free_withsiblings(new_info->node);
    new_info->node = info->node;

    if (!existed) {
        rc = sr_btree_insert(to->session_modules[to->datastore], new_info);
        if (SR_ERR_OK != rc) {
            dm_data_info_free(new_info);
        }
    }
    return rc;
}

int
dm_copy_if_not_loaded(dm_ctx_t *dm_ctx, dm_session_t *from_session, dm_session_t *session, const char *module_name)
{
    CHECK_NULL_ARG4(dm_ctx, from_session, session, module_name);
    int rc = SR_ERR_OK;
    dm_data_info_t lookup = {0};
    dm_data_info_t *info  = NULL;
    dm_schema_info_t *schema_info = NULL;

    rc = dm_get_module_and_lock(dm_ctx, module_name, &schema_info);
    CHECK_RC_LOG_RETURN(rc, "Get module %s failed", module_name);

    lookup.schema = schema_info;

    info = sr_btree_search(session->session_modules[session->datastore], &lookup);

    if (NULL == info) {
        rc = dm_create_rdonly_ptr_data_tree(dm_ctx, from_session, session, schema_info);
    }
    pthread_rwlock_unlock(&schema_info->model_lock);
    return rc;
}

int
dm_move_session_tree_and_ops_all_ds(dm_ctx_t *dm_ctx, dm_session_t *from, dm_session_t *to)
{
    CHECK_NULL_ARG3(dm_ctx, from, to);
    CHECK_NULL_ARG(from->session_modules);
    int rc = SR_ERR_OK;

    int from_ds = from->datastore;
    int to_ds = to->datastore;
    for (int ds = 0; ds < DM_DATASTORE_COUNT; ds++) {
        dm_session_switch_ds(from, ds);
        dm_session_switch_ds(to, ds);
        sr_btree_cleanup(to->session_modules[ds]);
        dm_free_sess_operations(to->operations[ds], to->oper_count[ds]);

        to->session_modules[ds] = from->session_modules[ds];
        to->oper_count[ds] = from->oper_count[ds];
        to->oper_size[ds] = from->oper_size[ds];
        to->operations[ds] = from->operations[ds];

        from->session_modules[ds] = NULL;
        from->operations[ds] = NULL;
        from->oper_count[ds] = 0;
        from->oper_size[ds] = 0;

        dm_session_switch_ds(from, ds);
        rc = dm_discard_changes(dm_ctx, from);
    }
    dm_session_switch_ds(from, from_ds);
    dm_session_switch_ds(to, to_ds);
    CHECK_RC_MSG_RETURN(rc, "Discard changes failed");
    return rc;
}


int
dm_move_session_trees_in_session(dm_ctx_t *dm_ctx, dm_session_t *session, sr_datastore_t from, sr_datastore_t to)
{
    CHECK_NULL_ARG2(dm_ctx, session);
    CHECK_NULL_ARG(session->session_modules);
    int rc = SR_ERR_OK;

    if (from == to) {
        return rc;
    }

    int prev_ds = session->datastore;

    /* cleanup the target*/
    sr_btree_cleanup(session->session_modules[to]);
    dm_free_sess_operations(session->operations[to], session->oper_count[to]);

    /* move */
    session->session_modules[to] = session->session_modules[from];
    session->oper_count[to] = session->oper_count[from];
    session->oper_size[to] = session->oper_size[from];
    session->operations[to] = session->operations[from];

    dm_session_switch_ds(session, from);
    session->session_modules[from] = NULL;
    session->operations[from] = NULL;
    session->oper_count[from] = 0;
    session->oper_size[from] = 0;

    /* initialize the from datastore binary tree*/
    dm_session_switch_ds(session, from);
    rc = dm_discard_changes(dm_ctx, session);
    CHECK_RC_MSG_RETURN(rc, "Discard changes failed");

    rc = dm_session_switch_ds(session, prev_ds);
    return rc;
}

int
dm_session_switch_ds(dm_session_t *session, sr_datastore_t ds)
{
    CHECK_NULL_ARG(session);
    session->datastore = ds;
    return SR_ERR_OK;
}

int
dm_get_all_modules(dm_ctx_t *dm_ctx, dm_session_t *session, bool enabled_only, sr_list_t **result)
{
    CHECK_NULL_ARG3(dm_ctx, session, result);
    int rc = SR_ERR_OK;

    md_module_t *module = NULL;
    sr_list_t *modules = NULL;
    sr_llist_node_t *module_ll_node = NULL;
    rc = sr_list_init(&modules);
    CHECK_RC_MSG_RETURN(rc, "List init failed");

    md_ctx_lock(dm_ctx->md_ctx, false);

    module_ll_node = dm_ctx->md_ctx->modules->first;
    while (module_ll_node) {
        module = (md_module_t *)module_ll_node->data;
        module_ll_node = module_ll_node->next;
        if (module->submodule) {
            /* skip submodules */
            continue;
        }
        if (!module->latest_revision) {
            continue;
        }

        if (enabled_only) {
            bool enabled = false;
            rc = dm_has_enabled_subtree(dm_ctx, module->name, NULL, &enabled);
            CHECK_RC_LOG_GOTO(rc, cleanup, "Has enabled subtree failed %s", module->name);
            if (!enabled) {
                continue;
            }
        }
        rc = sr_list_add(modules, module->name);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Adding to list failed");
    }

cleanup:
    if (SR_ERR_OK != rc) {
        sr_list_cleanup(modules);
    } else {
        *result = modules;
    }

    md_ctx_unlock(dm_ctx->md_ctx);
    return rc;
}

int
dm_is_model_modified(dm_ctx_t *dm_ctx, dm_session_t *session, const char *module_name, bool *res)
{
    CHECK_NULL_ARG3(dm_ctx, session, module_name);
    int rc = SR_ERR_OK;
    dm_schema_info_t *schema_info = NULL;
    dm_data_info_t lookup = {0};
    dm_data_info_t *info  = NULL;

    rc = dm_get_module_and_lock(dm_ctx, module_name, &schema_info);
    CHECK_RC_MSG_RETURN(rc, "Dm get module failed");

    lookup.schema = schema_info;

    info = sr_btree_search(session->session_modules[session->datastore], &lookup);
    pthread_rwlock_unlock(&schema_info->model_lock);

    *res = NULL != info ? info->modified : false;
    return rc;
}

int
dm_get_commit_context(dm_ctx_t *dm_ctx, uint32_t c_ctx_id, dm_commit_context_t **c_ctx)
{
    CHECK_NULL_ARG2(dm_ctx, c_ctx);
    dm_commit_context_t lookup = {0};
    lookup.id = c_ctx_id;
    *c_ctx = sr_btree_search(dm_ctx->commit_ctxs.tree, &lookup);
    return SR_ERR_OK;
}

int
dm_get_commit_ctxs(dm_ctx_t *dm_ctx, dm_commit_ctxs_t **commit_ctxs)
{
    CHECK_NULL_ARG2(dm_ctx, commit_ctxs);
    *commit_ctxs = &dm_ctx->commit_ctxs;
    return SR_ERR_OK;
}

int
dm_get_md_ctx(dm_ctx_t *dm_ctx, md_ctx_t **md_ctx){
    CHECK_NULL_ARG2(dm_ctx, md_ctx);
    *md_ctx = dm_ctx->md_ctx;
    return SR_ERR_OK;
}

int
dm_lock_schema_info(dm_schema_info_t *schema_info)
{
    CHECK_NULL_ARG2(schema_info, schema_info->module_name);
    RWLOCK_RDLOCK_TIMED_CHECK_RETURN(&schema_info->model_lock);
    if (NULL != schema_info->ly_ctx && NULL != schema_info->module) {
        return SR_ERR_OK;
    } else {
        SR_LOG_ERR("Schema info can not be locked for module %s. Module has been uninstalled.", schema_info->module_name);
        pthread_rwlock_unlock(&schema_info->model_lock);
        return SR_ERR_UNKNOWN_MODEL;
    }
}

int
dm_lock_schema_info_write(dm_schema_info_t *schema_info)
{
    CHECK_NULL_ARG2(schema_info, schema_info->module_name);
    RWLOCK_WRLOCK_TIMED_CHECK_RETURN(&schema_info->model_lock);
    if (NULL != schema_info->ly_ctx && NULL != schema_info->module) {
        return SR_ERR_OK;
    } else {
        SR_LOG_ERR("Schema info can not be locked for module %s. Module has been uninstalled.", schema_info->module_name);
        pthread_rwlock_unlock(&schema_info->model_lock);
        return SR_ERR_UNKNOWN_MODEL;
    }
}

int
dm_get_nodes_by_schema(dm_session_t *session, const char *module_name, const struct lys_node *node, struct ly_set **res)
{
    CHECK_NULL_ARG4(session, module_name, node, res);
    int rc = SR_ERR_OK;
    dm_data_info_t *di = NULL;

    rc = dm_get_data_info(session->dm_ctx, session, module_name, &di);
    CHECK_RC_MSG_RETURN(rc, "Get data info failed");

    *res = lyd_find_instance(di->node, node);
    if (NULL == *res) {
        SR_LOG_ERR("Failed to find nodes %s in module %s", node->name, module_name);
        rc = SR_ERR_INTERNAL;
    }

    return rc;
}
