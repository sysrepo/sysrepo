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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <pthread.h>
#include <fcntl.h>
#include <libyang/libyang.h>
#include <string.h>

#include "data_manager.h"
#include "sr_common.h"
#include "rp_dt_xpath.h"
#include "access_control.h"
#include "notification_processor.h"
#include "persistence_manager.h"

/**
 * @brief Helper structure for advisory locking. Holds
 * binary tree with filename -> fd maping. This structure
 * is used to avoid the loss of the lock by file closing.
 * File name is first looked up in this structure to detect if the
 * file is currently opened by the process.
 */
typedef struct dm_lock_ctx_s {
    sr_btree_t *lock_files;       /**< Binary tree of lock files for fast look up by file name */
    pthread_mutex_t mutex;        /**< Mutex for exclusive access to binary tree */
}dm_lock_ctx_t;

/**
 * @brief The item of the lock_files binary tree in dm_lock_ctx_t
 */
typedef struct dm_lock_item_s {
    char *filename;               /**< File name of the lockfile */
    int fd;                       /**< File descriptor of the file */
}dm_lock_item_t;

/**
 * @brief Data manager context holding loaded schemas, data trees
 * and corresponding locks
 */
typedef struct dm_ctx_s {
    ac_ctx_t *ac_ctx;             /**< Access Control module context */
    np_ctx_t *np_ctx;             /**< Notification Processor context */
    pm_ctx_t *pm_ctx;             /**< Persistence Manager context */
    char *schema_search_dir;      /**< location where schema files are located */
    char *data_search_dir;        /**< location where data files are located */
    struct ly_ctx *ly_ctx;        /**< libyang context holding all loaded schemas */
    pthread_rwlock_t lyctx_lock;  /**< rwlock to access ly_ctx */
    dm_lock_ctx_t lock_ctx;       /**< lock context for lock/unlock/commit operations */
    bool ds_lock;                 /**< Flag if the ds lock is hold by a session*/
    pthread_mutex_t ds_lock_mutex;/**< Data store lock mutex */
    struct ly_set *disabled_sch;  /**< Set of schema that has been disabled */
    sr_btree_t *schema_info_tree; /**< Binary tree holding information about schemas*/
} dm_ctx_t;

/**
 * @brief Structure that holds Data Manager's per-session context.
 */
typedef struct dm_session_s {
    sr_datastore_t datastore;           /**< datastore to which the session is tied */
    const ac_ucred_t *user_credentials; /**< credentials of the user who this session belongs to */
    sr_btree_t *session_modules;        /**< binary holding session copies of data models */
    char *error_msg;                    /**< description of the last error */
    char *error_xpath;                  /**< xpath of the last error if applicable */
    dm_sess_op_t *operations;           /**< list of operations performed in this session */
    size_t oper_count;                  /**< number of performed operation */
    size_t oper_size;                   /**< number of allocated operations */
    struct ly_set *locked_files;        /**< set of filename that are locked by this session */
    bool holds_ds_lock;                 /**< flags if the session holds ds lock*/
} dm_session_t;

/**
 * @brief Info structure for the node holds the state of the running data store.
 * (It will hold information about notification subscriptions.)
 */
typedef struct dm_node_info_s {
    dm_node_state_t state;
} dm_node_info_t;

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

    int res = strcmp(node_a->module->name, node_b->module->name);
    if (res == 0) {
        return 0;
    } else if (res < 0) {
        return -1;
    } else {
        return 1;
    }
}

/**
 * @brief Compare two lock items
 */
static int
dm_compare_lock_item(const void *a, const void *b)
{
    assert(a);
    assert(b);
    dm_lock_item_t *item_a = (dm_lock_item_t *) a;
    dm_lock_item_t *item_b = (dm_lock_item_t *) b;

    int res = strcmp(item_a->filename, item_b->filename);
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

static void
dm_free_schema_info(void *schema_info)
{
    CHECK_NULL_ARG_VOID(schema_info);
    dm_schema_info_t *si = (dm_schema_info_t *) schema_info;
    pthread_rwlock_destroy(&si->model_lock);
    free(si);
}

/**
 * @brief frees the dm_data_info stored in binary tree
 */
static void
dm_data_info_free(void *item)
{
    dm_data_info_t *info = (dm_data_info_t *) item;
    if (NULL != info) {
        lyd_free_withsiblings(info->node);
    }
    free(info);
}

int
dm_get_schema_info(dm_ctx_t *dm_ctx, const char *module_name, dm_schema_info_t **schema_info)
{
    CHECK_NULL_ARG3(dm_ctx, module_name, schema_info);
    int rc = SR_ERR_OK;
    dm_schema_info_t lookup_item = {0,};
    lookup_item.module_name = module_name;
    pthread_rwlock_rdlock(&dm_ctx->lyctx_lock);
    *schema_info = sr_btree_search(dm_ctx->schema_info_tree, &lookup_item);
    pthread_rwlock_unlock(&dm_ctx->lyctx_lock);
    if (NULL == *schema_info) {
        SR_LOG_ERR("Schema info not found for model %s", module_name);
        return SR_ERR_NOT_FOUND;
    }
    return rc;
}

/**
 * @brief Check whether the file_name corresponds to the schema file.
 * @return 1 if it does, 0 otherwise.
 */
static int
dm_is_schema_file(const char *file_name)
{
    CHECK_NULL_ARG(file_name);
    return sr_str_ends_with(file_name, SR_SCHEMA_YIN_FILE_EXT) || sr_str_ends_with(file_name, SR_SCHEMA_YANG_FILE_EXT);
}

/**
 * @brief Loads the schema file into the context. The path for loading file is specified as concatenation of dir_name
 * and file_name. Function returns SR_ERR_OK if loading was successful. It might return SR_ERR_IO if the file can not
 * be opened, SR_ERR_INTERNAL if parsing of the file failed or SR_ERR_NOMEM if memory allocation failed.
 * @param [in] dm_ctx
 * @param [in] dir_name
 * @param [in] file_name
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_load_schema_file(dm_ctx_t *dm_ctx, const char *dir_name, const char *file_name)
{
    CHECK_NULL_ARG3(dm_ctx, dir_name, file_name);
    const struct lys_module *module = NULL;
    char *schema_filename = NULL;
    char **features = NULL;
    size_t feature_cnt = 0;
    bool running_enabled = false;
    dm_schema_info_t *si = NULL;
    int rc = SR_ERR_OK;

    rc = sr_str_join(dir_name, file_name, &schema_filename);
    if (SR_ERR_OK != rc) {
        return SR_ERR_NOMEM;
    }

    si = calloc(1, sizeof(*si));
    if (NULL == si) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        free(schema_filename);
        return SR_ERR_NOMEM;
    }

    /* load schema tree */
    LYS_INFORMAT fmt = sr_str_ends_with(file_name, SR_SCHEMA_YIN_FILE_EXT) ? LYS_IN_YIN : LYS_IN_YANG;
    pthread_rwlock_wrlock(&dm_ctx->lyctx_lock);
    module = lys_parse_path(dm_ctx->ly_ctx, schema_filename, fmt);
    free(schema_filename);
    if (module == NULL) {
        SR_LOG_WRN("Unable to parse a schema file: %s", file_name);
        dm_free_schema_info(si);
        pthread_rwlock_unlock(&dm_ctx->lyctx_lock);
        return SR_ERR_INTERNAL;
    }

    pthread_rwlock_init(&si->model_lock, NULL);
    si->module_name = module->name;

    rc = sr_btree_insert(dm_ctx->schema_info_tree, si);
    if (SR_ERR_OK != rc) {
        dm_free_schema_info(si);
        if (SR_ERR_DATA_EXISTS != rc) {
            SR_LOG_WRN_MSG("Insert into schema binary tree failed");
            pthread_rwlock_unlock(&dm_ctx->lyctx_lock);
            return rc;
        }
    }

    pthread_rwlock_unlock(&dm_ctx->lyctx_lock);
    /* load module's persistent data */
    rc = pm_get_module_info(dm_ctx->pm_ctx, module->name, &running_enabled, &features, &feature_cnt);
    if (SR_ERR_OK == rc) {
        /* enable active features */
        for (size_t i = 0; i < feature_cnt; i++) {
            rc = dm_feature_enable(dm_ctx, module->name, features[i], true);
            if (SR_ERR_OK != rc) {
                SR_LOG_WRN("Unable to enable feature '%s' in module '%s' in Data Manager.", features[i], module->name);
            }
            free(features[i]);
        }
        free(features);
    }
    if (SR_ERR_OK == rc && running_enabled) {
        /* enable running datastore */
        rc = dm_enable_module_running(dm_ctx, NULL, module->name, module);
    }

    return SR_ERR_OK;
}

/**
 * @brief Loops through the specified directory (dm_ctx->schema_search_dir) and tries to load schema files from it.
 * Schemas that can not be loaded are skipped.
 * @param [in] dm_ctx
 * @return Error code (SR_ERR_OK on success), SR_ERR_IO if the directory can not be opened
 */
static int
dm_load_schemas(dm_ctx_t *dm_ctx)
{
    CHECK_NULL_ARG(dm_ctx);
    DIR *dir = NULL;
    struct dirent *ent = NULL;
    if ((dir = opendir(dm_ctx->schema_search_dir)) != NULL) {
        while ((ent = readdir(dir)) != NULL) {
            if (dm_is_schema_file(ent->d_name)) {
                if (SR_ERR_OK != dm_load_schema_file(dm_ctx, dm_ctx->schema_search_dir, ent->d_name)) {
                    SR_LOG_WRN("Loading schema file: %s failed.", ent->d_name);
                } else {
                    SR_LOG_INF("Schema file %s loaded successfully", ent->d_name);
                }
            }
        }
        closedir(dir);
        return SR_ERR_OK;
    } else {
        SR_LOG_ERR("Could not open the directory %s: %s", dm_ctx->schema_search_dir, strerror(errno));
        return SR_ERR_IO;
    }
}

static bool
dm_is_module_disabled(dm_ctx_t *dm_ctx, const char *module_name)
{
    if (NULL == dm_ctx || NULL == module_name) {
        return true;
    }

    for (size_t i = 0; i < dm_ctx->disabled_sch->number; i++) {
        if (0 == strcmp((char *) dm_ctx->disabled_sch->set.g[i], module_name)) {
            return true;
        }
    }
    return false;
}

/**
 * Checks whether the schema of the module has been loaded
 * @param [in] dm_ctx
 * @param [in] module_name
 * @param [out] module NULL can be passed
 * @return Error code (SR_ERR_OK on success), SR_ERR_UNKNOWN_MODEL
 */
static int
dm_find_module_schema(dm_ctx_t *dm_ctx, const char *module_name, const struct lys_module **module)
{
    CHECK_NULL_ARG2(dm_ctx, module_name);
    const struct lys_module *m = NULL;
    pthread_rwlock_rdlock(&dm_ctx->lyctx_lock);
    m = ly_ctx_get_module(dm_ctx->ly_ctx, module_name, NULL);
    pthread_rwlock_unlock(&dm_ctx->lyctx_lock);
    if (NULL != module) {
        *module = m;
    }
    return m == NULL || dm_is_module_disabled(dm_ctx, module_name) ? SR_ERR_UNKNOWN_MODEL : SR_ERR_OK;
}

/**
 * @brief Tries to load data tree from provided opened file.
 * @param [in] dm_ctx
 * @param [in] fd to be read from, function does not close it
 * If NULL passed data info with empty data will be created
 * @param [in] module
 * @param [in] data_info
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_load_data_tree_file(dm_ctx_t *dm_ctx, int fd, const char *data_filename, const struct lys_module *module, dm_data_info_t **data_info)
{
    CHECK_NULL_ARG4(dm_ctx, module, data_filename, data_info);
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
        SR_LOG_DBG("Loaded module %s: mtime sec=%lld nsec=%lld", module->name,
                (long long) st.st_mtim.tv_sec,
                (long long) st.st_mtim.tv_nsec);
#endif
        data_tree = lyd_parse_fd(dm_ctx->ly_ctx, fd, LYD_XML, LYD_OPT_STRICT | LYD_OPT_CONFIG);
        if (NULL == data_tree && LY_SUCCESS != ly_errno) {
            SR_LOG_ERR("Parsing data tree from file %s failed: %s", data_filename, ly_errmsg());
            free(data);
            return SR_ERR_INTERNAL;
        }
    }

    /* if the data tree is loaded, validate it*/
    if (NULL != data_tree && 0 != lyd_validate(&data_tree, LYD_OPT_STRICT | LYD_OPT_CONFIG | LYD_WD_IMPL_TAG)) {
        SR_LOG_ERR("Loaded data tree '%s' is not valid", data_filename);
        lyd_free_withsiblings(data_tree);
        free(data);
        return SR_ERR_INTERNAL;
    }
    /* add default nodes to the empty data tree */
    else if (NULL == data_tree) {
        lyd_wd_add(dm_ctx->ly_ctx, &data_tree, LYD_WD_IMPL_TAG);
    }

    data->module = module;
    data->modified = false;
    data->node = data_tree;

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
 * @param [in] dm_ctx
 * @param [in] dm_session_ctx
 * @param [in] module
 * @param [in] ds
 * @param [out] data_info
 * @return Error code (SR_ERR_OK on success), SR_ERR_INTERAL if the parsing of the data tree fails.
 */
static int
dm_load_data_tree(dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx, const struct lys_module *module, sr_datastore_t ds, dm_data_info_t **data_info)
{
    CHECK_NULL_ARG2(dm_ctx, module);

    char *data_filename = NULL;
    int rc = 0;
    *data_info = NULL;
    rc = sr_get_data_file_name(dm_ctx->data_search_dir, module->name, ds, &data_filename);
    CHECK_RC_LOG_RETURN(rc, "Get data_filename failed for %s", module->name);

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

    rc = dm_load_data_tree_file(dm_ctx, fd, data_filename, module, data_info);

    if (-1 != fd) {
        sr_unlock_fd(fd);
        close(fd);
    }

    free(data_filename);
    return rc;
}

static void
dm_free_lys_private_data(const struct lys_node *node, void *private)
{
    if (NULL != private) {
        free(private);
    }
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

static void
dm_free_lock_item(void *lock_item)
{
    CHECK_NULL_ARG_VOID(lock_item);
    dm_lock_item_t *li = (dm_lock_item_t *) lock_item;
    free(li->filename);
    if (-1 != li->fd) {
        close(li->fd);
    }
    free(li);
}

/**
 * @brief Locks a file based on provided file name.
 * @param [in] lock_ctx
 * @param [in] filename
 * @return Error code (SR_ERR_OK on success), SR_ERR_LOCKED if the file is already locked,
 * SR_ERR_UNATHORIZED if the file can not be locked because of the permission.
 */
static int
dm_lock_file(dm_lock_ctx_t *lock_ctx, char *filename)
{
    CHECK_NULL_ARG2(lock_ctx, filename);
    int rc = SR_ERR_OK;
    dm_lock_item_t lookup_item = {0,};
    dm_lock_item_t *found_item = NULL;
    lookup_item.filename = filename;

    pthread_mutex_lock(&lock_ctx->mutex);

    found_item = sr_btree_search(lock_ctx->lock_files, &lookup_item);
    if (NULL == found_item) {
        found_item = calloc(1, sizeof(*found_item));
        CHECK_NULL_NOMEM_GOTO(found_item, rc, cleanup);

        found_item->fd = -1;
        found_item->filename = strdup(filename);
        if (NULL == found_item->filename) {
            SR_LOG_ERR_MSG("Filename duplication failed");
            free(found_item);
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }

        rc = sr_btree_insert(lock_ctx->lock_files, found_item);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Adding to binary tree failed");
            dm_free_lock_item(found_item);
            goto cleanup;
        }
    }

    if (-1 == found_item->fd) {
        found_item->fd = open(filename, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
        if (-1 == found_item->fd) {
            if (EACCES == errno) {
                SR_LOG_ERR("Insufficient permissions to lock the file '%s'", filename);
                rc = SR_ERR_UNAUTHORIZED;
            } else {
                SR_LOG_ERR("Error by opening the file '%s': %s", filename, strerror(errno));
                rc = SR_ERR_INTERNAL;
            }
            goto cleanup;
        }
        rc = sr_lock_fd(found_item->fd, true, false);
        if (SR_ERR_OK == rc) {
            SR_LOG_DBG("File %s has been locked", filename);
        } else {
            SR_LOG_INF("File %s locked by other process", filename);
            close(found_item->fd);
            found_item->fd = -1;
        }
    } else {
        rc = SR_ERR_LOCKED;
        SR_LOG_INF("File %s is already locked", filename);
    }

cleanup:
    pthread_mutex_unlock(&lock_ctx->mutex);
    return rc;
}

/**
 * @brief Unlocks the file based on the filename
 * @param [in] lock_ctx
 * @param [in] filename
 * @return Error code (SR_ERR_OK on success) SR_ERR_INVAL_ARG if the
 * file had not been locked in provided context
 */
static int
dm_unlock_file(dm_lock_ctx_t *lock_ctx, char *filename)
{
    CHECK_NULL_ARG2(lock_ctx, filename);
    int rc = SR_ERR_OK;
    dm_lock_item_t lookup_item = {0,};
    dm_lock_item_t *found_item = NULL;
    lookup_item.filename = filename;

    pthread_mutex_lock(&lock_ctx->mutex);

    found_item = sr_btree_search(lock_ctx->lock_files, &lookup_item);
    if (NULL == found_item || -1 == found_item->fd) {
        SR_LOG_ERR("File %s has not been locked in this context", filename);
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }
    close(found_item->fd);
    found_item->fd = -1;
    SR_LOG_DBG("File %s has been unlocked", filename);

cleanup:
    pthread_mutex_unlock(&lock_ctx->mutex);
    return rc;
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
dm_lock_module(dm_ctx_t *dm_ctx, dm_session_t *session, char *modul_name)
{
    CHECK_NULL_ARG3(dm_ctx, session, modul_name);
    int rc = SR_ERR_OK;
    char *lock_file = NULL;

    /* check if module name is valid */
    rc = dm_find_module_schema(dm_ctx, modul_name, NULL);
    CHECK_RC_LOG_RETURN(rc, "Unknown module %s to lock", modul_name);

    rc = sr_get_lock_data_file_name(dm_ctx->data_search_dir, modul_name, session->datastore, &lock_file);
    CHECK_RC_MSG_RETURN(rc, "Lock file name can not be created");

    /* check if already locked by this session */
    for (size_t i = 0; i < session->locked_files->number; i++) {
        if (0 == strcmp(lock_file, (char *) session->locked_files->set.g[i])) {
            SR_LOG_INF("File %s is already by this session", lock_file);
            free(lock_file);
            return rc;
        }
    }

    /* switch identity */
    ac_set_user_identity(dm_ctx->ac_ctx, session->user_credentials);

    rc = dm_lock_file(&dm_ctx->lock_ctx, lock_file);

    /* switch identity back */
    ac_unset_user_identity(dm_ctx->ac_ctx);

    /* log information about locked model */
    if (SR_ERR_OK != rc) {
        free(lock_file);
    } else {
        ly_set_add(session->locked_files, lock_file);
    }
    return rc;
}

int
dm_unlock_module(dm_ctx_t *dm_ctx, dm_session_t *session, char *modul_name)
{
    CHECK_NULL_ARG3(dm_ctx, session, modul_name);
    int rc = SR_ERR_OK;
    char *lock_file = NULL;
    size_t i = 0;

    rc = sr_get_lock_data_file_name(dm_ctx->data_search_dir, modul_name, session->datastore, &lock_file);
    CHECK_RC_MSG_RETURN(rc, "Lock file name can not be created");

    /* check if already locked */
    bool found = false;
    for (i = 0; i < session->locked_files->number; i++) {
        if (0 == strcmp(lock_file, (char *) session->locked_files->set.g[i])) {
            found = true;
            break;
        }
    }

    if (!found) {
        SR_LOG_ERR("File %s has not been locked in this context", lock_file);
        rc = SR_ERR_INVAL_ARG;
    } else {
        rc = dm_unlock_file(&dm_ctx->lock_ctx, lock_file);
        free(session->locked_files->set.g[i]);
        ly_set_rm_index(session->locked_files, i);
    }

    free(lock_file);
    return rc;
}

int
dm_lock_datastore(dm_ctx_t *dm_ctx, dm_session_t *session)
{
    CHECK_NULL_ARG2(dm_ctx, session);
    int rc = SR_ERR_OK;
    sr_schema_t *schemas = NULL;
    size_t schema_count = 0;

    struct ly_set *locked = ly_set_new();
    CHECK_NULL_NOMEM_RETURN(locked);

    rc = dm_list_schemas(dm_ctx, session, &schemas, &schema_count);
    CHECK_RC_MSG_GOTO(rc, cleanup, "List schemas failed");

    pthread_mutex_lock(&dm_ctx->ds_lock_mutex);
    if (dm_ctx->ds_lock) {
        SR_LOG_ERR_MSG("Datastore lock is hold by other session");
        rc = SR_ERR_LOCKED;
        pthread_mutex_unlock(&dm_ctx->ds_lock_mutex);
        goto cleanup;
    }
    dm_ctx->ds_lock = true;
    pthread_mutex_unlock(&dm_ctx->ds_lock_mutex);
    session->holds_ds_lock = true;

    for (size_t i = 0; i < schema_count; i++) {
        rc = dm_lock_module(dm_ctx, session, (char *) schemas[i].module_name);
        if (SR_ERR_OK != rc) {
            if (SR_ERR_UNAUTHORIZED == rc) {
                SR_LOG_INF("Not allowed to lock %s, skipping", schemas[i].module_name);
                continue;
            } else if (SR_ERR_LOCKED == rc) {
                SR_LOG_ERR("Model %s is already locked by other session", schemas[i].module_name);
            }
            for (size_t l = 0; l < locked->number; l++) {
                dm_unlock_module(dm_ctx, session, (char *) locked->set.g[l]);
            }
            pthread_mutex_lock(&dm_ctx->ds_lock_mutex);
            dm_ctx->ds_lock = false;
            pthread_mutex_unlock(&dm_ctx->ds_lock_mutex);
            session->holds_ds_lock = false;
            goto cleanup;
        }
        SR_LOG_DBG("Module %s locked", schemas[i].module_name);
        ly_set_add(locked, (char *) schemas[i].module_name);
    }
cleanup:
    sr_free_schemas(schemas, schema_count);
    ly_set_free(locked);
    return rc;
}

int
dm_unlock_datastore(dm_ctx_t *dm_ctx, dm_session_t *session)
{
    CHECK_NULL_ARG2(dm_ctx, session);

    while (session->locked_files->number > 0) {
        dm_unlock_file(&dm_ctx->lock_ctx, (char *) session->locked_files->set.g[0]);
        free(session->locked_files->set.g[0]);
        ly_set_rm_index(session->locked_files, 0);
    }
    if (session->holds_ds_lock) {
        pthread_mutex_lock(&dm_ctx->ds_lock_mutex);
        dm_ctx->ds_lock = false;
        session->holds_ds_lock = false;
        pthread_mutex_unlock(&dm_ctx->ds_lock_mutex);
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

    if (NULL == session->operations) {
        session->oper_size = 1;
        session->operations = calloc(session->oper_size, sizeof(*session->operations));
        CHECK_NULL_NOMEM_GOTO(session->operations, rc, cleanup);
    } else if (session->oper_count == session->oper_size) {
        session->oper_size *= 2;
        dm_sess_op_t *tmp_op = realloc(session->operations, session->oper_size * sizeof(*session->operations));
        CHECK_NULL_NOMEM_GOTO(tmp_op, rc, cleanup);
        session->operations = tmp_op;
    }
    session->operations[session->oper_count].op = op;
    session->operations[session->oper_count].has_error = false;
    session->operations[session->oper_count].xpath = strdup(xpath);
    CHECK_NULL_NOMEM_GOTO(session->operations[session->oper_count].xpath, rc, cleanup);
    if (DM_SET_OP == op) {
        session->operations[session->oper_count].detail.set.val = val;
        session->operations[session->oper_count].detail.set.options = opts;
    } else if (DM_DELETE_OP == op) {
        session->operations[session->oper_count].detail.del.options = opts;
    } else if (DM_MOVE_OP == op) {
        session->operations[session->oper_count].detail.mov.position = pos;
        if (NULL != rel_item) {
            session->operations[session->oper_count].detail.mov.relative_item = strdup(rel_item);
            CHECK_NULL_NOMEM_GOTO(session->operations[session->oper_count].detail.mov.relative_item, rc, cleanup);
        } else {
            session->operations[session->oper_count].detail.mov.relative_item = NULL;
        }
    }

    session->oper_count++;
    return rc;
cleanup:
    sr_free_val(val);
    return rc;
}

void
dm_remove_last_operation(dm_session_t *session)
{
    CHECK_NULL_ARG_VOID(session);
    if (session->oper_count > 0) {
        session->oper_count--;
        dm_free_sess_op(&session->operations[session->oper_count]);
        session->operations[session->oper_count].xpath = NULL;
        session->operations[session->oper_count].detail.set.val = NULL;
    }
}

void
dm_get_session_operations(dm_session_t *session, dm_sess_op_t **ops, size_t *count)
{
    CHECK_NULL_ARG_VOID3(session, ops, count);
    *ops = session->operations;
    *count = session->oper_count;
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
dm_report_error(dm_session_t *session, const char *msg, char *err_path, int rc)
{
    if (NULL == session) {
        return SR_ERR_INTERNAL;
    }

    /* if NULL is provided, message will be generated according to the error code*/
    if (NULL == msg) {
        msg = sr_strerror(rc);
    }

    if (NULL != session->error_msg) {
        SR_LOG_WRN("Overwriting session error message %s", session->error_msg);
        free(session->error_msg);
    }
    session->error_msg = strdup(msg);
    if (NULL == session->error_msg) {
        SR_LOG_ERR_MSG("Error message duplication failed");
        free(err_path);
        return SR_ERR_INTERNAL;
    }

    if (NULL != session->error_xpath) {
        SR_LOG_WRN("Overwriting session error xpath %s", session->error_xpath);
        free(session->error_xpath);
    }
    session->error_xpath = err_path;
    if (NULL == session->error_xpath) {
        SR_LOG_WRN_MSG("Error xpath passed to dm_report is NULL");
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
dm_copy_errors(dm_session_t *session, char **error_msg, char **err_xpath)
{
    CHECK_NULL_ARG3(session, error_msg, err_xpath);
    if (NULL != session->error_msg) {
        *error_msg = strdup(session->error_msg);
    }
    if (NULL != session->error_xpath) {
        *err_xpath = strdup(session->error_xpath);
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
        if (NULL == node->priv) {
            SR_LOG_ERR_MSG("Memory allocation failed");
            return SR_ERR_NOMEM;
        }
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

int
dm_init(ac_ctx_t *ac_ctx, np_ctx_t *np_ctx, pm_ctx_t *pm_ctx,
        const char *schema_search_dir, const char *data_search_dir, dm_ctx_t **dm_ctx)
{
    CHECK_NULL_ARG3(schema_search_dir, data_search_dir, dm_ctx);

    SR_LOG_INF("Initializing Data Manager, schema_search_dir=%s, data_search_dir=%s", schema_search_dir, data_search_dir);

    dm_ctx_t *ctx = NULL;
    int rc = SR_ERR_OK;
    ctx = calloc(1, sizeof(*ctx));
    CHECK_NULL_NOMEM_GOTO(ctx, rc, cleanup);
    ctx->ac_ctx = ac_ctx;
    ctx->np_ctx = np_ctx;
    ctx->pm_ctx = pm_ctx;

    ctx->ly_ctx = ly_ctx_new(schema_search_dir);
    CHECK_NULL_NOMEM_GOTO(ctx->ly_ctx, rc, cleanup);

    ly_set_log_clb(dm_ly_log_cb, 1);

    ctx->schema_search_dir = strdup(schema_search_dir);
    CHECK_NULL_NOMEM_GOTO(ctx->schema_search_dir, rc, cleanup);

    ctx->data_search_dir = strdup(data_search_dir);
    CHECK_NULL_NOMEM_GOTO(ctx->data_search_dir, rc, cleanup);

    ctx->disabled_sch = ly_set_new();
    CHECK_NULL_NOMEM_GOTO(ctx->disabled_sch, rc, cleanup);

    pthread_mutex_init(&ctx->ds_lock_mutex, NULL);
    pthread_mutex_init(&ctx->lock_ctx.mutex, NULL);
    rc = sr_btree_init(dm_compare_lock_item, dm_free_lock_item, &ctx->lock_ctx.lock_files);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Creating of lock files binary tree failed");
    pthread_rwlockattr_t attr;
    pthread_rwlockattr_init(&attr);
#if defined(HAVE_PTHREAD_RWLOCKATTR_SETKIND_NP)
    pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
#endif

    rc = pthread_rwlock_init(&ctx->lyctx_lock, &attr);
    pthread_rwlockattr_destroy(&attr);
    if (0 != rc) {
        SR_LOG_ERR_MSG("lyctx mutex initialization failed");
        dm_cleanup(ctx);
        return SR_ERR_INTERNAL;
    }

    rc = sr_btree_init(dm_schema_info_cmp, dm_free_schema_info, &ctx->schema_info_tree);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Schema binary tree allocation failed");

    *dm_ctx = ctx;
    rc = dm_load_schemas(ctx);

cleanup:
    if (SR_ERR_OK != rc) {
        dm_cleanup(ctx);
    }
    return rc;

}

void
dm_cleanup(dm_ctx_t *dm_ctx)
{
    if (NULL != dm_ctx) {
        free(dm_ctx->schema_search_dir);
        free(dm_ctx->data_search_dir);
        sr_btree_cleanup(dm_ctx->schema_info_tree);
        if (NULL != dm_ctx->ly_ctx) {
            ly_ctx_destroy(dm_ctx->ly_ctx, dm_free_lys_private_data);
        }
        pthread_rwlock_destroy(&dm_ctx->lyctx_lock);
        if (NULL != dm_ctx->lock_ctx.lock_files) {
            sr_btree_cleanup(dm_ctx->lock_ctx.lock_files);
        }
        pthread_mutex_destroy(&dm_ctx->lock_ctx.mutex);
        pthread_mutex_destroy(&dm_ctx->ds_lock_mutex);
        ly_set_free(dm_ctx->disabled_sch);
        free(dm_ctx);
    }
}

int
dm_session_start(const dm_ctx_t *dm_ctx, const ac_ucred_t *user_credentials, const sr_datastore_t ds, dm_session_t **dm_session_ctx)
{
    CHECK_NULL_ARG(dm_session_ctx);

    dm_session_t *session_ctx = NULL;
    session_ctx = calloc(1, sizeof(*session_ctx));
    CHECK_NULL_NOMEM_RETURN(session_ctx);
    session_ctx->user_credentials = user_credentials;
    session_ctx->datastore = ds;

    int rc = SR_ERR_OK;
    rc = sr_btree_init(dm_data_info_cmp, dm_data_info_free, &session_ctx->session_modules);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Binary tree allocation failed");
        free(session_ctx);
        return SR_ERR_NOMEM;
    }
    session_ctx->locked_files = ly_set_new();
    if (NULL == session_ctx->locked_files) {
        SR_LOG_ERR_MSG("Locked file set init failed");
        sr_btree_cleanup(session_ctx->session_modules);
        free(session_ctx);
        return SR_ERR_INTERNAL;
    }
    *dm_session_ctx = session_ctx;

    return SR_ERR_OK;
}

void
dm_session_stop(dm_ctx_t *dm_ctx, dm_session_t *session)
{
    CHECK_NULL_ARG_VOID2(dm_ctx, session);
    if (NULL != session->locked_files) {
        dm_unlock_datastore(dm_ctx, session);
        ly_set_free(session->locked_files);
    }
    sr_btree_cleanup(session->session_modules);
    dm_clear_session_errors(session);
    dm_free_sess_operations(session->operations, session->oper_count);
    free(session);
}

int
dm_get_data_info(dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx, const char *module_name, dm_data_info_t **info)
{
    CHECK_NULL_ARG4(dm_ctx, dm_session_ctx, module_name, info);
    int rc = SR_ERR_OK;
    const struct lys_module *module = NULL;
    dm_data_info_t *exisiting_data_info = NULL;

    if (dm_find_module_schema(dm_ctx, module_name, &module) != SR_ERR_OK) {
        SR_LOG_WRN("Unknown schema: %s", module_name);
        return SR_ERR_UNKNOWN_MODEL;
    }

    dm_data_info_t lookup_data = {0};
    lookup_data.module = module;
    exisiting_data_info = sr_btree_search(dm_session_ctx->session_modules, &lookup_data);

    if (NULL != exisiting_data_info) {
        *info = exisiting_data_info;
        SR_LOG_DBG("Module %s already loaded", module_name);
        return SR_ERR_OK;
    }

    /* session copy not found load it from file system */
    dm_data_info_t *di = NULL;
    rc = dm_load_data_tree(dm_ctx, dm_session_ctx, module, dm_session_ctx->datastore, &di);
    CHECK_RC_LOG_RETURN(rc, "Getting data tree for %s failed.", module_name);

    rc = sr_btree_insert(dm_session_ctx->session_modules, (void *) di);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Insert into session avl failed module %s", module_name);
        dm_data_info_free(di);
        return rc;
    }
    SR_LOG_DBG("Module %s has been loaded", module_name);
    *info = di;
    return SR_ERR_OK;
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

int
dm_get_module(dm_ctx_t *dm_ctx, const char *module_name, const char *revision, const struct lys_module **module)
{
    CHECK_NULL_ARG3(dm_ctx, module_name, module); /* revision might be NULL*/
    *module = ly_ctx_get_module(dm_ctx->ly_ctx, module_name, revision);
    if (NULL == *module) {
        SR_LOG_ERR("Get module failed %s", module_name);
        return SR_ERR_UNKNOWN_MODEL;
    }
    return SR_ERR_OK;
}

static int
dm_list_rev_file(dm_ctx_t *dm_ctx, const char *module_name, const char *rev_date, sr_sch_revision_t *rev)
{
    CHECK_NULL_ARG3(dm_ctx, module_name, rev);
    int rc = SR_ERR_OK;

    if (NULL != rev_date) {
        rev->revision = strdup(rev_date);
        CHECK_NULL_NOMEM_GOTO(rev->revision, rc, cleanup);
    }

    rc = sr_get_schema_file_name(dm_ctx->schema_search_dir, module_name, rev_date, true, (char**) &rev->file_path_yang);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Get schema file name failed");

    rc = sr_get_schema_file_name(dm_ctx->schema_search_dir, module_name, rev_date, false, (char**) &rev->file_path_yin);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Get schema file name failed");

    if (-1 == access(rev->file_path_yang, F_OK)) {
        free((void*) rev->file_path_yang);
        rev->file_path_yang = NULL;
    }
    if (-1 == access(rev->file_path_yin, F_OK)) {
        free((void*) rev->file_path_yin);
        rev->file_path_yin = NULL;
    }
    return rc;

cleanup:
    free((void*) rev->revision);
    free((void*) rev->file_path_yang);
    free((void*) rev->file_path_yin);
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
dm_list_module(dm_ctx_t *dm_ctx, const char *module_name, const char *revision, sr_schema_t *schema)
{
    CHECK_NULL_ARG3(dm_ctx, module_name, schema);

    int rc = SR_ERR_INTERNAL;

    const struct lys_module *module = ly_ctx_get_module(dm_ctx->ly_ctx, module_name, revision);
    if (NULL == module) {
        SR_LOG_ERR("Module %s at revision %s not found", module_name, revision);
        return SR_ERR_INTERNAL;
    }
    if (NULL == module_name || NULL == module->prefix || NULL == module->ns) {
        SR_LOG_ERR_MSG("Schema information missing");
        return SR_ERR_INTERNAL;
    }

    schema->module_name = strdup(module->name);
    schema->prefix = strdup(module->prefix);
    schema->ns = strdup(module->ns);
    if (NULL == schema->module_name || NULL == schema->prefix || NULL == schema->ns) {
        SR_LOG_ERR_MSG("Duplication of string for schema_t failed");
        goto cleanup;
    }


    rc = dm_list_rev_file(dm_ctx, module_name, revision, &schema->revision);
    CHECK_RC_LOG_GOTO(rc, cleanup, "List rev file failed module %s", module->name);

    uint8_t *state = NULL;
    size_t feature_cnt = 0;
    size_t enabled = 0;
    const char **features = lys_features_list(module, &state);

    while (NULL != features[feature_cnt]) feature_cnt++;

    for (size_t i = 0; i < feature_cnt; i++) {
        if (state[i] == 1) {
            enabled++;
        }
    }

    if (feature_cnt > 0) {
        schema->enabled_features = calloc(feature_cnt, sizeof(*schema->enabled_features));
        CHECK_NULL_NOMEM_GOTO(schema->enabled_features, rc, cleanup);
        for (size_t i = 0; i < feature_cnt; i++) {
            if (state[i] == 1) {
                schema->enabled_features[schema->enabled_feature_cnt] = strdup(features[i]);
                CHECK_NULL_NOMEM_GOTO(schema->enabled_features[schema->enabled_feature_cnt], rc, cleanup);
                schema->enabled_feature_cnt++;
            }
        }
    }
    free(features);
    free(state);

    schema->submodules = calloc(module->inc_size, sizeof(*schema->submodules));
    CHECK_NULL_NOMEM_GOTO(schema->submodules, rc, cleanup);

    for (size_t s = 0; s < module->inc_size; s++) {
        const struct lys_submodule *sub = module->inc[s].submodule;
        if (NULL == sub->name) {
            SR_LOG_ERR_MSG("Missing schema information");
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
        schema->submodules[s].submodule_name = strdup(sub->name);
        CHECK_NULL_NOMEM_GOTO(schema->submodules[s].submodule_name, rc, cleanup);

        rc = dm_list_rev_file(dm_ctx, sub->name, sub->rev[0].date, &schema->submodules[s].revision);
        CHECK_RC_LOG_GOTO(rc, cleanup, "List rev file failed module %s", module->name);

        schema->submodule_count++;
    }
    return rc;

cleanup:
    sr_free_schema(schema);
    return rc;
}

static const char *
dm_get_module_revision(struct lyd_node *module)
{
    int rc = 0;
    const char *result = NULL;
    CHECK_NULL_ARG_NORET(rc, module);
    if (0 != rc) {
        return NULL;
    }
    struct ly_set *rev = lyd_get_node(module, "revision");
    if (NULL == rev) {
        SR_LOG_ERR_MSG("Getting module revision failed");
        return NULL;
    }
    if (0 == rev->number) {
        ly_set_free(rev);
    } else {
        result = ((struct lyd_node_leaf_list *) rev->set.d[0])->value_str;
        if (0 == strcmp(result, "")) {
            result = NULL;
        }
    }
    ly_set_free(rev);
    return result;

}

int
dm_list_schemas(dm_ctx_t *dm_ctx, dm_session_t *dm_session, sr_schema_t **schemas, size_t *schema_count)
{
    CHECK_NULL_ARG4(dm_ctx, dm_session, schemas, schema_count);
    int rc = SR_ERR_OK;
    *schemas = NULL;
    *schema_count = 0;

    struct lyd_node *info = ly_ctx_info(dm_ctx->ly_ctx);
    if (NULL == info) {
        SR_LOG_ERR("No info data found %d", ly_errno);
        return SR_ERR_INTERNAL;
    }

    struct ly_set *modules = lyd_get_node(info, "/ietf-yang-library:modules-state/module/name");
    if (NULL == modules) {
        SR_LOG_ERR_MSG("Error during module listing");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    } else if (0 == modules->number) {
        goto cleanup;
    }

    *schemas = calloc(modules->number, sizeof(**schemas));
    CHECK_NULL_NOMEM_GOTO(*schemas, rc, cleanup);

    for (unsigned int i = 0; i < modules->number; i++) {
        const char *revision = dm_get_module_revision(modules->set.d[i]->parent);
        const char *module_name = ((struct lyd_node_leaf_list *) modules->set.d[i])->value_str;
        if (dm_is_module_disabled(dm_ctx, module_name)) {
            SR_LOG_WRN("Module %s is disabled and will not be included in list schema", module_name);
            continue;
        }
        rc = dm_list_module(dm_ctx, module_name, revision, &(*schemas)[*schema_count]);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Filling sr_schema_t failed");
        (*schema_count)++;
    }

    /* return only files where we can locate schema files */
    for (int i = *schema_count - 1; i >= 0; i--) {
        sr_schema_t *s = &((*schemas)[i]);
        if (NULL == s->revision.file_path_yang && NULL == s->revision.file_path_yin) {
            sr_free_schema(s);
            memmove(&(*schemas)[i],
                    &(*schemas)[i + 1],
                    (*schema_count - i - 1) * sizeof(*s));
            (*schema_count)--;
        }
    }

cleanup:
    if (SR_ERR_OK != rc) {
        sr_free_schemas(*schemas, *schema_count);
        *schemas = NULL;
        *schema_count = 0;
    }
    ly_set_free(modules);
    lyd_free_withsiblings(info);
    return rc;
}

int
dm_get_schema(dm_ctx_t *dm_ctx, const char *module_name, const char *module_revision, const char *submodule_name, bool yang_format, char **schema)
{
    CHECK_NULL_ARG2(dm_ctx, module_name);
    int rc = SR_ERR_OK;

    const struct lys_module *module = ly_ctx_get_module(dm_ctx->ly_ctx, module_name, module_revision);
    if (NULL == module) {
        SR_LOG_ERR("Module %s with revision %s was not found", module_name, module_revision);
        return SR_ERR_NOT_FOUND;
    }

    if (NULL == submodule_name) {
        /* module*/
        rc = lys_print_mem(schema, module, yang_format ? LYS_OUT_YANG : LYS_OUT_YIN, NULL);
        if (0 != rc) {
            SR_LOG_ERR("Module %s print failed.", module->name);
            return SR_ERR_INTERNAL;
        }
        return SR_ERR_OK;
    }

    /* submodule */
    const struct lys_submodule *submodule = ly_ctx_get_submodule2(module, submodule_name);
    if (NULL == submodule) {
        SR_LOG_ERR("Submodule %s of module %s (%s) was not found.", submodule_name, module_name, module_revision);
        return SR_ERR_NOT_FOUND;
    }

    rc = lys_print_mem(schema, (const struct lys_module *) submodule, yang_format ? LYS_OUT_YANG : LYS_OUT_YIN, NULL);
    if (0 != rc) {
        SR_LOG_ERR("Submodule %s print failed.", submodule->name);
        return SR_ERR_INTERNAL;
    }
    return SR_ERR_OK;

}

int
dm_validate_session_data_trees(dm_ctx_t *dm_ctx, dm_session_t *session, sr_error_info_t **errors, size_t *err_cnt)
{
    CHECK_NULL_ARG4(dm_ctx, session, errors, err_cnt);
    int rc = SR_ERR_OK;

    size_t cnt = 0;
    *err_cnt = 0;
    dm_data_info_t *info = NULL;
    while (NULL != (info = sr_btree_get_at(session->session_modules, cnt))) {
        /* loaded data trees are valid, so check only the modified ones */
        if (info->modified) {
            if (NULL == info->module || NULL == info->module->name) {
                SR_LOG_ERR_MSG("Missing schema information");
                sr_free_errors(*errors, *err_cnt);
                return SR_ERR_INTERNAL;
            }
            if (NULL != info->node && 0 != lyd_validate(&info->node, LYD_OPT_STRICT | LYD_OPT_NOAUTODEL | LYD_OPT_CONFIG)) {
                SR_LOG_DBG("Validation failed for %s module", info->module->name);
                (*err_cnt)++;
                sr_error_info_t *tmp_err = realloc(*errors, *err_cnt * sizeof(**errors));
                if (NULL == tmp_err) {
                    SR_LOG_ERR_MSG("Memory allocation failed");
                    sr_free_errors(*errors, *err_cnt - 1);
                    return SR_ERR_NOMEM;
                }
                *errors = tmp_err;
                (*errors)[(*err_cnt) - 1].message = strdup(ly_errmsg());
                (*errors)[(*err_cnt) - 1].xpath = strdup(ly_errpath());

                rc = SR_ERR_VALIDATION_FAILED;
            } else {
                SR_LOG_DBG("Validation succeeded for '%s' module", info->module->name);
            }
        }
        cnt++;
    }
    return rc;
}

int
dm_discard_changes(dm_ctx_t *dm_ctx, dm_session_t *session)
{
    CHECK_NULL_ARG2(dm_ctx, session);
    int rc = SR_ERR_OK;

    sr_btree_cleanup(session->session_modules);
    session->session_modules = NULL;

    rc = sr_btree_init(dm_data_info_cmp, dm_data_info_free, &session->session_modules);
    CHECK_RC_MSG_RETURN(rc, "Binary tree allocation failed");
    dm_free_sess_operations(session->operations, session->oper_count);
    session->operations = NULL;
    session->oper_count = 0;
    session->oper_size = 0;

    return SR_ERR_OK;
}

static int
dm_is_info_copy_uptodate(const char *file_name, const dm_data_info_t *info, bool *res)
{
    CHECK_NULL_ARG(info);
    int rc;
#ifdef HAVE_STAT_ST_MTIM
    struct stat st = {0};
    rc = stat(file_name, &st);
    if (-1 == rc) {
        SR_LOG_ERR_MSG("Stat failed");
        return SR_ERR_INTERNAL;
    }
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    SR_LOG_DBG("Session copy %s: mtime sec=%lld nsec=%lld", info->module->name,
            (long long) info->timestamp.tv_sec,
            (long long) info->timestamp.tv_nsec);
    SR_LOG_DBG("Loaded module %s: mtime sec=%lld nsec=%lld", info->module->name,
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
            info->timestamp.tv_nsec == 0) {
        SR_LOG_DBG("Module %s will be refreshed", info->module->name);
        *res = false;

    } else {
        *res = true;
    }
#else
    *res = false;
#endif
    return SR_ERR_OK;

}

int
dm_update_session_data_trees(dm_ctx_t *dm_ctx, dm_session_t *session, struct ly_set **up_to_date_models)
{
    CHECK_NULL_ARG3(dm_ctx, session, up_to_date_models);
    int rc = SR_ERR_OK;
    int fd = -1;
    char *file_name = NULL;
    dm_data_info_t *info = NULL;
    size_t i = 0;
    struct ly_set *to_be_refreshed = NULL, *up_to_date = NULL;
    to_be_refreshed = ly_set_new();
    up_to_date = ly_set_new();

    CHECK_NULL_NOMEM_GOTO(to_be_refreshed, rc, cleanup);
    CHECK_NULL_NOMEM_GOTO(up_to_date, rc, cleanup);

    while (NULL != (info = sr_btree_get_at(session->session_modules, i++))) {
        rc = sr_get_data_file_name(dm_ctx->data_search_dir, info->module->name, session->datastore, &file_name);
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

        /*  to lock for read, blocking */
        rc = sr_lock_fd(fd, false, false);

        bool copy_uptodate = false;
        rc = dm_is_info_copy_uptodate(file_name, info, &copy_uptodate);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("File up to date check failed");
            close(fd);
            goto cleanup;
        }

        if (copy_uptodate) {
            if (info->modified) {
                ly_set_add(up_to_date, (void *) info->module->name);
            }
        } else {
            SR_LOG_DBG("Module %s will be refreshed", info->module->name);
            ly_set_add(to_be_refreshed, info);
        }
        free(file_name);
        file_name = NULL;
        close(fd);

    }

    for (i = 0; i < to_be_refreshed->number; i++) {
        sr_btree_delete(session->session_modules, to_be_refreshed->set.g[i]);
    }

cleanup:
    ly_set_free(to_be_refreshed);
    if (SR_ERR_OK == rc) {
        *up_to_date_models = up_to_date;
    } else {
        ly_set_free(up_to_date);
    }
    free(file_name);
    return rc;
}

void
dm_remove_operations_with_error(dm_session_t *session)
{
    CHECK_NULL_ARG_VOID(session);
    for (int i = session->oper_count - 1; i >= 0; i--) {
        dm_sess_op_t *op = &session->operations[i];
        if (op->has_error) {
            dm_free_sess_op(op);
            memmove(&session->operations[i],
                    &session->operations[i + 1],
                    (session->oper_count - i - 1) * sizeof(*op));
            session->oper_count--;
        }
    }
}

void
dm_free_commit_context(dm_ctx_t *dm_ctx, dm_commit_context_t *c_ctx)
{
    CHECK_NULL_ARG_VOID(c_ctx);
    for (size_t i = 0; i < c_ctx->modif_count; i++) {
        close(c_ctx->fds[i]);
    }
    free(c_ctx->fds);
    free(c_ctx->existed);
    ly_set_free(c_ctx->up_to_date_models);
    c_ctx->up_to_date_models = NULL;
    c_ctx->fds = NULL;
    c_ctx->existed = NULL;
    c_ctx->modif_count = 0;

    dm_session_stop(dm_ctx, c_ctx->session);
    c_ctx->session = NULL;
    free(c_ctx);
}

int
dm_commit_prepare_context(dm_ctx_t *dm_ctx, dm_session_t *session, dm_commit_context_t **commit_ctx)
{
    CHECK_NULL_ARG2(session, commit_ctx);
    dm_data_info_t *info = NULL;
    size_t i = 0;
    int rc = SR_ERR_OK;
    dm_commit_context_t *c_ctx = NULL;
    c_ctx = calloc(1, sizeof(*c_ctx));
    CHECK_NULL_NOMEM_RETURN(c_ctx);

    c_ctx->modif_count = 0;
    /* count modified files */
    while (NULL != (info = sr_btree_get_at(session->session_modules, i))) {
        if (info->modified) {
            c_ctx->modif_count++;
        }
        i++;
    }

    SR_LOG_DBG("Commit: In the session there are %zu / %zu modified models", c_ctx->modif_count, i);

    if (0 == session->oper_count && 0 != c_ctx->modif_count) {
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
    rc = dm_session_start(dm_ctx, session->user_credentials, session->datastore, &c_ctx->session);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Commit session initialization failed");

    c_ctx->up_to_date_models = ly_set_new();
    CHECK_NULL_NOMEM_GOTO(c_ctx->up_to_date_models, rc, cleanup);

    /* set pointer to the list of operations to be committed */
    c_ctx->operations = session->operations;
    c_ctx->oper_count = session->oper_count;

    *commit_ctx = c_ctx;
    return rc;

cleanup:
    dm_free_commit_context(dm_ctx, c_ctx);
    return rc;
}

int
dm_commit_load_modified_models(dm_ctx_t *dm_ctx, const dm_session_t *session, dm_commit_context_t *c_ctx)
{
    CHECK_NULL_ARG(c_ctx);
    CHECK_NULL_ARG5(dm_ctx, session, c_ctx->session, c_ctx->fds, c_ctx->existed);
    CHECK_NULL_ARG(c_ctx->up_to_date_models);
    dm_data_info_t *info = NULL;
    size_t i = 0;
    size_t count = 0;
    int rc = SR_ERR_OK;
    char *file_name = NULL;
    c_ctx->modif_count = 0; /* how many file descriptors should be closed on cleanup */

    while (NULL != (info = sr_btree_get_at(session->session_modules, i++))) {
        if (info->modified) {
            rc = dm_lock_module(dm_ctx, c_ctx->session, (char *) info->module->name);
            if (SR_ERR_LOCKED == rc) {
                /* check if the lock is hold by session that issued commit */
                rc = dm_lock_module(dm_ctx, (dm_session_t *) session, (char *) info->module->name);
            }
            CHECK_RC_LOG_RETURN(rc, "Module %s can not be locked", info->module->name);
        }
    }
    i = 0;

    ac_set_user_identity(dm_ctx->ac_ctx, session->user_credentials);

    while (NULL != (info = sr_btree_get_at(session->session_modules, i++))) {
        if (!info->modified) {
            continue;
        }
        rc = sr_get_data_file_name(dm_ctx->data_search_dir, info->module->name, session->datastore, &file_name);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Get data file name failed");

        c_ctx->fds[count] = open(file_name, O_RDWR);
        if (-1 == c_ctx->fds[count]) {
            SR_LOG_DBG("File %s can not be opened for read write", file_name);
            if (EACCES == errno) {
                SR_LOG_ERR("File %s can not be opened because of authorization", file_name);
                rc = SR_ERR_UNAUTHORIZED;
                goto cleanup;
            }

            if (ENOENT == errno) {
                SR_LOG_DBG("File %s does not exist, trying to create an empty one", file_name);
                c_ctx->fds[count] = open(file_name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
                if (-1 == c_ctx->fds[count]) {
                    SR_LOG_ERR("File %s can not be created", file_name);
                    rc = SR_ERR_IO;
                    goto cleanup;
                }
            }
        } else {
            c_ctx->existed[count] = true;
        }
        /* file was opened successfully increment the number of files to be closed */
        c_ctx->modif_count++;
        /* try to lock for write, non-blocking */
        rc = sr_lock_fd(c_ctx->fds[count], true, false);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Locking of file '%s' failed: %s.", file_name, sr_strerror(rc));
            rc = SR_ERR_COMMIT_FAILED;
            goto cleanup;
        }
        dm_data_info_t *di = NULL;

        bool copy_uptodate = false;
        rc = dm_is_info_copy_uptodate(file_name, info, &copy_uptodate);
        CHECK_RC_MSG_GOTO(rc, cleanup, "File up to date check failed");

        if (copy_uptodate) {
            SR_LOG_DBG("Timestamp for the model %s matches, ops will be skipped", info->module->name);
            rc = ly_set_add(c_ctx->up_to_date_models, (void *) info->module->name);
            if (0 != rc) {
                SR_LOG_ERR_MSG("Adding to ly set failed");
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            di = calloc(1, sizeof(*di));
            CHECK_NULL_NOMEM_GOTO(di, rc, cleanup);
            di->node = sr_dup_datatree(info->node);
            if (NULL != info->node && NULL == di->node) {
                SR_LOG_ERR_MSG("Data tree duplication failed");
                rc = SR_ERR_INTERNAL;
                dm_data_info_free(di);
                goto cleanup;
            }
            di->module = info->module;
        } else {
            /* if the file existed pass FILE 'r+', otherwise pass -1 because there is 'w' fd already */
            rc = dm_load_data_tree_file(dm_ctx, c_ctx->existed[count] ? c_ctx->fds[count] : -1, file_name, info->module, &di);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Loading data file failed");
        }

        rc = sr_btree_insert(c_ctx->session->session_modules, (void *) di);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Insert into commit session avl failed module %s", info->module->name);
            dm_data_info_free(di);
            goto cleanup;
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
    while (NULL != (info = sr_btree_get_at(session->session_modules, i))) {
        if (info->modified) {
            /* get merged info */
            merged_info = sr_btree_search(c_ctx->session->session_modules, info);
            if (NULL == merged_info) {
                SR_LOG_ERR("Merged data info %s not found", info->module->name);
                rc = SR_ERR_INTERNAL;
                continue;
            }
            ret = ftruncate(c_ctx->fds[count], 0);
            if (0 == ret) {
                lyd_wd_cleanup(&merged_info->node, 0);
                ly_errno = LY_SUCCESS; /* needed to check if the error was in libyang or not below */
                ret = lyd_print_fd(c_ctx->fds[count], merged_info->node, LYD_XML, LYP_WITHSIBLINGS | LYP_FORMAT);
            }
            if (0 == ret) {
                ret = fsync(c_ctx->fds[count]);
            }
            if (0 != ret) {
                SR_LOG_ERR("Failed to write data of '%s' module: %s", info->module->name,
                        (ly_errno != LY_SUCCESS) ? ly_errmsg() : strerror(errno));
                rc = SR_ERR_INTERNAL;
            } else {
                SR_LOG_DBG("Data successfully written for module '%s'", info->module->name);
            }
            count++;
        }
        i++;
    }
    return rc;
}

int
dm_commit_notify(dm_ctx_t *dm_ctx, dm_session_t *session, dm_commit_context_t *c_ctx)
{
    CHECK_NULL_ARG3(dm_ctx, session, c_ctx);
    int rc = SR_ERR_OK;
    size_t i = 0;
    dm_data_info_t *info = NULL;

    if (SR_DS_RUNNING == session->datastore) {
        SR_LOG_DBG_MSG("Sending notifications about the changes made in running datastore...");
        i = 0;
        while (NULL != (info = sr_btree_get_at(session->session_modules, i))) {
            if (info->modified) {
                rc = np_module_change_notify(dm_ctx->np_ctx, info->module->name);
                if (SR_ERR_OK != rc) {
                    SR_LOG_WRN("Unable to send notifications about the changes made in the '%s' module.", info->module->name);
                }
            }
            i++;
        }
    }

    return SR_ERR_OK;
}

int
dm_feature_enable(dm_ctx_t *dm_ctx, const char *module_name, const char *feature_name, bool enable)
{
    CHECK_NULL_ARG3(dm_ctx, module_name, feature_name);
    int rc = SR_ERR_OK;

    pthread_rwlock_wrlock(&dm_ctx->lyctx_lock);

    const struct lys_module *module = ly_ctx_get_module(dm_ctx->ly_ctx, module_name, NULL);
    if (NULL == module) {
        pthread_rwlock_unlock(&dm_ctx->lyctx_lock);
        SR_LOG_ERR("Module %s was not found", module_name);
        return SR_ERR_UNKNOWN_MODEL;
    }
    rc = enable ? lys_features_enable(module, feature_name) : lys_features_disable(module, feature_name);
    pthread_rwlock_unlock(&dm_ctx->lyctx_lock);

    if (1 == rc) {
        SR_LOG_ERR("Unknown feature %s in model %s", feature_name, module_name);
    }

    return rc;
}

int
dm_install_module(dm_ctx_t *dm_ctx, const char *module_name, const char *revision)
{
    CHECK_NULL_ARG2(dm_ctx, module_name);

    pthread_rwlock_wrlock(&dm_ctx->lyctx_lock);

    /* if module is disabled require sysrepo restart to its reinstall*/
    if (dm_is_module_disabled(dm_ctx, module_name)) {
        pthread_rwlock_unlock(&dm_ctx->lyctx_lock);
        SR_LOG_WRN("To install module %s sysrepo must be restarted", module_name);
        return SR_ERR_INTERNAL;
    }
    const struct lys_module *module = ly_ctx_load_module(dm_ctx->ly_ctx, module_name, revision);
    pthread_rwlock_unlock(&dm_ctx->lyctx_lock);

    if (NULL == module) {
        SR_LOG_ERR("Module %s with revision %s was not found", module_name, revision);
        return SR_ERR_NOT_FOUND;
    } else {
        return SR_ERR_OK;
    }
}

int
dm_uninstall_module(dm_ctx_t *dm_ctx, const char *module_name, const char *revision)
{
    CHECK_NULL_ARG2(dm_ctx, module_name);
    int rc = SR_ERR_OK;

    pthread_rwlock_wrlock(&dm_ctx->lyctx_lock);
    const struct lys_module *module = ly_ctx_get_module(dm_ctx->ly_ctx, module_name, revision);

    if (NULL == module) {
        SR_LOG_ERR("Module %s with revision %s was not found", module_name, revision);
        rc = SR_ERR_NOT_FOUND;
    } else {
        ly_set_add(dm_ctx->disabled_sch, (void *) module->name);
        rc = SR_ERR_OK;
    }

    pthread_rwlock_unlock(&dm_ctx->lyctx_lock);
    return rc;
}

static int
dm_copy_config(dm_ctx_t *dm_ctx, dm_session_t *session, const struct ly_set *modules, sr_datastore_t src, sr_datastore_t dst)
{
    CHECK_NULL_ARG2(dm_ctx, modules);
    int rc = SR_ERR_OK;
    dm_session_t *src_session = NULL;
    dm_session_t *dst_session = NULL;
    struct lys_module *module = NULL;
    dm_data_info_t **src_infos = NULL;
    size_t opened_files = 0;
    char *file_name = NULL;
    int *fds = NULL;

    if (src == dst || 0 == modules->number) {
        return rc;
    }

    src_infos = calloc(modules->number, sizeof(*src_infos));
    CHECK_NULL_NOMEM_GOTO(src_infos, rc, cleanup);
    fds = calloc(modules->number, sizeof(*fds));
    CHECK_NULL_NOMEM_GOTO(fds, rc, cleanup);

    /* create source session */
    rc = dm_session_start(dm_ctx, (session != NULL ? session->user_credentials : NULL), src, &src_session);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Creating of temporary session failed");

    /* create destination session */
    rc = dm_session_start(dm_ctx, (session != NULL ? session->user_credentials : NULL), dst, &dst_session);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Creating of temporary session failed");

    for (size_t i = 0; i < modules->number; i++) {
        module = (struct lys_module *) modules->set.g[i];
        /* lock module in source ds */
        rc = dm_lock_module(dm_ctx, src_session, (char *) module->name);
        if (SR_ERR_LOCKED == rc && NULL != session && src == session->datastore) {
            /* check if the lock is hold by session that issued copy-config */
            rc = dm_lock_module(dm_ctx, session, (char *) module->name);
        }
        CHECK_RC_LOG_GOTO(rc, cleanup, "Module %s can not be locked in source datastore", module->name);

        /* lock module in destination */
        rc = dm_lock_module(dm_ctx, dst_session, (char *) module->name);
        if (SR_ERR_LOCKED == rc && NULL != session && dst == session->datastore) {
            /* check if the lock is hold by session that issued copy-config */
            rc = dm_lock_module(dm_ctx, session, (char *) module->name);
        }
        CHECK_RC_LOG_GOTO(rc, cleanup, "Module %s can not be locked in destination datastore", module->name);

        /* load data tree to be copied*/
        rc = dm_get_data_info(dm_ctx, src_session, module->name, &(src_infos[i]));
        CHECK_RC_MSG_GOTO(rc, cleanup, "Get data info failed");

        /* create data file name */
        rc = sr_get_data_file_name(dm_ctx->data_search_dir, module->name, dst_session->datastore, &file_name);
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

    int ret = 0;
    for (size_t i = 0; i < modules->number; i++) {
        /* write dest file*/
        lyd_wd_cleanup(&src_infos[i]->node, 0);
        if (0 != lyd_print_fd(fds[i], src_infos[i]->node, LYD_XML, LYP_WITHSIBLINGS | LYP_FORMAT)) {
            SR_LOG_ERR("Copy of module %s failed", module->name);
            rc = SR_ERR_INTERNAL;
        }
        ret = fsync(fds[i]);
        if (0 != ret) {
            SR_LOG_ERR("Failed to write data of '%s' module: %s", src_infos[i]->module->name,
                    (ly_errno != LY_SUCCESS) ? ly_errmsg() : strerror(errno));
            rc = SR_ERR_INTERNAL;
        }
    }

cleanup:
    dm_session_stop(dm_ctx, src_session);
    dm_session_stop(dm_ctx, dst_session);
    for (size_t i = 0; i < opened_files; i++) {
        close(fds[i]);
    }
    free(fds);
    free(src_infos);
    return rc;
}

int
dm_has_enabled_subtree(dm_ctx_t *ctx, const char *module_name, const struct lys_module **module, bool *res)
{
    CHECK_NULL_ARG3(ctx, module_name, res);
    int rc = SR_ERR_OK;
    const struct lys_module *mod = NULL;
    rc = dm_get_module(ctx, module_name, NULL, &mod);
    CHECK_RC_MSG_RETURN(rc, "Get module failed");
    CHECK_NULL_ARG(mod->name);

    *res = false;
    struct lys_node *node = mod->data;
    dm_schema_info_t *si = NULL;
    rc = dm_get_schema_info((dm_ctx_t *) ctx, mod->name, &si);
    CHECK_RC_LOG_RETURN(rc, "Get schema info failed for %s", mod->name);

    pthread_rwlock_rdlock(&si->model_lock);
    while (NULL != node) {
        if (dm_is_enabled_check_recursively(node)) {
            *res = true;
            break;
        }
        node = node->next;
    }
    pthread_rwlock_unlock(&si->model_lock);
    if (NULL != module) {
        *module = (struct lys_module *) mod;
    }

    return rc;
}

int
dm_enable_module_running(dm_ctx_t *ctx, dm_session_t *session, const char *module_name, const struct lys_module *module)
{
    CHECK_NULL_ARG2(ctx, module_name);
    bool module_enabled = false;
    char xpath[PATH_MAX] = {0,};
    int rc = SR_ERR_OK;

    if (NULL == module) {
        /* if module is not known, get it and check if it is already enabled */
        rc = dm_has_enabled_subtree(ctx, module_name, &module, &module_enabled);
    }
    if (SR_ERR_OK == rc && !module_enabled) {
        /* if not already enabled, enable each subtree within the module */
        struct lys_node *node = module->data;
        while (NULL != node) {
            if ((LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST) & node->nodetype) {
                snprintf(xpath, PATH_MAX, "/%s:%s", node->module->name, node->name);
                rc = rp_dt_enable_xpath(ctx, session, xpath);
                if (SR_ERR_OK != rc) {
                    break;
                }
            }
            node = node->next;
        }
    }
    if (SR_ERR_OK == rc && !module_enabled) {
        /* if not already enabled, copy the data from startup */
        rc = dm_copy_module(ctx, session, module_name, SR_DS_STARTUP, SR_DS_RUNNING);
    }
    return rc;
}

int
dm_disable_module_running(dm_ctx_t *ctx, dm_session_t *session, const char *module_name, const struct lys_module *module)
{
    CHECK_NULL_ARG2(ctx, module_name);
    bool module_enabled = false;
    int rc = SR_ERR_OK;

    if (NULL == module) {
        /* if module is not known, get it and check if it is already enabled */
        rc = dm_has_enabled_subtree(ctx, module_name, &module, &module_enabled);
    }
    if (SR_ERR_OK == rc && module_enabled) {
        /* if enabled, disable each subtree within the module */

        dm_schema_info_t *si = NULL;
        rc = dm_get_schema_info(ctx, module->name, &si);
        CHECK_RC_LOG_RETURN(rc, "Get schema info failed %s", module->name);
        struct lys_node *iter = NULL, *child = NULL;
        struct ly_set *stack = NULL;
        stack = ly_set_new();
        CHECK_NULL_NOMEM_RETURN(stack);
        pthread_rwlock_wrlock(&si->model_lock);

        /* iterate through top-level nodes */
        LY_TREE_FOR(module->data, iter)
        {
            if (((LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST) & iter->nodetype) && dm_is_node_enabled(iter)) {
                rc = dm_set_node_state(iter, DM_NODE_DISABLED);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Set node state failed");

                if ((LYS_CONTAINER | LYS_LIST) & iter->nodetype) {
                    LY_TREE_FOR(iter->child, child)
                    {
                        if (((LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST) & iter->nodetype) && dm_is_node_enabled(child)) {
                            rc = ly_set_add(stack, child);
                            CHECK_ZERO_MSG_GOTO(rc, rc, SR_ERR_INTERNAL, cleanup, "Adding to ly_set failed");
                        }
                    }
                }
            }
        }

        /* recursively disable all enabled children*/
        while (stack->number != 0) {
            iter = stack->set.s[stack->number - 1];
            rc = dm_set_node_state(iter, DM_NODE_DISABLED);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Set node state failed");

            ly_set_rm_index(stack, stack->number - 1);

            if ((LYS_CONTAINER | LYS_LIST) & iter->nodetype) {
                LY_TREE_FOR(iter->child, child)
                {
                    if (((LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST) & child->nodetype) && dm_is_node_enabled(child)) {
                        rc = ly_set_add(stack, child);
                        CHECK_ZERO_MSG_GOTO(rc, rc, SR_ERR_INTERNAL, cleanup, "Adding to ly_set failed");
                    }
                }
            }
        }
cleanup:
        pthread_rwlock_unlock(&si->model_lock);
        ly_set_free(stack);
    }

    return rc;
}

int
dm_copy_module(dm_ctx_t *dm_ctx, dm_session_t *session, const char *module_name, sr_datastore_t src, sr_datastore_t dst)
{
    CHECK_NULL_ARG2(dm_ctx, module_name);
    struct ly_set *module_set = NULL;
    const struct lys_module *module = NULL;
    int rc = SR_ERR_OK;

    module_set = ly_set_new();
    CHECK_NULL_NOMEM_RETURN(module_set);

    rc = dm_get_module(dm_ctx, module_name, NULL, &module);
    CHECK_RC_MSG_GOTO(rc, cleanup, "dm_get_module failed");

    if (0 != ly_set_add(module_set, (struct lys_module *) module)) {
        SR_LOG_ERR_MSG("ly_set_add failed");
        goto cleanup;
    }

    rc = dm_copy_config(dm_ctx, session, module_set, src, dst);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Dm copy config failed");

cleanup:
    ly_set_free(module_set);
    return rc;
}

int
dm_copy_all_models(dm_ctx_t *dm_ctx, dm_session_t *session, sr_datastore_t src, sr_datastore_t dst)
{
    CHECK_NULL_ARG2(dm_ctx, session);
    struct ly_set *enabled_modules = NULL;
    sr_schema_t *schemas = NULL;
    size_t count = 0;
    const struct lys_module *module = NULL;
    int rc = SR_ERR_OK;

    enabled_modules = ly_set_new();
    CHECK_NULL_NOMEM_RETURN(enabled_modules);

    rc = dm_list_schemas(dm_ctx, session, &schemas, &count);
    CHECK_RC_MSG_GOTO(rc, cleanup, "List schemas failed");

    /* find enable subtrees */
    for (size_t i = 0; i < count; i++) {
        bool enabled = false;
        rc = dm_has_enabled_subtree(dm_ctx, schemas[i].module_name, &module, &enabled);
        CHECK_RC_LOG_GOTO(rc, cleanup, "Has enabled subtree failed %s", schemas[i].module_name);

        if (!enabled) {
            continue;
        }
        if (0 != ly_set_add(enabled_modules, (struct lys_module *) module)) {
            SR_LOG_ERR_MSG("ly_set_add failed");
            goto cleanup;
        }
    }
    rc = dm_copy_config(dm_ctx, session, enabled_modules, src, dst);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Dm copy config failed");

cleanup:
    ly_set_free(enabled_modules);
    sr_free_schemas(schemas, count);
    return rc;
}
