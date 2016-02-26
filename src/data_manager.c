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
#include "rp_dt_edit.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <pthread.h>
#include <fcntl.h>


/*
 * @brief Data manager context holding loaded schemas, data trees
 * and corresponding locks
 */
typedef struct dm_ctx_s {
    char *schema_search_dir;      /**< location where schema files are located */
    char *data_search_dir;        /**< location where data files are located */
    struct ly_ctx *ly_ctx;        /**< libyang context holding all loaded schemas */
    pthread_rwlock_t lyctx_lock;  /**< rwlock to access ly_ctx */
    pthread_mutex_t commit_lock;  /**< lock to synchronize commit in this instance */
} dm_ctx_t;

/**
 * @brief Structure that holds Data Manager's per-session context.
 */
typedef struct dm_session_s {
    sr_datastore_t datastore;       /**< datastore to which the session is tied */
    sr_btree_t *session_modules;    /**< binary holding session copies of data models */
    char *error_msg;                /**< description of the last error */
    char *error_xpath;              /**< xpath of the last error if applicable */
    dm_sess_op_t *operations;       /**< list of operations performed in this session */
    size_t oper_count;              /**< number of performed operation */
    size_t oper_size;               /**< number of allocated operations */
} dm_session_t;

/**
 * @brief Structure holding information used during commit process
 */
typedef struct dm_commit_context_s {
    dm_session_t *session;      /**< session where mereged (user changes + file system state) data trees are stored */
    int *fds;                   /**< opened file descriptors */
    bool *existed;              /**< flag wheter the file for the filedesriptor existed (and should be truncated) before commit*/
    size_t modif_count;         /**< number of modified models fds to be closed*/
#ifdef HAVE_STAT_ST_MTIM
    struct ly_set *up_to_date_models; /**< set of module names where the timestamp of the session copy is equal to file system timestamp */
#endif
} dm_commit_context_t;
/**
 * @brief Info structure for the node holds the state of the running data store.
 * (It will hold information about notification subscriptions.)
 */
typedef struct dm_node_info_s {
    dm_node_state_t state;
} dm_node_info_t;

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

/**
 * @brief Check whether the file_name corresponds to the schema file.
 * @return 1 if it does, 0 otherwise.
 */
static int
dm_is_schema_file(const char *file_name)
{
    CHECK_NULL_ARG(file_name);
    return sr_str_ends_with(file_name, SR_SCHEMA_YIN_FILE_EXT);
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
    int rc = sr_str_join(dir_name, file_name, &schema_filename);
    if (SR_ERR_OK != rc) {
        return SR_ERR_NOMEM;
    }

    pthread_rwlock_wrlock(&dm_ctx->lyctx_lock);
    module = lys_parse_path(dm_ctx->ly_ctx, schema_filename, LYS_IN_YIN);
    free(schema_filename);
    if (module == NULL) {
        SR_LOG_WRN("Unable to parse a schema file: %s", file_name);
        pthread_rwlock_unlock(&dm_ctx->lyctx_lock);
        return SR_ERR_INTERNAL;
    }

    pthread_rwlock_unlock(&dm_ctx->lyctx_lock);
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

/**
 * Checks whether the schema of the module has been loaded
 * @param [in] dm_ctx
 * @param [in] module_name
 * @return Error code (SR_ERR_OK on success), SR_ERR_UNKNOWN_MODEL
 */
static int
dm_find_module_schema(dm_ctx_t *dm_ctx, const char *module_name, const struct lys_module **module)
{
    CHECK_NULL_ARG2(dm_ctx, module_name);
    pthread_rwlock_rdlock(&dm_ctx->lyctx_lock);
    *module = ly_ctx_get_module(dm_ctx->ly_ctx, module_name, NULL);
    pthread_rwlock_unlock(&dm_ctx->lyctx_lock);
    return *module == NULL ? SR_ERR_UNKNOWN_MODEL : SR_ERR_OK;
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
    if (NULL == data) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }

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
        SR_LOG_DBG("Loaded module %s: mtime sec=%lld nsec=%lld\n", module->name,
                (long long) st.st_mtim.tv_sec,
                (long long) st.st_mtim.tv_nsec);
#endif
        data_tree = lyd_parse_fd(dm_ctx->ly_ctx, fd, LYD_XML, LYD_OPT_STRICT);
        if (NULL == data_tree) {
            SR_LOG_ERR("Parsing data tree from file %s failed", data_filename);
            free(data);
            return SR_ERR_INTERNAL;
        }
    }

    /* if the data tree is loaded, validate it*/
    if (NULL != data_tree && 0 != lyd_validate(data_tree, LYD_OPT_STRICT)) {
        SR_LOG_ERR("Loaded data tree '%s' is not valid", data_filename);
        lyd_free_withsiblings(data_tree);
        free(data);
        return SR_ERR_INTERNAL;
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
 * @param [in] module
 * @param [in] ds
 * @param [out] data_info
 * @return Error code (SR_ERR_OK on success), SR_ERR_INTERAL if the parsing of the data tree fails.
 */
static int
dm_load_data_tree(dm_ctx_t *dm_ctx, const struct lys_module *module, sr_datastore_t ds, dm_data_info_t **data_info)
{
    CHECK_NULL_ARG2(dm_ctx, module);

    char *data_filename = NULL;
    int rc = 0;
    *data_info = NULL;
    rc = sr_get_data_file_name(dm_ctx->data_search_dir, module->name, ds, &data_filename);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Get data_filename failed for %s", module->name);
        return rc;
    }

    int fd = open(data_filename, O_RDONLY);

    if (-1 != fd) {
        lockf(fd, F_LOCK, 0);
    } else if (ENOENT == errno) {
        SR_LOG_DBG("Data file %s does not exist, creating empty data tree", data_filename);
    } else if (EACCES == errno) {
        SR_LOG_DBG("Data file %s can't be read because of access rights", data_filename);
        free(data_filename);
        return SR_ERR_UNAUTHORIZED;
    }

    rc = dm_load_data_tree_file(dm_ctx, fd, data_filename, module, data_info);

    if (-1 != fd) {
        lockf(fd, F_ULOCK, 0);
        close(fd);
    }

    free(data_filename);
    return rc;
}

/**
 * @brief Fills the schema_t from lys_module structure
 * @return Error code (SR_ERR_OK on success), SR_ERR_INTERNAL in case of string duplication failure
 */
static int
dm_fill_schema_t(dm_ctx_t *dm_ctx, dm_session_t *session, const struct lys_module *module, sr_schema_t *schema)
{
    CHECK_NULL_ARG2(module, schema);
    CHECK_NULL_ARG3(module->name, module->prefix, module->ns);
    int rc = SR_ERR_INTERNAL;

    schema->module_name = strdup(module->name);
    schema->prefix = strdup(module->prefix);
    schema->ns = strdup(module->ns);
    if (NULL == schema->module_name || NULL == schema->prefix || NULL == schema->ns) {
        SR_LOG_ERR_MSG("Duplication of string for schema_t failed");
        goto cleanup;
    }

    /* revision is optional*/
    if (NULL != module->rev) {
        schema->revision = strdup(module->rev[0].date);
        if (NULL == schema->revision) {
            SR_LOG_ERR_MSG("Duplication of revision string failed");
            goto cleanup;
        }
    }

    rc = sr_get_schema_file_name(dm_ctx->schema_search_dir, module->name, true, &schema->file_path_yang);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Get schema file name failed");
        goto cleanup;
    }
    rc = sr_get_schema_file_name(dm_ctx->schema_search_dir, module->name, false, &schema->file_path_yin);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Get schema file name failed");
        goto cleanup;
    }
    if (-1 == access(schema->file_path_yang, F_OK)) {
        free(schema->file_path_yang);
        schema->file_path_yang = NULL;
    }
    if (-1 == access(schema->file_path_yin, F_OK)) {
        free(schema->file_path_yin);
        schema->file_path_yin = NULL;
    }
    return rc;

cleanup:
    free(schema->module_name);
    free(schema->prefix);
    free(schema->ns);
    free(schema->revision);
    free(schema->file_path_yang);
    free(schema->file_path_yin);
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
    xp_free_loc_id(op->loc_id);
    sr_free_val(op->val);
}

static void
dm_free_sess_operations(dm_sess_op_t *ops, size_t count)
{
    if (NULL == ops){
        return;
    }

    for (size_t i = 0; i < count; i++) {
        dm_free_sess_op(&ops[i]);
    }
    free(ops);
}

/**
 * @brief Returns the state of node. If the NULL is provided as an argument
 * DM_NODE_DISABLED is returned.
 */
static dm_node_state_t
dm_get_node_state(struct lys_node *node)
{
    if (NULL == node || NULL == node->private) {
        return DM_NODE_DISABLED;
    }
    dm_node_info_t *n_info = (dm_node_info_t *) node->private;

    if (NULL == n_info) {
        return DM_NODE_DISABLED;
    }
    return n_info->state;
}

int
dm_add_operation(dm_session_t *session, dm_operation_t op, xp_loc_id_t *loc_id, sr_val_t *val, sr_edit_options_t opts)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_ARG_NORET2(rc, session, loc_id); /* value can be NULL*/
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    if (NULL == session->operations){
        session->oper_size = 1;
        session->operations = calloc(session->oper_size, sizeof(*session->operations));
        if (NULL == session->operations){
            SR_LOG_ERR_MSG("Memory allocation failed");
            rc = SR_ERR_NOMEM;
            goto cleanup;
        }
    } else if (session->oper_count == session->oper_size){
        session->oper_size *= 2;
        dm_sess_op_t *tmp_op = realloc(session->operations, session->oper_size * sizeof(*session->operations));
        if (NULL == tmp_op){
            SR_LOG_ERR_MSG("Memory allocation failed");
            rc = SR_ERR_NOMEM;
            goto cleanup;
        }
        session->operations = tmp_op;
    }
    session->operations[session->oper_count].op = op;
    session->operations[session->oper_count].loc_id = loc_id;
    session->operations[session->oper_count].val = val;
    session->operations[session->oper_count].options = opts;

    session->oper_count++;
    return rc;
cleanup:
    xp_free_loc_id(loc_id);
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
        session->operations[session->oper_count].loc_id = NULL;
        session->operations[session->oper_count].val = NULL;
    }
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
    if (NULL == node->private) {
        node->private = calloc(1, sizeof(dm_node_info_t));
        if (NULL == node->private) {
            SR_LOG_ERR_MSG("Memory allocation failed");
            return SR_ERR_NOMEM;
        }
    }
    ((dm_node_info_t *) node->private)->state = state;
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
dm_init(const char *schema_search_dir, const char *data_search_dir, dm_ctx_t **dm_ctx)
{
    CHECK_NULL_ARG3(schema_search_dir, data_search_dir, dm_ctx);

    SR_LOG_INF("Initializing Data Manager, schema_search_dir=%s, data_search_dir=%s", schema_search_dir, data_search_dir);

    dm_ctx_t *ctx = NULL;
    ctx = calloc(1, sizeof(*ctx));
    if (NULL == ctx) {
        SR_LOG_ERR_MSG("Cannot allocate memory for Data Manager.");
        return SR_ERR_NOMEM;
    }
    ctx->ly_ctx = ly_ctx_new(schema_search_dir);
    if (NULL == ctx->ly_ctx) {
        SR_LOG_ERR_MSG("Cannot initialize libyang context in Data Manager.");
        dm_cleanup(ctx);
        return SR_ERR_NOMEM;
    }

    ctx->schema_search_dir = strdup(schema_search_dir);
    if (NULL == ctx->schema_search_dir) {
        SR_LOG_ERR_MSG("Cannot allocate memory for schema search dir string in Data Manager.");
        dm_cleanup(ctx);
        return SR_ERR_NOMEM;
    }

    ctx->data_search_dir = strdup(data_search_dir);
    if (NULL == ctx->data_search_dir) {
        SR_LOG_ERR_MSG("Cannot allocate memory for data search dir string in Data Manager.");
        dm_cleanup(ctx);
        return SR_ERR_NOMEM;
    }

    pthread_rwlockattr_t attr;
    pthread_rwlockattr_init(&attr);
#if defined(HAVE_PTHREAD_RWLOCKATTR_SETKIND_NP)
    pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
#endif

    int rc = pthread_rwlock_init(&ctx->lyctx_lock, &attr);
    pthread_rwlockattr_destroy(&attr);
    if (0 != rc) {
        SR_LOG_ERR_MSG("lyctx mutex initialization failed");
        dm_cleanup(ctx);
        return SR_ERR_INTERNAL;
    }

    rc = pthread_mutex_init(&ctx->commit_lock, NULL);
    if (0 != rc) {
        SR_LOG_ERR_MSG("Pthread mutex init failed");
        dm_cleanup(ctx);
        return SR_ERR_INTERNAL;
    }

    *dm_ctx = ctx;
    rc = dm_load_schemas(ctx);
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
        if (NULL != dm_ctx->ly_ctx) {
            ly_ctx_destroy(dm_ctx->ly_ctx, dm_free_lys_private_data);
        }
        pthread_mutex_destroy(&dm_ctx->commit_lock);
        pthread_rwlock_destroy(&dm_ctx->lyctx_lock);
        free(dm_ctx);
    }
}

int
dm_session_start(const dm_ctx_t *dm_ctx, const sr_datastore_t ds, dm_session_t **dm_session_ctx)
{
    CHECK_NULL_ARG(dm_session_ctx);

    dm_session_t *session_ctx = NULL;
    session_ctx = calloc(1, sizeof(*session_ctx));
    if (NULL == session_ctx) {
        SR_LOG_ERR_MSG("Cannot allocate session_ctx in Data Manager.");
        return SR_ERR_NOMEM;
    }
    session_ctx->datastore = ds;

    int rc = SR_ERR_OK;
    rc = sr_btree_init(dm_data_info_cmp, dm_data_info_free, &session_ctx->session_modules);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Binary tree allocation failed");
        free(session_ctx);
        return SR_ERR_NOMEM;
    }
    *dm_session_ctx = session_ctx;

    return SR_ERR_OK;
}

void
dm_session_stop(const dm_ctx_t *dm_ctx, dm_session_t *session)
{
    CHECK_NULL_ARG_VOID2(dm_ctx, session);
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
    rc = dm_load_data_tree(dm_ctx, module, dm_session_ctx->datastore, &di);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Getting data tree for %s failed.", module_name);
        return rc;
    }

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
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Get data info failed for module %s", module_name);
        return rc;
    }
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

int
dm_list_schemas(dm_ctx_t *dm_ctx, dm_session_t *dm_session, sr_schema_t **schemas, size_t *schema_count)
{
    CHECK_NULL_ARG4(dm_ctx, dm_session, schemas, schema_count);
    size_t count = 0;
    size_t i = 0;
    sr_schema_t *sch = NULL;
    int rc = SR_ERR_OK;
    const char **names = ly_ctx_get_module_names(dm_ctx->ly_ctx);
    if (NULL == names) {
        *schema_count = 0;
        *schemas = NULL;
        return SR_ERR_OK;
    }

    while (NULL != names[count]) count++;

    sch = calloc(count, sizeof(*sch));
    if (NULL == sch) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        free(names);
        return SR_ERR_NOMEM;
    }

    const struct lys_module *module = NULL;
    i = 0;
    while (NULL != names[i]) {
        module = ly_ctx_get_module(dm_ctx->ly_ctx, names[i], NULL);
        rc = dm_fill_schema_t(dm_ctx, dm_session, module, &sch[i]);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Filling sr_schema_t failed");
            sr_free_schemas(sch, i);
            free(names);
            return rc;
        }
        i++;
    }

    *schemas = sch;
    *schema_count = count;
    free(names);
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
            if (0 != lyd_validate(info->node, LYD_OPT_STRICT)) {
                SR_LOG_DBG("Validation failed for %s module", info->module->name);
                (*err_cnt)++;
                sr_error_info_t *tmp_err = realloc(*errors, *err_cnt * sizeof(**errors));
                if (NULL == tmp_err){
                    SR_LOG_ERR_MSG("Memory allocation failed");
                    sr_free_errors(*errors, *err_cnt - 1);
                    return SR_ERR_NOMEM;
                }
                *errors = tmp_err;
                (*errors)[(*err_cnt)-1].message = strdup(ly_errmsg());
                (*errors)[(*err_cnt)-1].path = strdup(ly_errpath());

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
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Binary tree allocation failed");
        return SR_ERR_NOMEM;
    }
    dm_free_sess_operations(session->operations, session->oper_count);
    session->operations = NULL;
    session->oper_count = 0;
    session->oper_size  = 0;

    return SR_ERR_OK;
}

/**
 * @breif Frees all resources allocated in commit context closes
 * modif_count of files.
 */
void
dm_free_commit_context(dm_ctx_t *dm_ctx, dm_commit_context_t *c_ctx)
{
    CHECK_NULL_ARG_VOID(c_ctx);
    for (size_t i = 0; i < c_ctx->modif_count; i++) {
        close(c_ctx->fds[i]);
    }
    free(c_ctx->fds);
    free(c_ctx->existed);
#ifdef HAVE_STAT_ST_MTIM
    ly_set_free(c_ctx->up_to_date_models);
    c_ctx->up_to_date_models = NULL;
#endif
    c_ctx->fds = NULL;
    c_ctx->existed = NULL;
    c_ctx->modif_count = 0;

    dm_session_stop(dm_ctx, c_ctx->session);
}

/**
 * @brief Counts modified models and allocates structures used during commit process if the
 * number of modified models is greater than zero. In case of error all allocated resources
 * are cleaned up.
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] c_ctx
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_commit_prepare_context(dm_ctx_t *dm_ctx, dm_session_t *session, dm_commit_context_t *c_ctx)
{
    CHECK_NULL_ARG2(session, c_ctx);
    dm_data_info_t *info = NULL;
    size_t i = 0;
    int rc = SR_ERR_OK;
    c_ctx->modif_count = 0;
    /* count modified files */
    while (NULL != (info = sr_btree_get_at(session->session_modules, i))) {
        if (info->modified) {
            c_ctx->modif_count++;
        }
        i++;
    }

    SR_LOG_DBG("Commit: In the session there are %zu / %zu modified models \n", c_ctx->modif_count, i);

    if (0 == session->oper_count && 0 != c_ctx->modif_count) {
        SR_LOG_WRN_MSG("No operation logged, however data tree marked as modified");
        c_ctx->modif_count = 0;
        return SR_ERR_OK;
    }

    c_ctx->fds = calloc(c_ctx->modif_count, sizeof(*c_ctx->fds));
    c_ctx->existed = calloc(c_ctx->modif_count, sizeof(*c_ctx->existed));
    if(NULL == c_ctx->fds || NULL == c_ctx->existed){
        SR_LOG_ERR_MSG("Memory allocation failed");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    /* create commit session*/
    rc = dm_session_start(dm_ctx, session->datastore, &c_ctx->session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Commit session initialization failed");
        goto cleanup;
    }

#ifdef HAVE_STAT_ST_MTIM
    c_ctx->up_to_date_models = ly_set_new();
    if (NULL == c_ctx->up_to_date_models) {
        SR_LOG_ERR_MSG("Not modified set initialization failed");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }
#endif
    return rc;

cleanup:
    dm_free_commit_context(dm_ctx, c_ctx);
    return rc;
}
/**
 * @brief Loads the data tree which has been modified in the session to the commit session. If the session copy has
 * the same timestamp as the file system file it is copied otherwise it is loaded from file.
 * In case of error all files are closed.
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] commit_session - session where the data models are loaded (either from file or copied from session)
 * @param [in] fds - array where file descriptor of opened files will be stored
 * @param [in] existed - array where the true is set if the file existed
 * @param [out] up_to_date
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_commit_load_modified_models(dm_ctx_t *dm_ctx, const dm_session_t *session, dm_commit_context_t *c_ctx)
{
    CHECK_NULL_ARG(c_ctx);
    CHECK_NULL_ARG5(dm_ctx, session, c_ctx->session, c_ctx->fds, c_ctx->existed);
#ifdef HAVE_STAT_ST_MTIM
    CHECK_NULL_ARG(c_ctx->up_to_date_models);
#endif
    dm_data_info_t *info = NULL;
    size_t i = 0;
    size_t count = 0;
    int rc = SR_ERR_OK;
    char *file_name = NULL;
    c_ctx->modif_count = 0; /* how many file descriptors should be closed on cleanup */

    while (NULL != (info = sr_btree_get_at(session->session_modules, i))) {
        if (info->modified) {
            rc = sr_get_data_file_name(dm_ctx->data_search_dir, info->module->name, session->datastore, &file_name);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR_MSG("Get data file name failed");
                goto cleanup;
            }
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
                    c_ctx->fds[count] = open(file_name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
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
            if (lockf(c_ctx->fds[count], F_TLOCK, 0) < 0) {
                SR_LOG_ERR("Locking of file '%s': %s.", file_name, strerror(errno));
                rc = SR_ERR_COMMIT_FAILED;
                goto cleanup;
            }
            dm_data_info_t *di = NULL;
#ifdef HAVE_STAT_ST_MTIM
            struct stat st = {0};
            rc = stat(file_name, &st);
            if (-1 == rc) {
                SR_LOG_ERR_MSG("Stat failed");
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            if (info->timestamp.tv_sec == st.st_mtim.tv_sec &&
                    info->timestamp.tv_nsec == st.st_mtim.tv_nsec) {
                SR_LOG_DBG("Loaded module %s: mtime sec=%lld nsec=%lld\n", info->module->name,
                        (long long) st.st_mtim.tv_sec,
                        (long long) st.st_mtim.tv_nsec);
                SR_LOG_DBG("Timestamp for the model %s matches, ops will be skipped", info->module->name);
                rc = ly_set_add(c_ctx->up_to_date_models, (void *) info->module->name);
                if (0 != rc) {
                    SR_LOG_ERR_MSG("Adding to ly set failed");
                    rc = SR_ERR_INTERNAL;
                    goto cleanup;
                }
                di = calloc(1, sizeof(*di));
                if (NULL == di) {
                    SR_LOG_ERR_MSG("Memory allocation failed");
                    rc = SR_ERR_NOMEM;
                    goto cleanup;
                }
                di->node = sr_dup_datatree(info->node);
                if (NULL == di->node) {
                    SR_LOG_ERR_MSG("Data tree duplication failed");
                    rc = SR_ERR_INTERNAL;
                    goto cleanup;
                }
                di->module = info->module;
            } else {
#endif
                /* if the file existed pass FILE 'r+', otherwise pass -1 because there is 'w' fd already */
                rc = dm_load_data_tree_file(dm_ctx, c_ctx->existed[count] ? c_ctx->fds[count] : -1, file_name, info->module, &di);
                if (SR_ERR_OK != rc) {
                    SR_LOG_ERR_MSG("Loading data file failed");
                    goto cleanup;
                }
#ifdef HAVE_STAT_ST_MTIM
            }
#endif
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
        i++;
    }

    return rc;

cleanup:
    dm_free_commit_context(dm_ctx, c_ctx);
    free(file_name);
    return rc;
}

/**
 * @brief Writes the data trees from commit session stored in commit context into the files.
 * In case of error tries to countinue. Does not do a cleanup.
 * @param [in] session
 * @param [in] c_ctx
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_commit_write_files(dm_session_t *session, dm_commit_context_t *c_ctx)
{
    CHECK_NULL_ARG2(session, c_ctx);
    int rc = SR_ERR_OK;
    size_t i = 0;
    size_t count = 0;
    dm_data_info_t *info = NULL;

    /* empty existing files */
    for (i=0; i < c_ctx->modif_count; i++) {
        if (c_ctx->existed[i]) {
            ftruncate(c_ctx->fds[i], 0);
        }
    }

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
            if (0 != lyd_print_fd(c_ctx->fds[count], merged_info->node, LYD_XML_FORMAT, LYP_WITHSIBLINGS)) {
                SR_LOG_ERR("Failed to write output for %s", info->module->name);
                rc = SR_ERR_INTERNAL;
            }
#ifdef HAVE_STAT_ST_MTIM
            /* if we skipped the merging, make sure that modification time is updated */
            for (unsigned int m = 0; m < c_ctx->up_to_date_models->number; m++) {
                if (0 == strcmp(info->module->name, (char *) c_ctx->up_to_date_models->set[m])) {
                    info->timestamp.tv_nsec++;
                    struct timespec times[2];
                    times[0] = info->timestamp;
                    times[1] = info->timestamp;
                    if (0 != futimens(c_ctx->fds[count], times)) {
                        SR_LOG_ERR_MSG("Time update failed");
                        rc = SR_ERR_INTERNAL;
                    }
                    break;
                }
            }
#endif
            count++;
        }
        i++;
    }
    return rc;
}

int
dm_commit(dm_ctx_t *dm_ctx, dm_session_t *session, sr_error_info_t **errors, size_t *err_cnt)
{
    CHECK_NULL_ARG2(dm_ctx, session);
    int rc = SR_ERR_OK;
    dm_commit_context_t commit_ctx = {0, };

    SR_LOG_DBG_MSG("Commit (1/6): process stared");

    //TODO send validate notifications

    /* YANG validation */
    rc = dm_validate_session_data_trees(dm_ctx, session, errors, err_cnt);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Data validation failed");
        return SR_ERR_VALIDATION_FAILED;
    }
    SR_LOG_DBG_MSG("Commit (2/6): validation succeeded");

    /* lock context for writing */
    pthread_mutex_lock(&dm_ctx->commit_lock);

    rc = dm_commit_prepare_context(dm_ctx, session, &commit_ctx);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("commit prepare context failed");
        pthread_mutex_unlock(&dm_ctx->commit_lock);
        return rc;
    } else if (0 == commit_ctx.modif_count) {
        SR_LOG_DBG_MSG("Commit: Finished - no model modified");
        dm_free_commit_context(dm_ctx, &commit_ctx);
        pthread_mutex_unlock(&dm_ctx->commit_lock);
        return SR_ERR_OK;
    }

    /* open all files */
    rc = dm_commit_load_modified_models(dm_ctx, session, &commit_ctx);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Loading of modified models failed");
        goto cleanup;
    }
    SR_LOG_DBG_MSG("Commit (3/6): all modified models loaded successfully");

    /* replay operations */
    rc = rp_dt_replay_operations(dm_ctx, commit_ctx.session, session->operations, session->oper_count
#ifdef HAVE_STAT_ST_MTIM
            , commit_ctx.up_to_date_models
#endif
            );
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Replay of operations failed");
        goto cleanup;
    }
    SR_LOG_DBG_MSG("Commit (4/6): replay of operation succeeded");

    /* validate data trees after merge */
    rc = dm_validate_session_data_trees(dm_ctx, commit_ctx.session, errors, err_cnt);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Validation after merging failed");
        rc = SR_ERR_VALIDATION_FAILED;
        goto cleanup;
    }
    SR_LOG_DBG_MSG("Commit (5/6): merged models validation succeeded");

    rc = dm_commit_write_files(session, &commit_ctx);

cleanup:
    dm_free_commit_context(dm_ctx, &commit_ctx);

    if (SR_ERR_OK == rc){
        /* discard changes in session in next get_data_tree call newly committed content will be loaded */
        rc = dm_discard_changes(dm_ctx, session);
        SR_LOG_DBG_MSG("Commit (6/6): finished successfully");
    }
    pthread_mutex_unlock(&dm_ctx->commit_lock);
    return rc;
}
