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
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <pthread.h>

/**
 * @brief suffix of data file for startup datastore
 */
#define DM_STARTUP_SUFFIX ".data"

/**
 * @brief suffix of data file for running datastore
 */
#define DM_RUNNING_SUFFIX ".running"

/**
 * @brief Lock the rw_lock for reading, the lock is selected according to the datastore parameter.
 * @param [in] ds sr_datastore_t
 * @param [in] ctx structutre that contains startup_lock and running_lock
 */
#define LOCK_READ_DS(DS, CTX) do{ pthread_rwlock_rdlock((DS) == SR_DS_STARTUP ? &(CTX)->startup_lock : &(CTX)->running_lock); }while(0)

/**
 * @brief Lock the rw_lock for writing, the lock is selected according to the datastore parameter.
 * @param [in] ds sr_datastore_t
 * @param [in] ctx structutre that contains startup_lock and running_lock
 */
#define LOCK_WRITE_DS(DS, CTX) do{ pthread_rwlock_wrlock((DS) == SR_DS_STARTUP ? &(CTX)->startup_lock : &(CTX)->running_lock); }while(0)

/**
 * @brief Unlocks the rw_lock, the lock is selected according to the datastore parameter.
 * @param [in] ds sr_datastore_t
 * @param [in] ctx structutre that contains startup_lock and running_lock
 */
#define UNLOCK_DS(DS, CTX) do{ pthread_rwlock_unlock((DS) == SR_DS_STARTUP ? &(CTX)->startup_lock : &(CTX)->running_lock); }while(0)

/*
 * @brief Data manager context holding loaded schemas, data trees
 * and corresponding locks
 */
typedef struct dm_ctx_s {
    char *schema_search_dir;      /**< location where schema files are located */
    char *data_search_dir;        /**< location where data files are located */
    struct ly_ctx *ly_ctx;        /**< libyang context holding all loaded schemas */
    pthread_rwlock_t lyctx_lock;  /**< rwlock to access ly_ctx */
    sr_btree_t *startup_btree;      /**< binary tree where loaded startup datatrees are stored */
    sr_btree_t *running_btree;      /**< binary tree where loaded running datatrees are stored */
    pthread_rwlock_t startup_lock;  /**< rwlock to access  startup module_btree */
    pthread_rwlock_t running_lock;  /**< rwlock to access running module_btree */
} dm_ctx_t;

/**
 * @brief Data manager session context
 */
typedef struct dm_session_s {
    sr_datastore_t datastore;       /**< datastore to which the session is tied */
    sr_btree_t *session_modules;    /**< binary holding session copies of data models */
} dm_session_t;

typedef struct dm_model_info_s{
    pthread_rwlock_t running_lock;
    time_t running_timestamp;
    pthread_rwlock_t startup_lock;
    time_t startup_timestamp;
}dm_model_info_t;

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
 * @brief Creates the data file name corresponding to the module_name (schema). Function does not check if the schema name
 * is valid. The file name is allocated on heap and needs to be freed by caller. Returns SR_ERR_OK or SR_ERR_NOMEM
 * if memory allocation failed.
 * @param [in] dm_ctx
 * @param [in] module_name
 * @param [in] ds
 * @param [out] file_name
 * @return err_code
 */
static int
dm_get_data_file(const dm_ctx_t *dm_ctx, const char *module_name, const sr_datastore_t ds, char **file_name)
{
    CHECK_NULL_ARG3(dm_ctx, module_name, file_name);
    char *tmp = NULL;
    int rc = sr_str_join(dm_ctx->data_search_dir, module_name, &tmp);
    if (SR_ERR_OK == rc) {
        char *suffix = SR_DS_STARTUP == ds ? DM_STARTUP_SUFFIX : DM_RUNNING_SUFFIX;
        rc = sr_str_join(tmp, suffix, file_name);
        free(tmp);
        return rc;
    }
    return SR_ERR_NOMEM;
}

/**
 * @brief Creates the schema file name corresponding to the module_name (schema). Function does not check if the schema name
 * is valid. The file name is allocated on heap and needs to be freed by caller. Returns SR_ERR_OK or SR_ERR_NOMEM
 * if memory allocation failed.
 * @param [in] dm_ctx
 * @param [in] module_name
 * @param [out] file_name
 * @return err_code
 */
static int
dm_get_schema_file(const dm_ctx_t *dm_ctx, const char *module_name, char **file_name)
{
    CHECK_NULL_ARG3(dm_ctx, module_name, file_name);
    char *tmp = NULL;
    int rc = sr_str_join(dm_ctx->schema_search_dir, module_name, &tmp);
    if (SR_ERR_OK == rc) {
        rc = sr_str_join(tmp, ".yang", file_name);
        free(tmp);
        return rc;
    }
    return SR_ERR_NOMEM;
}

/**
 * @brief Check whether the file_name corresponds to the schema file. Returns 1 if it does, 0 otherwise.
 */
static int
dm_is_schema_file(const char *file_name)
{
    CHECK_NULL_ARG(file_name);
    return sr_str_ends_with(file_name, ".yin");
}
/**
 * Initialize model_info structure
 * @param info
 * @return err_code
 */
static int
dm_alloc_model_info(dm_model_info_t **info)
{
    CHECK_NULL_ARG(info);

    dm_model_info_t *i = NULL;
    pthread_rwlockattr_t attr;

    i = calloc(1, sizeof(*i));
    if (NULL == i) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }

    pthread_rwlockattr_init(&attr);
#if defined(HAVE_PTHREAD_RWLOCKATTR_SETKIND_NP)
    pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
#endif

    if (0 != pthread_rwlock_init(&i->running_lock, &attr)) {
        SR_LOG_ERR_MSG("info rwlock initialization failed");
        free(i);
        return SR_ERR_INTERNAL;
    }

    if (0 != pthread_rwlock_init(&i->startup_lock, &attr)) {
        SR_LOG_ERR_MSG("info rwlock initialization failed");
        free(i);
        return SR_ERR_INTERNAL;
    }

    *info = i;
    return SR_ERR_OK;
}

/**
 * @brief Loads the schema file into the context. The path for loading file is specified as concatenation of dir_name
 * and file_name. Function returns SR_ERR_OK if loading was successful. It might return SR_ERR_IO if the file can not
 * be opened, SR_ERR_INTERNAL if parsing of the file failed or SR_ERR_NOMEM if memory allocation failed.
 * @param [in] dm_ctx
 * @param [in] dir_name
 * @param [in] file_name
 * @return err_code
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

    FILE *fd = fopen(schema_filename, "r");
    free(schema_filename);

    if (NULL == fd) {
        SR_LOG_WRN("Unable to open a schema file %s: %s", file_name, strerror(errno));
        return SR_ERR_IO;
    }

    dm_model_info_t *info = NULL;
    rc = dm_alloc_model_info(&info);
    if (SR_ERR_OK != rc){
        SR_LOG_ERR_MSG("Model info initialization failed");
        fclose(fd);
        return rc;
    }

    pthread_rwlock_wrlock(&dm_ctx->lyctx_lock);
    module = lys_parse_fd(dm_ctx->ly_ctx, fileno(fd), LYS_IN_YIN);
    fclose(fd);
    if (module == NULL) {
        SR_LOG_WRN("Unable to parse a schema file: %s", file_name);
        free(info);
        pthread_rwlock_unlock(&dm_ctx->lyctx_lock);
        return SR_ERR_INTERNAL;
    }

    /* check if model has root (augment model doesn't have)*/
    if (NULL != module->data){
        module->data->private = info;
    }
    else{
        free(info);
    }
    pthread_rwlock_unlock(&dm_ctx->lyctx_lock);
    return SR_ERR_OK;
}

/**
 * @brief Loops through the specified directory and tries to load schema files from it.
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
        return EXIT_FAILURE;
    }
}

/**
 * Checks whether the schema of the module has been loaded
 * @param [in] dm_ctx
 * @param [in] module_name
 * @return err_code
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
 * @brief Loads data tree from file and adds it into dm context
 * @param [in] dm_ctx
 * @param [in] module
 * @param [in] ds
 * @param [out] data_tree
 * @return err_code
 */
static int
dm_load_data_tree(dm_ctx_t *dm_ctx, const struct lys_module *module, sr_datastore_t ds, dm_data_info_t **data_info)
{
    CHECK_NULL_ARG2(dm_ctx, module);

    char *data_filename = NULL;
    int rc = 0;
    struct lyd_node *data_tree = NULL;
    *data_info = NULL;
    rc = dm_get_data_file(dm_ctx, module->name, ds, &data_filename);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Get data_filename failed for %s", module->name);
        return rc;
    }

    dm_data_info_t *data = NULL;
    data = calloc(1, sizeof(*data));
    if (NULL == data){
        SR_LOG_ERR_MSG("Memory allocation failed");
        free(data_filename);
        return SR_ERR_NOMEM;
    }

    FILE *f = fopen(data_filename, "r");
    if (NULL != f) {
        pthread_rwlock_wrlock(&dm_ctx->lyctx_lock);
        data_tree = lyd_parse_fd(dm_ctx->ly_ctx, fileno(f), LYD_XML, LYD_OPT_STRICT);
        if (NULL == data_tree) {
            SR_LOG_ERR("Parsing data tree from file %s failed", data_filename);
            free(data_filename);
            free(data);
            fclose(f);
            pthread_rwlock_unlock(&dm_ctx->lyctx_lock);
            return SR_ERR_INTERNAL;
        }
        fclose(f);
    } else {
        SR_LOG_INF("File %s couldn't be opened for reading: %s", data_filename, strerror(errno));
    }

    /* if the data tree is loaded, validate it*/
    if (NULL != data_tree && 0 != lyd_validate(data_tree, LYD_OPT_STRICT)) {
        SR_LOG_ERR("Loaded data tree '%s' is not valid", data_filename);
        free(data_filename);
        lyd_free_withsiblings(data_tree);
        free(data);
        pthread_rwlock_unlock(&dm_ctx->lyctx_lock);
        return SR_ERR_INTERNAL;
    }

    data->module = module;
    data->modified = false;
    data->timestamp = time(NULL);
    data->node = data_tree;
    if (SR_DS_STARTUP == ds) {
        ((dm_model_info_t *) module->data->private)->startup_timestamp = data->timestamp;
    } else {
        ((dm_model_info_t *) module->data->private)->running_timestamp = data->timestamp;
    }
    if (NULL == data_tree){
        SR_LOG_INF("Data file %s is empty", data_filename);
    }
    else{
        SR_LOG_INF("Data file %s loaded successfully", data_filename);
        pthread_rwlock_unlock(&dm_ctx->lyctx_lock);
    }

    free(data_filename);

    /* select b_tree according to the datastore argument */
    sr_btree_t *btree = SR_DS_STARTUP == ds ? dm_ctx->startup_btree : dm_ctx->running_btree;

    /* insert into binary tree */
    LOCK_WRITE_DS(ds, dm_ctx);
    rc = sr_btree_insert(btree, data);
    if (SR_ERR_OK != rc) {
        if (SR_ERR_EXISTS == rc) {
            /* if the node has been inserted meanwhile by someone else find it */
            *data_info = sr_btree_search(btree, data);
            lyd_free_withsiblings(data->node);
            free(data);
            if (NULL != *data_info) {
                SR_LOG_INF("Data tree '%s' has been inserted already", module->name);
                UNLOCK_DS(ds, dm_ctx);
                return SR_ERR_OK;
            }
            SR_LOG_ERR("Insert data tree %s into avl tree failed", module->name);
            UNLOCK_DS(ds, dm_ctx);
            return SR_ERR_INTERNAL;
        }
        else{
            SR_LOG_ERR("Insert data tree %s into avl tree failed", module->name);
            lyd_free_withsiblings(data->node);
            free(data);
            UNLOCK_DS(ds, dm_ctx);
            return rc;
        }
    }
    UNLOCK_DS(ds, dm_ctx);
    *data_info = data;

    return SR_ERR_OK;
}
/**
 * @brief copies the data from dm_ctx where all datatree that have already been loaded are stored
 * @param [in] dm_ctx
 * @param [in] lookup_node
 * @param [in] model_info
 * @param [in] ds
 * @param [out] data_info created copy needs to be freed by caller
 * @return err_code
 */
static int
dm_copy_from_loaded(dm_ctx_t *dm_ctx, const struct lys_module *lookup_node, dm_model_info_t *model_info, sr_datastore_t ds, dm_data_info_t **data_info)
{
    CHECK_NULL_ARG4(dm_ctx, lookup_node, model_info, data_info);

    dm_data_info_t *di = NULL;
    di = calloc(1, sizeof(*di));
    if (NULL == di) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }

    dm_data_info_t lookup_data;
    lookup_data.module = lookup_node;

    LOCK_READ_DS(ds, dm_ctx);
    LOCK_READ_DS(ds, model_info);
    sr_btree_t *btree = SR_DS_STARTUP == ds ? dm_ctx->startup_btree : dm_ctx->running_btree;
    dm_data_info_t *d = sr_btree_search(btree, &lookup_data);
    if (NULL != d) {
        di->node = sr_dup_datatree(d->node);
        di->timestamp = SR_DS_STARTUP == ds ? model_info->startup_timestamp : model_info->running_timestamp;
        di->module = d->module;
        di->modified = false;
        UNLOCK_DS(ds, model_info);
        UNLOCK_DS(ds, dm_ctx);
        if (NULL != d->node && NULL == di->node) {
            SR_LOG_ERR_MSG("Duplication of data tree for failed");
            free(di);
            return SR_ERR_INTERNAL;
        }
        *data_info = di;
        return SR_ERR_OK;
    }
    UNLOCK_DS(ds, model_info);
    UNLOCK_DS(ds, dm_ctx);
    free(di);
    return SR_ERR_NOT_FOUND;
}

/**
 * @brief Handles the process of creating the copy from dm_ctx, loads the data from file system if need
 * @param [in] dm_ctx
 * @param [in] module
 * @param [in] ds
 * @param [out] data_info created copy needs to be freed by caller.
 * @return err_code
 */
static int
dm_copy_data_info(dm_ctx_t *dm_ctx, const struct lys_module *module, sr_datastore_t ds, dm_data_info_t **data_info)
{
    CHECK_NULL_ARG3(dm_ctx, module, data_info);
    CHECK_NULL_ARG3(module->name, module->data, module->data->name);
    int rc = SR_ERR_OK;

    dm_model_info_t *info = module->data->private;
    dm_data_info_t *data = NULL;

    /* look up in loaded */
    rc = dm_copy_from_loaded(dm_ctx, module, info, ds, data_info);
    if (SR_ERR_NOT_FOUND == rc){
        SR_LOG_DBG("Data model %s is not loaded", module->name);
    } else if(SR_ERR_OK == rc){
        return rc;
    }
    else if (SR_ERR_OK != rc){
        SR_LOG_ERR("Copy data tree from loaded failed for module %s", module->name);
        return rc;
    }


    /* try to load data_tree to dm_ctx */
    rc = dm_load_data_tree(dm_ctx, module, ds, &data);
    if (SR_ERR_NOT_FOUND == rc) {
        return SR_ERR_NOT_FOUND;
    } else if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Loading data_tree %s failed", module->name);
        return rc;
    }

    /* if the loading to dm_ctx succeed, create a copy for the session*/
    rc = dm_copy_from_loaded(dm_ctx, module, info, ds, data_info);
    if (SR_ERR_OK != rc){
        SR_LOG_ERR("Copy data tree from loaded failed for module %s", module->name);
    }
    return rc;
}

/**
 * @brief Fills the schema_t from lys_module structure
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

    rc = dm_get_schema_file(dm_ctx, module->name, &schema->file_path);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Get schema file name failed");
        goto cleanup;
    }
    return rc;

cleanup:
    free(schema->module_name);
    free(schema->prefix);
    free(schema->ns);
    free(schema->revision);
    free(schema->file_path);
    return rc;
}

int
dm_init(const char *schema_search_dir, const char *data_search_dir, dm_ctx_t **dm_ctx)
{
    CHECK_NULL_ARG3(schema_search_dir, data_search_dir, dm_ctx);

    SR_LOG_INF("Initializing Data Manager, schema_search_dir=%s, data_search_dir=%s", schema_search_dir, data_search_dir);

    int rc = SR_ERR_OK;
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

    rc = sr_btree_init(dm_data_info_cmp, dm_data_info_free, &ctx->startup_btree);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate memory for startup binary tree in Data Manager.");
        dm_cleanup(ctx);
        return SR_ERR_NOMEM;
    }

    rc = sr_btree_init(dm_data_info_cmp, dm_data_info_free, &ctx->running_btree);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate memory for running binary tree in Data Manager.");
        dm_cleanup(ctx);
        return SR_ERR_NOMEM;
    }

    pthread_rwlockattr_t attr;
    pthread_rwlockattr_init(&attr);
#if defined(HAVE_PTHREAD_RWLOCKATTR_SETKIND_NP)
    pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
#endif

    if (0 != pthread_rwlock_init(&ctx->lyctx_lock, &attr)) {
        SR_LOG_ERR_MSG("lyctx mutex initialization failed");
        dm_cleanup(ctx);
        return SR_ERR_INTERNAL;
    }

    if (0 != pthread_rwlock_init(&ctx->startup_lock, &attr)){
        SR_LOG_ERR_MSG("avl rwlock init failed");
        dm_cleanup(ctx);
        return SR_ERR_INTERNAL;
    }

    *dm_ctx = ctx;
    int res = dm_load_schemas(ctx);
    if (SR_ERR_OK != res) {
        dm_cleanup(ctx);
        return res;
    }

    return SR_ERR_OK;
}

static void
dm_free_lys_private_data(const struct lys_node *node, void *private){
    if (NULL != private){
        free(private);
    }
}

void
dm_cleanup(dm_ctx_t *dm_ctx)
{
    if (NULL != dm_ctx) {
        free(dm_ctx->schema_search_dir);
        free(dm_ctx->data_search_dir);
        if (NULL != dm_ctx->startup_btree) {
            sr_btree_cleanup(dm_ctx->startup_btree);
        }
        if (NULL != dm_ctx->running_btree) {
            sr_btree_cleanup(dm_ctx->running_btree);
        }
        if (NULL != dm_ctx->ly_ctx) {
            ly_ctx_destroy(dm_ctx->ly_ctx, dm_free_lys_private_data);
        }
        pthread_rwlock_destroy(&dm_ctx->startup_lock);
        pthread_rwlock_destroy(&dm_ctx->running_lock);
        pthread_rwlock_destroy(&dm_ctx->lyctx_lock);
        free(dm_ctx);
    }
}

int
dm_session_start(const dm_ctx_t *dm_ctx, const sr_datastore_t ds, dm_session_t **dm_session_ctx)
{
    CHECK_NULL_ARG(dm_session_ctx);

    dm_session_t *session_ctx = NULL;
    session_ctx = malloc(sizeof(*session_ctx));
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

int
dm_session_stop(const dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx)
{
    CHECK_NULL_ARG2(dm_ctx, dm_session_ctx);
    sr_btree_cleanup(dm_session_ctx->session_modules);
    free(dm_session_ctx);
    return SR_ERR_OK;
}

int
dm_get_data_info(dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx, const char *module_name, dm_data_info_t **info){
    CHECK_NULL_ARG4(dm_ctx, dm_session_ctx, module_name, info);
    int rc = SR_ERR_OK;
    const struct lys_module *module = NULL;
    dm_data_info_t *exisiting_data_info = NULL;

    if (dm_find_module_schema(dm_ctx, module_name, &module) != SR_ERR_OK) {
        SR_LOG_WRN("Unknown schema: %s", module_name);
        return SR_ERR_UNKNOWN_MODEL;
    }

    /* check session copy*/
    dm_model_info_t *m_info = module->data->private;

    dm_data_info_t lookup_data = { 0 };
    lookup_data.module = module;
    exisiting_data_info = sr_btree_search(dm_session_ctx->session_modules, &lookup_data);

    if (NULL != exisiting_data_info) {
        if (exisiting_data_info->modified) {
            /* copy has already been changed by user */
            *info = exisiting_data_info;
            SR_LOG_DBG("Copy of module %s has already been modified", module_name);
            return SR_ERR_OK;
        }
        LOCK_READ_DS(dm_session_ctx->datastore, m_info);
        bool changed = (SR_DS_STARTUP == dm_session_ctx->datastore ? m_info->startup_timestamp : m_info->running_timestamp) != exisiting_data_info->timestamp;
        UNLOCK_DS(dm_session_ctx->datastore, m_info);
        /* session copy is up-to date*/
        if (!changed){
            *info = exisiting_data_info;
            SR_LOG_DBG("Copy of module %s already is up-to date", module_name);
            return SR_ERR_OK;
        }
    }

    /* session copy not found or not up-to date, try to create copy from dm_ctx*/
    dm_data_info_t *di = NULL;
    rc = dm_copy_data_info(dm_ctx, module, dm_session_ctx->datastore, &di);
    if (SR_ERR_NOT_FOUND == rc) {
        SR_LOG_DBG("Data tree for %s not found.", module_name);
        return rc;
    } else if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Getting data tree for %s failed.", module_name);
        return rc;
    }

    /* insert into session*/
    if (NULL != exisiting_data_info) {
        /* update session copy*/
        lyd_free_withsiblings(exisiting_data_info->node);
        exisiting_data_info->node = di->node;
        exisiting_data_info->timestamp = di->timestamp;
        exisiting_data_info->modified = false;
        free(di);
        *info = exisiting_data_info;
    } else {
            rc = sr_btree_insert(dm_session_ctx->session_modules, (void *)di);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Insert into session running avl failed module %s", module_name);
                dm_data_info_free(di);
                return rc;
            }
            SR_LOG_DBG("Copy of module %s has been created", module_name);
            *info = di;
            return SR_ERR_OK;
    }

    return rc;
}

int
dm_get_datatree(dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx, const char *module_name, struct lyd_node **data_tree)
{
    CHECK_NULL_ARG4(dm_ctx, dm_session_ctx, module_name, data_tree);
    int rc = SR_ERR_OK;
    dm_data_info_t *info = NULL;
    rc = dm_get_data_info(dm_ctx, dm_session_ctx, module_name, &info);
    if (SR_ERR_OK != rc){
        SR_LOG_ERR("Get data info failed for module %s", module_name);
        return rc;
    }
    *data_tree = info->node;
    if (NULL == info->node){
        return SR_ERR_NOT_FOUND;
    }
    return rc;
}

int
dm_get_module(dm_ctx_t *dm_ctx, const char *module_name, const char *revision, const struct lys_module **module){
    CHECK_NULL_ARG3(dm_ctx, module_name, module); /* revision might be NULL*/
    *module = ly_ctx_get_module(dm_ctx->ly_ctx, module_name, revision);
    if (NULL == *module){
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
    CHECK_NULL_ARG3(dm_ctx, session, errors);
    int rc = SR_ERR_OK;

    size_t cnt = 0;
    dm_data_info_t *info = NULL;
    while (NULL != (info = sr_btree_get_at(session->session_modules, cnt))) {
        /* loaded data trees are valid, so check only the modified ones */
        if (info->modified) {
            //TODO lock mutex for logging a collect error messages
            if (NULL == info->module || NULL == info->module->name) {
                SR_LOG_ERR_MSG("Missing schema information");
                return SR_ERR_INTERNAL;
            }
            if (0 != lyd_validate(info->node, LYD_OPT_STRICT)){
                SR_LOG_DBG("Validation failed for %s module", info->module->name);

                // TODO: fill-in proper errors
                *errors = calloc(1, sizeof(**errors));
                (*errors)[0].message = strdup("Validation failed.");
                (*errors)[0].path = strdup(info->module->name);
                *err_cnt = 1;

                rc = SR_ERR_VALIDATION_FAILED;
            }
            else{
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

    size_t cnt = 0;
    dm_data_info_t *info = NULL;
    while (NULL != (info = sr_btree_get_at(session->session_modules, cnt))) {
        if (info->modified) {
            /* invalidate timestamp
             * and set modified to false to discard the changes
             * next dm_get_data_tree / dm_get_data_info call will update the data tree */
            info->modified = false;
            info->timestamp = 0;
        }
        cnt++;
    }
    return SR_ERR_OK;
}

int
dm_commit(dm_ctx_t *dm_ctx, dm_session_t *session, sr_error_info_t **errors, size_t *err_cnt)
{
    CHECK_NULL_ARG2(dm_ctx, session);
    int rc = SR_ERR_OK;
    //TODO send validate notifications

    /* YANG validation */
    rc = dm_validate_session_data_trees(dm_ctx, session, errors, err_cnt);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Data validation failed");
        return SR_ERR_COMMIT_FAILED;
    }

    /* TODO aquire data file lock*/

    /* lock context for writing */
    pthread_rwlock_wrlock(&dm_ctx->lyctx_lock);

    size_t cnt = 0;
    dm_data_info_t *info = NULL;
    while (NULL != (info = sr_btree_get_at(session->session_modules, cnt))) {
        if (info->modified) {
            /* lookup data_tree in dm_ctx*/
            dm_data_info_t *sys_wide_data_info = NULL;
            dm_data_info_t search_node = { 0 };
            search_node.module = info->module;
            sr_btree_t *btree = SR_DS_STARTUP == session->datastore ? dm_ctx->startup_btree : dm_ctx->running_btree;
            sys_wide_data_info = sr_btree_search(btree, &search_node);
            if (NULL == sys_wide_data_info){
                SR_LOG_ERR("Module '%s' not found in data manager context", info->module->name);
                pthread_rwlock_unlock(&dm_ctx->lyctx_lock);
                return SR_ERR_INTERNAL;
            }

            /* update data trees in dm_ctx */
            if (info->timestamp != sys_wide_data_info->timestamp) {
                SR_LOG_INF("Merging needs to be done for module '%s', currently just overwriting", info->module->name);
            }
            lyd_free_withsiblings(sys_wide_data_info->node);
            sys_wide_data_info->node = sr_dup_datatree(info->node);
            if (NULL == sys_wide_data_info->node){
                SR_LOG_ERR("Duplication of data tree %s", info->module->name);
                pthread_rwlock_unlock(&dm_ctx->lyctx_lock);
                return SR_ERR_INTERNAL;
            }
            /* increment timestamp to invalidate older copies */
            sys_wide_data_info->timestamp++;
            if (SR_DS_STARTUP == session->datastore) {
                ((dm_model_info_t *) sys_wide_data_info->module->data->private)->startup_timestamp = sys_wide_data_info->timestamp;
            } else {
                ((dm_model_info_t *) sys_wide_data_info->module->data->private)->running_timestamp = sys_wide_data_info->timestamp;
            }

            char *data_filename = NULL;
            rc = dm_get_data_file(dm_ctx, info->module->name, session->datastore, &data_filename);
            if (SR_ERR_OK != rc){
                SR_LOG_ERR_MSG("Getting data file name failed");
                pthread_rwlock_unlock(&dm_ctx->lyctx_lock);
                return rc;
            }

            rc = sr_save_data_tree_file(data_filename, sys_wide_data_info->node);
            free(data_filename);
            if (SR_ERR_OK != rc){
                SR_LOG_ERR("Saving data file for module %s failed", info->module->name);
                pthread_rwlock_unlock(&dm_ctx->lyctx_lock);
                return rc;
            }
        }
        cnt++;
    }

    pthread_rwlock_unlock(&dm_ctx->lyctx_lock);

    /* discard changes in session in next get_data_tree call newly committed content will be loaded */
    rc = dm_discard_changes(dm_ctx, session);

    return rc;
}
