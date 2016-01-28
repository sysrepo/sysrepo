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
#include <avl.h>
#include <pthread.h>

/*
 * @brief Data manager context holding loaded schemas, data trees
 * and corresponding locks
 */
typedef struct dm_ctx_s {
    char *schema_search_dir;      /**< location where schema files are located */
    char *data_search_dir;        /**< location where data files are located */
    struct ly_ctx *ly_ctx;        /**< libyang context holding all loaded schemas */
    pthread_rwlock_t lyctx_lock;  /**< rwlock to access ly_ctx */
    avl_tree_t *module_avl;       /**< avl tree where loaded datatrees are stored */
    pthread_rwlock_t avl_lock;    /**< rwlock to access module_avl */
} dm_ctx_t;

typedef struct dm_session_s {
    struct lyd_node *modules;
    size_t modules_count;
} dm_session_t;

/**
 * @brief Compares two data trees by module name
 */
static int
dm_module_cmp(const void *a, const void *b)
{
    assert(a);
    assert(b);
    struct lyd_node *module_a = (struct lyd_node *) a;
    struct lyd_node *module_b = (struct lyd_node *) b;

    int res = strcmp(module_a->schema->module->name, module_b->schema->module->name);
    if (res == 0) {
        return 0;
    } else if (res < 0) {
        return -1;
    } else {
        return 1;
    }
}

/**
 * @brief frees the data_tree stored in avl tree
 */
static void
dm_module_cleanup(void *module)
{
    struct lyd_node *m = (struct lyd_node *) module;
    if (NULL != m) {
        sr_free_datatree(m);
    }
}

/**
 * @brief Creates the data file name corresponding to the module_name (schema). Function does not check if the schema name
 * is valid. The file name is allocated on heap and needs to be freed by caller. Returns SR_ERR_OK or SR_ERR_NOMEM
 * if memory allocation failed.
 * @param [in] dm_ctx
 * @param [in] module_name
 * @param [out] file_name
 * @return err_code
 */
static int
dm_get_data_file(const dm_ctx_t *dm_ctx, const char *module_name, char **file_name)
{
    CHECK_NULL_ARG3(dm_ctx, module_name, file_name);
    char *tmp = NULL;
    int rc = sr_str_join(dm_ctx->data_search_dir, module_name, &tmp);
    if (SR_ERR_OK == rc) {
        rc = sr_str_join(tmp, ".data", file_name);
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
    int res = sr_str_join(dir_name, file_name, &schema_filename);
    if (SR_ERR_OK != res) {
        return SR_ERR_NOMEM;
    }

    FILE *fd = fopen(schema_filename, "r");
    free(schema_filename);

    if (NULL == fd) {
        SR_LOG_WRN("Unable to open a schema file %s: %s", file_name, strerror(errno));
        return SR_ERR_IO;
    }
    pthread_rwlock_wrlock(&dm_ctx->lyctx_lock);
    module = lys_parse_fd(dm_ctx->ly_ctx, fileno(fd), LYS_IN_YIN);
    pthread_rwlock_unlock(&dm_ctx->lyctx_lock);
    fclose(fd);
    if (module == NULL) {
        SR_LOG_WRN("Unable to parse a schema file: %s", file_name);
        return SR_ERR_INTERNAL;
    }
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

#if 0
//will be used with edit config

/**
 * @brief adds empty data tree for the specified module into dm_ctx
 * @param [in] dm_ctx
 * @param [in] module
 * @param [out] data_tree
 * @return err_code
 */
static int
dm_add_empty_data_tree(const dm_ctx_t *dm_ctx, const struct lys_module *module, struct lyd_node **data_tree)
{
    CHECK_NULL_ARG3(dm_ctx, module, data_tree);
    *data_tree = lyd_new(NULL, module, module->data->name);
    if (NULL == *data_tree) {
        SR_LOG_ERR_MSG("Creating empty data tree failed");
        return SR_ERR_INTERNAL;
    }
    avl_node_t *avl_node = avl_insert(dm_ctx->module_avl, *data_tree);
    if (NULL == avl_node) {
        SR_LOG_ERR("Insert data tree %s into avl tree failed", module->name);
        lyd_free(*data_tree);
        *data_tree = NULL;
        return SR_ERR_INTERNAL;
    }
    return SR_ERR_OK;
}
#endif

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
 * @param [out] data_tree
 * @return err_code
 */
static int
dm_load_data_tree(dm_ctx_t *dm_ctx, const struct lys_module *module, struct lyd_node **data_tree)
{
    CHECK_NULL_ARG2(dm_ctx, module);

    char *data_filename = NULL;
    int rc = 0;
    *data_tree = NULL;
    rc = dm_get_data_file(dm_ctx, module->name, &data_filename);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Get data_filename failed for %s", module->name);
        return rc;
    }

    FILE *f = fopen(data_filename, "r");
    if (NULL != f) {
        pthread_rwlock_wrlock(&dm_ctx->lyctx_lock);
        *data_tree = lyd_parse_fd(dm_ctx->ly_ctx, fileno(f), LYD_XML, LYD_OPT_STRICT);
        if (NULL == *data_tree) {
            SR_LOG_ERR("Parsing data tree from file %s failed", data_filename);
            free(data_filename);
            fclose(f);
            pthread_rwlock_unlock(&dm_ctx->lyctx_lock);
            return SR_ERR_INTERNAL;
        }
        fclose(f);
    } else {
        SR_LOG_INF("File %s couldn't be opened for reading: %s", data_filename, strerror(errno));
        free(data_filename);
        return SR_ERR_NOT_FOUND;
    }

    if (0 != lyd_validate(*data_tree, LYD_OPT_STRICT)) {
        SR_LOG_ERR("Loaded data tree '%s' is not valid", data_filename);
        free(data_filename);
        sr_free_datatree(*data_tree);
        pthread_rwlock_unlock(&dm_ctx->lyctx_lock);
        return SR_ERR_INTERNAL;
    }
    pthread_rwlock_unlock(&dm_ctx->lyctx_lock);

    SR_LOG_INF("Data file %s loaded successfuly", data_filename);
    free(data_filename);

    /* insert into avl tree */
    pthread_rwlock_wrlock(&dm_ctx->avl_lock);
    avl_node_t *avl_node = avl_insert(dm_ctx->module_avl, *data_tree);
    if (NULL == avl_node) {
        if (EEXIST == errno){
            /* if the node has been inserted meanwhile by someone else find it*/
            avl_node = avl_search(dm_ctx->module_avl, *data_tree);
            sr_free_datatree(*data_tree);
            *data_tree = NULL;
            if (NULL != avl_node){
                SR_LOG_INF("Data tree '%s' has been inserted already", module->name);
                *data_tree = avl_node->item;
                pthread_rwlock_unlock(&dm_ctx->avl_lock);
                return SR_ERR_OK;
            }
            SR_LOG_ERR("Insert data tree %s into avl tree failed", module->name);
            pthread_rwlock_unlock(&dm_ctx->avl_lock);
            return SR_ERR_INTERNAL;
        }
        else{
            SR_LOG_ERR("Insert data tree %s into avl tree failed", module->name);
            sr_free_datatree(*data_tree);
            *data_tree = NULL;
            pthread_rwlock_unlock(&dm_ctx->avl_lock);
            return SR_ERR_INTERNAL;
        }
    }
    pthread_rwlock_unlock(&dm_ctx->avl_lock);

    return SR_ERR_OK;
}

/**
 * @brief Looks up the data tree in already loaded structures. If it is not found it tries to load it from file.
 * If data_tree does not exists empty data_tree is created
 */
static int
dm_find_data_tree(dm_ctx_t *dm_ctx, const struct lys_module *module, struct lyd_node **data_tree)
{
    CHECK_NULL_ARG3(dm_ctx, module, data_tree);
    int rc = 0;
    struct lyd_node *data_node = NULL;
    avl_node_t *avl_node = NULL;
    data_node = lyd_new(NULL, module, module->data->name);
    if (NULL == data_node) {
        SR_LOG_ERR_MSG("Unable to create node for lookup");
        return SR_ERR_NOMEM;
    }

    /* look up in loaded */
    pthread_rwlock_rdlock(&dm_ctx->avl_lock);
    avl_node = avl_search(dm_ctx->module_avl, data_node);
    lyd_free(data_node);
    if (NULL != avl_node) {
        *data_tree = avl_node->item;
        pthread_rwlock_unlock(&dm_ctx->avl_lock);
        return SR_ERR_OK;
    }
    pthread_rwlock_unlock(&dm_ctx->avl_lock);

    /* try to load data_tree */
    rc = dm_load_data_tree(dm_ctx, module, data_tree);
    if (SR_ERR_NOT_FOUND == rc) {
        return SR_ERR_NOT_FOUND;
    } else if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Loading data_tree %s failed", module->name);
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

    dm_ctx_t *ctx = NULL;
    ctx = calloc(1, sizeof(*ctx));
    if (NULL == ctx) {
        SR_LOG_ERR_MSG("Cannot allocate memory for Data Manager.");
        return SR_ERR_NOMEM;
    }
    ctx->ly_ctx = ly_ctx_new(schema_search_dir);
    if (NULL == ctx->ly_ctx) {
        SR_LOG_ERR_MSG("Cannot initialize libyang context in Data Manager.");
        free(ctx);
        return SR_ERR_NOMEM;
    }

    ctx->schema_search_dir = strdup(schema_search_dir);
    if (NULL == ctx->schema_search_dir) {
        SR_LOG_ERR_MSG("Cannot allocate memory for schema search dir string in Data Manager.");
        ly_ctx_destroy(ctx->ly_ctx);
        free(ctx);
        return SR_ERR_NOMEM;
    }

    ctx->data_search_dir = strdup(data_search_dir);
    if (NULL == ctx->data_search_dir) {
        SR_LOG_ERR_MSG("Cannot allocate memory for data search dir string in Data Manager.");
        free(ctx->schema_search_dir);
        ly_ctx_destroy(ctx->ly_ctx);
        free(ctx);
        return SR_ERR_NOMEM;
    }

    ctx->module_avl = avl_alloc_tree(dm_module_cmp, dm_module_cleanup);
    if (NULL == ctx->module_avl) {
        SR_LOG_ERR_MSG("Cannot allocate memory for avl module in Data Manager.");
        free(ctx->schema_search_dir);
        free(ctx->data_search_dir);
        ly_ctx_destroy(ctx->ly_ctx);
        free(ctx);
        return SR_ERR_NOMEM;
    }

    pthread_rwlockattr_t attr;
    pthread_rwlockattr_init(&attr);
    pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);

    if (0 != pthread_rwlock_init(&ctx->lyctx_lock, &attr)) {
        SR_LOG_ERR_MSG("lyctx mutex initialization failed");
        dm_cleanup(ctx);
        return SR_ERR_INTERNAL;
    }

    if (0 != pthread_rwlock_init(&ctx->avl_lock, &attr)){
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

void
dm_cleanup(dm_ctx_t *dm_ctx)
{
    if (NULL != dm_ctx) {
        free(dm_ctx->schema_search_dir);
        free(dm_ctx->data_search_dir);
        if (NULL != dm_ctx->module_avl) {
            avl_free_tree(dm_ctx->module_avl);
        }
        ly_ctx_destroy(dm_ctx->ly_ctx);
        pthread_rwlock_destroy(&dm_ctx->avl_lock);
        pthread_rwlock_destroy(&dm_ctx->lyctx_lock);
        free(dm_ctx);
    }
}

int
dm_session_start(const dm_ctx_t *dm_ctx, dm_session_t **dm_session_ctx)
{
    CHECK_NULL_ARG(dm_session_ctx);

    dm_session_t *session_ctx;
    session_ctx = malloc(sizeof(*session_ctx));
    if (NULL == session_ctx) {
        SR_LOG_ERR_MSG("Cannot allocate session_ctx in Data Manager.");
        return SR_ERR_NOMEM;
    }
    session_ctx->modules = NULL;
    session_ctx->modules_count = 0;
    *dm_session_ctx = session_ctx;

    return SR_ERR_OK;
}

int
dm_session_stop(const dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx)
{
    CHECK_NULL_ARG2(dm_ctx, dm_session_ctx);
    free(dm_session_ctx->modules);
    free(dm_session_ctx);
    return SR_ERR_OK;
}

int
dm_get_datatree(dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx, const char *module_name, struct lyd_node **data_tree)
{
    CHECK_NULL_ARG4(dm_ctx, dm_session_ctx, module_name, data_tree);
    int rc = SR_ERR_OK;
    const struct lys_module *module = NULL;
    if (dm_find_module_schema(dm_ctx, module_name, &module) != SR_ERR_OK) {
        SR_LOG_WRN("Unknown schema: %s", module_name);
        return SR_ERR_UNKNOWN_MODEL;
    }

    rc = dm_find_data_tree(dm_ctx, module, data_tree);
    if (SR_ERR_NOT_FOUND == rc) {
        SR_LOG_DBG("Data tree for %s not found.", module_name);
    } else if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Getting data tree for %s failed.", module_name);
    }

    return rc;
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

