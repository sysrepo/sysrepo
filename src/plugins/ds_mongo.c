/**
 * @file ds_mongo.c
 * @author Ondrej Kusnirik <Ondrej.Kusnirik@cesnet.cz>
 * @brief internal MongoDB datastore plugin
 *
 * @copyright
 * Copyright (c) 2021 - 2025 Deutsche Telekom AG.
 * Copyright (c) 2021 - 2025 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include <bson/bson.h>
#include <libyang/libyang.h>
#include <mongoc/mongoc.h>

#include "common_db.h"
#include "compat.h"
#include "config.h"
#include "plugins_datastore.h"
#include "sysrepo.h"

#define plugin_name "MONGO DS"

typedef struct mongo_data_s {
    mongoc_client_t *client; /* client that connects to the database and manages changes on the data */
    mongoc_database_t *datastore; /* specific database that is currently being managed (startup, running, ...) */
    mongoc_collection_t *module; /* specific collection that is currently being managed (contains data of a specific
            YANG module) */
    char *module_name; /* allocated module name of the module */
} mongo_data_t;

typedef struct mongo_plg_conn_data_s {
    mongoc_client_pool_t *pool; /* pool of clients that connect to the database so that multithreading is supported,
            pool is the used pool of clients */
} mongo_plg_conn_data_t;

/* specific data for MongoDB */
typedef struct mongo_plg_data_s {
    int is_mongoc_initialized; /* global variable that checks whether mongoc_init() was called */
    pthread_mutex_t lock; /* mutex */
} mongo_plg_data_t;

mongo_plg_data_t plugin_data = {0};

typedef struct mongo_bulk_data_s {
    mongoc_bulk_operation_t *bulk; /* MongoDB abstraction for handling bulk pipelines */
    int has_operation; /* whether the bulk has an operation in it (MongoDB cannot execute an empty bulk) */
} mongo_bulk_data_t;

/**
 * @brief Exit function.
 *
 */
static void
terminate(void)
{
    mongoc_cleanup();
}

/**
 * @brief Get the name of the database for the given datastore.
 *
 * @param[in] ds Given datastore.
 * @return Name of the database or NULL if datastore is not supported.
 */
static const char *
srpds_ds2database(sr_datastore_t ds)
{
    switch (ds) {
    case SR_DS_STARTUP:
        return "sr_startup";
    case SR_DS_RUNNING:
        return "sr_running";
    case SR_DS_CANDIDATE:
        return "sr_candidate";
    case SR_DS_OPERATIONAL:
        return "sr_operational";
    case SR_DS_FACTORY_DEFAULT:
        return "sr_factory-default";
    default:
        return NULL;
    }
}

/**
 * @brief Get the name of the collection.
 *
 * @param[in] mod_name Mdoule name.
 * @param[in] cid Connection ID.
 * @param[in] sid Session ID.
 * @param[in] is_oper Whether the collection is for operational data and unique for @p cid and @p sid.
 * @param[out] collection_name Generated collection name.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_get_collection_name(const char *mod_name, sr_cid_t cid, uint32_t sid, int is_oper, char **collection_name)
{
    sr_error_info_t *err_info = NULL;
    int r;

    if (is_oper) {
        r = asprintf(collection_name, "%s:%s+%" PRIu32 "+%" PRIu32, sr_get_shm_prefix(), mod_name, cid, sid);
    } else {
        r = asprintf(collection_name, "%s:%s", sr_get_shm_prefix(), mod_name);
    }
    if (r == -1) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
        return err_info;
    }

    return NULL;
}

/**
 * @brief Try a general command in order to establish whether authentication is required.
 *
 * @param[in] client Connected client.
 * @param[out] auth_prob 1 if command failed due to authentication problem, 0 otherwise.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_check_auth(mongoc_client_t *client, int *auth_prob)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    bson_t *command = NULL;

    *auth_prob = 0;

    command = BCON_NEW("usersInfo", BCON_INT32(1));

    /* try a command */
    if (!mongoc_client_command_simple(client, "sr_running", command, NULL, NULL, &error)) {
        if ((error.code == 11) || (error.code == 13)) {
            /* authentication failed | authorization failed */
            *auth_prob = 1;
        } else {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_client_command_simple()", error.message);
            goto cleanup;
        }
    }

cleanup:
    bson_destroy(command);
    return err_info;
}

/**
 * @brief Establish a database client at the start of the connection.
 *
 * @param[out] pool New pool of connected clients.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_client_init(mongoc_client_pool_t **pool)
{
    sr_error_info_t *err_info = NULL;
    mongoc_uri_t *uri = NULL;
    mongoc_client_t *temp = NULL;
    int auth_prob;

    if (!strcmp(SR_DS_PLG_MONGO_SOCKET, "")) {
        uri = mongoc_uri_new("mongodb://" SR_DS_PLG_MONGO_HOST ":" SR_DS_PLG_MONGO_PORT
                "/?authSource=" SR_DS_PLG_MONGO_AUTHSOURCE "&" MONGOC_URI_SOCKETTIMEOUTMS "=3600000&"
                MONGOC_URI_CONNECTTIMEOUTMS "=3600000");
    } else {
        uri = mongoc_uri_new("mongodb://" SR_DS_PLG_MONGO_SOCKET
                "/?authSource=" SR_DS_PLG_MONGO_AUTHSOURCE "&" MONGOC_URI_SOCKETTIMEOUTMS "=3600000&"
                MONGOC_URI_CONNECTTIMEOUTMS "=3600000");
    }
    *pool = mongoc_client_pool_new(uri);
    temp = mongoc_client_pool_pop(*pool);

    /* try to execute a command without authentication */
    if ((err_info = srpds_check_auth(temp, &auth_prob))) {
        goto cleanup;
    }

    /* no authentication required, continue */
    if (!auth_prob) {
        goto cleanup;
    }

    /* executing a command without authentication failed */
    mongoc_client_pool_push(*pool, temp);
    mongoc_client_pool_destroy(*pool);
    mongoc_uri_destroy(uri);

    /* authenticate as a client based on the provided username and password */
    if (!strcmp(SR_DS_PLG_MONGO_SOCKET, "")) {
        uri = mongoc_uri_new("mongodb://" SR_DS_PLG_MONGO_USERNAME ":" SR_DS_PLG_MONGO_PASSWORD "@" SR_DS_PLG_MONGO_HOST ":" SR_DS_PLG_MONGO_PORT
                "/?authSource=" SR_DS_PLG_MONGO_AUTHSOURCE "&" MONGOC_URI_SOCKETTIMEOUTMS "=3600000&"
                MONGOC_URI_CONNECTTIMEOUTMS "=3600000");
    } else {
        uri = mongoc_uri_new("mongodb://" SR_DS_PLG_MONGO_USERNAME ":" SR_DS_PLG_MONGO_PASSWORD "@" SR_DS_PLG_MONGO_SOCKET
                "/?authSource=" SR_DS_PLG_MONGO_AUTHSOURCE "&" MONGOC_URI_SOCKETTIMEOUTMS "=3600000&"
                MONGOC_URI_CONNECTTIMEOUTMS "=3600000");
    }
    *pool = mongoc_client_pool_new(uri);
    temp = mongoc_client_pool_pop(*pool);

    /* try to execute a command with authentication */
    if ((err_info = srpds_check_auth(temp, &auth_prob))) {
        goto cleanup;
    }

    /* authentication failed */
    if (auth_prob) {
        ERRINFO(&err_info, plugin_name, SR_ERR_UNAUTHORIZED, "Authentication",
                "Please create a client in MongoDB with username and password provided during compilation");
        goto cleanup;
    }

cleanup:
    mongoc_client_pool_push(*pool, temp);
    mongoc_uri_destroy(uri);
    return err_info;
}

/**
 * @brief Initialize plugin data for each callback.
 *
 * @param[in] mod Given module.
 * @param[in] ds Given datastore.
 * @param[in] cid Connection ID.
 * @param[in] sid Session ID.
 * @param[in] installed Whether module was already installed.
 * @param[in] pdata Plugin connection data.
 * @param[out] mdata Module data.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_data_init(const struct lys_module *mod, sr_datastore_t ds, sr_cid_t cid, uint32_t sid, int installed,
        mongo_plg_conn_data_t *pdata, mongo_data_t *mdata)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    int is_oper;

    mdata->client = mongoc_client_pool_pop(pdata->pool);
    mdata->datastore = mongoc_client_get_database(mdata->client, srpds_ds2database(ds));

    /* get the module name (collection name) */
    is_oper = ((ds == SR_DS_OPERATIONAL) && cid && sid) ? 1 : 0;
    if ((err_info = srpds_get_collection_name(mod->name, cid, sid, is_oper, &mdata->module_name))) {
        goto cleanup;
    }

    /* create or get the module from the database */
    if (installed) {
        mdata->module = mongoc_client_get_collection(mdata->client, srpds_ds2database(ds), mdata->module_name);
    } else {
        mdata->module = mongoc_database_create_collection(mdata->datastore, mdata->module_name, NULL, &error);
        if (!mdata->module) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_database_create_collection()",
                    error.message);
            goto cleanup;
        }
    }

cleanup:
    return err_info;
}

/**
 * @brief Free all of the allocated data from initialization.
 *
 * @param[in] pdata Plugin connection data.
 * @param[in] mdata Module data.
 */
static void
srpds_data_destroy(mongo_plg_conn_data_t *pdata, mongo_data_t *mdata)
{
    free(mdata->module_name);
    mongoc_collection_destroy(mdata->module);
    mongoc_database_destroy(mdata->datastore);
    mongoc_client_pool_push(pdata->pool, mdata->client);
}

/**
 * @brief Get module owner, group and permissions from the database.
 *
 * @param[in] module Given MongoDB collection.
 * @param[out] owner Module owner.
 * @param[out] group Module group.
 * @param[out] perm Module permissions.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_get_access(mongoc_collection_t *module, char **owner, char **group, mode_t *perm)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    bson_t *query = NULL, *query_opts = NULL, *query_iter = NULL;
    mongoc_cursor_t *cursor = NULL;
    bson_iter_t iter;
    const char *str;

    if (owner) {
        *owner = NULL;
    }
    if (group) {
        *group = NULL;
    }
    if (perm) {
        *perm = 0;
    }

    query = BCON_NEW("_id", BCON_UTF8("2"));
    query_opts = BCON_NEW("projection", "{", "owner", BCON_BOOL(1), "group", BCON_BOOL(1), "perm", BCON_BOOL(1),
            "_id", BCON_BOOL(0), "}");
    cursor = mongoc_collection_find_with_opts(module, query, query_opts, NULL);

    if (mongoc_cursor_next(cursor, (const bson_t **) &query_iter)) {
        if (!bson_iter_init(&iter, query_iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_init()", "");
            goto cleanup;
        }

        if (bson_iter_next(&iter) && owner) {
            str = bson_iter_utf8(&iter, NULL);
            if (!bson_utf8_validate(str, strlen(str), 0)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_utf8()", "");
                goto cleanup;
            }
            *owner = strdup(str);
            if (!*owner) {
                ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "strdup()", strerror(errno));
                goto cleanup;
            }
        }

        if (bson_iter_next(&iter) && group) {
            str = bson_iter_utf8(&iter, NULL);
            if (!bson_utf8_validate(str, strlen(str), 0)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_utf8()", "");
                goto cleanup;
            }
            *group = strdup(str);
            if (!*group) {
                ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "strdup()", strerror(errno));
                goto cleanup;
            }
        }

        if (bson_iter_next(&iter) && perm) {
            *perm = bson_iter_int32(&iter);
        }
    }

    if (mongoc_cursor_error(cursor, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_find_with_opts()", error.message);
        goto cleanup;
    }

cleanup:
    if (err_info) {
        if (owner) {
            free(*owner);
            *owner = NULL;
        }
        if (group) {
            free(*group);
            *group = NULL;
        }
        if (perm) {
            *perm = 0;
        }
    }
    bson_destroy(query);
    bson_destroy(query_opts);
    mongoc_cursor_destroy(cursor);
    return err_info;
}

/**
 * @brief Put all load XPaths into a regex.
 *
 * @param[in] ctx Libyang context.
 * @param[in] xpaths Array of XPaths.
 * @param[in] xpath_cnt XPath count.
 * @param[in] oper_ds Flag if the filter is for loading operational data and special handling is needed.
 * @param[out] is_valid Whether the @p xpath_filter is valid.
 * @param[out] xpath_filter XPath filter for the database.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_process_load_paths(struct ly_ctx *ctx, const char **xpaths, uint32_t xpath_cnt, int oper_ds, int *is_valid,
        bson_t *xpath_filter)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    char *tmp = NULL, *path = NULL, *escaped_path = NULL;
    struct lyd_node *ctx_node = NULL, *match = NULL;
    uint32_t log_options = 0, *old_options;
    bson_t top, bottom;
    LY_ERR lyrc;

    /* prepare the start of the filter document */
    bson_init(xpath_filter);
    bson_append_array_begin(xpath_filter, "$or", 3, &top);

    /* create new data node for lyd_find_path to work correctly */
    if (lyd_new_path(NULL, ctx, "/ietf-yang-library:yang-library", NULL, 0, &ctx_node) != LY_SUCCESS) {
        ERRINFO(&err_info, plugin_name, SR_ERR_LY, "lyd_new_path()", "");
        goto cleanup;
    }

    /* build a regex */
    for (i = 0; i < xpath_cnt; ++i) {
        old_options = ly_temp_log_options(&log_options);
        /* check whether the xpaths are paths */
        lyrc = lyd_find_path(ctx_node, xpaths[i], 0, &match);
        ly_temp_log_options(old_options);
        if (lyrc != LY_ENOTFOUND) {
            /* not a path, load all data */
            goto cleanup;
        }

        /* copy the path for further manipulation */
        path = strdup(xpaths[i]);
        if (!path) {
            ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "strdup()", strerror(errno));
            goto cleanup;
        }

        /* all relative paths should be transformed into absolute */
        if (path[0] != '/') {
            if (asprintf(&tmp, "/%s", path) == -1) {
                ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
                goto cleanup;
            }
            free(path);
            path = tmp;
            tmp = NULL;
        }

        /* path is key */
        if (lysc_is_key(lys_find_path(ctx, NULL, path, 0))) {
            srpds_get_parent_path(path);
        }

        if ((err_info = srpds_escape_string(plugin_name, path, '\\', &escaped_path))) {
            goto cleanup;
        }

        /* add path as regex */
        if (asprintf(&tmp, "^%s", escaped_path) == -1) {
            ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
            goto cleanup;
        }
        bson_append_document_begin(&top, "_id", 3, &bottom);
        bson_append_regex(&bottom, "_id", 3, tmp, "s");
        bson_append_document_end(&top, &bottom);
        free(tmp);
        tmp = NULL;
        free(escaped_path);
        escaped_path = NULL;

        /* add all parent paths also */
        srpds_get_parent_path(path);
        while (path[0] != '\0') {
            /* continue with exact match (for parent nodes) */
            bson_append_document_begin(&top, "_id", 3, &bottom);
            bson_append_utf8(&bottom, "_id", 3, path, -1);
            bson_append_document_end(&top, &bottom);
            srpds_get_parent_path(path);
        }

        free(path);
        path = NULL;
    }

    if (xpath_cnt && oper_ds) {
        /* explicitly add discard-items to the query for operational datastore */
        if ((err_info = srpds_escape_string(plugin_name, "/sysrepo:discard-items", '\\', &escaped_path))) {
            goto cleanup;
        }

        /* add path as regex */
        if (asprintf(&tmp, "^%s", escaped_path) == -1) {
            ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
            goto cleanup;
        }
        bson_append_document_begin(&top, "_id", 3, &bottom);
        bson_append_regex(&bottom, "_id", 3, tmp, "s");
        bson_append_document_end(&top, &bottom);
        free(tmp);
        tmp = NULL;
        free(escaped_path);
        escaped_path = NULL;
    }

    *is_valid = xpath_cnt;

cleanup:
    bson_append_array_end(xpath_filter, &top);
    if (!*is_valid) {
        bson_destroy(xpath_filter);
    }
    free(path);
    free(escaped_path);
    free(tmp);
    lyd_free_all(ctx_node);
    return err_info;
}

/**
 * @brief Load all data and store them inside the lyd_node structure.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] mod Given module.
 * @param[in] ds Given datastore.
 * @param[in] xpath_filter XPath filter for the database.
 * @param[out] mod_data Retrieved module data from the database.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_all(mongoc_collection_t *module, const struct lys_module *mod, sr_datastore_t ds, bson_t *xpath_filter,
        struct lyd_node **mod_data)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    const char *path, *name, *module_name = NULL, *value = NULL, *path_no_pred = NULL;
    char **keys = NULL;
    uint32_t *bit_lengths = NULL;
    enum srpds_db_ly_types type;
    int32_t valtype = 0;
    int64_t order = 0;
    int dflt_flag = 0;
    int32_t meta_count = 0;
    const char *meta_name = NULL, *meta_value = NULL;
    srpds_db_userordered_lists_t uo_lists = {0};
    struct lyd_node **parent_nodes = NULL;
    size_t pnodes_size = 0;

    bson_t *query_opts = NULL, *query_iter = NULL;
    mongoc_cursor_t *cursor = NULL;
    bson_iter_t iter;

    query_opts = BCON_NEW("sort", "{", "path_modif", BCON_INT32(1), "}");
    cursor = mongoc_collection_find_with_opts(module, xpath_filter, query_opts, NULL);

    /*
    *   Loading multiple different sets of data
    *
    *   Load All Datastores
    *   | 1) containers (LYS_CONTAINER)
    *   |    Dataset [ path(_id) | name | type | module_name | path_modif | meta_count | {metadata} ]
    *   |
    *   | 2) lists (LYS_LIST)
    *   |    Dataset [ path(_id) | name | type | module_name | keys | path_modif | meta_count | {metadata} ]
    *   |
    *   | 3) leafs and leaf-lists (LYS_LEAF and LYS_LEAFLIST)
    *   |    Dataset [ path(_id) | name | type | module_name | dflt_flag | value | path_modif | meta_count
    *   |            | {metadata} ]
    *   |
    *   | 4) anydata and anyxml (LYS_ANYDATA and LYS_ANYXML)
    *   |    Dataset [ path(_id) | name | type | module_name | value | valtype | path_modif | meta_count | {metadata} ]
    *   |
    *   | 5) user-ordered lists
    *   |    Dataset [ path(_id) | name | type | module_name | keys | order | path_no_pred | prev | path_modif
    *   |            | meta_count | {metadata} ]
    *   |
    *   | 6) user-ordered leaf-lists
    *   |    Dataset [ path(_id) | name | type | module_name | dflt_flag | value | order | path_no_pred | prev
    *   |            | path_modif | meta_count | {metadata} ]
    *   |
    *   | 7) opaque nodes
    *   |    Dataset [ path_with_value(_id) | name | type | module_name | path | value | path_modif | attr_count
    *   |            | {attributes} ]
    *   |
    *   | 8) other metadata (0, 1, 2, #) DO NOT LOAD
    *   |
    *   | module_name = NULL - use parent's module | name - use the module specified by this name
    *   | {metadata}  = meta_count number of fields containing metadata of the node
    *   | valtype     = 0 - XML | 1 - JSON
    *   | start number defines the type (1 - container, 2 - list...)
    *
    *   Metadata and MaxOrder
    *   | 1) global metadata (starting with a number)
    *   |     1.1) 0 = timestamp (last-modif) [ !!! NOT LOADED ]
    *   |     1.2) 1 = is different from running? (for candidate datastore) [ !!! NOT LOADED ]
    *   |     1.3) 2 = owner, group and permissions [ !!! NOT LOADED ]
    *   |    Dataset [ path(_id) | value ]
    *   |
    *   | 2) maximum order for a userordered list or leaflist (starting with a #)
    *   |     2.1) # = maximum order [ !!! NOT LOADED ]
    *   |    Dataset [ path(_id) | value ]
    *
    *   [ !!! NOT LOADED ] data are only for internal use
    */

    while (mongoc_cursor_next(cursor, (const bson_t **) &query_iter)) {
        if (!bson_iter_init(&iter, query_iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_init()", "");
            goto cleanup;
        }

        /* get path */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
            goto cleanup;
        }
        path = bson_iter_utf8(&iter, NULL);
        if (!bson_utf8_validate(path, strlen(path), 0)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_utf8()", "");
            goto cleanup;
        }

        /* do not load, this is additional data
         * 0 - timestamp of the last modification
         * 1 - modified flag for candidate datastore
         * 2 - owner, group and permissions
         * # - maximum load-order for list or leaf-list */
        switch (path[0]) {
        case '0':
        case '1':
        case '#':
        case '2':
            continue;
        default:
            break;
        }

        /* get name */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
            goto cleanup;
        }
        name = bson_iter_utf8(&iter, NULL);
        if (!bson_utf8_validate(name, strlen(name), 0)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_utf8()", "");
            goto cleanup;
        }

        /* get type */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
            goto cleanup;
        }
        type = bson_iter_int32(&iter);

        /* get module_name */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
            goto cleanup;
        }
        module_name = bson_iter_utf8(&iter, NULL);
        if (module_name && !bson_utf8_validate(module_name, strlen(module_name), 0)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_utf8()", "");
            goto cleanup;
        }

        /* get path based on type */
        switch (type) {
        case SRPDS_DB_LY_OPAQUE:
            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
                goto cleanup;
            }
            path = bson_iter_utf8(&iter, NULL);
            if (!bson_utf8_validate(path, strlen(path), 0)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_utf8()", "");
                goto cleanup;
            }
            break;
        default:
            break;
        }

        /* get keys or dflt flag based on type */
        switch (type) {
        case SRPDS_DB_LY_LIST:     /* lists */
        case SRPDS_DB_LY_LIST_UO:  /* user-ordered lists */
            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
                goto cleanup;
            }
            value = bson_iter_utf8(&iter, NULL);
            if ((err_info = srpds_parse_keys(plugin_name, value, &keys, &bit_lengths))) {
                goto cleanup;
            }
            break;
        case SRPDS_DB_LY_TERM:         /* leafs and leaf-lists */
        case SRPDS_DB_LY_LEAFLIST_UO:  /* user-ordered leaf-lists */
            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
                goto cleanup;
            }
            dflt_flag = bson_iter_as_bool(&iter);
            break;
        default:
            break;
        }

        /* get value based on type */
        switch (type) {
        case SRPDS_DB_LY_TERM:         /* leafs and leaf-lists */
        case SRPDS_DB_LY_ANY:          /* anydata and anyxml */
        case SRPDS_DB_LY_LEAFLIST_UO:  /* user-ordered leaf-lists */
        case SRPDS_DB_LY_OPAQUE:       /* opaque nodes */
            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
                goto cleanup;
            }
            value = bson_iter_utf8(&iter, NULL);
            if (!bson_utf8_validate(value, strlen(value), 0)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_utf8()", "");
                goto cleanup;
            }
            break;
        default:
            break;
        }

        /* get valtype or order based on type */
        switch (type) {
        case SRPDS_DB_LY_ANY:  /* anydata and anyxml */
            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
                goto cleanup;
            }
            valtype = bson_iter_int32(&iter);
            break;
        case SRPDS_DB_LY_LIST_UO:      /* user-ordered lists */
        case SRPDS_DB_LY_LEAFLIST_UO:  /* user-ordered leaf-lists */
            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
                goto cleanup;
            }
            order = bson_iter_int64(&iter);
            break;
        default:
            break;
        }

        /* get path_no_pred based on type */
        switch (type) {
        case SRPDS_DB_LY_LIST_UO:      /* user-ordered lists */
        case SRPDS_DB_LY_LEAFLIST_UO:  /* user-ordered leaf-lists */
            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
                goto cleanup;
            }
            path_no_pred = bson_iter_utf8(&iter, NULL);
            if (!bson_utf8_validate(path_no_pred, strlen(path_no_pred), 0)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_utf8()", "");
                goto cleanup;
            }

            /* skip prev */
            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
                goto cleanup;
            }
            break;
        default:
            break;
        }

        /* skip path_modif */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
            goto cleanup;
        }

        /* get meta_count */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
            goto cleanup;
        }
        meta_count = bson_iter_int32(&iter);

        /* get meta name and meta value */
        if (meta_count) {
            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
                goto cleanup;
            }
            meta_name = bson_iter_utf8(&iter, NULL);
            if (!bson_utf8_validate(meta_name, strlen(meta_name), 0)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_utf8()", "");
                goto cleanup;
            }

            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
                goto cleanup;
            }
            meta_value = bson_iter_utf8(&iter, NULL);
            if (!bson_utf8_validate(meta_value, strlen(meta_value), 0)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_utf8()", "");
                goto cleanup;
            }
        }

        /* add a new node to mod_data */
        if ((err_info = srpds_add_mod_data(plugin_name, mod->ctx, ds, path, name, type, module_name, value, valtype,
                &dflt_flag, (const char **)keys, bit_lengths, order, path_no_pred, meta_count, meta_name, meta_value,
                &uo_lists, &parent_nodes, &pnodes_size, mod_data))) {
            goto cleanup;
        }
        free(keys);
        free(bit_lengths);
        keys = NULL;
        bit_lengths = NULL;
    }

    if (mongoc_cursor_error(cursor, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_find_with_opts()", error.message);
        goto cleanup;
    }

    /* go through all userordered lists and leaflists and order them */
    if ((err_info = srpds_order_uo_lists(plugin_name, &uo_lists))) {
        goto cleanup;
    }

    *mod_data = lyd_first_sibling(*mod_data);

cleanup:
    free(keys);
    free(bit_lengths);
    free(parent_nodes);
    srpds_cleanup_uo_lists(&uo_lists);
    bson_destroy(query_opts);
    mongoc_cursor_destroy(cursor);
    return err_info;
}

/**
 * @brief Add metadata to the query to store in the database.
 *
 * @param[in] meta Metadata to store.
 * @param[out] query Query to append metadata to.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_add_meta(const struct lyd_meta *meta, bson_t *query)
{
    sr_error_info_t *err_info = NULL;
    int32_t meta_count = srpds_get_meta_count(meta);
    char *meta_name = NULL;

    /* store the number of metadata */
    bson_append_int32(query, "meta_count", 10, meta_count);

    /* we are only expecting zero or one metadata (origin) */
    while (meta_count && meta) {
        /* skip yang: and sysrepo: metadata, this is libyang and sysrepo specific data */
        if (strcmp(meta->annotation->module->name, "yang") && strcmp(meta->annotation->module->name, "sysrepo")) {
            /* concatenate meta name with module name */
            if (asprintf(&meta_name, "%s:%s", meta->annotation->module->name, meta->name) == -1) {
                ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
                goto cleanup;
            }

            /* store metadata */
            bson_append_utf8(query, "meta_name", 9, meta_name, -1);
            bson_append_utf8(query, "meta_value", 10, lyd_get_meta_value(meta), -1);

            free(meta_name);
            meta_name = NULL;

            /* we found origin, break */
            break;
        }
        meta = meta->next;
    }

cleanup:
    free(meta_name);
    return err_info;
}

/**
 * @brief Get a bson command to create a container.
 *
 * @param[in] path Path to the node.
 * @param[in] name Name of the node.
 * @param[in] module_name Name of the module.
 * @param[in] path_modif Modified path.
 * @param[in] meta Metadata of the node.
 * @param[out] query Query to use.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_container(const char *path, const char *name, const char *module_name, const char *path_modif,
        const struct lyd_meta *meta, bson_t **query)
{
    sr_error_info_t *err_info = NULL;

    *query = bson_new();
    bson_append_utf8(*query, "_id", 3, path, -1);
    bson_append_utf8(*query, "name", 4, name, -1);
    bson_append_int32(*query, "type", 4, SRPDS_DB_LY_CONTAINER);
    bson_append_utf8(*query, "module_name", 11, module_name, -1);
    bson_append_utf8(*query, "path_modif", 10, path_modif, -1);
    if ((err_info = srpds_add_meta(meta, *query))) {
        goto cleanup;
    }

cleanup:
    if (err_info) {
        bson_destroy(*query);
        *query = NULL;
    }
    return err_info;
}

/**
 * @brief Get a bson command to create a list instance.
 *
 * @param[in] path Path to the node.
 * @param[in] name Name of the node.
 * @param[in] module_name Name of the module.
 * @param[in] keys Keys of the list.
 * @param[in] keys_length Length of @p keys.
 * @param[in] path_modif Modified path.
 * @param[in] meta Metadata of the node.
 * @param[out] query Query to use.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_list(const char *path, const char *name, const char *module_name, const char *keys, uint32_t keys_length,
        const char *path_modif, const struct lyd_meta *meta, bson_t **query)
{
    sr_error_info_t *err_info = NULL;

    *query = bson_new();
    bson_append_utf8(*query, "_id", 3, path, -1);
    bson_append_utf8(*query, "name", 4, name, -1);
    bson_append_int32(*query, "type", 4, SRPDS_DB_LY_LIST);
    bson_append_utf8(*query, "module_name", 11, module_name, -1);
    bson_append_utf8(*query, "keys", 4, keys, keys_length);
    bson_append_utf8(*query, "path_modif", 10, path_modif, -1);
    if ((err_info = srpds_add_meta(meta, *query))) {
        goto cleanup;
    }

cleanup:
    if (err_info) {
        bson_destroy(*query);
        *query = NULL;
    }
    return err_info;
}

/**
 * @brief Get a bson command to create a term.
 *
 * @param[in] path Path to the node.
 * @param[in] name Name of the node.
 * @param[in] module_name Name of the module.
 * @param[in] dflt_flag Default flag of the node.
 * @param[in] value Value of the node.
 * @param[in] path_modif Modified path.
 * @param[in] meta Metadata of the node.
 * @param[out] query Query to use.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_term(const char *path, const char *name, const char *module_name, int dflt_flag, const char *value,
        const char *path_modif, const struct lyd_meta *meta, bson_t **query)
{
    sr_error_info_t *err_info = NULL;

    *query = bson_new();
    bson_append_utf8(*query, "_id", 3, path, -1);
    bson_append_utf8(*query, "name", 4, name, -1);
    bson_append_int32(*query, "type", 4, SRPDS_DB_LY_TERM);
    bson_append_utf8(*query, "module_name", 11, module_name, -1);
    bson_append_bool(*query, "dflt_flag", 9, dflt_flag);
    bson_append_utf8(*query, "value", 5, value, -1);
    bson_append_utf8(*query, "path_modif", 10, path_modif, -1);
    if ((err_info = srpds_add_meta(meta, *query))) {
        goto cleanup;
    }

cleanup:
    if (err_info) {
        bson_destroy(*query);
        *query = NULL;
    }
    return err_info;
}

/**
 * @brief Get a bson command to create an anyxml or anydata node.
 *
 * @param[in] path Path to the node.
 * @param[in] name Name of the node.
 * @param[in] module_name Name of the module.
 * @param[in] value Value of the node.
 * @param[in] valtype Type of the value (LYD_ANYDATA_XML = 0; LYD_ANYDATA_JSON = 1)
 * @param[in] path_modif Modified path.
 * @param[in] meta Metadata of the node.
 * @param[out] query Query to use.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_any(const char *path, const char *name, const char *module_name, const char *value, int32_t valtype,
        const char *path_modif, const struct lyd_meta *meta, bson_t **query)
{
    sr_error_info_t *err_info = NULL;

    *query = bson_new();
    bson_append_utf8(*query, "_id", 3, path, -1);
    bson_append_utf8(*query, "name", 4, name, -1);
    bson_append_int32(*query, "type", 4, SRPDS_DB_LY_ANY);
    bson_append_utf8(*query, "module_name", 11, module_name, -1);
    bson_append_utf8(*query, "value", 5, value, -1);
    bson_append_int32(*query, "valtype", 7, valtype);
    bson_append_utf8(*query, "path_modif", 10, path_modif, -1);
    if ((err_info = srpds_add_meta(meta, *query))) {
        goto cleanup;
    }

cleanup:
    if (err_info) {
        bson_destroy(*query);
        *query = NULL;
    }
    return err_info;
}

/**
 * @brief Get a bson command to create a userordered list instance.
 *
 * @param[in] path Path to the node.
 * @param[in] name Name of the node.
 * @param[in] module_name Name of the module.
 * @param[in] keys Keys of the list.
 * @param[in] keys_length Length of @p keys.
 * @param[in] order Order of the node.
 * @param[in] path_no_pred Path to the node without predicate.
 * @param[in] prev_pred Predicate of the previous node.
 * @param[in] path_modif Modified path.
 * @param[in] meta Metadata of the node.
 * @param[out] query Query to use.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_list_uo(const char *path, const char *name, const char *module_name, const char *keys, uint32_t keys_length,
        uint64_t order, const char *path_no_pred, const char *prev_pred, const char *path_modif,
        const struct lyd_meta *meta, bson_t **query)
{
    sr_error_info_t *err_info = NULL;

    *query = bson_new();
    bson_append_utf8(*query, "_id", 3, path, -1);
    bson_append_utf8(*query, "name", 4, name, -1);
    bson_append_int32(*query, "type", 4, SRPDS_DB_LY_LIST_UO);
    bson_append_utf8(*query, "module_name", 11, module_name, -1);
    bson_append_utf8(*query, "keys", 4, keys, keys_length);
    bson_append_int64(*query, "order", 5, order);
    bson_append_utf8(*query, "path_no_pred", 12, path_no_pred, -1);
    bson_append_utf8(*query, "prev", 4, prev_pred, -1);
    bson_append_utf8(*query, "path_modif", 10, path_modif, -1);
    if ((err_info = srpds_add_meta(meta, *query))) {
        goto cleanup;
    }

cleanup:
    if (err_info) {
        bson_destroy(*query);
        *query = NULL;
    }
    return err_info;
}

/**
 * @brief Get a bson command to create a userordered leaf-list instance.
 *
 * @param[in] path Path to the node.
 * @param[in] name Name of the node.
 * @param[in] module_name Name of the module.
 * @param[in] dflt_flag Default flag of the node.
 * @param[in] value Value of the node.
 * @param[in] order Order of the node.
 * @param[in] path_no_pred Path to the node without predicate.
 * @param[in] prev_pred Predicate of the previous node.
 * @param[in] path_modif Modified path.
 * @param[in] meta Metadata of the node.
 * @param[out] query Query to use.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_leaflist_uo(const char *path, const char *name, const char *module_name, int dflt_flag, const char *value,
        uint64_t order, const char *path_no_pred, const char *prev_pred, const char *path_modif,
        const struct lyd_meta *meta, bson_t **query)
{
    sr_error_info_t *err_info = NULL;

    *query = bson_new();
    bson_append_utf8(*query, "_id", 3, path, -1);
    bson_append_utf8(*query, "name", 4, name, -1);
    bson_append_int32(*query, "type", 4, SRPDS_DB_LY_LEAFLIST_UO);
    bson_append_utf8(*query, "module_name", 11, module_name, -1);
    bson_append_bool(*query, "dflt_flag", 9, dflt_flag);
    bson_append_utf8(*query, "value", 5, value, -1);
    bson_append_int64(*query, "order", 5, order);
    bson_append_utf8(*query, "path_no_pred", 12, path_no_pred, -1);
    bson_append_utf8(*query, "prev", 4, prev_pred, -1);
    bson_append_utf8(*query, "path_modif", 10, path_modif, -1);
    if ((err_info = srpds_add_meta(meta, *query))) {
        goto cleanup;
    }

cleanup:
    if (err_info) {
        bson_destroy(*query);
        *query = NULL;
    }
    return err_info;
}

/**
 * @brief Get a bson command to create an opaque node.
 *
 * @param[in] path_with_value Path to the node with value.
 * @param[in] name Name of the node.
 * @param[in] module_name Name of the module.
 * @param[in] path Path to the node.
 * @param[in] value Value of the node.
 * @param[in] path_modif Modified path.
 * @return Command to create an opaque node.
 */
static bson_t *
srpds_opaque(const char *path_with_value, const char *name, const char *module_name, const char *path,
        const char *value, const char *path_modif)
{
    return BCON_NEW("_id", BCON_UTF8(path_with_value),
            "name", BCON_UTF8(name),
            "type", BCON_INT32(SRPDS_DB_LY_OPAQUE),
            "module_name", BCON_UTF8(module_name),
            "path", BCON_UTF8(path),
            "value", BCON_UTF8(value),
            "path_modif", BCON_UTF8(path_modif),
            "attr_count", BCON_INT32(0));
}

/**
 * @brief Delete one element from the database using its id.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] id In-database id of the element.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_delete_id(mongoc_collection_t *module, const char *id)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    bson_t *query;

    query = BCON_NEW("_id", BCON_UTF8(id));
    if (!mongoc_collection_delete_one(module, query, NULL, NULL, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_delete_one()", error.message);
    }

    bson_destroy(query);
    return err_info;
}

/**
 * @brief Delete one element from the database using its id (but use bulk pipeline).
 *
 * @param[in] id In-database id of the element.
 * @param[out] bulk Bulk structure to insert query into.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_bulk_delete_id(const char *id, mongo_bulk_data_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    bson_t *query;

    query = BCON_NEW("_id", BCON_UTF8(id));
    if (!mongoc_bulk_operation_remove_one_with_opts(bulk->bulk, (const bson_t *)query, NULL, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_bulk_operation_remove_one_with_opts()",
                error.message);
    }
    bulk->has_operation = 1;

    bson_destroy(query);
    return err_info;
}

/**
 * @brief Delete multiple elements from the database using regex.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] regex Regex to match for deletion.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_delete_regex(mongoc_collection_t *module, const char *regex)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    bson_t *query;

    query = BCON_NEW("_id", "{", "$regex", BCON_UTF8(regex), "$options", "s", "}");
    if (!mongoc_collection_delete_many(module, query, NULL, NULL, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_delete_many()", error.message);
    }

    bson_destroy(query);
    return err_info;
}

/**
 * @brief Delete multiple elements from the database using regex (but use bulk pipeline).
 *
 * @param[in] regex Regex to match for deletion.
 * @param[out] bulk Bulk structure to insert query into.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_bulk_delete_regex(const char *regex, mongo_bulk_data_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    bson_t *query;

    query = BCON_NEW("_id", "{", "$regex", BCON_UTF8(regex), "$options", "s", "}");
    if (!mongoc_bulk_operation_remove_many_with_opts(bulk->bulk, (const bson_t *)query, NULL,
            &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_bulk_operation_remove_many_with_opts()",
                error.message);
    }
    bulk->has_operation = 1;

    bson_destroy(query);
    return err_info;
}

/**
 * @brief Delete everything under the node defined by @p path except for the node itself.
 *
 * @param[in] path Path to the top node of the subtree.
 * @param[out] bulk Bulk structure to insert query into.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_bulk_delete_subtree(const char *path, mongo_bulk_data_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    char *escaped = NULL, *regex = NULL;

    if ((err_info = srpds_escape_string(plugin_name, path, '\\', &escaped))) {
        goto cleanup;
    }

    if (asprintf(&regex, "^%s[\\/\\[]", escaped) == -1) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
        goto cleanup;
    }

    /* delete data under this node */
    if ((err_info = srpds_bulk_delete_regex(regex, bulk))) {
        goto cleanup;
    }

cleanup:
    free(escaped);
    free(regex);
    return err_info;
}

/**
 * @brief Insert an element into the database.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] query Query to use.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_insert(mongoc_collection_t *module, const bson_t *query)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;

    if (!mongoc_collection_insert_one(module, query, NULL, NULL, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_insert_one()", error.message);
    }

    return err_info;
}

/**
 * @brief Insert an element into the database (but use bulk pipeline).
 *
 * @param[in] query Query to use.
 * @param[out] bulk Bulk structure to insert query into.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_bulk_insert(const bson_t *query, mongo_bulk_data_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;

    if (!mongoc_bulk_operation_insert_with_opts(bulk->bulk, query, NULL, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_bulk_operation_insert_with_opts()",
                error.message);
    }
    bulk->has_operation = 1;

    return err_info;
}

/**
 * @brief Update an element in the database.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] query_key Query to specify the node.
 * @param[in] query Query to use for the update.
 * @param[in] upsert Whether to create the element if it is not found.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_update(mongoc_collection_t *module, const bson_t *query_key, const bson_t *query, int upsert)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    bson_t *opts = BCON_NEW("upsert", BCON_BOOL(upsert));

    if (!mongoc_collection_update_one(module, query_key, query, opts, NULL, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message);
    }

    bson_destroy(opts);
    return err_info;
}

/**
 * @brief Update an element in the database (but use bulk pipeline).
 *
 * @param[in] query_key Query to specify the node.
 * @param[in] query Query to use for the update.
 * @param[in] upsert Whether to create the element if it is not found.
 * @param[out] bulk Bulk structure to insert query into.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_bulk_update(const bson_t *query_key, const bson_t *query, int upsert, mongo_bulk_data_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    bson_t *opts = BCON_NEW("upsert", BCON_BOOL(upsert));

    if (!mongoc_bulk_operation_update_one_with_opts(bulk->bulk, query_key, query, opts, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_bulk_operation_update_one_with_opts()",
                error.message);
    }
    bulk->has_operation = 1;

    bson_destroy(opts);
    return err_info;
}

/**
 * @brief Delete all metadata fields of an element in the database.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] path Path to the node with metadata.
 * @param[out] bulk Bulk structure to insert query into.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_delete_meta(mongoc_collection_t *module, const char *path, mongo_bulk_data_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    bson_t *query = NULL, *query_key = NULL;
    bson_t subquery;

    query = bson_new();
    bson_append_document_begin(query, "$unset", 6, &subquery);
    bson_append_utf8(&subquery, "meta_name", 9, "", -1);
    bson_append_utf8(&subquery, "meta_value", 10, "", -1);
    bson_append_document_end(query, &subquery);

    /* delete all metadata */
    query_key = BCON_NEW("_id", BCON_UTF8(path));
    if (bulk) {
        if ((err_info = srpds_bulk_update(query_key, query, 0, bulk))) {
            goto cleanup;
        }
    } else {
        if ((err_info = srpds_update(module, query_key, query, 0))) {
            goto cleanup;
        }
    }

cleanup:
    bson_destroy(query);
    bson_destroy(query_key);
    return err_info;
}

/**
 * @brief Update the maximum order of a list or a leaf-list in the database.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] path_no_pred Path of a list/leaf-list instance without a predicate.
 * @param[in] max_order Maximum order to store.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_set_maxord(mongoc_collection_t *module, const char *path_no_pred, uint64_t max_order)
{
    sr_error_info_t *err_info = NULL;
    bson_t *query = NULL, *query_key = NULL;
    char *maxord_path = NULL;

    /* update only if max_order has been changed
     * aka is different from zero */
    if (max_order) {
        /* update maximum order of the list
         * list's maximum order is stored here */
        if (asprintf(&maxord_path, "#%s", path_no_pred) == -1) {
            ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
            goto cleanup;
        }

        query_key = BCON_NEW("_id", BCON_UTF8(maxord_path));
        query = BCON_NEW("$set", "{", "value", BCON_INT64(max_order), "}");
        if ((err_info = srpds_update(module, query_key, query, 1))) {
            goto cleanup;
        }
    }

cleanup:
    free(maxord_path);
    bson_destroy(query_key);
    bson_destroy(query);
    return err_info;
}

/**
 * @brief Increment the maximum order of a list or a leaf-list.
 *
 * @param[out] out_max_order Incremented maximum order.
 */
static void
srpds_inc_maxord(uint64_t *out_max_order)
{
    /* new elements added at the end of the list
     * also have a large gap between them
     * so that the insertion is faster */
    *out_max_order = *out_max_order + SRPDS_DB_UO_ELEMS_GAP_SIZE;
}

/**
 * @brief Get the maximum order of a list or a leaf-list from the database.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] path_no_pred Path of a list/leaf-list instance without a predicate.
 * @param[out] out_max_order Retrieved maximum order from the database.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_get_maxord(mongoc_collection_t *module, const char *path_no_pred, uint64_t *out_max_order)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    mongoc_cursor_t *cursor = NULL;
    bson_t *query = NULL, *query_opts = NULL, *query_iter = NULL;
    bson_iter_t iter;
    char *maxord_path = NULL;

    if (*out_max_order == 0) {
        /* get maximum order of the list
         * list's maximum order is stored here */
        if (asprintf(&maxord_path, "#%s", path_no_pred) == -1) {
            ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
            goto cleanup;
        }

        query = BCON_NEW("_id", BCON_UTF8(maxord_path));
        query_opts = BCON_NEW("projection", "{", "value", BCON_BOOL(1), "_id", BCON_BOOL(0), "}");
        cursor = mongoc_collection_find_with_opts(module, query, query_opts, NULL);

        if (mongoc_cursor_next(cursor, (const bson_t **) &query_iter)) {
            if (!bson_iter_init(&iter, query_iter)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_init()", "");
                goto cleanup;
            }

            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
                goto cleanup;
            } else {
                *out_max_order = bson_iter_int64(&iter);
            }
        } else {
            ERRINFO(&err_info, plugin_name, SR_ERR_NOT_FOUND, "Finding maximum order of the list", "");
            goto cleanup;
        }

        if (mongoc_cursor_error(cursor, &error)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_find_with_opts()", error.message);
            goto cleanup;
        }
    }

cleanup:
    free(maxord_path);
    bson_destroy(query);
    bson_destroy(query_opts);
    mongoc_cursor_destroy(cursor);
    return err_info;
}

/**
 * @brief Get the order of the previous element in a list or a leaf-list from the database.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] prev_pred Predicate of the previous element.
 * @param[in] path_no_pred Path of a list/leaf-list instance without a predicate.
 * @param[out] order Order of the previous element.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_prev(mongoc_collection_t *module, const char *prev_pred, const char *path_no_pred, uint64_t *order)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    mongoc_cursor_t *cursor = NULL;
    bson_t *query = NULL, *query_opts = NULL, *query_iter = NULL;
    bson_iter_t iter;
    char *prev_path = NULL;

    /* prepare path of the previous element */
    if (asprintf(&prev_path, "%s%s", path_no_pred, prev_pred) == -1) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
        goto cleanup;
    }

    query = BCON_NEW("_id", BCON_UTF8(prev_path));
    query_opts = BCON_NEW("projection", "{", "order", BCON_BOOL(1), "_id", BCON_BOOL(0), "}");
    cursor = mongoc_collection_find_with_opts(module, query, query_opts, NULL);

    if (mongoc_cursor_next(cursor, (const bson_t **) &query_iter)) {
        if (!bson_iter_init(&iter, query_iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_init()", "");
            goto cleanup;
        }

        /* order */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
            goto cleanup;
        }
        *order = bson_iter_int64(&iter);
    }

    if (mongoc_cursor_error(cursor, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_find_with_opts()", error.message);
        goto cleanup;
    }

cleanup:
    free(prev_path);
    bson_destroy(query);
    bson_destroy(query_opts);
    mongoc_cursor_destroy(cursor);
    return err_info;
}

/**
 * @brief Get the order of the next element in a list or a leaf-list from the database.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] prev_pred Predicate of the next element's previous element.
 * @param[in] path_no_pred Path of a list/leaf-list instance without a predicate.
 * @param[out] order Order of the next element.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_next(mongoc_collection_t *module, const char *prev_pred, const char *path_no_pred, uint64_t *order)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    mongoc_cursor_t *cursor = NULL;
    bson_t *query = NULL, *query_opts = NULL, *query_iter = NULL;
    bson_iter_t iter;
    char *order_str = NULL;
    uint64_t order_cur = 0, order_min = UINT64_MAX;

    *order = 0;

    query = BCON_NEW("prev", BCON_UTF8(prev_pred), "path_no_pred", BCON_UTF8(path_no_pred));
    query_opts = BCON_NEW("projection", "{", "order", BCON_BOOL(1), "_id", BCON_BOOL(0), "}");
    cursor = mongoc_collection_find_with_opts(module, query, query_opts, NULL);

    if (mongoc_cursor_next(cursor, (const bson_t **) &query_iter)) {
        if (!bson_iter_init(&iter, query_iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_init()", "");
            goto cleanup;
        }

        /* order */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
            goto cleanup;
        }
        order_cur = bson_iter_int64(&iter);
        if (order_min > order_cur) {
            order_min = order_cur;
        }
    }

    if (mongoc_cursor_error(cursor, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_find_with_opts()", error.message);
        goto cleanup;
    }

    if (order_min < UINT64_MAX) {
        *order = order_min;
    }

cleanup:
    free(order_str);
    bson_destroy(query);
    bson_destroy(query_opts);
    mongoc_cursor_destroy(cursor);
    return err_info;
}

/**
 * @brief If there is only one point order gap between elements where newly created element
 *          should be placed, shifting has to be done, e.g. 1  3  {4}   [5]  8  13
 *                                                                    *
 *                                                                    |
 *                                                                new element
 *                                                                    |
*                                                                     *
 *                                                          1  3  {4} 5 [6]  8  13
 * @param[in] module Given MongoDB collection.
 * @param[in] path_no_pred Path of a list/leaf-list instance without a predicate.
 * @param[in] next_elem_order Order of the next element.
 * @param[out] max_order Changed maximum order (shifting can change maximum order).
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_shift_uo_list_recursively(mongoc_collection_t *module, const char *path_no_pred, uint64_t next_elem_order,
        uint64_t *max_order)
{
    sr_error_info_t *err_info = 0;
    int found = 0;
    bson_error_t error;
    mongoc_cursor_t *cursor = NULL;
    bson_t *query = NULL, *query_opts = NULL, *query_iter = NULL, *query_key = NULL;
    bson_iter_t iter;
    const char *path = NULL;

    if ((err_info = srpds_get_maxord(module, path_no_pred, max_order))) {
        goto cleanup;
    }

    if (*max_order < next_elem_order) {
        *max_order = next_elem_order;
    }

    /* find the next element */
    query = BCON_NEW("order", BCON_INT64(next_elem_order), "path_no_pred", BCON_UTF8(path_no_pred));
    query_opts = BCON_NEW("projection", "{", "_id", BCON_BOOL(1), "}");
    cursor = mongoc_collection_find_with_opts(module, query, query_opts, NULL);

    if (mongoc_cursor_next(cursor, (const bson_t **) &query_iter)) {
        found = 1;

        if (!bson_iter_init(&iter, query_iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_init()", "");
            goto cleanup;
        }

        /* get path of the next element */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
            goto cleanup;
        }
        path = bson_iter_utf8(&iter, NULL);
        if (!bson_utf8_validate(path, strlen(path), 0)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_utf8()", "");
            goto cleanup;
        }
    }

    if (mongoc_cursor_error(cursor, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_find_with_opts()", error.message);
        goto cleanup;
    }
    bson_destroy(query);
    query = NULL;

    if (found) {
        /* An element with such order has been found, shift all elements
         * after this element */
        if ((err_info = srpds_shift_uo_list_recursively(module, path_no_pred, next_elem_order + 1, max_order))) {
            goto cleanup;
        }

        /* change order of this element */
        query_key = BCON_NEW("_id", BCON_UTF8(path));
        query = BCON_NEW("$set", "{", "order", BCON_INT64(next_elem_order + 1), "}");
        if ((err_info = srpds_update(module, query_key, query, 0))) {
            goto cleanup;
        }
    }

cleanup:
    bson_destroy(query);
    bson_destroy(query_opts);
    mongoc_cursor_destroy(cursor);
    bson_destroy(query_key);
    return err_info;
}

/**
 * @brief Prepare the insertion/update of a user-ordered element in the database.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] path_no_pred Path without a predicate of the user-ordered element.
 * @param[in] predicate Predicate of the user-ordered element.
 * @param[in] prev Value of the node before this node.
 * @param[out] max_order Changed maximum order.
 * @param[out] order Order to use for insert/update.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_prepare_create_uo_op(mongoc_collection_t *module, const char *path_no_pred, const char *predicate,
        const char *prev, uint64_t *max_order, uint64_t *order)
{
    sr_error_info_t *err_info = NULL;
    bson_t *query = NULL, *query_key = NULL;
    uint64_t prev_order = 0, next_order = 0;

    /* there is a previous element */
    if (strcmp(prev, "")) {
        /* load previous,
         * get order of the previous element */
        if ((err_info = srpds_load_prev(module, prev, path_no_pred, &prev_order))) {
            goto cleanup;
        }

        /* load next
         * get order of the next element */
        if ((err_info = srpds_load_next(module, prev, path_no_pred, &next_order))) {
            goto cleanup;
        }

        if (!next_order) {
            /* get max order for lists and leaf-lists */
            if ((err_info = srpds_get_maxord(module, path_no_pred, max_order))) {
                goto cleanup;
            }

            srpds_inc_maxord(max_order);

            /* calculate order */
            *order = *max_order;
        } else if (next_order - prev_order == 1) {
            /* shift the next elements by one recursively */
            if ((err_info = srpds_shift_uo_list_recursively(module, path_no_pred, next_order, max_order))) {
                goto cleanup;
            }

            /* calculate order */
            *order = next_order;

            /* add new prev element to the next element */
            query_key = BCON_NEW("prev", BCON_UTF8(prev), "path_no_pred", BCON_UTF8(path_no_pred));
            query = BCON_NEW("$set", "{", "prev", BCON_UTF8(predicate), "}");
            if ((err_info = srpds_update(module, query_key, query, 0))) {
                goto cleanup;
            }
        } else {
            /* calculate order */
            *order = (uint64_t)(prev_order + (next_order - prev_order) / 2);

            /* add new prev element to the next element */
            query_key = BCON_NEW("prev", BCON_UTF8(prev), "path_no_pred", BCON_UTF8(path_no_pred));
            query = BCON_NEW("$set", "{", "prev", BCON_UTF8(predicate), "}");
            if ((err_info = srpds_update(module, query_key, query, 0))) {
                goto cleanup;
            }
        }
        /* there is no previous element */
    } else {
        /* load next */
        if ((err_info = srpds_load_next(module, prev, path_no_pred, &next_order))) {
            goto cleanup;
        }

        if (!next_order) {
            /* "no previous element and no next element" might
             * mean two things - either the max order was not
             * inserted yet or it was but all elements of the
             * list were deleted */

            /* set max order for lists and leaf-lists */
            if ((err_info = srpds_set_maxord(module, path_no_pred, SRPDS_DB_UO_ELEMS_GAP_SIZE))) {
                goto cleanup;
            }

            /* calculate order */
            *order = SRPDS_DB_UO_ELEMS_GAP_SIZE;
        } else if (next_order == 1) {
            /* shift next elements by one recursively */
            if ((err_info = srpds_shift_uo_list_recursively(module, path_no_pred, next_order, max_order))) {
                goto cleanup;
            }

            /* calculate order */
            *order = next_order;

            /* add new prev element to the next element */
            query_key = BCON_NEW("prev", BCON_UTF8(prev), "path_no_pred", BCON_UTF8(path_no_pred));
            query = BCON_NEW("$set", "{", "prev", BCON_UTF8(predicate), "}");
            if ((err_info = srpds_update(module, query_key, query, 0))) {
                goto cleanup;
            }
        } else {
            /* calculate order */
            *order = (uint64_t)(next_order / 2);

            /* add new prev element to the next element */
            query_key = BCON_NEW("prev", BCON_UTF8(prev), "path_no_pred", BCON_UTF8(path_no_pred));
            query = BCON_NEW("$set", "{", "prev", BCON_UTF8(predicate), "}");
            if ((err_info = srpds_update(module, query_key, query, 0))) {
                goto cleanup;
            }
        }
    }

cleanup:
    bson_destroy(query_key);
    bson_destroy(query);
    return err_info;
}

/**
 * @brief Prepare a deletion/update of a user-ordered element from a list or a leaf-list in the database.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] path_no_pred Path without a predicate of the user-ordered element.
 * @param[in] predicate Predicate of the user-ordered element.
 * @param[in] orig_value_pred Predicate of a previous element.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_prepare_delete_uo_op(mongoc_collection_t *module, const char *path_no_pred, const char *predicate,
        const char *orig_value_pred)
{
    sr_error_info_t *err_info = NULL;
    bson_t *query = NULL, *query_key = NULL;

    /* add new prev element to the next element */
    query_key = BCON_NEW("prev", BCON_UTF8(predicate), "path_no_pred", BCON_UTF8(path_no_pred));
    query = BCON_NEW("$set", "{", "prev", BCON_UTF8(orig_value_pred), "}");
    if ((err_info = srpds_update(module, query_key, query, 0))) {
        goto cleanup;
    }

cleanup:
    bson_destroy(query_key);
    bson_destroy(query);
    return err_info;
}

/**
 * @brief Create a userordered element in the database.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] ds Given datastore.
 * @param[in] node Node to store.
 * @param[in] path Path to the node.
 * @param[in] path_no_pred Path without a predicate.
 * @param[in] tree Whole data tree.
 * @param[out] max_order Maximum order of the userordered list/leaflist.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_create_uo_op(mongoc_collection_t *module, sr_datastore_t ds, const struct lyd_node *node, const char *path,
        const char *path_no_pred, const struct lyd_node *tree, uint64_t *max_order)
{
    sr_error_info_t *err_info = NULL;
    bson_t *query = NULL;
    const char *module_name, *value;
    char *path_modif = NULL, *prev = NULL, *keys = NULL;
    uint32_t keys_length = 0;
    struct lyd_node *match = NULL;
    uint64_t order = 0;

    /* get modified version of path */
    if ((err_info = srpds_get_modif_path(plugin_name, path, &path_modif))) {
        goto cleanup;
    }

    /* get module name */
    if ((node->parent == NULL) || strcmp(node->schema->module->name, node->parent->schema->module->name)) {
        module_name = node->schema->module->name;
    } else {
        module_name = NULL;
    }

    /* get prev value */
    if ((err_info = srpds_get_prev_value(plugin_name, node, &prev))) {
        goto cleanup;
    }

    /* metadata are only stored in oper ds */
    if (ds == SR_DS_OPERATIONAL) {
        /* find the node in the mod_data to read metadata from */
        if ((err_info = srpds_find_node(plugin_name, node, tree, &match))) {
            goto cleanup;
        }
    }

    /* prepare insertion of a new element into the user-ordered list */
    if ((err_info = srpds_prepare_create_uo_op(module, path_no_pred, srpds_get_predicate(path, path_no_pred),
            prev, max_order, &order))) {
        goto cleanup;
    }

    /* insert an element */
    /* we need is_prev_empty field since we cannot check if prev is empty or not */
    switch (node->schema->nodetype) {
    case LYS_LIST:
        if ((err_info = srpds_concat_key_values(plugin_name, node, &keys, &keys_length))) {
            goto cleanup;
        }
        if ((err_info = srpds_list_uo(path, node->schema->name, module_name, keys, keys_length, order,
                path_no_pred, prev, path_modif, match ? match->meta : NULL, &query))) {
            goto cleanup;
        }
        break;
    case LYS_LEAFLIST:
        value = lyd_get_value(node);
        if ((err_info = srpds_leaflist_uo(path, node->schema->name, module_name, (node->flags & LYD_DEFAULT),
                value, order, path_no_pred, prev, path_modif, match ? match->meta : NULL, &query))) {
            goto cleanup;
        }
        break;
    }

    if ((err_info = srpds_insert(module, query))) {
        goto cleanup;
    }

cleanup:
    free(path_modif);
    free(prev);
    free(keys);
    bson_destroy(query);
    return err_info;
}

/**
 * @brief Delete a userordered element from the database.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] node Node to delete.
 * @param[in] path Path to the node.
 * @param[in] path_no_pred Path without a predicate.
 * @param[out] bulk Bulk structure to insert query into.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_delete_uo_op(mongoc_collection_t *module, const struct lyd_node *node, const char *path,
        const char *path_no_pred, mongo_bulk_data_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    char *orig_prev = NULL;

    /* get orig_prev value */
    if ((err_info = srpds_get_orig_prev_value(plugin_name, node, &orig_prev))) {
        goto cleanup;
    }

    /* prepare deletion of an element from the user-ordered list */
    if ((err_info = srpds_prepare_delete_uo_op(module, path_no_pred, srpds_get_predicate(path, path_no_pred),
            orig_prev))) {
        goto cleanup;
    }

    /* delete one element */
    if ((err_info = srpds_delete_id(module, path))) {
        goto cleanup;
    }

    if (lyd_child_no_keys(node)) {
        /* delete a whole subtree */
        if ((err_info = srpds_bulk_delete_subtree(path, bulk))) {
            goto cleanup;
        }
    }

cleanup:
    free(orig_prev);
    return err_info;
}

/**
 * @brief Move/update a userordered element in the database.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] ds Given datastore.
 * @param[in] node Node to update.
 * @param[in] path Path to the node.
 * @param[in] path_no_pred Path without a predicate.
 * @param[in] tree Whole data tree.
 * @param[out] max_order Maximum order of the userordered list/leaflist.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_replace_uo_op(mongoc_collection_t *module, sr_datastore_t ds, const struct lyd_node *node, const char *path,
        const char *path_no_pred, const struct lyd_node *tree, uint64_t *max_order)
{
    sr_error_info_t *err_info = NULL;
    bson_t *query_key = NULL, *query = NULL;
    bson_t subquery;
    const char *predicate, *value;
    char *prev = NULL, *orig_prev = NULL;
    struct lyd_node *match = NULL;
    uint64_t order = 0;

    /* get predicate */
    predicate = srpds_get_predicate(path, path_no_pred);

    /* get prev value */
    if ((err_info = srpds_get_prev_value(plugin_name, node, &prev))) {
        goto cleanup;
    }

    /* get orig_prev value */
    if ((err_info = srpds_get_orig_prev_value(plugin_name, node, &orig_prev))) {
        goto cleanup;
    }

    /* prepare deletion of an element from the user-ordered list */
    if ((err_info = srpds_prepare_delete_uo_op(module, path_no_pred, predicate, orig_prev))) {
        goto cleanup;
    }

    /* insert a new element into the user-ordered list */
    if ((err_info = srpds_prepare_create_uo_op(module, path_no_pred, predicate, prev, max_order, &order))) {
        goto cleanup;
    }

    /* replace command */
    query = bson_new();
    bson_append_document_begin(query, "$set", 4, &subquery);
    switch (node->schema->nodetype) {
    case LYS_LIST:
        /* add nothing */
        break;
    case LYS_LEAFLIST:
        value = lyd_get_value(node);
        bson_append_bool(&subquery, "dflt_flag", 9, node->flags & LYD_DEFAULT);
        bson_append_utf8(&subquery, "value", 5, value, -1);
        break;
    }
    bson_append_int64(&subquery, "order", 5, order);
    bson_append_utf8(&subquery, "prev", 4, prev, -1);

    if (ds == SR_DS_OPERATIONAL) {
        /* delete metadata immediately (no bulking) */
        if ((err_info = srpds_delete_meta(module, path, NULL))) {
            goto cleanup;
        }

        /* find the node in the mod_data to read metadata from */
        if ((err_info = srpds_find_node(plugin_name, node, tree, &match))) {
            goto cleanup;
        }

        /* add new metadata */
        if ((err_info = srpds_add_meta(match->meta, &subquery))) {
            goto cleanup;
        }
    }
    bson_append_document_end(query, &subquery);

    query_key = BCON_NEW("_id", BCON_UTF8(path));
    if ((err_info = srpds_update(module, query_key, query, 0))) {
        goto cleanup;
    }

cleanup:
    free(prev);
    free(orig_prev);
    bson_destroy(query_key);
    bson_destroy(query);
    return err_info;
}

/**
 * @brief Update node's default flag and metadata.
 *
 * @param[in] ds Given datastore.
 * @param[in] node Node to update.
 * @param[in] path Path to the node.
 * @param[in] tree Whole data tree.
 * @param[out] bulk Bulk structure to insert query into.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_none_op(sr_datastore_t ds, const struct lyd_node *node, const char *path, const struct lyd_node *tree,
        mongo_bulk_data_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    bson_t *query = NULL, *query_key = NULL;
    bson_t subquery;
    struct lyd_node *match = NULL;

    if (!(node->schema->nodetype & LYD_NODE_TERM) && (ds != SR_DS_OPERATIONAL)) {
        goto cleanup;
    }

    query = bson_new();
    bson_append_document_begin(query, "$set", 4, &subquery);

    /* update default flag */
    if (node->schema->nodetype & LYD_NODE_TERM) {
        bson_append_bool(&subquery, "dflt_flag", 9, node->flags & LYD_DEFAULT);
    }

    /* metadata are only stored in oper ds */
    if (ds == SR_DS_OPERATIONAL) {
        /* delete metadata */
        if ((err_info = srpds_delete_meta(NULL, path, bulk))) {
            goto cleanup;
        }

        /* find the node in the mod_data to read metadata from */
        if ((err_info = srpds_find_node(plugin_name, node, tree, &match))) {
            goto cleanup;
        }

        /* add metadata */
        if ((err_info = srpds_add_meta(match->meta, &subquery))) {
            goto cleanup;
        }
    }
    bson_append_document_end(query, &subquery);

    query_key = BCON_NEW("_id", BCON_UTF8(path));
    if ((err_info = srpds_bulk_update(query_key, query, 0, bulk))) {
        goto cleanup;
    }

cleanup:
    bson_destroy(query_key);
    bson_destroy(query);
    return err_info;
}

/**
 * @brief Create a standard node in the database.
 *
 * @param[in] ds Given datastore.
 * @param[in] node Node to store.
 * @param[in] path Path to the node.
 * @param[in] tree Whole data tree.
 * @param[out] bulk Bulk structure to insert query into.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_create_op(sr_datastore_t ds, const struct lyd_node *node, const char *path, const struct lyd_node *tree,
        mongo_bulk_data_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    bson_t *query = NULL;
    const char *module_name, *value;
    char *any_value = NULL, *keys = NULL, *path_modif = NULL;
    uint32_t keys_length = 0;
    struct lyd_node *match = NULL;

    /* get modified version of path */
    if ((err_info = srpds_get_modif_path(plugin_name, path, &path_modif))) {
        goto cleanup;
    }

    /* get module name */
    if ((node->parent == NULL) || strcmp(node->schema->module->name, node->parent->schema->module->name)) {
        module_name = node->schema->module->name;
    } else {
        module_name = NULL;
    }

    /* metadata are only stored in oper ds */
    if (ds == SR_DS_OPERATIONAL) {
        /* find the node in the mod_data to read metadata from */
        if ((err_info = srpds_find_node(plugin_name, node, tree, &match))) {
            goto cleanup;
        }
    }

    /* insert an element */
    switch (node->schema->nodetype) {
    case LYS_CONTAINER:
        if ((err_info = srpds_container(path, node->schema->name, module_name, path_modif, match ? match->meta : NULL,
                &query))) {
            goto cleanup;
        }
        break;
    case LYS_LIST:
        if ((err_info = srpds_concat_key_values(plugin_name, node, &keys, &keys_length))) {
            goto cleanup;
        }
        if ((err_info = srpds_list(path, node->schema->name, module_name, keys, keys_length, path_modif,
                match ? match->meta : NULL, &query))) {
            goto cleanup;
        }
        break;
    case LYS_LEAF:
    case LYS_LEAFLIST:
        value = lyd_get_value(node);
        if ((err_info = srpds_term(path, node->schema->name, module_name, (node->flags & LYD_DEFAULT), value,
                path_modif, match ? match->meta : NULL, &query))) {
            goto cleanup;
        }
        break;
    case LYS_ANYDATA:
    case LYS_ANYXML:
        /* lyd_node_any */
        if (lyd_any_value_str(node, &any_value) != LY_SUCCESS) {
            ERRINFO(&err_info, plugin_name, SR_ERR_LY, "lyd_any_value_str()", "");
            goto cleanup;
        }
        if ((err_info = srpds_any(path, node->schema->name, module_name, any_value,
                (((struct lyd_node_any *)node)->value_type == LYD_ANYDATA_JSON), path_modif,
                match ? match->meta : NULL, &query))) {
            goto cleanup;
        }
        break;
    default:
        break;
    }

    /* insert element */
    if ((err_info = srpds_bulk_insert(query, bulk))) {
        goto cleanup;
    }

cleanup:
    free(path_modif);
    free(any_value);
    free(keys);
    bson_destroy(query);
    return err_info;
}

/**
 * @brief Delete a standard node from the database.
 *
 * @param[in] node Node to delete.
 * @param[in] path Path to the node.
 * @param[out] bulk Bulk structure to insert query into.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_delete_op(const struct lyd_node *node, const char *path, mongo_bulk_data_t *bulk)
{
    sr_error_info_t *err_info = NULL;

    /* delete one element */
    if ((err_info = srpds_bulk_delete_id(path, bulk))) {
        goto cleanup;
    }

    if (lyd_child_no_keys(node)) {
        /* delete a whole subtree */
        if ((err_info = srpds_bulk_delete_subtree(path, bulk))) {
            goto cleanup;
        }
    }

cleanup:
    return err_info;
}

/**
 * @brief Update a standard node in the database.
 *
 * @param[in] ds Given datastore.
 * @param[in] node Node to update.
 * @param[in] path Path to the node.
 * @param[in] tree Whole data tree.
 * @param[out] bulk Bulk structure to insert query into.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_replace_op(sr_datastore_t ds, const struct lyd_node *node, const char *path, const struct lyd_node *tree,
        mongo_bulk_data_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    bson_t *query = NULL, *query_key = NULL;
    bson_t subquery;
    const char *value;
    char *any_value = NULL;
    struct lyd_node *match = NULL;

    /* get value */
    if ((err_info = srpds_get_norm_values(plugin_name, node, &value, &any_value))) {
        goto cleanup;
    }

    query = bson_new();
    bson_append_document_begin(query, "$set", 4, &subquery);
    bson_append_utf8(&subquery, "value", 5, value, -1);

    /* handle default flag update */
    if (node->schema->nodetype & LYD_NODE_TERM) {
        bson_append_bool(&subquery, "dflt_flag", 9, node->flags & LYD_DEFAULT);
    }

    /* metadata are only stored in oper ds */
    if (ds == SR_DS_OPERATIONAL) {
        /* delete metadata (with bulking) */
        if ((err_info = srpds_delete_meta(NULL, path, bulk))) {
            goto cleanup;
        }

        /* find the node in the mod_data to read metadata from */
        if ((err_info = srpds_find_node(plugin_name, node, tree, &match))) {
            goto cleanup;
        }

        /* add new metadata */
        if ((err_info = srpds_add_meta(match->meta, &subquery))) {
            goto cleanup;
        }
    }
    bson_append_document_end(query, &subquery);

    query_key = BCON_NEW("_id", BCON_UTF8(path));
    if ((err_info = srpds_bulk_update(query_key, query, 0, bulk))) {
        goto cleanup;
    }

cleanup:
    free(any_value);
    bson_destroy(query_key);
    bson_destroy(query);
    return err_info;
}

/**
 * @brief Load state data subtree (only for state data).
 *
 * @param[in] set Set of data nodes which need to be stored.
 * @param[in] node Data subtree.
 * @param[out] bulk Bulk structure to insert query into.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_store_state_recursively(const struct ly_set *set, const struct lyd_node *node, mongo_bulk_data_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    bson_t *query = NULL;
    const struct lyd_node *sibling = node;
    struct lyd_node *child = NULL;
    char *path = NULL, *path_no_pred = NULL, *path_modif = NULL;
    const char *module_name = NULL, *value = NULL;
    char *any_value = NULL;
    char *keys = NULL;
    uint32_t keys_length = 0;
    uint64_t order = 1;
    uint32_t set_idx = 1;

    while (sibling) {
        /* get path */
        path = lyd_path(sibling, LYD_PATH_STD, NULL, 0);
        if (!path) {
            ERRINFO(&err_info, plugin_name, SR_ERR_LY, "lyd_path()", "");
            return err_info;
        }

        /* get path_no_pred */
        if (lysc_is_userordered(sibling->schema)) {
            path_no_pred = lyd_path(sibling, LYD_PATH_STD_NO_LAST_PRED, NULL, 0);
            if (!path_no_pred) {
                ERRINFO(&err_info, plugin_name, SR_ERR_LY, "lyd_path()", "");
                return err_info;
            }
        }

        /* get modified version of path */
        if ((err_info = srpds_get_modif_path(plugin_name, path, &path_modif))) {
            goto cleanup;
        }

        /* create all data (state nodes) */
        /* get module name */
        if ((sibling->parent == NULL) || strcmp(sibling->schema->module->name, sibling->parent->schema->module->name)) {
            module_name = sibling->schema->module->name;
        } else {
            module_name = NULL;
        }

        switch (sibling->schema->nodetype) {
        case LYS_CONTAINER:
            if ((err_info = srpds_container(path, sibling->schema->name, module_name, path_modif, sibling->meta,
                    &query))) {
                goto cleanup;
            }
            break;
        case LYS_LIST:     /* state lists are always userordered (either key or keyless) */
            if ((err_info = srpds_concat_key_values(plugin_name, sibling, &keys, &keys_length))) {
                goto cleanup;
            }

            /* only change the predicate for keyless lists since state key lists are guaranteed to be unique */
            if (sibling->schema->flags & LYS_KEYLESS) {
                free(path);
                path = NULL;

                /* create unique path (duplicates can be present in state data) */
                if (asprintf(&path, "%s[%" PRIu64 "]", path_no_pred, order) == -1) {
                    ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
                    goto cleanup;
                }
            }

            if ((err_info = srpds_list_uo(path, sibling->schema->name, module_name, keys, keys_length, order,
                    path_no_pred, "", path_modif, sibling->meta, &query))) {
                goto cleanup;
            }
            free(keys);
            keys = NULL;
            keys_length = 0;
            order++;
            break;
        case LYS_LEAF:
            value = lyd_get_value(sibling);
            if ((err_info = srpds_term(path, sibling->schema->name, module_name, sibling->flags & LYD_DEFAULT, value,
                    path_modif, sibling->meta, &query))) {
                goto cleanup;
            }
            break;
        case LYS_LEAFLIST:  /* state leaf-lists are always userordered */
            value = lyd_get_value(sibling);
            free(path);
            path = NULL;

            /* create unique path (duplicates can be present in state data) */
            if (asprintf(&path, "%s[%" PRIu64 "]", path_no_pred, order) == -1) {
                ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
                goto cleanup;
            }
            if ((err_info = srpds_leaflist_uo(path, sibling->schema->name, module_name, sibling->flags & LYD_DEFAULT,
                    value, order, path_no_pred, "", path_modif, sibling->meta, &query))) {
                goto cleanup;
            }
            order++;
            break;
        case LYS_ANYDATA:
        case LYS_ANYXML:
            /* lyd_node_any */
            if (lyd_any_value_str(sibling, &any_value) != LY_SUCCESS) {
                ERRINFO(&err_info, plugin_name, SR_ERR_LY, "lyd_any_value_str()", "");
                goto cleanup;
            }
            if ((err_info = srpds_any(path, sibling->schema->name, module_name, any_value,
                    (((struct lyd_node_any *)sibling)->value_type == LYD_ANYDATA_JSON), path_modif, sibling->meta,
                    &query))) {
                goto cleanup;
            }
            free(any_value);
            any_value = NULL;
            break;
        default:
            break;
        }

        /* create new node */
        if ((err_info = srpds_bulk_insert(query, bulk))) {
            goto cleanup;
        }

        /* reset the order if the next sibling
         * is from a different list or if the next sibling does not exist */
        if (lysc_is_userordered(sibling->schema) &&
                ((sibling->next && (sibling->schema->name != sibling->next->schema->name)) || !sibling->next)) {
            order = 1;
        }

        /* free memory early before further recursion */
        free(path);
        path = NULL;
        free(path_no_pred);
        path_no_pred = NULL;
        free(path_modif);
        path_modif = NULL;
        bson_destroy(query);
        query = NULL;

        if ((child = lyd_child_no_keys(sibling))) {
            if ((err_info = srpds_store_state_recursively(NULL, child, bulk))) {
                goto cleanup;
            }
        }

        /* top level node should only consider its siblings in set since its siblings can be configuration nodes */
        if (set) {
            sibling = (set_idx < set->count) ? set->dnodes[set_idx++] : NULL;
        } else {
            sibling = sibling->next;
        }
    }

cleanup:
    free(path);
    free(path_no_pred);
    free(path_modif);
    free(any_value);
    free(keys);
    bson_destroy(query);
    return err_info;
}

/**
 * @brief Store the whole subtree using @p sibling inside a bulk with info from mod_data.
 *
 * @param[in] mod_data Module data tree to store.
 * @param[in] node Subtree from diff to use.
 * @param[out] bulk Bulk structure to insert query into.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_use_tree2store(const struct lyd_node *mod_data, const struct lyd_node *node, mongo_bulk_data_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    char *path_no_pred = NULL;
    struct ly_set *set = NULL;
    LY_ERR lerr;

    path_no_pred = lyd_path(node, LYD_PATH_STD_NO_LAST_PRED, NULL, 0);
    if (!path_no_pred) {
        ERRINFO(&err_info, plugin_name, SR_ERR_LY, "lyd_path()", "");
        goto cleanup;
    }

    if ((node->schema->nodetype != LYS_LIST) && (node->schema->nodetype != LYS_LEAFLIST)) {
        /* also delete the node if it has no predicate, otherwise it is deleted afterwards */
        if ((err_info = srpds_bulk_delete_id(path_no_pred, bulk))) {
            goto cleanup;
        }
    }
    if ((err_info = srpds_bulk_delete_subtree(path_no_pred, bulk))) {
        goto cleanup;
    }

    /* we NEED to store a deleted subtree
     * (could be a list or a leaf-list instance with siblings which we just deleted)
     * state data have to be stored from mod_data
     * find all data of state list/leaf-list */
    if (mod_data) {
        lerr = lyd_find_xpath(mod_data, path_no_pred, &set);
        if ((lerr != LY_SUCCESS) && (lerr != LY_ENOTFOUND)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_LY, "lyd_find_xpath()", "");
            goto cleanup;
        }
        free(path_no_pred);
        path_no_pred = NULL;

        if (lerr != LY_ENOTFOUND) {
            /* go through the whole subtree and create every node */
            if (set->count) {
                if ((err_info = srpds_store_state_recursively(set, set->dnodes[0], bulk))) {
                    goto cleanup;
                }
            }

            ly_set_free(set, NULL);
            set = NULL;
        }
    }

cleanup:
    free(path_no_pred);
    ly_set_free(set, NULL);
    return err_info;
}

static sr_error_info_t *srpds_store_diff_recursively(mongoc_collection_t *module, sr_datastore_t ds,
        const struct lyd_node *mod_data, const struct lyd_node *node, char parent_op, uint64_t *max_order,
        mongo_bulk_data_t *bulk);

/**
 * @brief Store the userordered node @p sibling inside a bulk with info from diff.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] ds Datastore in use.
 * @param[in] mod_data Whole module data tree.
 * @param[in] sibling Current data node in the diff.
 * @param[in] this_op Operation on this node.
 * @param[in, out] max_order Max order for userordered lists and leaf-lists.
 * @param[out] bulk Bulk structure to insert query into.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_use_diff_uo2store(mongoc_collection_t *module, sr_datastore_t ds, const struct lyd_node *mod_data,
        const struct lyd_node *sibling, char this_op, uint64_t *max_order, mongo_bulk_data_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *child = NULL;
    char *path = NULL, *path_no_pred = NULL;

    /* get path */
    path = lyd_path(sibling, LYD_PATH_STD, NULL, 0);
    if (!path) {
        ERRINFO(&err_info, plugin_name, SR_ERR_LY, "lyd_path()", "");
        return err_info;
    }

    /* get path_no_pred */
    path_no_pred = lyd_path(sibling, LYD_PATH_STD_NO_LAST_PRED, NULL, 0);
    if (!path_no_pred) {
        ERRINFO(&err_info, plugin_name, SR_ERR_LY, "lyd_path()", "");
        return err_info;
    }

    /* operation */
    switch (this_op) {
    case 'n':
        /* use bulk */
        if ((err_info = srpds_none_op(ds, sibling, path, mod_data, bulk))) {
            goto cleanup;
        }
        break;
    case 'c':
        if ((err_info = srpds_create_uo_op(module, ds, sibling, path, path_no_pred, mod_data, max_order))) {
            goto cleanup;
        }
        break;
    case 'd':
        if ((err_info = srpds_delete_uo_op(module, sibling, path, path_no_pred, bulk))) {
            goto cleanup;
        }
        break;
    case 'r':
        if ((err_info = srpds_replace_uo_op(module, ds, sibling, path, path_no_pred, mod_data, max_order))) {
            goto cleanup;
        }
        break;
    default:
        ERRINFO(&err_info, plugin_name, SR_ERR_UNSUPPORTED, "Operation for a node", "Unsupported operation");
        goto cleanup;
    }

    /* reset the max_order if the next sibling
     * is from a different list or if the next sibling does not exist */
    if ((sibling->next && (sibling->schema->name != sibling->next->schema->name)) || !(sibling->next)) {
        /* update max order for lists and leaf-lists */
        if ((err_info = srpds_set_maxord(module, path_no_pred, *max_order))) {
            goto cleanup;
        }
        *max_order = 0;
    }

    /* free memory early before further recursion */
    free(path);
    path = NULL;
    free(path_no_pred);
    path_no_pred = NULL;

    /* we do not care about children that were already deleted */
    if ((this_op != 'd') && (child = lyd_child_no_keys(sibling))) {
        if ((err_info = srpds_store_diff_recursively(module, ds, mod_data, child, this_op, max_order, bulk))) {
            goto cleanup;
        }
    }

cleanup:
    free(path);
    free(path_no_pred);
    return err_info;
}

/**
 * @brief Store the node @p sibling inside a bulk with info from diff.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] ds Datastore in use.
 * @param[in] mod_data Whole module data tree.
 * @param[in] sibling Current data node in the diff.
 * @param[in] this_op Operation on this node.
 * @param[in, out] max_order Max order for userordered lists and leaf-lists.
 * @param[out] bulk Bulk structure to insert query into.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_use_diff2store(mongoc_collection_t *module, sr_datastore_t ds, const struct lyd_node *mod_data,
        const struct lyd_node *sibling, char this_op, uint64_t *max_order, mongo_bulk_data_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *child = NULL;
    char *path = NULL;

    /* get path */
    path = lyd_path(sibling, LYD_PATH_STD, NULL, 0);
    if (!path) {
        ERRINFO(&err_info, plugin_name, SR_ERR_LY, "lyd_path()", "");
        return err_info;
    }

    /* operation */
    switch (this_op) {
    case 'n':
        if ((err_info = srpds_none_op(ds, sibling, path, mod_data, bulk))) {
            goto cleanup;
        }
        break;
    case 'c':
        if ((err_info = srpds_create_op(ds, sibling, path, mod_data, bulk))) {
            goto cleanup;
        }
        break;
    case 'd':
        if ((err_info = srpds_delete_op(sibling, path, bulk))) {
            goto cleanup;
        }
        break;
    case 'r':
        if ((err_info = srpds_replace_op(ds, sibling, path, mod_data, bulk))) {
            goto cleanup;
        }
        break;
    default:
        ERRINFO(&err_info, plugin_name, SR_ERR_UNSUPPORTED, "Operation for a node", "Unsupported operation");
        goto cleanup;
    }

    /* free memory early before further recursion */
    free(path);
    path = NULL;

    /* we do not care about children that were already deleted */
    if ((this_op != 'd') && (child = lyd_child_no_keys(sibling))) {
        if ((err_info = srpds_store_diff_recursively(module, ds, mod_data, child, this_op, max_order, bulk))) {
            goto cleanup;
        }
    }

cleanup:
    free(path);
    return err_info;
}

/**
 * @brief Handle an opaque node.
 *
 * @param[in] node Opaque node.
 * @param[in] op Operation to perform.
 * @param[out] bulk Bulk structure to insert query into.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_handle_opaque_node(const struct lyd_node *node, char op, mongo_bulk_data_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node_opaq *opaque = NULL;
    char *path = NULL, *path_modif = NULL, *discard_items_path = NULL;
    const char *module_name = NULL, *value = NULL;
    bson_t *query = NULL;
    struct lyd_attr *attr = NULL;

    /* get node's path */
    path = lyd_path(node, LYD_PATH_STD, NULL, 0);
    if (!path) {
        ERRINFO(&err_info, plugin_name, SR_ERR_LY, "lyd_path()", "");
        goto cleanup;
    }

    /* get value */
    value = lyd_get_value(node);

    /* get a unique path for the database */
    if (asprintf(&discard_items_path, "%s$%s", path, value) == -1) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
        goto cleanup;
    }

    opaque = ((struct lyd_node_opaq *)node);

    /* opaque node has to have a JSON format */
    assert(opaque->format == LY_VALUE_JSON);

    /* operation is unknown */
    if (!op) {
        attr = opaque->attr;

        /* find the operation (only attribute) */
        if (attr) {
            op = attr->value[0];
        } else {
            ERRINFO(&err_info, plugin_name, SR_ERR_NOT_FOUND, "",
                    "Operation for opaque node was not found in attributes.");
            goto cleanup;
        }
    }

    switch (op) {
    case 'd':
        /* delete only one instance (attributes are not stored and opaque nodes are only top-level discard-items) */
        if ((err_info = srpds_bulk_delete_id(discard_items_path, bulk))) {
            goto cleanup;
        }
        break;
    case 'c':
        /* get modified version of path */
        if ((err_info = srpds_get_modif_path(plugin_name, discard_items_path, &path_modif))) {
            goto cleanup;
        }

        /* get module name */
        module_name = opaque->name.module_name;

        /* create new opaque node */
        query = srpds_opaque(discard_items_path, opaque->name.name, module_name, path, value, path_modif);
        if ((err_info = srpds_bulk_insert(query, bulk))) {
            goto cleanup;
        }
        break;
    default:
        ERRINFO(&err_info, plugin_name, SR_ERR_UNSUPPORTED, "Operation for a node", "Unsupported operation");
        goto cleanup;
    }

cleanup:
    free(path);
    free(discard_items_path);
    free(path_modif);
    bson_destroy(query);
    return err_info;
}

/**
 * @brief Load the whole diff and store the operations inside a bulk.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] ds Datastore in use.
 * @param[in] mod_data Module data tree to store.
 * @param[in] node Current data node in the diff.
 * @param[in] parent_op Operation on the node's parent.
 * @param[in,out] max_order Maximum order of the userordered lists/leaflists.
 * @param[out] bulk Bulk structure to insert query into.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_store_diff_recursively(mongoc_collection_t *module, sr_datastore_t ds, const struct lyd_node *mod_data,
        const struct lyd_node *node, char parent_op, uint64_t *max_order, mongo_bulk_data_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *sibling = node;
    struct lyd_meta *meta_op;
    char this_op = 0;
    const struct lysc_node *previous_schema = NULL;

    while (sibling) {
        /* n - none, c - create, d - delete, r - replace */
        meta_op = lyd_find_meta(sibling->meta, NULL, "yang:operation");
        if (meta_op) {
            this_op = lyd_get_meta_value(meta_op)[0];
        } else {
            this_op = parent_op;
        }

        /* check whether to rely on diff or delete and store the whole subtree from mod_data */
        if (!sibling->schema) {
            if ((err_info = srpds_handle_opaque_node(sibling, 0, bulk))) {
                goto cleanup;
            }
        } else if (!(sibling->schema->flags & LYS_CONFIG_W)) {
            /* only delete and store a state subtree if it was not stored before */
            if (previous_schema != sibling->schema) {
                if ((err_info = srpds_use_tree2store(mod_data, sibling, bulk))) {
                    goto cleanup;
                }
            }
            previous_schema = sibling->schema;
        } else if (lysc_is_userordered(sibling->schema)) {
            if ((err_info = srpds_use_diff_uo2store(module, ds, mod_data, sibling, this_op, max_order, bulk))) {
                goto cleanup;
            }
        } else {
            if ((err_info = srpds_use_diff2store(module, ds, mod_data, sibling, this_op, max_order, bulk))) {
                goto cleanup;
            }
        }

        sibling = sibling->next;
    }

cleanup:
    return err_info;
}

/**
 * @brief Store the whole diff inside the database.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] ds Datastore in use.
 * @param[in] mod_data Module data tree to store.
 * @param[in] mod_diff Module diff.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_store_diff(mongoc_collection_t *module, sr_datastore_t ds, const struct lyd_node *mod_data,
        const struct lyd_node *mod_diff)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    mongo_bulk_data_t bulk = {0};
    bson_t *opts = NULL, reply;
    uint64_t max_order = 0;

    bson_init(&reply);

    opts = BCON_NEW("ordered", BCON_BOOL(0));
    bulk.bulk = mongoc_collection_create_bulk_operation_with_opts(module, opts);

    if ((err_info = srpds_store_diff_recursively(module, ds, mod_data, mod_diff, 0, &max_order, &bulk))) {
        goto cleanup;
    }

    if (bulk.has_operation) {
        if (!mongoc_bulk_operation_execute(bulk.bulk, &reply, &error)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_bulk_operation_execute()", error.message);
            goto cleanup;
        }
    }

cleanup:
    bson_destroy(opts);
    mongoc_bulk_operation_destroy(bulk.bulk);
    bson_destroy(&reply);
    return err_info;
}

/**
 * @brief Load the whole data tree (if there is no diff).
 *
 * @param[in] mod_data Whole data tree.
 * @param[out] bulk Bulk structure to insert query into.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_store_data_recursively(const struct lyd_node *mod_data, mongo_bulk_data_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    bson_t *query = NULL;
    const struct lyd_node *sibling = mod_data;
    struct lyd_node *child = NULL;
    char *path = NULL, *path_no_pred = NULL, *path_modif = NULL, *prev = NULL, *any_value = NULL;
    const char *value, *module_name;
    char *keys = NULL;
    uint32_t keys_length = 0;
    uint64_t state_order = 1, uo_order = 1024;

    while (sibling) {
        /* store opaque nodes separately */
        if (!sibling->schema) {
            if ((err_info = srpds_handle_opaque_node(sibling, 'c', bulk))) {
                goto cleanup;
            }
            sibling = sibling->next;
            continue;
        }

        /* get path */
        path = lyd_path(sibling, LYD_PATH_STD, NULL, 0);
        if (!path) {
            ERRINFO(&err_info, plugin_name, SR_ERR_LY, "lyd_path()", "");
            return err_info;
        }

        /* get path_no_pred */
        if (lysc_is_userordered(sibling->schema)) {
            path_no_pred = lyd_path(sibling, LYD_PATH_STD_NO_LAST_PRED, NULL, 0);
            if (!path_no_pred) {
                ERRINFO(&err_info, plugin_name, SR_ERR_LY, "lyd_path()", "");
                return err_info;
            }
        }

        /* get modified version of path */
        if ((err_info = srpds_get_modif_path(plugin_name, path, &path_modif))) {
            goto cleanup;
        }

        /* get prev value */
        if ((err_info = srpds_get_prev_value(plugin_name, sibling, &prev))) {
            goto cleanup;
        }

        /* get module name */
        if ((sibling->parent == NULL) || strcmp(sibling->schema->module->name, sibling->parent->schema->module->name)) {
            module_name = sibling->schema->module->name;
        } else {
            module_name = NULL;
        }

        /* create all data */
        switch (sibling->schema->nodetype) {
        case LYS_CONTAINER:
            if ((err_info = srpds_container(path, sibling->schema->name, module_name, path_modif, sibling->meta,
                    &query))) {
                goto cleanup;
            }
            break;
        case LYS_LIST:
            if ((err_info = srpds_concat_key_values(plugin_name, sibling, &keys, &keys_length))) {
                goto cleanup;
            }

            if (!(sibling->schema->flags & LYS_CONFIG_W)) {
                /* only change the predicate for keyless lists since state key lists are guaranteed to be unique */
                if (sibling->schema->flags & LYS_KEYLESS) {
                    /* state lists */
                    free(path);
                    path = NULL;

                    /* create unique path (duplicates can be present in state data) */
                    if (asprintf(&path, "%s[%" PRIu64 "]", path_no_pred, state_order) == -1) {
                        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
                        goto cleanup;
                    }
                }

                if ((err_info = srpds_list_uo(path, sibling->schema->name, module_name, keys, keys_length, state_order,
                        path_no_pred, "", path_modif, sibling->meta, &query))) {
                    goto cleanup;
                }
                ++state_order;
            } else if (lysc_is_userordered(sibling->schema)) {
                /* userordered lists */
                if ((err_info = srpds_list_uo(path, sibling->schema->name, module_name, keys, keys_length, uo_order,
                        path_no_pred, prev, path_modif, sibling->meta, &query))) {
                    goto cleanup;
                }
                uo_order += 1024;
            } else {
                /* lists */
                if ((err_info = srpds_list(path, sibling->schema->name, module_name, keys, keys_length, path_modif,
                        sibling->meta, &query))) {
                    goto cleanup;
                }
            }
            free(keys);
            keys = NULL;
            keys_length = 0;
            break;
        case LYS_LEAF:
            value = lyd_get_value(sibling);
            if ((err_info = srpds_term(path, sibling->schema->name, module_name, sibling->flags & LYD_DEFAULT, value,
                    path_modif, sibling->meta, &query))) {
                goto cleanup;
            }
            break;
        case LYS_LEAFLIST:
            value = lyd_get_value(sibling);
            if (!(sibling->schema->flags & LYS_CONFIG_W)) {
                /* state leaf-lists */
                free(path);
                path = NULL;

                /* create unique path (duplicates can be present in state data) */
                if (asprintf(&path, "%s[%" PRIu64 "]", path_no_pred, state_order) == -1) {
                    ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
                    goto cleanup;
                }

                if ((err_info = srpds_leaflist_uo(path, sibling->schema->name, module_name,
                        sibling->flags & LYD_DEFAULT, value, state_order, path_no_pred, "", path_modif, sibling->meta,
                        &query))) {
                    goto cleanup;
                }
                ++state_order;
            } else if (lysc_is_userordered(sibling->schema)) {
                /* userordered leaf-lists */
                if ((err_info = srpds_leaflist_uo(path, sibling->schema->name, module_name,
                        sibling->flags & LYD_DEFAULT, value, uo_order, path_no_pred, prev, path_modif,
                        sibling->meta, &query))) {
                    goto cleanup;
                }
                uo_order += 1024;
            } else {
                /* leaf-lists */
                if ((err_info = srpds_term(path, sibling->schema->name, module_name, sibling->flags & LYD_DEFAULT,
                        value, path_modif, sibling->meta, &query))) {
                    goto cleanup;
                }
            }
            break;
        case LYS_ANYDATA:
        case LYS_ANYXML:
            /* lyd_node_any */
            if (lyd_any_value_str(sibling, &any_value) != LY_SUCCESS) {
                ERRINFO(&err_info, plugin_name, SR_ERR_LY, "lyd_any_value_str()", "");
                goto cleanup;
            }
            if ((err_info = srpds_any(path, sibling->schema->name, module_name, any_value,
                    (((struct lyd_node_any *)sibling)->value_type == LYD_ANYDATA_JSON), path_modif, sibling->meta,
                    &query))) {
                goto cleanup;
            }
            free(any_value);
            any_value = NULL;
            break;
        }

        /* create new node */
        if ((err_info = srpds_bulk_insert(query, bulk))) {
            goto cleanup;
        }

        /* reset the orders if the next sibling
            * is from a different list or if the next sibling does not exist */
        if (lysc_is_userordered(sibling->schema) && ((sibling->next &&
                (sibling->schema->name != sibling->next->schema->name)) || !(sibling->next))) {
            state_order = 1;
            uo_order = 1024;
        }

        /* free memory early before further recursion */
        free(path);
        path = NULL;
        free(path_no_pred);
        path_no_pred = NULL;
        free(path_modif);
        path_modif = NULL;
        free(prev);
        prev = NULL;
        bson_destroy(query);
        query = NULL;

        if ((child = lyd_child_no_keys(sibling))) {
            if ((err_info = srpds_store_data_recursively(child, bulk))) {
                goto cleanup;
            }
        }

        sibling = sibling->next;
    }

cleanup:
    free(path);
    free(path_no_pred);
    free(path_modif);
    free(prev);
    free(any_value);
    free(keys);
    bson_destroy(query);
    return err_info;
}

/**
 * @brief Store the whole data tree in the database.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] mod_data Whole data tree.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_store_data(mongoc_collection_t *module, const struct lyd_node *mod_data)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    mongo_bulk_data_t bulk = {0};
    bson_t *opts = NULL, reply;

    bson_init(&reply);

    /* delete all data */
    if ((err_info = srpds_delete_regex(module, "^[^012]"))) {
        goto cleanup;
    }

    opts = BCON_NEW("ordered", BCON_BOOL(0));
    bulk.bulk = mongoc_collection_create_bulk_operation_with_opts(module, opts);

    if (mod_data && (err_info = srpds_store_data_recursively(mod_data, &bulk))) {
        goto cleanup;
    }

    if (bulk.has_operation) {
        if (!mongoc_bulk_operation_execute(bulk.bulk, &reply, &error)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_bulk_operation_execute()", error.message);
            goto cleanup;
        }
    }

cleanup:
    bson_destroy(opts);
    mongoc_bulk_operation_destroy(bulk.bulk);
    bson_destroy(&reply);
    return err_info;
}

/**
 * @brief Update last-modif flag.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] reset Whether to reset flag.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_set_last_modif_flag(mongoc_collection_t *module, int reset)
{
    sr_error_info_t *err_info = NULL;
    bson_t *query_key = NULL, *query = NULL;
    struct timespec spec = {0};

    if (!reset) {
        clock_gettime(CLOCK_REALTIME, &spec);
    }
    query_key = BCON_NEW("_id", BCON_UTF8("0"));
    query = BCON_NEW("$set", "{", "nsec", BCON_INT64((int64_t)(spec.tv_nsec)), "sec",
            BCON_INT64((int64_t)(spec.tv_sec)), "}");
    if ((err_info = srpds_update(module, query_key, query, 1))) {
        goto cleanup;
    }

cleanup:
    bson_destroy(query_key);
    bson_destroy(query);
    return err_info;
}

/**
 * @brief Update candidate-modified flag.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] modified Whether candidate datastore is modified.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_set_candidate_modified_flag(mongoc_collection_t *module, int modified)
{
    sr_error_info_t *err_info = NULL;
    bson_t *query_key = NULL, *query = NULL;

    query_key = BCON_NEW("_id", BCON_UTF8("1"));
    query = BCON_NEW("$set", "{", "modified", BCON_BOOL(modified), "}");
    if ((err_info = srpds_update(module, query_key, query, 1))) {
        goto cleanup;
    }

cleanup:
    bson_destroy(query_key);
    bson_destroy(query);
    return err_info;
}

/**
 * @brief Create a bunch of indices.
 *
 * @param[in] module Given MongoDB collection.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_create_indices(mongoc_collection_t *module)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    uint32_t i, idx_cnt = 3;
    bson_t *bson_index_keys[idx_cnt];
    mongoc_index_model_t *im[idx_cnt];

    /* create a compound index on prev and path for load_next(),
     * compound index on order and path_no_pred for srpds_shift_uo_list_recursively()
     * and index on path_modif for quicker loading */
    bson_index_keys[0] = BCON_NEW("prev", BCON_INT32(1), "path_no_pred", BCON_INT32(1));
    bson_index_keys[1] = BCON_NEW("order", BCON_INT32(1), "path_no_pred", BCON_INT32(1));
    bson_index_keys[2] = BCON_NEW("path_modif", BCON_INT32(1));
    for (i = 0; i < idx_cnt; ++i) {
        im[i] = mongoc_index_model_new(bson_index_keys[i], NULL /* opts */);
    }
    if (!mongoc_collection_create_indexes_with_opts(module, im, idx_cnt, NULL /* opts */, NULL /* reply */, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_create_indexes_with_opts",
                error.message);
        goto cleanup;
    }

cleanup:
    for (i = 0; i < idx_cnt; ++i) {
        mongoc_index_model_destroy(im[i]);
        bson_destroy(bson_index_keys[i]);
    }
    return err_info;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_mongo_candidate_modified(const struct lys_module *mod, void *plg_data, int *modified)
{
    mongo_data_t mdata;
    mongo_plg_conn_data_t *pdata = (mongo_plg_conn_data_t *)plg_data;
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    bson_t *query = NULL, *query_opts = NULL, *query_iter = NULL;
    mongoc_cursor_t *cursor = NULL;
    bson_iter_t iter;

    assert(mod && modified);

    if ((err_info = srpds_data_init(mod, SR_DS_CANDIDATE, 0, 0, 1, pdata, &mdata))) {
        goto cleanup;
    }

    query = BCON_NEW("_id", BCON_UTF8("1"));
    query_opts = BCON_NEW("projection", "{", "modified", BCON_BOOL(1), "_id", BCON_BOOL(0), "}");
    cursor = mongoc_collection_find_with_opts(mdata.module, query, query_opts, NULL);

    if (mongoc_cursor_next(cursor, (const bson_t **) &query_iter)) {
        if (!bson_iter_init(&iter, query_iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_init()", "");
            goto cleanup;
        }

        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
            goto cleanup;
        }
        *modified = bson_iter_bool(&iter);
    }

    if (mongoc_cursor_error(cursor, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_find_with_opts()", error.message);
        goto cleanup;
    }

cleanup:
    bson_destroy(query);
    bson_destroy(query_opts);
    mongoc_cursor_destroy(cursor);
    srpds_data_destroy(pdata, &mdata);
    return err_info;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_mongo_copy(const struct lys_module *mod, sr_datastore_t trg_ds, sr_datastore_t src_ds, void *plg_data)
{
    mongo_data_t mdata;
    mongo_plg_conn_data_t *pdata = (mongo_plg_conn_data_t *)plg_data;
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    bson_t *query = NULL, *query_iter = NULL;
    mongoc_cursor_t *cursor = NULL;

    assert(mod);

    if ((err_info = srpds_data_init(mod, src_ds, 0, 0, 1, pdata, &mdata))) {
        goto cleanup;
    }

    query = BCON_NEW("pipeline", "[",
            "{", "$addFields",
            "{", "returns",
            "{", "$regexMatch",
            "{", "input", "$_id",
            "regex", "^[^2]",
            "options", "s",
            "}",
            "}",
            "}",
            "}",
            "{", "$out",
            "{", "db", BCON_UTF8(srpds_ds2database(trg_ds)),
            "coll", BCON_UTF8(mdata.module_name),
            "}",
            "}", "]");

    cursor = mongoc_collection_aggregate(mdata.module, MONGOC_QUERY_NONE, query, NULL, NULL);

    while (mongoc_cursor_next(cursor, (const bson_t **)&query_iter)) {}
    if (mongoc_cursor_error(cursor, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_aggregate()", error.message);
        goto cleanup;
    }
    srpds_data_destroy(pdata, &mdata);
    if ((err_info = srpds_data_init(mod, trg_ds, 0, 0, 1, pdata, &mdata))) {
        goto cleanup;
    }

    if ((err_info = srpds_set_last_modif_flag(mdata.module, 0))) {
        goto cleanup;
    }

    if (trg_ds == SR_DS_CANDIDATE) {
        /* the modified flag got deleted while copying data */
        if ((err_info = srpds_set_candidate_modified_flag(mdata.module, !(src_ds == SR_DS_RUNNING)))) {
            goto cleanup;
        }
    }

cleanup:
    mongoc_cursor_destroy(cursor);
    bson_destroy(query);
    srpds_data_destroy(pdata, &mdata);
    return err_info;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_mongo_store_prepare(const struct lys_module *mod, sr_datastore_t ds, sr_cid_t cid, uint32_t sid,
        const struct lyd_node *mod_diff, const struct lyd_node *mod_data, void *plg_data)
{
    (void) mod;
    (void) ds;
    (void) cid;
    (void) sid;
    (void) mod_diff;
    (void) mod_data;
    (void) plg_data;

    return NULL;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_mongo_store_commit(const struct lys_module *mod, sr_datastore_t ds, sr_cid_t cid, uint32_t sid,
        const struct lyd_node *mod_diff, const struct lyd_node *mod_data, void *plg_data)
{
    mongo_data_t mdata;
    mongo_plg_conn_data_t *pdata = (mongo_plg_conn_data_t *)plg_data;
    sr_error_info_t *err_info = NULL;
    int modified = 1;

    assert(mod);

    /* for candidate ds learn if modified */
    if (ds == SR_DS_CANDIDATE) {
        if ((err_info = srpds_mongo_candidate_modified(mod, plg_data, &modified))) {
            return err_info;
        }
    }

    /* if not modified, then copy running */
    if (!modified) {
        if ((err_info = srpds_mongo_copy(mod, SR_DS_CANDIDATE, SR_DS_RUNNING, plg_data))) {
            return err_info;
        }
    }

    if ((err_info = srpds_data_init(mod, ds, cid, sid, 1, pdata, &mdata))) {
        goto cleanup;
    }

    /* in case of empty mod_data, just delete everything (do not bother storing) */
    if (!mod_data) {
        /* delete all data */
        if ((err_info = srpds_delete_regex(mdata.module, "^[^012]"))) {
            goto cleanup;
        }
    } else if (mod_diff) {
        if ((err_info = srpds_store_diff(mdata.module, ds, mod_data, mod_diff))) {
            goto cleanup;
        }
    } else {
        /* diff is not always present, in that case store all data */
        if ((err_info = srpds_store_data(mdata.module, mod_data))) {
            goto cleanup;
        }
    }

    /* for last-modif flag, use data collection without cid and sid */
    if (ds == SR_DS_OPERATIONAL) {
        srpds_data_destroy(pdata, &mdata);
        if ((err_info = srpds_data_init(mod, ds, 0, 0, 1, pdata, &mdata))) {
            goto cleanup;
        }
    }

    if ((err_info = srpds_set_last_modif_flag(mdata.module, 0))) {
        goto cleanup;
    }

    if (ds == SR_DS_CANDIDATE) {
        if ((err_info = srpds_set_candidate_modified_flag(mdata.module, 1))) {
            goto cleanup;
        }
    }

cleanup:
    srpds_data_destroy(pdata, &mdata);
    return err_info;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_mongo_init(const struct lys_module *mod, sr_datastore_t ds, void *plg_data)
{
    (void) plg_data;
    (void) mod;
    (void) ds;
    return NULL;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_mongo_conn_init(sr_conn_ctx_t *conn, void **plg_data)
{
    sr_error_info_t *err_info = NULL;
    mongo_plg_conn_data_t *data = NULL;

    (void) conn;

    /* ONE process (conn), ONE thread (mutex), only ONE call to mongoc_init() */
    pthread_mutex_lock(&(plugin_data.lock));
    if (!plugin_data.is_mongoc_initialized) {
        if (atexit(terminate)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_SYS, "atexit()", "");
            goto cleanup;
        }
        mongoc_init();

        /* mongoc is initialized */
        plugin_data.is_mongoc_initialized = 1;
    }
    pthread_mutex_unlock(&(plugin_data.lock));

    data = calloc(1, sizeof *data);
    if (!data) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "calloc()", "");
        goto cleanup;
    }

    /* initialize MongoDB client to connect to the database */
    if ((err_info = srpds_client_init(&(data->pool)))) {
        goto cleanup;
    }

    *plg_data = data;

cleanup:
    return err_info;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
void
srpds_mongo_conn_destroy(sr_conn_ctx_t *conn, void *plg_data)
{
    mongo_plg_conn_data_t *data = (mongo_plg_conn_data_t *)plg_data;

    (void) conn;

    mongoc_client_pool_destroy(data->pool);
    free(data);
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_mongo_install(const struct lys_module *mod, sr_datastore_t ds, const char *owner, const char *group, mode_t perm,
        void *plg_data)
{
    mongo_data_t mdata;
    mongo_plg_conn_data_t *pdata = (mongo_plg_conn_data_t *)plg_data;
    sr_error_info_t *err_info = NULL;
    bson_t *query = NULL;
    char *process_user = NULL, *process_group = NULL;

    assert(mod && perm);

    if ((err_info = srpds_data_init(mod, ds, 0, 0, 0, pdata, &mdata))) {
        goto cleanup;
    }

    if ((err_info = srpds_create_indices(mdata.module))) {
        goto cleanup;
    }

    if (!owner) {
        if ((err_info = srpds_uid2usr(plugin_name, getuid(), &process_user))) {
            goto cleanup;
        }
        owner = process_user;
    }

    if (!group) {
        if ((err_info = srpds_gid2grp(plugin_name, getgid(), &process_group))) {
            goto cleanup;
        }
        group = process_group;
    }

    /* insert owner, group and permissions */
    query = BCON_NEW("_id", "2", "owner", BCON_UTF8(owner), "group", BCON_UTF8(group), "perm",
            BCON_INT32((int32_t)perm));
    if ((err_info = srpds_insert(mdata.module, query))) {
        goto cleanup;
    }

    if ((ds == SR_DS_RUNNING) || (ds == SR_DS_STARTUP) || (ds == SR_DS_FACTORY_DEFAULT)) {
        if ((err_info = srpds_set_last_modif_flag(mdata.module, 0))) {
            goto cleanup;
        }
    } else {
        if ((err_info = srpds_set_last_modif_flag(mdata.module, 1))) {
            goto cleanup;
        }
    }

    if (ds == SR_DS_CANDIDATE) {
        if ((err_info = srpds_set_candidate_modified_flag(mdata.module, 0))) {
            goto cleanup;
        }
    }

cleanup:
    free(process_user);
    free(process_group);
    bson_destroy(query);
    srpds_data_destroy(pdata, &mdata);
    return err_info;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_mongo_access_get(const struct lys_module *mod, sr_datastore_t ds, void *plg_data, char **owner, char **group,
        mode_t *perm)
{
    mongo_data_t mdata;
    mongo_plg_conn_data_t *pdata = (mongo_plg_conn_data_t *)plg_data;
    sr_error_info_t *err_info = NULL;

    assert(mod);

    if ((err_info = srpds_data_init(mod, ds, 0, 0, 1, pdata, &mdata))) {
        goto cleanup;
    }

    if ((err_info = srpds_get_access(mdata.module, owner, group, perm))) {
        goto cleanup;
    }

cleanup:
    srpds_data_destroy(pdata, &mdata);
    return err_info;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_mongo_access_set(const struct lys_module *mod, sr_datastore_t ds, const char *owner, const char *group,
        mode_t perm, void *plg_data)
{
    mongo_data_t mdata;
    mongo_plg_conn_data_t *pdata = (mongo_plg_conn_data_t *)plg_data;
    sr_error_info_t *err_info = NULL;
    bson_t *query_key = NULL, *query = NULL;

    assert(mod);

    if ((err_info = srpds_data_init(mod, ds, 0, 0, 1, pdata, &mdata))) {
        goto cleanup;
    }

    /* _id for owner, group and permissions */
    query_key = BCON_NEW("_id", "2");

    /* set owner */
    if (owner) {
        query = BCON_NEW("$set", "{", "owner", BCON_UTF8(owner), "}");
        if ((err_info = srpds_update(mdata.module, query_key, query, 0))) {
            goto cleanup;
        }
        bson_destroy(query);
    }

    /* set group */
    if (group) {
        query = BCON_NEW("$set", "{", "group", BCON_UTF8(group), "}");
        if ((err_info = srpds_update(mdata.module, query_key, query, 0))) {
            goto cleanup;
        }
        bson_destroy(query);
    }

    /* set permissions */
    if (perm) {
        query = BCON_NEW("$set", "{", "perm", BCON_INT32(perm), "}");
        if ((err_info = srpds_update(mdata.module, query_key, query, 0))) {
            goto cleanup;
        }
    }

cleanup:
    bson_destroy(query_key);
    bson_destroy(query);
    srpds_data_destroy(pdata, &mdata);
    return err_info;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_mongo_access_check(const struct lys_module *mod, sr_datastore_t ds, void *plg_data, int *read, int *write)
{
    mongo_data_t mdata;
    mongo_plg_conn_data_t *pdata = (mongo_plg_conn_data_t *)plg_data;
    sr_error_info_t *err_info = NULL;
    int is_owner, in_group;
    char *username = NULL, *groupname = NULL,
            *owner = NULL, *group = NULL;
    mode_t perm = 0;

    assert(mod);

    if ((err_info = srpds_data_init(mod, ds, 0, 0, 1, pdata, &mdata))) {
        goto cleanup;
    }

    /* learn module access */
    if ((err_info = srpds_get_access(mdata.module, &owner, &group, &perm))) {
        goto cleanup;
    }

    /* learn the current process username */
    if ((err_info = srpds_uid2usr(plugin_name, getuid(), &username))) {
        goto cleanup;
    }

    /* learn the current process groupname */
    if ((err_info = srpds_gid2grp(plugin_name, getgid(), &groupname))) {
        goto cleanup;
    }

    /* check whether the current user is the owner of the module
     * and whether the user is in the same group */
    is_owner = !strcmp(owner ? owner : "", username);
    in_group = !strcmp(group ? group : "", groupname);

    if (read) {
        /* clear read flag */
        *read = 0;

        /* grant read privilege based on ownership */
        if (is_owner && (perm & S_IRUSR)) {
            *read = 1;
        }

        /* grant read privilege based on group */
        if (in_group && (perm & S_IRGRP)) {
            *read = 1;
        }

        /* grant read privilege for others */
        if (!is_owner && !in_group && (perm & S_IROTH)) {
            *read = 1;
        }
    }

    if (write) {
        /* clear write flag */
        *write = 0;

        /* grant write privilege based on ownership */
        if (is_owner && (perm & S_IWUSR)) {
            *write = 1;
        }

        /* grant write privilege based on group */
        if (in_group && (perm & S_IWGRP)) {
            *write = 1;
        }

        /* grant write privilege for others */
        if (!is_owner && !in_group && (perm & S_IWOTH)) {
            *write = 1;
        }
    }

cleanup:
    free(username);
    free(groupname);
    free(owner);
    free(group);
    srpds_data_destroy(pdata, &mdata);
    return err_info;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_mongo_uninstall(const struct lys_module *mod, sr_datastore_t ds, void *plg_data)
{
    mongo_data_t mdata;
    mongo_plg_conn_data_t *pdata = (mongo_plg_conn_data_t *)plg_data;
    sr_error_info_t *err_info = NULL;
    bson_error_t error;

    assert(mod);

    if ((err_info = srpds_data_init(mod, ds, 0, 0, 1, pdata, &mdata))) {
        goto cleanup;
    }

    /* owner, group and permissions are part of the data */
    if (!mongoc_collection_drop_with_opts(mdata.module, NULL, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_drop_with_opts()", error.message);
        goto cleanup;
    }

cleanup:
    srpds_data_destroy(pdata, &mdata);
    return err_info;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_mongo_load(const struct lys_module *mod, sr_datastore_t ds, sr_cid_t cid, uint32_t sid, const char **xpaths,
        uint32_t xpath_count, void *plg_data, struct lyd_node **mod_data)
{
    mongo_data_t mdata;
    mongo_plg_conn_data_t *pdata = (mongo_plg_conn_data_t *)plg_data;
    sr_error_info_t *err_info = NULL;
    bson_t xpath_filter;
    int is_valid = 0;

    assert(mod && mod_data);

    *mod_data = NULL;

    if ((err_info = srpds_data_init(mod, ds, cid, sid, 1, pdata, &mdata))) {
        goto cleanup;
    }

    if ((err_info = srpds_process_load_paths(mod->ctx, xpaths, xpath_count, (ds == SR_DS_OPERATIONAL), &is_valid,
            &xpath_filter))) {
        goto cleanup;
    }

    /* initialize xpath_filter for loading */
    if (!is_valid) {
        bson_init(&xpath_filter);
    }

    if ((err_info = srpds_load_all(mdata.module, mod, ds, &xpath_filter, mod_data))) {
        goto cleanup;
    }

cleanup:
    bson_destroy(&xpath_filter);
    srpds_data_destroy(pdata, &mdata);
    return err_info;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_mongo_last_modif(const struct lys_module *mod, sr_datastore_t ds, void *plg_data, struct timespec *mtime)
{
    mongo_data_t mdata;
    mongo_plg_conn_data_t *pdata = (mongo_plg_conn_data_t *)plg_data;
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    bson_t *query = NULL, *query_opts = NULL, *query_iter = NULL;
    mongoc_cursor_t *cursor = NULL;
    bson_iter_t iter;

    assert(mod && mtime);

    if ((err_info = srpds_data_init(mod, ds, 0, 0, 1, pdata, &mdata))) {
        goto cleanup;
    }

    query = BCON_NEW("_id", BCON_UTF8("0"));
    query_opts = BCON_NEW("projection", "{", "nsec", BCON_BOOL(1), "sec", BCON_BOOL(1), "_id", BCON_BOOL(0), "}");
    cursor = mongoc_collection_find_with_opts(mdata.module, query, query_opts, NULL);

    if (mongoc_cursor_next(cursor, (const bson_t **) &query_iter)) {
        if (!bson_iter_init(&iter, query_iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_init()", "");
            goto cleanup;
        }

        if (bson_iter_next(&iter)) {
            mtime->tv_nsec = bson_iter_int64(&iter);
        }

        if (bson_iter_next(&iter)) {
            mtime->tv_sec = bson_iter_int64(&iter);
        }
    }

    if (mongoc_cursor_error(cursor, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_find_with_opts()", error.message);
        goto cleanup;
    }

cleanup:
    bson_destroy(query);
    bson_destroy(query_opts);
    mongoc_cursor_destroy(cursor);
    srpds_data_destroy(pdata, &mdata);
    return err_info;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_mongo_candidate_reset(const struct lys_module *mod, void *plg_data)
{
    mongo_data_t mdata;
    mongo_plg_conn_data_t *pdata = (mongo_plg_conn_data_t *)plg_data;
    sr_error_info_t *err_info = NULL;

    assert(mod);

    if ((err_info = srpds_data_init(mod, SR_DS_CANDIDATE, 0, 0, 1, pdata, &mdata))) {
        goto cleanup;
    }

    if ((err_info = srpds_delete_regex(mdata.module, "^[^012]"))) {
        goto cleanup;
    }

    if ((err_info = srpds_set_last_modif_flag(mdata.module, 1))) {
        goto cleanup;
    }

    if ((err_info = srpds_set_candidate_modified_flag(mdata.module, 0))) {
        goto cleanup;
    }

cleanup:
    srpds_data_destroy(pdata, &mdata);
    return err_info;
}

const struct srplg_ds_s srpds_mongo = {
    .name = plugin_name,
    .install_cb = srpds_mongo_install,
    .uninstall_cb = srpds_mongo_uninstall,
    .init_cb = srpds_mongo_init,
    .conn_init_cb = srpds_mongo_conn_init,
    .conn_destroy_cb = srpds_mongo_conn_destroy,
    .store_prepare_cb = srpds_mongo_store_prepare,
    .store_commit_cb = srpds_mongo_store_commit,
    .load_cb = srpds_mongo_load,
    .copy_cb = srpds_mongo_copy,
    .candidate_modified_cb = srpds_mongo_candidate_modified,
    .candidate_reset_cb = srpds_mongo_candidate_reset,
    .access_set_cb = srpds_mongo_access_set,
    .access_get_cb = srpds_mongo_access_get,
    .access_check_cb = srpds_mongo_access_check,
    .last_modif_cb = srpds_mongo_last_modif,
    .data_version_cb = NULL,
};
