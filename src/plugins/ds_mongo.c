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
    mongoc_collection_t *module; /* specific collection that is currently being managed (contains data of a specific YANG module) */
    char *module_name; /* allocated module name of the module */
} mongo_data_t;

typedef struct mongo_plg_conn_data_s {
    mongoc_client_pool_t *pool; /* pool of clients that connect to the database so that multithreading is supported, pool is the used pool of clients */
} mongo_plg_conn_data_t;

/* specific data for MongoDB */
typedef struct mongo_plg_data_s {
    int is_mongoc_initialized; /* global variable that checks whether mongoc_init() was called */
    pthread_mutex_t lock; /* mutex */
} mongo_plg_data_t;

mongo_plg_data_t plugin_data = {0};

/* helper structure for storing bson data */
struct mongo_diff_inner_data {
    bson_t **docs;
    uint32_t size;
    uint32_t idx;
};

/* helper structure for storing data to be committed */
struct mongo_diff_data {
    struct mongo_diff_inner_data cre; /* array for storing nodes with create operation */
    struct mongo_diff_inner_data del; /* array for storing nodes with delete operation */
    struct mongo_diff_inner_data del_many; /* array for storing nodes with delete many operation */
    struct mongo_diff_inner_data rep; /* array for storing nodes with replace operation */
    struct mongo_diff_inner_data rep_keys; /* array for storing selectors for replace operation */
};

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
        r = asprintf(collection_name, "%s_%s-%" PRIu32 "-%" PRIu32, sr_get_shm_prefix(), mod_name, cid, sid);
    } else {
        r = asprintf(collection_name, "%s_%s", sr_get_shm_prefix(), mod_name);
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

    uri = mongoc_uri_new("mongodb://" SR_DS_PLG_MONGO_HOST ":" SR_DS_PLG_MONGO_PORT
            "/?authSource=" SR_DS_PLG_MONGO_AUTHSOURCE "&" MONGOC_URI_SOCKETTIMEOUTMS "=3600000&"
            MONGOC_URI_CONNECTTIMEOUTMS "=3600000");
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
    uri = mongoc_uri_new("mongodb://" SR_DS_PLG_MONGO_USERNAME ":" SR_DS_PLG_MONGO_PASSWORD "@" SR_DS_PLG_MONGO_HOST ":" SR_DS_PLG_MONGO_PORT
            "/?authSource=" SR_DS_PLG_MONGO_AUTHSOURCE "&" MONGOC_URI_SOCKETTIMEOUTMS "=3600000&"
            MONGOC_URI_CONNECTTIMEOUTMS "=3600000");
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
    bson_t *doc = NULL, *doc2 = NULL;
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

    doc = BCON_NEW("_id", BCON_UTF8("2"));
    cursor = mongoc_collection_find_with_opts(module, doc, NULL, NULL);

    if (mongoc_cursor_next(cursor, (const bson_t **) &doc2)) {
        if (!bson_iter_init(&iter, doc2)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_init()", "");
            goto cleanup;
        }

        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
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
    bson_destroy(doc);
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
srpds_process_load_paths(struct ly_ctx *ctx, const char **xpaths, uint32_t xpath_cnt, int oper_ds, int *is_valid, bson_t *xpath_filter)
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

    if (oper_ds) {
        /*
         * TODO
         * xpath filtering is unimplemented for MONGO DS operational datastore.
         * /sysrepo:discard-items and metadata (ietf-origin) needs to be explicitly retrieved.
         *
         * So, just fetch all the data until then.
         */
        goto cleanup;
    }

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

/*
 * @brief Load all data (only nodes (/), metadata (4) and attributes (5)) and store them inside the lyd_node structure.
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
srpds_load_all(mongoc_collection_t *module, const struct lys_module *mod, sr_datastore_t ds, bson_t *xpath_filter, struct lyd_node **mod_data)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    const char *path, *name, *module_name, *path_to_node, *value = NULL, *path_no_pred = NULL;
    char **keys = NULL;
    uint32_t *lengths = NULL;
    enum srpds_db_ly_types type;
    int32_t valtype = 0;
    int64_t order = 0;
    int dflt_flag = 0;
    srpds_db_userordered_lists_t uo_lists = {0};
    struct lyd_node **parent_nodes = NULL;
    size_t pnodes_size = 0;

    uint32_t pathlen = 0;
    char *newpath = NULL;

    bson_t *doc2 = NULL, *opts = NULL;
    mongoc_cursor_t *cursor = NULL;
    bson_iter_t iter;

    opts = BCON_NEW("sort", "{", "path_modif", BCON_INT32(1), "}");
    cursor = mongoc_collection_find_with_opts(module, xpath_filter, opts, NULL);

    /*
    *   Loading multiple different sets of data
    *
    *   Load All Datastores
    *   | 1) containers (LYS_CONTAINER)
    *   |    Dataset [ path(_id) | name | type | module_name | path_modif ]
    *   |
    *   | 2) lists (LYS_LIST)
    *   |    Dataset [ path(_id) | name | type | module_name | keys | path_modif ]
    *   |
    *   | 3) leafs and leaf-lists (LYS_LEAF and LYS_LEAFLIST)
    *   |    Dataset [ path(_id) | name | type | module_name | dflt_flag | value | path_modif ]
    *   |
    *   | 4) anydata and anyxml (LYS_ANYDATA and LYS_ANYXML)
    *   |    Dataset [ path(_id) | name | type | module_name | dflt_flag | value | valtype | path_modif ]
    *   |
    *   | 5) user-ordered lists (for state lists prev field is omitted)
    *   |    Dataset [ path(_id) | name | type | module_name | keys | order | path_no_pred | prev | path_modif ]
    *   |
    *   | 6) user-ordered leaf-lists (for state leaf-lists prev field is omitted)
    *   |    Dataset [ path(_id) | name | type | module_name | dflt_flag | value | order | path_no_pred | prev | path_modif ]
    *   |
    *   | 7) opaque nodes
    *   |    Dataset [ path_with_value(_id) | name | type | module_name | value | path_modif ]
    *   |
    *   | 8) metadata
    *   |    Dataset [ path_with_name(_id) | name | type | path_to_node | value | path_modif ]
    *   |
    *   | 9) other metadata (0, 1, 2, #) DO NOT LOAD
    *   |
    *   | module_name = NULL - use parent's module | name - use the module specified by this name
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

    while (mongoc_cursor_next(cursor, (const bson_t **) &doc2)) {
        if (!bson_iter_init(&iter, doc2)) {
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
         * # - maximum load-order for list or leaf-list
         * 2 - owner, group and permissions */
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

        /* get module_name or path_to_node based on type */
        switch (type) {
        case SRPDS_DB_LY_CONTAINER:    /* containers */
        case SRPDS_DB_LY_LIST:         /* lists */
        case SRPDS_DB_LY_TERM:         /* leafs and leaf-lists */
        case SRPDS_DB_LY_ANY:          /* anydata and anyxml */
        case SRPDS_DB_LY_LIST_UO:      /* userordered lists */
        case SRPDS_DB_LY_LEAFLIST_UO:  /* userordered leaf-lists */
        case SRPDS_DB_LY_OPAQUE:       /* opaque nodes */
            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
                goto cleanup;
            }
            module_name = bson_iter_utf8(&iter, NULL);
            if (module_name && !bson_utf8_validate(module_name, strlen(module_name), 0)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_utf8()", "");
                goto cleanup;
            }
            break;
        case SRPDS_DB_LY_META:
            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
                goto cleanup;
            }
            path_to_node = bson_iter_utf8(&iter, NULL);
            if (!bson_utf8_validate(path_to_node, strlen(path_to_node), 0)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_utf8()", "");
                goto cleanup;
            }
            path = path_to_node;
            break;
        default:
            break;
        }

        /* get keys or dflt flag or value based on type */
        switch (type) {
        case SRPDS_DB_LY_LIST:     /* lists */
        case SRPDS_DB_LY_LIST_UO:  /* user-ordered lists */
            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
                goto cleanup;
            }
            value = bson_iter_utf8(&iter, NULL);
            if ((err_info = srpds_parse_keys(plugin_name, value, &keys, &lengths))) {
                goto cleanup;
            }
            break;
        case SRPDS_DB_LY_TERM:         /* leafs and leaf-lists */
        case SRPDS_DB_LY_ANY:          /* anydata and anyxml */
        case SRPDS_DB_LY_LEAFLIST_UO:  /* user-ordered leaf-lists */
            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
                goto cleanup;
            }
            dflt_flag = bson_iter_as_bool(&iter);
            break;
        case SRPDS_DB_LY_OPAQUE:    /* opaque nodes */
        case SRPDS_DB_LY_META:      /* metadata */
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

        /* get value or order based on type */
        switch (type) {
        case SRPDS_DB_LY_TERM:         /* leafs and leaf-lists */
        case SRPDS_DB_LY_ANY:          /* anydata and anyxml */
        case SRPDS_DB_LY_LEAFLIST_UO:  /* user-ordered leaf-lists */
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
        case SRPDS_DB_LY_LIST_UO:  /* user-ordered lists */
            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
                goto cleanup;
            }
            order = bson_iter_int64(&iter);
            break;
        default:
            break;
        }

        /* get valtype or path_no_pred or order based on type */
        switch (type) {
        case SRPDS_DB_LY_ANY:  /* anydata and anyxml */
            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
                goto cleanup;
            }
            valtype = bson_iter_int32(&iter);
            break;
        case SRPDS_DB_LY_LIST_UO:  /* user-ordered lists */
            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
                goto cleanup;
            }
            path_no_pred = bson_iter_utf8(&iter, NULL);
            if (!bson_utf8_validate(path_no_pred, strlen(path_no_pred), 0)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_utf8()", "");
                goto cleanup;
            }
            break;
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

        switch (type) {
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
            break;
        default:
            break;
        }

        /* get proper path to node */
        if (type == SRPDS_DB_LY_OPAQUE) {
            pathlen = strlen(path) - strlen(value);
            newpath = malloc(pathlen);
            if (!newpath) {
                ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "malloc()", "");
                goto cleanup;
            }
            strncpy(newpath, path, pathlen);
            newpath[pathlen - 1] = '\0';
            path = newpath;
        }

        /* add a new node to mod_data */
        if ((err_info = srpds_add_mod_data(plugin_name, mod->ctx, ds, path, name, type, module_name, value, valtype,
                &dflt_flag, (const char **)keys, lengths, order, path_no_pred, &uo_lists, &parent_nodes, &pnodes_size,
                mod_data))) {
            goto cleanup;
        }
        free(keys);
        free(lengths);
        free(newpath);
        keys = NULL;
        lengths = NULL;
        newpath = NULL;
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
    free(lengths);
    free(newpath);
    free(parent_nodes);
    srpds_cleanup_uo_lists(&uo_lists);
    bson_destroy(opts);
    mongoc_cursor_destroy(cursor);
    return err_info;
}

/**
 * @brief Initialize an array of bson documents.
 *
 * @param[out] docs New array of bson documents.
 * @param[out] size New size of the array.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_docs_init(bson_t ***docs, uint32_t *size)
{
    sr_error_info_t *err_info = NULL;
    bson_t **ptr;

    ptr = (bson_t **)calloc(1000, sizeof *ptr);
    if (!ptr) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "calloc()", "");
        return err_info;
    }
    *docs = ptr;
    *size = 1000;

    return err_info;
}

/**
 * @brief Add a bson document to the array.
 *
 * @param[in,out] docs Array of bson documents.
 * @param[in,out] size Size of the array.
 * @param[in,out] index Index of the last bson document in the array.
 * @param[in] doc Document to insert into the array.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_docs_add(bson_t ***docs, uint32_t *size, uint32_t *index, bson_t *doc)
{
    sr_error_info_t *err_info = NULL;
    bson_t **ptr;

    if (*index >= *size) {
        ptr = (bson_t **)realloc(*docs, *size * 2 * sizeof *ptr);
        if (!ptr) {
            ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "realloc()", "");
            return err_info;
        }

        *docs = ptr;
        *size *= 2;
    }

    (*docs)[*index] = doc;
    *index += 1;

    return err_info;
}

/**
 * @brief Free the bson document array.
 *
 * @param[in] docs Array of bson documents.
 */
static void
srpds_docs_destroy(bson_t **docs)
{
    free(docs);
}

/**
 * @brief Initialize a helper structure for storing the contents of a diff inside the database.
 *
 * @param[out] diff_data Helper structure to initialize.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_diff_data_init(struct mongo_diff_data *diff_data)
{
    sr_error_info_t *err_info = NULL;

    diff_data->cre.docs = NULL;
    diff_data->cre.idx = 0;
    diff_data->cre.size = 0;
    diff_data->del.docs = NULL;
    diff_data->del.idx = 0;
    diff_data->del.size = 0;
    diff_data->del_many.docs = NULL;
    diff_data->del_many.idx = 0;
    diff_data->del_many.size = 0;
    diff_data->rep.docs = NULL;
    diff_data->rep.idx = 0;
    diff_data->rep.size = 0;
    diff_data->rep_keys.docs = NULL;
    diff_data->rep_keys.idx = 0;
    diff_data->rep_keys.size = 0;

    if ((err_info = srpds_docs_init(&(diff_data->cre.docs), &(diff_data->cre.size)))) {
        goto cleanup;
    }
    if ((err_info = srpds_docs_init(&(diff_data->del.docs), &(diff_data->del.size)))) {
        goto cleanup;
    }
    if ((err_info = srpds_docs_init(&(diff_data->del_many.docs), &(diff_data->del_many.size)))) {
        goto cleanup;
    }
    if ((err_info = srpds_docs_init(&(diff_data->rep.docs), &(diff_data->rep.size)))) {
        goto cleanup;
    }
    if ((err_info = srpds_docs_init(&(diff_data->rep_keys.docs), &(diff_data->rep_keys.size)))) {
        goto cleanup;
    }

cleanup:
    return err_info;
}

/**
 * @brief Destroy the helper structure for storing the contents of a diff inside the database.
 *
 * @param[in] diff_data Helper structure to destroy.
 */
static void
srpds_diff_data_destroy(struct mongo_diff_data *diff_data)
{
    uint32_t i;

    for (i = 0; i < diff_data->cre.idx; ++i) {
        bson_destroy(diff_data->cre.docs[i]);
    }
    srpds_docs_destroy(diff_data->cre.docs);

    for (i = 0; i < diff_data->del.idx; ++i) {
        bson_destroy(diff_data->del.docs[i]);
    }
    srpds_docs_destroy(diff_data->del.docs);

    for (i = 0; i < diff_data->del_many.idx; ++i) {
        bson_destroy(diff_data->del_many.docs[i]);
    }
    srpds_docs_destroy(diff_data->del_many.docs);

    for (i = 0; i < diff_data->rep.idx; ++i) {
        bson_destroy(diff_data->rep.docs[i]);
    }
    srpds_docs_destroy(diff_data->rep.docs);

    for (i = 0; i < diff_data->rep_keys.idx; ++i) {
        bson_destroy(diff_data->rep_keys.docs[i]);
    }
    srpds_docs_destroy(diff_data->rep_keys.docs);
}

/**
 * @brief Get a bson command to create a container.
 *
 * @param[in] path Path to the node.
 * @param[in] name Name of the node.
 * @param[in] module_name Name of the module.
 * @param[in] path_modif Modified path.
 * @return Command to create a container.
 */
static bson_t *
srpds_container(const char *path, const char *name, const char *module_name, const char *path_modif)
{
    return BCON_NEW("_id", BCON_UTF8(path),
            "name", BCON_UTF8(name),
            "type", BCON_INT32(SRPDS_DB_LY_CONTAINER),
            "module_name", BCON_UTF8(module_name),
            "path_modif", BCON_UTF8(path_modif));
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
 * @return Command to create a list instance.
 */
static bson_t *
srpds_list(const char *path, const char *name, const char *module_name, const char *keys, uint32_t keys_length,
        const char *path_modif)
{
    bson_t *bson_query;

    bson_query = bson_new();
    bson_append_utf8(bson_query, "_id", 3, path, -1);
    bson_append_utf8(bson_query, "name", 4, name, -1);
    bson_append_int32(bson_query, "type", 4, SRPDS_DB_LY_LIST);
    bson_append_utf8(bson_query, "module_name", 11, module_name, -1);
    bson_append_utf8(bson_query, "keys", 4, keys, keys_length);
    bson_append_utf8(bson_query, "path_modif", 10, path_modif, -1);

    return bson_query;
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
 * @return Command to create a term.
 */
static bson_t *
srpds_term(const char *path, const char *name, const char *module_name, int dflt_flag, const char *value,
        const char *path_modif)
{
    return BCON_NEW("_id", BCON_UTF8(path),
            "name", BCON_UTF8(name),
            "type", BCON_INT32(SRPDS_DB_LY_TERM),
            "module_name", BCON_UTF8(module_name),
            "dflt_flag", BCON_BOOL(dflt_flag),
            "value", BCON_UTF8(value),
            "path_modif", BCON_UTF8(path_modif));
}

/**
 * @brief Get a bson command to create an anyxml or anydata node.
 *
 * @param[in] path Path to the node.
 * @param[in] name Name of the node.
 * @param[in] module_name Name of the module.
 * @param[in] dflt_flag Default flag of the node.
 * @param[in] value Value of the node.
 * @param[in] valtype Type of the value (LYD_ANYDATA_XML = 0; LYD_ANYDATA_JSON = 1)
 * @param[in] path_modif Modified path.
 * @return Command to create an anyxml or anydata node.
 */
static bson_t *
srpds_any(const char *path, const char *name, const char *module_name, int dflt_flag, const char *value, int32_t valtype,
        const char *path_modif)
{
    return BCON_NEW("_id", BCON_UTF8(path),
            "name", BCON_UTF8(name),
            "type", BCON_INT32(SRPDS_DB_LY_ANY),
            "module_name", BCON_UTF8(module_name),
            "dflt_flag", BCON_BOOL(dflt_flag),
            "value", BCON_UTF8(value),
            "valtype", BCON_INT32(valtype),
            "path_modif", BCON_UTF8(path_modif));
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
 * @param[in] include_prev Whether to include predicate of the previous node.
 * @param[in] path_modif Modified path.
 * @return Command to create a list instance.
 */
static bson_t *
srpds_list_uo(const char *path, const char *name, const char *module_name, const char *keys, uint32_t keys_length,
        uint64_t order, const char *path_no_pred, const char *prev_pred, int include_prev, const char *path_modif)
{
    bson_t *bson_query;

    bson_query = bson_new();
    bson_append_utf8(bson_query, "_id", 3, path, -1);
    bson_append_utf8(bson_query, "name", 4, name, -1);
    bson_append_int32(bson_query, "type", 4, SRPDS_DB_LY_LIST_UO);
    bson_append_utf8(bson_query, "module_name", 11, module_name, -1);
    bson_append_utf8(bson_query, "keys", 4, keys, keys_length);
    bson_append_int64(bson_query, "order", 5, order);
    bson_append_utf8(bson_query, "path_no_pred", 12, path_no_pred, -1);
    if (include_prev) {
        bson_append_utf8(bson_query, "prev", 4, prev_pred, -1);
    }
    bson_append_utf8(bson_query, "path_modif", 10, path_modif, -1);

    return bson_query;
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
 * @param[in] include_prev Whether to include predicate of the previous node.
 * @param[in] path_modif Modified path.
 * @return Command to create a leaf-list instance.
 */
static bson_t *
srpds_leaflist_uo(const char *path, const char *name, const char *module_name, int dflt_flag, const char *value,
        uint64_t order, const char *path_no_pred, const char *prev_pred, int include_prev, const char *path_modif)
{
    bson_t *bson_query;

    bson_query = bson_new();
    bson_append_utf8(bson_query, "_id", 3, path, -1);
    bson_append_utf8(bson_query, "name", 4, name, -1);
    bson_append_int32(bson_query, "type", 4, SRPDS_DB_LY_LEAFLIST_UO);
    bson_append_utf8(bson_query, "module_name", 11, module_name, -1);
    bson_append_bool(bson_query, "dflt_flag", 9, dflt_flag);
    bson_append_utf8(bson_query, "value", 5, value, -1);
    bson_append_int64(bson_query, "order", 5, order);
    bson_append_utf8(bson_query, "path_no_pred", 12, path_no_pred, -1);
    if (include_prev) {
        bson_append_utf8(bson_query, "prev", 4, prev_pred, -1);
    }
    bson_append_utf8(bson_query, "path_modif", 10, path_modif, -1);

    return bson_query;
}

/**
 * @brief Get a bson command to create an opaque node.
 *
 * @param[in] path Path to the node.
 * @param[in] name Name of the node.
 * @param[in] module_name Name of the module.
 * @param[in] value Value of the node.
 * @param[in] path_modif Modified path.
 * @return Command to create an opaque node.
 */
static bson_t *
srpds_opaque(const char *path, const char *name, const char *module_name, const char *value, const char *path_modif)
{
    return BCON_NEW("_id", BCON_UTF8(path),
            "name", BCON_UTF8(name),
            "type", BCON_INT32(SRPDS_DB_LY_OPAQUE),
            "module_name", BCON_UTF8(module_name),
            "value", BCON_UTF8(value),
            "path_modif", BCON_UTF8(path_modif));
}

/**
 * @brief Get a bson command to create metadata.
 *
 * @param[in] id_path Path to the node with module name and name of the metadata.
 * @param[in] name Name of the metadata.
 * @param[in] path Path to the node.
 * @param[in] value Value of the metadata.
 * @param[in] id_path_modif Modified path with module name and name of the metadata.
 * @return Command to create metadata.
 */
static bson_t *
srpds_meta(const char *id_path, const char *name, const char *path, const char *value, const char *id_path_modif)
{
    return BCON_NEW("_id", BCON_UTF8(id_path),
            "name", BCON_UTF8(name),
            "type", BCON_INT32(SRPDS_DB_LY_META),
            "path_to_node", BCON_UTF8(path),
            "value", BCON_UTF8(value),
            "path_modif", BCON_UTF8(id_path_modif));
}

/**
 * @brief Add a new operation to a bson document array to store later.
 *
 * @param[in] bson_query Bson query (operation) to add.
 * @param[out] inner Inner structure to add the operation to.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_add_operation(bson_t *bson_query, struct mongo_diff_inner_data *inner)
{
    sr_error_info_t *err_info = NULL;

    if (!bson_query) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "Adding operation to a list", "");
        return err_info;
    }
    if ((err_info = srpds_docs_add(&(inner->docs), &(inner->size), &(inner->idx), bson_query))) {
        return err_info;
    }
    return err_info;
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
    bson_t *doc = NULL;

    doc = BCON_NEW("_id", BCON_UTF8(id));
    if (!mongoc_collection_delete_one(module, doc, NULL, NULL, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_delete_one()", error.message);
    }

    bson_destroy(doc);
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
    bson_t *doc = NULL;

    doc = BCON_NEW("_id", "{", "$regex", BCON_UTF8(regex), "$options", "s", "}");
    if (!mongoc_collection_delete_many(module, doc, NULL, NULL, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_delete_many()", error.message);
    }

    bson_destroy(doc);
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
srpds_update_maxord(mongoc_collection_t *module, const char *path_no_pred, uint64_t max_order)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    char *final_path = NULL;
    bson_t *bson_query = NULL, *bson_query_key = NULL;

    /* update only if max_order has been changed
     * aka is different from zero */
    if (max_order) {
        /* update maximum order of the list
         * list's maximum order is stored here */
        if (asprintf(&final_path, "#%s", path_no_pred) == -1) {
            ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
            goto cleanup;
        }

        /* selector for replace command */
        bson_query_key = BCON_NEW("_id", BCON_UTF8(final_path));

        /* replace command */
        bson_query = BCON_NEW("$set", "{", "value", BCON_INT64(max_order), "}");
        if (!mongoc_collection_update_one(module, bson_query_key, bson_query, NULL, NULL, &error)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message);
            goto cleanup;
        }
    }

cleanup:
    free(final_path);
    bson_destroy(bson_query_key);
    bson_destroy(bson_query);
    return err_info;
}

/**
 * @brief Update the maximum order of a list or a leaf-list in the database by deleting the old record and creating a new record.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] path_no_pred Path of a list/leaf-list instance without a predicate.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_set_maxord(mongoc_collection_t *module, const char *path_no_pred)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    bson_t *bson_query = NULL;
    char *final_path = NULL;

    /* set maximum order of the list */
    if (asprintf(&final_path, "#%s", path_no_pred) == -1) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
        goto cleanup;
    }

    /* use case: some elements are inserted, all of them are deleted and another element is
     * inserted -> previous max order has to be deleted and a new one inserted */
    if ((err_info = srpds_delete_id(module, final_path))) {
        goto cleanup;
    }

    /* maximum order starts at 1024, so that a large gap in front of the first element is created
     * to easily insert elements here */
    bson_query = BCON_NEW("_id", BCON_UTF8(final_path), "value", BCON_INT64(SRPDS_DB_UO_ELEMS_GAP_SIZE));
    if (!mongoc_collection_insert_one(module, bson_query, NULL, NULL, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_insert_one()", error.message);
        goto cleanup;
    }

cleanup:
    free(final_path);
    bson_destroy(bson_query);
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
    bson_t *doc = NULL, *doc2 = NULL;
    bson_iter_t iter;
    char *final_path = NULL;

    if (*out_max_order == 0) {
        /* get maximum order of the list
         * list's maximum order is stored here */
        if (asprintf(&final_path, "#%s", path_no_pred) == -1) {
            ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
            goto cleanup;
        }

        doc = BCON_NEW("_id", BCON_UTF8(final_path));
        cursor = mongoc_collection_find_with_opts(module, doc, NULL, NULL);

        if (mongoc_cursor_next(cursor, (const bson_t **) &doc2)) {
            if (!bson_iter_init(&iter, doc2)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_init()", "");
                goto cleanup;
            }

            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
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
    free(final_path);
    bson_destroy(doc);
    mongoc_cursor_destroy(cursor);
    return err_info;
}

/**
 * @brief Get the order of the previous element in a list or a leaf-list from the database.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] nodetype Type of the node (userordered list or leaflist).
 * @param[in] prev_pred Predicate of the previous element.
 * @param[in] path_no_pred Path of a list/leaf-list instance without a predicate.
 * @param[out] order Order of the previous element.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_prev(mongoc_collection_t *module, uint16_t nodetype, const char *prev_pred, const char *path_no_pred, uint64_t *order)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    mongoc_cursor_t *cursor = NULL;
    bson_t *doc = NULL, *doc2 = NULL;
    bson_iter_t iter;
    char *prev_path = NULL;

    /* prepare path of the previous element */
    if (asprintf(&prev_path, "%s%s", path_no_pred, prev_pred) == -1) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
        goto cleanup;
    }

    doc = BCON_NEW("_id", BCON_UTF8(prev_path));
    cursor = mongoc_collection_find_with_opts(module, doc, NULL, NULL);

    if (mongoc_cursor_next(cursor, (const bson_t **) &doc2)) {
        if (!bson_iter_init(&iter, doc2)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_init()", "");
            goto cleanup;
        }

        /* path */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
            goto cleanup;
        }
        /* name */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
            goto cleanup;
        }
        /* type */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
            goto cleanup;
        }
        /* module_name */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
            goto cleanup;
        }
        /* predicate or dflt_flag */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
            goto cleanup;
        }
        /* value */
        if ((nodetype == LYS_LEAFLIST) && !bson_iter_next(&iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
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
    bson_destroy(doc);
    mongoc_cursor_destroy(cursor);
    return err_info;
}

/**
 * @brief Get the order of the next element in a list or a leaf-list from the database.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] nodetype Type of the node (userordered list or leaflist).
 * @param[in] prev_pred Predicate of the next element's previous element.
 * @param[in] path_no_pred Path of a list/leaf-list instance without a predicate.
 * @param[out] order Order of the next element.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_next(mongoc_collection_t *module, uint16_t nodetype, const char *prev_pred, const char *path_no_pred, uint64_t *order)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    mongoc_cursor_t *cursor = NULL;
    bson_t *doc = NULL, *doc2 = NULL;
    bson_iter_t iter;
    char *order_str = NULL;
    uint64_t order_cur = 0, order_min = UINT64_MAX;

    *order = 0;

    doc = BCON_NEW("prev", BCON_UTF8(prev_pred), "path_no_pred", BCON_UTF8(path_no_pred));
    cursor = mongoc_collection_find_with_opts(module, doc, NULL, NULL);

    if (mongoc_cursor_next(cursor, (const bson_t **) &doc2)) {
        if (!bson_iter_init(&iter, doc2)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_init()", "");
            goto cleanup;
        }

        /* path */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
            goto cleanup;
        }
        /* name */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
            goto cleanup;
        }
        /* type */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
            goto cleanup;
        }
        /* module_name */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
            goto cleanup;
        }
        /* predicate or dflt_flag */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
            goto cleanup;
        }
        /* value */
        if ((nodetype == LYS_LEAFLIST) && !bson_iter_next(&iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
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
    bson_destroy(doc);
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
srpds_shift_uo_list_recursively(mongoc_collection_t *module, const char *path_no_pred, uint64_t next_elem_order, uint64_t *max_order)
{
    sr_error_info_t *err_info = 0;
    int found = 0;
    bson_error_t error;
    mongoc_cursor_t *cursor = NULL;
    bson_t *doc = NULL, *doc2 = NULL, *bson_query_key = NULL,
            *bson_query_rep = NULL;
    bson_iter_t iter;
    const char *path = NULL;

    if ((err_info = srpds_get_maxord(module, path_no_pred, max_order))) {
        goto cleanup;
    }

    if (*max_order < next_elem_order) {
        *max_order = next_elem_order;
    }

    /* find the next element */
    doc = BCON_NEW("order", BCON_INT64(next_elem_order), "path_no_pred", BCON_UTF8(path_no_pred));
    cursor = mongoc_collection_find_with_opts(module, doc, NULL, NULL);

    if (mongoc_cursor_next(cursor, (const bson_t **) &doc2)) {
        found = 1;

        if (!bson_iter_init(&iter, doc2)) {
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

    if (found) {
        /* An element with such order has been found, shift all elements
         * after this element */
        if ((err_info = srpds_shift_uo_list_recursively(module, path_no_pred, next_elem_order + 1, max_order))) {
            goto cleanup;
        }

        /* change order of this element,
         * selector for replace command */
        bson_query_key = BCON_NEW("_id", BCON_UTF8(path));

        /* replace command */
        bson_query_rep = BCON_NEW("$set", "{", "order", BCON_INT64(next_elem_order + 1), "}");
        if (!mongoc_collection_update_one(module, bson_query_key, bson_query_rep, NULL, NULL, &error)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message);
            goto cleanup;
        }
    }

cleanup:
    bson_destroy(doc);
    mongoc_cursor_destroy(cursor);
    bson_destroy(bson_query_key);
    bson_destroy(bson_query_rep);
    return err_info;
}

/**
 * @brief Insert a user-ordered element into a list or a leaf-list in the database.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] node Current data node in the diff.
 * @param[in] module_name Name of the module the node belongs to.
 * @param[in] path Path of the user-ordered element.
 * @param[in] path_no_pred Path without a predicate of the user-ordered element.
 * @param[in] path_modif Modified path with ' ' instead of '/' for loading purposes.
 * @param[in] predicate Predicate of the user-ordered element.
 * @param[in] value Value of the user-ordered element.
 * @param[in] prev Value of the node before this node.
 * @param[in] prev_pred Value of the node before this node in predicate.
 * @param[out] max_order Changed maximum order.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_create_uo_op(mongoc_collection_t *module, const struct lyd_node *node, const char *module_name, const char *path,
        const char *path_no_pred, const char *path_modif, const char *predicate, const char *value, const char *prev,
        const char *prev_pred, uint64_t *max_order)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    bson_t *bson_query_uo_rep = NULL, *bson_query_uo_key = NULL,
            *bson_query_uo = NULL;
    uint64_t prev_order = 0, next_order = 0, order;
    char *keys = NULL;
    uint32_t keys_length = 0;

    /* there is a previous element */
    if (strcmp(prev, "")) {
        /* load previous,
         * get order of the previous element */
        if ((err_info = srpds_load_prev(module, node->schema->nodetype, prev_pred, path_no_pred, &prev_order))) {
            goto cleanup;
        }

        /* load next
         * get order of the next element */
        if ((err_info = srpds_load_next(module, node->schema->nodetype, prev_pred, path_no_pred, &next_order))) {
            goto cleanup;
        }

        if (!next_order) {
            /* get max order for lists and leaf-lists */
            if ((err_info = srpds_get_maxord(module, path_no_pred, max_order))) {
                goto cleanup;
            }

            srpds_inc_maxord(max_order);

            /* calculate order */
            order = *max_order;
        } else if (next_order - prev_order == 1) {
            /* shift the next elements by one recursively */
            if ((err_info = srpds_shift_uo_list_recursively(module, path_no_pred, next_order, max_order))) {
                goto cleanup;
            }

            /* calculate order */
            order = next_order;

            /* add new prev element to the next element,
             * selector for replace command */
            bson_query_uo_key = BCON_NEW("prev", BCON_UTF8(prev_pred), "path_no_pred", BCON_UTF8(path_no_pred));

            /* replace command */
            bson_query_uo_rep = BCON_NEW("$set", "{", "prev", BCON_UTF8(predicate), "}");
            if (!mongoc_collection_update_one(module, bson_query_uo_key, bson_query_uo_rep, NULL, NULL, &error)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message);
                goto cleanup;
            }
        } else {
            /* calculate order */
            order = (uint64_t)(prev_order + (next_order - prev_order) / 2);

            /* add new prev element to the next element,
             * selector for replace command */
            bson_query_uo_key = BCON_NEW("prev", BCON_UTF8(prev_pred), "path_no_pred", BCON_UTF8(path_no_pred));

            /* replace command */
            bson_query_uo_rep = BCON_NEW("$set", "{", "prev", BCON_UTF8(predicate), "}");
            if (!mongoc_collection_update_one(module, bson_query_uo_key, bson_query_uo_rep, NULL, NULL, &error)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message);
                goto cleanup;
            }
        }
        /* there is no previous element */
    } else {
        /* load next */
        if ((err_info = srpds_load_next(module, node->schema->nodetype, prev_pred, path_no_pred, &next_order))) {
            goto cleanup;
        }

        if (!next_order) {
            /* "no previous element and no next element" might
             * mean two things - either the max order was not
             * inserted yet or it was but all elements of the
             * list were deleted */

            /* set max order for lists and leaf-lists */
            if ((err_info = srpds_set_maxord(module, path_no_pred))) {
                goto cleanup;
            }

            /* calculate order */
            order = SRPDS_DB_UO_ELEMS_GAP_SIZE;
        } else if (next_order == 1) {
            /* shift next elements by one recursively */
            if ((err_info = srpds_shift_uo_list_recursively(module, path_no_pred, next_order, max_order))) {
                goto cleanup;
            }

            /* calculate order */
            order = next_order;

            /* add new prev element to the next element,
             * selector for replace command */
            bson_query_uo_key = BCON_NEW("prev", BCON_UTF8(prev_pred), "path_no_pred", BCON_UTF8(path_no_pred));

            /* replace command */
            bson_query_uo_rep = BCON_NEW("$set", "{", "prev", BCON_UTF8(predicate), "}");
            if (!mongoc_collection_update_one(module, bson_query_uo_key, bson_query_uo_rep, NULL, NULL, &error)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message);
                goto cleanup;
            }
        } else {
            /* calculate order */
            order = (uint64_t)(next_order / 2);

            /* add new prev element to the next element,
             * selector for replace command */
            bson_query_uo_key = BCON_NEW("prev", BCON_UTF8(prev_pred), "path_no_pred", BCON_UTF8(path_no_pred));

            /* replace command */
            bson_query_uo_rep = BCON_NEW("$set", "{", "prev", BCON_UTF8(predicate), "}");
            if (!mongoc_collection_update_one(module, bson_query_uo_key, bson_query_uo_rep, NULL, NULL, &error)) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message);
                goto cleanup;
            }
        }
    }

    /* insert an element */
    switch (node->schema->nodetype) {
    case LYS_LIST:
        if ((err_info = srpds_concat_key_values(plugin_name, node, &keys, &keys_length))) {
            goto cleanup;
        }
        bson_query_uo = srpds_list_uo(path, node->schema->name, module_name, keys, keys_length, order, path_no_pred,
                prev_pred, 1, path_modif);
        break;
    case LYS_LEAFLIST:
        bson_query_uo = srpds_leaflist_uo(path, node->schema->name, module_name, 0, value, order, path_no_pred,
                prev_pred, 1, path_modif);
        break;
    }
    if (!mongoc_collection_insert_one(module, bson_query_uo, NULL, NULL, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_insert_one()", error.message);
        goto cleanup;
    }

cleanup:
    free(keys);
    bson_destroy(bson_query_uo);
    bson_destroy(bson_query_uo_key);
    bson_destroy(bson_query_uo_rep);
    return err_info;
}

/**
 * @brief Delete a user-ordered element from a list or a leaf-list in the database.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] path Path of the user-ordered element.
 * @param[in] path_no_pred Path without a predicate of the user-ordered element.
 * @param[in] predicate Predicate of the user-ordered element.
 * @param[in] orig_value_pred Predicate of a previous element.
 * @param[in] is_del_many Whether a delete many operation should be executed.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_delete_uo_op(mongoc_collection_t *module, const char *path, const char *path_no_pred, const char *predicate,
        const char *orig_value_pred, int is_del_many)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    bson_t *bson_query_uo_rep = NULL, *bson_query_uo_key = NULL;
    char *escaped = NULL, *regex = NULL;

    /* add new prev element to the next element,
     * selector for replace command */
    bson_query_uo_key = BCON_NEW("prev", BCON_UTF8(predicate), "path_no_pred", BCON_UTF8(path_no_pred));

    /* change the next element's prev */
    bson_query_uo_rep = BCON_NEW("$set", "{", "prev", BCON_UTF8(orig_value_pred), "}");
    if (!mongoc_collection_update_one(module, bson_query_uo_key, bson_query_uo_rep, NULL, NULL, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message);
        goto cleanup;
    }

    if (is_del_many) {
        /* delete many command for userordered lists and leaf-lists to delete a whole subtree */
        if ((err_info = srpds_escape_string(plugin_name, path, '\\', &escaped))) {
            goto cleanup;
        }
        if (asprintf(&regex, "^%s", escaped) == -1) {
            ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
            goto cleanup;
        }
        if ((err_info = srpds_delete_regex(module, regex))) {
            goto cleanup;
        }
    } else {
        /* delete command for userordered lists and leaf-lists */
        if ((err_info = srpds_delete_id(module, path))) {
            goto cleanup;
        }
    }

cleanup:
    bson_destroy(bson_query_uo_key);
    bson_destroy(bson_query_uo_rep);
    free(escaped);
    free(regex);
    return err_info;
}

/**
 * @brief Change the default flag of a node.
 *
 * @param[in] path Path to a data node.
 * @param[in] diff_data Helper structure for storing diff operations.
 * @param[in] add_or_remove Whether the default flag should be added or removed.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_change_default_flag(const char *path, struct mongo_diff_data *diff_data, int add_or_remove)
{
    sr_error_info_t *err_info = NULL;

    /* selector for replace command */
    if ((err_info = srpds_add_operation(BCON_NEW("_id", BCON_UTF8(path)), &(diff_data->rep_keys)))) {
        goto cleanup;
    }

    /* replace command */
    if ((err_info = srpds_add_operation(BCON_NEW("$set", "{", "dflt_flag", BCON_BOOL(add_or_remove), "}"), &(diff_data->rep)))) {
        goto cleanup;
    }

cleanup:
    return err_info;
}

/**
 * @brief Change the default flag of a node to the opposite.
 *
 * @param[in] path Path to a data node.
 * @param[in] node Data node.
 * @param[in] diff_data Helper structure for storing diff operations.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_update_default_flag(const char *path, const struct lyd_node *node, struct mongo_diff_data *diff_data)
{
    sr_error_info_t *err_info = NULL;

    if (!strcmp(lyd_get_meta_value(lyd_find_meta(node->meta, NULL, "yang:orig-default")), "true")) {
        if (!(node->flags & LYD_DEFAULT)) {
            err_info = srpds_change_default_flag(path, diff_data, 0);
        }
    } else {
        if (node->flags & LYD_DEFAULT) {
            err_info = srpds_change_default_flag(path, diff_data, 1);
        }
    }

    return err_info;
}

/**
 * @brief Change the default flag of a node to true.
 *
 * @param[in] path Path to a data node.
 * @param[in] node Data node.
 * @param[out] diff_data Helper structure for storing diff operations.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_create_op_default_flag(const char *path, const struct lyd_node *node, struct mongo_diff_data *diff_data)
{
    sr_error_info_t *err_info = NULL;

    if (!(node->schema->nodetype & LYD_NODE_TERM)) {
        goto cleanup;
    }

    if (node->flags & LYD_DEFAULT) {
        err_info = srpds_change_default_flag(path, diff_data, 1);
    }

cleanup:
    return err_info;
}

/**
 * @brief Change the default flag of a node to the opposite.
 *
 * @param[in] path Path to a data node.
 * @param[in] node Data node.
 * @param[out] diff_data Helper structure for storing diff operations.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_none_op_default_flag(const char *path, const struct lyd_node *node, struct mongo_diff_data *diff_data)
{
    sr_error_info_t *err_info = NULL;

    if (!(node->schema->nodetype & LYD_NODE_TERM)) {
        goto cleanup;
    }

    err_info = srpds_update_default_flag(path, node, diff_data);

cleanup:
    return err_info;
}

/**
 * @brief Change the default flag of a node to the opposite.
 *
 * @param[in] path Path to a data node.
 * @param[in] node Data node.
 * @param[out] diff_data Helper structure for storing diff operations.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_replace_op_default_flag(const char *path, const struct lyd_node *node, struct mongo_diff_data *diff_data)
{
    sr_error_info_t *err_info = NULL;

    /* for userordered leaflists replace operation can never change the default flag */
    if (!(node->schema->nodetype & LYD_NODE_TERM) ||
            ((node->schema->nodetype & LYS_LEAFLIST) && lysc_is_userordered(node->schema))) {
        goto cleanup;
    }

    err_info = srpds_update_default_flag(path, node, diff_data);

cleanup:
    return err_info;
}

/**
 * @brief Diff operation create.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] node Current data node in the diff.
 * @param[in] module_name Name of the module the node belongs to.
 * @param[in] path Path of the data node.
 * @param[in] path_no_pred Path without the predicate of the data node.
 * @param[in] predicate Predicate of the data node.
 * @param[in] path_modif Modified path with ' ' instead of '/' for loading purposes.
 * @param[in] value Value of the node.
 * @param[in] prev Value of the node before this node.
 * @param[in] prev_pred Value of the node before this node in predicate.
 * @param[in] valtype Type of the node's value (XML or JSON).
 * @param[in,out] max_order Maximum order of the list or leaf-list.
 * @param[out] diff_data Helper structure for storing diff operations.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_create_op(mongoc_collection_t *module, const struct lyd_node *node, const char *module_name, const char *path, const char *path_no_pred,
        const char *predicate, const char *path_modif, const char *value, const char *prev, const char *prev_pred, int32_t valtype,
        uint64_t *max_order, struct mongo_diff_data *diff_data)
{
    sr_error_info_t *err_info = NULL;
    bson_t *bson_query = NULL;
    char *keys = NULL;
    uint32_t keys_length = 0;

    if (lysc_is_userordered(node->schema)) {
        /* insert a new element into the user-ordered list */
        if ((err_info = srpds_create_uo_op(module, node, module_name, path, path_no_pred, path_modif, predicate, value, prev, prev_pred, max_order))) {
            goto cleanup;
        }
    } else {
        switch (node->schema->nodetype) {
        case LYS_CONTAINER:
            bson_query = srpds_container(path, node->schema->name, module_name, path_modif);
            break;
        case LYS_LIST:
            if ((err_info = srpds_concat_key_values(plugin_name, node, &keys, &keys_length))) {
                goto cleanup;
            }
            bson_query = srpds_list(path, node->schema->name, module_name, keys, keys_length, path_modif);
            break;
        case LYS_LEAF:
        case LYS_LEAFLIST:
            bson_query = srpds_term(path, node->schema->name, module_name, 0, value, path_modif);
            break;
        case LYS_ANYDATA:
        case LYS_ANYXML:
            bson_query = srpds_any(path, node->schema->name, module_name, 0, value, valtype, path_modif);
            break;
        }

        if ((err_info = srpds_add_operation(bson_query, &(diff_data->cre)))) {
            goto cleanup;
        }
    }

    /* default nodes */
    if ((err_info = srpds_create_op_default_flag(path, node, diff_data))) {
        goto cleanup;
    }

cleanup:
    free(keys);
    if (err_info) {
        bson_destroy(bson_query);
    }
    return err_info;
}

/**
 * @brief Diff operation delete.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] node Current data node in the diff.
 * @param[in] path Path of the data node.
 * @param[in] path_no_pred Path without the predicate of the data node.
 * @param[in] predicate Predicate of the data node.
 * @param[in] orig_prev_pred Original value of the previous node in predicate.
 * @param[out] diff_data Helper structure for storing diff operations.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_delete_op(mongoc_collection_t *module, const struct lyd_node *node, const char *path, const char *path_no_pred,
        const char *predicate, const char *orig_prev_pred, struct mongo_diff_data *diff_data)
{
    sr_error_info_t *err_info = NULL;
    char *escaped = NULL, *regex = NULL;

    if (lysc_is_userordered(node->schema)) {
        /* delete an element from the user-ordered list */
        if ((err_info = srpds_delete_uo_op(module, path, path_no_pred, predicate, orig_prev_pred, 1))) {
            goto cleanup;
        }
    } else {
        /* delete a whole subtree (you have to do this even if you have no children since you can have metadata) */
        if ((err_info = srpds_escape_string(plugin_name, path, '\\', &escaped))) {
            goto cleanup;
        }
        if (asprintf(&regex, "^%s", escaped) == -1) {
            ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
            goto cleanup;
        }
        if ((err_info = srpds_add_operation(BCON_NEW("_id", "{", "$regex", BCON_UTF8(regex), "$options", "s", "}"),
                &(diff_data->del_many)))) {
            goto cleanup;
        }
    }

cleanup:
    free(escaped);
    free(regex);
    return err_info;
}

/**
 * @brief Diff operation replace.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] node Current data node in the diff.
 * @param[in] module_name Name of the module the node belongs to.
 * @param[in] path Path of the data node.
 * @param[in] path_no_pred Path without the predicate of the data node.
 * @param[in] path_modif Modified path with ' ' instead of '/' for loading purposes.
 * @param[in] predicate Predicate of the data node.
 * @param[in] value Value of the node.
 * @param[in] prev Value of the node before this node.
 * @param[in] prev_pred Value of the node before this node in predicate.
 * @param[in] orig_prev_pred Original value of the node in predicate.
 * @param[in,out] max_order Maximum order of the list or leaf-list.
 * @param[out] diff_data Helper structure for storing diff operations.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_replace_op(mongoc_collection_t *module, const struct lyd_node *node, const char *module_name, const char *path, const char *path_no_pred,
        const char *path_modif, const char *predicate, const char *value, const char *prev, const char *prev_pred, const char *orig_prev_pred,
        uint64_t *max_order, struct mongo_diff_data *diff_data)
{
    sr_error_info_t *err_info = NULL;

    if (lysc_is_userordered(node->schema)) {
        /* note: replace can be executed more efficiently by only calling
            * mongo_collection_update_one() instead of delete and then create,
            * however the rest of the code in srpds_delete_uo_op and srpds_create_uo_op
            * has to be executed nevertheless */

        /* delete an element from the user-ordered list */
        if ((err_info = srpds_delete_uo_op(module, path, path_no_pred, predicate, orig_prev_pred, 0))) {
            goto cleanup;
        }

        /* insert a new element into the user-ordered list */
        if ((err_info = srpds_create_uo_op(module, node, module_name, path, path_no_pred, path_modif, predicate, value, prev, prev_pred, max_order))) {
            goto cleanup;
        }
    } else {
        /* selector for replace command */
        if ((err_info = srpds_add_operation(BCON_NEW("_id", BCON_UTF8(path)), &(diff_data->rep_keys)))) {
            goto cleanup;
        }

        /* replace command */
        if ((err_info = srpds_add_operation(BCON_NEW("$set", "{", "value", BCON_UTF8(value), "}"), &(diff_data->rep)))) {
            goto cleanup;
        }
    }

    /* default nodes */
    if ((err_info = srpds_replace_op_default_flag(path, node, diff_data))) {
        goto cleanup;
    }

cleanup:
    return err_info;
}

/**
 * @brief Add new metadata to store in the database.
 *
 * @param[in] meta Metadata to store.
 * @param[in] path Path to the node with metadata.
 * @param[in] path_modif Modified path.
 * @param[out] diff_data Structure to store the operation in.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_add_meta(struct lyd_meta *meta, const char *path, const char *path_modif, struct mongo_diff_data *diff_data)
{
    sr_error_info_t *err_info = NULL;
    const char *meta_value;
    char *path_with_name = NULL, *path_modif_with_name = NULL, *meta_name = NULL;
    bson_t *bson_query = NULL;

    while (meta) {
        meta_value = lyd_get_meta_value(meta);

        /* skip yang: and sysrepo: metadata, this is libyang and sysrepo specific data */
        if (strcmp(meta->annotation->module->name, "yang") && strcmp(meta->annotation->module->name, "sysrepo")) {
            /* concatenate meta name with module name */
            if (asprintf(&meta_name, "%s:%s", meta->annotation->module->name, meta->name) == -1) {
                ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
                goto cleanup;
            }

            /* create unique path for new metadata */
            if (asprintf(&path_with_name, "%s#%s", path, meta_name) == -1) {
                ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
                goto cleanup;
            }

            /* create modified unique path for loading */
            if (asprintf(&path_modif_with_name, "%s#%s", path_modif, meta_name) == -1) {
                ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
                goto cleanup;
            }

            /* create new metadata */
            bson_query = srpds_meta(path_with_name, meta_name, path, meta_value, path_modif_with_name);

            if ((err_info = srpds_add_operation(bson_query, &(diff_data->cre)))) {
                goto cleanup;
            }

            free(meta_name);
            meta_name = NULL;
            free(path_with_name);
            path_with_name = NULL;
            free(path_modif_with_name);
            path_modif_with_name = NULL;
        }

        meta = meta->next;
    }

cleanup:
    free(meta_name);
    free(path_with_name);
    free(path_modif_with_name);
    if (err_info) {
        bson_destroy(bson_query);
    }
    return err_info;
}

/**
 * @brief Load state data subtree (only for state data).
 *
 * @param[in] set Set of data nodes which need to be stored.
 * @param[in] node Data subtree.
 * @param[out] diff_data Helper structure for storing diff operations.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_state_recursively(const struct ly_set *set, const struct lyd_node *node, struct mongo_diff_data *diff_data)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *sibling = node;
    struct lyd_node *child = NULL;
    char *path = NULL, *path_no_pred = NULL, *path_modif = NULL;
    const char *module_name = NULL, *value = NULL;
    char *any_value = NULL;
    int32_t valtype;
    bson_t *bson_query = NULL;
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

        /* node's values */
        if ((err_info = srpds_get_values(plugin_name, sibling, &value, NULL, NULL, NULL, NULL,
                &any_value, &valtype))) {
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
            bson_query = srpds_container(path, sibling->schema->name, module_name, path_modif);
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

            bson_query = srpds_list_uo(path, sibling->schema->name, module_name, keys, keys_length, order, path_no_pred,
                    NULL, 0, path_modif);
            free(keys);
            keys = NULL;
            keys_length = 0;
            order++;
            break;
        case LYS_LEAF:
            bson_query = srpds_term(path, sibling->schema->name, module_name, sibling->flags & LYD_DEFAULT, value,
                    path_modif);
            break;
        case LYS_LEAFLIST:  /* state leaf-lists are always userordered */
            free(path);
            path = NULL;

            /* create unique path (duplicates can be present in state data) */
            if (asprintf(&path, "%s[%" PRIu64 "]", path_no_pred, order) == -1) {
                ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
                goto cleanup;
            }
            bson_query = srpds_leaflist_uo(path, sibling->schema->name, module_name, sibling->flags & LYD_DEFAULT,
                    value, order, path_no_pred, NULL, 0, path_modif);
            order++;
            break;
        case LYS_ANYDATA:
        case LYS_ANYXML:
            bson_query = srpds_any(path, sibling->schema->name, module_name, sibling->flags & LYD_DEFAULT, value,
                    valtype, path_modif);
            break;
        default:
            break;
        }

        /* create new node */
        if ((err_info = srpds_add_operation(bson_query, &(diff_data->cre)))) {
            goto cleanup;
        }

        /* create new metadata */
        if ((err_info = srpds_add_meta(sibling->meta, path, path_modif, diff_data))) {
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
        free(any_value);
        any_value = NULL;

        if ((child = lyd_child_no_keys(sibling))) {
            if ((err_info = srpds_load_state_recursively(NULL, child, diff_data))) {
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
    if (err_info) {
        bson_destroy(bson_query);
    }
    return err_info;
}

/**
 * @brief Store the whole subtree using @p sibling inside a helper structure with info from mod_data.
 *
 * @param[in] mod_data Module data tree to store.
 * @param[in] node Subtree from diff to use.
 * @param[out] diff_data Helper structure for storing diff operations.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_use_tree2store(const struct lyd_node *mod_data, const struct lyd_node *node, struct mongo_diff_data *diff_data)
{
    sr_error_info_t *err_info = NULL;
    char *escaped = NULL, *regex = NULL, *path_no_pred = NULL;
    bson_t *del_query = NULL;
    struct ly_set *set = NULL;
    LY_ERR lerr;

    path_no_pred = lyd_path(node, LYD_PATH_STD_NO_LAST_PRED, NULL, 0);
    if (!path_no_pred) {
        ERRINFO(&err_info, plugin_name, SR_ERR_LY, "lyd_path()", "");
        goto cleanup;
    }

    if ((err_info = srpds_escape_string(plugin_name, path_no_pred, '\\', &escaped))) {
        goto cleanup;
    }

    if (asprintf(&regex, "^%s", escaped) == -1) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
        goto cleanup;
    }
    free(escaped);
    escaped = NULL;

    /* delete the whole subtree */
    del_query = BCON_NEW("_id", "{", "$regex", BCON_UTF8(regex), "$options", "s", "}");
    if ((err_info = srpds_add_operation(del_query, &(diff_data->del_many)))) {
        goto cleanup;
    }
    free(regex);
    regex = NULL;

    /* we NEED to store a deleted subtree (could be a list or a leaf-list instance with siblings which we just deleted) */
    /* state data have to be stored from mod_data */
    /* metadata of state data are always stored */
    /* find all data of state list/leaf-list or opaque nodes */
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
                if ((err_info = srpds_load_state_recursively(set, set->dnodes[0], diff_data))) {
                    goto cleanup;
                }
            }

            ly_set_free(set, NULL);
            set = NULL;
        }
    }

cleanup:
    free(path_no_pred);
    free(escaped);
    free(regex);
    ly_set_free(set, NULL);
    if (err_info) {
        bson_destroy(del_query);
    }
    return err_info;
}

static sr_error_info_t *srpds_load_diff_recursively(mongoc_collection_t *module, sr_datastore_t ds,
        const struct lyd_node *mod_data, const struct lyd_node *node, char parent_op, struct mongo_diff_data *diff_data);

/**
 * @brief Store the node @p sibling inside a helper structure with info from diff.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] ds Datastore in use.
 * @param[in] mod_data Whole module data tree.
 * @param[in] sibling Current data node in the diff.
 * @param[in] this_op Operation on this node.
 * @param[in, out] max_order Max order for userordered lists and leaf-lists.
 * @param[out] diff_data Helper structure for storing diff operations.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_use_diff2store(mongoc_collection_t *module, sr_datastore_t ds, const struct lyd_node *mod_data,
        const struct lyd_node *sibling, char this_op, uint64_t *max_order, struct mongo_diff_data *diff_data)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *child = NULL, *match = NULL;
    char *path = NULL, *path_no_pred = NULL, *path_modif = NULL;
    const char *module_name = NULL;
    const char *value = NULL, *prev = NULL, *orig_prev = NULL;
    char *prev_pred = NULL, *orig_prev_pred = NULL, *any_value = NULL;
    int32_t valtype;
    bson_t *del_query = NULL;
    char *tmp = NULL, *regex = NULL;

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

    /* node's values */
    if ((err_info = srpds_get_values(plugin_name, sibling, &value, &prev, &orig_prev, &prev_pred, &orig_prev_pred,
            &any_value, &valtype))) {
        goto cleanup;
    }

    /* get module name */
    if ((sibling->parent == NULL) || strcmp(sibling->schema->module->name, sibling->parent->schema->module->name)) {
        module_name = sibling->schema->module->name;
    } else {
        module_name = NULL;
    }

    /* operation */
    switch (this_op) {
    case 'n':
        /* default nodes */
        if ((err_info = srpds_none_op_default_flag(path, sibling, diff_data))) {
            goto cleanup;
        }
        break;
    case 'c':
        if ((err_info = srpds_create_op(module, sibling, module_name, path, path_no_pred,
                srpds_get_predicate(path, path_no_pred), path_modif, value, prev, prev_pred, valtype, max_order,
                diff_data))) {
            goto cleanup;
        }
        break;
    case 'd':
        if ((err_info = srpds_delete_op(module, sibling, path, path_no_pred, srpds_get_predicate(path, path_no_pred),
                orig_prev_pred, diff_data))) {
            goto cleanup;
        }
        break;
    case 'r':
        if ((err_info = srpds_replace_op(module, sibling, module_name, path, path_no_pred, path_modif,
                srpds_get_predicate(path, path_no_pred), value, prev, prev_pred, orig_prev_pred, max_order,
                diff_data))) {
            goto cleanup;
        }
        break;
    default:
        ERRINFO(&err_info, plugin_name, SR_ERR_UNSUPPORTED, "Operation for a node", "Unsupported operation");
        goto cleanup;
    }

    /* reset the max_order if the next sibling
     * is from a different list or if the next sibling does not exist */
    if (lysc_is_userordered(sibling->schema) && ((sibling->next &&
            (sibling->schema->name != sibling->next->schema->name)) || !(sibling->next))) {
        /* update max order for lists and leaf-lists */
        if ((err_info = srpds_update_maxord(module, path_no_pred, *max_order))) {
            goto cleanup;
        }
        *max_order = 0;
    }

    /* metadata are not always included in diff
     * delete any related to this node in the database,
     * find them in mod_data and store them (best-effort) */
    /* if delete operation: do not delete metadata or store them,
     * all node's metadata and descendants are deleted in srpds_delete_op() */
    /* for now store metadata using diff only in oper ds as it is an expensive operation */
    if ((ds == SR_DS_OPERATIONAL) && (this_op != 'd')) {
        /* If the node has to be created, then there is nothing to delete in the database */
        if (this_op != 'c') {
            if ((err_info = srpds_escape_string(plugin_name, path, '\\', &tmp))) {
                goto cleanup;
            }

            /* this regex only deletes node's metadata and not the whole subtree because of # (specific for metadata) */
            if (asprintf(&regex, "^%s\\#", tmp) == -1) {
                ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
                goto cleanup;
            }

            /* delete all metadata connected to the node */
            del_query = BCON_NEW("_id", "{", "$regex", BCON_UTF8(regex), "$options", "s", "}");
            if ((err_info = srpds_add_operation(del_query, &(diff_data->del_many)))) {
                goto cleanup;
            }
        }

        /* find the node in the mod_data to read metadata from */
        if ((err_info = srpds_find_node(plugin_name, sibling, mod_data, &match))) {
            goto cleanup;
        }

        /* create new metadata */
        if ((err_info = srpds_add_meta(match->meta, path, path_modif, diff_data))) {
            goto cleanup;
        }
    }

    /* free memory early before further recursion */
    free(path);
    path = NULL;
    free(path_no_pred);
    path_no_pred = NULL;
    free(path_modif);
    path_modif = NULL;
    free(tmp);
    tmp = NULL;
    free(regex);
    regex = NULL;
    srpds_cleanup_values(sibling, prev, orig_prev, &prev_pred, &orig_prev_pred, &any_value);

    /* we do not care about children that were already deleted */
    if ((this_op != 'd') && (child = lyd_child_no_keys(sibling))) {
        if ((err_info = srpds_load_diff_recursively(module, ds, mod_data, child, this_op, diff_data))) {
            goto cleanup;
        }
    }

cleanup:
    free(path);
    free(path_no_pred);
    free(path_modif);
    free(tmp);
    free(regex);
    srpds_cleanup_values(sibling, prev, orig_prev, &prev_pred, &orig_prev_pred, &any_value);
    if (err_info) {
        bson_destroy(del_query);
    }
    return err_info;
}

/**
 * @brief Handle an opaque node.
 *
 * @param[in] node Opaque node.
 * @param[in] op Operation to perform.
 * @param[out] diff_data Helper structure for storing diff operations.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_handle_opaque_node(const struct lyd_node *node, char op, struct mongo_diff_data *diff_data)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node_opaq *opaque = NULL;
    char *path = NULL, *path_modif = NULL, *discard_items_path = NULL,
            *escaped = NULL, *regex = NULL;
    const char *module_name = NULL, *value = NULL;
    bson_t *bson_query = NULL;
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
            ERRINFO(&err_info, plugin_name, SR_ERR_NOT_FOUND, "", "Operation for opaque node was not found in attributes.");
            goto cleanup;
        }
    }

    switch (op) {
    case 'd':
        /* delete only one instance (attributes are not stored and opaque nodes are only top-level discard-items) */
        if ((err_info = srpds_add_operation(BCON_NEW("_id", BCON_UTF8(discard_items_path)),
                &(diff_data->del)))) {
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
        bson_query = srpds_opaque(discard_items_path, opaque->name.name, module_name, value, path_modif);
        if ((err_info = srpds_add_operation(bson_query, &(diff_data->cre)))) {
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
    free(escaped);
    free(regex);
    if (err_info) {
        bson_destroy(bson_query);
    }
    return err_info;
}

/**
 * @brief Load the whole diff and store the operations inside a helper structure.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] ds Datastore in use.
 * @param[in] mod_data Module data tree to store.
 * @param[in] node Current data node in the diff.
 * @param[in] parent_op Operation on the node's parent.
 * @param[out] diff_data Helper structure for storing diff operations.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_diff_recursively(mongoc_collection_t *module, sr_datastore_t ds, const struct lyd_node *mod_data,
        const struct lyd_node *node, char parent_op, struct mongo_diff_data *diff_data)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *sibling = node;
    struct lyd_meta *meta_op;
    char this_op = 0;
    uint64_t max_order = 0;
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
            if ((err_info = srpds_handle_opaque_node(sibling, 0, diff_data))) {
                goto cleanup;
            }
        } else if (!(sibling->schema->flags & LYS_CONFIG_W)) {
            /* only delete and store a state subtree if it was not stored before */
            if (previous_schema != sibling->schema) {
                if ((err_info = srpds_use_tree2store(mod_data, sibling, diff_data))) {
                    goto cleanup;
                }
            }
            previous_schema = sibling->schema;
        } else {
            if ((err_info = srpds_use_diff2store(module, ds, mod_data, sibling, this_op, &max_order, diff_data))) {
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
srpds_store_diff(mongoc_collection_t *module, sr_datastore_t ds, const struct lyd_node *mod_data, const struct lyd_node *mod_diff)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    struct mongo_diff_data diff_data;
    uint32_t i;
    mongoc_bulk_operation_t *bulk = NULL;
    bson_t *opts = NULL, reply;

    bson_init(&reply);

    if ((err_info = srpds_diff_data_init(&diff_data))) {
        goto cleanup;
    }

    if ((err_info = srpds_load_diff_recursively(module, ds, mod_data, mod_diff, 0, &diff_data))) {
        goto cleanup;
    }

    opts = BCON_NEW("ordered", BCON_BOOL(0));
    bulk = mongoc_collection_create_bulk_operation_with_opts(module, opts);

    for (i = 0; i < diff_data.del.idx; ++i) {
        if (!mongoc_bulk_operation_remove_one_with_opts(bulk, (const bson_t *)(diff_data.del.docs)[i], NULL, &error)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_bulk_operation_remove_one_with_opts()",
                    error.message);
            goto cleanup;
        }
    }

    for (i = 0; i < diff_data.del_many.idx; ++i) {
        if (!mongoc_bulk_operation_remove_many_with_opts(bulk, (const bson_t *)(diff_data.del_many.docs)[i], NULL,
                &error)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_bulk_operation_remove_many_with_opts()",
                    error.message);
            goto cleanup;
        }
    }

    /* order of operations matters... first: nodes have to be created in order for default flags to be updated later */
    for (i = 0; i < diff_data.cre.idx; ++i) {
        if (!mongoc_bulk_operation_insert_with_opts(bulk, (const bson_t *)(diff_data.cre.docs)[i], NULL, &error)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_bulk_operation_insert_with_opts()",
                    error.message);
            goto cleanup;
        }
    }

    for (i = 0; i < diff_data.rep.idx; ++i) {
        if (!mongoc_bulk_operation_update_one_with_opts(bulk, (const bson_t *)(diff_data.rep_keys.docs)[i],
                (const bson_t *)(diff_data.rep.docs)[i], NULL, &error)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_bulk_operation_update_one_with_opts()",
                    error.message);
            goto cleanup;
        }
    }

    if (diff_data.cre.idx || diff_data.rep.idx || diff_data.del.idx || diff_data.del_many.idx) {
        if (!mongoc_bulk_operation_execute(bulk, &reply, &error)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_bulk_operation_execute()", error.message);
            goto cleanup;
        }
    }

cleanup:
    srpds_diff_data_destroy(&diff_data);
    mongoc_bulk_operation_destroy(bulk);
    bson_destroy(opts);
    bson_destroy(&reply);
    return err_info;
}

/**
 * @brief Load the whole data tree (if there is no diff).
 *
 * @param[in] mod_data Whole data tree.
 * @param[out] diff_data Helper structure for storing diff operations.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_data_recursively(const struct lyd_node *mod_data, struct mongo_diff_data *diff_data)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *sibling = mod_data;
    struct lyd_node *child = NULL;
    char *path = NULL, *path_no_pred = NULL, *path_modif = NULL;
    const char *value, *module_name, *prev = NULL, *orig_prev = NULL;
    char *prev_pred = NULL, *orig_prev_pred = NULL, *any_value = NULL;
    bson_t *bson_query = NULL;
    int32_t valtype = 0;
    char *keys = NULL;
    uint32_t keys_length = 0;
    uint64_t state_order = 1, uo_order = 1024;

    while (sibling) {
        /* store opaque nodes separately */
        if (!sibling->schema) {
            if ((err_info = srpds_handle_opaque_node(sibling, 'c', diff_data))) {
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

        /* get values */
        if ((err_info = srpds_get_values(plugin_name, sibling, &value, &prev, &orig_prev, &prev_pred,
                &orig_prev_pred, &any_value, &valtype))) {
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
            bson_query = srpds_container(path, sibling->schema->name, module_name, path_modif);
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

                bson_query = srpds_list_uo(path, sibling->schema->name, module_name, keys, keys_length, state_order,
                        path_no_pred, NULL, 0, path_modif);
                ++state_order;
            } else if (lysc_is_userordered(sibling->schema)) {
                /* userordered lists */
                bson_query = srpds_list_uo(path, sibling->schema->name, module_name, keys, keys_length, uo_order,
                        path_no_pred, prev_pred, 1, path_modif);
                uo_order += 1024;
            } else {
                /* lists */
                bson_query = srpds_list(path, sibling->schema->name, module_name, keys, keys_length, path_modif);
            }
            free(keys);
            keys = NULL;
            keys_length = 0;
            break;
        case LYS_LEAF:
            bson_query = srpds_term(path, sibling->schema->name, module_name, sibling->flags & LYD_DEFAULT, value,
                    path_modif);
            break;
        case LYS_LEAFLIST:
            if (!(sibling->schema->flags & LYS_CONFIG_W)) {
                /* state leaf-lists */
                free(path);
                path = NULL;

                /* create unique path (duplicates can be present in state data) */
                if (asprintf(&path, "%s[%" PRIu64 "]", path_no_pred, state_order) == -1) {
                    ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
                    goto cleanup;
                }

                bson_query = srpds_leaflist_uo(path, sibling->schema->name, module_name, sibling->flags & LYD_DEFAULT,
                        value, state_order, path_no_pred, NULL, 0, path_modif);
                ++state_order;
            } else if (lysc_is_userordered(sibling->schema)) {
                /* userordered leaf-lists */
                bson_query = srpds_leaflist_uo(path, sibling->schema->name, module_name, sibling->flags & LYD_DEFAULT,
                        value, uo_order, path_no_pred, prev_pred, 1, path_modif);
                uo_order += 1024;
            } else {
                /* leaf-lists */
                bson_query = srpds_term(path, sibling->schema->name, module_name, sibling->flags & LYD_DEFAULT, value,
                        path_modif);
            }
            break;
        case LYS_ANYDATA:
        case LYS_ANYXML:
            bson_query = srpds_any(path, sibling->schema->name, module_name, sibling->flags & LYD_DEFAULT, value,
                    valtype, path_modif);
            break;
        }

        /* create new node */
        if ((err_info = srpds_add_operation(bson_query, &(diff_data->cre)))) {
            goto cleanup;
        }

        /* create new metadata */
        if ((err_info = srpds_add_meta(sibling->meta, path, path_modif, diff_data))) {
            goto cleanup;
        }

        /* reset the orders if the next sibling
            * is from a different list or if the next sibling does not exist */
        if (lysc_is_userordered(sibling->schema) && ((sibling->next &&
                (sibling->schema->name != sibling->next->schema->name)) || !(sibling->next))) {
            state_order = 1;
            uo_order = 1024;
        }

        if ((child = lyd_child_no_keys(sibling))) {
            if ((err_info = srpds_load_data_recursively(child, diff_data))) {
                goto cleanup;
            }
        }

        free(path);
        path = NULL;
        free(path_no_pred);
        path_no_pred = NULL;
        free(path_modif);
        path_modif = NULL;
        srpds_cleanup_values(sibling, prev, orig_prev, &prev_pred, &orig_prev_pred, &any_value);

        sibling = sibling->next;
    }

cleanup:
    free(path);
    free(path_no_pred);
    free(path_modif);
    srpds_cleanup_values(sibling, prev, orig_prev, &prev_pred, &orig_prev_pred, &any_value);
    free(keys);
    if (err_info) {
        bson_destroy(bson_query);
    }
    return err_info;
}

/**
 * @brief Store the whole data tree in the database (only for operational).
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
    struct mongo_diff_data diff_data;

    if ((err_info = srpds_diff_data_init(&diff_data))) {
        goto cleanup;
    }

    if (mod_data && (err_info = srpds_load_data_recursively(mod_data, &diff_data))) {
        goto cleanup;
    }

    /* delete all data */
    if ((err_info = srpds_delete_regex(module, "^[^012]"))) {
        goto cleanup;
    }

    /* create all data and metadata and attributes */
    if (diff_data.cre.idx) {
        if (!mongoc_collection_insert_many(module, (const bson_t **) diff_data.cre.docs,
                diff_data.cre.idx, NULL, NULL, &error)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_insert_many()", error.message);
            goto cleanup;
        }
    }

cleanup:
    srpds_diff_data_destroy(&diff_data);
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
    bson_error_t error;
    bson_t *doc = NULL, *update = NULL;
    struct timespec spec = {0};

    if (!reset) {
        clock_gettime(CLOCK_REALTIME, &spec);
    }
    doc = BCON_NEW("_id", BCON_UTF8("0"));
    update = BCON_NEW("$set", "{", "sec", BCON_INT64((int64_t)(spec.tv_sec)), "nsec", BCON_INT64((int64_t)(spec.tv_nsec)), "}");
    if (!mongoc_collection_update_one(module, doc, update, NULL, NULL, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message);
        goto cleanup;
    }

cleanup:
    bson_destroy(doc);
    bson_destroy(update);
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
    bson_error_t error;
    bson_t *doc = NULL, *update = NULL;

    doc = BCON_NEW("_id", BCON_UTF8("1"));
    update = BCON_NEW("$set", "{", "modified", BCON_BOOL(modified), "}");
    if (!mongoc_collection_update_one(module, doc, update, NULL, NULL, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message);
        goto cleanup;
    }

cleanup:
    bson_destroy(doc);
    bson_destroy(update);
    return err_info;
}

/**
 * @brief Create last-modif flag.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] spec Time of the last modification.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_insert_last_modif_flag(mongoc_collection_t *module, struct timespec *spec)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    bson_t *doc = NULL;

    doc = BCON_NEW("_id", BCON_UTF8("0"), "sec", BCON_INT64(spec->tv_sec), "nsec", BCON_INT64(spec->tv_nsec));
    if (!mongoc_collection_insert_one(module, doc, NULL, NULL, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_insert_one()", error.message);
        goto cleanup;
    }

cleanup:
    bson_destroy(doc);
    return err_info;
}

/**
 * @brief Create candidate-modified flag.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] modified Whether candidate datastore is modified.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_insert_candidate_modified_flag(mongoc_collection_t *module, int modified)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    bson_t *doc = NULL;

    doc = BCON_NEW("_id", BCON_UTF8("1"), "modified", BCON_BOOL(modified));
    if (!mongoc_collection_insert_one(module, doc, NULL, NULL, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_insert_one()", error.message);
        goto cleanup;
    }

cleanup:
    bson_destroy(doc);
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
    bson_t *doc = NULL, *doc2 = NULL;
    mongoc_cursor_t *cursor = NULL;
    bson_iter_t iter;

    assert(mod && modified);

    if ((err_info = srpds_data_init(mod, SR_DS_CANDIDATE, 0, 0, 1, pdata, &mdata))) {
        goto cleanup;
    }

    doc = BCON_NEW("_id", BCON_UTF8("1"));
    cursor = mongoc_collection_find_with_opts(mdata.module, doc, NULL, NULL);

    if (mongoc_cursor_next(cursor, (const bson_t **) &doc2)) {
        if (!bson_iter_init(&iter, doc2)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_init()", "");
            goto cleanup;
        }

        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
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
    bson_destroy(doc);
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
    bson_t *command = NULL, *doc = NULL;
    mongoc_cursor_t *cursor = NULL;

    assert(mod);

    if ((err_info = srpds_data_init(mod, src_ds, 0, 0, 1, pdata, &mdata))) {
        goto cleanup;
    }

    command = BCON_NEW("pipeline", "[",
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

    cursor = mongoc_collection_aggregate(mdata.module, MONGOC_QUERY_NONE, command, NULL, NULL);

    while (mongoc_cursor_next(cursor, (const bson_t **)&doc)) {}
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
        if ((err_info = srpds_insert_candidate_modified_flag(mdata.module, !(src_ds == SR_DS_RUNNING)))) {
            goto cleanup;
        }
    }

cleanup:
    mongoc_cursor_destroy(cursor);
    bson_destroy(command);
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
srpds_mongo_install(const struct lys_module *mod, sr_datastore_t ds, const char *owner, const char *group, mode_t perm, void *plg_data)
{
    mongo_data_t mdata;
    mongo_plg_conn_data_t *pdata = (mongo_plg_conn_data_t *)plg_data;
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    uint32_t i, idx_cnt = 3;
    bson_t *bson_query = NULL, *bson_index_keys[idx_cnt];
    mongoc_index_model_t *im[idx_cnt];
    char *process_user = NULL, *process_group = NULL;
    struct timespec spec = {0};

    assert(mod && perm);

    if ((err_info = srpds_data_init(mod, ds, 0, 0, 0, pdata, &mdata))) {
        goto cleanup;
    }

    /* create a compound index on prev and path for load_next(),
     * compound index on order and path_no_pred for srpds_shift_uo_list_recursively()
     * and index on path_modif for quicker loading */
    bson_index_keys[0] = BCON_NEW("prev", BCON_INT32(1), "path_no_pred", BCON_INT32(1));
    bson_index_keys[1] = BCON_NEW("order", BCON_INT32(1), "path_no_pred", BCON_INT32(1));
    bson_index_keys[2] = BCON_NEW("path_modif", BCON_INT32(1));
    for (i = 0; i < idx_cnt; ++i) {
        im[i] = mongoc_index_model_new(bson_index_keys[i], NULL /* opts */);
    }
    if (!mongoc_collection_create_indexes_with_opts(mdata.module, im, idx_cnt, NULL /* opts */, NULL /* reply */, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_create_indexes_with_opts",
                error.message);
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
    bson_query = BCON_NEW("_id", "2", "owner", BCON_UTF8(owner), "group", BCON_UTF8(group), "perm", BCON_INT32((int32_t)perm));
    if (!mongoc_collection_insert_one(mdata.module, bson_query, NULL, NULL, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_insert_one()", error.message);
        goto cleanup;
    }

    if ((ds == SR_DS_RUNNING) || (ds == SR_DS_STARTUP) || (ds == SR_DS_FACTORY_DEFAULT)) {
        clock_gettime(CLOCK_REALTIME, &spec);
        if ((err_info = srpds_insert_last_modif_flag(mdata.module, &spec))) {
            goto cleanup;
        }
    } else {
        if ((err_info = srpds_insert_last_modif_flag(mdata.module, &spec))) {
            goto cleanup;
        }
    }

    if (ds == SR_DS_CANDIDATE) {
        if ((err_info = srpds_insert_candidate_modified_flag(mdata.module, 0))) {
            goto cleanup;
        }
    }

cleanup:
    free(process_user);
    free(process_group);
    for (i = 0; i < idx_cnt; ++i) {
        mongoc_index_model_destroy(im[i]);
        bson_destroy(bson_index_keys[i]);
    }
    bson_destroy(bson_query);
    srpds_data_destroy(pdata, &mdata);
    return err_info;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_mongo_access_get(const struct lys_module *mod, sr_datastore_t ds, void *plg_data, char **owner, char **group, mode_t *perm)
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
srpds_mongo_access_set(const struct lys_module *mod, sr_datastore_t ds, const char *owner, const char *group, mode_t perm, void *plg_data)
{
    mongo_data_t mdata;
    mongo_plg_conn_data_t *pdata = (mongo_plg_conn_data_t *)plg_data;
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    bson_t *bson_query_key = NULL, *bson_query = NULL;

    assert(mod);

    if ((err_info = srpds_data_init(mod, ds, 0, 0, 1, pdata, &mdata))) {
        goto cleanup;
    }

    /* _id for owner, group and permissions */
    bson_query_key = BCON_NEW("_id", "2");

    /* set owner */
    if (owner) {
        bson_query = BCON_NEW("$set", "{", "owner", BCON_UTF8(owner), "}");
        if (!mongoc_collection_update_one(mdata.module, bson_query_key, bson_query, NULL, NULL, &error)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message);
            goto cleanup;
        }
        bson_destroy(bson_query);
    }

    /* set group */
    if (group) {
        bson_query = BCON_NEW("$set", "{", "group", BCON_UTF8(group), "}");
        if (!mongoc_collection_update_one(mdata.module, bson_query_key, bson_query, NULL, NULL, &error)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message);
            goto cleanup;
        }
        bson_destroy(bson_query);
    }

    /* set permissions */
    if (perm) {
        bson_query = BCON_NEW("$set", "{", "perm", BCON_INT32(perm), "}");
        if (!mongoc_collection_update_one(mdata.module, bson_query_key, bson_query, NULL, NULL, &error)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message);
            goto cleanup;
        }
    }

cleanup:
    bson_destroy(bson_query_key);
    bson_destroy(bson_query);
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

    if ((err_info = srpds_process_load_paths(mod->ctx, xpaths, xpath_count, (ds == SR_DS_OPERATIONAL), &is_valid, &xpath_filter))) {
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
    bson_t *doc = NULL;
    bson_t *doc2 = NULL;
    mongoc_cursor_t *cursor = NULL;
    bson_iter_t iter;

    assert(mod && mtime);

    if ((err_info = srpds_data_init(mod, ds, 0, 0, 1, pdata, &mdata))) {
        goto cleanup;
    }

    doc = BCON_NEW("_id", BCON_UTF8("0"));
    cursor = mongoc_collection_find_with_opts(mdata.module, doc, NULL, NULL);

    if (mongoc_cursor_next(cursor, (const bson_t **) &doc2)) {
        if (!bson_iter_init(&iter, doc2)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_init()", "");
            goto cleanup;
        }

        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "");
            goto cleanup;
        }

        if (bson_iter_next(&iter)) {
            mtime->tv_sec = bson_iter_int64(&iter);
        }

        if (bson_iter_next(&iter)) {
            mtime->tv_nsec = bson_iter_int64(&iter);
        }
    }

    if (mongoc_cursor_error(cursor, &error)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "mongoc_collection_find_with_opts()", error.message);
        goto cleanup;
    }

cleanup:
    bson_destroy(doc);
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
    .oper_store_require_diff = 0,
};
