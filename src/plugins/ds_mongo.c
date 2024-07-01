/**
 * @file ds_mongo.c
 * @author Ondrej Kusnirik <Ondrej.Kusnirik@cesnet.cz>
 * @brief internal MongoDB datastore plugin
 *
 * @copyright
 * Copyright (c) 2021 - 2024 Deutsche Telekom AG.
 * Copyright (c) 2021 - 2024 CESNET, z.s.p.o.
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
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <bson/bson.h>
#include <libyang/libyang.h>
#include <mongoc/mongoc.h>

#include "compat.h"
#include "config.h"
#include "plugins_datastore.h"
#include "sysrepo.h"

#define plugin_name "MONGO DS"

#define ERRINFO(err, type, func, message) srplg_log_errinfo(err, plugin_name, NULL, type, func " failed on %d in %s [%s].", __LINE__, __FILE__, message);

#define MONGO_LIST_KEY_LEN_BYTES 2 /* MongoDB stores the length of a list key in two bytes */
#define MONGO_LIST_KEY_LEN_BITS 7 /* MongoDB uses only 7 bits in a byte to store the length of a list key */
#define MONGO_LIST_KEY_GET_LEN(first_byte, second_byte) ((uint32_t)(first_byte) << MONGO_LIST_KEY_LEN_BITS) | second_byte /* get length of a list key */
#define MONGO_LIST_KEY_IS_END(first_byte, second_byte) (second_byte != '\0') || (first_byte != '\0')

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
    struct mongo_diff_inner_data rep; /* array for storing nodes with replace operation */
    struct mongo_diff_inner_data rep_keys; /* array for storing selectors for replace operation */
};

typedef struct mongo_userordered_data_s {
    struct lyd_node *ptr;
    int64_t order;
} mongo_userordered_data_t;

typedef struct mongo_userordered_list_s {
    char *name;
    size_t size;
    mongo_userordered_data_t *data;
} mongo_userordered_list_t;

typedef struct mongo_userordered_lists_s {
    size_t size;
    mongo_userordered_list_t *lists;
} mongo_userordered_lists_t;

enum srpds_mongo_ly_types {
    MONGO_LY_NONE = 0,      /* none */
    MONGO_LY_CONTAINER,     /* container */
    MONGO_LY_LIST,          /* list */
    MONGO_LY_TERM,          /* leaf or leaf-list */
    MONGO_LY_ANY,           /* anydata or anyxml */
    MONGO_LY_LIST_UO,       /* user-ordered list */
    MONGO_LY_LEAFLIST_UO    /* user-ordered leaf-list */
};

static void
terminate(void)
{
    mongoc_cleanup();
}

static int
srpds_uo_elem_comp(const void *a, const void *b)
{
    return ((mongo_userordered_data_t *)a)->order - ((mongo_userordered_data_t *)b)->order;
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
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_client_command_simple()", error.message)
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
        ERRINFO(&err_info, SR_ERR_UNAUTHORIZED, "Authentication",
                "Please create a client in MongoDB with username and password provided during compilation")
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
 * @param[in] installed Whether module was already installed.
 * @param[in] pdata Plugin connection data.
 * @param[out] mdata Module data.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_data_init(const struct lys_module *mod, sr_datastore_t ds, int installed, mongo_plg_conn_data_t *pdata, mongo_data_t *mdata)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    char *shm_prefix = NULL;

    mdata->client = mongoc_client_pool_pop(pdata->pool);
    mdata->datastore = mongoc_client_get_database(mdata->client, srpds_ds2database(ds));

    /* get the module name */
    shm_prefix = getenv("SYSREPO_SHM_PREFIX");
    if (asprintf(&(mdata->module_name), "%s_%s", shm_prefix ? shm_prefix : "", mod->name) == -1) {
        ERRINFO(&err_info, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno))
        goto cleanup;
    }

    /* create or get the module from the database */
    if (installed) {
        mdata->module = mongoc_client_get_collection(mdata->client, srpds_ds2database(ds), mdata->module_name);
    } else {
        mdata->module = mongoc_database_create_collection(mdata->datastore, mdata->module_name, NULL, &error);
        if (!mdata->module) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_database_create_collection()", error.message)
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

    doc = BCON_NEW("_id", BCON_UTF8("4"));
    cursor = mongoc_collection_find_with_opts(module, doc, NULL, NULL);

    if (mongoc_cursor_next(cursor, (const bson_t **) &doc2)) {
        if (!bson_iter_init(&iter, doc2)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_init()", "")
            goto cleanup;
        }

        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
            goto cleanup;
        }

        if (bson_iter_next(&iter) && owner) {
            str = bson_iter_utf8(&iter, NULL);
            if (!bson_utf8_validate(str, strlen(str), 0)) {
                ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_utf8()", "")
                goto cleanup;
            }
            *owner = strdup(str);
            if (!*owner) {
                ERRINFO(&err_info, SR_ERR_NO_MEMORY, "strdup()", strerror(errno))
                goto cleanup;
            }
        }

        if (bson_iter_next(&iter) && group) {
            str = bson_iter_utf8(&iter, NULL);
            if (!bson_utf8_validate(str, strlen(str), 0)) {
                ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_utf8()", "")
                goto cleanup;
            }
            *group = strdup(str);
            if (!*group) {
                ERRINFO(&err_info, SR_ERR_NO_MEMORY, "strdup()", strerror(errno))
                goto cleanup;
            }
        }

        if (bson_iter_next(&iter) && perm) {
            *perm = bson_iter_int32(&iter);
        }
    }

    if (mongoc_cursor_error(cursor, &error)) {
        ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_find_with_opts()", error.message)
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
 * @brief Get the name of the current process user.
 *
 * @param[in] uid Process user ID.
 * @param[out] username Username.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_uid2usr(uid_t uid, char **username)
{
    sr_error_info_t *err_info = NULL;
    int r;
    struct passwd pwd, *pwd_p;
    char *buf = NULL, *mem;
    ssize_t buflen = 0;

    assert(username);

    do {
        if (!buflen) {
            // learn suitable buffer size
            buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
            if (buflen == -1) {
                buflen = 2048;
            }
        } else {
            // enlarge buffer
            buflen += 2048;
        }

        // allocate some buffer
        mem = realloc(buf, buflen);
        if (!mem) {
            ERRINFO(&err_info, SR_ERR_NO_MEMORY, "realloc()", "")
            goto cleanup;
        }
        buf = mem;

        // UID -> user
        r = getpwuid_r(uid, &pwd, buf, buflen, &pwd_p);
    } while (r == ERANGE);

    if (r) {
        ERRINFO(&err_info, SR_ERR_INTERNAL, "Retrieving UID passwd entry", strerror(r))
        goto cleanup;
    } else if (!pwd_p) {
        ERRINFO(&err_info, SR_ERR_NOT_FOUND, "Retrieving UID passwd entry (No such UID)", "")
        goto cleanup;
    }

    *username = strdup(pwd.pw_name);
    if (!*username) {
        ERRINFO(&err_info, SR_ERR_NO_MEMORY, "strdup()", strerror(errno))
        goto cleanup;
    }

cleanup:
    free(buf);
    return err_info;
}

/**
 * @brief Get the name of the current process group.
 *
 * @param[in] gid Process group ID.
 * @param[out] group Groupname.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_gid2grp(gid_t gid, char **group)
{
    sr_error_info_t *err_info = NULL;
    int r;
    struct group grp, *grp_p;
    char *buf = NULL, *mem;
    ssize_t buflen = 0;

    assert(group);

    do {
        if (!buflen) {
            // learn suitable buffer size
            buflen = sysconf(_SC_GETGR_R_SIZE_MAX);
            if (buflen == -1) {
                buflen = 2048;
            }
        } else {
            // enlarge buffer
            buflen += 2048;
        }

        // allocate some buffer
        mem = realloc(buf, buflen);
        if (!mem) {
            ERRINFO(&err_info, SR_ERR_NO_MEMORY, "realloc()", "")
            goto cleanup;
        }
        buf = mem;

        // GID -> group
        r = getgrgid_r(gid, &grp, buf, buflen, &grp_p);
    } while (r == ERANGE);

    if (r) {
        ERRINFO(&err_info, SR_ERR_INTERNAL, "Retrieving GID grp entry", strerror(r))
        goto cleanup;
    } else if (!grp_p) {
        ERRINFO(&err_info, SR_ERR_NOT_FOUND, "Retrieving GID grp entry (No such GID)", "")
        goto cleanup;
    }

    // assign group
    *group = strdup(grp.gr_name);
    if (!*group) {
        ERRINFO(&err_info, SR_ERR_NO_MEMORY, "strdup()", strerror(errno))
        goto cleanup;
    }

cleanup:
    free(buf);
    return err_info;
}

/**
 * @brief Get path, predicate and path without the predicate of a data node.
 *
 * @param[in] node Given data node.
 * @param[out] predicate Predicate of the data node.
 * @param[out] standard Path of the data node. Should be freed.
 * @param[out] no_predicate Path without the predicate of the data node. Should be freed.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_get_predicate(const struct lyd_node *node, const char **predicate, char **standard, char **no_predicate)
{
    sr_error_info_t *err_info = NULL;

    *standard = lyd_path(node, LYD_PATH_STD, NULL, 0);
    if (!*standard) {
        ERRINFO(&err_info, SR_ERR_LY, "lyd_path()", "")
        return err_info;
    }
    *no_predicate = lyd_path(node, LYD_PATH_STD_NO_LAST_PRED, NULL, 0);
    if (!*no_predicate) {
        ERRINFO(&err_info, SR_ERR_LY, "lyd_path()", "")
        return err_info;
    }
    *predicate = *standard + strlen(*no_predicate);

    return err_info;
}

/**
 * @brief Iterates through @p path in the direction @p direction ,
 *      finds '/' and returns a pointer to the '/'.
 *
 * @param[in] path Path ending with NULL.
 * @param[in] direction Direction in which to go through @p path .
 * 1 = from start to end. -1 = from end to start.
 * @return Pointer to the first occurence of '/' in @p path .
 */
static char *
srpds_path_token(const char *path, int direction)
{
    int open_single_quote = 0, open_double_quote = 0;

    if (direction == -1) {
        path = path + strlen(path) - 1;
    }

    while (1) {
        switch (path[0]) {
        case '\'':
            if (open_single_quote) {
                open_single_quote = 0;
            }
            /* XPath allows nesting single quotes inside double quotes */
            else if (!open_double_quote) {
                open_single_quote = 1;
            }
            break;
        case '"':
            if (open_double_quote) {
                open_double_quote = 0;
            }
            /* XPath allows nesting double quotes inside single quotes */
            else if (!open_single_quote) {
                open_double_quote = 1;
            }
            break;
        case '/':
            /* return only if we are not inside of a string */
            if (!open_single_quote && !open_double_quote) {
                return (char *)path;
            }
            break;
        case '\0':
            return NULL;
        }
        path += direction;
    }

    return NULL;
}

/**
 * @brief Change all '/' in the path for ' ', except in the predicate.
 *
 * @param[in] path Path.
 * @param[out] out Allocated result with ' '.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_get_modif_path(const char *path, char **out)
{
    sr_error_info_t *err_info = NULL;
    char *it = NULL;

    if (asprintf(out, "%s ", path) == -1) {
        ERRINFO(&err_info, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno))
        goto cleanup;
    }

    it = *out;
    while ((it = srpds_path_token(it, 1))) {
        *it = ' ';
        ++it;
    }

cleanup:
    return err_info;
}

/**
 * @brief Get path of the parent node.
 *
 * @param[in] path Path of the current node.
 */
static void
srpds_get_parent_path(char *path)
{
    char *it = srpds_path_token(path, -1);

    *it = '\0';
}

/**
 * @brief Set default flags for nodes and its parents.
 *
 * @param[in] node Given data node.
 */
static void
srpds_cont_set_dflt(struct lyd_node *node)
{
    const struct lyd_node *child;

    while (node) {
        if (!node->schema || (node->flags & LYD_DEFAULT) || !lysc_is_np_cont(node->schema)) {
            /* not a non-dflt NP container */
            break;
        }

        LY_LIST_FOR(lyd_child(node), child) {
            if (!(child->flags & LYD_DEFAULT)) {
                break;
            }
        }
        if (child) {
            /* explicit child, no dflt change */
            break;
        }

        /* set the dflt flag */
        node->flags |= LYD_DEFAULT;

        /* check all parent containers */
        node = lyd_parent(node);
    }
}

/**
 * @brief Get the escaped string for a MongoDB query.
 *
 * @param[in] string String to escape.
 * @param[out] escaped_string Escaped string.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_escape_string(const char *string, char **escaped_string)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, count, len = strlen(string);

    *escaped_string = calloc(2 * len + 1, sizeof(char));
    if (!(*escaped_string)) {
        ERRINFO(&err_info, SR_ERR_NO_MEMORY, "calloc()", "")
        return err_info;
    }
    for (i = 0, count = 0; i < len; ++i, ++count) {
        if (((string[i] >= ' ') && (string[i] <= '/')) ||
                ((string[i] >= ':') && (string[i] <= '@')) ||
                ((string[i] >= '[') && (string[i] <= '`')) ||
                ((string[i] >= '{') && (string[i] <= '~'))) {
            (*escaped_string)[count] = '\\';
            ++count;
        }
        (*escaped_string)[count] = string[i];
    }
    (*escaped_string)[count] = '\0';

    return err_info;
}

/**
 * @brief Put all load XPaths into a regex.
 *
 * @param[in] ctx Libyang context.
 * @param[in] xpaths Array of XPaths.
 * @param[in] xpath_cnt XPath count.
 * @param[out] out Final regular expression.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_process_load_paths(struct ly_ctx *ctx, const char **xpaths, uint32_t xpath_cnt, int *is_valid, bson_t *xpath_filter)
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
        ERRINFO(&err_info, SR_ERR_LY, "lyd_new_path()", "")
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
            ERRINFO(&err_info, SR_ERR_NO_MEMORY, "strdup()", strerror(errno))
            goto cleanup;
        }

        /* all relative paths should be transformed into absolute */
        if (path[0] != '/') {
            if (asprintf(&tmp, "/%s", path) == -1) {
                ERRINFO(&err_info, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno))
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

        if ((err_info = srpds_escape_string(path, &escaped_path))) {
            goto cleanup;
        }

        /* add path as regex */
        if (asprintf(&tmp, "^%s", escaped_path) == -1) {
            ERRINFO(&err_info, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno))
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

/**
 * @brief Load all data (only nodes (/), metadata (2) and attributes (3)) from the database and store them inside the lyd_node structure (only for operational datastore).
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] mod Given module.
 * @param[out] mod_data Retrieved module data from the database.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_oper(mongoc_collection_t *module, const struct lys_module *mod, struct lyd_node **mod_data)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    const char *xpath, *ptr, *key_value, *value = NULL;
    char *meta_name = NULL;
    int32_t valtype = 0;
    bson_t *doc2 = NULL, *filter = NULL;
    mongoc_cursor_t *cursor = NULL;
    bson_iter_t iter;
    struct lyd_node *meta_match = NULL, *last_node = NULL, *first_node = NULL;
    struct ly_set *meta_match_nodes = NULL;
    uint32_t idx = -1;
    int is_opaque = 0;

    filter = bson_new();
    cursor = mongoc_collection_find_with_opts(module, filter, NULL, NULL);

    /*
    *   Loading multiple different sets of data
    *
    *   Load Oper
    *   | 1) nodes without a value
    *   |    Dataset [ xpath(_id) | is_opaque ]
    *   |
    *   | 2) nodes with a value
    *   |    Dataset [ xpath(_id) | value | valtype | is_opaque ] - valtype can be 0 - XML, 1 - JSON
    *   |
    *   | 3) metadata and attributes (0, 1, 2, 3, 4) ... (0, 1, 4) DO NOT LOAD
    *
    *   Metadata, Attributes and MaxOrder
    *   | 1) metadata and attributes (starting with a number)
    *   |     1.1) 0 timestamp (last-modif) [ !!! NOT LOADED ]
    *   |     1.2) 1 is different from running? (for candidate datastore) [ !!! NOT LOADED ]
    *   |     1.3) 2 node metadata
    *   |     1.4) 3 attribute data for opaque nodes
    *   |     1.5) 4 owner, group and permissions [ !!! NOT LOADED]
    *   |    Dataset [ xpath(_id) | value ]
    *
    *   [ !!! NOT LOADED ] data are only for internal use
    */

    while (mongoc_cursor_next(cursor, (const bson_t **) &doc2)) {
        if (!bson_iter_init(&iter, doc2)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_init()", "")
            goto cleanup;
        }

        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
            goto cleanup;
        }
        xpath = bson_iter_utf8(&iter, NULL);
        if (!bson_utf8_validate(xpath, strlen(xpath), 0)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_utf8()", "")
            goto cleanup;
        }

        /* do not load, this is additional data
         * 0 - timestamp of the last modification
         * 1 - modified flag for candidate datastore
         * 4 - owner, group and permissions */
        if ((xpath[0] == '0') || (xpath[0] == '1') || (xpath[0] == '4')) {
            continue;
        }

        /* next item differs in different datasets */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
            goto cleanup;
        }
        key_value = bson_iter_key(&iter);

        /* if no valtype present, valtype is 0 - LYD_ANYDATA_XML */
        value = NULL;
        valtype = 0;
        is_opaque = 0;

        /* is_opaque, this is a node without a value */
        if (!strcmp(key_value, "is_opaque")) {
            is_opaque = bson_iter_bool(&iter);
            /* value, this is a node with a value or metadata */
        } else if (!strcmp(key_value, "value")) {
            /* get value */
            value = bson_iter_utf8(&iter, NULL);
            if (!bson_utf8_validate(value, strlen(value), 0)) {
                ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_utf8()", "")
                goto cleanup;
            }

            /* get valtype */
            if (bson_iter_next(&iter)) {
                valtype = bson_iter_int32(&iter);
            }

            /* get opaque flag */
            if (bson_iter_next(&iter)) {
                is_opaque = bson_iter_bool(&iter);
            }
        }

        /* 2 - tree metadata (e.g. 'nc:operation="merge"' or 'or:origin="unknown"') */
        /* 3 - attributes of opaque nodes (e.g. 'operation="delete"') */
        if ((xpath[0] == '2') || (xpath[0] == '3')) {
            if (asprintf(&meta_name, "%s", xpath + 1) == -1) {
                ERRINFO(&err_info, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno))
                goto cleanup;
            }
            ptr = strchr(meta_name, '#');
            if (!ptr) {
                ERRINFO(&err_info, SR_ERR_NOT_FOUND, "strchr()", "")
                goto cleanup;
            }
            idx = (uint32_t)(ptr - meta_name);
            meta_name[idx] = '\0';
            if (lyd_find_xpath(*mod_data, meta_name, &meta_match_nodes) != LY_SUCCESS) {
                ERRINFO(&err_info, SR_ERR_LY, "lyd_find_xpath()", "")
                goto cleanup;
            }
            if (!meta_match_nodes->count) {
                ERRINFO(&err_info, SR_ERR_NOT_FOUND, "lyd_find_xpath()", "XPath not found")
                goto cleanup;
            }
            meta_match = meta_match_nodes->dnodes[0];

            /* setting the default flag */
            if (!strcmp(meta_name + idx + 1, "ietf-netconf-with-defaults:default")) {
                meta_match->flags = meta_match->flags | LYD_DEFAULT;
                srpds_cont_set_dflt(lyd_parent(meta_match));
                /* setting metadata */
            } else if ((xpath[0] == '2') && (lyd_new_meta(LYD_CTX(meta_match), meta_match, NULL, meta_name + idx + 1, value, 0, NULL) != LY_SUCCESS)) {
                ERRINFO(&err_info, SR_ERR_LY, "lyd_new_meta()", "")
                goto cleanup;
                /* setting attributes for opaque nodes */
            } else if ((xpath[0] == '3') && lyd_new_attr(meta_match, NULL, meta_name + idx + 1, value, NULL)) {
                ERRINFO(&err_info, SR_ERR_LY, "lyd_new_attr()", "")
                goto cleanup;
            }
        } else {
            if (lyd_new_path2(*mod_data, mod->ctx, xpath, value, 0, valtype ? LYD_ANYDATA_JSON : LYD_ANYDATA_XML, is_opaque ? LYD_NEW_PATH_OPAQ : 0, &first_node, &last_node) != LY_SUCCESS) {
                ERRINFO(&err_info, SR_ERR_LY, "lyd_new_path2()", "")
                goto cleanup;
            }

            if (*mod_data == NULL) {
                *mod_data = first_node;
            }
        }

        ly_set_free(meta_match_nodes, NULL);
        free(meta_name);
        meta_match_nodes = NULL;
        meta_name = NULL;
    }

    if (mongoc_cursor_error(cursor, &error)) {
        ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_find_with_opts()", error.message)
        goto cleanup;
    }

    *mod_data = lyd_first_sibling(*mod_data);

cleanup:
    ly_set_free(meta_match_nodes, NULL);
    free(meta_name);
    bson_destroy(filter);
    mongoc_cursor_destroy(cursor);
    return err_info;
}

/**
 * @brief Get how deep the node is within the data tree.
 *
 * @param[in] path Path to node.
 * @return Depth of the node.
 */
static uint32_t
srpds_get_node_depth(const char *path)
{
    uint32_t depth = 0;
    char *it = (char *)path;

    while ((it = srpds_path_token(it, 1))) {
        ++depth;
        ++it;
    }

    return depth;
}

/**
 * @brief Goes through concatenated keys and separates them.
 *
 * @param[in] keys Concatenated keys and their respective lengths
 *      (length is the first two bytes and then the key).
 * @param[out] parsed Array of keys.
 * @param[out] lengths Array of key lengths.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_parse_keys(const char *keys, char ***parsed, uint32_t **lengths)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i = 0;
    const char *key = keys;
    void *mem;

    *parsed = NULL;
    *lengths = NULL;

    /* collect all other remaining keys and put them into the array */
    while (MONGO_LIST_KEY_IS_END(key[0], key[1])) {
        mem = realloc(*parsed, (i + 1) * sizeof **parsed);
        if (!mem) {
            ERRINFO(&err_info, SR_ERR_NO_MEMORY, "realloc()", "")
            goto cleanup;
        }
        *parsed = mem;

        mem = realloc(*lengths, (i + 1) * sizeof **lengths);
        if (!mem) {
            ERRINFO(&err_info, SR_ERR_NO_MEMORY, "realloc()", "")
            goto cleanup;
        }
        *lengths = mem;

        /* get key (do not forget to skip length) */
        (*parsed)[i] = ((char *)key) + MONGO_LIST_KEY_LEN_BYTES;

        /* get length of the key from the first two bytes */
        (*lengths)[i] = MONGO_LIST_KEY_GET_LEN(key[0], key[1]);

        /* move onto the next key */
        key += MONGO_LIST_KEY_LEN_BYTES + (*lengths)[i];
        ++i;
    }

cleanup:
    return err_info;
}

/**
 * @brief Load all data (only nodes (/)) and store them inside the lyd_node structure (for all datastores except oper).
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] mod Given module.
 * @param[in] ds Given datastore.
 * @param[in] paths_regex Regular expression composed of load XPaths to speed up the loading process.
 * @param[out] mod_data Retrieved module data from the database.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_conv(mongoc_collection_t *module, const struct lys_module *mod, sr_datastore_t ds, bson_t *xpath_filter, struct lyd_node **mod_data)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    const char *path, *name, *module_name, *value = NULL, *path_no_pred;
    char **keys = NULL;
    uint32_t *lengths = NULL;
    enum srpds_mongo_ly_types type;
    int32_t valtype;
    int64_t order;
    int dflt_flag = 0;
    mongo_userordered_lists_t uo_lists = {0};
    mongo_userordered_list_t *list = NULL;
    mongo_userordered_data_t *data = NULL;
    size_t size;
    int uo_found;

    bson_t *doc2 = NULL, *opts = NULL;
    mongoc_cursor_t *cursor = NULL;
    bson_iter_t iter;
    struct lyd_node *new_node = NULL, *parent_node = NULL;

    struct lyd_node **parent_nodes = NULL, **tmp_pnodes = NULL;
    size_t pnodes_size = 1;
    uint32_t node_idx = 0, i, j;
    struct lys_module *node_module = NULL;

    opts = BCON_NEW("sort", "{", "path_modif", BCON_INT32(1), "}");
    cursor = mongoc_collection_find_with_opts(module, xpath_filter, opts, NULL);

    /*
    *   Loading multiple different sets of data
    *
    *   Load Conventional Datastore
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
    *   | 5) user-ordered lists
    *   |    Dataset [ path(_id) | name | type | module_name | keys | order | path_no_pred | prev | path_modif ]
    *   |
    *   | 6) user-ordered leaf-lists
    *   |    Dataset [ path(_id) | name | type | module_name | dflt_flag | value | order | path_no_pred | prev | path_modif ]
    *   |
    *   | 7) metadata and maxorder (0, 1, 4, #)
    *   |
    *   | module_name = NULL - use parent's module | name - use the module specified by this name
    *   | valtype = 0 - XML | 1 - JSON
    *   | start number defines the type (1 - container, 2 - list...)
    *
    *   Metadata and MaxOrder
    *   | 1) metadata
    *   |     1.1) 0 timestamp (last-modif) [ !!! NOT LOADED ]
    *   |     1.2) 1 is different from running? (for candidate datastore) [ !!! NOT LOADED ]
    *   |     1.3) 4 owner, group and permissions [ !!! NOT LOADED ]
    *   |    Dataset [ path(_id) | value ]
    *   |
    *   | 2) maximum order for a userordered list or leaflist (starting with a #)
    *   |     2.1) # maximum order [ !!! NOT LOADED ]
    *   |    Dataset [ path(_id) | value ]
    *
    *   [ !!! NOT LOADED ] data are only for internal use
    */

    parent_nodes = calloc(1, sizeof *parent_nodes);
    if (!parent_nodes) {
        ERRINFO(&err_info, SR_ERR_NO_MEMORY, "calloc()", "")
        goto cleanup;
    }

    while (mongoc_cursor_next(cursor, (const bson_t **) &doc2)) {
        if (!bson_iter_init(&iter, doc2)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_init()", "")
            goto cleanup;
        }

        /* get path */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
            goto cleanup;
        }
        path = bson_iter_utf8(&iter, NULL);
        if (!bson_utf8_validate(path, strlen(path), 0)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_utf8()", "")
            goto cleanup;
        }

        /* do not load, this is additional data
         * 0 - timestamp of the last modification
         * 1 - modified flag for candidate datastore
         * # - maximum load-order for list or leaf-list
         * 4 - owner, group and permissions */
        switch (path[0]) {
        case '0':
        case '1':
        case '#':
        case '4':
            continue;
        default:
            break;
        }

        /* get name */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
            goto cleanup;
        }
        name = bson_iter_utf8(&iter, NULL);
        if (!bson_utf8_validate(name, strlen(name), 0)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_utf8()", "")
            goto cleanup;
        }

        /* get type */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
            goto cleanup;
        }
        type = bson_iter_int32(&iter);

        /* get module name */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
            goto cleanup;
        }
        module_name = bson_iter_utf8(&iter, NULL);
        if (module_name && !bson_utf8_validate(module_name, strlen(module_name), 0)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_utf8()", "")
            goto cleanup;
        }

        /* get default flag or keys based on type */
        switch (type) {
        case MONGO_LY_TERM:         /* leafs and leaf-lists */
        case MONGO_LY_ANY:          /* anydata and anyxml */
        case MONGO_LY_LEAFLIST_UO:  /* user-ordered leaf-lists */
            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
                goto cleanup;
            }
            dflt_flag = bson_iter_as_bool(&iter);
            break;
        case MONGO_LY_LIST:     /* lists */
        case MONGO_LY_LIST_UO:  /* user-ordered lists */
            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
                goto cleanup;
            }
            value = bson_iter_utf8(&iter, NULL);
            if ((err_info = srpds_parse_keys(value, &keys, &lengths))) {
                goto cleanup;
            }
            break;
        default:
            break;
        }

        /* get value or order based on type */
        switch (type) {
        case MONGO_LY_TERM:         /* leafs and leaf-lists */
        case MONGO_LY_ANY:          /* anydata and anyxml */
        case MONGO_LY_LEAFLIST_UO:  /* user-ordered leaf-lists */
            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
                goto cleanup;
            }
            value = bson_iter_utf8(&iter, NULL);
            if (!bson_utf8_validate(value, strlen(value), 0)) {
                ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_utf8()", "")
                goto cleanup;
            }
            break;
        case MONGO_LY_LIST_UO:  /* user-ordered lists */
            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
                goto cleanup;
            }
            order = bson_iter_int64(&iter);
            break;
        default:
            break;
        }

        /* get valtype or path_no_pred or order based on type */
        switch (type) {
        case MONGO_LY_ANY:  /* anydata and anyxml */
            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
                goto cleanup;
            }
            valtype = bson_iter_int32(&iter);
            break;
        case MONGO_LY_LIST_UO:  /* user-ordered lists */
            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
                goto cleanup;
            }
            path_no_pred = bson_iter_utf8(&iter, NULL);
            if (!bson_utf8_validate(path_no_pred, strlen(path_no_pred), 0)) {
                ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_utf8()", "")
                goto cleanup;
            }
            break;
        case MONGO_LY_LEAFLIST_UO:  /* user-ordered leaf-lists */
            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
                goto cleanup;
            }
            order = bson_iter_int64(&iter);
            break;
        default:
            break;
        }

        switch (type) {
        case MONGO_LY_LEAFLIST_UO:  /* user-ordered leaf-lists */
            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
                goto cleanup;
            }
            path_no_pred = bson_iter_utf8(&iter, NULL);
            if (!bson_utf8_validate(path_no_pred, strlen(path_no_pred), 0)) {
                ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_utf8()", "")
                goto cleanup;
            }
            break;
        default:
            break;
        }

        /* get module from module_name */
        if (module_name) {
            node_module = ly_ctx_get_module_implemented(mod->ctx, module_name);
        } else {
            node_module = NULL;
        }

        /* get index of the node in the parent_nodes array based on its height */
        node_idx = srpds_get_node_depth(path) - 1;
        parent_node = node_idx ? parent_nodes[node_idx - 1] : NULL;

        /* create a node based on type */
        switch (type) {
        case MONGO_LY_CONTAINER:    /* containers */
            if (lyd_new_inner(parent_node, node_module, name, 0, &new_node) != LY_SUCCESS) {
                ERRINFO(&err_info, SR_ERR_LY, "lyd_new_inner()", "")
                goto cleanup;
            }
            break;
        case MONGO_LY_LIST:     /* lists */
        case MONGO_LY_LIST_UO:  /* user-ordered lists */
            if (lyd_new_list3(parent_node, node_module, name, (const char **)keys, lengths, LYD_NEW_VAL_STORE_ONLY,
                    &new_node) != LY_SUCCESS) {
                ERRINFO(&err_info, SR_ERR_LY, "lyd_new_list3()", "")
                goto cleanup;
            }
            free(keys);
            free(lengths);
            keys = NULL;
            lengths = NULL;
            break;
        case MONGO_LY_TERM:         /* leafs and leaf-lists */
        case MONGO_LY_LEAFLIST_UO:  /* user-ordered leaf-lists */
            if (lyd_new_term(parent_node, node_module, name, value, LYD_NEW_VAL_STORE_ONLY,
                    &new_node) != LY_SUCCESS) {
                ERRINFO(&err_info, SR_ERR_LY, "lyd_new_term()", "")
                goto cleanup;
            }
            break;
        case MONGO_LY_ANY:   /* anydata and anyxml */
            if (lyd_new_any(parent_node, node_module, name, value, valtype ? LYD_ANYDATA_JSON : LYD_ANYDATA_XML,
                    LYD_NEW_VAL_STORE_ONLY, &new_node) != LY_SUCCESS) {
                ERRINFO(&err_info, SR_ERR_LY, "lyd_new_any()", "")
                goto cleanup;
            }
            break;
        default:
            break;
        }

        /* store new node in the parent nodes array for children */
        if (node_idx >= pnodes_size) {
            tmp_pnodes = realloc(parent_nodes, (++pnodes_size) * sizeof *parent_nodes);
            if (!tmp_pnodes) {
                ERRINFO(&err_info, SR_ERR_NO_MEMORY, "realloc()", "")
                goto cleanup;
            }
            parent_nodes = tmp_pnodes;
        }
        parent_nodes[node_idx] = new_node;
        if (!node_idx) {
            if (lyd_insert_sibling(*mod_data, new_node, mod_data) != LY_SUCCESS) {
                ERRINFO(&err_info, SR_ERR_LY, "lyd_insert_sibling()", "")
                goto cleanup;
            }
        }

        /* store nodes and their orders of userordered lists and leaflists for final ordering */
        if ((type == MONGO_LY_LIST_UO) || (type == MONGO_LY_LEAFLIST_UO)) {
            uo_found = 0;
            for (i = 0; i < uo_lists.size; ++i) {
                if (!strcmp(uo_lists.lists[i].name, path_no_pred)) {
                    uo_found = 1;
                    size = uo_lists.lists[i].size;
                    data = realloc(uo_lists.lists[i].data, (size + 1) * sizeof *data);
                    if (!data) {
                        ERRINFO(&err_info, SR_ERR_NO_MEMORY, "realloc()", "")
                        goto cleanup;
                    }
                    uo_lists.lists[i].data = data;
                    uo_lists.lists[i].data[size].ptr = new_node;
                    uo_lists.lists[i].data[size].order = order;
                    uo_lists.lists[i].size = size + 1;
                }
            }
            if (!uo_found) {
                size = uo_lists.size;
                if (size) {
                    list = realloc(uo_lists.lists, (size + 1) * sizeof *list);
                    if (!list) {
                        ERRINFO(&err_info, SR_ERR_NO_MEMORY, "realloc()", "")
                        goto cleanup;
                    }
                    uo_lists.lists = list;
                    uo_lists.size = size + 1;
                } else {
                    list = calloc(1, sizeof *list);
                    if (!list) {
                        ERRINFO(&err_info, SR_ERR_NO_MEMORY, "calloc()", "")
                        goto cleanup;
                    }
                    uo_lists.lists = list;
                    uo_lists.size = 1;
                }
                if (!(uo_lists.lists[size].name = strdup(path_no_pred))) {
                    ERRINFO(&err_info, SR_ERR_NO_MEMORY, "strdup()", strerror(errno))
                    goto cleanup;
                }
                uo_lists.lists[size].size = 1;
                data = calloc(1, sizeof *data);
                if (!data) {
                    ERRINFO(&err_info, SR_ERR_NO_MEMORY, "calloc()", "")
                    goto cleanup;
                }
                uo_lists.lists[size].data = data;
                uo_lists.lists[size].data[0].ptr = new_node;
                uo_lists.lists[size].data[0].order = order;
                uo_lists.lists[size].size = 1;
            }
        }

        /* for default nodes add a flag */
        if (dflt_flag) {
            new_node->flags = new_node->flags | LYD_DEFAULT;
            dflt_flag = 0;
            srpds_cont_set_dflt(lyd_parent(new_node));
        }

        /* for 'when' nodes add a flag */
        if ((ds == SR_DS_RUNNING) || (ds == SR_DS_STARTUP) || (ds == SR_DS_FACTORY_DEFAULT)) {
            while (parent_nodes[0] != new_node) {
                if (lysc_has_when(new_node->schema)) {
                    new_node->flags |= LYD_WHEN_TRUE;
                }
                new_node->flags &= ~LYD_NEW;
                new_node = lyd_parent(new_node);
            }
            if (lysc_has_when(parent_nodes[0]->schema)) {
                parent_nodes[0]->flags |= LYD_WHEN_TRUE;
            }
            parent_nodes[0]->flags &= ~LYD_NEW;
        }
    }

    if (mongoc_cursor_error(cursor, &error)) {
        ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_find_with_opts()", error.message)
        goto cleanup;
    }

    /* go through all userordered lists and leaflists and order them */
    for (i = 0; i < uo_lists.size; ++i) {
        data = uo_lists.lists[i].data;
        size = uo_lists.lists[i].size;
        qsort(data, size, sizeof *data, srpds_uo_elem_comp);
        for (j = 1; j < size; ++j) {
            if (lyd_insert_after(data[0].ptr, data[size - j].ptr) != LY_SUCCESS) {
                ERRINFO(&err_info, SR_ERR_LY, "lyd_insert_after()", "")
                goto cleanup;
            }
        }
    }

    *mod_data = lyd_first_sibling(*mod_data);

cleanup:
    free(keys);
    free(lengths);
    for (i = 0; i < uo_lists.size; ++i) {
        free(uo_lists.lists[i].name);
        free(uo_lists.lists[i].data);
    }
    free(uo_lists.lists);
    free(parent_nodes);
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
        ERRINFO(&err_info, SR_ERR_NO_MEMORY, "calloc()", "")
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
            ERRINFO(&err_info, SR_ERR_NO_MEMORY, "realloc()", "")
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
        ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "Adding operation to a list", "")
        return err_info;
    }
    if ((err_info = srpds_docs_add(&(inner->docs), &(inner->size), &(inner->idx), bson_query))) {
        return err_info;
    }
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
            ERRINFO(&err_info, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno))
            goto cleanup;
        }

        /* selector for replace command */
        bson_query_key = BCON_NEW("_id", BCON_UTF8(final_path));

        /* replace command */
        bson_query = BCON_NEW("$set", "{", "value", BCON_INT64(max_order), "}");
        if (!mongoc_collection_update_one(module, bson_query_key, bson_query, NULL, NULL, &error)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message)
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
    bson_t *bson_query = NULL,
            *bson_query_del = NULL;
    char *final_path = NULL;

    /* set maximum order of the list */
    if (asprintf(&final_path, "#%s", path_no_pred) == -1) {
        ERRINFO(&err_info, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno))
        goto cleanup;
    }

    /* use case: some elements are inserted, all of them are deleted and another element is
     * inserted -> previous max order has to be deleted and a new one inserted */
    bson_query_del = BCON_NEW("_id", BCON_UTF8(final_path));
    if (!mongoc_collection_delete_one(module, bson_query_del, NULL, NULL, &error)) {
        ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_delete_one()", error.message)
        goto cleanup;
    }

    /* maximum order starts at 1000, so that a large gap in front of the first element is created
     * to easily insert elements here */
    bson_query = BCON_NEW("_id", BCON_UTF8(final_path), "value", BCON_INT64(1000));
    if (!mongoc_collection_insert_one(module, bson_query, NULL, NULL, &error)) {
        ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_insert_one()", error.message)
        goto cleanup;
    }

cleanup:
    free(final_path);
    bson_destroy(bson_query);
    bson_destroy(bson_query_del);
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
    *out_max_order = *out_max_order + 1000;
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
            ERRINFO(&err_info, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno))
            goto cleanup;
        }

        doc = BCON_NEW("_id", BCON_UTF8(final_path));
        cursor = mongoc_collection_find_with_opts(module, doc, NULL, NULL);

        if (mongoc_cursor_next(cursor, (const bson_t **) &doc2)) {
            if (!bson_iter_init(&iter, doc2)) {
                ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_init()", "")
                goto cleanup;
            }

            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
                goto cleanup;
            }
            if (!bson_iter_next(&iter)) {
                ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
                goto cleanup;
            } else {
                *out_max_order = bson_iter_int64(&iter);
            }
        } else {
            ERRINFO(&err_info, SR_ERR_NOT_FOUND, "Finding maximum order of the list", "")
            goto cleanup;
        }

        if (mongoc_cursor_error(cursor, &error)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_find_with_opts()", error.message)
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
 * @param[in] prev Predicate of the previous element.
 * @param[in] path_no_pred Path of a list/leaf-list instance without a predicate.
 * @param[out] order Order of the previous element.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_prev(mongoc_collection_t *module, uint16_t nodetype, const char *prev, const char *path_no_pred, uint64_t *order)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    mongoc_cursor_t *cursor = NULL;
    bson_t *doc = NULL, *doc2 = NULL;
    bson_iter_t iter;
    char *prev_path = NULL;

    /* prepare path of the previous element */
    if (asprintf(&prev_path, "%s%s", path_no_pred, prev) == -1) {
        ERRINFO(&err_info, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno))
        goto cleanup;
    }

    doc = BCON_NEW("_id", BCON_UTF8(prev_path));
    cursor = mongoc_collection_find_with_opts(module, doc, NULL, NULL);

    if (mongoc_cursor_next(cursor, (const bson_t **) &doc2)) {
        if (!bson_iter_init(&iter, doc2)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_init()", "")
            goto cleanup;
        }

        /* path */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
            goto cleanup;
        }
        /* name */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
            goto cleanup;
        }
        /* type */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
            goto cleanup;
        }
        /* module_name */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
            goto cleanup;
        }
        /* predicate or dflt_flag */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
            goto cleanup;
        }
        /* value */
        if ((nodetype == LYS_LEAFLIST) && !bson_iter_next(&iter)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
            goto cleanup;
        }
        /* order */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
            goto cleanup;
        }
        *order = bson_iter_int64(&iter);
    }

    if (mongoc_cursor_error(cursor, &error)) {
        ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_find_with_opts()", error.message)
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
 * @param[in] prev Predicate of the next element's previous element.
 * @param[in] path_no_pred Path of a list/leaf-list instance without a predicate.
 * @param[out] order Order of the next element.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_next(mongoc_collection_t *module, uint16_t nodetype, const char *prev, const char *path_no_pred, uint64_t *order)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    mongoc_cursor_t *cursor = NULL;
    bson_t *doc = NULL, *doc2 = NULL;
    bson_iter_t iter;
    char *order_str = NULL;
    uint64_t order_cur = 0, order_min = UINT64_MAX;

    *order = 0;

    doc = BCON_NEW("prev", BCON_UTF8(prev), "path_no_pred", BCON_UTF8(path_no_pred));
    cursor = mongoc_collection_find_with_opts(module, doc, NULL, NULL);

    if (mongoc_cursor_next(cursor, (const bson_t **) &doc2)) {
        if (!bson_iter_init(&iter, doc2)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_init()", "")
            goto cleanup;
        }

        /* path */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
            goto cleanup;
        }
        /* name */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
            goto cleanup;
        }
        /* type */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
            goto cleanup;
        }
        /* module_name */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
            goto cleanup;
        }
        /* predicate or dflt_flag */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
            goto cleanup;
        }
        /* value */
        if ((nodetype == LYS_LEAFLIST) && !bson_iter_next(&iter)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
            goto cleanup;
        }
        /* order */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
            goto cleanup;
        }
        order_cur = bson_iter_int64(&iter);
        if (order_min > order_cur) {
            order_min = order_cur;
        }
    }

    if (mongoc_cursor_error(cursor, &error)) {
        ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_find_with_opts()", error.message)
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
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_init()", "")
            goto cleanup;
        }

        /* get path of the next element */
        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
            goto cleanup;
        }
        path = bson_iter_utf8(&iter, NULL);
        if (!bson_utf8_validate(path, strlen(path), 0)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_utf8()", "")
            goto cleanup;
        }
    }

    if (mongoc_cursor_error(cursor, &error)) {
        ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_find_with_opts()", error.message)
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
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message)
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
 * @brief Concatenate the keys of a list instance into a single string.
 *
 * @param[in] node List instance.
 * @param[out] keys String containing all of the keys and their respective lengths.
 * @param[out] keys_length Length of the @p keys .
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_concat_key_values(struct lyd_node *node, char **keys, uint32_t *keys_length)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *child = lyd_child(node);
    char *tmp = NULL;
    const char *key;
    uint16_t keylen;
    uint32_t i, prev_keys_len = 0;

    *keys = NULL;
    *keys_length = 0;

    while (child && lysc_is_key(child->schema)) {
        key = lyd_get_value(child);
        keylen = strlen(key);

        /* we are only using 7 bits of two bytes for length,
         * therefore length cannot be bigger than (UINT16_MAX >> 2) */
        if (keylen > (UINT16_MAX >> 2)) {
            ERRINFO(&err_info, SR_ERR_INTERNAL, "srpds_concat_key_values()", "Value is bigger than (UINT16_MAX >> 2)")
            goto cleanup;
        }

        /* store length from previous iteration */
        prev_keys_len = *keys_length;

        /* length of a newly created string will increase by length of the next key and
         * two bytes for storing length of the next key */
        *keys_length += keylen + MONGO_LIST_KEY_LEN_BYTES;
        tmp = malloc(*keys_length);
        if (!tmp) {
            ERRINFO(&err_info, SR_ERR_NO_MEMORY, "malloc()", strerror(errno))
            goto cleanup;
        }

        /* copy contents of the previous string */
        for (i = 0; i < prev_keys_len; ++i) {
            tmp[i] = (*keys)[i];
        }

        /* store length of the next key */
        tmp[prev_keys_len] = keylen >> MONGO_LIST_KEY_LEN_BITS; /* upper byte */
        tmp[prev_keys_len + 1] = keylen & 0x007f; /* lower byte */

        /* store the next key */
        for (i = 0; i < keylen; ++i) {
            tmp[prev_keys_len + 2 + i] = key[i];
        }

        free(*keys);
        *keys = tmp;
        tmp = NULL;
        child = child->next;
    }

    /* store length from previous iteration */
    prev_keys_len = *keys_length;

    /* store the last two null bytes signaling the end of the string */
    *keys_length += MONGO_LIST_KEY_LEN_BYTES;
    tmp = malloc(*keys_length);
    if (!tmp) {
        ERRINFO(&err_info, SR_ERR_NO_MEMORY, "malloc()", strerror(errno))
        goto cleanup;
    }

    /* copy contents of the previous string */
    for (i = 0; i < prev_keys_len; ++i) {
        tmp[i] = (*keys)[i];
    }

    /* store last two null bytes */
    tmp[prev_keys_len] = '\0';
    tmp[prev_keys_len + 1] = '\0';
    free(*keys);
    *keys = tmp;
    tmp = NULL;

cleanup:
    free(tmp);
    return err_info;
}

/**
 * @brief Insert a user-ordered element into a list or a leaf-list in the database.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] path Path of the user-ordered element.
 * @param[in] path_no_pred Path without a predicate of the user-ordered element.
 * @param[in] predicate Predicate of the user-ordered element.
 * @param[in] value Value of the user-ordered element.
 * @param[in] value_pred Value of the user-ordered element in a predicate, e.g. [.=''].
 * @param[out] max_order Changed maximum order.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_create_uo_op(mongoc_collection_t *module, struct lyd_node *node, const char *module_name, const char *path,
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
                ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message)
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
                ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message)
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
            order = 1000;
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
                ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message)
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
                ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message)
                goto cleanup;
            }
        }
    }

    /* insert an element */
    switch (node->schema->nodetype) {
    case LYS_LIST:
        if ((err_info = srpds_concat_key_values(node, &keys, &keys_length))) {
            goto cleanup;
        }
        bson_query_uo = bson_new();
        bson_append_utf8(bson_query_uo, "_id", 3, path, -1);
        bson_append_utf8(bson_query_uo, "name", 4, node->schema->name, -1);
        bson_append_int32(bson_query_uo, "type", 4, MONGO_LY_LIST_UO);
        bson_append_utf8(bson_query_uo, "module_name", 11, module_name, -1);
        bson_append_utf8(bson_query_uo, "keys", 4, keys, keys_length);
        bson_append_int64(bson_query_uo, "order", 5, order);
        bson_append_utf8(bson_query_uo, "path_no_pred", 12, path_no_pred, -1);
        bson_append_utf8(bson_query_uo, "prev", 4, prev, -1);
        bson_append_utf8(bson_query_uo, "path_modif", 10, path_modif, -1);
        break;
    case LYS_LEAFLIST:
        bson_query_uo = BCON_NEW("_id", BCON_UTF8(path),
                "name", BCON_UTF8(node->schema->name),
                "type", BCON_INT32(MONGO_LY_LEAFLIST_UO),
                "module_name", BCON_UTF8(module_name),
                "dflt_flag", BCON_BOOL(0),
                "value", BCON_UTF8(value),
                "order", BCON_INT64(order),
                "path_no_pred", BCON_UTF8(path_no_pred),
                "prev", BCON_UTF8(prev_pred),
                "path_modif", BCON_UTF8(path_modif));
        break;
    }
    if (!mongoc_collection_insert_one(module, bson_query_uo, NULL, NULL, &error)) {
        ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_insert_one()", error.message)
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
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_delete_uo_op(mongoc_collection_t *module, const char *path, const char *path_no_pred, const char *predicate,
        const char *orig_value_pred)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    bson_t *bson_query_uo_rep = NULL, *bson_query_uo_key = NULL,
            *bson_query_uo = NULL;

    /* add new prev element to the next element,
     * selector for replace command */
    bson_query_uo_key = BCON_NEW("prev", BCON_UTF8(predicate), "path_no_pred", BCON_UTF8(path_no_pred));

    /* change the next element's prev */
    bson_query_uo_rep = BCON_NEW("$set", "{", "prev", BCON_UTF8(orig_value_pred), "}");
    if (!mongoc_collection_update_one(module, bson_query_uo_key, bson_query_uo_rep, NULL, NULL, &error)) {
        ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message)
        goto cleanup;
    }

    /* delete command for userordered lists and leaf-lists */
    bson_query_uo = BCON_NEW("_id", BCON_UTF8(path));
    if (!mongoc_collection_delete_one(module, bson_query_uo, NULL, NULL, &error)) {
        ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_delete_one()", error.message)
        goto cleanup;
    }

cleanup:
    bson_destroy(bson_query_uo);
    bson_destroy(bson_query_uo_key);
    bson_destroy(bson_query_uo_rep);
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
srpds_update_default_flag(const char *path, struct lyd_node *node, struct mongo_diff_data *diff_data)
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
srpds_create_op_default_flag(const char *path, struct lyd_node *node, struct mongo_diff_data *diff_data)
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
srpds_none_op_default_flag(const char *path, struct lyd_node *node, struct mongo_diff_data *diff_data)
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
srpds_replace_op_default_flag(const char *path, struct lyd_node *node, struct mongo_diff_data *diff_data)
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
 * @param[in] path Path of the data node.
 * @param[in] path_no_pred Path without the predicate of the data node.
 * @param[in] predicate Predicate of the data node.
 * @param[in] value Value of the node.
 * @param[in] value_pred Value of the node in predicate.
 * @param[in] valtype Type of the node's value (XML or JSON).
 * @param[in,out] max_order Maximum order of the list or leaf-list.
 * @param[out] diff_data Helper structure for storing diff operations.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_create_op(mongoc_collection_t *module, struct lyd_node *node, const char *module_name, const char *path, const char *path_no_pred,
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
            bson_query = BCON_NEW("_id", BCON_UTF8(path), "name", BCON_UTF8(node->schema->name), "type", BCON_INT32(MONGO_LY_CONTAINER),
                    "module_name", BCON_UTF8(module_name), "path_modif", BCON_UTF8(path_modif));
            break;
        case LYS_LIST:
            if ((err_info = srpds_concat_key_values(node, &keys, &keys_length))) {
                goto cleanup;
            }
            bson_query = bson_new();
            bson_append_utf8(bson_query, "_id", 3, path, -1);
            bson_append_utf8(bson_query, "name", 4, node->schema->name, -1);
            bson_append_int32(bson_query, "type", 4, MONGO_LY_LIST);
            bson_append_utf8(bson_query, "module_name", 11, module_name, -1);
            bson_append_utf8(bson_query, "keys", 4, keys, keys_length);
            bson_append_utf8(bson_query, "path_modif", 10, path_modif, -1);
            break;
        case LYS_LEAF:
        case LYS_LEAFLIST:
            bson_query = BCON_NEW("_id", BCON_UTF8(path), "name", BCON_UTF8(node->schema->name), "type", BCON_INT32(MONGO_LY_TERM),
                    "module_name", BCON_UTF8(module_name), "dflt_flag", BCON_BOOL(0), "value", BCON_UTF8(value), "path_modif", BCON_UTF8(path_modif));
            break;
        case LYS_ANYDATA:
        case LYS_ANYXML:
            bson_query = BCON_NEW("_id", BCON_UTF8(path), "name", BCON_UTF8(node->schema->name), "type", BCON_INT32(MONGO_LY_ANY),
                    "module_name", BCON_UTF8(module_name), "dflt_flag", BCON_BOOL(0), "value", BCON_UTF8(value),
                    "valtype", BCON_INT32(valtype), "path_modif", BCON_UTF8(path_modif));
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
 * @param[in] orig_value_pred Original value of the node in predicate.
 * @param[out] diff_data Helper structure for storing diff operations.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_delete_op(mongoc_collection_t *module, struct lyd_node *node, const char *path, const char *path_no_pred,
        const char *predicate, const char *orig_value_pred, struct mongo_diff_data *diff_data)
{
    sr_error_info_t *err_info = NULL;

    if (lysc_is_userordered(node->schema)) {
        /* delete an element from the user-ordered list */
        if ((err_info = srpds_delete_uo_op(module, path, path_no_pred, predicate, orig_value_pred))) {
            goto cleanup;
        }
    } else {
        /* normal delete command */
        if ((err_info = srpds_add_operation(BCON_NEW("_id", BCON_UTF8(path)), &(diff_data->del)))) {
            goto cleanup;
        }
    }

cleanup:
    return err_info;
}

/**
 * @brief Diff operation replace.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] node Current data node in the diff.
 * @param[in] path Path of the data node.
 * @param[in] path_no_pred Path without the predicate of the data node.
 * @param[in] predicate Predicate of the data node.
 * @param[in] value Value of the node.
 * @param[in] value_pred Value of the node in predicate.
 * @param[in] orig_value_pred Original value of the node in predicate.
 * @param[in,out] max_order Maximum order of the list or leaf-list.
 * @param[out] diff_data Helper structure for storing diff operations.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_replace_op(mongoc_collection_t *module, struct lyd_node *node, const char *module_name, const char *path, const char *path_no_pred,
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
        if ((err_info = srpds_delete_uo_op(module, path, path_no_pred, predicate, orig_prev_pred))) {
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
 * @brief Get all the values associated with the node.
 *
 * @param[in] node Data node for which to get the values.
 * @param[out] value Value of the node.
 * @param[out] orig_value Original value of the node.
 * @param[out] value_pred Value of the node in predicate.
 * @param[out] orig_value_pred Original value of the node in predicate.
 * @param[out] any_value Value of the type 'any value'.
 * @param[out] valtype Type of the node's value (XML or JSON).
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_get_values(struct lyd_node *node, const char **value, const char **prev, const char **orig_prev, char **prev_pred, char **orig_prev_pred, char **any_value, int32_t *valtype)
{
    sr_error_info_t *err_info = NULL;

    /* LYD_ANYDATA_XML */
    *valtype = 0;

    if (node->schema->nodetype & LYD_NODE_ANY) {
        /* these are JSON data, set valtype */
        if (((struct lyd_node_any *)node)->value_type == LYD_ANYDATA_JSON) {
            /* LYD_ANYDATA_JSON */
            *valtype = 1;
        }

        /* lyd_node_any */
        if (lyd_any_value_str(node, any_value) != LY_SUCCESS) {
            ERRINFO(&err_info, SR_ERR_LY, "lyd_any_value_str()", "")
            goto cleanup;
        }
        *value = *any_value;
    } else if (lysc_is_userordered(node->schema)) {
        /* get value of the previous node */
        if (node->schema->nodetype == LYS_LEAFLIST) {
            *prev = lyd_get_meta_value(lyd_find_meta(node->meta, NULL, "yang:value"));
            if (*prev && !strlen(*prev)) {
                *prev_pred = (char *)*prev;
            } else if (asprintf(prev_pred, "[.='%s']", *prev) == -1) {
                ERRINFO(&err_info, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno))
                goto cleanup;
            }
            *orig_prev = lyd_get_meta_value(lyd_find_meta(node->meta, NULL, "yang:orig-value"));
            if (*orig_prev && !strlen(*orig_prev)) {
                *orig_prev_pred = (char *)*orig_prev;
            } else if (asprintf(orig_prev_pred, "[.='%s']", *orig_prev) == -1) {
                ERRINFO(&err_info, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno))
                goto cleanup;
            }
            *value = lyd_get_value(node);
        } else {
            *prev = lyd_get_meta_value(lyd_find_meta(node->meta, NULL, "yang:key"));
            *prev_pred = (char *)*prev;
            *orig_prev = lyd_get_meta_value(lyd_find_meta(node->meta, NULL, "yang:orig-key"));
            *orig_prev_pred = (char *)*orig_prev;
        }
    } else {
        *value = lyd_get_value(node);
    }

cleanup:
    return err_info;
}

/**
 * @brief Free all the memory allocated in srpds_get_values().
 *
 * @param[in] node Data node for which to free the values.
 * @param[in] value Value of the node.
 * @param[in] orig_value Original value of the node.
 * @param[in] value_pred Value of the node in predicate.
 * @param[in] orig_value_pred Original value of the node in predicate.
 * @param[in] any_value Value of the type 'any value'.
 */
static void
srpds_cleanup_values(struct lyd_node *node, const char *prev, const char *orig_prev, char **prev_pred, char **orig_prev_pred, char **any_value)
{
    free(*any_value);
    *any_value = NULL;
    if (node && node->schema && (node->schema->nodetype == LYS_LEAFLIST)) {
        if (*prev_pred != prev) {
            free(*prev_pred);
            *prev_pred = NULL;
        }
        if (*orig_prev_pred != orig_prev) {
            free(*orig_prev_pred);
            *orig_prev_pred = NULL;
        }
    }
}

/**
 * @brief Load the whole diff and store the operations inside a helper structure.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] node Current data node in the diff.
 * @param[in] parent_op Operation on the node's parent.
 * @param[out] diff_data Helper structure for storing diff operations.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_diff_recursively(mongoc_collection_t *module, const struct lyd_node *node, char parent_op, struct mongo_diff_data *diff_data)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sibling = (struct lyd_node *)node, *child = NULL;
    char *path = NULL, *path_no_pred = NULL, *path_modif = NULL;
    const char *predicate = NULL, *module_name = NULL;
    const char *value = NULL, *prev = NULL, *orig_prev = NULL;
    char *prev_pred = NULL, *orig_prev_pred = NULL, *any_value = NULL;
    int32_t valtype;
    char this_op = 0;
    struct lyd_meta *meta_op;
    uint64_t max_order = 0;

    while (sibling) {
        /* n - none, c - create, d - delete, r - replace */
        meta_op = lyd_find_meta(sibling->meta, NULL, "yang:operation");
        if (meta_op) {
            this_op = lyd_get_meta_value(meta_op)[0];
        } else {
            this_op = parent_op;
        }

        /* get node's path, path without last predicate and predicate */
        if ((err_info = srpds_get_predicate(sibling, &predicate, &path, &path_no_pred))) {
            goto cleanup;
        }

        /* get modified version of path and path_no_pred */
        if ((err_info = srpds_get_modif_path(path, &path_modif))) {
            goto cleanup;
        }

        /* node's values */
        if ((err_info = srpds_get_values(sibling, &value, &prev, &orig_prev, &prev_pred, &orig_prev_pred, &any_value, &valtype))) {
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
            if ((err_info = srpds_create_op(module, sibling, module_name, path, path_no_pred, predicate, path_modif, value, prev, prev_pred,
                    valtype, &max_order, diff_data))) {
                goto cleanup;
            }
            break;
        case 'd':
            if ((err_info = srpds_delete_op(module, sibling, path, path_no_pred, predicate, orig_prev_pred, diff_data))) {
                goto cleanup;
            }
            break;
        case 'r':
            if ((err_info = srpds_replace_op(module, sibling, module_name, path, path_no_pred, path_modif, predicate, value, prev, prev_pred,
                    orig_prev_pred, &max_order, diff_data))) {
                goto cleanup;
            }
            break;
        case 0:
            ERRINFO(&err_info, SR_ERR_UNSUPPORTED, "Operation for a node", "Unsupported operation")
            goto cleanup;
        }

        /* reset the max_order if the next sibling
         * is from a different list or if the next sibling does not exist */
        if (lysc_is_userordered(sibling->schema) && ((sibling->next &&
                (sibling->schema->name != sibling->next->schema->name)) || !(sibling->next))) {
            /* update max order for lists and leaf-lists */
            if ((err_info = srpds_update_maxord(module, path_no_pred, max_order))) {
                goto cleanup;
            }
            max_order = 0;
        }

        free(path);
        path = NULL;
        free(path_no_pred);
        path_no_pred = NULL;
        free(path_modif);
        path_modif = NULL;
        srpds_cleanup_values(sibling, prev, orig_prev, &prev_pred, &orig_prev_pred, &any_value);

        if ((child = lyd_child_no_keys(sibling))) {
            if ((err_info = srpds_load_diff_recursively(module, child, this_op, diff_data))) {
                goto cleanup;
            }
        }

        sibling = sibling->next;
    }

cleanup:
    free(path);
    free(path_no_pred);
    free(path_modif);
    srpds_cleanup_values(sibling, prev, orig_prev, &prev_pred, &orig_prev_pred, &any_value);
    return err_info;
}

/**
 * @brief Store the whole diff inside the database.
 *
 * @param[in] module Given MongoDB collection.
 * @param[in] mod_diff Module diff.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_store_all(mongoc_collection_t *module, const struct lyd_node *mod_diff)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    struct mongo_diff_data diff_data;
    uint32_t i;

    if ((err_info = srpds_diff_data_init(&diff_data))) {
        goto cleanup;
    }

    if ((err_info = srpds_load_diff_recursively(module, mod_diff, 0, &diff_data))) {
        goto cleanup;
    }

    if (diff_data.cre.idx) {
        if (!mongoc_collection_insert_many(module, (const bson_t **)diff_data.cre.docs,
                diff_data.cre.idx, NULL, NULL, &error)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_insert_many()", error.message)
            goto cleanup;
        }
    }

    for (i = 0; i < diff_data.rep.idx; ++i) {
        if (!mongoc_collection_update_one(module, (const bson_t *)(diff_data.rep_keys.docs)[i],
                (const bson_t *)(diff_data.rep.docs)[i], NULL, NULL, &error)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message)
            goto cleanup;
        }
    }

    for (i = 0; i < diff_data.del.idx; ++i) {
        if (!mongoc_collection_delete_one(module, (const bson_t *)(diff_data.del.docs)[i],
                NULL, NULL, &error)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_delete_one()", error.message)
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
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_set_last_modif_flag(mongoc_collection_t *module)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    bson_t *doc = NULL, *update = NULL;
    struct timespec spec;

    clock_gettime(CLOCK_REALTIME, &spec);
    doc = BCON_NEW("_id", BCON_UTF8("0"));
    update = BCON_NEW("$set", "{", "sec", BCON_INT64((int64_t)(spec.tv_sec)), "nsec", BCON_INT64((int64_t)(spec.tv_nsec)), "}");
    if (!mongoc_collection_update_one(module, doc, update, NULL, NULL, &error)) {
        ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message)
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
        ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message)
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
        ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_insert_one()", error.message)
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
        ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_insert_one()", error.message)
        goto cleanup;
    }

cleanup:
    bson_destroy(doc);
    return err_info;
}

/**
 * @brief Load the whole data tree (only for operational).
 *
 * @param[in] mod_data Whole data tree.
 * @param[out] diff_data Helper structure for storing diff operations.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_oper_recursively(const struct lyd_node *mod_data, struct mongo_diff_data *diff_data)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *sibling = mod_data;
    struct lyd_node *child = NULL;
    struct lyd_meta *meta = NULL;
    struct lys_module *module = NULL; // for opaque nodes
    struct lyd_attr *attr = NULL; // for opaque nodes
    const char *meta_value, *predicate = NULL;
    char *path_no_pred = NULL;
    char *path = NULL, *final_path = NULL;
    const char *value = NULL;
    char *any_value = NULL;
    int32_t valtype;
    bson_t *bson_query = NULL;

    while (sibling) {
        /* get path */
        if ((err_info = srpds_get_predicate(sibling, &predicate, &path, &path_no_pred))) {
            goto cleanup;
        }

        /* LYD_ANYDATA_XML */
        valtype = 0;

        /* get value */
        if (sibling->schema && (sibling->schema->nodetype & LYD_NODE_ANY)) {
            /* these are JSON data, set valtype */
            if (((struct lyd_node_any *)sibling)->value_type == LYD_ANYDATA_JSON) {
                /* LYD_ANYDATA_JSON */
                valtype = 1;
            }

            /* lyd_node_any */
            if (lyd_any_value_str(sibling, &any_value) != LY_SUCCESS) {
                ERRINFO(&err_info, SR_ERR_LY, "lyd_any_value_str()", "")
                goto cleanup;
            }
            value = any_value;
        } else {
            /* node values, opaque node values and rest */
            value = lyd_get_value(sibling);
        }

        /* create all data,
         * there is no need to store order for userordered lists and leaflists
         * since MongoDB does load all data in the same order in which they were stored */
        if (!value) {
            if ((err_info = srpds_add_operation(BCON_NEW("_id", BCON_UTF8(path), "is_opaque", BCON_BOOL(sibling->schema ? 0 : 1)), &(diff_data->cre)))) {
                goto cleanup;
            }
        } else {
            if ((err_info = srpds_add_operation(BCON_NEW("_id", BCON_UTF8(path), "value", BCON_UTF8(value), "valtype", BCON_INT32(valtype), "is_opaque", BCON_BOOL(sibling->schema ? 0 : 1)), &(diff_data->cre)))) {
                goto cleanup;
            }
        }

        /* for default nodes metadata */
        if ((sibling->flags & LYD_DEFAULT) && (sibling->schema->nodetype & LYD_NODE_TERM)) {
            if (asprintf(&final_path, "2%s#ietf-netconf-with-defaults:default", path) == -1) {
                ERRINFO(&err_info, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno))
                goto cleanup;
            }

            bson_query = BCON_NEW("_id", BCON_UTF8(final_path), "value", BCON_UTF8("true"));
            if ((err_info = srpds_add_operation(bson_query, &(diff_data->cre)))) {
                goto cleanup;
            }

            free(final_path);
            final_path = NULL;
        }

        /* create metadata and attributes of the node */
        if (sibling->schema) {
            /* nodes */
            meta = sibling->meta;
            while (meta) {
                meta_value = lyd_get_meta_value(meta);

                /* skip yang:lyds_tree metadata, this is libyang specific data */
                if (strcmp(meta->annotation->module->name, "yang") || strcmp(meta->name, "lyds_tree")) {
                    /* create new metadata */
                    if (asprintf(&final_path, "2%s#%s:%s", path, meta->annotation->module->name, meta->name) == -1) {
                        ERRINFO(&err_info, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno))
                        goto cleanup;
                    }

                    bson_query = BCON_NEW("_id", BCON_UTF8(final_path), "value", BCON_UTF8(meta_value));
                    if ((err_info = srpds_add_operation(bson_query, &(diff_data->cre)))) {
                        goto cleanup;
                    }
                }

                meta = meta->next;
                free(final_path);
                final_path = NULL;
            }
        } else {
            /* opaque nodes */
            attr = ((struct lyd_node_opaq *)sibling)->attr;
            while (attr) {
                if (attr->format == LY_VALUE_JSON) {
                    module = ly_ctx_get_module_implemented(attr->parent->ctx, attr->name.module_name);
                } else if (attr->format == LY_VALUE_XML) {
                    module = ly_ctx_get_module_implemented(attr->parent->ctx, attr->name.module_ns);
                }

                if (!module) {
                    ERRINFO(&err_info, SR_ERR_LY, "ly_ctx_get_module_implemented()", "Did not return any module.")
                    goto cleanup;
                }

                /* skip yang:lyds_tree attributes, this is libyang specific data */
                if (strcmp(module->name, "yang") || strcmp(attr->name.name, "lyds_tree")) {
                    /* create new attribute data */
                    if (asprintf(&final_path, "3%s#%s:%s", path, module->name, attr->name.name) == -1) {
                        ERRINFO(&err_info, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno))
                        goto cleanup;
                    }

                    bson_query = BCON_NEW("_id", BCON_UTF8(final_path), "value", BCON_UTF8(attr->value));
                    if ((err_info = srpds_add_operation(bson_query, &(diff_data->cre)))) {
                        goto cleanup;
                    }
                }

                attr = attr->next;
                free(final_path);
                final_path = NULL;
                module = NULL;
            }
        }

        if ((child = lyd_child_no_keys(sibling))) {
            if ((err_info = srpds_load_oper_recursively(child, diff_data))) {
                goto cleanup;
            }
        }

        sibling = sibling->next;

        free(path);
        free(path_no_pred);
        path = NULL;
        path_no_pred = NULL;
    }

cleanup:
    free(path);
    free(path_no_pred);
    free(final_path);
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
srpds_store_oper(mongoc_collection_t *module, const struct lyd_node *mod_data)
{
    sr_error_info_t *err_info = NULL;
    bson_error_t error;
    struct mongo_diff_data diff_data;
    bson_t *del_query = NULL;

    if ((err_info = srpds_diff_data_init(&diff_data))) {
        goto cleanup;
    }

    if (mod_data && (err_info = srpds_load_oper_recursively(mod_data, &diff_data))) {
        goto cleanup;
    }

    /* delete all data */
    del_query = BCON_NEW("_id", "{", "$regex", "^[^4]", "$options", "s", "}");
    if (!mongoc_collection_delete_many(module, del_query, NULL,
            NULL, &error)) {
        ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_delete_many()", error.message)
        goto cleanup;
    }

    /* create all data and metadata and attributes */
    if (diff_data.cre.idx) {
        if (!mongoc_collection_insert_many(module, (const bson_t **) diff_data.cre.docs,
                diff_data.cre.idx, NULL, NULL, &error)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_insert_many()", error.message)
            goto cleanup;
        }
    }

cleanup:
    bson_destroy(del_query);
    srpds_diff_data_destroy(&diff_data);
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

    if ((err_info = srpds_data_init(mod, SR_DS_CANDIDATE, 1, pdata, &mdata))) {
        goto cleanup;
    }

    doc = BCON_NEW("_id", BCON_UTF8("1"));
    cursor = mongoc_collection_find_with_opts(mdata.module, doc, NULL, NULL);

    if (mongoc_cursor_next(cursor, (const bson_t **) &doc2)) {
        if (!bson_iter_init(&iter, doc2)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_init()", "")
            goto cleanup;
        }

        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
            goto cleanup;
        }

        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
            goto cleanup;
        }
        *modified = bson_iter_bool(&iter);
    }

    if (mongoc_cursor_error(cursor, &error)) {
        ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_find_with_opts()", error.message)
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

    if ((err_info = srpds_data_init(mod, src_ds, 1, pdata, &mdata))) {
        goto cleanup;
    }

    command = BCON_NEW("pipeline", "[",
            "{", "$addFields",
            "{", "returns",
            "{", "$regexMatch",
            "{", "input", "$_id",
            "regex", "^[^4]",
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
        ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_aggregate()", error.message)
        goto cleanup;
    }
    srpds_data_destroy(pdata, &mdata);
    if ((err_info = srpds_data_init(mod, trg_ds, 1, pdata, &mdata))) {
        goto cleanup;
    }

    if ((err_info = srpds_set_last_modif_flag(mdata.module))) {
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
srpds_mongo_store(const struct lys_module *mod, sr_datastore_t ds, const struct lyd_node *mod_diff,
        const struct lyd_node *mod_data, void *plg_data)
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

    if ((err_info = srpds_data_init(mod, ds, 1, pdata, &mdata))) {
        goto cleanup;
    }

    if (ds == SR_DS_OPERATIONAL) {
        if ((err_info = srpds_store_oper(mdata.module, mod_data))) {
            goto cleanup;
        }
    } else if (mod_diff) {
        if ((err_info = srpds_store_all(mdata.module, mod_diff))) {
            goto cleanup;
        }
    }

    if ((err_info = srpds_set_last_modif_flag(mdata.module))) {
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
            ERRINFO(&err_info, SR_ERR_SYS, "atexit()", "")
            goto cleanup;
        }
        mongoc_init();

        /* mongoc is initialized */
        plugin_data.is_mongoc_initialized = 1;
    }
    pthread_mutex_unlock(&(plugin_data.lock));

    data = calloc(1, sizeof *data);
    if (!data) {
        ERRINFO(&err_info, SR_ERR_NO_MEMORY, "calloc()", "")
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
    bson_t *bson_query = NULL, *bson_index_key1 = NULL;
    mongoc_index_model_t *im = NULL;
    char *process_user = NULL, *process_group = NULL;
    struct timespec spec = {0};

    assert(mod && perm);

    if ((err_info = srpds_data_init(mod, ds, 0, pdata, &mdata))) {
        goto cleanup;
    }

    /* create indices on prev for quicker data retrieval while managing the userordered lists */
    bson_index_key1 = BCON_NEW("prev", BCON_INT32(1));
    im = mongoc_index_model_new(bson_index_key1, NULL /* opts */);
    if (!mongoc_collection_create_indexes_with_opts(mdata.module, &im, 1, NULL /* opts */, NULL /* reply */, &error)) {
        ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_create_indexes_with_opts", error.message)
        goto cleanup;
    }

    if (!owner) {
        if ((err_info = srpds_uid2usr(getuid(), &process_user))) {
            goto cleanup;
        }
        owner = process_user;
    }

    if (!group) {
        if ((err_info = srpds_gid2grp(getgid(), &process_group))) {
            goto cleanup;
        }
        group = process_group;
    }

    /* insert owner, group and permissions */
    bson_query = BCON_NEW("_id", "4", "owner", BCON_UTF8(owner), "group", BCON_UTF8(group), "perm", BCON_INT32((int32_t)perm));
    if (!mongoc_collection_insert_one(mdata.module, bson_query, NULL, NULL, &error)) {
        ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_insert_one()", error.message)
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
    mongoc_index_model_destroy(im);
    bson_destroy(bson_index_key1);
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

    if ((err_info = srpds_data_init(mod, ds, 1, pdata, &mdata))) {
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

    if ((err_info = srpds_data_init(mod, ds, 1, pdata, &mdata))) {
        goto cleanup;
    }

    /* _id for owner, group and permissions */
    bson_query_key = BCON_NEW("_id", "4");

    /* set owner */
    if (owner) {
        bson_query = BCON_NEW("$set", "{", "owner", BCON_UTF8(owner), "}");
        if (!mongoc_collection_update_one(mdata.module, bson_query_key, bson_query, NULL, NULL, &error)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message)
            goto cleanup;
        }
        bson_destroy(bson_query);
    }

    /* set group */
    if (group) {
        bson_query = BCON_NEW("$set", "{", "group", BCON_UTF8(group), "}");
        if (!mongoc_collection_update_one(mdata.module, bson_query_key, bson_query, NULL, NULL, &error)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message)
            goto cleanup;
        }
        bson_destroy(bson_query);
    }

    /* set permissions */
    if (perm) {
        bson_query = BCON_NEW("$set", "{", "perm", BCON_INT32(perm), "}");
        if (!mongoc_collection_update_one(mdata.module, bson_query_key, bson_query, NULL, NULL, &error)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_update_one()", error.message)
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

    if ((err_info = srpds_data_init(mod, ds, 1, pdata, &mdata))) {
        goto cleanup;
    }

    /* learn module access */
    if ((err_info = srpds_get_access(mdata.module, &owner, &group, &perm))) {
        goto cleanup;
    }

    /* learn the current process username */
    if ((err_info = srpds_uid2usr(getuid(), &username))) {
        goto cleanup;
    }

    /* learn the current process groupname */
    if ((err_info = srpds_gid2grp(getgid(), &groupname))) {
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

    if ((err_info = srpds_data_init(mod, ds, 1, pdata, &mdata))) {
        goto cleanup;
    }

    /* owner, group and permissions are part of the data */
    if (!mongoc_collection_drop_with_opts(mdata.module, NULL, &error)) {
        ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_drop_with_opts()", error.message)
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
srpds_mongo_load(const struct lys_module *mod, sr_datastore_t ds, const char **xpaths, uint32_t xpath_count, void *plg_data,
        struct lyd_node **mod_data)
{
    mongo_data_t mdata;
    mongo_plg_conn_data_t *pdata = (mongo_plg_conn_data_t *)plg_data;
    sr_error_info_t *err_info = NULL;
    bson_t xpath_filter;
    int is_valid = 0;

    assert(mod && mod_data);
    *mod_data = NULL;

    if ((err_info = srpds_data_init(mod, ds, 1, pdata, &mdata))) {
        goto cleanup;
    }

    if ((err_info = srpds_process_load_paths(mod->ctx, xpaths, xpath_count, &is_valid, &xpath_filter))) {
        goto cleanup;
    }

    /* initialize xpath_filter for loading */
    if (!is_valid) {
        bson_init(&xpath_filter);
    }

    if (ds == SR_DS_OPERATIONAL) {
        if ((err_info = srpds_load_oper(mdata.module, mod, mod_data))) {
            goto cleanup;
        }
    } else {
        if ((err_info = srpds_load_conv(mdata.module, mod, ds, &xpath_filter, mod_data))) {
            goto cleanup;
        }
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
void
srpds_mongo_recover(const struct lys_module *mod, sr_datastore_t ds, void *plg_data)
{
    (void) plg_data;
    (void) mod;
    (void) ds;
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

    if ((err_info = srpds_data_init(mod, ds, 1, pdata, &mdata))) {
        goto cleanup;
    }

    doc = BCON_NEW("_id", BCON_UTF8("0"));
    cursor = mongoc_collection_find_with_opts(mdata.module, doc, NULL, NULL);

    if (mongoc_cursor_next(cursor, (const bson_t **) &doc2)) {
        if (!bson_iter_init(&iter, doc2)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_init()", "")
            goto cleanup;
        }

        if (!bson_iter_next(&iter)) {
            ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "bson_iter_next()", "")
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
        ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_find_with_opts()", error.message)
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
    bson_error_t error;
    bson_t *doc = NULL;

    assert(mod);

    if ((err_info = srpds_data_init(mod, SR_DS_CANDIDATE, 1, pdata, &mdata))) {
        goto cleanup;
    }

    doc = BCON_NEW("_id", "{", "$regex", "^[^014]", "$options", "s", "}");

    if (!mongoc_collection_delete_many(mdata.module, doc,
            NULL, NULL, &error)) {
        ERRINFO(&err_info, SR_ERR_OPERATION_FAILED, "mongoc_collection_delete_many()", error.message)
        goto cleanup;
    }

    if ((err_info = srpds_set_last_modif_flag(mdata.module))) {
        goto cleanup;
    }

    if ((err_info = srpds_set_candidate_modified_flag(mdata.module, 0))) {
        goto cleanup;
    }

cleanup:
    bson_destroy(doc);
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
    .store_cb = srpds_mongo_store,
    .recover_cb = srpds_mongo_recover,
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
